// Copyright 2024 Saorsa Labs Limited
//
// This software is licensed under the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT> or the Apache License, Version 2.0
// <LICENSE-APACHE or https://www.apache.org/licenses/LICENSE-2.0>, at your
// option. This file may not be copied, modified, or distributed except
// according to those terms.
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Transport handle module
//!
//! Encapsulates transport-level concerns (QUIC connections, peer registry,
//! message I/O, events) extracted from [`P2PNode`] to enable sharing between
//! `P2PNode` and [`DhtNetworkManager`] without coupling to the full node.

use crate::MultiAddr;
use crate::PeerId;
use crate::bgp_geo_provider::BgpGeoProvider;
use crate::dht::core_engine::AddressType;
use crate::error::{NetworkError, P2PError, P2pResult as Result, SendFailureKind, TransportError};
use crate::identity::node_identity::{NodeIdentity, peer_id_from_public_key_spki};
use crate::network::{
    ConnectionStatus, MAX_ACTIVE_REQUESTS, MAX_REQUEST_TIMEOUT, MESSAGE_RECV_CHANNEL_CAPACITY,
    NetworkSender, P2PEvent, ParsedMessage, PeerInfo, PeerResponse, PendingRequest,
    RequestResponseEnvelope, WireMessage, broadcast_event, normalize_wildcard_to_loopback,
    parse_protocol_message, register_new_channel,
};
use crate::reachability::{RelaySessionEstablishError, RelaySessionEstablisher};
use crate::transport::external_addresses::ExternalAddresses;
use crate::transport::saorsa_transport_adapter::{
    AddressEventPublisher, ConnectionEvent, DualStackNetworkNode,
};
use crate::validation::{RateLimitConfig, RateLimiter};

use dashmap::mapref::entry::Entry as DashEntry;
use dashmap::{DashMap, DashSet};
use saorsa_transport::nat_traversal_api::PreparedRelay;
use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{RwLock, broadcast, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

// Test configuration defaults (used by `new_for_tests()` which is available in all builds)
const TEST_EVENT_CHANNEL_CAPACITY: usize = 16;
const TEST_MAX_REQUESTS: u32 = 100;
const TEST_BURST_SIZE: u32 = 100;
const TEST_RATE_LIMIT_WINDOW_SECS: u64 = 1;
const TEST_CONNECTION_TIMEOUT_SECS: u64 = 30;

/// Minimum distinct source-disjoint observers required before an external
/// address is considered cold-dialable.
///
/// "Source-disjoint" means the observer IP was not already in this node's
/// known-peer set at the time of the inbound — i.e. not a peer we had ever
/// dialed or seen connect to us. Two such observers eliminates the
/// pinhole-self-fulfillment case (one already-known peer redialing through
/// their pre-existing NAT binding) while still allowing prompt promotion
/// in healthy clusters where multiple bootstraps independently reach the
/// node within the first connect window.
///
/// Matches `MIN_OBSERVERS_FOR_QUORUM` in saorsa-transport's address-pinning
/// path (`nat_traversal_api.rs`) — same statistical argument.
pub(crate) const MIN_DISTINCT_OBSERVERS_FOR_DIRECT: usize = 2;

/// Cap on the number of distinct externals a single peer's IP may
/// have on record in `peer_observations` before further reports are
/// dropped.
///
/// A well-behaved peer observes us at exactly one external per family
/// (the one their packets reached us through). The cap protects against
/// a hostile peer flooding many fake `OBSERVED_ADDRESS` entries to bloat
/// memory or to "vote" for arbitrary externals — that vote still requires
/// a separate Side::Server inbound from the same peer to count, but the
/// table itself should not grow without bound under attack. 8 is well
/// above the realistic 1–2 needed for v4+v6 and dual-NAT setups.
pub(crate) const MAX_OBSERVATIONS_PER_PEER: usize = 8;

/// Return `true` iff `external` has cleared the per-address proof
/// threshold in `proven_externals`.
///
/// Free function so the threshold semantics — and the address
/// normalisation that backs lookups — can be exercised in unit tests
/// without constructing a full [`TransportHandle`] (which performs real
/// network binds).
pub(crate) fn external_meets_proof_threshold(
    external: SocketAddr,
    proven_externals: &DashMap<SocketAddr, HashSet<IpAddr>>,
) -> bool {
    let normalized = saorsa_transport::shared::normalize_socket_addr(external);
    proven_externals
        .get(&normalized)
        .map(|set| set.len() >= MIN_DISTINCT_OBSERVERS_FOR_DIRECT)
        .unwrap_or(false)
}

/// Stable label for an address-type tag, used as a structured `kind`
/// field on the `connect_peer` success/failure logs. `None` is rendered
/// as `"unknown"` for callers that don't carry a tag (e.g., the public
/// `connect_peer` entry point used by tests).
fn address_kind_label(kind: Option<AddressType>) -> &'static str {
    match kind {
        Some(AddressType::Relay) => "Relay",
        Some(AddressType::Direct) => "Direct",
        Some(AddressType::Unverified) => "Unverified",
        Some(AddressType::Lan) => "Lan",
        None => "unknown",
    }
}

fn classify_send_error(error: &anyhow::Error) -> SendFailureKind {
    for cause in error.chain() {
        if let Some(endpoint_error) = cause.downcast_ref::<saorsa_transport::EndpointError>() {
            return match endpoint_error {
                saorsa_transport::EndpointError::PeerNotFound(_) => SendFailureKind::StaleChannel,
                saorsa_transport::EndpointError::SendFailed { stage, .. } => {
                    classify_transport_send_stage(*stage)
                }
                _ => SendFailureKind::Other,
            };
        }
    }

    SendFailureKind::Other
}

fn classify_transport_send_stage(stage: saorsa_transport::SendFailureStage) -> SendFailureKind {
    match stage {
        saorsa_transport::SendFailureStage::OpenStream => SendFailureKind::StaleChannel,
        saorsa_transport::SendFailureStage::OpenStreamProgressTimeout => {
            SendFailureKind::OpenStreamProgressTimeout
        }
        saorsa_transport::SendFailureStage::WriteProgressTimeout => {
            SendFailureKind::WriteProgressTimeout
        }
        saorsa_transport::SendFailureStage::Write => SendFailureKind::StreamWrite,
        saorsa_transport::SendFailureStage::Finish => SendFailureKind::StreamFinish,
        saorsa_transport::SendFailureStage::DeliveryAck => SendFailureKind::StreamFinish,
    }
}

/// Internal protocol for automatic identity announcement on connect.
/// Filtered from P2PEvent::Message emission — not visible to applications.
const IDENTITY_ANNOUNCE_PROTOCOL: &str = "/saorsa/identity/1.0";

/// Configuration for transport initialization, derived from [`NodeConfig`](crate::network::NodeConfig).
pub struct TransportConfig {
    /// Addresses to bind on. The transport partitions these into at most
    /// one IPv4 and one IPv6 QUIC endpoint.
    pub listen_addrs: Vec<MultiAddr>,
    /// Connection timeout for outbound dials and request waits.
    pub connection_timeout: Duration,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Broadcast channel capacity for P2P events.
    pub event_channel_capacity: usize,
    /// Optional override for the maximum application-layer message size.
    ///
    /// When `None`, saorsa-transport's built-in default is used. Set this to tune
    /// the QUIC stream receive window and the
    /// per-stream read buffer for larger or smaller payloads.
    pub max_message_size: Option<usize>,
    /// Cryptographic node identity (ML-DSA-65). The canonical peer ID is
    /// derived from this identity's public key hash.
    pub node_identity: Arc<NodeIdentity>,
    /// User agent string identifying this node's software.
    pub user_agent: String,
    /// Allow loopback addresses in the transport layer.
    pub allow_loopback: bool,
    /// Enable MASQUE relay service for other peers.
    /// False for client-mode nodes that are outbound-only.
    pub enable_relay_service: bool,
    /// Advertise discovered external addresses to connected peers.
    /// False for client-mode nodes that are outbound-only.
    pub advertise_external_addresses: bool,
}

impl TransportConfig {
    /// Build transport config directly from the node's canonical config.
    pub fn from_node_config(
        config: &crate::network::NodeConfig,
        event_channel_capacity: usize,
        node_identity: Arc<NodeIdentity>,
    ) -> Self {
        Self {
            listen_addrs: config.listen_addrs(),
            connection_timeout: config.connection_timeout,
            max_connections: config.max_connections,
            event_channel_capacity,
            max_message_size: config.max_message_size,
            node_identity,
            user_agent: config.user_agent(),
            allow_loopback: config.allow_loopback,
            enable_relay_service: config.mode != crate::network::NodeMode::Client,
            advertise_external_addresses: config.mode != crate::network::NodeMode::Client,
        }
    }
}

/// Cumulative wire-traffic counters (V2-623).
///
/// Plain relaxed `AtomicU64`s bumped at the transport tx/rx choke points, in
/// the same lock-free style as the sharded dispatcher's `drop_counter`. All
/// values are monotonic since process start; a periodic task in
/// [`DhtNetworkManager`](crate::dht_network_manager::DhtNetworkManager) emits
/// them as a `wire traffic summary (cumulative)` INFO line, and rates are
/// computed as deltas at query time.
///
/// `overhead_*` = wire − payload, i.e. the per-message envelope cost
/// (signature + ML-DSA-65 public key + framing). This is the direct
/// before/after instrument for V2-616 (stop embedding the ML-DSA-65 public key
/// in every `WireMessage`).
#[derive(Debug, Default)]
pub(crate) struct TrafficCounters {
    /// Total wire bytes sent (signed+serialised `WireMessage`s).
    pub wire_tx_bytes: AtomicU64,
    /// Total wire messages sent.
    pub wire_tx_count: AtomicU64,
    /// Envelope overhead sent = wire − payload.
    pub overhead_tx_bytes: AtomicU64,
    /// Wire bytes received and successfully decoded. These are decoded
    /// protocol bytes: malformed / signature-rejected frames are excluded, so
    /// this is not raw host ingress.
    pub wire_rx_bytes: AtomicU64,
    /// Wire messages received and successfully decoded.
    pub wire_rx_count: AtomicU64,
    /// Envelope overhead received = wire − payload (decoded messages only).
    pub overhead_rx_bytes: AtomicU64,
    /// FIND_NODE requests sent (counted only after a successful send).
    pub find_node_tx_count: AtomicU64,
    /// `NodesFound` response payload bytes *encoded*. Counts responses this
    /// node produced/serialised, not confirmed sends (the transmit happens in
    /// the caller); `wire_tx_*` covers the actual send.
    pub nodes_found_tx_bytes: AtomicU64,
    /// `NodesFound` responses encoded (see `nodes_found_tx_bytes`).
    pub nodes_found_tx_count: AtomicU64,
    /// `PUBLISH_ADDRESS_SET` operations sent (counted only after a successful send).
    pub publish_addr_tx_count: AtomicU64,
    /// Ping operations sent (counted only after a successful send).
    pub ping_tx_count: AtomicU64,
    /// Identity-announce wire bytes sent (bypasses `send_on_channel`).
    pub identity_announce_tx_bytes: AtomicU64,
    /// Identity announces sent.
    pub identity_announce_tx_count: AtomicU64,
}

impl TrafficCounters {
    /// Load every counter (relaxed) into a plain-value [`TrafficSnapshot`].
    pub(crate) fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            wire_tx_bytes: self.wire_tx_bytes.load(Ordering::Relaxed),
            wire_tx_count: self.wire_tx_count.load(Ordering::Relaxed),
            overhead_tx_bytes: self.overhead_tx_bytes.load(Ordering::Relaxed),
            wire_rx_bytes: self.wire_rx_bytes.load(Ordering::Relaxed),
            wire_rx_count: self.wire_rx_count.load(Ordering::Relaxed),
            overhead_rx_bytes: self.overhead_rx_bytes.load(Ordering::Relaxed),
            find_node_tx_count: self.find_node_tx_count.load(Ordering::Relaxed),
            nodes_found_tx_bytes: self.nodes_found_tx_bytes.load(Ordering::Relaxed),
            nodes_found_tx_count: self.nodes_found_tx_count.load(Ordering::Relaxed),
            publish_addr_tx_count: self.publish_addr_tx_count.load(Ordering::Relaxed),
            ping_tx_count: self.ping_tx_count.load(Ordering::Relaxed),
            identity_announce_tx_bytes: self.identity_announce_tx_bytes.load(Ordering::Relaxed),
            identity_announce_tx_count: self.identity_announce_tx_count.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time copy of the cumulative wire-traffic counters (V2-623).
///
/// Returned by `TransportHandle::traffic_snapshot`. All values are monotonic
/// since process start (relaxed atomic loads of the internal counters); compute
/// rates as deltas between two snapshots. `wire_rx_bytes` counts decoded
/// protocol bytes — malformed / signature-rejected frames are excluded, so it
/// is not raw host ingress. `overhead_*` = wire − payload (per-message
/// envelope cost: signature + ML-DSA-65 public key + framing).
///
/// This is the same counter set the periodic
/// `wire traffic summary (cumulative)` INFO line emits, exposed as an API so
/// embedders (bandwidth meters, data-usage screens) can read it on their own
/// schedule instead of scraping tracing output.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TrafficSnapshot {
    /// Total wire bytes sent (signed+serialised `WireMessage`s).
    pub wire_tx_bytes: u64,
    /// Total wire messages sent.
    pub wire_tx_count: u64,
    /// Envelope overhead sent = wire − payload.
    pub overhead_tx_bytes: u64,
    /// Wire bytes received and successfully decoded.
    pub wire_rx_bytes: u64,
    /// Wire messages received and successfully decoded.
    pub wire_rx_count: u64,
    /// Envelope overhead received = wire − payload (decoded messages only).
    pub overhead_rx_bytes: u64,
    /// FIND_NODE requests sent (counted only after a successful send).
    pub find_node_tx_count: u64,
    /// `NodesFound` response payload bytes encoded, not confirmed sends.
    pub nodes_found_tx_bytes: u64,
    /// `NodesFound` responses encoded.
    pub nodes_found_tx_count: u64,
    /// `PUBLISH_ADDRESS_SET` operations sent (counted only after a successful send).
    pub publish_addr_tx_count: u64,
    /// Ping operations sent (counted only after a successful send).
    pub ping_tx_count: u64,
    /// Identity-announce wire bytes sent (bypasses `send_on_channel`).
    pub identity_announce_tx_bytes: u64,
    /// Identity announces sent.
    pub identity_announce_tx_count: u64,
}

/// Encapsulates transport-level concerns: QUIC connections, peer registry,
/// message I/O, and network events.
///
/// Both [`P2PNode`](crate::network::P2PNode) and
/// [`DhtNetworkManager`](crate::dht_network_manager::DhtNetworkManager)
/// hold `Arc<TransportHandle>` so they share the same transport state.
pub struct TransportHandle {
    dual_node: Arc<DualStackNetworkNode>,
    /// Channel-level peer registry. Sharded internally — concurrent
    /// reads/writes on different keys never serialise. Replaces the previous
    /// `Arc<RwLock<HashMap>>`, which serialised the inbound accept loop and
    /// every per-peer event handler behind a single writer.
    peers: Arc<DashMap<String, PeerInfo>>,
    /// Active transport-level channels. Sharded internally; same rationale
    /// as `peers`.
    active_connections: Arc<DashSet<String>>,
    event_tx: broadcast::Sender<P2PEvent>,
    listen_addrs: RwLock<Vec<MultiAddr>>,
    rate_limiter: Arc<RateLimiter>,
    active_requests: Arc<DashMap<String, PendingRequest>>,
    /// Cumulative wire-traffic counters (V2-623). Shared (via the enclosing
    /// `Arc<TransportHandle>`) with the DHT manager's summary-emitting task and
    /// with the rx/monitor background tasks that receive a clone.
    pub(crate) traffic: Arc<TrafficCounters>,
    // Held to keep the Arc alive for background tasks that captured a clone.
    #[allow(dead_code)]
    geo_provider: Arc<BgpGeoProvider>,
    shutdown: CancellationToken,
    /// Relay established events — received when this node sets up a MASQUE relay.
    relay_established_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<SocketAddr>>,
    /// Relay lost events — received when a previously-advertised MASQUE
    /// relay address is no longer reachable (tunnel died, health check
    /// failed, accept loop exited).  Drained by the reachability driver
    /// to trigger an immediate DHT republish with the stale relay
    /// address removed — without this, peers keep dialing the dead
    /// relay for the full health-poll cycle (5 s) or longer.
    relay_lost_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<SocketAddr>>,
    /// Direct address promotion events — received when the passive
    /// reachability classifier proves one of this node's pinned external
    /// addresses is cold-dialable. Drained by the reachability driver while
    /// holding a relay so it can republish `Relay + Direct` instead of
    /// leaving peers with the older `Relay + Unverified` self-record.
    direct_address_promoted_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<SocketAddr>>,
    /// Latest direct-address promotion for observers/tests. This is
    /// separate from the driver's single-consumer mpsc receiver so callers
    /// can observe state changes without contending with the driver's
    /// `recv().await`.
    direct_address_promoted_watch_tx: watch::Sender<Option<SocketAddr>>,
    direct_address_promoted_watch_rx: parking_lot::Mutex<watch::Receiver<Option<SocketAddr>>>,
    /// Self-address update events — received when a newly observed
    /// external address becomes publishable as Unverified or is pinned as
    /// Direct without crossing the Direct proof threshold. Drained by the
    /// reachability driver so a relay-only self-record can be corrected as
    /// soon as a non-relay fallback appears.
    self_address_updated_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<SocketAddr>>,
    /// Latest self-address update for observers/tests. Separate from the
    /// driver's single-consumer mpsc receiver for the same reason as
    /// `direct_address_promoted_watch_rx`.
    self_address_updated_watch_tx: watch::Sender<Option<SocketAddr>>,
    self_address_updated_watch_rx: parking_lot::Mutex<watch::Receiver<Option<SocketAddr>>>,
    /// External addresses: direct addresses pinned from transport quorum,
    /// unverified candidates from QUIC `OBSERVED_ADDRESS` frames, plus the
    /// relay-allocated address when a MASQUE relay is held. Populated by
    /// the address-update forwarder and reachability classifier; survives
    /// connection drops; reset on process restart.
    external_addresses: Arc<parking_lot::Mutex<ExternalAddresses>>,
    connection_timeout: Duration,
    connection_monitor_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    recv_handles: Arc<RwLock<Vec<JoinHandle<()>>>>,
    listener_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    /// Cryptographic node identity for signing outgoing messages.
    node_identity: Arc<NodeIdentity>,
    /// User agent string included in every outgoing wire message.
    user_agent: String,
    /// Maps app-level [`PeerId`] → set of channel IDs (QUIC, Bluetooth, …).
    ///
    /// A single peer may communicate over multiple channels simultaneously.
    /// Sharded `DashMap` so concurrent registrations for different peers
    /// don't serialise behind a single writer.
    peer_to_channel: Arc<DashMap<PeerId, HashSet<String>>>,
    /// Reverse index: channel ID → set of app-level [`PeerId`]s on that channel.
    channel_to_peers: Arc<DashMap<String, HashSet<PeerId>>>,
    /// Maps app-level [`PeerId`] → user agent string received during authentication.
    ///
    /// Stored so that late subscribers (e.g. DHT manager reconciliation) can look
    /// up a peer's mode without re-receiving the `PeerConnected` event.
    peer_user_agents: Arc<DashMap<PeerId, String>>,
    /// Remote socket addresses this handle has dialed out to, populated
    /// before each dial in [`Self::connect_peer`]. Read-only input to the
    /// passive direct-reachability classifier spawned below. Monotonic —
    /// entries are never removed for the lifetime of the handle because the
    /// classifier only cares about "did we ever dial this remote?".
    dialed_addrs: Arc<DashSet<SocketAddr>>,
    /// IPs of every peer this handle has ever interacted with. Populated by
    /// [`Self::connect_peer`] (alongside `dialed_addrs`) and by the passive
    /// reachability classifier on every `PeerConnected` event (both sides).
    /// Used as the source-disjointness exclusion set for the per-address
    /// proof: an inbound from an IP already in this set does not prove
    /// cold-dialability — that peer already had reason to know our address
    /// (we dialed them, or they connected to us before) and could therefore
    /// reach us through a pre-existing NAT pinhole. Per-IP (not per
    /// SocketAddr) because NAT remappings between sessions change the port
    /// while the IP — and therefore the pinhole — is what matters.
    known_peer_ips: Arc<DashSet<IpAddr>>,
    /// Distinct source-disjoint observer IPs per pinned external address.
    ///
    /// An entry is added when a peer that passed the source-disjoint /
    /// sibling-hairpin / Side::Server filter reports — via a QUIC
    /// `OBSERVED_ADDRESS` frame — that they observe us at the named
    /// external. The peer's own report is the per-address attribution
    /// signal: an inbound from peer P on local v4 stack only credits the
    /// externals P actually told us about, never any other same-family
    /// pinned external.
    ///
    /// An external is considered cold-dialable
    /// ([`AddressType::Direct`](crate::dht::AddressType::Direct)) once its
    /// observer set reaches [`MIN_DISTINCT_OBSERVERS_FOR_DIRECT`].
    /// Per-address — never globally — so one external's proof does not
    /// promote unrelated externals, even on multi-WAN hosts with several
    /// concurrently-pinned same-family externals.
    proven_externals: Arc<DashMap<SocketAddr, HashSet<IpAddr>>>,
    /// Per-peer-IP set of externals each peer has reported observing us
    /// at, derived from `P2pEvent::PeerObservedExternal`.
    ///
    /// Used by the classifier to do per-address attribution: when peer P
    /// makes a source-disjoint Side::Server inbound, only the externals
    /// P has told us about (intersected with currently pinned externals)
    /// are credited with P's IP. A peer reporting external `E` is the
    /// peer's own statement that they reached us at `E` — there is no
    /// stronger per-address signal available at this layer.
    ///
    /// Capped at [`MAX_OBSERVATIONS_PER_PEER`] entries per peer to bound
    /// memory under hostile reporting. Per-IP (not per-SocketAddr)
    /// because NAT remappings rotate the port between sessions while the
    /// IP — and therefore the proof identity — is what matters.
    ///
    /// Held to keep the `Arc` alive for the classifier and forwarder
    /// tasks that captured clones — `self`-side accesses go through the
    /// background tasks, not through this field directly.
    #[allow(dead_code)]
    peer_observations: Arc<DashMap<IpAddr, HashSet<SocketAddr>>>,
    /// IPs of source-disjoint Side::Server inbounds that passed the
    /// classifier's filters and are therefore eligible to contribute proof.
    ///
    /// An observation from a peer not in this set is recorded in
    /// `peer_observations` but does not credit `proven_externals`.
    /// Membership is monotonic: once a peer's IP is added (i.e. they
    /// arrived as a stranger), their observations remain attributable
    /// for the lifetime of the handle.
    ///
    /// Held to keep the `Arc` alive for the classifier and forwarder
    /// tasks that captured clones — `self`-side accesses go through the
    /// background tasks, not through this field directly.
    #[allow(dead_code)]
    proof_eligible_peers: Arc<DashSet<IpAddr>>,
}

struct ActiveRequestGuard {
    active_requests: Arc<DashMap<String, PendingRequest>>,
    message_id: String,
}

impl ActiveRequestGuard {
    fn new(active_requests: Arc<DashMap<String, PendingRequest>>, message_id: String) -> Self {
        Self {
            active_requests,
            message_id,
        }
    }
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        self.active_requests.remove(&self.message_id);
    }
}

// ============================================================================
// Construction
// ============================================================================

impl TransportHandle {
    /// Create a new transport handle with the given configuration.
    ///
    /// This performs the transport-level initialization that was previously
    /// embedded in `P2PNode::new()`: dual-stack QUIC binding, rate limiter,
    /// GeoIP provider, and a background connection lifecycle monitor.
    pub async fn new(config: TransportConfig) -> Result<Self> {
        let (event_tx, _) = broadcast::channel(config.event_channel_capacity);

        // Initialize dual-stack saorsa-transport nodes
        // Partition listen addresses into first IPv4 and first IPv6 for
        // dual-stack binding. Non-IP addresses are skipped.
        let mut v4_opt: Option<SocketAddr> = None;
        let mut v6_opt: Option<SocketAddr> = None;
        for addr in &config.listen_addrs {
            if let Some(sa) = addr.dialable_socket_addr() {
                match sa.ip() {
                    std::net::IpAddr::V4(_) if v4_opt.is_none() => v4_opt = Some(sa),
                    std::net::IpAddr::V6(_) if v6_opt.is_none() => v6_opt = Some(sa),
                    _ => {} // already have one for this family
                }
            }
        }

        let dual_node = Arc::new(
            DualStackNetworkNode::new_with_options(
                v6_opt,
                v4_opt,
                config.max_connections,
                config.max_message_size,
                config.allow_loopback,
                config.enable_relay_service,
                config.advertise_external_addresses,
                // ADR-011: seed the transport TLS identity with the node's
                // persistent ML-DSA key so the relay-authenticated fingerprint
                // is stable across restarts (the on-disk node_identity, not a
                // fresh per-process key).
                Some((
                    config.node_identity.public_key().clone(),
                    config.node_identity.secret_key().clone(),
                )),
            )
            .await
            .map_err(|e| {
                P2PError::Transport(crate::error::TransportError::SetupFailed(
                    format!("Failed to create dual-stack network nodes: {}", e).into(),
                ))
            })?,
        );

        let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::default()));
        let active_connections: Arc<DashSet<String>> = Arc::new(DashSet::new());
        let geo_provider = Arc::new(BgpGeoProvider::new());
        let peers: Arc<DashMap<String, PeerInfo>> = Arc::new(DashMap::new());

        let shutdown = CancellationToken::new();

        // External addresses. The forwarder and classifier below feed this
        // from `ExternalAddressDiscovered` and `PeerObservedExternal`
        // events; pinned direct addresses are retained for the process
        // lifetime and single-observer reports are retained as Unverified
        // publish candidates.
        let external_addresses = Arc::new(parking_lot::Mutex::new(ExternalAddresses::new()));

        // Passive direct-reachability classifier: subscribe to
        // `P2pEvent::PeerConnected` and `P2pEvent::PeerObservedExternal`,
        // attribute proof per-address using each peer's own
        // `OBSERVED_ADDRESS` reports. Consumed by
        // `AcquisitionDriver::publish_typed_set` (via
        // `Self::is_external_proven`) to tag each address as
        // `AddressType::Direct` only once that address itself has cleared
        // the observer threshold. The classifier also writes into
        // `known_peer_ips` on every `PeerConnected` event so subsequent
        // inbounds from the same IP do not count as fresh proof.
        let dialed_addrs: Arc<DashSet<SocketAddr>> = Arc::new(DashSet::new());
        let known_peer_ips: Arc<DashSet<IpAddr>> = Arc::new(DashSet::new());
        let proven_externals: Arc<DashMap<SocketAddr, HashSet<IpAddr>>> = Arc::new(DashMap::new());
        let peer_observations: Arc<DashMap<IpAddr, HashSet<SocketAddr>>> = Arc::new(DashMap::new());
        let proof_eligible_peers: Arc<DashSet<IpAddr>> = Arc::new(DashSet::new());

        // Subscribe to address-related P2pEvents from the transport layer:
        //   - RelayEstablished → mpsc, drained by the DHT bridge
        //   - RelayLost → mpsc, drained by the reachability driver
        //   - DirectAddressPromoted → mpsc, drained by the reachability driver
        //   - SelfAddressUpdated → mpsc, drained by the reachability driver
        //   - ExternalAddressDiscovered → pinned into external_addresses
        //     and triggers a back-fill of any earlier observations now
        //     that the address is known. PeerObservedExternal is consumed
        //     by the classifier and retained as an Unverified candidate.
        let (direct_promoted_tx, direct_address_promoted_rx) = tokio::sync::mpsc::channel(
            crate::transport::saorsa_transport_adapter::ADDRESS_EVENT_CHANNEL_CAPACITY,
        );
        let (self_address_updated_tx, self_address_updated_rx) = tokio::sync::mpsc::channel(
            crate::transport::saorsa_transport_adapter::ADDRESS_EVENT_CHANNEL_CAPACITY,
        );
        let (direct_address_promoted_watch_tx, direct_address_promoted_watch_rx) =
            watch::channel(None);
        let (self_address_updated_watch_tx, self_address_updated_watch_rx) = watch::channel(None);
        let direct_promoted_events = AddressEventPublisher::new(
            "DirectAddressPromoted",
            direct_promoted_tx,
            direct_address_promoted_watch_tx.clone(),
        );
        let self_address_updated_events = AddressEventPublisher::new(
            "SelfAddressUpdated",
            self_address_updated_tx,
            self_address_updated_watch_tx.clone(),
        );
        let (relay_established_rx, relay_lost_rx) = dual_node.spawn_address_event_forwarder(
            Arc::clone(&external_addresses),
            Arc::clone(&peer_observations),
            Arc::clone(&proof_eligible_peers),
            Arc::clone(&proven_externals),
            direct_promoted_events.clone(),
            self_address_updated_events.clone(),
        );

        dual_node.spawn_direct_reachability_classifier(
            Arc::clone(&dialed_addrs),
            Arc::clone(&known_peer_ips),
            Arc::clone(&proven_externals),
            Arc::clone(&external_addresses),
            Arc::clone(&peer_observations),
            Arc::clone(&proof_eligible_peers),
            direct_promoted_events,
            self_address_updated_events,
        );

        // Subscribe to connection events BEFORE spawning the monitor task
        let connection_event_rx = dual_node.subscribe_connection_events();

        let peer_to_channel: Arc<DashMap<PeerId, HashSet<String>>> = Arc::new(DashMap::new());
        let channel_to_peers: Arc<DashMap<String, HashSet<PeerId>>> = Arc::new(DashMap::new());
        let peer_user_agents: Arc<DashMap<PeerId, String>> = Arc::new(DashMap::new());
        // (peer_addr_update_tx removed — dedicated forwarder creates its own)

        let traffic = Arc::new(TrafficCounters::default());

        let connection_monitor_handle = {
            let active_conns = Arc::clone(&active_connections);
            let peers_map = Arc::clone(&peers);
            let event_tx_clone = event_tx.clone();
            let dual_node_clone = Arc::clone(&dual_node);
            let geo_provider_clone = Arc::clone(&geo_provider);
            let shutdown_token = shutdown.clone();
            let p2c = Arc::clone(&peer_to_channel);
            let c2p = Arc::clone(&channel_to_peers);
            let pua = Arc::clone(&peer_user_agents);
            let identity_clone = config.node_identity.clone();
            let user_agent_clone = config.user_agent.clone();
            let traffic_clone = Arc::clone(&traffic);

            let handle = tokio::spawn(async move {
                Self::connection_lifecycle_monitor_with_rx(
                    dual_node_clone,
                    connection_event_rx,
                    active_conns,
                    peers_map,
                    event_tx_clone,
                    geo_provider_clone,
                    shutdown_token,
                    p2c,
                    c2p,
                    pua,
                    identity_clone,
                    user_agent_clone,
                    traffic_clone,
                )
                .await;
            });
            Arc::new(RwLock::new(Some(handle)))
        };

        Ok(Self {
            dual_node,
            peers,
            active_connections,
            event_tx,
            listen_addrs: RwLock::new(Vec::new()),
            rate_limiter,
            active_requests: Arc::new(DashMap::new()),
            traffic,
            geo_provider,
            shutdown,
            relay_established_rx: tokio::sync::Mutex::new(relay_established_rx),
            relay_lost_rx: tokio::sync::Mutex::new(relay_lost_rx),
            direct_address_promoted_rx: tokio::sync::Mutex::new(direct_address_promoted_rx),
            direct_address_promoted_watch_tx,
            direct_address_promoted_watch_rx: parking_lot::Mutex::new(
                direct_address_promoted_watch_rx,
            ),
            self_address_updated_rx: tokio::sync::Mutex::new(self_address_updated_rx),
            self_address_updated_watch_tx,
            self_address_updated_watch_rx: parking_lot::Mutex::new(self_address_updated_watch_rx),
            external_addresses,
            connection_timeout: config.connection_timeout,
            connection_monitor_handle,
            recv_handles: Arc::new(RwLock::new(Vec::new())),
            listener_handle: Arc::new(RwLock::new(None)),
            node_identity: config.node_identity,
            user_agent: config.user_agent,
            peer_to_channel,
            channel_to_peers,
            peer_user_agents,
            dialed_addrs,
            known_peer_ips,
            proven_externals,
            peer_observations,
            proof_eligible_peers,
        })
    }

    /// Minimal constructor for tests that avoids real networking.
    pub fn new_for_tests() -> Result<Self> {
        let identity = Arc::new(NodeIdentity::generate().map_err(|e| {
            P2PError::Network(NetworkError::BindError(
                format!("Failed to generate test node identity: {}", e).into(),
            ))
        })?);
        let (event_tx, _) = broadcast::channel(TEST_EVENT_CHANNEL_CAPACITY);
        let dual_node = {
            let v6: Option<SocketAddr> = "[::1]:0"
                .parse()
                .ok()
                .or(Some(SocketAddr::from(([0, 0, 0, 0], 0))));
            let v4: Option<SocketAddr> = "127.0.0.1:0".parse().ok();
            let handle = tokio::runtime::Handle::current();
            let dual_attempt = handle.block_on(DualStackNetworkNode::new(v6, v4));
            let dual = match dual_attempt {
                Ok(d) => d,
                Err(_e1) => {
                    let fallback = handle
                        .block_on(DualStackNetworkNode::new(None, "127.0.0.1:0".parse().ok()));
                    match fallback {
                        Ok(d) => d,
                        Err(e2) => {
                            return Err(P2PError::Network(NetworkError::BindError(
                                format!("Failed to create dual-stack network node: {}", e2).into(),
                            )));
                        }
                    }
                }
            };
            Arc::new(dual)
        };
        let (direct_address_promoted_watch_tx, direct_address_promoted_watch_rx) =
            watch::channel(None);
        let (self_address_updated_watch_tx, self_address_updated_watch_rx) = watch::channel(None);

        Ok(Self {
            dual_node,
            peers: Arc::new(DashMap::new()),
            active_connections: Arc::new(DashSet::new()),
            event_tx,
            listen_addrs: RwLock::new(Vec::new()),
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig {
                max_requests: TEST_MAX_REQUESTS,
                burst_size: TEST_BURST_SIZE,
                window: std::time::Duration::from_secs(TEST_RATE_LIMIT_WINDOW_SECS),
                ..Default::default()
            })),
            active_requests: Arc::new(DashMap::new()),
            traffic: Arc::new(TrafficCounters::default()),
            geo_provider: Arc::new(BgpGeoProvider::new()),
            shutdown: CancellationToken::new(),
            relay_established_rx: {
                let (_tx, rx) = tokio::sync::mpsc::channel(
                    crate::transport::saorsa_transport_adapter::ADDRESS_EVENT_CHANNEL_CAPACITY,
                );
                tokio::sync::Mutex::new(rx)
            },
            relay_lost_rx: {
                let (_tx, rx) = tokio::sync::mpsc::channel(
                    crate::transport::saorsa_transport_adapter::ADDRESS_EVENT_CHANNEL_CAPACITY,
                );
                tokio::sync::Mutex::new(rx)
            },
            direct_address_promoted_rx: {
                let (_tx, rx) = tokio::sync::mpsc::channel(
                    crate::transport::saorsa_transport_adapter::ADDRESS_EVENT_CHANNEL_CAPACITY,
                );
                tokio::sync::Mutex::new(rx)
            },
            direct_address_promoted_watch_tx,
            direct_address_promoted_watch_rx: parking_lot::Mutex::new(
                direct_address_promoted_watch_rx,
            ),
            self_address_updated_rx: {
                let (_tx, rx) = tokio::sync::mpsc::channel(
                    crate::transport::saorsa_transport_adapter::ADDRESS_EVENT_CHANNEL_CAPACITY,
                );
                tokio::sync::Mutex::new(rx)
            },
            self_address_updated_watch_tx,
            self_address_updated_watch_rx: parking_lot::Mutex::new(self_address_updated_watch_rx),
            external_addresses: Arc::new(parking_lot::Mutex::new(ExternalAddresses::new())),
            connection_timeout: Duration::from_secs(TEST_CONNECTION_TIMEOUT_SECS),
            connection_monitor_handle: Arc::new(RwLock::new(None)),
            recv_handles: Arc::new(RwLock::new(Vec::new())),
            listener_handle: Arc::new(RwLock::new(None)),
            node_identity: identity,
            user_agent: crate::network::user_agent_for_mode(crate::network::NodeMode::Node),
            peer_to_channel: Arc::new(DashMap::new()),
            channel_to_peers: Arc::new(DashMap::new()),
            peer_user_agents: Arc::new(DashMap::new()),
            dialed_addrs: Arc::new(DashSet::new()),
            known_peer_ips: Arc::new(DashSet::new()),
            proven_externals: Arc::new(DashMap::new()),
            peer_observations: Arc::new(DashMap::new()),
            proof_eligible_peers: Arc::new(DashSet::new()),
        })
    }
}

// ============================================================================
// Identity & Address Accessors
// ============================================================================

impl TransportHandle {
    /// Get the application-level peer ID (cryptographic identity).
    pub fn peer_id(&self) -> PeerId {
        *self.node_identity.peer_id()
    }

    /// Get the cryptographic node identity.
    pub fn node_identity(&self) -> &Arc<NodeIdentity> {
        &self.node_identity
    }

    /// Whether the named external address has been proven cold-dialable.
    ///
    /// Returns `true` iff at least
    /// [`MIN_DISTINCT_OBSERVERS_FOR_DIRECT`] distinct source-disjoint peers
    /// have made unsolicited inbound connections that the classifier
    /// attributed to this external. "Source-disjoint" means the observer
    /// IP was not in `known_peer_ips` at the time of the inbound — i.e.
    /// not a peer this handle had any prior reason to know about.
    ///
    /// Per-address: one external's proof never promotes another. An
    /// inbound on the v4 stack only credits v4 externals, and an inbound
    /// from a peer behind the same NAT (sibling-hairpin) is rejected.
    ///
    /// Consumed by the shared self-address builder to tag each address as
    /// [`AddressType::Direct`](crate::dht::AddressType::Direct) (proven)
    /// or [`AddressType::Unverified`](crate::dht::AddressType::Unverified)
    /// (not yet proven).
    pub fn is_external_proven(&self, addr: SocketAddr) -> bool {
        external_meets_proof_threshold(addr, &self.proven_externals)
    }

    /// Get the first listen address as a string.
    pub fn local_addr(&self) -> Option<MultiAddr> {
        self.listen_addrs
            .try_read()
            .ok()
            .and_then(|addrs| addrs.first().cloned())
    }

    /// Get all current listen addresses.
    pub async fn listen_addrs(&self) -> Vec<MultiAddr> {
        self.listen_addrs.read().await.clone()
    }

    /// Returns the node's preferred external address, or `None` if no
    /// address has been observed yet.
    ///
    /// When a relay is held, this returns the relay address (preferred).
    /// Otherwise it returns the first pinned direct address from bootstrap
    /// OBSERVED_ADDRESS frames.
    pub fn observed_external_address(&self) -> Option<SocketAddr> {
        self.observed_external_addresses().into_iter().next()
    }

    /// Return **all** external addresses for this node: relay first
    /// (preferred), then pinned direct addresses, then observed-but-
    /// unverified external candidates from QUIC `OBSERVED_ADDRESS` frames.
    ///
    /// Callers should still use [`Self::is_external_proven`] to decide
    /// whether a non-relay address is Direct or Unverified. A single
    /// observation is publishable as Unverified so dialers can try it
    /// after the relay, but it is not treated as proven Direct until it
    /// crosses the passive proof threshold.
    pub fn observed_external_addresses(&self) -> Vec<SocketAddr> {
        self.external_addresses.lock().all_addresses()
    }

    /// Return only the pinned **direct** external addresses (no relay, no
    /// unverified candidates).
    pub fn direct_external_addresses(&self) -> Vec<SocketAddr> {
        self.external_addresses.lock().direct_addresses()
    }

    /// Return all non-relay external addresses that should be considered
    /// for typed self-publication.
    ///
    /// Used by callers that tag addresses by type (e.g. the relay driver's
    /// `publish_typed_set`) to avoid double-tagging the relay address as
    /// both Direct and Relay. Returned addresses may be Direct or
    /// Unverified; call [`Self::is_external_proven`] per address to tag
    /// them correctly.
    pub fn non_relay_external_addresses(&self) -> Vec<SocketAddr> {
        self.external_addresses.lock().non_relay_addresses()
    }

    /// Return the relay-allocated external address, if a relay is currently
    /// held.
    pub(crate) fn relay_external_address(&self) -> Option<SocketAddr> {
        self.external_addresses.lock().relay_address()
    }

    /// Store the relay-allocated address so it is included (first) in
    /// [`Self::observed_external_addresses`].
    pub fn set_relay_address(&self, addr: SocketAddr) {
        self.external_addresses.lock().set_relay(addr);
    }

    /// Clear the relay-allocated address.
    pub fn clear_relay_address(&self) {
        self.external_addresses.lock().clear_relay();
    }

    /// Returns the first pinned external address, bypassing the live
    /// `dual_node` read entirely.
    ///
    /// Exists for integration tests that need to poll until the forwarder
    /// has pinned an address from `ExternalAddressDiscovered` events.
    pub fn pinned_external_address(&self) -> Option<SocketAddr> {
        self.external_addresses
            .lock()
            .all_addresses()
            .into_iter()
            .next()
    }

    /// Get the connection timeout duration.
    pub fn connection_timeout(&self) -> Duration {
        self.connection_timeout
    }
}

// ============================================================================
// Peer Management
// ============================================================================

impl TransportHandle {
    /// Get list of authenticated app-level peer IDs.
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.peer_to_channel.iter().map(|e| *e.key()).collect()
    }

    /// Get count of authenticated app-level peers.
    pub async fn peer_count(&self) -> usize {
        self.peer_to_channel.len()
    }

    /// Get the user agent string for a connected peer, if known.
    pub async fn peer_user_agent(&self, peer_id: &PeerId) -> Option<String> {
        self.peer_user_agents
            .get(peer_id)
            .map(|e| e.value().clone())
    }

    /// Get all active transport-level channel IDs (internal bookkeeping).
    #[allow(dead_code)]
    pub(crate) async fn active_channels(&self) -> Vec<String> {
        self.active_connections
            .iter()
            .map(|e| e.key().clone())
            .collect()
    }

    /// Get info for a specific peer.
    ///
    /// Resolves the app-level [`PeerId`] to a channel ID via the
    /// `peer_to_channel` mapping, then looks up the channel's [`PeerInfo`].
    pub async fn peer_info(&self, peer_id: &PeerId) -> Option<PeerInfo> {
        let channel = self
            .peer_to_channel
            .get(peer_id)
            .and_then(|chs| chs.value().iter().next().cloned())?;
        self.peers.get(&channel).map(|e| e.value().clone())
    }

    /// Get info for a transport-level channel by its channel ID (internal only).
    #[allow(dead_code)]
    pub(crate) async fn peer_info_by_channel(&self, channel_id: &str) -> Option<PeerInfo> {
        self.peers.get(channel_id).map(|e| e.value().clone())
    }

    /// Get the channel ID for a given address, if connected (internal only).
    ///
    /// Iteration over the sharded map is not a consistent snapshot — a
    /// concurrently-removed entry may be missed — but for "find any
    /// matching peer" semantics that's the correct behaviour.
    #[allow(dead_code)]
    pub(crate) async fn get_channel_id_by_address(&self, addr: &MultiAddr) -> Option<String> {
        let target = addr.socket_addr()?;
        for entry in self.peers.iter() {
            if entry
                .value()
                .addresses
                .iter()
                .any(|peer_addr| peer_addr.socket_addr() == Some(target))
            {
                return Some(entry.key().clone());
            }
        }
        None
    }

    /// List all active connections with peer IDs and addresses (internal only).
    #[allow(dead_code)]
    pub(crate) async fn list_active_connections(&self) -> Vec<(String, Vec<MultiAddr>)> {
        self.active_connections
            .iter()
            .map(|entry| {
                let key = entry.key().clone();
                let addresses = self
                    .peers
                    .get(&key)
                    .map(|info| info.value().addresses.clone())
                    .unwrap_or_default();
                (key, addresses)
            })
            .collect()
    }

    /// Remove a channel from the tracking maps (internal only).
    pub(crate) async fn remove_channel(&self, channel_id: &str) -> bool {
        self.active_connections.remove(channel_id);
        self.remove_channel_mappings(channel_id).await;
        self.peers.remove(channel_id).is_some()
    }

    /// Close a channel's QUIC connection and remove it from all tracking maps.
    ///
    /// Use this when a transport-level connection was established but the
    /// identity exchange failed, so no [`PeerId`] is available for
    /// [`disconnect_peer`].
    pub(crate) async fn disconnect_channel(&self, channel_id: &str) {
        match channel_id.parse::<SocketAddr>() {
            Ok(addr) => self.dual_node.disconnect_peer_by_addr(&addr).await,
            Err(e) => {
                warn!(
                    channel = %channel_id,
                    error = %e,
                    "Failed to parse channel ID as SocketAddr — QUIC connection will not be closed",
                );
            }
        }
        self.active_connections.remove(channel_id);
        self.remove_channel_mappings(channel_id).await;
        self.peers.remove(channel_id);
    }

    /// Look up the peer ID for a given connection address.
    pub async fn peer_id_for_addr(&self, addr: &SocketAddr) -> Option<PeerId> {
        let normalized = saorsa_transport::shared::normalize_socket_addr(*addr);
        let channel_id = normalized.to_string();
        if let Some(peer_id) = self
            .channel_to_peers
            .get(&channel_id)
            .and_then(|p| p.value().iter().next().copied())
        {
            return Some(peer_id);
        }

        // Defensive lookup against the IPv4-mapped IPv6 alternate form in case
        // any code path inserts via a non-canonical key.
        let alt_addr = saorsa_transport::shared::dual_stack_alternate(&normalized)?;
        let alt_channel_id = alt_addr.to_string();
        self.channel_to_peers
            .get(&alt_channel_id)
            .and_then(|p| p.value().iter().next().copied())
    }

    /// Drain any relay established events. Returns the relay address if this
    /// node has just established a MASQUE relay.
    pub async fn drain_relay_established(&self) -> Option<SocketAddr> {
        let mut rx = self.relay_established_rx.lock().await;
        // Only care about the first one (relay is established once)
        rx.try_recv().ok()
    }

    /// Wait for the next relay-established event.
    ///
    /// Resolves when this node has just set up a MASQUE relay (yielding
    /// the relay socket address), or `None` if the underlying channel has
    /// closed (transport shut down).
    ///
    /// Use this in a `tokio::select!` against a shutdown token to react to
    /// relay establishment immediately instead of polling.
    pub async fn recv_relay_established(&self) -> Option<SocketAddr> {
        let mut rx = self.relay_established_rx.lock().await;
        rx.recv().await
    }

    /// Drain any relay-lost events. Returns the relay address that
    /// became unreachable, if one is queued.
    pub async fn drain_relay_lost(&self) -> Option<SocketAddr> {
        let mut rx = self.relay_lost_rx.lock().await;
        rx.try_recv().ok()
    }

    fn drain_latest_socket_event(
        rx: &parking_lot::Mutex<watch::Receiver<Option<SocketAddr>>>,
    ) -> Option<SocketAddr> {
        let mut rx = rx.lock();
        if rx.has_changed().ok()? {
            *rx.borrow_and_update()
        } else {
            None
        }
    }

    /// Drain the latest direct-address promotion notification, if one has
    /// arrived since the previous drain.
    ///
    /// This is watch-backed and never waits on the reachability driver's
    /// single-consumer mpsc receiver. Multiple raw promotion events may
    /// coalesce to the latest address.
    pub async fn drain_direct_address_promoted(&self) -> Option<SocketAddr> {
        Self::drain_latest_socket_event(&self.direct_address_promoted_watch_rx)
    }

    /// Drain the latest self-address update notification, if one has
    /// arrived since the previous drain.
    ///
    /// This is watch-backed and never waits on the reachability driver's
    /// single-consumer mpsc receiver. Multiple raw update events may
    /// coalesce to the latest address.
    pub async fn drain_self_address_updated(&self) -> Option<SocketAddr> {
        Self::drain_latest_socket_event(&self.self_address_updated_watch_rx)
    }

    /// Subscribe to direct-address promotion notifications.
    ///
    /// The returned watch receiver retains only the latest promoted
    /// address. Its initial value is `None`; after `changed().await`,
    /// read the current value with `borrow_and_update()`.
    pub fn subscribe_direct_address_promoted(&self) -> watch::Receiver<Option<SocketAddr>> {
        self.direct_address_promoted_watch_tx.subscribe()
    }

    /// Subscribe to self-address update notifications.
    ///
    /// The returned watch receiver retains only the latest publishable
    /// address update. Its initial value is `None`; after
    /// `changed().await`, read the current value with
    /// `borrow_and_update()`.
    pub fn subscribe_self_address_updated(&self) -> watch::Receiver<Option<SocketAddr>> {
        self.self_address_updated_watch_tx.subscribe()
    }

    /// Wait for the next relay-lost event.
    ///
    /// Resolves when a previously-advertised MASQUE relay address has
    /// become unreachable (yielding the dead relay address), or `None`
    /// if the underlying channel has closed (transport shut down).
    ///
    /// Use this in a `tokio::select!` against a shutdown token to react
    /// to relay failures immediately instead of polling — without this,
    /// the reachability driver waits for its 5 s health tick before
    /// republishing, leaving a window where peers continue to dial the
    /// dead relay address.
    pub async fn recv_relay_lost(&self) -> Option<SocketAddr> {
        let mut rx = self.relay_lost_rx.lock().await;
        rx.recv().await
    }

    /// Wait for the next direct-address promotion event.
    ///
    /// Resolves when one of this node's pinned external addresses crosses
    /// the passive proof threshold and should be republished as
    /// [`AddressType::Direct`](crate::dht::AddressType::Direct), or `None`
    /// if the underlying channel has closed.
    pub async fn recv_direct_address_promoted(&self) -> Option<SocketAddr> {
        let mut rx = self.direct_address_promoted_rx.lock().await;
        rx.recv().await
    }

    /// Wait for the next self-address update event.
    ///
    /// Resolves when a non-relay external address newly becomes
    /// publishable as Unverified or is pinned as Direct without crossing
    /// the Direct proof threshold, or `None` if the channel has closed.
    pub async fn recv_self_address_updated(&self) -> Option<SocketAddr> {
        let mut rx = self.self_address_updated_rx.lock().await;
        rx.recv().await
    }

    /// Check if an authenticated peer is connected (has at least one active
    /// channel).
    pub async fn is_peer_connected(&self, peer_id: &PeerId) -> bool {
        self.peer_to_channel.contains_key(peer_id)
    }

    /// Check if a connection to a peer is active at the transport layer (internal only).
    pub(crate) async fn is_connection_active(&self, channel_id: &str) -> bool {
        self.active_connections.contains(channel_id)
    }

    /// Remove channel mappings for a disconnected channel.
    ///
    /// Removes the channel from `channel_to_peers` and scrubs it from every
    /// affected peer's channel set in `peer_to_channel`. When a peer's last
    /// channel is removed, emits `PeerDisconnected`.
    async fn remove_channel_mappings(&self, channel_id: &str) {
        Self::remove_channel_mappings_static(
            channel_id,
            &self.peer_to_channel,
            &self.channel_to_peers,
            &self.peer_user_agents,
            &self.event_tx,
        );
    }

    /// Static version of channel mapping removal — usable from background tasks
    /// that don't have `&self`.
    ///
    /// Operations are sync (DashMap shard locks) so the function is sync; the
    /// caller still awaits it at existing call sites via the returned future.
    fn remove_channel_mappings_static(
        channel_id: &str,
        peer_to_channel: &DashMap<PeerId, HashSet<String>>,
        channel_to_peers: &DashMap<String, HashSet<PeerId>>,
        peer_user_agents: &DashMap<PeerId, String>,
        event_tx: &broadcast::Sender<P2PEvent>,
    ) {
        let Some((_, app_peers)) = channel_to_peers.remove(channel_id) else {
            return;
        };
        for app_peer in &app_peers {
            // Remove the channel from this peer's set and check whether the
            // peer has any channels left — atomic per-shard via the entry API
            // so a concurrent accept-loop insertion for the same peer can't
            // race us into an inconsistent state.
            let became_empty = match peer_to_channel.entry(*app_peer) {
                DashEntry::Occupied(mut entry) => {
                    let channels = entry.get_mut();
                    channels.remove(channel_id);
                    if channels.is_empty() {
                        entry.remove();
                        true
                    } else {
                        false
                    }
                }
                DashEntry::Vacant(_) => false,
            };
            if became_empty {
                peer_user_agents.remove(app_peer);
                let _ = event_tx.send(P2PEvent::PeerDisconnected(*app_peer));
            }
        }
    }

    fn upsert_connected_channel_static(
        active_connections: &DashSet<String>,
        peers: &DashMap<String, PeerInfo>,
        channel_id: &str,
        remote_address: SocketAddr,
        source: &'static str,
        refresh_connected_at: bool,
    ) {
        let normalized_addr = saorsa_transport::shared::normalize_socket_addr(remote_address);
        let address = MultiAddr::quic(normalized_addr);
        let now = Instant::now();

        active_connections.insert(channel_id.to_string());

        match peers.entry(channel_id.to_string()) {
            DashEntry::Occupied(mut entry) => {
                let peer_info = entry.get_mut();
                peer_info.status = ConnectionStatus::Connected;
                if refresh_connected_at {
                    peer_info.connected_at = now;
                }
                if !peer_info.addresses.contains(&address) {
                    peer_info.addresses.push(address);
                }
            }
            DashEntry::Vacant(entry) => {
                debug!("{source}: registering connected channel {channel_id}");
                entry.insert(PeerInfo {
                    channel_id: channel_id.to_string(),
                    addresses: vec![address],
                    status: ConnectionStatus::Connected,
                    last_seen: now,
                    connected_at: now,
                    protocols: Vec::new(),
                    heartbeat_count: 0,
                });
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn register_authenticated_peer_channel_static(
        active_connections: &DashSet<String>,
        peers: &DashMap<String, PeerInfo>,
        peer_to_channel: &DashMap<PeerId, HashSet<String>>,
        channel_to_peers: &DashMap<String, HashSet<PeerId>>,
        peer_user_agents: &DashMap<PeerId, String>,
        event_tx: &broadcast::Sender<P2PEvent>,
        channel_id: &str,
        remote_address: SocketAddr,
        app_id: PeerId,
        peer_user_agent: &str,
    ) {
        Self::upsert_connected_channel_static(
            active_connections,
            peers,
            channel_id,
            remote_address,
            "authenticated peer registration",
            false,
        );

        let mut is_new_peer = false;
        let inserted = match peer_to_channel.entry(app_id) {
            DashEntry::Occupied(mut entry) => entry.get_mut().insert(channel_id.to_string()),
            DashEntry::Vacant(entry) => {
                is_new_peer = true;
                let mut set = HashSet::new();
                set.insert(channel_id.to_string());
                entry.insert(set);
                true
            }
        };
        if inserted {
            channel_to_peers
                .entry(channel_id.to_string())
                .or_default()
                .insert(app_id);
        }

        if is_new_peer {
            let peer_user_agent = peer_user_agent.to_string();
            peer_user_agents.insert(app_id, peer_user_agent.clone());
            broadcast_event(event_tx, P2PEvent::PeerConnected(app_id, peer_user_agent));
        }
    }
}

// ============================================================================
// Connection Management
// ============================================================================

impl TransportHandle {
    /// Set the target peer ID for a hole-punch attempt to a specific address.
    /// See [`P2pEndpoint::set_hole_punch_target_peer_id`].
    pub async fn set_hole_punch_target_peer_id(&self, target: SocketAddr, peer_id: [u8; 32]) {
        self.dual_node
            .set_hole_punch_target_peer_id(target, peer_id)
            .await;
    }

    /// Set a preferred coordinator for hole-punching to a specific target.
    /// The preferred coordinator is a peer that referred us to the target
    /// during a DHT lookup, so it has a connection to the target.
    pub async fn set_hole_punch_preferred_coordinator(
        &self,
        target: SocketAddr,
        coordinator: SocketAddr,
    ) {
        self.dual_node
            .set_hole_punch_preferred_coordinator(target, coordinator)
            .await;
    }

    /// Connect to a peer at the given address.
    ///
    /// Only QUIC [`MultiAddr`] values are accepted. Non-QUIC transports
    /// return [`NetworkError::InvalidAddress`].
    ///
    /// Callers that already know how the address was classified (Direct,
    /// Relay, Unverified, Lan) should prefer
    /// [`Self::connect_peer_typed`] so the success/failure logs include
    /// the address kind. This entry point is preserved for callers
    /// (tests, public API consumers) that don't have type metadata.
    pub async fn connect_peer(&self, address: &MultiAddr) -> Result<String> {
        self.connect_peer_inner(address, None).await
    }

    /// Connect to a peer at the given typed address.
    ///
    /// Same as [`Self::connect_peer`] but additionally records the
    /// [`AddressType`] tag in the success/failure logs so an operator
    /// can tell, after the fact, whether a failed dial was against a
    /// `Direct`, `Relay`, `Unverified`, or `Lan` address.
    pub async fn connect_peer_typed(
        &self,
        address: &MultiAddr,
        kind: AddressType,
    ) -> Result<String> {
        self.connect_peer_inner(address, Some(kind)).await
    }

    /// Connect to a prospective relay during third-party canary validation.
    ///
    /// The transport semantics remain [`AddressType::Relay`], but the
    /// dedicated structured log kind keeps a failed pre-publication probe
    /// distinguishable from a failed dial of an already-published relay.
    pub(crate) async fn probe_relay_canary_authenticated(
        &self,
        address: &MultiAddr,
    ) -> Result<PeerId> {
        let socket_addr = address.dialable_socket_addr().ok_or_else(|| {
            P2PError::Network(NetworkError::InvalidAddress(
                format!("relay canary requires a QUIC address, got {address}").into(),
            ))
        })?;
        let target = normalize_wildcard_to_loopback(socket_addr);
        let peer_public_key_spki = self
            .dual_node
            .probe_fresh_authenticated(target)
            .await
            .map_err(|error| P2PError::connection_failed(target, error.to_string()))?;
        peer_id_from_public_key_spki(&peer_public_key_spki)
    }

    async fn connect_peer_inner(
        &self,
        address: &MultiAddr,
        kind: Option<AddressType>,
    ) -> Result<String> {
        self.connect_peer_inner_authenticated(address, kind, None)
            .await
            .map(|(channel_id, _)| channel_id)
    }

    async fn connect_peer_inner_authenticated(
        &self,
        address: &MultiAddr,
        kind: Option<AddressType>,
        log_kind: Option<&'static str>,
    ) -> Result<(String, Option<Vec<u8>>)> {
        let kind_label = log_kind.unwrap_or_else(|| address_kind_label(kind));

        // Require a dialable (QUIC) transport.
        let socket_addr = address.dialable_socket_addr().ok_or_else(|| {
            P2PError::Network(NetworkError::InvalidAddress(
                format!(
                    "only QUIC transport is supported for connect, got {}: {}",
                    address.transport().kind(),
                    address
                )
                .into(),
            ))
        })?;

        let normalized_addr = normalize_wildcard_to_loopback(socket_addr);
        let addr_list = vec![normalized_addr];

        // Record this outbound dial target BEFORE the dial starts so the
        // passive reachability classifier can distinguish simultaneous-open
        // replies from genuinely unsolicited inbounds. The set is
        // monotonic; we do not remove entries on disconnect.
        let dial_target_normalized =
            saorsa_transport::shared::normalize_socket_addr(normalized_addr);
        self.dialed_addrs.insert(dial_target_normalized);
        // Also record the dial target's IP in `known_peer_ips` so that an
        // inbound from this peer through a NAT-remapped source port — same
        // IP, different port, missed by the SocketAddr-keyed `dialed_addrs`
        // — is correctly recognised as not source-disjoint by the
        // reachability classifier.
        self.known_peer_ips.insert(crate::security::canonicalize_ip(
            dial_target_normalized.ip(),
        ));

        let (peer_id, peer_public_key_spki) = match self
            .dual_node
            .connect_happy_eyeballs_authenticated(&addr_list)
            .await
        {
            Ok(dialed_peer) => {
                let addr = dialed_peer.remote_addr;
                let connected_peer_id = canonical_channel_id(addr);

                // Prevent self-connections by comparing against all listen
                // addresses (dual-stack nodes may have both IPv4 and IPv6).
                let is_self = {
                    let addrs = self.listen_addrs.read().await;
                    addrs.iter().any(|a| a.socket_addr() == Some(addr))
                };
                if is_self {
                    warn!(
                        kind = kind_label,
                        %address,
                        channel_id = %connected_peer_id,
                        "Detected self-connection to own address, rejecting"
                    );
                    self.dual_node.disconnect_peer_by_addr(&addr).await;
                    return Err(P2PError::Network(NetworkError::InvalidAddress(
                        format!("Cannot connect to self ({})", address).into(),
                    )));
                }

                info!(
                    kind = kind_label,
                    %address,
                    channel_id = %connected_peer_id,
                    "Successfully connected to channel"
                );
                (connected_peer_id, dialed_peer.peer_public_key_spki)
            }
            Err(e) => {
                warn!(
                    kind = kind_label,
                    %address,
                    error = %e,
                    "connect_happy_eyeballs failed"
                );
                return Err(P2PError::Transport(
                    crate::error::TransportError::ConnectionFailed {
                        addr: normalized_addr,
                        reason: e.to_string().into(),
                    },
                ));
            }
        };

        let peer_info = PeerInfo {
            channel_id: peer_id.clone(),
            addresses: vec![address.clone()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["p2p-foundation/1.0".to_string()],
            heartbeat_count: 0,
        };

        self.peers.insert(peer_id.clone(), peer_info);
        self.active_connections.insert(peer_id.clone());

        // PeerConnected is emitted later when the peer's identity is
        // authenticated via a signed message — not at transport level.
        Ok((peer_id, peer_public_key_spki))
    }

    /// Check if the proactive relay session is still alive.
    ///
    /// Returns `true` if no relay was established or the relay is healthy.
    /// Returns `false` if a relay was established but the QUIC connection
    /// has closed. Used by the relayer monitor (ADR-014 item 6).
    pub async fn is_relay_healthy(&self) -> bool {
        self.dual_node.is_relay_healthy().await
    }

    /// Enable or disable relay serving on this node's MASQUE relay servers.
    ///
    /// Delegates to [`DualStackNetworkNode::set_relay_serving_enabled`].
    /// Called by the ADR-014 reachability classifier after classification
    /// completes: public nodes leave it enabled, private nodes disable it.
    pub fn set_relay_serving_enabled(&self, enabled: bool) {
        self.dual_node.set_relay_serving_enabled(enabled);
    }

    /// Prepare a proactive MASQUE relay session with the peer reachable at
    /// `relay_addr`, returning its provisional public socket address.
    ///
    /// This is the caller-driven entry point for ADR-014 relay acquisition.
    /// It delegates through [`DualStackNetworkNode::prepare_proactive_relay`]
    /// to saorsa-transport's `NatTraversalEndpoint::prepare_proactive_relay`,
    /// which establishes the MASQUE `CONNECT-UDP` session and a relay-backed
    /// Quinn endpoint without advertising the address. The reachability driver
    /// publishes or aborts the allocation after the canary verdict.
    ///
    /// Error conversion: saorsa-transport's `RelayAtCapacity` variant is
    /// mapped to [`RelaySessionEstablishError::AtCapacity`] so the acquisition
    /// coordinator can walk to the next candidate; all other failure modes
    /// (network errors, config errors, protocol errors) become
    /// [`RelaySessionEstablishError::Unreachable`].
    pub async fn setup_proactive_relay_session(
        &self,
        relay_addr: SocketAddr,
    ) -> std::result::Result<PreparedRelay, RelaySessionEstablishError> {
        use saorsa_transport::nat_traversal_api::NatTraversalError;
        use saorsa_transport::p2p_endpoint::EndpointError;

        debug!(
            relay = %relay_addr,
            "requesting proactive MASQUE relay session from transport layer"
        );

        match self.dual_node.prepare_proactive_relay(relay_addr).await {
            Ok(allocated) => {
                info!(
                    relay = %relay_addr,
                    allocated = %allocated.public_addr(),
                    "proactive relay prepared for canary verification"
                );
                Ok(allocated)
            }
            Err(EndpointError::NatTraversal(NatTraversalError::RelayAtCapacity { reason })) => {
                debug!(
                    relay = %relay_addr,
                    reason = %reason,
                    "relay rejected request: at client capacity"
                );
                Err(RelaySessionEstablishError::AtCapacity(reason))
            }
            Err(other) => {
                debug!(
                    relay = %relay_addr,
                    error = %other,
                    "relay session establishment failed"
                );
                Err(RelaySessionEstablishError::Unreachable(other.to_string()))
            }
        }
    }

    /// Commit a canary-verified proactive relay and advertise it to peers.
    pub async fn publish_proactive_relay_session(&self, allocation: PreparedRelay) -> Result<()> {
        let relay_public_addr = allocation.public_addr();
        self.dual_node
            .publish_proactive_relay(allocation)
            .await
            .map_err(|error| {
                P2PError::Transport(TransportError::SetupFailed(
                    format!("Failed to publish proactive relay {relay_public_addr}: {error}")
                        .into(),
                ))
            })
    }

    /// Abort a proactive relay allocation and release its MASQUE resources.
    pub async fn abort_proactive_relay_session(&self, allocation: PreparedRelay) -> Result<()> {
        let relay_public_addr = allocation.public_addr();
        self.dual_node
            .abort_proactive_relay(allocation)
            .await
            .map_err(|error| {
                P2PError::Transport(TransportError::SetupFailed(
                    format!("Failed to abort proactive relay {relay_public_addr}: {error}").into(),
                ))
            })
    }

    /// Disconnect from a peer, closing the underlying QUIC connection only
    /// when no other peers share the channel.
    ///
    /// Accepts an app-level [`PeerId`], removes it from the bidirectional
    /// peer/channel maps, and tears down the QUIC transport for any channels
    /// that become orphaned (no remaining peers).
    pub async fn disconnect_peer(&self, peer_id: &PeerId) -> Result<()> {
        info!("Disconnecting from peer: {}", peer_id);

        // Remove this peer from the bidirectional maps, collecting channels
        // that have no remaining peers and should be closed at QUIC level.
        let orphaned_channels = {
            let Some((_, channel_ids)) = self.peer_to_channel.remove(peer_id) else {
                info!(
                    "Peer {} has no tracked channels, nothing to disconnect",
                    peer_id
                );
                return Ok(());
            };

            let mut orphaned = Vec::new();
            for channel_id in &channel_ids {
                // Atomic per-shard check-and-remove so a concurrent
                // registration for the same channel can't leave an orphaned
                // entry behind.
                let became_empty = match self.channel_to_peers.entry(channel_id.clone()) {
                    DashEntry::Occupied(mut entry) => {
                        let peers = entry.get_mut();
                        peers.remove(peer_id);
                        if peers.is_empty() {
                            entry.remove();
                            true
                        } else {
                            false
                        }
                    }
                    DashEntry::Vacant(_) => false,
                };
                if became_empty {
                    orphaned.push(channel_id.clone());
                }
            }

            orphaned
        };

        self.peer_user_agents.remove(peer_id);
        let _ = self.event_tx.send(P2PEvent::PeerDisconnected(*peer_id));

        // Close QUIC connections for channels with no remaining peers.
        for channel_id in &orphaned_channels {
            match channel_id.parse::<SocketAddr>() {
                Ok(addr) => self.dual_node.disconnect_peer_by_addr(&addr).await,
                Err(e) => {
                    warn!(
                        peer = %peer_id,
                        channel = %channel_id,
                        error = %e,
                        "Failed to parse channel ID as SocketAddr — QUIC connection will not be closed",
                    );
                }
            }
            self.active_connections.remove(channel_id);
            self.peers.remove(channel_id);
        }

        info!("Disconnected from peer: {}", peer_id);
        Ok(())
    }

    /// Disconnect from all peers.
    async fn disconnect_all_peers(&self) -> Result<()> {
        let peer_ids: Vec<PeerId> = self.peer_to_channel.iter().map(|e| *e.key()).collect();
        for peer_id in &peer_ids {
            self.disconnect_peer(peer_id).await?;
        }
        Ok(())
    }
}

// ============================================================================
// Messaging
// ============================================================================

impl TransportHandle {
    /// Send a message to an authenticated peer (raw, no trust reporting).
    ///
    /// Resolves the app-level [`PeerId`] to transport channels via the
    /// `peer_to_channel` mapping. Stale channels are pruned and skipped, but
    /// active send failures are returned without trying another channel so
    /// large/partial writes are not duplicated.
    pub async fn send_message(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        let peer_hex = peer_id.to_hex();
        let channels: Vec<String> = self
            .peer_to_channel
            .get(peer_id)
            .map(|set| set.value().iter().cloned().collect())
            .unwrap_or_default();

        if channels.is_empty() {
            return Err(P2PError::Network(NetworkError::PeerNotFound(
                peer_hex.into(),
            )));
        }

        let mut last_err = None;
        for channel_id in &channels {
            match self
                .send_on_channel(channel_id, protocol, data.clone())
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if e.is_stale_channel_send_failure() {
                        warn!(
                            peer = %peer_hex,
                            channel = %channel_id,
                            error = %e,
                            "Stale channel send failed, removing and trying next",
                        );
                        self.remove_channel(channel_id).await;
                        last_err = Some(e);
                        continue;
                    }

                    warn!(
                        peer = %peer_hex,
                        channel = %channel_id,
                        error = %e,
                        "Channel send failed during active send, removing without retry",
                    );
                    self.remove_channel(channel_id).await;
                    return Err(e);
                }
            }
        }

        // All channels exhausted — return the last error.
        Err(last_err
            .unwrap_or_else(|| P2PError::Network(NetworkError::PeerNotFound(peer_hex.into()))))
    }

    /// Send a message on a specific transport channel (raw, no trust reporting).
    ///
    /// `channel_id` is the transport-level QUIC connection identifier. Internal
    /// callers (publish, keepalive, etc.) that already have a channel ID use
    /// this method directly to avoid an extra PeerId → channel lookup.
    pub(crate) async fn send_on_channel(
        &self,
        channel_id: &str,
        protocol: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        debug!(
            "Sending message to channel {} on protocol {}",
            channel_id, protocol
        );

        // If the peer isn't in `self.peers`, register it on the fly.
        // Hole-punched connections are accepted at the transport layer and
        // registered in P2pEndpoint::connected_peers, but the event chain
        // to populate TransportHandle::peers may not have completed yet.
        //
        // DashMap's `entry().or_insert_with()` is atomic on the relevant
        // shard, so two concurrent senders will not produce duplicate
        // PeerInfo entries.
        self.peers.entry(channel_id.to_string()).or_insert_with(|| {
            debug!(
                "send_on_channel: registering new channel {} on the fly",
                channel_id
            );
            let addresses = channel_id
                .parse::<std::net::SocketAddr>()
                .map(|addr| vec![MultiAddr::quic(addr)])
                .unwrap_or_default();
            PeerInfo {
                channel_id: channel_id.to_string(),
                addresses,
                status: ConnectionStatus::Connected,
                last_seen: Instant::now(),
                connected_at: Instant::now(),
                protocols: Vec::new(),
                heartbeat_count: 0,
            }
        });

        // NOTE: We no longer *reject* sends based on is_connection_active().
        //
        // Hole-punch and NAT-traversed connections have a registration delay
        // (the ConnectionEvent chain takes ~500ms). During this window, the
        // connection IS live at the QUIC level but not yet in
        // active_connections. Using is_connection_active() as a hard gate
        // here would reject valid sends.
        //
        // Instead, we always attempt the actual QUIC send and let
        // P2pEndpoint::send() return PeerNotFound naturally if the
        // connection doesn't exist. The is_connection_active() check below
        // is used only to opportunistically populate active_connections,
        // not to decide whether we send.
        if !self.is_connection_active(channel_id).await {
            self.active_connections.insert(channel_id.to_string());
        }

        let raw_data_len = data.len();
        let message_data = self.create_protocol_message(protocol, data)?;
        debug!(
            "Sending {} bytes to channel {} on protocol {} (raw data: {} bytes)",
            message_data.len(),
            channel_id,
            protocol,
            raw_data_len
        );

        let addr: SocketAddr = channel_id.parse().map_err(|e: std::net::AddrParseError| {
            P2PError::Network(NetworkError::PeerNotFound(
                format!("Invalid channel ID address: {e}").into(),
            ))
        })?;
        let send_result = self
            .dual_node
            .send_to_peer_optimized(&addr, &message_data)
            .await;
        let result = send_result.map_err(|e| {
            let kind = classify_send_error(&e);
            P2PError::Transport(TransportError::SendFailed {
                kind,
                reason: e.to_string().into(),
            })
        });

        if result.is_ok() {
            // V2-623: cumulative wire-traffic accounting. Count only bytes we
            // actually put on the wire. `overhead` is the signature + ML-DSA-65
            // public-key + framing cost (wire − payload).
            let wire_len = message_data.len() as u64;
            let overhead = wire_len.saturating_sub(raw_data_len as u64);
            self.traffic
                .wire_tx_bytes
                .fetch_add(wire_len, Ordering::Relaxed);
            self.traffic.wire_tx_count.fetch_add(1, Ordering::Relaxed);
            self.traffic
                .overhead_tx_bytes
                .fetch_add(overhead, Ordering::Relaxed);
            debug!(
                "Successfully sent {} bytes to channel {}",
                message_data.len(),
                channel_id
            );
        } else {
            warn!("Failed to send message to channel {}", channel_id);
            // Clean up the optimistic active_connections entry so stale
            // entries don't accumulate for unknown channels.
            self.active_connections.remove(channel_id);
        }

        result
    }

    /// Return all channel IDs for an app-level peer, if known.
    pub async fn channels_for_peer(&self, app_peer_id: &PeerId) -> Vec<String> {
        self.peer_to_channel
            .get(app_peer_id)
            .map(|channels| channels.value().iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get all authenticated app-level peer IDs communicating over a channel.
    pub(crate) async fn peers_on_channel(&self, channel_id: &str) -> Vec<PeerId> {
        self.channel_to_peers
            .get(channel_id)
            .map(|set| set.value().iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Return true if `peer_id` is a known authenticated app-level peer ID.
    pub async fn is_known_app_peer_id(&self, peer_id: &PeerId) -> bool {
        self.peer_to_channel.contains_key(peer_id)
    }

    /// Wait for the identity exchange to complete on `channel_id` and return
    /// the authenticated app-level [`PeerId`].
    ///
    /// After [`connect_peer`](Self::connect_peer) returns a channel ID, the
    /// remote's identity is not yet known — it arrives asynchronously via a
    /// signed identity-announce message. This helper polls the
    /// `channel_to_peers` index until the channel has an associated peer,
    /// or the timeout expires.
    ///
    /// **Channel-death short-circuit.** If the underlying QUIC connection is
    /// torn down while we are waiting (the connection-lifecycle monitor
    /// removes the channel from `active_connections` on Lost/Failed events),
    /// the identity exchange can never complete on this channel — we fail
    /// fast instead of blocking for the remaining timeout. Without this,
    /// a dead channel holds bootstrap convergence up for the entire
    /// `IDENTITY_EXCHANGE_TIMEOUT` budget, which cascades into serialised
    /// startup delays on the rest of the network.
    ///
    /// The short-circuit checks `is_connection_active` on every poll tick
    /// *after* the initial check, so it doesn't race the brief window
    /// between `connect_peer` returning and the channel being observed in
    /// `active_connections`: `connect_peer` inserts the channel into that
    /// set before returning, so the first tick always sees it present and
    /// a later transition to absent is the death signal.
    pub async fn wait_for_peer_identity(
        &self,
        channel_id: &str,
        timeout: Duration,
    ) -> Result<PeerId> {
        let deadline = Instant::now() + timeout;
        let poll_interval = Duration::from_millis(50);

        loop {
            // Check if any app-level peer has been authenticated on this channel.
            let peers = self.peers_on_channel(channel_id).await;
            if let Some(peer_id) = peers.into_iter().next() {
                return Ok(peer_id);
            }

            // Channel-death short-circuit. If the channel is no longer
            // active, the connection has been torn down and the identity
            // exchange can never complete — bail immediately with a
            // dedicated error so the caller stops waiting.
            if !self.is_connection_active(channel_id).await {
                return Err(P2PError::Transport(
                    crate::error::TransportError::StreamError(
                        format!("channel {channel_id} closed before identity exchange completed")
                            .into(),
                    ),
                ));
            }

            if Instant::now() >= deadline {
                return Err(P2PError::Timeout(timeout));
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Send a request and wait for a response (no trust reporting).
    ///
    /// This is the raw request-response correlation mechanism. Callers that
    /// need trust feedback should wrap this method (as `P2PNode` does).
    pub async fn send_request(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<PeerResponse> {
        let timeout = timeout.min(MAX_REQUEST_TIMEOUT);

        validate_protocol_name(protocol)?;

        let message_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let started_at = Instant::now();

        // MAX_ACTIVE_REQUESTS is a soft backpressure ceiling: a microscopic
        // race across shards may admit one request over the limit under
        // extreme contention, but the next caller is rejected — good enough
        // for a guard that exists to cap unbounded growth.
        if self.active_requests.len() >= MAX_ACTIVE_REQUESTS {
            return Err(P2PError::Transport(
                crate::error::TransportError::StreamError(
                    format!("Too many active requests ({MAX_ACTIVE_REQUESTS}); try again later")
                        .into(),
                ),
            ));
        }
        self.active_requests.insert(
            message_id.clone(),
            PendingRequest {
                response_tx: tx,
                expected_peer: *peer_id,
            },
        );
        let _active_request_guard =
            ActiveRequestGuard::new(Arc::clone(&self.active_requests), message_id.clone());

        let envelope = RequestResponseEnvelope {
            message_id: message_id.clone(),
            is_response: false,
            payload: data,
        };
        let envelope_bytes = match postcard::to_allocvec(&envelope) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(P2PError::Serialization(
                    format!("Failed to serialize request envelope: {e}").into(),
                ));
            }
        };

        let wire_protocol = format!("/rr/{}", protocol);
        self.send_message(peer_id, &wire_protocol, envelope_bytes)
            .await?;

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response_bytes)) => {
                let latency = started_at.elapsed();
                Ok(PeerResponse {
                    peer_id: *peer_id,
                    data: response_bytes,
                    latency,
                })
            }
            Ok(Err(_)) => Err(P2PError::Network(NetworkError::ConnectionClosed {
                peer_id: peer_id.to_hex().into(),
            })),
            Err(_) => Err(P2PError::Timeout(timeout)),
        }
    }

    /// Send a response to a previously received request.
    pub async fn send_response(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        message_id: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        validate_protocol_name(protocol)?;

        let envelope = RequestResponseEnvelope {
            message_id: message_id.to_string(),
            is_response: true,
            payload: data,
        };
        let envelope_bytes = postcard::to_allocvec(&envelope).map_err(|e| {
            P2PError::Serialization(format!("Failed to serialize response envelope: {e}").into())
        })?;

        let wire_protocol = format!("/rr/{}", protocol);
        self.send_message(peer_id, &wire_protocol, envelope_bytes)
            .await
    }

    /// Parse a request/response envelope from incoming message bytes.
    pub fn parse_request_envelope(data: &[u8]) -> Option<(String, bool, Vec<u8>)> {
        let envelope: RequestResponseEnvelope = postcard::from_bytes(data).ok()?;
        Some((envelope.message_id, envelope.is_response, envelope.payload))
    }

    /// Create a protocol message wrapper (WireMessage serialized with postcard).
    ///
    /// Signs the message with the node's ML-DSA-65 key.
    fn create_protocol_message(&self, protocol: &str, data: Vec<u8>) -> Result<Vec<u8>> {
        let mut message = WireMessage {
            protocol: protocol.to_string(),
            data,
            from: *self.node_identity.peer_id(),
            timestamp: Self::current_timestamp_secs()?,
            user_agent: self.user_agent.clone(),
            public_key: Vec::new(),
            signature: Vec::new(),
        };

        Self::sign_wire_message(&mut message, &self.node_identity)?;

        Self::serialize_wire_message(&message)
    }

    /// Build a signed identity announce as serialized bytes (static — no `&self`).
    ///
    /// Used by the lifecycle monitor to send an announce immediately after a
    /// transport connection is established, before the full `TransportHandle`
    /// is available in that context.
    fn create_identity_announce_bytes(
        identity: &NodeIdentity,
        user_agent: &str,
    ) -> Result<Vec<u8>> {
        let mut message = WireMessage {
            protocol: IDENTITY_ANNOUNCE_PROTOCOL.to_string(),
            data: vec![],
            from: *identity.peer_id(),
            timestamp: Self::current_timestamp_secs()?,
            user_agent: user_agent.to_owned(),
            public_key: Vec::new(),
            signature: Vec::new(),
        };

        Self::sign_wire_message(&mut message, identity)?;
        Self::serialize_wire_message(&message)
    }

    /// Get the current Unix timestamp in seconds.
    fn current_timestamp_secs() -> Result<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| {
                P2PError::Network(NetworkError::ProtocolError(
                    format!("System time error: {e}").into(),
                ))
            })
    }

    /// Sign a `WireMessage` in place using the given identity.
    fn sign_wire_message(message: &mut WireMessage, identity: &NodeIdentity) -> Result<()> {
        let signable = Self::compute_signable_bytes(
            &message.protocol,
            &message.data,
            &message.from,
            message.timestamp,
            &message.user_agent,
        )?;
        let sig = identity.sign(&signable).map_err(|e| {
            P2PError::Network(NetworkError::ProtocolError(
                format!("Failed to sign message: {e}").into(),
            ))
        })?;
        message.public_key = identity.public_key().as_bytes().to_vec();
        message.signature = sig.as_bytes().to_vec();
        Ok(())
    }

    /// Serialize a `WireMessage` to postcard bytes.
    fn serialize_wire_message(message: &WireMessage) -> Result<Vec<u8>> {
        postcard::to_stdvec(message).map_err(|e| {
            P2PError::Transport(crate::error::TransportError::StreamError(
                format!("Failed to serialize wire message: {e}").into(),
            ))
        })
    }

    /// Compute the canonical bytes to sign/verify for a WireMessage.
    fn compute_signable_bytes(
        protocol: &str,
        data: &[u8],
        from: &PeerId,
        timestamp: u64,
        user_agent: &str,
    ) -> Result<Vec<u8>> {
        postcard::to_stdvec(&(protocol, data, from, timestamp, user_agent)).map_err(|e| {
            P2PError::Network(NetworkError::ProtocolError(
                format!("Failed to serialize signable bytes: {e}").into(),
            ))
        })
    }
}

// ============================================================================
// Pub/Sub
// ============================================================================

impl TransportHandle {
    /// Subscribe to a topic (currently a no-op stub).
    pub async fn subscribe(&self, topic: &str) -> Result<()> {
        info!("Subscribed to topic: {}", topic);
        Ok(())
    }

    /// Publish a message to all connected peers on the given topic.
    ///
    /// De-duplicates by app-level peer: when a peer has multiple channels,
    /// tries each channel until one succeeds (fallback on failure).
    /// Unauthenticated channels (not yet mapped to an app-level peer) are
    /// also included once each.
    pub async fn publish(&self, topic: &str, data: &[u8]) -> Result<()> {
        info!(
            "Publishing message to topic: {} ({} bytes)",
            topic,
            data.len()
        );

        // Collect all channels grouped by authenticated app-level peer,
        // plus any unauthenticated channels. DashMap iteration is not a
        // consistent snapshot, but a peer added/removed mid-iteration is
        // not a correctness issue — the next publish picks it up.
        let mut peer_channel_groups: Vec<Vec<String>> = Vec::new();
        let mut mapped_channels: HashSet<String> = HashSet::new();
        for entry in self.peer_to_channel.iter() {
            let chs: Vec<String> = entry.value().iter().cloned().collect();
            mapped_channels.extend(chs.iter().cloned());
            if !chs.is_empty() {
                peer_channel_groups.push(chs);
            }
        }

        // Include unauthenticated channels (single-channel groups, no fallback).
        // DashMap iteration is not a consistent snapshot, but a missed
        // freshly-inserted/removed channel here is not a correctness issue —
        // the next publish picks it up.
        for entry in self.peers.iter() {
            if !mapped_channels.contains(entry.key()) {
                peer_channel_groups.push(vec![entry.key().clone()]);
            }
        }

        if peer_channel_groups.is_empty() {
            debug!("No peers connected, message will only be sent to local subscribers");
        } else {
            let mut send_count = 0;
            let total = peer_channel_groups.len();
            for channels in &peer_channel_groups {
                let mut sent = false;
                for channel_id in channels {
                    match self.send_on_channel(channel_id, topic, data.to_vec()).await {
                        Ok(()) => {
                            send_count += 1;
                            debug!("Published message via channel: {}", channel_id);
                            sent = true;
                            break;
                        }
                        Err(e) => {
                            warn!(
                                channel = %channel_id,
                                error = %e,
                                "Publish channel failed, removing and trying next",
                            );
                            self.remove_channel(channel_id).await;
                        }
                    }
                }
                if !sent {
                    warn!("All channels exhausted for one peer during publish");
                }
            }
            info!(
                "Published message to {}/{} connected peers",
                send_count, total
            );
        }

        // Self-emit to local subscribers. The on-wire timestamp lives on each
        // serialized WireMessage built by `send_on_channel`; this local copy
        // just stamps "when the publisher sent it" so handlers see the same
        // shape they would for a received signed message.
        let timestamp = Self::current_timestamp_secs().unwrap_or(0);
        self.send_event(P2PEvent::Message {
            topic: topic.to_string(),
            source: Some(*self.node_identity.peer_id()),
            transport_source: None,
            timestamp,
            data: data.to_vec(),
        });

        Ok(())
    }
}

// ============================================================================
// Events
// ============================================================================

impl TransportHandle {
    /// Subscribe to network events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<P2PEvent> {
        self.event_tx.subscribe()
    }

    /// Snapshot the cumulative wire-traffic counters (V2-623).
    ///
    /// Cheap (13 relaxed atomic loads, no locks); safe to call on any
    /// cadence. See [`TrafficSnapshot`] for field semantics. Reachable from
    /// embedding applications via
    /// [`P2PNode::transport`](crate::network::P2PNode::transport) or
    /// [`DhtNetworkManager::transport`](crate::dht_network_manager::DhtNetworkManager::transport).
    pub fn traffic_snapshot(&self) -> TrafficSnapshot {
        self.traffic.snapshot()
    }

    /// Send an event to all subscribers.
    pub(crate) fn send_event(&self, event: P2PEvent) {
        if let Err(e) = self.event_tx.send(event) {
            tracing::trace!("Event broadcast has no receivers: {e}");
        }
    }
}

// ============================================================================
// Network Listeners & Receive System
// ============================================================================

impl TransportHandle {
    /// Start network listeners on the dual-stack transport.
    pub async fn start_network_listeners(&self) -> Result<()> {
        info!("Starting dual-stack listeners (saorsa-transport)...");
        let socket_addrs = self.dual_node.local_addrs().await.map_err(|e| {
            P2PError::Transport(crate::error::TransportError::SetupFailed(
                format!("Failed to get local addresses: {}", e).into(),
            ))
        })?;
        let addrs: Vec<SocketAddr> = socket_addrs.clone();
        {
            let mut la = self.listen_addrs.write().await;
            *la = socket_addrs.into_iter().map(MultiAddr::quic).collect();
        }

        let peers = self.peers.clone();
        let active_connections = self.active_connections.clone();
        let rate_limiter = self.rate_limiter.clone();
        let dual = self.dual_node.clone();

        let handle = tokio::spawn(async move {
            loop {
                let Some(remote_sock) = dual.accept_any().await else {
                    break;
                };

                if let Err(e) = rate_limiter.check_ip(&remote_sock.ip()) {
                    warn!(
                        "Rate-limited incoming connection from {}: {}",
                        remote_sock, e
                    );
                    continue;
                }

                let channel_id = canonical_channel_id(remote_sock);
                let remote_addr = MultiAddr::quic(remote_sock);
                // PeerConnected is emitted later when the peer's identity is
                // authenticated via a signed message — not at transport level.
                //
                // Both register_new_channel and active_connections.insert are
                // sync DashMap operations — the loop never awaits any lock,
                // so it cannot stall and back-pressure the upstream
                // handshake channel under high accept rates.
                register_new_channel(&peers, &channel_id, &remote_addr);
                active_connections.insert(channel_id);
            }
        });
        *self.listener_handle.write().await = Some(handle);

        self.start_message_receiving_system().await?;

        info!("Dual-stack listeners active on: {:?}", addrs);
        Ok(())
    }

    /// Spawns per-stack recv tasks and a **sharded** dispatcher that routes
    /// incoming messages across [`MESSAGE_DISPATCH_SHARDS`] parallel consumer
    /// tasks.
    ///
    /// # Why sharded?
    ///
    /// The previous implementation used a single consumer task to drain
    /// every inbound message in the entire node. At 60 peers this kept up
    /// comfortably, but at 1000 peers it became the dominant serialisation
    /// point: each message pass through this loop took three async write
    /// locks (`peer_to_channel`, `channel_to_peers`, `peer_user_agents`)
    /// and an awaited `register_connection_peer_id` call before the next
    /// message could even be looked at. Responses arrived late, past the
    /// 25 s caller timeout, producing the `[STEP 6 FAILED]` and
    /// `[STEP 5a FAILED] Response channel closed (receiver timed out)`
    /// cascades observed in the 1000-node testnet logs.
    ///
    /// Sharding by hash of the source IP gives each shard its own consumer
    /// running in parallel, so lock contention is now distributed across N
    /// simultaneous writers instead of serialised behind a single task.
    /// Messages from the **same peer** always route to the **same shard**
    /// (ordering is preserved per peer). The dispatcher task is light
    /// (hash + channel send) so it is never the bottleneck.
    async fn start_message_receiving_system(&self) -> Result<()> {
        info!(
            "Starting message receiving system ({} dispatch shards)",
            MESSAGE_DISPATCH_SHARDS
        );

        let (upstream_tx, mut upstream_rx) =
            tokio::sync::mpsc::channel(MESSAGE_RECV_CHANNEL_CAPACITY);

        let mut handles = self
            .dual_node
            .spawn_recv_tasks(upstream_tx.clone(), self.shutdown.clone());
        drop(upstream_tx);

        // Per-shard capacity so the aggregate buffered depth matches the old
        // single-channel capacity, keeping memory usage comparable. Floor
        // at `MIN_SHARD_CHANNEL_CAPACITY` so each shard retains enough
        // slack for small bursts even if the global capacity is tiny.
        let per_shard_capacity = (MESSAGE_RECV_CHANNEL_CAPACITY / MESSAGE_DISPATCH_SHARDS)
            .max(MIN_SHARD_CHANNEL_CAPACITY);

        let mut shard_txs: Vec<tokio::sync::mpsc::Sender<(SocketAddr, Vec<u8>)>> =
            Vec::with_capacity(MESSAGE_DISPATCH_SHARDS);

        for shard_idx in 0..MESSAGE_DISPATCH_SHARDS {
            let (shard_tx, shard_rx) = tokio::sync::mpsc::channel(per_shard_capacity);
            shard_txs.push(shard_tx);

            let event_tx = self.event_tx.clone();
            let active_requests = Arc::clone(&self.active_requests);
            let active_connections = Arc::clone(&self.active_connections);
            let peers = Arc::clone(&self.peers);
            let peer_to_channel = Arc::clone(&self.peer_to_channel);
            let channel_to_peers = Arc::clone(&self.channel_to_peers);
            let peer_user_agents = Arc::clone(&self.peer_user_agents);
            let self_peer_id = *self.node_identity.peer_id();
            let dual_node_for_peer_reg = Arc::clone(&self.dual_node);
            let traffic = Arc::clone(&self.traffic);

            handles.push(tokio::spawn(async move {
                Self::run_shard_consumer(
                    shard_idx,
                    shard_rx,
                    event_tx,
                    active_requests,
                    active_connections,
                    peers,
                    peer_to_channel,
                    channel_to_peers,
                    peer_user_agents,
                    self_peer_id,
                    dual_node_for_peer_reg,
                    traffic,
                )
                .await;
            }));
        }

        // Dispatcher: single task whose only job is to hash `from_addr` and
        // hand the message off to the appropriate shard. The actual heavy
        // lifting happens in parallel in the shard consumers.
        //
        // Failure isolation: a single shard's `try_send` failure must NOT
        // collapse the dispatcher. If a shard channel is full we log and
        // drop the message (incrementing a counter). If a shard task has
        // panicked and its receiver is closed we log and drop, but keep
        // routing to the other healthy shards. The dispatcher only exits
        // when its upstream channel closes (i.e. transport shutdown).
        let drop_counter = Arc::new(AtomicU64::new(0));
        handles.push(tokio::spawn(async move {
            info!(
                "Message dispatcher loop started (sharded across {} consumers)",
                MESSAGE_DISPATCH_SHARDS
            );
            while let Some((from_addr, bytes)) = upstream_rx.recv().await {
                let shard_idx = shard_index_for_addr(&from_addr);
                match shard_txs[shard_idx].try_send((from_addr, bytes)) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_dropped)) => {
                        // Backpressure: this shard is overloaded. Drop the
                        // message rather than blocking the dispatcher and
                        // starving the other shards. Per-shard ordering for
                        // this peer is broken for the dropped message but
                        // preserved for everything that does land.
                        let prev = drop_counter.fetch_add(1, Ordering::Relaxed);
                        if prev.is_multiple_of(SHARD_DROP_LOG_INTERVAL) {
                            warn!(
                                shard = shard_idx,
                                from = %from_addr,
                                total_drops = prev + 1,
                                "Dispatcher dropped inbound message: shard channel full"
                            );
                        }
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_dropped)) => {
                        // Shard consumer task has exited (likely panic).
                        // Drop this message but keep routing to the other
                        // shards — fault isolation, not cascade failure.
                        let prev = drop_counter.fetch_add(1, Ordering::Relaxed);
                        if prev.is_multiple_of(SHARD_DROP_LOG_INTERVAL) {
                            warn!(
                                shard = shard_idx,
                                from = %from_addr,
                                total_drops = prev + 1,
                                "Dispatcher dropped inbound message: shard consumer closed"
                            );
                        }
                    }
                }
            }
            info!("Message dispatcher loop ended — upstream channel closed");
        }));

        *self.recv_handles.write().await = handles;
        Ok(())
    }

    /// Consumer loop for a single dispatch shard.
    ///
    /// Each shard runs one of these in its own `tokio::spawn` task. Shard
    /// assignment is by hash of the source IP, so messages from the same
    /// peer always go through the same shard (ordering is preserved per
    /// peer). Shared state (`peer_to_channel`, `active_requests`, etc.) is
    /// held in sharded `DashMap`s, so writes from different shard consumers
    /// never contend unless they hit the same map shard — contention is now
    /// bounded by the DashMap shard count rather than a single global writer.
    #[allow(clippy::too_many_arguments)]
    async fn run_shard_consumer(
        shard_idx: usize,
        mut shard_rx: tokio::sync::mpsc::Receiver<(SocketAddr, Vec<u8>)>,
        event_tx: broadcast::Sender<P2PEvent>,
        active_requests: Arc<DashMap<String, PendingRequest>>,
        active_connections: Arc<DashSet<String>>,
        peers: Arc<DashMap<String, PeerInfo>>,
        peer_to_channel: Arc<DashMap<PeerId, HashSet<String>>>,
        channel_to_peers: Arc<DashMap<String, HashSet<PeerId>>>,
        peer_user_agents: Arc<DashMap<PeerId, String>>,
        self_peer_id: PeerId,
        dual_node_for_peer_reg: Arc<DualStackNetworkNode>,
        traffic: Arc<TrafficCounters>,
    ) {
        info!("Message dispatch shard {shard_idx} started");
        while let Some((from_addr, bytes)) = shard_rx.recv().await {
            let channel_id = canonical_channel_id(from_addr);
            trace!(
                shard = shard_idx,
                "Received {} bytes from channel {}",
                bytes.len(),
                channel_id
            );

            match parse_protocol_message(&bytes, &channel_id) {
                Some(ParsedMessage {
                    event,
                    authenticated_node_id,
                    user_agent: peer_user_agent,
                    payload_len,
                }) => {
                    // V2-623: cumulative wire-traffic accounting (rx). Only
                    // successfully-decoded wire messages are counted. `overhead`
                    // is the signature + ML-DSA-65 public-key + framing cost.
                    let wire_len = bytes.len() as u64;
                    let overhead = wire_len.saturating_sub(payload_len as u64);
                    traffic.wire_rx_bytes.fetch_add(wire_len, Ordering::Relaxed);
                    traffic.wire_rx_count.fetch_add(1, Ordering::Relaxed);
                    traffic
                        .overhead_rx_bytes
                        .fetch_add(overhead, Ordering::Relaxed);
                    // If the message was signed, record the app↔channel mapping.
                    // A peer may be reachable over multiple channels simultaneously
                    // (e.g. QUIC + Bluetooth), so we add to the set — never replace.
                    // Skip our own identity to avoid self-registration via echoed messages.
                    if let Some(ref app_id) = authenticated_node_id
                        && *app_id != self_peer_id
                    {
                        let already_mapped = peer_to_channel
                            .get(app_id)
                            .is_some_and(|channels| channels.value().contains(&channel_id));

                        // Register peer ID at the low-level transport
                        // endpoint BEFORE inserting into peer_to_channel so
                        // any concurrent reader who observes the app-level
                        // entry already has the transport's addr→peer map
                        // populated. Previously this was achieved by
                        // holding a `peer_to_channel` write lock across the
                        // await; under sharded `DashMap` we can't hold a
                        // shard guard across an await, so we rely on
                        // happens-before via operation ordering instead.
                        if !already_mapped {
                            dual_node_for_peer_reg
                                .register_connection_peer_id(from_addr, *app_id.to_bytes())
                                .await;
                        }

                        // This helper owns the app-level PeerConnected invariant:
                        // `peer_info(app_id)` must be queryable before the event
                        // is broadcast to DHT or other subscribers.
                        Self::register_authenticated_peer_channel_static(
                            &active_connections,
                            &peers,
                            &peer_to_channel,
                            &channel_to_peers,
                            &peer_user_agents,
                            &event_tx,
                            &channel_id,
                            from_addr,
                            *app_id,
                            &peer_user_agent,
                        );
                    }

                    // Identity announces are internal plumbing — don't
                    // emit as app-level messages.
                    if let P2PEvent::Message { ref topic, .. } = event
                        && topic == IDENTITY_ANNOUNCE_PROTOCOL
                    {
                        continue;
                    }

                    if let P2PEvent::Message {
                        ref topic,
                        ref data,
                        ..
                    } = event
                        && topic.starts_with("/rr/")
                        && let Ok(envelope) = postcard::from_bytes::<RequestResponseEnvelope>(data)
                        && envelope.is_response
                    {
                        // Peek at the expected peer without removing so a
                        // spoofed response can't evict a legitimate pending
                        // request — the entry stays until either a matching
                        // response arrives or the caller times out.
                        let expected_peer = match active_requests.get(&envelope.message_id) {
                            Some(pending) => pending.expected_peer,
                            None => {
                                trace!(
                                    message_id = %envelope.message_id,
                                    "Unmatched /rr/ response (likely timed out) — suppressing"
                                );
                                continue;
                            }
                        };
                        // Accept response only if the authenticated app-level
                        // identity matches. Channel IDs identify connections,
                        // not peers, so they are not checked here.
                        if authenticated_node_id.as_ref() != Some(&expected_peer) {
                            warn!(
                                message_id = %envelope.message_id,
                                expected = %expected_peer,
                                actual_channel = %channel_id,
                                authenticated = ?authenticated_node_id,
                                "Response origin mismatch — ignoring"
                            );
                            continue;
                        }
                        if let Some((_, pending)) = active_requests.remove(&envelope.message_id)
                            && pending.response_tx.send(envelope.payload).is_err()
                        {
                            warn!(
                                message_id = %envelope.message_id,
                                "Response receiver dropped before delivery"
                            );
                        }
                        continue;
                    }
                    broadcast_event(&event_tx, event);
                }
                None => {
                    warn!(
                        shard = shard_idx,
                        "Failed to parse protocol message ({} bytes)",
                        bytes.len()
                    );
                }
            }
        }
        info!("Message dispatch shard {shard_idx} ended — channel closed");
    }
}

/// Number of parallel dispatch shards for inbound messages.
///
/// Messages are routed to a shard by hash of the source IP so each peer's
/// messages are processed by the same consumer (preserving per-peer
/// ordering) while different peers' messages run in parallel. Picked to
/// match typical core counts on deployment hardware — tuning higher helps
/// only if `DashMap` shard contention in `peer_to_channel` / `active_requests`
/// is observed to be the dominant bottleneck.
const MESSAGE_DISPATCH_SHARDS: usize = 8;

/// Minimum mpsc capacity for an individual dispatch shard channel.
///
/// The per-shard capacity is normally `MESSAGE_RECV_CHANNEL_CAPACITY /
/// MESSAGE_DISPATCH_SHARDS`, but when that division rounds to something
/// too small for healthy bursts we floor it at this value so each shard
/// retains a reasonable amount of buffering headroom.
const MIN_SHARD_CHANNEL_CAPACITY: usize = 16;

/// Log a warning every Nth dropped message in the dispatcher.
///
/// `try_send` failures (channel full, or shard task closed) increment a
/// global drop counter; logging at every drop would flood the log under
/// sustained backpressure, so we coalesce to one warning per
/// `SHARD_DROP_LOG_INTERVAL` drops. The first drop in a burst is always
/// logged so the operator sees the onset.
const SHARD_DROP_LOG_INTERVAL: u64 = 64;

/// Pick the dispatch shard for an inbound message.
///
/// Hashes by `IpAddr` (not full `SocketAddr`) so a peer re-connecting from
/// a new ephemeral port still lands in the same shard.
///
/// **Ordering caveat:** ordering is preserved per *source IP*, not per
/// authenticated peer. If a peer's public IP changes (NAT rebinding to a
/// new external address, mobile Wi-Fi↔cellular roaming, dual-stack
/// failover) it now hashes to a different shard, and messages from the
/// old IP that are still queued in the old shard may be processed
/// concurrently with new messages from the new IP. Application-layer
/// causality across an IP change is *not* guaranteed by this dispatcher.
fn shard_index_for_addr(addr: &SocketAddr) -> usize {
    let mut hasher = DefaultHasher::new();
    addr.ip().hash(&mut hasher);
    (hasher.finish() as usize) % MESSAGE_DISPATCH_SHARDS
}

fn canonical_channel_id(addr: SocketAddr) -> String {
    saorsa_transport::shared::normalize_socket_addr(addr).to_string()
}

// ============================================================================
// Shutdown
// ============================================================================

impl TransportHandle {
    /// Stop the transport layer: shutdown endpoints, join tasks, disconnect peers.
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping transport...");

        self.shutdown.cancel();
        self.dual_node.shutdown_endpoints().await;

        // Await recv system tasks
        let handles: Vec<_> = self.recv_handles.write().await.drain(..).collect();
        Self::join_task_handles(handles, "recv").await;
        Self::join_task_slot(&self.listener_handle, "listener").await;
        Self::join_task_slot(&self.connection_monitor_handle, "connection monitor").await;

        self.disconnect_all_peers().await?;

        info!("Transport stopped");
        Ok(())
    }

    async fn join_task_slot(handle_slot: &RwLock<Option<JoinHandle<()>>>, task_name: &str) {
        let handle = handle_slot.write().await.take();
        if let Some(handle) = handle {
            Self::join_task_handle(handle, task_name).await;
        }
    }

    async fn join_task_handles(handles: Vec<JoinHandle<()>>, task_name: &str) {
        for handle in handles {
            Self::join_task_handle(handle, task_name).await;
        }
    }

    async fn join_task_handle(handle: JoinHandle<()>, task_name: &str) {
        match handle.await {
            Ok(()) => {}
            Err(e) if e.is_cancelled() => {
                tracing::debug!("{task_name} task was cancelled during shutdown");
            }
            Err(e) if e.is_panic() => {
                tracing::error!("{task_name} task panicked during shutdown: {:?}", e);
            }
            Err(e) => {
                tracing::warn!("{task_name} task join error during shutdown: {:?}", e);
            }
        }
    }
}

// ============================================================================
// Background Tasks (static)
// ============================================================================

impl TransportHandle {
    /// Connection lifecycle monitor — processes saorsa-transport connection events.
    #[allow(clippy::too_many_arguments)]
    async fn connection_lifecycle_monitor_with_rx(
        dual_node: Arc<DualStackNetworkNode>,
        mut event_rx: broadcast::Receiver<
            crate::transport::saorsa_transport_adapter::ConnectionEvent,
        >,
        active_connections: Arc<DashSet<String>>,
        peers: Arc<DashMap<String, PeerInfo>>,
        event_tx: broadcast::Sender<P2PEvent>,
        _geo_provider: Arc<BgpGeoProvider>,
        shutdown: CancellationToken,
        peer_to_channel: Arc<DashMap<PeerId, HashSet<String>>>,
        channel_to_peers: Arc<DashMap<String, HashSet<PeerId>>>,
        peer_user_agents: Arc<DashMap<PeerId, String>>,
        node_identity: Arc<NodeIdentity>,
        user_agent: String,
        traffic: Arc<TrafficCounters>,
    ) {
        info!("Connection lifecycle monitor started (pre-subscribed receiver)");

        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    info!("Connection lifecycle monitor shutting down");
                    break;
                }
                recv = event_rx.recv() => {
                    match recv {
                        Ok(event) => match event {
                            ConnectionEvent::Established {
                                remote_address, ..
                            } => {
                                let channel_id = canonical_channel_id(remote_address);
                                debug!(
                                    "Connection established: channel={}, addr={}",
                                    channel_id, remote_address
                                );

                                Self::upsert_connected_channel_static(
                                    &active_connections,
                                    &peers,
                                    &channel_id,
                                    remote_address,
                                    "connection lifecycle",
                                    true,
                                );

                                // Send identity announce so the remote peer can authenticate us.
                                //
                                // Build the bytes inline (cheap, infallible
                                // for valid identities) but spawn the actual
                                // QUIC send so a stalled peer's 1s ACK
                                // timeout doesn't block the lifecycle
                                // monitor and back up identity announces for
                                // every other peer that just (re)connected.
                                match Self::create_identity_announce_bytes(&node_identity, &user_agent) {
                                    Ok(announce_bytes) => {
                                        let dual_node = Arc::clone(&dual_node);
                                        let channel_id_for_send = channel_id.clone();
                                        // V2-623: identity announce bypasses
                                        // `send_on_channel`, so account for it
                                        // here. Counted on successful send.
                                        let traffic = Arc::clone(&traffic);
                                        let announce_len = announce_bytes.len() as u64;
                                        tokio::spawn(async move {
                                            if let Err(e) = dual_node
                                                .send_to_peer_optimized(&remote_address, &announce_bytes)
                                                .await
                                            {
                                                if e
                                                    .downcast_ref::<saorsa_transport::p2p_endpoint::EndpointError>()
                                                    .is_some_and(|error| matches!(
                                                        error,
                                                        saorsa_transport::p2p_endpoint::EndpointError::PeerNotFound(_)
                                                    ))
                                                {
                                                    // A one-shot reachability probe closes as
                                                    // soon as TLS exposes the target identity.
                                                    // Its inbound Established event can race this
                                                    // ordinary identity hook; by the time the send
                                                    // runs there is intentionally no peer left.
                                                    debug!(
                                                        "Skipping identity announce for closed channel {channel_id_for_send}"
                                                    );
                                                    return;
                                                }
                                                // {e:#} prints the full anyhow cause chain so we
                                                // can see the underlying reason (e.g. "peer did
                                                // not acknowledge stream data within 1s",
                                                // "open_uni failed", "PeerNotFound").
                                                warn!(
                                                    "Failed to send identity announce to {channel_id_for_send}: {e:#}"
                                                );
                                            } else {
                                                traffic
                                                    .identity_announce_tx_bytes
                                                    .fetch_add(announce_len, Ordering::Relaxed);
                                                traffic
                                                    .identity_announce_tx_count
                                                    .fetch_add(1, Ordering::Relaxed);
                                                // Also fold into the wire totals — this send
                                                // bypasses `send_on_channel` and would otherwise
                                                // be invisible to the reconciliation line.
                                                traffic
                                                    .wire_tx_bytes
                                                    .fetch_add(announce_len, Ordering::Relaxed);
                                                traffic
                                                    .wire_tx_count
                                                    .fetch_add(1, Ordering::Relaxed);
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        warn!("Failed to create identity announce: {e}");
                                    }
                                }

                                // PeerConnected is emitted when the remote receives and
                                // verifies our identity announce — not at transport level.
                            }
                            ConnectionEvent::Lost { remote_address, reason }
                            | ConnectionEvent::Failed { remote_address, reason } => {
                                let channel_id = canonical_channel_id(remote_address);
                                debug!("Connection lost/failed: channel={channel_id}, reason={reason}");

                                active_connections.remove(&channel_id);
                                peers.remove(&channel_id);
                                // Remove channel mappings and emit PeerDisconnected
                                // when the peer's last channel is closed.
                                Self::remove_channel_mappings_static(
                                    &channel_id,
                                    &peer_to_channel,
                                    &channel_to_peers,
                                    &peer_user_agents,
                                    &event_tx,
                                );
                            }
                            ConnectionEvent::PeerAddressUpdated { .. } => {
                                // Handled by dedicated forwarder, not here
                            }
                        },
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(
                                "Connection event receiver lagged, skipped {} events",
                                skipped
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("Connection event channel closed, stopping lifecycle monitor");
                            break;
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Free helper functions
// ============================================================================

/// Validate that a protocol name is non-empty and contains no path separators or null bytes.
fn validate_protocol_name(protocol: &str) -> Result<()> {
    if protocol.is_empty() || protocol.contains(&['/', '\\', '\0'][..]) {
        return Err(P2PError::Transport(
            crate::error::TransportError::StreamError(
                format!("Invalid protocol name: {:?}", protocol).into(),
            ),
        ));
    }
    Ok(())
}

// ============================================================================
// NetworkSender impl
// ============================================================================

#[async_trait::async_trait]
impl NetworkSender for TransportHandle {
    async fn send_message(&self, peer_id: &PeerId, protocol: &str, data: Vec<u8>) -> Result<()> {
        TransportHandle::send_message(self, peer_id, protocol, data).await
    }

    fn local_peer_id(&self) -> PeerId {
        self.peer_id()
    }
}

// Test-only helpers for injecting state
#[cfg(test)]
impl TransportHandle {
    /// Insert a peer into the peers map (test helper)
    pub(crate) async fn inject_peer(&self, peer_id: String, info: PeerInfo) {
        self.peers.insert(peer_id, info);
    }

    /// Insert a channel ID into the active_connections set (test helper)
    pub(crate) async fn inject_active_connection(&self, channel_id: String) {
        self.active_connections.insert(channel_id);
    }

    /// Map an app-level PeerId to a channel ID in both `peer_to_channel` and
    /// `channel_to_peers` (test helper). The bidirectional mapping ensures
    /// `remove_channel` correctly cleans up both maps.
    pub(crate) async fn inject_peer_to_channel(&self, peer_id: PeerId, channel_id: String) {
        self.peer_to_channel
            .entry(peer_id)
            .or_default()
            .insert(channel_id.clone());
        self.channel_to_peers
            .entry(channel_id)
            .or_default()
            .insert(peer_id);
    }
}

/// Wire `TransportHandle` into the reachability subsystem's
/// [`RelaySessionEstablisher`] abstraction so the ADR-014 relay acquisition
/// coordinator can drive it directly. The trait impl is a thin delegate to
/// [`TransportHandle::setup_proactive_relay_session`].
///
/// Both `TransportHandle` and `Arc<TransportHandle>` implement the trait so
/// callers can pass either an owned handle or a shared reference without
/// wrapping.
#[async_trait::async_trait]
impl RelaySessionEstablisher for TransportHandle {
    async fn establish(
        &self,
        relay_addr: SocketAddr,
    ) -> std::result::Result<PreparedRelay, RelaySessionEstablishError> {
        self.setup_proactive_relay_session(relay_addr).await
    }
}

#[async_trait::async_trait]
impl RelaySessionEstablisher for Arc<TransportHandle> {
    async fn establish(
        &self,
        relay_addr: SocketAddr,
    ) -> std::result::Result<PreparedRelay, RelaySessionEstablishError> {
        self.setup_proactive_relay_session(relay_addr).await
    }
}

#[cfg(test)]
mod address_event_observer_tests {
    use super::*;

    #[test]
    fn watch_drain_returns_latest_event_once() {
        let (tx, rx) = watch::channel(None);
        let rx = parking_lot::Mutex::new(rx);
        let first: SocketAddr = "198.51.100.1:10000".parse().expect("test addr");
        let second: SocketAddr = "198.51.100.2:10000".parse().expect("test addr");

        assert_eq!(TransportHandle::drain_latest_socket_event(&rx), None);

        let _ = tx.send_replace(Some(first));
        let _ = tx.send_replace(Some(second));

        assert_eq!(
            TransportHandle::drain_latest_socket_event(&rx),
            Some(second)
        );
        assert_eq!(TransportHandle::drain_latest_socket_event(&rx), None);
    }
}

#[cfg(test)]
mod traffic_snapshot_tests {
    use super::*;

    #[test]
    fn default_counters_snapshot_to_zero() {
        assert_eq!(
            TrafficCounters::default().snapshot(),
            TrafficSnapshot::default()
        );
    }

    #[test]
    fn snapshot_reflects_counter_values() {
        let counters = TrafficCounters::default();
        counters.wire_tx_bytes.fetch_add(1024, Ordering::Relaxed);
        counters.wire_tx_count.fetch_add(3, Ordering::Relaxed);
        counters.wire_rx_bytes.fetch_add(2048, Ordering::Relaxed);
        counters.wire_rx_count.fetch_add(5, Ordering::Relaxed);
        counters.overhead_tx_bytes.fetch_add(7, Ordering::Relaxed);
        counters.ping_tx_count.fetch_add(2, Ordering::Relaxed);

        let snap = counters.snapshot();
        assert_eq!(snap.wire_tx_bytes, 1024);
        assert_eq!(snap.wire_tx_count, 3);
        assert_eq!(snap.wire_rx_bytes, 2048);
        assert_eq!(snap.wire_rx_count, 5);
        assert_eq!(snap.overhead_tx_bytes, 7);
        assert_eq!(snap.ping_tx_count, 2);
        assert_eq!(snap.find_node_tx_count, 0);
        assert_eq!(snap.identity_announce_tx_bytes, 0);
    }
}

#[cfg(test)]
mod authenticated_peer_registration_tests {
    use super::*;

    #[test]
    fn authenticated_registration_makes_peer_info_queryable_before_event_consumers_run() {
        let active_connections = DashSet::new();
        let peers = DashMap::new();
        let peer_to_channel = DashMap::new();
        let channel_to_peers = DashMap::new();
        let peer_user_agents = DashMap::new();
        let (event_tx, mut event_rx) = broadcast::channel(4);

        let app_id = PeerId::from_bytes([0x31; 32]);
        let remote_addr: SocketAddr = "64.227.163.41:43782".parse().expect("test addr");
        let channel_id = canonical_channel_id(remote_addr);

        TransportHandle::register_authenticated_peer_channel_static(
            &active_connections,
            &peers,
            &peer_to_channel,
            &channel_to_peers,
            &peer_user_agents,
            &event_tx,
            &channel_id,
            remote_addr,
            app_id,
            "node/test",
        );

        assert!(active_connections.contains(&channel_id));

        let mapped_channel = peer_to_channel
            .get(&app_id)
            .and_then(|channels| channels.value().iter().next().cloned())
            .expect("app peer should be mapped to a channel");
        let peer_info = peers
            .get(&mapped_channel)
            .map(|entry| entry.value().clone())
            .expect("mapped channel should have peer info before event consumers run");

        assert_eq!(peer_info.channel_id, channel_id);
        assert_eq!(peer_info.status, ConnectionStatus::Connected);
        assert_eq!(peer_info.addresses, vec![MultiAddr::quic(remote_addr)]);

        match event_rx.try_recv().expect("peer connected event") {
            P2PEvent::PeerConnected(peer_id, user_agent) => {
                assert_eq!(peer_id, app_id);
                assert_eq!(user_agent, "node/test");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }
}

#[cfg(test)]
mod proven_externals_tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test IP")
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().expect("test socket addr")
    }

    fn seed_observer(
        proven: &DashMap<SocketAddr, HashSet<IpAddr>>,
        external: SocketAddr,
        observer: IpAddr,
    ) {
        let normalized = saorsa_transport::shared::normalize_socket_addr(external);
        proven.entry(normalized).or_default().insert(observer);
    }

    #[test]
    fn external_with_no_observers_is_not_proven() {
        let proven = DashMap::new();
        assert!(!external_meets_proof_threshold(
            sa("198.51.100.1:10000"),
            &proven
        ));
    }

    #[test]
    fn external_with_one_observer_is_not_proven() {
        let proven = DashMap::new();
        let ext = sa("198.51.100.1:10000");
        seed_observer(&proven, ext, ip("203.0.113.1"));
        assert!(!external_meets_proof_threshold(ext, &proven));
    }

    #[test]
    fn external_with_two_distinct_observers_is_proven() {
        let proven = DashMap::new();
        let ext = sa("198.51.100.1:10000");
        seed_observer(&proven, ext, ip("203.0.113.1"));
        seed_observer(&proven, ext, ip("203.0.113.2"));
        assert!(external_meets_proof_threshold(ext, &proven));
    }

    #[test]
    fn duplicate_observer_does_not_count_twice() {
        let proven = DashMap::new();
        let ext = sa("198.51.100.1:10000");
        seed_observer(&proven, ext, ip("203.0.113.1"));
        seed_observer(&proven, ext, ip("203.0.113.1"));
        assert!(
            !external_meets_proof_threshold(ext, &proven),
            "the same observer reporting twice must not satisfy the distinct-observer quorum"
        );
    }

    #[test]
    fn one_externals_proof_does_not_promote_another() {
        let proven = DashMap::new();
        let ext_a = sa("198.51.100.1:10000");
        let ext_b = sa("198.51.100.2:10000");
        seed_observer(&proven, ext_a, ip("203.0.113.1"));
        seed_observer(&proven, ext_a, ip("203.0.113.2"));
        assert!(external_meets_proof_threshold(ext_a, &proven));
        assert!(
            !external_meets_proof_threshold(ext_b, &proven),
            "B has no observers; A's proof must not leak across externals"
        );
    }

    #[test]
    fn v4_external_proof_does_not_promote_v6_external() {
        let proven = DashMap::new();
        let v4 = sa("198.51.100.1:10000");
        let v6 = sa("[2001:db8::1]:10000");
        seed_observer(&proven, v4, ip("203.0.113.1"));
        seed_observer(&proven, v4, ip("203.0.113.2"));
        assert!(external_meets_proof_threshold(v4, &proven));
        assert!(
            !external_meets_proof_threshold(v6, &proven),
            "different family: v4 proof must not leak to a v6 external"
        );
    }

    #[test]
    fn lookup_normalises_v4_mapped_v6() {
        // External pinned in plain v4 form; caller queries via
        // IPv4-mapped IPv6 (`::ffff:198.51.100.1`). Both must hit the
        // same entry after normalisation; otherwise the publisher's
        // per-address tag computation can disagree with what the
        // classifier wrote, and an address would be tagged Unverified
        // despite having reached its observer quorum.
        let proven = DashMap::new();
        let v4 = sa("198.51.100.1:10000");
        seed_observer(&proven, v4, ip("203.0.113.1"));
        seed_observer(&proven, v4, ip("203.0.113.2"));

        let mapped: SocketAddr = "[::ffff:198.51.100.1]:10000"
            .parse()
            .expect("test mapped addr");
        assert!(
            external_meets_proof_threshold(mapped, &proven),
            "lookup via IPv4-mapped IPv6 must normalize to the v4 entry"
        );
    }
}
