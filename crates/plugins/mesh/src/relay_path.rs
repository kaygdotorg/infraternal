//! Relayed pairs through the userspace shim, and relay address observation, for seam C [163,185,313].
//!
//! Only pairs that cannot go direct come here. For each relayed peer the shim
//! binds one loopback UDP socket; once a relay link is active, it points the
//! selected data plane's endpoint at it. The engine sends peer ciphertext to
//! that socket; the shim prefixes the relay link id and sends it as one QUIC
//! DATAGRAM. Ciphertext arriving from the relay is sent from the same socket to
//! the engine's UDP port, so the engine authenticates it. The shim never sees
//! plaintext and never holds a mesh key.
//!
//! Session start on a new link (see `settle`): both ends keep an established
//! session and only move its endpoint to the shim. Without one, both ends drop
//! any direct-path attempt still in flight and wait without an endpoint; the
//! lower host id then initiates through the shim, and the other end learns the
//! shim's address from that authenticated initiation. Moving the endpoint
//! before a link exists would send initiations into a shim that drops them.
//!
//! Relay choice (#201, D185, D313 Q5): every node gets the same relay list and keeps
//! one connection to each. A relayed pair asks every live relay for a link and keeps
//! every link it gets, so a second relay is always ready for a make-before-break
//! move. The first link that comes up carries the pair at once; nothing waits for a
//! measurement. While a pair has two or more links, it measures each one end to end
//! with a 12-byte probe DATAGRAM on the link itself (see [`probe_frame`]): the peer's
//! shim answers it on the same link, so the round trip covers both legs and the
//! relay's own queueing, exactly what the pair's packets see. Both ends measure the
//! same quantity, so they settle on the same relay without a new relay message; for
//! the moment they disagree, either relay delivers, because a node accepts its peer's
//! packets on every link. The pair moves only on the shared rule in
//! [`infraternal_mesh::path_choice`]: a sustained win of at least max(5 ms, 15 %),
//! at most once per 10 s. The one exception is the first measured choice: when every
//! link has its first sample, a link that beats the unmeasured default (the lowest
//! index) by the margin takes over at once. A lost relay is left at once for the best
//! remaining link.
//!
//! Probing never runs on a timer. A probe round goes out only from the send path,
//! after a packet of the pair's own traffic, at most once per [`PROBE_INTERVAL`], and
//! only when there is a choice (two links or more). An idle pair, or one with a
//! single relay, sends nothing extra and is never woken by this module (D81).
//!
//! The direct path is a candidate too (#220, [`crate::direct_probe`]). A pair that knows its
//! peer's direct endpoint probes it from the `WireGuard` port alongside its relay links and
//! feeds the answers into the same rule, so a direct path that works but is slower than a relay
//! loses, and a relayed pair whose direct path opens or turns out faster moves back. The rule's
//! direct preference applies: direct wins inside the margin, a relay needs the full margin. A
//! pair on the direct path keeps its relay links as standby only when some relay's own round
//! trip (which the QUIC connection measures for free) leaves room to beat the direct path;
//! otherwise it requests none. Probe rounds of such a pair start from inbound traffic on the
//! `WireGuard` port (the receive guard carries the clock), at one round per
//! [`PROBE_INTERVAL`] while a decision is open and one per [`STEADY_INTERVAL`] once every window
//! is sustained and steady, so an idle pair is never woken (D81). A peer that has never
//! answered a direct probe (an older node) is not judged: silence is not a slow path.
//!
//! A relay sees the probe's token and could answer for the peer to look faster than
//! it is. It cannot look faster than its own leg, which this node's QUIC connection
//! to it measures independently; relays already hold the deployment's server-purpose
//! certificate. Authenticating probes per pair is a later hardening step.

use crate::{
    dataplane,
    direct_probe::{self, Answer, DirectProbes},
    seam::{Received, Seam},
    wireguard,
};
use bytes::{BufMut, BytesMut};
use infraternal_mesh::path_choice::{Path, Samples, Selector, band, first_choice};
use infraternal_plugin_relay::{
    client::{Client, Notices},
    probe::{self, ProbeKey},
    quinn,
    tls::Credentials,
    wire::{self, HostId, LinkId, Notice},
};
use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::{
        Arc, Mutex, OnceLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::mpsc,
    task::JoinHandle,
};

/// A loopback datagram socket whose only reactor interest is readability. Relay injection
/// sends directly and drops on congestion, so a writable event would only wake the runtime.
struct ShimSocket(AsyncFd<UdpSocket>);

impl ShimSocket {
    /// Bind an ephemeral port and accept datagrams only from the engine port.
    fn bind(engine_port: u16) -> io::Result<Self> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        socket.set_nonblocking(true)?;
        socket.connect((Ipv4Addr::LOCALHOST, engine_port))?;
        Ok(Self(AsyncFd::with_interest(socket, Interest::READABLE)?))
    }

    /// Return the loopback address advertised as this peer's endpoint.
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.get_ref().local_addr()
    }

    /// Wait for input before the caller allocates room for a relay frame.
    async fn readable(&self) -> io::Result<()> {
        self.0.readable().await.map(|_| ())
    }

    /// Append one datagram after the relay header without initializing or copying its payload.
    #[allow(unsafe_code)]
    fn try_recv(&self, buffer: &mut BytesMut) -> io::Result<()> {
        let size = self.0.try_io(Interest::READABLE, |socket| {
            socket2::SockRef::from(socket).recv(buffer.spare_capacity_mut())
        })?;
        // SAFETY: recv initialized exactly this many bytes in the spare capacity.
        unsafe { buffer.advance_mut(size) };
        Ok(())
    }

    /// Attempt injection at once. The caller counts congestion as a dropped datagram.
    fn try_send(&self, payload: &[u8]) -> io::Result<usize> {
        self.0.get_ref().send(payload)
    }
}

/// Largest `WireGuard` packet the shim reads: a mesh-MTU data packet is 1412.
const PACKET: usize = 1_500;
/// Reconnect backoff for a lost relay, doubling up to the maximum.
const BACKOFF: Duration = Duration::from_millis(250);
const BACKOFF_MAX: Duration = Duration::from_secs(5);
const BACKOFF_RECENT_MAX: Duration = Duration::from_millis(250);
const RECENT_HEALTH: Duration = Duration::from_secs(60);
const CONNECT: Duration = Duration::from_secs(5);
/// Avoid letting a failed handshake wait through QUIC's longer idle timeout during quick recovery.
const CONNECT_RECENT: Duration = Duration::from_millis(750);
/// Recheck Quinn's live application-payload limit for path-MTU changes.
const RELAY_MTU_POLL: Duration = Duration::from_secs(1);
/// How long a new link may still change before the session start (`settle`).
const SETTLE: Duration = Duration::from_millis(25);
/// Least time between two probe rounds of one pair. Rounds ride on the pair's traffic, so
/// this caps probe cost at one small DATAGRAM per link per second while the pair is busy.
const PROBE_INTERVAL: Duration = Duration::from_secs(1);
/// Least time between two probe rounds of a pair whose every window is sustained and steady
/// (see [`PeerState::round_interval`]): five seconds keep a five-sample window 20 s wide, inside
/// the path rule's freshness limit of 30 s, so the pair still judges on fresh samples.
const STEADY_INTERVAL: Duration = Duration::from_secs(5);
/// A link probe unanswered for this long counts as a sample of this round trip, so a link
/// that silently stopped forwarding loses the comparison instead of keeping its old samples.
const PROBE_LOST: Duration = Duration::from_secs(2);
/// First payload byte of a link probe. `WireGuard` message types are 1–4 (little-endian, so
/// the first byte), so a probe can never be mistaken for ciphertext.
const PING: u8 = 0xF0;
/// First payload byte of the answer to a link probe; like [`PING`], never a `WireGuard` type.
const PONG: u8 = 0xF1;
/// A link probe after the link id: kind, three zero bytes, a big-endian 64-bit token.
const PROBE_LEN: usize = 12;
/// Probe retransmissions after the first send (#220 design §2: 250/750 ms).
const PROBE_WAITS: [Duration; 3] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_millis(1_000),
];

/// Whether a pair cannot go direct after its endpoint-install grace period.
/// The kernel and caller timestamps share wall-clock time, so compare both
/// seconds and nanoseconds: an equal or older handshake cannot prove freshness,
/// while a later handshake (including one in the same second) proves the
/// direct path. One `WireGuard` handshake attempt is 5 s.
/// Hole punching (slice 3) and the #201 selector (slice 4) replace this with
/// proven candidates and measured paths; until then an unproven pair is
/// relayed.
#[must_use]
pub fn direct_failed(
    counters: Option<&wireguard::Counters>,
    endpoint_installed_at: SystemTime,
) -> bool {
    counters
        .and_then(|counters| {
            (counters.handshake_secs != 0).then(|| {
                UNIX_EPOCH.checked_add(Duration::new(
                    counters.handshake_secs,
                    counters.handshake_nanos,
                ))
            })
        })
        .flatten()
        .is_none_or(|handshake| handshake <= endpoint_installed_at)
}

/// One relay in the shared, ordered list.
#[derive(Clone, Debug)]
pub struct RelaySpec {
    pub address: SocketAddr,
    /// The DNS name in the relay's server-purpose certificate.
    pub name: String,
}

/// Path changes, reported in the order they happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    RelayUp {
        relay: usize,
    },
    RelayDown {
        relay: usize,
    },
    /// The relay a peer's packets now use; `None` while no relay links it.
    Active {
        peer: HostId,
        relay: Option<usize>,
    },
}

/// Watches one connection's application-payload limit and reports changed inner route budgets.
#[derive(Default)]
struct RelayMtuTracker {
    last_limit: Option<Option<usize>>,
}

impl RelayMtuTracker {
    /// Return a new safe mesh MTU only when Quinn's current limit changes.
    fn update(&mut self, max_datagram_size: Option<usize>) -> Option<u16> {
        if self.last_limit == Some(max_datagram_size) {
            return None;
        }
        self.last_limit = Some(max_datagram_size);
        Some(crate::mesh_mtu::for_relay_datagram(max_datagram_size))
    }

    /// Retry a failed route update on the next observation, even if Quinn's limit is unchanged.
    fn retry(&mut self) {
        self.last_limit = None;
    }
}

/// A callback that installs a relay-specific MTU or re-derives the direct endpoint MTU.
pub type RouteMtuUpdater = Arc<dyn Fn(Option<u16>) -> io::Result<()> + Send + Sync>;

/// Data-path counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub sent: u64,
    pub received: u64,
    /// Kernel packets for a peer with no active link.
    pub unlinked: u64,
    /// Packets larger than the relay connection's current DATAGRAM size.
    pub too_large: u64,
    /// Link probes this node sent to measure its relayed pairs' paths.
    pub probes_sent: u64,
    /// Peers' link probes this node answered.
    pub probes_answered: u64,
    /// Answers to this node's own probes that matched an outstanding probe.
    pub probe_answers: u64,
    /// Pairs moved to a measurably faster relay (failovers are not counted).
    pub switches: u64,
    /// Incoming relay datagrams inspected by the namespace fixture.
    #[cfg(feature = "test-support")]
    pub inbound_datagrams: u64,
    /// Incoming relay datagrams with an invalid framing header.
    #[cfg(feature = "test-support")]
    pub malformed_datagrams: u64,
    /// Incoming relay datagrams with no current link-id mapping.
    #[cfg(feature = "test-support")]
    pub unknown_links: u64,
    /// Incoming relay datagrams with no current peer shim.
    #[cfg(feature = "test-support")]
    pub unknown_peers: u64,
    /// Incoming relay datagrams refused by the connected loopback socket.
    #[cfg(feature = "test-support")]
    pub injection_errors: u64,
    /// Relay receive tasks that ended on a QUIC read error.
    #[cfg(feature = "test-support")]
    pub receive_errors: u64,
}

/// The live counters behind [`Stats`], updated lock-free from the data path.
#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    received: AtomicU64,
    unlinked: AtomicU64,
    too_large: AtomicU64,
    probes_sent: AtomicU64,
    probes_answered: AtomicU64,
    probe_answers: AtomicU64,
    switches: AtomicU64,
    #[cfg(feature = "test-support")]
    inbound_datagrams: AtomicU64,
    #[cfg(feature = "test-support")]
    malformed_datagrams: AtomicU64,
    #[cfg(feature = "test-support")]
    unknown_links: AtomicU64,
    #[cfg(feature = "test-support")]
    unknown_peers: AtomicU64,
    #[cfg(feature = "test-support")]
    injection_errors: AtomicU64,
    #[cfg(feature = "test-support")]
    receive_errors: AtomicU64,
}

/// Holds a connected relay session and the peer links that use it.
struct Live {
    /// Relay slot that owns this connection.
    index: usize,
    client: Client,
    links: RwLock<HashMap<LinkId, HostId>>,
}

/// Tracks one peer's relay control state and active path callbacks.
struct Peer {
    host: HostId,
    /// Moves the peer to the shim once a relay link is active (see `settle`).
    prepare_handshake: Arc<dyn Fn() -> io::Result<()> + Send + Sync>,
    /// Starts a handshake through the engine that owns this peer.
    handshake_starter: Arc<dyn Fn() + Send + Sync>,
    /// Updates this peer's route from the live relay MTU, or re-derives its direct-path budget.
    route_mtu_updater: RouteMtuUpdater,
    /// Moves the engine's endpoint for this peer back to its direct endpoint, keeping the
    /// session; `None` when the pair has no direct endpoint.
    use_direct: Option<Arc<dyn Fn() -> io::Result<()> + Send + Sync>>,
    socket: ShimSocket,
    /// A delayed session start is pending (see `settle`).
    starting: std::sync::atomic::AtomicBool,
    state: Mutex<PeerState>,
    /// Serializes MTU route writes and invalidates results from an older selected path.
    route_mtu_generation: Mutex<u64>,
    active: RwLock<Option<(Arc<Live>, LinkId)>>,
    /// Limits concurrent route refreshes after an oversized relay packet.
    refreshing_route_mtu: std::sync::atomic::AtomicBool,
    /// Milliseconds since [`Shared::epoch`] before which no probe round starts. Read on every
    /// sent packet without taking `state`, so the send path stays lock-free between rounds.
    next_round_ms: AtomicU64,
    /// Serializes publication of `state.active` to `active` and the route (see [`publish`]).
    publishing: tokio::sync::Mutex<()>,
}

/// One relayed pair's links, requests, measurements and choice, behind `Peer::state`.
///
/// Lock order: this state before `Peer::route_mtu_generation`, everywhere.
#[derive(Default)]
struct PeerState {
    /// Per relay index: the link there, and whether a request is outstanding.
    links: Vec<Option<LinkId>>,
    requested: Vec<bool>,
    /// The relay index and link id the data path uses.
    active: Option<(usize, LinkId)>,
    /// Per relay index: this pair's end-to-end round trips through the link there. Cleared
    /// whenever that link changes, so samples always describe the current link.
    rtt: Vec<Samples>,
    /// Per relay index: the outstanding probe's token and send time.
    probing: Vec<Option<(u64, Duration)>>,
    /// The measured rule's view of `active` and its dwell clock.
    selector: Selector,
    /// Whether the first measured choice was made since the pair last had nothing measured
    /// (see [`PeerState::first_measured`]).
    decided: bool,
    /// The pair's direct path, when its peer's direct endpoint is known.
    direct: Option<DirectPath>,
    /// Whether a pair on the direct path asked its relays for standby links (see
    /// [`consider_relays`]). Until then it requests none.
    want_relay: bool,
}

/// The direct path of one pair: the endpoint probed from the `WireGuard` port and what the
/// probes showed.
struct DirectPath {
    /// The peer's direct endpoint, as the engine would send to it.
    endpoint: SocketAddr,
    /// Round trips of probes sent to `endpoint`, lost ones included once the peer has answered.
    samples: Samples,
    /// Whether the peer ever answered a probe. A peer that never did (an older node, or a
    /// path that never opened) is not judged slow: it has no samples at all.
    answered: bool,
    /// Whether the direct path carries the pair now (the relay links, if any, are standby).
    on: bool,
}

impl PeerState {
    /// Fresh state for a pair over `relays` relays: no link, no request, no samples.
    fn new(relays: usize) -> Self {
        Self {
            links: vec![None; relays],
            requested: vec![false; relays],
            active: None,
            rtt: vec![Samples::default(); relays],
            probing: vec![None; relays],
            selector: Selector::default(),
            decided: false,
            direct: None,
            want_relay: false,
        }
    }

    /// The same state for a pair with a known direct endpoint. `on` says whether the direct
    /// path carries the pair now (a pair that has not been relayed) or a relay does.
    fn with_direct(mut self, endpoint: SocketAddr, on: bool) -> Self {
        self.direct = Some(DirectPath {
            endpoint,
            samples: Samples::default(),
            answered: false,
            on,
        });
        if on {
            self.selector.start(Some(Path::Direct));
        }
        self
    }

    /// Whether the direct path carries the pair.
    fn on_direct(&self) -> bool {
        self.direct.as_ref().is_some_and(|direct| direct.on)
    }

    /// Record one direct probe result at `now`. A loss counts only once the peer has answered
    /// before, so a peer without a responder is never judged slow (see [`DirectPath::answered`]).
    fn record_direct(&mut self, now: Duration, rtt: Duration, lost: bool) {
        let Some(direct) = self.direct.as_mut() else {
            return;
        };
        if lost && !direct.answered {
            return;
        }
        direct.answered |= !lost;
        direct.samples.record(now, rtt);
    }

    /// How long until the pair's next probe round: one [`PROBE_INTERVAL`] while a decision is
    /// open, [`STEADY_INTERVAL`] once every candidate's window is sustained and the newest
    /// direct sample sits inside the margin of its median. Pairs with no direct path keep the
    /// fixed interval they always had.
    fn round_interval(&self, now: Duration) -> Duration {
        // A peer that has never answered costs one ping per steady interval, not per second: it
        // may be an older node, or a path that has not opened. The first answer speeds it up.
        let Some(direct) = self.direct.as_ref().filter(|direct| direct.answered) else {
            return STEADY_INTERVAL;
        };
        let linked = self
            .links
            .iter()
            .zip(&self.rtt)
            .filter(|(link, _)| link.is_some())
            .map(|(_, samples)| samples);
        let settled = std::iter::once(&direct.samples)
            .chain(linked)
            .all(|samples| samples.sustained(now));
        let steady = direct.samples.median().is_some_and(|median| {
            direct
                .samples
                .newest()
                .is_some_and(|newest| newest.abs_diff(median) <= band(median))
        });
        if settled && steady {
            STEADY_INTERVAL
        } else {
            PROBE_INTERVAL
        }
    }

    /// Whether any link of the pair has a round-trip sample.
    fn measured(&self) -> bool {
        self.rtt.iter().any(|samples| !samples.is_empty())
    }

    /// Once every link has its first sample, make the first measured choice: leave the
    /// unmeasured default (the lowest index) at once for a link that beats it by the margin
    /// ([`first_choice`]). Returns `true` when `active` moved; the caller publishes.
    ///
    /// Without this a pair whose default relay is far waits for a full sustained window, and
    /// J1105's first perf run showed why that hurts: the near relay linked first, the default
    /// moved the pair to the far one, and keys paid 300 ms for 10 s. With equal links the
    /// default stays, so both ends of a pair keep agreeing on it.
    fn first_measured(&mut self, now: Duration) -> bool {
        if self.decided {
            return false;
        }
        let linked: Vec<(usize, LinkId, Duration)> = self
            .links
            .iter()
            .enumerate()
            .filter_map(|(index, link)| link.map(|id| (index, id)))
            .map(|(index, id)| (index, id, self.rtt[index].median()))
            .map_while(|(index, id, rtt)| rtt.map(|rtt| (index, id, rtt)))
            .collect();
        if linked.len() != self.links.iter().flatten().count() {
            return false;
        }
        self.decided = true;
        let Some((current, _)) = self.active else {
            return false;
        };
        let Some(&(_, _, current_rtt)) = linked.iter().find(|&&(index, _, _)| index == current)
        else {
            return false;
        };
        let Some(&(best, id, best_rtt)) =
            linked.iter().min_by_key(|&&(index, _, rtt)| (rtt, index))
        else {
            return false;
        };
        if best == current || !first_choice(Path::Relay(best), best_rtt, current_rtt) {
            return false;
        }
        self.active = Some((best, id));
        self.selector.install(Some(Path::Relay(best)), now);
        true
    }

    /// Record that relay `index`'s link changed: its samples and probe described the old one.
    fn link_changed(&mut self, index: usize) {
        self.rtt[index].clear();
        self.probing[index] = None;
    }

    /// The link a pair without a usable active link should take: the lowest measured median,
    /// unmeasured links after measured ones, then the lowest index (the old fixed order).
    fn best_link(&self) -> Option<(usize, LinkId)> {
        self.links
            .iter()
            .enumerate()
            .filter_map(|(index, link)| link.map(|id| (index, id)))
            .min_by_key(|&(index, _)| (self.rtt[index].median().unwrap_or(Duration::MAX), index))
    }

    /// Ask the measured rule whether a faster link should carry the pair, and move `active`
    /// there if so. The caller holds the state lock and publishes when this returns `true`.
    fn choose(&mut self, now: Duration) -> bool {
        let Self {
            links,
            rtt,
            selector,
            active,
            direct,
            ..
        } = self;
        let mut candidates: Vec<(Path, &Samples)> = links
            .iter()
            .zip(rtt.iter())
            .enumerate()
            .filter(|(_, (link, _))| link.is_some())
            .map(|(index, (_, samples))| (Path::Relay(index), samples))
            .collect();
        if let Some(direct) = direct.as_ref().filter(|direct| direct.answered) {
            candidates.push((Path::Direct, &direct.samples));
        }
        match selector.choose(now, candidates) {
            Some(Path::Relay(index)) => {
                let Some(id) = links[index] else {
                    return false;
                };
                *active = Some((index, id));
                if let Some(direct) = direct.as_mut() {
                    direct.on = false;
                }
                true
            }
            Some(Path::Direct) => {
                *active = None;
                if let Some(direct) = direct.as_mut() {
                    direct.on = true;
                }
                true
            }
            None => false,
        }
    }
}

/// What every task of one node's relay paths shares: identity, relay connections, peers,
/// counters and the clock the path rule reads.
struct Shared {
    /// This node's host id; it decides which end of a pair starts a session.
    local: HostId,
    wg_port: u16,
    endpoint: quinn::Endpoint,
    config: quinn::ClientConfig,
    relays: Vec<RelaySpec>,
    live: Vec<RwLock<Option<Arc<Live>>>>,
    peers: RwLock<HashMap<HostId, Arc<Peer>>>,
    events: mpsc::Sender<Event>,
    counters: Counters,
    /// The zero of the monotonic clock the path rule reads ([`path_choice`](infraternal_mesh::path_choice)).
    epoch: Instant,
    /// Source of probe tokens. Tokens only match answers to probes; they are not secret.
    tokens: AtomicU64,
    /// The node's direct-path probes, when the owner gave them (see
    /// [`RelayPaths::with_direct_probes`]); without them pairs have relay candidates only.
    probes: OnceLock<DirectProbes>,
}

impl Shared {
    /// Monotonic time since this node's relay paths started.
    fn now(&self) -> Duration {
        self.epoch.elapsed()
    }
}

fn read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The relayed pairs of one node, over an ordered list of relays.
pub struct RelayPaths {
    shared: Arc<Shared>,
    drivers: Vec<JoinHandle<()>>,
    shims: Mutex<HashMap<HostId, JoinHandle<()>>>,
}

/// The selected data plane's relay callbacks for one configured peer (see `settle`).
pub trait EndpointUpdater {
    /// Return a callback that moves an established session to the peer's shim endpoint,
    /// or resets an unestablished peer to an endpoint-less responder.
    /// # Errors
    /// Reports a stopped or unavailable data plane.
    fn handshake_preparer(
        &self,
        peer: &dataplane::Peer,
    ) -> io::Result<Arc<dyn Fn() -> io::Result<()> + Send + Sync>>;

    /// Return a callback that starts a handshake through the selected data plane.
    /// # Errors
    /// Reports a stopped or unavailable data plane.
    fn handshake_starter(&self, peer: &dataplane::Peer) -> io::Result<Arc<dyn Fn() + Send + Sync>>;

    /// Return a callback that writes this peer's route budget for a direct or relayed path.
    fn route_mtu_updater(&self, peer: &dataplane::Peer) -> RouteMtuUpdater;
}

impl EndpointUpdater for crate::node::Node {
    fn handshake_starter(&self, peer: &dataplane::Peer) -> io::Result<Arc<dyn Fn() + Send + Sync>> {
        self.relay_handshake_starter(peer)
    }

    fn handshake_preparer(
        &self,
        peer: &dataplane::Peer,
    ) -> io::Result<Arc<dyn Fn() -> io::Result<()> + Send + Sync>> {
        self.relay_handshake_preparer(peer)
    }

    fn route_mtu_updater(&self, peer: &dataplane::Peer) -> RouteMtuUpdater {
        self.relay_route_mtu_updater(peer)
    }
}

impl RelayPaths {
    /// Start connecting to every relay. Events go to `events`; a full queue drops them.
    /// # Errors
    /// Fails on an invalid identity or if no client socket can be bound.
    pub fn start(
        local: HostId,
        wg_port: u16,
        relays: Vec<RelaySpec>,
        credentials: Credentials,
        events: mpsc::Sender<Event>,
    ) -> io::Result<Self> {
        let config = infraternal_plugin_relay::tls::client_config(credentials)?;
        let endpoint = quinn::Endpoint::client((Ipv4Addr::UNSPECIFIED, 0).into())?;
        let shared = Arc::new(Shared {
            local,
            wg_port,
            endpoint,
            config,
            live: relays.iter().map(|_| RwLock::new(None)).collect(),
            relays,
            peers: RwLock::new(HashMap::new()),
            events,
            counters: Counters::default(),
            epoch: Instant::now(),
            tokens: AtomicU64::new(token_seed()),
            probes: OnceLock::new(),
        });
        let drivers = (0..shared.relays.len())
            .map(|index| tokio::spawn(drive(shared.clone(), index)))
            .collect();
        Ok(Self {
            shared,
            drivers,
            shims: Mutex::new(HashMap::new()),
        })
    }

    /// Relay `peer`: bind its shim socket and ask the live relays for a link. The data
    /// plane's endpoint moves to the shim once a link is active (see `settle`).
    /// # Errors
    /// Fails if the socket cannot be bound or the selected data plane is stopped.
    pub async fn relay_with_endpoint(
        &self,
        endpoint_updater: &mut impl EndpointUpdater,
        peer: HostId,
        kernel: &dataplane::Peer,
    ) -> io::Result<SocketAddr> {
        self.add_peer(endpoint_updater, peer, kernel, false).await
    }

    /// Watch a pair that is on its direct path: probe its direct endpoint (`kernel.endpoint`)
    /// from the `WireGuard` port and move the pair to a relay only when the path rule finds a
    /// relay measurably faster. No relay link is requested until some relay's own round trip
    /// leaves room to win (see [`consider_relays`]), and nothing is sent while the pair is idle.
    /// Needs [`RelayPaths::with_direct_probes`]; without probes it only registers the pair.
    /// # Errors
    /// Fails if the shim socket cannot be bound or the selected data plane is stopped.
    pub async fn watch_direct(
        &self,
        endpoint_updater: &mut impl EndpointUpdater,
        peer: HostId,
        kernel: &dataplane::Peer,
    ) -> io::Result<SocketAddr> {
        self.add_peer(endpoint_updater, peer, kernel, true).await
    }

    /// Register `peer` with a shim socket. `standby` leaves the pair on the direct path with no
    /// relay link requested; otherwise the pair is relayed at once and the direct path (if
    /// `kernel` has an endpoint) is probed as a candidate to move back to.
    async fn add_peer(
        &self,
        endpoint_updater: &mut impl EndpointUpdater,
        peer: HostId,
        kernel: &dataplane::Peer,
        standby: bool,
    ) -> io::Result<SocketAddr> {
        if let Some(existing) = read(&self.shared.peers).get(&peer) {
            return existing.socket.local_addr();
        }
        // Connected: only the selected engine's UDP socket can feed this shim. Do not
        // update the peer endpoint until settle confirms an active relay; updating both
        // endpoints while the direct path is still pending starts crossed handshakes.
        let socket = ShimSocket::bind(self.shared.wg_port)?;
        let local = socket.local_addr()?;
        let relayed_peer = dataplane::Peer {
            endpoint: Some(local),
            ..kernel.clone()
        };
        let prepare_handshake = endpoint_updater.handshake_preparer(&relayed_peer)?;
        let handshake_starter = endpoint_updater.handshake_starter(&relayed_peer)?;
        let route_mtu_updater = endpoint_updater.route_mtu_updater(kernel);
        // Moving back to the direct path re-prepares the peer with its own endpoint.
        let use_direct = kernel
            .endpoint
            .map(|_| endpoint_updater.handshake_preparer(kernel))
            .transpose()?;
        let relays = self.shared.relays.len();
        let mut state = PeerState::new(relays);
        if let Some(endpoint) = kernel.endpoint {
            state = state.with_direct(endpoint, standby);
        }
        let shim = Arc::new(Peer {
            host: peer,
            prepare_handshake,
            handshake_starter,
            route_mtu_updater,
            use_direct,
            socket,
            starting: std::sync::atomic::AtomicBool::new(false),
            route_mtu_generation: Mutex::new(0),
            state: Mutex::new(state),
            active: RwLock::new(None),
            refreshing_route_mtu: std::sync::atomic::AtomicBool::new(false),
            next_round_ms: AtomicU64::new(0),
            publishing: tokio::sync::Mutex::new(()),
        });
        write(&self.shared.peers).insert(peer, shim.clone());
        let task = tokio::spawn(outbound(self.shared.clone(), shim.clone()));
        lock(&self.shims).insert(peer, task);
        if standby {
            if let Some(probes) = self.shared.probes.get() {
                probes.want_round_in(Duration::ZERO);
            }
        } else {
            request_everywhere(&self.shared, &shim).await;
        }
        Ok(local)
    }

    /// Give this node's direct-path probes to the relay paths and start the two tasks that run
    /// them: one starts rounds when inbound traffic says one is due, the other turns finished
    /// probes into samples for the path rule. Without this call pairs choose between relays only.
    #[must_use]
    pub fn with_direct_probes(
        mut self,
        probes: DirectProbes,
        answers: mpsc::Receiver<Answer>,
    ) -> Self {
        if self.shared.probes.set(probes.clone()).is_err() {
            return self;
        }
        self.drivers.push(tokio::spawn(direct_rounds(
            self.shared.clone(),
            probes.clone(),
        )));
        self.drivers.push(tokio::spawn(direct_answers(
            self.shared.clone(),
            probes,
            answers,
        )));
        self
    }

    /// The median direct round trip of `peer`, and whether the direct path carries it now.
    /// `None` when the pair has no direct path or no answer yet. For diagnostics and fixtures.
    #[must_use]
    pub fn direct(&self, peer: HostId) -> Option<(Duration, bool)> {
        let shim = read(&self.shared.peers).get(&peer).cloned()?;
        let state = lock(&shim.state);
        let direct = state.direct.as_ref()?;
        Some((direct.samples.median()?, direct.on))
    }

    /// Stop relaying `peer`: withdraw its requests and close its shim socket.
    /// The caller installs whatever endpoint replaces the shim.
    pub async fn release(&self, peer: HostId) {
        let Some(shim) = write(&self.shared.peers).remove(&peer) else {
            return;
        };
        if let Some(task) = lock(&self.shims).remove(&peer) {
            task.abort();
        }
        let requested: Vec<usize> = {
            let state = lock(&shim.state);
            (0..self.shared.relays.len())
                .filter(|&index| state.requested[index] || state.links[index].is_some())
                .collect()
        };
        for index in requested {
            if let Some(live) = live(&self.shared, index) {
                let _ = live.client.unlink(peer).await;
            }
        }
    }

    /// The relay index a peer's packets use now.
    #[must_use]
    pub fn active(&self, peer: HostId) -> Option<usize> {
        read(&self.shared.peers)
            .get(&peer)
            .and_then(|shim| lock(&shim.state).active.map(|(index, _)| index))
    }

    /// The median end-to-end round trip of `peer`'s link on each relay, by relay index:
    /// `None` where it has no link or no answered probe yet. For diagnostics and fixtures.
    #[must_use]
    pub fn rtt(&self, peer: HostId) -> Vec<Option<Duration>> {
        read(&self.shared.peers)
            .get(&peer)
            .map(|shim| {
                let state = lock(&shim.state);
                state
                    .links
                    .iter()
                    .zip(&state.rtt)
                    .map(|(link, samples)| link.and(samples.median()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Ask relay `index` which public address it sees for this node's
    /// `WireGuard` port, through `observer`.
    /// # Errors
    /// Fails if the relay is not connected, is not IPv4, or never answers.
    pub async fn observe(&self, observer: &Observer, index: usize) -> io::Result<SocketAddr> {
        let live = self
            .shared
            .live
            .get(index)
            .and_then(|slot| read(slot).clone())
            .ok_or(io::ErrorKind::NotConnected)?;
        let SocketAddr::V4(address) = self.shared.relays[index].address else {
            return Err(io::ErrorKind::Unsupported.into());
        };
        observer.observe(live.client.probe_key(), address).await
    }

    /// Data-path counters so far.
    #[must_use]
    pub fn stats(&self) -> Stats {
        let counters = &self.shared.counters;
        Stats {
            sent: counters.sent.load(Ordering::Relaxed),
            received: counters.received.load(Ordering::Relaxed),
            unlinked: counters.unlinked.load(Ordering::Relaxed),
            too_large: counters.too_large.load(Ordering::Relaxed),
            probes_sent: counters.probes_sent.load(Ordering::Relaxed),
            probes_answered: counters.probes_answered.load(Ordering::Relaxed),
            probe_answers: counters.probe_answers.load(Ordering::Relaxed),
            switches: counters.switches.load(Ordering::Relaxed),
            #[cfg(feature = "test-support")]
            inbound_datagrams: counters.inbound_datagrams.load(Ordering::Relaxed),
            #[cfg(feature = "test-support")]
            malformed_datagrams: counters.malformed_datagrams.load(Ordering::Relaxed),
            #[cfg(feature = "test-support")]
            unknown_links: counters.unknown_links.load(Ordering::Relaxed),
            #[cfg(feature = "test-support")]
            unknown_peers: counters.unknown_peers.load(Ordering::Relaxed),
            #[cfg(feature = "test-support")]
            injection_errors: counters.injection_errors.load(Ordering::Relaxed),
            #[cfg(feature = "test-support")]
            receive_errors: counters.receive_errors.load(Ordering::Relaxed),
        }
    }

    /// Stop every task and close every relay connection.
    pub async fn close(self) {
        for task in &self.drivers {
            task.abort();
        }
        for (_, task) in lock(&self.shims).drain() {
            task.abort();
        }
        for slot in &self.shared.live {
            if let Some(live) = write(slot).take() {
                live.client.close();
            }
        }
        let _ =
            tokio::time::timeout(Duration::from_secs(1), self.shared.endpoint.wait_idle()).await;
    }
}

impl Drop for RelayPaths {
    fn drop(&mut self) {
        for task in &self.drivers {
            task.abort();
        }
        for (_, task) in lock(&self.shims).drain() {
            task.abort();
        }
    }
}

/// The live connection of relay `index`, with no lock held afterwards.
fn live(shared: &Shared, index: usize) -> Option<Arc<Live>> {
    let slot = read(&shared.live[index]);
    slot.clone()
}

/// Advance the generation when relay state and the published data path select `expected`.
fn route_generation_for_live(shared: &Shared, peer: &Peer, expected: &Arc<Live>) -> Option<u64> {
    let state = lock(&peer.state);
    let (index, link_id) = state.active?;
    if index != expected.index
        || !live(shared, index).is_some_and(|current| Arc::ptr_eq(&current, expected))
    {
        return None;
    }
    if !read(&peer.active)
        .as_ref()
        .is_some_and(|(current, current_id)| {
            *current_id == link_id && Arc::ptr_eq(current, expected)
        })
    {
        return None;
    }
    let mut generation = lock(&peer.route_mtu_generation);
    *generation = generation.wrapping_add(1);
    Some(*generation)
}

fn emit(shared: &Shared, event: Event) {
    let _ = shared.events.try_send(event);
}

/// Kernel ciphertext for one peer, out through its active link.
async fn outbound(shared: Arc<Shared>, peer: Arc<Peer>) {
    loop {
        if peer.socket.readable().await.is_err() {
            return;
        }
        let mut buffer = BytesMut::with_capacity(wire::HEADER + PACKET);
        buffer.put_u32(0);
        // Read readiness can go stale, and a refused send can surface on this receive.
        if peer.socket.try_recv(&mut buffer).is_err() {
            continue;
        }
        let Some((live, id)) = read(&peer.active)
            .clone()
            .or_else(|| standby_link(&shared, &peer))
        else {
            shared.counters.unlinked.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        buffer[..wire::HEADER].copy_from_slice(&id.0.to_be_bytes());
        // Whether this packet is data worth a probe round, decided before the buffer is sent.
        let carries_data = direct_probe::is_traffic(&buffer[wire::HEADER..]);
        match live.client.connection().send_datagram(buffer.freeze()) {
            Ok(()) => {
                shared.counters.sent.fetch_add(1, Ordering::Relaxed);
                // Only the pair's data starts a round: an idle pair's engine keepalives, which
                // also pass here, must not wake the probes (D81).
                if carries_data {
                    probe_round(&shared, &peer);
                }
            }
            Err(quinn::SendDatagramError::TooLarge) => {
                shared.counters.too_large.fetch_add(1, Ordering::Relaxed);
                if !peer.refreshing_route_mtu.swap(true, Ordering::AcqRel) {
                    if let Some(generation) = route_generation_for_live(&shared, &peer, &live) {
                        let refresh = peer.clone();
                        let mtu = crate::mesh_mtu::for_relay_datagram(
                            live.client.connection().max_datagram_size(),
                        );
                        tokio::spawn(async move {
                            if !update_peer_route_mtu(&refresh, generation, Some(mtu)).await {
                                tracing::warn!(
                                    relay_mtu = mtu,
                                    "Could not refresh peer route after an oversized relay datagram"
                                );
                            }
                            refresh.refreshing_route_mtu.store(false, Ordering::Release);
                        });
                    } else {
                        peer.refreshing_route_mtu.store(false, Ordering::Release);
                    }
                }
            }
            Err(_) => {
                shared.counters.unlinked.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// A pair on the direct path still hears from a peer that has moved to a relay: its relayed
/// packets reach the engine, which then answers to the shim. Such an answer goes out on the best
/// standby link, as the peer accepts packets on every link, instead of being dropped until the
/// two ends agree again.
fn standby_link(shared: &Shared, peer: &Peer) -> Option<(Arc<Live>, LinkId)> {
    let state = lock(&peer.state);
    if !state.on_direct() {
        return None;
    }
    let (index, id) = state.best_link()?;
    live(shared, index).map(|live| (live, id))
}

/// Relayed ciphertext from one relay connection, into the kernel.
async fn inbound(shared: Arc<Shared>, live: Arc<Live>) {
    loop {
        let Ok(datagram) = live.client.connection().read_datagram().await else {
            #[cfg(feature = "test-support")]
            shared
                .counters
                .receive_errors
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        #[cfg(feature = "test-support")]
        shared
            .counters
            .inbound_datagrams
            .fetch_add(1, Ordering::Relaxed);
        let Some((id, payload)) = wire::split(&datagram) else {
            #[cfg(feature = "test-support")]
            shared
                .counters
                .malformed_datagrams
                .fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let Some(host) = read(&live.links).get(&id).copied() else {
            #[cfg(feature = "test-support")]
            shared
                .counters
                .unknown_links
                .fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let Some(peer) = read(&shared.peers).get(&host).cloned() else {
            #[cfg(feature = "test-support")]
            shared
                .counters
                .unknown_peers
                .fetch_add(1, Ordering::Relaxed);
            continue;
        };
        if let Some((kind, token)) = parse_probe(payload) {
            if kind == PING {
                // Answer on the same link, so the round trip is this relay's both ways.
                if live
                    .client
                    .connection()
                    .send_datagram(probe_frame(id, PONG, token))
                    .is_ok()
                {
                    shared
                        .counters
                        .probes_answered
                        .fetch_add(1, Ordering::Relaxed);
                }
            } else {
                answered(&shared, &peer, live.index, id, token);
            }
            continue;
        }
        // A full loopback buffer drops the packet, as a congested path would.
        if peer.socket.try_send(payload).is_ok() {
            shared.counters.received.fetch_add(1, Ordering::Relaxed);
        } else {
            #[cfg(feature = "test-support")]
            shared
                .counters
                .injection_errors
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A start value for probe tokens that differs between runs; tokens need not be secret.
fn token_seed() -> u64 {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    since.as_secs().rotate_left(32)
        ^ u64::from(since.subsec_nanos())
        ^ u64::from(std::process::id())
}

/// One link probe DATAGRAM: the link id, then `kind` ([`PING`] or [`PONG`]), three zero
/// bytes and the token, all big-endian. The relay forwards it like any other frame.
fn probe_frame(id: LinkId, kind: u8, token: u64) -> bytes::Bytes {
    let mut frame = BytesMut::with_capacity(wire::HEADER + PROBE_LEN);
    frame.put_u32(id.0);
    frame.put_u8(kind);
    frame.put_bytes(0, 3);
    frame.put_u64(token);
    frame.freeze()
}

/// The kind and token of a link probe payload (after the link id), or `None` for anything
/// else, which is `WireGuard` ciphertext for the engine to authenticate.
fn parse_probe(payload: &[u8]) -> Option<(u8, u64)> {
    let probe: &[u8; PROBE_LEN] = payload.try_into().ok()?;
    let kind = probe[0];
    ((kind == PING || kind == PONG) && probe[1..4] == [0; 3]).then(|| {
        (
            kind,
            u64::from_be_bytes(probe[4..].try_into().unwrap_or_default()),
        )
    })
}

/// Whole milliseconds of a monotonic time, for the lock-free round gate.
fn millis(time: Duration) -> u64 {
    u64::try_from(time.as_millis()).unwrap_or(u64::MAX)
}

/// After one of `peer`'s packets went out: start a probe round if one is due and the pair has
/// a choice of links. This is the only place probes start, so an idle pair sends none.
///
/// Each linked relay gets one probe unless its previous one is still in flight and younger
/// than [`PROBE_LOST`]; an older one is recorded as a [`PROBE_LOST`] sample first, which may
/// move the pair off a link that stopped answering.
fn probe_round(shared: &Arc<Shared>, peer: &Arc<Peer>) {
    let now = shared.now();
    let now_ms = millis(now);
    if now_ms < peer.next_round_ms.load(Ordering::Relaxed) {
        return;
    }
    peer.next_round_ms.store(
        now_ms.saturating_add(millis(PROBE_INTERVAL)),
        Ordering::Relaxed,
    );
    let (probes, direct_ping, moved) = {
        let mut state = lock(&peer.state);
        // A pair with a direct path has a choice from its first link; with no link at all it
        // still probes the direct path, to learn whether a relay could beat it.
        if state.direct.is_none() && state.links.iter().flatten().count() < 2 {
            return;
        }
        let interval = state.round_interval(now);
        peer.next_round_ms
            .store(now_ms.saturating_add(millis(interval)), Ordering::Relaxed);
        let mut probes = Vec::new();
        for index in 0..state.links.len() {
            let Some(id) = state.links[index] else {
                continue;
            };
            if let Some((_, sent)) = state.probing[index] {
                if now.saturating_sub(sent) < PROBE_LOST {
                    continue;
                }
                state.rtt[index].record(sent + PROBE_LOST, PROBE_LOST);
            }
            let token = shared.tokens.fetch_add(1, Ordering::Relaxed);
            state.probing[index] = Some((token, now));
            probes.push((index, id, token));
        }
        let moved = state.first_measured(now) || state.choose(now);
        if moved {
            advance_generation(peer);
        }
        let direct_ping = state.direct.as_ref().map(|direct| direct.endpoint);
        (probes, direct_ping, moved)
    };
    if let (Some(endpoint), Some(direct_probes)) = (direct_ping, shared.probes.get()) {
        let direct_probes = direct_probes.clone();
        tokio::spawn(async move {
            // A refused send is a lost sample in due course; nothing to do here.
            let _ = direct_probes.ping(endpoint).await;
        });
    }
    for (index, id, token) in probes {
        if let Some(live) = live(shared, index)
            && live
                .client
                .connection()
                .send_datagram(probe_frame(id, PING, token))
                .is_ok()
        {
            shared.counters.probes_sent.fetch_add(1, Ordering::Relaxed);
        }
    }
    if moved {
        switched(shared, peer);
    }
}

/// An answer to one of this node's probes arrived on relay `index`'s link `id`: record the
/// round trip if it matches the outstanding probe there, then apply the path rule.
fn answered(shared: &Arc<Shared>, peer: &Arc<Peer>, index: usize, id: LinkId, token: u64) {
    let now = shared.now();
    let moved = {
        let mut state = lock(&peer.state);
        let Some((expected, sent)) = state.probing[index] else {
            return;
        };
        if expected != token || state.links[index] != Some(id) {
            return;
        }
        state.probing[index] = None;
        state.rtt[index].record(now, now.saturating_sub(sent));
        shared
            .counters
            .probe_answers
            .fetch_add(1, Ordering::Relaxed);
        let moved = state.first_measured(now) || state.choose(now);
        if moved {
            advance_generation(peer);
        }
        moved
    };
    if moved {
        switched(shared, peer);
    }
}

/// Start probe rounds when inbound traffic says one is due, then ask for the next.
///
/// Sleeps on [`DirectProbes::round_due`], which only the receive task wakes, so a node with no
/// inbound traffic has no timer here (D81). Each round covers every pair with a direct path;
/// a pair that is not due yet declines (`next_round_ms`), and the next wake is asked for at
/// the earliest due time.
async fn direct_rounds(shared: Arc<Shared>, probes: DirectProbes) {
    loop {
        probes.round_due().await;
        let peers: Vec<Arc<Peer>> = read(&shared.peers)
            .values()
            .filter(|peer| lock(&peer.state).direct.is_some())
            .cloned()
            .collect();
        for peer in &peers {
            probe_round(&shared, peer);
        }
        let now_ms = millis(shared.now());
        let earliest = peers
            .iter()
            .map(|peer| peer.next_round_ms.load(Ordering::Relaxed))
            .min();
        if let Some(due) = earliest {
            probes.want_round_in(Duration::from_millis(due.saturating_sub(now_ms)));
        }
    }
}

/// Turn finished direct probes into samples, and time out the ones that never come back.
///
/// The only timer is the loss timeout of a probe that is in flight; with none in flight the
/// task waits for the next ping or answer and costs nothing.
async fn direct_answers(
    shared: Arc<Shared>,
    probes: DirectProbes,
    mut answers: mpsc::Receiver<Answer>,
) {
    loop {
        let answer = match probes.expire() {
            Some(delay) => tokio::select! {
                answer = answers.recv() => answer,
                () = tokio::time::sleep(delay) => continue,
                () = probes.pinged() => continue,
            },
            None => tokio::select! {
                answer = answers.recv() => answer,
                () = probes.pinged() => continue,
            },
        };
        let Some(answer) = answer else {
            return;
        };
        apply_direct(&shared, &answer);
        while let Ok(more) = answers.try_recv() {
            apply_direct(&shared, &more);
        }
    }
}

/// Record one finished direct probe for the pair it belongs to, apply the path rule, and
/// consider standby relays.
fn apply_direct(shared: &Arc<Shared>, answer: &Answer) {
    let now = shared.now();
    let peers: Vec<Arc<Peer>> = read(&shared.peers).values().cloned().collect();
    for peer in peers {
        let moved = {
            let mut state = lock(&peer.state);
            let ours = state
                .direct
                .as_ref()
                .is_some_and(|direct| direct_probe::canonical(direct.endpoint) == answer.endpoint);
            if !ours {
                continue;
            }
            state.record_direct(now, answer.rtt, answer.lost);
            // A sample that breaks the steady picture reopens the decision at the fast rate
            // now, not at the end of the steady interval that was set before it arrived.
            let interval = state.round_interval(now);
            if interval < STEADY_INTERVAL {
                let due = millis(now).saturating_add(millis(interval));
                if peer.next_round_ms.fetch_min(due, Ordering::Relaxed) > due
                    && let Some(probes) = shared.probes.get()
                {
                    probes.want_round_in(interval);
                }
            }
            let moved = state.first_measured(now) || state.choose(now);
            if moved {
                advance_generation(&peer);
            }
            moved
        };
        if moved {
            switched(shared, &peer);
        }
        consider_relays(shared, &peer);
    }
}

/// A pair on the direct path asks its relays for standby links only when one could win: some
/// live relay's own round trip, which its QUIC connection measures without any probe, plus the
/// margin is below the newest direct round trip. A relay path is at least as long as this node's leg to
/// the relay, so when even that leg is not clearly faster the direct path cannot lose and
/// requesting links would cost relay state for nothing. Asked once; the links then stay.
fn consider_relays(shared: &Arc<Shared>, peer: &Arc<Peer>) {
    let worthwhile = {
        let mut state = lock(&peer.state);
        if !state.on_direct() || state.want_relay {
            return;
        }
        // The newest sample, not the median: one slow answer is enough to prepare standby links
        // (cheap, and kept), so the sustained windows can fill while the median catches up.
        let Some(newest) = state
            .direct
            .as_ref()
            .and_then(|direct| direct.samples.newest())
        else {
            return;
        };
        let leg = (0..shared.relays.len())
            .filter_map(|index| live(shared, index))
            .map(|live| live.client.connection().rtt())
            .min();
        let worthwhile = leg.is_some_and(|leg| leg + band(newest) < newest);
        state.want_relay |= worthwhile;
        worthwhile
    };
    if worthwhile {
        let shared = shared.clone();
        let peer = peer.clone();
        tokio::spawn(async move { request_everywhere(&shared, &peer).await });
    }
}

/// Invalidate route writes for the previously selected path. The caller holds `peer.state`,
/// which keeps the lock order of [`settle`]: state, then generation.
fn advance_generation(peer: &Peer) {
    let mut generation = lock(&peer.route_mtu_generation);
    *generation = generation.wrapping_add(1);
}

/// The path rule moved `peer` to a faster link: count it and publish the move. Both links
/// are live and the session is up, so the endpoint and handshake stay as they are.
fn switched(shared: &Arc<Shared>, peer: &Arc<Peer>) {
    shared.counters.switches.fetch_add(1, Ordering::Relaxed);
    let shared = shared.clone();
    let peer = peer.clone();
    tokio::spawn(async move { publish(&shared, &peer, false).await });
}

/// Ask every live relay where this peer has no link and no request yet.
async fn request_everywhere(shared: &Arc<Shared>, peer: &Arc<Peer>) {
    {
        let state = lock(&peer.state);
        if state.on_direct() && !state.want_relay {
            return;
        }
    }
    for index in 0..shared.relays.len() {
        let Some(live) = live(shared, index) else {
            continue;
        };
        let send = {
            let mut state = lock(&peer.state);
            // Every relay, not only while unlinked: a second link is the pair's ready
            // alternative, both for a failover and for a measured move.
            let send = state.links[index].is_none() && !state.requested[index];
            if send {
                state.requested[index] = true;
            }
            send
        };
        if send {
            let _ = live.client.link(peer.host).await;
        }
    }
}

/// Apply a link change: keep the active link while it lasts, otherwise take the best
/// remaining one ([`PeerState::best_link`]), publish any change, and ask the live relays
/// for the links still missing. Nothing is withdrawn: every link is a ready alternative.
///
/// Until any link of the pair is measured, the lowest-indexed link wins, as in the fixed
/// order before #201: links that come up together during setup then land both ends on the
/// same relay whatever order their notices arrive in. Once samples exist, only a lost link
/// or the measured rule moves the pair.
async fn settle(shared: &Arc<Shared>, peer: &Arc<Peer>) {
    let changed = {
        let mut state = lock(&peer.state);
        let kept = state
            .active
            .filter(|&(index, id)| state.links[index] == Some(id))
            .filter(|_| state.measured());
        // On the direct path the relay links are standby: they carry nothing.
        let active = if state.on_direct() {
            None
        } else {
            kept.or_else(|| state.best_link())
        };
        let changed = state.active != active;
        if changed {
            // Route writers hold this lock through the install, so a path change either waits
            // for an older write or advances first and makes that queued result stale.
            advance_generation(peer);
            let path = active.map(|(index, _)| Path::Relay(index));
            if state.measured() {
                state.selector.install(path, shared.now());
            } else {
                // Setup on unmeasured links: no dwell, and the first measured choice is due.
                state.selector.start(path);
                state.decided = false;
            }
        }
        state.active = active;
        changed
    };
    if changed {
        publish(shared, peer, true).await;
    }
    request_everywhere(shared, peer).await;
}

/// Make the data path follow `state.active`: route budget, `active`, the session start on a
/// first link, and an [`Event::Active`]. Publications of one peer run one at a time and each
/// reads the latest state, so a failover and a measured move racing each other still leave
/// the data path on whatever `state.active` says last.
///
/// `prepare` asks for the endpoint and session preparation of [`EndpointUpdater`] on any
/// change to a linked path (link changes, as before); a measured move passes `false` and
/// prepares only if the pair had no published link.
async fn publish(shared: &Arc<Shared>, peer: &Arc<Peer>, prepare: bool) {
    let _turn = peer.publishing.lock().await;
    let (active, route_mtu_generation, on_direct) = {
        let state = lock(&peer.state);
        (
            state.active,
            *lock(&peer.route_mtu_generation),
            state.on_direct(),
        )
    };
    let installed = active.and_then(|(index, id)| live(shared, index).map(|live| (live, id)));
    let linked = installed.is_some();
    let unchanged = match (read(&peer.active).as_ref(), installed.as_ref()) {
        (Some((current, current_id)), Some((next, next_id))) => {
            Arc::ptr_eq(current, next) && current_id == next_id
        }
        (None, None) => true,
        _ => false,
    };
    if unchanged {
        return;
    }
    let was_linked = read(&peer.active).is_some();
    let previous_mtu = read(&peer.active).as_ref().map(|(live, _)| {
        crate::mesh_mtu::for_relay_datagram(live.client.connection().max_datagram_size())
    });
    let route_mtu = installed.as_ref().map(|(live, _)| {
        crate::mesh_mtu::for_relay_datagram(live.client.connection().max_datagram_size())
    });
    match (previous_mtu, route_mtu) {
        (Some(previous), Some(next)) => {
            // The smaller budget is safe on both connections while the data path switches.
            let transition = previous.min(next);
            if !update_peer_route_mtu(peer, route_mtu_generation, Some(transition)).await {
                tracing::warn!(
                    relay_mtu = transition,
                    "Could not install relay transition route MTU"
                );
            }
            write(&peer.active).clone_from(&installed);
            if next != transition
                && !update_peer_route_mtu(peer, route_mtu_generation, Some(next)).await
            {
                tracing::warn!(
                    relay_mtu = next,
                    "Could not refresh peer route for relay path change"
                );
            }
        }
        (None, Some(next)) => {
            if !update_peer_route_mtu(peer, route_mtu_generation, Some(next)).await {
                tracing::warn!(
                    relay_mtu = next,
                    "Could not refresh peer route for relay path change"
                );
            }
            write(&peer.active).clone_from(&installed);
        }
        (_, None) => {
            // Stop sending through a lost relay before restoring the direct-path budget.
            *write(&peer.active) = None;
            if !update_peer_route_mtu(peer, route_mtu_generation, None).await {
                tracing::warn!("Could not refresh peer route for direct-path fallback");
            }
            // A pair the rule moved to the direct path sends to the peer's own endpoint again
            // (the session is kept: only the endpoint moves).
            if on_direct && let Some(use_direct) = peer.use_direct.clone() {
                let moved = tokio::task::spawn_blocking(move || use_direct())
                    .await
                    .is_ok_and(|result| result.is_ok());
                if !moved {
                    tracing::warn!("Could not move the engine endpoint back to the direct path");
                }
            }
        }
    }
    // Prepare the endpoint only after the relay is active. Existing sessions are
    // retained with an endpoint-only update; incomplete handshakes are reset on
    // both ends and the lower host id starts the replacement session after settling.
    if linked && (prepare || !was_linked) && !peer.starting.swap(true, Ordering::AcqRel) {
        let peer = peer.clone();
        let prepare_handshake = peer.prepare_handshake.clone();
        let handshake_starter = peer.handshake_starter.clone();
        let initiates = shared.local < peer.host;
        tokio::spawn(async move {
            let prepared = tokio::task::spawn_blocking(move || prepare_handshake())
                .await
                .is_ok_and(|result| result.is_ok());
            if !prepared {
                peer.starting.store(false, Ordering::Release);
                return;
            }
            tokio::time::sleep(SETTLE).await;
            peer.starting.store(false, Ordering::Release);
            if initiates && read(&peer.active).is_some() {
                let _ = tokio::task::spawn_blocking(move || handshake_starter()).await;
            }
        });
    }
    emit(
        shared,
        Event::Active {
            peer: peer.host,
            relay: active.map(|(index, _)| index),
        },
    );
}

/// Install one peer's newly derived direct or relayed route budget on a blocking netlink worker.
async fn update_peer_route_mtu(peer: &Arc<Peer>, generation: u64, mtu: Option<u16>) -> bool {
    let updater = peer.route_mtu_updater.clone();
    let peer = peer.clone();
    tokio::task::spawn_blocking(move || {
        let current = lock(&peer.route_mtu_generation);
        if *current != generation {
            return Ok(());
        }
        // Keep the generation stable until the route write completes.
        updater(mtu)
    })
    .await
    .is_ok_and(|result| result.is_ok())
}

/// Poll a live connection for path-MTU changes and refresh every peer using that connection.
async fn watch_relay_mtu(shared: Arc<Shared>, live: Arc<Live>) {
    let connection = live.client.connection().clone();
    let mut ticker = tokio::time::interval(RELAY_MTU_POLL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut tracker = RelayMtuTracker::default();
    loop {
        ticker.tick().await;
        let Some(mtu) = tracker.update(connection.max_datagram_size()) else {
            continue;
        };
        let peers: Vec<_> = read(&shared.peers)
            .values()
            .filter_map(|peer| {
                route_generation_for_live(&shared, peer, &live)
                    .map(|generation| (peer.clone(), generation))
            })
            .collect();
        let mut updated = true;
        for (peer, generation) in peers {
            if !update_peer_route_mtu(&peer, generation, Some(mtu)).await {
                tracing::warn!(
                    relay_mtu = mtu,
                    "Could not refresh peer route for relay MTU change"
                );
                updated = false;
            }
        }
        if !updated {
            tracker.retry();
        }
    }
}

/// Start a kernel-backed peer's first session through a new link (see `settle`).
/// A peer with an existing handshake is left alone so endpoint changes keep its session.
pub(crate) fn start_kernel_handshake(peer: &dataplane::Peer) -> io::Result<()> {
    let counters = wireguard::Device::counters()?;
    if counters
        .get(&peer.key)
        .is_some_and(|counters| counters.handshake_secs != 0)
    {
        return Ok(());
    }
    let mut client = wireguard::Client::new()?;
    client.peers(&[], &[peer.key])?;
    client.peers(std::slice::from_ref(peer), &[])
}

/// Prepare a kernel peer for the relay after its link is active.
/// Preserve an established session with an endpoint-only update; reset an incomplete
/// handshake to an endpoint-less responder so only the selected initiator starts a session.
pub(crate) fn prepare_kernel_handshake(peer: &dataplane::Peer) -> io::Result<()> {
    let counters = wireguard::Device::counters()?;
    if counters
        .get(&peer.key)
        .is_some_and(|counters| counters.handshake_secs != 0)
    {
        return wireguard::Client::new()?
            .endpoint(peer.key, peer.endpoint.ok_or(io::ErrorKind::InvalidInput)?);
    }
    let mut client = wireguard::Client::new()?;
    client.peers(&[], &[peer.key])?;
    let mut responder = peer.clone();
    responder.endpoint = None;
    client.peers(&[responder], &[])
}

/// Keep one relay connected, apply its notices, and repair pairs when it goes.
async fn drive(shared: Arc<Shared>, index: usize) {
    let mut failures = 0_u32;
    let mut last_healthy = None;
    loop {
        let spec = &shared.relays[index];
        let recently_healthy =
            last_healthy.is_some_and(|healthy: Instant| healthy.elapsed() < RECENT_HEALTH);
        let connect_deadline = if recently_healthy {
            CONNECT_RECENT
        } else {
            CONNECT
        };
        if let Ok((client, notices)) = Client::connect(
            &shared.endpoint,
            shared.config.clone(),
            spec.address,
            &spec.name,
            connect_deadline,
        )
        .await
        {
            serve(&shared, index, client, notices).await;
            last_healthy = Some(Instant::now());
            failures = 0;
            continue;
        }
        failures = failures.saturating_add(1);
        let exponent = failures.saturating_sub(1).min(5);
        let backoff = (BACKOFF * 2_u32.pow(exponent)).min(if recently_healthy {
            BACKOFF_RECENT_MAX
        } else {
            BACKOFF_MAX
        });
        tokio::time::sleep(backoff).await;
    }
}

/// Serve one relay connection until its control stream closes, watching path MTU changes too.
async fn serve(shared: &Arc<Shared>, index: usize, client: Client, mut notices: Notices) {
    let live = Arc::new(Live {
        index,
        client,
        links: RwLock::new(HashMap::new()),
    });
    *write(&shared.live[index]) = Some(live.clone());
    emit(shared, Event::RelayUp { relay: index });
    let reader = tokio::spawn(inbound(shared.clone(), live.clone()));
    let mtu_watcher = tokio::spawn(watch_relay_mtu(shared.clone(), live.clone()));
    let peers: Vec<Arc<Peer>> = read(&shared.peers).values().cloned().collect();
    for peer in &peers {
        request_everywhere(shared, peer).await;
    }
    while let Some(notice) = notices.next().await {
        let (host, link) = match notice {
            Notice::Linked { peer, id } => (peer, Some(id)),
            Notice::Unlinked { peer } => (peer, None),
        };
        let Some(peer) = read(&shared.peers).get(&host).cloned() else {
            // A link for a peer this node no longer relays: withdraw it.
            if link.is_some() {
                let _ = live.client.unlink(host).await;
            }
            continue;
        };
        {
            let mut links = write(&live.links);
            links.retain(|_, linked| *linked != host);
            if let Some(id) = link {
                links.insert(id, host);
            }
        }
        {
            let mut state = lock(&peer.state);
            if link.is_none() {
                // A link we still held ended from the peer's side, so our
                // request stays pending at the relay. A link we already
                // dropped is the echo of our own withdrawal: nothing pending.
                state.requested[index] = state.links[index].is_some();
            }
            if state.links[index] != link {
                state.link_changed(index);
            }
            state.links[index] = link;
        }
        settle(shared, &peer).await;
    }
    reader.abort();
    mtu_watcher.abort();
    *write(&shared.live[index]) = None;
    emit(shared, Event::RelayDown { relay: index });
    let peers: Vec<Arc<Peer>> = read(&shared.peers).values().cloned().collect();
    for peer in &peers {
        {
            let mut state = lock(&peer.state);
            state.links[index] = None;
            state.requested[index] = false;
            state.link_changed(index);
        }
        // Settling also asks the remaining live relays for any link still missing.
        settle(shared, peer).await;
    }
}

/// Dispatches tapped probe replies to the observation waiting for them.
pub struct Observer {
    seam: Arc<Seam>,
    waiting: Arc<Mutex<HashMap<[u8; 16], mpsc::Sender<Received>>>>,
    reader: JoinHandle<()>,
}

impl Observer {
    /// Take over `seam`'s receive side.
    #[must_use]
    pub fn new(seam: Seam) -> Self {
        let seam = Arc::new(seam);
        let waiting: Arc<Mutex<HashMap<[u8; 16], mpsc::Sender<Received>>>> = Arc::default();
        let reader = tokio::spawn({
            let seam = seam.clone();
            let waiting = waiting.clone();
            async move {
                while let Ok(received) = seam.recv().await {
                    if !probe::is_probe(&received.payload) {
                        continue;
                    }
                    let mut transaction = [0; 16];
                    transaction.copy_from_slice(&received.payload[16..32]);
                    // The id is not authenticated yet: the waiter checks the tag
                    // and keeps waiting after a forgery.
                    if let Some(waiter) = lock(&waiting).get(&transaction) {
                        let _ = waiter.try_send(received);
                    }
                }
            }
        });
        Self {
            seam,
            waiting,
            reader,
        }
    }

    /// Packets the seam's filter passed to userspace so far.
    #[must_use]
    pub fn delivered(&self) -> u64 {
        self.seam.delivered()
    }

    /// Probe `relay` from the `WireGuard` port and return the source it saw.
    /// # Errors
    /// Fails if sending fails or no valid reply arrives after the retries.
    pub async fn observe(&self, key: &ProbeKey, relay: SocketAddrV4) -> io::Result<SocketAddr> {
        let transaction = probe::transaction()?;
        let (sender, mut replies) = mpsc::channel(4);
        lock(&self.waiting).insert(transaction, sender);
        let request = key.request(transaction);
        let mut result = Err(io::ErrorKind::TimedOut.into());
        'attempts: for wait in PROBE_WAITS {
            if let Err(error) = self.seam.send(relay, &request) {
                result = Err(error);
                break;
            }
            let deadline = tokio::time::Instant::now() + wait;
            while let Ok(Some(reply)) = tokio::time::timeout_at(deadline, replies.recv()).await {
                if reply.source != relay {
                    continue;
                }
                if let Some((echoed, observed)) = key.reply(&reply.payload)
                    && echoed == transaction
                {
                    result = Ok(observed);
                    break 'attempts;
                }
            }
        }
        lock(&self.waiting).remove(&transaction);
        result
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

#[cfg(test)]
mod tests {
    //! The relay trigger, link probes, link choice and loopback socket. The full data path runs
    //! in the namespace proof and `examples/relay_echo.rs`.
    use super::{
        LinkId, PING, PONG, PROBE_LEN, PeerState, RelayMtuTracker, direct_failed, parse_probe,
        probe_frame, wire,
    };
    use crate::wireguard::Counters;
    use infraternal_mesh::path_choice::Path;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// The shim accepts only its engine's datagrams, preserves the relay prefix, and injects
    /// a reply into the same engine socket.
    #[tokio::test]
    async fn shim_socket_keeps_the_engine_connected_in_both_directions() {
        use super::ShimSocket;
        use bytes::BytesMut;
        use std::net::Ipv4Addr;
        use tokio::net::UdpSocket;

        let engine = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let shim = ShimSocket::bind(engine.local_addr().unwrap().port()).unwrap();
        let foreign = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = shim.local_addr().unwrap();
        foreign.send_to(b"foreign", addr).await.unwrap();
        engine.send_to(b"cipher", addr).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), shim.readable())
            .await
            .unwrap()
            .unwrap();
        let mut frame = BytesMut::with_capacity(32);
        frame.extend_from_slice(b"link");
        shim.try_recv(&mut frame).unwrap();
        assert_eq!(&frame[..], b"linkcipher");

        assert_eq!(shim.try_send(b"reply").unwrap(), 5);
        let mut reply = [0; 16];
        let (size, source) =
            tokio::time::timeout(Duration::from_secs(5), engine.recv_from(&mut reply))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(source, addr);
        assert_eq!(&reply[..size], b"reply");
    }

    /// A probe survives the relay's framing and is never confused with `WireGuard` ciphertext.
    #[test]
    fn link_probes_round_trip_and_never_match_wireguard_packets() {
        let frame = probe_frame(LinkId(7), PING, 0x0102_0304_0506_0708);
        assert_eq!(frame.len(), wire::HEADER + PROBE_LEN);
        let Some((id, payload)) = wire::split(&frame) else {
            panic!("a probe frame has a link id and a payload");
        };
        assert_eq!(id, LinkId(7));
        assert_eq!(parse_probe(payload), Some((PING, 0x0102_0304_0506_0708)));
        let answer = probe_frame(LinkId(7), PONG, 9);
        assert_eq!(
            wire::split(&answer).and_then(|(_, payload)| parse_probe(payload)),
            Some((PONG, 9))
        );
        // WireGuard's four message types, a keepalive-sized data packet and a probe-length
        // data packet stay ciphertext.
        for kind in 1..=4_u8 {
            let mut packet = [0_u8; PROBE_LEN];
            packet[0] = kind;
            assert_eq!(parse_probe(&packet), None, "type {kind}");
        }
        assert_eq!(parse_probe(&[4, 0, 0, 0]), None);
        let mut nonzero = [0_u8; PROBE_LEN];
        nonzero[0] = PING;
        nonzero[2] = 1;
        assert_eq!(parse_probe(&nonzero), None, "reserved bytes must be zero");
        let mut long = [0_u8; PROBE_LEN + 1];
        long[0] = PING;
        assert_eq!(parse_probe(&long), None, "exact length only");
    }

    /// A pair with one relay link and a direct path, driven second by second as the probe
    /// rounds drive it: both paths get a sample with up to `jitter_percent` of noise, then the
    /// rule runs. Returns when the pair first moved (seconds from the start), how many times
    /// it moved in all, and whether it ended on the direct path.
    fn simulate(
        direct_ms: u64,
        relay_ms: u64,
        start_on_direct: bool,
        jitter_percent: u64,
        seconds: u64,
        seed: u64,
    ) -> (Option<u64>, u32, bool) {
        let endpoint = "127.0.0.1:9".parse().unwrap();
        let mut state = PeerState::new(1).with_direct(endpoint, start_on_direct);
        state.links = vec![Some(LinkId(1))];
        if !start_on_direct {
            state.active = Some((0, LinkId(1)));
            state.selector.start(Some(Path::Relay(0)));
        }
        let mut noise = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut jittered = |ms: u64| {
            noise ^= noise << 13;
            noise ^= noise >> 7;
            noise ^= noise << 17;
            let spread = 2 * jitter_percent + 1;
            let offset =
                i64::try_from(noise % spread).unwrap() - i64::try_from(jitter_percent).unwrap();
            let micros = i64::try_from(ms * 1_000).unwrap();
            Duration::from_micros(u64::try_from(micros + micros * offset / 100).unwrap())
        };
        let (mut first, mut moves) = (None, 0);
        for second in 1..=seconds {
            let at = Duration::from_secs(second);
            state.record_direct(at, jittered(direct_ms), false);
            state.rtt[0].record(at, jittered(relay_ms));
            if state.first_measured(at) || state.choose(at) {
                first.get_or_insert(second);
                moves += 1;
            }
        }
        (first, moves, state.on_direct())
    }

    /// A direct path 80 ms against a relay of 20 ms loses within one window of probes, and the
    /// reverse pair never moves; the same holds under 15 % jitter for 40 seeds each.
    #[test]
    fn a_slow_direct_path_loses_to_a_faster_relay_and_the_reverse_stays() {
        for seed in 1..=40 {
            let (first, moves, direct) = simulate(80, 20, true, 15, 600, seed);
            assert!(
                first.is_some_and(|at| at <= 6),
                "seed {seed}: moved at {first:?}"
            );
            assert_eq!(
                (moves, direct),
                (1, false),
                "seed {seed}: one move, to the relay"
            );
            let (first, moves, direct) = simulate(20, 80, true, 15, 600, seed);
            assert_eq!(
                (first, moves, direct),
                (None, 0, true),
                "seed {seed}: direct stays"
            );
            let (first, moves, direct) = simulate(80, 20, false, 15, 600, seed);
            assert_eq!(
                (first, moves, direct),
                (None, 0, false),
                "seed {seed}: relay stays"
            );
            let (first, moves, direct) = simulate(20, 80, false, 15, 600, seed);
            assert!(
                first.is_some_and(|at| at <= 6),
                "seed {seed}: moved at {first:?}"
            );
            assert_eq!(
                (moves, direct),
                (1, true),
                "seed {seed}: one move, to direct"
            );
        }
    }

    /// Direct wins inside the margin: a direct path a little slower than a relay keeps the
    /// pair (or takes it back), and a relay that is only a little faster rarely moves it. The
    /// path rule is allowed an occasional move on a lucky streak of samples (J1105 measured 0 to
    /// 2.4 moves an hour at 10 to 20 % jitter for two equal paths, and a relay that is really 10 %
    /// faster is a harder case), so this counts moves over 40 ten-minute runs instead of
    /// demanding none.
    #[test]
    fn direct_wins_inside_the_margin_and_nothing_flaps() {
        let (mut off_direct, mut back, mut ended_direct) = (0, 0, 0);
        for seed in 1..=40 {
            let (_, moves, _) = simulate(44, 40, true, 10, 600, seed);
            off_direct += moves;
            let (_, moves, direct) = simulate(44, 40, false, 10, 600, seed);
            back += moves;
            ended_direct += u32::from(direct);
        }
        // Measured: 9 moves in 40 runs (6.7 hours of 1 s samples), about 1.3 an hour, for a 10 %
        // faster relay under 10 % jitter on both paths; the bound leaves room for seed luck.
        assert!(
            off_direct <= 14,
            "{off_direct} moves off direct in 40 runs of 600 s"
        );
        // The rule wants every direct sample inside the margin to take a pair back, so a direct
        // path with jitter wider than the gap may stay on the relay for a whole run.
        assert!(
            ended_direct >= 30,
            "only {ended_direct} of 40 relayed pairs returned to direct"
        );
        // Measured: 49 moves in 40 runs, 40 at most to return plus about 9 flaps (1.3 an hour).
        assert!(
            back <= 40 + 14,
            "{back} moves in 40 runs that each need at most one to return"
        );
    }

    /// A peer that never answered is not slow: lost probes before the first answer are not
    /// samples, and the pair stays where it is.
    #[test]
    fn silence_before_the_first_answer_is_not_a_slow_path() {
        let endpoint = "127.0.0.1:9".parse().unwrap();
        let mut state = PeerState::new(1).with_direct(endpoint, true);
        state.links = vec![Some(LinkId(1))];
        for second in 1..=30 {
            let at = Duration::from_secs(second);
            state.record_direct(at, Duration::from_secs(2), true);
            state.rtt[0].record(at, Duration::from_millis(20));
            assert!(!state.choose(at), "second {second}");
        }
        assert!(state.on_direct());
        assert_eq!(
            state.round_interval(Duration::from_secs(30)),
            Duration::from_secs(5),
            "a silent peer is pinged at the steady rate"
        );
        // Once it has answered, losses count: a path that goes dark loses to the relay.
        let mut at = Duration::from_secs(31);
        state.record_direct(at, Duration::from_millis(30), false);
        let mut moved_at = None;
        for second in 32..=60 {
            at = Duration::from_secs(second);
            state.record_direct(at, Duration::from_secs(2), true);
            state.rtt[0].record(at, Duration::from_millis(20));
            if state.choose(at) {
                moved_at.get_or_insert(second);
            }
        }
        assert!(moved_at.is_some_and(|second| second <= 42), "{moved_at:?}");
        assert!(!state.on_direct());
    }

    /// A pair probes every second while a decision is open and every five seconds once all its
    /// windows are sustained and the newest direct sample sits near its median.
    #[test]
    fn probe_rounds_slow_down_only_when_everything_is_settled_and_steady() {
        let endpoint = "127.0.0.1:9".parse().unwrap();
        let mut state = PeerState::new(1).with_direct(endpoint, true);
        state.links = vec![Some(LinkId(1))];
        assert_eq!(
            state.round_interval(Duration::ZERO),
            Duration::from_secs(5),
            "an unanswered peer is pinged at the steady rate"
        );
        state.record_direct(Duration::ZERO, Duration::from_millis(30), false);
        assert_eq!(state.round_interval(Duration::ZERO), Duration::from_secs(1));
        for second in 1..=5 {
            let at = Duration::from_secs(second);
            state.record_direct(at, Duration::from_millis(30), false);
            state.rtt[0].record(at, Duration::from_millis(60));
        }
        let now = Duration::from_secs(5);
        assert_eq!(state.round_interval(now), Duration::from_secs(5));
        // One sample far from the median reopens the decision at the fast rate.
        state.record_direct(now, Duration::from_millis(90), false);
        assert_eq!(state.round_interval(now), Duration::from_secs(1));
    }

    /// Without a usable active link, the fastest measured link wins, then the lowest index.
    #[test]
    fn the_fallback_link_is_the_fastest_measured_then_the_lowest_index() {
        let mut state = PeerState::new(3);
        assert_eq!(state.best_link(), None);
        state.links = vec![None, Some(LinkId(5)), Some(LinkId(6))];
        assert_eq!(
            state.best_link(),
            Some((1, LinkId(5))),
            "unmeasured: list order"
        );
        state.rtt[2].record(Duration::from_secs(1), Duration::from_millis(30));
        assert_eq!(
            state.best_link(),
            Some((2, LinkId(6))),
            "measured beats unmeasured"
        );
        state.rtt[1].record(Duration::from_secs(1), Duration::from_millis(10));
        assert_eq!(state.best_link(), Some((1, LinkId(5))));
        state.link_changed(1);
        assert_eq!(
            state.best_link(),
            Some((2, LinkId(6))),
            "a changed link forgets its samples"
        );
    }

    /// The first complete probe round leaves a far default at once, and keeps an equal one.
    #[test]
    fn the_first_probe_round_leaves_a_far_default_at_once() {
        let at = Duration::from_millis(1_300);
        let mut state = PeerState::new(2);
        state.links = vec![Some(LinkId(1)), Some(LinkId(2))];
        state.active = Some((0, LinkId(1)));
        state.rtt[1].record(at, Duration::from_millis(30));
        assert!(!state.first_measured(at), "relay 0 has no sample yet");
        state.rtt[0].record(at, Duration::from_millis(300));
        assert!(state.first_measured(at));
        assert_eq!(state.active, Some((1, LinkId(2))));
        assert!(!state.first_measured(at), "only once");

        let mut equal = PeerState::new(2);
        equal.links = vec![Some(LinkId(1)), Some(LinkId(2))];
        equal.active = Some((0, LinkId(1)));
        equal.rtt[0].record(at, Duration::from_millis(41));
        equal.rtt[1].record(at, Duration::from_millis(39));
        assert!(!equal.first_measured(at));
        assert_eq!(
            equal.active,
            Some((0, LinkId(1))),
            "equal links keep the shared default"
        );
    }

    /// A sustained faster link takes over the active one; the rule itself is tested in
    /// `infraternal_mesh::path_choice`.
    #[test]
    fn a_sustained_faster_link_becomes_active() {
        let mut state = PeerState::new(2);
        state.links = vec![Some(LinkId(1)), Some(LinkId(2))];
        state.active = Some((0, LinkId(1)));
        state.selector.install(Some(Path::Relay(0)), Duration::ZERO);
        for second in 1..=5 {
            let at = Duration::from_secs(second);
            state.rtt[0].record(at, Duration::from_millis(300));
            state.rtt[1].record(at, Duration::from_millis(30));
            let moved = state.choose(at);
            assert_eq!(moved, second == 5, "second {second}");
        }
        assert_eq!(state.active, Some((1, LinkId(2))));
        assert_eq!(state.selector.current(), Some(Path::Relay(1)));
    }

    fn timestamp(seconds: u64, nanoseconds: u32) -> SystemTime {
        UNIX_EPOCH + Duration::new(seconds, nanoseconds)
    }

    /// A peer is a relay candidate when its endpoint has no newer handshake.
    #[test]
    fn a_pair_is_relayed_only_without_a_handshake_since_its_endpoint() {
        let since = 1_800_000_000;
        let installed_at = timestamp(since, 500_000_000);
        assert!(direct_failed(None, installed_at), "unknown peer");
        let never = Counters::default();
        assert!(direct_failed(Some(&never), installed_at));
        let stale = Counters {
            handshake_secs: since - 1,
            ..Counters::default()
        };
        assert!(
            direct_failed(Some(&stale), installed_at),
            "a handshake before the endpoint"
        );
        for fresh in [since + 1, since + 3] {
            let counters = Counters {
                handshake_secs: fresh,
                ..Counters::default()
            };
            assert!(!direct_failed(Some(&counters), installed_at));
        }
    }

    /// A live QUIC path change must produce a new route budget only when its limit changes.
    #[test]
    fn relay_route_budget_tracks_live_datagram_limit_changes() {
        let mut tracker = RelayMtuTracker::default();
        assert_eq!(tracker.update(Some(1434)), Some(1392));
        assert_eq!(tracker.update(Some(1434)), None);
        assert_eq!(tracker.update(Some(1214)), Some(1168));
        assert_eq!(tracker.update(Some(1434)), Some(1392));
    }

    #[test]
    fn a_same_second_handshake_cannot_prove_it_followed_the_endpoint_update() {
        let since = 1_800_000_000;
        // The endpoint can be installed later in the same second than the
        // previous handshake. Compare the kernel's nanoseconds to the precise
        // install time rather than treating every equal second as ambiguous.
        let before_endpoint_in_same_second = Counters {
            handshake_secs: since,
            handshake_nanos: 100_000_000,
            ..Counters::default()
        };
        assert!(
            direct_failed(
                Some(&before_endpoint_in_same_second),
                timestamp(since, 500_000_000),
            ),
            "an ambiguous same-second handshake must not suppress relay fallback"
        );
    }

    #[test]
    fn a_fresh_same_second_handshake_keeps_the_direct_path() {
        let since = 1_800_000_000;
        let after_endpoint_install = Counters {
            handshake_secs: since,
            handshake_nanos: 800_000_000,
            ..Counters::default()
        };
        assert!(
            !direct_failed(Some(&after_endpoint_install), timestamp(since, 200_000_000),),
            "a handshake later in the install second proves the direct path"
        );
    }

    #[test]
    fn a_handshake_equal_to_the_endpoint_install_time_is_not_fresh() {
        let installed_at = timestamp(1_800_000_000, 500_000_000);
        let counters = Counters {
            handshake_secs: 1_800_000_000,
            handshake_nanos: 500_000_000,
            ..Counters::default()
        };
        assert!(
            direct_failed(Some(&counters), installed_at),
            "equal timestamps do not establish ordering"
        );
    }
}

#[cfg(all(test, feature = "test-support"))]
mod review_j375_tests {
    //! Deterministically exercises a stale relay-MTU write across direct-path fallback (#381).
    use super::*;
    use infraternal_plugin_relay::{
        relay::{Admission, Limits, Relay},
        testing::{Authority, Purpose},
        tls,
    };
    use std::sync::atomic::{AtomicBool, AtomicU16};

    /// A delayed relay callback must not overwrite a subsequently restored direct MTU.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_relay_callback_must_not_overwrite_direct_path_budget() {
        let mut authority = Authority::new();
        let admission: Admission = Arc::new(|_| true);
        let relay = Relay::start(
            "127.0.0.1:0".parse().unwrap(),
            authority.issue(Purpose::Relay("relay.mesh.test")),
            Limits::default(),
            admission,
        )
        .unwrap();
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut config =
            tls::client_config(authority.issue(Purpose::Host(HostId([1; 16])))).unwrap();
        let mut transport = quinn::TransportConfig::default();
        transport
            .initial_mtu(1472)
            .min_mtu(1472)
            .mtu_discovery_config(None);
        config.transport_config(Arc::new(transport));
        let (client, _notices) = Client::connect(
            &endpoint,
            config.clone(),
            relay.local_addr().unwrap(),
            "relay.mesh.test",
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let live = Arc::new(Live {
            index: 0,
            client,
            links: RwLock::default(),
        });
        let maximum = live.client.connection().max_datagram_size();
        assert_eq!(maximum, Some(1434));
        let budget = Arc::new(AtomicU16::new(1392));
        let callback_budget = budget.clone();
        let callback: RouteMtuUpdater = Arc::new(move |mtu| {
            callback_budget.store(mtu.unwrap_or(1200), Ordering::Release);
            Ok(())
        });
        let host = HostId([2; 16]);
        let engine = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let peer = Arc::new(Peer {
            host,
            prepare_handshake: Arc::new(|| Ok(())),
            handshake_starter: Arc::new(|| {}),
            route_mtu_updater: callback,
            use_direct: None,
            socket: ShimSocket::bind(engine.local_addr().unwrap().port()).unwrap(),
            starting: AtomicBool::new(false),
            route_mtu_generation: Mutex::new(0),
            state: Mutex::new(PeerState {
                active: Some((0, LinkId(1))),
                ..PeerState::new(1)
            }),
            active: RwLock::new(Some((live.clone(), LinkId(1)))),
            refreshing_route_mtu: AtomicBool::new(false),
            next_round_ms: AtomicU64::new(0),
            publishing: tokio::sync::Mutex::new(()),
        });
        let (events, _rx) = mpsc::channel(16);
        let shared = Arc::new(Shared {
            local: HostId([1; 16]),
            wg_port: 0,
            endpoint,
            config,
            relays: vec![],
            live: vec![],
            peers: RwLock::new(HashMap::from([(host, peer.clone())])),
            events,
            counters: Default::default(),
            epoch: Instant::now(),
            tokens: AtomicU64::new(1),
            probes: OnceLock::new(),
        });
        let stale_generation = *lock(&peer.route_mtu_generation);
        let delayed_peer = peer.clone();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let delayed_relay_result = tokio::spawn(async move {
            release_rx.await.unwrap();
            update_peer_route_mtu(&delayed_peer, stale_generation, Some(1392)).await
        });
        // This is settle's direct-path order: retire the relay, then restore the direct budget.
        settle(&shared, &peer).await;
        assert!(read(&peer.active).is_none());
        assert_eq!(budget.load(Ordering::Acquire), 1200);
        release_tx.send(()).unwrap();
        assert!(delayed_relay_result.await.unwrap());
        let final_budget = budget.load(Ordering::Acquire);
        let mut tracker = RelayMtuTracker::default();
        assert_eq!(tracker.update(maximum), Some(1392));
        assert_eq!(tracker.update(maximum), None);
        live.client.connection().close(0_u32.into(), b"done");
        relay.close().await;
        println!(
            "direct MTU=1200, stale relay MTU=1392, final route MTU={final_budget}, unchanged relay limit produces no further refresh"
        );
        assert_eq!(
            final_budget, 1200,
            "inactive relay overwrote the direct path's safe route budget"
        );
    }
}
