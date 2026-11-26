//! Drops handshake initiations from keys the node has not granted, before `GotaTun` sees them.
//!
//! `GotaTun` answers a MAC1-valid initiation with a cookie while the device is under load (its
//! handshake backlog is an eighth full, #260 J1112), and it does so before it looks up the
//! sender's key. MAC1 needs only the node's public key, which mesh members can see, so without
//! this guard a stranger could make the node reply.
//! The guard sits between the UDP socket and `GotaTun` on both node platforms (Linux and macOS):
//! it validates MAC1, decrypts the sender's static key, and passes the initiation on only when
//! that key belongs to a peer the node has installed. Every other packet passes unchanged, and
//! admitted peers still reach `GotaTun`'s own limiter and cookie path.
//!
//! Decrypting the sender's key costs one X25519 key agreement, far more than the MAC1 check, and
//! it runs in the single receive task that also carries every peer's data packets. So the guard
//! checks budgets before any key agreement (J555 F1), in this order, per one-second window:
//! - per source (an IPv4 address, an IPv6 /64, or a link-local IPv6 address on its interface):
//!   at most [`REFUSED_SOURCE_BUDGET`] key agreements that admitted nobody, and at most
//!   [`SOURCE_BUDGET`] in all;
//! - per network (an IPv4 /24, an IPv6 /48, or one link for link-local sources): at most
//!   [`REFUSED_NETWORK_BUDGET`] refused and [`NETWORK_BUDGET`] in all, so one network's many
//!   addresses share one budget (J713);
//! - per node: at most [`NODE_BUDGET`] in all, in two halves. Sources that are not known peer
//!   endpoints share [`UNKNOWN_SOURCE_BUDGET`]; known endpoints share [`RESERVED_BUDGET`].
//!
//! A known endpoint is an exact address and port (and interface, for a link-local address) that
//! the coordinator configured for an installed peer, or that `GotaTun` confirmed from a peer's
//! authenticated traffic. Each one may spend its own share of the reserve per window (see
//! [`reserve_share`]: the reserve divided by the number of known endpoints, at least one), and
//! those key agreements skip the source and network budgets. Past its share, or once the
//! reserve is spent, a known endpoint is held to the same budgets as any other source. A
//! refused key agreement at a known endpoint (a spoofed source or a stale key: the real peer's
//! key is installed) uses up that endpoint's share for the rest of the window. Replacing an
//! endpoint list keeps each endpoint's count, and an endpoint new to the lists starts the window
//! spent, so a list change never refills a share before the window ends (J754, #483): a member
//! that roams its own endpoint four times a second cannot renew a spoofer's shares. One exception
//! (J778): a list that shrinks raises [`reserve_share`] at once, so each remaining endpoint may
//! spend up to the larger share for the rest of the window; [`RESERVED_BUDGET`] still caps the
//! total. Past any budget an initiation is dropped silently: ungranted keys' initiations still
//! never get a reply, and a flood costs one MAC1 check per packet, as it did before the guard
//! existed.
//!
//! The total per-source budget is twice [`REFUSED_SOURCE_BUDGET`], so a granted peer's burst
//! gets room a stranger's does not. `GotaTun` no longer limits per source at all: it demands
//! cookies only while its handshake backlog says it is under load (#260, J1112), so these budgets
//! are what bound one source's key agreements.
//!
//! What a sustained flood of MAC1-valid initiations does (a replayed initiation is enough, and
//! anyone who knows the node's public key can make one). The budgets refill every second, so a
//! flood that lasts takes its share again in every window, and these limits hold for as long as
//! it lasts. Measured by the `flood_fairness` tests at 20,000 packets a second for 90 s:
//! - From one network, however many of its addresses it uses: it gets at most
//!   [`REFUSED_NETWORK_BUDGET`] key agreements a second, and every granted peer outside that
//!   network is still admitted (18 of 18 attempts, at an unknown endpoint too).
//! - From many networks, or with spoofed sources that are not known endpoints: the flood
//!   spends [`UNKNOWN_SOURCE_BUDGET`] a second, and a granted peer at a known endpoint is still
//!   admitted every time.
//! - Spoofing known endpoints. Every mesh member learns its peers' endpoints from the
//!   coordinator, so an attacker on a network that allows spoofing can send from them. Each
//!   spoofed endpoint takes at most its share of the reserve a second, and only one key
//!   agreement when it sends a stranger's key; past that it is an ordinary source. While the
//!   node knows at most [`RESERVED_BUDGET`] distinct endpoints (one configured and confirmed
//!   both counts once, so with one endpoint per peer that is 500 peers), the shares add up to
//!   no more than the reserve, so spoofing *other* endpoints, however many, never takes an
//!   unspoofed known endpoint's initiation (J735's floods: 18 of 18). Spoofing a peer's own
//!   exact address and port does: the peer then falls back to the unknown share like a new
//!   join. With more known endpoints every share is one, and a flood that spoofs at least
//!   [`RESERVED_BUDGET`] other known endpoints in the same second, and also spends the unknown
//!   share, leaves an unspoofed known endpoint only the unknown-endpoint chance below.
//! - A peer at an endpoint the node does not know yet (a new join, or a NAT rebinding the
//!   coordinator has not published) is admitted only if its initiation arrives before the flood
//!   has spent the unknown share in that second; at a steady flood of R packets a second that is
//!   a chance of about [`UNKNOWN_SOURCE_BUDGET`] out of R per attempt (2.5% at 20,000/s), and it
//!   retries every five seconds.
//! - A granted peer that shares its source (its /64 or IPv4 address) with a flood loses its
//!   initiations to that source's budget, unless it is at its known endpoint and within its
//!   share, which skips the source budget: two peers behind one NAT keep each other's floods
//!   off their own ports.
//!
//! Established sessions keep their keys and their data path throughout, and the node's own
//! initiations to peers whose endpoints it knows are answered by responses, which the guard
//! never budgets. The alternative, letting over-budget initiations reach `GotaTun`'s cookie
//! reply, would answer ungranted keys.
//!
//! Handshake responses are not filtered (J778, #483). A response carries no sender key the guard
//! could check, and only `GotaTun` knows which of its own initiations a response answers.
//! `GotaTun` no longer counts responses per source (#260, J1112), so a burst of responses to the
//! node's own initiations (many peers behind one NAT after a restart) draws no cookie. While its
//! handshake backlog says it is under load, it answers a MAC1-valid response that lacks a valid
//! MAC2 with a cookie reply, before it looks the response up. MAC1 needs only the node's public
//! key, so anyone who knows that key and can build such a backlog can still draw cookie replies
//! this way, to a spoofed address too. Each reply (64 bytes) is smaller than the response that
//! caused it (92 bytes), so it never amplifies a flood. Closing this needs a response budget here
//! or a `GotaTun` change; it is a follow-up.
//!
//! Cookie-proven (MAC2) initiations get no budget of their own: the cookie secret is private to
//! the `GotaTun` device, so the guard cannot check MAC2 without a `GotaTun` change. `GotaTun`
//! sends cookies only while its handshake backlog says it is under load, which the guard's
//! budgets keep rare: they admit at most [`NODE_BUDGET`] key agreements a second, and the backlog
//! that means load is 128 waiting messages. A peer bursting from its known endpoint spends its
//! share of the reserve first and then the budgets every source has.

use gotatun::{
    noise::{handshake::parse_handshake_anon, rate_limiter::RateLimiter},
    packet::{Packet, PacketBufPool, WgKind, WgPacketType},
    udp::{UdpRecv, socket::UdpSocket as GotaUdpSocket},
    x25519::{PublicKey as X25519PublicKey, StaticSecret},
};
use std::{
    collections::{BTreeSet, HashMap},
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering as AtomicOrdering},
    },
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use crate::{
    direct_probe::{self, DirectProbes},
    policy::model::PublicKey,
    underlay_announce::CoalescedWake,
};

/// Why the guard kept an initiation away from `GotaTun`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The packet is not a well-formed initiation with a valid MAC1 for this node.
    InvalidMac,
    /// The source already used its [`REFUSED_SOURCE_BUDGET`] or [`SOURCE_BUDGET`] this second;
    /// no key agreement ran.
    SourceBudget,
    /// The source's network (IPv4 /24, IPv6 /48) already used its [`REFUSED_NETWORK_BUDGET`]
    /// or [`NETWORK_BUDGET`] this second; no key agreement ran.
    NetworkBudget,
    /// The node already used [`UNKNOWN_SOURCE_BUDGET`] this second, and this source could not
    /// spend from the reserve (it is not a known endpoint, or its share or the reserve is used
    /// up); no key agreement ran.
    NodeBudget,
    /// The key agreement ran and the sender's static key did not decrypt.
    Undecryptable,
    /// The sender's static key decrypted, and it is not an installed peer.
    UnknownKey,
}

/// Key agreements per second and source that may end in a refusal (an unknown or undecryptable
/// key).
///
/// This was `GotaTun`'s own per-source handshake limit before the guard existed. `GotaTun` now
/// decides load by its handshake backlog instead (#260, J1112), so this budget alone keeps one
/// stranger at 100 key agreements a second.
pub(crate) const REFUSED_SOURCE_BUDGET: u32 = 100;

/// Key agreements per second and source, admitted or not.
///
/// Twice [`REFUSED_SOURCE_BUDGET`], so a granted peer's burst gets more room than a stranger's.
/// The guard still bounds a granted peer's flood. (While `GotaTun` counted handshakes per source,
/// past 100 a granted peer met its cookie first; since #260 J1112 it sends cookies only when its
/// backlog says it is under load.)
pub(crate) const SOURCE_BUDGET: u32 = 2 * REFUSED_SOURCE_BUDGET;

/// Key agreements per second and network (IPv4 /24, IPv6 /48) that may end in a refusal.
///
/// One network can hold many sources: an IPv6 /48 is 65,536 /64s, and anyone with one routed
/// prefix can send from all of them without spoofing. Two sources' worth means a flood from one
/// network takes at most a fifth of [`UNKNOWN_SOURCE_BUDGET`], however many addresses it uses
/// (J713, #483).
pub(crate) const REFUSED_NETWORK_BUDGET: u32 = 2 * REFUSED_SOURCE_BUDGET;

/// Key agreements per second and network, admitted or not.
///
/// Twice [`REFUSED_NETWORK_BUDGET`], so peers behind one carrier NAT share room for a mass
/// reconnect. Known peer endpoints are not counted here (see [`UNKNOWN_SOURCE_BUDGET`]).
pub(crate) const NETWORK_BUDGET: u32 = 2 * REFUSED_NETWORK_BUDGET;

/// Key agreements the guard runs per second for the whole node.
///
/// It bounds floods from many (possibly spoofed) sources, and it bounds the per-window maps: a
/// source or network is recorded only when it spends from this budget. Sizing (J572, #483): one
/// key agreement costs about 26 µs of CPU (the flood bench below, on dev-02, aarch64), so the
/// guard spends at most about 2.6% of one core on them. A mesh of 4,096 hosts rekeys about 34
/// times a second (every two minutes per peer). If every peer reconnects at once from its known
/// endpoint, `WireGuard`'s five-second retry spreads 4,096 initiations over at most about eight
/// seconds of the reserve, fewer when the unknown share is idle; that sizing assumes no flood is
/// spending it at the same time (see [`RESERVED_BUDGET`] for what a flood leaves).
pub(crate) const NODE_BUDGET: u32 = 1_000;

/// The part of [`NODE_BUDGET`] that sources other than known peer endpoints may spend.
///
/// Half, because new joins and peers at unknown endpoints still need room, and known endpoints
/// alone use a few a second outside a mass reconnect. The other half is [`RESERVED_BUDGET`].
pub(crate) const UNKNOWN_SOURCE_BUDGET: u32 = NODE_BUDGET / 2;

/// The part of [`NODE_BUDGET`] reserved for known peer endpoints (an endpoint the coordinator
/// configured for a peer, or one `GotaTun` confirmed from a peer's authenticated traffic).
///
/// It is not one pool that any known endpoint may drain: each one may spend only its
/// [`reserve_share`] per window (J735, #483). So the reserve holds a known peer's initiation
/// against every flood that does not spoof that peer's exact endpoint, as long as the node knows
/// at most this many endpoints; the module doc states what happens with more.
pub(crate) const RESERVED_BUDGET: u32 = NODE_BUDGET - UNKNOWN_SOURCE_BUDGET;

/// How many key agreements one known endpoint may spend from [`RESERVED_BUDGET`] per window
/// while the node knows `known_endpoints` distinct ones (an endpoint both configured and
/// confirmed counts once, see [`distinct_endpoints`]).
///
/// The reserve divided evenly, so all shares together never exceed it: whatever a flood does
/// with the other endpoints, each one keeps its own. At least one, which a real peer's retry
/// every five seconds needs (so with more than [`RESERVED_BUDGET`] endpoints the shares can add
/// up to more than the reserve), and at most [`SOURCE_BUDGET`], what one source may spend anyway.
fn reserve_share(known_endpoints: usize) -> u8 {
    const _: () = assert!(
        SOURCE_BUDGET <= u8::MAX as u32,
        "a share must fit the u8 counters"
    );
    let even = RESERVED_BUDGET as usize / known_endpoints.max(1);
    u8::try_from(even.clamp(1, SOURCE_BUDGET as usize)).unwrap_or(u8::MAX)
}

/// How long one budget window lasts; every budget refills at its start.
const BUDGET_WINDOW: Duration = Duration::from_secs(1);

/// Who a per-source budget belongs to. IPv6 is keyed by /64, because one host can use every
/// address in its /64; IPv4-mapped IPv6 addresses (from the dual-stack socket) count as IPv4.
///
/// Link-local IPv6 addresses are the exception (J735 P3, #483): every one of them, on every
/// interface, sits in `fe80::/64`, so keying them by /64 would put every link-local peer the
/// node has into one budget. A link-local source is its interface identifier on its interface
/// (the scope id), and [`NetworkKey::Link`] bounds one on-link host that cycles addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SourceKey {
    V4([u8; 4]),
    V6([u8; 8]),
    /// A link-local source's low 64 bits, then its scope id (big-endian).
    LinkLocal([u8; 12]),
}

impl SourceKey {
    /// Key one packet source by its IPv4 address, its IPv6 /64, or its link-local address and
    /// interface.
    fn of(address: SocketAddr) -> Self {
        let scope = link_scope(address);
        match address.ip().to_canonical() {
            IpAddr::V4(v4) => Self::V4(v4.octets()),
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                if let Some(scope) = scope {
                    let mut key = [0; 12];
                    key[..8].copy_from_slice(&octets[8..]);
                    key[8..].copy_from_slice(&scope.to_be_bytes());
                    return Self::LinkLocal(key);
                }
                let mut prefix = [0; 8];
                prefix.copy_from_slice(&octets[..8]);
                Self::V6(prefix)
            }
        }
    }

    /// The network this source belongs to: its IPv4 /24 or its IPv6 /48.
    fn network(self) -> NetworkKey {
        match self {
            Self::V4(address) => {
                let mut network = [0; 3];
                network.copy_from_slice(&address[..3]);
                NetworkKey::V4(network)
            }
            Self::V6(prefix) => {
                let mut network = [0; 6];
                network.copy_from_slice(&prefix[..6]);
                NetworkKey::V6(network)
            }
            Self::LinkLocal(key) => {
                let mut scope = [0; 4];
                scope.copy_from_slice(&key[8..]);
                NetworkKey::Link(scope)
            }
        }
    }
}

/// The interface a link-local IPv6 source arrived on (its scope id), or `None` for any other
/// address. Only link-local addresses carry a meaningful scope, so other addresses ignore it
/// and match whatever scope id the socket reports for them.
fn link_scope(address: SocketAddr) -> Option<u32> {
    match address {
        SocketAddr::V6(v6) if v6.ip().is_unicast_link_local() => Some(v6.scope_id()),
        _ => None,
    }
}

/// Who a per-network budget belongs to: an IPv4 /24 or an IPv6 /48, the smallest blocks that
/// providers usually route to one customer, or one link for link-local sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum NetworkKey {
    V4([u8; 3]),
    V6([u8; 6]),
    /// Every link-local source on the interface with this scope id (big-endian): any host on
    /// the link can use any link-local address, as anyone with a /48 can use all its /64s.
    Link([u8; 4]),
}

/// One source's, or one network's, key agreements in the current window.
#[derive(Clone, Copy, Debug, Default)]
struct Spend {
    /// Every key agreement it caused.
    total: u32,
    /// Those that admitted nobody.
    refused: u32,
}

/// An exact peer endpoint in a compact, sortable form: the IPv6 (or IPv4-mapped) address, the
/// port, and the scope id of a link-local address (zero otherwise), 22 bytes with no padding.
type EndpointKey = [u8; 22];

/// Turn a socket address into its [`EndpointKey`], treating IPv4 and IPv4-mapped IPv6 alike. A
/// link-local endpoint is known only on its own interface (J735 P3, #483).
fn endpoint_key(address: SocketAddr) -> EndpointKey {
    let ip = match address.ip().to_canonical() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    let mut key = [0; 22];
    key[..16].copy_from_slice(&ip.octets());
    key[16..18].copy_from_slice(&address.port().to_be_bytes());
    key[18..].copy_from_slice(&link_scope(address).unwrap_or(0).to_be_bytes());
    key
}

/// Sort and deduplicate endpoints into a list [`slice::binary_search`] can look up.
fn endpoint_list(endpoints: impl IntoIterator<Item = SocketAddr>) -> Vec<EndpointKey> {
    let mut list: Vec<_> = endpoints.into_iter().map(endpoint_key).collect();
    list.sort_unstable();
    list.dedup();
    list.shrink_to_fit();
    list
}

/// What one successful [`Budget::spend`] charged, so a refusal can be charged to the same place.
#[derive(Clone, Copy, Debug)]
enum Charge {
    /// Paid from the reserve by the known endpoint in this slot (see
    /// [`PeerAdmission::known_slot`]).
    Reserve(usize),
    /// Paid from the unknown share by this source and its network.
    Shared {
        /// The source whose budget paid, charged again if the key agreement is refused.
        source: SourceKey,
        /// That source's network, charged the same way.
        network: NetworkKey,
    },
}

/// The key agreements spent in the current one-second window.
///
/// Invariants: `reserved` never exceeds [`RESERVED_BUDGET`] and `unknown` never exceeds
/// [`UNKNOWN_SOURCE_BUDGET`], so together they stay within [`NODE_BUDGET`]. `sources` and
/// `networks` hold at most [`UNKNOWN_SOURCE_BUDGET`] entries each, because an entry is inserted
/// only when it spends from the unknown share, and everything resets together. `endpoints` has
/// one counter per known endpoint slot, kept the same length as the two endpoint lists by
/// [`PeerAdmission`]'s setters (a slot past its end, which never happens, gets no reserve). Their
/// memory is therefore bounded whatever a flood sends (measured by the flood bench).
#[derive(Debug, Default)]
struct Budget {
    window_start: Option<Instant>,
    /// Key agreements spent this window from the reserve, by known endpoints within their share.
    reserved: u32,
    /// Key agreements spent this window from the unknown share, by every other source.
    unknown: u32,
    sources: HashMap<SourceKey, Spend>,
    networks: HashMap<NetworkKey, Spend>,
    /// Each known endpoint's spend from the reserve this window, indexed by its slot. A count
    /// at or above the endpoint's share means "no more from the reserve this window". A list
    /// replacement carries every count over to the endpoint's new slot (see
    /// [`carried_counts`]), so only the window's start refills them.
    endpoints: Vec<u8>,
}

impl Budget {
    /// Spend one key agreement for `source` at `now`, or say which budget is used up.
    ///
    /// `known` is the source's slot when it is exactly a known peer endpoint, and `share` the
    /// current [`reserve_share`]. A known endpoint within its share spends from the reserve and
    /// skips the source and network budgets;
    /// every other initiation, a known endpoint past its share included, is held to its source's
    /// and network's budgets and to [`UNKNOWN_SOURCE_BUDGET`].
    fn spend(
        &mut self,
        source: SocketAddr,
        known: Option<usize>,
        share: u8,
        now: Instant,
    ) -> Result<Charge, Refusal> {
        if self
            .window_start
            .is_none_or(|start| now.saturating_duration_since(start) >= BUDGET_WINDOW)
        {
            self.window_start = Some(now);
            self.reserved = 0;
            self.unknown = 0;
            self.sources.clear();
            self.networks.clear();
            self.endpoints.fill(0);
        }
        if let Some(slot) = known
            && let Some(spent) = self.endpoints.get_mut(slot)
            && *spent < share
            && self.reserved < RESERVED_BUDGET
        {
            *spent += 1;
            self.reserved += 1;
            return Ok(Charge::Reserve(slot));
        }
        let source = SourceKey::of(source);
        let spent = self.sources.get(&source).copied().unwrap_or_default();
        if spent.refused >= REFUSED_SOURCE_BUDGET || spent.total >= SOURCE_BUDGET {
            return Err(Refusal::SourceBudget);
        }
        let network = source.network();
        let spent = self.networks.get(&network).copied().unwrap_or_default();
        if spent.refused >= REFUSED_NETWORK_BUDGET || spent.total >= NETWORK_BUDGET {
            return Err(Refusal::NetworkBudget);
        }
        if self.unknown >= UNKNOWN_SOURCE_BUDGET {
            return Err(Refusal::NodeBudget);
        }
        self.unknown += 1;
        self.sources.entry(source).or_default().total += 1;
        self.networks.entry(network).or_default().total += 1;
        Ok(Charge::Shared { source, network })
    }

    /// Record that the key agreement `charge` paid for at `now` admitted nobody.
    ///
    /// A refusal at a known endpoint means a spoofed source or a stale key, so that endpoint
    /// gets nothing more from the reserve this window: a spoofer sending a stranger's key costs
    /// the reserve one key agreement per endpoint, not its whole share. A window that rolled
    /// over between [`Self::spend`] and this call has nothing to correct.
    fn refused(&mut self, charge: Charge, now: Instant) {
        if self
            .window_start
            .is_none_or(|start| now.saturating_duration_since(start) >= BUDGET_WINDOW)
        {
            return;
        }
        match charge {
            Charge::Reserve(slot) => {
                if let Some(spent) = self.endpoints.get_mut(slot) {
                    *spent = u8::MAX;
                }
            }
            Charge::Shared { source, network } => {
                if let Some(spent) = self.sources.get_mut(&source) {
                    spent.refused += 1;
                }
                if let Some(spent) = self.networks.get_mut(&network) {
                    spent.refused += 1;
                }
            }
        }
    }
}

/// Both sorted endpoint lists, as [`PeerAdmission`] lays out their slots: every configured
/// endpoint first, then every confirmed one.
#[derive(Clone, Copy)]
struct Lists<'a> {
    configured: &'a [EndpointKey],
    confirmed: &'a [EndpointKey],
}

/// A forward-only position in one sorted endpoint list, for merge-joins.
struct Cursor<'a> {
    keys: &'a [EndpointKey],
    at: usize,
}

impl<'a> Cursor<'a> {
    /// Start at the beginning of `keys`.
    fn new(keys: &'a [EndpointKey]) -> Self {
        Self { keys, at: 0 }
    }

    /// The index of `key` in the list, when it is there. Callers ask in ascending key order,
    /// so the cursor only moves forward and a whole join is linear.
    fn find(&mut self, key: &EndpointKey) -> Option<usize> {
        while self.keys.get(self.at).is_some_and(|here| here < key) {
            self.at += 1;
        }
        (self.keys.get(self.at) == Some(key)).then_some(self.at)
    }
}

/// The reserve counts for the slots of `new`, carried over from `counts`, the slots of `old`.
///
/// An endpoint in either old list keeps the count of its old slot, wherever it moves. An
/// endpoint in neither starts at `share`: spent for the rest of the window, so replacing a list
/// never hands out reserve the window had not already granted. A count missing from `counts`
/// (it is shorter than `old`'s slots only if a caller broke the layout) also counts as new. One
/// pass over each list, because every list is sorted (a merge-join, not a lookup per key).
fn carried_counts(old: Lists<'_>, counts: &[u8], new: Lists<'_>, share: u8) -> Vec<u8> {
    let mut carried = Vec::with_capacity(new.configured.len() + new.confirmed.len());
    for list in [new.configured, new.confirmed] {
        let mut configured = Cursor::new(old.configured);
        let mut confirmed = Cursor::new(old.confirmed);
        carried.extend(list.iter().map(|key| {
            configured
                .find(key)
                .or_else(|| {
                    confirmed
                        .find(key)
                        .map(|index| old.configured.len() + index)
                })
                .and_then(|slot| counts.get(slot).copied())
                .unwrap_or(share)
        }));
    }
    carried
}

/// How many different endpoints `lists` holds: every configured one, plus each confirmed one
/// that is not also configured. A peer whose confirmed endpoint is its configured one (the
/// usual case in a quiet mesh) is one endpoint with one share, not two (J754 P3, #483). One
/// merge-join pass, since both lists are sorted.
fn distinct_endpoints(lists: Lists<'_>) -> usize {
    let mut configured = Cursor::new(lists.configured);
    let also_configured = lists
        .confirmed
        .iter()
        .filter(|key| configured.find(key).is_some())
        .count();
    lists.configured.len() + lists.confirmed.len() - also_configured
}

/// Tells the node worker that a datagram arrived from a source `GotaTun` has not confirmed, so
/// it reads the peers' confirmed endpoints now instead of on a timer (#260 J1077 finding 3).
///
/// A peer's confirmed endpoint can only move after a datagram from the new address reaches the
/// receive task, so that task is the one place that knows a scan can find something. It keeps
/// a private copy of the confirmed list ([`Self::snapshot`]) and, per datagram, compares the
/// source with the previous one first and with the list second: no lock and no allocation. A
/// source in the list wakes nobody, which is every datagram of a steady mesh. An idle node
/// receives nothing from a new source, so it never scans.
///
/// The list is exactly what [`ConfirmedEndpointFeed`] last wrote into the guard; the guard
/// publishes it from [`PeerAdmission::set_confirmed_endpoints`]. A wake is a hint, never state:
/// a spurious one costs one scan, and the engine's own confirmed-endpoint signal
/// (`Device::confirmed_endpoint_changes`) covers every change this path cannot see, such as a
/// peer moving to an address another peer already confirmed (#260 J1253).
#[derive(Debug, Default)]
pub(crate) struct SourceWatch {
    /// Bumped when `confirmed` is replaced, so a receiver reloads its copy once per change.
    generation: AtomicU64,
    /// The confirmed endpoints in [`endpoint_list`] form. Held for one `Arc` clone, never across
    /// an `.await`.
    confirmed: Mutex<Arc<[EndpointKey]>>,
    /// Raised by the receive path for a source outside `confirmed`; the worker waits on it.
    pub(crate) wake: CoalescedWake,
}

impl SourceWatch {
    /// Publish a new confirmed list and its generation.
    fn publish(&self, list: &[EndpointKey]) {
        *self
            .confirmed
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = list.into();
        self.generation.fetch_add(1, AtomicOrdering::Release);
    }

    /// The current list and the generation it belongs to.
    fn snapshot(&self) -> (u64, Arc<[EndpointKey]>) {
        let list = Arc::clone(
            &self
                .confirmed
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        // Read after the list: a publish in between makes the generation newer than the list,
        // and the next batch reloads, which is harmless.
        (self.generation.load(AtomicOrdering::Acquire), list)
    }
}

/// One receive task's view of a [`SourceWatch`]: its copy of the list and the last source that
/// was in it.
struct SourceCursor {
    watch: Arc<SourceWatch>,
    generation: u64,
    list: Arc<[EndpointKey]>,
    /// The previous datagram's source when it was in `list`: a burst from one peer (the bulk
    /// case) costs one comparison per datagram.
    last_known: Option<SocketAddr>,
}

impl SourceCursor {
    fn new(watch: Arc<SourceWatch>) -> Self {
        let (generation, list) = watch.snapshot();
        Self {
            watch,
            generation,
            list,
            last_known: None,
        }
    }

    /// Reload the list if it changed. One relaxed-cost load per batch.
    fn sync(&mut self) {
        if self.watch.generation.load(AtomicOrdering::Acquire) != self.generation {
            (self.generation, self.list) = self.watch.snapshot();
            self.last_known = None;
        }
    }

    /// Note one datagram's source; wake the worker when no confirmed endpoint matches it.
    fn note(&mut self, source: SocketAddr) {
        if self.last_known == Some(source) {
            return;
        }
        if self.list.binary_search(&endpoint_key(source)).is_ok() {
            self.last_known = Some(source);
        } else {
            self.watch.wake.request();
        }
    }
}

/// Holds the live mesh identities allowed to reach `GotaTun`'s handshake queue and cookie check.
///
/// The peer list changes only after the device accepts a snapshot, while both key checks follow
/// live local-key rotation.
pub(crate) struct PeerAdmission {
    private_key: StaticSecret,
    public_key: X25519PublicKey,
    /// Checks MAC1 only; its own load limit is unused (see [`Self::check`]).
    mac1: RateLimiter,
    peers: BTreeSet<PublicKey>,
    /// The endpoints the coordinator configured for installed peers, sorted. With
    /// `confirmed_endpoints` these are the known endpoints that may spend the reserved part of
    /// the node budget (see [`UNKNOWN_SOURCE_BUDGET`]).
    configured_endpoints: Vec<EndpointKey>,
    /// The endpoints `GotaTun` confirmed from installed peers' authenticated traffic, sorted.
    confirmed_endpoints: Vec<EndpointKey>,
    /// Shows the receive task `confirmed_endpoints` and carries its wake to the worker.
    sources: Arc<SourceWatch>,
    /// The [`reserve_share`] for the current lists, worked out when a list changes so the
    /// receive path does no division.
    share: u8,
    /// Spent before every key agreement. A plain mutex: it is held for one map update and
    /// never across an `.await`.
    budget: Mutex<Budget>,
    /// The node's direct-path probes, once the engine socket exists (see [`crate::direct_probe`]).
    /// The receive task consumes probe-shaped datagrams here before `GotaTun` sees them.
    probes: Option<DirectProbes>,
    /// Key agreements this guard has run, counted in tests only, so a test can prove that a
    /// refused initiation never reached X25519 instead of inferring it from the verdict.
    #[cfg(test)]
    key_agreements: std::sync::atomic::AtomicU32,
}

impl PeerAdmission {
    /// Create an empty admission set for the node's current `WireGuard` identity.
    pub(crate) fn new(private_key: StaticSecret) -> Self {
        let public_key = X25519PublicKey::from(&private_key);
        let mac1 = RateLimiter::new(&public_key, u64::MAX);
        Self {
            private_key,
            public_key,
            mac1,
            peers: BTreeSet::new(),
            configured_endpoints: Vec::new(),
            confirmed_endpoints: Vec::new(),
            sources: Arc::default(),
            share: reserve_share(0),
            budget: Mutex::default(),
            probes: None,
            #[cfg(test)]
            key_agreements: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Replace the identities accepted by the most recently applied device snapshot.
    pub(crate) fn set_peers(&mut self, peers: impl IntoIterator<Item = PublicKey>) {
        self.peers = peers.into_iter().collect();
    }

    /// Replace the peers and their configured endpoints from the peer list the device just
    /// accepted: [`Self::set_peers`] and [`Self::set_configured_endpoints`] in one step.
    pub(crate) fn install(
        &mut self,
        keys: impl IntoIterator<Item = PublicKey>,
        peers: &[gotatun::device::Peer],
    ) {
        self.set_peers(keys);
        self.set_configured_endpoints(peers.iter().filter_map(|peer| peer.endpoint));
    }

    /// Replace the endpoints the coordinator configured for the installed peers.
    ///
    /// Call it with the same snapshot as [`Self::set_peers`]. Only exact addresses and ports
    /// count, so a flood has to spoof one to share a peer's reserved budget.
    pub(crate) fn set_configured_endpoints(
        &mut self,
        endpoints: impl IntoIterator<Item = SocketAddr>,
    ) {
        let configured = endpoint_list(endpoints);
        if configured != self.configured_endpoints {
            let old = std::mem::replace(&mut self.configured_endpoints, configured);
            self.carry_reserve_spend(Some(&old), None);
        }
    }

    /// Replace the endpoints `GotaTun` confirmed from installed peers' authenticated traffic.
    ///
    /// Use `GotaTun`'s `confirmed_endpoint`, never the send endpoint: an accepted initiation
    /// moves the send endpoint before its sender proves anything, so a replayed initiation could
    /// otherwise make an attacker's address known. The node workers call it through
    /// [`ConfirmedEndpointFeed`], which skips the write lock when nothing changed.
    pub(crate) fn set_confirmed_endpoints(
        &mut self,
        endpoints: impl IntoIterator<Item = SocketAddr>,
    ) {
        let confirmed = endpoint_list(endpoints);
        if confirmed != self.confirmed_endpoints {
            self.sources.publish(&confirmed);
            let old = std::mem::replace(&mut self.confirmed_endpoints, confirmed);
            self.carry_reserve_spend(None, Some(&old));
        }
    }

    /// Move every known endpoint's reserve count to its slot in the current lists, and work out
    /// the new share. `old_configured` and `old_confirmed` are the lists just replaced; `None`
    /// means that list did not change.
    ///
    /// A list change must never add reserve capacity within a window (J754 P2, #483): a mesh
    /// member can change its own confirmed endpoint four times a second, and if a change
    /// refilled the counts, every spoofed endpoint would get a fresh share each time. So a count
    /// follows its endpoint, and an endpoint new to the lists starts spent until the window
    /// ends; a real peer that just moved waits at most one second for its share and still has
    /// the unknown share meanwhile. Runs only when a list really changed, never per packet.
    fn carry_reserve_spend(
        &mut self,
        old_configured: Option<&[EndpointKey]>,
        old_confirmed: Option<&[EndpointKey]>,
    ) {
        let current = Lists {
            configured: &self.configured_endpoints,
            confirmed: &self.confirmed_endpoints,
        };
        self.share = reserve_share(distinct_endpoints(current));
        let budget = self
            .budget
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        budget.endpoints = carried_counts(
            Lists {
                configured: old_configured.unwrap_or(&self.configured_endpoints),
                confirmed: old_confirmed.unwrap_or(&self.confirmed_endpoints),
            },
            &budget.endpoints,
            current,
            self.share,
        );
    }

    /// Give the guard the node's direct-path probes. Without them probe-shaped datagrams pass to
    /// `GotaTun` unchanged (it drops them as invalid), which is how a node that does not probe
    /// behaves.
    pub(crate) fn set_probes(&mut self, probes: DirectProbes) {
        self.probes = Some(probes);
    }

    /// Whether `source` is exactly a known peer endpoint (configured or confirmed). The probe
    /// responder asks it, so only an installed peer's endpoint gets an answer; tests ask what a
    /// guard knows, including the Mac worker's live guard (J736).
    pub(crate) fn is_known_endpoint(&self, source: SocketAddr) -> bool {
        self.known_slot(source).is_some()
    }

    /// The slot of `source` among the known endpoints, when it is exactly one: its index in the
    /// configured list, or the configured list's length plus its index in the confirmed list.
    /// Slots index the per-endpoint reserve counters in [`Budget`]. A confirmed endpoint that is
    /// also configured always resolves to its configured slot, so its confirmed slot is a spare
    /// byte that is never spent and does not count toward the share.
    fn known_slot(&self, source: SocketAddr) -> Option<usize> {
        let key = endpoint_key(source);
        self.configured_endpoints
            .binary_search(&key)
            .ok()
            .or_else(|| {
                self.confirmed_endpoints
                    .binary_search(&key)
                    .ok()
                    .map(|index| self.configured_endpoints.len() + index)
            })
    }

    /// The watch the receive task and the node worker share (see [`SourceWatch`]).
    pub(crate) fn sources(&self) -> Arc<SourceWatch> {
        Arc::clone(&self.sources)
    }

    /// Replace the local identity after `GotaTun` accepts a key rotation.
    pub(crate) fn set_private_key(&mut self, private_key: StaticSecret) {
        self.public_key = X25519PublicKey::from(&private_key);
        self.mac1 = RateLimiter::new(&self.public_key, u64::MAX);
        self.private_key = private_key;
    }

    /// Mark only handshake initiations for cryptographic peer admission.
    pub(crate) fn needs_admission(packet: &Packet) -> bool {
        packet.as_ref().first() == Some(&WgPacketType::HandshakeInit.0)
    }

    /// Decide whether one packet from `source`, received at `now`, may reach `GotaTun`.
    ///
    /// Non-initiation traffic always passes. An initiation must carry a valid MAC1 and then
    /// fit its source's, its network's and the node's budgets before its sender's key is
    /// decrypted. `now` is a parameter so tests
    /// control the clock.
    /// # Errors
    /// Returns why an initiation was kept away from `GotaTun`; the caller drops it silently.
    pub(crate) fn check(
        &self,
        packet: &Packet,
        source: SocketAddr,
        now: Instant,
    ) -> Result<(), Refusal> {
        if !Self::needs_admission(packet) {
            return Ok(());
        }
        // Keep malformed traffic out of the static-key decryption path and out of the real
        // limiter. MAC1 does not depend on the source address. The validator is never told of a
        // handshake backlog, so it is never under load and only checks MAC1 (#260, J1112).
        let validation_source = SocketAddr::from(([0, 0, 0, 0], 0));
        let validation_packet: Packet = Packet::copy_from(packet.as_ref());
        let Ok(WgKind::HandshakeInit(initiation)) = self
            .mac1
            .verify_packet(validation_source, validation_packet)
        else {
            return Err(Refusal::InvalidMac);
        };
        // The budget is spent only after MAC1, so junk cannot use up a granted peer's budget.
        let known = self.known_slot(source);
        let charge = self
            .budget
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .spend(source, known, self.share, now)?;
        #[cfg(test)]
        self.key_agreements
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let verdict = match parse_handshake_anon(&self.private_key, &self.public_key, &initiation) {
            Ok(sender) if self.peers.contains(&PublicKey(sender.peer_static_public)) => Ok(()),
            Ok(_) => Err(Refusal::UnknownKey),
            Err(_) => Err(Refusal::Undecryptable),
        };
        if verdict.is_err() {
            self.budget
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .refused(charge, now);
        }
        verdict
    }
}

/// Hands the endpoints `GotaTun` confirmed for installed peers to a [`PeerAdmission`], but only
/// when they changed since the last hand-over.
///
/// Both node workers (Linux and macOS) keep one of these next to their device and call
/// [`Self::offer`] from a periodic scan of the device's peers. The receive task takes the
/// guard's read lock for every initiation, so the write lock is taken only on a real change: a
/// steady mesh costs one sorted list per scan and no lock at all.
///
/// Invariant: `last` is exactly the list most recently written into the guard this feed was
/// used with. Use one feed per guard; a feed shared by two guards would skip a write that the
/// second one still needs.
#[derive(Debug, Default)]
pub(crate) struct ConfirmedEndpointFeed {
    /// The confirmed endpoints last written into the guard, in [`endpoint_list`] form.
    last: Vec<EndpointKey>,
}

impl ConfirmedEndpointFeed {
    /// Offer the current confirmed endpoints: `GotaTun`'s `confirmed_endpoint` of each active
    /// installed peer. Never pass the send endpoint: an accepted initiation moves the send
    /// endpoint before its sender proves anything, so a replayed initiation could otherwise
    /// make an attacker's address known.
    ///
    /// Returns whether the guard's list was replaced. Order and duplicates do not matter: the
    /// list is compared after sorting, so IPv4 and IPv4-mapped forms of one endpoint are equal.
    pub(crate) async fn offer(
        &mut self,
        admission: &RwLock<PeerAdmission>,
        endpoints: impl IntoIterator<Item = SocketAddr>,
    ) -> bool {
        let endpoints: Vec<SocketAddr> = endpoints.into_iter().collect();
        let list = endpoint_list(endpoints.iter().copied());
        if list == self.last {
            return false;
        }
        // Through the setter, never by assigning the list: it also carries each endpoint's
        // reserve count to its new slot, so a roaming member cannot refill shares (J757).
        admission.write().await.set_confirmed_endpoints(endpoints);
        self.last = list;
        true
    }
}

/// The batch buffer of [`PeerAdmissionUdpReceiver`]. On Linux it also holds the kernel receive
/// stamp of every packet the guard kept, in the same order as the packets.
///
/// `GotaTun`'s receive-queue bound (D397) asks for a packet's stamp by its index in the batch
/// (`UdpRecv::rx_timestamp_ns`). The socket records stamps by the index each datagram had when
/// it arrived, and the guard removes refused initiations from the batch, which moves later
/// packets down. So the guard copies the stamps out when the batch arrives and moves them
/// together with their packets. A stamp of 0 means "unknown" and leaves the packet unjudged.
/// macOS uses only the socket buffer because its socket has no kernel receive stamps for AQM.
#[derive(Default)]
pub(crate) struct AdmissionRecvBuf {
    /// The socket's batch buffer, used only by the socket.
    socket_buf: <GotaUdpSocket as UdpRecv>::RecvManyBuf,
    /// `rx_stamps[i]` is the kernel receive time (ns) of `packets[i]` after the guard's pass.
    #[cfg(target_os = "linux")]
    rx_stamps: Vec<u64>,
}

/// Keeps the socket's batched receive path while filtering unregistered handshakes before `GotaTun`.
pub(crate) struct PeerAdmissionUdpReceiver {
    socket: GotaUdpSocket,
    admission: Arc<RwLock<PeerAdmission>>,
    /// Set on the first datagram (the constructor is not async): see [`SourceWatch`].
    sources: Option<SourceCursor>,
    /// The guard's probes, copied on the first datagram together with `sources`.
    probes: Option<DirectProbes>,
}

impl PeerAdmissionUdpReceiver {
    /// Wrap a bound receive socket with the node's shared admission state.
    pub(crate) fn new(socket: GotaUdpSocket, admission: Arc<RwLock<PeerAdmission>>) -> Self {
        Self {
            socket,
            admission,
            sources: None,
            probes: None,
        }
    }

    /// The address the wrapped socket is bound to, for the Mac tests that check socket reuse.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Run the guard on one received datagram, and tell the worker about a source it has not
    /// confirmed. Refused datagrams are not reported, so a flood of spoofed initiations cannot
    /// make the worker scan.
    async fn admits(&mut self, packet: &Packet, source: SocketAddr) -> bool {
        // A direct-path probe is the guard's own traffic: answer or match it, never forward it.
        if let Some(probes) = &self.probes
            && direct_probe::is_probe(packet.as_ref())
        {
            let known = self.admission.read().await.is_known_endpoint(source);
            probes.handle(packet.as_ref(), source, known).await;
            return false;
        }
        let admitted = !PeerAdmission::needs_admission(packet)
            || self
                .admission
                .read()
                .await
                .check(packet, source, Instant::now())
                .is_ok();
        if let (true, Some(cursor)) = (admitted, self.sources.as_mut()) {
            cursor.note(source);
        }
        admitted
    }

    /// Start or refresh this receiver's copy of the confirmed list before a batch.
    async fn sync_sources(&mut self) {
        if let Some(cursor) = self.sources.as_mut() {
            cursor.sync();
        } else {
            let admission = self.admission.read().await;
            self.probes.clone_from(&admission.probes);
            self.sources = Some(SourceCursor::new(admission.sources()));
        }
    }
}

impl UdpRecv for PeerAdmissionUdpReceiver {
    type RecvManyBuf = AdmissionRecvBuf;

    /// Receive one packet and suppress any valid-MAC1 initiation from an unknown peer key.
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        loop {
            let packet = self.socket.recv_from(pool).await?;
            self.sync_sources().await;
            let data = direct_probe::is_traffic(packet.0.as_ref());
            if self.admits(&packet.0, packet.1).await {
                if let (true, Some(probes)) = (data, &self.probes) {
                    probes.note_traffic();
                }
                return Ok(packet);
            }
        }
    }

    /// Preserve `GotaTun`'s socket batch receive and remove only rejected handshake initiations.
    ///
    /// On Linux each receive stamp moves with its packet (see [`AdmissionRecvBuf`]), so the bound
    /// judges the packet it timed. Packets already in `packets` keep the stamps an earlier call
    /// gave them; if that call failed part-way, the missing ones read as 0 (unknown).
    async fn recv_many_from(
        &mut self,
        recv_buf: &mut Self::RecvManyBuf,
        pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        let first_new_packet = packets.len();
        #[cfg(target_os = "linux")]
        let stamps = {
            let stamps = &mut recv_buf.rx_stamps;
            stamps.resize(first_new_packet, 0);
            stamps
        };
        self.socket
            .recv_many_from(&mut recv_buf.socket_buf, pool, packets)
            .await?;
        // The socket indexes its stamps by position in `packets`, which is still the arrival
        // order here. With the bound off it has none and every copy is 0.
        #[cfg(target_os = "linux")]
        stamps.extend(
            (first_new_packet..packets.len())
                .map(|index| GotaUdpSocket::rx_timestamp_ns(&recv_buf.socket_buf, index)),
        );
        self.sync_sources().await;
        let mut read = first_new_packet;
        let mut write = first_new_packet;
        let mut data = false;
        while read < packets.len() {
            let (packet, source) = &packets[read];
            data |= direct_probe::is_traffic(packet.as_ref());
            if self.admits(packet, *source).await {
                if write != read {
                    packets.swap(write, read);
                    #[cfg(target_os = "linux")]
                    stamps.swap(write, read);
                }
                write += 1;
            }
            read += 1;
        }
        packets.truncate(write);
        #[cfg(target_os = "linux")]
        stamps.truncate(write);
        // Only a batch with data carries the clock for the probe owner (see `note_traffic`): an
        // idle pair's 25 s keepalives and rekey handshakes must not start probe rounds (D81).
        if data && let Some(probes) = &self.probes {
            probes.note_traffic();
        }
        Ok(())
    }

    /// The kernel receive time of `packets[index]` from the last batch, after the guard's
    /// pass, or 0 if unknown. `GotaTun`'s queue bound reads it; without this override the
    /// trait's default 0 would turn the bound off for every node (#260, D397).
    #[cfg(target_os = "linux")]
    fn rx_timestamp_ns(recv_buf: &Self::RecvManyBuf, index: usize) -> u64 {
        recv_buf.rx_stamps.get(index).copied().unwrap_or(0)
    }

    /// Pass `GotaTun`'s idle-time release through to the socket, so an idle node gives its
    /// batch receive pages back. The trait's default does nothing, which would keep them.
    /// On Linux the stamp list is a few hundred bytes at most, so it stays allocated.
    fn release_recv_buf(&self, recv_buf: &mut Self::RecvManyBuf) {
        self.socket.release_recv_buf(&mut recv_buf.socket_buf);
    }

    /// Keep the underlying socket's UDP GRO support available to `GotaTun`.
    fn enable_udp_gro(&self) -> io::Result<()> {
        self.socket.enable_udp_gro()
    }
}

/// Checks the guard's verdicts and budgets, plus a hand-run flood cost bench.
#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "a broken fixture (bad address, key or clock) must stop the test loudly"
    )]
    use super::{
        NODE_BUDGET, PeerAdmission, REFUSED_NETWORK_BUDGET, REFUSED_SOURCE_BUDGET, Refusal,
        SOURCE_BUDGET, UNKNOWN_SOURCE_BUDGET,
    };
    use crate::policy::model::PublicKey;
    use gotatun::{
        noise::{Tunn, index_table::IndexTable, rate_limiter::RateLimiter},
        packet::Packet,
        x25519::{PublicKey as X25519PublicKey, StaticSecret},
    };
    use std::{
        net::SocketAddr,
        sync::{Arc, atomic::Ordering},
        time::{Duration, Instant},
    };

    /// A macOS receive guard has no timestamp storage because its socket never stamps packets.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_receive_guard_keeps_the_native_batch_buffer_size() {
        use super::{GotaUdpSocket, PeerAdmissionUdpReceiver, UdpRecv};
        let wrapped = size_of::<<PeerAdmissionUdpReceiver as UdpRecv>::RecvManyBuf>();
        let socket = size_of::<<GotaUdpSocket as UdpRecv>::RecvManyBuf>();
        eprintln!("macOS receive buffer sizes: wrapper={wrapped} socket={socket}");
        assert_eq!(wrapped, socket, "macOS has no receive stamps to retain");
    }

    /// The receive path wakes the worker for a source outside the confirmed list, and for no
    /// other (#260 J1077 finding 3): a steady mesh must cost the worker nothing.
    #[test]
    fn only_an_unconfirmed_source_wakes_the_worker() {
        use super::SourceCursor;
        let mut guard = PeerAdmission::new(StaticSecret::from(NODE));
        let known: SocketAddr = "192.0.2.10:51820".parse().expect("address");
        let moved: SocketAddr = "198.51.100.7:4000".parse().expect("address");
        let watch = guard.sources();
        let mut cursor = SourceCursor::new(Arc::clone(&watch));

        cursor.note(known);
        assert!(watch.wake.is_pending(), "nothing is confirmed yet");
        watch.wake.begin();

        guard.set_confirmed_endpoints([known]);
        cursor.sync();
        for _ in 0..1000 {
            cursor.note(known);
        }
        assert!(!watch.wake.is_pending(), "a confirmed source is silent");

        cursor.note(moved);
        assert!(watch.wake.is_pending(), "a source nobody confirmed wakes");
        watch.wake.begin();

        guard.set_confirmed_endpoints([moved]);
        cursor.sync();
        cursor.note(moved);
        assert!(
            !watch.wake.is_pending(),
            "the new list is silent for its source"
        );
        cursor.note(known);
        assert!(
            watch.wake.is_pending(),
            "a source that left the list wakes again, though it was cached as known"
        );
    }

    /// How many X25519 key agreements `admission` has run so far.
    fn key_agreements(admission: &PeerAdmission) -> u32 {
        admission.key_agreements.load(Ordering::Relaxed)
    }

    /// The node's fixed test identity.
    const NODE: [u8; 32] = [0x31; 32];

    /// Format one MAC1-valid handshake initiation from `sender` to the test node.
    fn initiation(sender: [u8; 32]) -> Vec<u8> {
        let node_public = X25519PublicKey::from(&StaticSecret::from(NODE));
        let sender = StaticSecret::from(sender);
        let sender_public = X25519PublicKey::from(&sender);
        let mut initiator = Tunn::new(
            sender,
            node_public,
            None,
            None,
            IndexTable::from_os_rng(),
            Arc::new(RateLimiter::new(&sender_public, 100)),
        );
        initiator
            .format_handshake_initiation(false)
            .expect("a MAC1-valid initiation")
            .into_bytes()
            .as_ref()
            .to_vec()
    }

    /// Parse a test source address.
    fn source(text: &str) -> SocketAddr {
        text.parse().expect("test source address")
    }

    /// Source `index` in `<first>.x.y.7`: a different IPv4 /24 for every index below 65,536,
    /// so only the per-node budgets apply.
    fn own_network(first: u8, index: u32) -> SocketAddr {
        let [_, _, high, low] = index.to_be_bytes();
        SocketAddr::from(([first, high, low, 7], 40000))
    }

    /// J555 F1 (#483): the admission guard must not do unbounded X25519 work per source.
    ///
    /// Anyone who knows a node's public key can compute MAC1. Before J510c, `GotaTun`'s limiter
    /// answered the 101st initiation from one address within a second with a cookie, so a
    /// flood cost one MAC check each and never reached Diffie-Hellman. The J510c guard ran
    /// `parse_handshake_anon` (an X25519 and an AEAD open) for every valid-MAC1 initiation,
    /// before `GotaTun`'s limiter and inside the single UDP receive task, so one unspoofed sender
    /// could drive unbounded key agreement on the path that carries every peer's data. Past
    /// `GotaTun`'s own 100-per-second budget, the guard must drop without decrypting.
    /// `Refusal::UnknownKey` is the only verdict that proves the key exchange ran.
    #[test]
    fn j555_admission_guard_stops_x25519_after_the_handshake_budget() {
        let admission = PeerAdmission::new(StaticSecret::from(NODE));
        let flood = initiation([0x55; 32]);
        let sender = source("198.51.100.7:40000");
        let now = Instant::now();
        for _ in 0..100 {
            assert_eq!(
                admission.check(&Packet::copy_from(&flood), sender, now),
                Err(Refusal::UnknownKey)
            );
        }
        let next = admission.check(&Packet::copy_from(&flood), sender, now);
        assert_ne!(
            next,
            Err(Refusal::UnknownKey),
            "after 100 initiations in one second the guard still ran X25519 for the next one"
        );
        assert!(next.is_err(), "an unknown key must never be admitted");
    }

    /// J648 (#483): every budget is checked before X25519, counted directly.
    ///
    /// The test above infers "no key agreement" from the verdict. This one counts the key
    /// agreements the guard runs and requires that refusals past the per-source budget, past the
    /// node budget, and for a bad MAC1 add none at all, for a flood far larger than any budget.
    #[test]
    fn refusals_past_any_budget_run_no_key_agreement() {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        // Known endpoints for the last part, listed before the window starts: an endpoint that
        // joins the lists mid-window starts it spent.
        let known: Vec<_> = (0..NODE_BUDGET - UNKNOWN_SOURCE_BUDGET + 10_000)
            .map(|index| own_network(20, index))
            .collect();
        admission.set_configured_endpoints(known.iter().copied());
        let flood = initiation([0x55; 32]);
        let now = Instant::now();
        let one_source = source("198.51.100.7:40000");
        for _ in 0..REFUSED_SOURCE_BUDGET {
            assert_eq!(
                admission.check(&Packet::copy_from(&flood), one_source, now),
                Err(Refusal::UnknownKey)
            );
        }
        assert_eq!(key_agreements(&admission), REFUSED_SOURCE_BUDGET);
        for _ in 0..10_000 {
            assert_eq!(
                admission.check(&Packet::copy_from(&flood), one_source, now),
                Err(Refusal::SourceBudget)
            );
        }
        assert_eq!(
            key_agreements(&admission),
            REFUSED_SOURCE_BUDGET,
            "a source past its budget caused X25519 work"
        );

        // Spoofed sources, each in its own /24, until the unknown-source share is spent.
        for index in 0..UNKNOWN_SOURCE_BUDGET - REFUSED_SOURCE_BUDGET {
            assert_eq!(
                admission.check(&Packet::copy_from(&flood), own_network(18, index), now),
                Err(Refusal::UnknownKey)
            );
        }
        assert_eq!(key_agreements(&admission), UNKNOWN_SOURCE_BUDGET);
        for index in 0..10_000_u32 {
            assert_eq!(
                admission.check(&Packet::copy_from(&flood), own_network(19, index), now),
                Err(Refusal::NodeBudget)
            );
        }
        assert_eq!(
            key_agreements(&admission),
            UNKNOWN_SOURCE_BUDGET,
            "a spoofed-source flood past the unknown-source share caused X25519 work"
        );
        // A flood that spoofs known endpoints exactly can spend the reserve, and no more.
        for (index, spoofed) in known.iter().enumerate() {
            let verdict = admission.check(&Packet::copy_from(&flood), *spoofed, now);
            if index < (NODE_BUDGET - UNKNOWN_SOURCE_BUDGET) as usize {
                assert_eq!(verdict, Err(Refusal::UnknownKey));
            } else {
                assert_eq!(verdict, Err(Refusal::NodeBudget));
            }
        }
        assert_eq!(
            key_agreements(&admission),
            NODE_BUDGET,
            "a flood past the node budget caused X25519 work"
        );

        let mut forged = flood.clone();
        forged[120] ^= 1;
        let later = now + Duration::from_secs(1);
        assert_eq!(
            admission.check(&Packet::copy_from(&forged), one_source, later),
            Err(Refusal::InvalidMac)
        );
        assert_eq!(
            key_agreements(&admission),
            NODE_BUDGET,
            "a bad MAC1 reached X25519"
        );
    }

    /// A registered peer's initiation still reaches `GotaTun`, and other packet types pass.
    #[test]
    fn installed_peers_pass_and_other_packets_are_untouched() {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        let peer = [0x66; 32];
        admission.set_peers([PublicKey(
            *X25519PublicKey::from(&StaticSecret::from(peer)).as_bytes(),
        )]);
        let now = Instant::now();
        let sender = source("198.51.100.8:40000");
        assert_eq!(
            admission.check(&Packet::copy_from(&initiation(peer)), sender, now),
            Ok(())
        );
        let data = [4_u8, 0, 0, 0, 1, 2, 3, 4];
        assert_eq!(
            admission.check(&Packet::copy_from(&data), sender, now),
            Ok(())
        );
        let mut forged = initiation(peer);
        forged[120] ^= 1;
        assert_eq!(
            admission.check(&Packet::copy_from(&forged), sender, now),
            Err(Refusal::InvalidMac)
        );
    }

    /// Past the source budget the guard refuses without key agreement, and the next window
    /// refills it. IPv6 sources share a budget per /64; IPv4-mapped sources count as IPv4.
    #[test]
    fn the_source_budget_is_per_ipv4_address_or_ipv6_prefix_and_refills() {
        let admission = PeerAdmission::new(StaticSecret::from(NODE));
        let flood = initiation([0x55; 32]);
        let now = Instant::now();
        let spend =
            |text: &str, at: Instant| admission.check(&Packet::copy_from(&flood), source(text), at);
        for index in 0..REFUSED_SOURCE_BUDGET {
            let address = format!("[2001:db8:1:2::{:x}]:40000", index + 1);
            assert_eq!(spend(&address, now), Err(Refusal::UnknownKey));
        }
        assert_eq!(
            spend("[2001:db8:1:2:ffff::9]:1", now),
            Err(Refusal::SourceBudget),
            "one /64 shares one source budget"
        );
        assert_eq!(
            spend("[2001:db8:1:3::1]:40000", now),
            Err(Refusal::UnknownKey),
            "another /64 has its own budget"
        );
        for _ in 0..REFUSED_SOURCE_BUDGET {
            assert_eq!(
                spend("[::ffff:192.0.2.1]:40000", now),
                Err(Refusal::UnknownKey)
            );
        }
        assert_eq!(
            spend("192.0.2.1:40001", now),
            Err(Refusal::SourceBudget),
            "an IPv4-mapped source and its IPv4 form share one budget"
        );
        assert_eq!(
            spend("[::ffff:192.0.2.2]:40000", now),
            Err(Refusal::UnknownKey),
            "IPv4-mapped sources are not grouped by the mapped /64"
        );
        assert_eq!(
            spend("192.0.2.1:40001", now + Duration::from_secs(1)),
            Err(Refusal::UnknownKey),
            "the next window refills the source budget"
        );
    }

    /// A granted peer's burst passes the guard up to twice the refusal budget, and the guard
    /// stops it there. A stranger on the same source is still cut off after 100 refusals.
    #[test]
    fn a_granted_peer_burst_gets_twice_a_strangers_budget() {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        let peer = [0x66; 32];
        admission.set_peers([PublicKey(
            *X25519PublicKey::from(&StaticSecret::from(peer)).as_bytes(),
        )]);
        let granted = initiation(peer);
        let shared = source("198.51.100.20:40000");
        let now = Instant::now();
        for _ in 0..SOURCE_BUDGET {
            assert_eq!(
                admission.check(&Packet::copy_from(&granted), shared, now),
                Ok(())
            );
        }
        assert_eq!(
            admission.check(&Packet::copy_from(&granted), shared, now),
            Err(Refusal::SourceBudget)
        );
        let stranger = initiation([0x55; 32]);
        let other = source("198.51.100.21:40000");
        for _ in 0..REFUSED_SOURCE_BUDGET {
            assert_eq!(
                admission.check(&Packet::copy_from(&stranger), other, now),
                Err(Refusal::UnknownKey)
            );
        }
        assert_eq!(
            admission.check(&Packet::copy_from(&granted), other, now),
            Err(Refusal::SourceBudget),
            "a source that used its refusals is cut off for everyone on it"
        );
    }

    /// A spoofed-source flood stops at the unknown-source share without key agreement. A
    /// granted peer at a known endpoint still gets in from the reserve, and one at an unknown
    /// endpoint is admitted again once the window refills.
    #[test]
    fn the_node_budget_bounds_floods_from_many_sources() {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        let peer = [0x66; 32];
        admission.set_peers([PublicKey(
            *X25519PublicKey::from(&StaticSecret::from(peer)).as_bytes(),
        )]);
        let known_source = source("192.0.2.44:51000");
        admission.set_configured_endpoints([known_source]);
        let flood = initiation([0x55; 32]);
        let now = Instant::now();
        for index in 0..UNKNOWN_SOURCE_BUDGET {
            assert_eq!(
                admission.check(&Packet::copy_from(&flood), own_network(18, index), now),
                Err(Refusal::UnknownKey)
            );
        }
        assert_eq!(
            admission.check(&Packet::copy_from(&flood), own_network(19, 0), now),
            Err(Refusal::NodeBudget)
        );
        let granted = initiation(peer);
        let peer_source = source("203.0.113.9:51000");
        assert_eq!(
            admission.check(&Packet::copy_from(&granted), peer_source, now),
            Err(Refusal::NodeBudget)
        );
        assert_eq!(
            admission.check(&Packet::copy_from(&granted), known_source, now),
            Ok(()),
            "the reserve admits a granted peer at its known endpoint"
        );
        assert_eq!(
            admission.check(
                &Packet::copy_from(&granted),
                peer_source,
                now + Duration::from_secs(1)
            ),
            Ok(())
        );
    }

    /// J713 (#483): many sources inside one network share that network's budget. Sixteen IPv6
    /// /64s of one /48, or every address of one IPv4 /24, stop at [`REFUSED_NETWORK_BUDGET`]
    /// refusals without key agreement; another network, and a known endpoint inside the flooded
    /// one, are unaffected.
    #[test]
    fn sources_in_one_network_share_its_budget() {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        let peer = [0x66; 32];
        admission.set_peers([PublicKey(
            *X25519PublicKey::from(&StaticSecret::from(peer)).as_bytes(),
        )]);
        let known_v6 = source("[2001:db8:77:ff::9]:51000");
        let known_v4 = source("198.51.100.250:51000");
        admission.set_configured_endpoints([known_v6, known_v4]);
        let flood = initiation([0x55; 32]);
        let now = Instant::now();
        for index in 0..REFUSED_NETWORK_BUDGET {
            let from = source(&format!("[2001:db8:77:{:x}::1]:40000", index % 16));
            assert_eq!(
                admission.check(&Packet::copy_from(&flood), from, now),
                Err(Refusal::UnknownKey)
            );
        }
        assert_eq!(
            admission.check(
                &Packet::copy_from(&flood),
                source("[2001:db8:77:20::1]:1"),
                now
            ),
            Err(Refusal::NetworkBudget),
            "a fresh /64 in the same /48 shares the /48's budget"
        );
        for index in 0..REFUSED_NETWORK_BUDGET {
            let from =
                SocketAddr::from(([198, 51, 100, u8::try_from(index % 200).expect("fits")], 1));
            assert_eq!(
                admission.check(&Packet::copy_from(&flood), from, now),
                Err(Refusal::UnknownKey)
            );
        }
        assert_eq!(
            admission.check(&Packet::copy_from(&flood), source("198.51.100.201:1"), now),
            Err(Refusal::NetworkBudget),
            "a fresh address in the same /24 shares the /24's budget"
        );
        assert_eq!(
            admission.check(
                &Packet::copy_from(&flood),
                source("[2001:db8:78::1]:1"),
                now
            ),
            Err(Refusal::UnknownKey),
            "another /48 has its own budget"
        );
        let granted = initiation(peer);
        assert_eq!(
            admission.check(&Packet::copy_from(&granted), known_v6, now),
            Ok(())
        );
        assert_eq!(
            admission.check(
                &Packet::copy_from(&granted),
                source("[::ffff:198.51.100.250]:51000"),
                now
            ),
            Ok(()),
            "a known IPv4 endpoint matches its IPv4-mapped form"
        );
        assert_eq!(
            admission.check(
                &Packet::copy_from(&granted),
                source("198.51.100.250:51001"),
                now
            ),
            Err(Refusal::NetworkBudget),
            "only the exact known port skips the network budget"
        );
    }

    /// A link-local IPv6 source on interface `scope`: `fe80::<host>`.
    fn link_local(host: u16, scope: u32) -> SocketAddr {
        let ip = std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, host);
        SocketAddr::V6(std::net::SocketAddrV6::new(ip, 51820, 0, scope))
    }

    /// J735 P3 (#483): link-local sources are told apart by their interface (scope id). Every
    /// link-local address shares the prefix `fe80::/64`, so keying them like global ones put
    /// every link-local peer on every link into one source budget. A link-local source is its
    /// full address on its link, and one link shares one network budget, the way an IPv4 /24
    /// does; the known-endpoint match needs the scope too.
    #[test]
    fn link_local_sources_are_told_apart_by_interface() {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        let peer = [0x66; 32];
        admission.set_peers([PublicKey(
            *X25519PublicKey::from(&StaticSecret::from(peer)).as_bytes(),
        )]);
        let flood = initiation([0x55; 32]);
        let granted = initiation(peer);
        let now = Instant::now();
        let check = |packet: &[u8], from: SocketAddr| {
            admission.check(&Packet::copy_from(packet), from, now)
        };
        for _ in 0..REFUSED_SOURCE_BUDGET {
            assert_eq!(check(&flood, link_local(1, 2)), Err(Refusal::UnknownKey));
        }
        assert_eq!(
            check(&flood, link_local(1, 2)),
            Err(Refusal::SourceBudget),
            "one link-local source still has one budget"
        );
        assert_eq!(
            check(&granted, link_local(1, 3)),
            Ok(()),
            "the same address on another interface is another source"
        );
        assert_eq!(
            check(&granted, link_local(7, 2)),
            Ok(()),
            "another host on the same link is another source"
        );
        // One host on a link can use any link-local address: the link's network budget bounds it.
        for host in 0..u16::try_from(REFUSED_NETWORK_BUDGET - REFUSED_SOURCE_BUDGET).expect("fits")
        {
            assert_eq!(
                check(&flood, link_local(100 + host, 2)),
                Err(Refusal::UnknownKey)
            );
        }
        assert_eq!(
            check(&granted, link_local(9, 2)),
            Err(Refusal::NetworkBudget),
            "a link shares one network budget"
        );
        assert_eq!(
            check(&granted, link_local(9, 3)),
            Ok(()),
            "another link has its own network budget"
        );

        let mut admission = admission;
        admission.set_configured_endpoints([link_local(9, 2)]);
        assert!(admission.is_known_endpoint(link_local(9, 2)));
        assert!(
            !admission.is_known_endpoint(link_local(9, 3)),
            "a known link-local endpoint is known only on its own interface"
        );
    }

    /// Endpoints `GotaTun` confirmed count as known exactly like configured ones, and each list
    /// is replaced, not merged, by its next update.
    #[test]
    fn confirmed_endpoints_are_known_and_replaced() {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        let confirmed = source("192.0.2.77:41000");
        assert!(!admission.is_known_endpoint(confirmed));
        admission.set_confirmed_endpoints([confirmed]);
        assert!(admission.is_known_endpoint(confirmed));
        assert!(admission.is_known_endpoint(source("[::ffff:192.0.2.77]:41000")));
        admission.set_configured_endpoints([source("192.0.2.78:41000")]);
        assert!(
            admission.is_known_endpoint(confirmed),
            "configured updates keep confirmed ones"
        );
        admission.set_confirmed_endpoints([]);
        assert!(!admission.is_known_endpoint(confirmed));
        assert!(admission.is_known_endpoint(source("192.0.2.78:41000")));
    }

    /// Spend the whole unknown-source share at `now` with a stranger's key from 500 networks, so
    /// any later initiation in that window is admitted only from the reserve.
    fn spend_unknown_share(admission: &PeerAdmission, now: Instant) {
        let flood = initiation([0x55; 32]);
        for index in 0..UNKNOWN_SOURCE_BUDGET {
            assert_eq!(
                admission.check(&Packet::copy_from(&flood), own_network(18, index), now),
                Err(Refusal::UnknownKey)
            );
        }
    }

    /// J754 P2/P3 (#483): replacing an endpoint list keeps each endpoint's reserve count with
    /// that endpoint, not with its slot, and an endpoint new to the lists starts the window spent.
    ///
    /// `b05743838` zeroed every count on a replacement, so a member that changed its own
    /// confirmed endpoint four times a second handed every spoofed endpoint a fresh share each
    /// time. Here the list keeps its length while `B` moves from slot 1 to slot 0, so a fix that
    /// keyed counts by slot, or left them alone, fails too.
    #[test]
    fn a_list_replacement_carries_each_count_by_endpoint() {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        let peer = [0x66; 32];
        admission.set_peers([PublicKey(
            *X25519PublicKey::from(&StaticSecret::from(peer)).as_bytes(),
        )]);
        let [a, b, c, d] = [
            "192.0.2.10:1",
            "192.0.2.20:1",
            "192.0.2.30:1",
            "192.0.2.40:1",
        ]
        .map(source);
        admission.set_configured_endpoints([b, c, d]);
        let granted = initiation(peer);
        let now = Instant::now();
        let share = super::reserve_share(3);
        for _ in 0..share {
            assert_eq!(
                admission.check(&Packet::copy_from(&granted), b, now),
                Ok(())
            );
        }
        spend_unknown_share(&admission, now);
        assert_eq!(
            admission.check(&Packet::copy_from(&granted), b, now),
            Err(Refusal::NodeBudget),
            "B spent its share"
        );

        admission.set_configured_endpoints([a, b, d]);
        let check = |admission: &PeerAdmission, from| {
            admission.check(&Packet::copy_from(&granted), from, now)
        };
        assert_eq!(
            check(&admission, b),
            Err(Refusal::NodeBudget),
            "a replacement must not refill B's share"
        );
        assert_eq!(
            check(&admission, a),
            Err(Refusal::NodeBudget),
            "an endpoint new to the lists starts the window spent"
        );
        assert_eq!(check(&admission, d), Ok(()), "D kept its unspent share");
        admission.set_confirmed_endpoints([b]);
        assert_eq!(
            check(&admission, b),
            Err(Refusal::NodeBudget),
            "B confirmed as well is still the same spent endpoint"
        );
        let next = now + Duration::from_secs(1);
        assert_eq!(
            admission.check(&Packet::copy_from(&granted), a, next),
            Ok(()),
            "the next window gives A its share"
        );
    }

    /// J778 (#483): the confirmed-endpoint feed both workers use goes through the setter, so a
    /// roamed-to endpoint starts the window spent, as with [`PeerAdmission::set_confirmed_endpoints`].
    ///
    /// A feed that assigned the new list into the guard directly would leave the per-slot counts
    /// and the share where they were: a confirmed endpoint would get no reserve slot at all, or
    /// take over another endpoint's count, so the reserve would stop following the list.
    #[tokio::test]
    async fn the_confirmed_feed_starts_a_roamed_to_endpoint_spent() {
        let admission = tokio::sync::RwLock::new(PeerAdmission::new(StaticSecret::from(NODE)));
        let peer = [0x66; 32];
        admission.write().await.set_peers([PublicKey(
            *X25519PublicKey::from(&StaticSecret::from(peer)).as_bytes(),
        )]);
        let [old, roamed] = ["192.0.2.20:1", "192.0.2.10:1"].map(source);
        let mut feed = super::ConfirmedEndpointFeed::default();
        assert!(
            feed.offer(&admission, [old]).await,
            "the first list is written"
        );
        assert!(
            !feed.offer(&admission, [old, old]).await,
            "an unchanged list takes no write lock"
        );
        let now = Instant::now();
        spend_unknown_share(&*admission.read().await, now);

        assert!(
            feed.offer(&admission, [roamed]).await,
            "the roam is written"
        );
        let granted = initiation(peer);
        let guard = admission.read().await;
        assert!(guard.is_known_endpoint(roamed));
        assert_eq!(
            guard.check(&Packet::copy_from(&granted), roamed, now),
            Err(Refusal::NodeBudget),
            "a roamed-to endpoint must start the window spent"
        );
        // Spend the next window's unknown share first, so only the reserve can admit it.
        let next = now + Duration::from_secs(1);
        spend_unknown_share(&guard, next);
        assert_eq!(
            guard.check(&Packet::copy_from(&granted), roamed, next),
            Ok(()),
            "the next window gives it its share of the reserve"
        );
    }

    /// J754 P3 (#483): a spoofer sending a stranger's key from k known endpoints costs the
    /// reserve exactly k key agreements per window, because a refusal ends that endpoint's share.
    /// Past that, each one is an ordinary source with its own refused budget.
    #[test]
    fn a_refused_key_agreement_ends_the_endpoints_share() {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        let spoofed: Vec<_> = (0..5).map(|k| own_network(20, k)).collect();
        admission
            .set_configured_endpoints(spoofed.iter().copied().chain([source("203.0.113.9:51000")]));
        let flood = initiation([0x55; 32]);
        let now = Instant::now();
        for from in &spoofed {
            for _ in 0..300 {
                let _ = admission.check(&Packet::copy_from(&flood), *from, now);
            }
        }
        let reserved = admission.budget.lock().expect("budget lock").reserved;
        assert_eq!(
            reserved, 5,
            "one reserve key agreement per spoofed endpoint"
        );
        assert_eq!(
            key_agreements(&admission),
            5 * (1 + REFUSED_SOURCE_BUDGET),
            "each endpoint then spends only its own source's refused budget"
        );
    }

    /// J754 P3 (#483): an endpoint that is both configured and confirmed (the usual case in a
    /// quiet mesh) takes one share of the reserve, not two. With 250 peers so listed the share is
    /// the reserve over 250, two key agreements, not one.
    #[test]
    fn an_endpoint_in_both_lists_takes_one_share() {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        let peer = [0x66; 32];
        admission.set_peers([PublicKey(
            *X25519PublicKey::from(&StaticSecret::from(peer)).as_bytes(),
        )]);
        let known: Vec<_> = (0..250).map(|index| own_network(20, index)).collect();
        admission.set_configured_endpoints(known.iter().copied());
        admission.set_confirmed_endpoints(known.iter().copied());
        let now = Instant::now();
        spend_unknown_share(&admission, now);
        let granted = initiation(peer);
        let share = super::reserve_share(250);
        assert_eq!(share, 2);
        for _ in 0..share {
            assert_eq!(
                admission.check(&Packet::copy_from(&granted), known[0], now),
                Ok(())
            );
        }
        assert_eq!(
            admission.check(&Packet::copy_from(&granted), known[0], now),
            Err(Refusal::NodeBudget)
        );
    }

    /// The shared feed both node workers scan into: a changed set replaces the guard's
    /// confirmed list, while the same set in another order or address form takes no write lock.
    #[tokio::test]
    async fn the_confirmed_endpoint_feed_writes_only_changes() {
        let admission = tokio::sync::RwLock::new(PeerAdmission::new(StaticSecret::from(NODE)));
        let mut feed = super::ConfirmedEndpointFeed::default();
        let roamed = source("192.0.2.77:41000");
        let other = source("[2001:db8::7]:41000");
        assert!(
            !feed.offer(&admission, []).await,
            "empty to empty is no change"
        );
        assert!(feed.offer(&admission, [roamed, other]).await);
        assert!(admission.read().await.is_known_endpoint(roamed));
        assert!(admission.read().await.is_known_endpoint(other));
        // Held read lock: a write here would deadlock, so `offer` must not try one.
        let reader = admission.read().await;
        let unchanged = tokio::time::timeout(
            Duration::from_secs(1),
            feed.offer(
                &admission,
                [other, source("[::ffff:192.0.2.77]:41000"), roamed],
            ),
        )
        .await
        .expect("an unchanged set took the write lock");
        assert!(!unchanged);
        drop(reader);
        assert!(feed.offer(&admission, [other]).await);
        assert!(
            !admission.read().await.is_known_endpoint(roamed),
            "a peer that roamed away loses its old endpoint"
        );
    }

    /// CPU per received initiation under a flood (J572, J648, #483); run by hand, it asserts nothing.
    ///
    /// `cargo test -p infraternal-plugin-mesh --features agent --release --lib
    /// bench_handshake_flood_cpu -- --ignored --nocapture` measures this thread's CPU time:
    /// - per key agreement: initiations that fit the budget, each one running X25519;
    /// - per rejected packet: initiations past the budget, which stop after MAC1;
    /// - per initiation in a real-time flood, once from one source and once from 65,536 spoofed
    ///   sources, with the key agreements counted.
    ///
    /// The receive task is single-threaded, so CPU per initiation sets the flood rate that
    /// saturates it.
    #[test]
    #[ignore = "measurement; run by hand on a build VM"]
    fn bench_handshake_flood_cpu() {
        /// This thread's consumed CPU time.
        fn thread_cpu() -> Duration {
            let time = nix::time::clock_gettime(nix::time::ClockId::CLOCK_THREAD_CPUTIME_ID)
                .expect("thread CPU clock");
            Duration::from(time)
        }
        /// Microseconds of CPU per packet.
        fn per_packet(cpu: Duration, packets: u32) -> f64 {
            cpu.as_secs_f64() * 1e6 / f64::from(packets)
        }
        let flood = initiation([0x55; 32]);

        // Within budget: a fresh window per packet, so every one runs X25519.
        let admission = PeerAdmission::new(StaticSecret::from(NODE));
        let start = Instant::now();
        let fresh = 2_000_u32;
        let cpu = thread_cpu();
        for index in 0..fresh {
            let at = start + Duration::from_secs(u64::from(index));
            let verdict = admission.check(&Packet::copy_from(&flood), source("198.18.0.1:1"), at);
            assert_eq!(verdict, Err(Refusal::UnknownKey));
        }
        let cpu = thread_cpu().saturating_sub(cpu);
        println!(
            "J648 within budget: {fresh} initiations, {} key agreements, {:.2} us CPU each",
            key_agreements(&admission),
            per_packet(cpu, fresh)
        );

        // Past budget: one window, budget already spent, so every packet is refused after MAC1.
        let admission = PeerAdmission::new(StaticSecret::from(NODE));
        let now = Instant::now();
        let one = source("198.18.0.1:1");
        for _ in 0..REFUSED_SOURCE_BUDGET {
            let _ = admission.check(&Packet::copy_from(&flood), one, now);
        }
        let before = key_agreements(&admission);
        let rejected = 200_000_u32;
        let cpu = thread_cpu();
        for _ in 0..rejected {
            let verdict = admission.check(&Packet::copy_from(&flood), one, now);
            assert_eq!(verdict, Err(Refusal::SourceBudget));
        }
        let cpu = thread_cpu().saturating_sub(cpu);
        println!(
            "J648 past budget: {rejected} rejected initiations, {} key agreements, \
             {:.3} us CPU per rejected packet",
            key_agreements(&admission) - before,
            per_packet(cpu, rejected)
        );

        // Limiter memory at its bound: the per-window maps full, and known endpoints for
        // D393's 1,000 peers (one configured and one confirmed each), listed before the window.
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        let known: Vec<_> = (0..NODE_BUDGET)
            .map(|index| own_network(20, index))
            .collect();
        admission.set_configured_endpoints(known.iter().copied());
        admission.set_confirmed_endpoints(known.iter().copied());
        let now = Instant::now();
        for index in 0..UNKNOWN_SOURCE_BUDGET {
            let _ = admission.check(&Packet::copy_from(&flood), own_network(18, index), now);
        }
        for spoofed in &known {
            let _ = admission.check(&Packet::copy_from(&flood), *spoofed, now);
        }
        // Rejected past the node budget, with both endpoint lists full: the costliest refusal.
        let rejected = 200_000_u32;
        let before = key_agreements(&admission);
        let cpu = thread_cpu();
        for index in 0..rejected {
            let verdict = admission.check(&Packet::copy_from(&flood), own_network(19, index), now);
            assert_eq!(verdict, Err(Refusal::NodeBudget));
        }
        let cpu = thread_cpu().saturating_sub(cpu);
        println!(
            "J717 past node budget, 1,000 peers in both lists: {rejected} rejected initiations, \
             {} key agreements, {:.3} us CPU per rejected packet",
            key_agreements(&admission) - before,
            per_packet(cpu, rejected)
        );
        // Rejected from known endpoints that used up their share of the reserve (J748): each
        // packet finds its slot, then takes the path every other source takes.
        let before = key_agreements(&admission);
        let cpu = thread_cpu();
        for index in 0..rejected {
            let spoofed = known[index as usize % known.len()];
            let verdict = admission.check(&Packet::copy_from(&flood), spoofed, now);
            assert_eq!(verdict, Err(Refusal::NodeBudget));
        }
        let cpu = thread_cpu().saturating_sub(cpu);
        println!(
            "J748 past their reserve share, 1,000 peers in both lists: {rejected} rejected \
             initiations, {} key agreements, {:.3} us CPU per rejected packet",
            key_agreements(&admission) - before,
            per_packet(cpu, rejected)
        );
        let budget = admission.budget.lock().expect("budget lock");
        let map_bytes = |entries: usize, capacity: usize, entry: usize| {
            // hashbrown: a power-of-two bucket count of at least capacity * 8 / 7, one control
            // byte per bucket plus 16 trailing ones.
            let buckets = (capacity * 8 / 7).next_power_of_two().max(4);
            println!("    {entries} entries, capacity {capacity}, {buckets} buckets of {entry} B");
            buckets * (entry + 1) + 16
        };
        let source_entry = size_of::<(super::SourceKey, super::Spend)>();
        let network_entry = size_of::<(super::NetworkKey, super::Spend)>();
        println!("J748 limiter memory at its bound:");
        let sources = map_bytes(
            budget.sources.len(),
            budget.sources.capacity(),
            source_entry,
        );
        let networks = map_bytes(
            budget.networks.len(),
            budget.networks.capacity(),
            network_entry,
        );
        let endpoints = (admission.configured_endpoints.capacity()
            + admission.confirmed_endpoints.capacity())
            * size_of::<super::EndpointKey>();
        // One reserve counter per known endpoint slot (J748).
        let shares = budget.endpoints.capacity() * size_of::<u8>();
        println!(
            "J748 limiter memory: sources {sources} B, networks {networks} B, \
             known endpoints {endpoints} B and their reserve counters {shares} B for \
             {NODE_BUDGET} peers, total {:.1} KiB",
            f64::from(u32::try_from(sources + networks + endpoints + shares).expect("fits"))
                / 1024.0
        );
        drop(budget);

        // A confirmed-list change at D393's 1,000 peers (J757): one peer's confirmed endpoint
        // moves, and the setter carries every count over. It runs on the 250 ms endpoint scan,
        // under the guard's write lock, never per packet.
        let mut moved = known.clone();
        moved[NODE_BUDGET as usize / 2] = own_network(21, 0);
        let changes = 10_000_u32;
        let cpu = thread_cpu();
        for change in 0..changes {
            let list = if change % 2 == 0 { &moved } else { &known };
            admission.set_confirmed_endpoints(list.iter().copied());
        }
        let cpu = thread_cpu().saturating_sub(cpu);
        println!(
            "J757 confirmed-list change, 1,000 peers in both lists: {changes} changes, \
             {:.1} us CPU each",
            per_packet(cpu, changes)
        );

        // The confirmed-endpoint scan both workers run every 250 ms (J736): one offer of D393's
        // 1,000 peers' unchanged endpoints, the steady-state cost per scan, and the feed's copy.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("bench runtime");
        let guard = tokio::sync::RwLock::new(admission);
        let mut feed = super::ConfirmedEndpointFeed::default();
        assert!(runtime.block_on(feed.offer(&guard, known.iter().copied())));
        let scans = 10_000_u32;
        let cpu = thread_cpu();
        for _ in 0..scans {
            assert!(!runtime.block_on(feed.offer(&guard, known.iter().copied())));
        }
        let cpu = thread_cpu().saturating_sub(cpu);
        println!(
            "J736 confirmed-endpoint scan, {NODE_BUDGET} unchanged endpoints: {:.2} us CPU per \
             scan ({:.4}% of one core at 4 scans/s), feed copy {} B",
            per_packet(cpu, scans),
            per_packet(cpu, scans) * 4.0 / 1e4,
            feed.last.capacity() * size_of::<super::EndpointKey>()
        );

        // Real-time floods.
        let packets = 200_000_u32;
        for (name, spoofed) in [("one source", false), ("65,536 spoofed sources", true)] {
            let admission = PeerAdmission::new(StaticSecret::from(NODE));
            let started = Instant::now();
            let cpu = thread_cpu();
            for index in 0..packets {
                let [_, _, high, low] = if spoofed {
                    index.to_be_bytes()
                } else {
                    [0, 0, 0, 1]
                };
                let from = SocketAddr::from(([198, 18, high, low], 40000));
                let _ = admission.check(&Packet::copy_from(&flood), from, Instant::now());
            }
            let cpu = thread_cpu().saturating_sub(cpu);
            let wall = started.elapsed();
            println!(
                "J648 flood ({name}): {packets} initiations, {} key agreements, \
                 thread CPU {:.3} s, wall {:.3} s, {:.2} us CPU per initiation, \
                 saturates one core at {:.0} initiations/s",
                key_agreements(&admission),
                cpu.as_secs_f64(),
                wall.as_secs_f64(),
                per_packet(cpu, packets),
                f64::from(packets) / cpu.as_secs_f64(),
            );
        }
    }
}

/// J713 (#483): a sustained, unspoofed, MAC1-valid flood against a granted peer's initiations.
///
/// A replayed initiation is free for anyone who knows the node's public key, so these tests
/// simulate a whole `WireGuard` handshake attempt period (90 s) of one at 20,000 packets a second,
/// on a simulated clock, while a granted peer retries every 5 s. They count how often the peer
/// still gets through, and check that the flood never runs more key agreements than the node
/// budget allows and that the limiter's maps stay small.
///
/// The Mac node's real-device test (J736) runs the same flood against its live worker's guard
/// through [`flood_against`] and [`report`].
#[cfg(test)]
pub(crate) mod flood_fairness {
    #![expect(
        clippy::expect_used,
        reason = "a broken fixture (bad address, key or lock) must stop the test loudly"
    )]
    use super::{NODE_BUDGET, PeerAdmission, Refusal};
    use crate::policy::model::PublicKey;
    use gotatun::{
        noise::{Tunn, index_table::IndexTable, rate_limiter::RateLimiter},
        packet::Packet,
        x25519::{PublicKey as X25519PublicKey, StaticSecret},
    };
    use std::{
        net::{IpAddr, Ipv6Addr, SocketAddr},
        sync::{Arc, atomic::Ordering},
        time::{Duration, Instant},
    };

    /// The node's fixed test identity.
    const NODE: [u8; 32] = [0x31; 32];

    /// The granted peer's fixed test identity.
    const PEER: [u8; 32] = [0x66; 32];

    /// How long each simulated flood lasts: `WireGuard`'s `REKEY_ATTEMPT_TIME`.
    const FLOOD_SECONDS: u32 = 90;

    /// One MAC1-valid initiation from `sender` to the node, with a fresh ephemeral key.
    fn initiation(sender: [u8; 32]) -> Vec<u8> {
        initiation_to(X25519PublicKey::from(&StaticSecret::from(NODE)), sender)
    }

    /// One MAC1-valid initiation from `sender` to the node whose public key is `node_public`,
    /// with a fresh ephemeral key.
    pub(crate) fn initiation_to(node_public: X25519PublicKey, sender: [u8; 32]) -> Vec<u8> {
        let sender = StaticSecret::from(sender);
        let sender_public = X25519PublicKey::from(&sender);
        let mut tunn = Tunn::new(
            sender,
            node_public,
            None,
            None,
            IndexTable::from_os_rng(),
            Arc::new(RateLimiter::new(&sender_public, 100)),
        );
        tunn.format_handshake_initiation(false)
            .expect("a MAC1-valid initiation")
            .into_bytes()
            .as_ref()
            .to_vec()
    }

    /// Flood source `n` inside the IPv6 /48 `2001:db8:<network>::/48`: a different /64 per `n`.
    fn v6_source(network: u16, n: u32) -> SocketAddr {
        let [_, _, high, low] = n.to_be_bytes();
        let ip = Ipv6Addr::new(
            0x2001,
            0xdb8,
            network,
            u16::from_be_bytes([high, low]),
            0,
            0,
            0,
            1,
        );
        SocketAddr::new(IpAddr::V6(ip), 40000)
    }

    /// The granted peer's source address in every simulation.
    fn peer_source() -> SocketAddr {
        "203.0.113.9:51000".parse().expect("test peer address")
    }

    /// The shape of one simulated flood.
    #[derive(Clone, Copy)]
    pub(crate) struct Flood {
        /// Flood initiations per second, evenly spaced.
        pub(crate) rate: u32,
        /// How many IPv6 /48 networks the flood comes from.
        pub(crate) networks: u16,
        /// How many /64s inside each /48 the flood rotates over.
        pub(crate) prefixes_per_network: u32,
        /// When, into each second, the granted peer sends its initiation.
        pub(crate) peer_offset_ms: u64,
        /// Whether the node knows the peer's source as one of its endpoints. Only [`simulate`]
        /// reads it; [`flood_against`] uses whatever the guard already knows.
        pub(crate) peer_endpoint_known: bool,
    }

    /// What one simulated flood did.
    pub(crate) struct Run {
        /// Granted-peer initiations the guard admitted.
        pub(crate) peer_admitted: u32,
        /// Granted-peer initiations sent (one every 5 s).
        pub(crate) peer_attempts: u32,
        /// Key agreements the guard ran during the flood.
        pub(crate) key_agreements: u32,
        /// The most per-source entries the budget held at a window's end.
        pub(crate) max_sources: usize,
        /// The largest per-source map capacity seen.
        pub(crate) max_capacity: usize,
    }

    /// Simulate `flood` for [`FLOOD_SECONDS`] while a granted peer retries every 5 s
    /// (`WireGuard`'s `REKEY_TIMEOUT`).
    fn simulate(flood: Flood) -> Run {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        admission.set_peers([PublicKey(
            *X25519PublicKey::from(&StaticSecret::from(PEER)).as_bytes(),
        )]);
        if flood.peer_endpoint_known {
            admission.set_configured_endpoints([peer_source()]);
        }
        flood_against(
            &admission,
            X25519PublicKey::from(&StaticSecret::from(NODE)),
            &initiation(PEER),
            peer_source(),
            flood,
            Instant::now(),
        )
    }

    /// Run `flood` for [`FLOOD_SECONDS`] against an existing guard whose node key is
    /// `node_public`, on a simulated clock from `start`, while a granted peer sends `granted`
    /// (its MAC1-valid initiation) from `peer` every 5 s.
    ///
    /// The guard keeps whatever peers and known endpoints it already has, so a live worker's
    /// guard shows what that worker taught it. `start` should be later than any real time the
    /// guard has seen, so the simulated windows are fresh.
    pub(crate) fn flood_against(
        admission: &PeerAdmission,
        node_public: X25519PublicKey,
        granted: &[u8],
        peer: SocketAddr,
        flood: Flood,
        start: Instant,
    ) -> Run {
        let attacker = initiation_to(node_public, [0x55; 32]);
        let agreements_before = admission.key_agreements.load(Ordering::Relaxed);
        let mut run = Run {
            peer_admitted: 0,
            peer_attempts: 0,
            key_agreements: 0,
            max_sources: 0,
            max_capacity: 0,
        };
        let sources = u32::from(flood.networks) * flood.prefixes_per_network;
        let step = Duration::from_secs(1) / flood.rate.max(1);
        let mut n = 0_u32;
        let peer_tries = |admission: &PeerAdmission, at: Instant, run: &mut Run| {
            run.peer_attempts += 1;
            if admission.check(&Packet::copy_from(granted), peer, at) == Ok(()) {
                run.peer_admitted += 1;
            }
        };
        for second in 0..FLOOD_SECONDS {
            let base = start + Duration::from_secs(u64::from(second));
            let peer_at = base + Duration::from_millis(flood.peer_offset_ms);
            let mut peer_done = second % 5 != 0;
            for i in 0..flood.rate {
                let at = base + step * i;
                if !peer_done && at >= peer_at {
                    peer_done = true;
                    peer_tries(admission, peer_at, &mut run);
                }
                let index = n % sources;
                let network =
                    u16::try_from(index / flood.prefixes_per_network).expect("network index fits");
                let from = v6_source(network, index % flood.prefixes_per_network);
                let verdict = admission.check(&Packet::copy_from(&attacker), from, at);
                assert_ne!(verdict, Ok(()), "a stranger was admitted");
                n = n.wrapping_add(1);
            }
            if !peer_done {
                peer_tries(admission, peer_at, &mut run);
            }
            let budget = admission.budget.lock().expect("budget lock");
            run.max_sources = run.max_sources.max(budget.sources.len());
            run.max_capacity = run.max_capacity.max(budget.sources.capacity());
        }
        run.key_agreements = admission
            .key_agreements
            .load(Ordering::Relaxed)
            .saturating_sub(agreements_before);
        run
    }

    /// Check the bounds every flood must keep, and print the run for the issue log.
    pub(crate) fn report(name: &str, run: &Run) {
        println!(
            "J717 {name}: peer admitted {}/{} attempts, key agreements {} (cap {}), \
             max sources {}, max map capacity {}",
            run.peer_admitted,
            run.peer_attempts,
            run.key_agreements,
            FLOOD_SECONDS * NODE_BUDGET,
            run.max_sources,
            run.max_capacity
        );
        assert!(
            run.key_agreements <= FLOOD_SECONDS * NODE_BUDGET,
            "{name}: the flood ran more key agreements than the node budget allows"
        );
        assert!(
            run.max_sources <= NODE_BUDGET as usize,
            "{name}: the per-source map outgrew the node budget"
        );
    }

    /// J713 P2: 20,000 initiations a second from 16 /64s inside one /48, no spoofing, must not
    /// starve a granted peer at an endpoint the node has never seen. The same flood from one
    /// /64 is the control.
    #[test]
    fn a_multi_prefix_flood_from_one_network_does_not_starve_a_granted_peer() {
        for offset in [10_u64, 100, 500, 900] {
            let run = simulate(Flood {
                rate: 20_000,
                networks: 1,
                prefixes_per_network: 16,
                peer_offset_ms: offset,
                peer_endpoint_known: false,
            });
            report(&format!("16 /64s in one /48, offset {offset} ms"), &run);
            assert_eq!(
                run.peer_admitted, run.peer_attempts,
                "a flood from one /48 starved a granted peer (offset {offset} ms)"
            );
        }
        let control = simulate(Flood {
            rate: 20_000,
            networks: 1,
            prefixes_per_network: 1,
            peer_offset_ms: 500,
            peer_endpoint_known: false,
        });
        report("control, one /64", &control);
        assert_eq!(
            control.peer_admitted, control.peer_attempts,
            "a single-/64 flood starved a granted peer"
        );
    }

    /// A flood from 64 networks (16 /64s in each of 64 /48s) is too wide for the network
    /// budgets: it spends the whole unknown-source share in every window. A granted peer at a
    /// known endpoint still gets every initiation in from the reserve. One at an unknown endpoint
    /// is the documented limit: it is admitted only when its initiation lands before the
    /// share runs out (here, at a 10 ms offset, it does; at 500 ms it does not).
    #[test]
    fn a_wide_flood_cannot_take_the_reserve_from_a_known_endpoint() {
        for offset in [10_u64, 100, 500, 900] {
            let run = simulate(Flood {
                rate: 20_000,
                networks: 64,
                prefixes_per_network: 16,
                peer_offset_ms: offset,
                peer_endpoint_known: true,
            });
            report(
                &format!("64 /48s x 16 /64s, known endpoint, offset {offset} ms"),
                &run,
            );
            assert_eq!(
                run.peer_admitted, run.peer_attempts,
                "a wide flood took the reserve from a known endpoint (offset {offset} ms)"
            );
        }
        let unknown = simulate(Flood {
            rate: 20_000,
            networks: 64,
            prefixes_per_network: 16,
            peer_offset_ms: 500,
            peer_endpoint_known: false,
        });
        report(
            "64 /48s x 16 /64s, unknown endpoint, offset 500 ms",
            &unknown,
        );
        assert_eq!(
            unknown.peer_admitted, 0,
            "the documented limit changed: update the module doc if an unknown endpoint now gets in"
        );
    }

    /// Peer `k`'s known endpoint in the spoofing tests: each peer in its own IPv4 /24.
    fn spoofed_peer_endpoint(k: u16) -> SocketAddr {
        let [high, low] = k.to_be_bytes();
        SocketAddr::from(([198, high, low, 9], 51820))
    }

    /// The shape of one flood that spoofs other peers' known endpoints (J735, #483).
    #[derive(Clone, Copy)]
    struct Spoofing {
        /// How many granted peers the node has besides peer 0, each with one configured
        /// endpoint. The flood spoofs every one of them.
        others: u16,
        /// Spoofed initiations per second sent from each of those endpoints.
        per_endpoint: u32,
        /// Whether the flood replays one granted peer's initiation (which the guard admits:
        /// it does not check timestamps) instead of sending a stranger's key.
        replay: bool,
        /// Whether a 20,000/s flood from 65,536 IPv4 /24s spends the unknown-source share too.
        wide: bool,
        /// Peer 0's own endpoint; the flood never spoofs it.
        peer: SocketAddr,
    }

    /// Simulate `spoofing` for [`FLOOD_SECONDS`] while peer 0, at its configured endpoint,
    /// retries every 5 s at 500 ms into the second. Every spoofed initiation of a second is sent
    /// at its start, the worst case for peer 0.
    fn simulate_spoofing(spoofing: Spoofing) -> Run {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        let key = |seed: u8| {
            PublicKey(*X25519PublicKey::from(&StaticSecret::from([seed; 32])).as_bytes())
        };
        admission.set_peers(
            std::iter::once(key(0x66)).chain((1..=spoofing.others).map(|k| {
                // Seeds 0x80..=0xfe (peer 1 is 0x81), never the stranger's or peer 0's; more
                // than 127 peers reuse them, which changes nothing here.
                key(0x80 + u8::try_from(k % 127).expect("fits"))
            })),
        );
        admission.set_configured_endpoints(
            std::iter::once(spoofing.peer).chain((1..=spoofing.others).map(spoofed_peer_endpoint)),
        );
        let payload = if spoofing.replay {
            initiation([0x81; 32])
        } else {
            initiation([0x55; 32])
        };
        let granted = initiation(PEER);
        let start = Instant::now();
        let mut run = Run {
            peer_admitted: 0,
            peer_attempts: 0,
            key_agreements: 0,
            max_sources: 0,
            max_capacity: 0,
        };
        for second in 0..FLOOD_SECONDS {
            let base = start + Duration::from_secs(u64::from(second));
            if spoofing.wide {
                for i in 0..20_000_u32 {
                    let [_, _, high, low] = i.to_be_bytes();
                    let from = SocketAddr::from(([10, high, low, 1], 40000));
                    let _ = admission.check(&Packet::copy_from(&payload), from, base);
                }
            }
            for k in 1..=spoofing.others {
                for _ in 0..spoofing.per_endpoint {
                    let from = spoofed_peer_endpoint(k);
                    let _ = admission.check(&Packet::copy_from(&payload), from, base);
                }
            }
            if second % 5 == 0 {
                run.peer_attempts += 1;
                let at = base + Duration::from_millis(500);
                if admission.check(&Packet::copy_from(&granted), spoofing.peer, at) == Ok(()) {
                    run.peer_admitted += 1;
                }
            }
            let budget = admission.budget.lock().expect("budget lock");
            run.max_sources = run.max_sources.max(budget.sources.len());
            run.max_capacity = run.max_capacity.max(budget.sources.capacity());
        }
        run.key_agreements = admission.key_agreements.load(Ordering::Relaxed);
        run
    }

    /// J735 P2 (#483): a flood that spoofs OTHER peers' known endpoints must not starve a peer
    /// whose own endpoint it does not spoof. On J717's guard the reserve was one shared pool, so
    /// five spoofed endpoints with a stranger's key (plus a wide flood), five replaying a granted
    /// initiation, or ten with a stranger's key took peer 0 to 0 of 18; four replaying ones (800
    /// a second, under the node budget) were the control at 18 of 18.
    #[test]
    fn spoofing_other_known_endpoints_cannot_starve_an_unspoofed_one() {
        let peer = "203.0.113.9:51000".parse().expect("test peer address");
        for (name, others, replay, wide) in [
            (
                "wide flood + 5 spoofed known endpoints, stranger's key",
                5,
                false,
                true,
            ),
            (
                "5 spoofed known endpoints replaying a granted initiation",
                5,
                true,
                false,
            ),
            (
                "10 spoofed known endpoints, stranger's key",
                10,
                false,
                false,
            ),
            (
                "control, 4 spoofed known endpoints replaying",
                4,
                true,
                false,
            ),
        ] {
            let run = simulate_spoofing(Spoofing {
                others,
                per_endpoint: 1_000,
                replay,
                wide,
                peer,
            });
            report(&format!("J735 {name}, 1,000/s each"), &run);
            assert_eq!(
                run.peer_admitted, run.peer_attempts,
                "{name}: spoofing other peers' endpoints starved an unspoofed known endpoint"
            );
        }
    }

    /// A peer behind the same address as a spoofed endpoint (two peers behind one NAT, on
    /// different ports) keeps its own known endpoint: spoofing its neighbour's port must not
    /// spend the address's budget for it.
    #[test]
    fn spoofing_a_neighbour_behind_the_same_address_does_not_starve_a_peer() {
        for replay in [false, true] {
            let run = simulate_spoofing(Spoofing {
                others: 1,
                per_endpoint: 1_000,
                replay,
                wide: true,
                // Peer 1's endpoint is 198.0.1.9:51820; peer 0 sits on the same address.
                peer: SocketAddr::from(([198, 0, 1, 9], 51821)),
            });
            report(
                &format!("J748 neighbour on the same address spoofed (replay {replay})"),
                &run,
            );
            assert_eq!(
                run.peer_admitted, run.peer_attempts,
                "spoofing a neighbour's port starved a peer at its known endpoint (replay {replay})"
            );
        }
    }

    /// The documented limit of the reserve: each known endpoint may spend only its share, so a
    /// flood must spoof at least [`super::RESERVED_BUDGET`] other known endpoints at once, and
    /// spend the unknown share, before an unspoofed known endpoint is refused. This one spoofs
    /// 600 of 601 peers' endpoints with a wide flood, and peer 0 is refused; if this changes,
    /// update the module doc.
    #[test]
    fn spoofing_more_endpoints_than_the_reserve_is_the_documented_limit() {
        let run = simulate_spoofing(Spoofing {
            others: 600,
            per_endpoint: 2,
            replay: true,
            wide: true,
            peer: "203.0.113.9:51000".parse().expect("test peer address"),
        });
        report(
            "J748 wide flood + 600 spoofed known endpoints replaying",
            &run,
        );
        assert_eq!(
            run.peer_admitted, 0,
            "the documented limit changed: update the module doc if peer 0 now gets in"
        );
    }

    /// J754 P2 (#483): a mesh member that roams its own confirmed endpoint must not refresh the
    /// shares of the endpoints a flood spoofs.
    ///
    /// Linux replaces the confirmed list on every 250 ms scan that sees a change, and a member
    /// holding a granted key can change its confirmed endpoint at will by sending from
    /// alternating ports. On `f8e581b1d` each replacement zeroed every endpoint's count, so five
    /// spoofed endpoints at 1,000/s plus a wide flood took peer 0 (unspoofed, retrying 900 ms
    /// into the second) from 18 of 18 to 0 of 18. J754's probe, kept as the regression test; the
    /// run without roaming is the control.
    #[test]
    fn a_member_roaming_its_endpoint_cannot_refresh_spoofed_shares() {
        for roaming in [false, true] {
            let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
            let key = |seed: u8| {
                PublicKey(*X25519PublicKey::from(&StaticSecret::from([seed; 32])).as_bytes())
            };
            admission.set_peers([
                key(0x66),
                key(0x81),
                key(0x82),
                key(0x83),
                key(0x84),
                key(0x85),
            ]);
            let peer = peer_source();
            admission.set_configured_endpoints(
                std::iter::once(peer).chain((1..=5).map(spoofed_peer_endpoint)),
            );
            let replay = initiation([0x81; 32]);
            let granted = initiation(PEER);
            // The roaming member's two source ports, swapped every quarter second.
            let roam = |n: u32| {
                SocketAddr::from((
                    [198, 51, 100, 7],
                    u16::try_from(40_000 + n % 2).expect("port"),
                ))
            };
            admission.set_confirmed_endpoints([roam(0)]);
            let start = Instant::now();
            let mut run = Run {
                peer_admitted: 0,
                peer_attempts: 0,
                key_agreements: 0,
                max_sources: 0,
                max_capacity: 0,
            };
            for second in 0..FLOOD_SECONDS {
                let base = start + Duration::from_secs(u64::from(second));
                for quarter in 0..4_u32 {
                    let at = base + Duration::from_millis(u64::from(quarter) * 250);
                    if roaming {
                        admission.set_confirmed_endpoints([roam(second * 4 + quarter + 1)]);
                    }
                    if quarter == 0 {
                        for i in 0..20_000_u32 {
                            let [_, _, high, low] = i.to_be_bytes();
                            let from = SocketAddr::from(([10, high, low, 1], 40000));
                            let _ = admission.check(&Packet::copy_from(&replay), from, at);
                        }
                    }
                    for k in 1..=5 {
                        for _ in 0..1_000 {
                            let from = spoofed_peer_endpoint(k);
                            let _ = admission.check(&Packet::copy_from(&replay), from, at);
                        }
                    }
                }
                if second % 5 == 0 {
                    run.peer_attempts += 1;
                    let at = base + Duration::from_millis(900);
                    if admission.check(&Packet::copy_from(&granted), peer, at) == Ok(()) {
                        run.peer_admitted += 1;
                    }
                }
                let budget = admission.budget.lock().expect("budget lock");
                run.max_sources = run.max_sources.max(budget.sources.len());
                run.max_capacity = run.max_capacity.max(budget.sources.capacity());
            }
            run.key_agreements = admission.key_agreements.load(Ordering::Relaxed);
            report(
                &format!("J754 5 spoofed endpoints + wide flood, member roaming {roaming}"),
                &run,
            );
            assert_eq!(
                run.peer_admitted, run.peer_attempts,
                "a member roaming its endpoint (roaming {roaming}) let spoofed endpoints starve peer 0"
            );
        }
    }

    /// After a flood stops, the very next window admits the peer.
    #[test]
    fn a_peer_is_admitted_right_after_a_flood_stops() {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        admission.set_peers([PublicKey(
            *X25519PublicKey::from(&StaticSecret::from(PEER)).as_bytes(),
        )]);
        let attacker = initiation([0x55; 32]);
        let now = Instant::now();
        for n in 0..65_536 {
            let network = u16::try_from(n / 256).expect("network index fits");
            let _ = admission.check(&Packet::copy_from(&attacker), v6_source(network, n), now);
        }
        assert_eq!(
            admission.check(&Packet::copy_from(&initiation(PEER)), peer_source(), now),
            Err(Refusal::NodeBudget)
        );
        assert_eq!(
            admission.check(
                &Packet::copy_from(&initiation(PEER)),
                peer_source(),
                now + Duration::from_secs(1)
            ),
            Ok(())
        );
    }
}

/// The guard keeps each packet's kernel receive time with the packet (Linux, D397, #260).
///
/// The pinned `GotaTun` bounds its receive queue by how long each packet waited since the kernel
/// stamped its datagram, and it asks the receiver for that stamp by the packet's index in the
/// batch. These tests receive a real batch through [`PeerAdmissionUdpReceiver`] and check that
/// the stamps reach `GotaTun` and still belong to the right packets after the guard removed one.
#[cfg(all(test, target_os = "linux"))]
mod receive_stamp_tests {
    #![expect(
        clippy::expect_used,
        reason = "a broken fixture (socket, key or clock) must stop the test loudly"
    )]
    use super::{PeerAdmission, PeerAdmissionUdpReceiver, flood_fairness::initiation_to};
    use gotatun::{
        packet::PacketBufPool,
        udp::{UdpRecv, UdpTransportFactory, UdpTransportFactoryParams, socket::UdpSocketFactory},
        x25519::{PublicKey as X25519PublicKey, StaticSecret},
    };
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };
    use tokio::sync::RwLock;

    /// The test node's identity; no peer is ever granted, so every initiation is refused.
    const NODE: [u8; 32] = [0x31; 32];

    /// How long the test waits between the refused initiation and the last data packet, so the
    /// two kernel stamps can't be mistaken for each other.
    const GAP: Duration = Duration::from_millis(30);

    /// A refused initiation in the middle of a batch must not shift the later packets' stamps.
    ///
    /// Sends data packet A, an initiation from a key the node never granted (the guard drops
    /// it), waits [`GAP`], then sends data packet B, all before the receiver reads. The batch
    /// that reaches `GotaTun` is A and B, and B's stamp must be B's own: at least [`GAP`] after
    /// A's. Index 1 carrying the dropped initiation's stamp (or no stamp at all, the trait's
    /// default) would leave the queue bound measuring the wrong packet or nothing.
    #[tokio::test]
    async fn stamps_stay_with_their_packets_after_the_guard_drops_one() {
        if std::env::var("GOTATUN_AQM").is_ok_and(|mode| mode.trim() == "off") {
            eprintln!("GOTATUN_AQM=off: the socket records no receive stamps; nothing to check");
            return;
        }
        let params = UdpTransportFactoryParams {
            addr: Some(Ipv4Addr::LOCALHOST.into()),
            port: 0,
            fwmark: None,
        };
        // The factory also turns on UDP GRO and, with the bound on, `SO_TIMESTAMPNS`, as the
        // node's own bind does.
        let (_send, receive) = UdpSocketFactory::default()
            .bind(&params)
            .await
            .expect("bind the receive socket");
        let target: SocketAddr = receive.local_addr().expect("receive address");
        let admission = Arc::new(RwLock::new(PeerAdmission::new(StaticSecret::from(NODE))));
        let mut receiver = PeerAdmissionUdpReceiver::new(receive, admission);

        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender socket");
        // Type 4 is a data packet, which the guard never inspects; the sizes differ so the
        // kernel can't coalesce A and B into one GRO batch.
        let first = [4_u8; 64];
        let last = [4_u8; 96];
        sender.send_to(&first, target).expect("send A");
        sender
            .send_to(
                &initiation_to(X25519PublicKey::from(&StaticSecret::from(NODE)), [0x55; 32]),
                target,
            )
            .expect("send the stranger's initiation");
        // sleep: put a measurable gap between the dropped initiation's stamp and B's.
        std::thread::sleep(GAP);
        sender.send_to(&last, target).expect("send B");

        let mut recv_buf = <PeerAdmissionUdpReceiver as UdpRecv>::RecvManyBuf::default();
        let mut pool = PacketBufPool::new(8);
        let mut packets = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), async {
            while packets.len() < 2 {
                receiver
                    .recv_many_from(&mut recv_buf, &mut pool, &mut packets)
                    .await
                    .expect("receive");
            }
        })
        .await
        .expect("A and B arrive");

        let sizes: Vec<usize> = packets.iter().map(|(packet, _)| packet.len()).collect();
        assert_eq!(
            sizes,
            [64, 96],
            "the guard must drop exactly the initiation"
        );
        let stamp_a = PeerAdmissionUdpReceiver::rx_timestamp_ns(&recv_buf, 0);
        let stamp_b = PeerAdmissionUdpReceiver::rx_timestamp_ns(&recv_buf, 1);
        assert!(
            stamp_a > 0 && stamp_b > 0,
            "GotaTun gets no receive stamps through the guard (A {stamp_a} ns, B {stamp_b} ns)"
        );
        let gap = u64::try_from(GAP.as_nanos()).expect("gap fits");
        assert!(
            stamp_b.saturating_sub(stamp_a) >= gap,
            "B's stamp {stamp_b} is within {gap} ns of A's {stamp_a}: it belongs to the dropped \
             initiation"
        );
    }
}
