//! The candidate walks a `GotaTun` node runs, one per peer (#515, D391): which peers walk, when a
//! walk starts again, and which address each step moves to. Linux and macOS both run `GotaTun`,
//! and both engine workers drive this one bookkeeping, so the two behave the same (the owner's
//! Mac-parity rule).
//!
//! The module does no I/O. Each engine worker:
//! 1. lists the peers it installed ([`walking_peers`]) after applying a snapshot;
//! 2. asks [`Walks::prepare`] whether anything needs the engine's counters, and reads them only
//!    then, as [`Observed`];
//! 3. installs each address [`Walks::start`] and [`Walks::step`] return, and sends a handshake
//!    there with `GotaTun`'s `rehandshake` (fork `1f646d4`), which sends even over a live session
//!    and keeps that session until the new one is up;
//! 4. reports an address it could not install ([`Walks::abandon`], [`Walks::install_failed`]).
//!
//! The walk itself, one peer's [`Rotation`], lives in [`crate::candidates`].
//!
//! Choices, and the alternatives rejected:
//! - The engine stays with the worker, not behind a trait object here: the two workers own their
//!   device differently (a TUN rebuilt after a fatal error on Linux, a utun with host routes on
//!   macOS), and the walk only needs counters in and addresses out.
//! - No timer runs for a finished walk, and a snapshot that leaves a working peer unchanged starts
//!   nothing for it, so an idle node stays idle (D81) and sends no extra handshake to an idle
//!   peer. A snapshot reads the counters only when a peer is new or changed, or a walk that found
//!   its peer must be checked for silence. Known follow-up (J699 P3-2, D393): once any walk has
//!   found its peer, that check reads every peer's counters on each applied snapshot, an O(peers)
//!   read not yet measured at 1,000 and 4,096 peers; a per-walk "earliest silent deadline" would
//!   skip it until a found walk can have gone silent.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    candidates::{Rotation, SILENT, Seen},
    dataplane::{Config, Peer, PeerPolicy},
    policy::model::PublicKey,
};

/// What the engine reports for each installed peer, by device key, as a walk reads it
/// ([`observe`]). A peer missing from the map reads as silent: no bytes, no handshake.
pub(crate) type Observed = BTreeMap<PublicKey, Seen>;

/// One peer's send address and the address a recent authenticated session confirmed.
///
/// `live_confirmed` is populated only when the last handshake is younger than [`SILENT`]. It
/// may preserve an address that a stale coordinator snapshot no longer lists, but only while
/// the engine is still sending there and the peer's session remains live.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct EngineEndpoint {
    /// Where the engine currently sends packets for this peer.
    pub(crate) send: Option<SocketAddr>,
    /// The last authenticated source address, while its handshake is still recent.
    pub(crate) live_confirmed: Option<SocketAddr>,
}

/// Build an endpoint snapshot from `GotaTun` without treating an unconfirmed roam as reachable.
///
/// The send endpoint can move when the engine accepts a handshake initiation, before that
/// sender proves its key. Only its separately confirmed endpoint is retained, and only for a
/// session that has not exceeded [`SILENT`].
#[must_use]
pub(crate) fn engine_endpoint(
    send: Option<SocketAddr>,
    confirmed: Option<SocketAddr>,
    last_handshake_age: Option<std::time::Duration>,
) -> EngineEndpoint {
    let live_confirmed = last_handshake_age
        .filter(|age| *age < SILENT)
        .and(confirmed);
    EngineEndpoint {
        send,
        live_confirmed,
    }
}

/// One walk that has just started running: the peer's device key, the address the walk is on,
/// and where the engine sent that peer's packets when the walk started. The worker moves the
/// engine to `address` when the two differ, then sends a handshake there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Started {
    /// The device key that owns the peer's endpoint ([`active_peer_key`]).
    pub key: PublicKey,
    /// The candidate the walk starts on.
    pub address: SocketAddr,
    /// The engine's address for the peer when the walk started, if it had one.
    pub engine_at: Option<SocketAddr>,
}

/// The identity that currently owns a peer's host routes and endpoint: the previous key while a
/// rotation overlap still routes through it, else the current key. Walks are kept under this key,
/// because it is the device peer whose address a walk moves.
#[must_use]
pub(crate) fn active_peer_key(peer: &Peer) -> PublicKey {
    if peer.previous_active {
        peer.previous_key.unwrap_or(peer.key)
    } else {
        peer.key
    }
}

/// The peers that walk, by device key: of the peers the engine `installed`, those with network
/// access ([`PeerPolicy::has_network_access`]), a first address and a candidate list after it.
///
/// Both `GotaTun` engines (Linux and macOS) install exactly the peers with network access, and
/// pass them here. The access check is repeated here so the rule holds in one place for every
/// caller: a walk never sends handshakes toward a peer whose grants allow no packet, even if a
/// caller passes every configured peer (J781 finding 3, #515, #483).
pub(crate) fn walking_peers<'a>(
    installed: impl IntoIterator<Item = &'a PeerPolicy>,
) -> BTreeMap<PublicKey, Peer> {
    installed
        .into_iter()
        .filter(|policy| {
            policy.has_network_access()
                && policy.peer.endpoint.is_some()
                && !policy.peer.candidates.is_empty()
        })
        .map(|policy| (active_peer_key(&policy.peer), policy.peer.clone()))
        .collect()
}

/// Whether a worker must read the engine's addresses before applying `next` over `applied`
/// (the `before` map [`kept_address`] judges, and [`Walks::start`] reads, J602 F1).
///
/// True when `next` changes any peer that was already installed (#483, J1025). A changed peer
/// is rewritten whole by the engine, endpoint included, so any of them, walking or not, relayed
/// or not, can lose a live NAT-roamed address to a stale snapshot unless [`kept_address`] sees
/// it. Limiting the read to walking and relayed peers left a single-address peer on its old
/// recovery time. The cost is one O(peers) read per snapshot that changes a peer; a snapshot
/// that changes none reads nothing, and neither does the first one.
#[must_use]
pub(crate) fn engine_read_needed(applied: Option<&Config>, next: &Config) -> bool {
    let Some(applied) = applied else {
        return false;
    };
    next.peers.iter().any(|(id, policy)| {
        applied
            .peers
            .get(id)
            .is_some_and(|previous| previous.peer != policy.peer)
    })
}

/// The address a re-installed peer keeps instead of its new first candidate, if any.
///
/// A worker re-installs a peer whose snapshot changed, and a fresh install aims at the first
/// candidate. Three cases keep where the engine already sends:
/// - a relayed peer stays on its `relay` (J699 P3-1; Linux relay builds only, `None` elsewhere);
/// - a walking peer stays on an address its new list still holds (J699 P3-3): its walk may have
///   found the peer there, and the new walk starts on the engine's address anyway (J602 F2), so
///   moving away first would cost a working session up to one walk step.
/// - any peer stays on an off-list address that a recent authenticated session confirmed, so a
///   changed snapshot cannot replace a live NAT-roamed endpoint with an older candidate (#483).
///
/// An unconfirmed send endpoint, or a confirmed endpoint whose handshake is no longer live,
/// takes the snapshot's.
#[must_use]
pub(crate) fn kept_address(
    peer: &Peer,
    engine: EngineEndpoint,
    relay: Option<SocketAddr>,
) -> Option<SocketAddr> {
    let at = engine.send?;
    let listed =
        !peer.candidates.is_empty() && (peer.endpoint == Some(at) || peer.candidates.contains(&at));
    let confirmed = engine.live_confirmed == Some(at);
    (relay == Some(at) || listed || confirmed).then_some(at)
}

/// How long a worker's handshake task waits for the session it asked for; `GotaTun`'s own wait
/// has no deadline. One `WireGuard` handshake attempt is 5 s, after which the peer's timers retry.
pub(crate) const HANDSHAKE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The wall clock in Unix seconds, the unit of the engine's handshake times.
#[must_use]
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Turn one peer's engine counters into what a walk reads at `unix_now`: its received bytes, its
/// last handshake (`0` once older than [`crate::candidates::SILENT`]) and the engine's address.
#[must_use]
pub(crate) const fn observe(
    received: u64,
    handshake_secs: u64,
    endpoint: Option<SocketAddr>,
    unix_now: u64,
) -> Seen {
    Seen {
        received,
        handshake: crate::candidates::live_handshake(handshake_secs, unix_now),
        endpoint,
    }
}

/// Wait until the next walk step is due, or forever when no walk is running. A worker selects on
/// it next to its commands, with the time from [`Walks::next_due`].
pub(crate) async fn walk_due(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
    }
}

/// Every running or finished walk of one node, by device key, with the peer it was started for:
/// a peer that is re-installed (it changed) starts a new walk.
#[derive(Debug, Default)]
pub(crate) struct Walks {
    walks: BTreeMap<PublicKey, (Peer, Rotation)>,
}

impl Walks {
    /// Drop every walk: the device stopped, or no configuration is applied.
    pub(crate) fn clear(&mut self) {
        self.walks.clear();
    }

    /// The first half of bringing the walks in line with an applied snapshot: drop the walks of
    /// peers that no longer walk, and say whether [`Self::start`] needs the engine's counters.
    ///
    /// It does when a `wanted` peer is new or changed, or when a walk that found its peer must be
    /// checked for silence. Otherwise the snapshot changed nothing a walk cares about, and the
    /// worker reads nothing.
    pub(crate) fn prepare(&mut self, wanted: &BTreeMap<PublicKey, Peer>) -> bool {
        self.walks.retain(|key, _| wanted.contains_key(key));
        let changed = wanted
            .iter()
            .any(|(key, peer)| self.walks.get(key).is_none_or(|(old, _)| old != peer));
        let watching = self
            .walks
            .values()
            .any(|(_, walk)| walk.went_silent(Seen::default()));
        changed || watching
    }

    /// The second half: start a walk for each `wanted` peer that is new or changed, and again for
    /// a peer whose walk once found it and whose path has since gone silent. Returns the walks
    /// that start running; a walk that starts finished needs nothing.
    ///
    /// A peer that is unchanged keeps its walk, finished or not (J585 F4), so an unrelated
    /// snapshot never sends a working peer back through its list. `before` holds the engine's
    /// send endpoint and its recent authenticated endpoint before the apply (empty unless
    /// [`reinstalls_a_peer`]). A changed peer may be live on a later candidate (J602 F1), and
    /// [`kept_address`] keeps that address if the new list still holds it (J699 P3-3). If a
    /// recent authenticated address fell off the list, it becomes the first item in this walk's
    /// private list too; otherwise the new walk would immediately undo the endpoint the apply
    /// just kept (#483).
    pub(crate) fn start(
        &mut self,
        wanted: BTreeMap<PublicKey, Peer>,
        observed: &Observed,
        before: &BTreeMap<PublicKey, EngineEndpoint>,
        now: Instant,
    ) -> Vec<Started> {
        let mut started = Vec::new();
        for (key, peer) in wanted {
            let mut seen = observed.get(&key).copied().unwrap_or_default();
            let engine_at = seen.endpoint;
            match self.walks.get(&key) {
                Some((old, walk)) if *old == peer => {
                    if !walk.went_silent(seen) {
                        continue;
                    }
                }
                _ => {
                    // The apply moved the engine here, so its live session was made elsewhere.
                    if before.get(&key).map(|endpoint| endpoint.send) != Some(engine_at) {
                        seen.endpoint = None;
                    }
                }
            }
            let mut list: Vec<_> = peer
                .endpoint
                .into_iter()
                .chain(peer.candidates.iter().copied())
                .collect();
            let live_off_list = before.get(&key).and_then(|engine| {
                (engine.send == engine_at && engine.live_confirmed == engine_at)
                    .then_some(engine.send)
                    .flatten()
            });
            if let Some(endpoint) = live_off_list
                && !list.contains(&endpoint)
            {
                list.insert(0, endpoint);
            }
            match Rotation::new(list, now, seen) {
                Some(walk) => {
                    if !walk.settled() {
                        started.push(Started {
                            key,
                            address: walk.current(),
                            engine_at,
                        });
                    }
                    self.walks.insert(key, (peer, walk));
                }
                None => {
                    self.walks.remove(&key);
                }
            }
        }
        started
    }

    /// The engine could not be moved to a started walk's address. Drop the walk; the next applied
    /// snapshot starts it again.
    pub(crate) fn abandon(&mut self, key: PublicKey) {
        self.walks.remove(&key);
    }

    /// When the earliest running walk needs its next step; `None` when every walk has stopped.
    #[must_use]
    pub(crate) fn next_due(&self) -> Option<Instant> {
        self.walks.values().filter_map(|(_, walk)| walk.due()).min()
    }

    /// Step every due walk at `now` with what the engine reports, and return the addresses to
    /// install, by device key. The worker installs each and sends a handshake there.
    pub(crate) fn step(
        &mut self,
        now: Instant,
        observed: &Observed,
    ) -> Vec<(PublicKey, SocketAddr)> {
        self.walks
            .iter_mut()
            .filter_map(|(key, (_, walk))| {
                walk.tick(now, observed.get(key).copied().unwrap_or_default())
                    .map(|next| (*key, next))
            })
            .collect()
    }

    /// The address the last [`Self::step`] returned for `key` could not be installed; the engine
    /// still sends to the previous one, and the walk's next step tries again.
    pub(crate) fn install_failed(&mut self, key: PublicKey) {
        if let Some((_, walk)) = self.walks.get_mut(&key) {
            walk.install_failed();
        }
    }
}

/// The shared bookkeeping both engines drive.
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{
        dataplane::PeerPolicy,
        policy::{model::Addresses, rules::TrafficPolicy},
    };
    use std::time::Duration;

    /// Parse a fixture address.
    fn at(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    /// One fixture peer with a first address and one more candidate.
    fn walking(key: u8) -> PeerPolicy {
        PeerPolicy {
            peer: Peer {
                key: PublicKey([key; 32]),
                previous_key: None,
                previous_active: false,
                addresses: Addresses {
                    ipv4: "10.254.0.4".parse().unwrap(),
                    ipv6: "fd01::4".parse().unwrap(),
                },
                endpoint: Some(at("198.51.100.4:30254")),
                candidates: vec![at("198.51.100.4:10254")],
                ipv4_only: false,
                side_port: false,
            },
            inbound: TrafficPolicy::All,
            outbound: TrafficPolicy::All,
            access_ssh: None,
            networks: crate::dataplane::PeerNetworks::default(),
        }
    }

    /// A changed snapshot cannot move a live off-list endpoint when its replacement walk starts.
    #[test]
    fn a_reinstall_starts_settled_on_a_live_authenticated_off_list_endpoint() {
        let mut walks = Walks::default();
        let peer = walking(8).peer;
        let key = peer.key;
        let live = at("10.9.0.44:10254");
        let observed = BTreeMap::from([(
            key,
            Seen {
                received: 42,
                handshake: 1,
                endpoint: Some(live),
            },
        )]);
        let before = BTreeMap::from([(
            key,
            engine_endpoint(Some(live), Some(live), Some(Duration::from_secs(1))),
        )]);
        let started = walks.start(
            BTreeMap::from([(key, peer)]),
            &observed,
            &before,
            Instant::now(),
        );

        assert_eq!(started, Vec::<Started>::new());
        let recorded = walks
            .walks
            .get(&key)
            .map(|(_, walk)| (walk.list().first().copied(), walk.settled()));
        assert_eq!(recorded, Some((Some(live), true)));
        assert_eq!(walks.next_due(), None);
    }

    /// A recent authenticated endpoint survives a stale list, but old or unconfirmed endpoints do not.
    #[test]
    fn a_reinstall_keeps_only_a_live_authenticated_off_list_endpoint() {
        let peer = walking(4).peer;
        let learned = at("10.9.0.44:10254");
        let live = engine_endpoint(Some(learned), Some(learned), Some(Duration::from_secs(179)));
        assert_eq!(kept_address(&peer, live, None), Some(learned));

        let expired = engine_endpoint(Some(learned), Some(learned), Some(SILENT));
        assert_eq!(kept_address(&peer, expired, None), None);

        let unconfirmed = engine_endpoint(Some(learned), None, Some(Duration::from_secs(1)));
        assert_eq!(kept_address(&peer, unconfirmed, None), None);

        let different = engine_endpoint(
            Some(learned),
            Some(at("10.9.0.45:10254")),
            Some(Duration::from_secs(1)),
        );
        assert_eq!(kept_address(&peer, different, None), None);
    }

    /// J988 review: only a handshake younger than [`SILENT`] keeps an authenticated address, and
    /// the age is the engine's own monotonic one, so no clock is compared across machines.
    #[test]
    fn engine_endpoint_keeps_the_confirmed_address_only_while_the_handshake_is_younger_than_silent()
    {
        let learned = at("10.9.0.44:10254");
        let just_inside = Duration::from_millis(179_999);
        assert_eq!(
            engine_endpoint(Some(learned), Some(learned), Some(just_inside)).live_confirmed,
            Some(learned)
        );
        assert_eq!(
            engine_endpoint(Some(learned), Some(learned), Some(SILENT)).live_confirmed,
            None
        );
        assert_eq!(
            engine_endpoint(Some(learned), Some(learned), None).live_confirmed,
            None,
            "a peer that never handshook has no live session to keep"
        );
        assert_eq!(
            engine_endpoint(Some(learned), Some(learned), Some(Duration::ZERO)).send,
            Some(learned),
            "the send endpoint is reported unchanged"
        );
    }

    /// J988 review: a peer kept on an off-list address that then really goes away is not kept
    /// forever. Once its session is older than [`SILENT`] the retained walk reads as silent and the
    /// next snapshot-less refresh walks the coordinator's list again, so the new endpoint is tried.
    #[test]
    fn a_kept_off_list_endpoint_ages_out_when_its_session_goes_silent() {
        let mut walks = Walks::default();
        let peer = walking(9).peer;
        let key = peer.key;
        let live = at("10.9.0.44:10254");
        let alive = Seen {
            received: 7,
            handshake: 1,
            endpoint: Some(live),
        };
        let before = BTreeMap::from([(
            key,
            engine_endpoint(Some(live), Some(live), Some(Duration::from_secs(1))),
        )]);
        let wanted = BTreeMap::from([(key, peer.clone())]);
        let now = Instant::now();
        assert_eq!(
            walks.start(
                wanted.clone(),
                &BTreeMap::from([(key, alive)]),
                &before,
                now
            ),
            Vec::<Started>::new()
        );
        // Still alive: an unrelated refresh starts nothing.
        let none = BTreeMap::new();
        assert_eq!(
            walks.start(wanted.clone(), &BTreeMap::from([(key, alive)]), &none, now),
            Vec::<Started>::new()
        );
        // Session now older than SILENT: `observe` reads its handshake as 0.
        let gone = Seen {
            handshake: 0,
            ..alive
        };
        let restarted = walks.start(wanted, &BTreeMap::from([(key, gone)]), &none, now);
        assert_eq!(restarted.len(), 1, "the silent peer is walked again");
        assert!(
            restarted
                .iter()
                .all(|started| started.key == key && started.engine_at == Some(live)),
            "the walk begins from where the engine sits"
        );
    }

    /// J988 review: an off-list address whose handshake has expired is not put on the new walk's
    /// list, so a peer that really moved walks the coordinator's addresses only.
    #[test]
    fn an_expired_off_list_endpoint_does_not_join_the_new_walk() {
        let mut walks = Walks::default();
        let peer = walking(10).peer;
        let key = peer.key;
        let stale = at("10.9.0.44:10254");
        let observed = BTreeMap::from([(
            key,
            Seen {
                received: 7,
                handshake: 0,
                endpoint: Some(stale),
            },
        )]);
        let before =
            BTreeMap::from([(key, engine_endpoint(Some(stale), Some(stale), Some(SILENT)))]);
        walks.start(
            BTreeMap::from([(key, peer.clone())]),
            &observed,
            &before,
            Instant::now(),
        );
        let list = walks.walks.get(&key).map(|(_, walk)| walk.list().to_vec());
        let expected: Vec<_> = peer
            .endpoint
            .into_iter()
            .chain(peer.candidates.iter().copied())
            .collect();
        assert_eq!(list, Some(expected));
    }

    /// An idle peer with a live session on its first address starts finished: no address to
    /// install, so no handshake, no timer, and later snapshots that leave it unchanged (and its
    /// session live) start nothing either.
    #[test]
    fn an_idle_established_peer_costs_no_handshake() {
        let policy = walking(4);
        let wanted = walking_peers([&policy]);
        let key = PublicKey([4; 32]);
        let mut walks = Walks::default();
        assert!(walks.prepare(&wanted), "a new peer needs one counter read");
        let observed = Observed::from([(
            key,
            Seen {
                received: 148,
                handshake: 1_000,
                endpoint: policy.peer.endpoint,
            },
        )]);
        let before = BTreeMap::from([(
            key,
            EngineEndpoint {
                send: policy.peer.endpoint,
                ..EngineEndpoint::default()
            },
        )]);
        let none: Vec<Started> = Vec::new();
        assert_eq!(
            walks.start(wanted.clone(), &observed, &before, Instant::now()),
            none
        );
        assert_eq!(walks.next_due(), None, "no timer for a finished walk");
        // A found walk is checked for silence on every snapshot (J699 P3-2), but a live
        // session starts nothing.
        walks.prepare(&wanted);
        assert_eq!(
            walks.start(wanted, &observed, &before, Instant::now()),
            none
        );
        assert_eq!(walks.next_due(), None);
    }

    /// A peer with no session starts running on its first candidate and steps to the next one
    /// after [`crate::candidates::STEP`].
    #[test]
    fn a_silent_peer_walks_to_its_next_candidate() {
        let policy = walking(4);
        let key = PublicKey([4; 32]);
        let mut walks = Walks::default();
        let wanted = walking_peers([&policy]);
        assert!(walks.prepare(&wanted));
        let now = Instant::now();
        let started = walks.start(wanted, &Observed::new(), &BTreeMap::new(), now);
        assert_eq!(
            started,
            [Started {
                key,
                address: at("198.51.100.4:30254"),
                engine_at: None,
            }]
        );
        let later = now + crate::candidates::STEP + Duration::from_millis(1);
        assert_eq!(
            walks.step(later, &Observed::new()),
            [(key, at("198.51.100.4:10254"))]
        );
    }

    /// A peer without a candidate list, or with no first address, never walks.
    #[test]
    fn only_peers_with_a_list_walk() {
        let mut bare = walking(4);
        bare.peer.candidates.clear();
        let mut unaddressed = walking(5);
        unaddressed.peer.endpoint = None;
        assert!(walking_peers([&bare, &unaddressed]).is_empty());
    }

    /// A peer whose grants allow no packet in either direction never walks, even with a first
    /// address and candidates: the engines don't install it, so a walk step would send
    /// handshakes toward a peer the node must not talk to (J781 finding 3, #515, #483).
    #[test]
    fn a_peer_without_network_access_never_walks() {
        let mut denied = walking(4);
        denied.inbound = TrafficPolicy::None;
        denied.outbound = TrafficPolicy::None;
        let mut no_ports = walking(5);
        no_ports.inbound = TrafficPolicy::Ports(std::collections::BTreeSet::new());
        no_ports.outbound = TrafficPolicy::None;
        let mut one_way = walking(6);
        one_way.inbound = TrafficPolicy::None;
        let wanted = walking_peers([&denied, &no_ports, &one_way]);
        assert_eq!(
            wanted.keys().copied().collect::<Vec<_>>(),
            [PublicKey([6; 32])],
            "only the peer with outbound access walks"
        );
    }

    /// A rotation overlap that still routes through the previous key walks under that key.
    #[test]
    fn a_walk_follows_the_key_that_owns_the_routes() {
        let mut policy = walking(4);
        policy.peer.previous_key = Some(PublicKey([9; 32]));
        policy.peer.previous_active = true;
        assert!(walking_peers([&policy]).contains_key(&PublicKey([9; 32])));
    }
}
