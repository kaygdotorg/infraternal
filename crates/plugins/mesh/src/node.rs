//! Owns the root-only Mesh node, staged public configuration and synchronous data-plane lifecycle [163,166,198].
pub use crate::enrolment::{Enrolment, MachineBindingError};
pub use crate::gotatun_node::{EngineKind, EngineReason, EngineSelection};
use crate::{
    dataplane::Config,
    firewall::Firewall,
    gotatun_node::Engine,
    wireguard::{Client, Device, Key, RouteValidation},
};
use std::os::unix::net::UnixStream;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, Shutdown},
    os::fd::AsFd,
    sync::{Arc, Mutex, MutexGuard},
    thread::{self, JoinHandle},
};

/// The per-peer route state shared by config updates, authenticated live endpoints, route
/// recovery, and relay callbacks (#381).
///
/// One mutex guards all maps, and every peer host-route write happens while it is held.
/// `peers` is the set of peers whose routes this node last installed, keyed by public key,
/// so a relay callback resolves the *current* endpoint and membership at write time instead
/// of a copy taken when its relay shim started. `live_endpoints` holds authenticated endpoints
/// learned by `GotaTun`; it only overrides route selection and never changes the accepted snapshot.
/// A key missing from `peers` means the coordinator removed that peer: callbacks for it write
/// nothing. `link` is the mesh link the route-repair worker proved when it started; live-endpoint
/// refreshes write only to that link, never to whichever link holds the shared name later.
#[derive(Clone, Debug, Default)]
struct PeerRouteState {
    /// Subnet routes share the same lock as the live endpoints they are derived from.
    client_routes: crate::subnet_routes::ClientRoutes,
    /// Active relay budgets; a peer without an entry uses its direct-path budget.
    overrides: BTreeMap<crate::policy::model::PublicKey, u16>,
    /// Live direct endpoints learned after the coordinator's configured endpoint.
    ///
    /// Invariant (#489 J552 P2-1): no entry is a loopback address, and no peer with a relay
    /// override has an entry. While a relay carries a peer, `GotaTun` confirms the relay shim's
    /// local `127.0.0.1` socket as the peer's endpoint; a direct budget derived from it is the
    /// loopback MTU (65456), which would outlive the relay. Installing a relay drops the peer's
    /// entry, so its direct fallback uses the configured endpoint until a direct packet proves
    /// another one.
    live_endpoints: BTreeMap<crate::policy::model::PublicKey, std::net::SocketAddr>,
    /// Installed peers, refreshed with their routes for repair and relay path updates.
    peers: BTreeMap<crate::policy::model::PublicKey, crate::dataplane::Peer>,
    /// The owner-marked link the running route-repair worker proved (J485), or `None` while no
    /// worker runs. Its index, engine and owner are re-checked before each live-endpoint write.
    link: Option<crate::wireguard::ActiveLink>,
    /// Each peer's host routes as this process last wrote them, from a snapshot or a
    /// live-endpoint refresh.
    ///
    /// Both writers skip a peer whose routes would not change: steady traffic does not rewrite
    /// two routes per peer up to four times a second (#489 J549 P2), and a snapshot that changes
    /// one peer writes that peer's routes only, not every peer's (#260 J1240: 424 ms at 4,096
    /// peers before). A relay change, a repair that added a route, a new link, and any failed or
    /// rolled-back batch forget the entry, which costs at most one extra write and never leaves
    /// a stale route in place. A process starts with no entries, so the first snapshot after a
    /// restart writes every route. Forget entries only through
    /// [`PeerRouteState::forget_written`] and [`PeerRouteState::forget_written_for`], which also
    /// schedule the re-derivation below.
    ///
    /// Invariant: an entry is never newer than the kernel. It is removed before its peer's write
    /// and stored again only once that write succeeded. Between snapshots the route-repair
    /// worker, not this record, notices routes that someone else deleted.
    written: BTreeMap<crate::policy::model::PublicKey, WrittenRoute>,
    /// Whether every installed peer outside `recheck` had its budget derived for its current
    /// route endpoint while the underlay watch read `checked_generation` (#489 J552 P2-2).
    ///
    /// A refresh re-derives only `recheck` while this holds and the generation is unchanged, so
    /// steady traffic costs no netlink request at all. It starts false, and anything that may
    /// leave a route at another budget (a new peer set, a new link, a failed write) clears it.
    all_current: bool,
    /// The underlay generation the last full re-derivation started from.
    checked_generation: Option<u64>,
    /// Peers whose learned endpoint or written budget changed since their last derivation.
    recheck: BTreeSet<crate::policy::model::PublicKey>,
    /// Peers whose last underlay lookup failed, with the retries already queued for them at this
    /// underlay generation (#489 J609 P3). A failed lookup writes the safe fallback, but the
    /// peer goes back to `recheck` up to [`FAILED_LOOKUP_RETRIES`] times so a transient error
    /// does not hold the fallback until the 30 s inventory check. Cleared by every full
    /// re-derivation, so each underlay change earns the peer new retries.
    failed_lookups: BTreeMap<crate::policy::model::PublicKey, u8>,
    /// The running route-repair worker's underlay watch, published with `link`. Without one, no
    /// change can be trusted to be announced, so every refresh re-derives every peer.
    underlay: Option<Arc<crate::wireguard::UnderlayWatch>>,
}

impl PeerRouteState {
    /// Record `peers` as the installed set, replacing the previous one.
    ///
    /// The next live refresh re-derives every peer, since configured endpoints may have moved.
    fn set_peers(&mut self, peers: &[crate::dataplane::Peer]) {
        let installed: BTreeMap<_, _> = peers.iter().map(|peer| (peer.key, peer.clone())).collect();
        self.live_endpoints
            .retain(|key, _| installed.contains_key(key));
        self.peers = installed;
        self.all_current = false;
    }

    /// Record that a snapshot derived or confirmed every installed peer's direct budget for its
    /// current route endpoint at underlay `generation` ([`write_snapshot_routes`]), which is what
    /// a full claim of the live refresh establishes (see `claim_live_route_rechecks`), so that
    /// refresh need not look every peer up again. `None` changes nothing.
    fn mark_current(&mut self, generation: Option<u64>) {
        let Some(generation) = generation else {
            return;
        };
        self.all_current = true;
        self.checked_generation = Some(generation);
        self.recheck.clear();
        self.failed_lookups.clear();
    }

    /// Forget every written budget: some other writer may have changed any peer's routes.
    fn forget_written(&mut self) {
        self.written.clear();
        self.recheck.clear();
        self.all_current = false;
    }

    /// Forget one peer's written budget and re-derive it on the next live refresh.
    fn forget_written_for(&mut self, key: crate::policy::model::PublicKey) {
        self.written.remove(&key);
        self.recheck.insert(key);
    }

    /// Record the outcome of one peer's underlay lookup: a failure queues the peer for the next
    /// refresh until its retries at this generation run out, and a success resets them.
    ///
    /// The bound keeps a path that keeps failing (an unreachable endpoint, a `prohibit` rule)
    /// from costing one netlink request per refresh under steady traffic. Once the retries are
    /// spent, the fallback stays until the underlay watch moves or the inventory check runs.
    fn note_lookup(&mut self, key: crate::policy::model::PublicKey, failed: bool) {
        if !failed {
            self.failed_lookups.remove(&key);
            return;
        }
        let retries = self.failed_lookups.entry(key).or_insert(0);
        if *retries < FAILED_LOOKUP_RETRIES {
            *retries += 1;
            self.recheck.insert(key);
        }
    }

    /// Copy a peer with its authenticated live endpoint for route-MTU selection.
    ///
    /// A peer a relay carries keeps its configured endpoint, and so does a learned endpoint that
    /// could not be a direct path; `live_endpoints` never holds either, and this re-checks it so
    /// a later writer cannot break the invariant by accident.
    fn route_peer(&self, peer: &crate::dataplane::Peer) -> crate::dataplane::Peer {
        let mut route_peer = peer.clone();
        if let Some(endpoint) = self.live_endpoints.get(&peer.key)
            && !self.overrides.contains_key(&peer.key)
            && is_direct_learned_endpoint(*endpoint)
        {
            route_peer.endpoint = Some(*endpoint);
        }
        route_peer
    }
}

/// Whether an authenticated endpoint `GotaTun` reports can be a direct underlay path.
///
/// Loopback and unspecified sources are local sockets, not a remote peer's address: the relay
/// shim delivers relayed datagrams from `127.0.0.1` (#489 J552 P2-1). The loopback route's MTU
/// (65536) says nothing about the real path, so such an address never chooses a route budget.
/// IPv4-mapped IPv6 sources are judged as the IPv4 address they carry.
fn is_direct_learned_endpoint(endpoint: std::net::SocketAddr) -> bool {
    let address = endpoint.ip().to_canonical();
    !address.is_loopback() && !address.is_unspecified()
}

/// The snapshot and live-endpoint route writers and their shared record, in their own file
/// (`node_peer_routes.rs`).
#[path = "node_peer_routes.rs"]
mod peer_routes;
use peer_routes::{WrittenRoute, update_live_peer_endpoints, write_snapshot_routes};

/// The route-repair worker and its inventory check, in their own file (`node_route_repair.rs`).
#[path = "node_route_repair.rs"]
mod route_repair;
use route_repair::RouteRepairWorker;
#[cfg(test)]
use route_repair::{ROUTE_REPAIR_PASSES, repair_accepted_routes};

/// How many refreshes in a row look a peer's underlay up again after a failed lookup, per
/// underlay generation (#489 J609 P3). Two covers a transient socket error (`EINTR`, `ENOMEM`)
/// and a lookup racing a change; more would only repeat a lookup that keeps failing.
const FAILED_LOOKUP_RETRIES: u8 = 2;

/// Recover route state after a callback panics while holding its mutex.
fn lock_route_state(state: &Mutex<PeerRouteState>) -> MutexGuard<'_, PeerRouteState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Apply a full route snapshot while retaining relay budgets and valid live endpoints.
///
/// On success `peers` becomes the installed set that relay callbacks resolve against. The
/// returned snapshot lets an enclosing transaction roll route state back. Keys in
/// `clear_overrides_for` also forget their learned endpoint because the coordinator changed or
/// removed that peer's direct route definition.
fn refresh_peer_routes_from(
    state: &Mutex<PeerRouteState>,
    peers: &[crate::dataplane::Peer],
    clear_overrides_for: &BTreeSet<crate::policy::model::PublicKey>,
) -> io::Result<PeerRouteState> {
    let mut state = lock_route_state(state);
    let previous = state.clone();
    for key in clear_overrides_for {
        state.overrides.remove(key);
        state.live_endpoints.remove(key);
    }
    state.set_peers(peers);
    match write_snapshot_routes(&mut state, peers) {
        Ok(current) => state.mark_current(current),
        Err(error) => {
            *state = previous;
            // A partial batch may have changed any route; the restored budgets are not trusted.
            state.forget_written();
            return Err(error);
        }
    }
    Ok(previous)
}

/// Write one peer's route from the accepted state, for a relay path change or MTU refresh.
///
/// `relay_mtu` is `Some` while a relay carries the peer and `None` once it falls back to its
/// direct endpoint. The peer is looked up by key under the state lock, so the write uses the
/// endpoint of the latest accepted snapshot. When the peer is gone, its override is dropped
/// and nothing is written: re-adding the host route would leak it outside the route inventory.
/// # Errors
/// Returns route-netlink errors and leaves the override map as it was.
#[cfg(feature = "relay")]
fn update_relay_route_mtu(
    state: &Mutex<PeerRouteState>,
    key: crate::policy::model::PublicKey,
    relay_mtu: Option<u16>,
) -> io::Result<()> {
    let mut state = lock_route_state(state);
    let Some(peer) = state.peers.get(&key).cloned() else {
        state.overrides.remove(&key);
        return Ok(());
    };
    let previous = match relay_mtu {
        Some(mtu) => state.overrides.insert(key, mtu),
        None => state.overrides.remove(&key),
    };
    // A relay starts because the direct path failed, and while it runs the confirmed endpoint
    // is its shim. Forget the learned one, so the fallback starts from the configured endpoint
    // (#489 J552 P2-1).
    let learned = if relay_mtu.is_some() {
        state.live_endpoints.remove(&key)
    } else {
        None
    };
    state.forget_written_for(key);
    let route_peer = state.route_peer(&peer);
    let result = Device::routes_with_mtu_overrides(
        std::slice::from_ref(&route_peer),
        &state.overrides,
        false,
        state.underlay.as_deref(),
    );
    if result.is_err() {
        match previous {
            Some(previous) => state.overrides.insert(key, previous),
            None => state.overrides.remove(&key),
        };
        if previous.is_none()
            && let Some(learned) = learned
        {
            state.live_endpoints.insert(key, learned);
        }
    } else if previous.is_some() != relay_mtu.is_some() && !state.client_routes.wanted.is_empty() {
        // The relay uses a local shim, so its former direct endpoint no longer needs a hole.
        state.client_routes.dirty = true;
        state.sync_client_routes(false);
    }
    result
}

pub use crate::dataplane::Chunk;

/// Test seam (#260 J220 P2): runs once in `up` on the kernel engine, after this node created and
/// claimed its link and before it configures the private key, so a namespace test can replace
/// the link in that window.
#[cfg(feature = "test-support")]
pub static BEFORE_KERNEL_KEY: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
/// Test seam (#285 J284 P3-b): runs once in a rotation settle that moves this node to the candidate, after
/// the marker and the recorded key and right before the journal save, so a namespace test can make that save
/// fail.
#[cfg(feature = "test-support")]
pub static BEFORE_SETTLE_SAVE: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
/// A one-shot, fallible test step: set it to a closure, and the transaction runs (and clears) it
/// at its seam; an `Err` fails the step the seam stands in front of.
#[cfg(feature = "test-support")]
pub type TransactionSeam = std::sync::Mutex<Option<Box<dyn FnOnce() -> io::Result<()> + Send>>>;
/// Test seam (#265 J618): runs once in a full mesh transaction right before its disk save. An
/// `Err` fails that save, so a namespace test can drive the rollback of a transaction that has
/// already changed the engine's peers.
#[cfg(feature = "test-support")]
pub static BEFORE_TRANSACTION_SAVE: TransactionSeam = std::sync::Mutex::new(None);
/// Test seam (#265 J618): runs once in a failed full transaction's rollback right before the
/// `GotaTun` engine gets its old peers back. An `Err` fails that step, leaving the state a
/// failed rollback leaves behind for the test to inspect.
#[cfg(feature = "test-support")]
pub static BEFORE_ROLLBACK_ENGINE_APPLY: TransactionSeam = std::sync::Mutex::new(None);
/// Run and clear one of the fallible transaction test seams above; `Ok` when none is set.
#[cfg(feature = "test-support")]
fn run_transaction_seam(seam: &TransactionSeam) -> io::Result<()> {
    seam.lock()
        .ok()
        .and_then(|mut hook| hook.take())
        .map_or(Ok(()), |hook| hook())
}
/// Test seam (#260 J143 P3-4): runs once in `down`, after this node's link is gone and before its
/// shared-filter decision, so a namespace test can start another installation in that window.
#[cfg(feature = "test-support")]
pub static BEFORE_SHARED_FILTER_DECISION: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
/// Holds an incomplete mesh snapshot until all ordered configuration chunks arrive.
struct Pending {
    server: Option<crate::policy::model::NodeId>,
    next: u32,
    version: u64,
    from_version: Option<u64>,
    default_policy: crate::dataplane::DefaultPolicy,
    config: Config,
}

/// Tracks whether a new authority has fenced old peers and still needs a full replacement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum AuthorityResetState {
    /// No authority reset is pending.
    #[default]
    Stable,
    /// The old peer set is fenced; only a complete snapshot may restore mesh access.
    AwaitingFullSnapshot,
}

/// The peer routes a restart may have to retire: the recorded inventory plus every route the saved
/// snapshot would install. An IPv4-only peer (#578, J1142) contributes only its IPv4 route.
fn restore_routes(
    store: &crate::node_state::Store,
    state: &crate::node_state::State,
) -> io::Result<BTreeSet<IpAddr>> {
    let mut routes = store.route_inventory()?;
    // A crash may leave the accepted snapshot older than a pruned journal.
    // Union its peer addresses before replay; never claim arbitrary routes.
    if let Some(config) = &state.config {
        routes.extend(
            config
                .peers
                .values()
                .flat_map(|peer| peer.peer.routed_addresses()),
        );
    }
    Ok(routes)
}

/// The keys that prove a live `GotaTun` TUN is this installation's, bounded by its durable
/// rotation journal. The root-only key file and interface marker must each name one of those
/// journal keys; retirement and TUN adoption use this same proof (D332, #367).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct GotatunProof(Vec<crate::policy::model::PublicKey>);
impl GotatunProof {
    /// Whether `key` is one of the identities this installation can prove.
    fn accepts(&self, key: crate::policy::model::PublicKey) -> bool {
        self.0.contains(&key)
    }

    /// Whether there is no saved identity that can prove ownership of a live link.
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Build the owner proof from the saved engine, interface key, private key and bounded journal.
fn gotatun_owner_proof(
    store: &crate::node_state::Store,
    snapshot_key: Option<crate::policy::model::PublicKey>,
) -> io::Result<GotatunProof> {
    if store.recorded_engine()? != Some(EngineKind::GotaTun) {
        return Ok(GotatunProof::default());
    }
    let Some(recorded) = store.recorded_interface()?.or(snapshot_key) else {
        return Ok(GotatunProof::default());
    };
    let Some(private_public) = store
        .read_private_key()?
        .map(|bytes| crate::gotatun_node::secret_from_bytes(&bytes).map(|pair| pair.1))
        .transpose()?
    else {
        return Ok(GotatunProof::default());
    };
    let mut keys = if let Some(rotation) = store.rotation_secret()? {
        let mut keys = Vec::with_capacity(2);
        if !rotation.completed {
            keys.push(crate::wireguard::Key::from_private(&rotation.previous)?.1);
        }
        if rotation.commit_requested || rotation.completed {
            keys.push(crate::wireguard::Key::from_private(&rotation.candidate)?.1);
        }
        keys
    } else {
        vec![recorded]
    };
    keys.sort_unstable();
    keys.dedup();
    if keys.contains(&recorded) && keys.contains(&private_public) {
        Ok(GotatunProof(keys))
    } else {
        Ok(GotatunProof::default())
    }
}

/// Whether `link` is the `GotaTun` TUN named by `proof`.
fn proven_gotatun_link(link: &crate::wireguard::ActiveLink, proof: &GotatunProof) -> bool {
    link.engine == EngineKind::GotaTun
        && !proof.is_empty()
        && link.owner.is_some_and(|owner| proof.accepts(owner))
}

/// Choose the port a restarted kernel node keeps on the link it adopted, and save it.
///
/// Kernel links outlive their process (D332), so restore finds the old port already bound.
/// D391 still applies: an explicit `INFRATERNAL_MESH_PORT` binds exactly that port and fails if it
/// is taken (J555 F3). Without an override, the node moves back to its saved or default port when
/// that is free, the same as `GotaTun`, which binds on every start, and otherwise keeps the port it
/// has as its fallback. A retained link from an older daemon may sit on the reserved 51820; it
/// moves to a fresh port. The saved port follows `up`'s rule: a fallback is saved, an override
/// saves the default, so removing the override later moves the node back.
/// # Errors
/// Reports a malformed override, a taken explicit port, kernel errors, or a failed state write.
fn restore_kernel_listen_port(node: &Node, ifindex: u32, current: u16) -> io::Result<u16> {
    let saved = node
        .store
        .as_ref()
        .map(crate::node_state::Store::recorded_listen_port)
        .transpose()?
        .flatten();
    let request = crate::listen_port::from_environment(saved)?;
    let mut port = current;
    if request.port != current {
        match Device::set_listen_port(ifindex, request.port) {
            Ok(()) => port = request.port,
            Err(error) if request.allow_fallback && error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error),
        }
    }
    if port == 51820 {
        port = Device::allocate_port(ifindex)?;
    }
    if let Some(store) = &node.store {
        let keep = if request.allow_fallback {
            port
        } else {
            crate::listen_port::DEFAULT_PORT
        };
        if saved != Some(keep) {
            store.record_listen_port(keep)?;
        }
    }
    Ok(port)
}

/// Recreate the `GotaTun` private-key file only from the durable rotation journal.
///
/// A clean stop removes that file after stopping the userspace engine. During an open commit, a
/// restart must select the candidate even if the old file survived; before commit intent, only
/// the predecessor is authorized. The recorded public key bounds both states so an unrelated or
/// incomplete journal can never replace the local key.
fn recover_gotatun_private_key_from_journal(store: &crate::node_state::Store) -> io::Result<()> {
    let Some(rotation) = store.rotation_secret()? else {
        return Ok(());
    };
    let candidate_public = Key::from_private(&rotation.candidate)?.1;
    let previous_public = if rotation.completed {
        None
    } else {
        Some(Key::from_private(&rotation.previous)?.1)
    };
    let recorded = store
        .recorded_interface()?
        .ok_or(io::ErrorKind::InvalidData)?;
    let recorded_is_authorized = if rotation.completed {
        recorded == candidate_public
    } else if rotation.commit_requested {
        Some(recorded) == previous_public || recorded == candidate_public
    } else {
        Some(recorded) == previous_public
    };
    if !recorded_is_authorized {
        return Err(io::ErrorKind::InvalidData.into());
    }

    let selected = if rotation.completed || rotation.commit_requested {
        &rotation.candidate
    } else {
        &rotation.previous
    };
    if let Some(saved) = store.read_private_key()? {
        if saved.as_slice() == selected.as_slice() {
            return Ok(());
        }
        if rotation.commit_requested
            && !rotation.completed
            && saved.as_slice() == rotation.previous.as_slice()
        {
            return store.replace_private_key(&rotation.candidate);
        }
        return Err(io::ErrorKind::InvalidData.into());
    }
    store.replace_private_key(selected)
}

/// The keys that prove a live kernel link is this installation's (D340, #285).
///
/// Normally exactly one: the interface key this node recorded, or for older state the key the
/// coordinator bound. A kernel key rotation changes four things that cannot change at once: the
/// device key, the link's owner marker, the recorded key and the rotation journal. While one is
/// open, the journal's own keys are accepted too: the predecessor until the rotation completes,
/// and the candidate once commit intent is durable. No key outside this installation's own
/// private records is ever accepted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct KernelProof(Vec<crate::policy::model::PublicKey>);
impl KernelProof {
    /// A proof by exactly one key: the one this node created or committed its link for.
    fn single(key: crate::policy::model::PublicKey) -> Self {
        Self(vec![key])
    }
    /// Whether `key` is one of this installation's own.
    fn accepts(&self, key: crate::policy::model::PublicKey) -> bool {
        self.0.contains(&key)
    }
    /// Whether nothing can be proven, as for a node that never created a kernel link.
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The proof that a live kernel link is this installation's: the state recorded the kernel
/// engine (or no engine, as the kernel-only format did) and the interface key this node created
/// its link for, bounded by an open key rotation (see [`KernelProof`]). Kernel `WireGuard` holds
/// the private key itself, so there is no key file to check. Restore, `down`, retirement and the
/// D346 key carry all use this one proof (D340).
fn kernel_owner_proof(
    store: &crate::node_state::Store,
    snapshot_key: Option<crate::policy::model::PublicKey>,
) -> io::Result<KernelProof> {
    if store
        .recorded_engine()?
        .is_some_and(|engine| engine != EngineKind::Kernel)
    {
        return Ok(KernelProof::default());
    }
    let mut keys: Vec<_> = store
        .recorded_interface()?
        .or(snapshot_key)
        .into_iter()
        .collect();
    if let Some(rotation) = store.rotation_secret()? {
        if !rotation.completed {
            keys.push(Key::from_private(&rotation.previous)?.1);
        }
        if rotation.commit_requested || rotation.completed {
            keys.push(Key::from_private(&rotation.candidate)?.1);
        }
    }
    keys.sort_unstable();
    keys.dedup();
    Ok(KernelProof(keys))
}

/// Whether `link` is the kernel link that `proof` owns (D340). The link name and the engine
/// marker are shared by every installation on the host, so neither proves anything. A link
/// created since D340 names its owner in its marker, which holds before its key is set. A link
/// with the older unbound marker is ours only when the kernel holds our recorded key; an unkeyed
/// one cannot be proven and is left alone.
fn proven_kernel_link(link: &crate::wireguard::ActiveLink, proof: &KernelProof) -> bool {
    link.engine == EngineKind::Kernel
        && !proof.is_empty()
        && match link.owner {
            Some(owner) => proof.accepts(owner),
            None => Device::identity_at(link.ifindex).is_ok_and(|(key, _)| proof.accepts(key)),
        }
}

/// Retire this installation's own live link of the engine it no longer runs (D346): a node that
/// ran kernel `WireGuard` as the old default moves to `GotaTun`, and an explicit opt-out moves
/// back. The caller has proven `link` is ours.
///
/// The public key is kept both ways, so peers and the coordinator see no change. Kernel to
/// `GotaTun`: the kernel's private key goes to the node's private key file before the link is
/// deleted. `GotaTun` to kernel: the key file stays, and the kernel is configured from it. A
/// disabled node keeps nothing; its link only goes.
fn switch_engine(
    store: &crate::node_state::Store,
    link: crate::wireguard::ActiveLink,
    enabled: bool,
    kernel_proof: &KernelProof,
) -> io::Result<()> {
    if link.engine == EngineKind::Kernel {
        if enabled {
            carry_kernel_key(store, link.ifindex, kernel_proof)?;
        }
        // Retire peers before the link deletion removes all routes, as `down` does.
        Client::new()?.clear_peers()?;
        // The caller records the selected Linux engine after this key carry. Both engines use the
        // same journal, so an open operation remains recoverable after the data plane changes.
    }
    Device::delete_ifindex(link.ifindex)
}

/// Copy the proven kernel link's private key into the key file, unless the file already holds it.
/// A device without a key yet has no identity to carry, and the engine makes a new one.
///
/// The key is read from the proven link by its index, never by the shared name, and must derive
/// a key this node recorded (its interface key, or a key of its own open rotation), so a link
/// substituted under the name cannot hand us its identity (#260 J220 P2, #285).
fn carry_kernel_key(
    store: &crate::node_state::Store,
    ifindex: u32,
    recorded: &KernelProof,
) -> io::Result<()> {
    let key = match Device::private_key_at(ifindex) {
        Ok(key) => key,
        Err(error) if error.kind() == io::ErrorKind::InvalidData => return Ok(()),
        Err(error) => return Err(error),
    };
    let (_, public) = crate::gotatun_node::secret_from_bytes(&key[..])?;
    if !recorded.accepts(public) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if let Some(existing) = store.read_private_key()? {
        if crate::gotatun_node::secret_from_bytes(&existing)?.1 == public {
            return Ok(());
        }
        store.remove_private_key()?;
    }
    store.write_private_key(&key[..])
}

/// Whether a saved `GotaTun` snapshot key is still supported by the private records and rotation journal.
fn gotatun_snapshot_binding_is_authorized(
    store: &crate::node_state::Store,
    bound: crate::policy::model::PublicKey,
) -> io::Result<bool> {
    let Some(private) = store.read_private_key()? else {
        return Ok(false);
    };
    let private_public = crate::gotatun_node::secret_from_bytes(&private)?.1;
    let Some(rotation) = store.rotation_secret()? else {
        return Ok(private_public == bound);
    };
    let candidate_public = Key::from_private(&rotation.candidate)?.1;
    let recorded = store.recorded_interface()?;
    if rotation.completed {
        // Only the candidate's private file and public record prove the new identity. The finished
        // marker also binds a stale snapshot to this rotation's predecessor, if that key is known.
        return Ok(private_public == candidate_public
            && recorded == Some(candidate_public)
            && rotation.completed_binding_matches(bound, candidate_public));
    }
    let previous_public = Key::from_private(&rotation.previous)?.1;
    let candidate_is_authorized = rotation.commit_requested;
    let bound_is_authorized =
        bound == previous_public || (candidate_is_authorized && bound == candidate_public);
    let private_is_authorized = private_public == previous_public
        || (candidate_is_authorized && private_public == candidate_public);
    let record_is_authorized = recorded.is_none_or(|key| {
        key == previous_public || (candidate_is_authorized && key == candidate_public)
    });
    Ok(bound_is_authorized && private_is_authorized && record_is_authorized)
}

/// Restore accepted `GotaTun` configuration while allowing only a journal-proven commit transition.
fn restore_gotatun(node: &mut Node, saved_config: Option<Config>) -> io::Result<()> {
    let store = node.store.as_ref().ok_or(io::ErrorKind::NotFound)?;
    recover_gotatun_private_key_from_journal(store)?;
    if let Some(bound) = saved_config.as_ref().and_then(|config| config.local_key)
        && !gotatun_snapshot_binding_is_authorized(store, bound)?
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // Keep accepted public intent through startup, then clear only the in-memory
    // applied view so replay sends the full snapshot to the newly empty device.
    node.config.clone_from(&saved_config);
    let identity = node.up()?;
    let mut config = saved_config;
    if let Some(config) = config.as_mut()
        && let Some(bound) = config.local_key
        && bound != identity.public_key
    {
        let store = node.store.as_ref().ok_or(io::ErrorKind::NotFound)?;
        if !gotatun_snapshot_binding_is_authorized(store, bound)? {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // Commit intent selects the candidate for reattach; normalize the replayed snapshot
        // so a later restart cannot mistake its older local-key field for the active identity.
        config.local_key = Some(identity.public_key);
    }
    if let Some(config) = config {
        node.config = None;
        node.apply(config)?;
    }
    Ok(())
}

pub use crate::dataplane::Identity;

/// Where a node's engine choice came from (D346, #260 J213 P3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EngineSource {
    /// Nothing chose: the Linux default.
    Default,
    /// The machine's `INFRATERNAL_MESH_ENGINE`.
    Environment,
    /// Code chose it (`with_engine`, `restore_with_engine`); the environment cannot change it.
    Code,
}

impl EngineSource {
    /// What `mesh status` reports: the default, or a choice by the machine or its code.
    fn reason(self) -> EngineReason {
        match self {
            Self::Default => EngineReason::Default,
            Self::Environment | Self::Code => EngineReason::Chosen,
        }
    }
}

/// The component owns its route repair listener while active and closes it on explicit down.
pub struct Node {
    engine_kind: EngineKind,
    engine_source: EngineSource,
    identity: Option<Identity>,
    enabled: bool,
    store: Option<crate::node_state::Store>,
    config: Option<Config>,
    /// Records the irreversible authority fence until its full replacement snapshot arrives.
    authority_reset: AuthorityResetState,
    pending: Option<Pending>,
    routes: BTreeSet<IpAddr>,
    /// Proposed addresses already checked against observed foreign route prefixes.
    route_validation: RouteValidation,
    /// Installed peers and live relay budgets; relay callbacks share it (see [`PeerRouteState`]).
    peer_route_state: Arc<Mutex<PeerRouteState>>,
    /// Passively restores deleted owned peer routes until this node goes down.
    route_repair: Option<RouteRepairWorker>,
    /// Shared by every route-repair worker's listener and the `GotaTun` worker for this node's
    /// life, so peers hear our new endpoint after an underlay change whichever worker heard it
    /// (#483). A field of its own, because the route state is replaced wholesale on rollback.
    underlay_announce: Arc<crate::gotatun_node::UnderlayAnnounce>,
    firewall: Firewall,
    proxy_ingress: infraternal_mesh::proxy_ports::MeshProxyIngress,
    owned: bool,
    /// The key the owned kernel link was created or proven for; `down` re-proves the live link
    /// against it, because another installation can replace a link under the shared name (D340).
    kernel_owner: KernelProof,
    // A committed revision remains restrictive until exact retirement succeeds.
    connection_cleanup_pending: bool,
    /// Whether the last address install put the IPv6 /128 on the mesh link: `Some(false)` while
    /// the link has IPv6 off and the node runs IPv4-only (#578), `None` before any install in
    /// this process. It decides when to log the change and when to retry the IPv6 address.
    mesh_ipv6: Option<bool>,
    client: Option<Client>,
    gotatun: Option<Engine>,
    #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
    // Only a newly accepted full snapshot replaces DNS names; coordinator loss keeps D166 state.
    dns_resolver: Option<crate::dns::Resolver>,
    #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
    dns_integration: crate::dns_integration::DnsIntegration,
    #[cfg(feature = "cutoff-measure")]
    refusing_at_ns: Option<u64>,
    /// Subnet routes this node installs and forwards, rebuilt from the applied snapshot (D197 M3).
    subnet: crate::subnet_routes::SubnetState,
}
impl Default for Node {
    fn default() -> Self {
        Self {
            engine_kind: EngineKind::default(),
            engine_source: EngineSource::Default,
            identity: None,
            enabled: true,
            store: None,
            config: None,
            authority_reset: AuthorityResetState::Stable,
            pending: None,
            routes: BTreeSet::new(),
            route_validation: RouteValidation::default(),
            peer_route_state: Arc::default(),
            route_repair: None,
            underlay_announce: Arc::default(),
            firewall: Firewall::for_node(None, EngineKind::GotaTun),
            proxy_ingress: infraternal_mesh::proxy_ports::MeshProxyIngress::default(),
            owned: false,
            kernel_owner: KernelProof::default(),
            connection_cleanup_pending: false,
            mesh_ipv6: None,
            client: None,
            gotatun: None,
            #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
            dns_resolver: None,
            #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
            dns_integration: crate::dns_integration::DnsIntegration::default(),
            #[cfg(feature = "cutoff-measure")]
            refusing_at_ns: None,
            subnet: crate::subnet_routes::SubnetState::default(),
        }
    }
}

#[cfg(test)]
impl Node {
    /// Build an in-memory node with a known public identity for action-output tests.
    pub(crate) fn with_identity_for_action_test(identity: Identity) -> Self {
        Self {
            identity: Some(identity),
            ..Self::default()
        }
    }
}
impl Node {
    /// Ensure the active node has a listener for exact owned peer-route deletions.
    /// # Errors
    /// Returns route monitor or thread creation errors instead of claiming an unprotected node is up.
    fn ensure_route_repair(&mut self) -> io::Result<()> {
        if self
            .route_repair
            .as_ref()
            .is_some_and(RouteRepairWorker::is_finished)
        {
            self.route_repair.take();
        }
        if self.route_repair.is_none() {
            self.route_repair = Some(RouteRepairWorker::start(
                Arc::clone(&self.peer_route_state),
                Arc::clone(&self.underlay_announce),
            )?);
        }
        Ok(())
    }

    /// Diagnostic firewall completion, valid only when the enclosing chunk returns applied.
    #[cfg(feature = "cutoff-measure")]
    #[must_use]
    pub fn refusing_at_ns(&self) -> Option<u64> {
        self.refusing_at_ns
    }

    /// Use an explicitly selected supported packet-filter frontend in an isolated namespace.
    #[must_use]
    pub fn with_firewall(firewall: Firewall) -> Self {
        Self {
            firewall,
            ..Self::default()
        }
    }

    /// Use an explicitly selected data-plane engine instead of the default.
    ///
    /// Engine-specific tests and fixtures name their engine, so they keep testing it when the
    /// default changes. This choice wins over `INFRATERNAL_MESH_ENGINE` (#260 J213 P3).
    #[must_use]
    pub fn with_engine(mut self, engine: EngineKind) -> Self {
        self.engine_kind = engine;
        self.engine_source = EngineSource::Code;
        self.firewall = Firewall::for_node(self.firewall.backend(), engine);
        self
    }

    /// Restore public intent and the selected, marked mesh data plane.
    /// An ordinary account with no retained mesh ownership gets an inactive node;
    /// inspection alone never creates privileged networking for that account.
    /// # Errors
    /// Refuses unsafe state, unrelated interface ownership or failed policy recovery.
    pub fn restore(path: &std::path::Path) -> io::Result<Self> {
        let requested = EngineKind::from_environment()?;
        let source = if requested.is_some() {
            EngineSource::Environment
        } else {
            EngineSource::Default
        };
        Self::restore_requesting(path, requested, source)
    }

    /// Check the persistent machine ID before starting the remote connection supervisor.
    ///
    /// An installation whose directory has not been created has no prior binding.
    /// # Errors
    /// Refuses a missing persistent ID, foreign Mesh state, or an unsafe or damaged binding.
    pub fn check_enrolled_machine(path: &std::path::Path) -> io::Result<()> {
        use crate::node_state::{machine_fingerprint, read_enrolment_with};
        use std::os::unix::fs::MetadataExt as _;

        let machine = require_enrolment_machine(machine_fingerprint())?;
        match std::fs::symlink_metadata(path) {
            Ok(meta)
                if meta.is_dir()
                    && meta.uid() == nix::unistd::Uid::effective().as_raw()
                    // The low six mode bits are group and other permissions.
                    && meta.mode().trailing_zeros() >= 6 =>
            {
                read_enrolment_with(path, || Some(machine)).map(|_| ())
            }
            Ok(_) => Err(io::ErrorKind::PermissionDenied.into()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Bind a remote Mesh directory before the service can restore it or contact the server.
    ///
    /// The caller holds the process-owned runtime lock. A changed or legacy enrollment
    /// loses stale peers and keys after ownership-checked retirement. A different machine
    /// is refused before either state or networking can change.
    /// # Errors
    /// Requires a persistent machine ID and refuses unsafe state, unowned kernel objects and
    /// incomplete retirement or publication.
    pub fn prepare_enrolled_restore(
        path: &std::path::Path,
        enrolment: Enrolment,
    ) -> io::Result<()> {
        Self::prepare_enrolled_restore_with_machine(
            path,
            enrolment,
            crate::node_state::machine_fingerprint(),
        )
    }

    /// Prepare the restore with a snapshot of the current machine fingerprint.
    pub(crate) fn prepare_enrolled_restore_with_machine(
        path: &std::path::Path,
        enrolment: Enrolment,
        machine: Option<[u8; 32]>,
    ) -> io::Result<()> {
        use crate::node_state::{Store, read_enrolment_with};

        let machine = require_enrolment_machine(machine)?;
        let saved = read_enrolment_with(path, || Some(machine))?;
        if saved
            .as_ref()
            .is_some_and(|saved| saved.enrolment == enrolment)
        {
            return Ok(());
        }
        let (store, state) = Store::open(path)?;
        if store.has_mesh_state()? {
            // A link or filter can only be ours if saved state has an ownership proof.
            if state.backend.is_some()
                || state
                    .config
                    .as_ref()
                    .is_some_and(|config| config.local_key.is_some())
                || store.recorded_interface()?.is_some()
            {
                let plan = Self::plan_retirement(path)?;
                if !plan.left().is_empty() {
                    return Err(unproven_enrolment_retirement(plan.left()));
                }
                // Removing the proven link also retires its old peer routes.
                let left = plan.execute()?;
                if !left.is_empty() {
                    return Err(unproven_enrolment_retirement(&left));
                }
            } else {
                store.discard_rotation_state()?;
                store.remove_private_key()?;
            }
            store.reset_enrolment_state(state.enabled)?;
        }
        store.record_enrolment(path, machine, enrolment)
    }

    /// Restore with an engine chosen in code, in place of `INFRATERNAL_MESH_ENGINE`.
    /// # Errors
    /// The same as [`Node::restore`].
    pub fn restore_with_engine(path: &std::path::Path, engine: EngineKind) -> io::Result<Self> {
        Self::restore_requesting(path, Some(engine), EngineSource::Code)
    }

    /// Only the machine's explicit choice selects the engine (D346). The recorded engine says
    /// which link this node created, for the ownership proofs; a node that recorded kernel
    /// because it was the default before D346 never chose it.
    fn restore_requesting(
        path: &std::path::Path,
        requested_engine: Option<EngineKind>,
        engine_source: EngineSource,
    ) -> io::Result<Self> {
        let (store, state) = crate::node_state::Store::open(path)?;
        let engine_kind = requested_engine.unwrap_or_default();
        // A rootless installation without mesh ownership has nothing to restore.
        // Reading peers/status must not probe the host firewall or implicitly start
        // a TUN. Retained state still takes the full recovery path below; an explicit
        // up still attempts the ordinary privileged setup and reports its failure.
        if !nix::unistd::Uid::effective().is_root()
            && state.config.is_none()
            && state.backend.is_none()
            && !state.authority_reset_pending
            && store.recorded_interface()?.is_none()
            && store.recorded_engine()?.is_none()
            && store.route_inventory()?.is_empty()
            && store.read_private_key()?.is_none()
            && store.rotation_secret()?.is_none()
        {
            return Ok(Self {
                engine_kind,
                engine_source,
                enabled: false,
                store: Some(store),
                ..Self::default()
            });
        }
        let snapshot_key = state.config.as_ref().and_then(|c| c.local_key);
        let mut active_link = Device::active_link()?;
        if active_link
            .as_ref()
            .is_some_and(|link| link.engine == EngineKind::GotaTun)
        {
            recover_gotatun_private_key_from_journal(&store)?;
        }
        if let Some(link) = active_link.filter(|link| link.engine != engine_kind) {
            // A link of the other engine: ours moves to the selected engine, another node's is
            // left alone and keeps the name (D340).
            let kernel_proof = kernel_owner_proof(&store, snapshot_key)?;
            let ours = proven_kernel_link(&link, &kernel_proof)
                || proven_gotatun_link(&link, &gotatun_owner_proof(&store, snapshot_key)?);
            if ours {
                switch_engine(&store, link, state.enabled, &kernel_proof)?;
                store.record_engine(engine_kind)?;
                active_link = Device::active_link()?;
            }
        }
        let active_engine = active_link.map(|link| link.engine);
        let foreign_link = active_engine.is_some_and(|engine| engine != engine_kind);
        let routes = restore_routes(&store, &state)?;
        let proof = gotatun_owner_proof(&store, snapshot_key)?;
        let persisted = active_link.filter(|link| proven_gotatun_link(link, &proof));
        let kernel_proof = kernel_owner_proof(&store, snapshot_key)?;
        let adopted_kernel = active_link.filter(|link| proven_kernel_link(link, &kernel_proof));
        let mut node = Self {
            engine_kind,
            engine_source,
            routes,
            enabled: state.enabled,
            authority_reset: if state.authority_reset_pending {
                AuthorityResetState::AwaitingFullSnapshot
            } else {
                AuthorityResetState::Stable
            },
            store: Some(store),
            firewall: Firewall::for_node(state.backend, engine_kind),
            ..Self::default()
        };
        // Both links outlive their process (D332). A live one is this installation's only under
        // its engine's ownership proof; otherwise it is another node's, and so is the shared
        // filter that enforces its policy: never adopt either (#260, D340). One proof decides
        // both.
        if active_link.is_none() || persisted.is_some() || adopted_kernel.is_some() {
            node.firewall.adopt()?;
        }
        if let Some(link) = adopted_kernel {
            node.owned = true;
            node.kernel_owner = kernel_proof.clone();
            let identity = Device::identity_at(link.ifindex);
            // A process can stop after marking the interface but before setting its key and
            // binding its port. Such a link carries no session, whether or not a configuration
            // from before a reboot is still saved, and no restart could adopt it. Remove that
            // incomplete owned startup, by the index the proof read, so `up` starts afresh.
            let incomplete = identity
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::InvalidData)
                || identity
                    .as_ref()
                    .is_ok_and(|(key, port)| key.0 == [0; 32] || *port == 0);
            if incomplete {
                Device::delete_ifindex(link.ifindex)?;
                node.owned = false;
                node.kernel_owner = KernelProof::default();
                node.firewall.remove()?;
                if !node.enabled {
                    node.retire_routes()?;
                }
                return Ok(node);
            }
            let (public_key, mut port) = identity?;
            port = restore_kernel_listen_port(&node, link.ifindex, port)?;
            node.identity = Some(Identity {
                public_key,
                port,
                compact_access: true,
                #[cfg(feature = "mesh-dns")]
                dns_names: cfg!(target_os = "linux"),
                // Kernel `WireGuard` rotates its key in place (#285, D166).
                key_rotation: true,
                authority_epoch: true,
                rotation_continuity: true,
            });
            // The restored kernel socket's port is what the host input table admits (D386).
            node.firewall.set_listen_port(Some(port))?;
            node.client = Some(Client::new()?);
            if !node.enabled {
                node.down()?;
            } else if let Some(config) = state.config.clone() {
                // Recover public ownership while retained orphan keys still
                // exist. Prove both durable writes before replay can retire any
                // peer, route or policy. This republishes only accepted intent.
                node.routes.extend(Device::peer_routes()?);
                node.save(Some(&config), true)?;
                node.apply(config)?;
            }
        } else if engine_kind == EngineKind::GotaTun && node.enabled && !foreign_link {
            restore_gotatun(&mut node, state.config.clone())?;
        } else if let Some(link) = persisted.filter(|_| !node.enabled) {
            // A stop inside down left our persisted TUN behind with disabled intent: finish
            // that down. The filter and routes follow below, as for any disabled node.
            Device::delete_ifindex(link.ifindex)?;
        }
        if !node.owned {
            node.routes.clear();
        }
        if !node.owned && !node.enabled {
            // A stopped process may already have deleted the link but not the
            // policy or journal. Disabled intent fences adoption; finish that
            // cleanup instead of leaving durable ownership behind forever.
            node.remove_unshared_filter()?;
            node.retire_routes()?;
        }
        Ok(node)
    }
    /// Remove an adopted mesh filter that no live link depends on.
    ///
    /// Every installation uses the same interface name and filter table, so
    /// the table cannot name its owner. For a node without a live link of its
    /// own, a live mesh link belongs to another running node whose policy the
    /// filter enforces (#260). An unmarked interface with the shared name
    /// counts as live: it may be another node's TUN before it is marked.
    /// The same step closes the mesh listener this node opened in the host
    /// input table, which a `GotaTun` node may hold without any kernel table.
    fn remove_unshared_filter(&mut self) -> io::Result<()> {
        if !self.firewall.installed() && !self.firewall.host_ingress_open() {
            return Ok(());
        }
        match Device::active_link() {
            Ok(None) => self.firewall.remove(),
            Ok(Some(_)) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(error),
        }
    }
    /// Decide, changing nothing, which kernel objects host uninstall removes.
    ///
    /// The interface name and marker are shared by infraternal components.
    /// Match its engine and local public key against this node's durable record
    /// before uninstall removes the link. Its packet filter is ours when the
    /// state recorded a frontend and no other node's interface is live.
    ///
    /// Every object is decided before any is deleted (#235). An object with our
    /// name that is not ours is never an error: uninstall leaves it and names it,
    /// because the caller has usually already stopped the service.
    /// # Errors
    /// Reports unsafe state or a failed kernel or packet-filter query.
    pub fn plan_retirement(path: &std::path::Path) -> io::Result<Retirement> {
        let (recorded, backend, kernel_proof, gotatun_proof, store) =
            match crate::node_state::Store::open(path) {
                Ok((store, state)) => {
                    let snapshot_key = state.config.and_then(|config| config.local_key);
                    let recorded = store.recorded_interface()?.or(snapshot_key);
                    let kernel_proof = kernel_owner_proof(&store, snapshot_key)?;
                    let gotatun_proof = gotatun_owner_proof(&store, snapshot_key)?;
                    (
                        recorded,
                        state.backend,
                        kernel_proof,
                        gotatun_proof,
                        Some(store),
                    )
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => (
                    None,
                    None,
                    KernelProof::default(),
                    GotatunProof::default(),
                    None,
                ),
                Err(error) => return Err(error),
            };
        let mut left = Vec::new();
        let mut interface_index = None;
        // None: no interface with our name. Some(ours?) otherwise. Ownership of the userspace
        // TUN is its per-installation public-key marker, not the shared engine-kind alias.
        let interface = match Device::active_link() {
            Ok(None) => None,
            Ok(Some(link)) => {
                let owned = match link.engine {
                    EngineKind::Kernel => proven_kernel_link(&link, &kernel_proof),
                    EngineKind::GotaTun => proven_gotatun_link(&link, &gotatun_proof),
                };
                if owned {
                    interface_index = Some(link.ifindex);
                    Some(true)
                } else {
                    Some(false)
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Some(false),
            Err(error) => return Err(error),
        };
        if interface == Some(false) {
            left.push(crate::wireguard::INTERFACE);
        }
        let mut firewall = backend.map_or_else(Firewall::default, Firewall::for_backend);
        let filter = match firewall.adopt() {
            Ok(()) if !firewall.installed() => None,
            Ok(()) if backend.is_some() && recorded.is_some() && interface != Some(false) => {
                Some(firewall)
            }
            Ok(()) => {
                left.push(firewall.name());
                None
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                left.push(firewall.name());
                None
            }
            // Without a supported packet-filter frontend the node could never
            // install a filter, so there is none to remove.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::Unsupported
                ) =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        Ok(Retirement {
            interface: interface == Some(true),
            interface_index,
            filter,
            left,
            store,
        })
    }
    /// Remove the kernel objects this installation created, without a running node.
    ///
    /// Host uninstall calls this after the service has stopped (#235): it
    /// decides every object first (`plan_retirement`), then deletes only ours.
    /// # Errors
    /// Reports unsafe state or a failed kernel deletion; never foreign ownership.
    pub fn retire(path: &std::path::Path) -> io::Result<Vec<&'static str>> {
        Self::plan_retirement(path)?.execute()
    }
    /// Read the retained component intent, including an explicitly stopped node.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    /// Report an owned kernel identity; policy may still be awaiting the server.
    #[must_use]
    pub fn active(&self) -> bool {
        self.identity.is_some()
    }
    /// Return the active UDP listener port advertised by this node's mesh identity.
    ///
    /// `None` means the data plane is stopped or has not bound a socket yet. The value is the
    /// actual port after automatic fallback, so `mesh status` can report what peers should reach.
    #[must_use]
    pub fn listen_port(&self) -> Option<u16> {
        self.identity.as_ref().map(|identity| identity.port)
    }
    /// Whether a retired authority still needs a complete snapshot from the enrolled server.
    #[must_use]
    pub fn awaiting_server_snapshot(&self) -> bool {
        self.authority_reset == AuthorityResetState::AwaitingFullSnapshot
    }
    /// Apply the proxy's Mesh routes and public gate to the owned firewall.
    ///
    /// `confirmed` is true only when Traefik has confirmed a route snapshot rendered from the
    /// current Mesh configuration; gate-only and other local updates pass false.
    ///
    /// # Errors
    /// Returns a firewall or conntrack cleanup failure without accepting a new policy.
    pub fn set_proxy_ingress(
        &mut self,
        proxy_ingress: infraternal_mesh::proxy_ports::MeshProxyIngress,
        confirmed: bool,
    ) -> io::Result<()> {
        let policy = if self.engine_kind == EngineKind::GotaTun
            && self.active()
            && let Some(config) = self.config.as_ref()
        {
            self.gotatun.as_ref().ok_or(io::ErrorKind::NotConnected)?;
            Some(crate::gotatun_node::Engine::prepare_policy(
                config,
                proxy_ingress.clone(),
            )?)
        } else {
            None
        };
        // An unchanged snapshot still reaches the firewall: Traefik has just confirmed it, and
        // any source that lost a route since the last confirmation must lose its open flows.
        if self.active()
            && let Some(config) = self.config.as_ref()
        {
            self.firewall
                .apply_proxy_ingress(config, &proxy_ingress, confirmed)?;
        }
        if let Some(policy) = policy {
            self.gotatun
                .as_ref()
                .ok_or(io::ErrorKind::NotConnected)?
                .publish_policy(policy);
        }
        self.proxy_ingress = proxy_ingress;
        Ok(())
    }
    /// Disabled intent is not Off until retained kernel/socket ownership is gone.
    #[must_use]
    pub fn stopping(&self) -> bool {
        !self.enabled
            && (self.owned
                || self.client.is_some()
                || self.gotatun.is_some()
                || self.identity.is_some())
    }
    /// Start only an enabled node; a coordinator reconnect cannot override local down.
    /// # Errors
    /// Reports the same privilege, persistence and kernel failures as explicit up.
    pub fn ensure(&mut self) -> io::Result<Option<Identity>> {
        if self.enabled {
            self.up().map(Some)
        } else {
            Ok(None)
        }
    }
    /// Persist the accepted config and local enabled choice without a replacement rollback base.
    fn save(&self, config: Option<&Config>, enabled: bool) -> io::Result<()> {
        self.save_with_snapshot_base(config, enabled, None)
    }
    /// Persist an accepted config, using the exact old snapshot only for a complete replacement.
    /// # Errors
    /// Reports route-journal or public snapshot persistence failures.
    fn save_with_snapshot_base(
        &self,
        config: Option<&Config>,
        enabled: bool,
        full_snapshot_base: Option<&Config>,
    ) -> io::Result<()> {
        if let Some(store) = &self.store {
            store.record_routes(&self.routes)?;
            let state = crate::node_state::State {
                enabled,
                config: config.cloned(),
                authority_reset_pending: full_snapshot_base.is_none()
                    && self.authority_reset == AuthorityResetState::AwaitingFullSnapshot,
                backend: self.firewall.backend(),
            };
            if let Some(base) = full_snapshot_base {
                store.save_full_snapshot(&state, base)?;
            } else {
                store.save(&state)?;
            }
        }
        Ok(())
    }
    /// Persist a stable apply using the prior accepted configuration as the journal base.
    fn save_applied_revision(
        &self,
        config: &Config,
        snapshot_base: Option<&Config>,
        changed_routes: bool,
    ) -> io::Result<()> {
        if snapshot_base.is_none()
            && self.authority_reset == AuthorityResetState::Stable
            && self.engine_kind == EngineKind::GotaTun
            && let (Some(store), Some(previous)) = (&self.store, &self.config)
        {
            // The access-only path cannot change the route inventory. A topology change
            // still persists the reduced inventory after the kernel cleanup.
            if changed_routes {
                store.record_routes(&self.routes)?;
            }
            return store.save_peer_revision(previous, config, self.firewall.backend());
        }
        self.save_with_snapshot_base(Some(config), true, snapshot_base)
    }
    /// Read endpoint and traffic statistics for the currently installed peers.
    fn peer_counters(
        &self,
    ) -> io::Result<BTreeMap<crate::policy::model::PublicKey, crate::wireguard::Counters>> {
        match self.engine_kind {
            EngineKind::Kernel => Device::counters(),
            EngineKind::GotaTun => self
                .gotatun
                .as_ref()
                .ok_or(io::ErrorKind::NotConnected)?
                .counters(),
        }
    }

    /// Read the actual engine membership so reconciliation can retire orphan keys.
    fn installed_peer_keys(&self) -> io::Result<Vec<crate::policy::model::PublicKey>> {
        match self.engine_kind {
            EngineKind::Kernel => Ok(Device::counters()?.into_keys().collect()),
            EngineKind::GotaTun => self
                .gotatun
                .as_ref()
                .ok_or(io::ErrorKind::NotConnected)?
                .peer_keys(),
        }
    }

    /// Read counters from the selected node data plane.
    /// # Errors
    /// Reports a stopped node or a device query error.
    pub fn counters(
        &self,
    ) -> io::Result<BTreeMap<crate::policy::model::PublicKey, crate::wireguard::Counters>> {
        self.peer_counters()
    }

    /// The engine this node runs, and whether it is the default or the machine's choice (D346).
    #[must_use]
    pub fn engine_selection(&self) -> EngineSelection {
        EngineSelection {
            engine: self.engine_kind,
            reason: self.engine_source.reason(),
        }
    }

    /// Report the optional kernel-only guard that the `GotaTun` node currently has installed.
    #[must_use]
    pub(crate) fn kernel_guard_status(&self) -> Option<&crate::firewall::KernelGuardStatus> {
        self.firewall.kernel_guard_status()
    }

    /// Health of the running `GotaTun` engine; `None` under kernel `WireGuard` or when stopped.
    #[must_use]
    pub fn engine_health(&self) -> Option<crate::gotatun_node::EngineHealth> {
        self.gotatun.as_ref().map(Engine::health)
    }

    /// Return a relay callback that starts a handshake through this node's selected engine.
    #[cfg(feature = "relay")]
    pub(crate) fn relay_handshake_starter(
        &self,
        peer: &crate::dataplane::Peer,
    ) -> io::Result<Arc<dyn Fn() + Send + Sync>> {
        match self.engine_kind {
            EngineKind::Kernel => {
                let peer = peer.clone();
                Ok(Arc::new(move || {
                    let _ = crate::relay_path::start_kernel_handshake(&peer);
                }))
            }
            EngineKind::GotaTun => Ok(self
                .gotatun
                .as_ref()
                .ok_or(io::ErrorKind::NotConnected)?
                .handshake_starter(peer.key, peer.endpoint.ok_or(io::ErrorKind::InvalidInput)?)),
        }
    }

    /// Return a callback that preserves a completed session or clears an incomplete relay handshake.
    #[cfg(feature = "relay")]
    pub(crate) fn relay_handshake_preparer(
        &self,
        peer: &crate::dataplane::Peer,
    ) -> io::Result<Arc<dyn Fn() -> io::Result<()> + Send + Sync>> {
        match self.engine_kind {
            EngineKind::Kernel => {
                let peer = peer.clone();
                Ok(Arc::new(move || {
                    crate::relay_path::prepare_kernel_handshake(&peer)
                }))
            }
            EngineKind::GotaTun => Ok(self
                .gotatun
                .as_ref()
                .ok_or(io::ErrorKind::NotConnected)?
                .handshake_preparer(peer.key, peer.endpoint.ok_or(io::ErrorKind::InvalidInput)?)),
        }
    }

    /// Return a relay callback that restores this peer from its accepted Mesh configuration.
    /// # Errors
    /// Reports a stopped or unavailable data plane.
    #[cfg(feature = "relay")]
    pub(crate) fn relay_endpoint_restorer(
        &self,
        peer: &crate::dataplane::Peer,
    ) -> io::Result<Arc<dyn Fn() -> io::Result<()> + Send + Sync>> {
        match self.engine_kind {
            EngineKind::Kernel => {
                let peer = peer.clone();
                Ok(Arc::new(move || restore_kernel_peer(&peer)))
            }
            EngineKind::GotaTun => Ok(self
                .gotatun
                .as_ref()
                .ok_or(io::ErrorKind::NotConnected)?
                .endpoint_restorer(peer.key)),
        }
    }

    /// Restore a peer from the latest accepted snapshot after its relay shim stops.
    /// # Errors
    /// Reports a stopped or unavailable data plane.
    #[cfg(feature = "relay")]
    pub(crate) fn restore_relay_endpoint(
        &self,
        key: crate::policy::model::PublicKey,
    ) -> io::Result<()> {
        let peer =
            self.config()
                .and_then(|config| {
                    config.peers.values().find(|policy| {
                        policy.peer.key == key || policy.peer.previous_key == Some(key)
                    })
                })
                .map(|policy| policy.peer.clone());
        match self.engine_kind {
            EngineKind::Kernel => peer.map_or(Ok(()), |peer| restore_kernel_peer(&peer)),
            EngineKind::GotaTun => self
                .gotatun
                .as_ref()
                .ok_or(io::ErrorKind::NotConnected)?
                .restore_peer(key),
        }
    }

    /// Return a callback that keeps this peer's kernel route on its active path budget.
    ///
    /// The callback keeps only the peer's key. Each call resolves the accepted peer under the
    /// route-state lock (see [`update_relay_route_mtu`]), so it follows endpoint moves and does
    /// nothing once the peer is removed. `Some(mtu)` records the active relay's derived route
    /// MTU; `None` removes that override and re-derives from the current direct endpoint.
    #[cfg(feature = "relay")]
    pub(crate) fn relay_route_mtu_updater(
        &self,
        peer: &crate::dataplane::Peer,
    ) -> crate::relay_path::RouteMtuUpdater {
        let state = Arc::clone(&self.peer_route_state);
        let key = peer.key;
        Arc::new(move |relay_mtu| update_relay_route_mtu(&state, key, relay_mtu))
    }

    /// The direct-path probes of the running `GotaTun` engine's `WireGuard` port, and the receiver
    /// of their finished answers (given out once). Hand both to
    /// `RelayPaths::with_direct_probes`. `None` for the kernel engine, whose socket this
    /// process does not own, or while no engine runs.
    #[cfg(feature = "relay")]
    #[must_use]
    pub fn direct_probes(
        &self,
    ) -> Option<(
        crate::direct_probe::DirectProbes,
        Option<tokio::sync::mpsc::Receiver<crate::direct_probe::Answer>>,
    )> {
        match self.engine_kind {
            EngineKind::Kernel => None,
            EngineKind::GotaTun => self.gotatun.as_ref()?.direct_probes(),
        }
    }

    /// This node's mesh key as a relay [`PairSecret`](crate::relay_path::PairSecret): the
    /// secret both ends of a relayed pair derive their opaque link tokens from (D402 Q8).
    /// Read from the node's saved private key; the key itself never leaves the secret.
    /// # Errors
    /// Fails when the node has no saved key yet (it has never been brought up).
    #[cfg(feature = "relay")]
    pub fn relay_pair_secret(&self) -> io::Result<crate::relay_path::PairSecret> {
        let store = self.store.as_ref().ok_or(io::ErrorKind::NotFound)?;
        let key = store.read_private_key()?.ok_or(io::ErrorKind::NotFound)?;
        crate::relay_path::PairSecret::from_private(&key)
    }

    /// Return a callback for learned endpoints reported by the `GotaTun` worker.
    ///
    /// The callback only updates installed peers and leaves relay budgets active. It runs route
    /// netlink writes on Tokio's blocking pool, outside the packet workers' runtime tasks.
    pub(crate) fn route_endpoint_updater(&self) -> crate::gotatun_node::RouteEndpointUpdater {
        let state = Arc::clone(&self.peer_route_state);
        Arc::new(move |endpoints| update_live_peer_endpoints(&state, endpoints).map(|_| ()))
    }

    /// Refresh peer host routes using active relay budgets where present.
    ///
    /// `peers` is the complete installed set (an accepted snapshot or the one a rollback
    /// restores). After a successful install it becomes the set relay callbacks resolve against.
    /// # Errors
    /// Returns route-netlink errors without changing the route state.
    fn install_peer_routes(
        &self,
        peers: &[crate::dataplane::Peer],
        remove: bool,
    ) -> io::Result<()> {
        let mut state = lock_route_state(&self.peer_route_state);
        if remove {
            // Removal writes every peer: the record no longer describes any of them.
            state.forget_written();
            return Device::routes_with_mtu_overrides(peers, &state.overrides, true, None);
        }
        // Only routes that differ from the record are written (#260 J1240). The installed set
        // moves to `peers` only once they are in place, so a failure leaves relay callbacks
        // resolving the previous set, as the caller's rollback expects.
        let current = write_snapshot_routes(&mut state, peers)?;
        state.set_peers(peers);
        state.mark_current(current);
        Ok(())
    }

    /// Apply a full route refresh after clearing overrides for peers that returned to direct paths.
    ///
    /// The returned snapshot lets the caller restore the previous relay budgets and installed
    /// peers if a later part of the enclosing configuration transaction rolls back.
    /// # Errors
    /// Returns route-netlink errors and restores the route state if route installation fails.
    fn refresh_peer_routes(
        &self,
        peers: &[crate::dataplane::Peer],
        clear_overrides_for: &BTreeSet<crate::policy::model::PublicKey>,
    ) -> io::Result<PeerRouteState> {
        refresh_peer_routes_from(&self.peer_route_state, peers, clear_overrides_for)
    }

    /// Restore relay budgets and the installed peer set after a failed configuration transaction.
    ///
    /// The proven link belongs to the running route-repair worker, not to the transaction, so it
    /// is kept as it is now.
    fn restore_peer_route_state(&self, previous: PeerRouteState) {
        let mut state = lock_route_state(&self.peer_route_state);
        let link = state.link;
        let underlay = state.underlay.take();
        *state = previous;
        state.link = link;
        state.underlay = underlay;
        // The failed transaction may have rewritten routes after `previous` was taken.
        state.forget_written();
    }

    fn apply_peer_changes(
        &mut self,
        config: &Config,
        changed: &[crate::dataplane::Peer],
        retired: &[crate::policy::model::PublicKey],
    ) -> io::Result<()> {
        match self.engine_kind {
            EngineKind::Kernel => self
                .client
                .as_mut()
                .ok_or(io::ErrorKind::NotConnected)?
                .peers(changed, retired),
            EngineKind::GotaTun => self
                .gotatun
                .as_ref()
                .ok_or(io::ErrorKind::NotConnected)?
                .apply(config.clone())
                .map(|_| ()),
        }
    }
    /// Retire the recorded routes only after kernel teardown has completed.
    ///
    /// Keeping the inventory after a failure preserves the ordering of an explicit retry.
    fn retire_routes(&mut self) -> io::Result<()> {
        // Publish an empty inventory only after kernel teardown is complete.
        // Keep the in-memory inventory on failure so an explicit retry remains
        // ordered. Store's canonical cache makes completed replay write-free.
        if let Some(store) = &self.store {
            store.record_routes(&BTreeSet::new())?;
        }
        self.routes.clear();
        // The route-repair worker withdraws its own proven link when it stops.
        let mut state = lock_route_state(&self.peer_route_state);
        *state = PeerRouteState {
            link: state.link,
            underlay: state.underlay.take(),
            ..PeerRouteState::default()
        };
        Ok(())
    }
    /// The key an interrupted Linux rotation left as this node's identity: the candidate once
    /// commit intent is durable, and the predecessor before. Both Linux engines share the journal.
    fn rotation_key(&self) -> io::Result<Option<(Key, crate::policy::model::PublicKey)>> {
        let Some(store) = self.store.as_ref() else {
            return Ok(None);
        };
        let Some(rotation) = store.rotation_secret()? else {
            return Ok(None);
        };
        // The copy is wiped on drop, like the journal record it came from.
        let private = zeroize::Zeroizing::new(if rotation.commit_requested || rotation.completed {
            rotation.candidate
        } else {
            rotation.previous
        });
        Key::from_private(&private[..]).map(Some)
    }
    fn local_key(&self) -> io::Result<(Key, crate::policy::model::PublicKey)> {
        if let Some(store) = &self.store
            && let Some(bytes) = store.read_private_key()?
        {
            let (secret, public_key) = crate::gotatun_node::secret_from_bytes(&bytes)?;
            drop(secret);
            return Ok((Key::from_private_bytes(&bytes)?, public_key));
        }
        let (key, public_key) = Key::generate()?;
        if self.engine_kind == EngineKind::GotaTun
            && let Some(store) = &self.store
        {
            store.write_private_key(key.private_bytes())?;
        }
        Ok((key, public_key))
    }
    /// The index of this installation's persisted `GotaTun` TUN, if a live one passes the
    /// ownership proof (D332) and only this agent's user and group may attach it; the engine
    /// reattaches only that link.
    ///
    /// A proven TUN that any local user could attach (one persisted before #260 J213 P1) is not
    /// trusted: its queue may have been read or held while the agent was down. It is deleted by
    /// its index and the engine starts a fresh, restricted one; routes added by hand to it go.
    fn persisted_tun_to_adopt(
        &self,
        local_public_key: crate::policy::model::PublicKey,
    ) -> io::Result<Option<u32>> {
        let (Some(store), Some(link)) = (&self.store, Device::active_link()?) else {
            return Ok(None);
        };
        let proof = gotatun_owner_proof(store, self.config.as_ref().and_then(|c| c.local_key))?;
        if !proven_gotatun_link(&link, &proof) {
            return Ok(None);
        }
        let restricted = link.tun_owner == Some(nix::unistd::geteuid().as_raw())
            && link.tun_group == Some(nix::unistd::getegid().as_raw());
        if restricted {
            if link.owner != Some(local_public_key) {
                // Commit intent authorizes moving a predecessor marker to the candidate before
                // reattach. Rechecking by ifindex makes this safe if the shared name was replaced.
                if !proof.accepts(local_public_key) {
                    return Ok(None);
                }
                Device::remark(
                    link.ifindex,
                    link.owner.ok_or(io::ErrorKind::InvalidData)?,
                    local_public_key,
                )?;
            }
            return Ok(Some(link.ifindex));
        }
        Device::delete_ifindex(link.ifindex)?;
        Ok(None)
    }
    /// Start the selected data plane with a node-local key and advertise its UDP port.
    /// # Errors
    /// Refuses missing privilege or any kernel error; never returns private material.
    pub fn up(&mut self) -> io::Result<Identity> {
        let starting = self.identity.is_none();
        let identity = self.up_inner();
        // A start reinstalls the saved snapshot; bring its subnet routes back with it (D197 M3).
        if starting && identity.is_ok() {
            self.reconcile_subnet_routes();
        }
        identity
    }

    /// Start the data plane; [`Self::up`] adds the subnet-route reconcile after a start.
    fn up_inner(&mut self) -> io::Result<Identity> {
        // A failed down may have published disabled intent while retaining only
        // part of the old kernel state. Finish cleanup before returning/recreating identity.
        if !self.enabled {
            self.down()?;
        }
        if let Some(identity) = self.identity.clone() {
            self.ensure_route_repair()?;
            return Ok(identity);
        }
        let saved_port = self
            .store
            .as_ref()
            .map(crate::node_state::Store::recorded_listen_port)
            .transpose()?
            .flatten();
        let listen_port = crate::listen_port::from_environment(saved_port)?;
        if self.engine_kind == EngineKind::GotaTun
            && let Some(store) = &self.store
        {
            recover_gotatun_private_key_from_journal(store)?;
        }
        // The engine was settled when this node was made: by `Node::restore`, the infraternal
        // agent's path, which alone reads `INFRATERNAL_MESH_ENGINE`, or by code (#260 J220 P3).
        self.firewall.adopt()?;
        let (key, public_key) = match self.rotation_key()? {
            Some(key) => key,
            None => self.local_key()?,
        };
        if let Some(store) = &self.store {
            store.record_engine(self.engine_kind)?;
            store.record_interface(&public_key)?;
        }
        match self.engine_kind {
            EngineKind::Kernel => {
                let created = Device::create(public_key)?;
                self.owned = true;
                self.kernel_owner = KernelProof::single(public_key);
                #[cfg(feature = "test-support")]
                if let Some(hook) = BEFORE_KERNEL_KEY
                    .lock()
                    .ok()
                    .and_then(|mut hook| hook.take())
                {
                    hook();
                }
                let configure = Device::configure(created, public_key, &key, listen_port.port);
                let configure = match configure {
                    Err(error)
                        if listen_port.allow_fallback
                            && error.kind() == io::ErrorKind::AddrInUse =>
                    {
                        Device::configure(created, public_key, &key, 0)
                    }
                    result => result,
                };
                if let Err(error) = configure {
                    // Delete exactly the link this call created: `down` proves links by the
                    // shared name, which may no longer lead to ours (#260 J242).
                    let _ = Device::delete_ifindex(created);
                    let _ = self.down();
                    return Err(error);
                }
                let prepared = (|| {
                    let (device_key, port) = Device::identity_at(created)?;
                    if device_key != public_key || port == 0 {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    if let Some(store) = &self.store {
                        let saved = if listen_port.allow_fallback {
                            port
                        } else {
                            crate::listen_port::DEFAULT_PORT
                        };
                        store.record_listen_port(saved)?;
                    }
                    let client = Client::new()?;
                    let route_repair = RouteRepairWorker::start(
                        Arc::clone(&self.peer_route_state),
                        Arc::clone(&self.underlay_announce),
                    )?;
                    self.routes.clear();
                    self.save(None, true)?;
                    Ok((port, client, route_repair))
                })();
                match prepared {
                    Ok((port, client, route_repair)) => {
                        self.enabled = true;
                        self.client = Some(client);
                        self.route_repair = Some(route_repair);
                        let identity = Identity {
                            public_key,
                            port,
                            compact_access: true,
                            #[cfg(feature = "mesh-dns")]
                            dns_names: cfg!(target_os = "linux"),
                            key_rotation: true,
                            authority_epoch: true,
                            rotation_continuity: true,
                        };
                        self.identity = Some(identity.clone());
                        // The host input table admits exactly the port this socket bound (D386).
                        self.firewall.set_listen_port(Some(identity.port))?;
                        Ok(identity)
                    }
                    Err(error) => {
                        // Delete exactly the link this call created, never by the shared name.
                        Device::delete_ifindex(created)?;
                        self.owned = false;
                        self.kernel_owner = KernelProof::default();
                        Err(error)
                    }
                }
            }
            EngineKind::GotaTun => {
                #[cfg(test)]
                startup_crash_tests::checkpoint("recorded")?;
                let adopt = self.persisted_tun_to_adopt(public_key)?;
                let route_endpoint_updater = self.route_endpoint_updater();
                let (engine, tun) = Engine::start(
                    key.gotatun_secret()?,
                    public_key,
                    listen_port,
                    None,
                    &self.proxy_ingress,
                    adopt,
                    route_endpoint_updater,
                    Arc::clone(&self.underlay_announce),
                )?;
                #[cfg(test)]
                startup_crash_tests::checkpoint("bound")?;
                let (interface, port, thp_disabled, offloads_enabled) = engine.info();
                if interface != crate::wireguard::INTERFACE
                    || port == 0
                    || !thp_disabled
                    || !offloads_enabled
                {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                if let Some(store) = &self.store {
                    let saved = if listen_port.allow_fallback {
                        port
                    } else {
                        crate::listen_port::DEFAULT_PORT
                    };
                    store.record_listen_port(saved)?;
                }
                #[cfg(test)]
                startup_crash_tests::checkpoint("port-recorded")?;
                let route_repair = RouteRepairWorker::start(
                    Arc::clone(&self.peer_route_state),
                    Arc::clone(&self.underlay_announce),
                )?;
                #[cfg(test)]
                startup_crash_tests::checkpoint("route-listening")?;
                self.save(self.config.as_ref(), true)?;
                #[cfg(test)]
                startup_crash_tests::checkpoint("saved")?;
                // Commit point (D332): the interface outlives this process only from here, when
                // the saved state holds both the enabled choice and the proof that lets the next
                // start take the link back. Every earlier stop or error drops the last queue
                // descriptor and the kernel removes the link, so no start leaves one behind that
                // the next start has to refuse. A node without a store can never prove a link,
                // so its link stays transient. An adopted link is already persistent.
                if self.store.is_some() && adopt.is_none() {
                    tun.persist()?;
                }
                #[cfg(test)]
                startup_crash_tests::checkpoint("persisted")?;
                self.owned = true;
                self.gotatun = Some(engine);
                self.enabled = true;
                self.route_repair = Some(route_repair);
                let identity = Identity {
                    public_key,
                    port,
                    compact_access: true,
                    #[cfg(feature = "mesh-dns")]
                    dns_names: cfg!(target_os = "linux"),
                    // Linux GotaTun has durable live key rotation (#367); authority epochs stay
                    // available on the authenticated, enrollment-bound channel (#382, D166, D352).
                    key_rotation: true,
                    authority_epoch: true,
                    rotation_continuity: true,
                };
                self.identity = Some(identity.clone());
                // The host input table admits exactly the port this socket bound (D386).
                self.firewall.set_listen_port(Some(identity.port))?;
                #[cfg(test)]
                startup_crash_tests::checkpoint("listening")?;
                Ok(identity)
            }
        }
    }
    /// The proven Linux link every rotation step addresses by its index (#285, #367).
    fn rotation_link(&self) -> io::Result<crate::wireguard::ActiveLink> {
        if !self.owned {
            return Err(io::ErrorKind::NotConnected.into());
        }
        let link = Device::active_link()?.ok_or(io::ErrorKind::NotConnected)?;
        if link.engine != self.engine_kind || link.owner.is_none() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let proven = match self.engine_kind {
            EngineKind::Kernel => proven_kernel_link(&link, &self.kernel_owner),
            EngineKind::GotaTun => {
                let store = self.store.as_ref().ok_or(io::ErrorKind::NotConnected)?;
                let proof = gotatun_owner_proof(
                    store,
                    self.config.as_ref().and_then(|config| config.local_key),
                )?;
                proven_gotatun_link(&link, &proof)
            }
        };
        if !proven {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(link)
    }

    /// Return this node's proven kernel link for owner-only changes such as MTU updates.
    /// # Errors
    /// Refuses non-kernel engines, inactive links, and links whose owner marker changed.
    fn owned_kernel_link(&self) -> io::Result<crate::wireguard::ActiveLink> {
        if self.engine_kind != EngineKind::Kernel {
            return Err(io::ErrorKind::Unsupported.into());
        }
        self.rotation_link()
    }

    /// Return this node's live `GotaTun` link after validating its owner proof.
    ///
    /// Restored nodes prove the marker with durable state. A fresh in-memory node
    /// proves it against the key and engine handle it created in this process.
    /// # Errors
    /// Refuses non-`GotaTun` engines, inactive links, and links whose owner proof changed.
    fn owned_gotatun_link(&self) -> io::Result<crate::wireguard::ActiveLink> {
        if self.engine_kind != EngineKind::GotaTun {
            return Err(io::ErrorKind::Unsupported.into());
        }
        if self.store.is_none() {
            if !self.owned || self.gotatun.is_none() {
                return Err(io::ErrorKind::NotConnected.into());
            }
            let link = Device::active_link()?.ok_or(io::ErrorKind::NotConnected)?;
            let owner = self
                .identity
                .as_ref()
                .ok_or(io::ErrorKind::NotConnected)?
                .public_key;
            if link.engine != EngineKind::GotaTun || link.owner != Some(owner) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            return Ok(link);
        }
        self.rotation_link()
    }

    /// Whether this node runs `GotaTun` with its second UDP socket on (#260, J1211), so peers may
    /// send it marked small datagrams. The kernel engine has no second socket and never says so.
    #[must_use]
    pub fn side_socket(&self) -> bool {
        self.engine_kind == EngineKind::GotaTun && crate::side_socket::enabled()
    }

    /// Whether the node runs IPv4-only because the mesh link has IPv6 off (#578, J1142).
    ///
    /// This is what the last accepted snapshot installed, not a live reading: peers are told
    /// only about state the node has actually applied, so a node never advertises an IPv6 address
    /// it has not yet put on its link. `false` before the first install.
    #[must_use]
    pub const fn ipv4_only(&self) -> bool {
        matches!(self.mesh_ipv6, Some(false))
    }

    /// Record whether the mesh link took its IPv6 address, and say so once when that changes.
    ///
    /// An IPv6-off host (`net.ipv6.conf.*.disable_ipv6=1`) joins the mesh IPv4-only instead of
    /// being refused (#578). That is a real loss for the person (no IPv6 mesh address, no IPv6
    /// routes to peers), so it is said when it starts and when IPv6 is back, never on every
    /// configuration. It goes to stderr, not `tracing`: an infraternal agent has no tracing
    /// subscriber, and its stderr is the service journal.
    fn note_mesh_ipv6(&mut self, ipv6: bool) {
        if self.mesh_ipv6 == Some(ipv6) {
            return;
        }
        if !ipv6 {
            eprintln!(
                "Mesh runs IPv4-only: IPv6 is disabled on {} (net.ipv6.conf disable_ipv6), so its IPv6 mesh address and IPv6 peer routes are skipped.",
                crate::wireguard::INTERFACE
            );
        } else if self.mesh_ipv6.is_some() {
            eprintln!(
                "Mesh IPv6 is back: IPv6 is enabled on {} again and its IPv6 mesh address is installed.",
                crate::wireguard::INTERFACE
            );
        }
        self.mesh_ipv6 = Some(ipv6);
    }

    /// Set the MTU on this node's proven interface and keep `GotaTun`'s packet watcher in step.
    /// # Errors
    /// Refuses a changed interface index or reports a link update failure.
    fn set_mesh_mtu(&self, ifindex: u32, mtu: u16) -> io::Result<()> {
        match self.engine_kind {
            EngineKind::Kernel => Device::set_mtu(ifindex, mtu),
            EngineKind::GotaTun => {
                if self.owned_gotatun_link()?.ifindex != ifindex {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.gotatun
                    .as_ref()
                    .ok_or(io::ErrorKind::NotConnected)?
                    .set_mtu(mtu)
            }
        }
    }

    /// Read the identity the selected live engine currently presents for a proven link.
    /// Kernel `WireGuard` reports it by ifindex; `GotaTun` keeps the accepted live identity in memory.
    fn rotation_public_key(
        &self,
        link: &crate::wireguard::ActiveLink,
    ) -> io::Result<crate::policy::model::PublicKey> {
        if link.engine != self.engine_kind {
            return Err(io::ErrorKind::InvalidData.into());
        }
        match self.engine_kind {
            EngineKind::Kernel => Ok(Device::identity_at(link.ifindex)?.0),
            EngineKind::GotaTun => self
                .identity
                .as_ref()
                .map(|identity| identity.public_key)
                .ok_or(io::ErrorKind::NotConnected.into()),
        }
    }

    /// Prepare a local Linux identity without changing the live interface.
    /// Both engines persist the predecessor and candidate before returning the candidate key.
    /// # Errors
    /// Refuses an inactive or unproven node, invalid request, unsafe state, conflicting operation
    /// or failed durable write.
    pub(crate) fn prepare_rotation(
        &mut self,
        operation_id: &str,
        sequence: u64,
    ) -> io::Result<crate::policy::model::PublicKey> {
        if self.identity.is_none() || self.store.is_none() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        if sequence == 0
            || operation_id.len() != 36
            || !operation_id.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            })
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut link = self.rotation_link()?;
        // A strictly higher sequence from the authenticated coordinator proves the open operation
        // ended there (J262): it was abandoned, for example after a probe that could not show
        // support or a binary downgrade, while this journal stayed open. Settle on the held key
        // before preparing the new operation.
        {
            let store = self.store.as_ref().ok_or(io::ErrorKind::NotConnected)?;
            if let Some(existing) = store.rotation_secret()?
                && !existing.completed
                && existing.operation_id != operation_id
                && sequence > existing.sequence
            {
                self.settle_superseded_rotation(&link, &existing)?;
                link = self.rotation_link()?;
            }
        }
        let store = self.store.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let identity = self.identity.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        if let Some(existing) = store.rotation_secret()? {
            let (_, existing_public) = Key::from_private(&existing.candidate)?;
            if existing.completed {
                let current = self.rotation_public_key(&link)?;
                if current != existing_public
                    || identity.public_key != existing_public
                    || link.owner != Some(existing_public)
                    || existing.operation_id == operation_id
                    || sequence <= existing.sequence
                {
                    return Err(io::ErrorKind::InvalidData.into());
                }
            } else if existing.operation_id == operation_id && existing.sequence == sequence {
                return Ok(existing_public);
            } else {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        let previous = match self.engine_kind {
            EngineKind::Kernel => *Device::private_key_at(link.ifindex)?,
            EngineKind::GotaTun => {
                let bytes = store
                    .read_private_key()?
                    .ok_or(io::ErrorKind::InvalidData)?;
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| io::ErrorKind::InvalidData)?
            }
        };
        let previous = zeroize::Zeroizing::new(previous);
        let (_, previous_public) = Key::from_private(&previous[..])?;
        if previous_public != identity.public_key || link.owner != Some(previous_public) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let (candidate, candidate_public) = Key::generate()?;
        let state = crate::node_state::RotationSecret {
            operation_id: operation_id.to_owned(),
            sequence,
            previous: *previous,
            candidate: candidate
                .private_bytes()
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidData)?,
            commit_requested: false,
            completed: false,
        };
        store.save_rotation_secret(&state)?;
        #[cfg(test)]
        if self.engine_kind == EngineKind::GotaTun {
            rotation_tests::crash_checkpoint("rotation_prepared");
        }
        Ok(candidate_public)
    }

    /// Settle an open journal whose operation the coordinator has ended, by its active engine key.
    ///
    /// The journal also records which key this node holds: restart takes that key from it for both
    /// Linux engines, so settlement rewrites the journal instead of deleting it (J262).
    /// - The link holds the candidate (commit was requested and the key was sent): finish the
    ///   local commit steps a stop may have left (marker, recorded key, identity), then complete
    ///   the journal, which clears predecessor private bytes and keeps its public key. The candidate
    ///   is now our key.
    /// - The link still holds the predecessor (commit never requested, or stopped before the key
    ///   was sent): the candidate never went live. Record the predecessor as the completed key and
    ///   erase the candidate.
    /// - Anything else is not a state this node produced, and is refused.
    fn settle_superseded_rotation(
        &mut self,
        link: &crate::wireguard::ActiveLink,
        existing: &crate::node_state::RotationSecret,
    ) -> io::Result<()> {
        let current = self.rotation_public_key(link)?;
        let (_, previous_public) = Key::from_private(&existing.previous)?;
        let (_, candidate_public) = Key::from_private(&existing.candidate)?;
        let store = self.store.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        if existing.commit_requested && current == candidate_public {
            if self.identity.is_none() {
                return Err(io::ErrorKind::NotConnected.into());
            }
            match link.owner {
                Some(owner) if owner == previous_public => {
                    Device::remark(link.ifindex, previous_public, candidate_public)?;
                }
                Some(owner) if owner == candidate_public => {}
                _ => return Err(io::ErrorKind::InvalidData.into()),
            }
            // The marker now names the candidate while the journal still holds both keys with commit
            // intent. Keep both kernel keys in the proof until completion is durable, and leave the
            // presented identity unchanged until the same point, so a failed save is retryable (J284 P3-b).
            store.record_interface(&candidate_public)?;
            if self.engine_kind == EngineKind::GotaTun {
                store.replace_private_key(&existing.candidate)?;
            } else {
                self.kernel_owner = KernelProof(vec![previous_public, candidate_public]);
            }
            #[cfg(feature = "test-support")]
            if let Some(hook) = BEFORE_SETTLE_SAVE
                .lock()
                .ok()
                .and_then(|mut hook| hook.take())
            {
                hook();
            }
            store.complete_rotation_secret(&existing.operation_id, existing.sequence)?;
            if self.engine_kind == EngineKind::Kernel {
                self.kernel_owner = KernelProof::single(candidate_public);
            }
            self.identity
                .as_mut()
                .ok_or(io::ErrorKind::NotConnected)?
                .public_key = candidate_public;
            return Ok(());
        }
        if current != previous_public
            || link.owner != Some(previous_public)
            || self
                .identity
                .as_ref()
                .is_none_or(|identity| identity.public_key != previous_public)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        store.save_rotation_secret(&crate::node_state::RotationSecret {
            operation_id: existing.operation_id.clone(),
            sequence: existing.sequence,
            previous: previous_public.0,
            candidate: existing.previous,
            commit_requested: true,
            completed: true,
        })?;
        if self.engine_kind == EngineKind::Kernel {
            self.kernel_owner = KernelProof::single(previous_public);
        }
        Ok(())
    }

    /// Switch our proven Linux link to the prepared candidate; retry is safe after an abrupt stop.
    ///
    /// Order (#285): durable commit intent, then the key, sent by index after the owner marker is
    /// re-verified (`Device::configure`), then the marker moved to the candidate
    /// (`Device::remark`, again re-verified first), then the recorded key and `GotaTun` key file.
    /// Each step finds the previous ones done on a retry, and the engine-specific owner proof
    /// authorizes the predecessor and candidate only for the open journal.
    /// # Errors
    /// Refuses a stale operation, an altered local key or a failed durable/engine update.
    pub(crate) fn commit_rotation(
        &mut self,
        operation_id: &str,
        sequence: u64,
    ) -> io::Result<Identity> {
        let link = self.rotation_link()?;
        let store = self.store.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let mut state = store.rotation_secret()?.ok_or(io::ErrorKind::NotFound)?;
        if state.operation_id != operation_id || state.sequence != sequence {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let (candidate, candidate_public) = Key::from_private(&state.candidate)?;
        let current_public = self.rotation_public_key(&link)?;
        if state.completed {
            let identity = self.identity.as_ref().ok_or(io::ErrorKind::NotConnected)?;
            if current_public != candidate_public
                || identity.public_key != candidate_public
                || link.owner != Some(candidate_public)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            store.record_interface(&candidate_public)?;
            if self.engine_kind == EngineKind::GotaTun {
                let private = store
                    .read_private_key()?
                    .ok_or(io::ErrorKind::InvalidData)?;
                if crate::gotatun_node::secret_from_bytes(&private)?.1 != candidate_public {
                    return Err(io::ErrorKind::InvalidData.into());
                }
            }
            return Ok(identity.clone());
        }
        let previous_public = Key::from_private(&state.previous)?.1;
        if current_public == previous_public {
            if link.owner != Some(previous_public) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if !state.commit_requested {
                // Mark the operation before either engine changes its live key. A restart now
                // selects the candidate and the authenticated server can reconcile it.
                state.commit_requested = true;
                store.save_rotation_secret(&state)?;
                #[cfg(test)]
                if self.engine_kind == EngineKind::GotaTun {
                    rotation_tests::crash_checkpoint("rotation_commit_requested");
                }
            }
            match self.engine_kind {
                EngineKind::Kernel => {
                    let port = self
                        .identity
                        .as_ref()
                        .ok_or(io::ErrorKind::NotConnected)?
                        .port;
                    // The marker still names the predecessor; `configure` re-verifies it by index.
                    Device::configure(link.ifindex, previous_public, &candidate, port)?;
                }
                EngineKind::GotaTun => {
                    self.gotatun
                        .as_ref()
                        .ok_or(io::ErrorKind::NotConnected)?
                        .set_private_key(candidate.gotatun_secret()?)?;
                }
            }
            self.identity
                .as_mut()
                .ok_or(io::ErrorKind::NotConnected)?
                .public_key = candidate_public;
            #[cfg(test)]
            if self.engine_kind == EngineKind::GotaTun {
                rotation_tests::crash_checkpoint("rotation_device_key_changed");
            }
        } else if current_public != candidate_public {
            return Err(io::ErrorKind::InvalidData.into());
        } else if !state.commit_requested {
            state.commit_requested = true;
            store.save_rotation_secret(&state)?;
            #[cfg(test)]
            if self.engine_kind == EngineKind::GotaTun {
                rotation_tests::crash_checkpoint("rotation_commit_requested");
            }
        }
        self.identity
            .as_mut()
            .ok_or(io::ErrorKind::NotConnected)?
            .public_key = candidate_public;
        // Re-read the marker after the live key switch. A candidate marker is an idempotent retry.
        let live_link = Device::active_link()?
            .filter(|active| active.ifindex == link.ifindex && active.engine == self.engine_kind)
            .ok_or(io::ErrorKind::InvalidData)?;
        match live_link.owner {
            Some(owner) if owner == previous_public => {
                Device::remark(link.ifindex, previous_public, candidate_public)?;
            }
            Some(owner) if owner == candidate_public => {}
            _ => return Err(io::ErrorKind::InvalidData.into()),
        }
        #[cfg(test)]
        if self.engine_kind == EngineKind::GotaTun {
            rotation_tests::crash_checkpoint("rotation_owner_marker_changed");
        }
        // Keep uninstall ownership aligned only after the engine accepted the candidate key and
        // the marker names it. GotaTun's private key file is replaced atomically and synced.
        store.record_interface(&candidate_public)?;
        #[cfg(test)]
        if self.engine_kind == EngineKind::GotaTun {
            rotation_tests::crash_checkpoint("rotation_interface_recorded");
        }
        if self.engine_kind == EngineKind::GotaTun {
            store.replace_private_key(candidate.private_bytes())?;
        } else {
            self.kernel_owner = KernelProof::single(candidate_public);
        }
        #[cfg(test)]
        if self.engine_kind == EngineKind::GotaTun {
            rotation_tests::crash_checkpoint("rotation_private_key_saved");
        }
        if self.engine_kind == EngineKind::GotaTun {
            self.gotatun
                .as_ref()
                .ok_or(io::ErrorKind::NotConnected)?
                .set_owner(candidate_public)?;
        }
        // A rotation deliberately changes ownership; replace the worker with a fresh proof.
        self.route_repair.take();
        self.ensure_route_repair()?;
        let identity = self.identity.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        Ok(identity.clone())
    }

    /// Drop retained predecessor material after the server retires the overlap.
    /// # Errors
    /// Refuses a stale or not-yet-committed operation or an identity not fully persisted by commit.
    pub(crate) fn finish_rotation(&mut self, operation_id: &str, sequence: u64) -> io::Result<()> {
        let link = self.rotation_link()?;
        let store = self.store.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let state = store.rotation_secret()?.ok_or(io::ErrorKind::NotFound)?;
        if state.operation_id != operation_id || state.sequence != sequence {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let candidate = Key::from_private(&state.candidate)?.1;
        if self.rotation_public_key(&link)? != candidate
            || link.owner != Some(candidate)
            || self
                .identity
                .as_ref()
                .is_none_or(|identity| identity.public_key != candidate)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if !state.completed && !state.commit_requested {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if self.engine_kind == EngineKind::GotaTun {
            let private = store
                .read_private_key()?
                .ok_or(io::ErrorKind::InvalidData)?;
            if crate::gotatun_node::secret_from_bytes(&private)?.1 != candidate
                || store.recorded_interface()? != Some(candidate)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        store.complete_rotation_secret(operation_id, sequence)?;
        #[cfg(test)]
        if self.engine_kind == EngineKind::GotaTun {
            rotation_tests::crash_checkpoint("rotation_finished");
        }
        Ok(())
    }

    /// Prepare a rotation through the real node journal for an isolated namespace fixture.
    ///
    /// This entry point exists only with `test-support`; shipping callers use the authenticated
    /// action dispatcher, which keeps untrusted code from bypassing the coordinator protocol.
    /// # Errors
    /// Returns the same validation and durable-write failures as the internal rotation method.
    #[cfg(feature = "test-support")]
    pub fn prepare_rotation_for_fixture(
        &mut self,
        operation_id: &str,
        sequence: u64,
    ) -> io::Result<crate::policy::model::PublicKey> {
        self.prepare_rotation(operation_id, sequence)
    }

    /// Commit a prepared rotation through the real node engine for an isolated namespace fixture.
    /// # Errors
    /// Returns the same validation and engine-update failures as the internal rotation method.
    #[cfg(feature = "test-support")]
    pub fn commit_rotation_for_fixture(
        &mut self,
        operation_id: &str,
        sequence: u64,
    ) -> io::Result<crate::policy::model::PublicKey> {
        self.commit_rotation(operation_id, sequence)
            .map(|identity| identity.public_key)
    }

    /// Finish a committed rotation through the real node journal for an isolated namespace fixture.
    /// # Errors
    /// Returns the same validation and durable-write failures as the internal rotation method.
    #[cfg(feature = "test-support")]
    pub fn finish_rotation_for_fixture(
        &mut self,
        operation_id: &str,
        sequence: u64,
    ) -> io::Result<()> {
        self.finish_rotation(operation_id, sequence)
    }

    /// Remove all owned kernel work before reporting off. A failed cleanup remains visible.
    /// # Errors
    /// Reports failed kernel cleanup rather than claiming the component is disabled.
    pub fn down(&mut self) -> io::Result<()> {
        // Forwarding stops before the filter and link go, so no packet is forwarded unpoliced.
        self.stop_subnet_routes();
        // This durable intent precedes every kernel operation. A process stop
        // between the independent kernel transactions must reconcile as Off.
        let reset_state = self.authority_reset;
        self.authority_reset = AuthorityResetState::Stable;
        if let Err(error) = self.save(None, false) {
            self.authority_reset = reset_state;
            return Err(error);
        }
        self.enabled = false;
        #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
        {
            self.dns_integration.remove()?;
            self.dns_resolver = None;
        }
        self.route_repair.take();
        let mut foreign_live_link = false;
        if !self.owned && self.engine_kind == EngineKind::GotaTun {
            // A restore that failed after the TUN was proven ours never marked it owned, yet the
            // TUN outlives the process (D332). Down still removes it, under the same proof.
            if let (Some(store), Ok(Some(link))) = (&self.store, Device::active_link())
                && proven_gotatun_link(
                    &link,
                    &gotatun_owner_proof(store, self.config.as_ref().and_then(|c| c.local_key))?,
                )
            {
                if let Some(mut engine) = self.gotatun.take() {
                    engine.stop()?;
                }
                Device::delete_ifindex(link.ifindex)?;
            }
        }
        if self.owned {
            match Device::active_link()? {
                Some(active) if active.engine == self.engine_kind => {
                    if active.engine == EngineKind::Kernel {
                        if proven_kernel_link(&active, &self.kernel_owner) {
                            // Retire peers before the link deletion removes all routes.
                            if let Some(client) = &mut self.client {
                                client.clear_peers()?;
                            } else {
                                Client::new()?.clear_peers()?;
                            }
                            Device::delete_ifindex(active.ifindex)?;
                        } else {
                            // Another installation replaced this fixed-name link (D340): its
                            // peers, routes and the shared firewall are its own.
                            foreign_live_link = true;
                        }
                    } else {
                        let owns_link = self
                            .identity
                            .as_ref()
                            .is_some_and(|identity| active.owner == Some(identity.public_key));
                        if let Some(mut engine) = self.gotatun.take() {
                            engine.stop()?;
                        }
                        if owns_link {
                            Device::delete_ifindex(active.ifindex)?;
                        } else {
                            // Another installation replaced this fixed-name TUN. Stop only our
                            // stale worker; its link, routes and shared firewall belong to it.
                            foreign_live_link = true;
                        }
                    }
                }
                None => {
                    if let Some(mut engine) = self.gotatun.take() {
                        engine.stop()?;
                    }
                }
                Some(_) => return Err(io::ErrorKind::AlreadyExists.into()),
            }
            self.owned = false;
            self.kernel_owner = KernelProof::default();
        }
        #[cfg(feature = "test-support")]
        if let Some(hook) = BEFORE_SHARED_FILTER_DECISION
            .lock()
            .ok()
            .and_then(|mut hook| hook.take())
        {
            hook();
        }
        // The table's name is shared by every installation on the machine. Our link is gone by
        // now, so its name is free: another installation can create its link and adopt the table
        // before we get here (#260 J143 P3-4). Recheck for a live link right before removing it.
        // This narrows the race to the recheck itself; a per-installation table would close it.
        // A failed `up` can likewise leave another live node's filter adopted.
        if !foreign_live_link {
            self.remove_unshared_filter()?;
        }
        self.retire_routes()?;
        // A fresh firewall keeps this node's engine mode: a `GotaTun` node that comes up again
        // in this process must stay on the optional guard, not switch to the full kernel policy,
        // which needs nft or iptables-nft (D384).
        self.firewall = Firewall::for_node(None, self.engine_kind);
        self.proxy_ingress = infraternal_mesh::proxy_ports::MeshProxyIngress::default();
        self.client = None;
        self.gotatun = None;
        self.identity = None;
        self.config = None;
        self.connection_cleanup_pending = false;
        self.pending = None;
        if let Some(store) = &self.store {
            store.discard_rotation_state()?;
            store.remove_private_key()?;
        }
        Ok(())
    }
    /// The public key this node currently presents as its identity, once it is up.
    pub(crate) fn interface_key(&self) -> Option<crate::policy::model::PublicKey> {
        self.identity.as_ref().map(|identity| identity.public_key)
    }
    /// Read the retained applied configuration, never partial incoming chunks.
    #[must_use]
    pub fn config(&self) -> Option<&Config> {
        self.config.as_ref()
    }
    /// Stage a contiguous snapshot or delta. Apply only the final complete version.
    /// # Errors
    /// Refuses stale/out-of-order/wrong-node chunks before changing installed state.
    pub fn chunk(&mut self, chunk: Chunk) -> io::Result<bool> {
        let applied = self.chunk_inner(chunk);
        // A completed snapshot can add, change or withdraw subnet routes (D197 M3).
        if matches!(applied, Ok(true)) {
            self.reconcile_subnet_routes();
        }
        applied
    }

    /// The networks this node advertises as subnet routes (D197 M3), as saved by `mesh routes`.
    /// # Errors
    /// No state directory (an in-memory node) or an unreadable list.
    pub fn advertised_routes(&self) -> io::Result<BTreeSet<crate::policy::networks::Network>> {
        self.store
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .advertised_routes()
    }

    /// Replace the advertised networks; the caller tells the coordinator (`mesh.changed`).
    /// # Errors
    /// No state directory or a failed save.
    pub fn set_advertised_routes(
        &mut self,
        networks: &BTreeSet<crate::policy::networks::Network>,
    ) -> io::Result<()> {
        self.store
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .record_advertised_routes(networks)
    }

    /// Whether the route to `network`, reachable through a router peer, is installed, for `mesh routes`.
    #[must_use]
    pub fn network_route_state(
        &self,
        network: crate::policy::networks::Network,
    ) -> serde_json::Value {
        crate::subnet_routes::route_json(
            lock_route_state(&self.peer_route_state)
                .client_routes
                .states
                .get(&network),
        )
    }

    /// Whether this node forwards for the networks it serves, for `mesh routes`.
    #[must_use]
    pub fn forwarding_state(&self) -> serde_json::Value {
        self.subnet.forwarding_json()
    }

    /// Bring routes and forwarding in line with the applied snapshot (D197 M3).
    ///
    /// Idempotent, and never fails the snapshot: problems are kept for `mesh routes`. Only the
    /// `GotaTun` engine takes subnet routes; any other state (kernel engine, no snapshot, mesh
    /// off) stops serving and leaves no route behind.
    fn reconcile_subnet_routes(&mut self) {
        let config = match &self.config {
            Some(config)
                if self.enabled
                    && self.gotatun.is_some()
                    && self.engine_kind == EngineKind::GotaTun =>
            {
                config.clone()
            }
            _ => {
                self.stop_subnet_routes();
                return;
            }
        };
        {
            let mut state = lock_route_state(&self.peer_route_state);
            let endpoints = crate::subnet_routes::underlay_addresses(
                &config,
                state.live_endpoints.values().copied(),
            );
            state.client_routes.configure(&config, &endpoints);
            state.sync_client_routes(true);
        }
        let (served, _) = crate::firewall::served_networks(&config);
        if served.is_empty() {
            self.stop_forwarding();
            return;
        }
        if !self.firewall.forwards_served() {
            self.stop_forwarding();
            self.subnet.forwarding = crate::subnet_routes::Forwarding::Unavailable(
                "forwarding needs the kernel guard installed with nft; see mesh status".to_owned(),
            );
            return;
        }
        let owed = self
            .store
            .as_ref()
            .is_some_and(|store| store.ip_forward_owed().unwrap_or(false));
        let forwarding = match crate::subnet_routes::ip_forward() {
            Ok(true) => Ok(owed),
            Ok(false) => self
                .store
                .as_ref()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
                // Record the debt before the change, so a crash in between still turns it off.
                .and_then(|store| store.record_ip_forward_owed(true))
                .and_then(|()| crate::subnet_routes::set_ip_forward(true))
                .map(|()| true),
            Err(error) => Err(error),
        };
        match forwarding {
            Ok(turned_on) => {
                if let Some(engine) = &self.gotatun {
                    engine.set_forwarding(true);
                }
                self.subnet.forwarding = crate::subnet_routes::Forwarding::On { turned_on };
            }
            Err(error) => {
                self.stop_forwarding();
                self.subnet.forwarding = crate::subnet_routes::Forwarding::Unavailable(format!(
                    "IPv4 forwarding could not be turned on: {error}"
                ));
            }
        }
    }

    /// Stop forwarding for served networks: the packet filter first, then IPv4 forwarding, if this
    /// node turned it on. The nft rules go with the snapshot or the table.
    fn stop_forwarding(&mut self) {
        if let Some(engine) = &self.gotatun {
            engine.set_forwarding(false);
        }
        if let Some(store) = &self.store
            && store.ip_forward_owed().unwrap_or(false)
        {
            match crate::subnet_routes::set_ip_forward(false)
                .and_then(|()| store.record_ip_forward_owed(false))
            {
                Ok(()) => tracing::info!("mesh turned IPv4 forwarding off again"),
                Err(error) => {
                    tracing::warn!(error = %error, "mesh could not turn IPv4 forwarding off again");
                }
            }
        }
        self.subnet.forwarding = crate::subnet_routes::Forwarding::Idle;
    }

    /// Stop every subnet-route effect: forwarding, and the routes this node installed.
    ///
    /// The route dump runs only when the last reconcile wanted some network (installed, failed or
    /// overlapping), so the many snapshots of a node that routes nothing cost no netlink round
    /// trip. A route an earlier run left behind goes at the next reconcile, which always dumps,
    /// or with the link.
    fn stop_subnet_routes(&mut self) {
        self.stop_forwarding();
        let mut state = lock_route_state(&self.peer_route_state);
        if !state.client_routes.states.is_empty()
            && let Some(config) = self.config.as_ref()
            && let Err(error) =
                Device::sync_network_routes(&BTreeMap::new(), config.addresses.ipv4, None, None)
            && error.kind() != io::ErrorKind::NotConnected
        {
            tracing::warn!(error = %error, "mesh subnet routes could not be removed");
        }
        state.client_routes = crate::subnet_routes::ClientRoutes::default();
    }

    /// Apply one configuration chunk; [`Self::chunk`] adds the subnet-route reconcile.
    fn chunk_inner(&mut self, chunk: Chunk) -> io::Result<bool> {
        #[cfg(feature = "cutoff-measure")]
        {
            self.refusing_at_ns = None;
        }
        self.finish_connection_cleanup()?;
        if chunk
            .authority_epoch
            .as_deref()
            .is_some_and(|epoch| !crate::dataplane::valid_authority_epoch(epoch))
        {
            self.pending = None;
            tracing::warn!("mesh configuration chunk refused: authority epoch is malformed");
            return Err(io::ErrorKind::InvalidData.into());
        }
        let old_epoch = self
            .config
            .as_ref()
            .and_then(|old| old.authority_epoch.as_deref());
        let authority_changed = self
            .config
            .as_ref()
            .is_some_and(|old| old.authority_epoch != chunk.authority_epoch);
        if authority_changed {
            // Epoch-bearing snapshots are bound to the enabled local key before they can retire
            // any peers. Routing node IDs and revisions are not authority identities.
            if (old_epoch.is_some() || chunk.authority_epoch.is_some())
                && self
                    .identity
                    .as_ref()
                    .is_none_or(|identity| chunk.local_key != Some(identity.public_key))
            {
                self.pending = None;
                tracing::warn!(
                    error_kind = ?io::ErrorKind::InvalidData,
                    "mesh authority transition refused without the enrolled local key binding"
                );
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.validate_binding(&chunk)?;
            if old_epoch.is_some() && chunk.authority_epoch.is_none() && chunk.index == 0 {
                // A server rolled back to a release without epochs (D295) is one more authority
                // change, not an attack: whoever can send `mesh.configure` already controls peers.
                // Its full snapshot replaces the old peer set like any other (#382 P2).
                tracing::warn!(
                    old_epoch,
                    "mesh server stopped sending an authority epoch, likely a rollback; adopting its full snapshot"
                );
            }
            let pending_new_authority = self.pending.as_ref().is_some_and(|pending| {
                pending.config.authority_epoch == chunk.authority_epoch
                    && pending.from_version.is_none()
            });
            if chunk.index == 0 {
                if chunk.from_version.is_some() {
                    self.pending = None;
                    tracing::warn!(
                        "mesh configuration chunk refused: a new authority must start with a full snapshot"
                    );
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.pending = None;
                tracing::info!(
                    old_epoch,
                    new_epoch = ?chunk.authority_epoch,
                    old_version = ?self.config.as_ref().map(|config| config.version),
                    new_version = chunk.version,
                    "staging a full mesh snapshot from the changed authority"
                );
            } else if !pending_new_authority {
                self.pending = None;
                tracing::warn!(
                    "mesh configuration chunk refused: a new authority must start with a full snapshot"
                );
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        let result = self.stage(chunk);
        if let Err(error) = &result {
            self.pending = None;
            tracing::warn!(
                error_kind = ?error.kind(),
                "mesh configuration chunk refused"
            );
        }
        result
    }
    /// Commit a complete new-authority snapshot without cutting the runtime while it is staged.
    ///
    /// A durable peer-free snapshot replaces the old authority before any runtime mutation. A
    /// changed peer set then reaches the engine through one replacement transaction. When only
    /// authority or revision metadata changed, the installed peer inventory is retained so its
    /// handshakes continue uninterrupted.
    /// # Errors
    /// Refuses an unbound snapshot, persistence failure, or replacement that cannot fail closed.
    fn apply_authority_replacement(&mut self, config: Config) -> io::Result<bool> {
        let previous = self.config.clone().ok_or(io::ErrorKind::InvalidData)?;
        let runtime_matches = crate::dataplane::same_runtime_content(&previous, &config)
            && self.runtime_peer_inventory_matches(&config);
        let denied = self.prepare_authority_replacement(&config)?;
        // The fast path keeps peers, but endpoint-derived MTUs can still move with the underlay
        // path (#381). A failed refresh falls back to the full replacement below.
        if runtime_matches && self.refresh_unchanged_mesh_mtus(&config).is_ok() {
            if let Err(error) = self.save_with_snapshot_base(Some(&config), true, Some(&denied)) {
                return Err(self.fail_closed_authority_replacement(error, &denied));
            }
            self.authority_reset = AuthorityResetState::Stable;
            self.config = Some(config);
            return Ok(true);
        }
        match self.apply_authority_snapshot(config, &denied) {
            Ok(()) => Ok(true),
            Err(error) => Err(self.fail_closed_authority_replacement(error, &denied)),
        }
    }

    /// Re-derive the route and interface MTUs for an unchanged peer set (#381) without touching
    /// peers, so a same-content authority replacement cuts no session yet keeps MTUs current.
    ///
    /// The interface MTU first rises to the larger of the old and new values, so no route ever
    /// exceeds it, then settles on the new value once the host routes are written. The route
    /// state's installed peers become `config`'s, which relay callbacks look up under the lock.
    /// # Errors
    /// Reports a link or route-netlink failure; the caller then runs the full replacement.
    fn refresh_unchanged_mesh_mtus(&self, config: &Config) -> io::Result<()> {
        let link = match self.engine_kind {
            EngineKind::Kernel => self.owned_kernel_link()?,
            EngineKind::GotaTun => self.owned_gotatun_link()?,
        };
        let target = crate::mesh_mtu::for_config(Some(config));
        self.set_mesh_mtu(link.ifindex, Device::mtu(link.ifindex)?.max(target))?;
        let peers: Vec<_> = config
            .peers
            .values()
            .map(|policy| policy.peer.clone())
            .collect();
        self.refresh_peer_routes(&peers, &BTreeSet::new())?;
        self.set_mesh_mtu(link.ifindex, target)
    }

    /// Check that the live data plane contains exactly the keys in a same-content snapshot.
    ///
    /// `GotaTun` omits peers with no network access so their configured endpoints cannot receive
    /// unsolicited handshakes. The kernel engine retains its complete peer inventory.
    fn runtime_peer_inventory_matches(&self, config: &Config) -> bool {
        let Ok(counters) = self.peer_counters() else {
            return false;
        };
        let installed: std::collections::BTreeSet<_> = counters.keys().copied().collect();
        let desired = match self.engine_kind {
            EngineKind::GotaTun => crate::gotatun_node::peer_keys_with_network_access(config),
            EngineKind::Kernel => config
                .peers
                .values()
                .flat_map(|peer| [Some(peer.peer.key), peer.peer.previous_key])
                .flatten()
                .collect(),
        };
        installed == desired
    }

    /// Persist the deny state and retire a superseded journal without touching live peers.
    ///
    /// This runs only after the new authority's complete snapshot has passed chunk validation.
    /// A process stop between persistence and replacement then restores no peers from the old
    /// authority. An exact operation match retains its journal for commit or finish retries.
    /// # Errors
    /// Stops the owned runtime if the durable reset or journal retirement cannot complete.
    fn prepare_authority_replacement(&mut self, replacement: &Config) -> io::Result<Config> {
        let mut denied = replacement.clone();
        denied.default_policy = crate::dataplane::DefaultPolicy::Deny;
        denied.peers.clear();
        #[cfg(feature = "mesh-dns")]
        denied.peer_names.clear();
        self.pending = None;
        // A new process can still own the same database operation. Its authenticated full
        // snapshot must name the exact UUID and sequence; key binding was checked by stage.
        let continuity = self
            .store
            .as_ref()
            .map(|store| store.rotation_matches(replacement.rotation_operation.as_ref()))
            .transpose()
            .map(|matched| matched.unwrap_or(false));
        let continues_rotation = matches!(continuity, Ok(true));
        let rotation_error = match continuity {
            Ok(true) => None,
            Ok(false) => self.settle_authority_rotation().err(),
            Err(error) => Some(error),
        };
        if let Some(identity) = &self.identity {
            denied.local_key = Some(identity.public_key);
        }
        self.config = Some(denied.clone());
        self.authority_reset = AuthorityResetState::AwaitingFullSnapshot;
        let persistence_error = self.persist_retired_snapshot(&denied).err();
        let journal_error =
            if persistence_error.is_none() && rotation_error.is_none() && !continues_rotation {
                self.store
                    .as_ref()
                    .map(crate::node_state::Store::discard_rotation_journal)
                    .transpose()
                    .err()
            } else {
                None
            };
        if let Some(error) = persistence_error.or(rotation_error).or(journal_error) {
            return Err(self.fail_closed_authority_replacement(error, &denied));
        }
        #[cfg(test)]
        rotation_tests::j363_retirement_crash_checkpoint();
        Ok(denied)
    }

    /// Stop instead of restoring old-authority peers after a replacement error.
    fn fail_closed_authority_replacement(
        &mut self,
        error: io::Error,
        denied: &Config,
    ) -> io::Error {
        // Rejected content fences peers but keeps the journal.
        let mut denied = denied.clone();
        denied.default_policy = crate::dataplane::DefaultPolicy::Deny;
        denied.peers.clear();
        #[cfg(feature = "mesh-dns")]
        denied.peer_names.clear();
        self.config = Some(denied.clone());
        self.authority_reset = AuthorityResetState::AwaitingFullSnapshot;
        self.pending = None;
        // Fence restore first; the disabled write below retries any failure.
        let _ = self.persist_retired_snapshot(&denied);
        let stop_error = self.stop_retired_runtime().err();
        if let Err(persist_error) = self.persist_retired_snapshot(&denied) {
            tracing::error!(
                error_kind = ?persist_error.kind(),
                "could not persist disabled peer-free mesh state after authority replacement failed"
            );
        }
        stop_error.unwrap_or(error)
    }

    /// Settle an open key rotation on the live identity before retiring its authority journal.
    ///
    /// The journal belongs to the previous server's sequence space, but its active key remains
    /// this node's identity. Completing it first lets the subsequent durable authority snapshot
    /// bind to that key before the journal file is removed.
    /// # Errors
    /// Refuses an unproven active key or any failed rotation-state update.
    fn settle_authority_rotation(&mut self) -> io::Result<()> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let Some(rotation) = store.rotation_secret()? else {
            return Ok(());
        };
        let link = self.rotation_link()?;
        if rotation.completed {
            let candidate = Key::from_private(&rotation.candidate)?.1;
            if self.rotation_public_key(&link)? != candidate
                || self.identity.as_ref().map(|identity| identity.public_key) != Some(candidate)
                || link.owner != Some(candidate)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
        } else {
            self.settle_superseded_rotation(&link, &rotation)?;
        }
        if let (Some(config), Some(identity)) = (&mut self.config, &self.identity) {
            config.local_key = Some(identity.public_key);
        }
        Ok(())
    }

    /// Retry retirement cleanup only after a full snapshot validates after an interrupted reset.
    ///
    /// A durable peer-free state records the pending reset. If its journal removal failed, settle
    /// and save the active key binding again before unlinking that previous authority's journal.
    /// The incoming full snapshot's exact operation match retains it, independent of cached metadata.
    /// # Errors
    /// Refuses an unproven rotation or a failed state or journal write.
    fn retire_settled_authority_rotation(
        &mut self,
        operation: Option<&crate::dataplane::RotationContinuation>,
    ) -> io::Result<()> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        if store.rotation_secret()?.is_none() || store.rotation_matches(operation)? {
            return Ok(());
        }
        self.settle_authority_rotation()?;
        let config = self.config.clone().ok_or(io::ErrorKind::InvalidData)?;
        self.save(Some(&config), self.enabled)?;
        self.store
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .discard_rotation_journal()
    }

    /// Persist the peer-free epoch snapshot before the runtime fence, with an in-place fail-closed fallback.
    /// # Errors
    /// Reports route or snapshot persistence failures without restoring the previous peers.
    fn persist_retired_snapshot(&mut self, deny: &Config) -> io::Result<()> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let routes = store.record_routes(&self.routes);
        let state = crate::node_state::State {
            enabled: self.enabled,
            config: Some(deny.clone()),
            authority_reset_pending: true,
            backend: self.firewall.backend(),
        };
        let saved = store.save_retired(&state);
        saved?;
        routes
    }
    /// Stop the owned runtime without asking persistence to authorize the stop first.
    ///
    /// This is used only after a direct peer fence fails. It deletes only a link proved to belong
    /// to this node; a link owned by another installation is left alone.
    /// # Errors
    /// Reports the first failed link, engine, route, or firewall cleanup operation.
    fn stop_retired_runtime(&mut self) -> io::Result<()> {
        self.enabled = false;
        self.pending = None;
        self.route_repair.take();
        #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
        {
            self.dns_resolver = None;
        }
        let mut first_error = None;
        match self.engine_kind {
            EngineKind::Kernel => match Device::active_link() {
                Ok(Some(link)) if proven_kernel_link(&link, &self.kernel_owner) => {
                    if let Err(error) = Device::delete_ifindex(link.ifindex) {
                        first_error = Some(error);
                    }
                }
                Ok(None) => {}
                Ok(Some(_)) => first_error = Some(io::ErrorKind::AlreadyExists.into()),
                Err(error) => first_error = Some(error),
            },
            EngineKind::GotaTun => {
                if let Some(mut engine) = self.gotatun.take()
                    && let Err(error) = engine.stop()
                {
                    first_error = Some(error);
                }
                let snapshot_key = self.config.as_ref().and_then(|config| config.local_key);
                let proof = self
                    .store
                    .as_ref()
                    .map(|store| gotatun_owner_proof(store, snapshot_key))
                    .transpose();
                match proof.and_then(|proof| match Device::active_link()? {
                    Some(link)
                        if proof
                            .as_ref()
                            .is_some_and(|proof| proven_gotatun_link(&link, proof)) =>
                    {
                        Device::delete_ifindex(link.ifindex)?;
                        Ok(())
                    }
                    Some(_) => Err(io::ErrorKind::AlreadyExists.into()),
                    None => Ok(()),
                }) {
                    Ok(()) => {}
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
        }
        self.client = None;
        self.gotatun = None;
        if let Err(error) = Device::routes(&[], false) {
            first_error.get_or_insert(error);
        }
        if let Err(error) = Device::retain_recorded_routes(&self.routes, &[]) {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.retire_routes() {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.remove_unshared_filter() {
            first_error.get_or_insert(error);
        }
        // Keep the engine's firewall mode for the next `up`, as `down` does (D384).
        self.firewall = Firewall::for_node(None, self.engine_kind);
        self.proxy_ingress = infraternal_mesh::proxy_ports::MeshProxyIngress::default();
        self.identity = None;
        self.owned = false;
        self.kernel_owner = KernelProof::default();
        self.connection_cleanup_pending = false;
        first_error.map_or(Ok(()), Err)
    }
    /// Check the authenticated node key before a chunk can change the accepted binding.
    fn validate_binding(&self, chunk: &Chunk) -> io::Result<()> {
        let identity = self.identity.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        if chunk
            .local_key
            .is_some_and(|key| identity.public_key != key)
            || chunk.authority_epoch.is_some() && chunk.local_key != Some(identity.public_key)
            || self.config.as_ref().is_some_and(|old| {
                old.node != chunk.node
                    && (chunk.local_key.is_none()
                        || chunk.from_version.is_some()
                        || old.authority_epoch == chunk.authority_epoch
                            && chunk.version <= old.version)
            })
        {
            // Only an authenticated full coordinator snapshot, bound to our
            // enabled kernel key at a newer revision, can authorize replacement.
            // Unbound snapshots and deltas retain the accepted identity fence.
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
    /// Validate ordering and assemble complete snapshots before changing the runtime.
    fn stage(&mut self, chunk: Chunk) -> io::Result<bool> {
        let pending_new_authority = self.pending.as_ref().is_some_and(|pending| {
            pending.config.authority_epoch == chunk.authority_epoch
                && pending.from_version.is_none()
        });
        if self.config.as_ref().is_some_and(|old| {
            old.authority_epoch != chunk.authority_epoch && !pending_new_authority
        }) && (chunk.index != 0 || chunk.from_version.is_some())
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if self.authority_reset == AuthorityResetState::AwaitingFullSnapshot
            && chunk.from_version.is_some()
        {
            self.pending = None;
            return Err(io::ErrorKind::InvalidData.into());
        }
        if !chunk.access_updates.is_empty()
            && (chunk.from_version.is_none()
                || chunk.index != 0
                || !chunk.last
                || !chunk.upserted.is_empty()
                || !chunk.merged.is_empty()
                || !chunk.removed.is_empty()
                || self
                    .config
                    .as_ref()
                    .is_none_or(|old| old.server != chunk.server))
        {
            // A range action replaces only rules in the acknowledged complete
            // base. It cannot hide identity changes or continue partial staging.
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.validate_binding(&chunk)?;
        if chunk.index == 0 {
            let current = self.config.as_ref().map(|config| config.version);
            if chunk.from_version.is_some() && chunk.from_version != current
                || current.is_some_and(|v| chunk.from_version.is_some() && chunk.version <= v)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut config = if chunk.from_version.is_some() {
                self.config.clone().ok_or(io::ErrorKind::InvalidData)?
            } else {
                Config {
                    authority_epoch: chunk.authority_epoch.clone(),
                    rotation_operation: chunk.rotation_operation.clone(),
                    local_key: chunk.local_key,
                    server: chunk.server,
                    node: chunk.node,
                    #[cfg(feature = "mesh-dns")]
                    name: chunk.name.clone(),
                    #[cfg(feature = "mesh-dns")]
                    dns_suffix: chunk.dns_suffix.clone(),
                    version: chunk.version,
                    addresses: chunk.addresses,
                    default_policy: chunk.default_policy,
                    exposure: chunk.exposure.clone(),
                    peers: BTreeMap::new(),
                    #[cfg(feature = "mesh-dns")]
                    peer_names: BTreeMap::new(),
                }
            };
            config
                .rotation_operation
                .clone_from(&chunk.rotation_operation);
            if chunk.from_version.is_some() {
                // Rotation commits change the authenticated local key inside the same authority.
                // `validate_binding` above ties this update to the key the live engine presents.
                config.local_key = chunk.local_key;
            }
            #[cfg(feature = "mesh-dns")]
            let config = {
                let mut config = config;
                config.name.clone_from(&chunk.name);
                config.dns_suffix.clone_from(&chunk.dns_suffix);
                config
            };
            self.pending = Some(Pending {
                server: chunk.server,
                next: 0,
                version: chunk.version,
                from_version: chunk.from_version,
                default_policy: chunk.default_policy,
                config,
            });
        }
        let pending = self.pending.as_mut().ok_or(io::ErrorKind::InvalidData)?;
        #[cfg(feature = "mesh-dns")]
        let name_changed = pending.config.name != chunk.name;
        #[cfg(feature = "mesh-dns")]
        let dns_suffix_changed = pending.config.dns_suffix != chunk.dns_suffix;
        #[cfg(not(feature = "mesh-dns"))]
        let name_changed = false;
        #[cfg(not(feature = "mesh-dns"))]
        let dns_suffix_changed = false;
        if pending.server != chunk.server
            || pending.config.authority_epoch != chunk.authority_epoch
            || pending.config.rotation_operation != chunk.rotation_operation
            || pending.next != chunk.index
            || pending.config.local_key != chunk.local_key
            || pending.config.node != chunk.node
            || name_changed
            || dns_suffix_changed
            || pending.config.addresses != chunk.addresses
            || pending.version != chunk.version
            || pending.from_version != chunk.from_version
            || pending.default_policy != chunk.default_policy
            || pending.config.exposure != chunk.exposure
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        pending.next = pending
            .next
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        pending.config.version = chunk.version;
        pending.config.default_policy = chunk.default_policy;
        pending.config.server = chunk.server;
        crate::access_updates::apply(&mut pending.config, &chunk.access_updates)?;
        for node in chunk.removed {
            pending.config.peers.remove(&node);
            #[cfg(feature = "mesh-dns")]
            pending.config.peer_names.remove(&node);
        }
        pending.config.peers.extend(chunk.upserted);
        #[cfg(feature = "mesh-dns")]
        for id in chunk.removed_peer_names {
            if !pending.config.peers.contains_key(&id)
                || pending.config.peer_names.remove(&id).is_none()
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        for (id, partial) in chunk.merged {
            let peer = pending
                .config
                .peers
                .get_mut(&id)
                .ok_or(io::ErrorKind::InvalidData)?;
            if !partial.continues(peer) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            peer.inbound.union(&partial.inbound);
            peer.outbound.union(&partial.outbound);
        }
        #[cfg(feature = "mesh-dns")]
        for (id, name) in chunk.peer_names {
            if !pending.config.peers.contains_key(&id)
                || name.is_empty()
                || name.len() > 63
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || name.starts_with('-')
                || name.ends_with('-')
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            pending.config.peer_names.insert(id, name);
        }
        if !chunk.last {
            return Ok(false);
        }
        let pending = self.pending.take().ok_or(io::ErrorKind::InvalidData)?;
        let full_snapshot = pending.from_version.is_none();
        let config = pending.config;
        let authority_changed = self
            .config
            .as_ref()
            .is_some_and(|old| old.authority_epoch != config.authority_epoch);
        let completes_authority_reset =
            self.authority_reset == AuthorityResetState::AwaitingFullSnapshot && full_snapshot;
        if authority_changed || completes_authority_reset {
            // Validate before settlement; rejected authorities still fence stale peers.
            let validation = (|| {
                self.validate_snapshot(&config)?;
                #[cfg(feature = "mesh-dns")]
                crate::dns::Records::from_config(&config)?;
                let proposed: Vec<_> = std::iter::once(config.addresses)
                    .chain(config.peers.values().map(|peer| peer.peer.addresses))
                    .collect();
                Device::check_routes(&proposed)?;
                if self.engine_kind == EngineKind::GotaTun {
                    crate::gotatun_node::Engine::prepare_policy(
                        &config,
                        self.proxy_ingress.clone(),
                    )?;
                }
                Ok::<_, io::Error>(())
            })();
            if let Err(error) = validation {
                return Err(if authority_changed {
                    self.fail_closed_authority_replacement(error, &config)
                } else {
                    error
                });
            }
            if !authority_changed {
                self.retire_settled_authority_rotation(config.rotation_operation.as_ref())?;
            }
        }
        if authority_changed {
            return self.apply_authority_replacement(config);
        }
        // A lower revision under the same epoch is accepted on purpose when this node has a
        // Store: a database restored under a running server keeps that process's epoch but
        // rewinds its revisions, and refusing would strand every node (#382). The Store's
        // exact-base compare-and-set (`save_full_snapshot`) makes the swap durable and atomic.
        // Only a node without a Store, which has no such base, refuses it. This is not a
        // revision fence for stored nodes (J418 P3-a).
        let lower_revision_replacement = self.config.as_ref().is_some_and(|old| {
            full_snapshot
                && old.authority_epoch == config.authority_epoch
                && config.version < old.version
        });
        if lower_revision_replacement && !completes_authority_reset && self.store.is_none() {
            tracing::warn!(
                old_version = ?self.config.as_ref().map(|old| old.version),
                new_version = config.version,
                "mesh lower-revision snapshot refused without a durable replacement base"
            );
            return Err(io::ErrorKind::InvalidData.into());
        }
        let snapshot_base = self
            .config
            .as_ref()
            .filter(|old| {
                full_snapshot
                    && old.authority_epoch == config.authority_epoch
                    && (completes_authority_reset || config.version < old.version)
            })
            .cloned();
        if self.config.as_ref() == Some(&config) {
            if completes_authority_reset {
                self.save_with_snapshot_base(Some(&config), true, snapshot_base.as_ref())?;
                self.authority_reset = AuthorityResetState::Stable;
            }
            return Ok(true);
        }
        if self
            .config
            .as_ref()
            .is_some_and(|old| old.version == config.version)
            && !completes_authority_reset
        {
            // Operation metadata can clear at completion without advancing packet policy.
            // Reconnect may replay that same revision; it still cannot change keys or access.
            if self
                .config
                .as_ref()
                .is_some_and(|old| crate::dataplane::same_runtime_content(old, &config))
            {
                self.save(Some(&config), true)?;
                self.config = Some(config);
                return Ok(true);
            }
            return self.upgrade_legacy_binding(config);
        }
        if let Some(base) = snapshot_base.as_ref() {
            self.apply_with_snapshot_base(config, base)?;
        } else {
            self.apply(config)?;
        }
        Ok(true)
    }
    fn upgrade_legacy_binding(&mut self, config: Config) -> io::Result<bool> {
        // The staging fence has already matched a present binding to the enabled
        // kernel key. Only this previously absent metadata may change at an
        // accepted revision; compare every prior field after the final chunk.
        let old = self.config.as_ref().ok_or(io::ErrorKind::InvalidData)?;
        if old.local_key.is_some() || config.local_key.is_none() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut bound = old.clone();
        bound.local_key = config.local_key;
        if bound != config {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.save(Some(&config), true)?;
        self.config = Some(config);
        Ok(true)
    }
    // Keep transition ingress protection available before any address mutation.
    fn apply_fence(&mut self, fence: &Config, recovery: &Config) -> io::Result<()> {
        let mut aliases: Vec<_> = self
            .config
            .as_ref()
            .filter(|old| old.addresses != fence.addresses)
            .map(|old| old.addresses)
            .into_iter()
            .collect();
        if self.config.is_none() {
            // During restart the kernel can retain aliases from an interrupted
            // replacement that the accepted snapshot never recorded. Fence them
            // before reconciliation can remove addresses or restore policy.
            aliases.extend(Device::host_addresses()?.into_iter().filter_map(|address| {
                let mut alias = fence.addresses;
                match address {
                    IpAddr::V4(address) if address != alias.ipv4 => alias.ipv4 = address,
                    IpAddr::V6(address) if address != alias.ipv6 => alias.ipv6 = address,
                    _ => return None,
                }
                Some(alias)
            }));
        }
        // Normal replacement preserves the accepted view. Recovery uses saved
        // intent even when connection cleanup was interrupted after persistence.
        let connections = self.config.as_ref().unwrap_or(recovery);
        self.firewall
            .apply_with_aliases(fence, &aliases, connections)?;
        Ok(())
    }
    /// Apply an ordinary config with the accepted state available for rollback.
    fn apply(&mut self, config: Config) -> io::Result<()> {
        self.apply_transaction(config, None, false)
    }
    /// Apply a full snapshot whose exact prior config authorizes a revision replacement.
    fn apply_with_snapshot_base(
        &mut self,
        config: Config,
        snapshot_base: &Config,
    ) -> io::Result<()> {
        self.apply_transaction(config, Some(snapshot_base), false)
    }
    /// Apply a changed authority snapshot while reconciling every live peer against its full set.
    fn apply_authority_snapshot(
        &mut self,
        config: Config,
        snapshot_base: &Config,
    ) -> io::Result<()> {
        self.apply_transaction(config, Some(snapshot_base), true)
    }
    /// Check complete peer identities and address ownership before any destructive reset.
    ///
    /// Staging checks each chunk's headers; these cross-peer checks need the assembled snapshot.
    /// # Errors
    /// Refuses address changes without overlap or colliding peer keys and addresses.
    fn validate_snapshot(&self, config: &Config) -> io::Result<()> {
        if self
            .config
            .as_ref()
            .is_some_and(|old| old.addresses != config.addresses && old.node == config.node)
        {
            // Address transitions require the later overlap barrier, never remove live addresses here [199].
            return Err(io::ErrorKind::Unsupported.into());
        }
        let mut keys = std::collections::BTreeSet::new();
        let mut addresses = std::collections::BTreeSet::new();
        let mut ipv6 = std::collections::BTreeSet::new();
        for (node, peer) in &config.peers {
            if *node == config.node
                || !keys.insert(peer.peer.key)
                || !addresses.insert(peer.peer.addresses.ipv4)
                || !ipv6.insert(peer.peer.addresses.ipv6)
                || peer.peer.addresses.ipv4 == config.addresses.ipv4
                || peer.peer.addresses.ipv6 == config.addresses.ipv6
                || self
                    .identity
                    .as_ref()
                    .is_some_and(|identity| identity.public_key == peer.peer.key)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if let Some(previous) = peer.peer.previous_key
                && (previous == peer.peer.key
                    || !keys.insert(previous)
                    || self
                        .identity
                        .as_ref()
                        .is_some_and(|identity| identity.public_key == previous))
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if peer.peer.previous_active && peer.peer.previous_key.is_none() {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        Ok(())
    }
    /// Keep the apply/fence/rollback transaction and its failure ordering visible together.
    fn apply_transaction(
        &mut self,
        config: Config,
        snapshot_base: Option<&Config>,
        force_reconcile: bool,
    ) -> io::Result<()> {
        #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
        let dns_records = crate::dns::Records::from_config(&config)?;
        #[cfg(feature = "cutoff-measure")]
        let validation = crate::cutoff_measure::Stage::new(config.node, config.version, "validate");
        self.validate_snapshot(&config)?;
        let mut packet_policy = if self.engine_kind == EngineKind::GotaTun {
            self.gotatun
                .as_ref()
                .map(|_| {
                    crate::gotatun_node::Engine::prepare_policy(&config, self.proxy_ingress.clone())
                })
                .transpose()?
        } else {
            None
        };
        #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
        if self.config.is_some() {
            self.ensure_dns_resolver(config.addresses.ipv4)?;
        }
        #[cfg(feature = "cutoff-measure")]
        drop(validation);
        // An IPv4-only node (IPv6 off on its link, #578) skips both fast paths below once the
        // link carries IPv6 again, so the full path installs its IPv6 address and peer routes.
        // Only that rare state pays for the extra link read.
        let ipv6_back = self.mesh_ipv6 == Some(false) && Device::mesh_ipv6_enabled()?;
        if ipv6_back {
            // The kernel dropped every IPv6 peer route while IPv6 was off; a record from before
            // could still list one, so this apply writes every route (#260 J1240).
            lock_route_state(&self.peer_route_state).forget_written();
        }
        if let Some(old) = &self.config {
            let endpoints_only = !force_reconcile
                && !ipv6_back
                && old.node == config.node
                && old.addresses == config.addresses
                && old.peers.len() == config.peers.len()
                && old.default_policy == config.default_policy
                && config.peers.iter().all(|(id, peer)| {
                    old.peers.get(id).is_some_and(|old| {
                        old.inbound == peer.inbound
                            && old.outbound == peer.outbound
                            // Subnet routes change allowed IPs, the packet filter and the
                            // guard's forward and NAT rules (D197 M3): never an endpoint update.
                            && old.networks == peer.networks
                            && old.peer.key == peer.peer.key
                            && old.peer.addresses == peer.peer.addresses
                            && old.peer.ipv4_only == peer.peer.ipv4_only
                            && old.peer.side_port == peer.peer.side_port
                            && old.peer.previous_key == peer.peer.previous_key
                            && old.peer.previous_active == peer.peer.previous_active
                    })
                });
            if endpoints_only {
                let mesh_link = match self.engine_kind {
                    EngineKind::Kernel => self.owned_kernel_link()?,
                    EngineKind::GotaTun => self.owned_gotatun_link()?,
                };
                let mesh_mtu = (
                    mesh_link.ifindex,
                    Device::mtu(mesh_link.ifindex)?,
                    crate::mesh_mtu::for_config(Some(&config)),
                );
                let mut updates = Vec::new();
                for (id, peer) in &config.peers {
                    let previous = &old.peers[id].peer;
                    if previous.endpoint != peer.peer.endpoint {
                        updates.push((
                            previous,
                            peer.peer.endpoint.ok_or(io::ErrorKind::Unsupported)?,
                        ));
                    }
                }
                match self.engine_kind {
                    EngineKind::Kernel => {
                        self.client.as_ref().ok_or(io::ErrorKind::NotConnected)?;
                    }
                    EngineKind::GotaTun => {
                        self.gotatun.as_ref().ok_or(io::ErrorKind::NotConnected)?;
                    }
                }
                // Persist intent before installing endpoints. Restore replays it
                // if the process stops between the save and kernel installation.
                let saved = self.save_applied_revision(&config, snapshot_base, false);
                if self.engine_kind == EngineKind::GotaTun
                    && snapshot_base.is_none()
                    && saved
                        .as_ref()
                        .is_err_and(|error| error.kind() == io::ErrorKind::InvalidData)
                {
                    // A failed endpoint apply can leave durable intent ahead of runtime.
                    // Keep the full writer's revision checks for that recovery case.
                    self.save(Some(&config), true)?;
                } else {
                    saved?;
                }
                if snapshot_base.is_some() {
                    self.authority_reset = AuthorityResetState::Stable;
                }
                self.set_mesh_mtu(mesh_mtu.0, mesh_mtu.1.max(mesh_mtu.2))?;
                let route_overrides_to_clear: BTreeSet<_> =
                    updates.iter().map(|(previous, _)| previous.key).collect();
                let route_state = Arc::clone(&self.peer_route_state);
                let peers: Vec<_> = config
                    .peers
                    .values()
                    .map(|policy| policy.peer.clone())
                    .collect();
                let mut previous_route_overrides = None;
                let installed: io::Result<()> = (|| {
                    match self.engine_kind {
                        EngineKind::Kernel => {
                            let client = self.client.as_mut().ok_or(io::ErrorKind::NotConnected)?;
                            updates.iter().try_for_each(|(previous, endpoint)| {
                                client.endpoint(previous.key, *endpoint)
                            })?;
                        }
                        EngineKind::GotaTun => {
                            self.gotatun
                                .as_ref()
                                .ok_or(io::ErrorKind::NotConnected)?
                                .apply(config.clone())?;
                        }
                    }
                    previous_route_overrides = Some(refresh_peer_routes_from(
                        &route_state,
                        &peers,
                        &route_overrides_to_clear,
                    )?);
                    Ok(())
                })();
                // Release the engine-field borrow before updating the shared interface MTU.
                let installed = installed.and_then(|()| self.set_mesh_mtu(mesh_mtu.0, mesh_mtu.2));
                if let Err(error) = installed {
                    if let Some(previous) = previous_route_overrides {
                        self.restore_peer_route_state(previous);
                    }
                    match self.engine_kind {
                        EngineKind::Kernel => {
                            let client = self.client.as_mut().ok_or(io::ErrorKind::NotConnected)?;
                            for (previous, _) in &updates {
                                if let Some(endpoint) = previous.endpoint {
                                    client.endpoint(previous.key, endpoint)?;
                                } else {
                                    // Omitting the endpoint attribute cannot clear one.
                                    // Recreate only this peer to restore the saved absence.
                                    client
                                        .peers(std::slice::from_ref(*previous), &[previous.key])?;
                                }
                            }
                        }
                        EngineKind::GotaTun => {
                            self.gotatun
                                .as_ref()
                                .ok_or(io::ErrorKind::NotConnected)?
                                .apply(old.clone())?;
                        }
                    }
                    let restore: Vec<_> = old
                        .peers
                        .values()
                        .map(|policy| policy.peer.clone())
                        .collect();
                    self.install_peer_routes(&restore, false)?;
                    self.set_mesh_mtu(
                        mesh_mtu.0,
                        mesh_mtu.1.max(crate::mesh_mtu::IPV6_MINIMUM_MTU),
                    )?;
                    // Keep the newer durable desired endpoints for recovery.
                    // No revision is acknowledged on failure; the server may
                    // retry it after this kernel-only rollback. Publishing old
                    // intent here would violate the durable revision fence.
                    return Err(error);
                }
                self.config = Some(config);
                #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
                self.publish_dns(dns_records)?;
                return Ok(());
            }
        }

        #[cfg(feature = "cutoff-measure")]
        let inventory = crate::cutoff_measure::Stage::new(config.node, config.version, "inventory");
        let proposed: Vec<_> = std::iter::once(config.addresses)
            .chain(config.peers.values().map(|peer| peer.peer.addresses))
            .collect();
        self.route_validation.check(&proposed)?;
        let old_peers = self.config.as_ref().map(|old| &old.peers);
        let changed: Vec<_> = config
            .peers
            .iter()
            .filter(|(node, peer)| {
                old_peers
                    .and_then(|old| old.get(node))
                    .is_none_or(|old| old.peer != peer.peer)
            })
            .map(|(_, peer)| peer.peer.clone())
            .collect();
        // Kernel state can be newer than the saved public snapshot after a crash.
        // Retire orphan keys as well as keys removed from the retained configuration.
        let desired: std::collections::BTreeSet<_> = config
            .peers
            .values()
            .flat_map(|peer| [Some(peer.peer.key), peer.peer.previous_key])
            .flatten()
            .collect();
        let retired_keys: Vec<_> = self
            .installed_peer_keys()?
            .into_iter()
            .filter(|key| !desired.contains(key))
            .collect();
        let mut route_overrides_to_clear: BTreeSet<_> = retired_keys.iter().copied().collect();
        if let Some(old) = &self.config {
            for (node, peer) in &config.peers {
                if old
                    .peers
                    .get(node)
                    .is_some_and(|old| old.peer.endpoint != peer.peer.endpoint)
                {
                    route_overrides_to_clear.insert(peer.peer.key);
                }
            }
        }
        #[cfg(feature = "cutoff-measure")]
        drop(inventory);
        if changed.is_empty()
            && !ipv6_back
            && retired_keys.is_empty()
            && route_overrides_to_clear.is_empty()
            && self.config.as_ref().is_some_and(|old| {
                old.node == config.node
                    && old.addresses == config.addresses
                    && old.peers.len() == config.peers.len()
            })
        {
            // Route validation and the actual key inventory above still run.
            // Only access changes remain. Keep the small firewall transaction, but
            // still rederive peer route budgets because their underlay can change
            // independently of the accepted peer snapshot.
            #[cfg(feature = "cutoff-measure")]
            let firewall =
                crate::cutoff_measure::Stage::new(config.node, config.version, "firewall");
            #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
            self.ensure_dns_resolver(config.addresses.ipv4)?;
            // The same nodes keep the same addresses here, so the new grants can reach the
            // packet path first: a revocation is enforced before the firewall, routes or the
            // disk save run, not after them (J592 P2-5). A failure below republishes the old
            // grants.
            self.publish_gotatun_policy(packet_policy.take());
            if let Err(error) = self.firewall.install_pending(&config) {
                self.restore_gotatun_policy(&BTreeSet::new());
                return Err(error);
            }
            // `GotaTun` installs only peers with network access (gotatun_node.rs), so a grant or
            // a revocation adds or removes engine peers although no peer field changed. Kernel
            // `WireGuard` keeps every peer and needs only the firewall (#515).
            // Networks behind a router peer are part of its allowed IPs (D197 M3), so a change
            // there reconfigures the engine as well.
            let engine_peers_changed = self.engine_kind == EngineKind::GotaTun
                && self.config.as_ref().is_none_or(|old| {
                    crate::gotatun_node::peer_keys_with_network_access(old)
                        != crate::gotatun_node::peer_keys_with_network_access(&config)
                        || crate::gotatun_node::networks_behind_peers(old)
                            != crate::gotatun_node::networks_behind_peers(&config)
                });
            // Undo this transaction's packet-path changes: the old grants, and the old engine
            // peers when this change added or removed some.
            let restore_engine = |node: &Self| -> io::Result<()> {
                node.restore_gotatun_policy(&BTreeSet::new());
                if engine_peers_changed {
                    node.gotatun
                        .as_ref()
                        .ok_or(io::ErrorKind::NotConnected)?
                        .apply(node.config.clone().ok_or(io::ErrorKind::NotConnected)?)?;
                }
                Ok(())
            };
            if engine_peers_changed
                && let Err(error) = self
                    .gotatun
                    .as_ref()
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
                    .and_then(|engine| engine.apply(config.clone()))
            {
                self.restore_gotatun_policy(&BTreeSet::new());
                self.firewall
                    .apply(self.config.as_ref().ok_or(io::ErrorKind::NotConnected)?)?;
                return Err(error);
            }
            let configured_peers: Vec<_> = config
                .peers
                .values()
                .map(|policy| policy.peer.clone())
                .collect();
            if let Err(error) = self.install_peer_routes(&configured_peers, false) {
                restore_engine(self)?;
                self.firewall
                    .apply(self.config.as_ref().ok_or(io::ErrorKind::NotConnected)?)?;
                return Err(error);
            }
            #[cfg(feature = "cutoff-measure")]
            {
                self.refusing_at_ns = crate::cutoff_measure::monotonic_ns();
            }
            #[cfg(feature = "cutoff-measure")]
            drop(firewall);
            #[cfg(feature = "cutoff-measure")]
            let persistence =
                crate::cutoff_measure::Stage::new(config.node, config.version, "persist");
            if let Err(error) = self.save_applied_revision(&config, snapshot_base, false) {
                restore_engine(self)?;
                self.firewall
                    .apply(self.config.as_ref().ok_or(io::ErrorKind::NotConnected)?)?;
                return Err(error);
            }
            if snapshot_base.is_some() {
                self.authority_reset = AuthorityResetState::Stable;
            }
            #[cfg(feature = "cutoff-measure")]
            drop(persistence);
            #[cfg(feature = "cutoff-measure")]
            let _retire = crate::cutoff_measure::Stage::new(config.node, config.version, "retire");
            self.config = Some(config);
            #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
            self.publish_dns(dns_records)?;
            self.connection_cleanup_pending = true;
            return self.finish_connection_cleanup();
        }
        let desired_routes: BTreeSet<IpAddr> = config
            .peers
            .values()
            .flat_map(|peer| peer.peer.routed_addresses())
            .collect();
        let mut recorded = self.routes.clone();
        if self.config.is_none() && self.engine_kind == EngineKind::Kernel {
            // Read retained AllowedIPs while orphan keys still exist. Persist
            // their public ownership before touching peers, routes or policy.
            recorded.extend(Device::peer_routes()?);
        }
        recorded.extend(&desired_routes);
        if let Some(store) = &self.store {
            store.record_routes(&recorded)?;
        }
        self.routes = recorded;
        // Fence all NEW traffic while multi-datagram kernel state changes. Established
        // sessions keep flowing. A failed apply restores the old view before removing the fence.
        let mut fence = config.clone();
        for peer in fence.peers.values_mut() {
            peer.inbound = crate::policy::rules::TrafficPolicy::None;
            peer.outbound = crate::policy::rules::TrafficPolicy::None;
        }
        let mesh_link = match self.engine_kind {
            EngineKind::Kernel => self.owned_kernel_link()?,
            EngineKind::GotaTun => self.owned_gotatun_link()?,
        };
        let mesh_mtu = (
            mesh_link.ifindex,
            Device::mtu(mesh_link.ifindex)?,
            crate::mesh_mtu::for_config(Some(&config)),
        );
        self.apply_fence(&fence, &config)?;
        // The engine starts delivering a reused or moved address's packets for its new owner as
        // soon as the peers change below. Withdraw the old owners from the packet path first,
        // then publish the new policy right after the peer change, before routes, the firewall
        // and the disk save (J592 P2-5). A failed transaction keeps them withdrawn until the
        // engine has its old peers back (J617 P2).
        let moved = self.moved_gotatun_peers(&config);
        if let Some(engine) = self.gotatun.as_ref() {
            engine.withdraw_peers(&moved);
        }
        #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
        let dns_was_running = self.dns_resolver.is_some();
        let mut previous_route_overrides = None;
        let result = (|| {
            if self
                .config
                .as_ref()
                .is_none_or(|old| old.addresses != config.addresses)
                || ipv6_back
            {
                let ipv6 = Device::addresses(config.addresses)?;
                self.note_mesh_ipv6(ipv6);
            }
            #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
            self.ensure_dns_resolver(config.addresses.ipv4)?;
            let (ifindex, previous_mtu, requested_mtu) = mesh_mtu;
            // Keep the larger interface until per-peer route metrics are installed. The shared
            // link stays IPv6-safe; its final size follows the largest peer budget.
            self.set_mesh_mtu(ifindex, previous_mtu.max(requested_mtu))?;
            self.apply_peer_changes(&config, &changed, &retired_keys)?;
            self.publish_gotatun_policy(packet_policy.take());
            // A full accepted snapshot also re-derives routes for unchanged peers: the endpoint
            // route or its egress link MTU may have changed since their last peer update.
            let configured_peers: Vec<_> = config
                .peers
                .values()
                .map(|policy| policy.peer.clone())
                .collect();
            previous_route_overrides =
                Some(self.refresh_peer_routes(&configured_peers, &route_overrides_to_clear)?);
            if self.config.is_none()
                || self
                    .routes
                    .iter()
                    .any(|route| !desired_routes.contains(route))
            {
                // An IPv4-only peer's IPv6 route is not retained: it is retired when the peer turns IPv4-only.
                let retained: Vec<IpAddr> = [
                    IpAddr::V4(config.addresses.ipv4),
                    IpAddr::V6(config.addresses.ipv6),
                ]
                .into_iter()
                .chain(desired_routes.iter().copied())
                .collect();
                Device::retain_recorded_routes(&self.routes, &retained)?;
            }
            self.set_mesh_mtu(ifindex, requested_mtu)?;
            self.firewall.install_pending(&config)?;
            #[cfg(feature = "cutoff-measure")]
            {
                self.refusing_at_ns = crate::cutoff_measure::monotonic_ns();
            }
            // Retire inventory only after kernel cleanup. If accepted-state
            // persistence fails, keep the union available for rollback/restart.
            let recorded = std::mem::replace(&mut self.routes, desired_routes);
            #[cfg(feature = "test-support")]
            let saved = run_transaction_seam(&BEFORE_TRANSACTION_SAVE)
                .and_then(|()| self.save_applied_revision(&config, snapshot_base, true));
            #[cfg(not(feature = "test-support"))]
            let saved = self.save_applied_revision(&config, snapshot_base, true);
            if saved.is_err() {
                self.routes = recorded;
            }
            saved
        })();
        if let Err(error) = result {
            if let Some(previous) = previous_route_overrides {
                self.restore_peer_route_state(previous);
            }
            #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
            if !dns_was_running && self.config.is_none() {
                self.dns_resolver = None;
            }
            // Saving can fail after the permissive policy transaction. Reinstall
            // the fence before rollback so any later error still denies NEW traffic.
            // The packet path goes back to the accepted grants (or denies everything when there
            // are none), whether or not the new policy was already published. The engine may
            // still hold the new peer set, where a moved peer's old address can belong to
            // another node, so the moved peers stay withdrawn until `apply(old)` below has
            // succeeded. If any rollback step fails, they stay withdrawn (J617 P2).
            self.restore_gotatun_policy(&moved);
            self.apply_fence(&fence, &config)?;
            if let Some(old) = &self.config {
                if old.addresses != config.addresses {
                    // Rollback restores the old state quietly; only accepted changes are logged.
                    self.mesh_ipv6 = Some(Device::addresses(old.addresses)?);
                }
                let restore: Vec<_> = old.peers.values().map(|peer| peer.peer.clone()).collect();
                // If rollback itself fails the restrictive fence remains. Never report an applied version.
                if self.engine_kind == EngineKind::Kernel {
                    self.client
                        .as_mut()
                        .ok_or(io::ErrorKind::NotConnected)?
                        .peers(
                            &restore,
                            &changed
                                .iter()
                                .filter(|peer| {
                                    !old.peers.values().any(|old| old.peer.key == peer.key)
                                })
                                .map(|peer| peer.key)
                                .collect::<Vec<_>>(),
                        )?;
                } else {
                    #[cfg(feature = "test-support")]
                    run_transaction_seam(&BEFORE_ROLLBACK_ENGINE_APPLY)?;
                    self.gotatun
                        .as_ref()
                        .ok_or(io::ErrorKind::NotConnected)?
                        .apply(old.clone())?;
                    // The engine has the accepted peers again, so their addresses mean what the
                    // accepted grants say: give the moved peers their grants back.
                    self.restore_gotatun_policy(&BTreeSet::new());
                }
                self.set_mesh_mtu(
                    mesh_mtu.0,
                    mesh_mtu.1.max(crate::mesh_mtu::IPV6_MINIMUM_MTU),
                )?;
                self.install_peer_routes(&restore, false)?;
                let retained: Vec<IpAddr> = [
                    IpAddr::V4(old.addresses.ipv4),
                    IpAddr::V6(old.addresses.ipv6),
                ]
                .into_iter()
                .chain(
                    restore
                        .iter()
                        .flat_map(crate::dataplane::Peer::routed_addresses),
                )
                .collect();
                Device::retain_recorded_routes(&self.routes, &retained)?;
                self.set_mesh_mtu(
                    mesh_mtu.0,
                    mesh_mtu.1.max(crate::mesh_mtu::IPV6_MINIMUM_MTU),
                )?;
                self.firewall.apply(old)?;
            } else {
                if self.engine_kind == EngineKind::Kernel {
                    // A transition without a rollback config has already retired the previous
                    // authority; clear every kernel peer, including keys that were orphaned at
                    // restart and therefore were not in `changed`.
                    self.client
                        .as_mut()
                        .ok_or(io::ErrorKind::NotConnected)?
                        .clear_peers()?;
                } else {
                    let mut empty = config.clone();
                    empty.peers.clear();
                    self.gotatun
                        .as_ref()
                        .ok_or(io::ErrorKind::NotConnected)?
                        .apply(empty)?;
                }
                Device::routes(&[], false)?;
                Device::retain_recorded_routes(&self.routes, &[])?;
            }
            self.set_mesh_mtu(
                mesh_mtu.0,
                mesh_mtu.1.max(crate::mesh_mtu::IPV6_MINIMUM_MTU),
            )?;
            return Err(error);
        }
        if snapshot_base.is_some() {
            self.authority_reset = AuthorityResetState::Stable;
        }
        self.config = Some(config);
        #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
        self.publish_dns(dns_records)?;
        self.connection_cleanup_pending = true;
        self.finish_connection_cleanup()
    }

    /// Publish a precompiled `GotaTun` policy as soon as the engine's peers match it.
    ///
    /// Callers publish before the firewall, routes and disk save, so a narrowed grant is
    /// enforced first; a failed transaction then calls [`Self::restore_gotatun_policy`].
    fn publish_gotatun_policy(&self, policy: Option<crate::packet_filter::PreparedPolicy>) {
        if let (Some(engine), Some(policy)) = (self.gotatun.as_ref(), policy) {
            engine.publish_policy(policy);
        }
    }

    /// Put the accepted config's grants back on the packet path after a failed transaction,
    /// leaving out the `withheld` peers.
    ///
    /// `self.config` is still the accepted config here. When it cannot be compiled again, or
    /// there is none, the filter denies everything rather than keep a half-applied snapshot.
    /// `withheld` holds the accepted peers whose addresses the engine may currently give to
    /// another node (see [`Self::moved_gotatun_peers`]); they are left out in the same atomic
    /// publish, so there is no moment when their old grants match those addresses.
    fn restore_gotatun_policy(&self, withheld: &BTreeSet<crate::policy::model::NodeId>) {
        let Some(engine) = self.gotatun.as_ref() else {
            return;
        };
        let restored = self
            .config
            .as_ref()
            .and_then(|old| {
                crate::gotatun_node::Engine::prepare_policy(old, self.proxy_ingress.clone()).ok()
            })
            .map_or_else(
                crate::packet_filter::PacketFilter::deny_all_policy,
                |policy| policy.without_peers(withheld),
            );
        engine.publish_policy(restored);
    }

    /// The accepted peers that `config` removes or moves to other addresses: once the engine
    /// takes `config`'s peers, another node's packets may arrive from their old addresses, so
    /// their grants must not be on the packet path. Empty without an accepted config or a
    /// `GotaTun` engine.
    fn moved_gotatun_peers(&self, config: &Config) -> BTreeSet<crate::policy::model::NodeId> {
        let (Some(_), Some(old)) = (self.gotatun.as_ref(), self.config.as_ref()) else {
            return BTreeSet::new();
        };
        old.peers
            .iter()
            .filter(|(node, previous)| {
                config
                    .peers
                    .get(node)
                    .is_none_or(|next| next.peer.addresses != previous.peer.addresses)
            })
            .map(|(node, _)| *node)
            .collect()
    }

    /// What the host resolver integration did, for `mesh status`.
    pub fn dns_state(&self) -> serde_json::Value {
        #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
        {
            serde_json::json!(self.dns_integration.state())
        }
        #[cfg(not(all(feature = "mesh-dns", target_os = "linux")))]
        {
            serde_json::Value::Null
        }
    }

    #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
    /// Binds the DNS sockets after the mesh address exists and before names are published.
    fn ensure_dns_resolver(&mut self, address: std::net::Ipv4Addr) -> io::Result<()> {
        match &self.dns_resolver {
            Some(resolver) if resolver.address() == address => Ok(()),
            Some(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "mesh DNS address changes require resolver replacement",
            )),
            None => {
                let resolver = if let Some(config) = &self.config {
                    crate::dns::Resolver::bind_for_node(config)?
                } else {
                    crate::dns::Resolver::bind_empty_for_node(address)?
                };
                if resolver.address() != address {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "mesh DNS address changes require resolver replacement",
                    ));
                }
                self.dns_resolver = Some(resolver);
                Ok(())
            }
        }
    }

    #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
    /// Routes the accepted suffixes through the host resolver, then swaps in their names.
    fn publish_dns(&mut self, records: crate::dns::Records) -> io::Result<()> {
        let resolver = self
            .dns_resolver
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?;
        if let Err(error) = self.dns_integration.configure(
            crate::wireguard::INTERFACE,
            &records,
            nix::unistd::Uid::effective().as_raw(),
        ) {
            tracing::warn!("mesh DNS host resolver integration could not be updated: {error}");
        }
        resolver.publish(records);
        Ok(())
    }
    fn finish_connection_cleanup(&mut self) -> io::Result<()> {
        if self.connection_cleanup_pending {
            // Public intent and the final rules have committed. Never roll
            // back access after irreversible retirement begins. A failed
            // cleanup is retried before replay can acknowledge this revision.
            self.firewall
                .complete(self.config.as_ref().ok_or(io::ErrorKind::NotConnected)?)?;
            self.connection_cleanup_pending = false;
        }
        Ok(())
    }
}

/// Restore one kernel peer after its loopback relay shim closes.
#[cfg(all(feature = "relay", target_os = "linux"))]
fn restore_kernel_peer(peer: &crate::dataplane::Peer) -> io::Result<()> {
    if peer.endpoint.is_some() {
        return crate::relay_path::prepare_kernel_handshake(peer);
    }
    let mut client = crate::wireguard::Client::new()?;
    client.peers(&[], &[peer.key])?;
    client.peers(std::slice::from_ref(peer), &[])
}
// No Drop cleanup: kernel state and established flows survive control process loss [166].

/// Require a stable fingerprint before a remote host can start or publish its Mesh binding.
fn require_enrolment_machine(machine: Option<[u8; 32]>) -> io::Result<[u8; 32]> {
    machine.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            MachineBindingError::MissingId,
        )
    })
}

/// Report which kernel objects could not be proven to belong to the previous enrollment.
fn unproven_enrolment_retirement(left: &[&'static str]) -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "Mesh enrollment changed; could not retire kernel state with unproven ownership: {}",
            left.join(", ")
        ),
    )
}

/// The kernel objects host uninstall removes, decided before any is deleted (#235).
pub struct Retirement {
    interface: bool,
    interface_index: Option<u32>,
    filter: Option<Firewall>,
    left: Vec<&'static str>,
    /// This installation's state; its `GotaTun` private key file goes last.
    store: Option<crate::node_state::Store>,
}
impl Retirement {
    /// Objects with our name that this installation did not create; they stay.
    #[must_use]
    pub fn left(&self) -> &[&'static str] {
        &self.left
    }
    /// Delete exactly the planned objects and return the names left in place.
    /// # Errors
    /// Reports a failed kernel deletion.
    pub fn execute(mut self) -> io::Result<Vec<&'static str>> {
        if self.interface {
            Device::delete_ifindex(self.interface_index.ok_or(io::ErrorKind::InvalidData)?)?;
        }
        // As in `down`: the deleted link freed the shared name, so recheck before removing the
        // shared table (#260 J143 P3-4).
        if let Some(mut filter) = self.filter.take() {
            match Device::active_link() {
                Ok(None) => filter.remove()?,
                Ok(Some(_)) => self.left.push(filter.name()),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    self.left.push(filter.name());
                }
                Err(error) => return Err(error),
            }
        }
        // This installation's key and journal are ours, whoever holds the interface now. Retire
        // both after the engine is gone; uninstall must not leave a completed marker that can
        // recreate the key (#260 J143 P3-3, #367).
        if let Some(store) = &self.store {
            store.discard_rotation_state()?;
            store.remove_private_key()?;
        }
        Ok(self.left)
    }
}
/// Node lifecycle, retirement and rotation checks that need no kernel.
#[cfg(test)]
#[path = "node_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "node_rotation_tests.rs"]
mod rotation_tests;

/// Namespace proofs that a `GotaTun` node opens and closes its host listener without any
/// firewall tool (#483, D384, D386).
#[cfg(test)]
#[path = "node_host_listener_tests.rs"]
mod host_listener_tests;

/// Root-only measurement of live traffic across a same-content coordinator restart (#382 P2-c).
#[cfg(test)]
#[path = "node_restart_continuity_bench.rs"]
mod restart_continuity_bench;

/// Namespace proofs that incremental snapshot apply equals a full apply, also across a SIGKILL
/// mid-apply (#260 J1240).
#[cfg(all(test, feature = "test-support"))]
#[path = "node_incremental_apply_tests.rs"]
mod incremental_apply_tests;

/// Namespace regressions for periodic route recovery and its idle measurement (#483).
#[cfg(test)]
#[path = "node_route_repair_tests.rs"]
mod route_repair_tests;

/// Live-endpoint route refresh: learned endpoints, the proven link, relay fallback and refresh
/// cost (#489).
#[cfg(test)]
#[path = "node_live_route_tests.rs"]
mod live_route_tests;

/// Stops or fails a Linux `GotaTun` start after each step and checks that the next one works.
#[cfg(test)]
#[path = "node_startup_crash_tests.rs"]
pub(crate) mod startup_crash_tests;
