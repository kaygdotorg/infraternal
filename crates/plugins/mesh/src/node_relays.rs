//! The node's relay manager: the relay role it may serve and the relay paths its pairs use (D401).
//!
//! It is a child of `node_actions` so it can reach the node through the same owner lock,
//! briefly and never across an `.await`. Two independent parts:
//!
//! - **The relay role** ([`RelayManager::set_list`] with a `serve` part, D401 Q3/Q4): a QUIC
//!   relay on the given UDP port with the relay leaf the coordinator handed over. Admission
//!   is "a host leaf from the deployment CA, not revoked"; every new list re-checks live
//!   connections, and each connection also ends when its leaf expires (`relay::Relay`). A
//!   renewed leaf is swapped in for new handshakes without a restart. The key stays in
//!   memory only: the role lives as long as the coordinator keeps sending it.
//! - **The relay paths** (D401 Q2, D285): one [`RelayPaths`] for the listed relays, keyed by
//!   the relays' names and addresses and the host leaf, started only once a pair needs a relay
//!   (see [`begin_paths`]), so a node whose pairs all go direct holds no relay connection.
//!   After a complete configuration,
//!   every peer this node may exchange packets with gets one deadline [`GRACE`] after its
//!   configuration was installed. A pair with no `WireGuard` handshake since then is relayed
//!   ([`relay_path::direct_failed`]) and records why. This is the slice-1 backstop: the
//!   hard-NAT prediction (D401 Q6) and fast failover (Q7) build on it.
//!
//! Idle cost (D81): no timer runs for a pair after its one deadline, and no relay connection
//! exists until a pair is relayed; from then on the relay paths keep one QUIC connection per
//! listed relay with its keep-alive (see `tls::KEEP_ALIVE`).

use super::Owner;
use crate::{
    dataplane::{Config, Peer},
    policy::model::NodeId,
    relay_list::{RelayEntry, RelayList},
    relay_path::{self, EndpointUpdater, Event, RelayPaths, RelaySpec, RouteMtuUpdater},
};
use infraternal_plugin_relay::{
    relay::{Admission, Limits, Relay},
    tls::Credentials,
    wire::HostId,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::{Duration, SystemTime},
};

/// How long a pair may go without a handshake after its configuration was installed before
/// it is relayed: one `WireGuard` handshake attempt (5 s) plus a margin for the first retry.
pub const GRACE: Duration = Duration::from_millis(5_500);

/// The enrolled host leaf a node presents to relays, as DER.
pub struct HostLeaf {
    /// The host leaf certificate.
    pub certificate: Vec<u8>,
    /// Its PKCS#8 private key; wiped when dropped.
    pub key: zeroize::Zeroizing<Vec<u8>>,
    /// The deployment CA certificates relay leaves must chain to.
    pub roots: Vec<Vec<u8>>,
}

impl HostLeaf {
    /// The relay client's credentials for this leaf.
    fn credentials(self) -> Credentials {
        Credentials::from_der(self.certificate, self.key.to_vec(), self.roots)
    }
}

/// Where the node gets the host leaf it presents to relays: read fresh each time the paths
/// start, so a renewed host leaf is used from the next start on.
pub type CredentialSource = Arc<dyn Fn() -> io::Result<HostLeaf> + Send + Sync>;

/// The host leaf source the enrolled agent set, if any.
static CREDENTIALS: OnceLock<CredentialSource> = OnceLock::new();

/// Give this process's mesh node its host leaf for relay connections (the enrolled
/// infraternal agent does this at start). A node without it serves the relay role at most.
pub fn set_credentials(source: CredentialSource) {
    let _ = CREDENTIALS.set(source);
}

/// Namespace proofs run unenrolled `agent --fd 3` nodes, which have no host leaf. A build
/// with `test-support` (never shipped) reads one from the PEM files the proof names in
/// `INFRATERNAL_TEST_RELAY_HOST_LEAF` (certificate then key) and `INFRATERNAL_TEST_RELAY_CA`.
#[cfg(feature = "test-support")]
fn test_credentials() -> Option<CredentialSource> {
    let leaf = std::env::var_os("INFRATERNAL_TEST_RELAY_HOST_LEAF")?;
    let ca = std::env::var_os("INFRATERNAL_TEST_RELAY_CA")?;
    Some(Arc::new(move || {
        let leaf = std::fs::read(&leaf)?;
        let ca = std::fs::read(&ca)?;
        let refused = || io::Error::from(io::ErrorKind::InvalidData);
        let certificate = openssl::x509::X509::from_pem(&leaf).map_err(|_| refused())?;
        let key = openssl::pkey::PKey::private_key_from_pem(&leaf).map_err(|_| refused())?;
        let root = openssl::x509::X509::from_pem(&ca).map_err(|_| refused())?;
        Ok(HostLeaf {
            certificate: certificate.to_der().map_err(|_| refused())?,
            key: zeroize::Zeroizing::new(key.private_key_to_pkcs8().map_err(|_| refused())?),
            roots: vec![root.to_der().map_err(|_| refused())?],
        })
    }))
}

/// Shipping builds have no test host leaf.
#[cfg(not(feature = "test-support"))]
fn test_credentials() -> Option<CredentialSource> {
    None
}

/// Why a pair is relayed, for `mesh peers`, `relay status` and the logs (D285).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// No `WireGuard` handshake within [`GRACE`] of installing the peer.
    NoHandshake,
}

impl Reason {
    /// The plain sentence shown after "because".
    #[must_use]
    pub fn sentence(self) -> &'static str {
        match self {
            Self::NoHandshake => "no direct handshake within 5 seconds",
        }
    }
}

/// What the manager knows about one peer.
#[derive(Clone)]
struct Pair {
    /// The peer as its configuration was installed (endpoint, keys).
    peer: Peer,
    /// When that configuration was installed; a later handshake proves the direct path.
    installed: SystemTime,
    /// Set once the pair is relayed, with the reason.
    relayed: Option<Reason>,
    /// Bumped on every reinstall, so a stale deadline task does nothing.
    generation: u64,
}

/// The running relay role.
struct Role {
    relay: Relay,
    revoked: Arc<RwLock<HashSet<HostId>>>,
    name: String,
    port: u16,
    leaf: String,
    roots: Vec<String>,
}

/// The running relay paths and what they were started for.
struct Paths {
    running: Arc<RelayPaths>,
    relays: Vec<RelayEntry>,
    specs: Vec<RelaySpec>,
}

/// Everything behind the manager's one lock (never held across an `.await`).
#[derive(Default)]
struct State {
    relays: Vec<RelayEntry>,
    role: Option<Role>,
    paths: Option<Paths>,
    /// The relay each relayed pair uses now, by pair label, from the paths' events.
    active: HashMap<HostId, Option<usize>>,
    pairs: BTreeMap<NodeId, Pair>,
    generation: u64,
    /// The relay list changed; the next start replaces the paths.
    starting: bool,
    /// Bumped by every start; a start that finishes after a newer one began closes its own.
    paths_generation: u64,
    /// A first start is running, so pairs failing at the same deadline start it only once.
    paths_starting: Option<u64>,
}

/// Clears [`State::paths_starting`] when a start ends, whichever way it ends.
struct Starting {
    state: Arc<Mutex<State>>,
    generation: u64,
}

impl Drop for Starting {
    fn drop(&mut self) {
        let mut state = lock(&self.state);
        if state.paths_starting == Some(self.generation) {
            state.paths_starting = None;
        }
    }
}

/// The node's relay role and relay paths.
pub(super) struct RelayManager {
    owner: Arc<Mutex<Owner>>,
    state: Arc<Mutex<State>>,
    /// The relay's own runtime, made on first use: plugin actions run outside any runtime,
    /// and relayed packets should not share the agent's event loop. Its two worker threads
    /// park when nothing is relayed, so an idle node pays no wakeups (D81); a node with no
    /// relays and no role never creates it.
    runtime: OnceLock<tokio::runtime::Runtime>,
}

impl Drop for RelayManager {
    fn drop(&mut self) {
        // Dropping a runtime from inside another one panics; let it wind down on its own.
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// Lock a mutex, taking the data of a poisoned one (no invariant spans a panic here).
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The stable label a pair uses in [`RelayPaths`]: the peer's coordinator node id in the
/// last eight bytes. Labels never leave this node (the relay sees only pair tokens).
fn label(node: NodeId) -> HostId {
    let mut bytes = [0; 16];
    bytes[8..].copy_from_slice(&node.0.to_be_bytes());
    HostId(bytes)
}

/// The key the peer's sessions use now: the previous one while an overlap still routes on it.
fn active_key(peer: &Peer) -> crate::policy::model::PublicKey {
    match (peer.previous_active, peer.previous_key) {
        (true, Some(previous)) => previous,
        _ => peer.key,
    }
}

/// Hands the relay paths the node's engine callbacks, taking the owner lock only for the
/// moment each callback is built.
struct OwnerUpdater(Arc<Mutex<Owner>>);

impl OwnerUpdater {
    /// Run `run` on the restored node under the owner lock, briefly.
    fn with_node<T>(&self, run: impl FnOnce(&crate::node::Node) -> io::Result<T>) -> io::Result<T> {
        let mut owner = lock(&self.0);
        let node = owner
            .node()
            .map_err(|_| io::Error::from(io::ErrorKind::NotConnected))?;
        run(node)
    }
}

impl EndpointUpdater for OwnerUpdater {
    fn handshake_preparer(
        &self,
        peer: &Peer,
    ) -> io::Result<Arc<dyn Fn() -> io::Result<()> + Send + Sync>> {
        self.with_node(|node| node.relay_handshake_preparer(peer))
    }

    fn handshake_starter(&self, peer: &Peer) -> io::Result<Arc<dyn Fn() + Send + Sync>> {
        self.with_node(|node| node.relay_handshake_starter(peer))
    }

    fn route_mtu_updater(&self, peer: &Peer) -> RouteMtuUpdater {
        match self.with_node(|node| Ok(node.relay_route_mtu_updater(peer))) {
            Ok(updater) => updater,
            // A stopped node has no route to update; a later reinstall builds a new one.
            Err(_) => Arc::new(|_| Ok(())),
        }
    }

    fn restorer(&self, peer: &Peer) -> io::Result<Arc<dyn Fn() -> io::Result<()> + Send + Sync>> {
        let owner = self.0.clone();
        let key = peer.key;
        Ok(Arc::new(move || {
            OwnerUpdater(owner.clone()).with_node(|node| node.restore_relay_endpoint(key))
        }))
    }
}

impl RelayManager {
    /// A manager for `owner`'s node that starts from the relay list saved last (D285).
    pub(super) fn new(owner: Arc<Mutex<Owner>>, saved: &RelayList) -> Self {
        let state = State {
            relays: saved.relays.clone(),
            ..State::default()
        };
        Self {
            owner,
            state: Arc::new(Mutex::new(state)),
            runtime: OnceLock::new(),
        }
    }

    /// The relay runtime's handle, creating the runtime on first use.
    fn handle(&self) -> Option<tokio::runtime::Handle> {
        if let Some(runtime) = self.runtime.get() {
            return Some(runtime.handle().clone());
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("infraternal-relay")
            .enable_all()
            .build()
            .inspect_err(|error| tracing::warn!(%error, "relay: no runtime"))
            .ok()?;
        let handle = runtime.handle().clone();
        if let Err(runtime) = self.runtime.set(runtime) {
            runtime.shutdown_background();
        }
        Some(handle)
    }

    /// Run `future` on the relay runtime.
    fn spawn(&self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        if let Some(handle) = self.handle() {
            handle.spawn(future);
        }
    }

    /// Take a new list from the coordinator: run, renew or stop the relay role, and restart the
    /// relay paths when the relays changed. Returns the UDP port the relay role serves on.
    pub(super) fn set_list(&self, list: &RelayList) -> (bool, Option<u16>) {
        let (accepted, serving) = self.set_role(list);
        let mut state = lock(&self.state);
        // Pairs installed while no relay was listed had no deadline; they get one now.
        let first_relays = state.relays.is_empty() && !list.relays.is_empty();
        if state.relays != list.relays {
            state.relays.clone_from(&list.relays);
            state.starting = true;
            if list.relays.is_empty() {
                for pair in state.pairs.values_mut() {
                    pair.relayed = None;
                }
                state.active.clear();
            }
        }
        let pending: Vec<(NodeId, u64, Duration)> = if first_relays {
            let now = SystemTime::now();
            state
                .pairs
                .iter()
                .filter(|(_, pair)| pair.relayed.is_none())
                .map(|(node, pair)| {
                    let waited = now.duration_since(pair.installed).unwrap_or_default();
                    (*node, pair.generation, GRACE.saturating_sub(waited))
                })
                .collect()
        } else {
            Vec::new()
        };
        drop(state);
        self.start_paths();
        for (node, generation, wait) in pending {
            self.deadline(node, generation, wait);
        }
        (accepted, serving)
    }

    /// Stop pair paths after the node removes its mesh interface and private key.
    pub(super) fn mesh_down(&self) {
        let paths = {
            let mut state = lock(&self.state);
            state.paths_generation = state.paths_generation.wrapping_add(1);
            state.paths_starting = None;
            state.starting = false;
            state.pairs.clear();
            state.active.clear();
            state.paths.take().map(|paths| paths.running)
        };
        if let Some(paths) = paths {
            self.spawn(async move { paths.shutdown(false).await });
        }
    }

    /// Rebuild pair tokens from the node's newly committed mesh identity.
    pub(super) fn identity_changed(&self) {
        {
            let mut state = lock(&self.state);
            if state.paths.is_some() {
                state.starting = true;
                state.active.clear();
            } else if state.paths_starting.is_some() {
                // Invalidate a start that may already have read the previous host identity.
                state.paths_generation = state.paths_generation.wrapping_add(1);
                state.paths_starting = None;
            }
        }
        self.start_paths();
    }

    /// Judge `node` once, `wait` from now (D81: one timer per installed peer, never repeated).
    fn deadline(&self, node: NodeId, generation: u64, wait: Duration) {
        let owner = self.owner.clone();
        let state = self.state.clone();
        self.spawn(async move {
            // sleep: this pair's one deadline.
            tokio::time::sleep(wait).await;
            judge(&owner, &state, node, generation, false).await;
        });
    }

    /// Run the relay role `list.serve` asks for, if any, and return its bound port.
    fn set_role(&self, list: &RelayList) -> (bool, Option<u16>) {
        let Some(serve) = &list.serve else {
            if let Some(role) = lock(&self.state).role.take() {
                self.spawn(role.relay.close());
            }
            return (true, None);
        };
        let revoked: HashSet<HostId> = serve
            .revoked
            .iter()
            .filter_map(|host| HostId::parse(host))
            .collect();
        let mut state = lock(&self.state);
        if let Some(role) = state.role.as_mut()
            && role.name == serve.name
            && role.port == serve.port
        {
            let mut accepted = true;
            if role.leaf != serve.leaf || role.roots != serve.roots {
                // A renewed leaf or CA set: new handshakes get it, open connections keep theirs.
                let renewed = Credentials::from_pem(&serve.leaf, &serve.roots)
                    .and_then(|credentials| role.relay.set_credentials(credentials));
                if renewed.is_ok() {
                    role.leaf.clone_from(&serve.leaf);
                    role.roots.clone_from(&serve.roots);
                } else {
                    accepted = false;
                    tracing::warn!("relay: a renewed relay leaf was refused; keeping the old one");
                }
            }
            *role
                .revoked
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = revoked;
            role.relay.recheck();
            return (
                accepted,
                role.relay.local_addr().ok().map(|address| address.port()),
            );
        }
        if let Some(old) = state.role.take() {
            self.spawn(old.relay.close());
        }
        let Ok(credentials) = Credentials::from_pem(&serve.leaf, &serve.roots) else {
            tracing::warn!("relay: the relay leaf was refused; not serving");
            return (false, None);
        };
        let revoked = Arc::new(RwLock::new(revoked));
        let admission: Admission = {
            let revoked = revoked.clone();
            Arc::new(move |host| {
                !revoked
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(&host)
            })
        };
        let Some(runtime) = self.handle() else {
            tracing::warn!("relay: no runtime; not serving");
            return (false, None);
        };
        let _entered = runtime.enter();
        let listen = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), serve.port);
        match Relay::start(listen, credentials, Limits::default(), admission) {
            Ok(relay) => {
                let port = relay.local_addr().ok().map(|address| address.port());
                tracing::info!(port = ?port, name = %serve.name, "relay: serving");
                state.role = Some(Role {
                    relay,
                    revoked,
                    name: serve.name.clone(),
                    port: serve.port,
                    leaf: serve.leaf.clone(),
                    roots: serve.roots.clone(),
                });
                (true, port)
            }
            Err(error) => {
                tracing::warn!(port = serve.port, %error, "relay: could not bind the relay port");
                (true, None)
            }
        }
    }

    /// Start (or replace) the relay paths in the background, when they are needed: names
    /// resolve and the host leaf is read there, never under the plugin lock.
    fn start_paths(&self) {
        if let Some(start) = begin_paths(&self.state) {
            self.spawn(run_paths(self.owner.clone(), self.state.clone(), start));
        }
    }

    /// Whether any relay is listed, so a configuration needs relay deadlines at all.
    pub(super) fn has_relays(&self) -> bool {
        !lock(&self.state).relays.is_empty()
    }

    /// A complete configuration was accepted: release removed peers and give every new or
    /// changed peer its one relay deadline.
    ///
    /// `started` is when the chunk that completed it began to apply, so a handshake made
    /// while it applied counts as proof of the direct path; `counters` are the engine's
    /// counters read then. What counts as changed: for a relayed pair only its keys (they
    /// name its pair tokens), so the candidates and endpoint the coordinator republishes
    /// whenever it sees a NAT mapping move do not drop a working relay. For any other pair a
    /// change restarts its deadline unless it still has a live session (an idle direct pair
    /// shows no new handshake for up to two minutes, which is no failure). A node with no
    /// relay listed sets no deadline at all.
    pub(super) fn configured(
        &self,
        config: Option<&Config>,
        started: SystemTime,
        counters: Option<&EngineCounters>,
    ) {
        let Some(config) = config else {
            return;
        };
        let now = started;
        let current = SystemTime::now();
        let mut due = Vec::new();
        let mut released = Vec::new();
        let relays_listed;
        {
            let mut state = lock(&self.state);
            relays_listed = !state.relays.is_empty();
            let peers: BTreeMap<NodeId, &Peer> = config
                .peers
                .iter()
                .filter(|(_, policy)| policy.has_network_access())
                .map(|(node, policy)| (*node, &policy.peer))
                .collect();
            state.pairs.retain(|node, pair| {
                let Some(peer) = peers.get(node) else {
                    // A judge may have inserted its shim but not marked this pair relayed yet.
                    released.push(*node);
                    return false;
                };
                let same_keys = peer.key == pair.peer.key
                    && peer.previous_key == pair.peer.previous_key
                    && peer.previous_active == pair.peer.previous_active;
                let keep = if pair.relayed.is_some() {
                    same_keys
                } else {
                    **peer == pair.peer
                        || same_keys
                            && live_session(
                                counters.and_then(|counters| counters.get(&active_key(peer))),
                                current,
                            )
                };
                if keep {
                    pair.peer = (*peer).clone();
                } else {
                    // Also retire a shim created by a judge that is still awaiting its relay.
                    released.push(*node);
                }
                keep
            });
            for (node, peer) in peers {
                if state.pairs.contains_key(&node) {
                    continue;
                }
                state.generation += 1;
                let generation = state.generation;
                state.pairs.insert(
                    node,
                    Pair {
                        peer: peer.clone(),
                        installed: now,
                        relayed: None,
                        generation,
                    },
                );
                due.push((node, generation));
            }
        }
        let paths = lock(&self.state)
            .paths
            .as_ref()
            .map(|paths| paths.running.clone());
        if let Some(paths) = paths {
            for node in released {
                let paths = paths.clone();
                self.spawn(async move { paths.release(label(node)).await });
            }
        }
        if !relays_listed {
            return;
        }
        for (node, generation) in due {
            self.deadline(node, generation, GRACE);
        }
    }

    /// The relays this node knows, the role it serves and its relayed pairs, for
    /// `mesh.status` and `relay status`.
    pub(super) fn status(&self) -> serde_json::Value {
        let state = lock(&self.state);
        let names: Vec<&str> = state
            .paths
            .as_ref()
            .map(|paths| {
                paths
                    .relays
                    .iter()
                    .map(|relay| relay.name.as_str())
                    .collect()
            })
            .unwrap_or_default();
        let relayed: Vec<serde_json::Value> = state
            .pairs
            .iter()
            .filter_map(|(node, pair)| {
                let reason = pair.relayed?;
                let via = state
                    .active
                    .get(&label(*node))
                    .copied()
                    .flatten()
                    .and_then(|index| names.get(index).copied());
                Some(serde_json::json!({
                    "node": node.0,
                    "via": via,
                    "because": reason.sentence(),
                }))
            })
            .collect();
        serde_json::json!({
            "relays": state.relays.iter().map(|relay| serde_json::json!({
                "name": relay.name,
                "port": relay.port,
                "connected": state.paths.as_ref().is_some_and(|paths| {
                    paths.specs.iter().any(|spec| spec.name == relay.name)
                }),
            })).collect::<Vec<_>>(),
            "serving": state.role.as_ref().map(|role| serde_json::json!({
                "name": role.name,
                "port": role.relay.local_addr().ok().map(|address| address.port()),
                "hosts": role.relay.stats().hosts,
                "links": role.relay.stats().links,
                // Counters only, never per-pair records (D401 Q8).
                "forwarded": role.relay.stats().forwarded,
                "dropped": role.relay.stats().dropped,
            })),
            "relayed": relayed,
            // Data-path counters of the relay paths, while they run: what went through a relay,
            // and what could not (no link yet, or too large for the relay's DATAGRAM size).
            "paths": state.paths.as_ref().map(|paths| {
                let carried = paths.running.stats();
                serde_json::json!({
                    "sent": carried.sent,
                    "received": carried.received,
                    "unlinked": carried.unlinked,
                    "too_large": carried.too_large,
                })
            }),
        })
    }
}

/// How long a `WireGuard` session stays usable after its handshake (`REJECT_AFTER_TIME`). A
/// changed pair whose session is younger than this still has its direct path.
const SESSION: Duration = Duration::from_secs(180);

/// The engine's per-peer counters, by the key the peer's sessions use.
pub(super) type EngineCounters =
    BTreeMap<crate::policy::model::PublicKey, crate::wireguard::Counters>;

/// Whether `counters` show a session with the peer younger than [`SESSION`] at `now`.
fn live_session(counters: Option<&crate::wireguard::Counters>, now: SystemTime) -> bool {
    counters
        .filter(|counters| counters.handshake_secs != 0)
        .and_then(|counters| {
            std::time::UNIX_EPOCH.checked_add(Duration::from_secs(counters.handshake_secs))
        })
        .and_then(|handshake| now.duration_since(handshake).ok())
        .is_some_and(|age| age < SESSION)
}

/// What one start of the relay paths runs with.
struct PathsStart {
    relays: Vec<RelayEntry>,
    generation: u64,
    credentials: CredentialSource,
}

/// Whether the relay paths should start now, and with what.
///
/// They start only once some pair needs a relay (a pair marked relayed), and are replaced
/// when the list changed while they run. A node whose pairs all go direct never connects to
/// a relay, so it pays no keep-alive wakeups (D81); the first relayed pair waits one QUIC
/// handshake more after its 5.5 s deadline. The slow-keep-alive home relay (D401 Q5) replaces
/// this in slice 1b.
fn begin_paths(state: &Arc<Mutex<State>>) -> Option<PathsStart> {
    let credentials = CREDENTIALS.get().cloned().or_else(test_credentials)?;
    let mut state = lock(state);
    let wanted = state.pairs.values().any(|pair| pair.relayed.is_some());
    let replace = std::mem::take(&mut state.starting) && state.paths.is_some();
    let first = state.paths.is_none()
        && state.paths_starting.is_none()
        && wanted
        && !state.relays.is_empty();
    if !replace && !first {
        return None;
    }
    state.paths_generation += 1;
    let generation = state.paths_generation;
    state.paths_starting = Some(generation);
    Some(PathsStart {
        relays: state.relays.clone(),
        generation,
        credentials,
    })
}

/// Start the relay paths now if [`begin_paths`] says so, from inside a relay task. A plain
/// function on purpose: `run_paths` spawns `judge`, and `judge` calling `run_paths` directly
/// would make the two futures contain each other's types.
fn start_paths_now(owner: Arc<Mutex<Owner>>, state: Arc<Mutex<State>>) {
    if let Some(start) = begin_paths(&state) {
        spawn(run_paths(owner, state, start));
    }
}

/// Start the relay paths for `start.relays`, replacing running ones, then move every pair
/// that wants a relay onto them.
async fn run_paths(owner: Arc<Mutex<Owner>>, state: Arc<Mutex<State>>, start: PathsStart) {
    let PathsStart {
        relays,
        generation,
        credentials,
    } = start;
    let _starting = Starting {
        state: state.clone(),
        generation,
    };
    let old = lock(&state).paths.take();
    if let Some(old) = old {
        old.running.shutdown(relays.is_empty()).await;
    }
    if relays.is_empty() {
        return;
    }
    let specs = resolve(&relays).await;
    if specs.is_empty() {
        tracing::warn!("relay: no listed relay resolved to an IPv4 address");
        return;
    }
    let started = {
        let mut owner = lock(&owner);
        let Ok(node) = owner.node() else {
            return;
        };
        let (Ok(secret), Some(port)) = (node.relay_pair_secret(), node.listen_port()) else {
            return;
        };
        let probes = node.direct_probes();
        let (events, queue) = tokio::sync::mpsc::channel(256);
        let source = credentials.clone();
        let client_config = move || {
            source()
                .map(HostLeaf::credentials)
                .and_then(infraternal_plugin_relay::tls::client_config)
        };
        RelayPaths::start_with_config_source(secret, port, specs.clone(), client_config, events)
            .map(|paths| match probes {
                Some((probes, Some(answers))) => paths.with_direct_probes(probes, answers),
                _ => paths,
            })
            .map(|paths| (paths, queue))
    };
    let Ok((paths, mut queue)) = started else {
        tracing::warn!("relay: the relay paths could not start");
        return;
    };
    // A newer start began meanwhile: it owns the paths, so these close again.
    let superseded = lock(&state).paths_generation != generation;
    if superseded {
        paths.close().await;
        return;
    }
    let rejudge: Vec<(NodeId, u64)> = {
        let mut locked = lock(&state);
        locked.paths = Some(Paths {
            running: Arc::new(paths),
            relays,
            specs,
        });
        // Existing deadline tasks remain the sole owner of unrelayed pairs. Only pairs that
        // already failed a direct-path check need an immediate judge on the replacement paths.
        take_rejudges(&mut locked)
    };
    for (node, pair_generation) in rejudge {
        let owner = owner.clone();
        let state = state.clone();
        spawn(async move {
            judge(&owner, &state, node, pair_generation, true).await;
        });
    }
    let events_state = state.clone();
    spawn(async move {
        while let Some(event) = queue.recv().await {
            if let Event::Active { peer, relay } = event {
                lock(&events_state).active.insert(peer, relay);
            }
        }
    });
}

/// Resolve each listed relay to its first IPv4 address (the relay path is IPv4-only).
async fn resolve(relays: &[RelayEntry]) -> Vec<RelaySpec> {
    let mut specs = Vec::with_capacity(relays.len());
    for relay in relays {
        let listed = relay
            .addresses
            .iter()
            .find(|address| address.is_ipv4())
            .map(|address| SocketAddr::new(*address, relay.port));
        let address = match listed {
            Some(address) => Some(address),
            None => tokio::net::lookup_host((relay.name.as_str(), relay.port))
                .await
                .ok()
                .and_then(|mut found| found.find(SocketAddr::is_ipv4)),
        };
        if let Some(address) = address {
            specs.push(RelaySpec {
                address,
                name: relay.name.clone(),
            });
        }
    }
    specs
}

/// The deadline of one installed peer: relay it if it has had no handshake since then, or
/// at once when `relayed` (it was relayed before and its paths were replaced).
async fn judge(
    owner: &Arc<Mutex<Owner>>,
    state: &Arc<Mutex<State>>,
    node: NodeId,
    generation: u64,
    relayed: bool,
) {
    let (pair, paths) = {
        let state = lock(state);
        let Some(pair) = state
            .pairs
            .get(&node)
            .filter(|pair| pair.generation == generation)
        else {
            return;
        };
        if pair.relayed.is_some() {
            return;
        }
        (
            pair.clone(),
            state.paths.as_ref().map(|paths| paths.running.clone()),
        )
    };
    let failed = relayed || {
        let mut owner = lock(owner);
        let Ok(node) = owner.node() else {
            return;
        };
        let Ok(counters) = node.counters() else {
            return;
        };
        relay_path::direct_failed(counters.get(&active_key(&pair.peer)), pair.installed)
    };
    if !failed {
        return;
    }
    let Some(paths) = paths else {
        // No relay connection yet: this pair is the first that needs one. Mark it, start the
        // paths, and they relay it as soon as they run (see `run_paths`).
        if let Some(entry) = lock(state)
            .pairs
            .get_mut(&node)
            .filter(|entry| entry.generation == generation)
        {
            entry.relayed = Some(Reason::NoHandshake);
        }
        start_paths_now(owner.clone(), state.clone());
        return;
    };
    let mut updater = OwnerUpdater(owner.clone());
    match paths
        .relay_with_endpoint(&mut updater, label(node), &pair.peer)
        .await
    {
        Ok(endpoint) => {
            if !mark_relayed_if_current(&paths, state, node, generation, endpoint).await {
                return;
            }
            tracing::info!(
                peer = node.0,
                because = Reason::NoHandshake.sentence(),
                "relay: pair relayed"
            );
        }
        Err(error) => tracing::warn!(peer = node.0, %error, "relay: could not relay the pair"),
    }
}

/// Take only already-failed pairs when relay paths are replaced; their original deadline tasks
/// remain the only timers for every pair that has not failed yet.
fn take_rejudges(state: &mut State) -> Vec<(NodeId, u64)> {
    state
        .pairs
        .iter_mut()
        .filter_map(|(node, pair)| pair.relayed.take().map(|_| (*node, pair.generation)))
        .collect()
}

/// Record a completed relay setup, or remove its shim if configuration replaced that pair while
/// the async setup was in flight.
async fn mark_relayed_if_current(
    paths: &RelayPaths,
    state: &Arc<Mutex<State>>,
    node: NodeId,
    generation: u64,
    endpoint: SocketAddr,
) -> bool {
    let current = {
        let mut state = lock(state);
        if let Some(pair) = state
            .pairs
            .get_mut(&node)
            .filter(|pair| pair.generation == generation)
        {
            pair.relayed.get_or_insert(Reason::NoHandshake);
            true
        } else {
            false
        }
    };
    if !current {
        paths.release_if(label(node), endpoint).await;
    }
    current
}

/// Run `future` on the runtime of the task calling it (always the relay runtime here).
fn spawn(future: impl std::future::Future<Output = ()> + Send + 'static) {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(future);
    }
}

#[cfg(test)]
mod tests {
    //! Labels and reasons; the role and paths run in the namespace proof and relay tests.
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    /// A pair fixture for manager state transitions that do not need a live data plane.
    pub(super) fn pair(generation: u64, relayed: Option<Reason>) -> Pair {
        Pair {
            peer: Peer {
                key: crate::policy::model::PublicKey([1; 32]),
                previous_key: None,
                previous_active: false,
                addresses: crate::policy::model::Addresses {
                    ipv4: "10.254.0.2".parse().expect("IPv4 fixture"),
                    ipv6: "fd01::2".parse().expect("IPv6 fixture"),
                },
                endpoint: None,
                candidates: Vec::new(),
                ipv4_only: false,
                side_port: false,
            },
            installed: SystemTime::now(),
            relayed,
            generation,
        }
    }

    /// A pair label depends only on the node id, and different nodes get different labels.
    #[test]
    fn labels_are_stable_and_distinct_per_node() {
        assert_eq!(label(NodeId(7)), label(NodeId(7)));
        assert_ne!(label(NodeId(7)), label(NodeId(8)));
        assert_eq!(label(NodeId(1)).0[15], 1);
    }

    /// Replacing paths keeps one deadline task for waiting pairs and rejudges failures only.
    #[test]
    fn replacement_paths_do_not_duplicate_waiting_pair_deadlines() {
        let waiting = NodeId(1);
        let failed = NodeId(2);
        let mut state = State::default();
        state.pairs.insert(waiting, pair(11, None));
        state
            .pairs
            .insert(failed, pair(12, Some(Reason::NoHandshake)));

        assert_eq!(take_rejudges(&mut state), vec![(failed, 12)]);
        assert_eq!(state.pairs[&waiting].relayed, None);
        assert_eq!(state.pairs[&failed].relayed, None);
    }

    /// A session counts as live only while its handshake is younger than 180 s; no handshake,
    /// no counters or a clock before the handshake never count.
    #[test]
    fn a_live_session_is_a_handshake_younger_than_three_minutes() {
        let at = |secs| {
            std::time::UNIX_EPOCH
                .checked_add(Duration::from_secs(secs))
                .unwrap_or(std::time::UNIX_EPOCH)
        };
        let counters = |handshake_secs| crate::wireguard::Counters {
            handshake_secs,
            ..crate::wireguard::Counters::default()
        };
        assert!(live_session(Some(&counters(1_000)), at(1_100)));
        assert!(!live_session(Some(&counters(1_000)), at(1_180)));
        assert!(!live_session(Some(&counters(0)), at(100)));
        assert!(!live_session(None, at(100)));
        assert!(!live_session(Some(&counters(1_000)), at(900)));
    }

    /// The relay reason reads as the end of "because ...".
    #[test]
    fn the_reason_reads_as_a_sentence() {
        assert_eq!(
            Reason::NoHandshake.sentence(),
            "no direct handshake within 5 seconds"
        );
    }

    /// Updating only the CA roots changes which host leaves the live relay accepts.
    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn a_relay_role_reloads_changed_ca_roots() {
        use infraternal_plugin_relay::{
            client::Client,
            testing::{Authority, Purpose},
            tls,
            wire::HostId,
        };

        const NAME: &str = "relay.example.org";
        let mut first_ca = Authority::new();
        let (leaf, key) = first_ca.issue_pem(Purpose::Relay(NAME));
        let first_root = first_ca.pem();
        let mut second_ca = Authority::new();
        let second_root = second_ca.pem();
        let owner = Arc::new(Mutex::new(Owner {
            node: None,
            path: None,
            restore_failed: false,
        }));
        let manager = RelayManager::new(owner, &RelayList::default());
        let mut list = RelayList {
            relays: Vec::new(),
            serve: Some(crate::relay_list::ServeRelay {
                name: NAME.into(),
                port: 0,
                leaf: format!("{leaf}{key}"),
                roots: vec![first_root.clone()],
                revoked: Vec::new(),
            }),
        };
        manager.set_role(&list);
        list.serve.as_mut().unwrap().roots.push(second_root);
        manager.set_role(&list);
        let port = lock(&manager.state)
            .role
            .as_ref()
            .expect("the relay role remains running")
            .relay
            .local_addr()
            .unwrap()
            .port();
        // The role binds all IPv4 interfaces; this isolated client dials the same port on loopback.
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

        let mut host = second_ca.issue(Purpose::Host(HostId([2; 16])));
        host.roots = first_ca.issue(Purpose::Host(HostId([3; 16]))).roots;
        let config = tls::client_config(host).unwrap();
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let (client, _notices) =
            Client::connect(&endpoint, config, address, NAME, Duration::from_secs(5))
                .await
                .expect("the relay accepts a leaf from the newly trusted CA");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let hosts = lock(&manager.state)
                    .role
                    .as_ref()
                    .expect("the relay role remains running")
                    .relay
                    .stats()
                    .hosts;
                if hosts == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the refreshed host registers with the relay");
        client
            .connection()
            .close(quinn::VarInt::from_u32(0), b"test finished");
    }
}

/// Mesh-down path cleanup is tested without starting a `WireGuard` device or relay socket.
#[cfg(test)]
mod mesh_down_review_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    /// The `mesh.down` action clears relay pairs along with the node's mesh interface.
    #[test]
    fn mesh_down_action_clears_pair_state() {
        use infraternal_plugin_api::AgentPlugin;

        let mut plugin =
            crate::node_actions::MeshNodePlugin::from_node(crate::node::Node::default());
        plugin.relays = Some(RelayManager::new(
            plugin.owner.clone(),
            &RelayList::default(),
        ));
        {
            let manager = plugin.relays.as_ref().expect("relay manager");
            let mut state = lock(&manager.state);
            state.pairs.insert(
                NodeId(1),
                Pair {
                    peer: Peer {
                        key: crate::policy::model::PublicKey([1; 32]),
                        previous_key: None,
                        previous_active: false,
                        addresses: crate::policy::model::Addresses {
                            ipv4: "10.254.0.2".parse().expect("IPv4 fixture"),
                            ipv6: "fd01::2".parse().expect("IPv6 fixture"),
                        },
                        endpoint: None,
                        candidates: Vec::new(),
                        ipv4_only: false,
                        side_port: false,
                    },
                    installed: SystemTime::now(),
                    relayed: Some(Reason::NoHandshake),
                    generation: 3,
                },
            );
            state.active.insert(label(NodeId(1)), Some(0));
            state.starting = true;
        }

        plugin.call("mesh.down", b"{}").expect("mesh down action");

        let manager = plugin.relays.as_ref().expect("relay manager");
        let state = lock(&manager.state);
        assert!(state.pairs.is_empty());
        assert!(state.active.is_empty());
        assert!(!state.starting);
    }

    /// Mesh down invalidates a path start that is still using the previous mesh identity.
    #[test]
    fn mesh_down_invalidates_an_inflight_start() {
        let owner = Arc::new(Mutex::new(Owner {
            node: None,
            path: None,
            restore_failed: false,
        }));
        let manager = RelayManager::new(owner, &RelayList::default());
        {
            let mut state = lock(&manager.state);
            state.paths_starting = Some(2);
            state.paths_generation = 2;
            state.starting = true;
        }

        manager.mesh_down();

        let state = lock(&manager.state);
        assert_eq!(state.paths_starting, None);
        assert!(!state.starting);
        assert_eq!(state.paths_generation, 3);
    }

    /// A key commit invalidates startup work that captured the predecessor mesh identity.
    #[test]
    fn identity_change_invalidates_an_inflight_start() {
        let owner = Arc::new(Mutex::new(Owner {
            node: None,
            path: None,
            restore_failed: false,
        }));
        let manager = RelayManager::new(owner, &RelayList::default());
        {
            let mut state = lock(&manager.state);
            state.paths_starting = Some(4);
            state.paths_generation = 4;
        }

        manager.identity_changed();

        let state = lock(&manager.state);
        assert_eq!(state.paths_starting, None);
        assert_eq!(state.paths_generation, 5);
    }
}

/// A removed pair cannot keep the loopback shim after an async relay judgement completes.
#[cfg(all(test, feature = "test-support"))]
mod stale_relay_path_review_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;
    use crate::{dataplane::Peer, relay_path::PairSecret};
    use infraternal_plugin_relay::testing::{Authority, Purpose};
    use tokio::sync::mpsc;

    /// A data-plane adapter whose callbacks succeed without touching a WireGuard device.
    struct TestUpdater;

    impl EndpointUpdater for TestUpdater {
        fn handshake_preparer(
            &self,
            _peer: &Peer,
        ) -> io::Result<Arc<dyn Fn() -> io::Result<()> + Send + Sync>> {
            Ok(Arc::new(|| Ok(())))
        }

        fn handshake_starter(&self, _peer: &Peer) -> io::Result<Arc<dyn Fn() + Send + Sync>> {
            Ok(Arc::new(|| {}))
        }

        fn route_mtu_updater(&self, _peer: &Peer) -> RouteMtuUpdater {
            Arc::new(|_| Ok(()))
        }
    }

    /// Make a relayable peer without opening a `WireGuard` device.
    fn test_peer(key: u8) -> Peer {
        Peer {
            key: PairSecret::from_private(&[key; 32]).unwrap().public(),
            previous_key: None,
            previous_active: false,
            addresses: crate::policy::model::Addresses {
                ipv4: "10.254.0.2".parse().unwrap(),
                ipv6: "fd01::2".parse().unwrap(),
            },
            endpoint: None,
            candidates: Vec::new(),
            ipv4_only: false,
            side_port: false,
        }
    }

    /// Start idle relay paths; the empty relay list sends no network traffic.
    async fn idle_paths(host: HostId) -> Arc<RelayPaths> {
        let mut authority = Authority::new();
        let credentials = authority.issue(Purpose::Host(host));
        let (events, _receiver) = mpsc::channel(16);
        Arc::new(
            RelayPaths::start(
                PairSecret::from_private(&[1; 32]).unwrap(),
                9,
                Vec::new(),
                credentials,
                events,
            )
            .unwrap(),
        )
    }

    /// A pair removed during its relay await releases its now-stale shim and task.
    #[tokio::test]
    async fn stale_relay_judgement_releases_its_shim() {
        let node = NodeId(5);
        let host = label(node);
        let paths = idle_paths(host).await;
        let mut updater = TestUpdater;
        let local = paths
            .relay_with_endpoint(&mut updater, host, &test_peer(3))
            .await
            .unwrap();
        let state = Arc::new(Mutex::new(State::default()));

        assert!(!mark_relayed_if_current(&paths, &state, node, 9, local).await);
        assert!(!paths.has_registered_peer_for_test(host));
        paths.shutdown(false).await;
    }
}
