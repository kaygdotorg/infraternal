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
    paths_starting: bool,
}

/// Clears [`State::paths_starting`] when a start ends, whichever way it ends.
struct Starting(Arc<Mutex<State>>);

impl Drop for Starting {
    fn drop(&mut self) {
        lock(&self.0).paths_starting = false;
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
    pub(super) fn set_list(&self, list: &RelayList) -> Option<u16> {
        let serving = self.set_role(list);
        let mut state = lock(&self.state);
        if state.relays != list.relays {
            state.relays.clone_from(&list.relays);
            state.starting = true;
        }
        drop(state);
        self.start_paths();
        serving
    }

    /// Run the relay role `list.serve` asks for, if any, and return its bound port.
    fn set_role(&self, list: &RelayList) -> Option<u16> {
        let Some(serve) = &list.serve else {
            if let Some(role) = lock(&self.state).role.take() {
                self.spawn(role.relay.close());
            }
            return None;
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
            if role.leaf != serve.leaf {
                // A renewed leaf: new handshakes get it, open connections keep theirs.
                let renewed = Credentials::from_pem(&serve.leaf, &serve.roots)
                    .and_then(|credentials| role.relay.set_credentials(credentials));
                if renewed.is_ok() {
                    role.leaf.clone_from(&serve.leaf);
                } else {
                    tracing::warn!("relay: a renewed relay leaf was refused; keeping the old one");
                }
            }
            *role
                .revoked
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = revoked;
            role.relay.recheck();
            return role.relay.local_addr().ok().map(|address| address.port());
        }
        if let Some(old) = state.role.take() {
            self.spawn(old.relay.close());
        }
        let Ok(credentials) = Credentials::from_pem(&serve.leaf, &serve.roots) else {
            tracing::warn!("relay: the relay leaf was refused; not serving");
            return None;
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
        let runtime = self.handle()?;
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
                });
                port
            }
            Err(error) => {
                tracing::warn!(port = serve.port, %error, "relay: could not bind the relay port");
                None
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

    /// A complete configuration was accepted: release removed peers and give every new or
    /// changed peer its one relay deadline.
    pub(super) fn configured(&self, config: Option<&Config>) {
        let Some(config) = config else {
            return;
        };
        let now = SystemTime::now();
        let mut due = Vec::new();
        let mut released = Vec::new();
        {
            let mut state = lock(&self.state);
            let peers: BTreeMap<NodeId, &Peer> = config
                .peers
                .iter()
                .filter(|(_, policy)| policy.has_network_access())
                .map(|(node, policy)| (*node, &policy.peer))
                .collect();
            state.pairs.retain(|node, pair| {
                let keep = peers.get(node).is_some_and(|peer| **peer == pair.peer);
                if !keep && pair.relayed.is_some() {
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
        for (node, generation) in due {
            let owner = self.owner.clone();
            let state = self.state.clone();
            self.spawn(async move {
                // sleep: the one deadline per installed peer (D81: nothing repeats).
                tokio::time::sleep(GRACE).await;
                judge(&owner, &state, node, generation, false).await;
            });
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
            })),
            "relayed": relayed,
        })
    }
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
    let first =
        state.paths.is_none() && !state.paths_starting && wanted && !state.relays.is_empty();
    if !replace && !first {
        return None;
    }
    state.paths_starting = true;
    state.paths_generation += 1;
    Some(PathsStart {
        relays: state.relays.clone(),
        generation: state.paths_generation,
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
    let _starting = Starting(state.clone());
    let old = lock(&state).paths.take();
    if let Some(old) = old
        && let Ok(old) = Arc::try_unwrap(old.running)
    {
        old.close().await;
    }
    if relays.is_empty() {
        return;
    }
    let specs = resolve(&relays).await;
    if specs.is_empty() {
        tracing::warn!("relay: no listed relay resolved to an IPv4 address");
        return;
    }
    let Ok(credentials) = credentials().map(HostLeaf::credentials) else {
        return;
    };
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
        RelayPaths::start(secret, port, specs.clone(), credentials, events)
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
    let rejudge: Vec<(NodeId, u64, Duration, bool)> = {
        let mut locked = lock(&state);
        locked.paths = Some(Paths {
            running: Arc::new(paths),
            relays,
            specs,
        });
        // Pairs the replaced paths relayed move to the new ones at once (their
        // handshakes went through the old relay, so they prove nothing about the
        // direct path). Every other pair is judged at the rest of its own deadline,
        // which covers pairs whose deadline passed while no paths ran.
        let now = SystemTime::now();
        locked
            .pairs
            .iter_mut()
            .map(|(node, pair)| {
                let relayed = pair.relayed.take().is_some();
                let waited = now.duration_since(pair.installed).unwrap_or_default();
                let wait = if relayed {
                    Duration::ZERO
                } else {
                    GRACE.saturating_sub(waited)
                };
                (*node, pair.generation, wait, relayed)
            })
            .collect()
    };
    for (node, pair_generation, wait, relayed) in rejudge {
        let owner = owner.clone();
        let state = state.clone();
        spawn(async move {
            // sleep: the rest of this pair's one deadline (D81: nothing repeats).
            tokio::time::sleep(wait).await;
            judge(&owner, &state, node, pair_generation, relayed).await;
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
        Ok(_) => {
            if let Some(entry) = lock(state)
                .pairs
                .get_mut(&node)
                .filter(|entry| entry.generation == generation)
            {
                entry.relayed = Some(Reason::NoHandshake);
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

/// Run `future` on the runtime of the task calling it (always the relay runtime here).
fn spawn(future: impl std::future::Future<Output = ()> + Send + 'static) {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(future);
    }
}

#[cfg(test)]
mod tests {
    //! Labels and reasons; the role and paths run in the namespace proof and relay tests.
    use super::*;

    /// A pair label depends only on the node id, and different nodes get different labels.
    #[test]
    fn labels_are_stable_and_distinct_per_node() {
        assert_eq!(label(NodeId(7)), label(NodeId(7)));
        assert_ne!(label(NodeId(7)), label(NodeId(8)));
        assert_eq!(label(NodeId(1)).0[15], 1);
    }

    /// The relay reason reads as the end of "because ...".
    #[test]
    fn the_reason_reads_as_a_sentence() {
        assert_eq!(
            Reason::NoHandshake.sentence(),
            "no direct handshake within 5 seconds"
        );
    }
}
