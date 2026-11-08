//! Owns the root-only Mesh node, staged public configuration and synchronous data-plane lifecycle [163,166,198].
pub use crate::gotatun_node::{EngineKind, EngineReason, EngineSelection};
use crate::{
    dataplane::Config,
    firewall::Firewall,
    gotatun_node::Engine,
    wireguard::{Client, Device, Key},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard},
};

/// Serializes relay route budgets shared by config updates and active path callbacks.
type RelayRouteMtuOverrides = BTreeMap<crate::policy::model::PublicKey, u16>;

/// Recover route-budget state after a callback panics while holding its mutex.
fn lock_route_mtu_overrides(
    overrides: &Mutex<RelayRouteMtuOverrides>,
) -> MutexGuard<'_, RelayRouteMtuOverrides> {
    overrides
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Apply a route snapshot while retaining relay budgets, restoring state if the write fails.
fn refresh_peer_routes_from(
    state: &Mutex<RelayRouteMtuOverrides>,
    peers: &[crate::dataplane::Peer],
    clear_overrides_for: &BTreeSet<crate::policy::model::PublicKey>,
) -> io::Result<RelayRouteMtuOverrides> {
    let mut overrides = lock_route_mtu_overrides(state);
    let previous = overrides.clone();
    for key in clear_overrides_for {
        overrides.remove(key);
    }
    if let Err(error) = Device::routes_with_mtu_overrides(peers, &overrides, false) {
        *overrides = previous;
        return Err(error);
    }
    Ok(previous)
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
/// Test seam (#260 J143 P3-4): runs once in `down`, after this node's link is gone and before its
/// shared-filter decision, so a namespace test can start another installation in that window.
#[cfg(feature = "test-support")]
pub static BEFORE_SHARED_FILTER_DECISION: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
struct Pending {
    server: Option<crate::policy::model::NodeId>,
    next: u32,
    version: u64,
    from_version: Option<u64>,
    default_policy: crate::dataplane::DefaultPolicy,
    config: Config,
}

fn restore_routes(
    store: &crate::node_state::Store,
    state: &crate::node_state::State,
) -> io::Result<BTreeSet<IpAddr>> {
    let mut routes = store.route_inventory()?;
    // A crash may leave the accepted snapshot older than a pruned journal.
    // Union its peer addresses before replay; never claim arbitrary routes.
    if let Some(config) = &state.config {
        routes.extend(config.peers.values().flat_map(|peer| {
            [
                IpAddr::V4(peer.peer.addresses.ipv4),
                IpAddr::V6(peer.peer.addresses.ipv6),
            ]
        }));
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

/// The component has no polling loop. Its idle netlink socket closes on explicit down.
pub struct Node {
    engine_kind: EngineKind,
    engine_source: EngineSource,
    identity: Option<Identity>,
    enabled: bool,
    store: Option<crate::node_state::Store>,
    config: Option<Config>,
    pending: Option<Pending>,
    routes: BTreeSet<IpAddr>,
    /// Live relay budgets are retained across full snapshots and route re-derivation.
    relay_route_mtu_overrides: Arc<Mutex<RelayRouteMtuOverrides>>,
    firewall: Firewall,
    proxy_ingress: infraternal_mesh::proxy_ports::MeshProxyIngress,
    owned: bool,
    /// The key the owned kernel link was created or proven for; `down` re-proves the live link
    /// against it, because another installation can replace a link under the shared name (D340).
    kernel_owner: KernelProof,
    // A committed revision remains restrictive until exact retirement succeeds.
    connection_cleanup_pending: bool,
    client: Option<Client>,
    gotatun: Option<Engine>,
    #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
    // Only a newly accepted full snapshot replaces DNS names; coordinator loss keeps D166 state.
    dns_resolver: Option<crate::dns::Resolver>,
    #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
    dns_integration: crate::dns_integration::DnsIntegration,
    #[cfg(feature = "cutoff-measure")]
    refusing_at_ns: Option<u64>,
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
            pending: None,
            routes: BTreeSet::new(),
            relay_route_mtu_overrides: Arc::default(),
            firewall: Firewall::default(),
            proxy_ingress: infraternal_mesh::proxy_ports::MeshProxyIngress::default(),
            owned: false,
            kernel_owner: KernelProof::default(),
            connection_cleanup_pending: false,
            client: None,
            gotatun: None,
            #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
            dns_resolver: None,
            #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
            dns_integration: crate::dns_integration::DnsIntegration::default(),
            #[cfg(feature = "cutoff-measure")]
            refusing_at_ns: None,
        }
    }
}
impl Node {
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
        self
    }

    /// Restore public intent and the selected, marked mesh data plane.
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
            store: Some(store),
            firewall: state
                .backend
                .map_or_else(Firewall::default, Firewall::for_backend),
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
            // A process can stop after marking the interface but before setting
            // its key. With no saved configuration there are no retained mesh
            // sessions to preserve; remove that incomplete owned startup only,
            // by the index the proof read.
            let incomplete = state.config.is_none()
                && (identity
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::InvalidData)
                    || identity
                        .as_ref()
                        .is_ok_and(|(key, port)| key.0 == [0; 32] || *port == 0));
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
            if public_key.0 == [0; 32] || port == 0 {
                return Err(io::ErrorKind::NotConnected.into());
            }
            // A retained interface from an older daemon may have selected the
            // reserved port. Rebind its socket while preserving its private key.
            if port == 51820 {
                port = Device::allocate_port(link.ifindex)?;
            }
            node.identity = Some(Identity {
                public_key,
                port,
                compact_access: true,
                #[cfg(feature = "mesh-dns")]
                dns_names: cfg!(target_os = "linux"),
                // Kernel `WireGuard` rotates its key in place (#285, D166).
                key_rotation: true,
            });
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
    fn remove_unshared_filter(&mut self) -> io::Result<()> {
        if !self.firewall.installed() {
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
        // An unchanged snapshot still reaches the firewall: Traefik has just confirmed it, and
        // any source that lost a route since the last confirmation must lose its open flows.
        if self.active()
            && let Some(config) = self.config.as_ref()
        {
            self.firewall
                .apply_proxy_ingress(config, &proxy_ingress, confirmed)?;
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
    fn save(&self, config: Option<&Config>, enabled: bool) -> io::Result<()> {
        if let Some(store) = &self.store {
            store.record_routes(&self.routes)?;
            store.save(&crate::node_state::State {
                enabled,
                config: config.cloned(),
                backend: self.firewall.backend(),
            })?;
        }
        Ok(())
    }
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

    /// Return a callback that keeps this peer's kernel route on its active path budget.
    ///
    /// The direct endpoint remains in the accepted peer record. `Some(mtu)` records the active
    /// relay's derived route MTU; `None` removes that override and re-derives from the direct path.
    #[cfg(feature = "relay")]
    pub(crate) fn relay_route_mtu_updater(
        &self,
        peer: &crate::dataplane::Peer,
    ) -> crate::relay_path::RouteMtuUpdater {
        let overrides = Arc::clone(&self.relay_route_mtu_overrides);
        let peer = peer.clone();
        Arc::new(move |relay_mtu| {
            let mut overrides = lock_route_mtu_overrides(&overrides);
            let previous = match relay_mtu {
                Some(mtu) => overrides.insert(peer.key, mtu),
                None => overrides.remove(&peer.key),
            };
            let result =
                Device::routes_with_mtu_overrides(std::slice::from_ref(&peer), &overrides, false);
            if result.is_err() {
                if let Some(previous) = previous {
                    overrides.insert(peer.key, previous);
                } else {
                    overrides.remove(&peer.key);
                }
            }
            result
        })
    }

    /// Refresh peer host routes using active relay budgets where present.
    /// # Errors
    /// Returns route-netlink errors without changing relay override state.
    fn install_peer_routes(
        &self,
        peers: &[crate::dataplane::Peer],
        remove: bool,
    ) -> io::Result<()> {
        let overrides = lock_route_mtu_overrides(&self.relay_route_mtu_overrides);
        Device::routes_with_mtu_overrides(peers, &overrides, remove)
    }

    /// Apply a full route refresh after clearing overrides for peers that returned to direct paths.
    ///
    /// The returned snapshot lets the caller restore the previous relay budgets if a later part of
    /// the enclosing configuration transaction rolls back.
    /// # Errors
    /// Returns route-netlink errors and restores the override map if route installation fails.
    fn refresh_peer_routes(
        &self,
        peers: &[crate::dataplane::Peer],
        clear_overrides_for: &BTreeSet<crate::policy::model::PublicKey>,
    ) -> io::Result<RelayRouteMtuOverrides> {
        refresh_peer_routes_from(&self.relay_route_mtu_overrides, peers, clear_overrides_for)
    }

    /// Restore relay budgets after a failed configuration transaction.
    fn restore_peer_route_mtu_overrides(&self, previous: RelayRouteMtuOverrides) {
        *lock_route_mtu_overrides(&self.relay_route_mtu_overrides) = previous;
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
        lock_route_mtu_overrides(&self.relay_route_mtu_overrides).clear();
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
        // A failed down may have published disabled intent while retaining only
        // part of the old kernel state. Finish cleanup before returning/recreating identity.
        if !self.enabled {
            self.down()?;
        }
        if let Some(identity) = &self.identity {
            return Ok(identity.clone());
        }
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
                if let Err(error) = Device::configure(created, public_key, &key, 0) {
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
                    let client = Client::new()?;
                    self.routes.clear();
                    self.save(None, true)?;
                    Ok((port, client))
                })();
                match prepared {
                    Ok((port, client)) => {
                        self.enabled = true;
                        self.client = Some(client);
                        let identity = Identity {
                            public_key,
                            port,
                            compact_access: true,
                            #[cfg(feature = "mesh-dns")]
                            dns_names: cfg!(target_os = "linux"),
                            key_rotation: true,
                        };
                        self.identity = Some(identity.clone());
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
                let adopt = self.persisted_tun_to_adopt(public_key)?;
                let engine = Engine::start(key.gotatun_secret()?, public_key, 0, None, adopt)?;
                let (interface, port, thp_disabled, offloads_enabled) = engine.info();
                if interface != crate::wireguard::INTERFACE
                    || port == 0
                    || !thp_disabled
                    || !offloads_enabled
                {
                    let mut engine = engine;
                    let _ = engine.stop();
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.owned = true;
                self.gotatun = Some(engine);
                if let Err(error) = self.save(self.config.as_ref(), true) {
                    if let Some(mut engine) = self.gotatun.take() {
                        let _ = engine.stop();
                    }
                    self.owned = false;
                    return Err(error);
                }
                self.enabled = true;
                let identity = Identity {
                    public_key,
                    port,
                    compact_access: true,
                    #[cfg(feature = "mesh-dns")]
                    dns_names: cfg!(target_os = "linux"),
                    // Linux GotaTun uses the durable journal and live reconfigure command (#367).
                    key_rotation: true,
                };
                self.identity = Some(identity.clone());
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
        // This durable intent precedes every kernel operation. A process stop
        // between the independent kernel transactions must reconcile as Off.
        self.save(None, false)?;
        self.enabled = false;
        #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
        {
            self.dns_integration.remove()?;
            self.dns_resolver = None;
        }
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
        self.firewall = Firewall::default();
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
        #[cfg(feature = "cutoff-measure")]
        {
            self.refusing_at_ns = None;
        }
        self.finish_connection_cleanup()?;
        let result = self.stage(chunk);
        if result.is_err() {
            self.pending = None;
        }
        result
    }
    // Keep enabled-key authority separate from contiguous snapshot staging.
    fn validate_binding(&self, chunk: &Chunk) -> io::Result<()> {
        if self.identity.is_none() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        if chunk.local_key.is_some_and(|key| {
            self.identity
                .as_ref()
                .is_none_or(|identity| identity.public_key != key)
        }) || self.config.as_ref().is_some_and(|old| {
            old.node != chunk.node
                && (chunk.local_key.is_none()
                    || chunk.from_version.is_some()
                    || chunk.version <= old.version)
        }) {
            // Only an authenticated full coordinator snapshot, bound to our
            // enabled kernel key at a newer revision, can authorize replacement.
            // Unbound snapshots and deltas retain the accepted identity fence.
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
    /// Validates and stages a coordinator chunk without applying a partial snapshot.
    /// Version and identity binding checks run before any network state is installed.
    fn stage(&mut self, chunk: Chunk) -> io::Result<bool> {
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
                || current.is_some_and(|v| {
                    chunk.version < v || chunk.from_version.is_some() && chunk.version == v
                })
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let config = if chunk.from_version.is_some() {
                self.config.clone().ok_or(io::ErrorKind::InvalidData)?
            } else {
                Config {
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
            if peer.peer != partial.peer {
                return Err(io::ErrorKind::InvalidData.into());
            }
            for policy in [&partial.inbound, &partial.outbound] {
                if matches!(policy, crate::policy::rules::TrafficPolicy::All) {
                    return Err(io::ErrorKind::InvalidData.into());
                }
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
        let config = self
            .pending
            .take()
            .ok_or(io::ErrorKind::InvalidData)?
            .config;
        if self.config.as_ref() == Some(&config) {
            return Ok(true);
        }
        if self
            .config
            .as_ref()
            .is_some_and(|old| old.version == config.version)
        {
            return self.upgrade_legacy_binding(config);
        }
        self.apply(config)?;
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
    /// Applies a complete configuration through the route and firewall transaction.
    /// The fence and rollback ordering keep the previously accepted state usable on failure.
    fn apply(&mut self, config: Config) -> io::Result<()> {
        #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
        let dns_records = crate::dns::Records::from_config(&config)?;
        #[cfg(feature = "cutoff-measure")]
        let validation = crate::cutoff_measure::Stage::new(config.node, config.version, "validate");
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
        #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
        if self.config.is_some() {
            self.ensure_dns_resolver(config.addresses.ipv4)?;
        }
        #[cfg(feature = "cutoff-measure")]
        drop(validation);
        if let Some(old) = &self.config {
            let endpoints_only = old.node == config.node
                && old.addresses == config.addresses
                && old.peers.len() == config.peers.len()
                && old.default_policy == config.default_policy
                && config.peers.iter().all(|(id, peer)| {
                    old.peers.get(id).is_some_and(|old| {
                        old.inbound == peer.inbound
                            && old.outbound == peer.outbound
                            && old.peer.key == peer.peer.key
                            && old.peer.addresses == peer.peer.addresses
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
                self.save(Some(&config), true)?;
                self.set_mesh_mtu(mesh_mtu.0, mesh_mtu.1.max(mesh_mtu.2))?;
                let route_overrides_to_clear: BTreeSet<_> =
                    updates.iter().map(|(previous, _)| previous.key).collect();
                let route_mtu_overrides = Arc::clone(&self.relay_route_mtu_overrides);
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
                        &route_mtu_overrides,
                        &peers,
                        &route_overrides_to_clear,
                    )?);
                    Ok(())
                })();
                // Release the engine-field borrow before updating the shared interface MTU.
                let installed = installed.and_then(|()| self.set_mesh_mtu(mesh_mtu.0, mesh_mtu.2));
                if let Err(error) = installed {
                    if let Some(previous) = previous_route_overrides {
                        self.restore_peer_route_mtu_overrides(previous);
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
        Device::check_routes(&proposed)?;
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
            .peer_counters()?
            .keys()
            .filter(|key| !desired.contains(key))
            .copied()
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
            && retired_keys.is_empty()
            && self.config.as_ref().is_some_and(|old| {
                old.node == config.node
                    && old.addresses == config.addresses
                    && old.peers.len() == config.peers.len()
            })
        {
            // Route validation and the actual key inventory above still run.
            // Only access changes remain: one final firewall transaction is
            // sufficient, without an intermediate table or peer/route writes.
            #[cfg(feature = "cutoff-measure")]
            let firewall =
                crate::cutoff_measure::Stage::new(config.node, config.version, "firewall");
            #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
            self.ensure_dns_resolver(config.addresses.ipv4)?;
            self.firewall.install_pending(&config)?;
            #[cfg(feature = "cutoff-measure")]
            {
                self.refusing_at_ns = crate::cutoff_measure::monotonic_ns();
            }
            #[cfg(feature = "cutoff-measure")]
            drop(firewall);
            #[cfg(feature = "cutoff-measure")]
            let persistence =
                crate::cutoff_measure::Stage::new(config.node, config.version, "persist");
            if let Err(error) = self.save(Some(&config), true) {
                self.firewall
                    .apply(self.config.as_ref().ok_or(io::ErrorKind::NotConnected)?)?;
                return Err(error);
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
            .flat_map(|peer| {
                [
                    IpAddr::V4(peer.peer.addresses.ipv4),
                    IpAddr::V6(peer.peer.addresses.ipv6),
                ]
            })
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
        #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
        let dns_was_running = self.dns_resolver.is_some();
        let mut previous_route_overrides = None;
        let result = (|| {
            if self
                .config
                .as_ref()
                .is_none_or(|old| old.addresses != config.addresses)
            {
                Device::addresses(config.addresses)?;
            }
            #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
            self.ensure_dns_resolver(config.addresses.ipv4)?;
            let (ifindex, previous_mtu, requested_mtu) = mesh_mtu;
            // Keep the larger interface until per-peer route metrics are installed. The shared
            // link stays IPv6-safe; its final size follows the largest peer budget.
            self.set_mesh_mtu(ifindex, previous_mtu.max(requested_mtu))?;
            self.apply_peer_changes(&config, &changed, &retired_keys)?;
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
                Device::retain_recorded_routes(&self.routes, &proposed)?;
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
            let saved = self.save(Some(&config), true);
            if saved.is_err() {
                self.routes = recorded;
            }
            saved
        })();
        if let Err(error) = result {
            if let Some(previous) = previous_route_overrides {
                self.restore_peer_route_mtu_overrides(previous);
            }
            #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
            if !dns_was_running && self.config.is_none() {
                self.dns_resolver = None;
            }
            // Saving can fail after the permissive policy transaction. Reinstall
            // the fence before rollback so any later error still denies NEW traffic.
            self.apply_fence(&fence, &config)?;
            if let Some(old) = &self.config {
                if old.addresses != config.addresses {
                    Device::addresses(old.addresses)?;
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
                    self.gotatun
                        .as_ref()
                        .ok_or(io::ErrorKind::NotConnected)?
                        .apply(old.clone())?;
                }
                self.set_mesh_mtu(
                    mesh_mtu.0,
                    mesh_mtu.1.max(crate::mesh_mtu::IPV6_MINIMUM_MTU),
                )?;
                self.install_peer_routes(&restore, false)?;
                let retained: Vec<_> = std::iter::once(old.addresses)
                    .chain(restore.iter().map(|peer| peer.addresses))
                    .collect();
                Device::retain_recorded_routes(&self.routes, &retained)?;
                self.set_mesh_mtu(
                    mesh_mtu.0,
                    mesh_mtu.1.max(crate::mesh_mtu::IPV6_MINIMUM_MTU),
                )?;
                self.firewall.apply(old)?;
            } else {
                if self.engine_kind == EngineKind::Kernel {
                    self.client
                        .as_mut()
                        .ok_or(io::ErrorKind::NotConnected)?
                        .peers(
                            &[],
                            &changed.iter().map(|peer| peer.key).collect::<Vec<_>>(),
                        )?;
                } else {
                    let mut empty = config.clone();
                    empty.peers.clear();
                    self.gotatun
                        .as_ref()
                        .ok_or(io::ErrorKind::NotConnected)?
                        .apply(empty)?;
                }
                Device::retain_recorded_routes(&self.routes, &[])?;
            }
            self.set_mesh_mtu(
                mesh_mtu.0,
                mesh_mtu.1.max(crate::mesh_mtu::IPV6_MINIMUM_MTU),
            )?;
            return Err(error);
        }
        self.config = Some(config);
        #[cfg(all(feature = "mesh-dns", target_os = "linux"))]
        self.publish_dns(dns_records)?;
        self.connection_cleanup_pending = true;
        self.finish_connection_cleanup()
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
            resolver.has_system_port(),
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
// No Drop cleanup: kernel state and established flows survive control process loss [166].

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
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    /// Retirement removes the `GotaTun` private key file itself (#260 J143 P3-3).
    #[test]
    fn retirement_removes_the_private_key_file() {
        let directory = crate::node_state::tests::Directory::new();
        let (store, _) = crate::node_state::Store::open(&directory.0).expect("store");
        store.write_private_key(&[5; 32]).expect("key");
        let key = directory.0.join("mesh-private-key");
        assert!(key.exists());
        let retirement = Retirement {
            interface: false,
            interface_index: None,
            filter: None,
            left: Vec::new(),
            store: Some(store),
        };
        assert_eq!(retirement.execute().expect("retire"), Vec::<&str>::new());
        assert!(!key.exists(), "retirement leaves no private key behind");
    }

    /// A completed journal must not recreate the key after host-uninstall retirement (#367).
    #[test]
    fn j356_retirement_after_rotation_leaves_no_private_key() {
        let directory = crate::node_state::tests::Directory::new();
        let (store, _) = crate::node_state::Store::open(&directory.0).expect("store");
        let (candidate_key, candidate_public) = Key::generate().expect("candidate");
        let candidate: [u8; 32] = candidate_key.private_bytes().try_into().expect("32 bytes");
        store.record_engine(EngineKind::GotaTun).expect("engine");
        store
            .record_interface(&candidate_public)
            .expect("interface");
        store.write_private_key(&candidate).expect("key");
        store
            .save_rotation_secret(&crate::node_state::RotationSecret {
                operation_id: "00000000-0000-4000-8000-000000000356".to_owned(),
                sequence: 1,
                previous: [0; 32],
                candidate,
                commit_requested: true,
                completed: true,
            })
            .expect("completed marker");
        let retirement = Retirement {
            interface: false,
            interface_index: None,
            filter: None,
            left: Vec::new(),
            store: Some(store),
        };
        retirement.execute().expect("retire");
        assert!(!directory.0.join("mesh-private-key").exists());
        let (store, _) = crate::node_state::Store::open(&directory.0).expect("reopen");
        let residue = store.rotation_secret().expect("read journal");
        let interface = store.recorded_interface().expect("read interface record");
        let key_before_recovery = store.read_private_key().expect("read key");
        eprintln!(
            "J356 R1: retirement leaves journal={} interface={} private_key={}",
            residue.is_some(),
            interface.is_some(),
            key_before_recovery.is_some()
        );
        recover_gotatun_private_key_from_journal(&store).expect("recover");
        let resurrected = store.read_private_key().expect("read key");
        eprintln!(
            "J356 R1: key file recreated after retirement={}",
            resurrected
                .as_ref()
                .is_some_and(|k| k.as_slice() == candidate)
        );
        assert!(
            residue.is_none() && interface.is_none() && key_before_recovery.is_none(),
            "retirement left identity state: journal={}, interface={}, private_key={}",
            residue.is_some(),
            interface.is_some(),
            key_before_recovery.is_some()
        );
        assert!(resurrected.is_none(), "recovery recreated a retired key");
    }

    /// A finished `GotaTun` marker authorizes only its predecessor or candidate snapshot key.
    #[test]
    fn j356_completed_snapshot_binding_rejects_an_unrelated_key() {
        let directory = crate::node_state::tests::Directory::new();
        let (store, _) = crate::node_state::Store::open(&directory.0).expect("store");
        let previous = [0x11; 32];
        let candidate = [0x22; 32];
        let unrelated = [0x33; 32];
        let previous_public = Key::from_private(&previous).expect("previous key").1;
        let candidate_public = Key::from_private(&candidate).expect("candidate key").1;
        let unrelated_public = Key::from_private(&unrelated).expect("unrelated key").1;
        store.record_engine(EngineKind::GotaTun).expect("engine");
        store
            .record_interface(&candidate_public)
            .expect("candidate interface record");
        store
            .write_private_key(&candidate)
            .expect("candidate key file");
        store
            .save_rotation_secret(&crate::node_state::RotationSecret {
                operation_id: "00000000-0000-4000-8000-000000000367".to_owned(),
                sequence: 1,
                previous,
                candidate,
                commit_requested: true,
                completed: false,
            })
            .expect("commit intent");
        store
            .complete_rotation_secret("00000000-0000-4000-8000-000000000367", 1)
            .expect("finish rotation");

        assert!(gotatun_snapshot_binding_is_authorized(&store, previous_public).expect("old"));
        assert!(gotatun_snapshot_binding_is_authorized(&store, candidate_public).expect("new"));
        assert!(
            !gotatun_snapshot_binding_is_authorized(&store, unrelated_public).expect("unrelated"),
            "a completed marker does not authorize an unrelated saved binding"
        );
    }

    /// Both Linux engines require a live identity and owned link before rotation can start.
    #[test]
    fn inactive_engines_refuse_rotation_without_reading_or_mutating_state() {
        let operation = "00000000-0000-4000-8000-000000000005";
        let mut gotatun = Node::default().with_engine(EngineKind::GotaTun);
        for result in [
            gotatun.prepare_rotation(operation, 1).map(|_| ()),
            gotatun.commit_rotation(operation, 1).map(|_| ()),
            gotatun.finish_rotation(operation, 1),
        ] {
            assert_eq!(
                result.expect_err("inactive GotaTun refuses").kind(),
                io::ErrorKind::NotConnected
            );
        }
        let mut kernel = Node::default().with_engine(EngineKind::Kernel);
        assert_eq!(
            kernel
                .prepare_rotation(operation, 1)
                .expect_err("inactive kernel refuses")
                .kind(),
            io::ErrorKind::NotConnected
        );
    }

    /// A staged snapshot cannot change the server's identity.
    #[test]
    fn server_identity_cannot_change_inside_a_staged_snapshot() {
        use crate::policy::model::{Addresses, NodeId, PublicKey};
        let mut node = Node {
            identity: Some(Identity {
                compact_access: true,
                #[cfg(feature = "mesh-dns")]
                dns_names: cfg!(target_os = "linux"),
                key_rotation: true,
                public_key: PublicKey([1; 32]),
                port: 44000,
            }),
            ..Node::default()
        };
        let config = Config {
            server: Some(NodeId(1)),
            local_key: None,
            node: NodeId(2),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            version: 1,
            addresses: Addresses {
                ipv4: "10.254.0.2".parse().expect("IPv4"),
                ipv6: "fd01::2".parse().expect("IPv6"),
            },
            default_policy: crate::dataplane::DefaultPolicy::default(),
            exposure: None,
            peers: BTreeMap::new(),
            #[cfg(feature = "mesh-dns")]
            peer_names: std::collections::BTreeMap::new(),
        };
        let mut chunk = crate::configuration::chunks(None, &config)
            .expect("snapshot")
            .remove(0);
        chunk.last = false;
        assert!(!node.chunk(chunk.clone()).expect("staged header"));
        chunk.index = 1;
        chunk.server = Some(NodeId(3));
        assert!(node.chunk(chunk).is_err());
        assert!(node.config().is_none());
    }

    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn explicit_up_recovers_disabled_intent_before_reusing_identity() {
        let mut node = Node::default();
        node.up().expect("start");
        // Down publishes disabled intent before kernel cleanup. Model an
        // interrupted cleanup at that exact boundary with a still-live identity.
        node.enabled = false;
        node.up().expect("explicit restart");
        assert!(node.enabled());
        assert!(Device::owned().expect("owned interface"));
        node.down().expect("cleanup");
    }
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn externally_removed_interface_does_not_block_down() {
        let mut node = Node::default();
        node.up().expect("start");
        Device::delete().expect("external removal");
        node.down().expect("already absent owned interface");
        assert!(!node.active());
        assert!(!node.enabled());
    }
    /// A 1000-peer snapshot applied in chunks is accepted all at once, with every peer in the kernel.
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN; use release for timing."]
    fn chunked_snapshot_is_atomic_and_applies_1000_kernel_peers() {
        use crate::{
            dataplane::{DefaultPolicy, Peer, PeerPolicy},
            policy::{
                model::{Addresses, NodeId},
                rules::TrafficPolicy,
            },
        };
        let mut node = Node::default().with_engine(EngineKind::Kernel);
        node.up().expect("start");
        let addresses = |id: u32| Addresses {
            ipv4: std::net::Ipv4Addr::from(0x0afe_0000 + id),
            ipv6: std::net::Ipv6Addr::from((0xfd01_u128 << 112) + u128::from(id)),
        };
        let config = Config {
            local_key: None,
            server: None,
            node: NodeId(1),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            version: 1,
            addresses: addresses(1),
            default_policy: DefaultPolicy::Allow,
            exposure: None,
            peers: (2..=1001)
                .map(|id| {
                    let (_, key) = Key::generate().expect("public peer fixture");
                    (
                        NodeId(u64::from(id)),
                        PeerPolicy {
                            peer: Peer {
                                key,
                                previous_key: None,
                                previous_active: false,
                                addresses: addresses(id),
                                endpoint: Some("192.0.2.1:44000".parse().expect("public endpoint")),
                            },
                            inbound: TrafficPolicy::All,
                            outbound: TrafficPolicy::All,
                            access_ssh: None,
                        },
                    )
                })
                .collect(),
            #[cfg(feature = "mesh-dns")]
            peer_names: std::collections::BTreeMap::new(),
        };
        let chunks = crate::configuration::chunks(None, &config).expect("bounded chunks");
        let count = chunks.len();
        assert!(count > 1);
        // An interrupted or out-of-order snapshot cannot mutate the live view.
        node.chunk(chunks[0].clone()).expect("first staged");
        assert!(node.chunk(chunks[count - 1].clone()).is_err());
        assert!(node.config().is_none());
        assert_eq!(Device::counters().expect("empty kernel").len(), 0);
        let started = std::time::Instant::now();
        for chunk in chunks {
            let last = chunk.last;
            assert_eq!(node.chunk(chunk).expect("stage/apply"), last);
            if !last {
                assert!(node.config().is_none());
            }
        }
        let initial = started.elapsed().as_micros();
        assert_eq!(Device::counters().expect("kernel peers").len(), 1000);
        let mut next = config.clone();
        next.version += 1;
        next.peers
            .get_mut(&NodeId(500))
            .expect("member")
            .peer
            .endpoint = Some("192.0.2.2:44000".parse().expect("public endpoint"));
        let delta = crate::configuration::chunks(Some(&config), &next).expect("delta");
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].upserted.len(), 1);
        let started = std::time::Instant::now();
        node.chunk(delta[0].clone()).expect("endpoint delta");
        println!(
            "METRIC mesh_node machine=infraternal-dev peers=1000 chunks={count} apply_us={initial} single_endpoint_us={} load={}",
            started.elapsed().as_micros(),
            std::fs::read_to_string("/proc/loadavg")
                .expect("load")
                .trim()
        );
        assert_eq!(node.config().expect("applied").version, 2);
        node.down().expect("off");
        assert!(!Device::owned().expect("absent owned interface"));
    }
}

#[cfg(test)]
#[path = "node_rotation_tests.rs"]
mod rotation_tests;
