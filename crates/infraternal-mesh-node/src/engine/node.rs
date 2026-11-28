//! Durable lifecycle and configuration state machine for the userspace mesh device.

use super::{
    config::{Pending, needs_authority_reset, stage_chunk},
    runtime::{HostNet, PendingWorker, Worker, validate_underlay_routes},
};
use crate::{
    dataplane::Config,
    enrolment::Enrolment,
    node_state::RotationSecret,
    packet_filter::PacketFilter,
    peer_stats::{CounterMap, Counters},
    policy::proxy_ports::MeshProxyIngress,
};
use gotatun::x25519::{PublicKey as X25519PublicKey, StaticSecret};
use ring::rand::{SecureRandom as _, SystemRandom};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::IpAddr,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// Host facilities needed to restore and present the portable node.
pub trait NodeHost: HostNet {
    /// Durable node storage for this host.
    type Store: NodeStore;

    /// Refuse state scoped to a different installation.
    /// # Errors
    /// Reports a mismatched or unreadable machine binding.
    fn check_enrolled_machine(state: &Path) -> io::Result<()>;

    /// Set up the host before reading the durable configuration.
    /// # Errors
    /// Reports a failed machine binding.
    fn prepare_restore(state: &Path, enrolment: Option<&Enrolment>) -> io::Result<()>;

    /// Locate the host's public snapshot.
    fn public_state_path(state: &Path) -> PathBuf;

    /// Identify saved tunnel names owned by this host's tunnel provider.
    fn valid_interface_name(name: &str) -> bool;

    /// Open a tunnel without registering it with the packet runtime yet.
    /// # Errors
    /// Reports tunnel allocation failures.
    fn open_tunnel() -> io::Result<Self::OpenTunnel>;

    /// Select the UDP listener request from durable and host override settings.
    /// # Errors
    /// Reports an invalid listener override.
    fn listen_port(saved: Option<u16>) -> io::Result<crate::listen_port::Request>;

    /// Present a route's host installation status.
    fn network_route_state(
        status: &Self::NetworkStatus,
        network: crate::policy::networks::Network,
    ) -> serde_json::Value;

    /// Present the state of host split DNS integration.
    fn dns_state() -> serde_json::Value;

    /// Observe a durable rotation boundary in a host fixture.
    fn rotation_checkpoint(_name: &str) {}

    /// Observe the durable authority fence in a host fixture.
    fn authority_replacement_checkpoint() {}
}

/// Durable node operations that depend on files or the local key provider.
pub trait NodeStore: Send {
    /// Read the public snapshot and its authority record.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn load_public(path: &Path) -> io::Result<Option<SavedState>>;

    /// Atomically save public intent.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn store_public(path: &Path, state: &SavedState) -> io::Result<()>;

    /// Write a fail-closed snapshot when atomic replacement failed.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn fence_public(path: &Path, state: &SavedState) -> io::Result<()>;

    /// Replace public intent only if its accepted authority and base still match.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn replace_public(path: &Path, state: &SavedState, expected: &Config) -> io::Result<()>;

    /// Return the saved private key, if one exists, in a zeroizing buffer.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn load_private(&self) -> io::Result<Option<Zeroizing<Vec<u8>>>>;

    /// Open or initialize the platform key and return its public identity.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn open_private(state: &Path) -> io::Result<(StaticSecret, crate::policy::model::PublicKey)>;

    /// Record a journal-authorized private key and its public interface identity.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn record_rotation_identity(
        &self,
        operation: &str,
        sequence: u64,
        private: &[u8],
        public: &crate::policy::model::PublicKey,
    ) -> io::Result<()>;

    /// Retire the local identity when the enrolment changes.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn retire_private(state: &Path) -> io::Result<()>;

    /// Open the store for the enrolled node's state directory.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn open(state: &Path) -> io::Result<Self>
    where
        Self: Sized;

    /// Remove the enrolled key's previous rotation and ownership records.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn discard_rotation_state(&self) -> io::Result<()>;

    /// Read the local key's recorded public interface identity.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn recorded_interface(&self) -> io::Result<Option<crate::policy::model::PublicKey>>;

    /// Record the public identity assigned to this node.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn record_interface(&self, key: &crate::policy::model::PublicKey) -> io::Result<()>;

    /// Read the previous automatic UDP port selection.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn recorded_listen_port(&self) -> io::Result<Option<u16>>;

    /// Save the next automatic UDP port selection.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn record_listen_port(&self, port: u16) -> io::Result<()>;

    /// Read the current or recently completed key rotation.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn rotation_secret(&self) -> io::Result<Option<RotationSecret>>;

    /// Save rotation intent before changing the active key.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn save_rotation_secret(&self, state: &RotationSecret) -> io::Result<()>;

    /// Check whether a snapshot continues the stored rotation.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn rotation_matches(
        &self,
        operation: Option<&crate::dataplane::RotationContinuation>,
    ) -> io::Result<bool>;

    /// Mark a rotation complete and retire its predecessor's secret.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn complete_rotation_secret(&self, operation_id: &str, sequence: u64) -> io::Result<()>;

    /// Discard rotation metadata once the active identity is settled.
    /// # Errors
    /// Reports unsafe or unavailable durable state.
    fn discard_rotation_journal(&self) -> io::Result<()>;
}
/// Public durable intent shared with the Linux node journal; the `WireGuard` secret is never serialized.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedState {
    /// Whether the host requests a live mesh runtime.
    pub enabled: bool,
    /// Last accepted public configuration.
    pub config: Option<crate::dataplane::Config>,
    /// True while a peer-free reset snapshot awaits the new authority's full config.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub authority_reset_pending: bool,
    #[serde(default)]
    /// Host routes owned by the saved interface.
    pub routes: BTreeSet<IpAddr>,
    #[serde(default)]
    /// Name of the interface that owned the routes.
    pub interface: Option<String>,
    #[serde(default)]
    /// UDP port previously reported to the coordinator.
    pub port: u16,
    /// Linux-only legacy metadata is accepted as an opaque public value for cross-platform state reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<serde_json::Value>,
    /// The enrolment that issued `config`; absent only in state written by slice-1 builds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<Enrolment>,
}

impl Default for SavedState {
    fn default() -> Self {
        Self {
            enabled: true,
            config: None,
            authority_reset_pending: false,
            routes: BTreeSet::new(),
            interface: None,
            port: 0,
            backend: None,
            binding: None,
        }
    }
}

/// Apply the binding rule to saved state; `true` means the key must rotate.
///
/// Saved state that is not bound to the current enrolment loses its
/// configuration and the key; the node then registers a new key with its
/// coordinator. That includes unbound state: a slice-1 build wrote none, and a
/// slice-1 Mac may have been joined to another coordinator before upgrading,
/// so its peers cannot be trusted to be this enrolment's (J162 F3). Its key is
/// a fresh one anyway, because the slice-1 key is retired (`macos_key`), so
/// discarding the peers costs one coordinator round trip. A first start has no
/// saved state and is not passed here. Without a current enrolment (no
/// `identity.json`), nothing is compared.
#[must_use]
pub fn reconcile(mut state: SavedState, enrolment: Option<&Enrolment>) -> (SavedState, bool) {
    let Some(enrolment) = enrolment else {
        return (state, false);
    };
    let rotate = state.binding.as_ref() != Some(enrolment);
    if rotate {
        state.config = None;
        state.authority_reset_pending = false;
        // The old utun closed with the old process, which retired its routes.
        state.routes.clear();
        state.interface = None;
    }
    state.binding = Some(enrolment.clone());
    (state, rotate)
}

/// A temporary rotation key that clears its private bytes when dropped.
struct RotationKey(Zeroizing<[u8; 32]>);

impl RotationKey {
    /// Generate a candidate identity with the system random source.
    /// # Errors
    /// Reports an unavailable random source or an invalid X25519 key.
    fn generate() -> io::Result<(Self, crate::policy::model::PublicKey)> {
        let mut private = Zeroizing::new([0_u8; 32]);
        SystemRandom::new()
            .fill(&mut *private)
            .map_err(|_| io::Error::other("System random generator unavailable."))?;
        Self::from_private(&private[..])
    }

    /// Rebuild a temporary key from the private rotation journal.
    /// # Errors
    /// Refuses a private key with any length other than 32 bytes.
    fn from_private(bytes: &[u8]) -> io::Result<(Self, crate::policy::model::PublicKey)> {
        let private =
            Zeroizing::new(<[u8; 32]>::try_from(bytes).map_err(|_| io::ErrorKind::InvalidData)?);
        let secret = StaticSecret::from(*private);
        let public = X25519PublicKey::from(&secret);
        Ok((
            Self(private),
            crate::policy::model::PublicKey(*public.as_bytes()),
        ))
    }

    /// Borrow private bytes only long enough to write the protected key file.
    #[must_use]
    fn private_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Copy this key into `GotaTun`'s zeroizing secret type for a live update.
    fn gotatun_secret(&self) -> StaticSecret {
        StaticSecret::from(*self.0)
    }
}

/// Owns one mesh runtime, accepted configuration and durable identity state.
/// The serialized worker mutates the tunnel; enrollment binding scopes restored config to one host.
pub struct Node<H: NodeHost> {
    state: NodeState<H>,
}

/// Fields supplied by the engine's integration fixtures.
#[doc(hidden)]
pub struct NodeState<H: NodeHost> {
    /// Whether the node should be running.
    pub enabled: bool,
    /// Serialized live device worker.
    pub worker: Option<Worker>,
    /// Current public key and stable listener identity.
    pub identity: Option<crate::dataplane::Identity>,
    /// Durable node store, when configured.
    pub store: Option<H::Store>,
    /// Last accepted snapshot, if any.
    pub config: Option<Config>,
    /// Marks the peer-free snapshot left by an authority fence until its full replacement arrives.
    /// Whether a peer-free authority fence is still in effect.
    pub authority_reset_pending: bool,
    /// Snapshot being assembled from chunks.
    pub pending: Option<Pending>,
    /// Host routes installed by the live worker.
    pub routes: BTreeSet<IpAddr>,
    /// Name of the currently owned tunnel.
    pub interface: Option<String>,
    /// Current listener port.
    pub port: u16,
    /// Public state path from the host.
    pub path: Option<PathBuf>,
    /// Enrolment that authorized the accepted snapshot.
    pub binding: Option<Enrolment>,
    /// What the worker did with each reachable subnet route, for `mesh routes` (D197 M3).
    /// Status of routes behind subnet peers.
    pub network_status: H::NetworkStatus,
}

impl<H: NodeHost> Default for Node<H> {
    fn default() -> Self {
        Self {
            state: NodeState {
                enabled: true,
                worker: None,
                identity: None,
                store: None,
                config: None,
                authority_reset_pending: false,
                pending: None,
                routes: BTreeSet::new(),
                interface: None,
                port: 0,
                path: None,
                binding: None,
                network_status: H::NetworkStatus::default(),
            },
        }
    }
}

/// Recover the Mac identity selected by a prepared or committed rotation journal.
///
/// A pending commit selects the candidate on restart even if the key file or identity record was
/// the last write to reach disk. Only the predecessor and candidate from this journal are valid.
/// # Errors
/// Refuses a key file or identity record outside the journal's authorized phase.
fn recover_rotation_key(
    store: &impl NodeStore,
    rotation: &crate::node_state::RotationSecret,
) -> io::Result<(RotationKey, crate::policy::model::PublicKey)> {
    let (candidate, candidate_public) = RotationKey::from_private(&rotation.candidate)?;
    let recorded = store
        .recorded_interface()?
        .ok_or(io::ErrorKind::InvalidData)?;
    let saved = store.load_private()?.ok_or(io::ErrorKind::InvalidData)?;
    let saved_public = RotationKey::from_private(&saved)?.1;
    if rotation.completed {
        if recorded != candidate_public || saved_public != candidate_public {
            return Err(io::ErrorKind::InvalidData.into());
        }
        return Ok((candidate, candidate_public));
    }

    let (previous, previous_public) = RotationKey::from_private(&rotation.previous)?;
    if !rotation.commit_requested {
        if recorded != previous_public || saved_public != previous_public {
            return Err(io::ErrorKind::InvalidData.into());
        }
        return Ok((previous, previous_public));
    }

    let legal_partial_write = (recorded == previous_public && saved_public == previous_public)
        || (recorded == candidate_public
            && (saved_public == previous_public || saved_public == candidate_public));
    if !legal_partial_write {
        return Err(io::ErrorKind::InvalidData.into());
    }
    store.record_rotation_identity(
        &rotation.operation_id,
        rotation.sequence,
        candidate.private_bytes(),
        &candidate_public,
    )?;
    Ok((candidate, candidate_public))
}

/// Check that a saved Mac key names only an identity from its durable rotation journal.
/// # Errors
/// Refuses unsafe key records and mismatched journal state.
fn validate_rotation_proof(
    store: &impl NodeStore,
    rotation: &crate::node_state::RotationSecret,
    current: crate::policy::model::PublicKey,
) -> io::Result<()> {
    let candidate_public = RotationKey::from_private(&rotation.candidate)?.1;
    let recorded = store
        .recorded_interface()?
        .ok_or(io::ErrorKind::InvalidData)?;
    let saved = store.load_private()?.ok_or(io::ErrorKind::InvalidData)?;
    let saved_public = RotationKey::from_private(&saved)?.1;
    if rotation.completed {
        if current != candidate_public
            || recorded != candidate_public
            || saved_public != candidate_public
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        return Ok(());
    }
    let previous_public = RotationKey::from_private(&rotation.previous)?.1;
    let valid = if rotation.commit_requested {
        ((current == previous_public || current == candidate_public)
            && recorded == previous_public
            && saved_public == previous_public)
            || (current == candidate_public
                && recorded == candidate_public
                && (saved_public == previous_public || saved_public == candidate_public))
    } else {
        current == previous_public && recorded == previous_public && saved_public == previous_public
    };
    if !valid {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

/// Verify an accepted local-key binding against the key file and any open rotation journal.
/// # Errors
/// Refuses unreadable or invalid private state.
pub fn snapshot_binding_is_authorized(
    store: &impl NodeStore,
    bound: crate::policy::model::PublicKey,
) -> io::Result<bool> {
    let Some(private) = store.load_private()? else {
        return Ok(false);
    };
    let private_public = RotationKey::from_private(&private)?.1;
    let Some(rotation) = store.rotation_secret()? else {
        return Ok(store.recorded_interface()? == Some(private_public) && private_public == bound);
    };
    let candidate_public = RotationKey::from_private(&rotation.candidate)?.1;
    let Some(recorded) = store.recorded_interface()? else {
        return Ok(false);
    };
    if rotation.completed {
        // The candidate files prove the active identity; the marker bounds any stale snapshot to
        // this rotation's predecessor or candidate.
        return Ok(private_public == candidate_public
            && recorded == candidate_public
            && rotation.completed_binding_matches(bound, candidate_public));
    }
    let previous_public = RotationKey::from_private(&rotation.previous)?.1;
    let bound_authorized =
        bound == previous_public || (rotation.commit_requested && bound == candidate_public);
    let key_state_authorized = if rotation.commit_requested {
        (private_public == previous_public
            && (recorded == previous_public || recorded == candidate_public))
            || (private_public == candidate_public && recorded == candidate_public)
    } else {
        private_public == previous_public && recorded == previous_public
    };
    Ok(bound_authorized && key_state_authorized)
}

/// Check the coordinator's rotation identifier before creating any private state.
fn valid_rotation_request(operation_id: &str, sequence: u64) -> bool {
    sequence != 0
        && operation_id.len() == 36
        && operation_id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

impl<H: NodeHost> Node<H> {
    /// Construct a node with injected durable state and a recording worker for tests.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn from_test_state(state: NodeState<H>) -> Self {
        Self { state }
    }

    /// Inspect fixture state after exercising the shipping state machine.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn test_state(&self) -> &NodeState<H> {
        &self.state
    }

    /// Stop at the durable authority fence so a fixture can inspect the intermediate state.
    /// # Errors
    /// Reports a failure to persist the replacement fence.
    #[cfg(feature = "test-support")]
    pub fn test_prepare_authority_replacement(&mut self, replacement: &Config) -> io::Result<()> {
        self.prepare_authority_replacement(replacement)
    }

    /// What the platform resolver integration did, for the host's status view.
    #[must_use]
    pub fn dns_state(&self) -> serde_json::Value {
        H::dns_state()
    }

    /// Refuse a folder bound to another Mac before the supervisor starts (see `macos_machine`).
    /// # Errors
    /// `PermissionDenied` carrying a [`crate::enrolment::MachineBindingError`].
    pub fn check_enrolled_machine(state_directory: &Path) -> io::Result<()> {
        H::check_enrolled_machine(state_directory)
    }

    /// Restore accepted public intent, clean only old utun routes, and resume before coordinator dialing.
    ///
    /// State that another enrolment issued is discarded first (see [`reconcile`]).
    /// # Errors
    /// Refuses unsafe state, an unreadable node key or failed utun/device startup.
    pub fn restore(state_directory: &Path, enrolment: Option<&Enrolment>) -> io::Result<Self> {
        H::prepare_restore(state_directory, enrolment)?;
        #[cfg(feature = "mesh-dns")]
        H::clear_dns()?;
        let path = H::public_state_path(state_directory);
        let (state, rotate) = match H::Store::load_public(&path)? {
            Some(saved) => reconcile(saved, enrolment),
            None => (
                SavedState {
                    binding: enrolment.cloned(),
                    ..SavedState::default()
                },
                false,
            ),
        };
        let store = H::Store::open(state_directory)?;
        if rotate {
            tracing::warn!(
                "Mesh state is not bound to this enrolment; discarding its peers and starting with a new WireGuard key"
            );
            store.discard_rotation_state()?;
            H::Store::retire_private(state_directory)?;
        }
        let mut stale_routes = state.routes.clone();
        if let Some(config) = &state.config {
            stale_routes.extend(H::route_addresses(config));
        }
        match state.interface.as_deref() {
            Some(interface) if H::valid_interface_name(interface) => {
                // The old control socket's close retires its routes. Its utun unit may already
                // belong to another tunnel, so persisted names are never used to delete routes.
            }
            Some(_) => return Err(io::ErrorKind::InvalidData.into()),
            None if !stale_routes.is_empty() => return Err(io::ErrorKind::InvalidData.into()),
            None => {}
        }
        let mut node = Self {
            state: NodeState {
                enabled: state.enabled,
                config: state.config,
                authority_reset_pending: state.authority_reset_pending,
                port: state.port,
                path: Some(path),
                binding: state.binding,
                store: Some(store),
                ..Self::default().state
            },
        };
        if node.enabled() {
            node.up()?;
        } else {
            node.persist(false, None, BTreeSet::new(), None)?;
        }
        Ok(node)
    }

    /// Whether the node is configured to be enabled.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.state.enabled
    }

    /// Whether the enabled node has its authenticated identity and runtime worker available.
    #[must_use]
    pub fn active(&self) -> bool {
        self.state.enabled && self.state.identity.is_some() && self.state.worker.is_some()
    }

    /// Whether this node's `GotaTun` runs with its second UDP socket on (#260, J1211), so peers
    /// may send it marked small datagrams.
    #[must_use]
    pub fn side_socket(&self) -> bool {
        H::side_socket()
    }

    /// Return the active UDP listener port advertised by this node's mesh identity.
    ///
    /// `None` means the worker has not bound a socket. The value is the actual port after an
    /// automatic fallback, so `mesh status` reports the endpoint peers should reach.
    #[must_use]
    pub fn listen_port(&self) -> Option<u16> {
        self.state.identity.as_ref().map(|identity| identity.port)
    }

    /// Whether a retired authority still needs a complete snapshot from the enrolled server.
    #[must_use]
    pub fn awaiting_server_snapshot(&self) -> bool {
        self.state.authority_reset_pending
    }

    /// Whether disabled intent is waiting for its live worker to stop.
    #[must_use]
    pub fn stopping(&self) -> bool {
        !self.state.enabled && self.state.worker.is_some()
    }

    /// The public key this node currently presents as its identity, once it is up.
    #[must_use]
    pub fn interface_key(&self) -> Option<crate::policy::model::PublicKey> {
        self.state
            .identity
            .as_ref()
            .map(|identity| identity.public_key)
    }

    /// Borrow the most recently accepted public mesh snapshot.
    #[must_use]
    pub fn config(&self) -> Option<&Config> {
        self.state.config.as_ref()
    }

    /// Return the persistent key's current public identity and the stable UDP listen port.
    /// # Errors
    /// Refuses a non-root caller, a missing state directory or any failed utun, UDP bind or state update.
    pub fn up(&mut self) -> io::Result<crate::dataplane::Identity> {
        if !self.state.enabled && self.state.worker.is_some() {
            self.down()?;
        }
        if let Some(identity) = &self.state.identity {
            return Ok(identity.clone());
        }
        // The key and its rotation journal live beside the platform's public state.
        let state = self
            .state
            .path
            .as_deref()
            .and_then(Path::parent)
            .ok_or(io::ErrorKind::NotFound)?;
        let store = self.state.store.as_ref().ok_or(io::ErrorKind::NotFound)?;
        let saved_port = store.recorded_listen_port()?;
        let listen_port = H::listen_port(saved_port)?;
        let (private_key, public_key) = if let Some(rotation) = store.rotation_secret()? {
            let (journal_key, journal_public) = recover_rotation_key(store, &rotation)?;
            let (secret, platform_public) = H::Store::open_private(state)?;
            if platform_public != journal_public
                || RotationKey::from_private(journal_key.private_bytes())?.1 != journal_public
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            (secret, journal_public)
        } else {
            if store.recorded_interface()?.is_some() && store.load_private()?.is_none() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let (secret, platform_public) = H::Store::open_private(state)?;
            let bytes = store.load_private()?.ok_or(io::ErrorKind::NotFound)?;
            let (_, file_public) = RotationKey::from_private(&bytes)?;
            if file_public != platform_public {
                return Err(io::ErrorKind::InvalidData.into());
            }
            match store.recorded_interface()? {
                Some(recorded) if recorded != file_public => {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                Some(_) => {}
                None => store.record_interface(&file_public)?,
            }
            (secret, file_public)
        };
        if let Some(config) = self.state.config.as_mut()
            && let Some(bound) = config.local_key
        {
            if !snapshot_binding_is_authorized(store, bound)? {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if bound != public_key {
                config.local_key = Some(public_key);
            }
        }
        let open = H::open_tunnel()?;
        let desired_routes = self
            .state
            .config
            .as_ref()
            .map_or_else(BTreeSet::new, H::route_addresses);
        if let Some(config) = &self.state.config {
            validate_underlay_routes(config, &desired_routes)?;
        }
        let startup = PendingWorker::<H>::begin(
            open,
            private_key,
            listen_port,
            self.state.config.clone(),
            desired_routes.clone(),
            H::probe_paths(self.state.config.as_ref()),
            self.state.network_status.clone(),
        )?;
        let info = startup.info().clone();
        let saved_port = if listen_port.allow_fallback {
            info.port
        } else {
            crate::listen_port::DEFAULT_PORT
        };
        store.record_listen_port(saved_port)?;
        self.state.interface = Some(info.interface.clone());
        self.state.port = info.port;
        self.state.routes.clone_from(&desired_routes);
        self.state.enabled = true;
        self.persist(
            true,
            self.state.config.as_ref(),
            desired_routes,
            self.state.interface.clone(),
        )?;
        match startup.commit() {
            Ok((worker, started)) => {
                self.state.interface = Some(started.interface);
                self.state.port = started.port;
                self.state.routes = started.routes;
                self.state.worker = Some(worker);
            }
            Err(error) => {
                if let Some(interface) = self.state.interface.as_deref() {
                    let _ = H::remove_routes(interface, &self.state.routes);
                }
                self.state.interface = None;
                self.state.routes.clear();
                let _ = self.persist(true, self.state.config.as_ref(), BTreeSet::new(), None);
                return Err(error);
            }
        }
        let identity = crate::dataplane::Identity {
            public_key,
            port: self.state.port,
            compact_access: true,
            #[cfg(feature = "mesh-dns")]
            dns_names: true,
            // macOS GotaTun supports journaled key rotation (#367) and authenticated authority epochs.
            key_rotation: true,
            authority_epoch: true,
            rotation_continuity: true,
        };
        self.state.identity = Some(identity.clone());
        Ok(identity)
    }

    /// Start an enabled node before the coordinator reconnect loop uses its saved Mesh route.
    /// # Errors
    /// Reports node key, utun, persistent state, and `WireGuard` setup errors.
    pub fn ensure(&mut self) -> io::Result<Option<crate::dataplane::Identity>> {
        if self.state.enabled {
            self.up().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Return the identity only while this node owns a running `GotaTun` worker and utun.
    /// # Errors
    /// Refuses rotation when the node or its live interface is unavailable.
    fn rotation_identity(&self) -> io::Result<crate::dataplane::Identity> {
        if !self.state.enabled || self.state.worker.is_none() || self.state.interface.is_none() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        self.state
            .identity
            .clone()
            .ok_or(io::ErrorKind::NotConnected.into())
    }

    /// Settle an older open journal before accepting a higher coordinator sequence.
    ///
    /// The active identity is authoritative after a superseded operation: an accepted candidate
    /// is retained, while an uncommitted predecessor stays selected and the unused candidate is
    /// erased from the completion marker.
    /// # Errors
    /// Refuses a journal that does not describe the active key or any failed durable update.
    fn settle_superseded_rotation(
        &mut self,
        rotation: &crate::node_state::RotationSecret,
    ) -> io::Result<()> {
        if rotation.completed {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let current = self.rotation_identity()?.public_key;
        let store = self
            .state
            .store
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?;
        validate_rotation_proof(store, rotation, current)?;
        let (candidate, candidate_public) = RotationKey::from_private(&rotation.candidate)?;
        let (_, previous_public) = RotationKey::from_private(&rotation.previous)?;
        if rotation.commit_requested && current == candidate_public {
            store.record_rotation_identity(
                &rotation.operation_id,
                rotation.sequence,
                candidate.private_bytes(),
                &candidate_public,
            )?;
            if let Some(identity) = self.state.identity.as_mut() {
                identity.public_key = candidate_public;
            }
            if let Some(config) = self.state.config.as_mut() {
                config.local_key = Some(candidate_public);
            }
            store.complete_rotation_secret(&rotation.operation_id, rotation.sequence)?;
        } else if current == previous_public {
            store.save_rotation_secret(&crate::node_state::RotationSecret {
                operation_id: rotation.operation_id.clone(),
                sequence: rotation.sequence,
                previous: previous_public.0,
                candidate: rotation.previous,
                commit_requested: true,
                completed: true,
            })?;
        } else {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }

    /// Prepare a local Mac identity without changing the live `GotaTun` worker (#285, D166).
    /// The predecessor and candidate are durable before the coordinator may publish overlap.
    /// # Errors
    /// Refuses an inactive node, invalid request, conflicting operation, unsafe state or failed write.
    pub fn prepare_rotation(
        &mut self,
        operation_id: &str,
        sequence: u64,
    ) -> io::Result<crate::policy::model::PublicKey> {
        if !valid_rotation_request(operation_id, sequence) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let current = self.rotation_identity()?.public_key;
        let store = self
            .state
            .store
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?;
        let existing = store.rotation_secret()?;
        if let Some(existing) = existing.as_ref() {
            if existing.completed {
                validate_rotation_proof(store, existing, current)?;
                let completed_key = RotationKey::from_private(&existing.candidate)?.1;
                if current != completed_key
                    || existing.operation_id == operation_id
                    || sequence <= existing.sequence
                {
                    return Err(io::ErrorKind::InvalidData.into());
                }
            } else if existing.operation_id == operation_id && existing.sequence == sequence {
                validate_rotation_proof(store, existing, current)?;
                return Ok(RotationKey::from_private(&existing.candidate)?.1);
            } else if existing.operation_id != operation_id && sequence > existing.sequence {
                self.settle_superseded_rotation(existing)?;
            } else {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }

        let existing = self
            .state
            .store
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .rotation_secret()?;
        if let Some(existing) = existing.as_ref() {
            let current = self.rotation_identity()?.public_key;
            validate_rotation_proof(
                self.state
                    .store
                    .as_ref()
                    .ok_or(io::ErrorKind::NotConnected)?,
                existing,
                current,
            )?;
            if !existing.completed
                || existing.operation_id == operation_id
                || sequence <= existing.sequence
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }

        let store = self
            .state
            .store
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?;
        let private = store.load_private()?.ok_or(io::ErrorKind::InvalidData)?;
        let (previous, previous_public) = RotationKey::from_private(&private)?;
        if previous_public != current || store.recorded_interface()? != Some(current) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let (candidate, candidate_public) = loop {
            let pair = RotationKey::generate()?;
            if pair.1 != previous_public {
                break pair;
            }
        };
        store.save_rotation_secret(&crate::node_state::RotationSecret {
            operation_id: operation_id.to_owned(),
            sequence,
            previous: previous
                .private_bytes()
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidData)?,
            candidate: candidate
                .private_bytes()
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidData)?,
            commit_requested: false,
            completed: false,
        })?;
        H::rotation_checkpoint("rotation_prepared");
        Ok(candidate_public)
    }

    /// Commit the candidate after durably recording intent and changing the live worker key.
    /// Retries complete the identity record and key file after any process stop.
    /// # Errors
    /// Refuses a stale operation, an unproven key or any failed worker or durable update.
    pub fn commit_rotation(
        &mut self,
        operation_id: &str,
        sequence: u64,
    ) -> io::Result<crate::dataplane::Identity> {
        let mut identity = self.rotation_identity()?;
        let store = self
            .state
            .store
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?;
        let mut rotation = store.rotation_secret()?.ok_or(io::ErrorKind::NotFound)?;
        if rotation.operation_id != operation_id || rotation.sequence != sequence {
            return Err(io::ErrorKind::InvalidData.into());
        }
        validate_rotation_proof(store, &rotation, identity.public_key)?;
        let (candidate, candidate_public) = RotationKey::from_private(&rotation.candidate)?;
        if rotation.completed {
            return Ok(identity);
        }
        let previous_public = RotationKey::from_private(&rotation.previous)?.1;
        if identity.public_key == previous_public {
            if !rotation.commit_requested {
                rotation.commit_requested = true;
                store.save_rotation_secret(&rotation)?;
                H::rotation_checkpoint("rotation_commit_requested");
            }
            self.state
                .worker
                .as_ref()
                .ok_or(io::ErrorKind::NotConnected)?
                .set_private_key(candidate.gotatun_secret())?;
            identity.public_key = candidate_public;
            self.state.identity = Some(identity.clone());
            H::rotation_checkpoint("rotation_device_key_changed");
        } else if identity.public_key != candidate_public || !rotation.commit_requested {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if let Some(config) = self.state.config.as_mut() {
            config.local_key = Some(candidate_public);
        }
        store.record_rotation_identity(
            operation_id,
            sequence,
            candidate.private_bytes(),
            &candidate_public,
        )?;
        Ok(self
            .state
            .identity
            .clone()
            .ok_or(io::ErrorKind::NotConnected)?)
    }

    /// Finish an acknowledged rotation after saving its new local binding.
    /// The retained journal makes completion safe to retry and clears predecessor private bytes.
    /// # Errors
    /// Refuses a stale or uncommitted operation, an identity mismatch or a failed durable write.
    pub fn finish_rotation(&mut self, operation_id: &str, sequence: u64) -> io::Result<()> {
        let identity = self.rotation_identity()?;
        let store = self
            .state
            .store
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?;
        let rotation = store.rotation_secret()?.ok_or(io::ErrorKind::NotFound)?;
        if rotation.operation_id != operation_id || rotation.sequence != sequence {
            return Err(io::ErrorKind::InvalidData.into());
        }
        validate_rotation_proof(store, &rotation, identity.public_key)?;
        let candidate_public = RotationKey::from_private(&rotation.candidate)?.1;
        if identity.public_key != candidate_public
            || (!rotation.completed && !rotation.commit_requested)
            || store.recorded_interface()? != Some(candidate_public)
            || store
                .load_private()?
                .map(|private| RotationKey::from_private(&private).map(|(_, public)| public))
                .transpose()?
                != Some(candidate_public)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if let Some(config) = self.state.config.as_mut() {
            config.local_key = Some(candidate_public);
        }
        store.complete_rotation_secret(operation_id, sequence)?;
        H::rotation_checkpoint("rotation_finished");
        Ok(())
    }
    /// Persist disabled intent before retiring routes and the owned utun descriptor.
    /// # Errors
    /// Keeps the old route inventory when cleanup cannot be completed.
    pub fn down(&mut self) -> io::Result<()> {
        self.persist(
            false,
            self.state.config.as_ref(),
            self.state.routes.clone(),
            self.state.interface.clone(),
        )?;
        self.state.enabled = false;
        if let Some(worker) = self.state.worker.as_mut() {
            worker.stop()?;
        }
        self.state.worker = None;
        self.state.identity = None;
        self.state.config = None;
        self.state.authority_reset_pending = false;
        self.state.pending = None;
        self.state.routes.clear();
        self.state.interface = None;
        self.persist(false, None, BTreeSet::new(), None)
    }

    /// Whether the route to `network`, reachable through a router peer, is on the utun, and why
    /// not, for `mesh routes` (D197 M3).
    #[must_use]
    pub fn network_route_state(
        &self,
        network: crate::policy::networks::Network,
    ) -> serde_json::Value {
        H::network_route_state(&self.state.network_status, network)
    }

    /// Read current `GotaTun` peer counters without exposing private key material.
    /// # Errors
    /// Reports an unavailable worker thread.
    pub fn counters(&self) -> io::Result<BTreeMap<crate::policy::model::PublicKey, Counters>> {
        self.state
            .worker
            .as_ref()
            .map_or_else(|| Ok(CounterMap::new()), Worker::counters)
    }

    /// Apply only a complete, authenticated configuration revision and persist its public intent.
    /// # Errors
    /// Refuses wrong identity bindings, incomplete chunks, unsafe routes, or failed engine updates.
    pub fn chunk(&mut self, chunk: crate::dataplane::Chunk) -> io::Result<bool> {
        let Some(identity) = self.state.identity.clone() else {
            self.state.pending = None;
            tracing::warn!("Mac mesh configuration chunk refused while the node is not up");
            return Err(io::ErrorKind::NotConnected.into());
        };
        if !self.state.enabled
            || self.state.worker.is_none()
            || chunk.local_key != Some(identity.public_key)
        {
            self.state.pending = None;
            tracing::warn!(
                error_kind = ?io::ErrorKind::InvalidData,
                "Mac mesh configuration chunk refused"
            );
            return Err(io::ErrorKind::InvalidData.into());
        }
        if chunk
            .authority_epoch
            .as_deref()
            .is_some_and(|epoch| !crate::dataplane::valid_authority_epoch(epoch))
        {
            self.state.pending = None;
            tracing::warn!("Mac mesh configuration chunk refused: authority epoch is malformed");
            return Err(io::ErrorKind::InvalidData.into());
        }
        let authority_changed = needs_authority_reset(self.state.config.as_ref(), &chunk);
        if authority_changed {
            let old_epoch = self
                .state
                .config
                .as_ref()
                .and_then(|old| old.authority_epoch.as_deref());
            if old_epoch.is_some() && chunk.authority_epoch.is_none() && chunk.index == 0 {
                // A server rolled back to a release without epochs (D295) is one more authority
                // change: its full snapshot replaces the old peer set like any other (#382 P2).
                tracing::warn!(
                    old_epoch,
                    "Mac mesh server stopped sending an authority epoch, likely a rollback; adopting its full snapshot"
                );
            }
            let pending_new_authority = self.state.pending.as_ref().is_some_and(|pending| {
                pending.continues_authority(chunk.authority_epoch.as_deref())
            });
            if chunk.index == 0 {
                if chunk.from_version.is_some() {
                    self.state.pending = None;
                    tracing::warn!(
                        "Mac mesh configuration chunk refused: a new authority must start with a full snapshot"
                    );
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.state.pending = None;
                tracing::warn!(
                    old_epoch = ?old_epoch,
                    new_epoch = ?chunk.authority_epoch,
                    old_version = ?self.state.config.as_ref().map(|config| config.version),
                    new_version = chunk.version,
                    "staging a full Mac mesh snapshot from the changed authority"
                );
            } else if !pending_new_authority {
                self.state.pending = None;
                tracing::warn!(
                    "Mac mesh configuration chunk refused: a new authority must start with a full snapshot"
                );
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        if self.state.authority_reset_pending && chunk.from_version.is_some() {
            self.state.pending = None;
            tracing::warn!(
                error_kind = ?io::ErrorKind::InvalidData,
                "Mac mesh configuration chunk refused: an authority reset needs a full snapshot"
            );
            return Err(io::ErrorKind::InvalidData.into());
        }
        // With a Store, a lower same-epoch revision is accepted on purpose: a database restored
        // under a running server keeps its epoch but rewinds revisions (#382, J418 P3-a). The
        // exact-base write (`write_public_state_full_snapshot`) keeps that swap atomic.
        let result = stage_chunk(
            &mut self.state.pending,
            self.state.config.as_ref(),
            &identity,
            self.state.store.is_some() || self.state.authority_reset_pending,
            chunk,
        );
        if let Err(error) = &result {
            self.state.pending = None;
            tracing::warn!(
                error_kind = ?error.kind(),
                "Mac mesh configuration chunk refused"
            );
        }
        let Some(config) = result? else {
            return Ok(false);
        };
        let validation = (|| {
            validate_config(&config, identity.public_key)?;
            // A complete snapshot may replay its revision only with identical contents. Authority
            // reset is handled separately because the new epoch may reuse a revision.
            if !self.state.authority_reset_pending
                && self.state.config.as_ref().is_some_and(|accepted| {
                    accepted.authority_epoch == config.authority_epoch
                        && accepted.version == config.version
                        && !crate::dataplane::same_runtime_content(accepted, &config)
                })
            {
                tracing::warn!(
                    authority_epoch = ?config.authority_epoch,
                    version = config.version,
                    "Mac mesh configuration conflict at an accepted authority revision"
                );
                return Err(io::ErrorKind::InvalidData.into());
            }
            if self
                .state
                .config
                .as_ref()
                .is_some_and(|old| old.node == config.node && old.addresses != config.addresses)
            {
                return Err(io::ErrorKind::Unsupported.into());
            }
            let desired_routes = H::route_addresses(&config);
            validate_underlay_routes(&config, &desired_routes)?;
            if authority_changed || self.state.authority_reset_pending {
                #[cfg(feature = "mesh-dns")]
                crate::dns::Records::from_config(&config)?;
                PacketFilter::prepare_policy(&config, MeshProxyIngress::default())?;
            }
            Ok::<_, io::Error>(desired_routes)
        })();
        let desired_routes = match validation {
            Ok(routes) => routes,
            Err(error) if authority_changed => {
                return self.stop_after_retirement_failure(error, &config);
            }
            Err(error) => return Err(error),
        };
        // Preserve the receipt through incomplete or rejected snapshots. Only the fully
        // validated incoming operation can authorize continuity or journal retirement.
        if authority_changed {
            self.prepare_authority_replacement(&config)?;
        } else if self.state.authority_reset_pending {
            self.retire_settled_authority_rotation(config.rotation_operation.as_ref())?;
        }
        let completes_authority_reset = self.state.authority_reset_pending;
        let reset_config = completes_authority_reset
            .then(|| self.state.config.clone())
            .flatten();
        if completes_authority_reset {
            self.state.authority_reset_pending = false;
        }
        let lower_revision_base = (!completes_authority_reset)
            .then(|| {
                self.state
                    .config
                    .as_ref()
                    .filter(|old| {
                        old.authority_epoch == config.authority_epoch
                            && config.version < old.version
                    })
                    .cloned()
            })
            .flatten();
        let mut cleanup_routes = self.state.routes.clone();
        cleanup_routes.extend(desired_routes.iter().copied());
        let persistence = if let Some(base) = lower_revision_base.as_ref() {
            self.persist_full_snapshot(&config, cleanup_routes, self.state.interface.clone(), base)
        } else {
            self.persist(
                true,
                Some(&config),
                cleanup_routes,
                self.state.interface.clone(),
            )
        };
        if let Err(error) = persistence {
            if let Some(denied) = reset_config.as_ref() {
                self.state.authority_reset_pending = true;
                return self.stop_after_retirement_failure(error, denied);
            }
            return Err(error);
        }
        let applied = self
            .state
            .worker
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
            .and_then(|worker| {
                if reset_config.is_some() {
                    worker.replace_authority(config.clone())
                } else {
                    worker.apply(config.clone())
                }
            });
        let info = match applied {
            Ok(info) => info,
            Err(error) => {
                if let Some(denied) = reset_config.as_ref() {
                    self.state.authority_reset_pending = true;
                    return self.stop_after_retirement_failure(error, denied);
                }
                return Err(error);
            }
        };
        self.state.config = Some(config);
        self.state.routes = info.routes;
        self.state.interface = Some(info.interface);
        self.state.port = info.port;
        self.persist(
            true,
            self.state.config.as_ref(),
            self.state.routes.clone(),
            self.state.interface.clone(),
        )?;
        Ok(true)
    }

    /// Persist a complete authority change while leaving the current Mac peers untouched.
    ///
    /// The full replacement has already been authenticated and staged. This peer-free durable
    /// checkpoint is therefore crash-safe, while the serialized worker receives the complete
    /// replacement only after the checkpoint succeeds. Only an exact operation match retains
    /// the rotation journal for commit or finish retries.
    /// # Errors
    /// Stops the worker if snapshot persistence or rotation-journal retirement fails.
    fn prepare_authority_replacement(&mut self, replacement: &Config) -> io::Result<()> {
        let mut denied = replacement.clone();
        denied.default_policy = crate::dataplane::DefaultPolicy::Deny;
        denied.peers.clear();
        #[cfg(feature = "mesh-dns")]
        denied.peer_names.clear();
        self.state.pending = None;
        let continuity = self
            .state
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
        if let Some(identity) = &self.state.identity {
            denied.local_key = Some(identity.public_key);
        }
        self.state.config = Some(denied.clone());
        self.state.authority_reset_pending = true;
        let persistence_error = self.persist_retired_snapshot(&denied).err();
        let journal_error =
            if persistence_error.is_none() && rotation_error.is_none() && !continues_rotation {
                self.state
                    .store
                    .as_ref()
                    .map(NodeStore::discard_rotation_journal)
                    .transpose()
                    .err()
            } else {
                None
            };
        if let Some(error) = persistence_error.or(rotation_error).or(journal_error) {
            return self.stop_after_retirement_failure(error, &denied);
        }
        H::authority_replacement_checkpoint();
        Ok(())
    }

    /// Settle an open rotation on the active Mac key before retiring the old authority journal.
    ///
    /// The journal sequence belongs to the previous server. The current worker key and private key
    /// file remain the enrolled machine identity, so they stay selected while the journal is erased.
    /// # Errors
    /// Refuses an unproven key transition or a failed durable update.
    fn settle_authority_rotation(&mut self) -> io::Result<()> {
        let Some(store) = &self.state.store else {
            return Ok(());
        };
        let Some(rotation) = store.rotation_secret()? else {
            return Ok(());
        };
        let current = self.rotation_identity()?.public_key;
        validate_rotation_proof(store, &rotation, current)?;
        if !rotation.completed {
            self.settle_superseded_rotation(&rotation)?;
        }
        if let (Some(config), Some(identity)) = (&mut self.state.config, &self.state.identity) {
            config.local_key = Some(identity.public_key);
        }
        Ok(())
    }

    /// Retry journal retirement after validating a full snapshot for an interrupted reset.
    ///
    /// The peer-free reset record makes startup safe. This retry saves the settled live key binding
    /// before removing the previous authority's rotation journal. An exact operation match from
    /// the incoming full snapshot retains it; cached metadata alone never proves continuity.
    /// # Errors
    /// Refuses a journal that does not prove the active key or a failed state write.
    fn retire_settled_authority_rotation(
        &mut self,
        operation: Option<&crate::dataplane::RotationContinuation>,
    ) -> io::Result<()> {
        let Some(store) = &self.state.store else {
            return Ok(());
        };
        if store.rotation_secret()?.is_none() || store.rotation_matches(operation)? {
            return Ok(());
        }
        self.settle_authority_rotation()?;
        let config = self
            .state
            .config
            .clone()
            .ok_or(io::ErrorKind::InvalidData)?;
        self.persist(
            self.state.enabled,
            Some(&config),
            self.state.routes.clone(),
            self.state.interface.clone(),
        )?;
        self.state
            .store
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .discard_rotation_journal()
    }

    /// Persist peer-free authority state before the Mac worker removes old peers.
    /// # Errors
    /// Reports when neither atomic replacement nor the in-place fail-closed write succeeds.
    fn persist_retired_snapshot(&self, denied: &Config) -> io::Result<()> {
        let Some(path) = &self.state.path else {
            return Ok(());
        };
        let state = SavedState {
            enabled: self.state.enabled,
            config: Some(denied.clone()),
            authority_reset_pending: true,
            routes: self.state.routes.clone(),
            interface: self.state.interface.clone(),
            port: self.state.port,
            backend: None,
            binding: self.state.binding.clone(),
        };
        match H::Store::store_public(path, &state) {
            Ok(()) => Ok(()),
            Err(atomic_error) => H::Store::fence_public(path, &state).inspect_err(|error| {
                tracing::error!(
                    atomic_error_kind = ?atomic_error.kind(),
                    fallback_error_kind = ?error.kind(),
                    "atomic and in-place peer-free Mac state writes both failed before retirement"
                );
            }),
        }
    }

    /// Stop the node without restoring peers when a retirement step cannot be completed.
    /// # Errors
    /// Returns the reset cause unless shutdown reports a more immediate failure.
    fn stop_after_retirement_failure<T>(
        &mut self,
        reset_error: io::Error,
        denied: &Config,
    ) -> io::Result<T> {
        // A complete but rejected new authority retires peers without retiring its receipt.
        let mut denied = denied.clone();
        denied.default_policy = crate::dataplane::DefaultPolicy::Deny;
        denied.peers.clear();
        #[cfg(feature = "mesh-dns")]
        denied.peer_names.clear();
        // Fence restore first; the disabled write below retries any failure.
        let _ = self.persist_retired_snapshot(&denied);
        self.state.enabled = false;
        let stop_result = self
            .state
            .worker
            .take()
            .map_or(Ok(()), |mut worker| worker.stop());
        self.state.identity = None;
        self.state.config = Some(denied.clone());
        self.state.authority_reset_pending = true;
        self.state.pending = None;
        self.state.routes.clear();
        self.state.interface = None;
        let state = SavedState {
            enabled: false,
            config: Some(denied.clone()),
            authority_reset_pending: true,
            routes: BTreeSet::new(),
            interface: None,
            port: self.state.port,
            backend: None,
            binding: self.state.binding.clone(),
        };
        let persistence = self.state.path.as_ref().map_or(Ok(()), |path| {
            match H::Store::store_public(path, &state) {
                Ok(()) => Ok(()),
                Err(atomic_error) => H::Store::fence_public(path, &state).inspect_err(|error| {
                    tracing::error!(
                        atomic_error_kind = ?atomic_error.kind(),
                        fallback_error_kind = ?error.kind(),
                        "could not persist peer-free disabled Mac mesh state after retirement failed"
                    );
                }),
            }
        });
        if let Err(error) = persistence {
            tracing::error!(
                error_kind = ?error.kind(),
                "could not persist stopped Mac mesh state after peer retirement failed"
            );
        }
        match stop_result {
            Ok(()) => {
                tracing::warn!(
                    error_kind = ?reset_error.kind(),
                    "Mac mesh stopped because stale peers could not be retired"
                );
                Err(reset_error)
            }
            Err(stop_error) => {
                tracing::error!(
                    reset_error_kind = ?reset_error.kind(),
                    stop_error_kind = ?stop_error.kind(),
                    "Mac mesh peer retirement and fail-closed shutdown both failed"
                );
                Err(stop_error)
            }
        }
    }

    /// Save enabled state, accepted public config, and route ownership for restart recovery.
    fn persist(
        &self,
        enabled: bool,
        config: Option<&Config>,
        routes: BTreeSet<IpAddr>,
        interface: Option<String>,
    ) -> io::Result<()> {
        if let Some(path) = &self.state.path {
            H::Store::store_public(
                path,
                &SavedState {
                    enabled,
                    config: config.cloned(),
                    authority_reset_pending: self.state.authority_reset_pending,
                    routes,
                    interface,
                    port: self.state.port,
                    backend: None,
                    binding: self.state.binding.clone(),
                },
            )?;
        }
        Ok(())
    }

    /// Save a lower-revision full snapshot only against the exact accepted durable base.
    ///
    /// This Store-backed compare-and-set is the explicit same-authority replacement transaction;
    /// an in-memory config alone cannot authorize lowering the revision fence.
    /// # Errors
    /// Refuses an absent or changed base and reports failed durable writes.
    fn persist_full_snapshot(
        &self,
        config: &Config,
        routes: BTreeSet<IpAddr>,
        interface: Option<String>,
        expected: &Config,
    ) -> io::Result<()> {
        let path = self.state.path.as_ref().ok_or(io::ErrorKind::InvalidData)?;
        H::Store::replace_public(
            path,
            &SavedState {
                enabled: true,
                config: Some(config.clone()),
                authority_reset_pending: self.state.authority_reset_pending,
                routes,
                interface,
                port: self.state.port,
                backend: None,
                binding: self.state.binding.clone(),
            },
            expected,
        )
    }
}

/// Check the local identity and the uniqueness of peer keys and addresses.
/// # Errors
/// Refuses inconsistent peer identity or conflicting addresses.
pub fn validate_config(
    config: &Config,
    identity: crate::policy::model::PublicKey,
) -> io::Result<()> {
    if config.local_key != Some(identity) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut keys = BTreeSet::new();
    let mut ipv4 = BTreeSet::new();
    let mut ipv6 = BTreeSet::new();
    for (node, peer) in &config.peers {
        if *node == config.node
            || peer.peer.key == identity
            || !keys.insert(peer.peer.key)
            || peer.peer.addresses.ipv4 == config.addresses.ipv4
            || peer.peer.addresses.ipv6 == config.addresses.ipv6
            || !ipv4.insert(peer.peer.addresses.ipv4)
            || !ipv6.insert(peer.peer.addresses.ipv6)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok(())
}
