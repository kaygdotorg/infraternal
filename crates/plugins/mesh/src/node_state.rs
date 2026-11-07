//! Persists accepted public node intent, engine identity records and journaled key rotation
//! [166,198]. Kernel `WireGuard` keeps its key in kernel memory; Linux and Mac `GotaTun` keep it in
//! a private 0600 file. That key never leaves its node (D163), so backups (D147: database, CA key,
//! configuration) must never include this directory's private Mesh key. A clean `down` or host
//! uninstall retires the key, interface record and rotation journal, so a later `up` starts with a
//! fresh identity (#260, #367).
use crate::dataplane::Config;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};
use zeroize::{Zeroize, Zeroizing};
/// The accepted public mesh snapshot saved for restart, with a firewall choice on Linux.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub enabled: bool,
    pub config: Option<Config>,
    #[serde(default)]
    #[cfg(target_os = "linux")]
    pub backend: Option<crate::firewall::Backend>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            enabled: true,
            config: None,
            #[cfg(target_os = "linux")]
            backend: None,
        }
    }
}
/// One node's durable local state: public snapshot, routes, identity record, private key and rotation journal.
pub struct Store {
    path: PathBuf,
    route_path: PathBuf,
    // The key of the interface this installation created (#235). It lives in
    // its own file so the accepted snapshot keeps the format older binaries
    // read; a rollback never meets an unknown field.
    interface_path: PathBuf,
    // Pending local rotation keys are separate from the public snapshot and are
    // readable only by this installation's effective UID.
    rotation_path: PathBuf,
    #[cfg(target_os = "linux")]
    engine_path: PathBuf,
    key_path: PathBuf,
    // Canonical public bytes avoid repeated journal fsyncs on endpoint updates
    // without retaining a second per-peer tree. No private material is cached.
    route_body: Mutex<Vec<u8>>,
}

/// A locally retained old/candidate pair makes an interrupted key switch retryable.
/// The fixed-size binary record never enters diagnostics or the public snapshot.
pub(crate) struct RotationSecret {
    pub(crate) operation_id: String,
    pub(crate) sequence: u64,
    pub(crate) previous: [u8; 32],
    pub(crate) candidate: [u8; 32],
    pub(crate) commit_requested: bool,
    /// The candidate is now the retained interface key and the predecessor is erased.
    pub(crate) completed: bool,
}
impl Drop for RotationSecret {
    fn drop(&mut self) {
        self.previous.zeroize();
        self.candidate.zeroize();
    }
}

/// Marks the private rotation-secret file format, version 1.
const ROTATION_MAGIC: &[u8; 8] = b"IMKEYV1\0";
/// Exact size of that file: magic, phase, sequence, operation ID, previous and candidate private keys.
const ROTATION_FIXED_BYTES: usize = 8 + 1 + 8 + 36 + 32 + 32;

/// A canonical hyphenated UUID text, the only operation ID the secret file accepts.
fn valid_operation_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}
impl Store {
    /// Read an owned private directory's public snapshot without following symlinks.
    /// # Errors
    /// Refuses ownership/mode changes, invalid snapshots or filesystem errors.
    pub fn open(parent: &Path) -> io::Result<(Self, State)> {
        let meta = fs::symlink_metadata(parent)?;
        if !meta.is_dir()
            || meta.uid() != nix::unistd::Uid::effective().as_raw()
            || meta.mode() & 0o077 != 0
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let path = parent.join("mesh-public.json");
        let route_path = parent.join("mesh-routes.json");
        let interface_path = parent.join("mesh-interface.json");
        let rotation_path = parent.join("mesh-key-rotation.bin");
        #[cfg(target_os = "linux")]
        let engine_path = parent.join("mesh-engine.json");
        let key_path = parent.join("mesh-private-key");
        sweep_private_temporaries(&key_path)?;
        let state = read_public(&path)?.unwrap_or_default();
        let routes: BTreeSet<IpAddr> = read_public(&route_path)?.unwrap_or_default();
        let route_body = serde_json::to_vec(&routes).map_err(io::Error::other)?;
        Ok((
            Self {
                path,
                route_path,
                interface_path,
                rotation_path,
                #[cfg(target_os = "linux")]
                engine_path,
                key_path,
                route_body: Mutex::new(route_body),
            },
            state,
        ))
    }

    /// Open the shared journal beside the Mac public snapshot without decoding that platform's state.
    ///
    /// Mac and Linux use the same durable rotation files, while their public snapshots have
    /// different schemas. The Mac constructor binds the shared store to `mesh-wireguard.key`.
    /// # Errors
    /// Refuses an unsafe state directory or key-file temporary.
    #[cfg(target_os = "macos")]
    pub(crate) fn open_for_macos(parent: &Path) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let key_path = parent.join(crate::macos_key::KEY_FILE);
        sweep_private_temporaries(&key_path)?;
        let route_body =
            serde_json::to_vec(&BTreeSet::<IpAddr>::new()).map_err(io::Error::other)?;
        Ok(Self {
            path: parent.join("mesh-public.json"),
            route_path: parent.join("mesh-routes.json"),
            interface_path: parent.join("mesh-interface.json"),
            rotation_path: parent.join("mesh-key-rotation.bin"),
            key_path,
            route_body: Mutex::new(route_body),
        })
    }
    /// Read only the public host addresses recorded before kernel mutation.
    /// # Errors
    /// Refuses a poisoned cache or invalid journal without changing kernel state.
    pub fn route_inventory(&self) -> io::Result<BTreeSet<IpAddr>> {
        let body = self.route_body.lock().map_err(|_| io::ErrorKind::Other)?;
        serde_json::from_slice(&body).map_err(io::Error::other)
    }
    /// Record the public key this installation owns or is about to create.
    ///
    /// Initial creation writes before the kernel object exists, so every
    /// interface this installation made is named here. Rotation updates this
    /// marker only after the kernel accepts the candidate key. The fixed
    /// interface name and component marker are shared by every infraternal
    /// agent on a machine (the server's embedded one joins the same mesh);
    /// only this random key tells this installation's interface apart (#235).
    /// # Errors
    /// Uses the same private-file checks and atomic durable writer as `save`.
    pub fn record_interface(&self, key: &crate::policy::model::PublicKey) -> io::Result<()> {
        write_public(
            &self.interface_path,
            &serde_json::to_vec(key).map_err(io::Error::other)?,
        )
    }
    /// The key of the interface this installation last created, if any.
    /// # Errors
    /// Refuses an unsafe or malformed record.
    pub fn recorded_interface(&self) -> io::Result<Option<crate::policy::model::PublicKey>> {
        read_public(&self.interface_path)
    }

    /// Persist a candidate key and interface identity as one journal-authorized store operation.
    ///
    /// The interface record is written first. During either half of the update, the open journal
    /// proves both possible identities and startup completes the operation before opening a link.
    /// # Errors
    /// Refuses a stale operation or a candidate that is not the journaled private key.
    #[cfg(target_os = "macos")]
    pub(crate) fn record_rotation_identity(
        &self,
        operation_id: &str,
        sequence: u64,
        private_key: &[u8],
        public_key: &crate::policy::model::PublicKey,
    ) -> io::Result<()> {
        let rotation = self.rotation_secret()?.ok_or(io::ErrorKind::NotFound)?;
        let candidate_private = Zeroizing::new(rotation.candidate);
        let candidate_secret = gotatun::x25519::StaticSecret::from(*candidate_private);
        let candidate_public = crate::policy::model::PublicKey(
            *gotatun::x25519::PublicKey::from(&candidate_secret).as_bytes(),
        );
        if rotation.operation_id != operation_id
            || rotation.sequence != sequence
            || !rotation.commit_requested
            || rotation.completed
            || private_key != &candidate_private[..]
            || candidate_public != *public_key
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.record_interface(public_key)?;
        #[cfg(all(test, target_os = "macos"))]
        crate::macos_node::rotation_crash_checkpoint("rotation_interface_recorded");
        self.replace_private_key(private_key)?;
        #[cfg(all(test, target_os = "macos"))]
        crate::macos_node::rotation_crash_checkpoint("rotation_private_key_saved");
        Ok(())
    }

    /// Remove the saved interface identity and rotation journal when this node forgets or retires its mesh identity.
    ///
    /// Call after the engine has stopped; `remove_private_key` separately retires its key file.
    /// # Errors
    /// Refuses unsafe records and reports failed removals or directory syncs.
    pub(crate) fn discard_rotation_state(&self) -> io::Result<()> {
        let mut removed = false;
        for path in [&self.rotation_path, &self.interface_path] {
            match fs::symlink_metadata(path) {
                Ok(metadata)
                    if metadata.is_file()
                        && metadata.uid() == nix::unistd::Uid::effective().as_raw()
                        && metadata.mode() & 0o777 == 0o600 =>
                {
                    fs::remove_file(path)?;
                    removed = true;
                }
                Ok(_) => return Err(io::ErrorKind::PermissionDenied.into()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        if removed {
            FileSync::parent(&self.rotation_path)?;
        }
        Ok(())
    }

    /// Read a pending key pair or completed-operation marker from a private, no-follow file.
    /// # Errors
    /// Refuses unsafe ownership, modes, lengths, operation IDs or key-state encodings.
    pub(crate) fn rotation_secret(&self) -> io::Result<Option<RotationSecret>> {
        use std::os::unix::fs::MetadataExt;
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&self.rotation_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() != u64::try_from(ROTATION_FIXED_BYTES).unwrap_or(u64::MAX)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(ROTATION_FIXED_BYTES));
        file.read_to_end(&mut bytes)?;
        if bytes.len() != ROTATION_FIXED_BYTES || &bytes[..8] != ROTATION_MAGIC {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let phase = bytes[8];
        let sequence = u64::from_le_bytes(
            bytes[9..17]
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidData)?,
        );
        let operation_id = std::str::from_utf8(&bytes[17..53])
            .map_err(|_| io::ErrorKind::InvalidData)?
            .to_owned();
        if phase > 2 || sequence == 0 || !valid_operation_id(&operation_id) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let previous = bytes[53..85]
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?;
        let candidate = bytes[85..117]
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?;
        if phase == 2 && previous != [0; 32] {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Some(RotationSecret {
            operation_id,
            sequence,
            previous,
            candidate,
            commit_requested: phase >= 1,
            completed: phase == 2,
        }))
    }
    /// Durably replace the pending key pair before a server can publish its candidate.
    /// # Errors
    /// Refuses malformed state, unsafe paths or failed fsync/rename.
    pub(crate) fn save_rotation_secret(&self, state: &RotationSecret) -> io::Result<()> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if state.sequence == 0
            || !valid_operation_id(&state.operation_id)
            || (state.completed && (!state.commit_requested || state.previous != [0; 32]))
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.rotation_path)
            && (!metadata.is_file()
                || metadata.uid() != nix::unistd::Uid::effective().as_raw()
                || metadata.mode() & 0o777 != 0o600)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(ROTATION_FIXED_BYTES));
        bytes.extend_from_slice(ROTATION_MAGIC);
        bytes.push(if state.completed {
            2
        } else {
            u8::from(state.commit_requested)
        });
        bytes.extend_from_slice(&state.sequence.to_le_bytes());
        bytes.extend_from_slice(state.operation_id.as_bytes());
        bytes.extend_from_slice(&state.previous);
        bytes.extend_from_slice(&state.candidate);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let temporary = self.rotation_path.with_extension(format!(
            "{}.{}.{}.new",
            std::process::id(),
            nonce,
            ROTATION_MAGIC[6]
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.rotation_path)?;
            fs::File::open(
                self.rotation_path
                    .parent()
                    .ok_or(io::ErrorKind::InvalidInput)?,
            )?
            .sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
    /// Retire the predecessor and keep a small retry marker after server acknowledgement.
    /// # Errors
    /// Refuses a stale operation or a failed atomic durable replacement.
    pub(crate) fn complete_rotation_secret(
        &self,
        operation_id: &str,
        sequence: u64,
    ) -> io::Result<()> {
        let mut state = self.rotation_secret()?.ok_or(io::ErrorKind::NotFound)?;
        if state.operation_id != operation_id || state.sequence != sequence {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if state.completed {
            return Ok(());
        }
        if !state.commit_requested {
            return Err(io::ErrorKind::InvalidData.into());
        }
        state.previous.zeroize();
        state.completed = true;
        self.save_rotation_secret(&state)
    }
    /// Persist the selected engine separately from the legacy accepted snapshot.
    ///
    /// Both supported Linux engines use the same journal, so an engine switch must keep it with
    /// the key it describes. `switch_engine` carries the live key before changing this record.
    /// # Errors
    /// Refuses unsafe state files and reports durable-write failures.
    #[cfg(target_os = "linux")]
    pub(crate) fn record_engine(&self, engine: crate::gotatun_node::EngineKind) -> io::Result<()> {
        write_public(
            &self.engine_path,
            &serde_json::to_vec(&engine).map_err(io::Error::other)?,
        )
    }
    /// Read the selected engine, if this node has recorded one.
    /// # Errors
    /// Refuses unsafe metadata and malformed engine values.
    #[cfg(target_os = "linux")]
    pub(crate) fn recorded_engine(&self) -> io::Result<Option<crate::gotatun_node::EngineKind>> {
        read_public(&self.engine_path)
    }
    /// Create a durable private key file without replacing an existing identity.
    /// The bytes never enter the public state snapshot or a log.
    /// # Errors
    /// Refuses malformed key sizes, existing files and unsafe directory state.
    pub fn write_private_key(&self, key: &[u8]) -> io::Result<()> {
        if key.len() != 32 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
            .open(self.key_path.parent().ok_or(io::ErrorKind::InvalidInput)?)?;
        let _guard = nix::fcntl::Flock::lock(directory, nix::fcntl::FlockArg::LockExclusive)
            .map_err(|(_, error)| error)?;
        if self.key_path.exists() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        write_private(&self.key_path, key)
    }
    /// Atomically replace the private key after the rotation journal authorizes the candidate.
    ///
    /// The directory lock keeps temporary-file cleanup and another local writer from racing this
    /// replacement. The file and parent directory are synced before success is returned.
    /// # Errors
    /// Refuses malformed keys, unsafe existing files and failed durable replacements.
    pub(crate) fn replace_private_key(&self, key: &[u8]) -> io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        if key.len() != 32 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let parent = self.key_path.parent().ok_or(io::ErrorKind::InvalidInput)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
            .open(parent)?;
        let _guard = nix::fcntl::Flock::lock(directory, nix::fcntl::FlockArg::LockExclusive)
            .map_err(|(_, error)| error)?;
        if self
            .read_private_key()?
            .is_some_and(|current| current.as_slice() == key)
        {
            return Ok(());
        }
        let temporary = self
            .key_path
            .with_extension(format!("{}.new", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&temporary)?;
            file.write_all(key)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.key_path)?;
            FileSync::parent(&self.key_path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
    /// Read the private key through a checked no-follow descriptor.
    /// # Errors
    /// Refuses symlinks, wrong ownership or mode, and non-32-byte data.
    pub fn read_private_key(&self) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&self.key_path)
        {
            Ok(mut file) => {
                let metadata = file.metadata()?;
                if !metadata.is_file()
                    || metadata.uid() != nix::unistd::Uid::effective().as_raw()
                    || metadata.mode() & 0o777 != 0o600
                    || metadata.len() != 32
                {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                let mut key = Zeroizing::new(Vec::with_capacity(32));
                file.read_to_end(&mut key)?;
                if key.len() != 32 {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                Ok(Some(key))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    /// Remove the private key only after the owned userspace engine has stopped.
    /// # Errors
    /// Refuses unsafe key files and reports durable directory failures.
    pub fn remove_private_key(&self) -> io::Result<()> {
        if self.read_private_key()?.is_none() {
            return Ok(());
        }
        fs::remove_file(&self.key_path)?;
        FileSync::parent(&self.key_path)
    }
    /// Persist route ownership separately from accepting an in-flight config.
    /// # Errors
    /// Uses the same private-file checks and atomic durable writer as `save`.
    pub fn record_routes(&self, routes: &BTreeSet<IpAddr>) -> io::Result<()> {
        let body = serde_json::to_vec(routes).map_err(io::Error::other)?;
        let mut previous = self.route_body.lock().map_err(|_| io::ErrorKind::Other)?;
        if *previous != body {
            write_public(&self.route_path, &body)?;
            *previous = body;
        }
        Ok(())
    }
    /// Prove a same-version binding advance from an accepted `GotaTun` predecessor to its candidate.
    ///
    /// Restart may finish applying an already committed identity while replaying the same public
    /// revision. The journal must select the candidate, and both the private key file and recorded
    /// interface identity must already name it. An open journal also proves the snapshot's
    /// predecessor; a completed journal has erased that predecessor but still proves the candidate.
    fn rotation_binding_advance_is_proven(
        &self,
        previous: crate::policy::model::PublicKey,
        candidate: crate::policy::model::PublicKey,
    ) -> io::Result<bool> {
        let Some(rotation) = self.rotation_secret()? else {
            return Ok(false);
        };
        if !rotation.commit_requested {
            return Ok(false);
        }
        let journal_candidate = rotation_public_key(&rotation.candidate)?;
        if candidate != journal_candidate {
            return Ok(false);
        }
        if !rotation.completed {
            let journal_previous = rotation_public_key(&rotation.previous)?;
            if previous != journal_previous {
                return Ok(false);
            }
        }
        #[cfg(target_os = "linux")]
        if self.recorded_engine()? != Some(crate::gotatun_node::EngineKind::GotaTun) {
            return Ok(false);
        }
        if self.recorded_interface()? != Some(journal_candidate) {
            return Ok(false);
        }
        let Some(private_key) = self.read_private_key()? else {
            return Ok(false);
        };
        let private_public = rotation_public_key(&private_key)?;
        Ok(private_public == journal_candidate)
    }
    /// Atomically publish public intent and fsync the replacement and directory.
    /// # Errors
    /// Refuses stale/conflicting revisions or incomplete persistence; no existing
    /// temporary file is overwritten. Identical replay, legacy binding upgrades and journal-proven
    /// `GotaTun` binding advances retain their established semantics.
    pub fn save(&self, state: &State) -> io::Result<()> {
        // The directory inode is stable across atomic snapshot replacement.
        // Lock it, not the replaced file, so independent Store instances cannot
        // race the revision check and rename. No idle descriptor is retained.
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
            .open(self.path.parent().ok_or(io::ErrorKind::InvalidInput)?)?;
        let _guard = nix::fcntl::Flock::lock(directory, nix::fcntl::FlockArg::LockExclusive)
            .map_err(|(_, error)| error)?;
        // Disabled/unconfigured intent carries no access revision. It must
        // remain publishable even if the retained public snapshot is unreadable.
        if let Some(next) = &state.config
            && let Some(previous) = read_public::<State>(&self.path)?
            && let Some(old) = previous.config
        {
            if next.version < old.version {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if next.version == old.version && next != &old {
                // Legacy snapshots may gain their first binding. An existing binding may advance
                // only when the local GotaTun commit journal and identity files prove that exact
                // candidate; equal revision alone never authorizes new policy.
                let binding_advance = match (old.local_key, next.local_key) {
                    (Some(previous), Some(candidate)) if previous != candidate => {
                        self.rotation_binding_advance_is_proven(previous, candidate)?
                    }
                    _ => false,
                };
                let legacy_binding = old.local_key.is_none() && next.local_key.is_some();
                if !binding_advance && !legacy_binding {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let mut bound = old;
                bound.local_key = next.local_key;
                if &bound != next {
                    return Err(io::ErrorKind::InvalidData.into());
                }
            }
        }
        #[cfg(feature = "cutoff-measure")]
        let encode = state.config.as_ref().map(|config| {
            crate::cutoff_measure::Stage::new(config.node, config.version, "journal_encode")
        });
        let body = serde_json::to_vec(state).map_err(io::Error::other)?;
        #[cfg(feature = "cutoff-measure")]
        drop(encode);
        #[cfg(feature = "cutoff-measure")]
        let _write = state.config.as_ref().map(|config| {
            crate::cutoff_measure::Stage::new(config.node, config.version, "journal_write")
        });
        write_public(&self.path, &body)
    }
}

/// Derive a `GotaTun` public identity from a private key in the journal or key file.
///
/// This shared proof runs on Linux and macOS, where the kernel `WireGuard` adapter is not available
/// on both targets. `GotaTun` uses the same X25519 bytes on each platform.
/// # Errors
/// Returns `InvalidData` when the journal or private-key file does not contain exactly 32 bytes.
fn rotation_public_key(private_key: &[u8]) -> io::Result<crate::policy::model::PublicKey> {
    let private_bytes: [u8; 32] = private_key
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidData)?;
    let private_bytes = Zeroizing::new(private_bytes);
    let secret = gotatun::x25519::StaticSecret::from(*private_bytes);
    let public = gotatun::x25519::PublicKey::from(&secret);
    Ok(crate::policy::model::PublicKey(*public.as_bytes()))
}

// Both public files must pass the same ownership, mode and no-follow boundary.
fn read_public<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(mut file) => {
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.uid() != nix::unistd::Uid::effective().as_raw()
                || meta.mode() & 0o777 != 0o600
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            // Reuse the slice decoder already used for peer/access frames,
            // avoiding a second JSON specialization for public file input. Read
            // the checked descriptor so replacement cannot bypass no-follow or
            // ownership validation. These bytes contain no private key material.
            let mut body = Vec::new();
            file.read_to_end(&mut body)?;
            serde_json::from_slice(&body)
                .map(Some)
                .map_err(io::Error::other)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}
// Write the journal before kernel mutation and the accepted snapshot afterwards.
// A crash between writes can recover ownership from the journal, the accepted
// peer list and the retained kernel peer list; no cross-file atomicity is assumed.
fn write_public(path: &Path, body: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension(format!("{}.new", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(body)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(path.parent().ok_or(io::ErrorKind::InvalidInput)?)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn write_private(path: &Path, key: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension(format!("{}.new", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(key)?;
        file.sync_all()?;
        fs::hard_link(&temporary, path)?;
        fs::remove_file(&temporary)?;
        FileSync::parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

/// Remove the `<key>.<pid>.new` files that a stop between `create_new` and the cleanup in
/// `write_private` leaves behind. Each holds a copy of the key, and nothing else ever removes
/// one (#260 J143 P3-3). This holds the directory lock that `write_private_key` holds, so it
/// never removes a live writer's file.
fn sweep_private_temporaries(key_path: &Path) -> io::Result<()> {
    let parent = key_path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let prefix = format!(
        "{}.",
        key_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(io::ErrorKind::InvalidInput)?
    );
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(parent)?;
    let _guard = nix::fcntl::Flock::lock(directory, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, error)| error)?;
    let mut removed = false;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let is_temporary = name
            .to_str()
            .and_then(|name| name.strip_prefix(prefix.as_str()))
            .and_then(|rest| rest.strip_suffix(".new"))
            .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()));
        // The entry's own type: a symlink with this name is not followed, and not ours.
        if is_temporary && entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?;
            removed = true;
        }
    }
    if removed {
        FileSync::parent(key_path)?;
    }
    Ok(())
}

struct FileSync;
impl FileSync {
    fn parent(path: &Path) -> io::Result<()> {
        fs::File::open(path.parent().ok_or(io::ErrorKind::InvalidInput)?)?.sync_all()
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    //! Provides isolated filesystem state for node persistence tests.
    #![allow(clippy::expect_used)]
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };

    // Tests run concurrently; this counter keeps their temporary paths distinct.
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    pub(crate) struct Directory(pub(crate) PathBuf);
    impl Directory {
        pub(crate) fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test clock")
                .as_nanos();
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "infraternal-mesh-state-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("test mode");
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    /// Build a minimal accepted mesh view with one local identity binding.
    fn binding_state(local_key: crate::policy::model::PublicKey) -> State {
        State {
            enabled: true,
            config: Some(Config {
                local_key: Some(local_key),
                server: None,
                node: crate::policy::model::NodeId(1),
                #[cfg(feature = "mesh-dns-spike")]
                name: None,
                #[cfg(feature = "mesh-dns-spike")]
                dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
                version: 7,
                addresses: crate::policy::model::Addresses {
                    ipv4: "10.254.0.1".parse().expect("IPv4"),
                    ipv6: "fd01::1".parse().expect("IPv6"),
                },
                default_policy: crate::dataplane::DefaultPolicy::Deny,
                exposure: None,
                peers: std::collections::BTreeMap::new(),
                #[cfg(feature = "mesh-dns-spike")]
                peer_names: std::collections::BTreeMap::new(),
            }),
            #[cfg(target_os = "linux")]
            backend: Some(crate::firewall::Backend::Nft),
        }
    }

    /// A committed `GotaTun` journal authorizes persisting its candidate binding at the same revision.
    #[test]
    fn a_commit_journal_authorizes_the_same_version_gotatun_binding_advance() {
        let directory = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("initial state");
        let previous = [0x11; 32];
        let candidate = [0x22; 32];
        let previous_public = crate::wireguard::Key::from_private(&previous)
            .expect("previous key")
            .1;
        let candidate_public = crate::wireguard::Key::from_private(&candidate)
            .expect("candidate key")
            .1;
        store
            .save(&binding_state(previous_public))
            .expect("save the accepted predecessor binding");
        store
            .save_rotation_secret(&RotationSecret {
                operation_id: "00000000-0000-4000-8000-000000000367".to_owned(),
                sequence: 1,
                previous,
                candidate,
                commit_requested: true,
                completed: false,
            })
            .expect("durable commit intent");
        #[cfg(target_os = "linux")]
        store
            .record_engine(crate::gotatun_node::EngineKind::GotaTun)
            .expect("record the userspace engine");
        store
            .record_interface(&candidate_public)
            .expect("record the candidate interface identity");
        store
            .write_private_key(&candidate)
            .expect("save the candidate private key");

        store
            .save(&binding_state(candidate_public))
            .expect("journal-proven binding advance at the same config revision");

        let (_, restored) = Store::open(&directory.0).expect("restore candidate binding");
        assert_eq!(
            restored.config.and_then(|config| config.local_key),
            Some(candidate_public),
            "the candidate binding is durable after snapshot replacement"
        );
    }

    /// A completed journal still authorizes normalizing a snapshot that retained its old binding.
    #[test]
    fn a_completed_journal_authorizes_normalizing_a_stale_gotatun_binding() {
        let directory = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("initial state");
        let operation_id = "00000000-0000-4000-8000-000000000367";
        let previous = [0x11; 32];
        let candidate = [0x22; 32];
        let previous_public = crate::wireguard::Key::from_private(&previous)
            .expect("previous key")
            .1;
        let candidate_public = crate::wireguard::Key::from_private(&candidate)
            .expect("candidate key")
            .1;
        store
            .save(&binding_state(previous_public))
            .expect("save the accepted predecessor binding");
        store
            .save_rotation_secret(&RotationSecret {
                operation_id: operation_id.to_owned(),
                sequence: 1,
                previous,
                candidate,
                commit_requested: true,
                completed: false,
            })
            .expect("durable commit intent");
        #[cfg(target_os = "linux")]
        store
            .record_engine(crate::gotatun_node::EngineKind::GotaTun)
            .expect("record the userspace engine");
        store
            .record_interface(&candidate_public)
            .expect("record the candidate interface identity");
        store
            .write_private_key(&candidate)
            .expect("save the candidate private key");
        store
            .complete_rotation_secret(operation_id, 1)
            .expect("retire the predecessor before snapshot normalization");

        store
            .save(&binding_state(candidate_public))
            .expect("normalize the stale binding after finish");
    }

    /// A same-revision binding cannot move to a key that the commit journal does not select.
    #[test]
    fn an_unproven_same_version_gotatun_binding_advance_is_refused() {
        let directory = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("initial state");
        let previous = [0x11; 32];
        let candidate = [0x22; 32];
        let unrelated = [0x33; 32];
        let previous_public = crate::wireguard::Key::from_private(&previous)
            .expect("previous key")
            .1;
        let candidate_public = crate::wireguard::Key::from_private(&candidate)
            .expect("candidate key")
            .1;
        let unrelated_public = crate::wireguard::Key::from_private(&unrelated)
            .expect("unrelated key")
            .1;
        store
            .save(&binding_state(previous_public))
            .expect("save the accepted predecessor binding");
        store
            .save_rotation_secret(&RotationSecret {
                operation_id: "00000000-0000-4000-8000-000000000367".to_owned(),
                sequence: 1,
                previous,
                candidate,
                commit_requested: true,
                completed: false,
            })
            .expect("durable commit intent");
        #[cfg(target_os = "linux")]
        store
            .record_engine(crate::gotatun_node::EngineKind::GotaTun)
            .expect("record the userspace engine");
        store
            .record_interface(&candidate_public)
            .expect("record the candidate interface identity");
        store
            .write_private_key(&candidate)
            .expect("save the candidate private key");

        assert_eq!(
            store
                .save(&binding_state(unrelated_public))
                .expect_err("an unrelated key cannot replace the accepted binding")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn explicit_off_survives_restart_and_snapshot_contains_only_public_fields() {
        let directory = Directory::new();
        let (store, initial) = Store::open(&directory.0).expect("initial state");
        assert!(initial.enabled);
        store
            .save(&State {
                enabled: false,
                config: None,
                backend: Some(crate::firewall::Backend::Nft),
            })
            .expect("save");
        let (_, restored) = Store::open(&directory.0).expect("restore");
        assert!(!restored.enabled);
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&store.path).expect("public file"))
                .expect("public JSON");
        assert_eq!(value.as_object().expect("object").len(), 3);
        assert_eq!(
            fs::metadata(&store.path).expect("mode").mode() & 0o777,
            0o600
        );
    }
    /// Finishing a rotation removes only the predecessor key, and finishing it again is harmless.
    #[test]
    fn completed_rotation_retires_only_the_predecessor_and_is_retryable() {
        let directory = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("initial state");
        let operation_id = "00000000-0000-4000-8000-000000000001";
        store
            .save_rotation_secret(&RotationSecret {
                operation_id: operation_id.to_owned(),
                sequence: 1,
                previous: [0x11; 32],
                candidate: [0x22; 32],
                commit_requested: true,
                completed: false,
            })
            .expect("candidate already active");

        store
            .complete_rotation_secret(operation_id, 1)
            .expect("retire predecessor");
        store
            .complete_rotation_secret(operation_id, 1)
            .expect("retry lost completion response");
        let completed = store
            .rotation_secret()
            .expect("read completed marker")
            .expect("completion marker retained");
        assert!(completed.completed);
        assert_eq!(completed.previous, [0; 32]);
        assert_eq!(completed.candidate, [0x22; 32]);
        let bytes = fs::read(&store.rotation_path).expect("private rotation record");
        assert!(!bytes.windows(32).any(|window| window == [0x11; 32]));
        assert_eq!(
            fs::metadata(&store.rotation_path)
                .expect("private record mode")
                .mode()
                & 0o777,
            0o600
        );
    }

    /// Both supported engines carry the open rotation journal when the node switches its data plane (#367).
    #[test]
    fn switching_engines_keeps_the_rotation_journal() {
        let directory = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("initial state");
        let operation_id = "00000000-0000-4000-8000-000000000367";
        store
            .save_rotation_secret(&RotationSecret {
                operation_id: operation_id.to_owned(),
                sequence: 1,
                previous: [0x11; 32],
                candidate: [0x22; 32],
                commit_requested: false,
                completed: false,
            })
            .expect("prepared journal");
        store
            .record_engine(crate::gotatun_node::EngineKind::Kernel)
            .expect("record kernel");
        assert!(
            store.rotation_secret().expect("read journal").is_some(),
            "kernel keeps its own journal"
        );
        store
            .record_engine(crate::gotatun_node::EngineKind::GotaTun)
            .expect("record GotaTun");
        let carried = store
            .rotation_secret()
            .expect("read journal after switching to GotaTun")
            .expect("GotaTun keeps the pending operation");
        assert_eq!(carried.operation_id, operation_id);
        assert!(!carried.commit_requested);
        drop(carried);
        store
            .record_engine(crate::gotatun_node::EngineKind::Kernel)
            .expect("switching back to kernel");
        assert!(
            store
                .rotation_secret()
                .expect("read carried journal")
                .is_some(),
            "the same operation remains recoverable on either engine"
        );
    }

    /// A stop inside `write_private` leaves `mesh-private-key.<pid>.new` holding the key. Opening
    /// the store removes it and nothing else (#260 J143 P3-3).
    #[test]
    fn open_sweeps_stray_private_key_temporaries_only() {
        let directory = Directory::new();
        let stray = directory.0.join("mesh-private-key.4242.new");
        fs::write(&stray, [7_u8; 32]).expect("stray key copy");
        let kept = [
            "mesh-private-key.new",
            "mesh-private-key.x1.new",
            "mesh-public.4242.new",
        ];
        for name in kept {
            fs::write(directory.0.join(name), b"x").expect("unrelated file");
        }
        symlink(&stray, directory.0.join("mesh-private-key.99.new")).expect("symlink");
        let (store, _) = Store::open(&directory.0).expect("open");
        assert!(!stray.exists(), "the stray key copy is removed");
        for name in kept {
            assert!(directory.0.join(name).exists(), "{name} stays");
        }
        assert!(
            fs::symlink_metadata(directory.0.join("mesh-private-key.99.new")).is_ok(),
            "a symlink is never followed or removed"
        );
        store.write_private_key(&[9; 32]).expect("key");
        drop(Store::open(&directory.0).expect("reopen"));
        assert_eq!(
            store
                .read_private_key()
                .expect("read")
                .expect("key")
                .as_slice(),
            &[9; 32],
            "the key itself is never swept"
        );
    }

    /// A `GotaTun` identity can be restored from its private file without weakening its mode.
    #[test]
    fn gotatun_private_key_round_trips_only_as_a_private_file() {
        let directory = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("initial state");
        let key = [0x5a; 32];

        store.write_private_key(&key).expect("persist engine key");
        let restored = store
            .read_private_key()
            .expect("read engine key")
            .expect("persisted engine key");
        assert_eq!(restored.as_slice(), key);
        assert_eq!(
            fs::metadata(&store.key_path)
                .expect("private key metadata")
                .mode()
                & 0o777,
            0o600
        );
        store.remove_private_key().expect("remove private key");
        assert!(store.read_private_key().expect("key removed").is_none());
    }

    /// Rotation replaces the old key atomically while keeping its restrictive file mode.
    #[test]
    fn replacing_a_private_key_is_durable_private_and_idempotent() {
        let directory = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("initial state");
        let previous = [0x31; 32];
        let candidate = [0x42; 32];
        store.write_private_key(&previous).expect("initial key");
        let abandoned = store.key_path.with_extension("4242.new");
        fs::write(&abandoned, [0x77; 32]).expect("simulate a stop before the replacement rename");
        drop(store);
        let (store, _) =
            Store::open(&directory.0).expect("reopen after the interrupted replacement");
        assert!(
            !abandoned.exists(),
            "restart removes the private temporary left by a stopped replacement"
        );
        store
            .replace_private_key(&candidate)
            .expect("replace with the journaled key");
        let bytes = store
            .read_private_key()
            .expect("read replacement")
            .expect("replacement exists");
        assert_eq!(bytes.as_slice(), &candidate);
        assert_eq!(
            fs::metadata(&store.key_path)
                .expect("replacement metadata")
                .mode()
                & 0o777,
            0o600
        );
        store
            .replace_private_key(&candidate)
            .expect("replaying the same replacement is harmless");
        assert!(
            fs::read_dir(&directory.0)
                .expect("list private state")
                .all(|entry| !entry
                    .expect("state entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".new")),
            "no private temporary remains after a completed replacement"
        );
    }

    #[test]
    fn selected_engine_is_durable_outside_the_legacy_public_snapshot() {
        let directory = Directory::new();
        let (store, state) = Store::open(&directory.0).expect("initial state");
        assert!(store.recorded_engine().expect("no saved engine").is_none());
        store.save(&state).expect("save the legacy snapshot");
        store
            .record_engine(crate::gotatun_node::EngineKind::GotaTun)
            .expect("save engine");
        assert_eq!(
            store.recorded_engine().expect("saved engine"),
            Some(crate::gotatun_node::EngineKind::GotaTun)
        );
        assert_eq!(
            fs::metadata(&store.engine_path)
                .expect("engine metadata")
                .mode()
                & 0o777,
            0o600
        );
        assert!(
            !fs::read(&store.path)
                .expect("legacy state remains readable")
                .windows(b"gotatun".len())
                .any(|window| window == b"gotatun")
        );
    }
    #[test]
    fn route_recording_preserves_the_legacy_accepted_state_format() {
        let directory = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("initial state");
        let config = Config {
            local_key: None,
            server: None,
            node: crate::policy::model::NodeId(1),
            #[cfg(feature = "mesh-dns-spike")]
            name: None,
            #[cfg(feature = "mesh-dns-spike")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            version: 7,
            addresses: crate::policy::model::Addresses {
                ipv4: "10.254.0.1".parse().expect("IPv4"),
                ipv6: "fd01::1".parse().expect("IPv6"),
            },
            default_policy: crate::dataplane::DefaultPolicy::Deny,
            exposure: None,
            peers: std::collections::BTreeMap::new(),
            #[cfg(feature = "mesh-dns-spike")]
            peer_names: std::collections::BTreeMap::new(),
        };
        store
            .save(&State {
                enabled: false,
                config: Some(config.clone()),
                backend: Some(crate::firewall::Backend::Nft),
            })
            .expect("accepted intent");
        let before = fs::read(&store.path).expect("accepted bytes");
        assert!(
            store
                .route_inventory()
                .expect("legacy inventory")
                .is_empty()
        );
        let routes = BTreeSet::from([
            "10.254.0.2".parse().expect("peer IPv4"),
            "fd01::2".parse().expect("peer IPv6"),
        ]);
        store.record_routes(&routes).expect("write-ahead record");
        assert_eq!(fs::read(&store.path).expect("accepted bytes"), before);
        let (restored, state) = Store::open(&directory.0).expect("restore journal");
        assert_eq!(restored.route_inventory().expect("recorded routes"), routes);
        assert_eq!(state.config, Some(config));
        assert!(!state.enabled);
        assert!(matches!(state.backend, Some(crate::firewall::Backend::Nft)));
        assert_eq!(
            fs::metadata(&store.route_path)
                .expect("journal mode")
                .mode()
                & 0o777,
            0o600
        );
    }
    #[test]
    fn unsafe_route_journal_and_existing_temporary_files_are_preserved() {
        let directory = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("initial state");
        let routes = BTreeSet::from(["10.254.0.2".parse().expect("peer IPv4")]);
        let temporary = store
            .route_path
            .with_extension(format!("{}.new", std::process::id()));
        fs::write(&temporary, b"unrelated").expect("collision fixture");
        assert_eq!(
            store.record_routes(&routes).expect_err("collision").kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            fs::read(&temporary).expect("preserved collision"),
            b"unrelated"
        );
        assert!(store.route_inventory().expect("unchanged cache").is_empty());
        fs::remove_file(temporary).expect("remove fixture");
        store.record_routes(&routes).expect("record");
        fs::set_permissions(&store.route_path, fs::Permissions::from_mode(0o644))
            .expect("unsafe mode");
        assert!(Store::open(&directory.0).is_err());
        fs::remove_file(&store.route_path).expect("remove fixture");
        let other = directory.0.join("other-public-routes");
        fs::write(&other, b"[\"10.254.0.2\"]").expect("public fixture");
        fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).expect("private mode");
        symlink(&other, &store.route_path).expect("journal symlink");
        assert!(Store::open(&directory.0).is_err());
        assert_eq!(fs::read(other).expect("foreign bytes"), b"[\"10.254.0.2\"]");
    }
    #[test]
    fn unsafe_snapshots_and_preexisting_temporary_files_are_not_followed_or_removed() {
        let directory = Directory::new();
        let (store, state) = Store::open(&directory.0).expect("initial state");
        let other = directory.0.join("other");
        fs::write(&other, b"unrelated").expect("fixture");
        symlink(&other, &store.path).expect("symlink");
        assert!(Store::open(&directory.0).is_err());
        fs::remove_file(&store.path).expect("unlink fixture");
        let temporary = store
            .path
            .with_extension(format!("{}.new", std::process::id()));
        fs::write(&temporary, b"unrelated").expect("fixture");
        assert_eq!(
            store.save(&state).expect_err("collision").kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&temporary).expect("retained"), b"unrelated");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755))
            .expect("expose fixture");
        assert!(Store::open(&directory.0).is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "node_state_order_tests.rs"]
mod order_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "node_state_restore_tests.rs"]
mod restore_tests;
