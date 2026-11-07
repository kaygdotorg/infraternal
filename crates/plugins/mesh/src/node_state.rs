//! Persists accepted public node intent and write-ahead peer-route ownership [166,198]. Under
//! kernel `WireGuard` the private key lives only in kernel memory; the `GotaTun` engine keeps it in
//! one private 0600 file, which down and retirement remove (#260). That key never leaves its
//! node (D163), so backups (D147: database, CA key, configuration) must never include this
//! directory's `mesh-private-key`.
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

/// Bound public snapshots consistently with the macOS node's state reader.
const MAX_PUBLIC_STATE_BYTES: u64 = 16 * 1024 * 1024;
/// Public runtime state needed to restore mesh intent without storing private key material.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub enabled: bool,
    pub config: Option<Config>,
    /// True after a new authority is fenced and until its first full snapshot is saved.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub authority_reset_pending: bool,
    #[serde(default)]
    pub backend: Option<crate::firewall::Backend>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            enabled: true,
            config: None,
            authority_reset_pending: false,
            backend: None,
        }
    }
}
/// This node's durable local state: the public snapshot, routes, interface key, engine, private key and rotation journal.
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
        let engine_path = parent.join("mesh-engine.json");
        let key_path = parent.join("mesh-private-key");
        sweep_private_temporaries(&key_path)?;
        let state: State = read_public(&path)?.unwrap_or_default();
        if state
            .config
            .as_ref()
            .and_then(|config| config.authority_epoch.as_deref())
            .is_some_and(|epoch| !crate::dataplane::valid_authority_epoch(epoch))
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if state.authority_reset_pending
            && state.config.as_ref().is_none_or(|config| {
                config.authority_epoch.is_none()
                    || !config.peers.is_empty()
                    || config.default_policy != crate::dataplane::DefaultPolicy::Deny
            })
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let routes: BTreeSet<IpAddr> = read_public(&route_path)?.unwrap_or_default();
        let route_body = serde_json::to_vec(&routes).map_err(io::Error::other)?;
        Ok((
            Self {
                path,
                route_path,
                interface_path,
                rotation_path,
                engine_path,
                key_path,
                route_body: Mutex::new(route_body),
            },
            state,
        ))
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
    /// Remove the rotation journal, its keys included, when the engine that rotated is retired.
    /// # Errors
    /// Refuses an unsafe journal file and reports durable directory failures.
    pub(crate) fn discard_rotation_secret(&self) -> io::Result<()> {
        if self.rotation_secret()?.is_none() {
            return Ok(());
        }
        fs::remove_file(&self.rotation_path)?;
        FileSync::parent(&self.rotation_path)
    }
    /// Persist the selected engine separately from the legacy accepted snapshot.
    ///
    /// Only kernel `WireGuard` rotates (D166, D352), so recording any other engine also retires the rotation
    /// journal: whether or not a live link was switched, a later return to kernel must start from the key the
    /// node now uses, never from a journal key (#285, J252 P3-2). The engine is written first; a stop between the
    /// two leaves a journal that the kernel ownership proof already ignores, and the next recording removes it.
    /// # Errors
    /// Refuses unsafe state files and reports durable-write failures.
    pub(crate) fn record_engine(&self, engine: crate::gotatun_node::EngineKind) -> io::Result<()> {
        write_public(
            &self.engine_path,
            &serde_json::to_vec(&engine).map_err(io::Error::other)?,
        )?;
        if engine == crate::gotatun_node::EngineKind::Kernel {
            return Ok(());
        }
        self.discard_rotation_secret()
    }
    /// Read the selected engine, if this node has recorded one.
    /// # Errors
    /// Refuses unsafe metadata and malformed engine values.
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
    /// Atomically publish public intent and fsync the replacement and directory.
    /// # Errors
    /// Refuses stale/conflicting revisions or incomplete persistence; no existing
    /// temporary file is overwritten. Identical replay and exact legacy-key
    /// metadata upgrades retain their established semantics.
    pub fn save(&self, state: &State) -> io::Result<()> {
        self.save_checked(state, None)
    }
    /// Save a complete snapshot against the exact accepted config it replaces.
    ///
    /// This narrow compare-and-set permits a same-authority full snapshot to lower its revision,
    /// and permits the first full snapshot after an authority reset to complete at an equal
    /// revision. Ordinary saves keep the monotonic revision fence.
    /// # Errors
    /// Refuses a stale base, a changed authority, or an equal-revision conflict outside a reset.
    pub(crate) fn save_full_snapshot(&self, state: &State, expected: &Config) -> io::Result<()> {
        self.save_checked(state, Some(expected))
    }
    /// Validate revision ownership under the directory lock before replacing the public file.
    /// # Errors
    /// Reports a stale revision, a mismatched base, or a durable write failure.
    fn save_checked(&self, state: &State, full_snapshot_base: Option<&Config>) -> io::Result<()> {
        if state.authority_reset_pending
            && state.config.as_ref().is_none_or(|config| {
                config.authority_epoch.is_none()
                    || !config.peers.is_empty()
                    || config.default_policy != crate::dataplane::DefaultPolicy::Deny
            })
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // The directory inode is stable across atomic snapshot replacement.
        // Lock it, not the replaced file, so independent Store instances cannot
        // race the revision check and rename. No idle descriptor is retained.
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
            .open(self.path.parent().ok_or(io::ErrorKind::InvalidInput)?)?;
        let _guard = nix::fcntl::Flock::lock(directory, nix::fcntl::FlockArg::LockExclusive)
            .map_err(|(_, error)| error)?;
        let previous = read_public::<State>(&self.path)?;
        if let Some(expected) = full_snapshot_base {
            let previous = previous.as_ref().ok_or(io::ErrorKind::InvalidData)?;
            let old = previous.config.as_ref().ok_or(io::ErrorKind::InvalidData)?;
            let next = state.config.as_ref().ok_or(io::ErrorKind::InvalidData)?;
            let completes_reset = previous.authority_reset_pending
                && !state.authority_reset_pending
                && next.authority_epoch == old.authority_epoch;
            if old != expected
                || next.authority_epoch != old.authority_epoch
                || !(next.version < old.version || completes_reset)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        // Disabled/unconfigured intent carries no access revision. It must
        // remain publishable even if the retained public snapshot is unreadable.
        if let Some(next) = &state.config
            && let Some(previous) = previous.as_ref()
            && let Some(old) = previous.config.as_ref()
        {
            if next
                .authority_epoch
                .as_deref()
                .is_some_and(|epoch| !crate::dataplane::valid_authority_epoch(epoch))
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let same_authority = next.authority_epoch == old.authority_epoch;
            if !same_authority
                && (!next.peers.is_empty()
                    || next.default_policy != crate::dataplane::DefaultPolicy::Deny)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let authorized_reset_completion = full_snapshot_base == Some(old)
                && previous.authority_reset_pending
                && !state.authority_reset_pending;
            if next.version < old.version && same_authority && full_snapshot_base != Some(old) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if next.version == old.version
                && same_authority
                && next != old
                && !authorized_reset_completion
            {
                // An existing exact legacy-key upgrade changes metadata only;
                // Node's authenticated binding check still authorizes that key.
                let mut bound = old.clone();
                if bound.local_key.is_some() || next.local_key.is_none() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
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
    /// Persist peer-free intent after an authority has already been fenced at runtime.
    ///
    /// Atomic replacement is preferred. If that fails, the existing private snapshot is rewritten
    /// in place so a failed temporary-file write cannot make the retired peer copy restartable.
    /// A torn in-place write is invalid JSON and therefore fails closed at the next restore.
    /// # Errors
    /// Refuses snapshots that still carry peers and reports when neither safe write can complete.
    pub(crate) fn save_retired(&self, state: &State) -> io::Result<()> {
        if state.authority_reset_pending && state.config.is_none()
            || state.config.as_ref().is_some_and(|config| {
                !config.peers.is_empty()
                    || config.default_policy != crate::dataplane::DefaultPolicy::Deny
            })
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let body = serde_json::to_vec(state).map_err(io::Error::other)?;
        if body.len() as u64 > MAX_PUBLIC_STATE_BYTES {
            return Err(io::ErrorKind::InvalidData.into());
        }
        match self.save(state) {
            Ok(()) => Ok(()),
            Err(atomic_error) => {
                write_public_in_place(&self.path, &body).inspect_err(|fallback_error| {
                    tracing::error!(
                        atomic_error_kind = ?atomic_error.kind(),
                        fallback_error_kind = ?fallback_error.kind(),
                        "atomic and in-place fail-closed mesh state writes both failed"
                    );
                })
            }
        }
    }
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
/// Atomically replace a public state file through a synced temporary file.
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

/// Overwrite an existing private public-state file after runtime peers are already fenced.
///
/// This is the last safe write when a directory rename fails: truncation can leave invalid JSON,
/// which restore rejects, but it cannot silently retain the old peer snapshot after a complete
/// write. The regular atomic writer remains the normal path.
/// # Errors
/// Refuses unsafe parent/file metadata, oversized state or failed durable writes.
fn write_public_in_place(path: &Path, body: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    if body.len() as u64 > MAX_PUBLIC_STATE_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(parent)?;
    let _guard = nix::fcntl::Flock::lock(directory, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, error)| error)?;
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    let file_metadata = file.metadata()?;
    if !file_metadata.is_file()
        || file_metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || file_metadata.mode() & 0o777 != 0o600
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    file.set_len(0)?;
    file.write_all(body)?;
    file.sync_all()?;
    FileSync::parent(path)
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

#[cfg(test)]
pub(crate) mod tests {
    //! Provides isolated filesystem state for node persistence tests.
    #![allow(clippy::expect_used)]
    use super::*;
    use std::{
        collections::BTreeMap,
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
    /// Explicit local disablement survives restart and the public file contains no private key.
    #[test]
    fn explicit_off_survives_restart_and_snapshot_contains_only_public_fields() {
        let directory = Directory::new();
        let (store, initial) = Store::open(&directory.0).expect("initial state");
        assert!(initial.enabled);
        store
            .save(&State {
                enabled: false,
                config: None,
                authority_reset_pending: false,
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
    /// Ordinary persistence cannot move an accepted authority's revision backwards.
    #[test]
    fn ordinary_save_rejects_a_lower_same_authority_revision() {
        let directory = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("initial state");
        let mut config = Config {
            authority_epoch: Some("00000000-0000-4000-8000-000000000001".to_owned()),
            local_key: None,
            server: Some(crate::policy::model::NodeId(1)),
            node: crate::policy::model::NodeId(2),
            #[cfg(feature = "mesh-dns-spike")]
            name: None,
            #[cfg(feature = "mesh-dns-spike")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            version: 11,
            addresses: crate::policy::model::Addresses {
                ipv4: "10.254.0.2".parse().expect("IPv4"),
                ipv6: "fd01::2".parse().expect("IPv6"),
            },
            default_policy: crate::dataplane::DefaultPolicy::Deny,
            exposure: None,
            peers: BTreeMap::new(),
            #[cfg(feature = "mesh-dns-spike")]
            peer_names: BTreeMap::new(),
        };
        store
            .save(&State {
                enabled: true,
                config: Some(config.clone()),
                authority_reset_pending: false,
                backend: None,
            })
            .expect("accepted snapshot");
        config.version = 2;

        let result = store.save(&State {
            enabled: true,
            config: Some(config),
            authority_reset_pending: false,
            backend: None,
        });

        assert_eq!(
            result
                .expect_err("ordinary save must keep its revision fence")
                .kind(),
            io::ErrorKind::InvalidData
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

    /// Recording an engine other than kernel retires the rotation journal, even with no live link to switch, so a
    /// later return to kernel cannot revive an old key of ours from it (#285, J252 P3-2). Recording kernel keeps it.
    #[test]
    fn leaving_kernel_retires_the_rotation_journal() {
        let directory = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("initial state");
        store
            .save_rotation_secret(&RotationSecret {
                operation_id: "00000000-0000-4000-8000-000000000001".to_owned(),
                sequence: 1,
                previous: [0; 32],
                candidate: [0x22; 32],
                commit_requested: true,
                completed: true,
            })
            .expect("completed journal");
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
        assert!(store.rotation_secret().expect("read journal").is_none());
        assert!(!store.rotation_path.exists());
        store
            .record_engine(crate::gotatun_node::EngineKind::GotaTun)
            .expect("recording again is harmless");
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
    /// Route recording keeps older accepted-state files readable by the current node.
    #[test]
    fn route_recording_preserves_the_legacy_accepted_state_format() {
        let directory = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("initial state");
        let config = Config {
            authority_epoch: None,
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
                authority_reset_pending: false,
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

#[cfg(test)]
#[path = "node_state_order_tests.rs"]
mod order_tests;

#[cfg(test)]
#[path = "node_state_restore_tests.rs"]
mod restore_tests;
