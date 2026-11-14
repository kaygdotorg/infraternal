//! Holds the embedded server node's mesh files durably and keeps a runtime copy for previous builds [J501, #489].

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

/// Node files written by the mesh store; keep this list aligned with `Store::open`.
///
/// The test `mesh_files_cover_every_file_the_store_opens` fails when the store gains a file this
/// list lacks. `mesh-listen-port.json` is listed ahead of the hole-punching branch (#483) that
/// adds it, so that merge needs no change here. The private key stays last: a copy publishes the
/// identity only after its public state.
const MESH_FILES: &[&str] = &[
    "mesh-public.json",
    "mesh-routes.json",
    "mesh-interface.json",
    "mesh-key-rotation.bin",
    "mesh-engine.json",
    "mesh-authority.json",
    "mesh-listen-port.json",
    "mesh-private-key",
];

/// A durable marker that lets an interrupted cross-filesystem move resume safely.
const MIGRATION_MARKER: &str = ".mesh-state-migration.pending";
/// Versioned marker header; its body lists the files that the interrupted transfer owns.
const MIGRATION_MARKER_HEADER: &str = "J501 mesh state migration v1";
/// Marker body used by the first candidate; recovery infers its file list from both directories.
const LEGACY_MIGRATION_MARKER: &[u8] = b"J501 mesh state migration\n";
/// Durable record of the public key last mirrored to the runtime path; it is not secret.
const MIRROR_RECORD: &str = ".mesh-runtime-mirror";
/// Versioned header of [`MIRROR_RECORD`]; the second line is the hex public key.
const MIRROR_RECORD_HEADER: &str = "J598 mesh runtime mirror v1";
/// A source replaced repeatedly by an uncooperative writer is left intact and retried next start.
const MAX_SOURCE_RETRIES: usize = 16;

/// The direction recorded for one recoverable move between durable and runtime mesh state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Direction {
    Forward,
    Rollback,
}

/// A bounded manifest that keeps an interrupted transfer from forgetting any planned file.
/// Describes which files and direction an interrupted mesh-state handoff must recover.
struct Marker {
    direction: Direction,
    /// True only for the earlier marker format, which did not record its own file list.
    legacy: bool,
    files: Vec<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Device and inode numbers for the exact mesh file observed before a transfer.
/// Keeping this identity lets cleanup detect a replacement and leave the new file intact.
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    /// Capture the inode identity used to keep cleanup from unlinking a writer's newer file.
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

/// Ensure embedded server mesh files are ready before its child starts.
///
/// This takes the same directory flock that guards mesh-store writes. The durable directory is
/// the authority; the legacy runtime path is never emptied, and ends each start as a byte copy of
/// the durable identity (see [`mirror_locked`]) so a previous build started cold keeps it.
///
/// Which side wins when both hold a key:
/// - the same key: nothing to decide;
/// - the runtime key is the one this server last mirrored: the durable key rotated since, and
///   the mirror is refreshed;
/// - the runtime key changed after the last mirror and this database owns it: the previous
///   build ran (a cold rollback) and rotated or minted it, so it is adopted;
/// - otherwise the runtime key belongs to another server and is left exactly as found.
///
/// Transfers use unique synced 0600 temporaries, atomic renames, and source inode checks. A
/// marker records the exact unfinished file set; startup never clears an incomplete marker or
/// starts a child that could mint another identity.
///
/// `owns` receives the public key derived from a legacy runtime private key and answers whether
/// this data directory's server recorded that key as its own. Every root server on a host
/// resolves the same legacy runtime path, so an identity found there may belong to another
/// server, for example a throwaway check instance or a test server. Only an identity this
/// server owns is adopted; any other one is left in place and logged (J595 P0).
///
/// Mesh private keys stay outside the D147 backup set, which contains the database, CA key and
/// configuration.
/// # Errors
/// Refuses unsafe owners, permissions, file types, or any failed filesystem operation.
pub(crate) fn migrate(
    volatile: &Path,
    durable: &Path,
    owns: &dyn Fn(&[u8; 32]) -> bool,
) -> io::Result<()> {
    let uid = nix::unistd::Uid::effective().as_raw();
    ensure_mesh_directory(durable, uid)?;
    let _durable_lock = lock_mesh_directory(durable)?;
    let legacy_exists = owned_directory(volatile, uid, true)?;
    let _legacy_lock = if legacy_exists {
        Some(lock_mesh_directory(volatile)?)
    } else {
        None
    };

    sweep_migration_temporaries(durable, uid)?;
    if legacy_exists {
        sweep_migration_temporaries(volatile, uid)?;
    }
    let marker = durable.join(MIGRATION_MARKER);
    if let Some(mut pending) = read_marker(&marker, uid)? {
        if pending.legacy {
            pending.files = union_files(volatile, durable, uid)?;
        }
        if pending.direction == Direction::Rollback {
            for name in present_files(volatile, uid)? {
                if !pending.files.contains(&name) {
                    pending.files.push(name);
                }
            }
        }
        if pending.legacy || pending.direction == Direction::Rollback {
            rewrite_marker(&marker, Direction::Forward, &pending.files)?;
            sync_directory(durable)?;
        }
        ensure_recoverable_plan(volatile, durable, &pending.files, uid)?;
        validate_private_key(volatile, &present_files(volatile, uid)?, uid)?;
        if !present_files(volatile, uid)?.contains(&"mesh-private-key") {
            validate_private_key(durable, &present_files(durable, uid)?, uid)?;
        }
        // A rollback marker (written by the first J501 candidates) makes the previous build's
        // possibly updated runtime identity authoritative. The marker was written by this data
        // directory's own server, so it needs no further ownership proof.
        copy_plan(volatile, durable, &pending.files, uid)?;
        if !pending.legacy {
            remove_other_files(durable, &pending.files, uid)?;
        }
        finish_marker(&marker, uid)?;
        sync_directory(durable)?;
        return mirror_locked(durable, volatile, legacy_exists, uid);
    }

    let durable_files = present_files(durable, uid)?;
    let legacy_files = if legacy_exists {
        present_files(volatile, uid)?
    } else {
        Vec::new()
    };
    validate_private_key(durable, &durable_files, uid)?;
    validate_private_key(volatile, &legacy_files, uid)?;
    let durable_key = read_private_key(durable, uid)?;
    let legacy_key = if legacy_exists {
        read_private_key(volatile, uid)?
    } else {
        None
    };

    match (&durable_key, &legacy_key) {
        // Runtime files without a key carry no identity to prove or keep.
        (None, None) => return Ok(()),
        (Some(_), None) => {}
        (Some(durable_key), Some(legacy_key)) if durable_key[..] == legacy_key[..] => {}
        (None, Some(legacy_key)) => {
            let public = public_key(legacy_key)?;
            if !owns(&public) {
                log_foreign_identity(volatile, durable, &public);
                return Ok(());
            }
            adopt(volatile, durable, &legacy_files, &marker, uid)?;
        }
        (Some(_), Some(legacy_key)) => {
            let public = public_key(legacy_key)?;
            // A runtime key equal to our own earlier mirror means the durable key rotated since;
            // the mirror below refreshes it.
            let own_stale_mirror = read_mirror_record(durable, uid)? == Some(public);
            if !own_stale_mirror {
                if owns(&public) {
                    // The runtime key changed after our last mirror and this database records
                    // it: the previous build ran after a cold rollback and rotated or minted it,
                    // so peers know this key now.
                    tracing::warn!(
                        legacy_state = %volatile.display(),
                        public_key = %hex_key(&public),
                        "the previous server build changed its Mesh identity; adopting it"
                    );
                    adopt(volatile, durable, &legacy_files, &marker, uid)?;
                } else {
                    log_foreign_identity(volatile, durable, &public);
                    return sync_directory(durable);
                }
            }
        }
    }
    mirror_locked(durable, volatile, legacy_exists, uid)
}

/// Report a runtime identity this server does not own, which is left exactly as found.
fn log_foreign_identity(volatile: &Path, durable: &Path, public: &[u8; 32]) {
    tracing::error!(
        legacy_state = %volatile.display(),
        durable_state = %durable.display(),
        public_key = %hex_key(public),
        "the Mesh identity at the shared runtime path is not recorded as this server's own \
         node; it was left in place and this server neither adopts nor overwrites it"
    );
}

/// Copy an owned runtime identity into durable storage under a recoverable marker.
///
/// The runtime copy stays: a previous build started cold reads only that path (J595 P1). Durable
/// files absent from the runtime set belong to the replaced identity, for example its rotation
/// journal, and are removed so the durable set matches the adopted one.
/// # Errors
/// Leaves the marker in place when any copy, removal, or sync fails.
fn adopt(
    volatile: &Path,
    durable: &Path,
    legacy_files: &[&'static str],
    marker: &Path,
    uid: u32,
) -> io::Result<()> {
    create_marker(marker, Direction::Forward, legacy_files)?;
    sync_directory(durable)?;
    copy_plan(volatile, durable, legacy_files, uid)?;
    remove_other_files(durable, legacy_files, uid)?;
    finish_marker(marker, uid)?;
    sync_directory(durable)
}

/// Keep the runtime path a byte copy of the durable identity while a new build runs.
///
/// A previous build reads only the runtime path. Mirroring at every start and every warm restart
/// means a crash, a failed start, or a cold rollback to that build finds the same identity
/// instead of minting one (J595 P1, D295). The record of the mirrored public key lets the next
/// start tell its own stale mirror apart from a key the previous build changed.
///
/// Writing the key at the runtime path restores exactly what J501 builds had there: before them
/// the embedded node used that path directly.
///
/// `legacy_locked` says the caller already holds the runtime directory's lock; otherwise this
/// creates the directory if needed and takes the lock, after the durable lock (stable order).
/// # Errors
/// Refuses unsafe runtime entries and reports any copy, removal, or sync failure.
fn mirror_locked(durable: &Path, volatile: &Path, legacy_locked: bool, uid: u32) -> io::Result<()> {
    let Some(key) = read_private_key(durable, uid)? else {
        return Ok(());
    };
    let files = present_files(durable, uid)?;
    let _legacy_lock = if legacy_locked {
        None
    } else {
        match ensure_mesh_directory(volatile, uid) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                tracing::warn!(
                    legacy_state = %volatile.display(),
                    "the runtime Mesh path has no parent directory; a previous build started cold \
                     would not find this identity"
                );
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        Some(lock_mesh_directory(volatile)?)
    };
    sweep_migration_temporaries(volatile, uid)?;
    present_files(volatile, uid)?;
    for name in &files {
        copy_one(&durable.join(name), &volatile.join(name), uid)?
            .ok_or(io::ErrorKind::InvalidData)?;
    }
    remove_other_files(volatile, &files, uid)?;
    validate_private_key(volatile, &present_files(volatile, uid)?, uid)?;
    sync_directory(volatile)?;
    let public = public_key(&key)?;
    if read_mirror_record(durable, uid)? != Some(public) {
        replace_private_file(
            &durable.join(MIRROR_RECORD),
            format!("{MIRROR_RECORD_HEADER}\n{}\n", hex_key(&public)).as_bytes(),
        )?;
    }
    Ok(())
}

/// Read the public key last mirrored to the runtime path, if this data directory recorded one.
/// # Errors
/// Refuses an unsafe or malformed record instead of guessing which identity is newer.
fn read_mirror_record(durable: &Path, uid: u32) -> io::Result<Option<[u8; 32]>> {
    let path = durable.join(MIRROR_RECORD);
    if !owned_file(&path, uid, true)? {
        return Ok(None);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)?;
    if file.metadata()?.len() > 256 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut body = String::new();
    file.read_to_string(&mut body)?;
    let mut lines = body.lines();
    if lines.next() != Some(MIRROR_RECORD_HEADER) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let hex = lines.next().ok_or(io::ErrorKind::InvalidData)?;
    if hex.len() != 64 || lines.next().is_some() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut key = [0_u8; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| io::ErrorKind::InvalidData)?;
    }
    Ok(Some(key))
}

/// Remove known mesh files outside `keep`, unlinking only the exact inode that was checked.
/// # Errors
/// Refuses unsafe entries and stops if a writer replaces a file during removal.
fn remove_other_files(directory: &Path, keep: &[&str], uid: u32) -> io::Result<()> {
    let stale = present_files(directory, uid)?
        .into_iter()
        .filter(|name| !keep.contains(name))
        .collect::<Vec<_>>();
    remove_files(directory, &stale, uid)
}

/// Read every public key this data directory records for the server's own Mesh node.
///
/// The server's embedded node attaches under the fixed host name `server`. Its current key and
/// any key in an open rotation (candidate or previous) count as its own, so an identity caught
/// mid-rotation is still recognised.
/// # Errors
/// Returns the database error; the caller fails start closed instead of guessing.
pub(crate) async fn server_node_keys(pool: &sqlx::SqlitePool) -> io::Result<Vec<[u8; 32]>> {
    use sqlx::Row as _;

    let rows = sqlx::query(
        "SELECT n.public_key, r.candidate_public_key, r.previous_public_key \
         FROM mesh_nodes n LEFT JOIN mesh_node_key_rotation r ON r.node_id = n.id \
         WHERE n.dataplane_host = 'server'",
    )
    .fetch_all(pool)
    .await
    .map_err(io::Error::other)?;
    let mut keys = Vec::new();
    for row in rows {
        for column in ["public_key", "candidate_public_key", "previous_public_key"] {
            let value: Option<Vec<u8>> = row.try_get(column).map_err(io::Error::other)?;
            if let Some(key) = value.and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()) {
                keys.push(key);
            }
        }
    }
    Ok(keys)
}

/// Mirror current mesh state to the legacy /run path before another binary starts.
///
/// The caller first stops and reaps the embedded writer. This function then takes the same
/// directory flocks used by mesh-store writers, in the stable durable-then-runtime order, and
/// copies the durable identity to the runtime path. The durable copy always stays: deleting it
/// would leave a volatile copy as the only one, lost on the next reboot (J595 P3-2).
///
/// It refuses to overwrite a runtime key that is neither the durable key nor the one this server
/// last mirrored: that key belongs to another server sharing the path.
/// # Errors
/// Refuses an unsafe directory, an unfinished transfer, a foreign runtime identity, or any copy,
/// removal, or sync failure.
pub fn rollback_handoff(durable: &Path, volatile: &Path) -> io::Result<()> {
    let uid = nix::unistd::Uid::effective().as_raw();
    ensure_mesh_directory(durable, uid)?;
    ensure_mesh_directory(volatile, uid)?;
    // Store writers and both migration directions use this stable lock order.
    let _durable_lock = lock_mesh_directory(durable)?;
    let _legacy_lock = lock_mesh_directory(volatile)?;
    sweep_migration_temporaries(durable, uid)?;
    sweep_migration_temporaries(volatile, uid)?;

    let marker = durable.join(MIGRATION_MARKER);
    if read_marker(&marker, uid)?.is_some() {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    let files = present_files(durable, uid)?;
    validate_private_key(durable, &files, uid)?;
    validate_private_key(volatile, &present_files(volatile, uid)?, uid)?;
    if let (Some(durable_key), Some(legacy_key)) = (
        read_private_key(durable, uid)?,
        read_private_key(volatile, uid)?,
    ) && durable_key[..] != legacy_key[..]
        && read_mirror_record(durable, uid)? != Some(public_key(&legacy_key)?)
    {
        log_foreign_identity(volatile, durable, &public_key(&legacy_key)?);
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    mirror_locked(durable, volatile, true, uid)
}

/// Create a mesh directory privately or tighten one owned by this service.
/// # Errors
/// Rejects a symlink, non-directory, different owner, or failed permission update.
fn ensure_mesh_directory(path: &Path, uid: u32) -> io::Result<()> {
    let mut path_may_be_new = false;
    let mut mode_changed = false;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && metadata.uid() == uid => {
            if metadata.mode() & 0o7777 != 0o700 {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
                mode_changed = true;
            }
        }
        Ok(_) => return Err(io::ErrorKind::PermissionDenied.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            path_may_be_new = true;
            // Concurrent server starts may both observe the missing path; the loser verifies
            // and secures the directory created by the winner below.
            match DirBuilder::new().mode(0o700).create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    }
    if owned_directory(path, uid, true)? {
        if path_may_be_new || mode_changed {
            sync_directory(path)?;
        }
        if path_may_be_new {
            sync_parent(path)?;
        }
        Ok(())
    } else {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

/// Check a directory without following symlinks, optionally tightening it to 0700.
/// # Errors
/// Rejects a non-directory, unowned path, or a directory that cannot be secured.
fn owned_directory(path: &Path, uid: u32, repair_mode: bool) -> io::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.is_dir() || metadata.uid() != uid {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    if metadata.mode() & 0o7777 != 0o700 {
        if !repair_mode {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        let secured = fs::symlink_metadata(path)?;
        if !secured.is_dir() || secured.uid() != uid || secured.mode() & 0o7777 != 0o700 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    Ok(true)
}

/// Check a singly-linked regular file and optionally set its mode to exactly 0600.
/// # Errors
/// Rejects symlinks, hard links, non-files, different owners, and failed permission updates.
fn owned_file(path: &Path, uid: u32, repair_mode: bool) -> io::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.uid() != uid || metadata.nlink() != 1 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    if repair_mode && metadata.mode() & 0o7777 != 0o600 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let secured = fs::symlink_metadata(path)?;
        if !secured.is_file()
            || secured.uid() != uid
            || secured.nlink() != 1
            || secured.mode() & 0o7777 != 0o600
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    Ok(true)
}

/// Return known mesh files present in one already-locked directory.
/// # Errors
/// Rejects unsafe types, owners, hard links, or mode updates.
fn present_files(directory: &Path, uid: u32) -> io::Result<Vec<&'static str>> {
    let mut files = Vec::new();
    for name in MESH_FILES {
        if owned_file(&directory.join(name), uid, true)? {
            files.push(*name);
        }
    }
    Ok(files)
}

/// Validate every present private key before migration can delete either copy.
/// # Errors
/// Refuses a key file whose stored seed is not exactly 32 bytes.
fn validate_private_key(directory: &Path, files: &[&str], uid: u32) -> io::Result<()> {
    if files.contains(&"mesh-private-key") {
        let path = directory.join("mesh-private-key");
        if !owned_file(&path, uid, true)? || fs::symlink_metadata(&path)?.len() != 32 {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok(())
}

/// Read one directory's private key without following links; `None` means no key file exists.
///
/// The bytes stay in a zeroizing buffer and never leave this module: callers only derive the
/// public key or compare two keys.
/// # Errors
/// Refuses an unsafe file or one whose length is not exactly 32 bytes.
fn read_private_key(
    directory: &Path,
    uid: u32,
) -> io::Result<Option<zeroize::Zeroizing<[u8; 32]>>> {
    let path = directory.join("mesh-private-key");
    if !owned_file(&path, uid, true)? {
        return Ok(None);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != uid || metadata.nlink() != 1 || metadata.len() != 32
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut key = zeroize::Zeroizing::new([0_u8; 32]);
    file.read_exact(key.as_mut())?;
    Ok(Some(key))
}

/// Derive the X25519 public key that a Mesh private key presents to its peers.
///
/// X25519 clamps the scalar itself, so a stored key gives the same public key here as in either
/// Mesh engine.
/// # Errors
/// Returns `InvalidData` if the crypto library rejects the key.
pub(crate) fn public_key(private: &[u8; 32]) -> io::Result<[u8; 32]> {
    let key = openssl::pkey::PKey::private_key_from_raw_bytes(private, openssl::pkey::Id::X25519)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let public = key
        .raw_public_key()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    public
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidData.into())
}

/// Format a public key for logs and records; public keys are not secret.
fn hex_key(key: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    key.iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// Open the mesh directory and take the same exclusive flock that guards mesh-store writes.
/// # Errors
/// Returns path validation, open, or lock failures.
fn lock_mesh_directory(path: &Path) -> io::Result<nix::fcntl::Flock<File>> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(path)?;
    nix::fcntl::Flock::lock(directory, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, error)| error.into())
}

/// Write a non-secret, versioned manifest before moving files so recovery knows what must exist.
/// # Errors
/// Returns an error if the marker cannot be created, made private, or synced.
fn create_marker(path: &Path, direction: Direction, files: &[&str]) -> io::Result<()> {
    let body = marker_body(direction, files)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(body.as_bytes())?;
    file.sync_all()
}

/// Replace a pending marker atomically when rollback added runtime files absent from its manifest.
/// # Errors
/// Refuses unsafe marker paths and reports failed private staging, rename, or sync operations.
fn rewrite_marker(path: &Path, direction: Direction, files: &[&str]) -> io::Result<()> {
    let body = marker_body(direction, files)?;
    let uid = nix::unistd::Uid::effective().as_raw();
    if !owned_file(path, uid, true)? {
        return Err(io::ErrorKind::NotFound.into());
    }
    replace_private_file(path, body.as_bytes())
}

/// Atomically replace a small private file through a unique synced 0600 temporary.
///
/// The temporary is named `.<name>.migrate-<pid>-<nonce>.new`, which the startup sweep removes
/// if a crash leaves it behind.
/// # Errors
/// Refuses an unsafe existing file and reports failed staging, rename, or directory sync.
fn replace_private_file(path: &Path, body: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let uid = nix::unistd::Uid::effective().as_raw();
    let _ = owned_file(path, uid, true)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(io::ErrorKind::InvalidInput)?;
    let temporary = path.with_file_name(format!(
        ".{name}.migrate-{}-{}.new",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(body)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

/// Encode the marker's non-secret direction and stable list of mesh files.
/// # Errors
/// Rejects empty or unknown file lists.
fn marker_body(direction: Direction, files: &[&str]) -> io::Result<String> {
    if files.is_empty() || files.iter().any(|name| !MESH_FILES.contains(name)) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let direction = match direction {
        Direction::Forward => "forward",
        Direction::Rollback => "rollback",
    };
    Ok(format!(
        "{MIGRATION_MARKER_HEADER}\n{direction}\n{}\n",
        files.join("\n")
    ))
}

/// Read a pending marker without following links and decode its bounded non-secret manifest.
/// # Errors
/// Rejects malformed marker data or unsafe file metadata without clearing the marker.
fn read_marker(path: &Path, uid: u32) -> io::Result<Option<Marker>> {
    if !owned_file(path, uid, true)? {
        return Ok(None);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    if file.metadata()?.len() > 1024 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut body = Vec::new();
    file.read_to_end(&mut body)?;
    if body == LEGACY_MIGRATION_MARKER {
        return Ok(Some(Marker {
            direction: Direction::Forward,
            legacy: true,
            files: Vec::new(),
        }));
    }
    let text = std::str::from_utf8(&body).map_err(|_| io::ErrorKind::InvalidData)?;
    let mut lines = text.lines();
    if lines.next() != Some(MIGRATION_MARKER_HEADER) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let direction = match lines.next() {
        Some("forward") => Direction::Forward,
        Some("rollback") => Direction::Rollback,
        _ => return Err(io::ErrorKind::InvalidData.into()),
    };
    let mut files = Vec::new();
    for line in lines {
        let Some(name) = MESH_FILES.iter().copied().find(|name| *name == line) else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        if files.contains(&name) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        files.push(name);
    }
    if files.is_empty() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(Marker {
        direction,
        legacy: false,
        files,
    }))
}

/// Rebuild an old marker's file list from both sides while both directories are locked.
/// # Errors
/// Refuses unsafe entries or an empty plan, which indicates there is nothing to resume.
fn union_files(source: &Path, target: &Path, uid: u32) -> io::Result<Vec<&'static str>> {
    let mut files = present_files(source, uid)?;
    for name in present_files(target, uid)? {
        if !files.contains(&name) {
            files.push(name);
        }
    }
    if files.is_empty() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(files)
}

/// Confirm that a marked transfer can still recover every file before changing either side.
/// # Errors
/// Leaves the marker in place if any planned file has disappeared from both directories.
fn ensure_recoverable_plan(
    source: &Path,
    target: &Path,
    files: &[&str],
    uid: u32,
) -> io::Result<()> {
    if files.is_empty() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    for name in files {
        let from = owned_file(&source.join(name), uid, true)?;
        let to = owned_file(&target.join(name), uid, true)?;
        if !from && !to {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok(())
}

/// Copy a marked set from the runtime path to durable storage and sync the target.
///
/// Sources stay in place. A source already consumed by an earlier move (first J501 candidates)
/// is accepted when its target exists, so recovery of their markers still completes.
/// # Errors
/// Leaves the marker in place when any planned file is missing from both sides or a copy fails.
fn copy_plan(source: &Path, target: &Path, files: &[&str], uid: u32) -> io::Result<()> {
    ensure_recoverable_plan(source, target, files, uid)?;
    for name in files {
        let _ = copy_one(&source.join(name), &target.join(name), uid)?;
    }
    for name in files {
        if !owned_file(&target.join(name), uid, true)? {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    validate_private_key(target, files, uid)?;
    sync_directory(target)
}

/// Publish one stable source as a unique, synced 0600 temporary followed by an atomic rename.
///
/// Ok(None) means a concurrent atomic writer changed the source before publication; callers retry
/// from its new inode. The directory flock normally prevents that race, while the identity check
/// keeps a non-cooperating writer's replacement from being unlinked.
/// # Errors
/// Refuses symlinks, hard links, malformed keys, and failed read, write, rename, or sync steps.
fn copy_one(source: &Path, target: &Path, uid: u32) -> io::Result<Option<FileIdentity>> {
    for _ in 0..MAX_SOURCE_RETRIES {
        match copy_one_attempt(source, target, uid)? {
            Some(identity) => return Ok(Some(identity)),
            None if !owned_file(source, uid, true)? => {
                if owned_file(target, uid, true)? {
                    return Ok(None);
                }
                return Err(io::ErrorKind::InvalidData.into());
            }
            None => {}
        }
    }
    Err(io::ErrorKind::WouldBlock.into())
}

/// Copy one stable inode; the caller retries if an atomic writer replaced its pathname.
fn copy_one_attempt(source: &Path, target: &Path, uid: u32) -> io::Result<Option<FileIdentity>> {
    if !owned_file(source, uid, true)? {
        if owned_file(target, uid, true)? {
            return Ok(None);
        }
        return Err(io::ErrorKind::InvalidData.into());
    }
    let is_key = source
        .file_name()
        .is_some_and(|name| name == "mesh-private-key");
    let source_metadata = fs::symlink_metadata(source)?;
    if is_key && source_metadata.len() != 32 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let identity = FileIdentity::from_metadata(&source_metadata);
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(source)?;
    let opened = input.metadata()?;
    if !opened.is_file()
        || opened.uid() != uid
        || opened.nlink() != 1
        || FileIdentity::from_metadata(&opened) != identity
        || opened.len() != source_metadata.len()
    {
        return Ok(None);
    }
    if is_key && opened.len() != 32 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let target_parent = target.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let target_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(io::ErrorKind::InvalidInput)?;
    let temporary = target.with_file_name(format!(
        ".{target_name}.migrate-{}-{}.new",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let result = (|| {
        let _ = owned_file(target, uid, true)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&temporary)?;
        output.set_permissions(fs::Permissions::from_mode(0o600))?;
        io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        drop(output);
        let current = fs::symlink_metadata(source)?;
        if !current.is_file()
            || current.uid() != uid
            || current.nlink() != 1
            || FileIdentity::from_metadata(&current) != identity
        {
            return Ok(None);
        }
        // The mesh directory lock makes replacement atomic with respect to every Store writer.
        fs::rename(&temporary, target)?;
        sync_directory(target_parent)?;
        Ok(Some(identity))
    })();
    if !matches!(&result, Ok(Some(_))) {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Check a pathname still names the copied inode and unlink it only when that check succeeds.
fn remove_if_same(path: &Path, expected: FileIdentity, uid: u32) -> io::Result<bool> {
    if !owned_file(path, uid, true)? {
        return Ok(true);
    }
    if !same_file_identity(path, expected)? {
        return Ok(false);
    }
    fs::remove_file(path)?;
    sync_parent(path)?;
    Ok(true)
}

/// Compare an existing pathname with the exact inode captured before the copy.
fn same_file_identity(path: &Path, expected: FileIdentity) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            Ok(FileIdentity::from_metadata(&metadata) == expected)
        }
        Ok(_) => Err(io::ErrorKind::PermissionDenied.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Remove the listed mesh files from one locked directory, each only if its inode is unchanged.
fn remove_files(directory: &Path, files: &[&str], uid: u32) -> io::Result<()> {
    for name in files {
        let path = directory.join(name);
        if owned_file(&path, uid, true)? {
            let metadata = fs::symlink_metadata(&path)?;
            if !remove_if_same(&path, FileIdentity::from_metadata(&metadata), uid)? {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
    }
    if owned_directory(directory, uid, false)? {
        sync_directory(directory)?;
    }
    Ok(())
}

/// Remove a completed marker only after every planned source and destination is durable.
/// # Errors
/// Returns validation, unlink, or sync errors without silently clearing an incomplete transfer.
fn finish_marker(path: &Path, uid: u32) -> io::Result<()> {
    if owned_file(path, uid, true)? {
        fs::remove_file(path)?;
        sync_parent(path)?;
    }
    Ok(())
}

/// Remove crash-left staging copies while holding the mesh directory's exclusive lock.
///
/// A staging key is safe to delete only because the transfer source remains present until after
/// its atomic destination rename. The old fixed staging name is accepted for recovery from the
/// first candidate; all new names include a process ID and random nonce.
/// # Errors
/// Refuses unsafe temporary entries and reports directory enumeration or unlink failures.
fn sweep_migration_temporaries(directory: &Path, uid: u32) -> io::Result<()> {
    let mut removed = false;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let has_new_extension = Path::new(&name)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("new"));
        let is_temporary = MESH_FILES.iter().any(|mesh_name| {
            name == format!(".{mesh_name}.migrate-new")
                || (name.starts_with(&format!(".{mesh_name}.migrate-")) && has_new_extension)
        }) || ([MIGRATION_MARKER, MIRROR_RECORD]
            .iter()
            .any(|record| name.starts_with(&format!(".{record}.migrate-")))
            && has_new_extension);
        if !is_temporary {
            continue;
        }
        if !entry.file_type()?.is_file() || !owned_file(&entry.path(), uid, true)? {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        fs::remove_file(entry.path())?;
        removed = true;
    }
    if removed {
        sync_directory(directory)?;
    }
    Ok(())
}

/// Sync the directory containing path after publishing or removing an entry.
/// # Errors
/// Returns a parent lookup, open, or sync error.
fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    sync_directory(parent)
}

/// Sync a directory entry set after a durable move step.
/// # Errors
/// Returns an open or sync error.
fn sync_directory(path: &Path) -> io::Result<()> {
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(path)?
        .sync_all()
}

#[cfg(test)]
mod tests {
    //! Proves legacy identity migration, durable precedence, permissions, and retry behavior.

    use super::{FileIdentity, MIGRATION_MARKER, migrate, remove_if_same, rollback_handoff};
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
        process::Command,
    };

    use sha2::Digest as _;

    /// Build a unique fixture root outside the repository so no private test key is committed.
    fn fixture_root() -> PathBuf {
        std::env::temp_dir().join(format!("j501-mesh-state-{}", uuid::Uuid::new_v4()))
    }

    /// RFC 7748 section 6.1 private key (Alice), used as a real X25519 identity fixture.
    const RFC7748_PRIVATE: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    /// The public key RFC 7748 section 6.1 gives for [`RFC7748_PRIVATE`].
    const RFC7748_PUBLIC: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];

    /// Ownership answer for fixtures whose database records the legacy key as the server's own.
    fn owned(_public: &[u8; 32]) -> bool {
        true
    }

    /// Find this migration's unique private staging file without depending on its random suffix.
    fn migration_temporary_exists(directory: &Path, file_name: &str) -> bool {
        let prefix = format!(".{file_name}.migrate-");
        fs::read_dir(directory).is_ok_and(|entries| {
            entries.flatten().any(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(&prefix) && name.ends_with(".new")
            })
        })
    }

    /// Copies the old private identity and public snapshot into a private durable directory.
    ///
    /// The runtime copy stays, so a previous build started cold still finds it (J595 P1).
    #[test]
    fn copies_legacy_mesh_identity_before_first_durable_start() {
        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let data = root.join("var/lib/infraternal");
        let durable = data.join("mesh");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime private");
        fs::create_dir_all(&data).expect("create server data directory");
        fs::write(volatile.join("mesh-private-key"), [0x11; 32])
            .expect("write synthetic legacy key");
        fs::write(volatile.join("mesh-public.json"), br#"{"enabled":true}"#)
            .expect("write synthetic public state");

        migrate(&volatile, &durable, &owned).expect("migrate legacy mesh state");

        assert_eq!(
            fs::read(durable.join("mesh-private-key")).expect("durable private key"),
            [0x11; 32]
        );
        assert_eq!(
            fs::read(durable.join("mesh-public.json")).expect("durable public state"),
            br#"{"enabled":true}"#
        );
        assert_eq!(
            fs::read(volatile.join("mesh-private-key")).expect("runtime key stays"),
            [0x11; 32]
        );
        let directory = fs::symlink_metadata(&durable).expect("durable directory metadata");
        assert_eq!(directory.uid(), nix::unistd::Uid::effective().as_raw());
        assert_eq!(directory.mode() & 0o777, 0o700);
        let key =
            fs::symlink_metadata(durable.join("mesh-private-key")).expect("durable key metadata");
        assert_eq!(key.uid(), nix::unistd::Uid::effective().as_raw());
        assert_eq!(key.mode() & 0o777, 0o600);
        migrate(&volatile, &durable, &owned).expect("a repeated start is harmless");
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    /// Keeps the durable identity and leaves another server's runtime identity untouched.
    #[test]
    fn durable_identity_wins_over_a_foreign_runtime_key() {
        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime private");
        fs::create_dir_all(&durable).expect("create durable mesh directory");
        fs::set_permissions(&durable, fs::Permissions::from_mode(0o755))
            .expect("make durable fixture initially broad");
        fs::write(volatile.join("mesh-private-key"), [0x21; 32])
            .expect("write synthetic runtime key");
        fs::write(volatile.join("mesh-public.json"), b"runtime-public")
            .expect("write synthetic runtime state");
        fs::write(durable.join("mesh-private-key"), [0x42; 32])
            .expect("write synthetic durable key");
        fs::set_permissions(
            durable.join("mesh-private-key"),
            fs::Permissions::from_mode(0o644),
        )
        .expect("make durable key initially broad");
        fs::write(durable.join("mesh-public.json"), b"durable-public")
            .expect("write synthetic durable state");

        migrate(&volatile, &durable, &|_| false).expect("keep the durable identity");

        assert_eq!(
            fs::read(durable.join("mesh-private-key")).expect("durable key"),
            [0x42; 32]
        );
        assert_eq!(
            fs::read(durable.join("mesh-public.json")).expect("durable public state"),
            b"durable-public"
        );
        assert_eq!(
            fs::read(volatile.join("mesh-private-key")).expect("foreign runtime key stays"),
            [0x21; 32]
        );
        assert_eq!(
            fs::read(volatile.join("mesh-public.json")).expect("foreign runtime state stays"),
            b"runtime-public"
        );
        let directory = fs::symlink_metadata(&durable).expect("durable directory metadata");
        assert_eq!(directory.mode() & 0o777, 0o700);
        let key =
            fs::symlink_metadata(durable.join("mesh-private-key")).expect("durable key metadata");
        assert_eq!(key.mode() & 0o777, 0o600);
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    /// Preserves a valid runtime key when the competing durable key is malformed.
    #[test]
    fn corrupt_durable_key_does_not_delete_a_valid_legacy_identity() {
        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime private");
        fs::create_dir_all(&durable).expect("create durable mesh directory");
        fs::set_permissions(&durable, fs::Permissions::from_mode(0o700))
            .expect("make durable mesh private");
        fs::write(volatile.join("mesh-private-key"), [0x42; 32])
            .expect("write valid-length legacy key");
        fs::set_permissions(
            volatile.join("mesh-private-key"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("make legacy key private");
        fs::write(durable.join("mesh-private-key"), b"truncated")
            .expect("write malformed durable key");
        fs::set_permissions(
            durable.join("mesh-private-key"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("make durable key private");

        let result = migrate(&volatile, &durable, &owned);
        let legacy_key_remains = volatile.join("mesh-private-key").exists();
        fs::remove_dir_all(root).expect("remove fixture root");

        assert!(result.is_err(), "a malformed durable key must fail closed");
        assert!(
            legacy_key_remains,
            "do not discard the valid legacy identity for malformed durable bytes"
        );
    }

    /// Finishes a marked move after the key reached durable storage but source cleanup did not.
    #[test]
    fn resumes_a_partial_move_without_replacing_the_durable_key() {
        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime private");
        fs::create_dir_all(&durable).expect("create durable mesh directory");
        fs::set_permissions(&durable, fs::Permissions::from_mode(0o700))
            .expect("make durable mesh private");
        fs::write(volatile.join("mesh-private-key"), [0x33; 32])
            .expect("write synthetic runtime key");
        fs::write(volatile.join("mesh-public.json"), b"runtime-public")
            .expect("write synthetic runtime state");
        fs::write(durable.join("mesh-private-key"), [0x33; 32])
            .expect("write already-published durable key");
        fs::write(
            durable.join(MIGRATION_MARKER),
            b"J501 mesh state migration\n",
        )
        .expect("write pending move marker");
        fs::set_permissions(
            durable.join(MIGRATION_MARKER),
            fs::Permissions::from_mode(0o600),
        )
        .expect("make pending move marker private");

        migrate(&volatile, &durable, &owned).expect("resume the interrupted move");

        assert_eq!(
            fs::read(durable.join("mesh-private-key")).expect("durable key"),
            [0x33; 32]
        );
        assert_eq!(
            fs::read(durable.join("mesh-public.json")).expect("durable public state"),
            b"runtime-public"
        );
        assert_eq!(
            fs::read(volatile.join("mesh-private-key")).expect("runtime mirror"),
            [0x33; 32]
        );
        assert!(!durable.join(MIGRATION_MARKER).exists());
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    /// Refuses a legacy symlink before following or deleting it.
    #[test]
    fn refuses_a_legacy_key_symlink_without_creating_a_replacement() {
        use std::os::unix::fs::symlink;

        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime private");
        fs::write(root.join("outside-key"), b"do-not-follow")
            .expect("write synthetic outside file");
        symlink(root.join("outside-key"), volatile.join("mesh-private-key"))
            .expect("create legacy key symlink");

        assert!(migrate(&volatile, &durable, &owned).is_err());
        assert!(!durable.join("mesh-private-key").exists());
        assert!(fs::symlink_metadata(volatile.join("mesh-private-key")).is_ok());
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    /// Refuses a durable key symlink without following it or deleting the legacy identity.
    #[test]
    fn refuses_a_durable_key_symlink_without_replacing_it() {
        use std::os::unix::fs::symlink;

        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime directory private");
        fs::create_dir_all(&durable).expect("create durable mesh directory");
        fs::set_permissions(&durable, fs::Permissions::from_mode(0o700))
            .expect("make durable mesh directory private");
        fs::write(volatile.join("mesh-private-key"), b"synthetic-legacy-key")
            .expect("write synthetic legacy key");
        let outside = root.join("outside-key");
        fs::write(&outside, b"synthetic-outside-key").expect("write outside fixture key");
        symlink(&outside, durable.join("mesh-private-key")).expect("create durable key symlink");

        let result = migrate(&volatile, &durable, &owned);

        assert!(result.is_err(), "a durable symlink must be rejected");
        assert!(volatile.join("mesh-private-key").exists());
        assert_eq!(
            fs::read(&outside).expect("outside fixture key"),
            b"synthetic-outside-key"
        );
        assert!(
            fs::symlink_metadata(durable.join("mesh-private-key"))
                .expect("durable symlink remains")
                .file_type()
                .is_symlink()
        );
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    /// Refuses a legacy runtime directory symlink instead of migrating through it.
    #[test]
    fn refuses_a_symlinked_legacy_directory() {
        use std::os::unix::fs::symlink;

        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let actual = root.join("actual-runtime");
        let durable = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(volatile.parent().expect("runtime parent"))
            .expect("create runtime parent");
        fs::create_dir(&actual).expect("create actual runtime directory");
        fs::set_permissions(&actual, fs::Permissions::from_mode(0o700))
            .expect("make actual runtime private");
        fs::write(actual.join("mesh-private-key"), [0x53; 32])
            .expect("write synthetic runtime key");
        symlink(&actual, &volatile).expect("link legacy runtime directory");

        let result = migrate(&volatile, &durable, &owned);

        assert!(
            result.is_err(),
            "a symlinked legacy directory must be rejected"
        );
        assert_eq!(
            fs::read(actual.join("mesh-private-key")).expect("actual legacy key remains"),
            [0x53; 32]
        );
        assert!(!durable.join("mesh-private-key").exists());
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    /// Refuses a durable mesh directory symlink without moving the legacy identity through it.
    #[test]
    fn refuses_a_symlinked_durable_directory() {
        use std::os::unix::fs::symlink;

        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        let actual = root.join("actual-durable");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime private");
        fs::write(volatile.join("mesh-private-key"), [0x53; 32])
            .expect("write synthetic runtime key");
        fs::create_dir_all(durable.parent().expect("durable parent"))
            .expect("create durable parent");
        fs::create_dir(&actual).expect("create actual durable directory");
        fs::set_permissions(&actual, fs::Permissions::from_mode(0o700))
            .expect("make actual durable directory private");
        symlink(&actual, &durable).expect("link durable mesh directory");

        let result = migrate(&volatile, &durable, &owned);

        assert!(
            result.is_err(),
            "a symlinked durable directory must be rejected"
        );
        assert_eq!(
            fs::read(volatile.join("mesh-private-key")).expect("legacy key remains"),
            [0x53; 32]
        );
        assert!(!actual.join("mesh-private-key").exists());
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    /// Leaves an interrupted migration marked when both the volatile source and durable key are gone.
    #[test]
    fn a_pending_migration_without_a_source_fails_closed() {
        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(&durable).expect("create durable mesh directory");
        fs::set_permissions(&durable, fs::Permissions::from_mode(0o700))
            .expect("make durable mesh directory private");
        fs::write(
            durable.join(MIGRATION_MARKER),
            b"J501 mesh state migration\n",
        )
        .expect("write pending migration marker");
        fs::set_permissions(
            durable.join(MIGRATION_MARKER),
            fs::Permissions::from_mode(0o600),
        )
        .expect("make migration marker private");

        let result = migrate(&volatile, &durable, &owned);
        let marker_remains = durable.join(MIGRATION_MARKER).exists();
        fs::remove_dir_all(root).expect("remove fixture root");

        assert!(
            result.is_err(),
            "a missing source must not create a new identity"
        );
        assert!(
            marker_remains,
            "retain evidence that the migration was interrupted"
        );
    }

    /// Copies the latest durable identity to the runtime path for a D295 rollback.
    ///
    /// The durable copy stays: removing it would leave a volatile copy as the only one (J595 P3-2).
    #[test]
    fn rollback_handoff_copies_the_identity_and_keeps_the_durable_copy() {
        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime directory private");
        fs::create_dir_all(&durable).expect("create durable mesh directory");
        fs::set_permissions(&durable, fs::Permissions::from_mode(0o700))
            .expect("make durable mesh directory private");
        fs::write(durable.join("mesh-private-key"), [0x55; 32])
            .expect("write synthetic durable key");
        fs::set_permissions(
            durable.join("mesh-private-key"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("make synthetic key private");
        fs::write(durable.join("mesh-public.json"), br#"{"enabled":true}"#)
            .expect("write synthetic durable state");
        fs::set_permissions(
            durable.join("mesh-public.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("make synthetic state private");

        rollback_handoff(&durable, &volatile).expect("restore durable state for the old binary");

        assert_eq!(
            fs::read(volatile.join("mesh-private-key")).expect("rollback key"),
            [0x55; 32]
        );
        assert_eq!(
            fs::read(volatile.join("mesh-public.json")).expect("rollback public state"),
            br#"{"enabled":true}"#
        );
        assert_eq!(
            fs::read(durable.join("mesh-private-key")).expect("durable key stays"),
            [0x55; 32]
        );
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    /// Keeps the public-key fingerprint unchanged through rollback and the next upgrade.
    ///
    /// The public state uses the real snapshot format: `config.local_key` of the mesh plugin's
    /// public `Config`, which `server mesh status` reads. The key that peers see is derived from
    /// the private key at every step, so the test proves the identity, not only copied bytes
    /// (J595 P3-1).
    #[cfg(feature = "mesh")]
    #[test]
    fn rollback_and_reupgrade_keep_the_same_public_key_fingerprint() {
        use infraternal_plugin_mesh::{
            dataplane::{Config, DefaultPolicy},
            policy::model::{Addresses, NodeId, PublicKey},
        };

        let root = fixture_root();
        let (volatile, durable) = private_directories(&root);
        write_private(&durable.join("mesh-private-key"), &RFC7748_PRIVATE);
        let config = Config {
            local_key: Some(PublicKey(RFC7748_PUBLIC)),
            server: Some(NodeId(1)),
            authority_epoch: None,
            node: NodeId(1),
            name: None,
            dns_suffix: infraternal_plugin_mesh::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            version: 1,
            addresses: Addresses {
                ipv4: "10.254.0.1".parse().expect("fixture IPv4"),
                ipv6: "fd01::1".parse().expect("fixture IPv6"),
            },
            default_policy: DefaultPolicy::Deny,
            exposure: None,
            peers: std::collections::BTreeMap::new(),
            peer_names: std::collections::BTreeMap::new(),
        };
        write_private(
            &durable.join("mesh-public.json"),
            &serde_json::to_vec(&serde_json::json!({"enabled": true, "config": config}))
                .expect("encode public state"),
        );

        // The fingerprint `server mesh status` prints: SHA-256 of the 32 public-key bytes.
        let fingerprint_at = |directory: &Path| {
            let state: serde_json::Value = serde_json::from_slice(
                &fs::read(directory.join("mesh-public.json")).expect("read public state"),
            )
            .expect("decode public state");
            let config: Config =
                serde_json::from_value(state["config"].clone()).expect("decode real config");
            let recorded = config.local_key.expect("recorded local key").0;
            let private: [u8; 32] = fs::read(directory.join("mesh-private-key"))
                .expect("read private key")
                .try_into()
                .expect("32-byte private key");
            let derived = super::public_key(&private).expect("derive public key");
            assert_eq!(recorded, derived, "public state must match the private key");
            <[u8; 32]>::from(sha2::Sha256::digest(derived))
        };
        let expected: [u8; 32] = sha2::Sha256::digest(RFC7748_PUBLIC).into();
        assert_eq!(fingerprint_at(&durable), expected);

        rollback_handoff(&durable, &volatile).expect("hand identity back to the previous build");
        assert_eq!(
            fingerprint_at(&volatile),
            expected,
            "the public-key fingerprint must survive rollback",
        );
        assert_eq!(
            fingerprint_at(&durable),
            expected,
            "the durable identity stays during rollback",
        );

        migrate(&volatile, &durable, &|public| *public == RFC7748_PUBLIC)
            .expect("migrate identity forward on re-upgrade");
        assert_eq!(
            fingerprint_at(&durable),
            expected,
            "the public-key fingerprint must survive re-upgrade",
        );
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    /// Removes the private staging link left if a process stops just after publishing its target.
    #[test]
    fn retry_cleans_a_temporary_key_after_the_durable_link_was_published() {
        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime private");
        fs::create_dir_all(&durable).expect("create durable mesh directory");
        fs::set_permissions(&durable, fs::Permissions::from_mode(0o700))
            .expect("make durable mesh private");
        fs::write(durable.join("mesh-private-key"), [0x53; 32])
            .expect("write already-published durable key");
        let temporary = durable.join(".mesh-private-key.migrate-new");
        fs::write(&temporary, [0x53; 32]).expect("write interrupted migration temporary");
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .expect("make interrupted temporary private");
        fs::write(volatile.join("mesh-private-key"), [0x53; 32])
            .expect("write remaining legacy source");
        fs::write(
            durable.join(MIGRATION_MARKER),
            b"J501 mesh state migration\n",
        )
        .expect("write pending migration marker");
        fs::set_permissions(
            durable.join(MIGRATION_MARKER),
            fs::Permissions::from_mode(0o600),
        )
        .expect("make migration marker private");

        migrate(&volatile, &durable, &owned).expect("resume the interrupted move");

        let temporary_remains = temporary.exists();
        let durable_key = fs::read(durable.join("mesh-private-key")).expect("durable key");
        fs::remove_dir_all(root).expect("remove fixture root");

        assert!(!temporary_remains, "retry must remove the extra key copy");
        assert_eq!(durable_key, [0x53; 32]);
    }

    /// Serializes two server starts so neither can unlink the other's in-progress staging file.
    #[test]
    fn concurrent_migrations_do_not_replace_each_others_temporary_key() {
        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime private");
        fs::create_dir_all(&durable).expect("create durable mesh directory");
        fs::set_permissions(&durable, fs::Permissions::from_mode(0o700))
            .expect("make durable mesh private");
        let key = [b'K'; 32];
        fs::write(
            volatile.join("mesh-public.json"),
            vec![b'P'; 64 * 1024 * 1024],
        )
        .expect("write large public state to hold the migration copy");
        fs::write(volatile.join("mesh-private-key"), key).expect("write synthetic key fixture");

        let first_source = volatile.clone();
        let first_durable = durable.clone();
        let first = std::thread::spawn(move || migrate(&first_source, &first_durable, &owned));
        for _ in 0..1_000_000 {
            if migration_temporary_exists(&durable, "mesh-public.json") {
                break;
            }
            std::thread::yield_now();
        }
        let temporary_was_published = migration_temporary_exists(&durable, "mesh-public.json");
        let second = migrate(&volatile, &durable, &owned);
        let first = first.join().expect("first migration thread");
        let durable_key = fs::read(durable.join("mesh-private-key")).ok();
        let temporary_remains = migration_temporary_exists(&durable, "mesh-public.json");
        fs::remove_dir_all(root).expect("remove fixture root");

        assert!(
            temporary_was_published,
            "first migration reached its staging file"
        );
        assert!(first.is_ok(), "first migration must complete");
        assert!(
            second.is_ok(),
            "second migration must wait for or join the first"
        );
        assert!(
            durable_key
                .as_deref()
                .is_some_and(|saved| saved == key.as_slice()),
            "the published key must be complete and unchanged"
        );
        assert!(
            !temporary_remains,
            "completed migrations leave no staging key"
        );
    }

    /// Lets many first starts race the absent durable directory without losing startup to `mkdir`.
    #[test]
    fn concurrent_first_starts_share_one_new_durable_mesh_directory() {
        use std::{
            sync::{Arc, Barrier},
            thread,
        };

        const STARTS: usize = 32;
        const ROUNDS: usize = 8;
        for _ in 0..ROUNDS {
            let root = fixture_root();
            let volatile = root.join("run/infraternal");
            let durable = root.join("var/lib/infraternal/mesh");
            fs::create_dir_all(&volatile).expect("create legacy runtime directory");
            fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
                .expect("make legacy runtime private");
            fs::write(volatile.join("mesh-private-key"), [0x61; 32])
                .expect("write synthetic legacy key");
            fs::create_dir_all(durable.parent().expect("durable parent"))
                .expect("create service data directory");

            let barrier = Arc::new(Barrier::new(STARTS + 1));
            let starts = (0..STARTS)
                .map(|_| {
                    let barrier = Arc::clone(&barrier);
                    let volatile = volatile.clone();
                    let durable = durable.clone();
                    thread::spawn(move || {
                        barrier.wait();
                        migrate(&volatile, &durable, &owned)
                    })
                })
                .collect::<Vec<_>>();
            barrier.wait();
            let results = starts
                .into_iter()
                .map(|start| start.join().expect("first-start migration thread"))
                .collect::<Vec<_>>();
            let failures = results
                .iter()
                .filter_map(|result| result.as_ref().err().map(std::io::Error::kind))
                .collect::<Vec<_>>();
            let key = fs::read(durable.join("mesh-private-key")).ok();
            fs::remove_dir_all(root).expect("remove fixture root");

            assert!(
                results.iter().all(Result::is_ok),
                "every concurrent first start must accept the one directory another start created; errors: {failures:?}"
            );
            assert_eq!(key.as_deref(), Some(&[0x61; 32][..]));
        }
    }

    /// Keeps an agent's atomic key update when it races a copy from its runtime directory.
    #[test]
    fn a_concurrent_agent_key_update_is_not_unlinked_or_overwritten() {
        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime private");
        fs::create_dir_all(&durable).expect("create durable mesh directory");
        fs::set_permissions(&durable, fs::Permissions::from_mode(0o700))
            .expect("make durable mesh private");
        let source = volatile.join("mesh-private-key");
        let original = [0x11; 32];
        fs::write(
            volatile.join("mesh-public.json"),
            vec![b'P'; 64 * 1024 * 1024],
        )
        .expect("write large public state to hold the migration copy");
        fs::write(&source, original).expect("write synthetic original key");
        let migration_source = volatile.clone();
        let migration_target = durable.clone();
        let migration =
            std::thread::spawn(move || migrate(&migration_source, &migration_target, &owned));
        for _ in 0..1_000_000 {
            if migration_temporary_exists(&durable, "mesh-public.json") {
                break;
            }
            std::thread::yield_now();
        }
        let temporary_was_published = migration_temporary_exists(&durable, "mesh-public.json");
        let writer_temporary = volatile.join("mesh-private-key.4242.new");
        fs::write(&writer_temporary, [0x24; 32]).expect("write synthetic rotated key");
        fs::set_permissions(&writer_temporary, fs::Permissions::from_mode(0o600))
            .expect("make rotated key private");
        fs::rename(&writer_temporary, &source).expect("atomically publish rotated key");

        let result = migration.join().expect("migration thread");
        let durable_is_latest =
            fs::read(durable.join("mesh-private-key")).ok().as_deref() == Some(&[0x24; 32][..]);
        fs::remove_dir_all(root).expect("remove fixture root");

        assert!(temporary_was_published, "migration reached its copy phase");
        assert!(result.is_ok(), "the migration must finish");
        assert!(
            durable_is_latest,
            "the durable path must receive the agent's latest key, not an older inode"
        );
    }

    /// Does not unlink a newer key that replaced the copied source inode.
    #[test]
    fn does_not_remove_a_newer_atomic_key_replacement() {
        let root = fixture_root();
        let directory = root.join("mesh");
        fs::create_dir_all(&directory).expect("create private fixture directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("make fixture directory private");
        let source = directory.join("mesh-private-key");
        let old = [0x11; 32];
        let newer = [0x24; 32];
        fs::write(&source, old).expect("write original synthetic key");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600))
            .expect("make original key private");
        let copied = FileIdentity::from_metadata(
            &fs::symlink_metadata(&source).expect("read original key identity"),
        );
        let temporary = directory.join("mesh-private-key.4242.new");
        fs::write(&temporary, newer).expect("write replacement synthetic key");
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .expect("make replacement key private");
        fs::rename(&temporary, &source).expect("atomically publish replacement key");

        let removed = remove_if_same(&source, copied, nix::unistd::Uid::effective().as_raw())
            .expect("check copied source before cleanup");
        let retained = fs::read(&source).ok();
        fs::remove_dir_all(root).expect("remove fixture root");

        assert!(!removed, "cleanup must not unlink a replacement inode");
        assert_eq!(
            retained.as_deref(),
            Some(&newer[..]),
            "the newer key must remain intact"
        );
    }

    /// Refuses a durable key hard-linked into another path that may be part of a backup.
    #[test]
    fn refuses_a_hardlinked_durable_private_key() {
        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        let data = durable.parent().expect("service data directory");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime private");
        fs::create_dir_all(data).expect("create service data directory");
        fs::create_dir_all(&durable).expect("create durable mesh directory");
        fs::set_permissions(&durable, fs::Permissions::from_mode(0o700))
            .expect("make durable mesh directory private");
        fs::write(volatile.join("mesh-private-key"), [0x53; 32])
            .expect("write synthetic legacy key");
        let backup_selected_path = data.join("backup-selected-config");
        fs::write(&backup_selected_path, [0x53; 32]).expect("write synthetic backup-selected file");
        fs::hard_link(&backup_selected_path, durable.join("mesh-private-key"))
            .expect("link durable key into backup-selected path");

        let result = migrate(&volatile, &durable, &owned);
        let legacy_key_remains = volatile.join("mesh-private-key").exists();
        fs::remove_dir_all(root).expect("remove fixture root");

        assert!(
            result.is_err(),
            "a multiply-linked key cannot be treated as private"
        );
        assert!(
            legacy_key_remains,
            "refusal must preserve the legacy identity"
        );
    }

    /// Refuses a legacy key whose inode is also reachable through a backup-selected path.
    #[test]
    fn refuses_a_hardlinked_legacy_private_key() {
        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        let data = durable.parent().expect("service data directory");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime private");
        fs::create_dir_all(data).expect("create service data directory");
        fs::create_dir_all(&durable).expect("create durable mesh directory");
        fs::set_permissions(&durable, fs::Permissions::from_mode(0o700))
            .expect("make durable mesh directory private");
        let backup_selected_path = data.join("backup-selected-config");
        fs::write(&backup_selected_path, [0x53; 32]).expect("write synthetic backup-selected file");
        fs::hard_link(&backup_selected_path, volatile.join("mesh-private-key"))
            .expect("link legacy key into backup-selected path");

        let result = migrate(&volatile, &durable, &owned);
        let backup_copy_remains = backup_selected_path.exists();
        fs::remove_dir_all(root).expect("remove fixture root");

        assert!(
            result.is_err(),
            "a multiply-linked key cannot be migrated as private"
        );
        assert!(
            backup_copy_remains,
            "refusal must not pretend the exposed key was moved"
        );
    }

    /// Keeps the durable key at the exact mode that the mesh store requires under a strict umask.
    #[test]
    fn durable_private_key_mode_is_exact_under_umask() {
        const CHILD_ENV: &str = "INFRATERAL_TEST_MESH_UMASK_ROOT";
        let root = if let Some(root) = std::env::var_os(CHILD_ENV) {
            PathBuf::from(root)
        } else {
            let root = fixture_root();
            let volatile = root.join("run/infraternal");
            let durable = root.join("var/lib/infraternal/mesh");
            fs::create_dir_all(&volatile).expect("create legacy runtime directory");
            fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
                .expect("make legacy runtime directory private");
            fs::create_dir_all(&durable).expect("create durable mesh directory");
            fs::set_permissions(&durable, fs::Permissions::from_mode(0o700))
                .expect("make durable mesh directory private");
            fs::write(volatile.join("mesh-private-key"), [0x53; 32])
                .expect("write synthetic legacy key");
            fs::set_permissions(
                volatile.join("mesh-private-key"),
                fs::Permissions::from_mode(0o600),
            )
            .expect("make synthetic key private");

            // `module_path!()` includes the crate name, while libtest's exact
            // names start at the first Rust module.
            let crate_prefix = format!("{}::", env!("CARGO_CRATE_NAME"));
            let test_module = module_path!()
                .strip_prefix(&crate_prefix)
                .unwrap_or(module_path!());
            let test_name = format!("{test_module}::durable_private_key_mode_is_exact_under_umask");
            let output = Command::new("sh")
                .args(["-c", "umask 0200; exec \"$@\"", "sh"])
                .arg(std::env::current_exe().expect("current test executable"))
                .args(["--exact", test_name.as_str(), "--nocapture"])
                .env(CHILD_ENV, &root)
                .output()
                .expect("run umask probe in an isolated process");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            fs::remove_dir_all(&root).expect("remove fixture root");
            assert!(
                output.status.success() && stdout.contains("1 passed"),
                "strict-umask probe did not pass: {stdout}{stderr}"
            );
            return;
        };

        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        migrate(&volatile, &durable, &owned).expect("migrate under a strict umask");
        let key =
            fs::symlink_metadata(durable.join("mesh-private-key")).expect("durable key metadata");
        assert_eq!(
            key.mode() & 0o777,
            0o600,
            "the mesh store requires the exact 0600 key mode"
        );
    }

    /// Creates a new durable directory with exact 0700 permissions under a strict umask.
    #[test]
    fn new_durable_directory_mode_is_exact_under_umask() {
        use std::os::unix::fs::MetadataExt;

        const CHILD_ENV: &str = "INFRATERAL_TEST_MESH_DIR_UMASK_ROOT";
        let root = if let Some(root) = std::env::var_os(CHILD_ENV) {
            PathBuf::from(root)
        } else {
            let root = fixture_root();
            let volatile = root.join("run/infraternal");
            let durable = root.join("var/lib/infraternal/mesh");
            fs::create_dir_all(&volatile).expect("create legacy runtime directory");
            fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
                .expect("make legacy runtime directory private");
            fs::create_dir_all(durable.parent().expect("durable parent"))
                .expect("create service data directory");
            fs::write(volatile.join("mesh-private-key"), [0x53; 32])
                .expect("write synthetic legacy key");
            fs::set_permissions(
                volatile.join("mesh-private-key"),
                fs::Permissions::from_mode(0o600),
            )
            .expect("make synthetic key private");

            let crate_prefix = format!("{}::", env!("CARGO_CRATE_NAME"));
            let test_module = module_path!()
                .strip_prefix(&crate_prefix)
                .unwrap_or(module_path!());
            let test_name =
                format!("{test_module}::new_durable_directory_mode_is_exact_under_umask");
            let output = Command::new("sh")
                .args(["-c", "umask 0200; exec \"$@\"", "sh"])
                .arg(std::env::current_exe().expect("current test executable"))
                .args(["--exact", test_name.as_str(), "--nocapture"])
                .env(CHILD_ENV, &root)
                .output()
                .expect("run directory-mode probe in an isolated process");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            fs::remove_dir_all(&root).expect("remove fixture root");
            assert!(
                output.status.success() && stdout.contains("1 passed"),
                "strict-umask directory probe did not pass: {stdout}{stderr}"
            );
            return;
        };

        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        migrate(&volatile, &durable, &owned).expect("migrate under a strict umask");
        let directory = fs::symlink_metadata(durable).expect("durable directory metadata");
        assert_eq!(
            directory.mode() & 0o777,
            0o700,
            "Mesh state requires the exact 0700 directory mode"
        );
    }

    /// Waits for the mesh store's directory lock before migration can move its files.
    #[test]
    fn migration_waits_for_the_mesh_store_directory_lock() {
        use std::{os::unix::fs::OpenOptionsExt, sync::mpsc, thread, time::Duration};

        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime private");
        fs::create_dir_all(&durable).expect("create durable mesh directory");
        fs::set_permissions(&durable, fs::Permissions::from_mode(0o700))
            .expect("make durable mesh directory private");
        fs::write(volatile.join("mesh-private-key"), [0x71; 32])
            .expect("write synthetic legacy key");

        let directory_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
            .open(&durable)
            .expect("open the mesh store directory");
        let store_lock = nix::fcntl::Flock::lock(directory_fd, nix::fcntl::FlockArg::LockExclusive)
            .expect("hold the lock used by mesh store writers");

        let (started, started_rx) = mpsc::sync_channel(1);
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let migration_source = volatile.clone();
        let migration_target = durable.clone();
        let migration = thread::spawn(move || {
            started.send(()).expect("signal migration start");
            result_tx
                .send(migrate(&migration_source, &migration_target, &owned))
                .expect("send migration result");
        });
        started_rx
            .recv()
            .expect("wait until migration thread is ready");

        // sleep: This bounded observation window proves migration cannot finish while the store lock is held.
        let while_locked = result_rx.recv_timeout(Duration::from_millis(250));
        assert!(
            matches!(while_locked, Err(mpsc::RecvTimeoutError::Timeout)),
            "migration must wait until the live mesh store releases its directory lock"
        );
        drop(store_lock);

        let result = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("migration should finish after the store lock is released");
        migration.join().expect("migration worker");
        assert!(
            result.is_ok(),
            "migration should succeed after lock release"
        );
        assert_eq!(
            fs::read(durable.join("mesh-private-key")).expect("durable private key"),
            [0x71; 32]
        );
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    /// J595 P0: a second root server on the same host must not take the live server's identity.
    ///
    /// Every root server resolves the same legacy path, `/run/infraternal`. The release flow
    /// starts a throwaway root server on a copy of production data (the migration check) before
    /// it upgrades production. If that check instance migrates first, it moves production's live
    /// key into its own scratch `mesh/` directory, which is then deleted. Production's own upgrade
    /// then finds nothing to migrate and mints a new key, which is the F8 failure this branch fixes.
    /// The fix is an ownership check: the public key derived from the legacy key must be the one
    /// this data directory's database records for its `server` node. Here the second instance's
    /// database does not record it; a byte copy of production's database is covered separately.
    #[test]
    fn a_second_server_instance_does_not_take_the_live_servers_legacy_identity() {
        let root = fixture_root();
        let shared_runtime = root.join("run/infraternal");
        let check_instance = root.join("root/migcheck/mesh");
        let production = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(&shared_runtime).expect("create shared legacy runtime directory");
        fs::set_permissions(&shared_runtime, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime private");
        fs::create_dir_all(check_instance.parent().expect("check data directory"))
            .expect("create migration-check data directory");
        fs::create_dir_all(production.parent().expect("production data directory"))
            .expect("create production data directory");
        fs::write(shared_runtime.join("mesh-private-key"), [0x2a; 32])
            .expect("write the live server's synthetic key");
        fs::write(
            shared_runtime.join("mesh-public.json"),
            br#"{"enabled":true}"#,
        )
        .expect("write the live server's public state");

        let live_public = super::public_key(&[0x2a; 32]).expect("derive the live public key");
        // The other server starts first; its database records some other server node key.
        let check = migrate(&shared_runtime, &check_instance, &|public| {
            *public == [0x99; 32]
        });
        // Production is upgraded afterwards and must still find its own identity.
        let production_result = migrate(&shared_runtime, &production, &|public| {
            *public == live_public
        });
        let production_key = fs::read(production.join("mesh-private-key")).ok();
        let check_key = fs::read(check_instance.join("mesh-private-key")).ok();
        fs::remove_dir_all(root).expect("remove fixture root");

        assert!(
            production_result.is_ok(),
            "production's upgrade must migrate"
        );
        assert_eq!(
            production_key.as_deref(),
            Some([0x2a; 32].as_slice()),
            "production must keep its live identity after another instance started (check: {check:?})"
        );
        assert_eq!(
            check_key, None,
            "a server that does not own the identity must never hold a copy of it"
        );
    }

    /// The ownership proof derives the same public key that peers know, per the RFC 7748 vector.
    #[test]
    fn ownership_proof_derives_the_x25519_public_key() {
        assert_eq!(
            super::public_key(&RFC7748_PRIVATE).expect("derive public key"),
            RFC7748_PUBLIC
        );
    }

    /// Only the `server` node's key counts as this server's own, read from the real schema.
    #[tokio::test]
    async fn ownership_reads_only_the_server_nodes_key() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("open in-memory database");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrate fixture database");
        sqlx::query(
            "INSERT INTO mesh_nodes(id,name,public_key,dataplane_host) \
             VALUES (1,'server',?,'server'),(2,'peer',?,'host-1')",
        )
        .bind(RFC7748_PUBLIC.as_slice())
        .bind([0x44_u8; 32].as_slice())
        .execute(&pool)
        .await
        .expect("insert server and peer nodes");

        let keys = super::server_node_keys(&pool)
            .await
            .expect("read server node keys");

        assert_eq!(keys, vec![RFC7748_PUBLIC]);
    }

    /// A legacy key the database does not record is left in place, and nothing is adopted.
    #[test]
    fn an_unowned_legacy_identity_is_left_in_place() {
        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime private");
        fs::create_dir_all(durable.parent().expect("data directory"))
            .expect("create data directory");
        fs::write(volatile.join("mesh-private-key"), RFC7748_PRIVATE)
            .expect("write synthetic legacy key");
        fs::write(volatile.join("mesh-public.json"), b"other-server-public")
            .expect("write synthetic legacy state");

        let result = migrate(&volatile, &durable, &|public| *public == [0; 32]);
        let legacy_key = fs::read(volatile.join("mesh-private-key")).ok();
        let legacy_public = fs::read(volatile.join("mesh-public.json")).ok();
        let durable_entries = fs::read_dir(&durable)
            .expect("durable directory exists")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>();
        fs::remove_dir_all(root).expect("remove fixture root");

        assert!(result.is_ok(), "an unowned identity is not a start failure");
        assert_eq!(legacy_key.as_deref(), Some(RFC7748_PRIVATE.as_slice()));
        assert_eq!(
            legacy_public.as_deref(),
            Some(b"other-server-public".as_slice())
        );
        assert!(
            durable_entries.is_empty(),
            "nothing may be adopted from an unowned identity: {durable_entries:?}"
        );
    }

    /// Create private runtime and durable fixture directories under one fixture root.
    fn private_directories(root: &Path) -> (PathBuf, PathBuf) {
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        for directory in [&volatile, &durable] {
            fs::create_dir_all(directory).expect("create fixture directory");
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("make fixture directory private");
        }
        (volatile, durable)
    }

    /// Write one private 0600 fixture file.
    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write fixture file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("make fixture file private");
    }

    /// J595 P0 limit: a byte copy of the database passes the ownership proof, so the check copy
    /// gets a copy too, but the live server's runtime identity is never taken away from it.
    #[test]
    fn a_byte_copy_of_the_database_never_takes_the_live_identity_away() {
        let root = fixture_root();
        let (shared_runtime, production) = private_directories(&root);
        let check_instance = root.join("root/migcheck/mesh");
        fs::create_dir_all(check_instance.parent().expect("check data directory"))
            .expect("create migration-check data directory");
        write_private(&shared_runtime.join("mesh-private-key"), &[0x2a; 32]);

        let check = migrate(&shared_runtime, &check_instance, &owned);
        fs::remove_dir_all(&check_instance).expect("the check deletes its scratch data");
        let production_result = migrate(&shared_runtime, &production, &owned);
        let production_key = fs::read(production.join("mesh-private-key")).ok();
        let runtime_key = fs::read(shared_runtime.join("mesh-private-key")).ok();
        fs::remove_dir_all(root).expect("remove fixture root");

        assert!(check.is_ok() && production_result.is_ok());
        assert_eq!(production_key.as_deref(), Some([0x2a; 32].as_slice()));
        assert_eq!(runtime_key.as_deref(), Some([0x2a; 32].as_slice()));
    }

    /// J595 P1: after any start of the new build, the previous build started cold keeps the key.
    ///
    /// This covers a crash or failed start of the new build (Restart=on-failure runs the previous
    /// build), a cold rollback, and `server restart --binary <old>` without `--rollback`.
    #[test]
    fn a_previous_build_started_cold_finds_the_same_identity() {
        let root = fixture_root();
        let (volatile, durable) = private_directories(&root);
        write_private(&volatile.join("mesh-private-key"), &[0x31; 32]);
        write_private(&volatile.join("mesh-public.json"), b"legacy-public");

        migrate(&volatile, &durable, &owned).expect("first start of the new build");
        // Reboot under the new build: the runtime path is empty again.
        fs::remove_dir_all(&volatile).expect("reboot clears the runtime path");
        fs::create_dir(&volatile).expect("service manager recreates the runtime path");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("runtime path is private");
        migrate(&volatile, &durable, &owned).expect("start after reboot");
        let runtime_key = fs::read(volatile.join("mesh-private-key")).ok();
        let runtime_public = fs::read(volatile.join("mesh-public.json")).ok();
        fs::remove_dir_all(root).expect("remove fixture root");

        assert_eq!(runtime_key.as_deref(), Some([0x31; 32].as_slice()));
        assert_eq!(runtime_public.as_deref(), Some(b"legacy-public".as_slice()));
    }

    /// The new build's own rotation since its last start refreshes the runtime mirror, even
    /// without an ownership answer, because the record shows the old runtime key was its mirror.
    #[test]
    fn an_own_stale_mirror_is_refreshed_after_rotation() {
        let root = fixture_root();
        let (volatile, durable) = private_directories(&root);
        write_private(&durable.join("mesh-private-key"), &[0x41; 32]);
        migrate(&volatile, &durable, &|_| false).expect("first mirror");
        // The running node rotates its durable key; only the durable copy changes.
        write_private(&durable.join("mesh-private-key"), &[0x42; 32]);
        write_private(&durable.join("mesh-key-rotation.bin"), b"journal");

        migrate(&volatile, &durable, &|_| false).expect("next start");
        let runtime_key = fs::read(volatile.join("mesh-private-key")).ok();
        let durable_key = fs::read(durable.join("mesh-private-key")).ok();
        let runtime_journal = fs::read(volatile.join("mesh-key-rotation.bin")).ok();
        fs::remove_dir_all(root).expect("remove fixture root");

        assert_eq!(durable_key.as_deref(), Some([0x42; 32].as_slice()));
        assert_eq!(runtime_key.as_deref(), Some([0x42; 32].as_slice()));
        assert_eq!(runtime_journal.as_deref(), Some(b"journal".as_slice()));
    }

    /// A key the previous build rotated or minted after a cold rollback is adopted on re-upgrade,
    /// with the replaced identity's durable-only files removed.
    #[test]
    fn a_key_the_previous_build_changed_is_adopted() {
        let root = fixture_root();
        let (volatile, durable) = private_directories(&root);
        write_private(&durable.join("mesh-private-key"), &[0x51; 32]);
        write_private(&durable.join("mesh-key-rotation.bin"), b"old-journal");
        migrate(&volatile, &durable, &owned).expect("mirror before the rollback");
        // The previous build runs cold, rotates its key and rewrites its public state.
        write_private(&volatile.join("mesh-private-key"), &[0x52; 32]);
        write_private(&volatile.join("mesh-public.json"), b"rotated-public");
        fs::remove_file(volatile.join("mesh-key-rotation.bin")).expect("journal finished");
        let rotated = super::public_key(&[0x52; 32]).expect("derive rotated public key");

        migrate(&volatile, &durable, &|public| *public == rotated).expect("re-upgrade");
        let durable_key = fs::read(durable.join("mesh-private-key")).ok();
        let durable_public = fs::read(durable.join("mesh-public.json")).ok();
        let stale_journal = durable.join("mesh-key-rotation.bin").exists();
        fs::remove_dir_all(root).expect("remove fixture root");

        assert_eq!(durable_key.as_deref(), Some([0x52; 32].as_slice()));
        assert_eq!(
            durable_public.as_deref(),
            Some(b"rotated-public".as_slice())
        );
        assert!(
            !stale_journal,
            "the replaced identity's journal must not survive"
        );
    }

    /// A warm handoff never overwrites a runtime key that another server put there.
    #[test]
    fn rollback_handoff_refuses_to_overwrite_a_foreign_runtime_key() {
        let root = fixture_root();
        let (volatile, durable) = private_directories(&root);
        write_private(&durable.join("mesh-private-key"), &[0x61; 32]);
        write_private(&volatile.join("mesh-private-key"), &[0x62; 32]);

        let result = rollback_handoff(&durable, &volatile);
        let runtime_key = fs::read(volatile.join("mesh-private-key")).ok();
        fs::remove_dir_all(root).expect("remove fixture root");

        assert!(
            result.is_err(),
            "a foreign runtime key must refuse the handoff"
        );
        assert_eq!(runtime_key.as_deref(), Some([0x62; 32].as_slice()));
    }

    /// J595 P2: every file the mesh Store keeps must be moved by migration and rollback.
    ///
    /// `MESH_FILES` is a hand-kept copy of the names `Store::open` uses. A branch that adds a Store
    /// file (J510c adds `mesh-listen-port.json`) would leave that file behind on upgrade and
    /// rollback with no failing test. This guard reads the Store source so the two lists cannot
    /// drift silently. It passes on J501b alone and fails once J510c is merged.
    #[test]
    fn mesh_files_cover_every_file_the_store_opens() {
        let source = include_str!("../../plugins/mesh/src/node_state.rs");
        let mut missing = Vec::new();
        for (index, _) in source.match_indices("parent.join(\"") {
            let start = index + "parent.join(\"".len();
            let Some(length) = source[start..].find('"') else {
                continue;
            };
            let name = &source[start..start + length];
            if !super::MESH_FILES.contains(&name) && !missing.contains(&name) {
                missing.push(name);
            }
        }
        assert!(
            missing.is_empty(),
            "Store files missing from MESH_FILES: {missing:?}"
        );
    }
}
