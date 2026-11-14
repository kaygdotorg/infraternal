//! Holds the embedded server node's mesh files durably and moves them safely across rollback [J501, #489].

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

/// Node files written by the mesh store; keep this list aligned with `Store::open`.
const MESH_FILES: &[&str] = &[
    "mesh-public.json",
    "mesh-routes.json",
    "mesh-interface.json",
    "mesh-key-rotation.bin",
    "mesh-engine.json",
    "mesh-authority.json",
    "mesh-private-key",
];

/// A durable marker that lets an interrupted cross-filesystem move resume safely.
const MIGRATION_MARKER: &str = ".mesh-state-migration.pending";
/// Versioned marker header; its body lists the files that the interrupted transfer owns.
const MIGRATION_MARKER_HEADER: &str = "J501 mesh state migration v1";
/// Marker body used by the first candidate; recovery infers its file list from both directories.
const LEGACY_MIGRATION_MARKER: &[u8] = b"J501 mesh state migration\n";
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
/// This takes the same directory flock that guards mesh-store writes. A durable private key wins
/// over stale runtime files unless a pending rollback marker says the previous build may have
/// updated its runtime copy. Transfers use unique synced 0600 temporaries, atomic renames, and
/// source inode checks. A marker records the exact unfinished file set; startup never clears an
/// incomplete marker or starts a child that could mint another identity.
///
/// Mesh private keys stay outside the D147 backup set, which contains the database, CA key and
/// configuration.
/// # Errors
/// Refuses unsafe owners, permissions, file types, or any failed filesystem operation.
pub(crate) fn migrate(volatile: &Path, durable: &Path) -> io::Result<()> {
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
        // A rollback marker makes the previous build's possibly updated runtime identity
        // authoritative on re-upgrade. Its expanded file list is durable before this move.
        move_plan(volatile, durable, &pending.files, uid)?;
        finish_marker(&marker, uid)?;
        sync_directory(durable)?;
        return if legacy_exists {
            sync_directory(volatile)
        } else {
            Ok(())
        };
    }

    let durable_files = present_files(durable, uid)?;
    let legacy_files = if legacy_exists {
        present_files(volatile, uid)?
    } else {
        Vec::new()
    };
    validate_private_key(durable, &durable_files, uid)?;
    validate_private_key(volatile, &legacy_files, uid)?;

    if durable_files.contains(&"mesh-private-key") {
        // Without a rollback marker, the complete durable identity wins over stale /run files.
        remove_files(volatile, &legacy_files, uid)?;
        return sync_directory(durable);
    }
    if legacy_files.is_empty() {
        return Ok(());
    }

    create_marker(&marker, Direction::Forward, &legacy_files)?;
    sync_directory(durable)?;
    move_plan(volatile, durable, &legacy_files, uid)?;
    finish_marker(&marker, uid)?;
    sync_directory(durable)?;
    sync_directory(volatile)
}

/// Hand current mesh state back to the legacy /run path before a previous binary starts.
///
/// The caller first stops and reaps the embedded writer. This function then takes the same
/// directory flock used by mesh-store writers, copies the selected state, verifies destination
/// files and source inodes, and only then removes durable entries. Its marker remains until the
/// next new build migrates the previous build's possibly updated state forward.
/// # Errors
/// Refuses an unsafe directory, incomplete state, or any copy, sync, or unlink failure.
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
    if files.is_empty() {
        return Ok(());
    }
    validate_private_key(durable, &files, uid)?;
    // Existing runtime bytes are stale, but their path types and link counts must be safe to replace.
    present_files(volatile, uid)?;
    create_marker(&marker, Direction::Rollback, &files)?;
    sync_directory(durable)?;

    let mut sources = Vec::with_capacity(files.len());
    for name in &files {
        let source = durable.join(name);
        let target = volatile.join(name);
        let identity = copy_one(&source, &target, uid)?.ok_or(io::ErrorKind::InvalidData)?;
        sources.push((source, identity));
    }
    validate_private_key(volatile, &present_files(volatile, uid)?, uid)?;
    sync_directory(volatile)?;
    // Check the complete source set before removing any source. The exclusive directory locks
    // make each following unlink safe against every mesh-store writer.
    for (source, identity) in &sources {
        if !same_file_identity(source, *identity)? {
            return Err(io::ErrorKind::WouldBlock.into());
        }
    }
    for (source, identity) in sources {
        if !remove_if_same(&source, identity, uid)? {
            return Err(io::ErrorKind::WouldBlock.into());
        }
    }
    sync_directory(durable)
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
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let uid = nix::unistd::Uid::effective().as_raw();
    if !owned_file(path, uid, true)? {
        return Err(io::ErrorKind::NotFound.into());
    }
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
        file.write_all(body.as_bytes())?;
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

/// Move a marked set from the runtime path to durable storage and sync both directories.
/// # Errors
/// Leaves the marker and any unfinished source file in place when a move fails.
fn move_plan(source: &Path, target: &Path, files: &[&str], uid: u32) -> io::Result<()> {
    ensure_recoverable_plan(source, target, files, uid)?;
    for name in files {
        move_one(&source.join(name), &target.join(name), uid)?;
    }
    for name in files {
        if !owned_file(&target.join(name), uid, true)? || owned_file(&source.join(name), uid, true)?
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    validate_private_key(target, files, uid)?;
    sync_directory(target)?;
    if owned_directory(source, uid, false)? {
        sync_directory(source)?;
    }
    Ok(())
}

/// Copy a source by atomic rename and unlink only the exact inode that was copied.
/// # Errors
/// Refuses unsafe entries and stops after bounded retries if a writer keeps replacing the source.
fn move_one(source: &Path, target: &Path, uid: u32) -> io::Result<()> {
    for _ in 0..MAX_SOURCE_RETRIES {
        let Some(identity) = copy_one(source, target, uid)? else {
            // The source may already have been consumed by a prior interrupted transfer.
            if owned_file(target, uid, true)? {
                if target
                    .file_name()
                    .is_some_and(|name| name == "mesh-private-key")
                {
                    let parent = target.parent().ok_or(io::ErrorKind::InvalidInput)?;
                    validate_private_key(parent, &["mesh-private-key"], uid)?;
                }
                return Ok(());
            }
            return Err(io::ErrorKind::InvalidData.into());
        };
        if remove_if_same(source, identity, uid)? {
            return Ok(());
        }
    }
    Err(io::ErrorKind::WouldBlock.into())
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

/// Remove stale runtime files only after a valid durable key has won.
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
        }) || (name.starts_with(&format!(".{MIGRATION_MARKER}.migrate-"))
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

    use base64::Engine as _;
    use sha2::Digest as _;

    /// Build a unique fixture root outside the repository so no private test key is committed.
    fn fixture_root() -> PathBuf {
        std::env::temp_dir().join(format!("j501-mesh-state-{}", uuid::Uuid::new_v4()))
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

    /// Moves the old private identity and public snapshot into a private durable directory.
    #[test]
    fn moves_legacy_mesh_identity_before_first_durable_start() {
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

        migrate(&volatile, &durable).expect("migrate legacy mesh state");

        assert_eq!(
            fs::read(durable.join("mesh-private-key")).expect("durable private key"),
            [0x11; 32]
        );
        assert_eq!(
            fs::read(durable.join("mesh-public.json")).expect("durable public state"),
            br#"{"enabled":true}"#
        );
        assert!(!volatile.join("mesh-private-key").exists());
        let directory = fs::symlink_metadata(&durable).expect("durable directory metadata");
        assert_eq!(directory.uid(), nix::unistd::Uid::effective().as_raw());
        assert_eq!(directory.mode() & 0o777, 0o700);
        let key =
            fs::symlink_metadata(durable.join("mesh-private-key")).expect("durable key metadata");
        assert_eq!(key.uid(), nix::unistd::Uid::effective().as_raw());
        assert_eq!(key.mode() & 0o777, 0o600);
        migrate(&volatile, &durable).expect("a repeated start is harmless");
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    /// Keeps the durable identity and all of its state when the runtime copy also exists.
    #[test]
    fn durable_identity_wins_over_a_different_runtime_key() {
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

        migrate(&volatile, &durable).expect("keep the durable identity");

        assert_eq!(
            fs::read(durable.join("mesh-private-key")).expect("durable key"),
            [0x42; 32]
        );
        assert_eq!(
            fs::read(durable.join("mesh-public.json")).expect("durable public state"),
            b"durable-public"
        );
        assert!(!volatile.join("mesh-private-key").exists());
        assert!(!volatile.join("mesh-public.json").exists());
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

        let result = migrate(&volatile, &durable);
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

        migrate(&volatile, &durable).expect("resume the interrupted move");

        assert_eq!(
            fs::read(durable.join("mesh-private-key")).expect("durable key"),
            [0x33; 32]
        );
        assert_eq!(
            fs::read(durable.join("mesh-public.json")).expect("durable public state"),
            b"runtime-public"
        );
        assert!(!volatile.join("mesh-private-key").exists());
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

        assert!(migrate(&volatile, &durable).is_err());
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

        let result = migrate(&volatile, &durable);

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

        let result = migrate(&volatile, &durable);

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

        let result = migrate(&volatile, &durable);

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

        let result = migrate(&volatile, &durable);
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

    /// Moves the latest durable identity back to the runtime path for a D295 rollback.
    #[test]
    fn rollback_restore_moves_the_identity_back_to_the_legacy_path() {
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
        assert!(!durable.join("mesh-private-key").exists());
        fs::remove_dir_all(root).expect("remove fixture root");
    }

    /// Keeps a known public-key fingerprint unchanged through rollback and the next upgrade.
    #[test]
    fn rollback_and_reupgrade_keep_the_same_public_key_fingerprint() {
        const PRIVATE: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        const PUBLIC: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];

        let root = fixture_root();
        let volatile = root.join("run/infraternal");
        let durable = root.join("var/lib/infraternal/mesh");
        fs::create_dir_all(&volatile).expect("create legacy runtime directory");
        fs::set_permissions(&volatile, fs::Permissions::from_mode(0o700))
            .expect("make legacy runtime directory private");
        fs::create_dir_all(&durable).expect("create durable mesh directory");
        fs::set_permissions(&durable, fs::Permissions::from_mode(0o700))
            .expect("make durable mesh directory private");
        fs::write(durable.join("mesh-private-key"), PRIVATE).expect("write RFC key fixture");
        fs::set_permissions(
            durable.join("mesh-private-key"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("make key fixture private");
        let public_state = serde_json::json!({
            "server_public_key": base64::engine::general_purpose::STANDARD.encode(PUBLIC),
        });
        let public_path = durable.join("mesh-public.json");
        fs::write(
            &public_path,
            serde_json::to_vec(&public_state).expect("encode public state"),
        )
        .expect("write public-key fixture");
        fs::set_permissions(&public_path, fs::Permissions::from_mode(0o600))
            .expect("make public state private");

        let fingerprint_at = |path: &std::path::Path| {
            let state: serde_json::Value =
                serde_json::from_slice(&fs::read(path).expect("read public state"))
                    .expect("decode public state");
            let encoded = state["server_public_key"]
                .as_str()
                .expect("public key text");
            let key = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .expect("decode public key");
            <[u8; 32]>::from(sha2::Sha256::digest(key))
        };
        let expected = sha2::Sha256::digest(PUBLIC);
        let expected_fingerprint: [u8; 32] = expected.into();
        assert_eq!(fingerprint_at(&public_path), expected_fingerprint);

        rollback_handoff(&durable, &volatile).expect("hand identity back to the previous build");
        assert_eq!(
            fs::read(volatile.join("mesh-private-key")).expect("rollback private key"),
            PRIVATE,
            "rollback must keep the private identity bytes",
        );
        assert_eq!(
            fingerprint_at(&volatile.join("mesh-public.json")),
            expected_fingerprint,
            "the public-key fingerprint must survive rollback",
        );

        migrate(&volatile, &durable).expect("migrate identity forward on re-upgrade");
        assert_eq!(
            fs::read(durable.join("mesh-private-key")).expect("re-upgraded private key"),
            PRIVATE,
            "re-upgrade must keep the private identity bytes",
        );
        assert_eq!(
            fingerprint_at(&durable.join("mesh-public.json")),
            expected_fingerprint,
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

        migrate(&volatile, &durable).expect("resume the interrupted move");

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
        let first = std::thread::spawn(move || migrate(&first_source, &first_durable));
        for _ in 0..1_000_000 {
            if migration_temporary_exists(&durable, "mesh-public.json") {
                break;
            }
            std::thread::yield_now();
        }
        let temporary_was_published = migration_temporary_exists(&durable, "mesh-public.json");
        let second = migrate(&volatile, &durable);
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
                        migrate(&volatile, &durable)
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
        let migration = std::thread::spawn(move || migrate(&migration_source, &migration_target));
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

        let result = migrate(&volatile, &durable);
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

        let result = migrate(&volatile, &durable);
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
        migrate(&volatile, &durable).expect("migrate under a strict umask");
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
        migrate(&volatile, &durable).expect("migrate under a strict umask");
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
                .send(migrate(&migration_source, &migration_target))
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
    /// The fix needs an ownership check (for example, the server node's public key recorded in this
    /// data directory) before a legacy identity is moved; adapt the calls below to that API.
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

        // The migration-check server starts first on its copy of production data.
        let check = migrate(&shared_runtime, &check_instance);
        // Production is upgraded afterwards and must still find its own identity.
        let production_result = migrate(&shared_runtime, &production);
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
