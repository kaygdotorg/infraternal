//! Holds the embedded server node's mesh files durably and migrates the old runtime copy [J501, #489].

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

/// Node files written by the mesh store; keep this list aligned with `Store::open`.
const MESH_FILES: &[&str] = &[
    "mesh-private-key",
    "mesh-public.json",
    "mesh-routes.json",
    "mesh-interface.json",
    "mesh-key-rotation.bin",
    "mesh-engine.json",
    "mesh-authority.json",
];

/// A durable marker that lets an interrupted cross-filesystem move resume safely.
const MIGRATION_MARKER: &str = ".mesh-state-migration.pending";

/// Ensure the embedded node's durable mesh directory is ready before its child starts.
///
/// A durable private key selects the whole durable identity when both copies exist. Otherwise,
/// each legacy file is copied to a synced 0600 temporary, linked into the durable directory
/// without replacement, then removed from the runtime directory. A marker keeps a partial move
/// resumable; errors stop server startup so the mesh store cannot silently mint another key.
/// Mesh private keys stay outside the D147 backup set, which contains the database, CA key and
/// configuration.
/// # Errors
/// Refuses unsafe owners, permissions, file types, or any failed filesystem operation.
pub(crate) fn migrate(volatile: &Path, durable: &Path) -> io::Result<()> {
    let uid = nix::unistd::Uid::effective().as_raw();
    ensure_durable_directory(durable, uid)?;
    let marker = durable.join(MIGRATION_MARKER);
    let pending = owned_file(&marker, uid, true)?;
    let durable_key = owned_file(&durable.join("mesh-private-key"), uid, true)?;
    let legacy_directory = owned_directory(volatile, uid, false)?;

    if durable_key && !pending {
        if legacy_directory {
            remove_legacy_files(volatile, uid)?;
        }
        return Ok(());
    }
    if !legacy_directory || !has_legacy_files(volatile, uid)? {
        finish_marker(&marker, uid)?;
        return Ok(());
    }
    if !pending {
        create_marker(&marker)?;
        sync_directory(durable)?;
    }

    migrate_legacy_files(volatile, durable, uid)?;
    finish_marker(&marker, uid)?;
    sync_directory(durable)?;
    sync_directory(volatile)
}

/// Create the durable mesh directory privately or tighten a directory owned by this service.
/// # Errors
/// Rejects a symlink, non-directory, different owner, or failed permission update.
fn ensure_durable_directory(path: &Path, uid: u32) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && metadata.uid() == uid => {
            if metadata.mode() & 0o777 != 0o700 {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(_) => return Err(io::ErrorKind::PermissionDenied.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            DirBuilder::new().mode(0o700).create(path)?;
        }
        Err(error) => return Err(error),
    }
    if owned_directory(path, uid, false)? {
        Ok(())
    } else {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

/// Check a directory without following symlinks, optionally tightening a durable directory.
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
    if metadata.mode() & 0o777 != 0o700 {
        if !repair_mode {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        let secured = fs::symlink_metadata(path)?;
        if !secured.is_dir() || secured.uid() != uid || secured.mode() & 0o777 != 0o700 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    Ok(true)
}

/// Check a regular file's owner and optionally set its durable mode to 0600.
/// # Errors
/// Rejects a symlink, non-file, different owner, or failed permission update.
fn owned_file(path: &Path, uid: u32, repair_mode: bool) -> io::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.uid() != uid {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    if repair_mode && metadata.mode() & 0o777 != 0o600 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        let secured = fs::symlink_metadata(path)?;
        if !secured.is_file() || secured.uid() != uid || secured.mode() & 0o777 != 0o600 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    Ok(true)
}

/// Return whether the runtime directory has any known mesh files to migrate.
/// # Errors
/// Rejects a non-file or foreign-owned entry at a mesh state path.
fn has_legacy_files(volatile: &Path, uid: u32) -> io::Result<bool> {
    for name in MESH_FILES {
        if owned_file(&volatile.join(name), uid, false)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Write the non-secret marker before the first file so a later start can resume a partial move.
/// # Errors
/// Returns an error if the marker cannot be created or synced privately.
fn create_marker(path: &Path) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(b"J501 mesh state migration\n")?;
    file.sync_all()
}

/// Move every known mesh file, preserving existing durable files and syncing both directories.
/// # Errors
/// Leaves the marker and any unremoved runtime file in place when a move fails.
fn migrate_legacy_files(volatile: &Path, durable: &Path, uid: u32) -> io::Result<()> {
    for name in MESH_FILES {
        migrate_one(&volatile.join(name), &durable.join(name), uid)?;
    }
    sync_directory(volatile)?;
    sync_directory(durable)
}

/// Copy one legacy file only when its durable counterpart is absent, then unlink the source.
/// # Errors
/// Refuses unsafe files and returns copy, sync, link, or unlink errors without starting the child.
fn migrate_one(source: &Path, target: &Path, uid: u32) -> io::Result<()> {
    if !owned_file(source, uid, false)? {
        return Ok(());
    }
    if owned_file(target, uid, true)? {
        fs::remove_file(source)?;
        return sync_parent(source);
    }
    publish_copy(source, target, uid)?;
    fs::remove_file(source)?;
    sync_parent(source)
}

/// Publish a synced private copy with no-replace semantics, so an existing durable file wins.
/// # Errors
/// Preserves the source and pending marker if a copy cannot be completed.
fn publish_copy(source: &Path, target: &Path, uid: u32) -> io::Result<()> {
    let name = target.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    let temporary = target.with_file_name(format!(".{}.migrate-new", name.to_string_lossy()));
    if owned_file(&temporary, uid, false)? {
        fs::remove_file(&temporary)?;
    }
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&temporary)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    drop(output);
    drop(input);

    match fs::hard_link(&temporary, target) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            owned_file(target, uid, true)?;
        }
        Err(error) => return Err(error),
    }
    fs::remove_file(&temporary)?;
    sync_parent(target)
}

/// Delete legacy mesh files after an already-present durable key has won.
/// # Errors
/// Refuses unsafe runtime entries and returns unlink or directory-sync errors.
fn remove_legacy_files(volatile: &Path, uid: u32) -> io::Result<()> {
    for name in MESH_FILES {
        let path = volatile.join(name);
        if owned_file(&path, uid, false)? {
            fs::remove_file(path)?;
        }
    }
    sync_directory(volatile)
}

/// Remove a completed marker only after all copies and source unlinks have been synced.
/// # Errors
/// Returns validation, unlink, or sync errors.
fn finish_marker(path: &Path, uid: u32) -> io::Result<()> {
    if owned_file(path, uid, true)? {
        fs::remove_file(path)?;
        sync_parent(path)?;
    }
    Ok(())
}

/// Sync the directory containing `path` after publishing or removing an entry.
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
    File::open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    //! Proves legacy identity migration, durable precedence, permissions, and retry behavior.

    use super::{MIGRATION_MARKER, migrate};
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
    };

    /// Build a unique fixture root outside the repository so no private test key is committed.
    fn fixture_root() -> PathBuf {
        std::env::temp_dir().join(format!("j501-mesh-state-{}", uuid::Uuid::new_v4()))
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
        fs::write(volatile.join("mesh-private-key"), b"fixture-private-key")
            .expect("write synthetic legacy key");
        fs::write(volatile.join("mesh-public.json"), br#"{"enabled":true}"#)
            .expect("write synthetic public state");

        migrate(&volatile, &durable).expect("migrate legacy mesh state");

        assert_eq!(
            fs::read(durable.join("mesh-private-key")).expect("durable private key"),
            b"fixture-private-key"
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
        fs::write(volatile.join("mesh-private-key"), b"runtime-key")
            .expect("write synthetic runtime key");
        fs::write(volatile.join("mesh-public.json"), b"runtime-public")
            .expect("write synthetic runtime state");
        fs::write(durable.join("mesh-private-key"), b"durable-key")
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
            b"durable-key"
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
        fs::write(volatile.join("mesh-private-key"), b"same-key")
            .expect("write synthetic runtime key");
        fs::write(volatile.join("mesh-public.json"), b"runtime-public")
            .expect("write synthetic runtime state");
        fs::write(durable.join("mesh-private-key"), b"same-key")
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
            b"same-key"
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
}
