//! Finds the private per-user runtime directory that a rootless infraternal agent and its shims share [D349], #146.
//!
//! Linux login sessions set `XDG_RUNTIME_DIR` to a private 0700 directory the
//! system clears at logout or boot, and the agent keeps its sockets under
//! `$XDG_RUNTIME_DIR/infraternal`. macOS sets no such variable, so a rootless
//! agent there (the one that captures app windows in the logged-in session)
//! would refuse to start. On macOS this module falls back to the account's own
//! `~/Library/Caches`, which macOS creates private (0700) for each account.
//!
//! Why not `$TMPDIR`: it is private too, but it is a long `/var/folders/…/T/`
//! path, and the session sockets under it would pass the 104-byte macOS limit
//! for a Unix socket path. `~/Library/Caches/infraternal/sessions/<32 hex>.sock`
//! stays inside the limit for account names up to about 20 characters.
//!
//! The agent and every shim share the lookup. Managed user-mode installs with
//! an overlong state path keep their terminal sockets in the private cache [D395].
use nix::unistd::Uid;
use std::{
    fs, io,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// State suffix owned by the macOS user-mode installer.
#[cfg(target_os = "macos")]
const MANAGED_MACOS_STATE: &str = "Library/Application Support/infraternal/state";

/// Returns the private runtime directory of the current (non-root) account.
///
/// `XDG_RUNTIME_DIR` wins when it is set. Otherwise, on macOS only, the answer
/// is `$HOME/Library/Caches`. Either way the directory must already exist, be
/// a real directory (not a symlink), belong to this account and have mode 0700;
/// anything else is refused, so another account can never plant the sockets.
///
/// # Errors
/// `InvalidData` when no runtime directory can be named (Linux without
/// `XDG_RUNTIME_DIR`, or macOS without `HOME`), `PermissionDenied` when the
/// directory is not private to this account, and any error from reading it.
pub fn user_runtime_dir() -> io::Result<PathBuf> {
    let runtime = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(runtime) => PathBuf::from(runtime),
        None => fallback()?,
    };
    check_private(&runtime)?;
    Ok(runtime)
}

/// The directory where the host and shims find session sockets and exit records.
#[must_use]
pub fn session_dir(state: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    if let Some(dir) = managed_macos_session_dir(state) {
        return dir;
    }
    state.join("sessions")
}

/// A private cache for user-mode installs whose standard state is too deep
/// for a Unix socket. The install's other state stays in Application Support.
/// This directory belongs only to the macOS user-mode install, so a manual
/// infraternal agent using the ordinary runtime directory keeps its own sockets.
#[cfg(target_os = "macos")]
#[must_use]
pub fn managed_macos_session_dir(state: &Path) -> Option<PathBuf> {
    macos_session_dir_for_uid(state, Uid::effective())
}

/// Select the private cache only for the long state paths of user-mode installs.
#[cfg(target_os = "macos")]
fn macos_session_dir_for_uid(state: &Path, uid: Uid) -> Option<PathBuf> {
    let managed = Path::new(MANAGED_MACOS_STATE);
    // Darwin's 104-byte sun_path includes the terminator. Count the separator,
    // 32 hex characters and ".sock" in bytes, as the kernel does.
    if uid.is_root()
        || !state.is_absolute()
        || !state.ends_with(managed)
        || state.join("sessions").as_os_str().len() + 1 + 32 + 5 < 104
    {
        return None;
    }
    let home = state.ancestors().nth(managed.components().count())?;
    Some(home.join("Library/Caches/infraternal/up"))
}

/// Create and validate the shared session directory inside the caller's own
/// private runtime. The Mac cache hierarchy must be private at every level.
/// The boolean says whether this call created the session directory itself.
/// # Errors
/// Refuses unsafe directory ownership, links and filesystem errors.
pub fn create_session_dir(state: &Path) -> io::Result<(PathBuf, bool)> {
    #[cfg(target_os = "macos")]
    if let Some(dir) = managed_macos_session_dir(state) {
        let root = dir.parent().ok_or(io::ErrorKind::InvalidInput)?;
        let caches = root.parent().ok_or(io::ErrorKind::InvalidInput)?;
        check_private(caches)?;
        create_private(root)?;
        let created = create_private(&dir)?;
        return Ok((dir, created));
    }
    let dir = state.join("sessions");
    let created = create_private(&dir)?;
    Ok((dir, created))
}

/// Create one 0700 directory or validate the one that already exists.
fn create_private(path: &Path) -> io::Result<bool> {
    let created = match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error),
    };
    check_private(path)?;
    Ok(created)
}

/// Remove only the managed Mac socket cache, after uninstall has stopped its
/// `LaunchAgent` and authenticated the installation receipt.
/// # Errors
/// Refuses a nonprivate hierarchy or a filesystem failure.
#[cfg(target_os = "macos")]
pub fn remove_managed_macos_session_dir(state: &Path) -> io::Result<()> {
    let Some(dir) = managed_macos_session_dir(state) else {
        return Ok(());
    };
    let root = dir.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let caches = root.parent().ok_or(io::ErrorKind::InvalidInput)?;
    for path in [caches, root, dir.as_path()] {
        match check_private(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    fs::remove_dir_all(dir)
}

/// The macOS fallback: the account's own `~/Library/Caches`.
#[cfg(target_os = "macos")]
fn fallback() -> io::Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "rootless infraternal agent needs HOME to find its runtime directory",
        )
    })?;
    Ok(PathBuf::from(home).join("Library/Caches"))
}

/// Other systems have no safe default, so the variable stays required there.
#[cfg(not(target_os = "macos"))]
fn fallback() -> io::Result<PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "rootless infraternal agent requires XDG_RUNTIME_DIR",
    ))
}

/// Refuses a runtime directory that is a symlink, not a directory, owned by
/// another account, or open to group or others.
fn check_private(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir()
        || meta.uid() != Uid::effective().as_raw()
        || meta.permissions().mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid runtime directory",
        ));
    }
    Ok(())
}

#[cfg(test)]
/// Checks the privacy rules every runtime directory must pass.
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    /// Darwin accepts 103 pathname bytes and rejects the next byte. The
    /// installer cache changes neither custom paths nor root-mode locations.
    #[cfg(target_os = "macos")]
    #[test]
    fn managed_mac_sessions_move_at_the_darwin_socket_limit() {
        let leaf = format!("{}.sock", "1".repeat(32));
        let used = Path::new("/")
            .join(MANAGED_MACOS_STATE)
            .join("sessions")
            .join(&leaf)
            .as_os_str()
            .len();
        let home = Path::new("/").join("a".repeat(102 - used));
        let fits = home.join(MANAGED_MACOS_STATE);
        let long_home = Path::new("/").join("a".repeat(103 - used));
        let long = long_home.join(MANAGED_MACOS_STATE);
        let user = Uid::from_raw(501);
        assert_eq!(fits.join("sessions").join(&leaf).as_os_str().len(), 103);
        assert_eq!(long.join("sessions").join(&leaf).as_os_str().len(), 104);
        assert_eq!(macos_session_dir_for_uid(&fits, user), None);
        assert_eq!(
            macos_session_dir_for_uid(&long, user),
            Some(long_home.join("Library/Caches/infraternal/up"))
        );
        assert_eq!(macos_session_dir_for_uid(&long, Uid::from_raw(0)), None);
        assert_eq!(macos_session_dir_for_uid(&long.join("custom"), user), None);
    }

    /// Cache creation and uninstall both reject links at every owned level.
    /// A successful uninstall preserves the manual infraternal agent's cache.
    #[cfg(target_os = "macos")]
    #[test]
    fn managed_mac_cache_refuses_links_and_removes_only_the_install_cache() {
        if Uid::effective().is_root() {
            return;
        }
        let home =
            std::env::temp_dir().join(format!("infraternal-macos-home-{}", std::process::id()));
        let state = home.join(MANAGED_MACOS_STATE);
        let target = home.join("symlink-target");
        fs::create_dir_all(home.join("Library")).unwrap();
        create_private(&target).unwrap();
        let cache = home.join("Library/Caches");
        let product = cache.join("infraternal");
        let install = product.join("up");
        for path in [&cache, &product, &install] {
            std::os::unix::fs::symlink(&target, path).unwrap();
            assert_eq!(
                create_session_dir(&state).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                remove_managed_macos_session_dir(&state).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            fs::remove_file(path).unwrap();
            if path != &install {
                create_private(path).unwrap();
            }
        }
        assert_eq!(create_session_dir(&state).unwrap(), (install.clone(), true));
        assert_eq!(
            create_session_dir(&state).unwrap(),
            (install.clone(), false)
        );
        let manual = product.join("sessions");
        create_private(&manual).unwrap();
        remove_managed_macos_session_dir(&state).unwrap();
        assert!(!install.exists() && manual.is_dir() && target.is_dir());
        fs::remove_dir_all(home).unwrap();
    }

    /// A fresh 0700 directory of this account is accepted; widening it to 0755 is refused.
    #[test]
    fn only_private_directories_of_this_account_pass() {
        let root = std::env::temp_dir().join(format!("ifr-rt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("create");
        assert!(check_private(&root).is_ok());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(
            check_private(&root).expect_err("0755 is shared").kind(),
            io::ErrorKind::PermissionDenied
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// A symlink to a private directory is refused: the link itself could be swapped.
    #[test]
    fn symlinked_runtime_directories_are_refused() {
        let root = std::env::temp_dir().join(format!("ifr-rl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("create");
        let target = root.join("real");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&target)
            .expect("create");
        let link = root.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(check_private(&link).is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
