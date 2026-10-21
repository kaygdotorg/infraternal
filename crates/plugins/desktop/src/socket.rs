//! Private runtime endpoint and same-effective-user admission before parsing [D203,D40].
use std::{
    fs, io,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
};

/// Owns only the endpoint created by this instance; never removes another helper's socket.
pub struct Endpoint {
    pub listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
}
impl Endpoint {
    /// # Errors
    /// Refuses symlinks, foreign/permissive runtime directories and occupied paths.
    pub fn bind(runtime: &Path) -> io::Result<Self> {
        validate_runtime(runtime)?;
        let path = runtime.join("desktop.sock");
        let listener = UnixListener::bind(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        let endpoint = Self {
            listener,
            path,
            identity: (metadata.dev(), metadata.ino()),
        };
        fs::set_permissions(&endpoint.path, fs::Permissions::from_mode(0o600))?;
        Ok(endpoint)
    }
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// # Errors
/// Rejects symlinks and a runtime directory visible to another Unix user.
pub fn validate_runtime(runtime: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(runtime)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "A private user runtime directory is required.",
        ));
    }
    Ok(())
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        // Recovery may have bound a new endpoint at the same path. Ownership
        // follows the bound filesystem inode, never just its pathname.
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == self.identity)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// # Errors
/// Uses kernel credentials; filesystem access alone is not authentication.
pub fn admit(stream: &UnixStream) -> io::Result<()> {
    admit_uid(stream, nix::unistd::geteuid().as_raw())
}

fn admit_uid(stream: &UnixStream, expected: u32) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    let uid = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(io::Error::from)?
        .uid();
    #[cfg(target_os = "macos")]
    let uid = nix::unistd::getpeereid(stream)
        .map_err(io::Error::from)?
        .0
        .as_raw();
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let uid = {
        let _ = stream;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Desktop helper credentials are unavailable.",
        ));
    };
    if uid != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "The desktop helper requires the same user.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_peer_credentials_reject_a_different_expected_user() {
        let (a, _) = UnixStream::pair().unwrap();
        admit(&a).unwrap();
        assert_eq!(
            admit_uid(&a, nix::unistd::geteuid().as_raw().wrapping_add(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }
    #[test]
    fn endpoint_refuses_foreign_permissions_and_never_takes_over() {
        // Unix socket names must fit sun_path even when build output is deep.
        let dir = nix::unistd::mkdtemp("/tmp/desktop-socket-XXXXXX").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Endpoint::bind(&dir).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let endpoint = Endpoint::bind(&dir).unwrap();
        assert_eq!(fs::metadata(endpoint.path()).unwrap().mode() & 0o777, 0o600);
        assert!(Endpoint::bind(&dir).is_err());
        assert!(endpoint.path().exists());
        drop(endpoint);
        assert!(!dir.join("desktop.sock").exists());
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn dropping_superseded_endpoint_preserves_replacement_socket() {
        let dir = nix::unistd::mkdtemp("/tmp/desktop-replace-XXXXXX").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let original = Endpoint::bind(&dir).unwrap();
        // A same-user recovery can replace a pathname while an old instance still
        // owns its listener. Retirement must distinguish the two socket inodes.
        fs::remove_file(original.path()).unwrap();
        let replacement = Endpoint::bind(&dir).unwrap();
        drop(original);
        let replacement_still_named = replacement.path().exists();
        drop(replacement);
        fs::remove_dir(dir).unwrap();
        assert!(
            replacement_still_named,
            "retiring a superseded endpoint removed the replacement helper socket"
        );
    }
}
