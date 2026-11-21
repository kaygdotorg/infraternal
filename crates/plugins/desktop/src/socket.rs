//! Private runtime endpoint and same-effective-user admission before parsing [D203,D40].
//!
//! The helper listens on a Unix socket named `desktop.sock` inside a private
//! runtime directory. Two checks protect it: the directory must be a real
//! directory owned by this user with no group/other access ([`validate_runtime`]),
//! and every connecting peer must have the same effective user id according to
//! the kernel ([`admit`]). File permissions alone are not treated as
//! authentication.
//!
//! A helper that a root infraternal agent started as the console user
//! ([`Peer::Daemon`], D203 C2) admits only root as its client, never its own
//! user, and sends the agent's one-time token before anything else. So
//! another process of the same user cannot connect first and learn the token.
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
    /// The bound listening socket.
    pub listener: UnixListener,
    path: PathBuf,
    /// Device and inode of the socket file we created. Drop removes the path only
    /// if it still has this identity.
    identity: (u64, u64),
}
impl Endpoint {
    /// Creates `desktop.sock` (mode 0600) inside `runtime` and listens on it.
    ///
    /// The name `desktop.sock` only ever appears already private and already
    /// listening. Clients refuse a socket with group or other permission bits,
    /// and `bind` creates the file with the umask's mode, so the socket is made
    /// under a short temporary name first: bound, set to 0600, listening. It is
    /// then published with `link`, which never replaces an existing file, and the
    /// temporary name is removed (#363).
    ///
    /// # Errors
    /// Refuses symlinks, foreign/permissive runtime directories and occupied paths.
    pub fn bind(runtime: &Path) -> io::Result<Self> {
        validate_runtime(runtime)?;
        let path = runtime.join("desktop.sock");
        let staging = runtime.join(staging_name());
        // A leftover name can only come from a dead process that had this PID.
        match fs::remove_file(&staging) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
        let listener = UnixListener::bind(&staging)?;
        let published = fs::set_permissions(&staging, fs::Permissions::from_mode(0o600))
            .and_then(|()| fs::symlink_metadata(&staging))
            .and_then(|metadata| fs::hard_link(&staging, &path).map(|()| metadata));
        let removed = fs::remove_file(&staging);
        let metadata = published?;
        removed?;
        Ok(Self {
            listener,
            path,
            identity: (metadata.dev(), metadata.ino()),
        })
    }
    /// Path of the socket file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A temporary socket name, unique within this process and among live
/// processes, no longer than `desktop.sock` so it fits wherever that name fits.
fn staging_name() -> String {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!(".d{:x}.{:x}", std::process::id(), next & 0xff)
}

/// Checks that `runtime` is a directory (not a symlink) owned by the current
/// user with no group or other permissions.
///
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

/// Accepts a connected peer only if the kernel says it runs as the same user as
/// this process.
///
/// # Errors
/// Uses kernel credentials; filesystem access alone is not authentication.
pub fn admit(stream: &UnixStream) -> io::Result<()> {
    admit_uid(stream, nix::unistd::geteuid().as_raw())
}

/// Who a helper accepts as its one client.
#[derive(Clone)]
pub enum Peer {
    /// A process of this helper's own user: the rootless infraternal agent
    /// in the person's login session, or the local desktop client.
    SameUser,
    /// The root infraternal agent that started this helper as the console
    /// user. It must be uid 0, and it receives these token bytes first.
    Daemon([u8; 32]),
}

impl Peer {
    /// Admits `stream` by kernel credentials and, for the root agent, sends
    /// the token before any frame.
    ///
    /// # Errors
    /// `PermissionDenied` for any other uid; write errors pass through.
    pub fn admit(&self, stream: &UnixStream) -> io::Result<()> {
        match self {
            Self::SameUser => admit(stream),
            Self::Daemon(token) => {
                admit_uid(stream, 0)?;
                io::Write::write_all(&mut &*stream, token)
            }
        }
    }
}

/// [`admit`] with the expected user id given explicitly. Fails with
/// `PermissionDenied` on a different user, or `Unsupported` on systems where
/// peer credentials cannot be read.
///
/// # Errors
/// As above.
pub fn admit_uid(stream: &UnixStream, expected: u32) -> io::Result<()> {
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
/// Peer admission by kernel credentials and safe socket publication.
mod tests {
    use super::*;
    /// A root-started helper refuses its own user as the client and sends
    /// nothing to it; only uid 0 is admitted (the test runs unprivileged).
    #[test]
    fn daemon_peer_refuses_the_helpers_own_user_and_sends_nothing() {
        use std::io::Read;
        let (helper, mut client) = UnixStream::pair().unwrap();
        let refused = Peer::Daemon([7; 32]).admit(&helper);
        if nix::unistd::geteuid().is_root() {
            refused.unwrap();
        } else {
            assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            drop(helper);
            let mut received = Vec::new();
            client.read_to_end(&mut received).unwrap();
            assert!(received.is_empty(), "the token reached a refused client");
        }
    }
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

    /// `desktop.sock` appears already private: its mode never changes after
    /// the name exists, so no client can find it with group or other bits
    /// (#363). A directory watch reports a chmod of a named entry as
    /// `IN_ATTRIB` with that name, synchronously, so the check needs no timing.
    #[cfg(target_os = "linux")]
    #[test]
    fn socket_name_appears_already_private() {
        use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
        let dir = nix::unistd::mkdtemp("/tmp/desktop-publish-XXXXXX").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let watch = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).unwrap();
        watch
            .add_watch(&dir, AddWatchFlags::IN_CREATE | AddWatchFlags::IN_ATTRIB)
            .unwrap();
        let endpoint = Endpoint::bind(&dir).unwrap();
        let events = watch.read_events().unwrap();
        let named = |flag: AddWatchFlags| {
            events.iter().any(|event| {
                event.mask.contains(flag)
                    && event.name.as_deref() == Some(std::ffi::OsStr::new("desktop.sock"))
            })
        };
        let (created, changed) = (
            named(AddWatchFlags::IN_CREATE),
            named(AddWatchFlags::IN_ATTRIB),
        );
        let mode = fs::metadata(endpoint.path()).unwrap().mode() & 0o777;
        let leftovers = fs::read_dir(&dir).unwrap().count();
        drop(endpoint);
        fs::remove_dir(dir).unwrap();
        assert!(created, "desktop.sock was never created: {events:?}");
        assert!(
            !changed,
            "desktop.sock changed mode after it appeared: {events:?}"
        );
        assert_eq!(mode, 0o600);
        assert_eq!(leftovers, 1, "the temporary socket name was left behind");
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
