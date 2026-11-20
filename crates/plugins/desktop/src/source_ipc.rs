//! Owns one helper process, private runtime and cancellation-safe IPC parser per admitted source leg [D203,D232].
//!
//! A [`Helper`] launches the desktop helper executable in one-shot mode, inside a
//! fresh compact UUID directory under the configured runtime directory (mode
//! 0700). It then connects to the helper's Unix socket, checks that the socket
//! is an owner-only socket of the expected user, and exchanges length-framed
//! protocol packets with it ([`Helper::send`] / [`Helper::receive`]).
//!
//! A rootless agent's helper runs as the agent's own user. A root agent's
//! helper runs as the console user, and is admitted only after the checks in
//! [`crate::cross_user`]: the uid, the code signature and the one-time token,
//! all before the first frame is parsed (D203 C2, #146).
//!
//! Teardown is by closing the socket: the helper sees end-of-file, restores any
//! native state it changed and exits. The private directory is deleted on drop,
//! but only if it is still the same directory (same device and inode) that was
//! created, so a swapped-in path is never removed.
use crate::{
    component::DesktopComponent,
    cross_user::{self, ConsoleUser, ConsoleWatch, CrossUser, Token},
    protocol::{self, Kind},
    socket,
};
use bytes::{Bytes, BytesMut};
use infraternal_plugin_api::ComponentPlugin;
use std::{
    fs, io,
    os::{
        fd::AsFd,
        unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt},
    },
    path::PathBuf,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::watch,
};

/// Where helpers live and what to run.
#[derive(Clone)]
pub(super) struct Config {
    /// Base directory under which each helper gets its own private directory.
    pub runtime: PathBuf,
    /// Path of the helper executable to launch.
    pub executable: PathBuf,
    /// Set for a root agent: start each helper as the console user and admit
    /// it through the cross-user checks. `None` keeps the same-user path.
    pub cross_user: Option<CrossUser>,
}
/// Why [`Helper::start`] failed, and whether anything is left to clean up.
pub(super) enum StartFailure {
    /// The helper could not be started or reached; nothing is left running.
    Unavailable,
    /// The helper could not be started and disabling it afterwards also failed,
    /// so a stray process or socket may remain.
    Cleanup,
}
impl StartFailure {
    /// Maps the failure to a result: `Ok` when nothing needs cleaning up, and a
    /// rejection when the helper may still be running.
    pub fn cleanup(&self) -> Result<(), infraternal_plugin_api::PluginError> {
        match self {
            Self::Unavailable => Ok(()),
            Self::Cleanup => Err(infraternal_plugin_api::PluginError::Rejected),
        }
    }
}
/// A running one-shot helper process and the connection to it.
pub(super) struct Helper {
    read: Reader,
    write: OwnedWriteHalf,
    /// Supervises the helper process; disabling it ends the process.
    component: DesktopComponent,
    /// Private directory holding the helper's socket; removed after the process.
    directory: Directory,
    /// The console user a cross-user helper runs as; `None` for same-user.
    console: Option<u32>,
}
/// A private per-helper directory that deletes itself on drop.
struct Directory {
    path: PathBuf,
    /// Device and inode at creation. Drop deletes only if the path still has this
    /// identity, so a replaced path is left alone.
    identity: (u64, u64),
}
impl Directory {
    /// Creates a compact UUID directory (mode 0700) under `base`, leaving room for the
    /// socket within Darwin's 104-byte pathname limit. `base` must already be a
    /// safe runtime directory, or be missing, in which case it is created
    /// privately. An existing base that is permissive, foreign or a symlink is an
    /// error and is not repaired.
    fn create(base: &std::path::Path) -> io::Result<Self> {
        Self::validate_base(base)?;
        Self::create_leaf(base)
    }
    /// Checks the same-user base, creating it privately when it is missing.
    fn validate_base(base: &std::path::Path) -> io::Result<()> {
        match socket::validate_runtime(base) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // Trusted setup supplies this path, but metadata enable remains
                // inert. Only admitted helper work creates new private parents;
                // existing permissive, foreign or symlink bases are not repaired.
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(base)?;
                socket::validate_runtime(base)?;
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }
    /// Creates a per-leg folder for a root agent's console-user helper: the
    /// base is root's (mode 0711), and the new 0700 folder is handed to the
    /// console user before the helper starts ([`cross_user::hand_over`]).
    fn create_for(base: &std::path::Path, user: ConsoleUser) -> io::Result<Self> {
        cross_user::prepare_base(base)?;
        let directory = Self::create_leaf(base)?;
        cross_user::hand_over(&directory.path, user)?;
        Ok(directory)
    }
    /// Creates the compact UUID folder itself and records its identity.
    fn create_leaf(base: &std::path::Path) -> io::Result<Self> {
        let path = base.join(uuid::Uuid::new_v4().simple().to_string());
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        Ok(Self {
            path,
            identity: (metadata.dev(), metadata.ino()),
        })
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|m| (m.dev(), m.ino()) == self.identity) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
/// Who the agent expects on the other end of a helper socket.
struct Expected<'a> {
    /// The uid that must own the socket and be the kernel's peer.
    uid: u32,
    /// For a cross-user helper: its code-signature check (in [`connect_ready`])
    /// and one-time token (in [`prove`]).
    cross: Option<(&'a CrossUser, &'a Token)>,
}
impl Expected<'_> {
    /// The same-user expectation of a rootless agent.
    fn same_user() -> Self {
        Self {
            uid: nix::unistd::geteuid().as_raw(),
            cross: None,
        }
    }
}
/// Makes one attempt to connect to the helper's socket at `path`.
///
/// Returns `Ok(None)` while the helper is still starting, so the caller polls
/// again: either the socket does not exist yet, or it exists but refuses
/// connections. The second case is normal. A helper creates the pathname with
/// `bind` and starts accepting only at `listen`, and a busy machine can
/// deschedule it between the two calls. Everything else is an error that
/// ends startup: a path that is not a private socket owned by the expected
/// user, a peer of another uid, or (cross-user) a peer whose code signature
/// does not match. Nothing is read from the socket here; a cross-user helper
/// then proves its token ([`prove`]) before any frame is read.
async fn connect_ready(
    path: &std::path::Path,
    expected: &Expected<'_>,
) -> io::Result<Option<UnixStream>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket()
                || metadata.uid() != expected.uid
                || metadata.mode() & 0o077 != 0
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let stream = match UnixStream::connect(path).await {
                Ok(stream) => stream.into_std()?,
                // Bound but not yet listening, or removed after the metadata
                // check: still starting, within the caller's startup budget.
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                    ) =>
                {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            socket::admit_uid(&stream, expected.uid)?;
            let Some((cross, _)) = expected.cross else {
                return UnixStream::from_std(stream).map(Some);
            };
            (cross.verify)(stream.as_fd())?;
            UnixStream::from_std(stream).map(Some)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// How long a cross-user helper may take to send its token. It sends it once
/// it accepts, which is after it has launched the capture app (bounded at 5
/// seconds in `native`), so this covers that launch plus scheduling slack.
/// The same wait exists without a token: there it is spent on the first reply.
const TOKEN_WAIT: Duration = Duration::from_secs(8);

/// Reads the cross-user helper's first 32 bytes and accepts the connection
/// only when they equal the one-time token. Setting `stop` aborts the wait.
async fn prove(
    stream: &mut UnixStream,
    token: &Token,
    stop: &mut watch::Receiver<bool>,
) -> io::Result<()> {
    let mut presented = [0_u8; Token::LEN];
    tokio::select! { biased;
        _ = stop.changed() => return Err(io::ErrorKind::Interrupted.into()),
        read = tokio::time::timeout(TOKEN_WAIT, stream.read_exact(&mut presented)) => {
            read.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        }
    }
    if token.matches(&presented) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "The desktop helper did not prove that this agent started it.",
        ))
    }
}

impl Helper {
    /// Launches the helper and connects to its socket, polling every 10 ms for up
    /// to 3 seconds for the socket to appear.
    ///
    /// The socket must be owned by the expected user with no group/other
    /// permissions, and the peer must pass the kernel uid check (plus, for a
    /// root agent, the code-signature and token checks of
    /// [`crate::cross_user`]). A root agent with nobody at the screen starts
    /// nothing. Setting `stop` to true aborts the wait. On any failure the
    /// helper is disabled again; if that fails too the error is
    /// [`StartFailure::Cleanup`].
    pub async fn start(
        config: &Config,
        stop: &mut watch::Receiver<bool>,
    ) -> Result<Self, StartFailure> {
        let cross = match &config.cross_user {
            Some(cross) => Some((
                cross,
                cross_user::console_user().ok_or(StartFailure::Unavailable)?,
                Token::random().map_err(|_| StartFailure::Unavailable)?,
            )),
            None => None,
        };
        let (directory, component, expected) = if let Some((cross, user, token)) = &cross {
            let directory = Directory::create_for(&config.runtime, *user)
                .map_err(|_| StartFailure::Unavailable)?;
            // No companion runtime: the helper may own only its per-leg
            // folder here, and that is where its private files go.
            let component =
                DesktopComponent::one_shot(directory.path.clone(), config.executable.clone())
                    .for_console_user(cross, user.uid, *token.bytes());
            let expected = Expected {
                uid: user.uid,
                cross: Some((*cross, token)),
            };
            (directory, component, expected)
        } else {
            let directory =
                Directory::create(&config.runtime).map_err(|_| StartFailure::Unavailable)?;
            let component =
                DesktopComponent::one_shot(directory.path.clone(), config.executable.clone())
                    .with_companion_runtime(config.runtime.clone());
            (directory, component, Expected::same_user())
        };
        component
            .set_enabled(true)
            .await
            .map_err(|_| StartFailure::Unavailable)?;
        let path = directory.path.join("desktop.sock");
        // Startup alone owns a retry timer; idle admitted sources have none.
        let connection: io::Result<UnixStream> =
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if *stop.borrow() {
                        return Err(io::ErrorKind::Interrupted.into());
                    }
                    if let Some(stream) = connect_ready(&path, &expected).await? {
                        return Ok(stream);
                    }
                    tokio::select! { biased;
                        _ = stop.changed() => return Err(io::ErrorKind::Interrupted.into()),
                        () = tokio::time::sleep(Duration::from_millis(10)) => {},
                    }
                }
            })
            .await
            .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
        let connection = match (connection, expected.cross) {
            (Ok(mut stream), Some((_, token))) => {
                prove(&mut stream, token, stop).await.map(|()| stream)
            }
            (connection, _) => connection,
        };
        let Ok(stream) = connection else {
            component
                .set_enabled(false)
                .await
                .map_err(|_| StartFailure::Cleanup)?;
            return Err(StartFailure::Unavailable);
        };
        let (read, write) = stream.into_split();
        Ok(Self {
            read: Reader {
                stream: read,
                buffered: BytesMut::new(),
                deadline: None,
                scratch: vec![0; 16 * 1024].into_boxed_slice(),
            },
            write,
            component,
            directory,
            console: cross.as_ref().map(|(_, user, _)| user.uid),
        })
    }
    /// A watch that resolves when the person at the screen is no longer the
    /// one this helper runs as. A same-user helper's watch never resolves.
    pub fn console_watch(&self) -> ConsoleWatch {
        ConsoleWatch::new(self.console)
    }
    /// Validates `body` as a command of `kind`, then writes it as one framed
    /// packet. Fails if the command is invalid or the write takes over 3 seconds.
    pub async fn send(&mut self, kind: Kind, body: &[u8]) -> io::Result<()> {
        protocol::validate_command(kind, body)?;
        let mut packet = Vec::new();
        protocol::write(&mut packet, kind, body)?;
        tokio::time::timeout(Duration::from_secs(3), self.write.write_all(&packet))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        Ok(())
    }
    /// Waits for the next packet from the helper and returns its kind and body.
    ///
    /// Cancellation-safe: dropping the future (for example in a `select!`) loses
    /// no bytes, because partial data stays buffered for the next call.
    pub async fn receive(&mut self) -> io::Result<(Kind, Bytes)> {
        self.read.next().await
    }
    /// Closes the connection, disables the helper process and removes its private
    /// directory. Returns the error from disabling the helper, if any.
    pub async fn stop(self) -> io::Result<()> {
        let Self {
            read,
            write,
            component,
            directory,
            console: _,
        } = self;
        // Dropping both halves makes EOF drive the helper's existing native
        // restoration path; --once then exits rather than retaining a listener.
        drop(read);
        drop(write);
        let result = component.set_enabled(false).await.map_err(io::Error::other);
        drop(component);
        drop(directory);
        result
    }
}
/// Incremental packet reader. Bytes read from the socket accumulate in
/// `buffered`, so a cancelled read never loses a half-received packet.
struct Reader {
    /// Reusable read buffer.
    scratch: Box<[u8]>,
    stream: OwnedReadHalf,
    /// Received bytes that do not yet form a whole packet, plus any extra bytes.
    buffered: BytesMut,
    /// While a packet is partly received, the time by which the rest must arrive
    /// (3 seconds after the first byte). `None` when idle, so an idle helper
    /// can stay silent indefinitely.
    deadline: Option<tokio::time::Instant>,
}
impl Reader {
    /// Returns the next whole packet (kind and body). Fails on end-of-file, a
    /// malformed or oversized frame, or a partial packet stalling past the
    /// deadline.
    async fn next(&mut self) -> io::Result<(Kind, Bytes)> {
        loop {
            if let Some((frame, count)) = protocol::decode(&self.buffered)? {
                let kind = frame.kind;
                let packet = self.buffered.split_to(count).freeze().slice(6..);
                self.deadline = if self.buffered.is_empty() {
                    None
                } else {
                    Some(tokio::time::Instant::now() + Duration::from_secs(3))
                };
                return Ok((kind, packet));
            }
            if self.buffered.len() >= protocol::MAX_FRAME + 4 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let count = match self.deadline {
                Some(deadline) => {
                    tokio::time::timeout_at(deadline, self.stream.read(&mut self.scratch))
                        .await
                        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??
                }
                None => self.stream.read(&mut self.scratch).await?,
            };
            if count == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.buffered.extend_from_slice(&self.scratch[..count]);
            self.deadline
                .get_or_insert_with(|| tokio::time::Instant::now() + Duration::from_secs(3));
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod readiness_tests {
    //! Linux socket-flag readiness test: hold a socket between `bind` and
    //! `listen` to check startup without depending on scheduler timing.
    use super::*;
    use nix::sys::socket::{
        AddressFamily, Backlog, SockFlag, SockType, UnixAddr, bind, listen, socket,
    };
    use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};

    /// A socket that is bound but not listening leaves startup pending, and the
    /// same socket connects as soon as its owner calls `listen`.
    #[tokio::test]
    async fn bound_helper_socket_waits_for_listen() {
        let root = nix::unistd::mkdtemp("/tmp/desktop-ready-XXXXXX").unwrap();
        let path = root.join("desktop.sock");
        let listener = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .unwrap();
        bind(listener.as_raw_fd(), &UnixAddr::new(&path).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let before = connect_ready(&path, &Expected::same_user()).await;
        listen(&listener, Backlog::new(1).unwrap()).unwrap();
        let after = connect_ready(&path, &Expected::same_user()).await;
        drop(listener);
        fs::remove_dir_all(root).unwrap();
        assert!(
            before.unwrap().is_none(),
            "bind alone must leave startup pending"
        );
        assert!(
            after.unwrap().is_some(),
            "listen completes helper readiness"
        );
    }
}
