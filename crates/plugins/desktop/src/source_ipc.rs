//! Owns one same-user helper process, private runtime and cancellation-safe IPC parser per admitted source leg [D203,D232].
//!
//! A [`Helper`] launches the desktop helper executable in one-shot mode, inside a
//! fresh `source-<uuid>` directory under the configured runtime directory (mode
//! 0700). It then connects to the helper's Unix socket, checks that the socket
//! is a same-user, owner-only socket, and exchanges length-framed protocol
//! packets with it ([`Helper::send`] / [`Helper::receive`]).
//!
//! Teardown is by closing the socket: the helper sees end-of-file, restores any
//! native state it changed and exits. The private directory is deleted on drop,
//! but only if it is still the same directory (same device and inode) that was
//! created, so a swapped-in path is never removed.
use crate::{
    component::DesktopComponent,
    protocol::{self, Kind},
    socket,
};
use bytes::{Bytes, BytesMut};
use infraternal_plugin_api::ComponentPlugin;
use std::{
    fs, io,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt},
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
}
/// A private per-helper directory that deletes itself on drop.
struct Directory {
    path: PathBuf,
    /// Device and inode at creation. Drop deletes only if the path still has this
    /// identity, so a replaced path is left alone.
    identity: (u64, u64),
}
impl Directory {
    /// Creates `source-<uuid>` (mode 0700) under `base`. `base` must already be a
    /// safe runtime directory, or be missing, in which case it is created
    /// privately. An existing base that is permissive, foreign or a symlink is an
    /// error and is not repaired.
    fn create(base: &std::path::Path) -> io::Result<Self> {
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
        let path = base.join(format!("source-{}", uuid::Uuid::new_v4()));
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
impl Helper {
    /// Launches the helper and connects to its socket, polling every 10 ms for up
    /// to 3 seconds for the socket to appear.
    ///
    /// The socket must be a socket owned by this user with no group/other
    /// permissions, and the peer must pass `socket::admit`. Setting `stop` to
    /// true aborts the wait. On any failure the helper is disabled again; if that
    /// fails too the error is [`StartFailure::Cleanup`].
    pub async fn start(
        config: &Config,
        stop: &mut watch::Receiver<bool>,
    ) -> Result<Self, StartFailure> {
        let directory =
            Directory::create(&config.runtime).map_err(|_| StartFailure::Unavailable)?;
        let component =
            DesktopComponent::one_shot(directory.path.clone(), config.executable.clone())
                .with_companion_runtime(config.runtime.clone());
        component
            .set_enabled(true)
            .await
            .map_err(|_| StartFailure::Unavailable)?;
        let path = directory.path.join("desktop.sock");
        // Startup alone owns a retry timer; idle admitted sources have none.
        let connection = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if *stop.borrow() {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                match fs::symlink_metadata(&path) {
                    Ok(metadata) => {
                        if !metadata.file_type().is_socket()
                            || metadata.uid() != nix::unistd::geteuid().as_raw()
                            || metadata.mode() & 0o077 != 0
                        {
                            return Err(io::ErrorKind::PermissionDenied.into());
                        }
                        let stream = UnixStream::connect(&path).await?.into_std()?;
                        socket::admit(&stream)?;
                        return UnixStream::from_std(stream);
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                tokio::select! { biased;
                    _ = stop.changed() => return Err(io::ErrorKind::Interrupted.into()),
                    () = tokio::time::sleep(Duration::from_millis(10)) => {},
                }
            }
        })
        .await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
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
        })
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
