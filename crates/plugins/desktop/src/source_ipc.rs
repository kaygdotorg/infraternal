//! Owns one same-user helper process, private runtime and cancellation-safe IPC parser per admitted source leg [D203,D232].
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

#[derive(Clone)]
pub(super) struct Config {
    pub runtime: PathBuf,
    pub executable: PathBuf,
}
pub(super) enum StartFailure {
    Unavailable,
    Cleanup,
}
impl StartFailure {
    pub fn cleanup(&self) -> Result<(), infraternal_plugin_api::PluginError> {
        match self {
            Self::Unavailable => Ok(()),
            Self::Cleanup => Err(infraternal_plugin_api::PluginError::Rejected),
        }
    }
}
pub(super) struct Helper {
    read: Reader,
    write: OwnedWriteHalf,
    component: DesktopComponent,
    directory: Directory,
}
struct Directory {
    path: PathBuf,
    identity: (u64, u64),
}
impl Directory {
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
    pub async fn send(&mut self, kind: Kind, body: &[u8]) -> io::Result<()> {
        protocol::validate_command(kind, body)?;
        let mut packet = Vec::new();
        protocol::write(&mut packet, kind, body)?;
        tokio::time::timeout(Duration::from_secs(3), self.write.write_all(&packet))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        Ok(())
    }
    pub async fn receive(&mut self) -> io::Result<(Kind, Bytes)> {
        self.read.next().await
    }
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
struct Reader {
    scratch: Box<[u8]>,
    stream: OwnedReadHalf,
    buffered: BytesMut,
    deadline: Option<tokio::time::Instant>,
}
impl Reader {
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
