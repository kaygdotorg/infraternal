//! Private server control socket shared by the restart and database checks.

use std::{
    io,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::net::UnixListener;

/// Same-account control listener and its owned filesystem entry.
pub(crate) struct Socket {
    /// Accepts local, credential-checked control requests.
    pub(crate) listener: UnixListener,
    /// Socket entry removed when its listener is dropped.
    path: PathBuf,
}

impl Socket {
    /// Bind the private endpoint without replacing a running server's listener.
    pub(crate) fn bind(data: &Path) -> io::Result<Self> {
        let directory = data.join("restart");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)?;
        let parent = std::fs::symlink_metadata(data)?;
        if !parent.is_dir()
            || parent.uid() != nix::unistd::Uid::effective().as_raw()
            || parent.mode() & 0o022 != 0
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let metadata = std::fs::symlink_metadata(&directory)?;
        if !metadata.is_dir()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let path = directory.join("control.sock");
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_socket()
                    || metadata.uid() != nix::unistd::Uid::effective().as_raw()
                {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                // Never steal a live server's restart endpoint. A pathname left
                // by a completed exec or abrupt stop has no listener.
                if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                    return Err(io::ErrorKind::AddrInUse.into());
                }
                std::fs::remove_file(&path)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self { listener, path })
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Check that the caller runs as the account that owns the server.
pub(crate) fn same_account(peer: &tokio::net::unix::UCred) -> bool {
    peer.uid() == nix::unistd::Uid::effective().as_raw()
}

/// Add a Linux database request to the existing zero-length control framing.
#[cfg(target_os = "linux")]
pub(crate) const DATABASE_REQUEST: [u8; 3] = [0, 0, 2];

/// The name of the SQLite file whose identity the move needs to prove.
#[cfg(target_os = "linux")]
pub(crate) const DATABASE_NAME: &str = "infraternal.sqlite";

/// A bounded reply fits in the existing length-prefixed control frame.
#[cfg(target_os = "linux")]
const MAX_DATABASE_REPLY: usize = 16 * 1024;

/// One open main SQLite file as observed by the server process itself.
#[cfg(target_os = "linux")]
#[derive(Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct Database {
    /// Absolute filename of the open database.
    path: PathBuf,
    /// Device number of the open file.
    device: u64,
    /// Inode number of the open file.
    inode: u64,
}

#[cfg(target_os = "linux")]
impl Database {
    /// Build the identity for a pinned file, without consulting the pathname.
    pub(crate) fn new(path: PathBuf, metadata: &std::fs::Metadata) -> Self {
        Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

/// Inspect only this process's handles, which are still visible with dump protection.
/// A pathname lookup alone would attest to a replacement SQLite never opened.
#[cfg(target_os = "linux")]
fn open_database(data: &Path) -> io::Result<Database> {
    let expected = std::path::absolute(data.join(DATABASE_NAME))?;
    let mut database = None;
    for fd in std::fs::read_dir("/proc/self/fd")? {
        let fd = fd?.path();
        if std::fs::read_link(&fd).is_ok_and(|path| path == expected)
            && let Ok(metadata) = fd.metadata()
            && metadata.is_file()
            && std::fs::read_link(&fd).is_ok_and(|path| path == expected)
        {
            let open = Database::new(expected.clone(), &metadata);
            if database.as_ref().is_some_and(|seen| *seen != open) {
                return Err(io::Error::other("server database handles disagree"));
            }
            database = Some(open);
        }
    }
    database.ok_or_else(|| io::Error::other("server has no open database at the configured path"))
}

/// Report the open file only after the caller has passed the owner check.
#[cfg(target_os = "linux")]
pub(crate) async fn send_database(
    socket: &mut tokio::net::UnixStream,
    data: &Path,
) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;

    // A running server can own many unrelated descriptors. Walk them on the
    // blocking pool so the private query does not stall the serving future.
    let data = data.to_owned();
    let database = tokio::task::spawn_blocking(move || open_database(&data)).await??;
    let payload = serde_json::to_vec(&database)?;
    if payload.len() > MAX_DATABASE_REPLY {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let length = u16::try_from(payload.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        socket.write_u16(length).await?;
        socket.write_all(&payload).await
    })
    .await?
}

/// Query only the socket peer that shares the service UID and owns its `MainPID`.
#[cfg(target_os = "linux")]
pub(crate) fn query_database(data: &Path, main_pid: u32) -> io::Result<Database> {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        time::Duration,
    };

    let mut socket = UnixStream::connect(data.join("restart/control.sock"))?;
    let peer = nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::PeerCredentials)?;
    if peer.uid() != nix::unistd::Uid::effective().as_raw()
        || u32::try_from(peer.pid()) != Ok(main_pid)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "database control peer does not match the service's main process",
        ));
    }
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    socket.write_all(&DATABASE_REQUEST)?;
    let mut length = [0; 2];
    socket.read_exact(&mut length)?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > MAX_DATABASE_REPLY {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut payload = vec![0; length];
    socket.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(io::Error::other)
}

/// Serve only the database operation on builds without restart support.
#[cfg(all(target_os = "linux", any(not(feature = "remote"), test)))]
pub(crate) async fn serve_database(socket: Socket, data: &Path) -> io::Result<()> {
    use tokio::io::AsyncReadExt;

    loop {
        let (mut stream, _) = socket.listener.accept().await?;
        if !stream.peer_cred().is_ok_and(|peer| same_account(&peer)) {
            continue;
        }
        let mut request = [0; DATABASE_REQUEST.len()];
        if tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_exact(&mut request),
        )
        .await
        .is_ok_and(|result| result.is_ok())
            && request == DATABASE_REQUEST
        {
            let _ = send_database(&mut stream, data).await;
        }
    }
}
