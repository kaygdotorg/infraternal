//! Implements local-owner restart requests and same-PID exec without transporting the CA over a named socket [168][217], #154.

use std::{
    ffi::OsString,
    io,
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    signal::unix::{SignalKind, signal},
};

#[derive(Debug, clap::Args)]
pub(crate) struct Options {
    /// Verified replacement executable (defaults to the running server's binary).
    #[arg(long)]
    pub binary: Option<PathBuf>,
}

const MAX_PATH: usize = 4096;

pub(crate) struct Control {
    listener: UnixListener,
    path: PathBuf,
    reload: tokio::signal::unix::Signal,
}
impl Control {
    pub(crate) fn start(data: &Path) -> io::Result<Self> {
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
        Ok(Self {
            listener,
            path,
            reload: signal(SignalKind::hangup())?,
        })
    }
    pub(crate) async fn requested(&mut self) -> io::Result<PathBuf> {
        loop {
            let mut socket = tokio::select! {
                _ = self.reload.recv() => return current_binary(),
                accepted = self.listener.accept() => accepted?.0,
            };
            if !socket
                .peer_cred()
                .is_ok_and(|peer| peer.uid() == nix::unistd::Uid::effective().as_raw())
            {
                continue;
            }
            let request =
                tokio::time::timeout(Duration::from_secs(2), read_request(&mut socket)).await;
            if let Ok(Ok(binary)) = request {
                if executable(&binary).is_err() {
                    let _ = socket.write_all(b"REFUSED\n").await;
                    continue;
                }
                socket.write_all(b"RESTARTING\n").await?;
                return Ok(binary);
            }
        }
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn read_request(socket: &mut UnixStream) -> io::Result<PathBuf> {
    let length = usize::from(socket.read_u16().await?);
    if length == 0 || length > MAX_PATH {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = vec![0; length];
    socket.read_exact(&mut bytes).await?;
    let path = PathBuf::from(String::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidInput)?);
    if path == Path::new(".") {
        return current_binary();
    }
    if !path.is_absolute() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(path)
}

fn current_binary() -> io::Result<PathBuf> {
    let binary = std::env::current_exe()?;
    executable(&binary)?;
    Ok(binary)
}

fn executable(binary: &Path) -> io::Result<()> {
    let owner = nix::unistd::Uid::effective().as_raw();
    for (index, path) in binary.ancestors().enumerate() {
        let metadata = std::fs::symlink_metadata(path)?;
        // Validate the original path before canonicalizing: a symlink in an
        // untrusted directory could redirect even to a root-owned executable
        // that prints stdin. Only the service UID and root may replace code.
        if (metadata.uid() != owner && metadata.uid() != 0)
            || metadata.mode() & 0o022 != 0
            || if index == 0 {
                !metadata.is_file() || metadata.mode() & 0o111 == 0 || metadata.mode() & 0o6000 != 0
            } else {
                !metadata.is_dir()
            }
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    Ok(())
}

pub(crate) async fn request(data: &Path, binary: Option<&Path>) -> io::Result<()> {
    // An omitted path means the server's own executable, not the CLI's binary.
    // The single-byte sentinel is expanded by the receiver before validation.
    let path = binary
        .map(|path| {
            let original = if path.is_absolute() {
                path.to_owned()
            } else {
                std::env::current_dir()?.join(path)
            };
            executable(&original)?;
            std::fs::canonicalize(original)
        })
        .transpose()?;
    let mut socket = UnixStream::connect(data.join("restart/control.sock")).await?;
    if socket.peer_cred()?.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let bytes = path
        .as_ref()
        .map_or(b".".as_slice(), |path| path.as_os_str().as_encoded_bytes());
    socket
        .write_u16(u16::try_from(bytes.len()).map_err(|_| io::ErrorKind::InvalidInput)?)
        .await?;
    socket.write_all(bytes).await?;
    let mut response = Vec::new();
    socket.take(32).read_to_end(&mut response).await?;
    if response != b"RESTARTING\n" {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

pub(crate) struct Replacement {
    binary: PathBuf,
    input: Option<std::os::unix::net::UnixStream>,
}
impl Replacement {
    pub(crate) fn new(
        binary: PathBuf,
        source: Option<&dyn infraternal_server::ca::CaKeySource>,
    ) -> Self {
        Self {
            binary,
            input: source.and_then(|source| infraternal_server::ca_handoff::prepare(source).ok()),
        }
    }
    pub(crate) fn exec(self) -> io::Error {
        let mut command = Command::new(self.binary);
        // Stdin is authenticated by its kernel peer identity, so no private
        // argv flag is needed. A predecessor without the import adapter can
        // still boot normally (cold-locked) during a compatibility rollback.
        let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
        command.args(arguments);
        if let Some(input) = self.input {
            command.stdin(Stdio::from(std::os::fd::OwnedFd::from(input)));
        } else {
            command.stdin(Stdio::null());
        }
        // Successful exec destroys every old key reference and thread while
        // retaining the service PID. No signer survives in a courier process.
        command.exec()
    }
}

/// Report one local restart request using the shared action definition.
pub(crate) fn run(
    runtime: &tokio::runtime::Runtime,
    data: &Path,
    options: &Options,
    json: bool,
) -> std::process::ExitCode {
    match runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(5),
            request(data, options.binary.as_deref()),
        )
        .await
    }) {
        Ok(Ok(())) => {
            super::output::report(
                json,
                infraternal_plugin_remote::RESTART.id,
                "requested",
                "Server replacement requested",
                "Check health and administrator CA status after startup.",
            );
            std::process::ExitCode::SUCCESS
        }
        _ => super::output::refuse(
            json,
            infraternal_plugin_remote::RESTART.id,
            "Server restart unavailable",
            "Use the running service account, its data directory and an executable binary.",
            1,
        ),
    }
}

/// Cancel old runtime tasks/listeners before exec; independent PTY shims survive.
pub(crate) fn replace(
    runtime: tokio::runtime::Runtime,
    replacement: Replacement,
    json: bool,
) -> std::process::ExitCode {
    drop(runtime);
    let _error = replacement.exec();
    super::output::refuse(
        json,
        infraternal_plugin_remote::RESTART.id,
        "Could not execute the replacement server",
        "Recover service with the retained binary; a cold start requires an administrator CA unlock.",
        1,
    )
}
