//! Implements local-owner restart requests and same-PID exec without transporting the CA over a named socket [168][217], #154.

use std::{
    ffi::CString,
    io,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    signal::unix::{SignalKind, signal},
};

#[derive(Debug, clap::Args)]
pub(crate) struct Options {
    /// Replacement executable (root-owned handoff-capable builds can retain CA unlock).
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
    pub(crate) async fn requested(
        &mut self,
        source: Option<&dyn infraternal_server::ca::CaKeySource>,
    ) -> io::Result<Replacement> {
        loop {
            let mut socket = tokio::select! {
                _ = self.reload.recv() => return crate::restart_binary::Opened::open(current_binary()?).map(|binary| Replacement::new(binary, source)),
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
                let Ok(binary) = crate::restart_binary::Opened::open(binary) else {
                    let _ = socket.write_all(b"REFUSED\n").await;
                    continue;
                };
                let replacement = Replacement::new(binary, source);
                let reply = if replacement.input.is_some() {
                    b"RESTARTING\n".as_slice()
                } else {
                    b"RESTARTING COLD (CA locked)\n".as_slice()
                };
                socket.write_all(reply).await?;
                return Ok(replacement);
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
    crate::restart_binary::Opened::open(binary.to_owned()).map(|_| ())
}

pub(crate) async fn request(data: &Path, binary: Option<&Path>) -> io::Result<bool> {
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
    socket.take(64).read_to_end(&mut response).await?;
    match response.as_slice() {
        b"RESTARTING\n" => Ok(true),
        b"RESTARTING COLD (CA locked)\n" => Ok(false),
        _ => Err(io::ErrorKind::PermissionDenied.into()),
    }
}

pub(crate) struct Replacement {
    binary: crate::restart_binary::Opened,
    input: Option<std::os::unix::net::UnixStream>,
}
impl Replacement {
    pub(crate) fn new(
        binary: crate::restart_binary::Opened,
        source: Option<&dyn infraternal_server::ca::CaKeySource>,
    ) -> Self {
        let input = if binary.warm {
            source.and_then(|source| infraternal_server::ca_handoff::prepare(source).ok())
        } else {
            None
        };
        Self { binary, input }
    }
    pub(crate) fn exec(self) -> io::Error {
        let execute = || -> io::Result<()> {
            let argv = std::iter::once(self.binary.path.as_os_str().to_owned())
                .chain(std::env::args_os().skip(1))
                .map(|argument| {
                    CString::new(argument.as_bytes())
                        .map_err(|_| io::ErrorKind::InvalidInput.into())
                })
                .collect::<io::Result<Vec<_>>>()?;
            let environment = std::env::vars_os()
                .map(|(key, value)| {
                    let mut entry = key.as_bytes().to_vec();
                    entry.push(b'=');
                    entry.extend_from_slice(value.as_bytes());
                    CString::new(entry).map_err(|_| io::ErrorKind::InvalidInput.into())
                })
                .collect::<io::Result<Vec<_>>>()?;
            if let Some(input) = &self.input {
                nix::unistd::dup2_stdin(input)?;
            } else {
                nix::unistd::dup2_stdin(std::fs::File::open("/dev/null")?)?;
            }
            // Execute exactly the checked inode; no pathname lookup occurs after
            // exporting the CA. O_CLOEXEC closes this fd in the successor.
            nix::unistd::fexecve(&self.binary.file, &argv, &environment)?;
            Ok(())
        };
        let error = execute()
            .err()
            .unwrap_or_else(|| io::ErrorKind::Other.into());
        // An exec error must not leave queued signing material on stdin.
        let _ = nix::unistd::close(0);
        error
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
        Ok(Ok(warm)) => {
            super::output::report(
                json,
                infraternal_plugin_remote::RESTART.id,
                "requested",
                if warm {
                    "Server replacement requested with CA handoff"
                } else {
                    "Server replacement requested cold (CA locked)"
                },
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

#[cfg(test)]
#[path = "restart_tests.rs"]
mod tests;
