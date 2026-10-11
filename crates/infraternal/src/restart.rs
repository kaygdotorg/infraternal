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
        let reload = signal(SignalKind::hangup())?;
        let mut mask = nix::sys::signal::SigSet::empty();
        mask.add(nix::sys::signal::Signal::SIGHUP);
        // Register first, then drain pending signals. Even a later endpoint
        // failure leaves a handler, rather than the terminating default.
        nix::sys::signal::sigprocmask(
            nix::sys::signal::SigmaskHow::SIG_UNBLOCK,
            Some(&mask),
            None,
        )?;
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
            reload,
        })
    }
    pub(crate) async fn requested(
        &mut self,
        source: Option<&dyn infraternal_server::ca::CaKeySource>,
    ) -> io::Result<Replacement> {
        loop {
            let mut socket = tokio::select! {
                _ = self.reload.recv() => {
                    let target = match current_binary() {
                        Ok(target) => target,
                        Err(error) => {
                            record_request("SIGHUP", None, None, "refused");
                            tracing::warn!(error_kind = ?error.kind(), "server reload target unavailable");
                            continue;
                        }
                    };
                    match crate::restart_binary::Opened::open(target.clone()) {
                        Ok(binary) => {
                            let replacement = Replacement::new(binary, source);
                            record_request("SIGHUP", None, Some(&replacement.binary.path), replacement.outcome());
                            return Ok(replacement);
                        }
                        Err(error) => {
                            record_request("SIGHUP", None, Some(&target), "refused");
                            tracing::warn!(error_kind = ?error.kind(), "server reload request refused");
                            continue;
                        }
                    }
                },
                accepted = self.listener.accept() => accepted?.0,
            };
            let peer = socket.peer_cred().ok();
            if peer
                .as_ref()
                .is_none_or(|peer| peer.uid() != nix::unistd::Uid::effective().as_raw())
            {
                record_request("socket", peer.as_ref(), None, "refused");
                continue;
            }
            let request =
                tokio::time::timeout(Duration::from_secs(2), read_request(&mut socket)).await;
            let Ok(Ok(binary)) = request else {
                record_request("socket", peer.as_ref(), None, "refused");
                continue;
            };
            let Ok(opened) = crate::restart_binary::Opened::open(binary.clone()) else {
                record_request("socket", peer.as_ref(), Some(&binary), "refused");
                let _ = socket.write_all(b"REFUSED\n").await;
                continue;
            };
            let replacement = Replacement::new(opened, source);
            let reply = if replacement.input.is_some() {
                b"RESTARTING\n".as_slice()
            } else {
                b"RESTARTING COLD (CA locked)\n".as_slice()
            };
            if let Err(error) = socket.write_all(reply).await {
                record_request(
                    "socket",
                    peer.as_ref(),
                    Some(&replacement.binary.path),
                    "reply_failed",
                );
                tracing::warn!(error_kind = ?error.kind(), "server restart requester disconnected");
                continue;
            }
            record_request(
                "socket",
                peer.as_ref(),
                Some(&replacement.binary.path),
                replacement.outcome(),
            );
            return Ok(replacement);
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
    let running = std::env::current_exe()?;
    if running.as_os_str().as_bytes().ends_with(b" (deleted)") {
        // ExecStart/our pinned exec argv[0] retains the configured install path.
        // Reopen its newly installed inode rather than the vanished old image.
        let configured = std::env::args_os()
            .next()
            .map(PathBuf::from)
            .ok_or(io::ErrorKind::NotFound)?;
        let configured = if configured.is_absolute() {
            configured
        } else {
            std::env::current_dir()?.join(configured)
        };
        return Ok(configured);
    }
    Ok(running)
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
    fn outcome(&self) -> &'static str {
        if self.input.is_some() { "warm" } else { "cold" }
    }
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
            // Retain ownership through exec: open may itself return fd0 when
            // cleanup previously closed stdin. Dropping that File would close it.
            let null = if self.input.is_none() {
                Some(std::fs::File::open("/dev/null")?)
            } else {
                None
            };
            if let Some(input) = &self.input {
                nix::unistd::dup2_stdin(input)?;
            } else {
                nix::unistd::dup2_stdin(null.as_ref().ok_or(io::ErrorKind::Other)?)?;
            }
            // dup2(oldfd, oldfd) preserves CLOEXEC. Stdin must survive even when
            // the newly opened null input was already descriptor zero.
            nix::fcntl::fcntl(
                std::io::stdin(),
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
            )?;

            // Execute exactly the checked inode; no pathname lookup occurs after
            // exporting the CA. O_CLOEXEC closes this fd in the successor.
            queue_reload()?;
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
    shutdown_runtime(runtime);
    let target = replacement.binary.path.clone();
    let error = replacement.exec();
    tracing::error!(target = ?target, error_kind = ?error.kind(), outcome = "cold", "server replacement exec failed");
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

/// Blocking cleanup has its own SIGKILL/reap deadline; exec cannot wait forever.
fn shutdown_runtime(runtime: tokio::runtime::Runtime) {
    runtime.shutdown_timeout(Duration::from_secs(4));
}

/// Block before spawning threads or exec; pending reloads cannot hit a default
/// disposition in the successor's loader/startup window.
pub(crate) fn queue_reload() -> io::Result<()> {
    let mut mask = nix::sys::signal::SigSet::empty();
    mask.add(nix::sys::signal::Signal::SIGHUP);
    nix::sys::signal::sigprocmask(nix::sys::signal::SigmaskHow::SIG_BLOCK, Some(&mask), None)?;
    Ok(())
}

/// Peer identity comes only from `SO_PEERCRED`; SIGHUP has no such credentials.
/// Debug path formatting escapes newline/control characters in human logs.
fn record_request(
    origin: &str,
    peer: Option<&tokio::net::unix::UCred>,
    target: Option<&Path>,
    outcome: &str,
) {
    let pid = peer.and_then(tokio::net::unix::UCred::pid);
    let uid = peer.map(tokio::net::unix::UCred::uid);
    tracing::info!(service_pid = std::process::id(), request_pid = ?pid, request_uid = ?uid, target = ?target,
        outcome, origin, "server_restart_request");
}
