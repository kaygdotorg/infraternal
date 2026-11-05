//! Implements local-owner restart requests and same-PID exec without transporting the CA over a named socket [168][217], #154.

use crate::cli::output::Exit;
use std::{
    ffi::CString,
    io::{self, Read, Write},
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

/// The private control endpoint: its socket, path and reload signal.
pub(crate) struct Control {
    listener: UnixListener,
    path: PathBuf,
    reload: tokio::signal::unix::Signal,
    clock_health: std::sync::Arc<infraternal_server::clock_health::ClockHealth>,
}
impl Control {
    /// Start the control endpoint with a fresh clock-health signal, for tests.
    #[cfg(test)]
    pub(crate) fn start(data: &Path) -> io::Result<Self> {
        Self::start_with_clock(
            data,
            std::sync::Arc::new(infraternal_server::clock_health::ClockHealth::default()),
        )
    }

    /// Start the control endpoint with a shared clock-health signal, so status can report CA expiry.
    pub(crate) fn start_with_clock(
        data: &Path,
        clock_health: std::sync::Arc<infraternal_server::clock_health::ClockHealth>,
    ) -> io::Result<Self> {
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
            clock_health,
        })
    }
    /// Wait for the next control request and answer it: status, or a restart into a verified replacement.
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
                    match crate::restart_binary::Opened::open_reload(target.clone()) {
                        Ok(binary) => {
                            let Ok(replacement) = Replacement::new(binary, source) else {
                                record_request("SIGHUP", None, Some(&target), "refused"); continue;
                            };
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
            let Ok(Ok(request)) = request else {
                record_request("socket", peer.as_ref(), None, "refused");
                continue;
            };
            let ControlRequest::Restart { binary, reload } = request else {
                let sent = send_status(&mut socket, source, &self.clock_health).await;
                if sent.is_ok() {
                    record_request("status", peer.as_ref(), None, "replied");
                } else {
                    record_request("status", peer.as_ref(), None, "reply_failed");
                }
                continue;
            };
            let opened = if reload {
                crate::restart_binary::Opened::open_reload(binary.clone())
            } else {
                crate::restart_binary::Opened::open(binary.clone())
            };
            let Ok(opened) = opened else {
                record_request("socket", peer.as_ref(), Some(&binary), "refused");
                let _ = socket.write_all(b"REFUSED\n").await;
                continue;
            };
            let Ok(replacement) = Replacement::new(opened, source) else {
                record_request("socket", peer.as_ref(), Some(&binary), "refused");
                let _ = socket.write_all(b"REFUSED\n").await;
                continue;
            };
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

/// Send the clock-aware trust snapshot through the private owner socket.
async fn send_status(
    socket: &mut UnixStream,
    source: Option<&dyn infraternal_server::ca::CaKeySource>,
    clock_health: &infraternal_server::clock_health::ClockHealth,
) -> io::Result<()> {
    let status = infraternal_server::ca_status::from_source(source, Some(clock_health))
        .unwrap_or_else(|_| infraternal_server::ca_status::CaStatus::unavailable());
    let payload = serde_json::to_vec(&status).map_err(io::Error::other)?;
    if payload.len() > 16 * 1024 {
        return Err(io::Error::other("status response too large"));
    }
    let length =
        u16::try_from(payload.len()).map_err(|_| io::Error::other("status response too large"))?;
    socket.write_u16(length).await?;
    socket.write_all(&payload).await
}

/// What the private control endpoint can be asked: status, or a restart into a binary.
enum ControlRequest {
    Status,
    Restart { binary: PathBuf, reload: bool },
}

/// Read one length-prefixed control request from `socket`.
async fn read_request(socket: &mut UnixStream) -> io::Result<ControlRequest> {
    let length = usize::from(socket.read_u16().await?);
    if length == 0 {
        return match socket.read_u8().await? {
            1 => Ok(ControlRequest::Status),
            _ => Err(io::ErrorKind::InvalidInput.into()),
        };
    }
    if length > MAX_PATH {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = vec![0; length];
    socket.read_exact(&mut bytes).await?;
    let path = PathBuf::from(String::from_utf8(bytes).map_err(|_| io::ErrorKind::InvalidInput)?);
    if path == Path::new(".") {
        return current_binary().map(|binary| ControlRequest::Restart {
            binary,
            reload: true,
        });
    }
    if !path.is_absolute() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(ControlRequest::Restart {
        binary: path,
        reload: false,
    })
}

/// Ask the running server for public-only CA status over the same-UID control socket.
///
/// # Errors
/// Returns unavailable socket, peer-UID, framing, timeout or decode failures to the caller.
pub(crate) fn query_ca_status(data: &Path) -> io::Result<infraternal_server::ca_status::CaStatus> {
    let mut socket = std::os::unix::net::UnixStream::connect(data.join("restart/control.sock"))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let peer = nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::PeerCredentials)?;
    if peer.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    socket.write_all(&0_u16.to_be_bytes())?;
    socket.write_all(&[1])?;
    let mut length = [0; 2];
    socket.read_exact(&mut length)?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 || length > 16 * 1024 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut payload = vec![0; length];
    socket.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(io::Error::other)
}

fn current_binary() -> io::Result<PathBuf> {
    let running = std::env::current_exe()?;
    if running.as_os_str().as_bytes().ends_with(b" (deleted)")
        || running.as_os_str().as_bytes().starts_with(b"/memfd:")
    {
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

#[cfg(test)]
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
            // The receiver owns signature admission and the image probe. Sending
            // the original path preserves symlink refusal and avoids doing the expensive work twice.
            Ok::<_, io::Error>(original)
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
    recovery: crate::restart_binary::Opened,
    recovery_input: Option<std::os::unix::net::UnixStream>,
}
impl Replacement {
    fn outcome(&self) -> &'static str {
        if self.input.is_some() { "warm" } else { "cold" }
    }
    pub(crate) fn new(
        binary: crate::restart_binary::Opened,
        source: Option<&dyn infraternal_server::ca::CaKeySource>,
    ) -> io::Result<Self> {
        // Pin recovery before exporting anything or dropping the serving future.
        let recovery = crate::restart_binary::Opened::running()?;
        let recovery_input = if recovery.warm {
            source.and_then(|source| infraternal_server::ca_handoff::prepare(source).ok())
        } else {
            None
        };
        let input = if binary.warm {
            source.and_then(|source| infraternal_server::ca_handoff::prepare(source).ok())
        } else {
            None
        };
        Ok(Self {
            binary,
            input,
            recovery,
            recovery_input,
        })
    }
    pub(crate) fn exec(self) -> io::Error {
        let error = execute_image(&self.binary, self.input.as_ref());
        drop(self.input);
        tracing::warn!(error_kind = ?error.kind(), outcome = "recovering", "invalid image refused; recovering current image");
        // The first receiver may have been mapped to stdin. A separate frame is
        // essential: failed exec must never reuse or partially consume that frame.
        execute_image(&self.recovery, self.recovery_input.as_ref())
    }
}

fn execute_image(
    binary: &crate::restart_binary::Opened,
    input: Option<&std::os::unix::net::UnixStream>,
) -> io::Error {
    let execute = || -> io::Result<()> {
        let argv = std::iter::once(binary.path.as_os_str().to_owned())
            .chain(std::env::args_os().skip(1))
            .map(|argument| {
                CString::new(argument.as_bytes()).map_err(|_| io::ErrorKind::InvalidInput.into())
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
        let null = if input.is_none() {
            Some(std::fs::File::open("/dev/null")?)
        } else {
            None
        };
        if let Some(input) = input {
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
        binary.image.execute(&argv, &environment)?;
        Ok(())
    };
    execute()
        .err()
        .unwrap_or_else(|| io::ErrorKind::Other.into())
}

/// Report one local restart request using the shared action definition.
pub(crate) fn run(
    runtime: &tokio::runtime::Runtime,
    data: &Path,
    options: &Options,
    json: bool,
) -> std::process::ExitCode {
    match crate::block_on(runtime, async {
        tokio::time::timeout(
            Duration::from_secs(5),
            request(data, options.binary.as_deref()),
        )
        .await
    }) {
        Ok(Ok(warm)) => super::output::done(
            json,
            infraternal_plugin_remote::RESTART.id,
            "requested",
            if warm {
                "Server replacement requested with CA handoff"
            } else {
                "Server replacement requested cold (CA locked)"
            },
            "infraternal status",
        ),
        _ => super::output::refuse(
            json,
            infraternal_plugin_remote::RESTART.id,
            "Server replacement refused",
            "Run this as the account that runs the server, with its --data directory and an executable --binary.",
            Exit::NotAllowed,
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
    tracing::error!(target = ?target, error_kind = ?error.kind(), outcome = "recovering_in_process", json, "replacement and recovery exec refused; resuming current code");
    // If even the pinned old image cannot exec (for example kernel resource
    // pressure), retain its prepared stdin and dispatch the same invocation in
    // the already-loaded code. Normal recovery never returns from fexecve.
    super::run_invocation()
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

#[cfg(test)]
#[path = "restart_recovery_tests.rs"]
mod recovery_tests;
