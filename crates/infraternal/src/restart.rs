//! Implements local-owner restart requests and same-PID exec without transporting the CA over a named socket [168][217], #154.

use crate::cli::output::{CommandResult, CommandState, Exit, emit};
use base64::Engine as _;
use std::{
    ffi::CString,
    fs::OpenOptions,
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    signal::unix::{SignalKind, signal},
};

/// Select the replacement image and whether the current build must hand Mesh state back first.
#[derive(Debug, clap::Args)]
pub(crate) struct Options {
    /// Replacement executable (root-owned handoff-capable builds can retain CA unlock).
    #[arg(long)]
    pub binary: Option<PathBuf>,
    /// Return persistent mesh state to the selected previous build before it starts.
    #[arg(long, requires = "binary")]
    pub rollback: bool,
}

const MAX_PATH: usize = 4096;
/// Caps the public Mesh state document read for a server fingerprint.
const MAX_PUBLIC_STATE_BYTES: u64 = 16 * 1024;

/// The private control endpoint: its socket, server data root, and reload signal.
pub(crate) struct Control {
    socket: crate::server_control::Socket,
    /// Trusted data root used to find the durable Mesh directory during rollback.
    data: PathBuf,
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
        Ok(Self {
            socket: crate::server_control::Socket::bind(data)?,
            data: data.to_owned(),
            reload,
            clock_health,
        })
    }
    /// Wait for the next control request and answer it: status, or a restart into a verified replacement.
    pub(crate) async fn requested(
        &mut self,
        source: Option<&std::sync::Arc<dyn infraternal_server::ca::CaKeySource>>,
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
                            let Ok(replacement) = Replacement::new(binary, source.cloned()) else {
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
                accepted = self.socket.listener.accept() => accepted?.0,
            };
            let peer = socket.peer_cred().ok();
            let same = peer
                .as_ref()
                .is_some_and(crate::server_control::same_account);
            // Root may also run update actions on a server that runs as another account
            // (D400); every other request stays the server account's own.
            #[cfg(feature = "release")]
            let update_caller = peer.as_ref().is_some_and(|peer| {
                infraternal_server::release_control::caller_allowed(
                    peer.uid(),
                    nix::unistd::Uid::effective().as_raw(),
                )
            });
            #[cfg(not(feature = "release"))]
            let update_caller = false;
            if !same && !update_caller {
                record_request("socket", peer.as_ref(), None, "refused");
                continue;
            }
            let request =
                tokio::time::timeout(Duration::from_secs(2), read_request(&mut socket)).await;
            let Ok(Ok(request)) = request else {
                record_request("socket", peer.as_ref(), None, "refused");
                continue;
            };
            // `infraternal server update` (D400): the action runs in its own task, because an
            // apply or roll back ends in a warm restart that this loop must stay free to perform.
            #[cfg(feature = "release")]
            if matches!(request, ControlRequest::Release) {
                record_request("update", peer.as_ref(), None, "accepted");
                let service = infraternal_server::release_control::registered(&self.data);
                tokio::spawn(async move {
                    let _ = infraternal_server::release_control::answer(&mut socket, service).await;
                });
                continue;
            }
            if !same {
                record_request("socket", peer.as_ref(), None, "refused");
                continue;
            }
            #[cfg(target_os = "linux")]
            if matches!(request, ControlRequest::Database) {
                let _ = crate::server_control::send_database(&mut socket, &self.data).await;
                continue;
            }
            let ControlRequest::Restart {
                binary,
                reload,
                rollback,
            } = request
            else {
                let sent = send_status(
                    &mut socket,
                    source.map(|source| &**source),
                    &self.clock_health,
                )
                .await;
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
            let Ok(mut replacement) = Replacement::new(opened, source.cloned()) else {
                record_request("socket", peer.as_ref(), Some(&binary), "refused");
                let _ = socket.write_all(b"REFUSED\n").await;
                continue;
            };
            // Any restart into a named binary may start a build that reads only the legacy runtime
            // path, so every one mirrors Mesh state there once writers stop (J595 P1). Only an
            // explicit rollback makes a failed mirror refuse the restart.
            if !reload {
                match infraternal_agent::sessions::state_path(None) {
                    Ok(volatile) => {
                        replacement.mesh_handoff = Some((self.data.join("mesh"), volatile));
                    }
                    Err(error) if rollback => {
                        record_request("socket", peer.as_ref(), Some(&binary), "refused");
                        let _ = socket.write_all(b"REFUSED\n").await;
                        tracing::warn!(error_kind = ?error.kind(), "server rollback Mesh path unavailable");
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(error_kind = ?error.kind(), "server restart Mesh runtime path unavailable; the next build may not find the Mesh identity");
                    }
                }
            }
            if rollback {
                let Ok(reply) = socket.into_std() else {
                    record_request("socket", peer.as_ref(), Some(&binary), "refused");
                    continue;
                };
                replacement.rollback_reply = Some(reply);
                return Ok(replacement);
            }
            let reply = if replacement.warm_at_request {
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

/// Read-only queries and restart or rollback requests for the private endpoint.
enum ControlRequest {
    /// Public CA status.
    Status,
    /// The live SQLite handle used during install relocation.
    #[cfg(target_os = "linux")]
    Database,
    /// Run one `release.update.*` action for `infraternal server update` (D400).
    #[cfg(feature = "release")]
    Release,
    /// Replace this process with a verified binary.
    Restart {
        binary: PathBuf,
        reload: bool,
        rollback: bool,
    },
}

/// Read one length-prefixed control request from `socket`.
async fn read_request(socket: &mut UnixStream) -> io::Result<ControlRequest> {
    let raw_length = socket.read_u16().await?;
    let rollback = raw_length & 0x8000 != 0;
    let length = usize::from(raw_length & 0x7fff);
    if length == 0 {
        if rollback {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        return match socket.read_u8().await? {
            1 => Ok(ControlRequest::Status),
            #[cfg(target_os = "linux")]
            2 => Ok(ControlRequest::Database),
            #[cfg(feature = "release")]
            infraternal_server::release_control::RELEASE_OPCODE => Ok(ControlRequest::Release),
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
        if rollback {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        return current_binary().map(|binary| ControlRequest::Restart {
            binary,
            reload: true,
            rollback: false,
        });
    }
    if !path.is_absolute() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(ControlRequest::Restart {
        binary: path,
        reload: false,
        rollback,
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
    // Authenticate the connected peer before sending a request. Both queries read
    // kernel credentials; SO_PEERCRED is Linux-only (#379), getpeereid is macOS's equivalent.
    #[cfg(target_os = "linux")]
    let peer_uid =
        nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::PeerCredentials)?.uid();
    #[cfg(target_os = "macos")]
    let peer_uid = nix::unistd::getpeereid(&socket)?.0.as_raw();
    if peer_uid != nix::unistd::Uid::effective().as_raw() {
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

/// Prove the server process is answering and print its active public Mesh fingerprint.
///
/// The private same-UID control socket confirms that a server is running. The data file is only
/// used to read the public key that the active build loads; when both supported state roots are
/// present, their identities must agree before the command reports success.
pub(crate) fn mesh_status(data: &Path, json: bool) -> std::process::ExitCode {
    match query_mesh_fingerprint(data) {
        Ok(fingerprint) => emit(
            CommandResult::new(
                "server mesh status",
                CommandState::Running,
                "The running server's Mesh identity is available.",
                serde_json::json!({
                    "running": true,
                    "public_key_fingerprint": fingerprint,
                }),
            )
            .with_body(format!("Fingerprint: {fingerprint}")),
            json,
            Exit::Ok,
        ),
        Err(error) => super::report_failure_as(
            "server mesh status",
            "The running server's Mesh identity could not be verified.",
            format!(
                "The private control or public state read failed ({:?}).",
                error.kind()
            ),
            json,
            if error.kind() == io::ErrorKind::PermissionDenied {
                Exit::NotAllowed
            } else if error.kind() == io::ErrorKind::NotFound {
                Exit::NotFound
            } else {
                Exit::Failed
            },
        ),
    }
}

/// Read the one public Mesh key that belongs to the responding server process.
/// # Errors
/// Refuses a stopped server, unsafe state path, conflicting copies, or malformed public identity.
fn query_mesh_fingerprint(data: &Path) -> io::Result<String> {
    // This same-account request must succeed before a state file can be described as running.
    let _server_status = query_ca_status(data)?;
    let uid = nix::unistd::Uid::effective().as_raw();
    let key = select_server_mesh_key(
        &data.join("mesh"),
        infraternal_agent::sessions::state_path(None),
        uid,
    )?;
    let fingerprint = openssl::sha::sha256(&key);
    Ok(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(fingerprint)
    ))
}

/// Choose one public Mesh key only after resolving both supported state locations.
/// # Errors
/// Refuses an unresolved runtime path, unsafe or malformed state, or conflicting identities.
fn select_server_mesh_key(
    durable_directory: &Path,
    runtime_path: io::Result<PathBuf>,
    uid: u32,
) -> io::Result<[u8; 32]> {
    let durable = public_mesh_key(durable_directory, uid)?;
    // Reporting a durable key alone could misidentify a live server when its runtime path failed
    // to resolve, so preserve that error instead of treating it as an absent runtime copy.
    let runtime_path = runtime_path?;
    let runtime = if runtime_path == durable_directory {
        None
    } else {
        public_mesh_key(&runtime_path, uid)?
    };
    match (durable, runtime) {
        (Some(durable), Some(runtime)) if durable == runtime => Ok(durable),
        (Some(_), Some(_)) => Err(io::ErrorKind::InvalidData.into()),
        (Some(key), None) | (None, Some(key)) => Ok(key),
        (None, None) => Err(io::ErrorKind::NotFound.into()),
    }
}

/// Read one private-directory public state document without following or accepting linked files.
/// # Errors
/// Refuses unsafe ownership, modes, links, an oversized document, or an invalid public key.
fn public_mesh_key(directory: &Path, uid: u32) -> io::Result<Option<[u8; 32]>> {
    let directory_metadata = match std::fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !directory_metadata.is_dir()
        || directory_metadata.uid() != uid
        || directory_metadata.mode() & 0o7777 != 0o700
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }

    let path = directory.join("mesh-public.json");
    let mut options = OpenOptions::new();
    let flags = nix::fcntl::OFlag::O_NOFOLLOW
        | nix::fcntl::OFlag::O_CLOEXEC
        | nix::fcntl::OFlag::O_NONBLOCK;
    options.read(true).custom_flags(flags.bits());
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let max_public_state_bytes =
        usize::try_from(MAX_PUBLIC_STATE_BYTES).map_err(|_| io::ErrorKind::InvalidData)?;
    let mut bytes = Vec::with_capacity(max_public_state_bytes);
    file.take(MAX_PUBLIC_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_public_state_bytes {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let state: serde_json::Value = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let local_key = state
        .get("config")
        .and_then(serde_json::Value::as_object)
        .and_then(|config| config.get("local_key"))
        .filter(|local_key| !local_key.is_null())
        .ok_or(io::ErrorKind::NotFound)?;
    serde_json::from_value(local_key.clone())
        .map(Some)
        .map_err(|_| io::ErrorKind::InvalidData.into())
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

/// Ask the running server to restart into an optional binary over its private control socket.
///
/// A rollback request must name its previous binary so the server can hand Mesh state back before
/// that image starts. The receiver validates and opens the image; this request only sends its path.
/// # Errors
/// Reports an invalid rollback request, an unsafe path, a missing socket, or a failed frame write.
pub(crate) async fn request(
    data: &Path,
    binary: Option<&Path>,
    rollback: bool,
) -> io::Result<bool> {
    if rollback && binary.is_none() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
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
    let length = u16::try_from(bytes.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    if bytes.len() > MAX_PATH {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    socket
        .write_u16(length | if rollback { 0x8000 } else { 0 })
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

/// A checked successor image, ready for the same-PID exec, plus the way back.
///
/// `binary` is the sealed image to exec and `input` the CA frame it receives on stdin
/// (only when both sides are handoff-capable and the CA is unlocked). `recovery` is the
/// running image, pinned before anything is exported, so a failed exec can exec it again
/// with its own separate frame. Every restart into a named binary mirrors Mesh state to
/// the legacy path once writers stop; a rollback is acknowledged only after that mirror
/// is complete.
pub(crate) struct Replacement {
    binary: crate::restart_binary::Opened,
    /// The live key source, kept so the CA is exported only right before exec (#559, J1099).
    ///
    /// Exporting when the request arrives would freeze the lock state for the whole shutdown
    /// window (up to 4 s of runtime shutdown plus the Mesh mirror). An administrator's unlock that
    /// finished inside that window answered "unlocked", yet the successor started cold.
    source: Option<std::sync::Arc<dyn infraternal_server::ca::CaKeySource>>,
    /// Whether the selected image would start warm if exec happened now; this only shapes the
    /// requester's reply and the request log. The actual frame is built later by `export_ca`.
    warm_at_request: bool,
    /// The successor's frame, filled by `export_ca` just before the selected image executes.
    input: Option<std::os::unix::net::UnixStream>,
    recovery: crate::restart_binary::Opened,
    /// The recovery image's own frame, filled just before recovery executes. A failed exec must
    /// never reuse or partially consume the successor's frame, so each image gets its own.
    recovery_input: Option<std::os::unix::net::UnixStream>,
    /// Held until the exec: the auto-update's folder lock and verified file (#211 S4).
    /// Both are close-on-exec, so the exec itself releases them.
    hold: Option<Box<dyn Send>>,
    /// Durable and legacy Mesh directories to mirror after quiescence, when a binary was named.
    mesh_handoff: Option<(PathBuf, PathBuf)>,
    /// Deferred reply to an explicit rollback request, sent only after the mirror finished.
    rollback_reply: Option<std::os::unix::net::UnixStream>,
    /// An auto-update undo (#211 S4, D295): like an explicit rollback, a failed Mesh mirror
    /// refuses the older image, which must never start without its Mesh identity.
    mesh_required: bool,
    /// The staging proof's `exec` fault: the exec of the new image is refused as if the
    /// kernel had refused it, so the late-exec recovery runs (#211 S4).
    #[cfg(feature = "staging-trust")]
    refuse_exec: bool,
}
impl Replacement {
    /// Describe whether the selected image can receive a warm CA handoff.
    fn outcome(&self) -> &'static str {
        if self.warm_at_request { "warm" } else { "cold" }
    }
    /// Pin the requested executable and the current image for recovery, keeping the key source.
    ///
    /// No CA material leaves the source here: both frames are built by `export_ca` right before
    /// their exec, so an unlock that lands while the runtime shuts down still reaches the
    /// successor. Both images stay open until the selected image is executed.
    /// # Errors
    /// Returns an error if the current image cannot be opened for recovery.
    pub(crate) fn new(
        binary: crate::restart_binary::Opened,
        source: Option<std::sync::Arc<dyn infraternal_server::ca::CaKeySource>>,
    ) -> io::Result<Self> {
        // Pin recovery before dropping the serving future.
        let recovery = crate::restart_binary::Opened::running()?;
        Ok(Self::with_recovery(binary, recovery, source))
    }

    /// Assemble a replacement from the selected image and an already pinned recovery image.
    ///
    /// Split from [`Replacement::new`] so tests can pass signed fixture images: a debug test
    /// executable is larger than the running-image bound `Opened::running` enforces.
    fn with_recovery(
        binary: crate::restart_binary::Opened,
        recovery: crate::restart_binary::Opened,
        source: Option<std::sync::Arc<dyn infraternal_server::ca::CaKeySource>>,
    ) -> Self {
        // A cheap probe for the reply only; the material it clones is dropped at once.
        let warm_at_request =
            binary.warm && source.as_ref().is_some_and(|source| source.load().is_ok());
        Self {
            binary,
            source,
            warm_at_request,
            input: None,
            recovery,
            recovery_input: None,
            hold: None,
            mesh_handoff: None,
            rollback_reply: None,
            mesh_required: false,
            #[cfg(feature = "staging-trust")]
            refuse_exec: false,
        }
    }

    /// Build one image's CA frame from the source's current state, or `None` to start cold.
    ///
    /// Called once per image, immediately before that image executes. A locked source, a cold-only
    /// image or a failed export all mean a cold start (D217: a failed handoff stays locked).
    fn export_ca(
        source: Option<&std::sync::Arc<dyn infraternal_server::ca::CaKeySource>>,
        image: &crate::restart_binary::Opened,
    ) -> Option<std::os::unix::net::UnixStream> {
        if !image.warm {
            return None;
        }
        source.and_then(|source| infraternal_server::ca_handoff::prepare(source.as_ref()).ok())
    }

    /// Mirror Mesh state to the legacy path once writers stop, before another image starts.
    ///
    /// For an explicit rollback a failed mirror refuses the older image and recovers this build.
    /// For any other named binary a failure is logged and the restart continues: the durable copy
    /// is untouched, and a newer build reads it directly.
    /// # Errors
    /// Returns the recovery exec error when a rollback is refused or its requester disconnected.
    fn handoff_after_quiescence(mut self) -> Result<Self, io::Error> {
        let rollback = self.rollback_reply.is_some() || self.mesh_required;
        let result = self
            .mesh_handoff
            .take()
            .map_or(Ok(()), |(durable, volatile)| {
                infraternal_server::embedded_mesh_state::rollback_handoff(&durable, &volatile)
            });
        if let Err(error) = result {
            if !rollback {
                tracing::warn!(error_kind = ?error.kind(), "server restart Mesh mirror failed; a previous build started next may not find the Mesh identity");
                return Ok(self);
            }
            tracing::warn!(error_kind = ?error.kind(), "server rollback Mesh handoff refused");
            let _ = self.reply_rollback(b"REFUSED\n");
            return Err(self.exec_recovery_only());
        }
        if rollback {
            if let Err(error) = self.reply_rollback(b"RESTARTING\n") {
                tracing::warn!(error_kind = ?error.kind(), "server rollback requester disconnected");
                return Err(self.exec_recovery_only());
            }
            tracing::info!(
                outcome = "rollback_mesh_handoff_complete",
                "server_restart_request"
            );
        }
        Ok(self)
    }

    /// Send the deferred reply only after the writer-quiesced handoff has finished.
    /// # Errors
    /// Returns a socket configuration or write error so the caller can recover this image.
    fn reply_rollback(&mut self, reply: &[u8]) -> io::Result<()> {
        let Some(mut socket) = self.rollback_reply.take() else {
            return Ok(());
        };
        socket.set_nonblocking(false)?;
        socket.set_write_timeout(Some(Duration::from_secs(2)))?;
        socket.write_all(reply)?;
        socket.shutdown(std::net::Shutdown::Write)
    }

    /// Restart only this image after rollback refusal, without ever executing the older image.
    fn exec_recovery_only(mut self) -> io::Error {
        drop(self.input.take());
        self.recovery_input = Self::export_ca(self.source.as_ref(), &self.recovery);
        let error = execute_image(&self.recovery, self.recovery_input.as_ref());
        drop(self.recovery_input.take());
        error
    }

    /// Exec the successor with a CA frame exported now; if that is refused, exec the pinned
    /// running image instead, with its own frame. Returns only when both execs failed.
    /// Anything in `hold` (an update's folder lock and verified file) lives until then and is
    /// closed by the exec.
    pub(crate) fn exec(mut self) -> io::Error {
        let _hold = self.hold.take();
        // Built here, after shutdown and the Mesh handoff, so a late unlock still counts (#559).
        self.input = Self::export_ca(self.source.as_ref(), &self.binary);
        #[cfg(feature = "staging-trust")]
        let error = if self.refuse_exec {
            io::ErrorKind::PermissionDenied.into()
        } else {
            execute_image(&self.binary, self.input.as_ref())
        };
        #[cfg(not(feature = "staging-trust"))]
        let error = execute_image(&self.binary, self.input.as_ref());
        drop(self.input.take());
        tracing::warn!(error_kind = ?error.kind(), outcome = "recovering", "invalid image refused; recovering current image");
        // The first receiver may have been mapped to stdin. A separate frame is
        // essential: failed exec must never reuse or partially consume that frame.
        self.recovery_input = Self::export_ca(self.source.as_ref(), &self.recovery);
        execute_image(&self.recovery, self.recovery_input.as_ref())
    }
}

/// Replace this process with exactly the checked inode of `binary`, passing the
/// same arguments and environment and `input` (or `/dev/null`) as stdin. Only
/// returns when the kernel refused the exec, with the reason, so the caller can
/// recover.
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
        // The new image records its launcher's transparent-huge-page policy
        // at startup and gives it to the shells it starts. Hand it the policy
        // this server was started with, not the opt-out the mesh engine took
        // for this process; a refused exec gets the opt-out back (#522).
        #[cfg(target_os = "linux")]
        infraternal_shim::with_launcher_thp(|| binary.image.execute(&argv, &environment))?;
        #[cfg(not(target_os = "linux"))]
        binary.image.execute(&argv, &environment)?;
        Ok(())
    };
    execute()
        .err()
        .unwrap_or_else(|| io::ErrorKind::Other.into())
}

/// Turn the auto-updater's switch request into a warm replacement (#211 S4; D217, D295).
///
/// **Forward:** the installed release is admitted from the updater's verified open
/// file (never reopened by path), with its signature checked again on the sealed copy.
/// **Undo:** the kept previous image is admitted only if its SHA-256 is the one the
/// previous release recorded for itself, and it gets its own argv\[0\] back.
///
/// Either way, if this process holds the unlocked CA, the replacement must receive it
/// (an update never locks the CA, D217). Otherwise the request is refused and the
/// server keeps serving. Returns the replacement to exec, or `None` after a refusal
/// (which has already been answered).
#[cfg(feature = "release")]
pub(crate) fn switch(
    request: infraternal_server::update_apply::SwitchRequest,
    source: Option<&std::sync::Arc<dyn infraternal_server::ca::CaKeySource>>,
    data: &Path,
) -> Option<Replacement> {
    use infraternal_server::update_apply::{SwitchRequest, ca_warm, image_digest};
    // The frame itself is built at exec (#559); admission checks that the image is warm-capable
    // and the source unlocked now.
    let keeps_ca = |replacement: &Replacement| !ca_warm() || replacement.warm_at_request;
    // Like any restart into a named binary, both directions mirror the durable Mesh state
    // to the legacy runtime path once writers stop (#489), so an older build finds its
    // identity. An undo cannot go ahead without that mirror.
    let mesh = |mut replacement: Replacement, required: bool| -> Option<Replacement> {
        match infraternal_agent::sessions::state_path(None) {
            Ok(volatile) => {
                replacement.mesh_handoff = Some((data.join("mesh"), volatile));
                replacement.mesh_required = required;
                Some(replacement)
            }
            Err(error) => {
                tracing::warn!(error_kind = ?error.kind(), "update switch Mesh runtime path unavailable");
                (!required).then_some(replacement)
            }
        }
    };
    match request {
        SwitchRequest::Apply { switch, reply } => {
            let admitted = crate::restart_binary::Opened::from_verified(
                switch.file(),
                switch.path().to_owned(),
            )
            .and_then(|binary| Replacement::new(binary, source.cloned()))
            .ok()
            .filter(keeps_ca)
            .and_then(|replacement| mesh(replacement, false));
            let Some(mut replacement) = admitted else {
                record_request("update", None, Some(switch.path()), "refused");
                let _ = reply.send(Err(switch));
                return None;
            };
            record_request("update", None, Some(switch.path()), replacement.outcome());
            #[cfg(feature = "staging-trust")]
            {
                use infraternal_server::update_apply::{StagingFault, staging_fault};
                replacement.refuse_exec =
                    staging_fault(switch.version()) == Some(StagingFault::Exec);
            }
            let _ = reply.send(Ok(()));
            replacement.hold = Some(Box::new(switch));
            Some(replacement)
        }
        SwitchRequest::Undo { undo, reply } => {
            let admitted =
                crate::restart_binary::Opened::open_with(undo.image.clone(), |file, _| {
                    (image_digest(file).map_err(|_| io::ErrorKind::InvalidData)? == undo.sha256)
                        .then_some(())
                        .ok_or_else(|| io::ErrorKind::PermissionDenied.into())
                })
                .map(|mut binary| {
                    binary.path.clone_from(&undo.path);
                    binary
                })
                .and_then(|binary| Replacement::new(binary, source.cloned()))
                .ok()
                .filter(keeps_ca)
                .and_then(|replacement| mesh(replacement, true));
            let Some(replacement) = admitted else {
                record_request("update-undo", None, Some(&undo.image), "refused");
                let _ = reply.send(Err(()));
                return None;
            };
            record_request("update-undo", None, Some(&undo.path), replacement.outcome());
            let _ = reply.send(Ok(()));
            Some(replacement)
        }
    }
}

/// The warm undo for a new release on trial whose serving failed at startup (#211 S4).
///
/// Builds the same undo request a failed health check sends and admits it with
/// [`switch`], so the previous release comes back in this process with the CA (D217)
/// and restores its database copy (D295). Returns `None` when this process is not on
/// trial or the undo was refused; the caller then returns the serving error as before.
#[cfg(feature = "release")]
pub(crate) fn failed_start(
    source: Option<&std::sync::Arc<dyn infraternal_server::ca::CaKeySource>>,
    data: &Path,
) -> Option<Replacement> {
    let undo = infraternal_server::update_apply::failed_start_undo(data)?;
    let (reply, _answer) = tokio::sync::oneshot::channel();
    switch(
        infraternal_server::update_apply::SwitchRequest::Undo { undo, reply },
        source,
        data,
    )
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
            request(data, options.binary.as_deref(), options.rollback),
        )
        .await
    }) {
        Ok(Ok(warm)) => super::output::done(
            json,
            infraternal_plugin_remote::RESTART.id,
            "requested",
            if options.rollback {
                "Server rollback requested with mesh state handoff"
            } else if warm {
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
    let replacement = match replacement.handoff_after_quiescence() {
        Ok(replacement) => replacement,
        Err(error) => {
            tracing::error!(error_kind = ?error.kind(), outcome = "rollback_refused_recovery_failed", json,
                "previous server build was not started because its Mesh handoff failed");
            return super::run_invocation();
        }
    };
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
