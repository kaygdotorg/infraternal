//! The short-lived root relay of a root upgrade (D376, #399): runs the server's install steps as root.
//!
//! [`crate::privilege_elevate`] starts this with the person's password, as
//! `infraternal __privilege-relay --socket <path> --uid <uid> --dir <dir>`,
//! from a digest-checked copy of the binary. It is the only thing a root
//! upgrade runs as root before the root infraternal agent itself, so it is
//! deliberately small:
//!
//! - It first reads a one-time token from its terminal, typed there by the
//!   rootless infraternal agent that started it (never in argv). It connects
//!   to that agent's socket and to nothing else, refuses unless the socket,
//!   its directory and the process listening on it all belong to `--uid`,
//!   and then refuses unless the first frame on it is that same token
//!   (J415 B5). Another process of the same account could swap the socket,
//!   but it can't make the relay run its bytes: the token never leaves the
//!   agent, which is non-dumpable from its start (no same-uid ptrace or
//!   memory reads, whatever Yama's setting). Such a process can open the
//!   terminal and read the typed token, but not type into the agent's
//!   socket; at worst the relay refuses and exits, a denial of service only
//!   (J465 P3-6).
//! - It runs only what arrives in [`Frame::Open`]: the server's root install
//!   steps (the same scripts a root Add host runs over SSH), each under
//!   `/bin/sh -c` with an empty environment, in its own process group.
//! - It keeps the server's [`Frame::Rollback`] script and runs it itself
//!   whenever the upgrade ends without a [`Frame::Commit`]: on `Close`, end
//!   of input, a protocol error or after [`LIFETIME`] (J415 R4). It stops
//!   every step first, and the script takes the install's own setup lock.
//!   So a lost link, a server restart or a killed rootless agent puts the
//!   host back as it was (D376), instead of leaving a half-installed root
//!   service behind.
//! - It also arms a host-side guard (an undo script, a boot-time unit and a
//!   watcher unit outside its own process tree), so a relay that is killed,
//!   crashes or loses its host to a reboot still puts the host back
//!   (J465 P1). `Commit` or its own rollback disarms the guard.
//! - It blocks `SIGHUP`: the terminal it was started on closes when the
//!   rootless agent lets go of it, and that must not skip the rollback. Its
//!   end is the socket's end (J415 B6). `--dir` (its own copy of the
//!   binary) is removed when it exits.
//!
//! It never sees the password: that was typed to sudo, doas or su before
//! this process existed.
use infraternal_plugin_remote::privilege_relay::{
    Decoder, Frame, MAX_CHANNELS, MAX_CHUNK, MAX_STDERR,
};
use std::{
    collections::HashMap,
    ffi::OsString,
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{ExitCode, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};
use zeroize::Zeroizing;

/// The longest a relay lives. An upgrade takes seconds to a minute; this is a
/// hang guard so a lost server can't leave a root process behind.
pub const LIFETIME: Duration = Duration::from_mins(15);
/// The hidden command word.
pub const COMMAND: &str = "__privilege-relay";

/// Run the relay when this process was started as one; `None` otherwise.
///
/// The arguments must be exactly `__privilege-relay --socket <path> --uid
/// <uid> --dir <dir>`, and the process must be root.
#[must_use]
pub fn run_if_requested() -> Option<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some(COMMAND) {
        return None;
    }
    let parsed = match &args[1..] {
        [s, socket, u, uid, d, dir] if s == "--socket" && u == "--uid" && d == "--dir" => uid
            .parse::<u32>()
            .ok()
            .map(|uid| (PathBuf::from(socket), uid, PathBuf::from(dir))),
        _ => None,
    };
    let Some((socket, uid, dir)) = parsed else {
        return Some(ExitCode::from(2));
    };
    if !nix::unistd::Uid::effective().is_root() || uid == 0 {
        return Some(ExitCode::from(2));
    }
    // The terminal closing must not stop the rollback (see the module docs):
    // SIGHUP stays blocked (pending, never delivered) for the relay's life.
    // Blocking needs no handler code, so no unsafe; threads and the steps the
    // relay starts inherit the mask.
    let mut hangup = nix::sys::signal::SigSet::empty();
    hangup.add(nix::sys::signal::Signal::SIGHUP);
    if hangup.thread_block().is_err() {
        return Some(ExitCode::from(2));
    }
    let own = dir.clone();
    let _cleanup = RemoveOnDrop(dir);
    let Some(token) = read_token(TOKEN_WAIT) else {
        return Some(ExitCode::from(2));
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return Some(ExitCode::FAILURE);
    };
    let config = GuardConfig::system();
    let runner = SystemdGuardCommandRunner;
    let result = runtime.block_on(async {
        let stream = connect(&socket, uid).await?;
        let (reader, writer) = stream.into_split();
        serve_with_guard(reader, writer, &token, LIFETIME, &config, &own, &runner).await
    });
    Some(if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// How long the relay waits for its token on its terminal.
const TOKEN_WAIT: Duration = Duration::from_secs(10);
/// How long the rollback script may run.
const ROLLBACK_BOUND: Duration = Duration::from_mins(2);
/// Most stdin bytes queued for one step before the relay stops it: a step
/// that stops reading its stdin must not stall the frame loop (B4), but a
/// step that is merely slow to start reading (the payload upload takes the
/// setup lock first) must not be killed. The payload is far below this.
const STDIN_CAP: usize = 256 << 20;

/// Read the one-time token from stdin (the terminal the agent types it
/// to): 64 lowercase hex digits and a newline, within `wait`. Then point
/// stdin at `/dev/null`, so the terminal is no longer read.
fn read_token(wait: Duration) -> Option<Zeroizing<[u8; 32]>> {
    use std::os::fd::AsFd as _;
    let stdin = std::io::stdin();
    let deadline = std::time::Instant::now() + wait;
    let mut line = Zeroizing::new(Vec::with_capacity(65));
    let mut byte = [0u8; 1];
    while !line.ends_with(b"\n") && line.len() <= 65 {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let millis = u16::try_from(left.as_millis()).unwrap_or(u16::MAX);
        if millis == 0 {
            return None;
        }
        let mut fds = [nix::poll::PollFd::new(
            stdin.as_fd(),
            nix::poll::PollFlags::POLLIN,
        )];
        if nix::poll::poll(&mut fds, nix::poll::PollTimeout::from(millis)).ok()? == 0 {
            continue;
        }
        match nix::unistd::read(stdin.as_fd(), &mut byte) {
            Ok(1) => line.push(byte[0]),
            _ => return None,
        }
    }
    if let Ok(null) = std::fs::File::open("/dev/null") {
        let _ = nix::unistd::dup2_stdin(null);
    }
    let mut text: &[u8] = line.strip_suffix(b"\n")?;
    if let Some(trimmed) = text.strip_suffix(b"\r") {
        text = trimmed;
    }
    if text.len() != 64 {
        return None;
    }
    let mut token = Zeroizing::new([0u8; 32]);
    for (slot, pair) in token.iter_mut().zip(text.chunks(2)) {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        *slot = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(token)
}

/// Removes the relay's private directory (its binary copy) when it ends.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    /// Removes the directory, but only one the snippet could have made.
    fn drop(&mut self) {
        // Only the directory the snippet made: a fresh root-owned one under /run.
        if self.0.starts_with("/run")
            && self
                .0
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("infraternal-privilege."))
        {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// Connect to the account's socket, checking that the socket file, its
/// directory and the process behind it all belong to `uid`.
async fn connect(socket: &Path, uid: u32) -> std::io::Result<tokio::net::UnixStream> {
    let denied = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    let parent = socket.parent().ok_or_else(denied)?;
    let directory = std::fs::symlink_metadata(parent)?;
    let file = std::fs::symlink_metadata(socket)?;
    if !directory.is_dir()
        || directory.uid() != uid
        || directory.mode() & 0o077 != 0
        || file.uid() != uid
    {
        return Err(denied());
    }
    let stream = tokio::net::UnixStream::connect(socket).await?;
    if stream.peer_cred()?.uid() != uid {
        return Err(denied());
    }
    Ok(stream)
}

/// One running install step.
struct Channel {
    /// Where its stdin bytes go; dropping it closes the script's stdin.
    stdin: Option<mpsc::UnboundedSender<Vec<u8>>>,
    /// Bytes queued for the step's stdin and not yet written to it.
    queued: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Its process group, to kill it.
    group: Option<nix::unistd::Pid>,
}

/// Serve the relay protocol on `reader`/`writer` until it ends.
///
/// The first frame must be [`Frame::Token`] carrying `token`, or nothing
/// runs. Then it sends [`Frame::Ready`]. The server's [`Frame::Rollback`]
/// must come before any `Open`. Each `Open` runs its script as this process
/// (root, in production) under `/bin/sh -c`, with the environment cleared
/// apart from `PATH`, `HOME` and the `C` locale, in its own process group.
/// Its stdout is forwarded whole and its stderr up to [`MAX_STDERR`] bytes,
/// the same bound the server keeps of an SSH command's stderr.
///
/// It ends on `Close`, end of input, a protocol error or `lifetime`. Every
/// step still running is killed; then, unless `Commit` came first, the
/// rollback script runs (see the module docs).
///
/// # Errors
/// The stream broke or carried something that is not relay protocol (the
/// rollback has run by then).
pub async fn serve(
    reader: impl AsyncRead + Unpin,
    writer: impl AsyncWrite + Unpin + Send + 'static,
    token: &[u8; 32],
    lifetime: Duration,
) -> std::io::Result<()> {
    serve_inner(
        reader,
        writer,
        token,
        lifetime,
        None,
        None,
        &SystemdGuardCommandRunner,
    )
    .await
}

/// Serve a promotion only after preparing its transaction-bound persistent guard.
async fn serve_with_guard<R: GuardCommandRunner>(
    reader: impl AsyncRead + Unpin,
    writer: impl AsyncWrite + Unpin + Send + 'static,
    token: &[u8; 32],
    lifetime: Duration,
    config: &GuardConfig,
    own: &Path,
    runner: &R,
) -> io::Result<()> {
    serve_inner(
        reader,
        writer,
        token,
        lifetime,
        Some(config),
        Some(own),
        runner,
    )
    .await
}

/// Run the relay protocol with optional host guard configuration for tests.
async fn serve_inner<R: GuardCommandRunner>(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin + Send + 'static,
    token: &[u8; 32],
    lifetime: Duration,
    guard_config: Option<&GuardConfig>,
    own: Option<&Path>,
    runner: &R,
) -> io::Result<()> {
    let (out, mut outgoing) = mpsc::channel::<Frame>(64);
    let write = tokio::spawn(async move {
        let mut bytes = Vec::new();
        while let Some(frame) = outgoing.recv().await {
            bytes.clear();
            frame.encode(&mut bytes);
            writer.write_all(&bytes).await?;
            writer.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    });
    let mut channels: HashMap<u32, Channel> = HashMap::new();
    let mut rollback: Option<Zeroizing<String>> = None;
    let mut transaction = None;
    let mut guard: Option<GuardFiles> = None;
    let mut committed = false;
    let mut authenticated = false;
    let mut decoder = Decoder::default();
    let mut buffer = vec![0; 64 << 10];
    let deadline = tokio::time::sleep(lifetime);
    tokio::pin!(deadline);
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    let result = 'serve: loop {
        let read = tokio::select! {
            read = reader.read(&mut buffer) => match read {
                Ok(read) => read,
                Err(error) => break 'serve Err(error),
            },
            () = &mut deadline => break 'serve Ok(()),
        };
        if read == 0 {
            break Ok(());
        }
        decoder.push(&buffer[..read]);
        loop {
            let frame = match decoder.frame() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(_) => break 'serve Err(invalid()),
            };
            if !authenticated {
                // B5: the listener must prove it is the agent that typed the token.
                match frame {
                    Frame::Token { bytes } if constant_time_eq(&bytes, token) => {
                        authenticated = true;
                        let _ = out.send(Frame::Ready).await;
                        continue;
                    }
                    _ => break 'serve Err(std::io::ErrorKind::PermissionDenied.into()),
                }
            }
            match frame {
                Frame::Rollback {
                    transaction: bytes,
                    script,
                } if rollback.is_none() => {
                    let id = uuid::Uuid::from_bytes(bytes);
                    if let Some(config) = guard_config {
                        let own = own
                            .map_or_else(String::new, |path| path.to_string_lossy().into_owned());
                        match arm_guard_for_relay(config, id, &script, &own, runner).await {
                            Ok(files) => {
                                guard = Some(files);
                                transaction = Some(id);
                                rollback = Some(Zeroizing::new(script));
                                if out
                                    .send(Frame::Guard {
                                        transaction: bytes,
                                        state: infraternal_plugin_remote::privilege_relay::GuardState::Armed,
                                    })
                                    .await
                                    .is_err()
                                {
                                    break 'serve Err(std::io::ErrorKind::BrokenPipe.into());
                                }
                            }
                            Err(error) => {
                                let state = if error.to_string().contains("systemd system manager")
                                {
                                    infraternal_plugin_remote::privilege_relay::GuardState::SystemdUnavailable
                                } else {
                                    infraternal_plugin_remote::privilege_relay::GuardState::ArmFailed
                                };
                                let _ = out
                                    .send(Frame::Guard {
                                        transaction: bytes,
                                        state,
                                    })
                                    .await;
                                break 'serve Err(error);
                            }
                        }
                    } else {
                        transaction = Some(id);
                        rollback = Some(Zeroizing::new(script));
                    }
                }
                Frame::Open { channel, script } => {
                    channels.retain(|_, open| open.group.is_some_and(alive));
                    if rollback.is_none()
                        || channels.len() >= MAX_CHANNELS
                        || channels.contains_key(&channel)
                    {
                        let _ = out
                            .send(Frame::Exit {
                                channel,
                                code: None,
                            })
                            .await;
                        continue;
                    }
                    channels.insert(channel, open(channel, &script, out.clone()));
                }
                Frame::Stdin { channel, bytes } => {
                    // Never wait on a step's stdin here: a step that stops
                    // reading would stall Kill and Close for every step (B4).
                    // A full queue stops that step instead.
                    let stuck = channels.get(&channel).is_some_and(|open| {
                        let length = bytes.len();
                        let queued = open
                            .queued
                            .fetch_add(length, std::sync::atomic::Ordering::AcqRel);
                        queued + length > STDIN_CAP
                            || open
                                .stdin
                                .as_ref()
                                .is_some_and(|stdin| stdin.send(bytes).is_err())
                    });
                    if stuck
                        && let Some(group) = channels.remove(&channel).and_then(|open| open.group)
                    {
                        let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
                    }
                }
                Frame::StdinEnd { channel } => {
                    if let Some(open) = channels.get_mut(&channel) {
                        open.stdin = None;
                    }
                }
                Frame::Kill { channel } => {
                    if let Some(group) = channels.remove(&channel).and_then(|open| open.group) {
                        let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
                    }
                }
                Frame::Commit { transaction: bytes } => {
                    let id = uuid::Uuid::from_bytes(bytes);
                    if transaction != Some(id) {
                        break 'serve Err(invalid());
                    }
                    if let Some(config) = guard_config {
                        let Some(files) = guard.as_ref() else {
                            break 'serve Err(invalid());
                        };
                        if let Err(error) = write_commit_receipt(files, id) {
                            let _ = out
                                .send(Frame::Guard {
                                    transaction: bytes,
                                    state: infraternal_plugin_remote::privilege_relay::GuardState::DisarmFailed,
                                })
                                .await;
                            break 'serve Err(error);
                        }
                        committed = true;
                        match disarm_guard(config, files).await {
                            Ok(()) => {
                                if out
                                    .send(Frame::Guard {
                                        transaction: bytes,
                                        state: infraternal_plugin_remote::privilege_relay::GuardState::Committed,
                                    })
                                    .await
                                    .is_err()
                                {
                                    break 'serve Err(std::io::ErrorKind::BrokenPipe.into());
                                }
                            }
                            Err(error) => {
                                let _ = out
                                    .send(Frame::Guard {
                                        transaction: bytes,
                                        state: infraternal_plugin_remote::privilege_relay::GuardState::DisarmFailed,
                                    })
                                    .await;
                                break 'serve Err(error);
                            }
                        }
                    } else {
                        committed = true;
                    }
                }
                Frame::Close => break 'serve Ok(()),
                // A second token or rollback, or a frame only the relay
                // sends, is a protocol error.
                Frame::Token { .. }
                | Frame::Rollback { .. }
                | Frame::Guard { .. }
                | Frame::Stdout { .. }
                | Frame::Stderr { .. }
                | Frame::Exit { .. }
                | Frame::Ready => break 'serve Err(invalid()),
            }
        }
    };
    for open in channels.into_values() {
        if let Some(group) = open.group {
            let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
        }
    }
    let mut cleanup_error = None;
    if !committed && let Some(script) = rollback {
        run_rollback(&script).await;
        if let (Some(config), Some(files)) = (guard_config, guard.as_ref())
            && let Err(error) = disarm_guard(config, files).await
        {
            cleanup_error = Some(error);
        }
    }
    drop(out);
    let _ = tokio::time::timeout(Duration::from_secs(2), write).await;
    match cleanup_error {
        Some(error) => Err(error),
        None => result,
    }
}

/// The shared parent paths for each transaction's systemd rollback guard.
const GUARD_ROOT: &str = "/var/lib/infraternal-promotion";
/// The root install base where the active journal and committed transaction live.
const INSTALL_BASE: &str = "/var/lib/infraternal";
/// The install journal field that says which transaction is still reversible.
const ACTIVE_TRANSACTION: &str = ".bootstrap-lock/transaction";
/// The durable marker that identifies the root install a later abandon may remove.
const COMMITTED_TRANSACTION: &str = ".promotion-transaction";
/// The system manager's unit directory.
const SYSTEMD_UNIT_ROOT: &str = "/etc/systemd/system";

/// Paths used by the production guard and its filesystem tests.
struct GuardConfig {
    /// Parent directory for per-transaction undo scripts.
    guard_root: PathBuf,
    /// Directory that contains system manager unit files.
    unit_root: PathBuf,
    /// Root install base whose journal binds this guard's undo script.
    install_base: PathBuf,
    #[cfg(test)]
    /// Scratch parent removed after a guard lifecycle test.
    scratch_root: PathBuf,
}

impl GuardConfig {
    /// Use the fixed root-owned host paths for a real promotion.
    fn system() -> Self {
        Self {
            guard_root: PathBuf::from(GUARD_ROOT),
            unit_root: PathBuf::from(SYSTEMD_UNIT_ROOT),
            install_base: PathBuf::from(INSTALL_BASE),
            #[cfg(test)]
            scratch_root: PathBuf::new(),
        }
    }
}

#[cfg(test)]
impl Drop for GuardConfig {
    /// Remove this test's guard fixture without touching production paths.
    fn drop(&mut self) {
        if !self.scratch_root.as_os_str().is_empty() {
            let _ = std::fs::remove_dir_all(&self.scratch_root);
        }
    }
}

/// The persistent paths owned by one install transaction.
struct GuardFiles {
    /// Transaction-specific private directory containing both scripts.
    directory: PathBuf,
    /// The undo script path in the private directory.
    undo: PathBuf,
    /// The watcher script path in the private directory.
    watcher_script: PathBuf,
    /// Boot unit file for this transaction.
    unit: PathBuf,
    /// Independent watcher unit name for this transaction.
    watcher: String,
    /// Durable install marker checked by delayed cleanup.
    committed: PathBuf,
}

/// Run one named system manager operation for a transaction's guard files.
trait GuardCommandRunner {
    /// Run the operation and return only after the manager reports success.
    async fn run(&self, operation: &str, files: &GuardFiles) -> io::Result<()>;
}

/// Run a checked systemd command without resolving privileged binaries through `PATH`.
struct SystemdGuardCommandRunner;

impl GuardCommandRunner for SystemdGuardCommandRunner {
    /// Run one system manager operation and check its exit status.
    async fn run(&self, operation: &str, files: &GuardFiles) -> io::Result<()> {
        let systemctl = fixed_root_binary("systemctl")?;
        let unit_name = files
            .unit
            .file_name()
            .ok_or_else(|| io::Error::other("invalid promotion guard unit path"))?;
        let watcher = OsString::from(&files.watcher);
        let args = match operation {
            "show" => {
                let output = checked_output(
                    systemctl,
                    vec!["--system", "show", "--property=Version", "--value"]
                        .into_iter()
                        .map(OsString::from)
                        .collect(),
                    "systemd system manager",
                )
                .await?;
                if output.iter().all(u8::is_ascii_whitespace) {
                    return Err(io::Error::other(
                        "systemd system manager returned no version",
                    ));
                }
                return Ok(());
            }
            "daemon-reload" => vec!["--system", "daemon-reload"],
            "enable" => vec!["--system", "enable", "--no-reload"],
            "is-enabled" => vec!["--system", "is-enabled", "--quiet"],
            "is-active" => vec!["--system", "is-active", "--quiet"],
            "stop" => vec!["--system", "stop"],
            "disable" => vec!["--system", "disable"],
            "start" => {
                let systemd_run = fixed_root_binary("systemd-run")?;
                let watcher_path = files
                    .watcher_script
                    .to_str()
                    .ok_or_else(|| io::Error::other("invalid promotion watcher path"))?;
                return checked_status(
                    systemd_run,
                    vec![
                        OsString::from("--system"),
                        OsString::from("--quiet"),
                        OsString::from("--collect"),
                        OsString::from("--service-type=exec"),
                        OsString::from("--unit"),
                        watcher,
                        OsString::from("/bin/sh"),
                        OsString::from(watcher_path),
                    ],
                    operation,
                )
                .await;
            }
            _ => return Err(io::Error::from(io::ErrorKind::InvalidInput)),
        };
        let mut args: Vec<OsString> = args.into_iter().map(OsString::from).collect();
        match operation {
            "enable" | "is-enabled" | "disable" => args.push(unit_name.to_os_string()),
            "is-active" | "stop" => args.push(watcher),
            _ => {}
        }
        checked_status(systemctl, args, operation).await
    }
}

/// Resolve a small fixed set of root-owned systemd executables.
pub(crate) fn fixed_root_binary(name: &str) -> io::Result<PathBuf> {
    let candidates: &[&str] = match name {
        "systemctl" => &[
            "/usr/bin/systemctl",
            "/bin/systemctl",
            "/run/current-system/sw/bin/systemctl",
        ],
        "systemd-run" => &[
            "/usr/bin/systemd-run",
            "/bin/systemd-run",
            "/run/current-system/sw/bin/systemd-run",
        ],
        "rm" => &["/usr/bin/rm", "/bin/rm", "/run/current-system/sw/bin/rm"],
        "sleep" => &[
            "/usr/bin/sleep",
            "/bin/sleep",
            "/run/current-system/sw/bin/sleep",
        ],
        _ => return Err(io::Error::from(io::ErrorKind::InvalidInput)),
    };
    for candidate in candidates {
        let path = Path::new(candidate);
        let Ok(link_metadata) = std::fs::symlink_metadata(path) else {
            continue;
        };
        let Ok(target) = std::fs::canonicalize(path) else {
            continue;
        };
        let Ok(target_metadata) = std::fs::metadata(&target) else {
            continue;
        };
        if link_metadata.uid() == 0
            && target_metadata.is_file()
            && target_metadata.uid() == 0
            && target_metadata.mode() & 0o022 == 0
        {
            return Ok(path.to_path_buf());
        }
    }
    Err(io::Error::other(format!(
        "fixed root-owned {name} binary is unavailable"
    )))
}

/// Run one fixed command with a clean environment, cwd `/`, and a 30-second bound.
async fn checked_status(program: PathBuf, args: Vec<OsString>, operation: &str) -> io::Result<()> {
    let status = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "systemd {operation} failed with status {:?}",
            status.code()
        )))
    }
}

/// Run a fixed command and return its successful stdout, with the same bound as status checks.
async fn checked_output(
    program: PathBuf,
    args: Vec<OsString>,
    operation: &str,
) -> io::Result<Vec<u8>> {
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(io::Error::other(format!(
            "{operation} failed with status {:?}",
            output.status.code()
        )))
    }
}

/// Keep a shell argument literal even when its path contains a quote.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Build names for one install transaction; an old guard never shares new state.
fn guard_paths(config: &GuardConfig, transaction: uuid::Uuid, _pid: u32) -> GuardFiles {
    let suffix = transaction.simple().to_string();
    let unit_name = format!("infraternal-promotion-{suffix}.service");
    GuardFiles {
        directory: config.guard_root.join(&suffix),
        undo: config.guard_root.join(&suffix).join("undo"),
        watcher_script: config.guard_root.join(&suffix).join("watcher"),
        unit: config.unit_root.join(unit_name),
        watcher: format!("infraternal-promotion-watch-{suffix}.service"),
        committed: config.install_base.join(COMMITTED_TRANSACTION),
    }
}

/// Build a rollback script that runs only while its exact install journal is active.
fn transaction_undo_script(
    rollback: &str,
    own: &str,
    transaction: uuid::Uuid,
    files: &GuardFiles,
    install_base: &Path,
) -> io::Result<String> {
    let active = shell_quote(&install_base.join(ACTIVE_TRANSACTION).to_string_lossy());
    let committed = shell_quote(&install_base.join(COMMITTED_TRANSACTION).to_string_lossy());
    let unit = shell_quote(&files.unit.to_string_lossy());
    let wants = shell_quote(
        &files
            .unit
            .parent()
            .unwrap_or_else(|| Path::new(SYSTEMD_UNIT_ROOT))
            .join("multi-user.target.wants")
            .join(files.unit.file_name().unwrap_or_default())
            .to_string_lossy(),
    );
    let directory = shell_quote(&files.directory.to_string_lossy());
    let transaction = shell_quote(&transaction.simple().to_string());
    let rm = shell_quote(&fixed_root_binary("rm")?.to_string_lossy());
    let own = if own.starts_with("/run/infraternal-privilege.") {
        format!("{rm} -rf -- {}\n", shell_quote(own))
    } else {
        String::new()
    };
    Ok(format!(
        "#!/bin/sh\nset -eu\nactive={active}\ncommitted={committed}\ntransaction={transaction}\n# A matching commit receipt makes this transaction's guard permanently inert.\nif [ -f \"$committed\" ] && [ \"$(cat \"$committed\")\" = \"$transaction\" ]; then exit 0; fi\nif [ ! -f \"$active\" ]; then exit 0; fi\n[ \"$(cat \"$active\")\" = \"$transaction\" ] || exit 0\n( {rollback} )\n{own}{rm} -f -- {wants} {unit}\n{rm} -rf -- {directory}\n"
    ))
}

/// Render the boot unit for one transaction's private undo script.
fn guard_unit(files: &GuardFiles) -> String {
    format!(
        "[Unit]\nDescription=infraternal: undo interrupted root upgrade {}\nConditionPathExists={}\nAfter=local-fs.target\n\n[Service]\nType=oneshot\nExecStart=/bin/sh {}\n\n[Install]\nWantedBy=multi-user.target\n",
        files.watcher,
        files.undo.display(),
        files.undo.display()
    )
}

/// Render the independent watcher that runs this transaction's undo after relay loss.
fn watcher_script(files: &GuardFiles, pid: u32) -> io::Result<String> {
    let sleep = shell_quote(&fixed_root_binary("sleep")?.to_string_lossy());
    Ok(format!(
        "#!/bin/sh\nwhile kill -0 {pid} 2>/dev/null; do {sleep} 1; done\nexec /bin/sh {}\n",
        shell_quote(&files.undo.to_string_lossy())
    ))
}

/// Create or verify an owned directory without following a pre-existing symlink.
fn ensure_guard_directory(path: &Path, create: bool, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    if create {
        match std::fs::DirBuilder::new().mode(mode).create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    let metadata = std::fs::symlink_metadata(path)?;
    let permissions = metadata.mode() & 0o777;
    let permission_mismatch = if mode.trailing_zeros() >= 6 {
        permissions != mode
    } else {
        permissions & 0o700 != 0o700 || permissions & 0o022 != 0
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || permission_mismatch
    {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

/// Write one guard file through a private sibling, then fsync and rename it into place.
fn write_guard_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
        .to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Persist the exact install transaction before disarming its recovery guard.
fn write_commit_receipt(files: &GuardFiles, transaction: uuid::Uuid) -> io::Result<()> {
    let parent = files
        .committed
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    ensure_guard_directory(parent, false, 0o755)?;
    let receipt = format!("{}\n", transaction.simple());
    write_guard_file(&files.committed, receipt.as_bytes(), 0o600)
}

/// Exercise the checked guard lifecycle through a replaceable command runner.
#[cfg(test)]
async fn arm_guard_with<R: GuardCommandRunner>(
    config: &GuardConfig,
    transaction: uuid::Uuid,
    rollback: &str,
    runner: &R,
) -> io::Result<GuardFiles> {
    arm_guard_for_relay(config, transaction, rollback, "", runner).await
}

/// Shared implementation used by the relay and its command-failure tests.
async fn arm_guard_for_relay<R: GuardCommandRunner>(
    config: &GuardConfig,
    transaction: uuid::Uuid,
    rollback: &str,
    own: &str,
    runner: &R,
) -> io::Result<GuardFiles> {
    let files = guard_paths(config, transaction, std::process::id());
    runner.run("show", &files).await.map_err(|_| {
        io::Error::other("a working systemd system manager is required for root promotion")
    })?;
    let prepared = (|| {
        ensure_guard_directory(&config.guard_root, true, 0o700)?;
        ensure_guard_directory(&config.unit_root, false, 0o755)?;
        ensure_guard_directory(&files.directory, false, 0o700).or_else(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                ensure_guard_directory(&files.directory, true, 0o700)
            } else {
                Err(error)
            }
        })?;
        if std::fs::symlink_metadata(&files.unit).is_ok() {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        let undo =
            transaction_undo_script(rollback, own, transaction, &files, &config.install_base)?;
        let watcher = watcher_script(&files, std::process::id())?;
        write_guard_file(&files.undo, undo.as_bytes(), 0o600)?;
        write_guard_file(&files.watcher_script, watcher.as_bytes(), 0o700)?;
        write_guard_file(&files.unit, guard_unit(&files).as_bytes(), 0o644)?;
        Ok(())
    })();
    if let Err(error) = prepared {
        return Err(fail_guard_setup(config, &files, runner, error).await);
    }
    for operation in [
        "daemon-reload",
        "enable",
        "is-enabled",
        "start",
        "is-active",
    ] {
        if let Err(error) = runner.run(operation, &files).await {
            return Err(fail_guard_setup(
                config,
                &files,
                runner,
                io::Error::other(format!("promotion guard {operation} failed: {error}")),
            )
            .await);
        }
    }
    Ok(files)
}

/// Remove a partial guard after arming failed, retaining both failure reasons.
async fn fail_guard_setup<R: GuardCommandRunner>(
    config: &GuardConfig,
    files: &GuardFiles,
    runner: &R,
    original: io::Error,
) -> io::Error {
    match disarm_guard_with(config, files, runner).await {
        Ok(()) => original,
        Err(cleanup) => io::Error::other(format!(
            "{original}; partial promotion guard cleanup also failed: {cleanup}"
        )),
    }
}

/// Disarm every guard layer and report any stop, disable, removal or reload failure.
async fn disarm_guard(config: &GuardConfig, files: &GuardFiles) -> io::Result<()> {
    disarm_guard_with(config, files, &SystemdGuardCommandRunner).await
}

/// Exercise checked disarm through a replaceable command runner.
async fn disarm_guard_with<R: GuardCommandRunner>(
    _config: &GuardConfig,
    files: &GuardFiles,
    runner: &R,
) -> io::Result<()> {
    let mut failures = Vec::new();
    for operation in ["stop", "disable"] {
        if let Err(error) = runner.run(operation, files).await {
            failures.push(format!("{operation}: {error}"));
        }
    }
    let wants = files
        .unit
        .parent()
        .unwrap_or_else(|| Path::new(SYSTEMD_UNIT_ROOT))
        .join("multi-user.target.wants")
        .join(files.unit.file_name().unwrap_or_default());
    for path in [&wants, &files.unit] {
        if let Err(error) = remove_guard_path(path, false) {
            failures.push(format!("remove {}: {error}", path.display()));
        }
    }
    if let Err(error) = remove_guard_path(&files.directory, true) {
        failures.push(format!("remove {}: {error}", files.directory.display()));
    }
    if let Err(error) = runner.run("daemon-reload", files).await {
        failures.push(format!("daemon-reload: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(failures.join("; ")))
    }
}

/// Remove a guard path and verify that no file remains at that transaction's name.
fn remove_guard_path(path: &Path, directory: bool) -> io::Result<()> {
    let result = if directory {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    match result {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(io::Error::other(
            "promotion guard path remains after removal",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Equal without an early exit on the first differing byte.
fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Run the rollback script as the steps run, with no stdin or output, in
/// its own process group, killed after [`ROLLBACK_BOUND`].
async fn run_rollback(script: &str) {
    let spawned = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true)
        .spawn();
    let Ok(mut child) = spawned else {
        return;
    };
    let group = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .map(nix::unistd::Pid::from_raw);
    if tokio::time::timeout(ROLLBACK_BOUND, child.wait())
        .await
        .is_err()
        && let Some(group) = group
    {
        let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
    }
}

/// The process group `group` still has a leader.
fn alive(group: nix::unistd::Pid) -> bool {
    nix::sys::signal::kill(group, None).is_ok()
}

/// Start one script and the tasks that carry its stdin, stdout and exit.
fn open(channel: u32, script: &str, out: mpsc::Sender<Frame>) -> Channel {
    let spawned = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        // Root never works inside the account's directories (J465 P2-4).
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn();
    let Ok(mut child) = spawned else {
        tokio::spawn(async move {
            out.send(Frame::Exit {
                channel,
                code: None,
            })
            .await
        });
        return Channel {
            stdin: None,
            queued: std::sync::Arc::default(),
            group: None,
        };
    };
    let group = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .map(nix::unistd::Pid::from_raw);
    let (stdin, mut pending) = mpsc::unbounded_channel::<Vec<u8>>();
    let queued = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    if let Some(mut pipe) = child.stdin.take() {
        let written = queued.clone();
        tokio::spawn(async move {
            while let Some(bytes) = pending.recv().await {
                if pipe.write_all(&bytes).await.is_err() {
                    break;
                }
                written.fetch_sub(bytes.len(), std::sync::atomic::Ordering::AcqRel);
            }
            // Dropping the pipe closes the script's stdin.
        });
    }
    let mut stdout = child.stdout.take();
    let stderr = child.stderr.take().map(|mut pipe| {
        let out = out.clone();
        tokio::spawn(async move {
            // Forward the first MAX_STDERR bytes, then drain the rest unread
            // so the script never blocks on a full pipe.
            let mut chunk = vec![0; MAX_STDERR];
            let mut sent = 0;
            loop {
                match pipe.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        let keep = read.min(MAX_STDERR - sent);
                        if keep > 0 {
                            sent += keep;
                            let _ = out
                                .send(Frame::Stderr {
                                    channel,
                                    bytes: chunk[..keep].to_vec(),
                                })
                                .await;
                        }
                    }
                }
            }
        })
    });
    tokio::spawn(async move {
        if let Some(pipe) = stdout.as_mut() {
            let mut chunk = vec![0; MAX_CHUNK];
            loop {
                match pipe.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if out
                            .send(Frame::Stdout {
                                channel,
                                bytes: chunk[..read].to_vec(),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        }
        if let Some(stderr) = stderr {
            // Stderr is complete before the exit is reported.
            let _ = stderr.await;
        }
        let code = child
            .wait()
            .await
            .ok()
            .and_then(|status| status.code())
            .and_then(|code| u8::try_from(code).ok());
        let _ = out.send(Frame::Exit { channel, code }).await;
    });
    Channel {
        stdin: Some(stdin),
        queued,
        group,
    }
}

#[cfg(test)]
mod tests {
    //! The relay runs scripts with their stdin and reports stdout and exit codes.
    use super::*;

    /// A command runner that records guard operations and can refuse selected ones.
    #[derive(Clone)]
    struct TestGuardCommands {
        calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        failures: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    }

    impl TestGuardCommands {
        /// Build a runner that fails the named operation.
        fn failing(operation: &str) -> Self {
            Self {
                calls: std::sync::Arc::default(),
                failures: std::sync::Arc::new(std::sync::Mutex::new(
                    [operation.to_owned()].into_iter().collect(),
                )),
            }
        }

        /// Build a runner that accepts every operation.
        fn successful() -> Self {
            Self {
                calls: std::sync::Arc::default(),
                failures: std::sync::Arc::default(),
            }
        }

        /// Build a runner that fails the selected occurrence of one operation.
        fn failing_nth(operation: &str, occurrence: usize) -> Self {
            let runner = Self::successful();
            runner
                .failures
                .lock()
                .unwrap()
                .insert(format!("{operation}#{occurrence}"));
            runner
        }

        /// Make later calls to `operation` fail.
        fn fail_on(&self, operation: &str) {
            self.failures.lock().unwrap().insert(operation.to_owned());
        }

        /// Whether the runner was asked to perform `operation`.
        fn called(&self, operation: &str) -> bool {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .any(|called| called == operation)
        }
    }

    impl GuardCommandRunner for TestGuardCommands {
        async fn run(&self, operation: &str, _files: &GuardFiles) -> io::Result<()> {
            tokio::task::yield_now().await;
            let occurrence = {
                let mut calls = self.calls.lock().unwrap();
                calls.push(operation.to_owned());
                calls
                    .iter()
                    .filter(|called| called.as_str() == operation)
                    .count()
            };
            let failures = self.failures.lock().unwrap();
            if failures.contains(operation)
                || failures.contains(&format!("{operation}#{occurrence}"))
            {
                Err(io::Error::other("injected system manager failure"))
            } else {
                Ok(())
            }
        }
    }

    /// Keep temporary guard files alive for one test and remove them afterward.
    fn test_guard_config() -> GuardConfig {
        let scratch_root = std::env::temp_dir().join(format!(
            "infraternal-guard-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&scratch_root).unwrap();
        let config = GuardConfig {
            guard_root: scratch_root.join("promotion"),
            unit_root: scratch_root.join("systemd"),
            install_base: scratch_root.join("install"),
            scratch_root,
        };
        std::fs::create_dir_all(&config.unit_root).unwrap();
        std::fs::create_dir_all(&config.install_base).unwrap();
        config
    }

    /// Drive `serve` over an in-memory pipe: send `frames`, collect everything
    /// it answers until it ends.
    async fn exchange(frames: Vec<Frame>) -> Vec<Frame> {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (server_read, server_write) = tokio::io::split(server);
        let relay =
            tokio::spawn(async move { serve(server_read, server_write, &TOKEN, LIFETIME).await });
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let mut bytes = Vec::new();
        Frame::Token { bytes: TOKEN }.encode(&mut bytes);
        Frame::Rollback {
            transaction: [0; 16],
            script: "true".into(),
        }
        .encode(&mut bytes);
        for frame in &frames {
            frame.encode(&mut bytes);
        }
        let mut decoder = Decoder::default();
        let mut seen = Vec::new();
        client_write.write_all(&bytes).await.unwrap();
        let mut buffer = vec![0; 1 << 16];
        let expected_exits = frames
            .iter()
            .filter(|frame| matches!(frame, Frame::Open { .. }))
            .count();
        while seen
            .iter()
            .filter(|frame| matches!(frame, Frame::Exit { .. }))
            .count()
            < expected_exits
        {
            let read = client_read.read(&mut buffer).await.unwrap();
            assert!(read > 0, "relay ended early: {seen:?}");
            decoder.push(&buffer[..read]);
            while let Some(frame) = decoder.frame().unwrap() {
                seen.push(frame);
            }
        }
        let mut close = Vec::new();
        Frame::Close.encode(&mut close);
        client_write.write_all(&close).await.unwrap();
        relay.await.unwrap().unwrap();
        seen
    }

    /// Joined stdout of `channel`.
    fn stdout(frames: &[Frame], channel: u32) -> Vec<u8> {
        frames
            .iter()
            .filter_map(|frame| match frame {
                Frame::Stdout { channel: c, bytes } if *c == channel => Some(bytes.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// Ready comes first; a script reads its stdin and its exit code comes back.
    #[tokio::test]
    async fn a_script_gets_its_stdin_and_reports_output_and_exit() {
        let seen = exchange(vec![
            Frame::Open {
                channel: 1,
                script: "read line; printf 'got %s' \"$line\"; exit 7".into(),
            },
            Frame::Stdin {
                channel: 1,
                bytes: b"hello\n".to_vec(),
            },
            Frame::StdinEnd { channel: 1 },
        ])
        .await;
        assert_eq!(seen[0], Frame::Ready);
        assert_eq!(stdout(&seen, 1), b"got hello");
        assert!(
            seen.contains(&Frame::Exit {
                channel: 1,
                code: Some(7)
            }),
            "{seen:?}"
        );
    }

    /// The environment is empty apart from PATH, HOME and the C locale, and
    /// stderr comes back on its own frames, bounded.
    #[tokio::test]
    async fn scripts_run_with_a_clean_environment_and_no_stderr() {
        let seen = exchange(vec![
            Frame::Open {
                channel: 2,
                script: "env | sort | tr '\\n' ' '; echo refused >&2; head -c 20000 /dev/zero >&2"
                    .into(),
            },
            Frame::StdinEnd { channel: 2 },
        ])
        .await;
        let text = String::from_utf8(stdout(&seen, 2)).unwrap();
        let names: Vec<&str> = text
            .split_whitespace()
            .map(|pair| pair.split('=').next().unwrap())
            .collect();
        assert!(
            names
                .iter()
                .all(|name| ["HOME", "LANG", "LC_ALL", "PATH", "PWD", "SHLVL", "_"].contains(name)),
            "{text}"
        );
        assert!(!text.contains("refused"));
        let errors: Vec<u8> = seen
            .iter()
            .filter_map(|frame| match frame {
                Frame::Stderr { bytes, .. } => Some(bytes.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert!(errors.starts_with(b"refused\n"));
        assert_eq!(errors.len(), MAX_STDERR);
    }

    /// Two scripts run side by side on separate channels.
    #[tokio::test]
    async fn channels_are_independent() {
        let seen = exchange(vec![
            Frame::Open {
                channel: 1,
                script: "cat".into(),
            },
            Frame::Open {
                channel: 2,
                script: "printf two".into(),
            },
            Frame::StdinEnd { channel: 2 },
            Frame::Stdin {
                channel: 1,
                bytes: b"one".to_vec(),
            },
            Frame::StdinEnd { channel: 1 },
        ])
        .await;
        assert_eq!(stdout(&seen, 1), b"one");
        assert_eq!(stdout(&seen, 2), b"two");
    }

    /// The token the tests' "agent" typed.
    const TOKEN: [u8; 32] = [5; 32];

    /// Send `frames` to a relay with `token`, then end the input (or not,
    /// with `hold`), and return how `serve` ended. `lifetime` bounds it.
    /// The frames are written while the relay runs, so a large input can't
    /// deadlock on the pipe's buffer.
    async fn run(
        frames: Vec<Frame>,
        token: [u8; 32],
        lifetime: Duration,
        hold: bool,
    ) -> std::io::Result<()> {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (server_read, server_write) = tokio::io::split(server);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        // Drain the relay's answers so it never blocks on a full pipe.
        tokio::spawn(async move {
            let mut sink = vec![0; 1 << 16];
            while client_read.read(&mut sink).await.is_ok_and(|read| read > 0) {}
        });
        let writer = tokio::spawn(async move {
            let mut bytes = Vec::new();
            for frame in &frames {
                frame.encode(&mut bytes);
            }
            // The relay may stop reading early (a refused token); that's fine.
            let _ = client_write.write_all(&bytes).await;
            if hold {
                // Keep the input open: the relay must end by itself.
                std::future::pending::<()>().await;
            }
            // End of input: the link is gone.
            let _ = client_write.shutdown().await;
        });
        let result = serve(server_read, server_write, &token, lifetime).await;
        writer.abort();
        result
    }

    /// A scratch directory, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        /// A fresh one under the system temp directory.
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("relay-test-{}", uuid::Uuid::new_v4().simple()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        /// Its path.
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A fresh scratch directory, and the rollback script that marks it.
    fn marker() -> (Scratch, String) {
        let dir = Scratch::new();
        let script = format!("touch '{}/rolled-back'", dir.path().display());
        (dir, script)
    }

    /// A frame only the relay may send ends the relay with an error.
    #[tokio::test]
    async fn a_relay_only_frame_from_the_server_is_refused() {
        let frames = vec![
            Frame::Token { bytes: TOKEN },
            Frame::Exit {
                channel: 1,
                code: Some(0),
            },
        ];
        assert!(run(frames, TOKEN, LIFETIME, false).await.is_err());
    }

    /// B5: without the typed token first, nothing runs and no rollback is
    /// even accepted.
    #[tokio::test]
    async fn a_socket_without_the_token_runs_nothing() {
        let (dir, script) = marker();
        let ran = dir.path().join("ran");
        let frames = vec![
            Frame::Token { bytes: [6; 32] },
            Frame::Rollback {
                transaction: [0; 16],
                script,
            },
            Frame::Open {
                channel: 1,
                script: format!("touch '{}'", ran.display()),
            },
        ];
        assert!(run(frames, TOKEN, LIFETIME, false).await.is_err());
        assert!(!ran.exists());
        assert!(!dir.path().join("rolled-back").exists());
    }

    /// R4 / B1: losing the link (end of input) without a commit runs the
    /// rollback, after the running steps were stopped.
    #[tokio::test]
    async fn a_lost_link_rolls_the_host_back() {
        let (dir, script) = marker();
        let frames = vec![
            Frame::Token { bytes: TOKEN },
            Frame::Rollback {
                transaction: [0; 16],
                script,
            },
            Frame::Open {
                channel: 1,
                script: "sleep 600".into(),
            },
        ];
        run(frames, TOKEN, LIFETIME, false).await.unwrap();
        assert!(dir.path().join("rolled-back").exists());
    }

    /// R4: a Close without a commit rolls back too; after Commit it doesn't.
    #[tokio::test]
    async fn only_a_commit_skips_the_rollback() {
        let (dir, script) = marker();
        let frames = vec![
            Frame::Token { bytes: TOKEN },
            Frame::Rollback {
                transaction: [0; 16],
                script: script.clone(),
            },
            Frame::Close,
        ];
        run(frames, TOKEN, LIFETIME, true).await.unwrap();
        assert!(dir.path().join("rolled-back").exists());
        let (dir, script) = marker();
        let frames = vec![
            Frame::Token { bytes: TOKEN },
            Frame::Rollback {
                transaction: [0; 16],
                script,
            },
            Frame::Commit {
                transaction: [0; 16],
            },
            Frame::Close,
        ];
        run(frames, TOKEN, LIFETIME, true).await.unwrap();
        assert!(!dir.path().join("rolled-back").exists());
    }

    /// R4: the lifetime ends a relay whose server went silent, and rolls back.
    #[tokio::test]
    async fn the_lifetime_rolls_back_a_silent_upgrade() {
        let (dir, script) = marker();
        let frames = vec![
            Frame::Token { bytes: TOKEN },
            Frame::Rollback {
                transaction: [0; 16],
                script,
            },
        ];
        run(frames, TOKEN, Duration::from_millis(300), true)
            .await
            .unwrap();
        assert!(dir.path().join("rolled-back").exists());
    }

    /// J465 P2-4: root never works inside the account's directories: every
    /// step and the rollback run with `/` as their working directory, not
    /// the cwd sudo or su inherited from the account.
    #[tokio::test]
    async fn steps_and_the_rollback_run_from_the_root_directory() {
        let dir = Scratch::new();
        let marker = dir.path().join("rollback-cwd");
        let seen = exchange(vec![
            Frame::Open {
                channel: 1,
                script: "pwd".into(),
            },
            Frame::StdinEnd { channel: 1 },
        ])
        .await;
        assert_eq!(stdout(&seen, 1), b"/\n");
        let frames = vec![
            Frame::Token { bytes: TOKEN },
            Frame::Rollback {
                transaction: [0; 16],
                script: format!("pwd > '{}'", marker.display()),
            },
        ];
        run(frames, TOKEN, LIFETIME, false).await.unwrap();
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "/\n");
    }

    /// R4: a step is refused until the rollback script is known.
    #[tokio::test]
    async fn no_step_runs_before_the_rollback_is_known() {
        let dir = Scratch::new();
        let ran = dir.path().join("ran");
        let frames = vec![
            Frame::Token { bytes: TOKEN },
            Frame::Open {
                channel: 1,
                script: format!("touch '{}'", ran.display()),
            },
        ];
        run(frames, TOKEN, LIFETIME, false).await.unwrap();
        assert!(!ran.exists());
    }

    /// B4: a step that never reads its stdin doesn't stall the frame loop
    /// (its input is queued, up to a cap); a later Close is still served
    /// and rolls back.
    #[tokio::test]
    async fn a_step_that_stops_reading_does_not_stall_close() {
        let (dir, script) = marker();
        let mut frames = vec![
            Frame::Token { bytes: TOKEN },
            Frame::Rollback {
                transaction: [0; 16],
                script,
            },
            Frame::Open {
                channel: 1,
                script: "sleep 600".into(),
            },
        ];
        for _ in 0..64 {
            frames.push(Frame::Stdin {
                channel: 1,
                bytes: vec![0; MAX_CHUNK],
            });
        }
        frames.push(Frame::Close);
        tokio::time::timeout(Duration::from_secs(20), run(frames, TOKEN, LIFETIME, true))
            .await
            .expect("Close was served")
            .unwrap();
        assert!(dir.path().join("rolled-back").exists());
    }

    /// Each relay transaction owns an independent persistent guard and watcher name.
    #[test]
    fn promotion_guards_have_transaction_scoped_paths() {
        let config = test_guard_config();
        let first = guard_paths(&config, uuid::Uuid::from_u128(0xa), 100);
        let second = guard_paths(&config, uuid::Uuid::from_u128(0xb), 100);
        assert_ne!(first.directory, second.directory);
        assert_ne!(first.unit, second.unit);
        assert_ne!(first.watcher, second.watcher);
    }

    /// Arming refuses promotion when it cannot prove the independent watcher is active.
    #[tokio::test]
    async fn promotion_guard_refuses_when_watcher_is_not_active() {
        let config = test_guard_config();
        let runner = TestGuardCommands::failing("is-active");
        let result = arm_guard_with(
            &config,
            uuid::Uuid::from_u128(0xa),
            "touch /tmp/should-not-run",
            &runner,
        )
        .await;
        assert!(result.is_err());
        assert!(runner.called("is-active"));
    }

    /// Arming stops before starting services when the undo script cannot be written safely.
    #[tokio::test]
    async fn promotion_guard_refuses_when_undo_script_cannot_be_written() {
        let config = test_guard_config();
        std::fs::create_dir_all(config.guard_root.parent().unwrap()).unwrap();
        std::fs::write(&config.guard_root, b"not a directory").unwrap();
        let runner = TestGuardCommands::successful();

        assert!(
            arm_guard_with(&config, uuid::Uuid::from_u128(0xa), "true", &runner,)
                .await
                .is_err()
        );
        assert!(!runner.called("enable"));
        assert!(!runner.called("start"));
    }

    /// Arming refuses when systemd does not confirm that the boot guard is enabled.
    #[tokio::test]
    async fn promotion_guard_refuses_when_boot_unit_is_not_enabled() {
        let config = test_guard_config();
        let runner = TestGuardCommands::failing("is-enabled");

        assert!(
            arm_guard_with(&config, uuid::Uuid::from_u128(0xa), "true", &runner,)
                .await
                .is_err()
        );
        assert!(runner.called("is-enabled"));
        assert!(!runner.called("start"));
    }

    /// Arming refuses when systemd cannot reload the newly written boot unit.
    #[tokio::test]
    async fn promotion_guard_refuses_when_boot_unit_reload_fails() {
        let config = test_guard_config();
        let runner = TestGuardCommands::failing("daemon-reload");

        assert!(
            arm_guard_with(&config, uuid::Uuid::from_u128(0xa), "true", &runner,)
                .await
                .is_err()
        );
        assert!(runner.called("daemon-reload"));
        assert!(!runner.called("start"));
    }

    /// A host without a running system manager gets a clear refusal before guard files are written.
    #[tokio::test]
    async fn promotion_guard_refuses_a_missing_systemd_manager() {
        let config = test_guard_config();
        let runner = TestGuardCommands::failing("show");
        let result = arm_guard_with(&config, uuid::Uuid::from_u128(0xa), "true", &runner).await;
        assert!(
            result
                .as_ref()
                .err()
                .is_some_and(|error| error.to_string().contains("systemd system manager"))
        );
        assert!(!config.guard_root.exists());
    }

    /// A relay must report guard failure and reject install steps when the manager is missing.
    #[tokio::test]
    async fn relay_refuses_install_steps_when_guard_cannot_be_armed() {
        let config = test_guard_config();
        let transaction = uuid::Uuid::from_u128(0xa);
        let marker = std::env::temp_dir().join(format!(
            "infraternal-install-step-ran-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let runner = TestGuardCommands::failing("show");
        let responses = guarded_exchange(
            config,
            runner.clone(),
            transaction,
            &format!("touch '{}'", marker.display()),
        )
        .await;

        let guard_refusal = responses.iter().any(|frame| matches!(
            frame,
            Frame::Guard {
                transaction: seen,
                state: infraternal_plugin_remote::privilege_relay::GuardState::SystemdUnavailable,
            } if *seen == transaction.into_bytes()
        ));
        let step_ran = marker.exists();
        let step_reported_exit = responses
            .iter()
            .any(|frame| matches!(frame, Frame::Exit { channel: 1, .. }));
        let system_manager_checked = runner.called("show");
        let _ = std::fs::remove_file(&marker);
        assert!(
            guard_refusal && !step_ran && !step_reported_exit && system_manager_checked,
            "guard_refusal={guard_refusal}, step_ran={step_ran}, step_reported_exit={step_reported_exit}, system_manager_checked={system_manager_checked}"
        );
    }

    /// Send one install step behind rollback and collect the relay's response frames.
    async fn guarded_exchange(
        config: GuardConfig,
        runner: TestGuardCommands,
        transaction: uuid::Uuid,
        script: &str,
    ) -> Vec<Frame> {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (server_read, server_write) = tokio::io::split(server);
        let task = tokio::spawn(async move {
            serve_with_guard(
                server_read,
                server_write,
                &TOKEN,
                LIFETIME,
                &config,
                Path::new("/run/infraternal-privilege.test"),
                &runner,
            )
            .await
        });
        let (mut reader, mut writer) = tokio::io::split(client);
        let mut requests = Vec::new();
        Frame::Token { bytes: TOKEN }.encode(&mut requests);
        Frame::Rollback {
            transaction: transaction.into_bytes(),
            script: "true".into(),
        }
        .encode(&mut requests);
        Frame::Open {
            channel: 1,
            script: script.to_owned(),
        }
        .encode(&mut requests);
        writer.write_all(&requests).await.unwrap();
        writer.flush().await.unwrap();

        let mut decoder = Decoder::default();
        let mut buffer = [0u8; 4096];
        let mut responses = Vec::new();
        let mut step_exited = false;
        let mut close_sent = false;
        loop {
            let count = reader.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            decoder.push(&buffer[..count]);
            while let Some(frame) = decoder.frame().unwrap() {
                step_exited |= matches!(frame, Frame::Exit { channel: 1, .. });
                responses.push(frame);
            }
            if step_exited && !close_sent {
                let mut close = Vec::new();
                Frame::Close.encode(&mut close);
                writer.write_all(&close).await.unwrap();
                writer.flush().await.unwrap();
                close_sent = true;
            }
        }
        let _ = task.await.unwrap();
        responses
    }

    /// Commit through the guarded relay and collect its transaction receipt.
    async fn guarded_commit_exchange(
        config: GuardConfig,
        runner: TestGuardCommands,
        transaction: uuid::Uuid,
    ) -> Vec<Frame> {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (server_read, server_write) = tokio::io::split(server);
        let task = tokio::spawn(async move {
            serve_with_guard(
                server_read,
                server_write,
                &TOKEN,
                LIFETIME,
                &config,
                Path::new("/run/infraternal-privilege.test"),
                &runner,
            )
            .await
        });
        let (mut reader, mut writer) = tokio::io::split(client);
        let mut requests = Vec::new();
        Frame::Token { bytes: TOKEN }.encode(&mut requests);
        Frame::Rollback {
            transaction: transaction.into_bytes(),
            script: "true".into(),
        }
        .encode(&mut requests);
        Frame::Commit {
            transaction: transaction.into_bytes(),
        }
        .encode(&mut requests);
        writer.write_all(&requests).await.unwrap();
        writer.shutdown().await.unwrap();

        let mut decoder = Decoder::default();
        let mut buffer = [0u8; 4096];
        let mut responses = Vec::new();
        loop {
            let count = reader.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            decoder.push(&buffer[..count]);
            while let Some(frame) = decoder.frame().unwrap() {
                responses.push(frame);
            }
        }
        let _ = task.await.unwrap();
        responses
    }

    /// Disarm reports a manager reload failure instead of hiding an incomplete cleanup.
    #[tokio::test]
    async fn promotion_guard_disarm_reports_reload_failure() {
        let config = test_guard_config();
        let transaction = uuid::Uuid::from_u128(0xa);
        let runner = TestGuardCommands::successful();
        let files = arm_guard_with(&config, transaction, "true", &runner)
            .await
            .unwrap();
        runner.fail_on("daemon-reload");

        assert!(disarm_guard_with(&config, &files, &runner).await.is_err());
    }

    /// The relay reports a disarm failure instead of acknowledging an incomplete commit.
    #[tokio::test]
    async fn relay_reports_guard_disarm_failure_after_commit() {
        let config = test_guard_config();
        let transaction = uuid::Uuid::from_u128(0xa);
        let runner = TestGuardCommands::failing_nth("daemon-reload", 2);
        let responses = guarded_commit_exchange(config, runner, transaction).await;

        assert!(responses.iter().any(|frame| matches!(
            frame,
            Frame::Guard {
                transaction: seen,
                state: infraternal_plugin_remote::privilege_relay::GuardState::DisarmFailed,
            } if *seen == transaction.into_bytes()
        )));
    }

    /// Disarm reports a filesystem removal failure even after the manager accepted the disable.
    #[tokio::test]
    async fn promotion_guard_disarm_reports_removal_failure() {
        let config = test_guard_config();
        let transaction = uuid::Uuid::from_u128(0xa);
        let runner = TestGuardCommands::successful();
        let files = arm_guard_with(&config, transaction, "true", &runner)
            .await
            .unwrap();
        std::fs::remove_dir_all(&files.directory).unwrap();
        std::fs::write(&files.directory, b"unexpected file").unwrap();

        assert!(disarm_guard_with(&config, &files, &runner).await.is_err());
    }

    /// A committed or superseded install makes an old guard inert before rollback runs.
    #[test]
    fn leftover_promotion_guard_cannot_change_a_committed_or_later_install() {
        use std::process::Stdio;

        let config = test_guard_config();
        let transaction_a = uuid::Uuid::from_u128(0xa);
        let transaction_b = uuid::Uuid::from_u128(0xb);
        let files = guard_paths(&config, transaction_a, 100);
        std::fs::create_dir_all(&config.install_base).unwrap();
        std::fs::create_dir_all(&files.directory).unwrap();
        let active = config.install_base.join(ACTIVE_TRANSACTION);
        std::fs::create_dir_all(active.parent().unwrap()).unwrap();
        std::fs::write(&active, format!("{}\n", transaction_a.simple())).unwrap();
        std::fs::write(
            config.install_base.join(COMMITTED_TRANSACTION),
            format!("{}\n", transaction_a.simple()),
        )
        .unwrap();
        let committed_rollback = config.install_base.join("committed-rollback");
        let script = transaction_undo_script(
            &format!("touch '{}'", committed_rollback.display()),
            "",
            transaction_a,
            &files,
            &config.install_base,
        )
        .unwrap();
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        assert!(!committed_rollback.exists());

        std::fs::write(&active, format!("{}\n", transaction_b.simple())).unwrap();
        std::fs::write(
            config.install_base.join(COMMITTED_TRANSACTION),
            format!("{}\n", transaction_b.simple()),
        )
        .unwrap();
        let rolled_back = config.install_base.join("rolled-back");
        let script = transaction_undo_script(
            &format!("touch '{}'", rolled_back.display()),
            "",
            transaction_a,
            &files,
            &config.install_base,
        )
        .unwrap();
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        assert!(!rolled_back.exists());

        std::fs::remove_file(&active).unwrap();
        std::fs::write(&files.committed, format!("{}\n", transaction_a.simple())).unwrap();
        let script = transaction_undo_script(
            &format!("touch '{}'", rolled_back.display()),
            "",
            transaction_a,
            &files,
            &config.install_base,
        )
        .unwrap();
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        assert!(!rolled_back.exists());
    }

    /// A standard root-owned unit directory may be traversable without being writable by others.
    #[tokio::test]
    async fn promotion_guard_accepts_a_root_owned_systemd_unit_directory() {
        use std::os::unix::fs::PermissionsExt;

        let config = test_guard_config();
        std::fs::set_permissions(&config.unit_root, std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let runner = TestGuardCommands::successful();
        assert!(
            arm_guard_with(&config, uuid::Uuid::from_u128(0xc), "true", &runner)
                .await
                .is_ok()
        );
    }
}
