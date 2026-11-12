//! Runs the root install steps of a root upgrade through the host's relay instead of SSH (D376, #399).
//!
//! An Add host runs its install steps (journal, ACTIVATE, START, commit,
//! rollback, `previous_attempt.sh` recovery) through [`SshSession`]. A root
//! upgrade runs the *same* steps as root on a host that has no SSH credential
//! here. The person's password started a short-lived root relay on the host,
//! and the rootless infraternal agent pipes its bytes to the server.
//! [`RelaySession`] is the [`SshSession`] over that pipe, so the unchanged
//! root [`crate::install::Installation`] drives the upgrade and its rollback.
//!
//! How one step runs: each [`SshSession::run`] starts a small local helper,
//! `infraternal __privilege-channel <socket> <channel>`. The helper plays the
//! part `ssh` plays for the OpenSSH adapter. It connects to this session's
//! private socket and bridges its own stdin, stdout, stderr and exit code to
//! one relay channel. The step then goes through the same
//! [`crate::process::execute`] as an SSH command, so every input mode
//! (payload transfer, negotiated upload, the commit's signal) behaves exactly
//! as over SSH. The exit-code and stderr mapping is the OpenSSH adapter's
//! own.
//!
//! The [`Pump`] carries bytes to and from the relay, through the rootless
//! infraternal agent's `privilege.pump` action. When the relay is gone, every
//! open step ends with exit 255, as when an SSH connection drops.
//!
//! The first thing this session sends is the install's rollback script
//! ([`Frame::Rollback`]); the relay keeps it and runs it itself if the
//! upgrade ends without [`RelaySession::commit`] (J415 R4). So a link lost
//! mid-install, here or on the host, puts the host back as it was even
//! though the server can't reach it any more (B1).
use crate::{
    model::Failure,
    process::execute,
    transport::{CommandOutput, Input, Operation, SshSession},
};
use infraternal_plugin_remote::privilege_relay::{
    Decoder, Frame, GuardState, MAX_CHUNK, MAX_STDERR,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::mpsc,
};

/// The hidden command word of the per-step helper.
pub const CHANNEL_COMMAND: &str = "__privilege-channel";
/// Exit code of a step whose relay went away (the SSH client's own code).
const LOST: u8 = 255;
/// Bound how long a promotion waits for the host to verify a guard operation.
const GUARD_ACK_BOUND: Duration = Duration::from_secs(180);

/// Moves relay bytes between the server and the host.
pub trait Pump: Send + Sync {
    /// Send `bytes` to the relay and return what it said since, plus whether
    /// it has closed. Waits briefly (about a second) when there is nothing.
    fn pump(&self, bytes: Vec<u8>) -> Operation<'_, (Vec<u8>, bool)>;
}

/// The [`SshSession`] of one root upgrade. See the module docs.
pub struct RelaySession {
    hub: Arc<Hub>,
    exe: PathBuf,
    timeout: Duration,
}

/// Shared state between the steps, the helper listener and the pump loop.
struct Hub {
    socket: PathBuf,
    next: AtomicU32,
    /// Scripts waiting for their helper to connect, by channel.
    pending: Mutex<HashMap<u32, String>>,
    /// Where to deliver relay frames for each connected channel.
    routes: Mutex<HashMap<u32, mpsc::UnboundedSender<Frame>>>,
    /// Frames for the relay.
    outgoing: mpsc::UnboundedSender<Frame>,
    /// Guard-arm replies keyed by the exact install transaction.
    arm_waiters: Mutex<HashMap<[u8; 16], tokio::sync::oneshot::Sender<GuardState>>>,
    /// Guard-commit replies keyed by the exact install transaction.
    commit_waiters: Mutex<HashMap<[u8; 16], tokio::sync::oneshot::Sender<GuardState>>>,
    /// Steps remain closed until the matching transaction reports `Armed`.
    guard_armed: AtomicBool,
    lost: AtomicBool,
}

impl RelaySession {
    /// Start the session: wait for the relay's `Ready`, then serve steps.
    ///
    /// `directory` must be a private (0700) directory of this server for the
    /// helper socket; `exe` is this server's own binary, which carries the
    /// helper. Returns when the relay has said `Ready`.
    ///
    /// Call [`Self::arm_rollback`] before the first step: the relay runs no
    /// step until it knows how to put the host back.
    ///
    /// # Errors
    /// The relay did not say `Ready` within `ready`, or the socket failed.
    pub async fn start(
        pump: Arc<dyn Pump>,
        directory: &Path,
        exe: PathBuf,
        timeout: Duration,
        ready: Duration,
    ) -> Result<Self, Failure> {
        let socket = directory.join("relay-channels.sock");
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket)
            .map_err(|_| Failure::install("The upgrade's local channel could not start."))?;
        let (outgoing, queued) = mpsc::unbounded_channel();
        let hub = Arc::new(Hub {
            socket,
            next: AtomicU32::new(1),
            pending: Mutex::new(HashMap::new()),
            routes: Mutex::new(HashMap::new()),
            outgoing,
            arm_waiters: Mutex::new(HashMap::new()),
            commit_waiters: Mutex::new(HashMap::new()),
            guard_armed: AtomicBool::new(false),
            lost: AtomicBool::new(false),
        });
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(pump_loop(hub.clone(), pump, queued, ready_tx));
        tokio::spawn(accept_loop(hub.clone(), listener));
        match tokio::time::timeout(ready, ready_rx).await {
            Ok(Ok(())) => Ok(Self { hub, exe, timeout }),
            _ => Err(Failure::install("The host's upgrade helper did not start.")),
        }
    }

    /// End the session: ask the relay to stop everything and exit. Without
    /// an earlier [`Self::commit`] the relay rolls the host back first.
    pub fn close(&self) {
        let _ = self.hub.outgoing.send(Frame::Close);
    }

    /// Close the session and wait up to `bound` for the close to reach the
    /// relay (its pump loop ends right after sending it). True when it did.
    pub async fn finish(&self, bound: Duration) -> bool {
        self.close();
        let deadline = tokio::time::Instant::now() + bound;
        while !self.lost() {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            // sleep: the pump loop marks the end with a flag; poll it briefly.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        true
    }

    /// Hand the relay the install's rollback script and wait for its matching
    /// transaction guard to be verified before allowing any step to run.
    ///
    /// # Errors
    /// Returns an install failure if the relay stops or cannot verify the guard.
    pub async fn arm_rollback(
        &self,
        transaction: uuid::Uuid,
        script: String,
    ) -> Result<(), Failure> {
        if self.lost() {
            return Err(Failure::install("The host's upgrade helper has stopped."));
        }
        let bytes = transaction.into_bytes();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        {
            let mut waiters = lock(&self.hub.arm_waiters);
            if waiters.contains_key(&bytes) {
                return Err(Failure::install(
                    "The install transaction already has a guard request.",
                ));
            }
            waiters.insert(bytes, sender);
        }
        if self
            .hub
            .outgoing
            .send(Frame::Rollback {
                transaction: bytes,
                script,
            })
            .is_err()
        {
            lock(&self.hub.arm_waiters).remove(&bytes);
            return Err(Failure::install("The host's upgrade helper has stopped."));
        }
        let state = match tokio::time::timeout(GUARD_ACK_BOUND, receiver).await {
            Ok(Ok(state)) => state,
            Ok(Err(_)) => {
                return Err(Failure::install(
                    "The host stopped before confirming its rollback guard.",
                ));
            }
            Err(_) => {
                lock(&self.hub.arm_waiters).remove(&bytes);
                return Err(Failure::install(
                    "The host did not confirm its rollback guard; root promotion was not started.",
                ));
            }
        };
        match state {
            GuardState::Armed => {
                self.hub.guard_armed.store(true, Ordering::SeqCst);
                Ok(())
            }
            GuardState::SystemdUnavailable => Err(Failure::install(
                "This host needs a working systemd system manager for a safe root upgrade.",
            )),
            GuardState::ArmFailed => Err(Failure::install(
                "The host could not verify its rollback guard; root promotion was not started.",
            )),
            GuardState::Committed | GuardState::DisarmFailed => Err(Failure::install(
                "The host returned a commit result before its rollback guard was armed.",
            )),
        }
    }

    /// Tell the relay the install committed and wait for checked guard cleanup.
    /// Call it only after the install's own commit step succeeded.
    ///
    /// # Errors
    /// Returns an install failure if the relay stops or cannot confirm guard cleanup.
    pub async fn commit(&self, transaction: uuid::Uuid) -> Result<(), Failure> {
        if self.lost() {
            return Err(Failure::install("The host's upgrade helper has stopped."));
        }
        let bytes = transaction.into_bytes();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        {
            let mut waiters = lock(&self.hub.commit_waiters);
            if waiters.contains_key(&bytes) {
                return Err(Failure::install(
                    "The install transaction already has a commit request.",
                ));
            }
            waiters.insert(bytes, sender);
        }
        if self
            .hub
            .outgoing
            .send(Frame::Commit { transaction: bytes })
            .is_err()
        {
            lock(&self.hub.commit_waiters).remove(&bytes);
            return Err(Failure::install("The host's upgrade helper has stopped."));
        }
        let state = match tokio::time::timeout(GUARD_ACK_BOUND, receiver).await {
            Ok(Ok(state)) => state,
            Ok(Err(_)) => {
                return Err(Failure::install(
                    "The host stopped before confirming committed guard cleanup.",
                ));
            }
            Err(_) => {
                lock(&self.hub.commit_waiters).remove(&bytes);
                return Err(Failure::install(
                    "The host did not confirm committed guard cleanup.",
                ));
            }
        };
        self.hub.guard_armed.store(false, Ordering::SeqCst);
        match state {
            GuardState::Committed => Ok(()),
            GuardState::DisarmFailed => Err(Failure::install(
                "The root install committed, but the host could not finish removing its rollback guard.",
            )),
            GuardState::Armed | GuardState::SystemdUnavailable | GuardState::ArmFailed => {
                Err(Failure::install(
                    "The host returned a guard-arm result instead of a commit result.",
                ))
            }
        }
    }

    /// The relay has gone away; every later step fails.
    #[must_use]
    pub fn lost(&self) -> bool {
        self.hub.lost.load(Ordering::SeqCst)
    }
}

impl Drop for RelaySession {
    /// Asks the relay to stop and removes the helper socket.
    fn drop(&mut self) {
        self.close();
        let _ = std::fs::remove_file(&self.hub.socket);
    }
}

impl SshSession for RelaySession {
    /// Steps use the fixed receipts, as over OpenSSH.
    fn setup_steps(&self) -> bool {
        true
    }
    /// Runs `script` with this session's default timeout.
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        self.run_with_timeout(script, input, self.timeout)
    }
    /// Runs `script` as one relay channel through the helper; see the module docs.
    fn run_with_timeout<'a>(
        &'a self,
        script: &'a str,
        input: Input<'a>,
        timeout: Duration,
    ) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            if self.lost() {
                return Err(Failure::new(
                    crate::model::FailureKind::Unreachable,
                    "The host's upgrade helper has stopped.",
                ));
            }
            if !self.hub.guard_armed.load(Ordering::SeqCst) {
                return Err(Failure::install(
                    "The host has not confirmed a rollback guard; no root install step was started.",
                ));
            }
            let channel = self.hub.next.fetch_add(1, Ordering::SeqCst);
            lock(&self.hub.pending).insert(channel, script.to_owned());
            let mut command = tokio::process::Command::new(&self.exe);
            command
                .arg(CHANNEL_COMMAND)
                .arg(&self.hub.socket)
                .arg(channel.to_string())
                .env_clear()
                .env("LC_ALL", "C");
            let result = execute(&mut command, input, timeout).await;
            lock(&self.hub.pending).remove(&channel);
            if lock(&self.hub.routes).remove(&channel).is_some() {
                // The step ended on our side (timeout); stop it on the host.
                let _ = self.hub.outgoing.send(Frame::Kill { channel });
            }
            let result = result?;
            if result.success {
                return Ok(CommandOutput {
                    stdout: result.stdout,
                });
            }
            // The same mapping as the OpenSSH adapter, so refusals, failed
            // steps and interrupted setups read the same either way.
            if script.starts_with("# INFRATERNAL_TRANSFER_SETUP_V1\n")
                && let Err(error) = crate::install::parse_transfer_setup(&result.stdout)
                && error.exit_status.is_some()
                && error.exit_status == result.exit_status
            {
                return Err(crate::openssh::capture_setup_stderr(
                    error,
                    script,
                    &result.stderr,
                ));
            }
            let mut failure = crate::openssh::command_failure(&result.stderr, result.exit_status);
            failure = crate::openssh::capture_setup_stderr(failure, script, &result.stderr);
            if script.starts_with("# INFRATERNAL_SETUP_STEPS_V1\n") {
                failure.failed_step = crate::install::interrupted_setup_step(&result.stdout);
            } else if script.starts_with("# INFRATERNAL_TRANSFER_SETUP_V1\n") {
                failure.failed_step = crate::install::interrupted_transfer_step(&result.stdout);
            }
            Err(failure)
        })
    }
}

/// Lock a mutex, recovering from a poisoned one (its maps stay consistent:
/// every update is a single insert or remove).
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Move frames between the relay and the channels until the relay closes.
async fn pump_loop(
    hub: Arc<Hub>,
    pump: Arc<dyn Pump>,
    mut queued: mpsc::UnboundedReceiver<Frame>,
    ready: tokio::sync::oneshot::Sender<()>,
) {
    let mut ready = Some(ready);
    let mut decoder = Decoder::default();
    let mut closing = false;
    // B10: the relay's stderr is capped here too, per channel, since the
    // rootless agent's pipe could inject more than the relay would send.
    let mut stderr: HashMap<u32, usize> = HashMap::new();
    loop {
        let mut send = Vec::new();
        while send.len() < 2 * MAX_CHUNK {
            match queued.try_recv() {
                Ok(frame) => {
                    closing |= frame == Frame::Close;
                    frame.encode(&mut send);
                }
                Err(_) => break,
            }
        }
        let Ok((received, closed)) = pump.pump(send).await else {
            break;
        };
        decoder.push(&received);
        let mut broken = false;
        loop {
            match decoder.frame() {
                Ok(Some(Frame::Ready)) => {
                    if let Some(ready) = ready.take() {
                        let _ = ready.send(());
                    }
                }
                // B10: nothing but Ready may come before Ready.
                Ok(Some(_)) if ready.is_some() => {
                    broken = true;
                    break;
                }
                Ok(Some(Frame::Guard { transaction, state })) => {
                    let sender = match state {
                        GuardState::Armed
                        | GuardState::SystemdUnavailable
                        | GuardState::ArmFailed => lock(&hub.arm_waiters).remove(&transaction),
                        GuardState::Committed | GuardState::DisarmFailed => {
                            lock(&hub.commit_waiters).remove(&transaction)
                        }
                    };
                    if sender.is_none_or(|sender| sender.send(state).is_err()) {
                        broken = true;
                        break;
                    }
                }
                Ok(Some(Frame::Stderr { channel, bytes })) => {
                    let forwarded = stderr.entry(channel).or_default();
                    let keep = bytes.len().min(MAX_STDERR.saturating_sub(*forwarded));
                    *forwarded += keep;
                    if keep > 0
                        && let Some(route) = lock(&hub.routes).get(&channel)
                    {
                        let _ = route.send(Frame::Stderr {
                            channel,
                            bytes: bytes[..keep].to_vec(),
                        });
                    }
                }
                Ok(Some(frame @ (Frame::Stdout { .. } | Frame::Exit { .. }))) => {
                    let channel = match &frame {
                        Frame::Stdout { channel, .. } | Frame::Exit { channel, .. } => *channel,
                        _ => 0,
                    };
                    let exit = matches!(frame, Frame::Exit { .. });
                    let mut routes = lock(&hub.routes);
                    if let Some(route) = routes.get(&channel) {
                        let _ = route.send(frame);
                    }
                    if exit {
                        routes.remove(&channel);
                    }
                }
                Ok(None) => break,
                // Anything else from the relay is a protocol error.
                Ok(Some(_)) | Err(_) => {
                    broken = true;
                    break;
                }
            }
        }
        if closed || broken || closing {
            break;
        }
    }
    hub.lost.store(true, Ordering::SeqCst);
    lock(&hub.arm_waiters).clear();
    lock(&hub.commit_waiters).clear();
    hub.guard_armed.store(false, Ordering::SeqCst);
    for (channel, route) in lock(&hub.routes).drain() {
        let _ = route.send(Frame::Exit {
            channel,
            code: Some(LOST),
        });
    }
}

/// Accept helper connections and bridge each to its relay channel.
async fn accept_loop(hub: Arc<Hub>, listener: UnixListener) {
    let me = nix::unistd::Uid::effective().as_raw();
    while let Ok((stream, _)) = listener.accept().await {
        if !stream.peer_cred().is_ok_and(|cred| cred.uid() == me) {
            continue;
        }
        tokio::spawn(bridge(hub.clone(), stream));
    }
}

/// One helper: read its channel number, open the channel on the relay, then
/// forward its stdin frames there and the relay's answers back to it.
async fn bridge(hub: Arc<Hub>, stream: UnixStream) {
    let (mut reader, mut writer) = stream.into_split();
    let mut number = [0; 4];
    if reader.read_exact(&mut number).await.is_err() {
        return;
    }
    let channel = u32::from_be_bytes(number);
    let Some(script) = lock(&hub.pending).remove(&channel) else {
        return;
    };
    let (route, mut answers) = mpsc::unbounded_channel();
    if hub.lost.load(Ordering::SeqCst) {
        let _ = route.send(Frame::Exit {
            channel,
            code: Some(LOST),
        });
    } else {
        lock(&hub.routes).insert(channel, route);
        let _ = hub.outgoing.send(Frame::Open { channel, script });
    }
    let outgoing = hub.outgoing.clone();
    let upstream = tokio::spawn(async move {
        let mut decoder = Decoder::default();
        let mut buffer = vec![0; MAX_CHUNK];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => decoder.push(&buffer[..read]),
            }
            while let Ok(Some(frame)) = decoder.frame() {
                match frame {
                    Frame::Stdin { bytes, .. } => {
                        let _ = outgoing.send(Frame::Stdin { channel, bytes });
                    }
                    Frame::StdinEnd { .. } => {
                        let _ = outgoing.send(Frame::StdinEnd { channel });
                    }
                    _ => {}
                }
            }
        }
    });
    let mut bytes = Vec::new();
    while let Some(frame) = answers.recv().await {
        let exit = matches!(frame, Frame::Exit { .. });
        bytes.clear();
        frame.encode(&mut bytes);
        if writer.write_all(&bytes).await.is_err() || exit {
            break;
        }
    }
    upstream.abort();
}

/// Run the per-step helper when this process was started as one; `None`
/// otherwise. Arguments: `__privilege-channel <socket> <channel>`.
///
/// It forwards its stdin to the channel as `Stdin` frames (then `StdinEnd`),
/// writes `Stdout`/`Stderr` frames to its own stdout/stderr, and exits with
/// the step's exit code (255 when the relay is gone or the code is unknown).
/// It is plain blocking I/O on two threads, with no runtime, because it only
/// lives for one step.
#[must_use]
pub fn run_if_requested() -> Option<std::process::ExitCode> {
    use std::io::{Read as _, Write as _};
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some(CHANNEL_COMMAND) {
        return None;
    }
    let (Some(socket), Some(Ok(channel)), 3) = (
        args.get(1),
        args.get(2).map(|value| value.parse::<u32>()),
        args.len(),
    ) else {
        return Some(std::process::ExitCode::from(LOST));
    };
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(socket) else {
        return Some(std::process::ExitCode::from(LOST));
    };
    if stream.write_all(&channel.to_be_bytes()).is_err() {
        return Some(std::process::ExitCode::from(LOST));
    }
    let Ok(mut upstream) = stream.try_clone() else {
        return Some(std::process::ExitCode::from(LOST));
    };
    std::thread::spawn(move || {
        let mut buffer = vec![0; MAX_CHUNK];
        let mut stdin = std::io::stdin().lock();
        let mut bytes = Vec::new();
        loop {
            bytes.clear();
            match stdin.read(&mut buffer) {
                Ok(0) | Err(_) => {
                    Frame::StdinEnd { channel }.encode(&mut bytes);
                    let _ = upstream.write_all(&bytes);
                    break;
                }
                Ok(read) => {
                    Frame::Stdin {
                        channel,
                        bytes: buffer[..read].to_vec(),
                    }
                    .encode(&mut bytes);
                    if upstream.write_all(&bytes).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut decoder = Decoder::default();
    let mut buffer = vec![0; MAX_CHUNK];
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    loop {
        let read = match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return Some(std::process::ExitCode::from(LOST)),
            Ok(read) => read,
        };
        decoder.push(&buffer[..read]);
        while let Ok(Some(frame)) = decoder.frame() {
            match frame {
                Frame::Stdout { bytes, .. } => {
                    let _ = stdout.write_all(&bytes).and_then(|()| stdout.flush());
                }
                Frame::Stderr { bytes, .. } => {
                    let _ = stderr.write_all(&bytes);
                }
                Frame::Exit { code, .. } => {
                    return Some(std::process::ExitCode::from(code.unwrap_or(LOST)));
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! The session needs the relay's Ready. Steps through the real helper
    //! binary are tested in `crates/infraternal/tests/privilege_relay_session.rs`,
    //! which has that binary.
    use super::*;

    /// Without a Ready from the relay the session doesn't start.
    #[tokio::test]
    async fn no_ready_no_session() {
        struct Silent;
        impl Pump for Silent {
            fn pump(&self, _: Vec<u8>) -> Operation<'_, (Vec<u8>, bool)> {
                Box::pin(async {
                    // sleep: pace the silent pump like the real one's short wait.
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok((Vec::new(), false))
                })
            }
        }
        let dir = std::env::temp_dir().join(format!("relay-silent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let started = RelaySession::start(
            Arc::new(Silent),
            &dir,
            PathBuf::from("/bin/false"),
            Duration::from_secs(1),
            Duration::from_millis(200),
        )
        .await;
        assert!(started.is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
