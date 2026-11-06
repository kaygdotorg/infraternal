//! Bounds bootstrap child input/output, deadlines and cancellation; arbitrary helper bytes never become diagnostics.

use crate::{
    model::Failure,
    prompt::PromptParent,
    transport::{Input, PayloadInput, TransferChoice},
};
use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use std::{os::unix::process::CommandExt, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::Command,
    signal::unix::{Signal as ExitEvents, SignalKind, signal},
    sync::watch,
    time::Instant,
};

/// Process data is bounded even when a compromised SSH endpoint streams endlessly.
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub success: bool,
    /// Exit code without any process text; signals have no numeric code.
    pub exit_status: Option<u8>,
    pub ssh_failure: bool,
}

/// Run one trusted helper with bounded pipes and a progress deadline.
/// Only validated remote byte acknowledgements renew `timeout`. The last byte
/// starts a separate completion/exit interval. Local pipe writes, banners and
/// diagnostics cannot renew it. Unacknowledged commands keep a total deadline.
/// Production SSH uses a 30-second interval.
/// # Errors
/// Reports helper startup, bounded I/O or active timeout without printing process data.
pub async fn execute(
    command: &mut Command,
    input: Input<'_>,
    timeout: Duration,
) -> Result<Output, Failure> {
    execute_bounded(command, input, timeout, 4096).await
}

/// Bound larger trusted helper output such as effective SSH configuration; stderr stays at8KiB.
/// # Errors
/// Refuses output limits over64KiB, then uses the same bounded process lifecycle.
pub async fn execute_bounded(
    command: &mut Command,
    input: Input<'_>,
    timeout: Duration,
    stdout_limit: usize,
) -> Result<Output, Failure> {
    execute_inner(command, input, timeout, stdout_limit, None).await
}

pub(crate) async fn execute_prompt(
    command: &mut Command,
    input: Input<'_>,
    timeout: Duration,
    parent: &PromptParent,
) -> Result<Output, Failure> {
    execute_inner(command, input, timeout, 4096, Some(parent)).await
}

/// Keep process ownership and bounded diagnostics intact across progress expiry.
async fn execute_inner(
    command: &mut Command,
    input: Input<'_>,
    timeout: Duration,
    stdout_limit: usize,
    parent: Option<&PromptParent>,
) -> Result<Output, Failure> {
    if stdout_limit > 65536 {
        return Err(Failure::install("The SSH helper output limit is invalid."));
    }
    infraternal_shim::prepare_child(command.as_std_mut());
    command.as_std_mut().process_group(0);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Subscribe before spawning so exit cannot fall between observation and
    // notification. The shared Tokio SIGCHLD path adds no blocking pool thread.
    let mut exits = signal(SignalKind::child())
        .map_err(|_| Failure::install("The SSH helper exit could not be observed."))?;
    let mut child = command
        .spawn()
        .map_err(|_| Failure::install("The SSH helper could not start."))?;
    let group = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .map(Pid::from_raw)
        .ok_or_else(|| Failure::install("The SSH helper identity is unavailable."))?;
    // This guard is created after Child so cancellation drops it first, while
    // the process identity is still owned. Proxies and askpass descendants share
    // this group; killing only the SSH parent would leave them alive.
    let mut group = Group {
        id: group,
        armed: true,
    };
    let prompt_lease = parent.map(|parent| parent.register(&child)).transpose()?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| Failure::install("The SSH input pipe is unavailable."))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Failure::install("The SSH output pipe is unavailable."))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Failure::install("The SSH diagnostic pipe is unavailable."))?;
    // Only the remote receipt parser can renew this bounded latest timestamp.
    let (progress, mut moved) = watch::channel(Instant::now());
    let total = match &input {
        Input::Transfer(payload) => Some(payload.size()),
        _ => None,
    };
    let sizes = match &input {
        Input::Negotiated {
            raw, gzip, zstd, ..
        } => (
            raw.size(),
            gzip.map(|bytes| bytes.len() as u64),
            zstd.map(|bytes| bytes.len() as u64),
        ),
        _ => (0, None, None),
    };
    let (negotiated, payload_ack, declared) = transfer_options(&input);
    let (choice, selected) = tokio::sync::oneshot::channel();
    let (ready, received) = tokio::sync::oneshot::channel();
    let result = {
        let operation = async {
            let write = write_input(stdin, input, selected, received);
            let read = async {
                let (stdout, stderr) = tokio::try_join!(
                    async {
                        if negotiated {
                            negotiated_output(
                                stdout,
                                stdout_limit,
                                choice,
                                ready,
                                payload_ack,
                                declared,
                                sizes,
                                &progress,
                            )
                            .await
                        } else if let Some(total) = total {
                            progress_output(stdout, stdout_limit, total, &progress).await
                        } else {
                            bounded(stdout, stdout_limit)
                                .await
                                .map(|bytes| (bytes, true))
                        }
                    },
                    bounded(stderr, 8192)
                )?;
                Ok::<_, Failure>((stdout, stderr))
            };
            // Retain the unreaped leader identity while inherited pipes are pending.
            // A descendant can leave the group but keep a pipe open; reaping first
            // would let cancellation signal a subsequently reused group id.
            let (write, read) = tokio::join!(write, read);
            observe_exit(group.id, &mut exits).await?;
            // Retire closed-pipe descendants before reaping releases the group id.
            group.retire();
            // Revoke helper authority before the leader identity can be reused.
            drop(prompt_lease);
            let status = child.wait().await;
            let status =
                status.map_err(|_| Failure::install("The SSH helper did not exit cleanly."))?;
            let ((stdout, acknowledged), stderr) = read?;
            // A negotiated setup may refuse a stage without consuming invitation
            // stdin. Keep only a complete canonical refusal for the caller's typed
            // decoder; successful or malformed receipts still require input delivery.
            let refused = negotiated
                && crate::install::parse_transfer_setup(&stdout)
                    .is_err_and(|failure| failure.exit_status.is_some());
            if status.success() && !refused {
                write?;
                if !acknowledged {
                    return Err(Failure::install(
                        "The SSH upload ended before its byte acknowledgement.",
                    ));
                }
            }
            Ok(Output {
                stdout,
                stderr,
                success: status.success(),
                exit_status: status.code().and_then(|code| u8::try_from(code).ok()),
                ssh_failure: status.code() == Some(255),
            })
        };
        tokio::pin!(operation);
        let expiry = tokio::time::sleep(timeout);
        tokio::pin!(expiry);
        loop {
            tokio::select! {
                biased;
                result = &mut operation => break Some(result),
                Ok(()) = moved.changed() => {
                    expiry.as_mut().reset(*moved.borrow_and_update() + timeout);
                },
                () = &mut expiry => break None,
            }
        }
    };
    if let Some(result) = result {
        // Normal completion retired the group before reaping. Early errors still
        // own the leader identity and must also retire descendants.
        group.retire();
        result
    } else {
        group.retire();
        let _ = child.wait().await;
        Err(Failure::install("The SSH operation timed out."))
    }
}

/// Keep the leader unreaped while awaiting its natural exit through the existing
/// asynchronous child signal path. Recheck after every notification because
/// SIGCHLD is shared and can describe another owned helper.
async fn observe_exit(pid: Pid, exits: &mut ExitEvents) -> Result<(), Failure> {
    loop {
        let exited = crate::child_exit::exited(pid)
            .map_err(|_| Failure::install("The SSH helper exit could not be observed."))?;
        if exited {
            return Ok(());
        }
        if exits.recv().await.is_none() {
            return Err(Failure::install(
                "The SSH helper exit could not be observed.",
            ));
        }
    }
}

pub(crate) struct Group {
    id: Pid,
    armed: bool,
}
impl Group {
    /// Guard a child spawned with `process_group(0)`. The caller retains its
    /// unreaped leader until retirement so the group id cannot be reused.
    pub(crate) fn owned(child: &tokio::process::Child) -> Result<Self, Failure> {
        let id = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .map(Pid::from_raw)
            .ok_or_else(|| Failure::install("The SSH helper identity is unavailable."))?;
        Ok(Self { id, armed: true })
    }

    pub(crate) fn retire(&mut self) {
        if self.armed {
            let _ = killpg(self.id, Signal::SIGKILL);
            self.armed = false;
        }
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        self.retire();
    }
}

async fn bounded(
    reader: impl tokio::io::AsyncRead + Unpin,
    limit: usize,
) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(limit + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| Failure::install("The SSH output was interrupted."))?;
    if bytes.len() > limit {
        return Err(Failure::install(
            "The SSH output exceeded its safety limit.",
        ));
    }
    Ok(bytes)
}

/// Declared public sources always require verified staging before private
/// stdin, even if a caller omitted the older optional acknowledgment flag.
fn transfer_options(input: &Input<'_>) -> (bool, bool, Option<TransferChoice>) {
    match input {
        Input::Negotiated {
            payload_ack,
            declared,
            ..
        } => (true, *payload_ack || declared.is_some(), *declared),
        _ => (false, false, None),
    }
}

/// Keep commit release and ordinary input under the same bounded child lifecycle.
async fn write_input(
    mut stdin: impl AsyncWrite + Unpin,
    input: Input<'_>,
    selected: tokio::sync::oneshot::Receiver<Option<TransferChoice>>,
    received: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), Failure> {
    match input {
        Input::Transfer(payload) => write_payload(&mut stdin, payload).await?,
        Input::Negotiated {
            raw,
            gzip,
            zstd,
            invitation,
            payload_ack,
            declared,
        } => {
            // Only public content can flow before the fixed selection receipt.
            // The reader independently checks that it names this exact source.
            let selection = if declared.is_some() {
                declared
            } else {
                selected.await.ok().flatten()
            };
            let payload = match selection {
                Some(TransferChoice::Raw) => Some(raw),
                Some(TransferChoice::Gzip) => Some(PayloadInput::Bytes(gzip.ok_or_else(|| {
                    Failure::install("The requested payload encoding is unavailable.")
                })?)),
                Some(TransferChoice::Zstd) => Some(PayloadInput::Bytes(zstd.ok_or_else(|| {
                    Failure::install("The requested payload encoding is unavailable.")
                })?)),
                Some(TransferChoice::Reuse) => None,
                None => return Ok(()), // Early fixed refusal retains its numeric command status.
            };
            if let Some(payload) = payload {
                write_payload(&mut stdin, payload).await?;
            }
            // A stdio-based bounded reader can discard bytes beyond the payload.
            // Its verified receipt proves that reader exited before private input.
            if (payload_ack || declared.is_some()) && received.await.is_err() {
                return Ok(());
            }
            stdin
                .write_all(invitation)
                .await
                .map_err(|_| Failure::install("The SSH input pipe closed."))?;
        }
        Input::PayloadAndInvitation {
            payload,
            invitation,
        } => {
            write_payload(&mut stdin, payload).await?;
            stdin
                .write_all(invitation)
                .await
                .map_err(|_| Failure::install("The SSH input pipe closed."))?;
        }
        Input::Signal(release) => {
            release.await.map_err(|_| {
                Failure::install("Host provisioning stopped before terminal proof.")
            })?;
            stdin
                .write_all(b"\n")
                .await
                .map_err(|_| Failure::install("The SSH input pipe closed."))?;
        }
        Input::Empty => {}
        Input::Bytes(bytes) => stdin
            .write_all(bytes)
            .await
            .map_err(|_| Failure::install("The SSH upload was interrupted."))?,
        Input::File(path) => {
            let mut file = tokio::fs::File::open(path)
                .await
                .map_err(|_| Failure::install("The matching infraternal binary is unavailable."))?;
            tokio::io::copy(&mut file, &mut stdin)
                .await
                .map_err(|_| Failure::install("The SSH upload was interrupted."))?;
        }
    }
    // Broken pipe is expected on pre-command authentication/host-key refusal;
    // retain the child's bounded diagnostics to classify the real failure.
    let _ = stdin.shutdown().await;
    Ok::<(), Failure>(())
}

/// Decode exactly two bounded public lines; retain all other bytes for failure classification.
async fn negotiated_output(
    mut stdout: tokio::process::ChildStdout,
    limit: usize,
    choice: tokio::sync::oneshot::Sender<Option<TransferChoice>>,
    ready: tokio::sync::oneshot::Sender<()>,
    payload_ack: bool,
    declared: Option<TransferChoice>,
    sizes: (u64, Option<u64>, Option<u64>),
    progress: &watch::Sender<Instant>,
) -> Result<(Vec<u8>, bool), Failure> {
    let mut prefix = Vec::new();
    let mut lines = 0;
    for _ in 0..limit.min(64) {
        let mut byte = [0_u8; 1];
        if stdout
            .read(&mut byte)
            .await
            .map_err(|_| Failure::install("The SSH output pipe closed."))?
            == 0
        {
            break;
        }
        prefix.push(byte[0]);
        lines += usize::from(byte[0] == b'\n');
        if lines == 2 {
            break;
        }
    }
    let selected = prefix
        .strip_prefix(b"STEP upload\n")
        .and_then(TransferChoice::parse);
    if let (Some(expected), Some(selected)) = (declared, selected)
        && expected.word() != selected.word()
    {
        // Dropping readiness closes the private-input barrier. A remote's
        // different encoder cannot reinterpret bytes already sent publicly.
        return Err(Failure::install(
            "The payload transfer selection was invalid.",
        ));
    }
    let _ = choice.send(selected);
    let mut acknowledged = true;
    if payload_ack && selected.is_some() {
        let total = match selected {
            Some(TransferChoice::Raw) => sizes.0,
            Some(TransferChoice::Gzip) => sizes
                .1
                .ok_or_else(|| Failure::install("The payload encoding is unavailable."))?,
            Some(TransferChoice::Zstd) => sizes
                .2
                .ok_or_else(|| Failure::install("The payload encoding is unavailable."))?,
            _ => 0,
        };
        let (mut refusal, complete) = consume_progress(&mut stdout, total, progress).await?;
        acknowledged = complete;
        prefix.append(&mut refusal);
        // Read only the public readiness receipt; leave final setup output in
        // its existing canonical shape for the shared refusal decoder.
        let mut line = Vec::new();
        loop {
            let mut byte = [0];
            if prefix.len() + line.len() >= limit
                || stdout
                    .read(&mut byte)
                    .await
                    .map_err(|_| Failure::install("The SSH output pipe closed."))?
                    == 0
            {
                break;
            }
            line.push(byte[0]);
            if byte[0] == b'\n' {
                if line == b"PAYLOAD ready\n" && acknowledged {
                    line.clear();
                    let _ = ready.send(());
                    break;
                }
                prefix.append(&mut line);
            }
        }
        prefix.append(&mut line);
    }
    let mut rest = bounded(stdout, limit.saturating_sub(prefix.len())).await?;
    prefix.append(&mut rest);
    Ok((prefix, acknowledged))
}

/// Consume a single bounded line without reading into later private protocol data.
async fn progress_line(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, Failure> {
    let mut line = Vec::new();
    while line.len() < 32 {
        let mut byte = [0];
        if reader
            .read(&mut byte)
            .await
            .map_err(|_| Failure::install("The SSH progress pipe closed."))?
            == 0
        {
            return Ok(line);
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(line);
        }
    }
    Err(Failure::install(
        "The SSH progress receipt exceeded its safety limit.",
    ))
}

/// Strip strictly increasing remote counters; retain a refusal for the existing decoder.
async fn consume_progress(
    reader: &mut (impl AsyncRead + Unpin),
    total: u64,
    progress: &watch::Sender<Instant>,
) -> Result<(Vec<u8>, bool), Failure> {
    let mut counter = crate::transfer_progress::Progress::new(total);
    while !counter.complete() {
        let line = progress_line(reader).await?;
        if !line.starts_with(b"PROGRESS ") {
            return Ok((line, false));
        }
        counter.accept(&line)?;
        progress.send_replace(Instant::now());
    }
    Ok((Vec::new(), true))
}

/// Public acknowledgements are not command output and do not consume its fixed cap.
async fn progress_output(
    mut stdout: tokio::process::ChildStdout,
    limit: usize,
    total: u64,
    progress: &watch::Sender<Instant>,
) -> Result<(Vec<u8>, bool), Failure> {
    let (mut prefix, complete) = consume_progress(&mut stdout, total, progress).await?;
    let mut rest = bounded(stdout, limit.saturating_sub(prefix.len())).await?;
    prefix.append(&mut rest);
    Ok((prefix, complete))
}

/// Public file framing is shared by both fixed and negotiated input paths.
async fn write_payload(
    stdin: &mut (impl AsyncWrite + Unpin),
    payload: PayloadInput<'_>,
) -> Result<(), Failure> {
    match payload {
        PayloadInput::Bytes(bytes) => stdin
            .write_all(bytes)
            .await
            .map_err(|_| Failure::install("The SSH upload was interrupted."))?,
        PayloadInput::File { path, size } => {
            let file = tokio::fs::File::open(path)
                .await
                .map_err(|_| Failure::install("The matching infraternal binary is unavailable."))?;
            if file
                .metadata()
                .await
                .map_err(|_| Failure::install("The payload metadata is unavailable."))?
                .len()
                != size
            {
                return Err(Failure::install(
                    "The static payload changed before transfer.",
                ));
            }
            let mut frame = file.take(size);
            let copied = tokio::io::copy(&mut frame, &mut *stdin)
                .await
                .map_err(|_| Failure::install("The SSH upload was interrupted."))?;
            if copied != size
                || frame
                    .get_ref()
                    .metadata()
                    .await
                    .map_err(|_| Failure::install("The payload metadata is unavailable."))?
                    .len()
                    != size
            {
                return Err(Failure::install(
                    "The static payload changed during transfer.",
                ));
            }
        }
    }
    Ok(())
}
