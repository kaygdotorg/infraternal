//! Bounds bootstrap child input/output, deadlines and cancellation; arbitrary helper bytes never become diagnostics.

use crate::{model::Failure, prompt::PromptParent, transport::Input};
use nix::{
    sys::{
        signal::{Signal, killpg},
        wait::{Id, WaitPidFlag, WaitStatus, waitid},
    },
    unistd::Pid,
};
use std::{os::unix::process::CommandExt, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    signal::unix::{Signal as ExitEvents, SignalKind, signal},
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

/// Run one trusted helper with bounded pipes and a total active deadline.
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
    let operation = async {
        let write = write_input(stdin, input);
        let read = async {
            let (stdout, stderr) =
                tokio::try_join!(bounded(stdout, stdout_limit), bounded(stderr, 8192))?;
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
        let (stdout, stderr) = read?;
        if status.success() {
            write?;
        }
        Ok(Output {
            stdout,
            stderr,
            success: status.success(),
            exit_status: status.code().and_then(|code| u8::try_from(code).ok()),
            ssh_failure: status.code() == Some(255),
        })
    };
    if let Ok(result) = tokio::time::timeout(timeout, operation).await {
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
        let status = exit_status(pid)
            .map_err(|_| Failure::install("The SSH helper exit could not be observed."))?;
        if status != WaitStatus::StillAlive {
            return Ok(());
        }
        if exits.recv().await.is_none() {
            return Err(Failure::install(
                "The SSH helper exit could not be observed.",
            ));
        }
    }
}

fn exit_status(pid: Pid) -> nix::Result<WaitStatus> {
    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG;
    loop {
        match waitid(Id::Pid(pid), flags) {
            Err(nix::errno::Errno::EINTR) => {}
            result => return result,
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

/// Keep commit release and ordinary input under the same bounded child lifecycle.
async fn write_input(
    mut stdin: tokio::process::ChildStdin,
    input: Input<'_>,
) -> Result<(), Failure> {
    match input {
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
