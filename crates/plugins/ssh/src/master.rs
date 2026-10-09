//! Owns one nonpersistent OpenSSH connection and its unreaped process group for a host attempt.

use crate::{
    model::{Failure, FailureKind, MeshEvidence},
    openssh::classify,
    process::Group,
    prompt::{PromptLease, PromptParent},
    transport::Secret,
};
use nix::{
    sys::wait::{Id, WaitPidFlag, WaitStatus, waitid},
    unistd::Pid,
};
use std::os::unix::process::CommandExt;
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    task::JoinHandle,
};

struct Diagnostics {
    bytes: Secret,
    authenticated: bool,
    failed: bool,
    complete: bool,
}

/// The child is never reaped until its group has been retired. Healthy connections
/// have one blocked diagnostic reader and no polling task or persistent reconnect.
pub struct Master {
    // Drop retires the group before Child's Tokio reaper can release the pid.
    group: Group,
    _prompt: PromptLease,
    child: Child,
    socket: PathBuf,
    diagnostics: Arc<Mutex<Diagnostics>>,
    reading: JoinHandle<()>,
}
impl Master {
    /// Authenticate with one owned foreground master; socket readiness follows SSH authentication.
    /// # Errors
    /// Refuses authentication/trust, diagnostic overflow, timeout and invalid control sockets.
    pub(crate) async fn start(
        mut command: Command,
        socket: PathBuf,
        timeout: Duration,
        mesh: MeshEvidence,
        parent: &PromptParent,
    ) -> Result<Self, Failure> {
        command.as_std_mut().process_group(0);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|_| Failure::install("The SSH connection helper could not start."))?;
        let group = Group::owned(&child)?;
        let prompt = parent.register(&child)?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| Failure::install("The SSH connection diagnostics are unavailable."))?;
        let diagnostics = Arc::new(Mutex::new(Diagnostics {
            bytes: Secret::new(Vec::new()),
            authenticated: false,
            failed: false,
            complete: false,
        }));
        let observed = diagnostics.clone();
        let reading = tokio::spawn(async move {
            let mut chunk = zeroize::Zeroizing::new([0; 1024]);
            loop {
                let count = match stderr.read(&mut chunk[..]).await {
                    Ok(0) => {
                        lock(&observed).complete = true;
                        return;
                    }
                    Ok(count) => count,
                    Err(_) => {
                        lock(&observed).failed = true;
                        return;
                    }
                };
                let mut state = lock(&observed);
                // Retain no further raw diagnostics after trusted authentication.
                // Command stderr belongs to each separate mux client's bounded pipe.
                if state.authenticated {
                    continue;
                }
                if state.bytes.expose().len() + count > 8192 {
                    state.failed = true;
                    return;
                }
                let mut bytes = state.bytes.expose().to_vec();
                bytes.extend_from_slice(&chunk[..count]);
                state.bytes = Secret::new(bytes);
            }
        });
        let master = Self {
            group,
            _prompt: prompt,
            child,
            socket,
            diagnostics,
            reading,
        };
        tokio::time::timeout(timeout, async {
            loop {
                let (failed, complete) = {
                    let state = lock(&master.diagnostics);
                    (state.failed, state.complete)
                };
                if failed {
                    return Err(Failure::install(
                        "The SSH diagnostics exceeded their safety limit.",
                    ));
                }
                if complete {
                    let state = lock(&master.diagnostics);
                    return Err(classify(state.bytes.expose(), true, mesh));
                }
                if !master.alive()? {
                    // Keep the leader unreaped and allow its bounded stderr to
                    // drain before classifying an authentication/trust refusal.
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                if let Ok(metadata) = std::fs::symlink_metadata(&master.socket) {
                    if !metadata.file_type().is_socket()
                        || metadata.uid() != nix::unistd::geteuid().as_raw()
                        || metadata.permissions().mode() & 0o077 != 0
                    {
                        return Err(Failure::install("The SSH control socket is invalid."));
                    }
                    let mut state = lock(&master.diagnostics);
                    state.authenticated = true;
                    state.bytes = Secret::new(Vec::new());
                    return Ok(());
                }
                // Active connection startup only. No healthy/idle polling loop.
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| Failure::new(FailureKind::Unreachable, "The SSH connection timed out."))??;
        Ok(master)
    }

    /// Observe exit without reaping: cancellation must retain the owned group identity.
    /// # Errors
    /// An unavailable child identity is a closed connection, never a new login attempt.
    pub fn alive(&self) -> Result<bool, Failure> {
        let id = self
            .child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .map(Pid::from_raw)
            .ok_or_else(|| {
                Failure::new(FailureKind::Unreachable, "The SSH connection has closed.")
            })?;
        match waitid(
            Id::Pid(id),
            WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG | WaitPidFlag::WNOWAIT,
        ) {
            Ok(WaitStatus::StillAlive) => Ok(true),
            Ok(_) => Ok(false),
            Err(_) => Err(Failure::new(
                FailureKind::Unreachable,
                "The SSH connection has closed.",
            )),
        }
    }
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }
}
impl Drop for Master {
    fn drop(&mut self) {
        self.group.retire();
        self.reading.abort();
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
