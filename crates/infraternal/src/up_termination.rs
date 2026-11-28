//! Defers termination until enrollment and installation have released their owned resources.

use nix::sys::signal::{Signal, kill};
use std::{
    future::Future,
    io,
    os::unix::process::ExitStatusExt,
    process::ExitStatus,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    process::Child,
    signal::unix::{SignalKind, signal},
    sync::watch,
};

/// The first termination signal and the flag checked by synchronous install steps.
#[derive(Clone)]
pub(crate) struct Cancellation {
    /// Wake pending approval or enrollment as soon as the first signal arrives.
    received: watch::Sender<Option<Signal>>,
    /// Share the interruption state with a synchronous installer.
    flag: Arc<AtomicBool>,
}

impl Cancellation {
    /// Read the signal without waiting.
    pub(super) fn received(&self) -> Option<Signal> {
        *self.received.borrow()
    }

    /// Record the first signal from this process or an installer with the foreground terminal.
    fn record(&self, signal: Signal) {
        self.flag.store(true, Ordering::Release);
        self.received.send_if_modified(|received| {
            if received.is_some() {
                return false;
            }
            *received = Some(signal);
            true
        });
    }

    /// Recognize sudo replaying its child's termination as a signal or shell-style status.
    fn record_child_exit(&self, status: ExitStatus) {
        let raw = status
            .signal()
            .or_else(|| status.code().map(|code| code - 128));
        if let Some(signal @ (Signal::SIGINT | Signal::SIGHUP | Signal::SIGTERM)) =
            raw.and_then(|raw| Signal::try_from(raw).ok())
        {
            self.record(signal);
        }
    }

    /// Share an interruption flag with the installer during synchronous activation.
    pub(super) fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.flag)
    }

    /// Stop before the next synchronous publication or launchd operation.
    pub(super) fn check(&self) -> io::Result<()> {
        self.received().map_or(Ok(()), |_| Err(interrupted()))
    }

    /// Stop awaiting a cancellable operation once a signal arrives.
    pub(super) async fn during<T>(&self, work: impl Future<Output = T>) -> io::Result<T> {
        tokio::select! {
            biased;
            _ = self.wait() => Err(interrupted()),
            result = work => Ok(result),
        }
    }

    /// Wait for the first signal, including one received before this wait started.
    async fn wait(&self) -> Signal {
        let mut received = self.received.subscribe();
        let received = received.wait_for(Option::is_some).await;
        received
            .ok()
            .and_then(|value| *value)
            .unwrap_or(Signal::SIGTERM)
    }

    /// Stop a sudo prompt or installer and reap it before returning to rollback.
    ///
    /// Sudo forwards the signal to the installer. The installer owns any privileged
    /// rollback and must be allowed to finish, including during a service-manager call.
    pub(super) async fn wait_for_child(&self, child: &mut Child) -> io::Result<ExitStatus> {
        let status = tokio::select! {
            biased;
            result = child.wait() => result,
            signal = self.wait() => {
                if let Some(pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) {
                    let _ = kill(nix::unistd::Pid::from_raw(pid), signal);
                }
                child.wait().await
            }
        }?;
        self.record_child_exit(status);
        Ok(status)
    }

    /// Read consent through a foreground child that Ctrl-C can stop and reap.
    #[cfg(any(target_os = "macos", all(target_os = "linux", feature = "plugin-ssh")))]
    pub(super) async fn confirm_on_terminal(&self) -> bool {
        use std::process::Stdio;
        use tokio::io::AsyncReadExt;

        if self.check().is_err() {
            return false;
        }
        // Use a foreground child for the terminal read. Blocking stdin in the CLI
        // can resume its read after SIGINT and keep waiting instead of unwinding.
        let Ok(mut child) = tokio::process::Command::new("/bin/sh")
            .args(["-c", "IFS= read -r answer; printf '%s' \"$answer\""])
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .spawn()
        else {
            return false;
        };
        let Some(mut stdout) = child.stdout.take() else {
            let _ = child.kill().await;
            return false;
        };
        let mut answer = String::new();
        let (status, read) = tokio::join!(
            self.wait_for_child(&mut child),
            stdout.read_to_string(&mut answer),
        );
        status.is_ok_and(|status| status.success())
            && read.is_ok()
            && matches!(answer.trim(), "y" | "Y" | "yes" | "Yes")
            && self.received().is_none()
    }

    /// Explain the elevation just before starting a cancellable sudo password prompt.
    #[cfg(target_os = "macos")]
    pub(super) async fn sudo_status(
        &self,
        command: std::process::Command,
        prompt: infraternal_plugin_api::elevation_prompt::ElevationPrompt,
        json_output: bool,
    ) -> io::Result<ExitStatus> {
        if self.received().is_some() {
            return Err(interrupted());
        }
        prompt.print_to_stderr(json_output);
        let mut child = tokio::process::Command::from(command).spawn()?;
        self.wait_for_child(&mut child).await
    }
}

/// Abort the signal listener when the installation finishes, including on an error or panic.
struct Monitor(tokio::task::JoinHandle<()>);

impl Drop for Monitor {
    /// Do not retain a listener after its installation scope has returned.
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Explain interruption without exposing private enrollment input.
pub(super) fn interrupted() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "Machine installation interrupted.",
    )
}

/// Register termination handling before the operation can create installation paths.
///
/// The runtime worker records the first signal even during synchronous service-manager calls.
/// Later signals remain handled while rollback runs.
pub(super) fn scope<F: Future>(operation: impl FnOnce(Cancellation) -> F) -> io::Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut hangup = signal(SignalKind::hangup())?;
        let (received, _) = watch::channel(None);
        let cancelled = Cancellation {
            received,
            flag: Arc::new(AtomicBool::new(false)),
        };
        let observed = cancelled.clone();
        let _monitor = Monitor(tokio::spawn(async move {
            let first = tokio::select! {
                _ = terminate.recv() => Signal::SIGTERM,
                _ = interrupt.recv() => Signal::SIGINT,
                _ = hangup.recv() => Signal::SIGHUP,
            };
            observed.record(first);
            std::future::pending::<()>().await;
        }));
        Ok(operation(cancelled).await)
    })
}

/// Exercises actual process signals without changing the test runner's own signal handlers.
#[cfg(test)]
mod tests {
    use super::{Signal, kill};
    use std::{
        io::{BufRead, BufReader},
        os::unix::process::ExitStatusExt,
        process::{Command, Stdio},
    };

    /// Mark rollback so the parent can verify it ran before SIGINT ended the process.
    struct Rollback;

    impl Drop for Rollback {
        /// Publish the rollback marker after the pending stage was dropped.
        fn drop(&mut self) {
            println!("ROLLBACK");
        }
    }

    /// Exercise the command-level signal boundary in a separate process.
    #[test]
    #[ignore = "run only as a child process that the parent signals"]
    fn interrupted_join_child() {
        super::super::with_cancellation(
            |cancelled| async move {
                let _rollback = Rollback;
                println!("READY");
                cancelled
                    .during(std::future::pending::<()>())
                    .await
                    .unwrap_err();
                Err(super::super::Failure::Failed)
            },
            true,
        );
    }

    /// Ctrl-C in sudo's own terminal still reaches the caller's cancellation boundary.
    #[test]
    fn sudo_interrupt_status_is_observed_without_a_parent_signal() {
        super::scope(|cancelled| async move {
            let mut child = tokio::process::Command::new("/bin/sh")
                .args(["-c", "exit 130"])
                .spawn()
                .unwrap();
            assert_eq!(
                cancelled.wait_for_child(&mut child).await.unwrap().code(),
                Some(130)
            );
            assert_eq!(cancelled.received(), Some(Signal::SIGINT));
        })
        .unwrap();
    }

    /// Ctrl-C rolls back first, emits one JSON envelope, then stops the process by SIGINT.
    #[test]
    fn interrupted_join_rolls_back_before_emitting_and_exiting() {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "up::termination::tests::interrupted_join_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap())
            .lines()
            .map_while(Result::ok);
        assert!(lines.by_ref().any(|line| line.ends_with("READY")));
        kill(
            nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap()),
            Signal::SIGINT,
        )
        .unwrap();
        assert_eq!(lines.next().as_deref(), Some("ROLLBACK"));
        let result: serde_json::Value = serde_json::from_str(&lines.next().unwrap()).unwrap();
        assert_eq!(result["error"]["code"], "interrupted");
        assert!(lines.next().is_none());
        assert_eq!(child.wait().unwrap().signal(), Some(Signal::SIGINT as i32));
    }
}
