//! Runtime desktop component owns its helper process; disabling waits for native cleanup [D198,D201].
use crate::manifest::DESCRIPTOR;
use infraternal_plugin_api::{
    ComponentPlugin, PluginDescriptor, PluginOperation, PluginState, PluginStatus,
};
use std::os::unix::process::CommandExt;
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub struct DesktopComponent {
    runtime: PathBuf,
    executable: PathBuf,
    child: Arc<Mutex<Option<Child>>>,
    once: bool,
    companion_runtime: Option<PathBuf>,
}
impl DesktopComponent {
    #[must_use]
    pub fn new(runtime: PathBuf, executable: PathBuf) -> Self {
        Self {
            runtime,
            executable,
            child: Arc::new(Mutex::new(None)),
            once: false,
            companion_runtime: None,
        }
    }
    /// A trusted per-source executable exits after its one owned IPC client.
    /// Production construction is macOS-gated; explicit transport fixtures may
    /// supply a same-user helper executable on another Unix platform.
    #[must_use]
    pub fn one_shot(runtime: PathBuf, executable: PathBuf) -> Self {
        let mut component = Self::new(runtime, executable);
        component.once = true;
        component
    }
    /// Keep native permission approvals attached to one trusted, stable directory
    /// while each source leg gets its own private IPC endpoint.
    #[must_use]
    pub fn with_companion_runtime(mut self, runtime: PathBuf) -> Self {
        self.companion_runtime = Some(runtime);
        self
    }
}
impl ComponentPlugin for DesktopComponent {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    fn status(&self) -> PluginStatus {
        let state = self
            .child
            .lock()
            .map_or(PluginState::Stopping, |mut child| {
                child.as_mut().map_or(PluginState::Off, |child| {
                    if matches!(child.try_wait(), Ok(None)) {
                        PluginState::On
                    } else if group_present(child).unwrap_or(true) {
                        PluginState::Stopping
                    } else {
                        PluginState::Off
                    }
                })
            });
        PluginStatus {
            state,
            active_work: usize::from(state != PluginState::Off),
        }
    }
    fn set_enabled(&self, enabled: bool) -> PluginOperation<'_, ()> {
        let child = Arc::clone(&self.child);
        let runtime = self.runtime.clone();
        let executable = self.executable.clone();
        let once = self.once;
        let companion_runtime = self.companion_runtime.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                #[cfg(not(target_os = "macos"))]
                if enabled && !once {
                    return Err("Desktop capture requires a logged-in macOS session.");
                }
                let mut guard = child
                    .lock()
                    .map_err(|_| "Desktop component state is unavailable.")?;
                if enabled {
                    if guard
                        .as_mut()
                        .is_some_and(|child| matches!(child.try_wait(), Ok(None)))
                    {
                        return Ok(());
                    }
                    if let Some(child) = guard.as_mut() {
                        retire(child)?;
                    }
                    guard.take();
                    let mut command = Command::new(executable);
                    command.arg(runtime);
                    if once {
                        command.arg("--once");
                    }
                    if let Some(runtime) = companion_runtime {
                        command.arg("--companion-runtime").arg(runtime);
                    }
                    let child = command
                        .process_group(0)
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .map_err(|_| "Desktop helper could not start.")?;
                    *guard = Some(child);
                } else if let Some(child) = guard.as_mut() {
                    // Keep ownership after a partial failure so status and a later
                    // disable can still observe and retire the remaining group.
                    retire(child)?;
                    guard.take();
                }
                Ok(())
            })
            .await
            .map_err(|_| "Desktop lifecycle operation is unavailable.")?
        })
    }
}
fn group_id(child: &Child) -> Result<nix::unistd::Pid, &'static str> {
    i32::try_from(child.id())
        .map(nix::unistd::Pid::from_raw)
        .map_err(|_| "Desktop helper identity is unavailable.")
}
fn group_present(child: &Child) -> Result<bool, &'static str> {
    match nix::sys::signal::killpg(group_id(child)?, None) {
        Ok(()) => Ok(true),
        Err(nix::errno::Errno::ESRCH) => Ok(false),
        Err(_) => Err("Desktop process group could not be inspected."),
    }
}
fn retired(child: &mut Child) -> Result<bool, &'static str> {
    if child
        .try_wait()
        .map_err(|_| "Desktop helper could not be reaped.")?
        .is_none()
    {
        return Ok(false);
    }
    // Native children normally belong to the helper (or to the OS reaper after
    // it exits). Reap any adopted children in this group, never unrelated work.
    loop {
        match nix::sys::wait::waitpid(
            nix::unistd::Pid::from_raw(-group_id(child)?.as_raw()),
            Some(nix::sys::wait::WaitPidFlag::WNOHANG),
        ) {
            Ok(nix::sys::wait::WaitStatus::StillAlive) | Err(nix::errno::Errno::ECHILD) => break,
            Err(nix::errno::Errno::EINTR) | Ok(_) => {}
            Err(_) => return Err("Desktop native child could not be reaped."),
        }
    }
    Ok(!group_present(child)?)
}
fn retire(child: &mut Child) -> Result<(), &'static str> {
    if retired(child)? {
        return Ok(());
    }
    // Give the helper time to restore AX geometry and close companion stdin.
    // Its exit alone is insufficient: native children can outlive the leader.
    match nix::sys::signal::kill(group_id(child)?, nix::sys::signal::Signal::SIGTERM) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
        Err(_) => return Err("Desktop helper could not be stopped."),
    }
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        if retired(child)? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let restoration_unconfirmed = matches!(child.try_wait(), Ok(None));
    // Escalate for the whole owned group even when the helper already exited.
    match nix::sys::signal::killpg(group_id(child)?, nix::sys::signal::Signal::SIGKILL) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
        Err(_) => {
            return Err("Desktop cleanup partially failed; native children could not be stopped.");
        }
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if retired(child)? {
            return if restoration_unconfirmed {
                Err("Desktop cleanup timed out; window restoration could not be confirmed.")
            } else {
                Ok(())
            };
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("Desktop cleanup partially failed; process group retirement could not be confirmed.")
}

impl Drop for DesktopComponent {
    fn drop(&mut self) {
        if let Ok(mut state) = self.child.lock()
            && let Some(mut child) = state.take()
        {
            let _ = retire(&mut child);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn disabled_component_creates_no_helper_and_off_is_idempotent() {
        let component = DesktopComponent::new(
            PathBuf::from("missing-runtime"),
            PathBuf::from("missing-helper"),
        );
        assert_eq!(component.status().state, PluginState::Off);
        component.set_enabled(false).await.unwrap();
        component.set_enabled(false).await.unwrap();
        assert_eq!(component.status().active_work, 0);
        #[cfg(not(target_os = "macos"))]
        assert!(component.set_enabled(true).await.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn disabling_after_helper_exit_retires_remaining_native_children() {
        use nix::{
            sys::signal::{Signal, kill},
            unistd::Pid,
        };
        use std::io::{BufRead, BufReader};

        // A stopped main process does not prove that its native framework children
        // have retired. The child blocks in a syscall and uses no CPU load loop.
        nix::sys::prctl::set_child_subreaper(true).unwrap();
        let program = r"import os, signal
ready_read, ready_write = os.pipe()
child = os.fork()
if child == 0:
    os.close(ready_read)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.write(ready_write, b'1')
    os.close(ready_write)
    signal.pause()
else:
    os.close(ready_write)
    os.read(ready_read, 1)
    os.close(ready_read)
    print(child, flush=True)
    signal.pause()
";
        let mut helper = Command::new("python3")
            .args(["-c", program])
            .process_group(0)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let group = i32::try_from(helper.id()).unwrap();
        let mut line = String::new();
        BufReader::new(helper.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let native_pid = Pid::from_raw(line.trim().parse().unwrap());
        let component = DesktopComponent::new(PathBuf::new(), PathBuf::new());
        *component.child.lock().unwrap() = Some(helper);
        // This fixture drives one component; do not require a multi-thread runtime
        // feature in the production dependency just to run its shutdown test.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(component.set_enabled(false));
        let native_still_present = std::fs::read_to_string(format!("/proc/{native_pid}/stat"))
            .is_ok_and(|stat| {
                stat.split_once(") ")
                    .is_some_and(|(_, state)| !state.starts_with('Z'))
            });
        // Always retire the fixture before asserting, including the failing path.
        let _ = kill(Pid::from_raw(-group), Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(native_pid, None);
        nix::sys::prctl::set_child_subreaper(false).unwrap();
        assert!(result.is_ok(), "disable result: {result:?}");
        assert_eq!(component.status().state, PluginState::Off);
        assert!(
            !native_still_present,
            "component is off but its native child still exists after helper exit"
        );
    }
}
