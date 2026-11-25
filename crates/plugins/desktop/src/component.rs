//! Runtime desktop component owns its helper process; disabling waits for native cleanup [D198,D201].
//!
//! [`DesktopComponent`] implements the plugin API's `ComponentPlugin` for the
//! desktop helper. Enabling spawns the helper executable in its own process
//! group; disabling retires the whole group: SIGTERM first, up to 12 seconds for
//! the helper to restore any window geometry it changed, then SIGKILL, and
//! only then does it report success. Waiting on the whole group matters because
//! native child processes can outlive the helper itself.
//!
//! A root infraternal agent starts its one-shot helpers as the console user
//! ([`DesktopComponent::for_console_user`], D203 C2): through the shim's
//! placement entry, with a cleared environment that carries only the capture
//! app's path and the capture-callback timeout, and with the one-time token
//! written to the helper's standard input. Root may signal that user's
//! process group, so retirement is unchanged.
use crate::{cross_user::Launch, manifest::DESCRIPTOR};
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

/// The desktop helper as a switchable component. Dropping it retires the helper.
pub struct DesktopComponent {
    /// Private runtime directory passed to the helper as its first argument.
    runtime: PathBuf,
    /// Helper executable to launch.
    executable: PathBuf,
    /// The running helper, if any. Kept after a failed disable so that status and
    /// a later disable can still see the leftover process group.
    child: Arc<Mutex<Option<Child>>>,
    /// Pass `--once`: the helper exits after serving a single connection.
    once: bool,
    /// Passed as `--companion-runtime` when set.
    companion_runtime: Option<PathBuf>,
    /// Set by a root agent: start the helper as the console user.
    console_user: Option<ConsoleLaunch>,
}
/// What a root agent needs to start one helper as the console user.
#[derive(Clone)]
struct ConsoleLaunch {
    /// Builds the placement command for `uid`.
    launch: Launch,
    /// The console user's uid.
    uid: u32,
    /// The one-time token, written to the helper's standard input.
    token: [u8; 32],
    /// The capture app's executable inside its signed bundle.
    companion: PathBuf,
}
impl DesktopComponent {
    /// A long-running component: the helper serves connections until disabled.
    /// `runtime` is the private directory for its socket; `executable` is the
    /// helper binary. Nothing is started until `set_enabled(true)`.
    #[must_use]
    pub fn new(runtime: PathBuf, executable: PathBuf) -> Self {
        Self {
            runtime,
            executable,
            child: Arc::new(Mutex::new(None)),
            once: false,
            companion_runtime: None,
            console_user: None,
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
    /// Start the helper as the console user `uid` (a root agent, D203 C2).
    /// The helper is told `--daemon-peer`: it reads `token` from standard
    /// input, admits only root as its client, and sends the token first.
    #[cfg(feature = "source")]
    #[must_use]
    pub(crate) fn for_console_user(
        mut self,
        cross: &crate::cross_user::CrossUser,
        uid: u32,
        token: [u8; 32],
    ) -> Self {
        self.console_user = Some(ConsoleLaunch {
            launch: cross.launch.clone(),
            uid,
            token,
            companion: cross.companion.clone(),
        });
        self
    }
}
impl ComponentPlugin for DesktopComponent {
    /// The static description of the desktop plugin.
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    /// `On` while the helper runs, `Stopping` when it has exited but its process
    /// group still has members (or state cannot be read), otherwise `Off`.
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
    /// Starts or stops the helper on a blocking thread.
    ///
    /// Enabling is a no-op if the helper already runs; a dead one is retired
    /// before a new one is spawned (stdio closed, own process group). On
    /// non-macOS systems only one-shot components can be enabled. Disabling a
    /// component that is off succeeds, so it is safe to repeat. Errors are fixed
    /// user-safe messages; a failed disable keeps the child so it can be retried.
    fn set_enabled(&self, enabled: bool) -> PluginOperation<'_, ()> {
        let child = Arc::clone(&self.child);
        let runtime = self.runtime.clone();
        let executable = self.executable.clone();
        let once = self.once;
        let companion_runtime = self.companion_runtime.clone();
        let console_user = self.console_user.clone();
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
                    let mut command = match &console_user {
                        Some(console) => {
                            let mut command = (console.launch)(console.uid)
                                .map_err(|_| "Desktop helper could not start.")?;
                            command
                                .arg(&executable)
                                .env("INFRATERNAL_DESKTOP_COMPANION", &console.companion)
                                // Set here so the helper never re-executes
                                // itself to add it (helper.rs main).
                                .env("SCREENCAPTUREKIT_COMPLETION_TIMEOUT_SECS", "3");
                            command
                        }
                        None => Command::new(executable),
                    };
                    command.arg(runtime);
                    if once {
                        command.arg("--once");
                    }
                    if let Some(runtime) = companion_runtime {
                        command.arg("--companion-runtime").arg(runtime);
                    }
                    if console_user.is_some() {
                        command.arg("--daemon-peer");
                    }
                    let mut child = command
                        .process_group(0)
                        .stdin(if console_user.is_some() {
                            Stdio::piped()
                        } else {
                            Stdio::null()
                        })
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .map_err(|_| "Desktop helper could not start.")?;
                    if let Some(console) = &console_user {
                        // 32 bytes fit any pipe buffer, so this never blocks;
                        // closing the pipe tells the helper the token is whole.
                        let written = child.stdin.take().ok_or(()).and_then(|mut input| {
                            std::io::Write::write_all(&mut input, &console.token).map_err(|_| ())
                        });
                        if written.is_err() {
                            retire(&mut child)?;
                            return Err("Desktop helper could not start.");
                        }
                    }
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
/// The child's process-group id. It equals the child's pid because the child is
/// spawned as its own group leader.
fn group_id(child: &Child) -> Result<nix::unistd::Pid, &'static str> {
    i32::try_from(child.id())
        .map(nix::unistd::Pid::from_raw)
        .map_err(|_| "Desktop helper identity is unavailable.")
}
/// True if any process is still in the child's process group (probed with
/// signal 0, which sends nothing).
fn group_present(child: &Child) -> Result<bool, &'static str> {
    match nix::sys::signal::killpg(group_id(child)?, None) {
        Ok(()) => Ok(true),
        Err(nix::errno::Errno::ESRCH) => Ok(false),
        Err(_) => Err("Desktop process group could not be inspected."),
    }
}
/// Non-blocking check: has the helper exited and its whole group disappeared?
/// Also reaps any leftover zombie members of the group. Returns `false` while
/// the helper still runs or group members remain.
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
/// Stops the helper's whole process group and waits until it is gone.
///
/// Sends SIGTERM and polls for up to 12 seconds, then SIGKILL and polls for up
/// to 3 more. If the helper had to be killed while still alive, success is
/// downgraded to an error, because the helper never confirmed that it restored
/// window geometry.
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

/// Tests the desktop plugin's helper lifecycle and native-child cleanup.
#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes Linux tests that temporarily make this process a child subreaper.
    #[cfg(target_os = "linux")]
    static NATIVE_CHILD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Owns the helper and forked child used to test native-process retirement.
    /// Dropping the fixture kills and reaps the whole group, including when a
    /// test panics before it reaches its ordinary assertions.
    #[cfg(target_os = "linux")]
    struct NativeChildFixture {
        group: Option<nix::unistd::Pid>,
        helper: Option<Child>,
        native_pid: Option<nix::unistd::Pid>,
        subreaper: bool,
    }

    #[cfg(target_os = "linux")]
    impl NativeChildFixture {
        /// Start a private helper group whose native child ignores SIGTERM.
        fn start() -> Self {
            use nix::unistd::Pid;
            use std::io::{BufRead, BufReader};

            let mut fixture = Self {
                group: None,
                helper: None,
                native_pid: None,
                subreaper: false,
            };
            nix::sys::prctl::set_child_subreaper(true).unwrap();
            fixture.subreaper = true;
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
            let helper = Command::new("python3")
                .args(["-c", program])
                .process_group(0)
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            fixture.group = Some(Pid::from_raw(i32::try_from(helper.id()).unwrap()));
            fixture.helper = Some(helper);

            let mut line = String::new();
            BufReader::new(
                fixture
                    .helper
                    .as_mut()
                    .expect("the helper was just started")
                    .stdout
                    .take()
                    .expect("the fixture captures the helper's child id"),
            )
            .read_line(&mut line)
            .unwrap();
            fixture.native_pid = Some(Pid::from_raw(line.trim().parse().unwrap()));
            fixture
        }

        /// Return the id of the SIGTERM-ignoring native child.
        fn native_pid(&self) -> nix::unistd::Pid {
            self.native_pid.expect("the native child was started")
        }

        /// Return the private process group that owns both fixture processes.
        fn group_id(&self) -> nix::unistd::Pid {
            self.group.expect("the helper process group was started")
        }

        /// Transfer the main helper to `DesktopComponent` while retaining group cleanup.
        fn take_helper(&mut self) -> Child {
            self.helper
                .take()
                .expect("the helper is still owned by the fixture")
        }

        /// Kill and reap the private process group, then restore this process's subreaper flag.
        fn cleanup(&mut self) {
            if let Some(group) = self.group.take() {
                let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
                if let Some(mut helper) = self.helper.take() {
                    let _ = helper.kill();
                    let _ = helper.wait();
                }
                loop {
                    match nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(-group.as_raw()), None)
                    {
                        Ok(nix::sys::wait::WaitStatus::StillAlive) => std::thread::yield_now(),
                        Ok(_) | Err(nix::errno::Errno::EINTR) => {}
                        Err(_) => break,
                    }
                }
            }
            if self.subreaper {
                let _ = nix::sys::prctl::set_child_subreaper(false);
                self.subreaper = false;
            }
        }
    }

    /// Reap the fixture on normal return and during panic unwinding.
    #[cfg(target_os = "linux")]
    impl Drop for NativeChildFixture {
        fn drop(&mut self) {
            self.cleanup();
        }
    }
    /// An absent helper stays off, and repeated disables remain harmless.
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

    /// Disabling the component retires its helper and every forked native child.
    #[cfg(target_os = "linux")]
    #[test]
    fn disabling_after_helper_exit_retires_remaining_native_children() {
        let _lock = NATIVE_CHILD_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // A stopped main process does not prove that its native framework children
        // have retired. The child blocks in a syscall and uses no CPU load loop.
        let mut fixture = NativeChildFixture::start();
        let native_pid = fixture.native_pid();
        let component = DesktopComponent::new(PathBuf::new(), PathBuf::new());
        *component.child.lock().unwrap() = Some(fixture.take_helper());
        // This fixture drives one component; do not require a multi-thread runtime
        // feature in the production dependency just to run its shutdown test.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(component.set_enabled(false));
        let native_still_present = std::path::Path::new(&format!("/proc/{native_pid}")).exists();
        let state = component.status().state;
        drop(component);
        fixture.cleanup();
        assert!(result.is_ok(), "disable result: {result:?}");
        assert_eq!(state, PluginState::Off);
        assert!(
            !native_still_present,
            "component is off but its native child was not reaped after helper exit"
        );
    }

    /// The test fixture must retire its native child even when its body unwinds.
    #[cfg(target_os = "linux")]
    #[test]
    fn interrupted_fixture_reaps_native_children() {
        use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

        let _lock = NATIVE_CHILD_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let spawned: Result<(), _> = catch_unwind(AssertUnwindSafe(|| {
            let fixture = NativeChildFixture::start();
            resume_unwind(Box::new((fixture.group_id(), fixture.native_pid())));
        }));
        let payload = spawned.expect_err("fixture unexpectedly returned without unwinding");
        let (group, native_pid) = *payload
            .downcast::<(nix::unistd::Pid, nix::unistd::Pid)>()
            .unwrap();
        let native_still_present = std::path::Path::new(&format!("/proc/{native_pid}")).exists();
        if native_still_present {
            // Keep a broken guard from leaving a second orphan during its red run.
            let _ = nix::sys::prctl::set_child_subreaper(true);
            let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(-group.as_raw()), None);
            let _ = nix::sys::wait::waitpid(native_pid, None);
            let _ = nix::sys::prctl::set_child_subreaper(false);
        }
        assert!(
            !native_still_present,
            "unwinding the helper fixture left its native child unreaped"
        );
    }
}
