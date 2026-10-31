//! Owns the `LaunchServices` companion channel with bounded I/O and process cleanup [D203,#146].
use crate::protocol::{self, Kind};
use std::{
    fs,
    io::{self, Read, Write},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(all(target_os = "macos", not(test)))]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixListener;
#[cfg(any(not(target_os = "macos"), test))]
use std::process::ChildStdin;

type Reply = io::Result<(Kind, Vec<u8>)>;

trait CompanionInput: Write + Send {
    fn poll_fd(&self) -> BorrowedFd<'_>;
    fn write_nonblocking(&mut self, bytes: &[u8]) -> io::Result<usize>;
    fn close_write(&self);
}

#[cfg(any(not(target_os = "macos"), test))]
impl CompanionInput for ChildStdin {
    fn poll_fd(&self) -> BorrowedFd<'_> {
        self.as_fd()
    }
    fn write_nonblocking(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write(bytes)
    }
    fn close_write(&self) {}
}

impl CompanionInput for UnixStream {
    fn poll_fd(&self) -> BorrowedFd<'_> {
        self.as_fd()
    }
    fn write_nonblocking(&mut self, bytes: &[u8]) -> io::Result<usize> {
        nix::sys::socket::send(
            self.as_raw_fd(),
            bytes,
            nix::sys::socket::MsgFlags::MSG_DONTWAIT,
        )
        .map_err(io::Error::from)
    }
    fn close_write(&self) {
        let _ = self.shutdown(std::net::Shutdown::Write);
    }
}

struct CompanionLaunch {
    launcher: Child,
    // Only `LaunchServices`-owned bundles publish a separate process identity.
    companion_pid: Option<u32>,
}

struct SpawnedCompanion {
    launch: CompanionLaunch,
    input: Box<dyn CompanionInput>,
    output: Box<dyn Read + Send>,
    private_directory: Option<PrivateDirectory>,
}

struct PrivateDirectory(PathBuf);

impl PrivateDirectory {
    #[cfg(target_os = "macos")]
    fn create() -> io::Result<Self> {
        let path = nix::unistd::mkdtemp("/tmp/it-c-XXXXXX")?;
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o700)) {
            let _ = fs::remove_dir(&path);
            return Err(error);
        }
        Ok(Self(path))
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(any(not(target_os = "macos"), test))]
fn spawn_direct(executable: &Path, encoder: bool, surface: bool) -> io::Result<SpawnedCompanion> {
    // Scripted pipe companions are used by crate tests only. Production macOS
    // builds take the LaunchServices path below so ScreenCaptureKit always runs
    // as the installed app bundle.
    let mut command = Command::new(executable);
    if encoder {
        command.arg("--encoder");
    }
    if surface {
        command.arg("--surface-capture");
    }
    let mut launcher = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let input = launcher
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("Desktop companion input unavailable."))?;
    // Bound writes as well as replies: a full pixel packet must not hold the
    // capture worker past its operation deadline.
    let flags = nix::fcntl::fcntl(input.as_fd(), nix::fcntl::FcntlArg::F_GETFL)?;
    nix::fcntl::fcntl(
        input.as_fd(),
        nix::fcntl::FcntlArg::F_SETFL(
            nix::fcntl::OFlag::from_bits_truncate(flags) | nix::fcntl::OFlag::O_NONBLOCK,
        ),
    )?;
    let output = launcher
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("Desktop companion output unavailable."))?;
    Ok(SpawnedCompanion {
        launch: CompanionLaunch {
            launcher,
            companion_pid: None,
        },
        input: Box::new(input),
        output: Box::new(output),
        private_directory: None,
    })
}

/// Return the containing signed app bundle for its fixed companion executable.
///
/// The helper refuses a loose extracted executable: TCC must see the installed
/// bundle `LaunchServices` starts, with the identity that owns the user's grants.
///
/// # Errors
/// Returns an error if the executable does not occupy the fixed companion path inside a bundle.
pub fn companion_app_bundle(executable: &Path) -> io::Result<PathBuf> {
    let macos = executable
        .parent()
        .ok_or_else(|| io::Error::other("Desktop companion must live inside its app bundle."))?;
    let contents = macos
        .parent()
        .ok_or_else(|| io::Error::other("Desktop companion must live inside its app bundle."))?;
    let bundle = contents
        .parent()
        .ok_or_else(|| io::Error::other("Desktop companion must live inside its app bundle."))?;
    if !executable.is_absolute()
        || executable
            .file_name()
            .is_none_or(|name| name != "InfraternalCaptureHelper")
        || macos.file_name().is_none_or(|name| name != "MacOS")
        || contents.file_name().is_none_or(|name| name != "Contents")
        || bundle
            .file_name()
            .is_none_or(|name| name != "InfraternalCaptureHelper.app")
        || bundle
            .extension()
            .is_none_or(|extension| extension != "app")
        || !contents.join("Info.plist").is_file()
    {
        return Err(io::Error::other(
            "Desktop capture requires the signed InfraternalCaptureHelper.app bundle.",
        ));
    }
    Ok(bundle.to_owned())
}

#[cfg(target_os = "macos")]
/// # Errors
/// Returns an error if `LaunchServices` fails, the companion exits, or its privacy state is invalid.
pub fn check_permissions(executable: &Path) -> io::Result<Vec<u8>> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let bundle = companion_app_bundle(executable)?;
    let private_directory = PrivateDirectory::create()?;
    let output_path = private_directory.0.join("o");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&output_path)?;
    let status = Command::new("/usr/bin/open")
        .args(["-n", "-W", "-g", "--stdin", "/dev/null", "--stdout"])
        .arg(&output_path)
        .args(["--stderr", "/dev/null"])
        .arg(&bundle)
        .arg("--args")
        .arg("--check-permissions")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other(
            "LaunchServices could not check desktop companion permissions.",
        ));
    }
    let output = fs::read(output_path)?;
    let permissions: serde_json::Value = serde_json::from_slice(&output)?;
    let Some(fields) = permissions.as_object() else {
        return Err(io::Error::other(
            "Desktop permission check returned invalid data.",
        ));
    };
    if fields.len() != 2
        || !fields.contains_key("device_control")
        || !fields.contains_key("screen_recording")
        || !fields.values().all(serde_json::Value::is_boolean)
    {
        return Err(io::Error::other(
            "Desktop permission check returned invalid data.",
        ));
    }
    Ok(output)
}

#[cfg(all(target_os = "macos", not(test)))]
fn read_companion_pid(path: &Path) -> io::Result<Option<u32>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Desktop companion launch identity is not private.",
        ));
    }
    parse_companion_pid(&fs::read_to_string(path)?, std::process::id())
}

fn parse_companion_pid(contents: &str, current_pid: u32) -> io::Result<Option<u32>> {
    // The companion publishes a newline only after its complete PID is written.
    // Ignore a partial file so cleanup can never signal a PID prefix.
    let Some(value) = contents.strip_suffix('\n') else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    let pid = value
        .parse::<u32>()
        .map_err(|_| io::Error::other("Desktop companion launch identity is invalid."))?;
    if pid <= 1 || pid == current_pid {
        return Err(io::Error::other(
            "Desktop companion launch identity is invalid.",
        ));
    }
    Ok(Some(pid))
}

#[cfg(all(target_os = "macos", not(test)))]
fn launch_services_command(
    bundle: &Path,
    socket_path: &Path,
    pid_path: &Path,
    measure: bool,
    encoder: bool,
    surface: bool,
) -> Command {
    let mut command = Command::new("/usr/bin/open");
    command.args([
        "-n",
        "-W",
        "-g",
        "--stdin",
        "/dev/null",
        "--stdout",
        "/dev/null",
    ]);
    if measure {
        command.arg("--env").arg("INFRATERNAL_DESKTOP_MEASURE=1");
        command.args(["--stderr", "/dev/fd/2"]);
    } else {
        command.args(["--stderr", "/dev/null"]);
    }
    command
        .arg(bundle)
        .arg("--args")
        .arg("--socket")
        .arg(socket_path)
        .arg("--launch-pid-file")
        .arg(pid_path);
    if encoder {
        command.arg("--encoder");
    }
    if surface {
        command.arg("--surface-capture");
    }
    command
}

#[cfg(target_os = "macos")]
#[cfg_attr(test, allow(dead_code))]
fn accept_blocking(listener: &UnixListener) -> io::Result<Option<UnixStream>> {
    match listener.accept() {
        Ok((stream, _)) => {
            // Darwin inherits O_NONBLOCK from this listener; protocol reads run
            // on a blocking reader thread and would otherwise fail with EAGAIN.
            stream.set_nonblocking(false)?;
            Ok(Some(stream))
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(all(target_os = "macos", not(test)))]
fn update_companion_pid(
    pid_path: &Path,
    companion_pid: &mut Option<u32>,
    pid_ready_ms: &mut Option<f64>,
    started: Instant,
) -> io::Result<()> {
    if companion_pid.is_none() {
        let pid = read_companion_pid(pid_path)?;
        if pid.is_some() && pid_ready_ms.is_none() {
            *pid_ready_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
        }
        *companion_pid = pid;
    }
    Ok(())
}

#[cfg(all(target_os = "macos", not(test)))]
fn accept_launch_connection(
    listener: &UnixListener,
    pid_path: &Path,
    companion_pid: &mut Option<u32>,
    pid_ready_ms: &mut Option<f64>,
    started: Instant,
    measure: bool,
) -> io::Result<Option<(UnixStream, u32)>> {
    update_companion_pid(pid_path, companion_pid, pid_ready_ms, started)?;
    let Some(stream) = accept_blocking(listener)? else {
        return Ok(None);
    };
    crate::socket::admit(&stream)?;
    update_companion_pid(pid_path, companion_pid, pid_ready_ms, started)?;
    let Some(pid) = *companion_pid else {
        return Err(io::Error::other(
            "Desktop companion did not publish its launch identity.",
        ));
    };
    if measure {
        eprintln!(
            "METRIC launch_services pid={pid} launch_ms={:.3}",
            (*pid_ready_ms).unwrap_or_else(|| started.elapsed().as_secs_f64() * 1000.0)
        );
    }
    Ok(Some((stream, pid)))
}

#[cfg(all(target_os = "macos", not(test)))]
fn spawn_via_launch_services(
    executable: &Path,
    encoder: bool,
    surface: bool,
) -> io::Result<SpawnedCompanion> {
    let bundle = companion_app_bundle(executable)?;
    let private_directory = PrivateDirectory::create()?;
    let socket_path = private_directory.0.join("s");
    let pid_path = private_directory.0.join("p");
    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;

    let measure = std::env::var_os("INFRATERNAL_DESKTOP_MEASURE").is_some();
    let started = Instant::now();
    let mut launcher =
        launch_services_command(&bundle, &socket_path, &pid_path, measure, encoder, surface)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(if measure {
                Stdio::inherit()
            } else {
                Stdio::null()
            })
            .spawn()?;

    let mut companion_pid = None;
    let mut pid_ready_ms = None;
    loop {
        match accept_launch_connection(
            &listener,
            &pid_path,
            &mut companion_pid,
            &mut pid_ready_ms,
            started,
            measure,
        ) {
            Ok(Some((stream, pid))) => {
                let input = match stream.try_clone() {
                    Ok(input) => Box::new(input) as Box<dyn CompanionInput>,
                    Err(error) => {
                        drop(stream);
                        retire_launch_services(launcher, Some(pid));
                        return Err(error);
                    }
                };
                return Ok(SpawnedCompanion {
                    launch: CompanionLaunch {
                        launcher,
                        companion_pid: Some(pid),
                    },
                    input,
                    output: Box::new(stream),
                    private_directory: Some(private_directory),
                });
            }
            Ok(None) => {}
            Err(error) => {
                retire_launch_services(launcher, companion_pid);
                return Err(error);
            }
        }
        match launcher.try_wait() {
            Ok(Some(_)) => {
                return Err(io::Error::other(
                    "LaunchServices exited before the desktop companion connected.",
                ));
            }
            Ok(None) => {}
            Err(error) => {
                retire_launch_services(launcher, companion_pid);
                return Err(error);
            }
        }
        if started.elapsed() >= std::time::Duration::from_secs(5) {
            retire_launch_services(launcher, companion_pid);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "LaunchServices did not start the desktop companion in time.",
            ));
        }
        thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(all(target_os = "macos", not(test)))]
fn retire_launch_services(mut launcher: Child, companion_pid: Option<u32>) {
    let mut deadline = Instant::now() + std::time::Duration::from_secs(3);
    while matches!(launcher.try_wait(), Ok(None)) && Instant::now() < deadline {
        thread::sleep(std::time::Duration::from_millis(10));
    }
    if !matches!(launcher.try_wait(), Ok(Some(_))) {
        if let Some(pid) = companion_pid.and_then(|pid| i32::try_from(pid).ok()) {
            let process = nix::unistd::Pid::from_raw(pid);
            let _ = nix::sys::signal::kill(process, nix::sys::signal::Signal::SIGTERM);
            deadline = Instant::now() + std::time::Duration::from_millis(500);
            while matches!(launcher.try_wait(), Ok(None)) && Instant::now() < deadline {
                thread::sleep(std::time::Duration::from_millis(10));
            }
            if matches!(launcher.try_wait(), Ok(None)) {
                let _ = nix::sys::signal::kill(process, nix::sys::signal::Signal::SIGKILL);
            }
        }
        let _ = launcher.kill();
    }
    let _ = launcher.wait();
}

pub struct Native {
    child: Option<CompanionLaunch>,
    _private_directory: Option<PrivateDirectory>,
    input: Option<Box<dyn CompanionInput>>,
    replies: Option<Receiver<Reply>>,
    reader: Option<JoinHandle<()>>,
    cancellation: Option<Arc<AtomicBool>>,
    retirement: Option<JoinHandle<()>>,
    encoder: bool,
    surface: bool,
    video: Option<Vec<u8>>,
    video_gap: bool,
}
impl Native {
    /// # Errors
    /// Reports launch failure or an unavailable companion channel.
    pub fn spawn(executable: &Path) -> io::Result<Self> {
        Self::spawn_mode(executable, false, false)
    }
    /// # Errors
    /// Starts only encoding; it cannot create a control indicator or inject input.
    pub fn spawn_encoder(executable: &Path) -> io::Result<Self> {
        Self::spawn_mode(executable, true, false)
    }
    /// # Errors
    /// Starts same-process companion capture, keeping H.264 on the public path.
    pub fn spawn_surface(executable: &Path) -> io::Result<Self> {
        Self::spawn_mode(executable, false, true)
    }
    fn spawn_mode(executable: &Path, encoder: bool, surface: bool) -> io::Result<Self> {
        #[cfg(all(target_os = "macos", not(test)))]
        let spawned = spawn_via_launch_services(executable, encoder, surface)?;
        #[cfg(any(not(target_os = "macos"), test))]
        let spawned = spawn_direct(executable, encoder, surface)?;

        let SpawnedCompanion {
            launch,
            input,
            mut output,
            private_directory,
        } = spawned;
        let (sender, replies) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            loop {
                let reply = protocol::read(&mut output);
                let failed = reply.is_err();
                // Once the receiver is sealed, drain final replies until EOF.
                // Keeping stdout open lets control cleanup finish without SIGPIPE.
                let _ = sender.send(reply);
                if failed {
                    break;
                }
            }
        });
        Ok(Self {
            child: Some(launch),
            _private_directory: private_directory,
            input: Some(input),
            replies: Some(replies),
            reader: Some(reader),
            cancellation: None,
            retirement: None,
            encoder,
            surface,
            video: None,
            video_gap: false,
        })
    }
    /// Stop in-flight writes/replies when the owning capture worker is cancelled.
    pub fn cancel_on(&mut self, cancellation: Arc<AtomicBool>) {
        self.cancellation = Some(cancellation);
    }
    /// Whether a failed exchange has sealed this companion and requires relaunch.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.input.is_none() || self.child.is_none()
    }
    /// # Errors
    /// Reports companion errors or a three-second deadline covering write and reply.
    pub fn call(&mut self, kind: Kind, payload: &[u8]) -> Reply {
        let deadline = Instant::now() + Duration::from_secs(3);
        let result = protocol::write(&mut self.writer(deadline)?, kind, payload);
        if let Err(error) = result {
            self.stop_now();
            return Err(error);
        }
        self.response(deadline, !self.encoder)
    }
    /// # Errors
    /// Requires one bounded owned BGRA image and a responsive encoder.
    pub fn encode(
        &mut self,
        pixels: &[u8],
        width: u32,
        height: u32,
        capture_ticks: u64,
        sharp: bool,
    ) -> Reply {
        if u64::from(width) * u64::from(height) > 4 * 1024 * 1024
            || pixels.len() as u64 != u64::from(width) * u64::from(height) * 4
        {
            return Err(io::Error::other("Desktop pixel bounds exceeded."));
        }
        let metadata = serde_json::to_vec(
            &serde_json::json!({"width":width,"height":height,"capture_ticks":capture_ticks,"sharp":sharp}),
        )?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let length = u32::try_from(2 + 4 + metadata.len() + pixels.len())
            .map_err(|_| io::Error::other("Desktop pixel bounds exceeded."))?;
        let meta_length = u32::try_from(metadata.len())
            .map_err(|_| io::Error::other("Desktop pixel bounds exceeded."))?;
        let result = (|| {
            let mut input = self.writer(deadline)?;
            input.write_all(&length.to_be_bytes())?;
            input.write_all(&[protocol::VERSION, 101])?;
            input.write_all(&meta_length.to_be_bytes())?;
            input.write_all(&metadata)?;
            input.write_all(pixels)
        })();
        if let Err(error) = result {
            // A partial packet cannot be reused. Cancellation must also release
            // the child before Worker::drop joins the capture thread.
            self.stop_now();
            return Err(error);
        }
        self.response(deadline, false)
    }
    fn writer(&mut self, deadline: Instant) -> io::Result<DeadlineWriter<'_>> {
        let input = self
            .input
            .as_mut()
            .map(Box::as_mut)
            .ok_or_else(|| io::Error::other("Desktop companion stopped."))?;
        Ok(DeadlineWriter {
            input,
            deadline,
            cancellation: self.cancellation.as_deref(),
        })
    }
    fn stop_now(&mut self) {
        self.replies.take();
        if let Some(input) = self.input.take() {
            input.close_write();
        }
        if self
            .child
            .as_ref()
            .is_some_and(|launch| launch.companion_pid.is_some())
        {
            if let Some(launch) = self.child.take() {
                self.retirement = Some(thread::spawn(move || retire_owned(launch)));
            }
        } else if let Some(launch) = self.child.as_mut() {
            let _ = launch.launcher.kill();
        }
    }
    fn retire_control(&mut self) {
        self.replies.take();
        if let Some(input) = self.input.take() {
            input.close_write();
        }
        if let Some(launch) = self.child.take() {
            // Seal the old exchange immediately, but preserve EOF restoration.
            // Cleanup runs outside the operation deadline and remains owned:
            // Drop joins it before the helper can report complete shutdown.
            self.retirement = Some(thread::spawn(move || retire_owned(launch)));
        }
    }
    fn response(&mut self, deadline: Instant, graceful: bool) -> Reply {
        let reply = loop {
            match self.receive_response(deadline) {
                Ok((Kind::Video, body)) if self.surface => {
                    // A newer IDR repairs any skipped references. Replacing an
                    // encoded frame with a delta cannot hide the gap from the
                    // worker: private video has no sequence numbers of its own.
                    if body.get(8) == Some(&1) {
                        self.video_gap = false;
                    } else {
                        self.video_gap |= self.video.is_some();
                    }
                    self.video = Some(body);
                }
                reply => break reply,
            }
        };
        if reply.is_err() {
            // The private protocol has no request IDs. Once a request fails,
            // queued or delayed replies must never answer a subsequent command.
            if graceful
                && !reply
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::ConnectionAborted)
            {
                self.retire_control();
            } else {
                self.stop_now();
            }
        }
        reply
    }
    /// An overwritten encoded delta requires a new IDR at the forwarding boundary.
    pub fn take_surface_gap(&mut self) -> bool {
        std::mem::take(&mut self.video_gap)
    }
    /// # Errors
    /// Returns only native video; bounded idle waits let the owning worker observe retirement.
    pub fn surface_video(&mut self) -> io::Result<Option<Vec<u8>>> {
        if let Some(video) = self.video.take() {
            return Ok(Some(video));
        }
        match self.receive_response(Instant::now() + Duration::from_millis(100)) {
            Ok((Kind::Video, body)) => Ok(Some(body)),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => Ok(None),
            _ => {
                self.stop_now();
                Err(io::Error::other("Desktop surface capture unavailable."))
            }
        }
    }
    fn receive_response(&self, deadline: Instant) -> Reply {
        let replies = self
            .replies
            .as_ref()
            .ok_or_else(|| io::Error::other("Desktop companion stopped."))?;
        loop {
            let timeout = remaining(deadline, self.cancellation.as_deref())?;
            match replies.recv_timeout(timeout) {
                Ok(reply) => return reply,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Desktop companion stopped.",
                    ));
                }
            }
        }
    }
}

fn remaining(deadline: Instant, cancellation: Option<&AtomicBool>) -> io::Result<Duration> {
    if cancellation.is_some_and(|stop| stop.load(Ordering::Acquire)) {
        // write_all retries Interrupted automatically; cancellation must end it.
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "Desktop capture stopped.",
        ));
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Desktop companion operation timed out.",
        ));
    }
    Ok(if cancellation.is_some() {
        remaining.min(Duration::from_millis(20))
    } else {
        remaining
    })
}

struct DeadlineWriter<'a> {
    input: &'a mut dyn CompanionInput,
    deadline: Instant,
    cancellation: Option<&'a AtomicBool>,
}
impl Write for DeadlineWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            let timeout = remaining(self.deadline, self.cancellation)?;
            match self.input.write_nonblocking(bytes) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut ready = [nix::poll::PollFd::new(
                        self.input.poll_fd(),
                        nix::poll::PollFlags::POLLOUT,
                    )];
                    let timeout =
                        nix::poll::PollTimeout::try_from(timeout).map_err(io::Error::other)?;
                    match nix::poll::poll(&mut ready, timeout) {
                        Ok(_) | Err(nix::errno::Errno::EINTR) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        // Closing the channel lets control restore before exit. A cancelled
        // encoder was already stopped, so drop cannot wait on a blocked writer.
        self.replies.take();
        if let Some(input) = self.input.take() {
            input.close_write();
        }
        if let Some(launch) = self.child.take() {
            retire_owned(launch);
        }
        if let Some(retirement) = self.retirement.take() {
            let _ = retirement.join();
        }
        // The receiver is closed before joining, so a full response slot cannot
        // block the reader while it drains the child's final cleanup response.
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn retire_child(mut child: Child) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(all(target_os = "macos", not(test)))]
fn retire_owned(launch: CompanionLaunch) {
    if let Some(companion_pid) = launch.companion_pid {
        retire_launch_services(launch.launcher, Some(companion_pid));
    } else {
        retire_child(launch.launcher);
    }
}

#[cfg(not(all(target_os = "macos", not(test))))]
fn retire_owned(launch: CompanionLaunch) {
    retire_child(launch.launcher);
}

#[cfg(test)]
mod launch_tests {
    #[cfg(target_os = "macos")]
    use super::accept_blocking;
    use super::{companion_app_bundle, parse_companion_pid};
    use std::{fs, path::PathBuf};

    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn companion_launch_requires_the_capture_app_bundle() {
        let root = std::env::temp_dir().join(format!("desktop-launch-test-{}", std::process::id()));
        let _cleanup = Cleanup(root.clone());
        let bundle = root.join("InfraternalCaptureHelper.app");
        let contents = bundle.join("Contents");
        let executable = contents.join("MacOS/InfraternalCaptureHelper");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(contents.join("Info.plist"), "bundle fixture").unwrap();
        fs::write(&executable, "bundle executable").unwrap();

        assert_eq!(companion_app_bundle(&executable).unwrap(), bundle);
        assert!(companion_app_bundle(&root.join("desktop-native")).is_err());
        assert!(companion_app_bundle(&root).is_err());
    }

    #[test]
    fn launch_identity_waits_for_complete_pid_and_rejects_invalid_values() {
        assert_eq!(parse_companion_pid("420", 41).unwrap(), None);
        assert_eq!(parse_companion_pid("", 41).unwrap(), None);
        assert_eq!(parse_companion_pid("420\n", 41).unwrap(), Some(420));
        assert!(parse_companion_pid("not-a-pid\n", 41).is_err());
        assert!(parse_companion_pid("1\n", 41).is_err());
        assert!(parse_companion_pid("41\n", 41).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launch_services_accept_resets_nonblocking_listener_mode() {
        use std::os::{
            fd::AsFd,
            unix::net::{UnixListener, UnixStream},
        };

        let root = std::env::temp_dir().join(format!("desktop-accept-mode-{}", std::process::id()));
        let _cleanup = Cleanup(root.clone());
        fs::create_dir(&root).unwrap();
        let socket_path = root.join("companion.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();

        let _client = UnixStream::connect(&socket_path).unwrap();
        let stream = accept_blocking(&listener).unwrap().unwrap();
        let flags = nix::fcntl::fcntl(stream.as_fd(), nix::fcntl::FcntlArg::F_GETFL).unwrap();

        assert_eq!(
            flags & nix::libc::O_NONBLOCK,
            0,
            "the protocol reader requires blocking reads"
        );
    }
}
