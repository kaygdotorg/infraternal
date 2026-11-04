//! Owns the `LaunchServices` companion channel with bounded I/O and process cleanup [D203,#146].
//!
//! The helper does not touch the screen itself. A small signed companion app
//! does, because macOS privacy grants (screen recording, accessibility) belong
//! to an installed app bundle. [`Native`] starts that companion and talks to it
//! with the framed messages from [`crate::protocol`].
//!
//! On macOS the companion is started through `LaunchServices` (`open`), so it
//! runs under the bundle's own identity. It connects back over a private Unix
//! socket in a fresh 0700 directory and writes its pid to a private file; the
//! pid is tracked with a kernel exit watch and double-checked against the
//! process's command line before it is ever signalled, so a recycled pid is
//! never killed. In unit tests (and on other systems) a plain child process
//! with piped stdin and stdout stands in.
//!
//! Every exchange is bounded by a deadline and by a cancellation flag. The
//! private protocol has no request ids, so after any failed exchange the
//! companion is retired rather than reused; a late reply could otherwise
//! answer the wrong command. Retiring first closes the channel, which lets the
//! companion restore any window geometry it changed, and only then escalates to
//! signals.
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

#[cfg(target_os = "macos")]
use nix::{
    errno::Errno,
    fcntl::{FcntlArg, FdFlag, fcntl},
    sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue},
};
#[cfg(all(target_os = "macos", not(test)))]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixListener;
#[cfg(any(not(target_os = "macos"), test))]
use std::process::ChildStdin;

/// One message from the companion (its kind and body), or the error that ended
/// the exchange.
type Reply = io::Result<(Kind, Vec<u8>)>;

/// The write side of the companion channel, abstracting a pipe (tests) and a
/// Unix socket (macOS) so the deadline-aware writer works with both.
trait CompanionInput: Write + Send {
    /// File descriptor to poll for writability.
    fn poll_fd(&self) -> BorrowedFd<'_>;
    /// Writes without ever blocking; returns `WouldBlock` when the channel is full.
    fn write_nonblocking(&mut self, bytes: &[u8]) -> io::Result<usize>;
    /// Signals end-of-input to the companion, which makes it restore and exit.
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

/// The processes behind a running companion.
struct CompanionLaunch {
    /// The process we spawned: the companion itself in tests, or the `open`
    /// waiter on macOS (which is not the companion and exits on its own).
    launcher: Child,
    /// The separately launched companion process (macOS `LaunchServices` only).
    #[cfg(target_os = "macos")]
    companion: Option<TrackedCompanion>,
}

/// A companion process started by `LaunchServices`, watched by pid with a
/// `kqueue` exit event and only signalled while it still looks like ours.
#[cfg(target_os = "macos")]
struct TrackedCompanion {
    pid: nix::unistd::Pid,
    /// Private socket path the companion was told to connect to.
    socket_path: PathBuf,
    /// Private pid file the companion was told to write.
    pid_path: PathBuf,
    /// Delivers the process-exit event.
    exit_queue: Kqueue,
    exited: bool,
}

#[cfg(target_os = "macos")]
impl TrackedCompanion {
    /// Starts watching `pid` for exit. The watch is registered before returning
    /// so an exit can never be missed. Fails if the process is already gone.
    fn new(pid: u32, socket_path: &Path, pid_path: &Path) -> io::Result<Self> {
        let pid = i32::try_from(pid)
            .map_err(|_| io::Error::other("Desktop companion launch identity is invalid."))?;
        let event_pid = usize::try_from(pid)
            .map_err(|_| io::Error::other("Desktop companion launch identity is invalid."))?;
        let exit_queue = Kqueue::new()?;
        fcntl(&exit_queue, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        let mut events = [process_exit_event(0)];
        let mut tracked = Self {
            pid: nix::unistd::Pid::from_raw(pid),
            socket_path: socket_path.to_owned(),
            pid_path: pid_path.to_owned(),
            exit_queue,
            exited: false,
        };
        match tracked.exit_queue.kevent(
            &[process_exit_event(event_pid)],
            &mut events,
            Some(zero_timeout()),
        ) {
            Ok(count) => tracked.exited = count != 0,
            Err(Errno::ESRCH) => {
                return Err(io::Error::other("Desktop companion exited during launch."));
            }
            Err(error) => return Err(error.into()),
        }
        Ok(tracked)
    }

    /// True if the tracked pid still belongs to our companion: running as this
    /// user, with this launch's socket and pid-file paths on its command line.
    ///
    /// The private per-launch socket and PID-file arguments identify this exact
    /// same-bundle process if its numeric PID is later reused.
    fn matches_current_launch(&self) -> io::Result<bool> {
        if self.exited {
            return Ok(false);
        }
        let pid = self.pid.as_raw().to_string();
        let output = Command::new("/bin/ps")
            .args(["-p", pid.as_str(), "-o", "uid=,command=", "-ww"])
            .output()?;
        if !output.status.success() {
            return Ok(false);
        }
        let line = String::from_utf8_lossy(&output.stdout);
        let mut columns = line.trim().splitn(2, char::is_whitespace);
        let Some(uid) = columns.next().and_then(|value| value.parse::<u32>().ok()) else {
            return Ok(false);
        };
        let Some(command) = columns.next() else {
            return Ok(false);
        };
        Ok(uid == nix::unistd::geteuid().as_raw()
            && has_process_argument(command, "--socket", &self.socket_path)
            && has_process_argument(command, "--launch-pid-file", &self.pid_path))
    }

    /// Waits up to `timeout` for the process to exit. Returns whether it has.
    fn wait_for_exit(&mut self, timeout: Duration) -> io::Result<bool> {
        if self.exited {
            return Ok(true);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let mut events = [process_exit_event(0)];
            match self
                .exit_queue
                .kevent(&[], &mut events, Some(duration_timespec(remaining)))
            {
                Ok(count) if count != 0 => {
                    self.exited = true;
                    return Ok(true);
                }
                Err(Errno::EINTR) if Instant::now() < deadline => {}
                Ok(_) | Err(Errno::EINTR) => return Ok(false),
                Err(Errno::ESRCH) => {
                    self.exited = true;
                    return Ok(true);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Sends `signal` only if the pid still matches this launch. Returns whether
    /// a signal was delivered.
    fn signal_if_current(&self, signal: nix::sys::signal::Signal) -> io::Result<bool> {
        if !self.matches_current_launch()? {
            return Ok(false);
        }
        match nix::sys::signal::kill(self.pid, signal) {
            Ok(()) => Ok(true),
            Err(Errno::ESRCH) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

/// True if `command` (a process command line) contains the argument `name`
/// immediately followed by `value`.
#[cfg(target_os = "macos")]
fn has_process_argument(command: &str, name: &str, value: &Path) -> bool {
    let Some(value) = value.to_str() else {
        return false;
    };
    let mut arguments = command.split_whitespace();
    while let Some(argument) = arguments.next() {
        if argument == name && arguments.next() == Some(value) {
            return true;
        }
    }
    false
}

/// A one-shot `kqueue` event that fires when process `pid` exits. A `pid` of 0
/// makes an empty slot for receiving results.
#[cfg(target_os = "macos")]
fn process_exit_event(pid: usize) -> KEvent {
    KEvent::new(
        pid,
        EventFilter::EVFILT_PROC,
        EvFlags::EV_ADD | EvFlags::EV_ONESHOT,
        FilterFlag::NOTE_EXIT,
        0,
        0,
    )
}

/// A zero timeout, which makes `kevent` poll without waiting.
#[cfg(target_os = "macos")]
fn zero_timeout() -> nix::libc::timespec {
    nix::libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }
}

/// Converts a `Duration` to a C `timespec`, saturating on overflow.
#[cfg(target_os = "macos")]
fn duration_timespec(duration: Duration) -> nix::libc::timespec {
    nix::libc::timespec {
        tv_sec: duration.as_secs().try_into().unwrap_or(i64::MAX),
        tv_nsec: duration.subsec_nanos().into(),
    }
}

/// A freshly started companion and its channel, before [`Native`] wraps them.
struct SpawnedCompanion {
    launch: CompanionLaunch,
    input: Box<dyn CompanionInput>,
    output: Box<dyn Read + Send>,
    /// A second handle to the socket, used to unblock the reader thread
    /// (shutting it down makes a pending read return).
    reader_interrupt: Option<UnixStream>,
    /// Directory holding the launch socket and pid file; deleted on drop.
    private_directory: Option<PrivateDirectory>,
}

/// A directory (mode 0700, under `/tmp`) that is deleted when dropped.
struct PrivateDirectory(PathBuf);

impl PrivateDirectory {
    /// Makes a unique `/tmp/it-c-XXXXXX` directory readable only by this user.
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

/// Starts `executable` as a plain child with piped stdin/stdout (test and
/// non-macOS path). `encoder` and `surface` choose the companion's mode. The
/// stdin pipe is made non-blocking so writes can honour deadlines.
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
            #[cfg(target_os = "macos")]
            companion: None,
        },
        input: Box::new(input),
        output: Box::new(output),
        reader_interrupt: None,
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
/// Runs the companion once with `--check-permissions` and returns its JSON
/// answer: exactly two boolean fields, `device_control` and `screen_recording`,
/// telling which macOS privacy permissions are granted.
///
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

/// Reads the pid the companion wrote to its pid file. `None` means not published
/// yet (missing or incomplete). A file that is not private to this user is an
/// error, since its contents cannot be trusted.
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

/// Parses pid-file contents. Returns `None` while the line is incomplete, the
/// pid when valid, and an error for non-numbers, pid 0/1, or our own pid
/// (which would make cleanup signal ourselves).
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

/// Builds the `open` command that starts the companion bundle as a new instance
/// without activating it, with no stdin and stdout, passing it the private socket
/// and pid-file paths. With `measure`, timing output is enabled in the companion.
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
    }
    let measured_stderr = std::env::var_os("INFRATERNAL_DESKTOP_MEASURE_STDERR").map(PathBuf::from);
    command
        .arg("--stderr")
        .arg(launch_stderr_path(measure, measured_stderr.as_deref()));
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

/// Keep companion diagnostics quiet by default; an explicit absolute path
/// makes `LaunchServices`' child stderr observable during a measured run.
fn launch_stderr_path(measure: bool, configured: Option<&Path>) -> PathBuf {
    if !measure {
        return PathBuf::from("/dev/null");
    }
    configured
        .filter(|path| path.is_absolute())
        .map_or_else(|| PathBuf::from("/dev/fd/2"), Path::to_path_buf)
}

/// Accepts one connection from a non-blocking listener, if one is waiting. The
/// returned stream is switched back to blocking mode.
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

/// State while waiting for a just-launched companion to connect back.
#[cfg(all(target_os = "macos", not(test)))]
struct LaunchHandshake<'a> {
    pid_path: &'a Path,
    socket_path: &'a Path,
    /// Pid read from the pid file, once published.
    companion_pid: Option<u32>,
    /// Exit watch, created as soon as the pid is known.
    companion: Option<TrackedCompanion>,
    /// Milliseconds from launch until the pid appeared (for measured runs).
    pid_ready_ms: Option<f64>,
    started: Instant,
    measure: bool,
}

#[cfg(all(target_os = "macos", not(test)))]
impl LaunchHandshake<'_> {
    /// Picks up the pid file if it appeared, and starts the exit watch once the
    /// pid is known.
    fn update_companion_pid(&mut self) -> io::Result<()> {
        if self.companion_pid.is_none() {
            let pid = read_companion_pid(self.pid_path)?;
            if pid.is_some() && self.pid_ready_ms.is_none() {
                self.pid_ready_ms = Some(self.started.elapsed().as_secs_f64() * 1000.0);
            }
            self.companion_pid = pid;
        }
        if self.companion.is_none()
            && let Some(pid) = self.companion_pid
        {
            self.companion = Some(TrackedCompanion::new(pid, self.socket_path, self.pid_path)?);
        }
        Ok(())
    }

    /// Tries to accept the companion's connection. Returns `None` if nobody has
    /// connected yet. A connection is accepted only if it is from this user and
    /// the companion has published a pid that matches the one being watched;
    /// otherwise it is an error.
    fn accept(&mut self, listener: &UnixListener) -> io::Result<Option<UnixStream>> {
        self.update_companion_pid()?;
        let Some(stream) = accept_blocking(listener)? else {
            return Ok(None);
        };
        crate::socket::admit(&stream)?;
        self.update_companion_pid()?;
        let Some(pid) = self.companion_pid else {
            return Err(io::Error::other(
                "Desktop companion did not publish its launch identity.",
            ));
        };
        let Some(tracked) = self.companion.as_ref() else {
            return Err(io::Error::other(
                "Desktop companion launch identity is unavailable.",
            ));
        };
        if tracked.pid.as_raw().cast_unsigned() != pid {
            return Err(io::Error::other(
                "Desktop companion launch identity changed during startup.",
            ));
        }
        if self.measure {
            eprintln!(
                "METRIC launch_services pid={pid} launch_ms={:.3}",
                self.pid_ready_ms
                    .unwrap_or_else(|| self.started.elapsed().as_secs_f64() * 1000.0)
            );
        }
        Ok(Some(stream))
    }
}

/// Splits the accepted socket into a write handle, a read handle and an
/// interrupt handle. If cloning fails, the launch is retired and the error
/// returned, so nothing is left running.
#[cfg(all(target_os = "macos", not(test)))]
fn finish_launch_connection(
    launcher: Child,
    private_directory: PrivateDirectory,
    stream: UnixStream,
    tracked: TrackedCompanion,
) -> io::Result<SpawnedCompanion> {
    let input = match stream.try_clone() {
        Ok(input) => Box::new(input) as Box<dyn CompanionInput>,
        Err(error) => {
            drop(stream);
            retire_launch_services(launcher, Some(tracked));
            return Err(error);
        }
    };
    let reader_interrupt = match stream.try_clone() {
        Ok(interrupt) => interrupt,
        Err(error) => {
            drop(input);
            drop(stream);
            retire_launch_services(launcher, Some(tracked));
            return Err(error);
        }
    };
    Ok(SpawnedCompanion {
        launch: CompanionLaunch {
            launcher,
            companion: Some(tracked),
        },
        input,
        output: Box::new(stream),
        reader_interrupt: Some(reader_interrupt),
        private_directory: Some(private_directory),
    })
}

/// Starts the companion through `LaunchServices` and waits up to 5 seconds for
/// it to connect to a private socket. The wait polls every 5 ms and gives up
/// early if the `open` process exits first. On any failure the launch is
/// retired before the error is returned.
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

    let mut handshake = LaunchHandshake {
        pid_path: &pid_path,
        socket_path: &socket_path,
        companion_pid: None,
        companion: None,
        pid_ready_ms: None,
        started,
        measure,
    };
    loop {
        match handshake.accept(&listener) {
            Ok(Some(stream)) => {
                let Some(tracked) = handshake.companion.take() else {
                    drop(stream);
                    retire_launch_services(launcher, None);
                    return Err(io::Error::other(
                        "Desktop companion launch identity is unavailable.",
                    ));
                };
                return finish_launch_connection(launcher, private_directory, stream, tracked);
            }
            Ok(None) => {}
            Err(error) => {
                retire_launch_services(launcher, handshake.companion.take());
                return Err(error);
            }
        }
        match launcher.try_wait() {
            Ok(Some(_)) => {
                retire_launch_services(launcher, handshake.companion.take());
                return Err(io::Error::other(
                    "LaunchServices exited before the desktop companion connected.",
                ));
            }
            Ok(None) => {}
            Err(error) => {
                retire_launch_services(launcher, handshake.companion.take());
                return Err(error);
            }
        }
        if started.elapsed() >= std::time::Duration::from_secs(5) {
            retire_launch_services(launcher, handshake.companion.take());
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "LaunchServices did not start the desktop companion in time.",
            ));
        }
        thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Ends a `LaunchServices` launch and waits for it. Gives both processes up to 3
/// seconds to exit on their own (they usually do once the channel is closed),
/// then sends the companion SIGTERM and finally SIGKILL (only if it is still
/// verifiably ours), and kills and reaps the `open` waiter. Returns true only
/// if the companion is confirmed gone and the waiter was reaped.
#[cfg(target_os = "macos")]
fn retire_launch_services(mut launcher: Child, mut companion: Option<TrackedCompanion>) -> bool {
    let mut launcher_exited = matches!(launcher.try_wait(), Ok(Some(_)));
    let mut companion_exited = companion
        .as_mut()
        .is_none_or(|process| process.wait_for_exit(Duration::ZERO).unwrap_or(false));
    let deadline = Instant::now() + Duration::from_secs(3);
    while !launcher_exited && !companion_exited && Instant::now() < deadline {
        if let Some(process) = companion.as_mut() {
            companion_exited = process
                .wait_for_exit(Duration::from_millis(10))
                .unwrap_or(false);
        } else {
            thread::sleep(Duration::from_millis(10));
        }
        launcher_exited = matches!(launcher.try_wait(), Ok(Some(_)));
    }

    if !companion_exited && let Some(process) = companion.as_mut() {
        // `open -W` is only a waiter; its exit is not evidence that this
        // separately launched process released the private socket.
        if let Ok(true) = process.signal_if_current(nix::sys::signal::Signal::SIGTERM) {
            companion_exited = process
                .wait_for_exit(Duration::from_millis(500))
                .unwrap_or(false);
        }
        if !companion_exited
            && let Ok(true) = process.signal_if_current(nix::sys::signal::Signal::SIGKILL)
        {
            companion_exited = process
                .wait_for_exit(Duration::from_secs(1))
                .unwrap_or(false);
        }
    }

    if matches!(launcher.try_wait(), Ok(None)) {
        let _ = launcher.kill();
    }
    let launcher_reaped = launcher.wait().is_ok();
    companion_exited && launcher_reaped
}

/// A running native companion and the request/reply channel to it.
///
/// Calls are strictly one at a time and each has a 3-second deadline. After a
/// failed call the companion is sealed (see [`Native::is_stopped`]) and a new
/// [`Native`] must be spawned. Dropping it closes the channel and waits for the
/// companion to finish restoring and exit.
pub struct Native {
    /// Processes to retire; `None` once sealed.
    child: Option<CompanionLaunch>,
    /// Kept only so the directory is deleted when this value is dropped.
    _private_directory: Option<PrivateDirectory>,
    /// Write side; `None` once sealed.
    input: Option<Box<dyn CompanionInput>>,
    reader_interrupt: Option<UnixStream>,
    /// Replies from the reader thread. One slot, so the thread blocks (and the
    /// companion with it) rather than queueing unread replies.
    replies: Option<Receiver<Reply>>,
    reader: Option<JoinHandle<()>>,
    /// Set by the owner to abort an exchange in progress.
    cancellation: Option<Arc<AtomicBool>>,
    /// Background cleanup of a sealed companion; joined on drop.
    retirement: Option<JoinHandle<bool>>,
    /// Encoder-only mode: cannot show a control indicator or inject input.
    encoder: bool,
    /// Companion captures the surface itself and streams video unprompted.
    surface: bool,
    /// Newest unread video frame that arrived while waiting for a reply.
    video: Option<Vec<u8>>,
    /// True if a video frame was replaced before being read and no keyframe has
    /// followed, so the stream has a hole until the next one.
    video_gap: bool,
}
impl Native {
    /// Starts a full control companion (windows, input and capture).
    ///
    /// # Errors
    /// Reports launch failure or an unavailable companion channel.
    pub fn spawn(executable: &Path) -> io::Result<Self> {
        Self::spawn_mode(executable, false, false)
    }
    /// Starts a companion that only encodes pixels it is given with [`Native::encode`].
    ///
    /// # Errors
    /// Starts only encoding; it cannot create a control indicator or inject input.
    pub fn spawn_encoder(executable: &Path) -> io::Result<Self> {
        Self::spawn_mode(executable, true, false)
    }
    /// Starts a companion that captures and encodes in its own process and
    /// streams the video back (read it with [`Native::surface_video`]).
    ///
    /// # Errors
    /// Starts same-process companion capture, keeping H.264 on the public path.
    pub fn spawn_surface(executable: &Path) -> io::Result<Self> {
        Self::spawn_mode(executable, false, true)
    }
    /// Launches the companion in the chosen mode and starts the reader thread
    /// that turns its output into replies.
    fn spawn_mode(executable: &Path, encoder: bool, surface: bool) -> io::Result<Self> {
        #[cfg(all(target_os = "macos", not(test)))]
        let spawned = spawn_via_launch_services(executable, encoder, surface)?;
        #[cfg(any(not(target_os = "macos"), test))]
        let spawned = spawn_direct(executable, encoder, surface)?;

        let SpawnedCompanion {
            launch,
            input,
            mut output,
            reader_interrupt,
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
            reader_interrupt,
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
    /// Sends one message and returns the companion's reply.
    ///
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
    /// Sends one BGRA image (`width * height * 4` bytes, at most 4 Mi pixels) to
    /// the encoder and returns its reply. `capture_ticks` is the capture time
    /// carried through to the encoded frame; `sharp` asks for the higher-quality
    /// setting. The same 3-second deadline applies to the whole exchange.
    ///
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
    /// A writer for the companion's input that fails after `deadline` or on
    /// cancellation. Errors if the companion is already sealed.
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
    /// Seals the companion after a failed exchange: drops the reply channel,
    /// closes its input, kills the launcher at once and cleans up in the
    /// background. Used when the channel state is unknown (partial write, timeout).
    fn stop_now(&mut self) {
        self.replies.take();
        if let Some(input) = self.input.take() {
            input.close_write();
        }
        if let Some(mut launch) = self.child.take() {
            // A cancelled exchange cannot use a late reply. Stop the waiter now;
            // LaunchServices cleanup still verifies and signals its detached app.
            let _ = launch.launcher.kill();
            self.retirement = Some(thread::spawn(move || retire_owned(launch)));
        }
    }
    /// Like [`Native::stop_now`] but gentle: it does not kill the launcher first,
    /// so the companion can see end-of-input and restore what it changed.
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
    /// Shuts the socket down so a reader thread stuck in a read returns.
    fn interrupt_reader(&mut self) {
        if let Some(stream) = self.reader_interrupt.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
    /// Waits for the reply to the request just sent. In surface mode, video
    /// frames arriving first are kept (only the newest) rather than treated as
    /// the reply. On failure the companion is sealed: gently when `graceful` is
    /// true (and the failure was not a cancellation), otherwise at once.
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
    /// Returns whether a frame was skipped since the last call (and clears the
    /// flag). The caller then needs a new keyframe.
    ///
    /// An overwritten encoded delta requires a new IDR at the forwarding boundary.
    pub fn take_surface_gap(&mut self) -> bool {
        std::mem::take(&mut self.video_gap)
    }
    /// Waits up to 100 ms for the next video frame from the companion. Returns
    /// `None` on a quiet timeout, so the caller can check for cancellation.
    ///
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
    /// Takes the next message from the reader thread, waiting until `deadline`
    /// (in short slices, so cancellation is noticed within about 20 ms).
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

/// How long a wait may still last. Errors with `ConnectionAborted` if
/// cancelled, or `TimedOut` if `deadline` has passed. With a cancellation flag
/// the result is capped at 20 ms so callers re-check it often.
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

/// A `Write` over the companion's input that never blocks past a deadline: it
/// tries a non-blocking write, waits for writability in short slices, and
/// gives up on timeout or cancellation.
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
        if let Some(launch) = self.child.take()
            && !retire_owned(launch)
        {
            self.interrupt_reader();
        }
        if let Some(retirement) = self.retirement.take()
            && !retirement.join().is_ok_and(|retired| retired)
        {
            self.interrupt_reader();
        }
        // The receiver is closed before joining, so a full response slot cannot
        // block the reader while it drains the child's final cleanup response.
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// Waits up to 3 seconds for a plain child to exit, then kills it, and reaps it.
/// Returns whether reaping succeeded.
fn retire_child(mut child: Child) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    child.wait().is_ok()
}

/// Retires a launch the right way for how it was started. Returns true if
/// everything is confirmed gone.
#[cfg(target_os = "macos")]
fn retire_owned(launch: CompanionLaunch) -> bool {
    if let Some(companion) = launch.companion {
        retire_launch_services(launch.launcher, Some(companion))
    } else {
        retire_child(launch.launcher)
    }
}

#[cfg(not(target_os = "macos"))]
fn retire_owned(launch: CompanionLaunch) -> bool {
    retire_child(launch.launcher)
}

#[cfg(test)]
mod launch_tests {
    #[cfg(target_os = "macos")]
    use super::{CompanionLaunch, Native, TrackedCompanion, accept_blocking};
    use super::{companion_app_bundle, launch_stderr_path, parse_companion_pid};
    use std::{
        fs,
        path::{Path, PathBuf},
    };
    #[cfg(target_os = "macos")]
    use std::{
        io::Read,
        os::unix::net::UnixListener,
        process::{Command, Stdio},
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

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

    #[test]
    fn measured_launch_services_can_write_companion_metrics_to_an_absolute_file() {
        assert_eq!(
            launch_stderr_path(true, Some(Path::new("/tmp/desktop-capture.stderr"))),
            PathBuf::from("/tmp/desktop-capture.stderr")
        );
        assert_eq!(launch_stderr_path(true, None), PathBuf::from("/dev/fd/2"));
        assert_eq!(
            launch_stderr_path(true, Some(Path::new("relative.stderr"))),
            PathBuf::from("/dev/fd/2")
        );
        assert_eq!(
            launch_stderr_path(false, Some(Path::new("/tmp/ignored.stderr"))),
            PathBuf::from("/dev/null")
        );
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

    #[cfg(target_os = "macos")]
    #[test]
    fn dropping_stream_retires_stopped_companion_after_waiter_exit() {
        use nix::{
            sys::wait::{WaitPidFlag, WaitStatus, waitpid},
            unistd::Pid,
        };

        let root =
            std::env::temp_dir().join(format!("desktop-retire-companion-{}", std::process::id()));
        let _cleanup = Cleanup(root.clone());
        fs::create_dir_all(&root).unwrap();
        let socket_path = root.join("s");
        let pid_path = root.join("p");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let script = "import os,signal,socket,sys,time; s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(sys.argv[sys.argv.index('--socket')+1]); open(sys.argv[sys.argv.index('--launch-pid-file')+1],'w').write(str(os.getpid())+'\\n'); os.kill(os.getpid(),signal.SIGSTOP); time.sleep(60)";
        let mut companion = Command::new("python3")
            .arg("-c")
            .arg(script)
            .arg("--socket")
            .arg(&socket_path)
            .arg("--launch-pid-file")
            .arg(&pid_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stream = listener.accept().unwrap().0;
        let pid = Pid::from_raw(companion.id().cast_signed());
        let stop_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED)).unwrap() {
                WaitStatus::Stopped(_, _) => break,
                WaitStatus::StillAlive if Instant::now() < stop_deadline => {
                    thread::sleep(Duration::from_millis(5));
                }
                status => panic!("companion did not stop with its socket open: {status:?}"),
            }
        }

        // A dead `open -W` waiter does not prove the separately launched app
        // exited. Keep a blocked reader to exercise the complete Drop path.
        let mut launcher = Command::new("/usr/bin/true").spawn().unwrap();
        launcher.wait().unwrap();
        let tracked = TrackedCompanion::new(companion.id(), &socket_path, &pid_path).unwrap();
        assert!(tracked.matches_current_launch().unwrap());
        let another_launch = TrackedCompanion::new(
            companion.id(),
            &root.join("other-socket"),
            &root.join("other-pid"),
        )
        .unwrap();
        assert!(!another_launch.matches_current_launch().unwrap());
        let input = stream.try_clone().unwrap();
        let reader_interrupt = input.try_clone().unwrap();
        let reader = thread::spawn(move || {
            let mut output = stream;
            let mut byte = [0; 1];
            while output.read(&mut byte).is_ok_and(|count| count > 0) {}
        });
        let native = Native {
            child: Some(CompanionLaunch {
                launcher,
                companion: Some(tracked),
            }),
            _private_directory: None,
            input: Some(Box::new(input)),
            reader_interrupt: Some(reader_interrupt),
            replies: None,
            reader: Some(reader),
            cancellation: None,
            retirement: None,
            encoder: false,
            surface: false,
            video: None,
            video_gap: false,
        };
        let (done_tx, done_rx) = mpsc::channel();
        let dropper = thread::spawn(move || {
            drop(native);
            let _ = done_tx.send(());
        });
        let completed = done_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        let companion_retired = companion.try_wait().unwrap().is_some();
        if !companion_retired {
            // Keep a failing regression run self-cleaning even when Drop hangs.
            let _ = companion.kill();
        }
        dropper.join().unwrap();
        if !companion_retired {
            let _ = companion.wait();
        }
        assert!(
            completed && companion_retired,
            "Native::drop must retire a stopped companion after its LaunchServices waiter exits"
        );
    }
}
