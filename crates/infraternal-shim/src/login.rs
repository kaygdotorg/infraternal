//! Host-login worker: shells inherit one account login while privileged shims retain their PTYs [D240,D247].
#![forbid(unsafe_code)]

use nix::{
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::{
        signal::{SigSet, Signal},
        signalfd::{SfdFlags, SignalFd},
        socket::{getsockopt, sockopt::PeerCredentials},
    },
    unistd::{Uid, User},
};
use std::{
    fs,
    io::{self, Read, Write},
    os::{
        fd::AsFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
            process::ExitStatusExt,
        },
    },
    path::Path,
    process::Child,
    time::{Duration, Instant},
};

/// A login retires once, after its last shell exits; no periodic infraternal agent task is involved.
pub const GRACE: Duration = Duration::from_secs(30);

/// The private v1 request has no strings or variable-length allocations.
#[derive(Debug, PartialEq, Eq)]
pub enum RequestHeader {
    /// Readiness probe (`?`, no descriptor). The worker answers `R`.
    Ready,
    /// Stop request (`!`, no descriptor). The worker ends every shell and answers
    /// `S`.
    Stop,
    /// Start a shell for the session with this 16-byte id (exactly one descriptor,
    /// the terminal, travels with it).
    Terminal([u8; 16]),
}
/// Shared pure decoder used by descriptor reception and parser fuzzing.
/// # Errors
/// Rejects every length/descriptor-count combination outside the fixed envelope.
pub fn decode_header(bytes: &[u8], descriptors: usize) -> io::Result<RequestHeader> {
    if bytes == b"?" && descriptors == 0 {
        return Ok(RequestHeader::Ready);
    }
    if bytes == b"!" && descriptors == 0 {
        return Ok(RequestHeader::Stop);
    }
    if bytes.len() == 16 && descriptors == 1 {
        let mut session = [0; 16];
        session.copy_from_slice(bytes);
        return Ok(RequestHeader::Terminal(session));
    }
    Err(io::Error::other("invalid login request header"))
}

/// Decode the fixed worker exit record without allocation or unchecked negation.
/// # Errors
/// Refuses truncation, trailing bytes and values outside exit-code/signal ranges.
pub fn decode_status(bytes: &[u8]) -> io::Result<i32> {
    let bytes: [u8; 4] = bytes.try_into().map_err(|_| io::ErrorKind::InvalidData)?;
    let code = i32::from_le_bytes(bytes);
    if (0..=255).contains(&code) || (-64..=-1).contains(&code) {
        Ok(code)
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
}

/// One shell the worker is tracking: its child process (`None` once its status
/// has been sent) and the connection that receives that status and signals
/// disconnection.
struct Running {
    child: Option<Child>,
    reply: UnixStream,
}
/// Removes the worker's socket file when dropped.
struct Endpoint<'a>(&'a Path);
impl Drop for Endpoint<'_> {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0);
    }
}

/// Serve only local privileged shim children in a host-created account login.
/// # Errors
/// Rejects unsafe runtime locations, duplicate workers, malformed descriptors, and process failures.
pub fn worker(endpoint: &Path, grace: Duration) -> io::Result<()> {
    worker_as_controller(endpoint, grace, Uid::effective().as_raw())
}

/// Bind a host-created login to the uid of its privileged local controller.
/// This process must be dedicated to the login: it becomes a child subreaper
/// and owns every descendant started within it through terminal retirement.
/// # Errors
/// Returns worker startup or descriptor errors.
pub fn worker_as_controller(endpoint: &Path, grace: Duration, controller: u32) -> io::Result<()> {
    worker_configured(endpoint, grace, controller, false, None)
}

/// Announce the original ready process on the system manager's private stdout
/// pipe. This is for fresh launches only; adoption still authenticates the unit.
/// # Errors
/// Returns normal worker startup errors or launch-pipe delivery failures.
pub fn worker_announced(endpoint: &Path, grace: Duration, controller: u32) -> io::Result<()> {
    worker_configured(endpoint, grace, controller, true, None)
}

/// [`worker_announced`] for a socket the root controller created: `bound` is a
/// Unix stream socket already bound at `endpoint`, inside a directory only
/// root can change, and not yet listening. The worker listens on it itself,
/// so connecting peers still see the worker's own credentials, but the
/// account can neither replace the socket nor its directory (J291 P1, J295
/// P1, #355). Root logins no longer use a separate stop socket: revocation
/// kills the login's session scope instead.
/// # Errors
/// Refuses a descriptor that is not a socket bound at `endpoint`.
pub fn worker_announced_on(
    endpoint: &Path,
    grace: Duration,
    controller: u32,
    bound: std::os::fd::OwnedFd,
) -> io::Result<()> {
    worker_configured(endpoint, grace, controller, true, Some(bound))
}

/// Takes the root-created socket `bound` for `endpoint`: checks that it is a
/// Unix socket bound at exactly that path, then listens on it.
fn adopt_listener(bound: std::os::fd::OwnedFd, endpoint: &Path) -> io::Result<UnixListener> {
    use nix::sys::socket::{Backlog, UnixAddr, getsockname, listen};
    use std::os::fd::AsRawFd as _;
    let address: UnixAddr = getsockname(bound.as_raw_fd()).map_err(io::Error::from)?;
    if address.path() != Some(endpoint) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "login socket descriptor is not bound at the login endpoint",
        ));
    }
    listen(&bound, Backlog::new(128).map_err(io::Error::from)?).map_err(io::Error::from)?;
    Ok(UnixListener::from(bound))
}

/// Shared body of the worker entry points; `announce` selects whether to report
/// readiness on the launch pipe.
fn worker_configured(
    endpoint: &Path,
    grace: Duration,
    controller: u32,
    announce: bool,
    bound: Option<std::os::fd::OwnedFd>,
) -> io::Result<()> {
    // A root-created socket lives in root's directory; otherwise the worker
    // binds in a directory private to its own account.
    if bound.is_none() {
        let parent = endpoint
            .parent()
            .ok_or_else(|| io::Error::other("login endpoint has no parent"))?;
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir()
            || metadata.uid() != Uid::effective().as_raw()
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "login directory must be private to the account",
            ));
        }
    }
    // The PAM-opened account context lasts until this login retires. Resolve
    // shell/home once before declaring readiness; each terminal still checks
    // kernel worker identity and effective uid, without another account lookup.
    let user = User::from_uid(Uid::effective())
        .map_err(io::Error::from)?
        .ok_or_else(|| io::Error::other("login account absent"))?;
    let mut shell = crate::pty::LoginShell::new(&user)?;
    // Binding without unlink is the final duplicate-start fence, even when two
    // concurrent terminal requests both saw an absent endpoint.
    let (listener, _endpoint, mut cleanup) = if let Some(bound) = bound {
        // The root controller owns and removes this socket and its directory.
        (adopt_listener(bound, endpoint)?, None, None)
    } else {
        let listener = UnixListener::bind(endpoint)?;
        let endpoint_guard = Endpoint(endpoint);
        fs::set_permissions(endpoint, fs::Permissions::from_mode(0o600))?;
        let cleanup = crate::cleanup::Cleanup::bind(endpoint, controller, b"S".to_vec())?;
        (listener, Some(endpoint_guard), Some(cleanup))
    };
    // Adopt detached descendants before starting any shell. Their parentage,
    // rather than an account-wide process scan, defines what this login owns.
    nix::sys::prctl::set_child_subreaper(true).map_err(io::Error::from)?;

    listener.set_nonblocking(true)?;
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGCHLD);
    mask.add(Signal::SIGTERM);
    mask.add(Signal::SIGHUP);
    mask.thread_block().map_err(io::Error::from)?;
    let signals = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC)
        .map_err(io::Error::from)?;
    let mut running: Vec<Running> = Vec::new();
    let mut deadline = Some(Instant::now() + grace.min(GRACE));
    if announce {
        crate::pty::announce_login()?;
    }
    loop {
        let mut index = 0;
        while index < running.len() {
            if let Some(child) = running[index].child.as_mut()
                && let Some(status) = child.try_wait()?
            {
                let code = status
                    .code()
                    .unwrap_or_else(|| -status.signal().unwrap_or(1));
                let _ = running[index].reply.write_all(&code.to_le_bytes());
                running[index].child = None;
            }
            index += 1;
        }
        reap_adopted(&running)?;
        let timeout = deadline.map_or(PollTimeout::NONE, |end| {
            PollTimeout::try_from(end.saturating_duration_since(Instant::now()))
                .unwrap_or(PollTimeout::MAX)
        });
        let mut fds = Vec::with_capacity(running.len() + 4);
        fds.push(PollFd::new(listener.as_fd(), PollFlags::POLLIN));
        fds.push(PollFd::new(signals.as_fd(), PollFlags::POLLIN));
        // Without a stop socket, slots 2 and 3 hold the listener with no
        // events, so the poll layout stays fixed.
        fds.push(match &cleanup {
            Some(cleanup) => PollFd::new(cleanup.listener().as_fd(), PollFlags::POLLIN),
            None => PollFd::new(listener.as_fd(), PollFlags::empty()),
        });
        fds.push(PollFd::new(
            cleanup
                .as_ref()
                .and_then(crate::cleanup::Cleanup::peer)
                .map_or(listener.as_fd(), AsFd::as_fd),
            if cleanup
                .as_ref()
                .is_some_and(crate::cleanup::Cleanup::reading)
            {
                PollFlags::POLLIN
            } else {
                PollFlags::empty()
            },
        ));
        for entry in &running {
            fds.push(PollFd::new(
                entry.reply.as_fd(),
                PollFlags::POLLHUP | PollFlags::POLLERR,
            ));
        }
        match poll(&mut fds, timeout) {
            Ok(0) if deadline.is_some_and(|end| Instant::now() >= end) => {
                finish_children()?;
                terminate();
                return Ok(());
            }
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(error.into()),
        }
        let closed: Vec<_> = fds
            .iter()
            .skip(4)
            .map(|fd| {
                fd.revents()
                    .is_some_and(|flags| flags.intersects(PollFlags::POLLHUP | PollFlags::POLLERR))
            })
            .collect();
        let cleanup_ready = fds[2]
            .revents()
            .is_some_and(|flags| flags.contains(PollFlags::POLLIN));
        let request_ready = fds[3]
            .revents()
            .is_some_and(|flags| flags.intersects(PollFlags::POLLIN | PollFlags::POLLHUP));
        drop(fds);
        if let Some(cleanup) = cleanup.as_mut() {
            if request_ready {
                cleanup.read_request();
            }
            if cleanup_ready {
                cleanup.accept()?;
            }
            if cleanup.requested() {
                finish_children()?;
                cleanup.confirm();
                cleanup.flush();
                terminate();
                return Ok(());
            }
        }
        for index in (0..closed.len()).rev() {
            if closed[index] {
                let mut ended = running.swap_remove(index);
                if let Some(mut child) = ended.child.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        if running.is_empty() && deadline.is_none() {
            deadline = Some(Instant::now() + grace.min(GRACE));
        }
        while let Some(signal) = signals.read_signal().map_err(io::Error::from)? {
            if signal.ssi_signo != u32::try_from(nix::libc::SIGCHLD).unwrap_or(0) {
                finish_children()?;
                terminate();
                return Ok(());
            }
        }
        // Never drain a connect backlog ahead of SIGCHLD or retirement. A
        // stalled legacy request is bounded; the next turn checks lifecycle
        // readiness before any other terminal is admitted, including at 512.
        for _ in 0..1 {
            let (mut peer, _) = match listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            };
            let uid = getsockopt(&peer, PeerCredentials)
                .map_err(io::Error::from)?
                .uid();
            if uid != controller {
                continue;
            }
            // A fixed-size private request has a bounded read. A stalled shim
            // cannot park child reaping indefinitely. Readiness probes carry no fd.
            peer.set_read_timeout(Some(Duration::from_secs(2)))?;
            peer.set_write_timeout(Some(Duration::from_secs(2)))?;
            let request = crate::pty::receive_terminal(&peer);
            match request {
                Ok(crate::pty::LoginRequest::Terminal(terminal, session)) => {
                    if running.len() >= 512 {
                        let _ = peer.write_all(&127_i32.to_le_bytes());
                        continue;
                    }
                    let Ok(mut child) = shell.spawn(terminal, &session) else {
                        let _ = peer.write_all(&127_i32.to_le_bytes());
                        continue;
                    };
                    // Cancellation belongs to this terminal, not the login.
                    // Never leave its newly spawned shell untracked after a
                    // failed acknowledgment, or retire unrelated terminals.
                    if peer.write_all(b"A").is_err() {
                        let _ = child.kill();
                        let _ = child.wait();
                        continue;
                    }
                    deadline = None;
                    running.push(Running {
                        child: Some(child),
                        reply: peer,
                    });
                }
                Ok(crate::pty::LoginRequest::Ready) => {
                    if running.is_empty() {
                        deadline = Some(Instant::now() + grace.min(GRACE));
                    }
                    // A controller may cancel a probe after sending it. Its
                    // broken reply must not end the person's existing login.
                    let _ = peer.write_all(b"R");
                }
                Ok(crate::pty::LoginRequest::Stop) => {
                    finish_children()?;
                    // Cleanup remains owned even when the requester leaves.
                    let _ = peer.write_all(b"S");
                    terminate();
                    return Ok(());
                }
                Err(_) => {}
            }
        }
    }
}

// Child identifiers come only from the kernel's lists for this process's
// threads. No owned child is reaped between enumeration and signal delivery,
// so those pids cannot be recycled into unrelated host processes.
/// Pids of this process's direct children, taken from the kernel's per-thread
/// lists. Taking them from the kernel (not scanning the account) means only
/// descendants this worker owns are ever signalled.
fn children() -> io::Result<Vec<nix::unistd::Pid>> {
    let mut children = Vec::new();
    for thread in fs::read_dir("/proc/self/task")? {
        let path = thread?.path().join("children");
        let record = match fs::read_to_string(path) {
            Ok(record) => record,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for value in record.split_whitespace() {
            let pid = value.parse::<i32>().map_err(io::Error::other)?;
            if pid <= 0 {
                return Err(io::Error::other("invalid owned child pid"));
            }
            children.push(nix::unistd::Pid::from_raw(pid));
        }
    }
    children.sort_unstable();
    children.dedup();
    Ok(children)
}

/// Reaps finished children that are not one of the `running` shells, so their
/// exit statuses are not stolen.
fn reap_adopted(running: &[Running]) -> io::Result<()> {
    reap_except(|pid| {
        running
            .iter()
            .any(|entry| entry.child.as_ref().is_some_and(|child| child.id() == pid))
    })
}

/// SIGCHLD releases completed adopted jobs without stealing the shell's status.
pub(crate) fn reap_terminal_jobs(shell: Option<u32>) -> io::Result<()> {
    reap_except(|pid| Some(pid) == shell)
}

/// Reaps every finished child whose pid `owned_status` rejects, without waiting.
fn reap_except(owned_status: impl Fn(u32) -> bool) -> io::Result<()> {
    use nix::sys::wait::{WaitPidFlag, waitpid};
    for pid in children()? {
        if u32::try_from(pid.as_raw()).is_ok_and(&owned_status) {
            continue;
        }
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(_) | Err(nix::errno::Errno::ECHILD) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Kills and reaps every child until none remain. Repeats because killing a
/// parent hands its children to this process, so detached and double-forked
/// descendants are collected too.
pub(crate) fn finish_children() -> io::Result<()> {
    use nix::sys::{signal::kill, wait::waitpid};
    loop {
        let owned = children()?;
        if owned.is_empty() {
            return Ok(());
        }
        for pid in &owned {
            match kill(*pid, Signal::SIGKILL) {
                Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                Err(error) => return Err(error.into()),
            }
        }
        for pid in owned {
            loop {
                match waitpid(pid, None) {
                    Ok(_) | Err(nix::errno::Errno::ECHILD) => break,
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        // Killing an intermediate parent adopts its children. Repeat until
        // detached sessions and double-forked descendants have all been reaped.
    }
}

/// Proxy one privileged shim's slave into its account login and return its actual exit status.
/// # Errors
/// Refuses a different account's worker or a truncated shell exit report.
pub fn proxy(endpoint: &Path, uid: u32, session: &[u8; 16], notify: bool) -> io::Result<i32> {
    proxy_at_pid(endpoint, uid, session, notify, None, None)
}

/// Authenticate the exact host-created worker on the connection that receives the terminal.
/// # Errors
/// Returns the same errors as `proxy`, or refuses a replacement worker pid.
pub fn proxy_at_pid(
    endpoint: &Path,
    uid: u32,
    session: &[u8; 16],
    notify: bool,
    expected: Option<i32>,
    pinned: Option<&Path>,
) -> io::Result<i32> {
    proxy_at_parent(endpoint, uid, session, notify, expected, pinned, None)
}

/// Keep a fallback worker attached to its authenticated original host login utility.
/// # Errors
/// Refuses worker death/replacement or kernel reparenting before terminal transfer.
pub fn proxy_at_parent(
    endpoint: &Path,
    uid: u32,
    session: &[u8; 16],
    notify: bool,
    expected: Option<i32>,
    pinned: Option<&Path>,
    parent: Option<i32>,
) -> io::Result<i32> {
    let mut peer = connect(endpoint, uid, expected, pinned, parent)?;
    crate::pty::send_terminal(&peer, session)?;
    acknowledge(&mut peer)?;
    if notify {
        crate::pty::notify_started(&peer)?;
    }
    let mut status = [0; 4];
    peer.read_exact(&mut status)?;
    Ok(i32::from_le_bytes(status))
}

/// Transfer directly from the privileged shim, retaining the same authenticated
/// connection through shell exit and output retention instead of execing a proxy.
pub(crate) fn start(
    endpoint: &Path,
    uid: u32,
    session: &[u8; 16],
    terminal: &std::fs::File,
    expected: Option<i32>,
    pinned: Option<&Path>,
    parent: Option<i32>,
) -> io::Result<UnixStream> {
    let mut peer = connect(endpoint, uid, expected, pinned, parent)?;
    peer.set_read_timeout(Some(Duration::from_secs(2)))?;
    peer.set_write_timeout(Some(Duration::from_secs(2)))?;
    crate::pty::send_terminal_from(&peer, terminal, session)?;
    acknowledge(&mut peer)?;
    peer.set_nonblocking(true)?;
    Ok(peer)
}

/// Reads the worker's one-byte `A` that confirms the shell started. Any other
/// byte means the host login refused to start it.
pub(crate) fn acknowledge(peer: &mut UnixStream) -> io::Result<()> {
    let mut started = [0];
    peer.read_exact(&mut started)?;
    if started != *b"A" {
        return Err(io::Error::other("host login shell refused startup"));
    }
    Ok(())
}

// Both launch adapters authenticate the connection that receives the terminal;
// readiness on a previous connection cannot authorize a replacement socket.
/// Connects to `endpoint` and authenticates that exact connection.
fn connect(
    endpoint: &Path,
    uid: u32,
    expected: Option<i32>,
    pinned: Option<&Path>,
    parent: Option<i32>,
) -> io::Result<UnixStream> {
    let peer = UnixStream::connect(endpoint)?;
    authenticate(&peer, uid, expected, pinned, parent)?;
    Ok(peer)
}

/// Authenticate the connected worker before sending or adopting a terminal.
/// A previously checked pathname or a separate readiness connection cannot
/// authorize this connection. Process pins prevent numeric PID reuse.
/// # Errors
/// Rejects account/PID mismatch, dead process pins and fallback reparenting.
pub fn authenticate(
    peer: &UnixStream,
    uid: u32,
    expected: Option<i32>,
    pinned: Option<&Path>,
    parent: Option<i32>,
) -> io::Result<()> {
    let credentials = getsockopt(peer, PeerCredentials).map_err(io::Error::from)?;
    // Validate the actual connection, not the pathname checked before launch.
    // A same-account process can replace its runtime socket between those steps.
    if credentials.uid() != uid || expected.is_some_and(|pid| pid <= 0 || credentials.pid() != pid)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "login worker identity differs",
        ));
    }
    if let Some(pinned) = pinned {
        let expected = expected.ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "pinned worker pid absent")
        })?;
        let record = fs::read_to_string(pinned.join("stat"))?;
        let pid = record
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<i32>().ok());
        let state = record
            .rsplit_once(')')
            .and_then(|(_, value)| value.split_whitespace().next());
        let actual_parent = record
            .rsplit_once(')')
            .and_then(|(_, value)| value.split_whitespace().nth(1))
            .and_then(|value| value.parse::<i32>().ok());
        // Reparenting selects an already-existing ancestor or init, whose PID
        // cannot equal the original live parent. The pinned worker prevents a
        // fresh worker PID lookup from bypassing this relationship check.
        if pid != Some(expected)
            || state.is_none_or(|state| matches!(state, "Z" | "X" | "x"))
            || parent.is_some_and(|expected| expected <= 1 || actual_parent != Some(expected))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pinned login worker no longer alive",
            ));
        }
    }
    Ok(())
}

// Only a worker that is the kernel-backed logind leader may end its session.
// Inherited rootless/fallback session identifiers must never terminate a host
// login that also contains the infraternal agent or unrelated account work.
/// The logind session id this process leads, or `None`. The id comes from this
/// process's cgroup and counts only if logind confirms this process is the
/// session leader, so inherited sessions that hold unrelated work are never
/// terminated.
fn owned_session() -> Option<String> {
    let record = fs::read_to_string("/proc/self/cgroup").ok()?;
    let id = record
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?
        .split('/')
        .find_map(|part| {
            part.strip_prefix("session-")
                .and_then(|part| part.strip_suffix(".scope"))
        })?;
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return None;
    }
    let mut command = std::process::Command::new("loginctl");
    crate::prepare_child(&mut command);
    let output = command
        .args(["show-session", id, "--property=Leader", "--value"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success()
        || output.stdout.len() > 32
        || std::str::from_utf8(&output.stdout)
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()?
            != std::process::id()
    {
        return None;
    }
    Some(id.to_owned())
}
/// Asks logind to end the session this worker leads, if any. Runs last in
/// retirement, after every descendant is gone. Errors are ignored.
fn terminate() {
    // Readiness and terminal opens need no logind round trip. Authenticate the
    // current leader only at retirement, after descendants have been reaped:
    // inherited or reassigned host sessions still fail the same leader check.
    if let Some(session) = owned_session() {
        let mut command = std::process::Command::new("loginctl");
        crate::prepare_child(&mut command);
        let _ = command
            .args(["--no-ask-password", "terminate-session", &session])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

#[cfg(test)]
mod tests {
    //! Exercise duplicate fencing and one-shot retirement against real Unix sockets.
    use super::*;
    #[test]
    fn matching_peer_pid_still_requires_a_live_pinned_process() {
        let root = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/rl3/dead-pin-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let endpoint = root.join("l.sock");
        let listener = UnixListener::bind(&endpoint).unwrap();
        let pinned = root.join("pinned");
        fs::create_dir(&pinned).unwrap();
        let pid = i32::try_from(std::process::id()).unwrap();
        // Model the kernel stat record after the authenticated worker exits.
        fs::write(pinned.join("stat"), format!("{pid} (fixture) Z 1\n")).unwrap();
        let error = proxy_at_pid(
            &endpoint,
            Uid::effective().as_raw(),
            &[0; 16],
            false,
            Some(pid),
            Some(&pinned),
        )
        .unwrap_err();
        drop(listener);
        fs::remove_dir_all(root).unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn stop_header_requires_exact_control_envelope() {
        assert!(decode_header(b"!", 0).is_ok());
        assert!(decode_header(b"!", 1).is_err());
        assert!(decode_header(b"!!", 0).is_err());
    }
    #[test]
    fn same_account_replacement_worker_is_refused_before_terminal_transfer() {
        let root = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/rl3/pid-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let endpoint = root.join("l.sock");
        let listener = UnixListener::bind(&endpoint).unwrap();
        let wrong_pid = i32::try_from(std::process::id()).unwrap() + 1;
        let error = proxy_at_pid(
            &endpoint,
            Uid::effective().as_raw(),
            &[0; 16],
            false,
            Some(wrong_pid),
            None,
        )
        .unwrap_err();
        drop(listener);
        fs::remove_dir_all(root).unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
    #[test]
    fn private_worker_retires_without_a_polling_controller() {
        const FIXTURE: &str = "INFRATERNAL_RETIRE_WORKER_FIXTURE";
        if std::env::var_os(FIXTURE).is_none() {
            assert!(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "login::tests::private_worker_retires_without_a_polling_controller"
                    ])
                    .env(FIXTURE, "1")
                    .status()
                    .unwrap()
                    .success()
            );
            return;
        }
        let root = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/real-logins/worker-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let endpoint = root.join("login.sock");
        worker(&endpoint, Duration::from_millis(5)).unwrap();
        assert!(!endpoint.exists());
        let listener = UnixListener::bind(&endpoint).unwrap();
        assert_eq!(
            worker(&endpoint, GRACE).unwrap_err().kind(),
            io::ErrorKind::AddrInUse
        );
        drop(listener);
        fs::remove_dir_all(root).unwrap();
    }
    /// A root-created socket is adopted only at the endpoint it is bound to,
    /// and the worker's own `listen` makes it accept connections (J295 P1).
    #[test]
    fn a_root_bound_socket_is_adopted_only_at_its_endpoint() {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, bind, socket};
        use std::os::fd::AsRawFd as _;
        let directory = nix::unistd::mkdtemp("/tmp/lw-XXXXXX").unwrap();
        let endpoint = directory.join("login.sock");
        let fresh = || {
            let _ = fs::remove_file(&endpoint);
            let bound = socket(
                AddressFamily::Unix,
                SockType::Stream,
                SockFlag::SOCK_CLOEXEC,
                None,
            )
            .unwrap();
            bind(bound.as_raw_fd(), &UnixAddr::new(&endpoint).unwrap()).unwrap();
            bound
        };
        let refused = adopt_listener(fresh(), &directory.join("other.sock")).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        let listener = adopt_listener(fresh(), &endpoint).unwrap();
        let _client = UnixStream::connect(&endpoint).unwrap();
        assert!(listener.accept().is_ok());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn exposed_login_directory_is_refused_before_bind() {
        let root = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/real-logins/exposed-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            worker(&root.join("login.sock"), GRACE).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(root).unwrap();
    }
}
