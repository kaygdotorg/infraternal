//! Single-threaded bounded PTY/socket pump; replay precedes live output at one cursor.
#![forbid(unsafe_code)]
use crate::{
    frame::{
        APPROXIMATE_SNAPSHOT, CLOSE_SESSION, Decoder, Frame, FrameRef, MAX_FRAME, MULTI_WRITER,
        QUERY_REPLIES, SEQUENCED_INPUT, SESSION_OWNER, SHARED_WRITER, SHELL_CLEANUP,
    },
    pty::Pty,
    ring::{DEFAULT_CAPACITY, Ring},
    terminal::Terminal,
};
use nix::{
    poll::{PollFd, PollFlags, poll},
    sys::{
        signal::{SigSet, Signal},
        stat::{Mode, umask},
    },
    unistd::Uid,
};
use std::fmt::Write as _;
#[cfg(feature = "host-diagnostics")]
use std::os::fd::AsRawFd;
use std::{
    collections::VecDeque,
    fs::{self, DirBuilder},
    io::{self, Read, Write},
    os::{
        fd::AsFd,
        unix::{
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
            process::ExitStatusExt,
        },
    },
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
/// Statically dispatched state boundary shared with the optional hosting experiment.
trait SessionTerminal {
    fn snapshot(&self) -> io::Result<Vec<u8>>;
    fn approximate_snapshot(&self) -> Vec<u8>;
    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()>;
    fn resize_with_ring(&mut self, cols: u16, rows: u16, ring: Option<&Ring>) -> io::Result<()>;
    fn requires_approximation(&self) -> bool;
}
impl SessionTerminal for Terminal {
    fn snapshot(&self) -> io::Result<Vec<u8>> {
        self.snapshot()
    }
    fn approximate_snapshot(&self) -> Vec<u8> {
        self.approximate_snapshot()
    }
    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        self.resize(cols, rows)
    }
    fn resize_with_ring(&mut self, cols: u16, rows: u16, ring: Option<&Ring>) -> io::Result<()> {
        self.resize_with_ring(cols, rows, ring)
    }
    fn requires_approximation(&self) -> bool {
        self.requires_approximation()
    }
}
#[cfg(feature = "process-per-user")]
#[path = "user_host.rs"]
pub(crate) mod user_host;
const CHUNK: usize = 16 * 1024;
const MAX_PEERS: usize = 32;
#[path = "inputs.rs"]
mod inputs;
use inputs::Inputs;
/// Startup parameters passed only by the local infraternal agent.
#[derive(Clone, Debug)]
pub struct Config {
    /// A private fixed non-login readiness command; no caller-supplied shell text.
    pub readiness: bool,
    /// Literal program arguments; empty selects the account login shell.
    pub command: Vec<std::ffi::OsString>,
    /// Automation has no persistent viewer; keep output until the existing one-shot exit deadline.
    pub retain_output: bool,
    pub session: [u8; 16],
    pub uid: u32,
    /// Private host-login worker endpoint; None retains legacy local startup.
    pub login_socket: Option<PathBuf>,
    /// Kernel-authenticated worker PID pins the proxy connection to the validated unit.
    pub login_worker_pid: Option<i32>,
    /// Original privileged host login parent; None for systemd workers.
    pub login_worker_parent: Option<i32>,
    /// Root controller descriptor link to the authenticated process directory.
    pub login_worker_proc: Option<PathBuf>,
    pub cols: u16,
    pub rows: u16,
    /// None selects /run/infraternal or $`XDG_RUNTIME_DIR/infraternal`.
    pub state: Option<PathBuf>,
    /// Output retention; production callers use the default 8 MiB.
    pub ring_capacity: usize,
}
impl Config {
    #[must_use]
    pub fn new(session: [u8; 16], uid: u32) -> Self {
        Self {
            readiness: false,
            command: Vec::new(),
            retain_output: false,
            session,
            uid,
            login_socket: None,
            login_worker_pid: None,
            login_worker_parent: None,
            login_worker_proc: None,
            cols: 80,
            rows: 24,
            state: None,
            ring_capacity: DEFAULT_CAPACITY,
        }
    }
}
struct SocketPath(PathBuf, bool);
impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        if self.1 {
            // Preserve the exemption until the probe's socket is unlinked.
            let _ = fs::remove_file(self.0.with_extension("readiness"));
        }
    }
}
enum Request {
    Read(u64),
    Snapshot,
}
#[derive(Clone, Copy)]
enum InputReply {
    Ack,
    State,
}
// Attachment, shared selection, exit delivery and cleanup are independent states.
// Keep their valid combinations compact rather than imposing exclusive phases.
#[allow(clippy::struct_excessive_bools)]
struct Peer {
    stream: UnixStream,
    decoder: Decoder,
    // One decoder-owned deferred frame plus at most one CHUNK of trailing wire.
    trailing: Vec<u8>,
    deferred: Option<u64>,
    attached: bool,
    caps: u64,
    input_reply: Option<InputReply>,
    writer: Option<u32>,
    // Selection mode belongs to this socket, never to the retained writer cursor.
    shared_writer: bool,
    ack_queued: u64,
    size: (u16, u16, u16, u16),
    cursor: Option<u64>,
    pending: Vec<u8>,
    written: usize,
    exited_sent: bool,
    stopping: bool,
    request: Option<Request>,
}
impl Peer {
    #[cfg(feature = "process-per-user")]
    fn buffer_bytes(&self) -> usize {
        self.decoder.allocated_bytes() + self.pending.capacity() + self.trailing.capacity()
    }
    /// Capacity cannot hide a malformed range. Shared requests reserve space
    /// before acceptance; neither geometry nor durable ownership changes here.
    fn input_waits(
        &self,
        sequence: u64,
        length: usize,
        accepted: u64,
        available: usize,
        reserved: bool,
    ) -> io::Result<bool> {
        if self.caps & SHARED_WRITER == 0 && !reserved {
            return Ok(false);
        }
        let end = sequence
            .checked_add(length as u64)
            .ok_or_else(invalid_input)?;
        if sequence > accepted {
            return Err(invalid_input());
        }
        let unseen = usize::try_from(end.saturating_sub(accepted)).map_err(|_| invalid_input())?;
        if unseen > 0 && reserved && self.caps & SHARED_WRITER == 0 {
            // Reserved space is unavailable to a fresh legacy request. Keep
            // capacity refusal, while duplicates and control requests proceed.
            return Err(invalid_input());
        }
        Ok(unseen > 0 && (reserved || unseen > available))
    }
    /// Ownership links never enter writer replacement or output backpressure.
    fn attach(&mut self, caps: u64) -> io::Result<()> {
        if self.attached {
            return Err(invalid_input());
        }
        self.attached = true;
        self.caps = caps
            & (SEQUENCED_INPUT
                | MULTI_WRITER
                | APPROXIMATE_SNAPSHOT
                | SESSION_OWNER
                | SHARED_WRITER
                | QUERY_REPLIES
                | CLOSE_SESSION
                | SHELL_CLEANUP);
        if self.caps & (SESSION_OWNER | SHELL_CLEANUP) != 0 {
            if self.caps != SESSION_OWNER && self.caps != SHELL_CLEANUP {
                return Err(invalid_input());
            }
            self.writer = None;
        } else if self.caps & SHARED_WRITER != 0
            && self.caps & (SEQUENCED_INPUT | MULTI_WRITER) != (SEQUENCED_INPUT | MULTI_WRITER)
        {
            return Err(invalid_input());
        } else if self.caps & MULTI_WRITER != 0 {
            if self.caps & SEQUENCED_INPUT == 0 {
                return Err(invalid_input());
            }
            self.writer = None;
        }
        Ok(())
    }
    fn queue(&mut self, frame: &Frame) -> io::Result<()> {
        frame.encode_into(&mut self.pending)?;
        self.written = 0;
        Ok(())
    }
    fn snapshot(&mut self, terminal: &impl SessionTerminal, head: u64) -> io::Result<()> {
        match terminal.snapshot() {
            Ok(bytes) => {
                self.queue(&Frame::Snapshot(head, bytes))?;
                self.cursor = Some(head);
            }
            Err(_) if self.caps & APPROXIMATE_SNAPSHOT != 0 => {
                self.queue(&Frame::SnapshotWithFlags(
                    head,
                    1,
                    terminal.approximate_snapshot(),
                ))?;
                self.cursor = Some(head);
            }
            Err(error) => {
                // A restoration API gap is not a frame-size overflow. Legacy
                // peers get the real bounded reason, with no source mutation.
                let code = if error.kind() == io::ErrorKind::Unsupported {
                    2
                } else {
                    1
                };
                self.queue(&Frame::Error(code, error.to_string()))?;
                self.cursor = None;
            }
        }
        Ok(())
    }
    /// Both explicit resizing and last-typist selection share refusal recovery.
    /// Accepted input stays owned by the shim even when native geometry is refused.
    fn resize(
        &mut self,
        pty: &mut Pty,
        terminal: &mut impl SessionTerminal,
        ring: &Ring,
        config: &mut Config,
    ) -> io::Result<bool> {
        let (cols, rows, px_w, px_h) = self.size;
        pty.resize(cols, rows, px_w, px_h)?;
        // Origin bytes alone cannot certify history at a changed geometry;
        // the terminal independently verifies provenance before reconstructing.
        trace_host!(
            ResizeStart,
            config.session,
            pty.master.as_raw_fd(),
            ring.head(),
            0
        );
        let resized = if ring.start() == 0 {
            terminal.resize_with_ring(cols, rows, Some(ring))
        } else {
            terminal.resize(cols, rows)
        };
        trace_host!(
            ResizeDone,
            config.session,
            pty.master.as_raw_fd(),
            ring.head(),
            0
        );
        if resized.is_err() {
            pty.resize(config.cols, config.rows, 0, 0)?;
            // Do not retry the refused geometry on the next accepted key.
            self.size = (config.cols, config.rows, 0, 0);
            if self.cursor.is_some() || matches!(self.request, Some(Request::Read(_))) {
                self.request = Some(Request::Snapshot);
            }
            // Control-only peers keep their ordered InputState fence; the
            // terminal provenance selects a notice on their next ReadFrom.
            return Ok(false);
        }
        config.cols = cols;
        config.rows = rows;
        Ok(true)
    }
    #[cfg(not(feature = "process-per-user"))]
    fn flush(&mut self) -> io::Result<()> {
        while self.written < self.pending.len() {
            match self.stream.write(&self.pending[self.written..]) {
                Ok(0) => return Err(io::ErrorKind::BrokenPipe.into()),
                Ok(n) => self.written += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        self.pending.clear();
        self.written = 0;
        Ok(())
    }
    #[cfg(feature = "process-per-user")]
    fn flush(&mut self) -> io::Result<()> {
        let mut bytes = usize::MAX;
        let mut attempts = usize::MAX;
        self.flush_bounded(&mut bytes, &mut attempts)
    }
    /// Shared hosts spend one byte/syscall budget across state and output
    /// frames. A partial write retains the original frame and cursor; only a
    /// completed frame may release its storage or admit a following frame.
    #[cfg(feature = "process-per-user")]
    fn flush_bounded(&mut self, bytes: &mut usize, attempts: &mut usize) -> io::Result<()> {
        while self.written < self.pending.len() && *bytes > 0 && *attempts > 0 {
            let end = self.pending.len().min(self.written.saturating_add(*bytes));
            *attempts -= 1;
            trace_host!(
                SocketWriteStart,
                [0; 16],
                self.stream.as_raw_fd(),
                self.cursor.unwrap_or(0),
                end - self.written
            );
            match self.stream.write(&self.pending[self.written..end]) {
                Ok(0) => return Err(io::ErrorKind::BrokenPipe.into()),
                Ok(n) => {
                    self.written += n;
                    *bytes -= n;
                    trace_host!(
                        SocketWriteDone,
                        [0; 16],
                        self.stream.as_raw_fd(),
                        u64::try_from(self.written).map_err(io::Error::other)?,
                        n,
                        self.pending.len()
                    );
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if self.written == self.pending.len() {
            self.pending.clear();
            if self.pending.capacity() > CHUNK * 4 {
                // Completion may be the last event before an indefinite idle
                // wait. Release large repaint storage at that boundary.
                self.pending = Vec::new();
            }
            self.written = 0;
        }
        Ok(())
    }
}
fn private_dir(path: &Path) -> io::Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "session directory must be owned by shim uid with mode 0700",
        ));
    }
    Ok(())
}

/// Same-UID shim clients are trusted; other UIDs need root privileges to connect.
fn shim_peer_uid_allowed(peer_uid: u32, agent_uid: u32) -> bool {
    peer_uid == 0 || peer_uid == agent_uid
}

#[cfg(test)]
mod peer_uid_tests {
    use super::shim_peer_uid_allowed;

    #[test]
    fn different_uid_shim_socket_peer_is_refused() {
        assert!(shim_peer_uid_allowed(1500, 1500));
        assert!(shim_peer_uid_allowed(0, 1500));
        assert!(!shim_peer_uid_allowed(65534, 1500));
    }
}

/// The connecting process's effective uid, recorded by the kernel at connect
/// time: `SO_PEERCRED` on Linux, `getpeereid` (`LOCAL_PEERCRED`) on macOS.
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    Ok(getsockopt(stream, PeerCredentials)
        .map_err(io::Error::from)?
        .uid())
}
#[cfg(target_os = "macos")]
/// The connecting process's effective uid on macOS, from `getpeereid` (`LOCAL_PEERCRED`).
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    Ok(nix::unistd::getpeereid(stream)
        .map_err(io::Error::from)?
        .0
        .as_raw())
}

/// SIGCHLD readiness for the poll loop, with SIGCHLD blocked so no handler runs:
/// a signalfd on Linux; on macOS a kqueue `EVFILT_SIGNAL` filter, which records
/// delivery attempts of the blocked signal and whose descriptor is pollable.
#[cfg(target_os = "linux")]
struct ChildSignals(nix::sys::signalfd::SignalFd);
#[cfg(target_os = "linux")]
impl ChildSignals {
    /// A signalfd for `mask`, which the caller has blocked.
    fn new(mask: SigSet) -> io::Result<Self> {
        use nix::sys::signalfd::{SfdFlags, SignalFd};
        SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC)
            .map(Self)
            .map_err(io::Error::from)
    }
    /// The descriptor the poll loop waits on.
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_fd()
    }
    /// Consume every queued signal so the descriptor reads as idle again.
    fn drain(&self) -> io::Result<()> {
        while self.0.read_signal().map_err(io::Error::from)?.is_some() {}
        Ok(())
    }
}
#[cfg(target_os = "macos")]
/// SIGCHLD readiness on macOS: a kqueue with one `EVFILT_SIGNAL` filter per signal.
struct ChildSignals(nix::sys::event::Kqueue);
#[cfg(target_os = "macos")]
impl ChildSignals {
    /// A zero timeout: register or drain without blocking.
    const NOW: nix::libc::timespec = nix::libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    /// A kqueue watching each signal in `mask`, which the caller has blocked.
    fn new(mask: SigSet) -> io::Result<Self> {
        use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};
        let queue = Kqueue::new().map_err(io::Error::from)?;
        let changes: Vec<KEvent> = mask
            .iter()
            .map(|signal| {
                KEvent::new(
                    signal as usize,
                    EventFilter::EVFILT_SIGNAL,
                    EvFlags::EV_ADD | EvFlags::EV_CLEAR,
                    FilterFlag::empty(),
                    0,
                    0,
                )
            })
            .collect();
        queue
            .kevent(&changes, &mut [], Some(Self::NOW))
            .map_err(io::Error::from)?;
        Ok(Self(queue))
    }
    /// The kqueue descriptor, which poll(2) reports readable when a signal arrived.
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_fd()
    }
    /// Read queued signal events until none are left.
    fn drain(&self) -> io::Result<()> {
        use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};
        let mut events = [KEvent::new(
            0,
            EventFilter::EVFILT_SIGNAL,
            EvFlags::empty(),
            FilterFlag::empty(),
            0,
            0,
        ); 4];
        while self
            .0
            .kevent(&[], &mut events, Some(Self::NOW))
            .map_err(io::Error::from)?
            == events.len()
        {}
        Ok(())
    }
}

fn socket(config: &Config) -> io::Result<(UnixListener, SocketPath)> {
    let state = if let Some(path) = &config.state {
        path.clone()
    } else if Uid::effective().is_root() {
        // Root runtime state that the OS clears at boot: /run on Linux,
        // /var/run (/private/var/run) on macOS, which has no /run.
        PathBuf::from(if cfg!(target_os = "macos") {
            "/var/run/infraternal"
        } else {
            "/run/infraternal"
        })
    } else {
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .ok_or_else(|| io::Error::other("rootless shim requires XDG_RUNTIME_DIR"))?;
        let runtime = PathBuf::from(runtime);
        let metadata = fs::symlink_metadata(&runtime)?;
        if !metadata.is_dir()
            || metadata.uid() != Uid::effective().as_raw()
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid runtime directory",
            ));
        }
        runtime.join("infraternal")
    };
    private_dir(&state)?;
    let sessions = state.join("sessions");
    private_dir(&sessions)?;
    let mut id = String::with_capacity(32);
    for byte in config.session {
        let _ = write!(id, "{byte:02x}");
    }
    let path = sessions.join(format!("{id}.sock"));
    // Never remove an existing socket: a second startup must not steal a live
    // session's rendezvous. Stale cleanup belongs to the infraternal agent.
    if path.with_extension("ended").try_exists()? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "session identity already ended",
        ));
    }
    let listener = UnixListener::bind(&path)?;
    let mut guard = SocketPath(path, false);
    fs::set_permissions(&guard.0, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    if config.readiness {
        // Only the fixed non-login probe publishes this role, before admitting
        // peers. A person terminal must never acquire this cleanup exemption.
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(guard.0.with_extension("readiness"))?;
        guard.1 = true;
    }
    Ok((listener, guard))
}
/// Run one Linux session through final delivery, owner release or the bounded exit ceiling.
/// # Errors
/// Returns invalid startup configuration, account, PTY, socket or resource failures.
pub fn run(config: Config) -> io::Result<()> {
    run_with_retention(config, crate::ended::MAX_RETENTION)
}

/// Run with a shortened exit ceiling for deterministic real-PTY verification.
/// # Errors
/// Returns the same errors as [`run`]; durations above ten minutes are clamped.
#[allow(clippy::too_many_lines)]
pub fn run_with_retention(config: Config, retention: Duration) -> io::Result<()> {
    run_configured(config, retention, None, None)
}

/// Place the privileged PTY owner in its authenticated login before Hello.
/// The account worker starts the real shell first, so shell initialization can
/// overlap the owner's cgroup migration. Account sockets remain authenticated
/// on the descriptor-transfer connection; this does not change shell membership.
/// # Errors
/// Rejects invalid placement coordinates and returns normal shim startup errors.
#[cfg(feature = "host-login")]
pub fn run_with_login_group(config: Config, retention: Duration, group: &Path) -> io::Result<()> {
    // Placement failure is cleaned up by the authenticated worker's terminal
    // lease. Local/probe Child drop cannot provide that lifetime guarantee.
    if config.login_socket.is_none() || config.readiness {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host login placement requires a login worker terminal",
        ));
    }
    run_configured(config, retention, Some(group), None)
}

/// Adopt a controller-prestarted shell on the same pinned worker connection.
/// Inherited descriptor integers are borrowed for this dedicated shim process;
/// all originals must close when it exits. No pathname reconnect can substitute
/// a different worker. Placement still precedes framed Hello.
/// # Errors
/// Rejects local/probe modes, absent identity, invalid descriptors and startup refusal.
#[cfg(feature = "host-login")]
pub fn run_with_prestarted_login(
    config: Config,
    retention: Duration,
    group: Option<&Path>,
    master: i32,
    lease: i32,
) -> io::Result<()> {
    if config.readiness
        || config.login_socket.is_none()
        || (!Uid::effective().is_root() && config.uid != Uid::effective().as_raw())
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let pid = config.login_worker_pid.ok_or(io::ErrorKind::InvalidInput)?;
    let pin = config
        .login_worker_proc
        .as_deref()
        .ok_or(io::ErrorKind::InvalidInput)?;
    let pty = crate::login_handoff::adopt(
        master,
        lease,
        config.uid,
        pid,
        pin,
        config.login_worker_parent,
    )?;
    run_configured(config, retention, group, Some(pty))
}

#[allow(clippy::too_many_lines)]
fn run_configured(
    mut config: Config,
    retention: Duration,
    group: Option<&Path>,
    prestarted: Option<Pty>,
) -> io::Result<()> {
    #[cfg(feature = "host-login")]
    let placement = group
        .map(|path| {
            use std::os::unix::fs::OpenOptionsExt as _;
            if !path.starts_with("/sys/fs/cgroup")
                || path.file_name().is_none_or(|name| name != "cgroup.procs")
            {
                return Err(io::Error::other("invalid host login cgroup path"));
            }
            fs::OpenOptions::new()
                .write(true)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(path)
        })
        .transpose()?;
    #[cfg(not(feature = "host-login"))]
    debug_assert!(group.is_none());
    if config.cols == 0
        || config.rows == 0
        || usize::from(config.cols) * usize::from(config.rows) > 200_000
        || config.ring_capacity == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid terminal dimensions or ring capacity",
        ));
    }
    // Sparse terminal mappings can gain ~2 MiB of resident holes while idle
    // when khugepaged collapses them (#24). Opt out before allocating terminal
    // state; the PTY child restores the inherited policy before exec.
    let child_thp = crate::pty::disable_shim_thp()?;
    // Startup is single threaded; restrictive umask also protects bind's brief
    // interval before chmod. The shim retains this mask for its whole lifetime.
    umask(Mode::from_bits_truncate(0o077));
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGCHLD);
    mask.thread_block().map_err(io::Error::from)?;
    let signals = ChildSignals::new(mask)?;
    // A root shim on macOS refuses debugger attach for its lifetime; core files
    // are already refused by the hard RLIMIT_CORE of 0 set in main (#328).
    #[cfg(target_os = "macos")]
    crate::pty::deny_debugger()?;
    #[cfg(feature = "host-login")]
    if !Uid::effective().is_root() && config.login_socket.is_none() && !config.readiness {
        // Own only this terminal's descendants, never every process of the
        // inherited host account. Detached jobs are adopted for revocation.
        nix::sys::prctl::set_child_subreaper(true).map_err(io::Error::from)?;
    }
    let (listener, path) = socket(&config)?;
    // Bind before spawning: a conflicting endpoint must not leave a new
    // untracked shell behind. Cleanup Hello carries identity only.
    #[cfg(feature = "host-login")]
    let mut cleanup =
        if !Uid::effective().is_root() && config.login_socket.is_none() && !config.readiness {
            Some(terminal_cleanup(&path.0, &config)?)
        } else {
            None
        };

    let mut pty = if let Some(pty) = prestarted {
        pty
    } else if config.readiness {
        Pty::spawn_with_readiness(config.uid, config.cols, config.rows, true, child_thp)?
    } else if config.login_socket.is_some() {
        Pty::spawn_with_login(
            config.uid,
            config.cols,
            config.rows,
            &config.session,
            config.login_socket.as_deref(),
            config.login_worker_pid,
            config.login_worker_parent,
            config.login_worker_proc.as_deref(),
        )?
    } else {
        Pty::spawn_with_command(
            config.uid,
            config.cols,
            config.rows,
            false,
            &config.command,
            child_thp,
        )?
    };
    #[cfg(feature = "host-login")]
    if let Some(mut placement) = placement {
        placement.write_all(nix::unistd::getpid().as_raw().to_string().as_bytes())?;
    }
    let created = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis(),
    )
    .map_err(io::Error::other)?;
    let mut terminal = Terminal::new(config.cols, config.rows)?;
    let mut ring = Ring::new(config.ring_capacity);
    let mut input = VecDeque::new();
    let mut cursors = Inputs::with_geometry((config.cols, config.rows, 0, 0));
    let mut peers: Vec<Peer> = Vec::new();
    let mut exit = None;
    let mut exit_deadline = None;
    let mut drained = false;
    // A private probe owns no durable terminal. A lost open reply or server
    // transport cannot leave its read waiting forever; ordinary live PTYs have no timer.
    let readiness_deadline = config
        .readiness
        .then(|| Instant::now() + Duration::from_secs(10));
    let mut next_deferred = 0_u64;
    loop {
        if readiness_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            if exit.is_none() {
                pty.child.kill()?;
                let _ = pty.child.wait()?;
            }
            return Ok(());
        }
        if exit.is_none()
            && let Some(status) = pty.child.try_wait()?
        {
            exit_deadline = Some(Instant::now() + retention.min(crate::ended::MAX_RETENTION));
            exit = Some(
                status
                    .code()
                    .unwrap_or_else(|| -status.signal().unwrap_or(1)),
            );
        }
        #[cfg(feature = "host-login")]
        if let Some(cleanup) = &mut cleanup
            && cleanup.requested()
        {
            if exit.is_none() {
                pty.child.kill()?;
            } else {
                crate::login::finish_children()?;
                cleanup.confirm();
            }
        }
        // The oldest deferred request reserves newly freed queue space. Smaller
        // fresh inputs cannot repeatedly consume it; duplicates need no space.
        let oldest = peers.iter().filter_map(|p| p.deferred).min();
        let mut retired = Vec::new();
        for (index, p) in peers.iter_mut().enumerate() {
            if p.deferred.is_none() && p.trailing.is_empty() {
                continue;
            }
            let mut trailing = std::mem::take(&mut p.trailing);
            match consume_peer(
                &trailing,
                p,
                &mut pty,
                &mut terminal,
                &ring,
                &mut config,
                &mut input,
                &mut cursors,
                exit.is_some() && drained,
                oldest.is_some() && p.deferred != oldest,
                &mut next_deferred,
            ) {
                Ok((false, used)) => {
                    trailing.drain(..used);
                    p.trailing = trailing;
                }
                Ok((true, _)) | Err(_) => retired.push(index),
            }
        }
        for index in retired.into_iter().rev() {
            peers.remove(index);
        }
        if peers.iter().filter_map(|p| p.deferred).min() != oldest {
            // Successful admission (or malformed-peer removal) advances the
            // reservation before polling; another deferred frame may now fit.
            continue;
        }
        for p in &mut peers {
            // Cleanup is independent of output credit and a retained owner.
            // SIGCHLD/try_wait supplies proof; sending a signal alone does not.
            if p.stopping && exit.is_some() && p.pending.is_empty() {
                #[cfg(feature = "host-login")]
                crate::login::finish_children()?;
                p.queue(&Frame::ShellStopped)?;
                p.stopping = false;
            }
            if p.caps & SEQUENCED_INPUT != 0
                && p.writer.is_some()
                && cursors.get(p.writer)?.written > p.ack_queued
                && p.input_reply.is_none()
            {
                p.input_reply = Some(InputReply::Ack);
            }
            if p.pending.is_empty()
                && let Some(reply) = p.input_reply.take()
            {
                let state = cursors.get(p.writer)?;
                p.ack_queued = state.written;
                p.queue(&match reply {
                    InputReply::State => Frame::InputState(state.written, state.accepted),
                    InputReply::Ack => Frame::InputAck(state.written),
                })?;
            }
            if p.pending.is_empty()
                && let Some(request) = p.request.take()
            {
                match request {
                    Request::Read(seq) => p.cursor = Some(seq),
                    Request::Snapshot => p.snapshot(&terminal, ring.head())?,
                }
            }
            if p.pending.is_empty()
                && let Some(seq) = p.cursor
            {
                if seq < ring.start() {
                    p.snapshot(&terminal, ring.head())?;
                } else if seq < ring.head() {
                    let bytes = ring
                        .read(seq, CHUNK)
                        .ok_or_else(|| io::Error::other("delivery cursor invariant"))?;
                    p.cursor = Some(seq + bytes.len() as u64);
                    p.queue(&Frame::Output(seq, bytes))?;
                } else if drained
                    && !p.exited_sent
                    && let Some(status) = exit
                {
                    p.queue(&Frame::Exited(status, ring.head()))?;
                    p.exited_sent = true;
                }
            }
        }
        // Private probes are not resumable: retire once confirmed exit delivery
        // has drained. Ordinary terminal ownership and exit acknowledgment stay unchanged.
        if config.readiness
            && exit.is_some()
            && drained
            // An input-only control peer can finish the fixed command before
            // its output peer attaches. Empty all() is not delivery evidence.
            && peers.iter().any(|p| p.cursor.is_some() && p.exited_sent)
            && peers
                .iter()
                .filter(|p| p.cursor.is_some())
                .all(|p| p.exited_sent && p.pending.is_empty())
        {
            return Ok(());
        }
        // Ownership is independent of data peers: an unfunded window releases
        // its data link but retains this small control link until ordered delivery
        // or close. The one-shot deadline cannot be renewed by another attach.
        let expired = exit_deadline.is_some_and(|deadline| Instant::now() >= deadline);
        let owned = peers
            .iter()
            .any(|p| p.attached && matches!(p.caps, SESSION_OWNER | SHELL_CLEANUP))
            || {
                #[cfg(feature = "host-login")]
                {
                    cleanup
                        .as_ref()
                        .is_some_and(|cleanup| cleanup.peer().is_some())
                }
                #[cfg(not(feature = "host-login"))]
                {
                    false
                }
            };
        if !config.readiness
            && let Some(status) = exit
            && (expired
                || (drained
                    && !config.retain_output
                    && !owned
                    && peers
                        .iter()
                        .filter(|p| p.cursor.is_some())
                        .all(|p| p.exited_sent && p.pending.is_empty())))
        {
            #[cfg(feature = "host-login")]
            if !Uid::effective().is_root() && config.login_socket.is_none() {
                // An ended record also certifies retirement of adopted jobs.
                // Never leave descendants beyond the owning shim's lifetime.
                crate::login::finish_children()?;
            }
            crate::ended::record(&path.0, status, ring.head())?;
            #[cfg(feature = "host-login")]
            if let Some(cleanup) = &cleanup {
                cleanup.retire_attribution()?;
            }
            return Ok(());
        }
        // Borrow descriptors only through poll. Every queue and ownership
        // mutation happens after this scope, so replacement cannot leave a
        // PollFd referring to a closed/reused file descriptor.
        // A fast viewer permits PTY progress. Lagging viewers catch up from
        // the ring or a snapshot; when every viewer stalls the old bounded
        // backpressure rule still applies until their daemon links detach.
        let can_read = !drained
            && (!peers.iter().any(|p| p.cursor.is_some())
                || peers.iter().any(|p| {
                    p.pending.is_empty() && p.cursor.is_some_and(|seq| seq == ring.head())
                }));
        let ready = {
            let has_input = !input.is_empty();
            // Stack slots preserve the allocation-free readiness loop. Disabled
            // PTYs are omitted because level-triggered HUP would otherwise spin.
            let mut fds: [PollFd<'_>; MAX_PEERS + 6] =
                std::array::from_fn(|_| PollFd::new(listener.as_fd(), PollFlags::empty()));
            fds[0] = PollFd::new(listener.as_fd(), PollFlags::POLLIN);
            fds[1] = PollFd::new(signals.as_fd(), PollFlags::POLLIN);
            if can_read || has_input {
                fds[2] = PollFd::new(
                    pty.master.as_fd(),
                    (if can_read {
                        PollFlags::POLLIN
                    } else {
                        PollFlags::empty()
                    }) | (if has_input {
                        PollFlags::POLLOUT
                    } else {
                        PollFlags::empty()
                    }),
                );
            }
            // A login shell is reaped by its worker. Its fixed status arrives
            // on the retained lease socket, replacing proxy SIGCHLD readiness.
            #[cfg(feature = "host-login")]
            if let Some(descriptor) = pty.child.descriptor() {
                fds[3] = PollFd::new(descriptor, PollFlags::POLLIN);
            }
            #[cfg(feature = "host-login")]
            if let Some(cleanup) = &cleanup {
                fds[4] = PollFd::new(cleanup.listener().as_fd(), PollFlags::POLLIN);
                if let Some(peer) = cleanup.peer() {
                    fds[5] = PollFd::new(
                        peer.as_fd(),
                        (if cleanup.reading() {
                            PollFlags::POLLIN
                        } else {
                            PollFlags::empty()
                        }) | if cleanup.writable() {
                            PollFlags::POLLOUT
                        } else {
                            PollFlags::empty()
                        },
                    );
                }
            }
            for (index, p) in peers.iter().enumerate() {
                let mut flags = PollFlags::empty();
                if p.deferred.is_none() && p.trailing.is_empty() {
                    flags |= PollFlags::POLLIN;
                }
                if !p.pending.is_empty() {
                    flags |= PollFlags::POLLOUT;
                }
                // Empty flags still observe HUP. A deferred peer is retired on
                // HUP without reading; live deferred sockets create no wakeups.
                fds[index + 6] = PollFd::new(p.stream.as_fd(), flags);
            }
            // Once the owned child exits, a descendant may hold the slave open
            // without producing a readiness event. Probe the nonblocking master
            // immediately, while retaining viewer backpressure during the drain.
            // Wake at the earliest private-probe or ordinary exit deadline;
            // no deadline keeps the live PTY fully event-driven.
            let timeout = if exit.is_some() && can_read {
                nix::poll::PollTimeout::ZERO
            } else {
                exit_deadline
                    .into_iter()
                    .chain(readiness_deadline)
                    .min()
                    .map_or(nix::poll::PollTimeout::NONE, |deadline| {
                        // Round upward: a submillisecond remainder must not busy-loop.
                        nix::poll::PollTimeout::try_from(
                            deadline.saturating_duration_since(Instant::now())
                                + Duration::from_millis(1),
                        )
                        .unwrap_or(nix::poll::PollTimeout::MAX)
                    })
            };
            match poll(&mut fds[..peers.len() + 6], timeout) {
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(e.into()),
            }
            let flags = |i: usize| fds[i].revents().unwrap_or_else(PollFlags::empty);
            let peer_flags: [PollFlags; MAX_PEERS] = std::array::from_fn(|i| flags(i + 6));
            (flags(0), flags(1), flags(2), peer_flags, flags(4), flags(5))
        };
        if ready.1.contains(PollFlags::POLLIN) {
            signals.drain()?;
            #[cfg(feature = "host-login")]
            if !Uid::effective().is_root() && config.login_socket.is_none() && !config.readiness {
                // Reap only on child readiness, with no idle scan or timer.
                // OwnedChild must retain the main shell's actual exit status.
                // Once status is owned, its old numeric PID can be reused and
                // must no longer exclude another adopted job from reaping.
                crate::login::reap_terminal_jobs(exit.is_none().then(|| pty.child.id()))?;
            }
        }
        #[cfg(feature = "host-login")]
        if let Some(cleanup) = &mut cleanup {
            // Lifecycle descriptors never depend on input capacity or ordinary
            // link admission. Its fixed request is independent of input bytes.
            if ready.5.intersects(PollFlags::POLLHUP | PollFlags::POLLERR) {
                cleanup.disconnect();
            } else if ready.5.contains(PollFlags::POLLOUT) {
                cleanup.flush();
            }
            if ready.5.contains(PollFlags::POLLIN) {
                cleanup.read_request();
                if cleanup.requested() {
                    continue;
                }
            }
            if ready.4.contains(PollFlags::POLLIN) {
                cleanup.accept()?;
                if cleanup.requested() {
                    continue;
                }
            }
        }
        if ready.0.contains(PollFlags::POLLIN) {
            // Accept at most one per iteration: a peer flooding connect cannot
            // starve PTY progress. Authenticate before replacing the old peer.
            match listener.accept() {
                Ok((stream, _)) => {
                    if shim_peer_uid_allowed(peer_uid(&stream)?, Uid::effective().as_raw())
                        && peers.len() < MAX_PEERS
                    {
                        stream.set_nonblocking(true)?;
                        let mut next = Peer {
                            stream,
                            decoder: Decoder::default(),
                            trailing: Vec::new(),
                            deferred: None,
                            attached: false,
                            caps: 0,
                            input_reply: None,
                            writer: Some(0),
                            shared_writer: false,
                            ack_queued: 0,
                            size: (config.cols, config.rows, 0, 0),
                            cursor: None,
                            pending: Vec::new(),
                            written: 0,
                            exited_sent: false,
                            stopping: false,
                            request: None,
                        };
                        next.queue(&Frame::Hello {
                            version: 1,
                            caps: SEQUENCED_INPUT
                                | MULTI_WRITER
                                | APPROXIMATE_SNAPSHOT
                                | SHARED_WRITER
                                | QUERY_REPLIES
                                | CLOSE_SESSION
                                // A private probe has no durable ended record.
                                // Its ownership EOF could otherwise overtake
                                // buffered output/Exited in the host relay.
                                | if config.readiness { 0 } else { SESSION_OWNER }
                                | if cfg!(feature = "host-login") && !Uid::effective().is_root() && config.login_socket.is_none() && !config.readiness { SHELL_CLEANUP } else { 0 }
                                | SHARED_WRITER,
                            session: config.session,
                            pid: std::process::id(),
                            cols: config.cols,
                            rows: config.rows,
                            created,
                            head: ring.head(),
                            start: ring.start(),
                        })?;
                        peers.push(next);
                        continue; // descriptors added after poll have no readiness yet
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        if ready.2.contains(PollFlags::POLLOUT) {
            {
                let (first, second) = input.as_slices();
                let bytes = if first.is_empty() { second } else { first };
                match pty.master.write(bytes) {
                    Ok(n) => {
                        input.drain(..n);
                        cursors.advance(n)?;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) if e.raw_os_error() == Some(nix::libc::EIO) => {
                        input.clear();
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        if !drained
            && (ready.2.intersects(PollFlags::POLLIN | PollFlags::POLLHUP)
                || (exit.is_some() && can_read))
        {
            let mut bytes = [0; CHUNK];
            let limit = CHUNK.min(config.ring_capacity);
            let mut used = 0;
            // Linux PTYs commonly return ~4 KiB despite a 16 KiB destination.
            // Drain immediately-ready bytes, but never wait to fill a batch.
            // Both byte and syscall bounds preserve input/resize/socket fairness.
            for _ in 0..16 {
                match pty.master.read(&mut bytes[used..limit]) {
                    Ok(0) => {
                        drained = true;
                        break;
                    }
                    Ok(n) => {
                        used += n;
                        if used == limit {
                            break;
                        }
                    }
                    Err(e) if e.raw_os_error() == Some(nix::libc::EIO) => {
                        drained = true;
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // Background descendants may keep the slave open after
                        // the owned shell exits. Drain ready bytes, never wait
                        // indefinitely for an unrelated descendant to close it.
                        drained = exit.is_some();
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            if used > 0 {
                terminal.process(&bytes[..used]);
                ring.append(&bytes[..used])?;
            }
        }

        let mut disconnects = [false; MAX_PEERS];
        for (index, p) in peers.iter_mut().enumerate() {
            let flags = ready.3[index];
            let mut disconnect = flags.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL);
            if flags.contains(PollFlags::POLLOUT) && p.flush().is_err() {
                disconnect = true;
            }
            if p.deferred.is_some() && flags.contains(PollFlags::POLLHUP) {
                disconnect = true;
            }
            if p.deferred.is_none() && flags.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
                let mut bytes = [0; CHUNK];
                match p.stream.read(&mut bytes) {
                    Ok(0) => disconnect = true,
                    Ok(n) => {
                        let reserved = oldest.is_some();
                        match consume_peer(
                            &bytes[..n],
                            p,
                            &mut pty,
                            &mut terminal,
                            &ring,
                            &mut config,
                            &mut input,
                            &mut cursors,
                            exit.is_some() && drained,
                            reserved,
                            &mut next_deferred,
                        ) {
                            Ok((false, used)) => p.trailing.extend_from_slice(&bytes[used..n]),
                            Ok((true, _)) | Err(_) => disconnect = true,
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => disconnect = true,
                }
            }
            disconnects[index] = disconnect;
        }
        // Coexisting ordinary/shared sockets use the same durable input cursor.
        // Replacement stays within a mode, including legacy writer zero. Decide
        // before removal so rejected successors and shifting indices cannot evict
        // a live peer; no admission failure mutates retained writer ownership.
        for index in 0..peers.len() {
            let p = &peers[index];
            let duplicate = p.attached
                && p.writer.is_some_and(|id| {
                    peers[index + 1..].iter().enumerate().any(|(offset, next)| {
                        !disconnects[index + 1 + offset]
                            && next.attached
                            && next.writer == Some(id)
                            && next.shared_writer == p.shared_writer
                    })
                });
            disconnects[index] |= duplicate;
        }
        for index in (0..peers.len()).rev() {
            if disconnects[index] {
                peers.remove(index);
            }
        }
    }
}

#[cfg(feature = "host-login")]
#[cold]
fn terminal_cleanup(path: &Path, config: &Config) -> io::Result<crate::cleanup::Cleanup> {
    let mut proof = Vec::new();
    Frame::Hello {
        version: 1,
        caps: SHELL_CLEANUP,
        session: config.session,
        pid: std::process::id(),
        cols: config.cols,
        rows: config.rows,
        created: 0,
        head: 0,
        start: 0,
    }
    .encode_into(&mut proof)?;
    // encode_into resets reusable storage; these are two consecutive frames.
    proof.extend_from_slice(&Frame::ShellStopped.encode()?);
    crate::cleanup::Cleanup::bind(path, Uid::effective().as_raw(), proof)
}
// Cleanup must not enlarge the ordinary input request's instruction working set.
#[cold]
#[inline(never)]
fn stop_shell(
    frame: &FrameRef<'_>,
    p: &mut Peer,
    pty: &mut Pty,
    config: &Config,
    exited: bool,
) -> io::Result<bool> {
    if !matches!(frame, FrameRef::Owned(Frame::StopShell))
        || !cfg!(feature = "host-login")
        || Uid::effective().is_root()
        || config.login_socket.is_some()
        || config.readiness
    {
        return Err(invalid_input());
    }
    // Kill the owned shell, even when a foreground job has a different group.
    // Only its reaped exit and retired descendants produce ShellStopped.
    if !exited && pty.child.try_wait()?.is_none() {
        pty.child.kill()?;
    }
    p.stopping = true;
    Ok(false)
}

/// Stop exactly at an unaccepted input frame; trailing wire belongs to this peer.
#[allow(clippy::too_many_arguments)]
fn consume_peer(
    bytes: &[u8],
    p: &mut Peer,
    pty: &mut Pty,
    terminal: &mut impl SessionTerminal,
    ring: &Ring,
    config: &mut Config,
    input: &mut VecDeque<u8>,
    cursors: &mut Inputs,
    exited: bool,
    mut reserved: bool,
    next_deferred: &mut u64,
) -> io::Result<(bool, usize)> {
    let mut decoder = std::mem::take(&mut p.decoder);
    let mut acknowledged_exit = false;
    let mut paused = false;
    let result = decoder.feed_until(bytes, |frame| {
        if acknowledged_exit {
            return Ok(true);
        }
        match handle(
            frame, p, pty, terminal, ring, config, input, cursors, exited, reserved,
        ) {
            Ok(acknowledged) => {
                if p.deferred.take().is_some() {
                    // The completed request releases its ticket. Fresh input in
                    // the same read must yield to already waiting peers; give it
                    // a new ticket on the next pause. Duplicates/control are free.
                    reserved = true;
                }
                acknowledged_exit = acknowledged;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                paused = true;
                Ok(false)
            }
            Err(error) => Err(error),
        }
    });
    p.decoder = decoder;
    let used = result?;
    if paused {
        if p.deferred.is_none() {
            p.deferred = Some(*next_deferred);
            *next_deferred = next_deferred.checked_add(1).ok_or_else(invalid_input)?;
        }
        debug_assert!(bytes.len() - used <= CHUNK);
    } else {
        p.deferred = None;
    }
    Ok((acknowledged_exit, used))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn handle<'a>(
    frame: impl Into<FrameRef<'a>>,
    p: &mut Peer,
    pty: &mut Pty,
    terminal: &mut impl SessionTerminal,
    ring: &Ring,
    config: &mut Config,
    input: &mut VecDeque<u8>,
    cursors: &mut Inputs,
    exited: bool,
    reserved: bool,
) -> io::Result<bool> {
    let invalid = invalid_request;
    let frame = frame.into();
    if let FrameRef::Owned(Frame::Attach(caps)) = frame {
        p.attach(caps)?;
        return Ok(false);
    }
    if p.attached && p.caps == SHELL_CLEANUP {
        return stop_shell(&frame, p, pty, config, exited);
    }
    if p.attached && p.caps == SESSION_OWNER {
        // A fixed zero State reply is a handshake barrier, never writer state.
        // It proves ownership was installed before the data link may detach.
        if matches!(frame, FrameRef::Owned(Frame::InputStateRequest)) && p.pending.is_empty() {
            p.queue(&Frame::InputState(0, 0))?;
            return Ok(false);
        }
        return Err(invalid());
    }
    if !p.attached
        || (p.writer.is_none()
            && !matches!(
                &frame,
                FrameRef::Owned(Frame::SelectWriter(_) | Frame::SelectSharedWriter(_))
            ))
    {
        return Err(invalid());
    }
    if let Some((offset, bytes)) = frame.input() {
        if exited || (offset.is_some() != (p.caps & SEQUENCED_INPUT != 0)) {
            return Err(invalid());
        }
        let writer = p.writer.ok_or_else(invalid)?;
        let accepted = cursors.get(p.writer)?.accepted;
        #[cfg(not(feature = "process-per-user"))]
        let available = MAX_FRAME - input.len();
        #[cfg(feature = "process-per-user")]
        let available = cursors.available(writer, input.len());
        if p.input_waits(
            offset.unwrap_or(accepted),
            bytes.len(),
            accepted,
            available,
            reserved,
        )? {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        cursors.accept(writer, offset.unwrap_or(accepted), bytes, input)?;
        trace_host!(
            InputQueued,
            config.session,
            p.stream.as_raw_fd(),
            accepted,
            usize::try_from(cursors.get(p.writer)?.accepted - accepted)
                .map_err(io::Error::other)?,
            writer as usize
        );
        if cursors.get(p.writer)?.accepted > accepted {
            // Only newly accepted input changes the active size [74]. Replayed
            // duplicate bytes cannot steal the last typist's terminal geometry.
            if cursors.active_writer != Some(writer) {
                p.size = cursors.get(p.writer)?.requested_size;
                let applied = p.resize(pty, terminal, ring, config)?;
                p.size = cursors.finish_resize(p.writer, applied)?;
                if applied {
                    cursors.active_writer = Some(writer);
                }
            }
        }
        if offset.is_some() && p.input_reply.is_none() {
            p.input_reply = Some(InputReply::Ack);
        }
        // The only input copy is into the surviving bounded queue. Try the PTY
        // immediately so batching output never adds a keystroke round trip.
        let (first, _) = input.as_slices();
        if !first.is_empty() {
            trace_host!(
                PtyWriteStart,
                config.session,
                pty.master.as_raw_fd(),
                0,
                first.len()
            );
            match pty.master.write(first) {
                Ok(n) => {
                    input.drain(..n);
                    cursors.advance(n)?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        return Ok(false);
    }
    // Output/Snapshot are invalid peer requests. Refuse without allocating.
    let FrameRef::Owned(frame) = frame else {
        return Err(invalid());
    };
    match frame {
        Frame::QueryReply(bytes) if p.caps & QUERY_REPLIES != 0 && !exited => {
            // Replies expire on reserved or full capacity without disconnecting
            // the peer; admission refusal leaves typing cursors intact [307].
            let _ = cursors.reply(reserved, &bytes, input);
        }
        Frame::SelectWriter(id) if p.caps & MULTI_WRITER != 0 && p.writer.is_none() && id != 0 => {
            cursors.select(id, p.size)?;
            p.writer = Some(id);
        }
        Frame::SelectSharedWriter(id)
            if p.caps & SHARED_WRITER != 0 && p.writer.is_none() && id != 0 =>
        {
            // Priming cannot invent a cursor or alter geometry, accepted input,
            // or an existing peer. Its input is deduplicated by this same writer.
            cursors.get(Some(id))?;
            p.writer = Some(id);
            p.shared_writer = true;
        }
        Frame::InputStateRequest if p.caps & SEQUENCED_INPUT != 0 && p.writer.is_some() => {
            p.input_reply = Some(InputReply::State);
        }
        Frame::Resize {
            cols,
            rows,
            px_w,
            px_h,
        } => {
            if cols == 0 || rows == 0 || usize::from(cols) * usize::from(rows) > 200_000 {
                return Err(invalid());
            }
            p.size = (cols, rows, px_w, px_h);
            cursors.request_resize(p.writer, p.size)?;
            if cursors.active_writer.is_none() || cursors.active_writer == p.writer {
                let applied = p.resize(pty, terminal, ring, config)?;
                p.size = cursors.finish_resize(p.writer, applied)?;
                if applied {
                    cursors.active_writer = p.writer;
                }
            }
        }
        Frame::ReadFrom(seq) if seq <= ring.head() => {
            // A new peer or a later request can replace the resize's queued
            // repaint. Lost native state must still be announced, even when
            // raw bytes cover this viewer's cursor; byte retention alone does
            // not cover state after historical resizes or omitted output.
            p.request = Some(if terminal.requires_approximation() {
                Request::Snapshot
            } else {
                Request::Read(seq)
            });
        }
        Frame::SnapshotRequest => p.request = Some(Request::Snapshot),
        Frame::Signal(signal) => pty.signal_unless_exited(signal, exited)?,
        Frame::CloseSession if p.caps & CLOSE_SESSION != 0 => pty.close_session(exited)?,
        Frame::ExitAck if exited && p.exited_sent && p.pending.is_empty() => return Ok(true),
        Frame::Error(..) => {}
        _ => return Err(invalid()),
    }
    Ok(false)
}

#[cfg(test)]
#[path = "../tests/unit/session_budgets.rs"]
mod measurements;

/// Survives peer replacement; accepted bytes are retained until a successful write.
#[derive(Default)]
struct InputCursors {
    written: u64,
    accepted: u64,
    // Inactive Resize is staged for the next typist. Keep the last successful
    // size separately so allocation refusal cannot overwrite durable geometry.
    requested_size: (u16, u16, u16, u16),
    accepted_size: (u16, u16, u16, u16),
}
impl InputCursors {
    fn accept(&mut self, seq: u64, bytes: &[u8], queue: &mut VecDeque<u8>) -> io::Result<()> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid input range or full queue",
            )
        };
        let end = seq.checked_add(bytes.len() as u64).ok_or_else(invalid)?;
        if seq > self.accepted {
            return Err(invalid());
        }
        if end <= self.accepted {
            return Ok(());
        }
        let skip = usize::try_from(self.accepted - seq).map_err(|_| invalid())?;
        let suffix = &bytes[skip..];
        // Full policy is refusal before mutation, never silent input loss.
        if queue.len() + suffix.len() > MAX_FRAME {
            return Err(invalid());
        }
        queue.extend(suffix);
        self.accepted = end;
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/unit/sequenced_input.rs"]
mod sequenced_checks;

/// An opaque error kind keeps invalid writer data out of diagnostics without allocation.
fn invalid_input() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

fn invalid_request() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid shim request ordering or payload",
    )
}
#[cfg(test)]
#[path = "../tests/unit/session_resize.rs"]
mod resize_checks;

#[cfg(test)]
mod readiness_marker_checks {
    //! A fixed private probe publishes its role before admission and removes it with its socket.
    use super::*;

    #[test]
    fn readiness_role_lives_only_as_long_as_its_socket() {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(format!(".cache/codex-scratch/rl12/m{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for readiness in [false, true] {
            let mut config = Config::new([u8::from(readiness); 16], Uid::effective().as_raw());
            config.state = Some(root.clone());
            config.readiness = readiness;
            let (listener, guard) = socket(&config).unwrap();
            let path = guard.0.clone();
            let marker = path.with_extension("readiness");
            assert_eq!(marker.exists(), readiness);
            if readiness {
                let metadata = fs::symlink_metadata(&marker).unwrap();
                assert!(metadata.is_file());
                assert_eq!(metadata.mode() & 0o7777, 0o600);
                assert_eq!(metadata.len(), 0);
                assert_eq!(metadata.uid(), Uid::effective().as_raw());
            }
            drop(listener);
            drop(guard);
            assert!(!path.exists());
            assert!(!marker.exists());
        }
        fs::remove_dir_all(root).unwrap();
    }
}
