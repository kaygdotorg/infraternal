//! Single-threaded bounded PTY/socket pump; replay precedes live output at one cursor.
#![forbid(unsafe_code)]
use crate::{
    frame::{
        APPROXIMATE_SNAPSHOT, CLOSE_SESSION, Decoder, Frame, FrameRef, MAX_FRAME, MULTI_WRITER,
        QUERY_REPLIES, SEQUENCED_INPUT, SESSION_OWNER, SHARED_WRITER,
    },
    pty::Pty,
    ring::{DEFAULT_CAPACITY, Ring},
    terminal::Terminal,
};
use nix::{
    poll::{PollFd, PollFlags, poll},
    sys::{
        signal::{SigSet, Signal},
        signalfd::{SfdFlags, SignalFd},
        socket::{getsockopt, sockopt::PeerCredentials},
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
            fs::{DirBuilderExt, MetadataExt, PermissionsExt},
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
            cols: 80,
            rows: 24,
            state: None,
            ring_capacity: DEFAULT_CAPACITY,
        }
    }
}
struct SocketPath(PathBuf);
impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
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
                | CLOSE_SESSION);
        if self.caps & SESSION_OWNER != 0 {
            if self.caps != SESSION_OWNER {
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
fn socket(config: &Config) -> io::Result<(UnixListener, SocketPath)> {
    let state = if let Some(path) = &config.state {
        path.clone()
    } else if Uid::effective().is_root() {
        PathBuf::from("/run/infraternal")
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
    let guard = SocketPath(path);
    fs::set_permissions(&guard.0, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
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
pub fn run_with_retention(mut config: Config, retention: Duration) -> io::Result<()> {
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
    // Startup is single threaded; restrictive umask also protects bind's brief
    // interval before chmod. The shim retains this mask for its whole lifetime.
    umask(Mode::from_bits_truncate(0o077));
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGCHLD);
    mask.thread_block().map_err(io::Error::from)?;
    let signals = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC)
        .map_err(io::Error::from)?;
    let (listener, path) = socket(&config)?;
    let mut pty = Pty::spawn_with_command(
        config.uid,
        config.cols,
        config.rows,
        config.readiness,
        &config.command,
    )?;
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
        let owned = peers.iter().any(|p| p.attached && p.caps == SESSION_OWNER);
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
            crate::ended::record(&path.0, status, ring.head())?;
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
            let mut fds: [PollFd<'_>; MAX_PEERS + 3] =
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
                fds[index + 3] = PollFd::new(p.stream.as_fd(), flags);
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
            match poll(&mut fds[..peers.len() + 3], timeout) {
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(e.into()),
            }
            let flags = |i: usize| fds[i].revents().unwrap_or_else(PollFlags::empty);
            let peer_flags: [PollFlags; MAX_PEERS] = std::array::from_fn(|i| flags(i + 3));
            (flags(0), flags(1), flags(2), peer_flags)
        };
        if ready.1.contains(PollFlags::POLLIN) {
            while signals.read_signal().map_err(io::Error::from)?.is_some() {}
        }
        if ready.0.contains(PollFlags::POLLIN) {
            // Accept at most one per iteration: a peer flooding connect cannot
            // starve PTY progress. Authenticate before replacing the old peer.
            match listener.accept() {
                Ok((stream, _)) => {
                    let credentials =
                        getsockopt(&stream, PeerCredentials).map_err(io::Error::from)?;
                    if (credentials.uid() == 0 || credentials.uid() == Uid::effective().as_raw())
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
                            request: None,
                        };
                        next.queue(&Frame::Hello {
                            version: 1,
                            caps: SEQUENCED_INPUT
                                | MULTI_WRITER
                                | APPROXIMATE_SNAPSHOT
                                | SESSION_OWNER
                                | SHARED_WRITER
                                | QUERY_REPLIES
                                | CLOSE_SESSION,
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
