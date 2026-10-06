//! Single-threaded bounded PTY/socket pump; replay precedes live output at one cursor.
#![forbid(unsafe_code)]
use crate::{
    frame::{APPROXIMATE_SNAPSHOT, Decoder, Frame, MAX_FRAME, SEQUENCED_INPUT},
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
    time::{SystemTime, UNIX_EPOCH},
};
const CHUNK: usize = 16 * 1024;
/// Startup parameters passed only by the local infraternal agent.
#[derive(Clone, Debug)]
pub struct Config {
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
    attached: bool,
    caps: u64,
    input_reply: Option<InputReply>,
    cursor: Option<u64>,
    pending: Vec<u8>,
    written: usize,
    exited_sent: bool,
    request: Option<Request>,
}
impl Peer {
    fn queue(&mut self, frame: &Frame) -> io::Result<()> {
        self.pending = frame.encode()?;
        self.written = 0;
        Ok(())
    }
    fn snapshot(&mut self, terminal: &Terminal, head: u64) -> io::Result<()> {
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
    let listener = UnixListener::bind(&path)?;
    let guard = SocketPath(path);
    fs::set_permissions(&guard.0, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    Ok((listener, guard))
}
/// Run one Linux session until an authenticated peer acknowledges its drained exit.
/// # Errors
/// Returns invalid startup configuration, account, PTY, socket or resource failures.
#[allow(clippy::too_many_lines)]
pub fn run(mut config: Config) -> io::Result<()> {
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
    let (listener, _path) = socket(&config)?;
    let mut pty = Pty::spawn(config.uid, config.cols, config.rows)?;
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
    let mut cursors = InputCursors::default();
    let mut peer: Option<Peer> = None;
    let mut exit = None;
    let mut drained = false;
    loop {
        if exit.is_none()
            && let Some(status) = pty.child.try_wait()?
        {
            exit = Some(
                status
                    .code()
                    .unwrap_or_else(|| -status.signal().unwrap_or(1)),
            );
        }
        if let Some(p) = &mut peer
            && p.pending.is_empty()
            && let Some(reply) = p.input_reply.take()
        {
            p.queue(&match reply {
                InputReply::State => Frame::InputState(cursors.written, cursors.accepted),
                InputReply::Ack => Frame::InputAck(cursors.written),
            })?;
        }
        if let Some(p) = &mut peer
            && p.pending.is_empty()
            && let Some(request) = p.request.take()
        {
            match request {
                Request::Read(seq) => p.cursor = Some(seq),
                Request::Snapshot => p.snapshot(&terminal, ring.head())?,
            }
        }
        if let Some(p) = &mut peer
            && p.pending.is_empty()
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
        // Borrow descriptors only through poll. Every queue and ownership
        // mutation happens after this scope, so replacement cannot leave a
        // PollFd referring to a closed/reused file descriptor.
        let ready = {
            let can_read = !drained
                && peer.as_ref().is_none_or(|p| {
                    p.pending.is_empty() && p.cursor.is_some_and(|seq| seq == ring.head())
                });
            let has_input = !input.is_empty();
            let mut fds = vec![
                PollFd::new(listener.as_fd(), PollFlags::POLLIN),
                PollFd::new(signals.as_fd(), PollFlags::POLLIN),
                PollFd::new(
                    pty.master.as_fd(),
                    (if can_read {
                        PollFlags::POLLIN
                    } else {
                        PollFlags::empty()
                    }) | if has_input {
                        PollFlags::POLLOUT
                    } else {
                        PollFlags::empty()
                    },
                ),
            ];
            // A disabled fd must be omitted: PTY HUP is level-triggered and
            // would otherwise spin while waiting for a stalled socket to drain.
            if !can_read && !has_input {
                fds.pop();
            }
            let pty_index = if fds.len() == 3 { Some(2) } else { None };
            let peer_index = if let Some(p) = &peer {
                let index = fds.len();
                let mut flags = PollFlags::empty();
                if input.len() < MAX_FRAME {
                    flags |= PollFlags::POLLIN;
                }
                if !p.pending.is_empty() {
                    flags |= PollFlags::POLLOUT;
                }
                fds.push(PollFd::new(p.stream.as_fd(), flags));
                Some(index)
            } else {
                None
            };
            match poll(&mut fds, None::<u16>) {
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(e.into()),
            }
            let flags = |index: Option<usize>| {
                index
                    .and_then(|i| fds[i].revents())
                    .unwrap_or_else(PollFlags::empty)
            };
            (
                flags(Some(0)),
                flags(Some(1)),
                flags(pty_index),
                flags(peer_index),
            )
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
                    if credentials.uid() == 0 || credentials.uid() == Uid::effective().as_raw() {
                        stream.set_nonblocking(true)?;
                        let mut next = Peer {
                            stream,
                            decoder: Decoder::default(),
                            attached: false,
                            caps: 0,
                            input_reply: None,
                            cursor: None,
                            pending: Vec::new(),
                            written: 0,
                            exited_sent: false,
                            request: None,
                        };
                        next.queue(&Frame::Hello {
                            version: 1,
                            caps: SEQUENCED_INPUT | APPROXIMATE_SNAPSHOT,
                            session: config.session,
                            pid: std::process::id(),
                            cols: config.cols,
                            rows: config.rows,
                            created,
                            head: ring.head(),
                            start: ring.start(),
                        })?;
                        peer = Some(next);
                        continue; // old socket readiness cannot apply to new fd
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
                        cursors.written += n as u64;
                        if let Some(p) = &mut peer
                            && p.caps & SEQUENCED_INPUT != 0
                            && p.input_reply.is_none()
                        {
                            p.input_reply = Some(InputReply::Ack);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) if e.raw_os_error() == Some(nix::libc::EIO) => {
                        input.clear();
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        if ready.2.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) && !drained {
            let mut bytes = [0; CHUNK];
            match pty
                .master
                .read(&mut bytes[..CHUNK.min(config.ring_capacity)])
            {
                Ok(0) => drained = true,
                Ok(n) => {
                    terminal.process(&bytes[..n]);
                    ring.append(&bytes[..n])?;
                }
                Err(e) if e.raw_os_error() == Some(nix::libc::EIO) => drained = true,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        let mut disconnect = ready.3.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL);
        if let Some(p) = &mut peer {
            if ready.3.contains(PollFlags::POLLOUT) && p.flush().is_err() {
                disconnect = true;
            }
            if ready.3.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
                let mut bytes = [0; CHUNK];
                match p.stream.read(&mut bytes) {
                    Ok(0) => disconnect = true,
                    Ok(n) => match p.decoder.feed(&bytes[..n]) {
                        Ok(frames) => {
                            for frame in frames {
                                match handle(
                                    frame,
                                    p,
                                    &mut pty,
                                    &mut terminal,
                                    &ring,
                                    &mut config,
                                    &mut input,
                                    &mut cursors,
                                    exit.is_some() && drained,
                                ) {
                                    Ok(true) => return Ok(()),
                                    Ok(false) => {}
                                    Err(_) => {
                                        disconnect = true;
                                        break;
                                    }
                                }
                            }
                        }
                        Err(_) => disconnect = true,
                    },
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => disconnect = true,
                }
            }
        }
        if disconnect {
            peer = None;
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn handle(
    frame: Frame,
    p: &mut Peer,
    pty: &mut Pty,
    terminal: &mut Terminal,
    ring: &Ring,
    config: &mut Config,
    input: &mut VecDeque<u8>,
    cursors: &mut InputCursors,
    exited: bool,
) -> io::Result<bool> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid shim request ordering or payload",
        )
    };
    if let Frame::Attach(caps) = frame {
        if p.attached {
            return Err(invalid());
        }
        p.attached = true;
        p.caps = caps & (SEQUENCED_INPUT | APPROXIMATE_SNAPSHOT);
        return Ok(false);
    }
    if !p.attached {
        return Err(invalid());
    }
    match frame {
        Frame::InputStateRequest if p.caps & SEQUENCED_INPUT != 0 => {
            p.input_reply = Some(InputReply::State);
        }
        Frame::SequencedInput(seq, bytes) if !exited && p.caps & SEQUENCED_INPUT != 0 => {
            cursors.accept(seq, &bytes, input)?;
            if p.input_reply.is_none() {
                p.input_reply = Some(InputReply::Ack);
            }
            let (first, _) = input.as_slices();
            if !first.is_empty() {
                match pty.master.write(first) {
                    Ok(n) => {
                        input.drain(..n);
                        cursors.written += n as u64;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Frame::Input(bytes) if !exited && p.caps & SEQUENCED_INPUT == 0 => {
            if input.len() + bytes.len() > MAX_FRAME {
                return Err(invalid());
            }
            // Try the PTY immediately: poll scheduling never adds a round trip
            // to the common keystroke path. Retain partial writes in order.
            cursors.accept(cursors.accepted, &bytes, input)?;
            let (first, _) = input.as_slices();
            match pty.master.write(first) {
                Ok(n) => {
                    input.drain(..n);
                    cursors.written += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
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
            pty.resize(cols, rows, px_w, px_h)?;
            // Ring origin coverage is necessary but the terminal also checks
            // resize history. On refusal the native handle is retired and a
            // fresh terminal is rebuilt at the unchanged last-good geometry.
            let resized = if ring.start() == 0 {
                terminal.resize_with_ring(cols, rows, Some(ring))
            } else {
                terminal.resize(cols, rows)
            };
            if resized.is_err() {
                pty.resize(config.cols, config.rows, 0, 0)?;
                // Force a repaint even when this viewer still has raw ring
                // coverage, so clean recovery receives a negotiated notice.
                // Keep the peer, session and accepted input flowing.
                if p.cursor.is_some() || matches!(p.request, Some(Request::Read(_))) {
                    p.request = Some(Request::Snapshot);
                }
                // Control-only peers await an ordered InputState fence. Their
                // recovery notice is selected by the next ReadFrom, rather
                // than sending an unsolicited frame before the State reply.
                return Ok(false);
            }
            config.cols = cols;
            config.rows = rows;
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
        Frame::Signal(signal) if !exited => pty.signal(signal)?,
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

#[cfg(test)]
#[path = "../tests/unit/session_resize.rs"]
mod resize_checks;
