//! Single-threaded bounded PTY/socket pump; replay precedes live output at one cursor.
#![forbid(unsafe_code)]
use crate::{
    frame::{
        APPROXIMATE_SNAPSHOT, Decoder, Frame, FrameRef, MAX_FRAME, MULTI_WRITER, SEQUENCED_INPUT,
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
    writer: Option<u32>,
    ack_queued: u64,
    size: (u16, u16, u16, u16),
    cursor: Option<u64>,
    pending: Vec<u8>,
    written: usize,
    exited_sent: bool,
    request: Option<Request>,
}
impl Peer {
    fn queue(&mut self, frame: &Frame) -> io::Result<()> {
        frame.encode_into(&mut self.pending)?;
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
    /// Both explicit resizing and last-typist selection share refusal recovery.
    /// Accepted input stays owned by the shim even when native geometry is refused.
    fn resize(
        &mut self,
        pty: &mut Pty,
        terminal: &mut Terminal,
        ring: &Ring,
        config: &mut Config,
    ) -> io::Result<bool> {
        let (cols, rows, px_w, px_h) = self.size;
        pty.resize(cols, rows, px_w, px_h)?;
        // Origin bytes alone cannot certify history at a changed geometry;
        // the terminal independently verifies provenance before reconstructing.
        let resized = if ring.start() == 0 {
            terminal.resize_with_ring(cols, rows, Some(ring))
        } else {
            terminal.resize(cols, rows)
        };
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
    let mut pty =
        Pty::spawn_with_readiness(config.uid, config.cols, config.rows, config.readiness)?;
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
    let mut cursors = Inputs::default();
    let mut peers: Vec<Peer> = Vec::new();
    let mut exit = None;
    let mut drained = false;
    // A private probe owns no durable terminal. A lost open reply or server
    // transport cannot leave its read waiting forever; ordinary PTYs have no timer.
    let readiness_deadline = config
        .readiness
        .then(|| Instant::now() + Duration::from_secs(10));
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
            exit = Some(
                status
                    .code()
                    .unwrap_or_else(|| -status.signal().unwrap_or(1)),
            );
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
        // Borrow descriptors only through poll. Every queue and ownership
        // mutation happens after this scope, so replacement cannot leave a
        // PollFd referring to a closed/reused file descriptor.
        let ready = {
            // A fast viewer permits PTY progress. Lagging viewers catch up from
            // the ring or a snapshot; when every viewer stalls the old bounded
            // backpressure rule still applies until their daemon links detach.
            let can_read = !drained
                && (peers.is_empty()
                    || peers.iter().any(|p| {
                        p.pending.is_empty() && p.cursor.is_some_and(|seq| seq == ring.head())
                    }));
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
                if input.len() < MAX_FRAME {
                    flags |= PollFlags::POLLIN;
                }
                if !p.pending.is_empty() {
                    flags |= PollFlags::POLLOUT;
                }
                fds[index + 3] = PollFd::new(p.stream.as_fd(), flags);
            }
            // Only private probes wake on a deadline; normal PTYs remain event-driven.
            let timeout = readiness_deadline.map_or(nix::poll::PollTimeout::NONE, |deadline| {
                // Round upward so a submillisecond remainder cannot busy-loop.
                nix::poll::PollTimeout::try_from(
                    deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
                )
                .unwrap_or(nix::poll::PollTimeout::MAX)
            });
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
                            attached: false,
                            caps: 0,
                            input_reply: None,
                            writer: Some(0),
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
                            caps: SEQUENCED_INPUT | MULTI_WRITER | APPROXIMATE_SNAPSHOT,
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
        if ready.2.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) && !drained {
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
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
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
            if flags.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
                let mut bytes = [0; CHUNK];
                match p.stream.read(&mut bytes) {
                    Ok(0) => disconnect = true,
                    Ok(n) => {
                        // Temporarily move only decoder ownership so the callback
                        // can mutate Peer while borrowing its reusable frame bytes.
                        let mut decoder = std::mem::take(&mut p.decoder);
                        let mut acknowledged_exit = false;
                        let result = decoder.feed_with(&bytes[..n], |frame| {
                            if acknowledged_exit {
                                return Ok(());
                            }
                            acknowledged_exit = handle(
                                frame,
                                p,
                                &mut pty,
                                &mut terminal,
                                &ring,
                                &mut config,
                                &mut input,
                                &mut cursors,
                                exit.is_some() && drained,
                            )?;
                            Ok(())
                        });
                        p.decoder = decoder;
                        if result.is_err() {
                            disconnect = true;
                        } else if acknowledged_exit {
                            return Ok(());
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => disconnect = true,
                }
            }
            disconnects[index] = disconnect;
        }
        // A reattachment supersedes only the same writer. Legacy writer zero
        // keeps v1 replacement semantics; selected viewers never evict siblings.
        for index in (0..peers.len()).rev() {
            let p = &peers[index];
            let duplicate = p.attached
                && p.writer.is_some_and(|id| {
                    peers[index + 1..]
                        .iter()
                        .any(|next| next.attached && next.writer == Some(id))
                });
            if disconnects[index] || duplicate {
                peers.remove(index);
            }
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn handle<'a>(
    frame: impl Into<FrameRef<'a>>,
    p: &mut Peer,
    pty: &mut Pty,
    terminal: &mut Terminal,
    ring: &Ring,
    config: &mut Config,
    input: &mut VecDeque<u8>,
    cursors: &mut Inputs,
    exited: bool,
) -> io::Result<bool> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid shim request ordering or payload",
        )
    };
    let frame = frame.into();
    if let FrameRef::Owned(Frame::Attach(caps)) = frame {
        if p.attached {
            return Err(invalid());
        }
        p.attached = true;
        p.caps = caps & (SEQUENCED_INPUT | MULTI_WRITER | APPROXIMATE_SNAPSHOT);
        if p.caps & MULTI_WRITER != 0 {
            if p.caps & SEQUENCED_INPUT == 0 {
                return Err(invalid());
            }
            p.writer = None;
        }
        return Ok(false);
    }
    if !p.attached
        || (p.writer.is_none() && !matches!(&frame, FrameRef::Owned(Frame::SelectWriter(_))))
    {
        return Err(invalid());
    }
    if let Some((offset, bytes)) = frame.input() {
        if exited || (offset.is_some() != (p.caps & SEQUENCED_INPUT != 0)) {
            return Err(invalid());
        }
        let writer = p.writer.ok_or_else(invalid)?;
        let accepted = cursors.get(p.writer)?.accepted;
        cursors.accept(writer, offset.unwrap_or(accepted), bytes, input)?;
        if cursors.get(p.writer)?.accepted > accepted {
            // Only newly accepted input changes the active size [74]. Replayed
            // duplicate bytes cannot steal the last typist's terminal geometry.
            if cursors.active_writer != Some(writer) {
                p.resize(pty, terminal, ring, config)?;
                cursors.active_writer = Some(writer);
            }
        }
        if offset.is_some() && p.input_reply.is_none() {
            p.input_reply = Some(InputReply::Ack);
        }
        // The only input copy is into the surviving bounded queue. Try the PTY
        // immediately so batching output never adds a keystroke round trip.
        let (first, _) = input.as_slices();
        if !first.is_empty() {
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
        Frame::SelectWriter(id) if p.caps & MULTI_WRITER != 0 && p.writer.is_none() && id != 0 => {
            cursors.select(id)?;
            p.writer = Some(id);
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
            if (cursors.active_writer.is_none() || cursors.active_writer == p.writer)
                && p.resize(pty, terminal, ring, config)?
            {
                cursors.active_writer = p.writer;
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

/// Static error copy keeps malformed writer data out of diagnostics.
fn invalid_input() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid shim writer input")
}
#[cfg(test)]
#[path = "../tests/unit/session_resize.rs"]
mod resize_checks;
