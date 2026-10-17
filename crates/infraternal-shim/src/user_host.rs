//! Optional single-UID PTY reactor using the frozen shim peers and bounded queues [D268].
//!
//! This experiment has no login authority: its caller must already be inside one
//! person's login. A UID shared by people is never sufficient to select a host.
use super::{
    CHUNK, Config, InputReply, Inputs, MAX_PEERS, Peer, Request, SessionTerminal, SocketPath,
    consume_peer, socket,
};
use crate::{
    frame::{
        APPROXIMATE_SNAPSHOT, Decoder, Frame, MULTI_WRITER, SEQUENCED_INPUT, SESSION_OWNER,
        SHARED_WRITER,
    },
    pty::Pty,
    ring::Ring,
    terminal::Terminal,
};
use nix::{
    poll::PollFlags,
    sys::{
        signal::{SigSet, Signal},
        signalfd::{SfdFlags, SignalFd},
        socket::{getsockopt, sockopt::PeerCredentials},
        stat::{Mode, umask},
    },
    unistd::Uid,
};
use std::cell::RefCell;
#[cfg(feature = "host-diagnostics")]
use std::os::fd::AsRawFd;
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    os::unix::{net::UnixListener, process::ExitStatusExt},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const PREFIX_LIMIT: usize = 4096;
const RESIZE_LIMIT: usize = 32;
// Event count alone can defer many large reflows to the first snapshot.
// Bound destination cells without adding another per-session counter.
const RESIZE_CELL_LIMIT: usize = 64 * 1024;
// A global output quantum keeps one thousand ready PTYs from postponing input.
const OUTPUTS_PER_ROUND: usize = 1;
const INTERACTIVE_READ_BYTES: usize = 4096;
const BULK_READ_BYTES: usize = 16 * 1024;
// Aggregate history is bounded at scale rather than multiplying defaults by 1000.
const HOST_HISTORY_BYTES: usize = 64 * 1024 * 1024;
/// Native VT bytes shared above the per-session floors [D270, #205]: the
/// history shares with their page headers, plus one full screen reservation
/// so a single large geometry fits. All sessions together stay under
/// `sessions * SESSION_SCREEN_BYTES + HOST_NATIVE_POOL_BYTES`.
const HOST_NATIVE_POOL_BYTES: usize = HOST_HISTORY_BYTES + HOST_HISTORY_BYTES / 8 + 8 * 1024 * 1024;
/// Native bytes each session owns outright: an idle 80x24 terminal and a few
/// history pages to recycle, so output never fails when the pool is empty.
const SESSION_SCREEN_BYTES: usize = 256 * 1024;
const MAX_SESSIONS: usize = 1000;
const PEER_BYTES: usize = 4 * 1024 * 1024;
const SESSION_BYTES: usize = 16 * 1024 * 1024;

/// A complete origin prefix is retained until VT materialization, never an evicting tail.
struct LazyTerminal {
    state: RefCell<LazyState>,
    cols: u16,
    rows: u16,
    history: usize,
    /// The host-wide native ceiling this terminal charges once materialized.
    host: Option<std::sync::Arc<crate::terminal_memory::HostBudget>>,
}
struct LazyState {
    terminal: Option<Box<Terminal>>,
    prefix: Vec<u8>,
    origin: (u16, u16),
    // Offsets refer to the complete prefix. Reflow and incomplete parser
    // sequences must occur at their original positions, never after replay.
    resizes: Vec<(usize, u16, u16)>,
    #[cfg(test)]
    panic_next_process: bool,
}
impl LazyTerminal {
    fn new(cols: u16, rows: u16, history: usize) -> Self {
        Self {
            state: RefCell::new(LazyState {
                terminal: None,
                prefix: Vec::new(),
                origin: (cols, rows),
                resizes: Vec::new(),
                #[cfg(test)]
                panic_next_process: false,
            }),
            cols,
            rows,
            history,
            host: None,
        }
    }
    fn materialize(&self) -> io::Result<()> {
        let mut state = self.state.borrow_mut();
        if state.terminal.is_none() {
            let mut terminal = Box::new(Terminal::with_host_budget(
                state.origin.0,
                state.origin.1,
                self.history,
                self.host.clone(),
            )?);
            let mut start = 0;
            for &(end, cols, rows) in &state.resizes {
                terminal.process(&state.prefix[start..end]);
                terminal.resize(cols, rows)?;
                start = end;
            }
            terminal.process(&state.prefix[start..]);
            state.terminal = Some(terminal);
            state.prefix = Vec::new();
            state.resizes = Vec::new();
        }
        Ok(())
    }
    fn allocated_bytes(&self) -> usize {
        let state = self.state.borrow();
        state.prefix.capacity()
            + state.resizes.capacity() * std::mem::size_of::<(usize, u16, u16)>()
            + state
                .terminal
                .as_ref()
                .map_or(0, |t| t.memory().0 + 8192 + std::mem::size_of::<Terminal>())
    }
    fn process(&mut self, bytes: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        assert!(!self.state.get_mut().panic_next_process, "fixture VT fault");
        if self.state.borrow().terminal.is_none()
            && self.state.borrow().prefix.len().saturating_add(bytes.len()) > PREFIX_LIMIT
        {
            self.materialize()?;
        }
        let state = self.state.get_mut();
        if let Some(terminal) = &mut state.terminal {
            terminal.process(bytes);
        } else {
            state.prefix.extend_from_slice(bytes);
        }
        Ok(())
    }
}
impl SessionTerminal for LazyTerminal {
    fn snapshot(&self) -> io::Result<Vec<u8>> {
        self.materialize()?;
        self.state
            .borrow()
            .terminal
            .as_ref()
            .ok_or_else(|| io::Error::other("VT absent"))?
            .snapshot()
    }
    fn approximate_snapshot(&self) -> Vec<u8> {
        // A failed allocation cannot masquerade as an exact empty screen.
        self.state
            .borrow()
            .terminal
            .as_ref()
            .map_or_else(|| b"\x1bc".to_vec(), |t| t.approximate_snapshot())
    }
    fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        self.resize_with_ring(cols, rows, None)
    }
    fn resize_with_ring(&mut self, cols: u16, rows: u16, ring: Option<&Ring>) -> io::Result<()> {
        let state = self.state.get_mut();
        // Native resize also ends synchronized output. Only an empty byte
        // range since the previous resize makes equal geometry redundant;
        // intervening bytes may have enabled that mode again.
        if (cols, rows) == (self.cols, self.rows)
            && state.terminal.is_none()
            && state
                .resizes
                .last()
                .map_or(state.prefix.is_empty(), |(offset, _, _)| {
                    *offset == state.prefix.len()
                })
        {
            return Ok(());
        }
        if state.terminal.is_none()
            && state.resizes.len() < RESIZE_LIMIT
            && state.resizes.iter().fold(
                usize::from(cols) * usize::from(rows),
                |cells, (_, cols, rows)| {
                    cells.saturating_add(usize::from(*cols) * usize::from(*rows))
                },
            ) <= RESIZE_CELL_LIMIT
        {
            // Small quiet geometry needs no screen pools. The bounded
            // transcript preserves each reflow at its historical byte offset;
            // large reflows are paid individually rather than in one snapshot.
            state.resizes.push((state.prefix.len(), cols, rows));
            self.cols = cols;
            self.rows = rows;
            return Ok(());
        }
        // Reaching any transcript bound materializes the original state
        // before applying this resize. A failed replay leaves it retryable.
        self.materialize()?;
        self.state
            .get_mut()
            .terminal
            .as_mut()
            .ok_or_else(|| io::Error::other("VT absent"))?
            .resize_with_ring(cols, rows, ring)?;
        self.cols = cols;
        self.rows = rows;
        Ok(())
    }
    fn requires_approximation(&self) -> bool {
        self.state
            .borrow()
            .terminal
            .as_ref()
            .is_some_and(|t| t.requires_approximation())
    }
}

struct Session {
    config: Config,
    listener: UnixListener,
    path: SocketPath,
    pty: Pty,
    terminal: LazyTerminal,
    ring: Ring,
    input: VecDeque<u8>,
    cursors: Inputs,
    peers: Vec<Peer>,
    created: u64,
    next_deferred: u64,
    exit: Option<i32>,
    drained: bool,
    deadline: Option<Instant>,
}
impl Drop for Session {
    fn drop(&mut self) {
        // Only our own child is reaped; no PID-pattern cleanup or unrelated sessions.
        if self.exit.is_none() {
            let _ = self.pty.child.kill();
            let _ = self.pty.child.wait();
        }
    }
}
/// A wholly logical data Ack may wait for output; real wire work and state
/// fences retain writable interest even while a PTY turn is queued.
fn may_coalesce_data_ack(peer: &Peer, head: u64, live: bool) -> bool {
    live && peer.pending.is_empty()
        && matches!(peer.input_reply, Some(InputReply::Ack))
        && peer.cursor == Some(head)
        && peer.request.is_none()
        && peer.deferred.is_none()
        && peer.trailing.is_empty()
}

impl Session {
    fn new(mut config: Config, history: usize) -> io::Result<Self> {
        let (listener, path) = socket(&config)?;
        // The bound socket owns the complete pathname. Runtime geometry and
        // wire handling never need a second copy of its startup directory.
        config.state = None;
        let pty =
            Pty::spawn_with_readiness(config.uid, config.cols, config.rows, config.readiness)?;
        Ok(Self {
            terminal: LazyTerminal::new(config.cols, config.rows, history),
            ring: Ring::new(config.ring_capacity),
            cursors: Inputs::for_host((config.cols, config.rows, 0, 0)),
            config,
            listener,
            path,
            pty,
            input: VecDeque::new(),
            peers: Vec::new(),
            created: u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(io::Error::other)?
                    .as_millis(),
            )
            .map_err(io::Error::other)?,
            next_deferred: 0,
            exit: None,
            drained: false,
            deadline: None,
        })
    }
    fn peer_bytes(&self) -> usize {
        self.peers.iter().map(Peer::buffer_bytes).sum()
    }
    fn allocated_bytes(&self) -> usize {
        self.terminal.allocated_bytes()
            + self.ring.allocated_bytes()
            + self.input.capacity()
            + self.cursors.allocated_bytes()
            + self.peer_bytes()
            + self.peers.capacity() * std::mem::size_of::<Peer>()
            + self
                .config
                .state
                .as_ref()
                .map_or(0, std::path::PathBuf::capacity)
            + self.path.0.capacity()
            + std::mem::size_of::<Self>()
    }
    fn record_memory(
        &self,
        index: usize,
        writer: &mut impl Write,
        reactor: Option<std::fmt::Arguments<'_>>,
    ) -> io::Result<()> {
        let state = self.terminal.state.borrow();
        let (ordinary, pages, resident, encoded, carry) = state
            .terminal
            .as_ref()
            .map_or(Ok((0, 0, 0, 0, 0)), |t| t.ownership())?;
        let history_rows = state
            .terminal
            .as_ref()
            .map_or(0, |t| t.retained_history_rows());
        write!(
            writer,
            "{{\"kind\":\"ownership\",\"session\":{index},\"total_bytes\":{},\"native_ordinary_bytes\":{ordinary},\"native_page_bytes\":{pages},\"native_resident_bytes\":{resident},\"native_encoded_bytes\":{encoded},\"native_history_rows\":{history_rows},\"carry_bytes\":{carry},\"struct_bytes\":{},\"path_bytes\":{},\"config_path_bytes\":{},\"prefix_bytes\":{},\"geometry_bytes\":{},\"ring_bytes\":{},\"input_bytes\":{},\"writer_bytes\":{},\"peer_bytes\":{},\"peer_slots_bytes\":{}",
            self.allocated_bytes(),
            std::mem::size_of::<Self>(),
            self.path.0.capacity(),
            self.config
                .state
                .as_ref()
                .map_or(0, std::path::PathBuf::capacity),
            state.prefix.capacity(),
            state.resizes.capacity() * std::mem::size_of::<(usize, u16, u16)>(),
            self.ring.allocated_bytes(),
            self.input.capacity(),
            self.cursors.allocated_bytes(),
            self.peer_bytes(),
            self.peers.capacity() * std::mem::size_of::<Peer>()
        )?;
        if let Some(reactor) = reactor {
            write!(writer, ",\"reactor\":{reactor}")?;
        }
        writeln!(writer, "}}")
    }
    fn can_read(&self) -> bool {
        !self.drained
            && (!self.peers.iter().any(|p| p.cursor.is_some())
                || self.peers.iter().any(|p| {
                    p.pending.is_empty() && p.cursor.is_some_and(|s| s == self.ring.head())
                }))
    }
    fn can_write(&self, peer: &Peer) -> bool {
        !peer.pending.is_empty()
            || peer.input_reply.is_some()
            || peer.request.is_some()
            || peer.cursor.is_some_and(|seq| {
                seq < self.ring.head() || (self.drained && self.exit.is_some() && !peer.exited_sent)
            })
    }
    /// Queued local service supplies the fallback for a logical Ack. Keeping
    /// that Ack writable would revisit it before its bounded continuation.
    fn can_write_with_ack_held(&self, peer: &Peer) -> bool {
        self.can_write(peer)
            && !may_coalesce_data_ack(peer, self.ring.head(), !self.drained && self.exit.is_none())
    }
    fn observe_exit(&mut self) -> io::Result<()> {
        if self.exit.is_none()
            && let Some(status) = self.pty.child.try_wait()?
        {
            self.exit = Some(
                status
                    .code()
                    .unwrap_or_else(|| -status.signal().unwrap_or(1)),
            );
            self.deadline = Some(Instant::now() + crate::ended::MAX_RETENTION);
        }
        Ok(())
    }
    fn housekeeping(&mut self) -> io::Result<bool> {
        self.housekeeping_coalesced(false)
    }
    /// Keep an ordinary data Ack logical while its caller prepares a read.
    /// The caller must retain writable interest or guarantee queued local service.
    /// Settle without deferral after that service, including an empty read;
    /// explicit state and input-only links are immediate.
    #[allow(clippy::too_many_lines)]
    fn housekeeping_coalesced(&mut self, coalesce_ack: bool) -> io::Result<bool> {
        #[cfg(feature = "host-diagnostics")]
        crate::host_trace::context(self.config.session, self.pty.master.as_raw_fd());
        if self.drained {
            self.observe_exit()?;
        }
        if self.allocated_bytes()
            > SESSION_BYTES + self.terminal.history * 2 + self.config.ring_capacity
        {
            return Err(io::Error::other("session memory budget exhausted"));
        }
        for p in &mut self.peers {
            if p.pending.is_empty() && p.pending.capacity() > CHUNK * 4 {
                p.pending = Vec::new();
            }
        }
        let mut wire_bytes = self.peer_bytes();
        let oldest = self.peers.iter().filter_map(|p| p.deferred).min();
        let mut retired = Vec::new();
        for (i, p) in self.peers.iter_mut().enumerate() {
            let mut before = p.buffer_bytes();
            // Healthy sockets need no writable-readiness round trip. Bound
            // each peer's work, including a partially transmitted repaint.
            let mut write_bytes = CHUNK * 2;
            let mut write_attempts = 4;
            if p.flush_bounded(&mut write_bytes, &mut write_attempts)
                .is_err()
            {
                retired.push(i);
                continue;
            }
            let current = p.buffer_bytes();
            wire_bytes = wire_bytes - before + current;
            before = current;
            if p.deferred.is_some() || !p.trailing.is_empty() {
                let mut trailing = std::mem::take(&mut p.trailing);
                match consume_peer(
                    &trailing,
                    p,
                    &mut self.pty,
                    &mut self.terminal,
                    &self.ring,
                    &mut self.config,
                    &mut self.input,
                    &mut self.cursors,
                    self.exit.is_some() && self.drained,
                    oldest.is_some() && p.deferred != oldest,
                    &mut self.next_deferred,
                ) {
                    Ok((false, used)) => {
                        trailing.drain(..used);
                        p.trailing = trailing;
                    }
                    _ => retired.push(i),
                }
            }
            if p.caps & SEQUENCED_INPUT != 0
                && p.writer.is_some()
                && self.cursors.get(p.writer)?.written > p.ack_queued
                && p.input_reply.is_none()
            {
                p.input_reply = Some(InputReply::Ack);
            }
            let current = p.buffer_bytes();
            wire_bytes = wire_bytes - before + current;
            before = current;
            let mut queued_reply = false;
            // Only a subscribed data peer at the current head may combine a
            // fresh Ack with its next read. State fences, replay/snapshot
            // requests, deferred input and ended sessions retain prompt replies.
            let defer_ack = coalesce_ack
                && may_coalesce_data_ack(p, self.ring.head(), !self.drained && self.exit.is_none());
            if p.pending.is_empty()
                && !defer_ack
                && let Some(reply) = p.input_reply.take()
            {
                let state = self.cursors.get(p.writer)?;
                p.ack_queued = state.written;
                p.queue(&match reply {
                    InputReply::State => Frame::InputState(state.written, state.accepted),
                    InputReply::Ack => Frame::InputAck(state.written),
                })?;
                queued_reply = true;
            }
            // Include all current buffers before reserving a repaint, even
            // when a preceding state frame completed without a new event.
            let current = p.buffer_bytes();
            wire_bytes = wire_bytes - before + current;
            before = current;
            if (p.pending.is_empty()
                || (queued_reply && matches!(p.request, Some(Request::Read(_)))))
                && let Some(request) = p.request.take()
            {
                match request {
                    Request::Read(seq) => p.cursor = Some(seq),
                    Request::Snapshot => {
                        if wire_bytes + 2 * crate::frame::MAX_FRAME <= PEER_BYTES {
                            trace_host!(
                                SnapshotStart,
                                self.config.session,
                                p.stream.as_raw_fd(),
                                self.ring.head(),
                                0
                            );
                            p.snapshot(&self.terminal, self.ring.head())?;
                            trace_host!(
                                SnapshotDone,
                                self.config.session,
                                p.stream.as_raw_fd(),
                                self.ring.head(),
                                p.pending.len()
                            );
                        } else {
                            p.queue(&Frame::Error(1, "session memory budget exhausted".into()))?;
                            p.cursor = None;
                        }
                    }
                }
            }
            // Only append output to this visit's wholly unsent state/ack.
            // Never overwrite a partial frame or append a costly repaint.
            if (p.pending.is_empty() || queued_reply)
                && !matches!(p.request, Some(Request::Snapshot))
                && let Some(seq) = p.cursor
            {
                if seq < self.ring.start() {
                    if queued_reply {
                        // Logical writable readiness resumes the repaint after
                        // the preceding control frame has completed.
                    } else if wire_bytes + 2 * crate::frame::MAX_FRAME <= PEER_BYTES {
                        trace_host!(
                            SnapshotStart,
                            self.config.session,
                            p.stream.as_raw_fd(),
                            self.ring.head(),
                            0
                        );
                        p.snapshot(&self.terminal, self.ring.head())?;
                        trace_host!(
                            SnapshotDone,
                            self.config.session,
                            p.stream.as_raw_fd(),
                            self.ring.head(),
                            p.pending.len()
                        );
                    } else {
                        p.queue(&Frame::Error(1, "session memory budget exhausted".into()))?;
                        p.cursor = None;
                    }
                } else if seq < self.ring.head() {
                    trace_host!(
                        FrameBuildStart,
                        self.config.session,
                        p.stream.as_raw_fd(),
                        seq,
                        0
                    );
                    let (first, second) = self
                        .ring
                        .read_slices(seq, CHUNK)
                        .ok_or_else(|| io::Error::other("delivery cursor invariant"))?;
                    if queued_reply {
                        Frame::output_slices_into::<true>(seq, first, second, &mut p.pending)?;
                    } else {
                        Frame::output_slices_into::<false>(seq, first, second, &mut p.pending)?;
                        p.written = 0;
                    }
                    trace_host!(
                        FrameBuilt,
                        self.config.session,
                        p.stream.as_raw_fd(),
                        seq,
                        first.len() + second.len(),
                        p.pending.len()
                    );
                    p.cursor = Some(seq + (first.len() + second.len()) as u64);
                } else if !queued_reply
                    && self.drained
                    && !p.exited_sent
                    && let Some(status) = self.exit
                {
                    p.queue(&Frame::Exited(status, self.ring.head()))?;
                    p.exited_sent = true;
                }
            }
            if p.flush_bounded(&mut write_bytes, &mut write_attempts)
                .is_err()
            {
                retired.push(i);
            }
            wire_bytes = wire_bytes - before + p.buffer_bytes();
        }
        // Indices follow peer order. Decoder refusal and an immediate write
        // failure can name the same peer; retire it only once.
        retired.dedup();
        for i in retired.into_iter().rev() {
            self.peers.remove(i);
        }
        if self.peers.is_empty() {
            self.peers = Vec::new();
        }
        if let Some(status) = self.exit
            && (self.deadline.is_some_and(|d| Instant::now() >= d)
                || (self.drained
                    && !self
                        .peers
                        .iter()
                        .any(|p| p.attached && p.caps == SESSION_OWNER)
                    && self
                        .peers
                        .iter()
                        .filter(|p| p.cursor.is_some())
                        .all(|p| p.exited_sent && p.pending.is_empty())))
        {
            crate::ended::record(&self.path.0, status, self.ring.head())?;
            return Ok(true);
        }
        Ok(false)
    }
    #[allow(clippy::too_many_lines)]
    fn step(
        &mut self,
        listener: PollFlags,
        master: PollFlags,
        peers: &[PollFlags],
        read_pty: bool,
    ) -> io::Result<()> {
        self.step_budget(
            listener,
            master,
            peers,
            if read_pty { BULK_READ_BYTES } else { 0 },
        )
    }
    #[allow(clippy::too_many_lines)]
    fn step_budget(
        &mut self,
        listener: PollFlags,
        master: PollFlags,
        peers: &[PollFlags],
        read_budget: usize,
    ) -> io::Result<()> {
        #[cfg(feature = "host-diagnostics")]
        crate::host_trace::context(self.config.session, self.pty.master.as_raw_fd());
        if listener.contains(PollFlags::POLLIN)
            && let Ok((stream, _)) = self.listener.accept()
        {
            let credential = getsockopt(&stream, PeerCredentials).map_err(io::Error::from)?;
            if (credential.uid() == 0 || credential.uid() == Uid::effective().as_raw())
                && self.peers.len() < MAX_PEERS
            {
                stream.set_nonblocking(true)?;
                // Most sessions have one viewer. Reserve exactly the next
                // slot rather than four large Peer records on first attach.
                self.peers.try_reserve_exact(1).map_err(io::Error::other)?;
                let mut peer = Peer {
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
                    size: (self.config.cols, self.config.rows, 0, 0),
                    cursor: None,
                    pending: Vec::new(),
                    written: 0,
                    exited_sent: false,
                    request: None,
                };
                peer.queue(&Frame::Hello {
                    version: 1,
                    caps: SEQUENCED_INPUT
                        | MULTI_WRITER
                        | APPROXIMATE_SNAPSHOT
                        | SESSION_OWNER
                        | SHARED_WRITER,
                    session: self.config.session,
                    pid: std::process::id(),
                    cols: self.config.cols,
                    rows: self.config.rows,
                    created: self.created,
                    head: self.ring.head(),
                    start: self.ring.start(),
                })?;
                self.peers.push(peer);
            }
        }
        if master.contains(PollFlags::POLLOUT) {
            let (first, second) = self.input.as_slices();
            trace_host!(
                PtyWriteStart,
                self.config.session,
                self.pty.master.as_raw_fd(),
                0,
                self.input.len()
            );
            match self
                .pty
                .master
                .write(if first.is_empty() { second } else { first })
            {
                Ok(n) => {
                    self.input.drain(..n);
                    self.cursors.advance(n)?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if e.raw_os_error() == Some(nix::libc::EIO) => self.input.clear(),
                Err(e) => return Err(e),
            }
        }
        if read_budget > 0
            && self.can_read()
            && (master.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) || self.exit.is_some())
        {
            let mut bytes = [0; BULK_READ_BYTES];
            let limit = read_budget.min(bytes.len()).min(self.config.ring_capacity);
            let mut used = 0;
            // One rotating bulk turn may amortize four short kernel reads.
            // Input and promoted small replies keep the smaller byte quantum;
            // no producer can turn this drain into an unbounded read loop.
            for _ in 0..4 {
                if used == limit {
                    break;
                }
                match self.pty.master.read(&mut bytes[used..limit]) {
                    Ok(0) => {
                        self.drained = true;
                        break;
                    }
                    Ok(n) => used += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        self.drained = self.exit.is_some();
                        break;
                    }
                    Err(e) if e.raw_os_error() == Some(nix::libc::EIO) => {
                        self.drained = true;
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            // One parser/ring append per bounded batch also amortizes native
            // ownership walks and cold-page work, preserving byte order.
            if used > 0 {
                trace_host!(
                    PtyRead,
                    self.config.session,
                    self.pty.master.as_raw_fd(),
                    self.ring.head(),
                    used
                );
                self.terminal.process(&bytes[..used])?;
                trace_host!(
                    ParseDone,
                    self.config.session,
                    self.pty.master.as_raw_fd(),
                    self.ring.head(),
                    used
                );
                self.ring.append(&bytes[..used])?;
            }
        }
        let oldest = self.peers.iter().filter_map(|p| p.deferred).min();
        let mut disconnects = [false; MAX_PEERS];
        for (i, flags) in peers.iter().copied().enumerate() {
            let retained = self.peer_bytes();
            let p = &mut self.peers[i];
            let mut disconnect = flags.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL);
            // Settle already spends the bounded write budget before and after
            // this step; writable readiness only schedules that continuation.
            if p.deferred.is_some() && flags.contains(PollFlags::POLLHUP) {
                disconnect = true;
            }
            if p.deferred.is_none() && flags.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
                let mut bytes = [0; CHUNK];
                match p.stream.read(&mut bytes) {
                    Ok(0) => disconnect = true,
                    Ok(n) if retained + p.decoder.growth_bound(n) + 2 * CHUNK > PEER_BYTES => {
                        disconnect = true;
                    }
                    Ok(n) => {
                        trace_host!(PeerRead, self.config.session, p.stream.as_raw_fd(), 0, n);
                        match consume_peer(
                            &bytes[..n],
                            p,
                            &mut self.pty,
                            &mut self.terminal,
                            &self.ring,
                            &mut self.config,
                            &mut self.input,
                            &mut self.cursors,
                            self.exit.is_some() && self.drained,
                            oldest.is_some(),
                            &mut self.next_deferred,
                        ) {
                            Ok((false, used)) => p.trailing.extend_from_slice(&bytes[used..n]),
                            _ => disconnect = true,
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => disconnect = true,
                }
            }
            disconnects[i] = disconnect;
        }
        for i in 0..self.peers.len() {
            let p = &self.peers[i];
            disconnects[i] |= p.attached
                && p.writer.is_some_and(|id| {
                    self.peers[i + 1..].iter().enumerate().any(|(j, next)| {
                        !disconnects[i + 1 + j]
                            && next.attached
                            && next.writer == Some(id)
                            && next.shared_writer == p.shared_writer
                    })
                });
        }
        for i in (0..self.peers.len()).rev() {
            if disconnects[i] {
                self.peers.remove(i);
            }
        }
        if self.peers.is_empty() {
            self.peers = Vec::new();
        }
        Ok(())
    }
}

/// Host an explicitly supplied batch inside one existing person's login [D240/D247].
///
/// Per-session Rust panics retire that session. Native faults and process OOM
/// still affect the whole host; this function does not claim process isolation.
/// Call during single-threaded startup: process-directed SIGCHLD must remain
/// blocked in every thread while this reactor owns its children.
/// # Errors
/// Rejects foreign UIDs, duplicate IDs, invalid geometry, threaded startup and other startup failures.
#[allow(clippy::too_many_lines)]
pub fn run_host(configs: Vec<Config>) -> io::Result<()> {
    run_host_accounted(configs, None)
}

/// Run the research host with optional numeric ownership receipts on SIGUSR2.
/// No timer or content capture is installed; the caller owns the private file.
/// # Errors
/// Requires the same single-threaded process boundary and batch validation as `run_host`.
#[allow(clippy::too_many_lines)]
pub fn run_host_accounted(
    mut configs: Vec<Config>,
    accounting: Option<std::fs::File>,
) -> io::Result<()> {
    if configs.is_empty()
        || configs.len() > MAX_SESSIONS
        || configs.iter().enumerate().any(|(i, c)| {
            c.uid != Uid::effective().as_raw()
                || c.cols == 0
                || c.rows == 0
                || usize::from(c.cols) * usize::from(c.rows) > 200_000
                || c.ring_capacity == 0
                || configs[i + 1..]
                    .iter()
                    .any(|other| other.session == c.session)
        })
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // A signalfd can consume process-directed SIGCHLD only when every thread
    // blocks it. Validate before changing the mask/umask or creating a PTY;
    // a caller with another unblocked thread would lose exit readiness.
    let single_threaded = {
        let mut tasks = std::fs::read_dir("/proc/self/task")?;
        tasks.next().transpose()?.is_some() && tasks.next().transpose()?.is_none()
    };
    if !single_threaded {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "shared host requires single-threaded startup",
        ));
    }
    #[cfg(feature = "host-diagnostics")]
    let mut accounting = accounting;
    #[cfg(feature = "host-diagnostics")]
    crate::host_trace::initialize(accounting.as_mut())?;
    umask(Mode::from_bits_truncate(0o077));
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGCHLD);
    if accounting.is_some() {
        mask.add(Signal::SIGUSR2);
        #[cfg(feature = "host-diagnostics")]
        mask.add(Signal::SIGUSR1);
    }
    mask.thread_block().map_err(io::Error::from)?;
    crate::pty::reset_host_child_notifications()?;
    let signals = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC)
        .map_err(io::Error::from)?;
    let history = (HOST_HISTORY_BYTES / configs.len()).min(17 * 1024 * 1024);
    let ring_budget = HOST_HISTORY_BYTES / configs.len();
    for config in &mut configs {
        config.ring_capacity = config.ring_capacity.min(ring_budget);
    }
    let native =
        crate::terminal_memory::HostBudget::new(HOST_NATIVE_POOL_BYTES, SESSION_SCREEN_BYTES);
    let sessions = configs
        .into_iter()
        .map(|config| {
            let mut session = Session::new(config, history)?;
            session.terminal.host = Some(native.clone());
            Ok(session)
        })
        .collect::<io::Result<Vec<_>>>()?;
    reactor::run(sessions, &signals, accounting)
}

#[path = "user_host_reactor.rs"]
mod reactor;

#[cfg(test)]
#[path = "../tests/unit/ppu_children.rs"]
mod child_checks;

#[cfg(test)]
#[path = "../tests/unit/ppu_lazy_bench.rs"]
mod lazy_bench;

#[cfg(test)]
mod tests {
    //! Differential state and admission tests for the research-only reactor.
    use super::*;

    pub(super) fn ack_fixture(tag: u8) -> (Session, std::os::unix::net::UnixStream, PathBuf) {
        let state = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/a{tag:x}{}",
            std::process::id()
        ));
        let mut config = Config::new([tag; 16], Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let mut session = Session::new(config, 65536).unwrap();
        let mut client = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
        session
            .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
            .unwrap();
        session.housekeeping().unwrap();
        client.read_exact(&mut [0; 63]).unwrap();
        client.set_nonblocking(true).unwrap();
        let peer = &mut session.peers[0];
        peer.attached = true;
        peer.caps = SEQUENCED_INPUT;
        peer.cursor = Some(0);
        peer.input_reply = Some(InputReply::Ack);
        (session, client, state)
    }

    #[test]
    fn data_ack_can_wait_for_a_writable_visit_without_requiring_output() {
        let (mut session, mut client, state) = ack_fixture(29);
        session.housekeeping_coalesced(true).unwrap();
        assert!(
            session.can_write(&session.peers[0]),
            "logical Ack must retain writable interest"
        );
        assert!(
            matches!(client.read(&mut [0; 64]), Err(e) if e.kind() == io::ErrorKind::WouldBlock),
            "a fresh data Ack should leave room for the next available output"
        );
        session.housekeeping().unwrap();
        let expected = Frame::InputAck(0).encode().unwrap();
        let mut received = vec![0; expected.len()];
        client.read_exact(&mut received).unwrap();
        assert_eq!(received, expected, "a silent program must not hold the Ack");
        drop(client);
        drop(session);
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn deferred_data_ack_and_available_output_share_one_ordered_batch() {
        let (mut session, mut client, state) = ack_fixture(30);
        session.housekeeping_coalesced(true).unwrap();
        session.ring.append(b"reply").unwrap();
        session.housekeeping_coalesced(true).unwrap();
        let mut expected = Frame::InputAck(0).encode().unwrap();
        expected.extend(Frame::Output(0, b"reply".to_vec()).encode().unwrap());
        let mut received = vec![0; expected.len()];
        client.read_exact(&mut received).unwrap();
        assert_eq!(received, expected);
        assert_eq!(session.peers[0].pending, [] as [u8; 0]);
        drop(client);
        drop(session);
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn state_fences_and_input_only_acks_bypass_coalescing() {
        for (tag, state_reply) in [(31, true), (32, false)] {
            let (mut session, mut client, state) = ack_fixture(tag);
            let expected = if state_reply {
                session.peers[0].input_reply = Some(InputReply::State);
                Frame::InputState(0, 0).encode().unwrap()
            } else {
                session.peers[0].cursor = None;
                Frame::InputAck(0).encode().unwrap()
            };
            assert!(session.can_write_with_ack_held(&session.peers[0]));
            session.housekeeping_coalesced(true).unwrap();
            let mut received = vec![0; expected.len()];
            client.read_exact(&mut received).unwrap();
            assert_eq!(received, expected);
            drop(client);
            drop(session);
            fs::remove_dir_all(state).unwrap();
        }
    }

    #[test]
    fn steady_replay_needs_no_payload_allocation() {
        let state = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/br{}",
            std::process::id()
        ));
        let mut config = Config::new([24; 16], Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let mut session = Session::new(config, 65536).unwrap();
        let mut client = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
        session
            .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
            .unwrap();
        session.housekeeping().unwrap();
        client.read_exact(&mut [0; 63]).unwrap();
        let peer = &mut session.peers[0];
        peer.attached = true;
        peer.cursor = Some(0);
        peer.pending.reserve(CHUNK + 13);
        session.ring.append(b"bounded replay").unwrap();
        let ((), delta) = crate::heap_accounting::measure(|| {
            session.housekeeping().unwrap();
        });
        drop(client);
        drop(session);
        fs::remove_dir_all(state).unwrap();
        assert_eq!(
            delta.allocations, 0,
            "replay must borrow retained ring bytes"
        );
    }

    #[test]
    fn blocked_state_and_output_share_one_ordered_write_batch() {
        let state = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/w{}",
            std::process::id()
        ));
        let mut config = Config::new([15; 16], Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let mut session = Session::new(config, 65536).unwrap();
        let mut client = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
        session
            .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
            .unwrap();
        session.housekeeping().unwrap();
        client.read_exact(&mut [0; 63]).unwrap();
        let peer = &mut session.peers[0];
        peer.attached = true;
        peer.caps = SEQUENCED_INPUT;
        peer.input_reply = Some(InputReply::State);
        peer.request = Some(Request::Read(0));
        loop {
            match peer.stream.write(&[b'x'; 4096]) {
                Ok(n) => assert!(n > 0),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("backpressure fixture failed: {e}"),
            }
        }
        session.ring.append(b"reply").unwrap();
        session.housekeeping().unwrap();
        let queued = session.peers[0].pending.clone();
        drop(client);
        drop(session);
        fs::remove_dir_all(state).unwrap();
        let mut expected = Frame::InputState(0, 0).encode().unwrap();
        expected.extend(Frame::Output(0, b"reply".to_vec()).encode().unwrap());
        assert_eq!(
            queued, expected,
            "state/output need a single bounded write batch"
        );
    }
    #[test]
    fn session_constructor_retains_only_the_bound_socket_path() {
        let state = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/ctor{}",
            std::process::id()
        ));
        // Global locale initialization is fixed process ownership, not this
        // session's constructor allocation.
        drop(crate::session_locale_environment());
        let (session, owned) = crate::heap_accounting::measure(|| {
            let mut config = Config::new([13; 16], Uid::effective().as_raw());
            config.state = Some(state.clone());
            config.readiness = true;
            Session::new(config, 65536).unwrap()
        });
        assert!(session.config.state.is_none());
        assert!(session.path.0.starts_with(&state));
        assert_eq!(
            owned.bytes,
            i64::try_from(session.path.0.capacity()).unwrap()
        );
        assert!(std::os::unix::net::UnixStream::connect(&session.path.0).is_ok());
        drop(session);
        fs::remove_dir_all(state).unwrap();
    }
    #[test]
    fn bulk_turn_advances_sixteen_kib_and_yields_before_the_rest() {
        let state = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/b{}",
            std::process::id()
        ));
        let mut config = Config::new([7; 16], Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let mut session = Session::new(config, 65536).unwrap();
        // A ready byte stream makes the byte quantum deterministic. Real PTY
        // chunking and input latency are checked by the locked flood driver.
        let (reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        writer.write_all(&vec![b'q'; 65536]).unwrap();
        drop(writer);
        session.pty.master = std::fs::File::from(std::os::fd::OwnedFd::from(reader));
        session
            .step(PollFlags::empty(), PollFlags::POLLIN, &[], true)
            .unwrap();
        assert_eq!(session.ring.head(), 16384, "bulk read yielded too early");
        assert!(!session.drained, "unread output was mistaken for EOF");
        for _ in 0..3 {
            session
                .step(PollFlags::empty(), PollFlags::POLLIN, &[], true)
                .unwrap();
        }
        assert_eq!(session.ring.head(), 65536);
        session
            .step(PollFlags::empty(), PollFlags::POLLIN, &[], true)
            .unwrap();
        assert!(session.drained);
        drop(session);
        fs::remove_dir_all(state).unwrap();
    }
    #[test]
    fn malformed_closed_peer_is_retired_once_and_keeps_its_sibling() {
        let state = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/d{}",
            std::process::id()
        ));
        let mut config = Config::new([10; 16], Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let mut session = Session::new(config, 65536).unwrap();
        let bad = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
        session
            .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
            .unwrap();
        session.housekeeping().unwrap();
        let good = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
        session
            .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
            .unwrap();
        session.housekeeping().unwrap();
        let expected = std::os::fd::AsRawFd::as_raw_fd(&session.peers[1].stream);
        let peer = &mut session.peers[0];
        peer.attached = true;
        peer.caps = SEQUENCED_INPUT;
        peer.trailing = Frame::InputStateRequest.encode().unwrap();
        peer.trailing
            .extend(Frame::Attach(SEQUENCED_INPUT).encode().unwrap());
        drop(bad);
        session.housekeeping().unwrap();
        assert_eq!(session.peers.len(), 1);
        assert_eq!(
            std::os::fd::AsRawFd::as_raw_fd(&session.peers[0].stream),
            expected
        );
        drop(good);
        drop(session);
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn writable_peer_receives_state_and_output_before_another_readiness_turn() {
        let state = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/f{}",
            std::process::id()
        ));
        let mut config = Config::new([8; 16], Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let mut session = Session::new(config, 65536).unwrap();
        let mut client = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
        client.set_nonblocking(true).unwrap();
        session
            .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
            .unwrap();
        session.housekeeping().unwrap();
        let mut hello = [0; 63];
        client.read_exact(&mut hello).unwrap();
        assert_eq!(hello[4], 1);
        session.ring.append(b"reply").unwrap();
        for frame in [
            Frame::Attach(SEQUENCED_INPUT),
            Frame::ReadFrom(0),
            Frame::InputStateRequest,
        ] {
            client.write_all(&frame.encode().unwrap()).unwrap();
        }
        session
            .step(
                PollFlags::empty(),
                PollFlags::empty(),
                &[PollFlags::POLLIN],
                false,
            )
            .unwrap();
        session.housekeeping().unwrap();
        let mut expected = Frame::InputState(0, 0).encode().unwrap();
        expected.extend(Frame::Output(0, b"reply".to_vec()).encode().unwrap());
        let mut received = vec![0; expected.len()];
        client.read_exact(&mut received).unwrap();
        assert_eq!(received, expected);
        assert_eq!(session.peers[0].pending, [] as [u8; 0]);
        drop(session);
        fs::remove_dir_all(state).unwrap();
    }

    use nix::poll::{PollFd, poll};
    use std::{
        fs,
        os::fd::AsFd,
        panic::{AssertUnwindSafe, catch_unwind},
        path::PathBuf,
        time::Duration,
    };
    fn assert_same_state(lazy: &LazyTerminal, eager: &Terminal) {
        lazy.materialize().unwrap();
        let state = lazy.state.borrow();
        let terminal = state.terminal.as_ref().unwrap();
        assert_eq!(terminal.research_state_difference(eager), 0);
        drop(state);
        match (lazy.snapshot(), eager.snapshot()) {
            (Ok(left), Ok(right)) => assert_eq!(left, right),
            (Err(left), Err(right)) => {
                assert_eq!(left.kind(), right.kind());
                assert_eq!(lazy.approximate_snapshot(), eager.approximate_snapshot());
            }
            _ => panic!("lazy/eager snapshot fidelity differs"),
        }
    }
    #[test]
    fn last_viewer_disconnect_releases_unused_peer_slots() {
        const CASE: &str =
            "session::user_host::tests::last_viewer_disconnect_releases_unused_peer_slots";
        const FLAG: &str = "INFRATERNAL_PPU_VIEWER_FIXTURE";
        // Concurrent fork/exec fixtures can briefly inherit this test's
        // socket. Isolate the descriptor lifetime just as the fd-reuse test.
        if std::env::var_os(FLAG).is_none() {
            assert!(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", CASE, "--test-threads=1"])
                    .env(FLAG, "1")
                    .status()
                    .unwrap()
                    .success()
            );
            return;
        }
        let state = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/b{}",
            std::process::id()
        ));
        let mut config = Config::new([8; 16], Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let mut session = Session::new(config, 65536).unwrap();
        let client = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
        session
            .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
            .unwrap();
        assert_eq!(session.peers.len(), 1);
        drop(client);
        session
            .step(
                PollFlags::empty(),
                PollFlags::empty(),
                &[PollFlags::POLLHUP],
                false,
            )
            .unwrap();
        assert!(session.peers.is_empty());
        assert_eq!(
            session.peers.capacity(),
            0,
            "idle session retains vacant viewer slots"
        );
        drop(session);
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    #[ignore = "perf VM only: per-session requested-byte ownership ledger at scale"]
    fn idle_session_ownership_ledger() {
        use crate::heap_accounting::measure;
        assert_eq!(
            fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap()
                .trim(),
            "infraternal-perf-test"
        );
        let count: usize = std::env::var("PPU_ACCOUNT_SESSIONS")
            .unwrap()
            .parse()
            .unwrap();
        assert!([1, 10, 100, 1000].contains(&count));
        let state = PathBuf::from(format!(
            "/root/infraternal-bench/p3-l{}",
            std::process::id()
        ));
        let (mut sessions, slots) = measure(|| Vec::with_capacity(count));
        let mut constructors = 0;
        let mut prefixes = 0;
        let mut viewers = 0;
        for index in 0..count {
            let (mut session, construction) = measure(|| {
                let mut config = Config::new(
                    u128::try_from(index + 1).unwrap().to_be_bytes(),
                    Uid::effective().as_raw(),
                );
                config.state = Some(state.clone());
                config.readiness = true;
                Session::new(config, 65536).unwrap()
            });
            constructors += construction.bytes;
            let ((), prefix) = measure(|| {
                session.terminal.process(&[b'p'; 38]).unwrap();
                session.ring.append(&[b'p'; 38]).unwrap();
            });
            prefixes += prefix.bytes;
            let ((), peer) = measure(|| {
                let client = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
                session
                    .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
                    .unwrap();
                drop(client);
                session
                    .step(
                        PollFlags::empty(),
                        PollFlags::empty(),
                        &[PollFlags::POLLHUP],
                        false,
                    )
                    .unwrap();
            });
            viewers += peer.bytes;
            sessions.push(session);
        }
        let signals = SignalFd::with_flags(&SigSet::empty(), SfdFlags::SFD_CLOEXEC).unwrap();
        let (registry, registration) =
            measure(|| reactor::ownership_fixture(&sessions, &signals).unwrap());
        println!(
            "PPU_LEDGER count={count} session_struct={} peer_struct={} slot_bytes={} constructor_bytes={constructors} prefix_ring_bytes={prefixes} closed_viewer_bytes={viewers} registry_bytes={} total_requested_bytes={}",
            std::mem::size_of::<Session>(),
            std::mem::size_of::<Peer>(),
            slots.bytes,
            registration.bytes,
            slots.bytes + constructors + prefixes + viewers + registration.bytes
        );
        print_idle_layout(&sessions[0]);
        drop(registry);
        drop(sessions);
        fs::remove_dir_all(state).unwrap();
    }
    fn print_idle_layout(first: &Session) {
        // cfg(test) adds a panic-injection boolean to the lazy VT state.
        // Report the tested layout explicitly rather than calling it shipping PSS.
        let sizes = [
            std::mem::size_of_val(&first.config),
            std::mem::size_of_val(&first.listener),
            std::mem::size_of_val(&first.path),
            std::mem::size_of_val(&first.pty),
            std::mem::size_of_val(&first.terminal),
            std::mem::size_of_val(&first.ring),
            std::mem::size_of_val(&first.input),
            std::mem::size_of_val(&first.cursors),
            std::mem::size_of_val(&first.peers),
            std::mem::size_of_val(&first.created),
            std::mem::size_of_val(&first.next_deferred),
            std::mem::size_of_val(&first.exit),
            std::mem::size_of_val(&first.drained),
            std::mem::size_of_val(&first.deadline),
        ];
        println!(
            "PPU_LAYOUT cfg_test=true config={} listener={} path={} pty={} lazy_vt={} ring={} input={} writers={} peers={} created={} deferred={} exit={} drained={} deadline={} padding={}",
            sizes[0],
            sizes[1],
            sizes[2],
            sizes[3],
            sizes[4],
            sizes[5],
            sizes[6],
            sizes[7],
            sizes[8],
            sizes[9],
            sizes[10],
            sizes[11],
            sizes[12],
            sizes[13],
            std::mem::size_of::<Session>() - sizes.iter().sum::<usize>()
        );
    }
    #[test]
    fn lazy_prefix_materializes_exactly_before_overflow_and_resize() {
        let bytes = b"prompt \x1b[31mred\x1b[0m\r\n";
        let mut lazy = LazyTerminal::new(80, 24, 65536);
        let mut eager = Terminal::with_history_budget(80, 24, 65536).unwrap();
        lazy.process(bytes).unwrap();
        eager.process(bytes);
        assert!(lazy.state.borrow().terminal.is_none());
        assert_same_state(&lazy, &eager);
        let mut lazy = LazyTerminal::new(80, 24, 65536);
        lazy.process(bytes).unwrap();
        lazy.resize(40, 12).unwrap();
        eager.resize(40, 12).unwrap();
        assert_same_state(&lazy, &eager);
        let bytes = vec![b'x'; PREFIX_LIMIT + 1];
        lazy.process(&bytes).unwrap();
        eager.process(&bytes);
        assert!(lazy.state.borrow().terminal.is_some());
        assert_eq!(lazy.state.borrow().prefix, [] as [u8; 0]);
        assert_same_state(&lazy, &eager);
    }
    #[test]
    fn same_geometry_input_selection_keeps_vt_unallocated() {
        let mut lazy = LazyTerminal::new(80, 24, 65536);
        lazy.process(b"prompt \x1b[31mred\x1b[0m\r\n").unwrap();
        lazy.resize_with_ring(80, 24, None).unwrap();
        assert!(
            lazy.state.borrow().terminal.is_none(),
            "first input at unchanged geometry allocated VT"
        );
        let mut eager = Terminal::with_history_budget(80, 24, 65536).unwrap();
        eager.process(b"prompt \x1b[31mred\x1b[0m\r\n");
        eager.resize(80, 24).unwrap();
        assert_same_state(&lazy, &eager);
    }

    #[test]
    fn quiet_geometry_changes_remain_lazy_and_replay_in_order() {
        let mut lazy = LazyTerminal::new(80, 24, 65536);
        let mut eager = Terminal::with_history_budget(80, 24, 65536).unwrap();
        for (bytes, cols, rows) in [
            (b"\x1bcquiet\r\n".as_slice(), 81, 24),
            (b"\x1b[31mnext\x1b[0m\r\n".as_slice(), 12, 6),
            (b"unfinished\x1b]0;ti".as_slice(), 80, 24),
            (b"tle\x1b\\\r\n".as_slice(), 80, 25),
        ] {
            lazy.process(bytes).unwrap();
            eager.process(bytes);
            lazy.resize(cols, rows).unwrap();
            eager.resize(cols, rows).unwrap();
            assert!(
                lazy.state.borrow().terminal.is_none(),
                "a bounded quiet prefix must retain geometry without native VT"
            );
        }
        assert_same_state(&lazy, &eager);
        lazy.process(b"after-materialization\r\n").unwrap();
        eager.process(b"after-materialization\r\n");
        assert_same_state(&lazy, &eager);
    }

    #[test]
    fn geometry_transcript_materializes_at_its_event_bound() {
        let mut lazy = LazyTerminal::new(80, 24, 65536);
        let mut eager = Terminal::with_history_budget(80, 24, 65536).unwrap();
        for number in 0..=RESIZE_LIMIT {
            let bytes = format!("row-{number}\r\n");
            lazy.process(bytes.as_bytes()).unwrap();
            eager.process(bytes.as_bytes());
            let cols = 79 + u16::try_from(number % 2).unwrap();
            lazy.resize(cols, 24).unwrap();
            eager.resize(cols, 24).unwrap();
            let state = lazy.state.borrow();
            assert!(state.resizes.len() <= RESIZE_LIMIT);
            assert_eq!(state.terminal.is_some(), number == RESIZE_LIMIT);
        }
        assert_eq!(lazy.state.borrow().resizes.capacity(), 0);
        assert_eq!(lazy.state.borrow().prefix.capacity(), 0);
        assert_same_state(&lazy, &eager);
    }

    // Deferred geometry CPU must not accumulate many large reflows on a later snapshot [D270].
    #[test]
    fn large_geometry_cannot_defer_a_long_first_snapshot_reflow_queue() {
        let mut lazy = LazyTerminal::new(80, 24, 65536);
        let mut eager = Terminal::with_history_budget(80, 24, 65536).unwrap();
        for number in 0..RESIZE_LIMIT {
            let cols = 999 + u16::try_from(number % 2).unwrap();
            lazy.process(b"\x1b[31mrow\x1b[0m\r\n").unwrap();
            eager.process(b"\x1b[31mrow\x1b[0m\r\n");
            lazy.resize(cols, 100).unwrap();
            eager.resize(cols, 100).unwrap();
            assert!(
                lazy.state.borrow().terminal.is_some(),
                "large reflows must not accumulate until first snapshot"
            );
        }
        assert_same_state(&lazy, &eager);
    }

    #[test]
    fn medium_geometry_materializes_before_deferred_cell_work_exceeds_the_bound() {
        let mut lazy = LazyTerminal::new(80, 24, 65536);
        let mut eager = Terminal::with_history_budget(80, 24, 65536).unwrap();
        for number in 0..8 {
            let cols = 160 + u16::try_from(number % 2).unwrap();
            lazy.process(b"row\r\n").unwrap();
            eager.process(b"row\r\n");
            lazy.resize(cols, 60).unwrap();
            eager.resize(cols, 60).unwrap();
            let state = lazy.state.borrow();
            let cells: usize = state
                .resizes
                .iter()
                .map(|(_, cols, rows)| usize::from(*cols) * usize::from(*rows))
                .sum();
            assert!(cells <= RESIZE_CELL_LIMIT);
            assert_eq!(state.terminal.is_some(), number >= 6);
        }
        assert_same_state(&lazy, &eager);
    }

    #[test]
    fn output_bound_replays_retained_geometry_before_new_bytes() {
        let mut lazy = LazyTerminal::new(80, 24, 65536);
        let mut eager = Terminal::with_history_budget(80, 24, 65536).unwrap();
        lazy.process(b"\x1bcseed\r\n").unwrap();
        eager.process(b"\x1bcseed\r\n");
        lazy.resize(40, 12).unwrap();
        eager.resize(40, 12).unwrap();
        let bytes = vec![b'x'; PREFIX_LIMIT + 1];
        lazy.process(&bytes).unwrap();
        eager.process(&bytes);
        assert!(lazy.state.borrow().terminal.is_some());
        assert_eq!(lazy.state.borrow().resizes.capacity(), 0);
        assert_same_state(&lazy, &eager);
    }

    #[test]
    fn geometry_transcript_property_cases_match_eager_native_state() {
        let sample =
            b"\x1bc\x1b[31mwide \xe7\x95\x8c \xf0\x9f\x8c\x90\x1b[0m\r\n\x1b]0;title\x1b\\";
        for seed in 0..64_u32 {
            let mut lazy = LazyTerminal::new(80, 24, 65536);
            let mut eager = Terminal::with_history_budget(80, 24, 65536).unwrap();
            let mut value = seed + 1;
            let mut offset = 0;
            for _ in 0..40 {
                value = value.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let end = (offset + 1 + value as usize % 7).min(sample.len());
                lazy.process(&sample[offset..end]).unwrap();
                eager.process(&sample[offset..end]);
                offset = if end == sample.len() { 0 } else { end };
                let cols = 4 + u16::try_from(value % 97).unwrap();
                let rows = 3 + u16::try_from((value >> 8) % 22).unwrap();
                lazy.resize(cols, rows).unwrap();
                eager.resize(cols, rows).unwrap();
            }
            assert_same_state(&lazy, &eager);
        }
    }

    #[test]
    fn unchanged_geometry_retains_native_resize_side_effects() {
        for resized_first in [false, true] {
            let mut lazy = LazyTerminal::new(80, 24, 65536);
            let mut eager = Terminal::with_history_budget(80, 24, 65536).unwrap();
            let cols = if resized_first { 81 } else { 80 };
            if resized_first {
                lazy.resize(cols, 24).unwrap();
                eager.resize(cols, 24).unwrap();
            }
            lazy.process(b"\x1bc\x1b[?2026h").unwrap();
            eager.process(b"\x1bc\x1b[?2026h");
            assert!(eager.research_synchronized_output().unwrap());
            lazy.resize(cols, 24).unwrap();
            eager.resize(cols, 24).unwrap();
            assert!(!eager.research_synchronized_output().unwrap());
            lazy.materialize().unwrap();
            assert!(
                !lazy
                    .state
                    .borrow()
                    .terminal
                    .as_ref()
                    .unwrap()
                    .research_synchronized_output()
                    .unwrap(),
                "unchanged geometry must retain the native synchronization reset"
            );
        }
    }
    #[test]
    fn prefix_threshold_preserves_unfinished_sequences() {
        let mut lazy = LazyTerminal::new(80, 24, 65536);
        let mut eager = Terminal::with_history_budget(80, 24, 65536).unwrap();
        for bytes in [&vec![b'x'; PREFIX_LIMIT - 2][..], b"\x1b[", b"31mred"] {
            lazy.process(bytes).unwrap();
            eager.process(bytes);
        }
        assert_same_state(&lazy, &eager);
    }
    #[test]
    fn admission_refuses_foreign_uid_duplicate_ids_and_geometry_before_spawn() {
        let mut config = Config::new([1; 16], Uid::effective().as_raw());
        config.uid = config.uid.wrapping_add(1);
        assert_eq!(
            run_host(vec![config.clone()]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        config.uid = Uid::effective().as_raw();
        assert_eq!(
            run_host(vec![config.clone(), config.clone()])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        config.cols = 0;
        assert_eq!(
            run_host(vec![config]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    #[test]
    fn vt_panic_retires_one_real_pty_and_sibling_keeps_its_output() {
        let state = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/p{}",
            std::process::id()
        ));
        let mut config = Config::new([1; 16], Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let mut first = Session::new(config.clone(), 65536).unwrap();
        config.session = [2; 16];
        let mut sibling = Session::new(config, 65536).unwrap();
        first.terminal.state.get_mut().panic_next_process = true;
        first.pty.master.write_all(b"start\n").unwrap();
        sibling.pty.master.write_all(b"start\n").unwrap();
        let mut fds = [PollFd::new(first.pty.master.as_fd(), PollFlags::POLLIN)];
        assert!(poll(&mut fds, 30000_u16).unwrap() > 0);
        assert!(
            catch_unwind(AssertUnwindSafe(|| first.step(
                PollFlags::empty(),
                PollFlags::POLLIN,
                &[],
                true
            )))
            .is_err()
        );
        drop(first);
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let mut fds = [PollFd::new(sibling.pty.master.as_fd(), PollFlags::POLLIN)];
            assert!(poll(&mut fds, 30000_u16).unwrap() > 0);
            sibling
                .step(PollFlags::empty(), PollFlags::POLLIN, &[], true)
                .unwrap();
            let output = sibling.ring.read(0, CHUNK).unwrap();
            if output
                .windows(17)
                .any(|bytes| bytes == b"infraternal-ready")
            {
                break;
            }
            assert!(Instant::now() < deadline);
        }
        drop(sibling);
        fs::remove_dir_all(state).unwrap();
    }
}
