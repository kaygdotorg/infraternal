//! Optional single-UID PTY reactor using the frozen shim peers and bounded queues [D268].
//!
//! This experiment has no login authority: its caller must already be inside one
//! person's login. A UID shared by people is never sufficient to select a host.
use super::{
    CHUNK, Config, InputReply, Inputs, MAX_PEERS, Peer, Request, SessionTerminal, SocketPath,
    consume_peer, shim_peer_uid_allowed, socket,
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
/// Smallest host pool [D270, #205]: every history share with its page
/// headers, plus one full screen reservation so a single large geometry
/// fits. Floors cover each session's screens, so with this pool neither a
/// history share nor an ordinary screen is ever refused.
const HOST_NATIVE_POOL_MIN: usize = HOST_HISTORY_BYTES + HOST_HISTORY_BYTES / 8 + 8 * 1024 * 1024;
/// Largest host pool: what screens beyond a floor (larger than two 250x180
/// screens) may borrow on a large machine.
const HOST_NATIVE_POOL_MAX: usize = 512 * 1024 * 1024;
/// The host pool's share of the memory this host may use.
const HOST_NATIVE_POOL_FRACTION: usize = 32;
/// Chosen D310 floor: 256 KiB covers the ordinary 80x24 screen and parser
/// state while keeping the per-session reservation small at hundreds of
/// sessions. Larger active geometries may raise it, up to 2 MiB.
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
    /// Reserved when the session opens, even while terminal state is lazy.
    floor_reservation: Option<std::sync::Arc<crate::terminal_memory::HostFloor>>,
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
            floor_reservation: None,
        }
    }
    fn materialize(&self) -> io::Result<()> {
        let mut state = self.state.borrow_mut();
        if state.terminal.is_none() {
            let mut terminal = Box::new(Terminal::with_host_floor(
                state.origin.0,
                state.origin.1,
                self.history,
                self.host.clone(),
                self.floor_reservation.clone(),
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
    fn pool_bytes(&self) -> usize {
        let state = self.state.borrow();
        let floor = self
            .floor_reservation
            .as_ref()
            .map_or(0, |reservation| reservation.bytes());
        let native = state
            .terminal
            .as_ref()
            .map_or(0, |terminal| terminal.memory().0);
        floor.max(native)
    }
    fn pool_limit_bytes(&self) -> usize {
        self.host.as_ref().map_or(0, |host| host.limit_bytes())
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
    /// Opens a host session only after its protected floor fits the same cap
    /// as native history and the output ring [D310].
    fn new_host(
        config: Config,
        history: usize,
        host: std::sync::Arc<crate::terminal_memory::HostBudget>,
    ) -> io::Result<Self> {
        let floor_bytes = crate::terminal_native::floor_for_geometry(
            config.cols,
            config.rows,
            host.minimum_floor(),
        );
        let floor = host.reserve_session(floor_bytes)?;
        let mut session = Self::new(config, history)?;
        session.terminal.host = Some(host.clone());
        session.terminal.floor_reservation = Some(floor);
        session.ring.set_budget(host);
        Ok(session)
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
            "{{\"kind\":\"ownership\",\"session\":{index},\"total_bytes\":{},\"pool_bytes\":{},\"pool_limit_bytes\":{},\"native_ordinary_bytes\":{ordinary},\"native_page_bytes\":{pages},\"native_resident_bytes\":{resident},\"native_encoded_bytes\":{encoded},\"native_history_rows\":{history_rows},\"carry_bytes\":{carry},\"struct_bytes\":{},\"path_bytes\":{},\"config_path_bytes\":{},\"prefix_bytes\":{},\"geometry_bytes\":{},\"ring_bytes\":{},\"input_bytes\":{},\"writer_bytes\":{},\"peer_bytes\":{},\"peer_slots_bytes\":{}",
            self.allocated_bytes(),
            self.terminal.pool_bytes() + self.ring.allocated_bytes(),
            self.terminal.pool_limit_bytes(),
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
            if shim_peer_uid_allowed(credential.uid(), Uid::effective().as_raw())
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
                        | SHARED_WRITER
                        | crate::frame::QUERY_REPLIES,
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
            // Retention limits how much history the ring keeps, not how much
            // PTY output the live screen can process. A zero-share ring still
            // advances its absolute head while dropping the old byte history.
            let limit = read_budget.min(bytes.len());
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

/// Admits sessions one at a time so a full pool refuses only the new opens.
fn open_host_sessions(
    configs: Vec<Config>,
    history: usize,
    host: std::sync::Arc<crate::terminal_memory::HostBudget>,
) -> io::Result<(Vec<Session>, Vec<io::Error>)> {
    let mut sessions = Vec::with_capacity(configs.len());
    let mut refusals = Vec::new();
    for config in configs {
        match Session::new_host(config, history, host.clone()) {
            Ok(session) => sessions.push(session),
            Err(error) if pool_full_error(&error) => refusals.push(error),
            Err(error) => return Err(error),
        }
    }
    if sessions.is_empty() {
        return Err(refusals
            .into_iter()
            .next()
            .unwrap_or_else(|| io::Error::other("no user sessions were admitted")));
    }
    Ok((sessions, refusals))
}

fn pool_full_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::OutOfMemory
        && error
            .to_string()
            .starts_with("terminal memory for this user is full (")
}

/// Host an explicitly supplied batch inside one existing person's login [D240/D247].
///
/// Per-session Rust panics retire that session. Native faults and process OOM
/// still affect the whole host; this function does not claim process isolation.
/// Call during single-threaded startup: process-directed SIGCHLD must remain
/// blocked in every thread while this reactor owns its children.
/// # Errors
/// Rejects foreign UIDs, duplicate IDs, invalid geometry, threaded startup and
/// other startup failures. Pool-full opens use the existing stderr error path;
/// already admitted sessions keep running when later opens are refused.
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
    let pool = host_native_pool_bytes();
    let native = crate::terminal_memory::HostBudget::new(pool, SESSION_SCREEN_BYTES);
    let floor_total = configs.iter().fold(0_usize, |total, config| {
        total.saturating_add(crate::terminal_native::floor_for_geometry(
            config.cols,
            config.rows,
            SESSION_SCREEN_BYTES,
        ))
    });
    let shareable = pool.saturating_sub(floor_total);
    // Equal per-session shares leave one eighth for geometry growth. The
    // rest is split between native scrollback and output replay retention.
    let content = shareable.saturating_mul(7) / 8;
    let history_total = (content * 3 / 4).min(HOST_HISTORY_BYTES);
    let ring_total = content.saturating_sub(history_total);
    let history = (history_total / configs.len()).min(17 * 1024 * 1024);
    let ring_budget = ring_total / configs.len();
    for config in &mut configs {
        config.ring_capacity = config.ring_capacity.min(ring_budget);
    }
    let (sessions, refusals) = open_host_sessions(configs, history, native)?;
    for error in refusals {
        eprintln!("session open failed: {error}");
    }
    reactor::run(sessions, &signals, accounting)
}

/// Host pool for this machine: 1/32 of available memory, or the tighter
/// cgroup limit, clamped to 80–512 MiB. Session floors are inside this cap.
fn host_native_pool_bytes() -> usize {
    let available = usable_memory().unwrap_or(HOST_NATIVE_POOL_MIN);
    host_pool_bytes(available, None)
}

fn host_pool_bytes(available: usize, cgroup_limit: Option<usize>) -> usize {
    let usable = cgroup_limit.map_or(available, |limit| available.min(limit));
    (usable / HOST_NATIVE_POOL_FRACTION).clamp(HOST_NATIVE_POOL_MIN, HOST_NATIVE_POOL_MAX)
}

/// MemAvailable, or the tightest cgroup limit when that is lower. Read once
/// at host start; a missing or unreadable source falls back to the minimum.
fn usable_memory() -> Option<usize> {
    let available = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|info| meminfo_available(&info))?;
    let limit = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|groups| cgroup_v2_limit(&groups, std::path::Path::new("/sys/fs/cgroup")));
    Some(limit.map_or(available, |limit| limit.min(available)))
}

fn meminfo_available(info: &str) -> Option<usize> {
    let kib = info
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))?
        .trim()
        .strip_suffix("kB")?
        .trim()
        .parse::<usize>()
        .ok()?;
    kib.checked_mul(1024)
}

/// Walks cgroup-v2 ancestors because an ancestor can impose a tighter cap.
fn cgroup_v2_limit(groups: &str, root: &std::path::Path) -> Option<usize> {
    let relative = groups
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?
        .trim_start_matches('/');
    let relative = std::path::Path::new(relative);
    if relative.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    }) {
        return None;
    }
    let mut current = root.join(relative);
    let mut tightest = None;
    loop {
        let value = std::fs::read_to_string(current.join("memory.max")).ok()?;
        if let Ok(limit) = value.trim().parse::<usize>() {
            tightest = Some(tightest.map_or(limit, |old: usize| old.min(limit)));
        }
        if current == root {
            break;
        }
        if !current.pop() || !current.starts_with(root) {
            return None;
        }
    }
    tightest
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

    /// Type bytes into a real PTY and finish one bounded output turn.
    ///
    /// The ring head is the replay position even when the configured ring has
    /// no retained capacity, so this helper checks both PTY drainage and that
    /// the replay position advanced with the output.
    fn type_and_drain(session: &mut Session, input: &[u8]) -> io::Result<u64> {
        use std::os::fd::AsFd;

        let head = session.ring.head();
        session.pty.master.write_all(input)?;
        let mut descriptors = [nix::poll::PollFd::new(
            session.pty.master.as_fd(),
            PollFlags::POLLIN,
        )];
        let ready = nix::poll::poll(&mut descriptors, 5000_u16)?;
        assert_ne!(ready, 0, "typed input did not produce PTY echo");
        let master = descriptors[0].revents().unwrap_or_else(PollFlags::empty);
        session.step(PollFlags::empty(), master, &[], true)?;
        let unread = crate::pty::available_output(&session.pty.master)?;
        assert_eq!(unread, 0, "session step left {unread} PTY bytes unread");
        let advanced = session.ring.head() - head;
        assert!(
            advanced > 0,
            "drained PTY output did not advance replay head"
        );
        assert_eq!(session.ring.start(), session.ring.head());
        Ok(advanced)
    }

    /// Attach an in-memory viewer at the current replay head for snapshot tests.
    fn snapshot_peer(session: &mut Session) -> io::Result<std::os::unix::net::UnixStream> {
        let (server, client) = std::os::unix::net::UnixStream::pair()?;
        server.set_nonblocking(true)?;
        client.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        session
            .peers
            .try_reserve_exact(1)
            .map_err(io::Error::other)?;
        session.peers.push(Peer {
            stream: server,
            decoder: Decoder::default(),
            trailing: Vec::new(),
            deferred: None,
            attached: true,
            caps: APPROXIMATE_SNAPSHOT,
            input_reply: None,
            writer: Some(0),
            shared_writer: false,
            ack_queued: 0,
            size: (session.config.cols, session.config.rows, 0, 0),
            cursor: Some(session.ring.head()),
            request: None,
            pending: Vec::new(),
            written: 0,
            exited_sent: false,
        });
        Ok(client)
    }

    /// Read one bounded frame and return its absolute snapshot head.
    fn snapshot_head(client: &mut std::os::unix::net::UnixStream) -> io::Result<u64> {
        let mut length = [0; 4];
        client.read_exact(&mut length)?;
        let length = usize::try_from(u32::from_le_bytes(length)).map_err(io::Error::other)?;
        if length == 0 || length > crate::frame::MAX_FRAME {
            return Err(io::Error::other(
                "snapshot frame length is outside protocol bounds",
            ));
        }
        let mut frame = vec![0; length];
        client.read_exact(&mut frame)?;
        match Frame::decode(&frame).map_err(io::Error::other)? {
            Frame::Snapshot(head, _) | Frame::SnapshotWithFlags(head, _, _) => Ok(head),
            Frame::Error(_, message) => Err(io::Error::other(message)),
            _ => Err(io::Error::other(
                "replay gap did not produce a screen snapshot",
            )),
        }
    }

    /// PPU-R3-2 (#205): the host pool follows the machine within its bounds.
    #[test]
    fn host_pool_scales_with_machine_memory_within_bounds() {
        assert_eq!(
            meminfo_available("MemAvailable:   16303428 kB\nMemFree: 1 kB\n"),
            Some(16_303_428 * 1024)
        );
        assert_eq!(meminfo_available("MemFree: 1 kB\n"), None);
        let pool = host_native_pool_bytes();
        eprintln!(
            "host pool {pool} B for usable memory {:?} B",
            usable_memory()
        );
        assert!((HOST_NATIVE_POOL_MIN..=HOST_NATIVE_POOL_MAX).contains(&pool));
        for (available, cgroup, expected) in [
            (32_usize << 30, None, HOST_NATIVE_POOL_MAX),
            (1_usize << 30, None, HOST_NATIVE_POOL_MIN),
            (32_usize << 30, Some(1_usize << 30), HOST_NATIVE_POOL_MIN),
            (32_usize << 30, Some(4_usize << 30), 128 << 20),
            (8_usize << 30, None, 256 << 20),
        ] {
            assert_eq!(host_pool_bytes(available, cgroup), expected);
        }
    }

    /// D310: deterministic property sequence over session admission, output
    /// growth and close operations. The committed total always stays in cap.
    #[test]
    fn pool_usage_never_exceeds_cap_under_open_write_close_sequences() {
        const CAP: usize = 4 * 1024 * 1024;
        struct SampleSession {
            ring: Ring,
            terminal: Terminal,
        }
        fn next(seed: &mut u64) -> u64 {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *seed
        }

        let host = crate::terminal_memory::HostBudget::new(CAP, SESSION_SCREEN_BYTES);
        let mut sessions: Vec<Option<SampleSession>> = Vec::new();
        let mut seed = 0x7a11_0c5e_55aa_0913;
        let mut output = [b'x'; 8192];
        for line in (79..output.len()).step_by(81) {
            output[line] = b'\r';
            output[line + 1] = b'\n';
        }
        for _ in 0..20_000 {
            match next(&mut seed) % 3 {
                0 if sessions.len() < 24 || sessions.iter().any(Option::is_none) => {
                    if let Ok(mut terminal) =
                        Terminal::with_host_budget(80, 24, 128 * 1024, Some(host.clone()))
                    {
                        terminal.process(b"\x1bc");
                        let mut ring = Ring::new(384 * 1024);
                        ring.set_budget(host.clone());
                        let session = SampleSession { ring, terminal };
                        if let Some(slot) = sessions.iter_mut().find(|slot| slot.is_none()) {
                            *slot = Some(session);
                        } else {
                            sessions.push(Some(session));
                        }
                    }
                }
                1 if !sessions.is_empty() => {
                    let index = next(&mut seed) as usize % sessions.len();
                    if let Some(session) = sessions[index].as_mut() {
                        let length = 1 + next(&mut seed) as usize % output.len();
                        session.terminal.process(&output[..length]);
                        session.ring.append(&output[..length]).unwrap();
                    }
                }
                _ if !sessions.is_empty() => {
                    let index = next(&mut seed) as usize % sessions.len();
                    sessions[index] = None;
                }
                _ => {}
            }
            assert!(
                host.total_used() <= CAP,
                "pool {} exceeded {CAP}",
                host.total_used()
            );
        }
        drop(sessions);
        assert_eq!(host.total_used(), 0, "closed sessions left pool charges");
    }

    /// Ring pressure drops the oldest retained output while preserving the
    /// absolute offset of the new tail.
    #[test]
    fn full_pool_reuses_ring_storage_for_newest_output() {
        let host = crate::terminal_memory::HostBudget::new(1024, SESSION_SCREEN_BYTES);
        let mut ring = Ring::new(4);
        ring.set_budget(host.clone());
        ring.append(b"abcd").unwrap();
        assert_eq!(ring.allocated_bytes(), 4);
        assert!(host.try_charge(1020));
        ring.append(b"efgh").unwrap();
        assert_eq!(ring.start(), 4);
        assert_eq!(ring.read(4, 4).unwrap(), b"efgh");
        assert_eq!(host.total_used(), 1024);
        drop(ring);
        assert_eq!(host.total_used(), 1020);
        host.release_charge(1020);
        assert_eq!(host.total_used(), 0);
    }

    /// D310: a refused open uses the session-open error and leaves a live
    /// sibling's terminal and replay history usable.
    #[test]
    fn full_pool_refuses_new_session_and_keeps_existing_session_working() {
        let floor = crate::terminal_native::floor_for_geometry(80, 24, SESSION_SCREEN_BYTES);
        let cap = floor + 1024;
        let host = crate::terminal_memory::HostBudget::new(cap, SESSION_SCREEN_BYTES);
        let state = crate::fixture_state::fixture_state();
        let mut config = Config::new([0x71; 16], Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.ring_capacity = 64 * 1024;
        let mut refused_config = config.clone();
        refused_config.session = [0x72; 16];
        let (mut sessions, mut refusals) =
            open_host_sessions(vec![config, refused_config], 64 * 1024, host.clone()).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(refusals.len(), 1);
        let error = refusals.pop().unwrap();
        let existing = &mut sessions[0];
        existing
            .terminal
            .process(b"\x1bcexisting session\r\n")
            .unwrap();
        existing.ring.append(b"existing output").unwrap();
        assert_eq!(
            error.to_string(),
            format!(
                "terminal memory for this user is full ({} KiB); close a session",
                cap / 1024
            )
        );
        assert!(existing.terminal.snapshot().is_ok());
        assert_eq!(existing.ring.read(0, 64).unwrap(), b"existing output");
        assert!(existing.pty.child.try_wait().unwrap().is_none());
        assert!(host.total_used() <= cap);
        drop(sessions);
        assert_eq!(host.total_used(), 0);
        std::fs::remove_dir_all(state).unwrap();
    }

    /// D310 review: a zero ring share can result when startup floors consume
    /// the whole host pool. The session must still drain its PTY rather than
    /// turning a bounded-memory choice into a permanently unread output fd.
    #[test]
    fn zero_ring_capacity_does_not_stall_a_live_pty() {
        let floor = crate::terminal_native::floor_for_geometry(80, 24, SESSION_SCREEN_BYTES);
        let host = crate::terminal_memory::HostBudget::new(floor, SESSION_SCREEN_BYTES);
        let state = crate::fixture_state::fixture_state();
        let mut config = Config::new([0x73; 16], Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        // run_host_accounted can reduce a valid requested capacity to zero
        // when floors consume all remaining pool bytes.
        config.ring_capacity = 0;
        let mut session = Session::new_host(config, 64 * 1024, host.clone()).unwrap();
        assert_eq!(host.total_used(), floor);

        let mut refused_config = Config::new([0x74; 16], Uid::effective().as_raw());
        refused_config.state = Some(state.clone());
        refused_config.ring_capacity = 1;
        let Err(refusal) = Session::new_host(refused_config, 64 * 1024, host.clone()) else {
            panic!("a full pool admitted another session");
        };
        eprintln!("full_pool_refusal={refusal}");
        assert!(
            refusal
                .to_string()
                .starts_with("terminal memory for this user is full (")
        );
        assert!(refusal.to_string().ends_with("; close a session"));

        let before_head = session.ring.head();
        session.terminal.process(b"\x1bcpool ready\r\n").unwrap();
        let before_screen = session.terminal.snapshot().unwrap();
        session.pty.master.write_all(b"continue\n").unwrap();
        let response_bytes = b"infraternal-ready\n".len();
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        while crate::pty::available_output(&session.pty.master).unwrap() < response_bytes {
            assert!(Instant::now() < deadline, "readiness shell did not answer");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let ready = crate::pty::available_output(&session.pty.master).unwrap();
        session
            .step(PollFlags::empty(), PollFlags::POLLIN, &[], true)
            .unwrap();
        let unread = crate::pty::available_output(&session.pty.master).unwrap();
        let after_screen = session.terminal.snapshot().unwrap();
        eprintln!("full_pool_pty_bytes_before={ready} after_session_step={unread}");
        assert_eq!(session.ring.head() - before_head, ready as u64);
        assert_eq!(session.ring.start(), session.ring.head());
        assert_ne!(
            before_screen, after_screen,
            "the visible screen did not advance"
        );

        drop(session);
        assert_eq!(
            host.total_used(),
            0,
            "retired PTY kept its pool reservation"
        );
        std::fs::remove_dir_all(state).unwrap();
        assert_eq!(
            unread, 0,
            "zero ring capacity left {unread} PTY response bytes unread"
        );
    }

    /// D310 property: random open/write/close churn at a full pool always
    /// drains each selected live PTY while screen state and replay offsets move.
    #[test]
    fn exhausted_pool_drains_live_ptys_during_random_session_churn() {
        const LIVE_SESSIONS: usize = 2;
        const OPERATIONS: usize = 128;

        fn next(seed: &mut u64) -> u64 {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *seed
        }

        let floor = crate::terminal_native::floor_for_geometry(80, 24, SESSION_SCREEN_BYTES);
        let cap = floor * LIVE_SESSIONS;
        let host = crate::terminal_memory::HostBudget::new(cap, SESSION_SCREEN_BYTES);
        let state = crate::fixture_state::fixture_state();
        let mut seed = 0x2051_0019_7a11_0c5e;
        let mut next_id = 0x7510_u128;
        let mut sessions: Vec<Option<Session>> = (0..LIVE_SESSIONS).map(|_| None).collect();

        let open = |id: u128| {
            let mut config = Config::new(id.to_le_bytes(), Uid::effective().as_raw());
            config.state = Some(state.clone());
            config.readiness = true;
            // run_host_accounted can set this to zero when all admitted floors
            // consume the pool; retention must not control PTY read progress.
            config.ring_capacity = 0;
            let mut session = Session::new_host(config, 64 * 1024, host.clone())?;
            session.terminal.process(b"\x1bcpool ready\r\n")?;
            Ok(session)
        };
        for slot in &mut sessions {
            *slot = Some(open(next_id).unwrap());
            next_id += 1;
        }
        assert_eq!(host.total_used(), cap);

        let mut full_pool_drains = 0;
        for _ in 0..OPERATIONS {
            match next(&mut seed) % 5 {
                0 => {
                    let index = usize::try_from(next(&mut seed) % 2).unwrap();
                    if sessions[index].is_none() {
                        sessions[index] = Some(open(next_id).unwrap());
                        next_id += 1;
                    } else if host.total_used() == cap {
                        let error = match open(next_id) {
                            Ok(session) => {
                                drop(session);
                                panic!("full-pool open unexpectedly succeeded");
                            }
                            Err(error) => error,
                        };
                        assert!(pool_full_error(&error));
                    }
                }
                1..=3 => {
                    let index = usize::try_from(next(&mut seed) % 2).unwrap();
                    if let Some(session) = sessions[index].as_mut() {
                        let before = session.terminal.snapshot().unwrap();
                        let key = b"abcdefghijklmnopqrstuvwxyz"
                            [usize::try_from(next(&mut seed) % 26).unwrap()];
                        assert_eq!(type_and_drain(session, &[key]).unwrap(), 1);
                        let after = session.terminal.snapshot().unwrap();
                        assert_ne!(before, after, "live screen did not display typed input");
                        type_and_drain(session, b"\x7f").unwrap();
                        if host.total_used() == cap {
                            full_pool_drains += 1;
                        }
                    }
                }
                _ => {
                    let index = usize::try_from(next(&mut seed) % 2).unwrap();
                    sessions[index] = None;
                }
            }

            if host.total_used() == cap {
                for session in sessions.iter_mut().flatten() {
                    let before = session.terminal.snapshot().unwrap();
                    let key = b"abcdefghijklmnopqrstuvwxyz"
                        [usize::try_from(next(&mut seed) % 26).unwrap()];
                    assert_eq!(type_and_drain(session, &[key]).unwrap(), 1);
                    let after = session.terminal.snapshot().unwrap();
                    assert_ne!(before, after, "live screen did not display typed input");
                    type_and_drain(session, b"\x7f").unwrap();
                    full_pool_drains += 1;
                }
            }
            assert!(host.total_used() <= cap);
        }

        assert!(
            full_pool_drains > 0,
            "property sequence never drained at full pool"
        );
        drop(sessions);
        assert_eq!(
            host.total_used(),
            0,
            "closed PTYs kept their floor reservations"
        );
        std::fs::remove_dir_all(&state).unwrap();
    }

    /// Measure a real typed-key echo turn on the perf VM with every pool byte
    /// reserved by two live screens. This reports shim-path p50/p99 and keeps
    /// the shell's input line clear between samples.
    #[test]
    #[ignore = "timing measurement runs on the perf VM"]
    fn full_pool_typing_echo_latency() {
        const SAMPLES: usize = 1000;
        let floor = crate::terminal_native::floor_for_geometry(80, 24, SESSION_SCREEN_BYTES);
        let cap = floor * 2;
        let host = crate::terminal_memory::HostBudget::new(cap, SESSION_SCREEN_BYTES);
        let state = crate::fixture_state::fixture_state();
        let open = |id: u128| {
            let mut config = Config::new(id.to_le_bytes(), Uid::effective().as_raw());
            config.state = Some(state.clone());
            config.readiness = true;
            config.ring_capacity = 0;
            Session::new_host(config, 64 * 1024, host.clone())
        };
        let mut session = open(0x7511).unwrap();
        session.terminal.process(b"\x1bcpool ready\r\n").unwrap();
        let neighbor = open(0x7512).unwrap();
        assert_eq!(host.total_used(), cap);
        let mut viewer = snapshot_peer(&mut session).unwrap();
        let refusal = match open(0x7513) {
            Ok(session) => {
                drop(session);
                panic!("full-pool open unexpectedly succeeded");
            }
            Err(error) => error,
        };
        assert!(pool_full_error(&refusal));

        let load_start = std::fs::read_to_string("/proc/loadavg").unwrap();
        let mut samples = Vec::with_capacity(SAMPLES);
        for index in 0..SAMPLES {
            let key = b"abcdefghijklmnopqrstuvwxyz"[index % 26];
            let started = Instant::now();
            assert_eq!(type_and_drain(&mut session, &[key]).unwrap(), 1);
            session.housekeeping().unwrap();
            assert_eq!(snapshot_head(&mut viewer).unwrap(), session.ring.head());
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
            type_and_drain(&mut session, b"\x7f").unwrap();
            session.housekeeping().unwrap();
            assert_eq!(snapshot_head(&mut viewer).unwrap(), session.ring.head());
        }
        samples.sort_unstable_by(f64::total_cmp);
        let p50 = samples[(SAMPLES - 1) * 50 / 100];
        let p99 = samples[(SAMPLES - 1) * 99 / 100];
        let maximum = samples[SAMPLES - 1];
        let load_end = std::fs::read_to_string("/proc/loadavg").unwrap();
        eprintln!(
            "METRIC name=pool_full_typing_echo_ms n={SAMPLES} p50={p50:.4} p99={p99:.4} max={maximum:.4} pool_bytes={}/{} loadavg_start={} loadavg_end={}",
            host.total_used(),
            cap,
            load_start
                .split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join("/"),
            load_end
                .split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join("/")
        );
        drop(neighbor);
        drop(session);
        assert_eq!(host.total_used(), 0);
        std::fs::remove_dir_all(&state).unwrap();
    }

    pub(super) fn ack_fixture(
        tag: u8,
    ) -> (
        Session,
        std::os::unix::net::UnixStream,
        crate::fixture_state::FixtureState,
    ) {
        let state = crate::fixture_state::fixture_state();
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
        let state = crate::fixture_state::fixture_state();
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
        let state = crate::fixture_state::fixture_state();
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
        let state = crate::fixture_state::fixture_state();
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
        let state = crate::fixture_state::fixture_state();
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
        let state = crate::fixture_state::fixture_state();
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
        let state = crate::fixture_state::fixture_state();
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
        let state = crate::fixture_state::fixture_state();
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
        let state = crate::fixture_state::fixture_state();
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
