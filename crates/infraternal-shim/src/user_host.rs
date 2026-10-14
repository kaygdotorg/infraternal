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
use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    os::unix::{net::UnixListener, process::ExitStatusExt},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const PREFIX_LIMIT: usize = 4096;
// A global output quantum keeps one thousand ready PTYs from postponing input.
const OUTPUTS_PER_ROUND: usize = 16;
// Aggregate history is bounded at scale rather than multiplying defaults by 1000.
const HOST_HISTORY_BYTES: usize = 64 * 1024 * 1024;

/// A complete origin prefix is retained until VT materialization, never an evicting tail.
struct LazyTerminal {
    state: RefCell<LazyState>,
    cols: u16,
    rows: u16,
    history: usize,
}
struct LazyState {
    terminal: Option<Box<Terminal>>,
    prefix: Vec<u8>,
    #[cfg(test)]
    panic_next_process: bool,
}
impl LazyTerminal {
    fn new(cols: u16, rows: u16, history: usize) -> Self {
        Self {
            state: RefCell::new(LazyState {
                terminal: None,
                prefix: Vec::new(),
                #[cfg(test)]
                panic_next_process: false,
            }),
            cols,
            rows,
            history,
        }
    }
    fn materialize(&self) -> io::Result<()> {
        let mut state = self.state.borrow_mut();
        if state.terminal.is_none() {
            let mut terminal = Box::new(Terminal::with_history_budget(
                self.cols,
                self.rows,
                self.history,
            )?);
            terminal.process(&state.prefix);
            state.terminal = Some(terminal);
            state.prefix = Vec::new();
        }
        Ok(())
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
        // Writer selection also reapplies unchanged geometry. That is not
        // reflow and must not allocate VT for a light-output idle session.
        if (cols, rows) == (self.cols, self.rows) && self.state.get_mut().terminal.is_none() {
            return Ok(());
        }
        // Materialize at the historical geometry before applying reflow.
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
impl Session {
    fn new(config: Config, history: usize) -> io::Result<Self> {
        let (listener, path) = socket(&config)?;
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
    fn can_read(&self) -> bool {
        !self.drained
            && (!self.peers.iter().any(|p| p.cursor.is_some())
                || self.peers.iter().any(|p| {
                    p.pending.is_empty() && p.cursor.is_some_and(|s| s == self.ring.head())
                }))
    }
    #[allow(clippy::too_many_lines)]
    fn housekeeping(&mut self) -> io::Result<bool> {
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
        let oldest = self.peers.iter().filter_map(|p| p.deferred).min();
        let mut retired = Vec::new();
        for (i, p) in self.peers.iter_mut().enumerate() {
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
            if p.pending.is_empty()
                && let Some(reply) = p.input_reply.take()
            {
                let state = self.cursors.get(p.writer)?;
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
                    Request::Snapshot => p.snapshot(&self.terminal, self.ring.head())?,
                }
            }
            if p.pending.is_empty()
                && let Some(seq) = p.cursor
            {
                if seq < self.ring.start() {
                    p.snapshot(&self.terminal, self.ring.head())?;
                } else if seq < self.ring.head() {
                    let bytes = self
                        .ring
                        .read(seq, CHUNK)
                        .ok_or_else(|| io::Error::other("delivery cursor invariant"))?;
                    p.cursor = Some(seq + bytes.len() as u64);
                    p.queue(&Frame::Output(seq, bytes))?;
                } else if self.drained
                    && !p.exited_sent
                    && let Some(status) = self.exit
                {
                    p.queue(&Frame::Exited(status, self.ring.head()))?;
                    p.exited_sent = true;
                }
            }
        }
        for i in retired.into_iter().rev() {
            self.peers.remove(i);
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
        if listener.contains(PollFlags::POLLIN)
            && let Ok((stream, _)) = self.listener.accept()
        {
            let credential = getsockopt(&stream, PeerCredentials).map_err(io::Error::from)?;
            if (credential.uid() == 0 || credential.uid() == Uid::effective().as_raw())
                && self.peers.len() < MAX_PEERS
            {
                stream.set_nonblocking(true)?;
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
        if read_pty
            && self.can_read()
            && (master.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) || self.exit.is_some())
        {
            let mut bytes = [0; CHUNK];
            match self
                .pty
                .master
                .read(&mut bytes[..CHUNK.min(self.config.ring_capacity)])
            {
                Ok(0) => self.drained = true,
                Ok(n) => {
                    self.terminal.process(&bytes[..n])?;
                    self.ring.append(&bytes[..n])?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.drained = self.exit.is_some();
                }
                Err(e) if e.raw_os_error() == Some(nix::libc::EIO) => self.drained = true,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        let oldest = self.peers.iter().filter_map(|p| p.deferred).min();
        let mut disconnects = [false; MAX_PEERS];
        for (i, flags) in peers.iter().copied().enumerate() {
            let p = &mut self.peers[i];
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
                    Ok(n) => match consume_peer(
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
                    },
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
        Ok(())
    }
}

/// Host an explicitly supplied batch inside one existing person's login [D240/D247].
///
/// Per-session Rust panics retire that session. Native faults and process OOM
/// still affect the whole host; this function does not claim process isolation.
/// # Errors
/// Rejects foreign UIDs, duplicate IDs, invalid geometry and startup failures.
#[allow(clippy::too_many_lines)]
pub fn run_host(mut configs: Vec<Config>) -> io::Result<()> {
    if configs.is_empty()
        || configs.len() > 1000
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
    umask(Mode::from_bits_truncate(0o077));
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGCHLD);
    mask.thread_block().map_err(io::Error::from)?;
    let signals = SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK | SfdFlags::SFD_CLOEXEC)
        .map_err(io::Error::from)?;
    let history = (HOST_HISTORY_BYTES / configs.len()).min(17 * 1024 * 1024);
    let ring_budget = HOST_HISTORY_BYTES / configs.len();
    for config in &mut configs {
        config.ring_capacity = config.ring_capacity.min(ring_budget);
    }
    let sessions = configs
        .into_iter()
        .map(|config| Session::new(config, history))
        .collect::<io::Result<Vec<_>>>()?;
    reactor::run(sessions, &signals)
}

#[path = "user_host_reactor.rs"]
mod reactor;

#[cfg(test)]
mod tests {
    //! Differential state and admission tests for the research-only reactor.
    use super::*;
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
