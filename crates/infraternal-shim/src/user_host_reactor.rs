//! Index ready sessions without idle scans; only child-exit readiness reconciles all owned children [D81/D268].
use super::{BULK_READ_BYTES, INTERACTIVE_READ_BYTES, MAX_PEERS, OUTPUTS_PER_ROUND, Session};
use nix::{
    poll::PollFlags,
    sys::{
        epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout},
        signal::Signal,
        signalfd::SignalFd,
    },
};
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    io::{self, Write},
    os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd},
    panic::{AssertUnwindSafe, catch_unwind},
    time::{Duration, Instant},
};

const SIGNAL: u64 = u64::MAX;
#[derive(Clone, Copy)]
struct Registration {
    fd: RawFd,
    flags: EpollFlags,
    key: u64,
    session: usize,
}
pub(super) struct Registry {
    epoll: Epoll,
    by_fd: HashMap<RawFd, Registration>,
    owned: Vec<Vec<RawFd>>,
    next_key: u32,
}

#[cfg(test)]
pub(super) fn ownership_fixture(sessions: &[Session], signals: &SignalFd) -> io::Result<Registry> {
    let mut registry = Registry::new(sessions.len(), signals)?;
    for (index, session) in sessions.iter().enumerate() {
        registry.sync(index, session)?;
    }
    Ok(registry)
}
impl Registry {
    fn new(count: usize, signals: &SignalFd) -> io::Result<Self> {
        let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?;
        epoll.add(signals, EpollEvent::new(EpollFlags::EPOLLIN, SIGNAL))?;
        Ok(Self {
            epoll,
            by_fd: HashMap::new(),
            owned: vec![Vec::new(); count],
            next_key: 0,
        })
    }
    fn retire(&mut self, index: usize) {
        for fd in self.owned[index].drain(..) {
            self.by_fd.remove(&fd);
        }
        // Owned session descriptors have closed; the kernel removes them.
    }
    /// Input retirement precedes the next listener admission. Remove only
    /// closed identities here: publishing temporary writable interest before
    /// the reply batch is flushed would add two epoll changes per keystroke.
    fn retire_closed(&mut self, index: usize, session: &Session) {
        self.owned[index].retain(|fd| {
            let live = *fd == session.listener.as_raw_fd()
                || *fd == session.pty.master.as_raw_fd()
                || session
                    .peers
                    .iter()
                    .any(|peer| peer.stream.as_raw_fd() == *fd);
            if !live {
                self.by_fd.remove(fd);
            }
            live
        });
    }
    fn registration(&self, key: u64) -> Option<&Registration> {
        let fd = RawFd::try_from(key & u64::from(u32::MAX)).ok()?;
        self.by_fd.get(&fd).filter(|entry| entry.key == key)
    }
    fn sync(&mut self, index: usize, session: &Session) -> io::Result<()> {
        // Peer admission already caps this array. Steady interest changes
        // borrow a small stack list rather than allocate on every settle.
        let mut storage: [Option<(BorrowedFd<'_>, EpollFlags)>; MAX_PEERS + 2] =
            [None; MAX_PEERS + 2];
        storage[0] = Some((session.listener.as_fd(), EpollFlags::EPOLLIN));
        let mut descriptor_count = 1;
        let mut master = EpollFlags::empty();
        if session.can_read() {
            master |= EpollFlags::EPOLLIN;
        }
        if !session.input.is_empty() {
            master |= EpollFlags::EPOLLOUT;
        }
        if !master.is_empty() {
            storage[descriptor_count] = Some((session.pty.master.as_fd(), master));
            descriptor_count += 1;
        }
        for peer in &session.peers {
            let mut flags = EpollFlags::empty();
            if peer.deferred.is_none() && peer.trailing.is_empty() {
                flags |= EpollFlags::EPOLLIN;
            }
            if session.can_write(peer) {
                flags |= EpollFlags::EPOLLOUT;
            }
            storage[descriptor_count] = Some((peer.stream.as_fd(), flags));
            descriptor_count += 1;
        }
        let descriptors = &storage[..descriptor_count];
        self.owned[index].retain(|fd| {
            if descriptors
                .iter()
                .flatten()
                .any(|(current, _)| current.as_raw_fd() == *fd)
            {
                return true;
            }
            if self.by_fd.remove(fd).is_some() && *fd == session.pty.master.as_raw_fd() {
                // A disabled but live master must be removed explicitly;
                // level-triggered HUP on a drained master otherwise spins.
                let _ = self.epoll.delete(&session.pty.master);
            }
            false
        });
        for (fd, flags) in descriptors.iter().flatten().copied() {
            if let Some(old) = self.by_fd.get_mut(&fd.as_raw_fd()) {
                if old.flags != flags {
                    self.epoll
                        .modify(fd, &mut EpollEvent::new(flags, old.key))?;
                    old.flags = flags;
                }
            } else {
                self.next_key = self
                    .next_key
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other("host readiness identity exhausted"))?;
                // The fd addresses the sole index; its generation rejects old
                // readiness after close/reuse. Refuse before generation wrap,
                // so a stale event can never regain authority over a new peer.
                let key = (u64::from(self.next_key) << 32)
                    | u64::try_from(fd.as_raw_fd()).map_err(io::Error::other)?;
                let entry = Registration {
                    fd: fd.as_raw_fd(),
                    flags,
                    key,
                    session: index,
                };
                self.epoll.add(fd, EpollEvent::new(flags, entry.key))?;
                self.by_fd.insert(entry.fd, entry);
                self.owned[index].push(entry.fd);
            }
        }
        Ok(())
    }
}
#[derive(Default)]
struct Ready {
    first: Option<(u64, EpollFlags)>,
    more: Vec<(u64, EpollFlags)>,
}
impl Ready {
    fn insert(&mut self, key: u64, flags: EpollFlags) {
        if let Some((first, current)) = &mut self.first {
            if *first == key {
                *current |= flags;
            } else if let Some((_, current)) = self.more.iter_mut().find(|(old, _)| *old == key) {
                *current |= flags;
            } else {
                self.more.push((key, flags));
            }
        } else {
            self.first = Some((key, flags));
        }
    }
    fn get(&self, key: u64) -> Option<EpollFlags> {
        self.first
            .filter(|(old, _)| *old == key)
            .map(|(_, flags)| flags)
            .or_else(|| {
                self.more
                    .iter()
                    .find(|(old, _)| *old == key)
                    .map(|(_, flags)| *flags)
            })
    }
    fn flags(&self, fd: RawFd, registry: &Registry) -> PollFlags {
        let flags = registry
            .by_fd
            .get(&fd)
            .and_then(|entry| self.get(entry.key))
            .unwrap_or_else(EpollFlags::empty);
        let mut result = PollFlags::empty();
        if flags.contains(EpollFlags::EPOLLIN) {
            result |= PollFlags::POLLIN;
        }
        if flags.contains(EpollFlags::EPOLLOUT) {
            result |= PollFlags::POLLOUT;
        }
        if flags.contains(EpollFlags::EPOLLHUP) {
            result |= PollFlags::POLLHUP;
        }
        if flags.contains(EpollFlags::EPOLLERR) {
            result |= PollFlags::POLLERR;
        }
        result
    }
}

/// Membership follows immutable session slots, not descriptor numbers. Read
/// generations avoid clearing all idle slots on each busy reactor turn.
struct ReadyMarks {
    queued: Vec<u8>,
    read: Vec<u32>,
    round: u32,
}
impl ReadyMarks {
    fn new(count: usize) -> Self {
        Self {
            queued: vec![0; count],
            read: vec![0; count],
            round: 1,
        }
    }
    fn next_round(&mut self) {
        if let Some(round) = self.round.checked_add(1) {
            self.round = round;
        } else {
            // Clear before reusing a generation: old marks can never skip
            // a newly ready session, even after billions of busy turns.
            self.read.fill(0);
            self.round = 1;
        }
    }
    fn queue(&mut self, index: usize) -> bool {
        // 0 has no deque entry; 1 is bulk; 2 is cancelled by promotion.
        // Revive a cancelled entry in place rather than inserting a duplicate.
        std::mem::replace(&mut self.queued[index], 1) == 0
    }
    fn promote(&mut self, index: usize) {
        if self.queued[index] != 0 {
            self.queued[index] = 2;
        }
    }
    fn take_bulk(&mut self, index: usize) -> bool {
        std::mem::replace(&mut self.queued[index], 0) == 1
    }
    fn read_once(&mut self, index: usize) -> bool {
        if self.read[index] == self.round {
            return false;
        }
        self.read[index] = self.round;
        true
    }
}

/// Settle queues and lifetimes only for a ready session. Registration happens
/// both before and after acceptance so a closed/reused fd cannot inherit a key.
fn settle(
    index: usize,
    slots: &mut [Option<Session>],
    registry: &mut Registry,
    timers: &mut BinaryHeap<Reverse<(Instant, usize)>>,
) -> io::Result<bool> {
    let Some(session) = slots[index].as_mut() else {
        return Ok(false);
    };
    let prior = session.deadline;
    if session.housekeeping()? {
        slots[index] = None;
        registry.retire(index);
        return Ok(false);
    }
    if prior.is_none()
        && let Some(deadline) = session.deadline
    {
        timers.push(Reverse((deadline, index)));
    }
    registry.sync(index, session)?;
    Ok(true)
}
fn retire_failed(index: usize, slots: &mut [Option<Session>], registry: &mut Registry) {
    slots[index] = None;
    registry.retire(index);
}

#[allow(clippy::too_many_lines)]
pub(super) fn run(
    sessions: Vec<Session>,
    signals: &SignalFd,
    mut accounting: Option<std::fs::File>,
) -> io::Result<()> {
    let mut registry = Registry::new(sessions.len(), signals)?;
    let mut slots: Vec<_> = sessions.into_iter().map(Some).collect();
    let mut timers: BinaryHeap<Reverse<(Instant, usize)>> = BinaryHeap::new();
    for (index, session) in slots.iter().enumerate() {
        if let Some(session) = session {
            registry.sync(index, session)?;
        }
    }
    let mut live = slots.len();
    let mut failed = false;
    let mut bulk = VecDeque::new();
    let mut marks = ReadyMarks::new(slots.len());
    // All ordinary PTYs/listeners fit this batch at the requested 1000-session
    // scale; control readiness is not hidden behind many small bulk-only waits.
    let mut events = vec![EpollEvent::empty(); 2048];
    // These are host-wide high-water buffers, not per-session idle storage.
    // Retain their bounded capacity across turns instead of fragmenting the
    // allocator with a fresh readiness table and two work lists per syscall.
    let mut work: HashMap<usize, Ready> = HashMap::new();
    let mut controls = Vec::new();
    let mut small_reads = Vec::new();
    while live > 0 {
        work.clear();
        controls.clear();
        small_reads.clear();
        marks.next_round();
        while timers
            .peek()
            .is_some_and(|Reverse((_, index))| slots[*index].is_none())
        {
            timers.pop();
        }
        let timeout = if bulk.is_empty() {
            timers
                .peek()
                .map_or(EpollTimeout::NONE, |Reverse((deadline, _))| {
                    EpollTimeout::try_from(
                        deadline.saturating_duration_since(Instant::now())
                            + Duration::from_millis(1),
                    )
                    .unwrap_or(EpollTimeout::MAX)
                })
        } else {
            EpollTimeout::ZERO
        };
        let count = match registry.epoll.wait(&mut events, timeout) {
            Ok(count) => count,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        };
        let mut child_exit = false;
        let mut signal_ready = false;
        for event in &events[..count] {
            if event.data() == SIGNAL {
                signal_ready = true;
                continue;
            }
            if let Some(entry) = registry.registration(event.data()) {
                work.entry(entry.session)
                    .or_default()
                    .insert(entry.key, event.events());
            }
        }
        if signal_ready {
            while let Some(information) = signals.read_signal().map_err(io::Error::from)? {
                let signal = i32::try_from(information.ssi_signo)
                    .ok()
                    .and_then(|value| Signal::try_from(value).ok());
                match signal {
                    Some(Signal::SIGCHLD) => child_exit = true,
                    Some(Signal::SIGUSR2) => record_ownership(&slots, &mut accounting),
                    _ => {}
                }
            }
        }
        if child_exit {
            // SIGCHLD coalesces, so this single event reconciles every owned
            // child. Ordinary output/input turns never poll live children.
            for (index, slot) in slots.iter_mut().enumerate() {
                if let Some(session) = slot {
                    if session.observe_exit().is_err() {
                        *slot = None;
                        registry.retire(index);
                        live -= 1;
                        failed = true;
                    } else {
                        work.entry(index).or_default();
                    }
                }
            }
        }
        while let Some(Reverse((deadline, index))) = timers.peek().copied() {
            if deadline > Instant::now() {
                break;
            }
            timers.pop();
            if slots[index].is_some() {
                work.entry(index).or_default();
            }
        }
        for (&index, ready) in &work {
            let Some(session) = slots[index].as_ref() else {
                continue;
            };
            let control = !ready
                .flags(session.listener.as_raw_fd(), &registry)
                .is_empty()
                || ready
                    .flags(session.pty.master.as_raw_fd(), &registry)
                    .contains(PollFlags::POLLOUT)
                || session
                    .peers
                    .iter()
                    .any(|p| !ready.flags(p.stream.as_raw_fd(), &registry).is_empty());
            if control || child_exit || session.exit.is_some() {
                controls.push((index, false));
            }
            if ready
                .flags(session.pty.master.as_raw_fd(), &registry)
                .intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
                || session.exit.is_some()
            {
                // Readiness alone cannot distinguish a shell's short reply
                // from a producer filling its PTY. Only connected consumers
                // can observe reply latency; detached output needs no ioctl
                // classification on every turn of the rotating bulk queue.
                if !session.peers.is_empty()
                    && crate::pty::available_output(&session.pty.master)
                        .is_ok_and(|bytes| bytes <= 1024)
                {
                    small_reads.push((index, INTERACTIVE_READ_BYTES));
                    marks.promote(index);
                } else if marks.queue(index) {
                    bulk.push_back(index);
                }
            }
        }
        // Give every ready shell its input before terminal output, repaint
        // generation or listener admission. Each child can run while the
        // remaining cohort is serviced, rather than behind another VT batch.
        for (index, incoming) in &mut controls {
            let index = *index;
            let result = catch_unwind(AssertUnwindSafe(|| -> io::Result<()> {
                let session = slots[index]
                    .as_mut()
                    .ok_or_else(|| io::Error::other("host session disappeared"))?;
                let ready = work
                    .get(&index)
                    .ok_or_else(|| io::Error::other("host readiness disappeared"))?;
                let flags: [PollFlags; MAX_PEERS] = std::array::from_fn(|i| {
                    session.peers.get(i).map_or_else(PollFlags::empty, |p| {
                        ready.flags(p.stream.as_raw_fd(), &registry)
                    })
                });
                let peers = &flags[..session.peers.len()];
                *incoming = peers.iter().any(|flags| flags.contains(PollFlags::POLLIN));
                session.step(
                    PollFlags::empty(),
                    ready.flags(session.pty.master.as_raw_fd(), &registry) & PollFlags::POLLOUT,
                    peers,
                    false,
                )?;
                // Closing a peer can free a descriptor number. Publish that
                // retirement before any later listener can reuse it; stale
                // readiness must never acquire authority over a new socket.
                registry.retire_closed(index, session);
                Ok(())
            }));
            if result.map_or(true, |result| result.is_err()) {
                failed = true;
                retire_failed(index, &mut slots, &mut registry);
                live -= 1;
            }
        }
        for (index, incoming) in controls.iter().copied() {
            if slots[index].is_none() {
                continue;
            }
            let result = catch_unwind(AssertUnwindSafe(|| -> io::Result<()> {
                // An expired retention deadline still fences listener
                // admission; ordinary live input needs no pre-work settle.
                if slots[index]
                    .as_ref()
                    .is_some_and(|session| session.deadline.is_some_and(|d| Instant::now() >= d))
                    && !settle(index, &mut slots, &mut registry, &mut timers)?
                {
                    return Ok(());
                }
                let session = slots[index]
                    .as_mut()
                    .ok_or_else(|| io::Error::other("host session disappeared"))?;
                let ready = work
                    .get(&index)
                    .ok_or_else(|| io::Error::other("host readiness disappeared"))?;
                session.step(
                    ready.flags(session.listener.as_raw_fd(), &registry),
                    PollFlags::empty(),
                    &[],
                    false,
                )?;
                if incoming {
                    marks.read_once(index);
                    session.step_budget(
                        PollFlags::empty(),
                        PollFlags::POLLIN,
                        &[],
                        INTERACTIVE_READ_BYTES,
                    )?;
                }
                settle(index, &mut slots, &mut registry, &mut timers)?;
                Ok(())
            }));
            if result.map_or(true, |result| result.is_err()) {
                failed = true;
                retire_failed(index, &mut slots, &mut registry);
            }
            if let Some(session) = &slots[index]
                && session.exit.is_some()
                && session.can_read()
                && marks.queue(index)
            {
                // Descendants can retain a slave after the owned shell exits.
                // Probe once without waiting for a readiness event from them.
                bulk.push_back(index);
            }
            if slots[index].is_none() {
                live -= 1;
            }
        }
        // Cancelled entries are discarded only when popped. Each session has
        // at most one deque entry; no turn scans the whole bulk backlog.
        let mut outputs = 0;
        while outputs < OUTPUTS_PER_ROUND {
            let Some(index) = bulk.pop_front() else { break };
            if marks.take_bulk(index) {
                small_reads.push((index, BULK_READ_BYTES));
                outputs += 1;
            }
        }
        for (index, read_budget) in small_reads.drain(..) {
            if !marks.read_once(index) {
                continue;
            }
            if slots[index].is_none() {
                continue;
            }
            let result = catch_unwind(AssertUnwindSafe(|| -> io::Result<()> {
                if !settle(index, &mut slots, &mut registry, &mut timers)? {
                    return Ok(());
                }
                let session = slots[index]
                    .as_mut()
                    .ok_or_else(|| io::Error::other("host session disappeared"))?;
                session.step_budget(PollFlags::empty(), PollFlags::POLLIN, &[], read_budget)?;
                settle(index, &mut slots, &mut registry, &mut timers)?;
                Ok(())
            }));
            if result.map_or(true, |result| result.is_err()) {
                failed = true;
                retire_failed(index, &mut slots, &mut registry);
            }
            if slots[index].is_none() {
                live -= 1;
            }
        }
    }
    if failed {
        Err(io::Error::other("one or more hosted sessions failed"))
    } else {
        Ok(())
    }
}

/// A profiling failure closes only the optional receipt, never live sessions.
/// Numeric ownership is sampled between native calls on the reactor thread.
fn record_ownership(slots: &[Option<Session>], accounting: &mut Option<std::fs::File>) {
    let result = accounting.as_mut().map(|file| -> io::Result<()> {
        let mut writer = io::BufWriter::new(file);
        for (index, session) in slots.iter().enumerate() {
            if let Some(session) = session {
                session.record_memory(index, &mut writer)?;
            }
        }
        writer.flush()
    });
    if let Some(Err(error)) = result {
        *accounting = None;
        eprintln!("shared-host accounting stopped: {error}");
    }
}

#[cfg(test)]
mod tests {
    //! Closed descriptor numbers never give stale readiness to a replacement peer.
    use super::*;
    #[test]
    fn input_phase_retires_closed_identity_without_publishing_transient_interest() {
        let state = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/i{}",
            std::process::id()
        ));
        let mut config = crate::Config::new([16; 16], nix::unistd::Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let mut session = Session::new(config, 65536).unwrap();
        let client = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
        session
            .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
            .unwrap();
        session.housekeeping().unwrap();
        let signals = SignalFd::with_flags(
            &nix::sys::signal::SigSet::empty(),
            nix::sys::signalfd::SfdFlags::SFD_CLOEXEC,
        )
        .unwrap();
        let mut registry = ownership_fixture(std::slice::from_ref(&session), &signals).unwrap();
        let fd = session.peers[0].stream.as_raw_fd();
        let key = registry.by_fd[&fd].key;
        session.peers[0].input_reply = Some(super::super::InputReply::State);
        let ((), delta) = crate::heap_accounting::measure(|| registry.retire_closed(0, &session));
        assert_eq!(delta.allocations, 0);
        assert_eq!(
            registry.registration(key).unwrap().flags,
            EpollFlags::EPOLLIN
        );
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
        registry.retire_closed(0, &session);
        assert!(registry.registration(key).is_none());
        assert!(!registry.owned[0].contains(&fd));
        drop(registry);
        drop(session);
        std::fs::remove_dir_all(state).unwrap();
    }
    #[test]
    fn inline_and_extra_descriptor_flags_merge_without_losing_generations() {
        let mut ready = Ready::default();
        ready.insert(7, EpollFlags::EPOLLIN);
        ready.insert(8, EpollFlags::EPOLLHUP);
        ready.insert(7, EpollFlags::EPOLLOUT);
        ready.insert(8, EpollFlags::EPOLLIN);
        assert_eq!(
            ready.get(7),
            Some(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT)
        );
        assert_eq!(
            ready.get(8),
            Some(EpollFlags::EPOLLHUP | EpollFlags::EPOLLIN)
        );
        assert_eq!(ready.get(9), None);
        assert_eq!(ready.more.len(), 1);
    }
    #[test]
    fn single_ready_descriptor_needs_no_heap_allocation() {
        let (_ready, delta) = crate::heap_accounting::measure(|| {
            let mut ready = Ready::default();
            ready.insert(7, EpollFlags::EPOLLIN);
            assert_eq!(ready.get(7), Some(EpollFlags::EPOLLIN));
            ready
        });
        assert_eq!(delta.allocations, 0);
    }
    #[test]
    fn unchanged_registration_sync_needs_no_heap_allocation() {
        let state = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/q{}",
            std::process::id()
        ));
        let mut config = crate::Config::new([12; 16], nix::unistd::Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let session = Session::new(config, 65536).unwrap();
        let signals = SignalFd::with_flags(
            &nix::sys::signal::SigSet::empty(),
            nix::sys::signalfd::SfdFlags::SFD_CLOEXEC,
        )
        .unwrap();
        let mut registry = ownership_fixture(std::slice::from_ref(&session), &signals).unwrap();
        let ((), delta) = crate::heap_accounting::measure(|| registry.sync(0, &session).unwrap());
        assert_eq!(delta.allocations, 0);
        drop(registry);
        drop(session);
        std::fs::remove_dir_all(state).unwrap();
    }
    #[test]
    fn cancelled_bulk_membership_reuses_the_existing_deque_entry() {
        let mut marks = ReadyMarks::new(1000);
        assert!(marks.queue(999));
        marks.promote(999);
        assert!(
            !marks.queue(999),
            "revival must not create a second deque entry"
        );
        assert!(marks.take_bulk(999));
        assert!(!marks.take_bulk(999));
        marks.promote(999);
        assert!(marks.queue(999));
        marks.promote(999);
        assert!(!marks.take_bulk(999));
        assert!(marks.queue(999));
    }
    #[test]
    fn round_reset_and_wrap_preserve_bulk_membership_without_reviving_reads() {
        let mut marks = ReadyMarks::new(1000);
        assert!(marks.queue(999));
        assert!(!marks.queue(999));
        assert!(marks.read_once(0));
        assert!(!marks.read_once(0));
        marks.next_round();
        assert_eq!(marks.queued[999], 1);
        assert!(marks.read_once(0));
        marks.round = u32::MAX;
        marks.read[999] = u32::MAX;
        marks.read[0] = 1;
        marks.next_round();
        assert!(marks.read_once(0));
        assert!(marks.read_once(999));
        assert!(!marks.read_once(999));
        assert_eq!(marks.queued[999], 1);
        assert!(marks.take_bulk(999));
        assert!(!marks.take_bulk(999));
    }
    #[test]
    fn readiness_membership_stays_within_five_bytes_per_session() {
        let (_marks, allocation) = crate::heap_accounting::measure(|| {
            let mut marks = ReadyMarks::new(1000);
            marks.next_round();
            for index in 0..1000 {
                assert!(marks.queue(index));
                assert!(marks.read_once(index));
            }
            marks
        });
        assert!(
            allocation.bytes <= 5000,
            "ready membership owns {} requested bytes",
            allocation.bytes
        );
    }
    #[test]
    fn replay_continues_after_its_frame_was_written_inline() {
        let state = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/c{}",
            std::process::id()
        ));
        let mut config = crate::Config::new([9; 16], nix::unistd::Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let mut session = Session::new(config, 65536).unwrap();
        let mut client = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
        session
            .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
            .unwrap();
        session.housekeeping().unwrap();
        session.ring.append(&vec![b'r'; 65536]).unwrap();
        for frame in [
            crate::frame::Frame::Attach(0),
            crate::frame::Frame::ReadFrom(0),
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
        assert_eq!(session.peers[0].pending, [] as [u8; 0]);
        assert!(session.peers[0].cursor.unwrap() < session.ring.head());
        let signals = SignalFd::with_flags(
            &nix::sys::signal::SigSet::empty(),
            nix::sys::signalfd::SfdFlags::SFD_CLOEXEC,
        )
        .unwrap();
        let registry = ownership_fixture(std::slice::from_ref(&session), &signals).unwrap();
        let registration = &registry.by_fd[&session.peers[0].stream.as_raw_fd()];
        assert!(
            registration.flags.contains(EpollFlags::EPOLLOUT),
            "unwritten replay lost its continuation"
        );
        drop(registry);
        drop(session);
        std::fs::remove_dir_all(state).unwrap();
    }
    #[test]
    fn one_session_readiness_fits_240_requested_bytes() {
        let state = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/reg{}",
            std::process::id()
        ));
        let mut config = crate::Config::new([6; 16], nix::unistd::Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let session = Session::new(config, 65536).unwrap();
        let signals = SignalFd::with_flags(
            &nix::sys::signal::SigSet::empty(),
            nix::sys::signalfd::SfdFlags::SFD_CLOEXEC,
        )
        .unwrap();
        let (registry, allocation) = crate::heap_accounting::measure(|| {
            ownership_fixture(std::slice::from_ref(&session), &signals).unwrap()
        });
        assert!(
            allocation.bytes <= 240,
            "readiness owns {} requested bytes",
            allocation.bytes
        );
        drop(registry);
        drop(session);
        std::fs::remove_dir_all(state).unwrap();
    }
    #[test]
    fn accounting_write_failure_disables_only_the_receipt() {
        let state = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/a{}",
            std::process::id()
        ));
        let mut config = crate::Config::new([5; 16], nix::unistd::Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let mut slots = [Some(Session::new(config, 65536).unwrap())];
        let mut accounting = Some(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        );
        record_ownership(&slots, &mut accounting);
        assert!(accounting.is_none());
        assert!(
            slots[0]
                .as_mut()
                .unwrap()
                .pty
                .child
                .try_wait()
                .unwrap()
                .is_none()
        );
        record_ownership(&slots, &mut accounting);
        drop(slots);
        std::fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn reused_peer_descriptor_receives_a_new_readiness_identity() {
        const CASE: &str = "session::user_host::reactor::tests::reused_peer_descriptor_receives_a_new_readiness_identity";
        const FLAG: &str = "INFRATERNAL_EPOLL_IDENTITY_FIXTURE";
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
        let state = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/process-per-user/ep{}",
            std::process::id()
        ));
        let mut config = crate::Config::new([3; 16], nix::unistd::Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let mut session = Session::new(config, 65536).unwrap();
        let signals = SignalFd::with_flags(
            &nix::sys::signal::SigSet::empty(),
            nix::sys::signalfd::SfdFlags::SFD_CLOEXEC,
        )
        .unwrap();
        let mut registry = Registry::new(1, &signals).unwrap();
        registry.sync(0, &session).unwrap();
        let peer = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
        session
            .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
            .unwrap();
        registry.sync(0, &session).unwrap();
        let fd = session.peers[0].stream.as_raw_fd();
        let key = registry.by_fd[&fd].key;
        session.peers.clear();
        registry.sync(0, &session).unwrap();
        assert!(registry.registration(key).is_none());
        drop(peer);
        let peer = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
        session
            .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
            .unwrap();
        registry.sync(0, &session).unwrap();
        assert_eq!(session.peers[0].stream.as_raw_fd(), fd);
        let replacement = registry.by_fd[&fd].key;
        assert_ne!(key, replacement);
        let obsolete = Ready {
            first: Some((key, EpollFlags::EPOLLIN)),
            more: Vec::new(),
        };
        assert_eq!(obsolete.flags(fd, &registry), PollFlags::empty());
        let current = Ready {
            first: Some((replacement, EpollFlags::EPOLLIN)),
            more: Vec::new(),
        };
        assert_eq!(current.flags(fd, &registry), PollFlags::POLLIN);
        drop(peer);
        drop(session);
        std::fs::remove_dir_all(state).unwrap();
    }
}
