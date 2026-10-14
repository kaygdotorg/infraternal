//! Index ready sessions without idle scans; only child-exit readiness reconciles all owned children [D81/D268].
use super::{OUTPUTS_PER_ROUND, Session};
use nix::{
    poll::PollFlags,
    sys::{
        epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout},
        signalfd::SignalFd,
    },
};
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    io,
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
struct Registry {
    epoll: Epoll,
    by_fd: HashMap<RawFd, Registration>,
    by_key: HashMap<u64, Registration>,
    owned: Vec<Vec<RawFd>>,
    next_key: u64,
}
impl Registry {
    fn new(count: usize, signals: &SignalFd) -> io::Result<Self> {
        let epoll = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)?;
        epoll.add(signals, EpollEvent::new(EpollFlags::EPOLLIN, SIGNAL))?;
        Ok(Self {
            epoll,
            by_fd: HashMap::new(),
            by_key: HashMap::new(),
            owned: vec![Vec::new(); count],
            next_key: 0,
        })
    }
    fn retire(&mut self, index: usize) {
        for fd in self.owned[index].drain(..) {
            if let Some(old) = self.by_fd.remove(&fd) {
                self.by_key.remove(&old.key);
            }
        }
        // Owned session descriptors have closed; the kernel removes them.
    }
    fn sync(&mut self, index: usize, session: &Session) -> io::Result<()> {
        let mut descriptors: Vec<(BorrowedFd<'_>, EpollFlags)> =
            Vec::with_capacity(session.peers.len() + 2);
        descriptors.push((session.listener.as_fd(), EpollFlags::EPOLLIN));
        let mut master = EpollFlags::empty();
        if session.can_read() {
            master |= EpollFlags::EPOLLIN;
        }
        if !session.input.is_empty() {
            master |= EpollFlags::EPOLLOUT;
        }
        if !master.is_empty() {
            descriptors.push((session.pty.master.as_fd(), master));
        }
        for peer in &session.peers {
            let mut flags = EpollFlags::empty();
            if peer.deferred.is_none() && peer.trailing.is_empty() {
                flags |= EpollFlags::EPOLLIN;
            }
            if !peer.pending.is_empty() {
                flags |= EpollFlags::EPOLLOUT;
            }
            descriptors.push((peer.stream.as_fd(), flags));
        }
        self.owned[index].retain(|fd| {
            if descriptors
                .iter()
                .any(|(current, _)| current.as_raw_fd() == *fd)
            {
                return true;
            }
            if let Some(old) = self.by_fd.remove(fd) {
                self.by_key.remove(&old.key);
                if *fd == session.pty.master.as_raw_fd() {
                    // A disabled but live master must be removed explicitly;
                    // level-triggered HUP on a drained master otherwise spins.
                    let _ = self.epoll.delete(&session.pty.master);
                }
            }
            false
        });
        for (fd, flags) in descriptors {
            if let Some(old) = self.by_fd.get_mut(&fd.as_raw_fd()) {
                if old.flags != flags {
                    self.epoll
                        .modify(fd, &mut EpollEvent::new(flags, old.key))?;
                    old.flags = flags;
                    self.by_key.insert(old.key, *old);
                }
            } else {
                self.next_key = self
                    .next_key
                    .checked_add(1)
                    .filter(|key| *key != SIGNAL)
                    .ok_or_else(|| io::Error::other("host readiness identity exhausted"))?;
                let entry = Registration {
                    fd: fd.as_raw_fd(),
                    flags,
                    key: self.next_key,
                    session: index,
                };
                self.epoll.add(fd, EpollEvent::new(flags, entry.key))?;
                self.by_fd.insert(entry.fd, entry);
                self.by_key.insert(entry.key, entry);
                self.owned[index].push(entry.fd);
            }
        }
        Ok(())
    }
}
#[derive(Default)]
struct Ready {
    flags: HashMap<u64, EpollFlags>,
}
impl Ready {
    fn flags(&self, fd: RawFd, registry: &Registry) -> PollFlags {
        let flags = registry
            .by_fd
            .get(&fd)
            .and_then(|entry| self.flags.get(&entry.key))
            .copied()
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
pub(super) fn run(sessions: Vec<Session>, signals: &SignalFd) -> io::Result<()> {
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
    let mut queued = HashSet::new();
    let mut read_attempted = HashSet::new();
    // All ordinary PTYs/listeners fit this batch at the requested 1000-session
    // scale; control readiness is not hidden behind many small bulk-only waits.
    let mut events = vec![EpollEvent::empty(); 2048];
    while live > 0 {
        read_attempted.clear();
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
        let mut work: HashMap<usize, Ready> = HashMap::new();
        let mut child_exit = false;
        for event in &events[..count] {
            if event.data() == SIGNAL {
                child_exit = true;
                continue;
            }
            if let Some(entry) = registry.by_key.get(&event.data()) {
                work.entry(entry.session)
                    .or_default()
                    .flags
                    .insert(entry.key, event.events());
            }
        }
        if child_exit {
            while signals.read_signal().map_err(io::Error::from)?.is_some() {}
            // SIGCHLD coalesces, so this single event reconciles every child.
            // No other event scans idle sessions or calls waitpid on them.
            for (index, slot) in slots.iter().enumerate() {
                if slot.is_some() {
                    work.entry(index).or_default();
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
        let mut controls = Vec::new();
        let mut small_reads = Vec::new();
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
                controls.push(index);
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
                    small_reads.push(index);
                    queued.remove(&index);
                } else if queued.insert(index) {
                    bulk.push_back(index);
                }
            }
        }
        // Service all input/control before the rotating bounded bulk quantum.
        for index in controls {
            let result = catch_unwind(AssertUnwindSafe(|| -> io::Result<()> {
                if !settle(index, &mut slots, &mut registry, &mut timers)? {
                    return Ok(());
                }
                let session = slots[index]
                    .as_mut()
                    .ok_or_else(|| io::Error::other("host session disappeared"))?;
                let ready = work
                    .get(&index)
                    .ok_or_else(|| io::Error::other("host readiness disappeared"))?;
                let peers: Vec<_> = session
                    .peers
                    .iter()
                    .map(|p| ready.flags(p.stream.as_raw_fd(), &registry))
                    .collect();
                let incoming = peers.iter().any(|flags| flags.contains(PollFlags::POLLIN));
                session.step(
                    ready.flags(session.listener.as_raw_fd(), &registry),
                    ready.flags(session.pty.master.as_raw_fd(), &registry) & PollFlags::POLLOUT,
                    &peers,
                    false,
                )?;
                registry.sync(index, session)?;
                if incoming {
                    read_attempted.insert(index);
                    session.step(PollFlags::empty(), PollFlags::POLLIN, &[], true)?;
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
                && queued.insert(index)
            {
                // Descendants can retain a slave after the owned shell exits.
                // Probe once without waiting for a readiness event from them.
                bulk.push_back(index);
            }
            if slots[index].is_none() {
                live -= 1;
            }
        }
        // A promoted session may already have an older bulk entry. Remove it
        // before selecting the quantum so it cannot spend two read budgets.
        bulk.retain(|index| queued.contains(index));
        for _ in 0..OUTPUTS_PER_ROUND {
            let Some(index) = bulk.pop_front() else { break };
            queued.remove(&index);
            small_reads.push(index);
        }
        for index in small_reads {
            if !read_attempted.insert(index) {
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
                session.step(PollFlags::empty(), PollFlags::POLLIN, &[], true)?;
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

#[cfg(test)]
mod tests {
    //! Closed descriptor numbers never give stale readiness to a replacement peer.
    use super::*;
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
        assert!(!registry.by_key.contains_key(&key));
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
            flags: HashMap::from([(key, EpollFlags::EPOLLIN)]),
        };
        assert_eq!(obsolete.flags(fd, &registry), PollFlags::empty());
        let current = Ready {
            flags: HashMap::from([(replacement, EpollFlags::EPOLLIN)]),
        };
        assert_eq!(current.flags(fd, &registry), PollFlags::POLLIN);
        drop(peer);
        drop(session);
        std::fs::remove_dir_all(state).unwrap();
    }
}
