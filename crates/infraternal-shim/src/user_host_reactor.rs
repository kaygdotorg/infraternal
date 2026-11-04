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

// Short output is latency-sensitive too, but an entire ready cohort must not
// postpone the next input poll. Bulk retains its independent rotating turn.
/// Most short-output PTY reads one scheduling round grants, so a large ready
/// group cannot postpone the next input poll. Bulk reads keep their own
/// rotating turn.
const INTERACTIVE_READS_PER_ROUND: usize = 64;
/// Time budget for short-output reads in one round (500 microseconds), counted
/// from the end of input dispatch.
const INTERACTIVE_OUTPUT_TIME: Duration = Duration::from_micros(500);
/// Epoll key reserved for the signal descriptor. It is never a descriptor
/// registration key.
const SIGNAL: u64 = u64::MAX;
/// What the reactor remembers about one registered descriptor: the epoll
/// interest `flags`, its `key` (a generation in the high 32 bits and the
/// descriptor number in the low 32), and the `session` slot that owns it.
#[derive(Clone, Copy)]
struct Registration {
    flags: EpollFlags,
    key: u64,
    session: u16,
}
/// The epoll set for every hosted session, with the bookkeeping that maps
/// ready events back to the session slot that owns the descriptor.
///
/// `next_key` only counts up and is refused before it wraps, so after a
/// descriptor is closed and its number reused, an old event for the previous
/// owner can never be mistaken for the new one.
pub(super) struct Registry {
    epoll: Epoll,
    by_fd: HashMap<RawFd, Registration>,
    owned: Vec<Vec<RawFd>>,
    next_key: u32,
}

/// Test helper: a registry with every session's descriptors registered.
#[cfg(test)]
pub(super) fn ownership_fixture(sessions: &[Session], signals: &SignalFd) -> io::Result<Registry> {
    let mut registry = Registry::new(sessions.len(), signals)?;
    for (index, session) in sessions.iter().enumerate() {
        registry.sync(index, session, false)?;
    }
    Ok(registry)
}
impl Registry {
    /// Creates an epoll set for `count` session slots with `signals` registered.
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
    /// Forgets all descriptors of slot `index`. They are already closed, so the
    /// kernel has removed them from epoll.
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
    /// Looks up the registration for an event key. `None` if the descriptor has
    /// since been closed or reused (the generation no longer matches).
    fn registration(&self, key: u64) -> Option<&Registration> {
        let fd = RawFd::try_from(key & u64::from(u32::MAX)).ok()?;
        self.by_fd.get(&fd).filter(|entry| entry.key == key)
    }
    /// Brings epoll up to date with the session at slot `index`: the listener
    /// (readable), the PTY master (readable while output can be read, writable while
    /// input is queued) and each viewer (readable unless it is waiting, writable when
    /// there is something to send). `hold_ack` keeps a pure logical acknowledgment
    /// from counting as writable. Descriptors that went away are dropped, and
    /// interest is only changed when it differs from what is registered. Fails if
    /// the identity counter or slot number is exhausted, or on an epoll error.
    fn sync(&mut self, index: usize, session: &Session, hold_ack: bool) -> io::Result<()> {
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
            let writable = if hold_ack {
                session.can_write_with_ack_held(peer)
            } else {
                session.can_write(peer)
            };
            if writable {
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
                    flags,
                    key,
                    // Admission caps slots below this bound; refuse rather
                    // than truncate if a caller ever exceeds it.
                    session: u16::try_from(index).map_err(io::Error::other)?,
                };
                self.epoll.add(fd, EpollEvent::new(flags, entry.key))?;
                self.by_fd.insert(fd.as_raw_fd(), entry);
                self.owned[index].push(fd.as_raw_fd());
            }
        }
        Ok(())
    }
}
/// Ordinary readiness holds a PTY and one viewer inline. Extra viewers spill
/// only their descriptor flags; generations still identify each exact open fd.
struct Ready {
    keys: [u64; 2],
    flags: [EpollFlags; 2],
    generation: u32,
    more: Vec<(u64, EpollFlags)>,
}
impl Default for Ready {
    fn default() -> Self {
        Self {
            keys: [0; 2],
            flags: [EpollFlags::empty(); 2],
            generation: 0,
            more: Vec::new(),
        }
    }
}
impl Ready {
    /// Records `flags` for `key`, merging with earlier flags for the same key.
    fn insert(&mut self, key: u64, flags: EpollFlags) {
        // Registration generations start at one, so zero is never an fd key.
        debug_assert_ne!(key, 0);
        for index in 0..self.keys.len() {
            if self.keys[index] == key || self.keys[index] == 0 {
                self.keys[index] = key;
                self.flags[index] |= flags;
                return;
            }
        }
        if let Some((_, current)) = self.more.iter_mut().find(|(old, _)| *old == key) {
            *current |= flags;
        } else {
            self.more.push((key, flags));
        }
    }
    /// The flags recorded for `key` this turn, if any.
    fn get(&self, key: u64) -> Option<EpollFlags> {
        self.keys
            .iter()
            .position(|old| *old == key && key != 0)
            .map(|index| self.flags[index])
            .or_else(|| {
                self.more
                    .iter()
                    .find(|(old, _)| *old == key)
                    .map(|(_, flags)| *flags)
            })
    }
    /// The flags for descriptor `fd` this turn, translated to poll flags for the
    /// session's step functions. Empty if the descriptor is no longer registered.
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

/// Immutable session slots address ready rows directly. Only rows touched in
/// this turn are reset; idle sessions cause no scans or per-turn allocations.
struct ReadyWork {
    rows: Vec<Ready>,
    active: Vec<usize>,
    round: u32,
}
impl ReadyWork {
    /// Creates rows for `count` session slots.
    fn new(count: usize) -> Self {
        Self {
            rows: (0..count).map(|_| Ready::default()).collect(),
            active: Vec::with_capacity(count),
            round: 0,
        }
    }
    /// Starts a new turn, discarding the previous turn's rows lazily. When the
    /// round counter would wrap, every row is cleared first so old rows can never
    /// look current.
    fn next_round(&mut self) {
        self.active.clear();
        if let Some(round) = self.round.checked_add(1) {
            self.round = round;
        } else {
            // Clear before reuse so an old row cannot become current again.
            for ready in &mut self.rows {
                ready.generation = 0;
            }
            self.round = 1;
        }
    }
    /// The row for slot `index` in this turn, creating it empty on first touch.
    fn entry(&mut self, index: usize) -> &mut Ready {
        let ready = &mut self.rows[index];
        if ready.generation != self.round {
            ready.keys.fill(0);
            ready.flags.fill(EpollFlags::empty());
            ready.more.clear();
            ready.generation = self.round;
            self.active.push(index);
        }
        ready
    }
    /// The row for slot `index` if it was touched this turn.
    fn get(&self, index: usize) -> Option<&Ready> {
        let ready = self.rows.get(index)?;
        (ready.generation == self.round && self.round != 0).then_some(ready)
    }
}

/// Membership follows immutable session slots, not descriptor numbers. Read
/// generations avoid clearing all idle slots on each busy reactor turn.
struct ReadyMarks {
    queued: Vec<u8>,
    read: Vec<u32>,
    round: u32,
    interactive_reads: usize,
    output_deadline: Option<Instant>,
}
impl ReadyMarks {
    /// Bits of a slot's mark for its bulk-read queue entry: 0 none, 1 queued,
    /// 2 cancelled (revived in place instead of queued twice).
    const BULK_MASK: u8 = 3;
    /// Mark bit: the slot has a deadline entry in the timer heap.
    const TIMER: u8 = 4;
    /// Mark bit: the slot has a pending acknowledgment fallback.
    const ACK: u8 = 8;

    /// Creates empty marks for `count` session slots.
    fn new(count: usize) -> Self {
        Self {
            queued: vec![0; count],
            read: vec![0; count],
            round: 1,
            interactive_reads: 0,
            output_deadline: None,
        }
    }
    /// Starts a new turn: resets the short-read count and the output deadline. When
    /// the round counter would wrap, the read marks are cleared first so an old mark
    /// can never skip a newly ready session.
    fn next_round(&mut self) {
        self.interactive_reads = 0;
        self.output_deadline = None;
        if let Some(round) = self.round.checked_add(1) {
            self.round = round;
        } else {
            // Clear before reusing a generation: old marks can never skip
            // a newly ready session, even after billions of busy turns.
            self.read.fill(0);
            self.round = 1;
        }
    }
    /// Marks slot `index` for a bulk read. Returns true if the caller must push a
    /// queue entry, false if one already exists (a cancelled one is revived).
    fn queue(&mut self, index: usize) -> bool {
        // Low bits: 0 has no deque entry, 1 is bulk, 2 is cancelled.
        // The timer bit survives every bulk transition. A cancelled entry
        // revives in place rather than inserting a duplicate deque entry.
        let state = &mut self.queued[index];
        let prior = *state & Self::BULK_MASK;
        *state = (*state & !Self::BULK_MASK) | 1;
        prior == 0
    }
    /// Cancels the slot's bulk queue entry, because a short read was granted
    /// instead. The entry stays in the queue and is skipped when reached.
    fn promote(&mut self, index: usize) {
        let state = &mut self.queued[index];
        if *state & Self::BULK_MASK != 0 {
            *state = (*state & !Self::BULK_MASK) | 2;
        }
    }
    /// Consumes the slot's bulk entry. True only if it was live, not cancelled.
    fn take_bulk(&mut self, index: usize) -> bool {
        let state = &mut self.queued[index];
        let prior = *state & Self::BULK_MASK;
        *state &= !Self::BULK_MASK;
        prior == 1
    }
    /// Marks the slot as having a timer entry. True if the caller must push one.
    fn queue_timer(&mut self, index: usize) -> bool {
        let state = &mut self.queued[index];
        let prior = *state & Self::TIMER;
        *state |= Self::TIMER;
        prior == 0
    }
    /// Clears the slot's timer mark after its heap entry was removed.
    fn retire_timer(&mut self, index: usize) {
        self.queued[index] &= !Self::TIMER;
    }
    /// Marks a pending acknowledgment fallback. True if the caller must queue it.
    fn queue_ack(&mut self, index: usize) -> bool {
        let state = &mut self.queued[index];
        let prior = *state & Self::ACK;
        *state |= Self::ACK;
        prior == 0
    }
    /// Consumes the pending acknowledgment mark. True if there was one.
    fn take_ack(&mut self, index: usize) -> bool {
        let state = &mut self.queued[index];
        let prior = *state & Self::ACK;
        *state &= !Self::ACK;
        prior != 0
    }
    /// Starts the round's output time budget at `now`. Called after input dispatch
    /// and never before a blocking wait, so waiting does not use up the budget.
    fn start_output_round(&mut self, now: Instant) {
        // Start after input dispatch, never before a blocking poll. Cheap
        // replies share a turn; costly output yields without an idle timer.
        self.output_deadline = Some(now + INTERACTIVE_OUTPUT_TIME);
        // A host-wide marker, never a peer identity. Sampling Instant precedes
        // this receipt, so the reason bits below are authoritative for expiry.
        trace_host!(
            OutputRoundStart,
            [0; 16],
            -1,
            u64::from(self.round),
            usize::try_from(INTERACTIVE_OUTPUT_TIME.as_micros()).unwrap_or(usize::MAX),
            INTERACTIVE_READS_PER_ROUND
        );
    }
    /// Grants a short read for slot `index` if the round still has budget; see
    /// `read_interactive_at`.
    fn read_interactive(&mut self, index: usize) -> bool {
        self.read_interactive_at(index, Instant::now())
    }
    /// Grants the slot one short PTY read at time `now`, or refuses. Refused when
    /// the round has used all its reads, the deadline has passed, or this slot
    /// already read this round. A grant cancels the slot's bulk entry; a refusal
    /// leaves it, so bulk progress continues to rotate.
    fn read_interactive_at(&mut self, index: usize, now: Instant) -> bool {
        if self.interactive_reads == INTERACTIVE_READS_PER_ROUND
            || self.output_deadline.is_some_and(|deadline| now >= deadline)
            || !self.read_once(index)
        {
            // Preserve the non-diagnostic branch exactly. Report only count
            // or elapsed guards; a duplicate with allowance left is neither.
            #[cfg(feature = "host-diagnostics")]
            {
                let count = self.interactive_reads == INTERACTIVE_READS_PER_ROUND;
                let elapsed = self.output_deadline.is_some_and(|deadline| now >= deadline);
                if count || elapsed {
                    trace_host!(
                        ReadBudgetDenied,
                        [0; 16],
                        -1,
                        u64::try_from(index).unwrap_or(u64::MAX),
                        self.interactive_reads,
                        usize::from(count) | (usize::from(elapsed) << 1)
                    );
                }
            }
            return false;
        }
        self.interactive_reads += 1;
        // Cancel an old bulk entry only after this turn actually grants the
        // promoted attempt. Denied promotions must keep rotating progress.
        self.promote(index);
        true
    }
    /// Marks the slot as having read this round. False if it already had.
    fn read_once(&mut self, index: usize) -> bool {
        if self.read[index] == self.round {
            return false;
        }
        self.read[index] = self.round;
        true
    }
}

/// Select bulk only after short attempts have granted/cancelled their entries.
/// Preselecting it would waste the bulk turn on an already promoted session.
fn next_output(
    short: &mut impl Iterator<Item = (usize, usize)>,
    bulk: &mut VecDeque<usize>,
    marks: &mut ReadyMarks,
    outputs: &mut usize,
) -> Option<(usize, usize)> {
    if let Some(ready) = short.next() {
        return Some(ready);
    }
    while *outputs < OUTPUTS_PER_ROUND {
        let index = bulk.pop_front()?;
        if marks.take_bulk(index) {
            *outputs += 1;
            return Some((index, BULK_READ_BYTES));
        }
    }
    None
}

/// Fresh Acks get one local next-turn fallback; a due fallback is immediate
/// even if more input arrived. `QueuedRead` relies on a bounded PTY attempt.
#[derive(Clone, Copy)]
enum AckMode {
    Immediate,
    Fresh,
    QueuedRead,
}
impl AckMode {
    /// Chooses how to handle an acknowledgment: `QueuedRead` when a PTY read is
    /// pending, `Fresh` for a new incoming acknowledgment with nothing writable,
    /// otherwise `Immediate`.
    fn for_control(incoming: bool, writable: bool, read_pending: bool) -> Self {
        if read_pending {
            Self::QueuedRead
        } else if incoming && !writable {
            Self::Fresh
        } else {
            Self::Immediate
        }
    }
}

/// A fresh logical Ack receives one local next-turn fallback, rather than
/// toggling kernel writable interest twice. Existing slot bits deduplicate it.
fn queue_fresh_ack(
    index: usize,
    session: &Session,
    mode: AckMode,
    marks: &mut ReadyMarks,
    fallback: &mut VecDeque<usize>,
) {
    if matches!(mode, AckMode::Fresh)
        && session.peers.iter().any(|peer| {
            super::may_coalesce_data_ack(
                peer,
                session.ring.head(),
                !session.drained && session.exit.is_none(),
            )
        })
        && marks.queue_ack(index)
    {
        fallback.push_back(index);
    }
}

/// Settle queues and lifetimes only for a ready session. Registration happens
/// both before and after acceptance so a closed/reused fd cannot inherit a key.
fn settle(
    index: usize,
    slots: &mut [Option<Session>],
    registry: &mut Registry,
    timers: &mut BinaryHeap<Reverse<(Instant, usize)>>,
    marks: &mut ReadyMarks,
) -> io::Result<bool> {
    settle_with_ack_mode(index, slots, registry, timers, marks, AckMode::Immediate)
}
/// Brings a ready session to rest after a step: runs its housekeeping (with
/// acknowledgments held back unless `ack_mode` is `Immediate`), removes it if it
/// finished, schedules its retention deadline once and re-syncs its epoll
/// interest. Returns false if the slot is empty or was just finished.
fn settle_with_ack_mode(
    index: usize,
    slots: &mut [Option<Session>],
    registry: &mut Registry,
    timers: &mut BinaryHeap<Reverse<(Instant, usize)>>,
    marks: &mut ReadyMarks,
    ack_mode: AckMode,
) -> io::Result<bool> {
    let Some(session) = slots[index].as_mut() else {
        return Ok(false);
    };
    let finished = if matches!(ack_mode, AckMode::Immediate) {
        session.housekeeping()?
    } else {
        session.housekeeping_coalesced(true)?
    };
    if finished {
        slots[index] = None;
        registry.retire(index);
        return Ok(false);
    }
    // Exit readiness can establish this before housekeeping. Membership,
    // not the timing of that assignment, authorizes exactly one heap entry.
    if let Some(deadline) = session.deadline
        && marks.queue_timer(index)
    {
        timers.push(Reverse((deadline, index)));
    }
    registry.sync(index, session, !matches!(ack_mode, AckMode::Immediate))?;
    Ok(true)
}
/// Drops the session in slot `index` and its registrations. Used when a step
/// fails or panics, so one hosted session cannot take the others down.
fn retire_failed(index: usize, slots: &mut [Option<Session>], registry: &mut Registry) {
    slots[index] = None;
    registry.retire(index);
}

/// The shared host's event loop. Serves all `sessions` on the current thread
/// until every one has ended, then returns.
///
/// Each turn waits in epoll (without a timeout when idle work exists, otherwise
/// until the next retention deadline), gathers readiness, reads signals
/// (child exit, and the diagnostic dump signals when built for diagnostics),
/// dispatches input, then spends a bounded output budget so input is never
/// starved by output. A session that fails or panics is retired alone; the
/// function then returns an error once the others finish. `accounting` is an
/// optional diagnostics file that is closed on its first write error.
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
            registry.sync(index, session, false)?;
        }
    }
    let mut live = slots.len();
    let mut failed = false;
    let mut bulk = VecDeque::new();
    let mut ack_fallback = VecDeque::new();
    let mut marks = ReadyMarks::new(slots.len());
    // All ordinary PTYs/listeners fit this batch at the requested 1000-session
    // scale; control readiness is not hidden behind many small bulk-only waits.
    let mut events = vec![EpollEvent::empty(); 2048];
    let mut work = ReadyWork::new(slots.len());
    // Retain bounded work lists instead of reallocating on every syscall.
    let mut controls = Vec::new();
    let mut small_reads = Vec::new();
    while live > 0 {
        work.next_round();
        controls.clear();
        small_reads.clear();
        marks.next_round();
        while timers
            .peek()
            .is_some_and(|Reverse((_, index))| slots[*index].is_none())
        {
            if let Some(Reverse((_, index))) = timers.pop() {
                marks.retire_timer(index);
            }
        }
        let timeout = if bulk.is_empty() && ack_fallback.is_empty() {
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
        // The prior turn's fallback can never hide ready input: first collect
        // all kernel readiness, then dispatch input for the combined work list.
        for index in ack_fallback.drain(..) {
            work.entry(index);
        }
        let mut child_exit = false;
        let mut signal_ready = false;
        for event in &events[..count] {
            if event.data() == SIGNAL {
                signal_ready = true;
                continue;
            }
            if let Some(entry) = registry.registration(event.data()) {
                work.entry(usize::from(entry.session))
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
                    #[cfg(feature = "host-diagnostics")]
                    Some(Signal::SIGUSR1) => {
                        let result = accounting.as_mut().map(crate::host_trace::flush);
                        if result.is_some_and(|result| result.is_err()) {
                            let _ = crate::host_trace::enable(false);
                            accounting = None;
                        }
                    }
                    Some(Signal::SIGUSR2) => {
                        // Publish requested vector capacities, not a second PSS
                        // estimate. Hash capacity is usable entries; its private
                        // bucket/control allocation is measured independently.
                        record_ownership(
                            &slots,
                            &mut accounting,
                            Some(format_args!(
                                "{{\"slots_capacity\":{},\"slot_size\":{},\"registry_vectors_bytes\":{},\"registry_capacity\":{},\"registry_pair_size\":{},\"ready_rows_bytes\":{},\"ready_indices_bytes\":{},\"ready_spill_bytes\":{},\"membership_bytes\":{},\"event_bytes\":{},\"bulk_bytes\":{},\"control_bytes\":{},\"ack_fallback_bytes\":{},\"small_read_bytes\":{},\"deadline_bytes\":{}}}",
                                slots.capacity(),
                                std::mem::size_of::<Option<Session>>(),
                                registry.owned.capacity() * std::mem::size_of::<Vec<RawFd>>()
                                    + registry
                                        .owned
                                        .iter()
                                        .map(|fds| fds.capacity() * std::mem::size_of::<RawFd>())
                                        .sum::<usize>(),
                                registry.by_fd.capacity(),
                                std::mem::size_of::<(RawFd, Registration)>(),
                                work.rows.capacity() * std::mem::size_of::<Ready>(),
                                work.active.capacity() * std::mem::size_of::<usize>(),
                                work.rows
                                    .iter()
                                    .map(|ready| ready.more.capacity()
                                        * std::mem::size_of::<(u64, EpollFlags)>())
                                    .sum::<usize>(),
                                marks.queued.capacity()
                                    + marks.read.capacity() * std::mem::size_of::<u32>(),
                                events.capacity() * std::mem::size_of::<EpollEvent>(),
                                bulk.capacity() * std::mem::size_of::<usize>(),
                                controls.capacity() * std::mem::size_of::<(usize, bool, bool)>(),
                                ack_fallback.capacity() * std::mem::size_of::<usize>(),
                                small_reads.capacity() * std::mem::size_of::<(usize, usize)>(),
                                timers.capacity()
                                    * std::mem::size_of::<Reverse<(Instant, usize)>>(),
                            )),
                        );
                    }
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
                        work.entry(index);
                    }
                }
            }
        }
        while let Some(Reverse((deadline, index))) = timers.peek().copied() {
            if deadline > Instant::now() {
                break;
            }
            timers.pop();
            marks.retire_timer(index);
            if slots[index].is_some() {
                work.entry(index);
            }
        }
        for &index in &work.active {
            let ready = &work.rows[index];
            let fallback = marks.take_ack(index);
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
            if control || fallback || child_exit || session.exit.is_some() {
                controls.push((index, false, fallback));
            }
        }
        // Give every ready shell its input before terminal output, repaint
        // generation or listener admission. Each child can run while the
        // remaining cohort is serviced, rather than behind another VT batch.
        for (index, incoming, _) in &mut controls {
            let index = *index;
            let result = catch_unwind(AssertUnwindSafe(|| -> io::Result<()> {
                let session = slots[index]
                    .as_mut()
                    .ok_or_else(|| io::Error::other("host session disappeared"))?;
                let ready = work
                    .get(index)
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
        marks.start_output_round(Instant::now());
        // The readable-byte hints are output work too. Even a thousand
        // simultaneous PTYs must receive ready input before those ioctls.
        for &index in &work.active {
            let ready = &work.rows[index];
            let Some(session) = slots[index].as_ref() else {
                continue;
            };
            if ready
                .flags(session.pty.master.as_raw_fd(), &registry)
                .intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
                || session.exit.is_some()
            {
                // Readiness alone cannot distinguish a shell's short reply
                // from a producer filling its PTY. Only connected consumers
                // can observe reply latency; detached output needs no ioctl
                // classification on every turn of the rotating bulk queue.
                // Once this turn's promotion list is full, the rotating
                // queue preserves progress without another classification ioctl.
                if small_reads.len() < INTERACTIVE_READS_PER_ROUND
                    && !session.peers.is_empty()
                    && crate::pty::available_output(&session.pty.master)
                        .is_ok_and(|bytes| bytes <= 1024)
                {
                    small_reads.push((index, INTERACTIVE_READ_BYTES));
                } else if marks.queue(index) {
                    bulk.push_back(index);
                }
            }
        }
        for (index, incoming, fallback) in controls.iter().copied() {
            if slots[index].is_none() {
                continue;
            }
            let result = catch_unwind(AssertUnwindSafe(|| -> io::Result<()> {
                // An expired retention deadline still fences listener
                // admission; ordinary live input needs no pre-work settle.
                if slots[index]
                    .as_ref()
                    .is_some_and(|session| session.deadline.is_some_and(|d| Instant::now() >= d))
                    && !settle(index, &mut slots, &mut registry, &mut timers, &mut marks)?
                {
                    return Ok(());
                }
                let session = slots[index]
                    .as_mut()
                    .ok_or_else(|| io::Error::other("host session disappeared"))?;
                let ready = work
                    .get(index)
                    .ok_or_else(|| io::Error::other("host readiness disappeared"))?;
                session.step(
                    ready.flags(session.listener.as_raw_fd(), &registry),
                    PollFlags::empty(),
                    &[],
                    false,
                )?;
                let master = ready.flags(session.pty.master.as_raw_fd(), &registry);
                let readable = master.intersects(PollFlags::POLLIN | PollFlags::POLLHUP);
                // Preserve pending control/resize ordering before adding an
                // opportunistic read for an Ack-only writable visit.
                let ack_pending = session
                    .peers
                    .iter()
                    .all(|peer| peer.trailing.is_empty() && peer.deferred.is_none())
                    && session.peers.iter().any(|peer| {
                        matches!(peer.input_reply, Some(super::super::InputReply::Ack))
                    });
                if (incoming || (readable && ack_pending)) && marks.read_interactive(index) {
                    session.step_budget(
                        PollFlags::empty(),
                        PollFlags::POLLIN,
                        &[],
                        INTERACTIVE_READ_BYTES,
                    )?;
                }
                let writable = session.peers.iter().any(|peer| {
                    ready
                        .flags(peer.stream.as_raw_fd(), &registry)
                        .contains(PollFlags::POLLOUT)
                });
                let ack_mode = AckMode::for_control(
                    incoming && !fallback,
                    writable,
                    readable && marks.read[index] != marks.round,
                );
                settle_with_ack_mode(
                    index,
                    &mut slots,
                    &mut registry,
                    &mut timers,
                    &mut marks,
                    ack_mode,
                )?;
                if let Some(session) = slots[index].as_ref() {
                    queue_fresh_ack(index, session, ack_mode, &mut marks, &mut ack_fallback);
                }
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
        // Granted short attempts cancel their old entries before bulk is
        // selected. Each session retains at most one rotating continuation.
        let mut outputs = 0;
        let mut short = small_reads.drain(..);
        while let Some((index, read_budget)) =
            next_output(&mut short, &mut bulk, &mut marks, &mut outputs)
        {
            if marks.read[index] == marks.round {
                continue;
            }
            if read_budget == INTERACTIVE_READ_BYTES {
                if !marks.read_interactive(index) {
                    // No byte was consumed. Keep one rotating continuation even
                    // if promotion cancelled an older bulk entry this round.
                    if marks.queue(index) {
                        bulk.push_back(index);
                    }
                    continue;
                }
            } else if !marks.read_once(index) {
                continue;
            }
            if slots[index].is_none() {
                continue;
            }
            let result = catch_unwind(AssertUnwindSafe(|| -> io::Result<()> {
                // The next bounded PTY read can share an ordered Ack/output
                // batch. Its final settle always sends even when that read is empty.
                if !settle_with_ack_mode(
                    index,
                    &mut slots,
                    &mut registry,
                    &mut timers,
                    &mut marks,
                    AckMode::QueuedRead,
                )? {
                    return Ok(());
                }
                let session = slots[index]
                    .as_mut()
                    .ok_or_else(|| io::Error::other("host session disappeared"))?;
                session.step_budget(PollFlags::empty(), PollFlags::POLLIN, &[], read_budget)?;
                settle(index, &mut slots, &mut registry, &mut timers, &mut marks)?;
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
fn record_ownership(
    slots: &[Option<Session>],
    accounting: &mut Option<std::fs::File>,
    reactor: Option<std::fmt::Arguments<'_>>,
) {
    let result = accounting.as_mut().map(|file| -> io::Result<()> {
        let mut writer = io::BufWriter::new(file);
        let mut reactor = reactor;
        for (index, session) in slots.iter().enumerate() {
            if let Some(session) = session {
                // Put shared facts on the first live row without adding a new
                // row kind or multiplying shared bytes into each session total.
                session.record_memory(index, &mut writer, reactor.take())?;
            }
        }
        writer.flush()
    });
    if let Some(Err(error)) = result {
        *accounting = None;
        #[cfg(feature = "host-diagnostics")]
        let _ = crate::host_trace::enable(false);
        eprintln!("shared-host accounting stopped: {error}");
    }
}

#[cfg(test)]
mod tests {
    //! Closed descriptor numbers never give stale readiness to a replacement peer.
    use super::*;
    #[test]
    fn exit_observed_before_settle_still_queues_one_retention_deadline() {
        let state = crate::fixture_state::fixture_state();
        let mut config = crate::Config::new([19; 16], nix::unistd::Uid::effective().as_raw());
        config.state = Some(state.clone());
        config.readiness = true;
        let mut session = Session::new(config, 65536).unwrap();
        let client = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
        session
            .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
            .unwrap();
        session.peers[0]
            .attach(crate::frame::SESSION_OWNER)
            .unwrap();
        session.pty.master.write_all(b"finish\n").unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        while session.exit.is_none() {
            session.observe_exit().unwrap();
            assert!(Instant::now() < until, "owned shell did not exit");
            std::thread::sleep(Duration::from_millis(1));
        }
        let deadline = session.deadline.unwrap();
        let signals = SignalFd::with_flags(
            &nix::sys::signal::SigSet::empty(),
            nix::sys::signalfd::SfdFlags::SFD_CLOEXEC,
        )
        .unwrap();
        let mut registry = ownership_fixture(std::slice::from_ref(&session), &signals).unwrap();
        let mut slots = vec![Some(session)];
        let mut timers = BinaryHeap::new();
        let mut marks = ReadyMarks::new(1);
        assert!(settle(0, &mut slots, &mut registry, &mut timers, &mut marks).unwrap());
        assert_eq!(
            timers.peek().map(|Reverse(entry)| *entry),
            Some((deadline, 0)),
            "the signal path established the deadline before housekeeping"
        );
        assert!(settle(0, &mut slots, &mut registry, &mut timers, &mut marks).unwrap());
        assert_eq!(timers.len(), 1, "repeat work must not duplicate timers");
        drop(client);
        drop(slots);
        std::fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn ownership_receipt_separates_session_components_and_shared_capacities() {
        let state = crate::fixture_state::fixture_state();
        let mut sessions = Vec::new();
        for id in [17_u8, 18] {
            let mut config = crate::Config::new([id; 16], nix::unistd::Uid::effective().as_raw());
            config.state = Some(state.clone());
            config.readiness = true;
            let mut session = Session::new(config, 65536).unwrap();
            session.terminal.process(b"prompt").unwrap();
            session.ring.append(b"prompt").unwrap();
            sessions.push(Some(session));
        }
        sessions.insert(0, None);
        let mut receipt = Some(std::fs::File::create(state.join("receipt")).unwrap());
        record_ownership(
            &sessions,
            &mut receipt,
            Some(format_args!(
                "{{\"slots_capacity\":{}}}",
                sessions.capacity()
            )),
        );
        let text = std::fs::read_to_string(state.join("receipt")).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert_eq!(text.matches("\"reactor\":").count(), 1);
        assert!(text.lines().next().unwrap().contains("\"session\":1,"));
        for row in text.lines() {
            let number = |name: &str| -> usize {
                row.split_once(&format!("\"{name}\":"))
                    .unwrap()
                    .1
                    .split(|character: char| !character.is_ascii_digit())
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap()
            };
            assert_eq!(number("struct_bytes"), std::mem::size_of::<Session>());
            assert_eq!(
                number("total_bytes"),
                [
                    "struct_bytes",
                    "path_bytes",
                    "config_path_bytes",
                    "prefix_bytes",
                    "geometry_bytes",
                    "ring_bytes",
                    "input_bytes",
                    "writer_bytes",
                    "peer_bytes",
                    "peer_slots_bytes",
                ]
                .map(number)
                .iter()
                .sum::<usize>()
            );
        }
        drop(receipt);
        drop(sessions);
        std::fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn timer_membership_survives_bulk_promotion_cancellation_and_round_wrap() {
        let mut marks = ReadyMarks::new(1);
        assert!(marks.queue_timer(0));
        assert!(marks.queue(0));
        marks.promote(0);
        assert!(!marks.queue_timer(0));
        assert!(!marks.queue(0));
        assert!(marks.take_bulk(0));
        assert!(!marks.queue_timer(0));
        assert!(marks.queue(0));
        marks.promote(0);
        assert!(!marks.take_bulk(0));
        marks.round = u32::MAX;
        marks.next_round();
        assert!(!marks.queue_timer(0));
        marks.retire_timer(0);
        assert!(marks.queue_timer(0));
        assert!(marks.queue(0));
        marks.retire_timer(0);
        assert!(marks.take_bulk(0));
    }

    #[test]
    fn readiness_storage_registration_is_at_most_sixteen_bytes() {
        assert!(
            std::mem::size_of::<Registration>() <= 16,
            "registration owns {} bytes before table overhead",
            std::mem::size_of::<Registration>()
        );
    }

    #[test]
    fn readiness_storage_two_descriptors_are_allocation_free() {
        let (_ready, delta) = crate::heap_accounting::measure(|| {
            let mut ready = Ready::default();
            ready.insert(7, EpollFlags::EPOLLIN);
            ready.insert(8, EpollFlags::EPOLLHUP);
            assert_eq!(ready.get(7), Some(EpollFlags::EPOLLIN));
            assert_eq!(ready.get(8), Some(EpollFlags::EPOLLHUP));
            ready
        });
        assert_eq!(
            delta.allocations, 0,
            "PTY and peer readiness must stay inline"
        );
    }
    #[test]
    fn ready_rows_clear_only_touched_slots_and_fence_round_wrap() {
        let mut work = ReadyWork::new(3);
        assert!(work.get(0).is_none());
        work.next_round();
        work.entry(2).insert(7, EpollFlags::EPOLLIN);
        work.entry(2).insert(8, EpollFlags::EPOLLHUP);
        assert_eq!(work.active, [2]);
        work.next_round();
        assert!(work.get(2).is_none());
        assert_eq!(work.rows[2].get(7), Some(EpollFlags::EPOLLIN));
        work.entry(2).insert(9, EpollFlags::EPOLLERR);
        assert_eq!(work.get(2).unwrap().get(7), None);
        work.rows[0].generation = 1;
        work.round = u32::MAX;
        work.next_round();
        assert!(work.get(0).is_none());
        assert!(work.get(2).is_none());
        work.entry(0).insert(10, EpollFlags::EPOLLIN);
        assert_eq!(work.active, [0]);
    }

    #[test]
    fn ready_rows_keep_two_descriptor_turns_allocation_free_within_64_bytes_per_slot() {
        let (mut work, allocation) = crate::heap_accounting::measure(|| ReadyWork::new(1000));
        assert!(
            allocation.bytes <= 64_000,
            "ready rows own {} bytes",
            allocation.bytes
        );
        let ((), allocation) = crate::heap_accounting::measure(|| {
            for _ in 0..3 {
                work.next_round();
                for index in 0..1000 {
                    work.entry(index).insert(7, EpollFlags::EPOLLIN);
                    work.entry(index).insert(8, EpollFlags::EPOLLOUT);
                }
            }
        });
        assert_eq!(allocation.allocations, 0);
        assert_eq!(work.active.len(), 1000);
        work.entry(0).insert(9, EpollFlags::EPOLLHUP);
        let ((), allocation) = crate::heap_accounting::measure(|| {
            work.next_round();
            for key in 7..=9 {
                work.entry(0).insert(key, EpollFlags::EPOLLIN);
            }
        });
        assert_eq!(
            allocation.allocations, 0,
            "viewer overflow capacity must survive the turn"
        );
        assert_eq!(work.active, [0]);
    }

    #[test]
    fn input_phase_retires_closed_identity_without_publishing_transient_interest() {
        let state = crate::fixture_state::fixture_state();
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
        // Other test threads may fork with this descriptor before exec.
        // Shutdown fences the connection even while an inherited copy exists.
        client.shutdown(std::net::Shutdown::Both).unwrap();
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
    fn fresh_ack_fallback_avoids_writable_poll_and_finishes_with_new_input() {
        use std::io::Read as _;
        let (session, mut client, state) = super::super::tests::ack_fixture(38);
        let signals = SignalFd::new(&nix::sys::signal::SigSet::empty()).unwrap();
        let mut registry = Registry::new(1, &signals).unwrap();
        let mut marks = ReadyMarks::new(1);
        let mut slots = [Some(session)];
        let mut timers = BinaryHeap::new();
        let mut fallback = VecDeque::new();
        settle_with_ack_mode(
            0,
            &mut slots,
            &mut registry,
            &mut timers,
            &mut marks,
            AckMode::Fresh,
        )
        .unwrap();
        let session = slots[0].as_ref().unwrap();
        let fd = session.peers[0].stream.as_raw_fd();
        assert!(
            !registry.by_fd[&fd].flags.contains(EpollFlags::EPOLLOUT),
            "a local fallback must not toggle logical Ack writability"
        );
        let mut events = [EpollEvent::empty(); 8];
        let count = registry
            .epoll
            .wait(&mut events, EpollTimeout::ZERO)
            .unwrap();
        assert!(
            !events[..count].iter().any(|event| {
                event.data() & u64::from(u32::MAX) == u64::try_from(fd).unwrap()
                    && event.events().contains(EpollFlags::EPOLLOUT)
            }),
            "the kernel must not return a held logical Ack as writable"
        );
        queue_fresh_ack(0, session, AckMode::Fresh, &mut marks, &mut fallback);
        queue_fresh_ack(0, session, AckMode::Fresh, &mut marks, &mut fallback);
        assert_eq!(fallback.len(), 1);
        assert!(marks.queue_timer(0));
        assert!(marks.queue(0));
        let mut work = ReadyWork::new(1);
        work.next_round();
        for index in fallback.drain(..) {
            work.entry(index);
        }
        assert_eq!(work.active, [0]);
        let due = marks.take_ack(0);
        assert!(due);
        assert!(!marks.take_ack(0));
        // New incoming bytes must not renew a silent program's Ack forever.
        let incoming = true;
        let mode = AckMode::for_control(incoming && !due, false, false);
        assert!(matches!(mode, AckMode::Immediate));
        settle_with_ack_mode(0, &mut slots, &mut registry, &mut timers, &mut marks, mode).unwrap();
        assert!(marks.take_bulk(0), "Ack membership must preserve bulk work");
        assert!(!marks.queue_timer(0), "Ack membership must preserve timers");
        let expected = super::super::super::Frame::InputAck(0).encode().unwrap();
        let mut received = vec![0; expected.len()];
        client.read_exact(&mut received).unwrap();
        assert_eq!(received, expected);
        assert!(fallback.is_empty());
        assert!(!registry.by_fd[&fd].flags.contains(EpollFlags::EPOLLOUT));
        drop(registry);
        drop(client);
        drop(slots);
        std::fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn queued_data_ack_needs_no_writable_poll_before_pty_service() {
        use std::io::Read as _;
        for output in [false, true] {
            let (mut session, mut client, state) =
                super::super::tests::ack_fixture(34 + u8::from(output));
            let signals = SignalFd::new(&nix::sys::signal::SigSet::empty()).unwrap();
            let mut registry = Registry::new(INTERACTIVE_READS_PER_ROUND + 1, &signals).unwrap();
            let mut marks = ReadyMarks::new(INTERACTIVE_READS_PER_ROUND + 1);
            for index in 0..INTERACTIVE_READS_PER_ROUND {
                assert!(marks.read_interactive(index));
            }
            assert!(!marks.read_interactive(INTERACTIVE_READS_PER_ROUND));
            let mut bulk = VecDeque::new();
            assert!(marks.queue(INTERACTIVE_READS_PER_ROUND));
            bulk.push_back(INTERACTIVE_READS_PER_ROUND);
            session.housekeeping_coalesced(true).unwrap();
            let fresh = AckMode::for_control(true, false, false);
            registry
                .sync(
                    INTERACTIVE_READS_PER_ROUND,
                    &session,
                    !matches!(fresh, AckMode::Immediate),
                )
                .unwrap();
            let fd = session.peers[0].stream.as_raw_fd();
            let fresh_write = registry.by_fd[&fd].flags.contains(EpollFlags::EPOLLOUT);
            // A queued read guarantees service without a second writable poll.
            let waiting = AckMode::for_control(false, true, true);
            registry
                .sync(
                    INTERACTIVE_READS_PER_ROUND,
                    &session,
                    !matches!(waiting, AckMode::Immediate),
                )
                .unwrap();
            let waiting_write = registry.by_fd[&fd].flags.contains(EpollFlags::EPOLLOUT);
            let mut events = [EpollEvent::empty(); 8];
            let count = registry
                .epoll
                .wait(&mut events, EpollTimeout::ZERO)
                .unwrap();
            let polled_write = events[..count].iter().any(|event| {
                event.data() & u64::from(u32::MAX) == u64::try_from(fd).unwrap()
                    && event.events().contains(EpollFlags::EPOLLOUT)
            });
            let mut outputs = 0;
            let chosen = next_output(&mut std::iter::empty(), &mut bulk, &mut marks, &mut outputs);
            let granted = marks.read_once(INTERACTIVE_READS_PER_ROUND);
            let mut expected = super::super::super::Frame::InputAck(0).encode().unwrap();
            if output {
                session.ring.append(b"reply").unwrap();
                expected.extend(
                    super::super::super::Frame::Output(0, b"reply".to_vec())
                        .encode()
                        .unwrap(),
                );
            }
            // The final settle acknowledges even an empty read attempt.
            session.housekeeping().unwrap();
            registry
                .sync(INTERACTIVE_READS_PER_ROUND, &session, false)
                .unwrap();
            let mut received = vec![0; expected.len()];
            let delivered = client.read_exact(&mut received);
            drop(registry);
            drop(client);
            drop(session);
            std::fs::remove_dir_all(state).unwrap();
            assert!(!fresh_write, "fresh Acks use the local next-turn fallback");
            assert!(
                !waiting_write,
                "a queued PTY turn must not rearm logical Ack writability"
            );
            assert!(
                !polled_write,
                "the kernel must not return the held logical Ack as writable"
            );
            assert_eq!(chosen, Some((INTERACTIVE_READS_PER_ROUND, BULK_READ_BYTES)));
            assert!(granted);
            delivered.expect("queued service must finish the Ack, including an empty read");
            assert_eq!(received, expected);
        }
    }

    #[test]
    fn inline_and_extra_descriptor_flags_merge_without_losing_generations() {
        let mut ready = Ready::default();
        ready.insert(7, EpollFlags::EPOLLIN);
        ready.insert(8, EpollFlags::EPOLLHUP);
        ready.insert(7, EpollFlags::EPOLLOUT);
        ready.insert(8, EpollFlags::EPOLLIN);
        ready.insert(9, EpollFlags::EPOLLERR);
        ready.insert(9, EpollFlags::EPOLLOUT);
        assert_eq!(
            ready.get(7),
            Some(EpollFlags::EPOLLIN | EpollFlags::EPOLLOUT)
        );
        assert_eq!(
            ready.get(8),
            Some(EpollFlags::EPOLLHUP | EpollFlags::EPOLLIN)
        );
        assert_eq!(
            ready.get(9),
            Some(EpollFlags::EPOLLERR | EpollFlags::EPOLLOUT)
        );
        assert_eq!(ready.get(10), None);
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
        let state = crate::fixture_state::fixture_state();
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
        let ((), delta) =
            crate::heap_accounting::measure(|| registry.sync(0, &session, false).unwrap());
        assert_eq!(delta.allocations, 0);
        drop(registry);
        drop(session);
        std::fs::remove_dir_all(state).unwrap();
    }
    #[test]
    fn cheap_replies_share_a_turn_but_expired_output_yields_to_input() {
        let mut marks = ReadyMarks::new(100);
        let start = Instant::now();
        marks.start_output_round(start);
        for index in 0..16 {
            assert!(
                marks.read_interactive_at(index, start + Duration::from_micros(index as u64 * 20)),
                "cheap replies should not need another poll before the output deadline"
            );
        }
        assert!(!marks.read_interactive_at(16, start + Duration::from_micros(500)));
        assert!(
            marks.queue(16),
            "denied output keeps its rotating continuation"
        );
        assert!(marks.take_bulk(16));
        assert!(marks.read_once(16), "bulk keeps its separate bounded turn");
        marks.next_round();
        marks.start_output_round(start + Duration::from_secs(1));
        assert!(marks.read_interactive_at(17, start + Duration::from_secs(1)));
        marks.round = u32::MAX;
        marks.next_round();
        marks.start_output_round(start + Duration::from_secs(2));
        assert!(marks.read_interactive_at(17, start + Duration::from_secs(2)));
    }

    #[test]
    fn short_output_cohort_yields_before_the_next_input_poll() {
        let mut marks = ReadyMarks::new(1000);
        let mut bulk = VecDeque::new();
        // Input-triggered opportunistic reads and readiness-promoted reads
        // spend the same allowance. A duplicate spends none of it.
        assert!(marks.read_interactive(0));
        assert!(!marks.read_interactive(0));
        let mut reads = 1;
        for index in 1..1000 {
            if marks.read_interactive(index) {
                reads += 1;
            } else if marks.queue(index) {
                bulk.push_back(index);
            }
        }
        assert_eq!(
            reads, INTERACTIVE_READS_PER_ROUND,
            "a short-output cohort must not monopolize one turn"
        );
        assert_eq!(
            bulk.len(),
            1000 - INTERACTIVE_READS_PER_ROUND,
            "unread output must retain continuation"
        );
        marks.next_round();
        let index = bulk.pop_front().unwrap();
        assert!(marks.take_bulk(index));
        assert!(marks.read_interactive(index));
        marks.round = u32::MAX;
        marks.next_round();
        assert!(
            marks.read_interactive(index),
            "wrap must also restore the allowance"
        );
    }

    #[test]
    fn actual_output_selector_keeps_a_bulk_turn_after_granted_and_denied_promotions() {
        for input_spent_allowance in [false, true] {
            let mut marks = ReadyMarks::new(1000);
            let mut bulk: VecDeque<_> = (0..1000).collect();
            for index in 0..1000 {
                assert!(marks.queue(index));
            }
            for turn in 0..4 {
                marks.next_round();
                if input_spent_allowance {
                    for index in 0..INTERACTIVE_READS_PER_ROUND {
                        assert!(marks.read_interactive(index));
                    }
                }
                // The same fast producers stay ready on every turn. Granted
                // promotions cancel old entries; denied ones retain rotation.
                let start = if input_spent_allowance {
                    INTERACTIVE_READS_PER_ROUND
                } else {
                    0
                };
                let mut short = (start..start + INTERACTIVE_READS_PER_ROUND)
                    .map(|index| (index, INTERACTIVE_READ_BYTES));
                let mut outputs = 0;
                let mut bulk_reads = Vec::new();
                while let Some((index, budget)) =
                    next_output(&mut short, &mut bulk, &mut marks, &mut outputs)
                {
                    if budget == INTERACTIVE_READ_BYTES {
                        if !marks.read_interactive(index) && marks.queue(index) {
                            bulk.push_back(index);
                        }
                    } else {
                        assert!(marks.read_once(index), "bulk cannot select a promoted read");
                        bulk_reads.push(index);
                    }
                }
                assert_eq!(bulk_reads, vec![INTERACTIVE_READS_PER_ROUND + turn]);
            }
        }
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
        let state = crate::fixture_state::fixture_state();
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
        let state = crate::fixture_state::fixture_state();
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
        let state = crate::fixture_state::fixture_state();
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
        record_ownership(&slots, &mut accounting, None);
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
        record_ownership(&slots, &mut accounting, None);
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
        let state = crate::fixture_state::fixture_state();
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
        registry.sync(0, &session, false).unwrap();
        let peer = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
        session
            .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
            .unwrap();
        registry.sync(0, &session, false).unwrap();
        let fd = session.peers[0].stream.as_raw_fd();
        let key = registry.by_fd[&fd].key;
        session.peers.clear();
        registry.sync(0, &session, false).unwrap();
        assert!(registry.registration(key).is_none());
        drop(peer);
        let peer = std::os::unix::net::UnixStream::connect(&session.path.0).unwrap();
        session
            .step(PollFlags::POLLIN, PollFlags::empty(), &[], false)
            .unwrap();
        registry.sync(0, &session, false).unwrap();
        assert_eq!(session.peers[0].stream.as_raw_fd(), fd);
        let replacement = registry.by_fd[&fd].key;
        assert_ne!(key, replacement);
        let mut obsolete = Ready::default();
        obsolete.insert(key, EpollFlags::EPOLLIN);
        assert_eq!(obsolete.flags(fd, &registry), PollFlags::empty());
        let mut current = Ready::default();
        current.insert(replacement, EpollFlags::EPOLLIN);
        assert_eq!(current.flags(fd, &registry), PollFlags::POLLIN);
        drop(peer);
        drop(session);
        std::fs::remove_dir_all(state).unwrap();
    }
}
