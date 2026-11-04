//! Ghostty VT state with bounded snapshot and unfinished-parser carry [13][94].
#![forbid(unsafe_code)]
use crate::{frame::MAX_FRAME, ring::Ring, terminal_native::Engine};
use std::io;
/// A byte budget, not a row count: about 10,000 typical 200-column ASCII rows.
/// Ghostty's page storage includes cell capacity and sparse style/grapheme data.
const SCROLLBACK_BYTES: usize = 17 * 1024 * 1024;
/// Second, lightweight parser that only watches whether the latest byte
/// finished a sequence. `Terminal` uses it to know which bytes form an unfinished
/// escape sequence at the end of the output, so a snapshot can carry that
/// prefix and the live stream can continue it.
#[derive(Default)]
struct Observer {
    complete: bool,
}
impl vte::Perform for Observer {
    fn print(&mut self, _: char) {
        self.complete = true;
    }
    fn execute(&mut self, byte: u8) {
        if matches!(byte, 0x18 | 0x1a) {
            self.complete = true;
        }
    }
    fn csi_dispatch(&mut self, _: &vte::Params, _: &[u8], _: bool, _: char) {
        self.complete = true;
    }
    fn esc_dispatch(&mut self, _: &[u8], _: bool, _: u8) {
        self.complete = true;
    }
    fn osc_dispatch(&mut self, _: &[&[u8]], _: bool) {
        self.complete = true;
    }
    fn unhook(&mut self) {
        self.complete = true;
    }
}
// Geometry changes and lost state are separate recovery certificates; neither
// permits raw reconstruction merely because the ring still has origin bytes.
/// How trustworthy the terminal's rebuilt state is. Geometry changes and lost
/// state are separate certificates; neither lets raw output be replayed
/// exactly, even if the ring still holds every byte since the start.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Recovery {
    /// State follows every byte seen so far at an unchanged size.
    Exact,
    /// Earlier output was produced at another size, so replaying it raw would not
    /// reproduce earlier reflow.
    GeometryChanged,
    /// State was rebuilt without the original bytes (a reset plus whatever came
    /// later) and cannot be called faithful.
    Approximate,
}
/// One session's terminal screen state, used to answer snapshot requests and
/// to keep the screen in step with the output ring.
///
/// Feed every PTY output byte to `process` and every size change to `resize`.
/// `snapshot` then yields bytes that reproduce the screen plus any unfinished
/// escape sequence (the "carry"), so the stream can carry on from a snapshot.
/// Memory is bounded: scrollback is a byte budget, and the carry never exceeds
/// the frame limit.
pub struct Terminal {
    engine: Engine,
    #[cfg(feature = "process-per-user")]
    history_budget: usize,
    #[cfg(feature = "process-per-user")]
    bounded: bool,
    #[cfg(feature = "process-per-user")]
    host: Option<std::sync::Arc<crate::terminal_memory::HostBudget>>,
    #[cfg(feature = "process-per-user")]
    host_floor: Option<std::sync::Arc<crate::terminal_memory::HostFloor>>,
    #[cfg(feature = "process-per-user")]
    limits: crate::terminal_limits::Limits,
    observer: Observer,
    parser: vte::Parser,
    pending: Vec<u8>,
    carry_overflow: bool,
    dimensions: (u16, u16),
    // Replaying raw output at a different historical geometry is not exact.
    recovery: Recovery,
    recovery_pending: bool,
}
impl Terminal {
    /// Inspect the live flag independently of repaint, which ends synchronization.
    #[cfg(all(test, feature = "process-per-user"))]
    pub(crate) fn research_synchronized_output(&self) -> io::Result<bool> {
        self.engine.synchronized_output()
    }
    /// Compare native state independently of the bounded repaint serializer.
    #[cfg(all(test, feature = "process-per-user"))]
    pub(crate) fn research_state_difference(&self, other: &Self) -> usize {
        self.engine.state_difference(&other.engine)
            + usize::from(self.pending != other.pending || self.dimensions != other.dimensions)
    }
    #[cfg(test)]
    pub(crate) fn allocation_fixture(engine: Engine, prefix: &[u8]) -> Self {
        let mut terminal = Self::new(80, 24).unwrap();
        // Seed the carry observer before replacing the native engine with the
        // real refusing allocator fixture, already seeded with the same bytes.
        terminal.process(prefix);
        terminal.engine = engine;
        terminal
    }

    /// Creates a terminal of `cols` x `rows` with the default 17 MiB scrollback
    /// budget. Fails if the terminal engine cannot allocate it.
    pub fn new(cols: u16, rows: u16) -> io::Result<Self> {
        Self::build(
            cols,
            rows,
            SCROLLBACK_BYTES,
            false,
            #[cfg(feature = "process-per-user")]
            None,
            #[cfg(feature = "process-per-user")]
            None,
        )
    }
    /// Reuse the selected VT engine with an explicit research retention budget.
    #[cfg(all(test, feature = "process-per-user"))]
    pub(super) fn with_history_budget(cols: u16, rows: u16, history: usize) -> io::Result<Self> {
        Self::with_host_budget(cols, rows, history, None)
    }
    /// A bounded terminal that also charges the host-wide native budget.
    #[cfg(feature = "process-per-user")]
    pub(super) fn with_host_budget(
        cols: u16,
        rows: u16,
        history: usize,
        host: Option<std::sync::Arc<crate::terminal_memory::HostBudget>>,
    ) -> io::Result<Self> {
        let floor_reservation = host
            .as_ref()
            .map(|host| {
                let floor =
                    crate::terminal_native::floor_for_geometry(cols, rows, host.minimum_floor());
                host.reserve_session(floor)
            })
            .transpose()?;
        Self::with_host_floor(cols, rows, history, host, floor_reservation)
    }
    /// Uses a session floor reserved before its PTY was created [D310].
    #[cfg(feature = "process-per-user")]
    pub(super) fn with_host_floor(
        cols: u16,
        rows: u16,
        history: usize,
        host: Option<std::sync::Arc<crate::terminal_memory::HostBudget>>,
        floor_reservation: Option<std::sync::Arc<crate::terminal_memory::HostFloor>>,
    ) -> io::Result<Self> {
        let mut terminal = Self::build(
            cols,
            rows,
            history,
            true,
            host.clone(),
            floor_reservation.clone(),
        )?;
        terminal.host = host;
        terminal.host_floor = floor_reservation;
        Ok(terminal)
    }
    /// Shared constructor behind `new` and the shared-host variants. `history` is the
    /// scrollback byte budget; `bounded` selects the shared-host engine that limits
    /// control-string length and charges `host` and `floor_reservation`.
    fn build(
        cols: u16,
        rows: u16,
        history: usize,
        bounded: bool,
        #[cfg(feature = "process-per-user")] host: Option<
            std::sync::Arc<crate::terminal_memory::HostBudget>,
        >,
        #[cfg(feature = "process-per-user")] floor_reservation: Option<
            std::sync::Arc<crate::terminal_memory::HostFloor>,
        >,
    ) -> io::Result<Self> {
        #[cfg(feature = "process-per-user")]
        let engine = if bounded {
            Engine::bounded(cols, rows, history, host, floor_reservation)?
        } else {
            Engine::new(cols, rows, history)?
        };
        #[cfg(not(feature = "process-per-user"))]
        let engine = {
            let _ = bounded;
            Engine::new(cols, rows, history)?
        };
        Ok(Self {
            engine,
            #[cfg(feature = "process-per-user")]
            history_budget: history,
            #[cfg(feature = "process-per-user")]
            bounded,
            #[cfg(feature = "process-per-user")]
            host: None,
            #[cfg(feature = "process-per-user")]
            host_floor: None,
            #[cfg(feature = "process-per-user")]
            limits: crate::terminal_limits::Limits::default(),
            observer: Observer::default(),
            parser: vte::Parser::new(),
            pending: Vec::with_capacity(4096),
            carry_overflow: false,
            dimensions: (cols, rows),
            recovery: Recovery::Exact,
            recovery_pending: false,
        })
    }
    /// Feeds a chunk of PTY output to the terminal.
    ///
    /// On a shared host, over-long control strings are cut down first (see
    /// `terminal_limits`) so their payload never becomes printable text or commands.
    /// Never fails: if memory for the engine cannot be had, output is skipped until
    /// a later chunk can retry, so the PTY and ring keep moving.
    pub fn process(&mut self, bytes: &[u8]) {
        #[cfg(feature = "process-per-user")]
        if self.bounded {
            use crate::terminal_limits::Action;
            let mut limits = std::mem::take(&mut self.limits);
            let mut start = 0;
            for (index, &byte) in bytes.iter().enumerate() {
                match limits.byte(byte) {
                    Action::Keep => {}
                    action => {
                        self.process_unbounded(&bytes[start..index]);
                        match action {
                            Action::Restart => self.process_unbounded(&[0x1b, byte]),
                            Action::Start(introducer) => {
                                self.process_unbounded(&[0x1b, introducer]);
                            }
                            Action::Drop | Action::Keep => {}
                        }
                        start = index + 1;
                    }
                }
            }
            self.process_unbounded(&bytes[start..]);
            self.limits = limits;
            return;
        }
        self.process_unbounded(bytes);
    }
    /// Applies bytes to the engine and keeps the unfinished-sequence carry up to
    /// date. If a rebuild is pending, retries it first and skips the bytes when it
    /// still fails. Carry bytes are limited (to `STRING_BYTES` on a shared host,
    /// otherwise just under one frame); a longer sequence sets an overflow flag
    /// so the carry is withheld.
    fn process_unbounded(&mut self, bytes: &[u8]) {
        // A persistent allocation refusal must not stop PTY/ring progress.
        // Retry fresh ownership on later output; until then, touch no handle.
        if self.recovery_pending && self.recover(None).is_err() {
            return;
        }
        self.engine.process(bytes);
        for &byte in bytes {
            // Only ESC can start a sequence among ground-state ASCII/C0.
            // LF/CR/TAB and charset shifts are already handled by Ghostty;
            // feeding them to the carry parser adds work to output floods.
            // Inside a pending sequence, still parse C0 execution/cancellation.
            if byte != 0x1b && byte < 0x80 && self.pending.is_empty() {
                continue;
            }
            let string = self
                .pending
                .get(1)
                .is_some_and(|start| matches!(start, b']' | b'P' | b'_' | b'^' | b'X'));
            if byte == 0x1b && !string {
                self.pending.clear();
                self.carry_overflow = false;
            }
            if !self.pending.is_empty() || byte == 0x1b || byte >= 0xc0 {
                let carry_limit = MAX_FRAME - 9;
                #[cfg(feature = "process-per-user")]
                let carry_limit = if self.bounded {
                    crate::terminal_limits::STRING_BYTES
                } else {
                    carry_limit
                };
                if self.pending.len() < carry_limit {
                    self.pending.push(byte);
                } else {
                    self.carry_overflow = true;
                }
            }
            self.observer.complete = false;
            self.parser.advance(&mut self.observer, &[byte]);
            if self.observer.complete {
                self.pending.clear();
                self.carry_overflow = false;
                if byte == 0x1b {
                    self.pending.push(byte);
                }
            }
            // C0 actions execute within CSI. Carry only its unfinished syntax,
            // otherwise the snapshot continuation executes those actions twice.
            if !self.observer.complete
                && byte < 0x20
                && byte != 0x1b
                && self.pending.last() == Some(&byte)
            {
                self.pending.pop();
            }
        }
    }
    /// Changes the size to `cols` x `rows` without a ring to recover from. See
    /// `resize_with_ring`.
    pub fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        self.resize_with_ring(cols, rows, None)
    }
    /// Recover at the last good size after any native resize error. Exact raw
    /// reconstruction requires origin coverage and unchanged geometry; byte
    /// coverage alone cannot reproduce earlier resize/reflow effects.
    pub fn resize_with_ring(
        &mut self,
        cols: u16,
        rows: u16,
        ring: Option<&Ring>,
    ) -> io::Result<()> {
        if let Err(error) = self.engine.resize(cols, rows) {
            self.recovery_pending = true;
            self.recover(ring)?;
            return Err(error);
        }
        if self.dimensions != (cols, rows) && self.recovery != Recovery::Approximate {
            self.recovery = Recovery::GeometryChanged;
        }
        self.dimensions = (cols, rows);
        Ok(())
    }
    /// Rebuilds the terminal from scratch at its last good size. When the ring
    /// still holds all output from the start and the geometry never changed, the
    /// original bytes are replayed and the state stays exact. Otherwise the screen
    /// is reset and marked approximate. On error `self` is left untouched.
    fn recover(&mut self, ring: Option<&Ring>) -> io::Result<()> {
        #[cfg(feature = "process-per-user")]
        let mut restored = Self::build(
            self.dimensions.0,
            self.dimensions.1,
            self.history_budget,
            self.bounded,
            self.host.clone(),
            self.host_floor.clone(),
        )?;
        // Clone, not take: a later error below leaves `self` in place.
        #[cfg(feature = "process-per-user")]
        {
            restored.host.clone_from(&self.host);
            restored.host_floor.clone_from(&self.host_floor);
        }
        #[cfg(not(feature = "process-per-user"))]
        let mut restored = Self::new(self.dimensions.0, self.dimensions.1)?;
        let complete = ring.filter(|ring| ring.start() == 0 && self.recovery == Recovery::Exact);
        if let Some(ring) = complete {
            // Borrow both deque fragments: recovery after allocation refusal
            // must not allocate an additional full-ring replay buffer.
            let (first, second) = ring
                .origin_slices()
                .ok_or_else(|| io::Error::other("recovery ring coverage changed"))?;
            restored.process(first);
            restored.process(second);
        } else {
            restored.process(b"\x1bc");
            restored.recovery = Recovery::Approximate;
        }
        *self = restored;
        Ok(())
    }
    /// Memory figures from the engine; the third value is true when the engine had
    /// to give up exact state because of its budget.
    #[cfg(feature = "process-per-user")]
    pub(super) fn memory(&self) -> (usize, usize, bool) {
        self.engine.memory()
    }
    /// Breakdown of memory held: ordinary allocations, page allocations, resident
    /// pages, encoded bytes and carry capacity, in that order.
    #[cfg(feature = "process-per-user")]
    pub(super) fn ownership(&self) -> io::Result<(usize, usize, usize, usize, usize)> {
        let (ordinary, pages, _) = self.engine.allocation_classes();
        Ok((
            ordinary,
            pages,
            self.engine.resident_pages()?,
            self.engine.encoded_bytes(),
            self.pending.capacity(),
        ))
    }
    /// Read only native row-count metadata; compressed backing stays cold.
    #[cfg(feature = "process-per-user")]
    pub(super) fn retained_history_rows(&self) -> usize {
        self.engine.history_rows()
    }
    /// A clean or still-pending rebuild cannot certify faithful state. Keep
    /// this provenance across peer replacement and further output/resizes.
    pub fn requires_approximation(&self) -> bool {
        #[cfg(feature = "process-per-user")]
        if self.engine.memory().2 {
            return true;
        }
        self.recovery == Recovery::Approximate || self.recovery_pending
    }
    // A discarded ESC at the frame boundary still belongs to the unfinished
    // string and must be reproduced before the next live byte arrives.
    // Snapshot uses one interface across feature builds; the default has no
    // extra carry state beyond its existing parser prefix.
    /// Bytes to append after the carry in a snapshot: an ESC left over from an
    /// over-long control string on a shared host, otherwise nothing.
    #[cfg_attr(not(feature = "process-per-user"), allow(clippy::unused_self))]
    fn carry_suffix(&self) -> &'static [u8] {
        #[cfg(feature = "process-per-user")]
        if self.bounded {
            return self.limits.carry_suffix();
        }
        b""
    }
    /// Bounded visible fallback; fidelity gaps and clipping are explicitly
    /// announced by the negotiated frame, never substituted for a faithful VT.
    #[must_use]
    pub fn approximate_snapshot(&self) -> Vec<u8> {
        let budget = MAX_FRAME - 10;
        // Preserve unfinished syntax only when the entire carry and a useful
        // repaint fit. Never trim a control string or UTF-8 scalar in half.
        let extra = self.carry_suffix();
        let carry = if !self.carry_overflow && self.pending.len() + extra.len() <= budget - 256 {
            self.pending.as_slice()
        } else {
            &[]
        };
        let mut out = vec![0; budget - carry.len() - extra.len()];
        let len = self.engine.approximate_snapshot(&mut out);
        out.truncate(len);
        if out.is_empty() {
            // A pending rebuild has no live handle; a bounded painter may
            // also return nothing. Both use an explicitly approximate reset.
            out.extend_from_slice(b"\x1bc");
        }
        out.extend_from_slice(carry);
        out.extend_from_slice(extra);
        out
    }
    /// Serializes the screen, then the unfinished escape sequence, so a client can
    /// resume the live stream from it.
    ///
    /// Fails with `Unsupported` when `requires_approximation` is true, and with an
    /// error when the unfinished sequence or the repaint cannot fit in one frame
    /// (`MAX_FRAME`). It retries with progressively less scrollback tail (halving,
    /// at most nine attempts); the visible screens themselves are mandatory.
    pub fn snapshot(&self) -> io::Result<Vec<u8>> {
        if self.requires_approximation() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "terminal state was recovered approximately after a resize error",
            ));
        }
        if self.carry_overflow {
            return Err(io::Error::other(
                "unfinished VT sequence exceeds frozen frame limit",
            ));
        }
        let extra = self.carry_suffix();
        let mut out = vec![0; MAX_FRAME - 9 - self.pending.len() - extra.len()];
        // Retry only when the bounded frame cannot fit the tail. The visible
        // screens are mandatory; Error(1) remains the session's response if
        // even those exceed the frozen 1 MiB frame limit.
        let mut tail = 256;
        loop {
            if let Some(len) = self.engine.try_snapshot(&mut out, tail)? {
                out.truncate(len);
                out.extend_from_slice(&self.pending);
                out.extend_from_slice(extra);
                return Ok(out);
            }
            if tail == 0 {
                break;
            }
            // Avoid repeatedly walking an oversized screen. A geometric tail
            // reduction bounds failed serialization to nine attempts.
            tail /= 2;
        }
        Err(io::Error::other(
            "screen repaint exceeds frozen frame limit",
        ))
    }
}
#[cfg(test)]
#[path = "../tests/unit/terminal.rs"]
mod checks;
#[cfg(test)]
#[path = "../tests/unit/terminal_budgets.rs"]
mod measurements;

#[cfg(test)]
#[path = "../tests/unit/snapshot_fidelity.rs"]
mod fidelity;

#[cfg(test)]
#[path = "../tests/unit/resize_recovery.rs"]
mod resize_recovery;

#[cfg(test)]
#[path = "../tests/unit/recovery_bench.rs"]
mod recovery_measurements;

#[cfg(all(test, feature = "process-per-user"))]
#[path = "../tests/unit/ppu_memory_bench.rs"]
mod ppu_memory_bench;

#[cfg(all(test, feature = "compact-history"))]
#[path = "../tests/unit/compact_history.rs"]
mod compact_history;

#[cfg(all(test, feature = "process-per-user"))]
#[path = "../tests/unit/review_r2.rs"]
mod review_r2;

#[cfg(all(test, feature = "process-per-user"))]
#[path = "../tests/unit/ppu_host_budget.rs"]
mod host_budget;

#[cfg(all(test, feature = "process-per-user"))]
#[path = "../tests/unit/review_r3.rs"]
mod review_r3;

#[cfg(all(test, feature = "process-per-user"))]
#[path = "../tests/unit/user_screen_pool_resize.rs"]
mod user_screen_pool_resize;

#[cfg(test)]
#[path = "../tests/unit/review_r3_default.rs"]
mod review_r3_default;
