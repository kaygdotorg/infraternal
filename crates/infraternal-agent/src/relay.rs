//! Offset and credit invariants for a bounded terminal relay [13][41][81][D381].
//!
//! This state owns no terminal bytes: retention belongs to the shim. A transport
//! may hold one bounded frame while credit is exhausted. After 250 ms with
//! pending output it detaches from the shim, letting the shim update its screen
//! and ring, and requests replay when credit returns. No idle timer runs.
//!
//! Raw output may spend only the ordinary 1 MiB bulk window. A relay attached
//! for the tracer also protects 64 KiB for an input-triggered repaint. A larger
//! replacement Snapshot may borrow credit from this stream's unreturned raw
//! Output, since the client drops that queued output when it accepts the
//! Snapshot. A raw byte can back at most one replacement before its credit
//! returns, even when the first Snapshot fits in the reserve. Returned credit
//! pays repaint debt before it funds more output. Snapshots stay under the
//! shim's 1 MiB frame cap. The unchanged 250 ms path uses ordinary bulk credit,
//! and every `Output` owns its own budgets.

use infraternal_shim::frame::MAX_FRAME;
use std::{
    ops::Range,
    time::{Duration, Instant},
};

/// The wire catch-up threshold; schedule a single deadline only for pending data.
pub const STARVATION: Duration = Duration::from_millis(250);

/// Credit held back from raw output for one input-triggered repaint budget.
pub const REPAINT_RESERVE: u32 = 64 * 1024;
/// Minimum raw output in flight that marks a stream as backlogged before its bulk window empties.
pub const KEY_REPAINT_BACKLOG: u64 = 16 * 1024;
/// Maximum bulk credit raw output may spend in a reserved relay.
const BULK_WINDOW: u64 = 1024 * 1024;
/// Reserve setup state before the first client credit grant is inspected.
const RESERVE_WAITING_FOR_INITIAL_CREDIT: u8 = 1;
/// Reserve setup state after the client grants the full bulk and repaint budgets.
const RESERVE_ACTIVE: u8 = 2;

/// Invalid sequence arithmetic, ordering, or credit consumption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A byte range has no representable exclusive end.
    Overflow,
    /// A producer skipped bytes that have not been acknowledged.
    Gap,
    /// Acknowledgment or forwarding exceeded the submitted range or credit.
    OutOfRange,
}

fn end(seq: u64, len: usize) -> Result<u64, Error> {
    seq.checked_add(u64::try_from(len).map_err(|_| Error::Overflow)?)
        .ok_or(Error::Overflow)
}

/// Input is deduplicated by the shim-confirmed PTY offset, never socket writes.
#[derive(Debug, Default)]
pub struct Input {
    acked: u64,
    submitted: u64,
}

impl Input {
    /// Initialize from the offset owned by the surviving shim.
    #[must_use]
    pub const fn resume(acked: u64) -> Self {
        Self {
            acked,
            submitted: acked,
        }
    }

    /// Select the unseen suffix, accepting overlaps but refusing gaps/overflow.
    /// The transport commits submission only after queueing to the shim.
    /// # Errors
    /// Rejects overflow or an input sequence beyond the submitted cursor.
    pub fn suffix(&self, seq: u64, len: usize) -> Result<Range<usize>, Error> {
        let limit = end(seq, len)?;
        if seq > self.submitted {
            return Err(Error::Gap);
        }
        if limit <= self.submitted {
            return Ok(len..len);
        }
        let skip = usize::try_from(self.submitted - seq).map_err(|_| Error::Overflow)?;
        Ok(skip..len)
    }

    /// Record the exclusive end queued to the shim, preserving monotonicity.
    /// # Errors
    /// Rejects offsets behind the submitted cursor.
    pub fn submit(&mut self, exclusive_end: u64) -> Result<(), Error> {
        if exclusive_end < self.submitted {
            return Err(Error::OutOfRange);
        }
        self.submitted = exclusive_end;
        Ok(())
    }

    /// Advance only on a shim acknowledgment of bytes written to the PTY.
    /// # Errors
    /// Rejects regression and acknowledgments of input never submitted.
    pub fn acknowledge(&mut self, exclusive_end: u64) -> Result<(), Error> {
        if exclusive_end < self.acked || exclusive_end > self.submitted {
            return Err(Error::OutOfRange);
        }
        self.acked = exclusive_end;
        Ok(())
    }

    /// Exclusive input offset confirmed by the shim.
    #[must_use]
    pub const fn acked(&self) -> u64 {
        self.acked
    }
}

/// Constant-space output flow state; bytes remain in the shim or one frame.
#[derive(Debug)]
pub struct Output {
    cursor: u64,
    credit: u64,
    /// Raw bytes sent to the client whose credit has not returned.
    raw_in_flight: u32,
    /// Unreturned raw bytes sent since the latest repaint, usable for one replacement.
    raw_replacement_credit: u32,
    /// Unspent portion of the initial repaint reserve, restored by returned credit.
    repaint_reserve: u32,
    /// Repaint bytes borrowed from raw output, paid before later credit is usable.
    repaint_debt: u32,
    stalled: Option<Instant>,
    snapshot: bool,
    required: u64,
    reserve_mode: u8,
}

impl Output {
    /// Start unfunded: only an explicit Credit permits Output or Snapshot.
    /// An implicit grant races the server's zero-credit relay and causes a
    /// whole leg-B reconnect when shim replay wins that race (#66).
    #[must_use]
    pub const fn attach(cursor: u64) -> Self {
        Self {
            cursor,
            credit: 0,
            raw_in_flight: 0,
            raw_replacement_credit: 0,
            repaint_reserve: 0,
            repaint_debt: 0,
            stalled: None,
            snapshot: false,
            required: 1,
            reserve_mode: 0,
        }
    }

    /// Attach with a small credit floor when the client offers it in its first grant.
    ///
    /// A client that sends only the legacy 1 MiB initial grant keeps the full
    /// amount for raw output and has no key-triggered repaint reserve.
    #[must_use]
    pub const fn attach_with_repaint_reserve(cursor: u64) -> Self {
        Self {
            cursor,
            credit: 0,
            raw_in_flight: 0,
            raw_replacement_credit: 0,
            repaint_reserve: 0,
            repaint_debt: 0,
            stalled: None,
            snapshot: false,
            required: 1,
            reserve_mode: RESERVE_WAITING_FOR_INITIAL_CREDIT,
        }
    }

    /// Grant bounded cumulative credit, paying any replacement repaint debt first.
    /// # Errors
    /// Rejects a credit counter overflow without mutating state.
    pub fn grant(&mut self, bytes: u32) -> Result<(), Error> {
        let repaid = bytes.min(self.repaint_debt);
        let available = bytes - repaid;
        let credit = self
            .credit
            .checked_add(u64::from(available))
            .ok_or(Error::Overflow)?;
        self.credit = credit;
        self.repaint_debt -= repaid;
        // Credit returns do not identify their frame. Treat them as older raw
        // output first, which is conservative if a repaint returned first.
        let raw_repaid = bytes.min(self.raw_in_flight);
        let already_replaced = self.raw_in_flight - self.raw_replacement_credit;
        self.raw_replacement_credit -= raw_repaid.saturating_sub(already_replaced);
        self.raw_in_flight -= raw_repaid;
        if self.reserve_mode == RESERVE_WAITING_FOR_INITIAL_CREDIT && bytes > 0 {
            self.reserve_mode = if u64::from(bytes) >= BULK_WINDOW + u64::from(REPAINT_RESERVE) {
                self.repaint_reserve = REPAINT_RESERVE;
                RESERVE_ACTIVE
            } else {
                self.repaint_reserve = 0;
                0
            };
        } else if self.reserve_mode == RESERVE_ACTIVE {
            self.repaint_reserve = self
                .repaint_reserve
                .saturating_add(available)
                .min(REPAINT_RESERVE);
        }
        if self.bulk_credit() >= self.required {
            self.stalled = None;
        }
        Ok(())
    }

    /// Select contiguous output affordable now, omitting already-sent overlap.
    /// # Errors
    /// Rejects overflow and a gap in the shim's raw byte stream.
    pub fn suffix(&self, seq: u64, len: usize) -> Result<Range<usize>, Error> {
        let limit = end(seq, len)?;
        if seq > self.cursor {
            return Err(Error::Gap);
        }
        if limit <= self.cursor || self.snapshot {
            return Ok(len..len);
        }
        let skip = usize::try_from(self.cursor - seq).map_err(|_| Error::Overflow)?;
        let available = usize::try_from(self.bulk_credit()).unwrap_or(usize::MAX);
        Ok(skip..skip + (len - skip).min(available))
    }

    /// Commit a successfully queued raw output suffix.
    /// # Errors
    /// Rejects insufficient credit or offset overflow without mutating state.
    pub fn forward(&mut self, len: usize) -> Result<(), Error> {
        let next = end(self.cursor, len)?;
        let bytes = u64::try_from(len).map_err(|_| Error::Overflow)?;
        if bytes > self.bulk_credit() || self.snapshot {
            return Err(Error::OutOfRange);
        }
        let raw_bytes = u32::try_from(bytes).map_err(|_| Error::Overflow)?;
        let raw_in_flight = self
            .raw_in_flight
            .checked_add(raw_bytes)
            .ok_or(Error::Overflow)?;
        let raw_replacement_credit = self
            .raw_replacement_credit
            .checked_add(raw_bytes)
            .ok_or(Error::Overflow)?;
        self.cursor = next;
        self.credit -= bytes;
        self.raw_in_flight = raw_in_flight;
        self.raw_replacement_credit = raw_replacement_credit;
        self.stalled = None;
        Ok(())
    }

    /// Record an unaffordable pending frame; callers arm this one-shot deadline.
    /// Calling again does not postpone catch-up.
    pub fn pending(&mut self, now: Instant) -> Option<Instant> {
        if self.bulk_credit() < self.required && !self.snapshot {
            let start = *self.stalled.get_or_insert(now);
            Some(start + STARVATION)
        } else {
            None
        }
    }

    /// Arm the unchanged starvation deadline for a reserved repaint that is too large.
    pub fn pending_reserved_repaint(&mut self, now: Instant) -> Option<Instant> {
        if self.repaint_budget() < self.required && !self.snapshot {
            let start = *self.stalled.get_or_insert(now);
            Some(start + STARVATION)
        } else {
            None
        }
    }

    /// Mark snapshot catch-up after the one-shot starvation deadline fires.
    pub fn expire(&mut self, now: Instant) -> bool {
        if self
            .stalled
            .is_some_and(|start| now.duration_since(start) >= STARVATION)
        {
            self.snapshot = true;
            self.stalled = None;
        }
        self.snapshot
    }

    /// Whether returned credit requires reattachment for replay or a repaint.
    #[must_use]
    pub fn needs_snapshot(&self) -> bool {
        self.snapshot && self.bulk_credit() >= self.required
    }

    /// Resume raw replay at the unchanged cursor after a successful `ReadFrom`.
    /// Ring coverage is decided by the shim, which may send a repaint instead.
    pub fn resume_replay(&mut self) {
        self.snapshot = false;
        self.stalled = None;
        self.required = 1;
    }

    /// Park/retry catch-up without keeping a payload or starting an idle timer.
    pub fn retry_recovery(&mut self) {
        self.snapshot = true;
        self.stalled = None;
    }

    /// Commit a repaint; its byte length consumes credit but never advances seq.
    /// # Errors
    /// Rejects regression/overflow without mutation. Insufficient credit records
    /// the minimum repaint credit, without changing the cursor or consuming credit.
    pub fn repaint(&mut self, seq: u64, len: usize) -> Result<(), Error> {
        let bytes = u64::try_from(len).map_err(|_| Error::Overflow)?;
        if seq < self.cursor {
            return Err(Error::OutOfRange);
        }
        if bytes > self.bulk_credit() {
            // Remember the frame cost after detaching, so unchanged or still
            // insufficient credit cannot repeatedly request native serialization.
            self.required = bytes;
            return Err(Error::OutOfRange);
        }
        self.required = 1;
        self.cursor = seq;
        self.credit -= bytes;
        self.snapshot = false;
        self.stalled = None;
        Ok(())
    }

    /// Commit a key repaint from granted credit and raw bytes the Snapshot replaces.
    ///
    /// The separate reserve pays first. A larger Snapshot can borrow only from
    /// raw bytes sent since the previous repaint; the client drops that output
    /// when it accepts the replacement. Returned credit pays the borrow before
    /// it funds more output. A zero-byte repaint still costs one byte.
    /// # Errors
    /// Rejects regression, overflow, a Snapshot above the shim frame limit, or
    /// a repaint larger than its available credit plus replaceable raw output.
    pub fn repaint_reserved(&mut self, seq: u64, len: usize) -> Result<(), Error> {
        let bytes = u64::try_from(len).map_err(|_| Error::Overflow)?;
        if seq < self.cursor {
            return Err(Error::OutOfRange);
        }
        let cost = bytes.max(1);
        let frame_limit = u64::try_from(MAX_FRAME.saturating_sub(9)).unwrap_or(u64::MAX);
        if self.reserve_mode != RESERVE_ACTIVE
            || bytes > frame_limit
            || cost > self.repaint_budget()
        {
            self.required = cost;
            return Err(Error::OutOfRange);
        }
        let spent = cost.min(u64::from(self.repaint_reserve));
        let borrowed = cost - spent;
        let borrowed = u32::try_from(borrowed).map_err(|_| Error::Overflow)?;
        let repaint_debt = self
            .repaint_debt
            .checked_add(borrowed)
            .ok_or(Error::Overflow)?;
        self.required = 1;
        self.cursor = seq;
        self.credit -= spent;
        self.repaint_reserve -= u32::try_from(spent).map_err(|_| Error::Overflow)?;
        // This repaint replaces the raw tail already sent. Those bytes may
        // still be in flight for credit accounting, but cannot back another
        // repaint until the client returns their credit.
        self.raw_replacement_credit = 0;
        self.repaint_debt = repaint_debt;
        self.snapshot = false;
        self.stalled = None;
        Ok(())
    }

    /// Remaining bytes protected from raw output and available to a key repaint.
    #[must_use]
    pub fn reserved_credit(&self) -> u64 {
        if self.reserve_mode == RESERVE_ACTIVE {
            u64::from(self.repaint_reserve)
        } else {
            0
        }
    }

    /// Whether raw output has no credit, even if the relay has not read its next frame yet.
    #[must_use]
    pub fn bulk_starved(&self) -> bool {
        self.bulk_credit() == 0
    }

    /// Bulk allowance unavailable because the client has not returned output credit.
    ///
    /// This excludes Snapshot frames because a key repaint may borrow only from
    /// raw output that it replaces. The daemon compares it with
    /// [`KEY_REPAINT_BACKLOG`] so a quiet stream does not repaint after tiny writes.
    #[must_use]
    pub fn unreturned_output_credit(&self) -> u64 {
        u64::from(self.raw_in_flight)
    }

    /// Credit available to the next repaint, including raw output not replaced yet.
    #[must_use]
    pub fn repaint_budget(&self) -> u64 {
        if self.reserve_mode == RESERVE_ACTIVE {
            u64::from(self.repaint_reserve)
                .saturating_add(u64::from(self.raw_replacement_credit))
                .saturating_sub(u64::from(self.repaint_debt))
        } else {
            0
        }
    }

    /// Ordinary credit left after preserving the key-triggered repaint floor.
    fn bulk_credit(&self) -> u64 {
        if self.reserve_mode == RESERVE_ACTIVE {
            self.credit
                .saturating_sub(u64::from(self.repaint_reserve))
                .min(BULK_WINDOW)
        } else {
            self.credit
        }
    }

    /// Exclusive raw output offset queued to the server.
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }
}

#[cfg(test)]
#[path = "../tests/unit/relay.rs"]
mod tests;
