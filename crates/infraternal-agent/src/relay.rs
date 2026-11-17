//! Offset and credit invariants for a bounded terminal relay [13][41][81][D381].
//!
//! This state owns no terminal bytes: retention belongs to the shim. A transport
//! may hold one bounded frame while credit is exhausted. After 250 ms with
//! pending output it detaches from the shim, letting the shim update its screen
//! and ring, and requests replay when credit returns. No idle timer runs.
//!
//! Raw output may spend only the ordinary 1 MiB bulk window. A relay attached
//! for the tracer also protects up to 64 KiB for an input-triggered repaint.
//! The reserve is set up from the opening grant only, and only from credit that
//! cannot be a refund (see [`Output::grant`]): the first Credit, plus the part
//! of the second that exceeds every byte charged so far. The one exception is
//! the server's 16 KiB shadow-priming split, whose remainder completes the
//! opening first. A legacy 1 MiB grant keeps its full bulk allowance even after
//! that output's credit returns. A
//! Snapshot spends that reserve first, then unused capped bulk credit, then
//! credit from unreturned raw Output that the client discards when it accepts
//! the Snapshot. Each granted byte can fund at most one sent frame: a raw byte
//! backs at most one replacement, and borrowed bytes become debt until credit
//! returns. Returned credit pays repaint debt before it funds more output.
//! Raw bytes that the leg-B writer drops because a key Snapshot replaces them
//! never reach the client, so the client can never return their credit. The
//! writer refunds them instead, and the daemon grants that refund exactly like
//! returned credit (#477, J799; see `daemon_writer::Refunds`).
//!
//! Key repaints run only once the reserve is ACTIVE, that is once the client
//! has proved it granted the bulk window plus the reserve (today the browser).
//! While negotiation is pending, and for a client that only ever grants the
//! legacy window (native clients), the repaint budget is zero: a key never
//! replaces raw output, so such a client keeps exact raw delivery and every
//! byte arrives once, in order. A browser whose shadow-split opening grant
//! completes later switches to ACTIVE in [`Output::grant`] and its next flood key
//! repaints; raw bytes sent before that switch may then be replaced, because
//! they were paid from that same client's confirmed window.
//! Snapshots stay under the shim's 1 MiB frame cap. The unchanged 250 ms path
//! uses ordinary bulk credit, and every `Output` owns its own budgets. Input
//! cannot create credit: while a repaint is pending, later keys coalesce to the
//! latest input offset, and each Snapshot must fit the remaining reserve, unused
//! bulk credit and replaceable raw bytes after outstanding debt. Repaint
//! accounting is per stream, so one session never spends or returns another
//! session's credit. The terminal writer keeps each key's shim-confirmed
//! acknowledgment ahead of the Snapshot containing its echo. A trusted remote
//! cursor rebase clears grantable credit before the ordered reissue, but keeps
//! the negotiated reserve mode and outstanding replacement/debt accounting; a
//! rebase during setup restarts setup from the reissued credit.

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
/// Reserve setup state before the attachment's first Credit.
const RESERVE_WAITING_FOR_INITIAL_CREDIT: u8 = 1;
/// Reserve setup state after the opening grant proved the repaint budget is available.
const RESERVE_ACTIVE: u8 = 2;
/// Reserve setup ended without a reserve: the opening grant did not cover the
/// bulk window plus the reserve, so the client keeps exact raw delivery.
const RESERVE_LEGACY: u8 = 3;
/// Reserve setup after a first Credit smaller than the reserve: the server's
/// shadow-priming split, whose next Credit completes the opening grant first.
const RESERVE_WAITING_FOR_SPLIT_REMAINDER: u8 = 4;
/// Reserve setup after a first Credit short of the full opening grant: the next
/// Credit settles setup, counted as a refund first.
const RESERVE_WAITING_TO_SETTLE: u8 = 5;
/// The full opening grant of a client that sets the repaint reserve aside.
const RESERVED_OPENING: u64 = BULK_WINDOW + REPAINT_RESERVE as u64;

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
    /// ACTIVE: unspent portion of the initial repaint reserve, restored by
    /// returned credit. During reserve setup (no reserve exists yet) it holds
    /// the credit counted as opening grant so far, which keeps `Output` small.
    repaint_reserve: u32,
    /// ACTIVE: repaint bytes borrowed from raw output, paid before later
    /// credit is usable. During reserve setup (no repaint can borrow yet) it
    /// holds the Output and Snapshot bytes charged since attach: nothing
    /// returns before the grant that settles setup, so this bounds how much
    /// of that grant can be a refund.
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

    /// Rebase on the server-confirmed client cursor after a remote route reset.
    ///
    /// The server follows this command with the credit currently available on
    /// that route, so discard grantable credit and the reserve balance before
    /// accepting it. Keep the negotiated reserve mode and outstanding raw
    /// replacement/debt accounting: queued raw output may still be skipped by
    /// the replacement Snapshot, and a borrowed byte must remain paid only once.
    /// The trusted cursor starts a fresh catch-up decision without changing
    /// any credit or allowing the reset itself to fund a repaint.
    pub fn reset_cursor(&mut self, cursor: u64) {
        self.cursor = cursor;
        self.credit = 0;
        if self.setting_up() {
            // The server's reissued credit is a fresh view of the client's
            // window, so reserve setup starts over from it.
            self.reserve_mode = RESERVE_WAITING_FOR_INITIAL_CREDIT;
            self.repaint_debt = 0;
        }
        self.repaint_reserve = 0;
        self.stalled = None;
        self.snapshot = false;
        self.required = 1;
    }

    /// Grant bounded credit, paying any replacement repaint debt first.
    ///
    /// A Credit frame does not say whether it is fresh window or returned
    /// output, so reserve setup decides from the opening grant alone, and only
    /// from what cannot be a refund (#477, J693):
    ///
    /// - The first Credit is always opening credit: nothing can be charged
    ///   before it. One covering the bulk window plus the reserve activates the
    ///   reserve at once.
    /// - Otherwise the second Credit settles setup. It is counted as a refund
    ///   first, up to every Output and Snapshot byte charged so far, and only
    ///   the rest as opening credit. Counted opening credit then never exceeds
    ///   the client's real window, so a plain 1 MiB client can never be talked
    ///   into reserve mode by how its refunds happen to be batched.
    /// - The one exception is the server's own shadow-priming split, which
    ///   sends a first Credit smaller than the reserve (16 KiB) and the rest
    ///   later. There the second Credit completes the opening first and only
    ///   its excess is a refund. A refund it hides is at most that first
    ///   Credit, so the error stays below the reserve and a 1 MiB window still
    ///   cannot reach the full opening.
    ///
    /// Setup that ends short of the full opening is a legacy window for the
    /// rest of the attachment: exact raw delivery, never a key repaint.
    /// # Errors
    /// Rejects a credit counter overflow without mutating state.
    pub fn grant(&mut self, bytes: u32) -> Result<(), Error> {
        let setting_up = self.setting_up();
        // During setup `repaint_debt` counts setup charges, not borrowed bytes.
        let repaid = if setting_up {
            0
        } else {
            bytes.min(self.repaint_debt)
        };
        let available = bytes - repaid;
        let credit = self
            .credit
            .checked_add(u64::from(available))
            .ok_or(Error::Overflow)?;
        self.credit = credit;
        self.repaint_debt -= repaid;
        let mut returned = bytes;
        if setting_up {
            let opening = u64::from(self.repaint_reserve);
            let fresh = match self.reserve_mode {
                RESERVE_WAITING_FOR_INITIAL_CREDIT => u64::from(bytes),
                RESERVE_WAITING_FOR_SPLIT_REMAINDER => {
                    u64::from(bytes).min(RESERVED_OPENING.saturating_sub(opening))
                }
                _ => u64::from(bytes).saturating_sub(u64::from(self.repaint_debt)),
            };
            returned = bytes - u32::try_from(fresh).map_err(|_| Error::Overflow)?;
            let opening = opening.saturating_add(fresh);
            if opening >= RESERVED_OPENING {
                // Early raw output may already have spent part of the extra
                // credit. Only currently unspent credit can be protected as
                // reserve; replaced raw bytes remain a separate way to pay for
                // the Snapshot.
                self.repaint_reserve =
                    REPAINT_RESERVE.min(u32::try_from(self.credit).unwrap_or(u32::MAX));
                self.repaint_debt = 0;
                self.reserve_mode = RESERVE_ACTIVE;
            } else if self.reserve_mode == RESERVE_WAITING_FOR_INITIAL_CREDIT {
                // `opening` is this first Credit, below the full opening grant.
                self.repaint_reserve = u32::try_from(opening).map_err(|_| Error::Overflow)?;
                self.reserve_mode = if bytes < REPAINT_RESERVE {
                    RESERVE_WAITING_FOR_SPLIT_REMAINDER
                } else {
                    RESERVE_WAITING_TO_SETTLE
                };
            } else {
                self.repaint_reserve = 0;
                self.repaint_debt = 0;
                self.reserve_mode = RESERVE_LEGACY;
            }
        } else if self.reserve_mode == RESERVE_ACTIVE {
            self.repaint_reserve = self
                .repaint_reserve
                .saturating_add(available)
                .min(REPAINT_RESERVE);
        }
        // Returned credit pays raw bytes in flight first, which can only
        // understate what a later repaint may replace.
        let raw_repaid = returned.min(self.raw_in_flight);
        let already_replaced = self.raw_in_flight - self.raw_replacement_credit;
        self.raw_replacement_credit -= raw_repaid.saturating_sub(already_replaced);
        self.raw_in_flight -= raw_repaid;
        if self.bulk_credit() >= self.required {
            self.stalled = None;
        }
        Ok(())
    }

    /// Whether reserve setup still waits for the opening grant to settle.
    const fn setting_up(&self) -> bool {
        matches!(
            self.reserve_mode,
            RESERVE_WAITING_FOR_INITIAL_CREDIT
                | RESERVE_WAITING_FOR_SPLIT_REMAINDER
                | RESERVE_WAITING_TO_SETTLE
        )
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
        self.note_setup_charge(bytes);
        self.raw_in_flight = raw_in_flight;
        self.raw_replacement_credit = raw_replacement_credit;
        self.stalled = None;
        Ok(())
    }

    /// Take back the newest raw forward, which will never reach the client.
    ///
    /// A key repaint may discard the one raw frame the daemon staged for its
    /// writer. [`Self::forward`] already charged those bytes and moved the
    /// cursor past them, but they are never sent: the client can never return
    /// their credit, so the bulk window would shrink by that much for the rest
    /// of the attachment, and a recovery that resumed at the cursor would skip
    /// them, a gap (#477, J794). Retracting undoes that forward exactly, as if
    /// the frame had never been read. Only the newest forward may be retracted,
    /// so `seq + len` must equal the cursor.
    /// # Errors
    /// Rejects a range that does not end at the cursor, or overflow, without
    /// mutating state.
    pub fn retract(&mut self, seq: u64, len: usize) -> Result<(), Error> {
        if end(seq, len)? != self.cursor {
            return Err(Error::OutOfRange);
        }
        let bytes = u64::try_from(len).map_err(|_| Error::Overflow)?;
        let raw_bytes = u32::try_from(bytes).map_err(|_| Error::Overflow)?;
        let credit = self.credit.checked_add(bytes).ok_or(Error::Overflow)?;
        self.cursor = seq;
        self.credit = credit;
        if self.setting_up() {
            // During setup `repaint_debt` counts the bytes charged so far.
            self.repaint_debt = self.repaint_debt.saturating_sub(raw_bytes);
        }
        // Returned credit may already have paid part of these counters down;
        // saturating only understates what a later repaint may replace.
        self.raw_in_flight = self.raw_in_flight.saturating_sub(raw_bytes);
        self.raw_replacement_credit = self.raw_replacement_credit.saturating_sub(raw_bytes);
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
        self.note_setup_charge(bytes);
        self.snapshot = false;
        self.stalled = None;
        Ok(())
    }

    /// Count bytes charged to the client while reserve setup waits, so the
    /// grant that settles setup can tell how much of it may be a refund.
    fn note_setup_charge(&mut self, bytes: u64) {
        if self.setting_up() {
            let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
            self.repaint_debt = self.repaint_debt.saturating_add(bytes);
        }
    }

    /// Commit a key repaint from granted credit and raw bytes the Snapshot replaces.
    ///
    /// Only an ACTIVE reserve funds a repaint (see the module docs): its
    /// separate reserve pays first, then unused capped bulk credit, then the
    /// Snapshot borrows from raw bytes sent since the previous repaint, which
    /// the client drops when it accepts the replacement. Returned credit pays
    /// the borrow before funding more output. A zero-byte repaint still costs
    /// one byte.
    /// # Errors
    /// Rejects a relay whose reserve is not ACTIVE (pending or legacy window),
    /// regression, overflow, a Snapshot above the shim frame limit, or a
    /// repaint larger than its available credit plus replaceable raw output.
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
        let reserve_spent = cost.min(u64::from(self.repaint_reserve));
        let bulk_spent = (cost - reserve_spent).min(self.bulk_credit());
        let borrowed = cost - reserve_spent - bulk_spent;
        let borrowed = u32::try_from(borrowed).map_err(|_| Error::Overflow)?;
        let repaint_debt = self
            .repaint_debt
            .checked_add(borrowed)
            .ok_or(Error::Overflow)?;
        self.required = 1;
        self.cursor = seq;
        self.credit -= reserve_spent + bulk_spent;
        self.repaint_reserve -= u32::try_from(reserve_spent).map_err(|_| Error::Overflow)?;
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

    /// Credit available to a repaint, including raw output it can replace.
    ///
    /// Zero unless the reserve is ACTIVE, so the daemon never starts a key
    /// repaint for a pending or legacy-window client (#477, J637).
    #[must_use]
    pub fn repaint_budget(&self) -> u64 {
        if self.reserve_mode == RESERVE_ACTIVE {
            u64::from(self.repaint_reserve)
                .saturating_add(self.bulk_credit())
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
