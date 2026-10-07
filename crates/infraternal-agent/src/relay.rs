//! Offset and credit invariants for a bounded terminal relay [13][41][81].
//!
//! This state owns no terminal bytes: retention belongs to the shim. A transport
//! may hold one bounded frame while credit is exhausted. After 250 ms with
//! pending output it detaches from the shim, letting the shim update its screen
//! and ring, and requests replay when credit returns. No idle timer runs.

use std::{
    ops::Range,
    time::{Duration, Instant},
};

/// The wire catch-up threshold; schedule a single deadline only for pending data.
pub const STARVATION: Duration = Duration::from_millis(250);

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
    stalled: Option<Instant>,
    snapshot: bool,
    required: u64,
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
            stalled: None,
            snapshot: false,
            required: 1,
        }
    }

    /// Grant bounded cumulative credit. Overflow is a protocol error.
    /// # Errors
    /// Rejects a credit counter overflow without mutating state.
    pub fn grant(&mut self, bytes: u32) -> Result<(), Error> {
        self.credit = self
            .credit
            .checked_add(u64::from(bytes))
            .ok_or(Error::Overflow)?;
        if self.credit >= self.required {
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
        let available = usize::try_from(self.credit).unwrap_or(usize::MAX);
        Ok(skip..skip + (len - skip).min(available))
    }

    /// Commit a successfully queued raw output suffix.
    /// # Errors
    /// Rejects insufficient credit or offset overflow without mutating state.
    pub fn forward(&mut self, len: usize) -> Result<(), Error> {
        let next = end(self.cursor, len)?;
        let bytes = u64::try_from(len).map_err(|_| Error::Overflow)?;
        if bytes > self.credit || self.snapshot {
            return Err(Error::OutOfRange);
        }
        self.cursor = next;
        self.credit -= bytes;
        self.stalled = None;
        Ok(())
    }

    /// Record an unaffordable pending frame; callers arm this one-shot deadline.
    /// Calling again does not postpone catch-up.
    pub fn pending(&mut self, now: Instant) -> Option<Instant> {
        if self.credit < self.required && !self.snapshot {
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
    pub const fn needs_snapshot(&self) -> bool {
        self.snapshot && self.credit >= self.required
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
        if bytes > self.credit {
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

    /// Exclusive raw output offset queued to the server.
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }
}

#[cfg(test)]
#[path = "../tests/unit/relay.rs"]
mod tests;
