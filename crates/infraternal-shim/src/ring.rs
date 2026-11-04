//! Bounded output history with absolute offsets; wrap changes retention, never identity.
#![forbid(unsafe_code)]
#[cfg(feature = "process-per-user")]
use std::sync::Arc;
use std::{collections::VecDeque, io};
/// Default output retention, allocated lazily so idle sessions remain small.
pub const DEFAULT_CAPACITY: usize = 8 * 1024 * 1024;
/// A byte stream indexed from session creation, independently of ring wrap.
pub struct Ring {
    bytes: VecDeque<u8>,
    capacity: usize,
    head: u64,
    #[cfg(feature = "process-per-user")]
    budget: Option<Arc<crate::terminal_memory::HostBudget>>,
    #[cfg(feature = "process-per-user")]
    charged: usize,
}
impl Ring {
    /// Creates an empty ring that will keep at most `capacity` bytes. No memory is
    /// allocated until output arrives, so idle sessions stay small.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            bytes: VecDeque::new(),
            capacity,
            head: 0,
            #[cfg(feature = "process-per-user")]
            budget: None,
            #[cfg(feature = "process-per-user")]
            charged: 0,
        }
    }
    /// Includes this ring's actual backing allocation in the user's pool.
    #[cfg(feature = "process-per-user")]
    pub(crate) fn set_budget(&mut self, budget: Arc<crate::terminal_memory::HostBudget>) {
        self.budget = Some(budget);
    }
    /// Bytes actually reserved by the backing buffer (not the bytes stored), which
    /// is what the user's memory pool is charged for.
    #[must_use]
    #[cfg(feature = "process-per-user")]
    pub(crate) fn allocated_bytes(&self) -> usize {
        self.bytes.capacity()
    }
    /// The absolute offset one past the newest byte: the total number of bytes ever
    /// appended. It only grows, and does not change when old bytes are dropped.
    #[must_use]
    pub fn head(&self) -> u64 {
        self.head
    }
    /// The absolute offset of the oldest byte still retained. Reads below this
    /// offset are no longer possible.
    #[must_use]
    pub fn start(&self) -> u64 {
        self.head - self.bytes.len() as u64
    }
    /// Borrow the complete stream from creation without allocating a replay
    /// copy. Missing origin bytes cannot certify reconstruction; the caller
    /// must also certify the historical geometry before replaying these slices.
    #[must_use]
    pub fn origin_slices(&self) -> Option<(&[u8], &[u8])> {
        (self.start() == 0).then_some(self.bytes.as_slices())
    }
    /// Borrow a bounded retained range across at most one physical wrap.
    /// Like `read`, the current head is a valid empty range, but stale and
    /// future offsets are refused. No temporary payload allocation is needed.
    #[cfg(feature = "process-per-user")]
    #[must_use]
    pub(crate) fn read_slices(&self, seq: u64, limit: usize) -> Option<(&[u8], &[u8])> {
        let offset = usize::try_from(seq.checked_sub(self.start())?).ok()?;
        let count = limit.min(self.bytes.len().checked_sub(offset)?);
        let (first, second) = self.bytes.as_slices();
        let second_at = offset.saturating_sub(first.len());
        let first_at = offset.min(first.len());
        let first = &first[first_at..first.len().min(first_at + count)];
        Some((first, &second[second_at..second_at + count - first.len()]))
    }
    /// Append output without resetting its identity when the ring wraps.
    /// # Errors
    /// Fails rather than wrapping the absolute offset after `u64::MAX` bytes.
    pub fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        let head = self
            .head
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("output offset exhausted"))?;
        // Shared hosts publish only after fallible pool accounting. Ordinary
        // rings retain the production publication order [243].
        #[cfg(not(feature = "process-per-user"))]
        {
            self.head = head;
        }
        let mut keep = bytes.len().min(self.capacity);
        let discard = self
            .bytes
            .len()
            .saturating_add(keep)
            .saturating_sub(self.capacity);
        self.bytes.drain(..discard);
        #[cfg(feature = "process-per-user")]
        {
            let needed = self.bytes.len() + keep;
            // Geometric VecDeque growth can double a non-power-of-two share.
            // Past the lazy VT prefix, commit small scale shares once: sparse
            // producers must not fault in more ring pages for hours. Large
            // single-session rings still grow lazily, bounded by their share.
            let precommit = needed > 4096 && self.capacity <= 128 * 1024;
            let reserve = if needed == 0 {
                0
            } else if precommit {
                self.capacity
            } else {
                needed.next_power_of_two().min(self.capacity)
            };
            let mut growth_refused = false;
            let old_capacity = self.bytes.capacity();
            if reserve > old_capacity {
                let growth = reserve - old_capacity;
                let reserved = self
                    .budget
                    .as_ref()
                    .is_none_or(|budget| budget.try_charge(growth));
                let mut grew = false;
                if reserved {
                    if self
                        .bytes
                        .try_reserve_exact(reserve - self.bytes.len())
                        .is_ok()
                    {
                        if precommit {
                            let retained = self.bytes.len();
                            self.bytes.resize(self.capacity, 0);
                            self.bytes.truncate(retained);
                        }
                        grew = true;
                    } else if let Some(budget) = &self.budget {
                        budget.release_charge(growth);
                    }
                } else {
                    growth_refused = true;
                }
                if grew {
                    let mut actual = self.bytes.capacity();
                    if actual > reserve
                        && self
                            .budget
                            .as_ref()
                            .is_some_and(|budget| !budget.try_charge(actual - reserve))
                    {
                        // VecDeque may round a request upward. Return that
                        // excess before admitting the ring's new bytes.
                        self.bytes.shrink_to(old_capacity);
                        actual = self.bytes.capacity();
                        growth_refused = true;
                    }
                    if let Some(budget) = &self.budget {
                        let charged_growth = actual.saturating_sub(old_capacity);
                        let reserved_growth = growth.min(charged_growth);
                        if growth > reserved_growth {
                            budget.release_charge(growth - reserved_growth);
                        }
                        if actual > reserve {
                            self.charged = self.charged.saturating_add(actual - reserve);
                        }
                        self.charged = self.charged.saturating_add(reserved_growth);
                    }
                }
            }
            if growth_refused || self.bytes.len().saturating_add(keep) > self.bytes.capacity() {
                keep = keep.min(self.capacity.min(self.bytes.capacity()));
                if keep < bytes.len() {
                    // A partial suffix has a gap before it; no older bytes
                    // can remain contiguous with its absolute stream offset.
                    self.bytes.clear();
                } else {
                    let room = self.bytes.capacity().saturating_sub(keep);
                    let discard = self.bytes.len().saturating_sub(room);
                    self.bytes.drain(..discard);
                }
            }
        }
        #[cfg(not(feature = "process-per-user"))]
        let _ = &mut keep;
        self.bytes.extend(&bytes[bytes.len() - keep..]);
        #[cfg(feature = "process-per-user")]
        {
            self.head = head;
        }
        Ok(())
    }
    /// Read at most limit bytes, or None if the offset is outside retained history.
    #[must_use]
    pub fn read(&self, seq: u64, limit: usize) -> Option<Vec<u8>> {
        if seq < self.start() || seq > self.head {
            return None;
        }
        let offset = usize::try_from(seq - self.start()).ok()?;
        Some(
            self.bytes
                .iter()
                .skip(offset)
                .take(limit)
                .copied()
                .collect(),
        )
    }
}

#[cfg(feature = "process-per-user")]
impl Drop for Ring {
    fn drop(&mut self) {
        if let Some(budget) = &self.budget {
            budget.release_charge(self.charged);
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/ring.rs"]
mod checks;
