//! Bounded output history with absolute offsets; wrap changes retention, never identity.
#![forbid(unsafe_code)]
use std::{collections::VecDeque, io};
/// Default output retention, allocated lazily so idle sessions remain small.
pub const DEFAULT_CAPACITY: usize = 8 * 1024 * 1024;
/// A byte stream indexed from session creation, independently of ring wrap.
pub struct Ring {
    bytes: VecDeque<u8>,
    capacity: usize,
    head: u64,
}
impl Ring {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            bytes: VecDeque::new(),
            capacity,
            head: 0,
        }
    }
    #[must_use]
    #[cfg(feature = "process-per-user")]
    pub(crate) fn allocated_bytes(&self) -> usize {
        self.bytes.capacity()
    }
    #[must_use]
    pub fn head(&self) -> u64 {
        self.head
    }
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
    /// Append output without resetting its identity when the ring wraps.
    /// # Errors
    /// Fails rather than wrapping the absolute offset after `u64::MAX` bytes.
    pub fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.head = self
            .head
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("output offset exhausted"))?;
        let keep = bytes.len().min(self.capacity);
        let discard = self
            .bytes
            .len()
            .saturating_add(keep)
            .saturating_sub(self.capacity);
        self.bytes.drain(..discard);
        self.bytes.extend(&bytes[bytes.len() - keep..]);
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

#[cfg(test)]
#[path = "../tests/unit/ring.rs"]
mod checks;
