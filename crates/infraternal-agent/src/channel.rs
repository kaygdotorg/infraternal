//! Abstracts an already-authenticated leg-B byte channel; inherited socket trust and remote mTLS admission stay with callers [9][64], #78.

use std::{future::Future, io};

/// A full-duplex channel with exactly one reader and one serialized writer.
/// Implementations retain partial-read progress; cancellation of a partial write
/// requires retiring the entire connection to avoid frame interleaving.
pub trait Channel: Send + Sync {
    /// Active incomplete-frame budget; inherited trusted channels have none.
    /// Remote adapters supply five seconds. Wholly idle reads arm no timer.
    fn frame_timeout(&self) -> Option<std::time::Duration> {
        None
    }
    /// Retire all directions after partial-frame expiry; remote adapters wake readers/writers.
    fn retire(&self) {}
    /// Read ready bytes; an empty result is EOF.
    fn read(&self, bytes: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;
    /// Complete one already-encoded bounded frame.
    fn write(&self, bytes: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
}
