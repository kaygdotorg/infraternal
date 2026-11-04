//! Shared owned desktop access units, bounds and fragment assembly deadline for source and server [D208,D232].
use bytes::Bytes;
use infraternal_protocol::desktop::MAX_VIDEO_BYTES;
use std::time::Duration;
/// A session's 16-byte identifier (a UUID's raw bytes).
pub type SessionId = [u8; 16];
/// One encoded video frame (an H.264 access unit) travelling from capture to viewers.
#[derive(Clone, Debug)]
pub struct Video {
    /// Increasing frame number. Zero is reserved and never valid.
    pub sequence: u64,
    /// When the picture was captured, in nanoseconds on the capture clock.
    pub capture_ns: u64,
    /// True if a viewer can start decoding from this frame.
    pub keyframe: bool,
    /// The encoded data; shared, so cloning does not copy it.
    pub bytes: Bytes,
}
impl Video {
    /// Validate once at the producer boundary before bytes enter shared storage.
    /// # Errors
    /// Rejects empty/oversize frames or the reserved sequence zero.
    pub fn validate(&self) -> Result<(), Error> {
        if self.sequence == 0 || self.bytes.is_empty() || self.bytes.len() > MAX_VIDEO_BYTES {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
}
/// Why a desktop operation was refused. Deliberately coarse so error text sent to
/// users reveals nothing about hosts, sessions or windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The caller may not do this (wrong owner, host not admitted, control held by another).
    Forbidden,
    /// The session, host or feature is missing, off or has stopped.
    Unavailable,
    /// A size, count or rate limit was reached.
    Limit,
    /// The request or data is malformed.
    Invalid,
    /// A queue is full; try again.
    Busy,
}

/// Active assembly budget; wholly idle connections never arm a deadline.
pub const ASSEMBLY_TIMEOUT: Duration = Duration::from_millis(250);
