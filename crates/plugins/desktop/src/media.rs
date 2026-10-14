//! Shared owned desktop access units, bounds and fragment assembly deadline for source and server [D208,D232].
use bytes::Bytes;
use infraternal_protocol::desktop::MAX_VIDEO_BYTES;
use std::time::Duration;
pub type SessionId = [u8; 16];
#[derive(Clone, Debug)]
pub struct Video {
    pub sequence: u64,
    pub capture_ns: u64,
    pub keyframe: bool,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Forbidden,
    Unavailable,
    Limit,
    Invalid,
    Busy,
}

/// Active assembly budget; wholly idle connections never arm a deadline.
pub const ASSEMBLY_TIMEOUT: Duration = Duration::from_millis(250);
