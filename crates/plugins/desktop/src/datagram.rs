//! One bounded authenticated-session assembly skips missing H.264 deltas and requests IDR repair [D232].
use crate::media::{ASSEMBLY_TIMEOUT, Error, SessionId, Video};
use infraternal_protocol::desktop::{MAX_VIDEO_BYTES, Message};
use std::time::Instant;

/// A fixed fragment shape bounds bitmap bookkeeping even for adversarial input.
/// QUIC's 1200-byte minimum path MTU leaves room for this payload and framing.
pub const FRAGMENT_BYTES: usize = 1024;
/// The frame currently being put back together from fragments.
struct Assembly {
    sequence: u64,
    capture_ns: u64,
    keyframe: bool,
    /// Output buffer, allocated at its full size up front (bounded by the maximum video size).
    bytes: Vec<u8>,
    /// Bitmap with one bit per fragment already received.
    seen: Vec<u8>,
    /// Number of distinct fragments received so far.
    received: usize,
    /// When to give up on this frame.
    deadline: Instant,
}
/// Rebuilds video frames from datagram fragments for one session.
///
/// Fragments may be lost, duplicated or reordered. Only one frame is assembled at
/// a time. When a frame is lost, later delta frames are discarded until a
/// keyframe arrives, and a repair request is raised (see [`Reassembler::take_repair`]).
///
/// Admission binds this object to a server-owned UUID before any untrusted length is used.
pub struct Reassembler {
    session: SessionId,
    assembly: Option<Assembly>,
    /// Sequence number of the last frame delivered.
    last_sequence: u64,
    /// Delta frames are skipped until a keyframe arrives.
    waiting_keyframe: bool,
    /// A repair request is waiting to be taken.
    repair: bool,
    /// Highest sequence a repair was already requested for.
    repair_sequence: Option<u64>,
}
impl Reassembler {
    /// Creates an assembler that accepts fragments of session `session` only.
    #[must_use]
    pub const fn new(session: SessionId) -> Self {
        Self {
            session,
            assembly: None,
            last_sequence: 0,
            waiting_keyframe: true,
            repair: false,
            repair_sequence: None,
        }
    }
    // One missing access unit can have thousands of fragments. Coalesce only
    // duplicates of that sequence: a new missing frame must repair immediately,
    // including after a fully lost replacement IDR, without an idle timer.
    fn request_repair(&mut self, sequence: u64) {
        if self.repair_sequence.is_none_or(|last| sequence > last) {
            self.repair = true;
            self.repair_sequence = Some(sequence);
        }
    }
    /// Abandons the frame in progress, asks for a repair, and waits for a keyframe.
    fn lose(&mut self) {
        if let Some(frame) = self.assembly.take() {
            self.request_repair(frame.sequence);
        }
        self.waiting_keyframe = true;
    }
    /// The caller arms this deadline only while an incomplete frame exists.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.assembly.as_ref().map(|frame| frame.deadline)
    }
    /// No periodic timer: the transport invokes this only at the active deadline.
    pub fn expire(&mut self, now: Instant) {
        if self.deadline().is_some_and(|deadline| now >= deadline) {
            self.lose();
        }
    }
    /// Consume a coalesced request, then send a repair request on the reliable control lane.
    pub fn take_repair(&mut self) -> bool {
        std::mem::take(&mut self.repair)
    }
    /// Memory held by the frame being assembled, for accounting.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.assembly
            .as_ref()
            .map_or(0, |frame| frame.bytes.capacity() + frame.seen.capacity())
    }
    /// Validate shape, UUID and arithmetic before reserving one bounded access unit.
    /// Duplicate fragments are idempotent; metadata/byte conflicts are protocol errors.
    /// # Errors
    /// Rejects foreign-session, malformed or conflicting fragments without allocating from them.
    pub fn push(&mut self, message: Message<'_>, now: Instant) -> Result<Option<Video>, Error> {
        message.validate().map_err(|_| Error::Invalid)?;
        let Message::Fragment {
            session_id,
            sequence,
            capture_ns,
            keyframe,
            total,
            offset,
            bytes,
        } = message
        else {
            return Err(Error::Invalid);
        };
        if *session_id != self.session {
            return Err(Error::Forbidden);
        }
        let total = total as usize;
        let offset = offset as usize;
        if !offset.is_multiple_of(FRAGMENT_BYTES)
            || bytes.len() != FRAGMENT_BYTES.min(total - offset)
            || total > MAX_VIDEO_BYTES
        {
            return Err(Error::Invalid);
        }
        self.expire(now);
        if sequence <= self.last_sequence {
            return Ok(None);
        }
        if let Some(frame) = self.assembly.as_ref() {
            if sequence < frame.sequence {
                return Ok(None);
            }
            if sequence > frame.sequence {
                self.lose();
            }
        }
        if self.assembly.is_none() {
            if self.last_sequence.checked_add(1) != Some(sequence) {
                self.waiting_keyframe = true;
            }
            if self.waiting_keyframe && !keyframe {
                self.request_repair(sequence);
                return Ok(None);
            }
            let count = total.div_ceil(FRAGMENT_BYTES);
            self.assembly = Some(Assembly {
                sequence,
                capture_ns,
                keyframe,
                bytes: vec![0; total],
                seen: vec![0; count.div_ceil(8)],
                received: 0,
                deadline: now + ASSEMBLY_TIMEOUT,
            });
        }
        let frame = self.assembly.as_mut().ok_or(Error::Unavailable)?;
        if frame.sequence != sequence
            || frame.capture_ns != capture_ns
            || frame.keyframe != keyframe
            || frame.bytes.len() != total
        {
            return Err(Error::Invalid);
        }
        let index = offset / FRAGMENT_BYTES;
        let mask = 1 << (index % 8);
        let slot = &mut frame.seen[index / 8];
        let range = offset..offset + bytes.len();
        if *slot & mask != 0 {
            if &frame.bytes[range] != bytes {
                return Err(Error::Invalid);
            }
            return Ok(None);
        }
        *slot |= mask;
        frame.received += 1;
        frame.bytes[range].copy_from_slice(bytes);
        if frame.received != total.div_ceil(FRAGMENT_BYTES) {
            return Ok(None);
        }
        let frame = self.assembly.take().ok_or(Error::Unavailable)?;
        self.last_sequence = sequence;
        self.waiting_keyframe = false;
        if keyframe {
            self.repair = false;
            self.repair_sequence = None;
        }
        Ok(Some(Video {
            sequence,
            capture_ns,
            keyframe,
            // Transfer the completed assembly without a second access-unit copy.
            bytes: bytes::Bytes::from(frame.bytes),
        }))
    }
}
/// Emit exactly one fixed-shape fragment per callback, borrowing original encoded bytes.
/// # Errors
/// Refuses invalid source video before any fragments are exposed.
pub fn fragments<'a>(
    session: &'a SessionId,
    video: &'a Video,
    mut send: impl FnMut(Message<'a>) -> Result<(), Error>,
) -> Result<(), Error> {
    video.validate()?;
    let total = u32::try_from(video.bytes.len()).map_err(|_| Error::Invalid)?;
    for (index, bytes) in video.bytes.chunks(FRAGMENT_BYTES).enumerate() {
        let offset = u32::try_from(index * FRAGMENT_BYTES).map_err(|_| Error::Invalid)?;
        send(Message::Fragment {
            session_id: session,
            sequence: video.sequence,
            capture_ns: video.capture_ns,
            keyframe: video.keyframe,
            total,
            offset,
            bytes,
        })?;
    }
    Ok(())
}
