//! Frozen v1 local framing; lengths are validated before allocation [12][40].
#![forbid(unsafe_code)]
use std::io;

/// Maximum type plus payload length, excluding the four-byte prefix.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Capability bit 0 selects shim-owned input deduplication and PTY-write cursors.
pub const SEQUENCED_INPUT: u64 = 1;

/// Capability bit 1 selects independent writer cursors and concurrent viewers.
/// It requires `SEQUENCED_INPUT`; a selected writer identity survives peer loss.
pub const MULTI_WRITER: u64 = 2;
/// Capability bit 2 selects additive bounded Snapshots with an approximation flag.
pub const APPROXIMATE_SNAPSHOT: u64 = 4;
/// Capability bit 3 selects an ownership-only link. It neither selects a writer
/// nor reads output; closing it releases the window independently of data credit.
pub const SESSION_OWNER: u64 = 8;
/// Capability bit 7 selects a cleanup-only link whose reply proves shell reaping.
pub const SHELL_CLEANUP: u64 = 128;
/// Capability bit 4 permits a shared peer and bounded sequenced-input deferral.
/// It requires [`SEQUENCED_INPUT`] and [`MULTI_WRITER`]. Deferral applies
/// independently of peer selection mode; ordinary writer selection and
/// replacement remain unchanged.
pub const SHARED_WRITER: u64 = 16;
/// Capability bit 5 permits bounded renderer replies without typing cursors or geometry changes [307].
pub const QUERY_REPLIES: u64 = 32;
/// Capability bit 6 permits an explicit saved-shell shutdown request [314].
pub const CLOSE_SESSION: u64 = 64;

/// Frozen v1 messages. Byte vectors are owned only after length validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Hello {
        version: u16,
        caps: u64,
        session: [u8; 16],
        pid: u32,
        cols: u16,
        rows: u16,
        created: u64,
        head: u64,
        start: u64,
    },
    Attach(u64),
    Input(Vec<u8>),
    /// Additive 0x1E; server-arbitrated reply bytes, at most 1024 bytes.
    QueryReply(Vec<u8>),
    Output(u64, Vec<u8>),
    Resize {
        cols: u16,
        rows: u16,
        px_w: u16,
        px_h: u16,
    },
    ReadFrom(u64),
    SnapshotRequest,
    Snapshot(u64, Vec<u8>),
    /// Additive 0x1C, legal only after selecting `APPROXIMATE_SNAPSHOT`.
    SnapshotWithFlags(u64, u8, Vec<u8>),
    Signal(u8),
    /// Additive 0x1F; requires negotiated `CLOSE_SESSION`, with no payload.
    CloseSession,
    SequencedInput(u64, Vec<u8>),
    InputAck(u64),
    InputStateRequest,
    InputState(u64, u64),
    SelectWriter(u32),
    /// Additive 0x1D; shares an existing nonzero writer without evicting its ordinary peer.
    SelectSharedWriter(u32),
    Exited(i32, u64),
    ExitAck,
    /// Additive cleanup request, legal only on a `SHELL_CLEANUP` link.
    StopShell,
    /// Sent only after the shim has reaped its owned shell.
    ShellStopped,
    Error(u16, String),
}
/// Borrowed payload decoding for frame-scoped consumers; scalar layouts reuse
/// the frozen owned codec. No payload allocation precedes frame validation.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameRef<'a> {
    Input(&'a [u8]),
    Output(u64, &'a [u8]),
    Snapshot(u64, &'a [u8]),
    SequencedInput(u64, &'a [u8]),
    Owned(Frame),
}
impl<'a> FrameRef<'a> {
    /// Decode without copying hot-path payloads.
    /// # Errors
    /// Rejects exactly the same malformed layouts as `Frame::decode`.
    pub fn decode(body: &'a [u8]) -> io::Result<Self> {
        if body.len() > MAX_FRAME {
            return Err(invalid());
        }
        let (&kind, bytes) = body.split_first().ok_or_else(invalid)?;
        if kind == 0x10 {
            return Ok(Self::Input(bytes));
        }
        if matches!(kind, 0x11 | 0x15 | 0x17) {
            let mut payload = Payload(bytes);
            let seq = payload.u64()?;
            return Ok(match kind {
                0x11 => Self::Output(seq, payload.0),
                0x15 => Self::Snapshot(seq, payload.0),
                _ => Self::SequencedInput(seq, payload.0),
            });
        }
        Frame::decode(body).map(Self::Owned)
    }
    /// Cross an ownership boundary explicitly; immediate consumers stay borrowed.
    #[must_use]
    pub fn into_owned(self) -> Frame {
        match self {
            Self::Input(bytes) => Frame::Input(bytes.to_vec()),
            Self::Output(seq, bytes) => Frame::Output(seq, bytes.to_vec()),
            Self::Snapshot(seq, bytes) => Frame::Snapshot(seq, bytes.to_vec()),
            Self::SequencedInput(seq, bytes) => Frame::SequencedInput(seq, bytes.to_vec()),
            Self::Owned(frame) => frame,
        }
    }
    /// Input slices, including owned compatibility requests, without cloning.
    #[must_use]
    pub fn input(&self) -> Option<(Option<u64>, &[u8])> {
        match self {
            Self::Input(bytes) => Some((None, bytes)),
            Self::SequencedInput(seq, bytes) => Some((Some(*seq), bytes)),
            Self::Owned(Frame::Input(bytes)) => Some((None, bytes)),
            Self::Owned(Frame::SequencedInput(seq, bytes)) => Some((Some(*seq), bytes)),
            _ => None,
        }
    }
}
impl From<Frame> for FrameRef<'_> {
    fn from(frame: Frame) -> Self {
        Self::Owned(frame)
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid shim v1 frame")
}
struct Payload<'a>(&'a [u8]);
impl Payload<'_> {
    fn take<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let (value, rest) = self.0.split_at_checked(N).ok_or_else(invalid)?;
        self.0 = rest;
        value.try_into().map_err(|_| invalid())
    }
    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_le_bytes(self.take()?))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    fn bytes(&mut self) -> Vec<u8> {
        let bytes = self.0.to_vec();
        self.0 = &[];
        bytes
    }
}
impl Frame {
    /// Encode one complete frame.
    /// # Errors
    /// Rejects frames larger than the frozen limit.
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut wire = Vec::new();
        self.encode_into(&mut wire)?;
        Ok(wire)
    }
    /// Encode into reusable storage, rejecting oversized payloads before growth.
    /// # Errors
    /// Rejects frames beyond the frozen limit without changing the buffer.
    pub fn encode_into(&self, wire: &mut Vec<u8>) -> io::Result<()> {
        self.encode_mode::<false>(wire)
    }
    /// Encode retained output directly from a possibly wrapped ring. The
    /// complete frame size is validated before touching any preceding batch.
    /// # Errors
    /// Rejects payloads beyond the frozen frame bound without changing `wire`.
    #[cfg(feature = "process-per-user")]
    pub(crate) fn output_slices_into<const APPEND: bool>(
        seq: u64,
        first: &[u8],
        second: &[u8],
        wire: &mut Vec<u8>,
    ) -> io::Result<()> {
        let size = first
            .len()
            .checked_add(second.len())
            .and_then(|bytes| bytes.checked_add(9))
            .filter(|size| *size <= MAX_FRAME)
            .ok_or_else(invalid)?;
        let length = u32::try_from(size).map_err(|_| invalid())?;
        if !APPEND {
            wire.clear();
        }
        wire.reserve(size + 4);
        wire.extend_from_slice(&length.to_le_bytes());
        wire.push(0x11);
        wire.extend_from_slice(&seq.to_le_bytes());
        wire.extend_from_slice(first);
        wire.extend_from_slice(second);
        Ok(())
    }
    #[allow(clippy::too_many_lines)]
    fn encode_mode<const APPEND: bool>(&self, wire: &mut Vec<u8>) -> io::Result<()> {
        #[cfg(feature = "process-per-user")]
        if let Self::Output(seq, bytes) = self {
            return Self::output_slices_into::<APPEND>(*seq, bytes, &[], wire);
        }
        let size = match self {
            Self::QueryReply(bytes) => {
                if bytes.is_empty() || bytes.len() > 1024 {
                    return Err(invalid());
                }
                1 + bytes.len()
            }
            Self::Input(bytes) => 1 + bytes.len(),
            Self::Output(_, bytes) | Self::Snapshot(_, bytes) | Self::SequencedInput(_, bytes) => {
                9 + bytes.len()
            }
            Self::SnapshotWithFlags(_, flags, bytes) => {
                if flags & !1 != 0 {
                    return Err(invalid());
                }
                10 + bytes.len()
            }
            Self::Error(_, message) => 3 + message.len(),
            _ => 59,
        };
        if size > MAX_FRAME {
            return Err(invalid());
        }
        if !APPEND {
            wire.clear();
        }
        let start = wire.len();
        wire.resize(start + 4, 0);
        let body = wire;
        macro_rules! put {
            ($value:expr) => {
                body.extend_from_slice(&$value.to_le_bytes())
            };
        }
        match self {
            Self::Hello {
                version,
                caps,
                session,
                pid,
                cols,
                rows,
                created,
                head,
                start,
            } => {
                body.push(1);
                put!(version);
                put!(caps);
                body.extend_from_slice(session);
                put!(pid);
                put!(cols);
                put!(rows);
                put!(created);
                put!(head);
                put!(start);
            }
            Self::Attach(caps) => {
                body.push(2);
                put!(caps);
            }
            Self::QueryReply(bytes) => {
                body.push(0x1e);
                body.extend_from_slice(bytes);
            }
            Self::Input(bytes) => {
                body.push(0x10);
                body.extend_from_slice(bytes);
            }
            Self::Output(seq, bytes) | Self::Snapshot(seq, bytes) => {
                body.push(if matches!(self, Self::Output(..)) {
                    0x11
                } else {
                    0x15
                });
                put!(seq);
                body.extend_from_slice(bytes);
            }
            Self::SnapshotWithFlags(seq, flags, bytes) => {
                body.push(0x1c);
                put!(seq);
                body.push(*flags);
                body.extend_from_slice(bytes);
            }
            Self::Resize {
                cols,
                rows,
                px_w,
                px_h,
            } => {
                body.push(0x12);
                put!(cols);
                put!(rows);
                put!(px_w);
                put!(px_h);
            }
            Self::ReadFrom(seq) => {
                body.push(0x13);
                put!(seq);
            }
            Self::SnapshotRequest => body.push(0x14),
            Self::CloseSession => body.push(0x1f),
            Self::Signal(signal) => {
                body.push(0x16);
                body.push(*signal);
            }
            Self::SequencedInput(seq, bytes) => {
                body.push(0x17);
                put!(seq);
                body.extend_from_slice(bytes);
            }
            Self::InputAck(seq) => {
                body.push(0x18);
                put!(seq);
            }
            Self::InputStateRequest => body.push(0x19),
            Self::InputState(written, accepted) => {
                body.push(0x1a);
                put!(written);
                put!(accepted);
            }
            Self::SelectWriter(writer) => {
                body.push(0x1b);
                put!(writer);
            }
            Self::SelectSharedWriter(writer) => {
                body.push(0x1d);
                put!(writer);
            }
            Self::Exited(status, seq) => {
                body.push(0x20);
                put!(status);
                put!(seq);
            }
            Self::ExitAck => body.push(0x21),
            Self::StopShell => body.push(0x22),
            Self::ShellStopped => body.push(0x23),
            Self::Error(code, message) => {
                body.push(0x7f);
                put!(code);
                body.extend_from_slice(message.as_bytes());
            }
        }
        let size = u32::try_from(body.len() - start - 4).map_err(|_| invalid())?;
        body[start..start + 4].copy_from_slice(&size.to_le_bytes());
        Ok(())
    }
    /// Decode a complete type plus payload (without the length prefix).
    /// # Errors
    /// Rejects unknown types, invalid UTF-8, and noncanonical payload lengths.
    pub fn decode(body: &[u8]) -> io::Result<Self> {
        if body.len() > MAX_FRAME {
            return Err(invalid());
        }
        let (&kind, bytes) = body.split_first().ok_or_else(invalid)?;
        let mut p = Payload(bytes);
        let frame = match kind {
            1 => Self::Hello {
                version: p.u16()?,
                caps: p.u64()?,
                session: p.take()?,
                pid: u32::from_le_bytes(p.take()?),
                cols: p.u16()?,
                rows: p.u16()?,
                created: p.u64()?,
                head: p.u64()?,
                start: p.u64()?,
            },
            2 => Self::Attach(p.u64()?),
            0x10 => Self::Input(p.bytes()),
            0x1e if !p.0.is_empty() && p.0.len() <= 1024 => Self::QueryReply(p.bytes()),
            0x11 => Self::Output(p.u64()?, p.bytes()),
            0x12 => Self::Resize {
                cols: p.u16()?,
                rows: p.u16()?,
                px_w: p.u16()?,
                px_h: p.u16()?,
            },
            0x13 => Self::ReadFrom(p.u64()?),
            0x14 => Self::SnapshotRequest,
            0x15 => Self::Snapshot(p.u64()?, p.bytes()),
            0x16 => Self::Signal(p.take::<1>()?[0]),
            0x1f => Self::CloseSession,
            0x17 => Self::SequencedInput(p.u64()?, p.bytes()),
            0x18 => Self::InputAck(p.u64()?),
            0x19 => Self::InputStateRequest,
            0x1a => Self::InputState(p.u64()?, p.u64()?),
            0x1b => Self::SelectWriter(u32::from_le_bytes(p.take()?)),
            0x1d => Self::SelectSharedWriter(u32::from_le_bytes(p.take()?)),
            0x1c => {
                let seq = p.u64()?;
                let flags = p.take::<1>()?[0];
                if flags & !1 != 0 {
                    return Err(invalid());
                }
                Self::SnapshotWithFlags(seq, flags, p.bytes())
            }
            0x20 => Self::Exited(i32::from_le_bytes(p.take()?), p.u64()?),
            0x21 => Self::ExitAck,
            0x22 => Self::StopShell,
            0x23 => Self::ShellStopped,
            0x7f => Self::Error(
                p.u16()?,
                String::from_utf8(p.bytes()).map_err(|_| invalid())?,
            ),
            _ => return Err(invalid()),
        };
        if !p.0.is_empty() {
            return Err(invalid());
        }
        Ok(frame)
    }
}
/// Incremental stream decoder; callers must not feed more than one bounded frame at once.
#[derive(Default)]
pub struct Decoder {
    bytes: Vec<u8>,
}
impl Decoder {
    #[cfg(feature = "process-per-user")]
    pub(crate) fn allocated_bytes(&self) -> usize {
        self.bytes.capacity()
    }
    #[cfg(feature = "process-per-user")]
    pub(crate) fn growth_bound(&self, incoming: usize) -> usize {
        let needed = self.bytes.len().saturating_add(incoming);
        if needed <= self.bytes.capacity() {
            0
        } else {
            self.bytes.capacity().saturating_mul(2).max(needed).max(8) - self.bytes.capacity()
        }
    }
    /// Consume bytes and return complete frames, preserving an incomplete suffix.
    /// # Errors
    /// Rejects invalid frames and storage beyond one maximum-sized frame.
    pub fn feed(&mut self, bytes: &[u8]) -> io::Result<Vec<Frame>> {
        let mut frames = Vec::new();
        self.feed_with(bytes, |frame| {
            frames.push(frame.into_owned());
            Ok(())
        })?;
        Ok(frames)
    }

    /// Consume complete frames before reusing bounded receive storage. The
    /// callback cannot retain borrowed payloads across the next frame.
    /// # Errors
    /// Returns framing or callback errors; callers disconnect on either.
    pub fn feed_with(
        &mut self,
        bytes: &[u8],
        mut consume: impl FnMut(FrameRef<'_>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.feed_until(bytes, |frame| {
            consume(frame)?;
            Ok(true)
        })?;
        Ok(())
    }

    /// Consume a prefix, retaining the complete current frame when the callback
    /// returns false. The caller retains the unused suffix and retries, including
    /// with an empty slice, before reading more bytes. No payload is copied on pause.
    /// # Errors
    /// Returns framing or callback errors without accepting a deferred frame.
    pub fn feed_until(
        &mut self,
        bytes: &[u8],
        mut consume: impl FnMut(FrameRef<'_>) -> io::Result<bool>,
    ) -> io::Result<usize> {
        // Copy contiguous runs rather than repeatedly parsing the same length
        // for every payload byte. At most one validated frame is retained.
        let mut rest = bytes;
        loop {
            let target = if self.bytes.len() < 4 {
                4
            } else {
                let length =
                    u32::from_le_bytes(self.bytes[..4].try_into().map_err(|_| invalid())?) as usize;
                if length == 0 || length > MAX_FRAME {
                    return Err(invalid());
                }
                length + 4
            };
            if self.bytes.len() == target && target > 4 {
                if !consume(FrameRef::decode(&self.bytes[4..])?)? {
                    return Ok(bytes.len() - rest.len());
                }
                self.bytes.clear();
                continue;
            }
            if rest.is_empty() {
                return Ok(bytes.len());
            }
            let count = (target - self.bytes.len()).min(rest.len());
            self.bytes.extend_from_slice(&rest[..count]);
            rest = &rest[count..];
            if self.bytes.len() >= 4 {
                let length =
                    u32::from_le_bytes(self.bytes[..4].try_into().map_err(|_| invalid())?) as usize;
                if length == 0 || length > MAX_FRAME {
                    return Err(invalid());
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/frame.rs"]
mod checks;
