//! Frozen v1 local framing; lengths are validated before allocation [12][40].
#![forbid(unsafe_code)]
use std::io;

/// Maximum type plus payload length, excluding the four-byte prefix.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Capability bit 0 selects shim-owned input deduplication and PTY-write cursors.
pub const SEQUENCED_INPUT: u64 = 1;

/// Capability bit 1 selects additive bounded Snapshots with an approximation flag.
pub const APPROXIMATE_SNAPSHOT: u64 = 2;

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
    /// Additive 0x1B, legal only after selecting `APPROXIMATE_SNAPSHOT`.
    SnapshotWithFlags(u64, u8, Vec<u8>),
    Signal(u8),
    SequencedInput(u64, Vec<u8>),
    InputAck(u64),
    InputStateRequest,
    InputState(u64, u64),
    Exited(i32, u64),
    ExitAck,
    Error(u16, String),
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
    #[allow(clippy::too_many_lines)]
    pub fn encode_into(&self, wire: &mut Vec<u8>) -> io::Result<()> {
        let size = match self {
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
        wire.clear();
        wire.resize(4, 0);
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
                body.push(0x1b);
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
            Self::Exited(status, seq) => {
                body.push(0x20);
                put!(status);
                put!(seq);
            }
            Self::ExitAck => body.push(0x21),
            Self::Error(code, message) => {
                body.push(0x7f);
                put!(code);
                body.extend_from_slice(message.as_bytes());
            }
        }
        let size = u32::try_from(body.len() - 4).map_err(|_| invalid())?;
        body[..4].copy_from_slice(&size.to_le_bytes());
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
            0x17 => Self::SequencedInput(p.u64()?, p.bytes()),
            0x18 => Self::InputAck(p.u64()?),
            0x19 => Self::InputStateRequest,
            0x1a => Self::InputState(p.u64()?, p.u64()?),
            0x1b => {
                let seq = p.u64()?;
                let flags = p.take::<1>()?[0];
                if flags & !1 != 0 {
                    return Err(invalid());
                }
                Self::SnapshotWithFlags(seq, flags, p.bytes())
            }
            0x20 => Self::Exited(i32::from_le_bytes(p.take()?), p.u64()?),
            0x21 => Self::ExitAck,
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
    /// Consume bytes and return complete frames, preserving an incomplete suffix.
    /// # Errors
    /// Rejects invalid frames and storage beyond one maximum-sized frame.
    pub fn feed(&mut self, bytes: &[u8]) -> io::Result<Vec<Frame>> {
        let mut frames = Vec::new();
        // Process bytewise to bound storage even for many coalesced frames. Socket
        // reads are capped at 16 KiB; this never allocates using untrusted lengths.
        for &byte in bytes {
            self.bytes.push(byte);
            if self.bytes.len() >= 4 {
                let length =
                    u32::from_le_bytes(self.bytes[..4].try_into().map_err(|_| invalid())?) as usize;
                if length == 0 || length > MAX_FRAME {
                    return Err(invalid());
                }
                if self.bytes.len() == length + 4 {
                    frames.push(Frame::decode(&self.bytes[4..])?);
                    self.bytes.clear();
                }
            }
        }
        Ok(frames)
    }
}

#[cfg(test)]
#[path = "../tests/unit/frame.rs"]
mod checks;
