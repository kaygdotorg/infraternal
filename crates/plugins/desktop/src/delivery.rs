//! Owner-selected QUIC carries both measured delivery candidates; stale writes retire only video [D232].
//!
//! Two ways to move one encoded video frame between the server and a peer over an
//! already-authenticated QUIC connection:
//!
//! - Reliable: each frame is written to a dedicated stream, preceded by a small
//!   header ([`Sender::Reliable`], read back with [`ReliableReader`]).
//! - Datagram: each frame is cut into fixed-size fragments sent as unreliable
//!   datagrams ([`Sender::Datagram`]); the receiver rebuilds them with
//!   [`crate::datagram::Reassembler`].
//!
//! Both give a frame about 250 ms (the assembly timeout) from the moment it was
//! queued. A frame that is already too old is skipped rather than sent, so
//! latency never grows; the caller then asks for a keyframe.
use crate::{
    datagram::Reassembler,
    session::{ASSEMBLY_TIMEOUT, Error, SessionId, Video},
};
use infraternal_protocol::desktop::{Delivery, Message};
use infraternal_protocol::{DecodeError, Frame, decode_frame, encode_frame_into};
use std::{io, time::Instant};

/// Report drops distinctly from network errors so the producer asks for IDR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    /// The whole frame was handed to the transport.
    Complete,
    /// The frame was too old, or took too long, and was dropped on purpose.
    Stale,
}
/// One caller owns the dedicated video lane and one reusable encoded buffer.
/// The existing authenticated connection and access rule admission stay with its owner.
pub enum Sender<'a> {
    /// Frames go over a dedicated QUIC send stream.
    Reliable(&'a mut quinn::SendStream),
    /// Frames go as QUIC datagrams on `connection`, tagged with `session`.
    Datagram {
        connection: &'a quinn::Connection,
        session: SessionId,
    },
}
/// Resets the stream on drop unless the write finished.
// A caller may cancel before the internal deadline. A partial reliable frame
// then owns a poisoned lane: resetting in Drop prevents the next write from
// being spliced into its abandoned body. The authenticated connection survives.
struct FrameWrite<'a> {
    stream: &'a mut quinn::SendStream,
    complete: bool,
}
impl Drop for FrameWrite<'_> {
    fn drop(&mut self) {
        if !self.complete {
            let _ = self.stream.reset(1u32.into());
        }
    }
}
impl Sender<'_> {
    /// Which delivery mode this sender uses.
    #[must_use]
    pub const fn mode(&self) -> Delivery {
        match self {
            Self::Reliable(_) => Delivery::Reliable,
            Self::Datagram { .. } => Delivery::Datagram,
        }
    }
    /// Complete one frame before writing another; skip already-stale work at the sender.
    /// In-flight reliable expiry resets the dedicated video direction, so a driver must
    /// reopen it for the same server-held session and request IDR. It must never splice
    /// a later frame onto an incomplete byte stream.
    /// # Errors
    /// Reports QUIC failure or invalid video. No payload bytes appear in errors.
    pub async fn send(
        &mut self,
        video: &Video,
        enqueued: Instant,
        encoded: &mut Vec<u8>,
    ) -> io::Result<Sent> {
        video.validate().map_err(|_| io::ErrorKind::InvalidData)?;
        let deadline = enqueued
            .checked_add(ASSEMBLY_TIMEOUT)
            .ok_or(io::ErrorKind::InvalidInput)?;
        if Instant::now() >= deadline {
            return Ok(Sent::Stale);
        }
        match self {
            Self::Reliable(stream) => {
                infraternal_protocol::desktop::encode_video_prefix_into(
                    video.sequence,
                    video.capture_ns,
                    video.keyframe,
                    &video.bytes,
                    encoded,
                )
                .map_err(|_| io::ErrorKind::InvalidData)?;
                // QUIC retains the immutable access-unit allocation directly.
                // Only the <=22-byte canonical header is copied per writer.
                let mut chunks = [bytes::Bytes::copy_from_slice(encoded), video.bytes.clone()];
                let mut write = FrameWrite {
                    stream,
                    complete: false,
                };
                match tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    write.stream.write_all_chunks(&mut chunks),
                )
                .await
                {
                    Ok(result) => {
                        result.map_err(|_| io::ErrorKind::BrokenPipe)?;
                        write.complete = true;
                        Ok(Sent::Complete)
                    }
                    Err(_) => Err(io::ErrorKind::TimedOut.into()),
                }
            }
            Self::Datagram {
                connection,
                session,
            } => {
                // Encode one fragment at a time into reused scratch; no per-frame
                // vector of fragment metadata or sender retransmission backlog.
                let total =
                    u32::try_from(video.bytes.len()).map_err(|_| io::ErrorKind::InvalidData)?;
                let send = async {
                    for (index, chunk) in video
                        .bytes
                        .chunks(crate::datagram::FRAGMENT_BYTES)
                        .enumerate()
                    {
                        let offset = u32::try_from(index * crate::datagram::FRAGMENT_BYTES)
                            .map_err(|_| io::ErrorKind::InvalidData)?;
                        let packet = Message::Fragment {
                            session_id: session,
                            sequence: video.sequence,
                            capture_ns: video.capture_ns,
                            keyframe: video.keyframe,
                            total,
                            offset,
                            bytes: chunk,
                        };
                        encode_frame_into(&Frame::Desktop(packet), encoded)
                            .map_err(|_| io::ErrorKind::InvalidData)?;
                        if connection
                            .max_datagram_size()
                            .is_none_or(|maximum| encoded.len() > maximum)
                        {
                            return Err(io::ErrorKind::Unsupported.into());
                        }
                        connection
                            .send_datagram_wait(bytes::Bytes::copy_from_slice(encoded))
                            .await
                            .map_err(|_| io::ErrorKind::BrokenPipe)?;
                    }
                    Ok(Sent::Complete)
                };
                match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), send).await
                {
                    Ok(result) => result,
                    Err(_) => Ok(Sent::Stale),
                }
            }
        }
    }
}
/// Cancellation-safe incremental reads keep partial progress in this owned object.
/// A healthy idle stream has no application timer; an active frame has 250ms.
pub struct ReliableReader {
    receive: quinn::RecvStream,
    /// Bytes of the frame being read (header first, then body).
    buffer: Vec<u8>,
    /// How many bytes of `buffer` are filled.
    filled: usize,
    /// Header length once it is fully read; 0 while the header is still incomplete.
    prefix: usize,
    /// Set from the first byte of a frame; none while the stream is idle.
    deadline: Option<tokio::time::Instant>,
}
impl ReliableReader {
    /// Wraps a QUIC receive stream.
    #[must_use]
    pub const fn new(receive: quinn::RecvStream) -> Self {
        Self {
            receive,
            buffer: Vec::new(),
            filled: 0,
            prefix: 0,
            deadline: None,
        }
    }
    /// Read one complete video frame. Header bounds/canonicality pass the shared
    /// decoder before resizing the body allocation.
    /// # Errors
    /// Refuses malformed frames, partial EOF and active-frame expiry.
    pub async fn next(&mut self) -> io::Result<Video> {
        loop {
            if self.prefix == 0 && self.buffer.len() == self.filled {
                self.buffer.push(0);
            }
            let target = if self.prefix == 0 {
                self.filled + 1
            } else {
                self.buffer.len()
            };
            let count = if let Some(deadline) = self.deadline {
                if let Ok(result) = tokio::time::timeout_at(
                    deadline,
                    self.receive.read(&mut self.buffer[self.filled..target]),
                )
                .await
                {
                    result.map_err(|_| io::ErrorKind::BrokenPipe)?
                } else {
                    let _ = self.receive.stop(1u32.into());
                    return Err(io::ErrorKind::TimedOut.into());
                }
            } else {
                self.receive
                    .read(&mut self.buffer[self.filled..target])
                    .await
                    .map_err(|_| io::ErrorKind::BrokenPipe)?
            };
            let Some(count) = count else {
                return Err(io::ErrorKind::UnexpectedEof.into());
            };
            if count == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.filled += count;
            if self.deadline.is_none() {
                self.deadline = Some(tokio::time::Instant::now() + ASSEMBLY_TIMEOUT);
            }
            if self.prefix == 0 {
                // Ask the shared codec to validate the prefix; no separate untrusted
                // length parser chooses allocation bounds in this transport.
                match decode_frame(&self.buffer[..self.filled]) {
                    Err(DecodeError::Incomplete) => {}
                    _ => return Err(io::ErrorKind::InvalidData.into()),
                }
                if self.buffer[self.filled - 1] & 0x80 != 0 {
                    continue;
                }
                self.prefix = self.filled;
                let length = self.buffer[..self.prefix]
                    .iter()
                    .enumerate()
                    .fold(0usize, |length, (index, byte)| {
                        length | ((usize::from(byte & 0x7f)) << (index * 7))
                    });
                self.buffer.resize(self.prefix + length, 0);
                continue;
            }
            if self.filled != self.buffer.len() {
                continue;
            }
            let decoded = decode_frame(&self.buffer).map_err(|_| io::ErrorKind::InvalidData)?;
            let Frame::Desktop(Message::Video {
                sequence,
                capture_ns,
                keyframe,
                bytes,
            }) = decoded.frame
            else {
                return Err(io::ErrorKind::InvalidData.into());
            };
            let payload_offset = self.buffer.len() - bytes.len();
            let metadata = (sequence, capture_ns, keyframe);
            // The validated frame becomes shared storage. Keep its tiny prefix
            // instead of copying a potentially 4 MiB access unit at fanout.
            let owned = bytes::Bytes::from(std::mem::take(&mut self.buffer));
            let video = Video {
                sequence: metadata.0,
                capture_ns: metadata.1,
                keyframe: metadata.2,
                bytes: owned.slice(payload_offset..),
            };
            self.filled = 0;
            self.prefix = 0;
            self.deadline = None;
            return Ok(video);
        }
    }
}
/// Feed a single complete datagram into an already-authorized session receiver.
/// # Errors
/// Refuses malformed/trailing wire data and foreign-session fragments.
pub fn receive_datagram(
    receiver: &mut Reassembler,
    wire: &[u8],
    now: Instant,
) -> Result<Option<Video>, Error> {
    let decoded = decode_frame(wire).map_err(|_| Error::Invalid)?;
    if decoded.wire_len != wire.len() {
        return Err(Error::Invalid);
    }
    let Frame::Desktop(message) = decoded.frame else {
        return Err(Error::Invalid);
    };
    receiver.push(message, now)
}
