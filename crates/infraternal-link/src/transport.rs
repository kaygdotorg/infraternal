//! The bounded leg-B frame codec over any [`Channel`]: one reader and one
//! writer per link, with reusable buffers [9][41].
//!
//! How to use it: keep one [`Receive`] per channel and call
//! [`Receive::next`] for each frame (or `next_wire` for an owned packet, with
//! the `native-streams` feature); keep one [`Transmit`] per channel and
//! serialise calls to [`Transmit::send`]. The channel decides the framing:
//! native QUIC streams carry raw frames, every other channel the mux envelope.
//! The inherited-socket channel itself stays with the infraternal agent; this
//! module has no file descriptors, so it builds for every client (#580).

#[cfg(feature = "native-streams")]
use bytes::{Buf, Bytes, BytesMut};
use infraternal_plugin_api::channel::Channel;
use infraternal_protocol::{
    DecodeError, DecodedMuxedFrame, Frame, MAX_FRAME_LEN, decode_frame, decode_muxed_frame,
    encode_frame_into, encode_muxed_frame_into,
};
use std::io;

/// Decodes the first complete frame in `bytes`. A native QUIC stream carries
/// raw frames and takes its stream id from the channel; every other channel
/// carries the mux envelope, whose header names the stream.
fn decode_channel<'a>(
    bytes: &'a [u8],
    socket: &impl Channel,
) -> Result<DecodedMuxedFrame<'a>, DecodeError> {
    if let Some(stream_id) = socket.native_stream_id() {
        let decoded = decode_frame(bytes)?;
        Ok(DecodedMuxedFrame {
            stream_id,
            frame: decoded.frame,
            wire_len: decoded.wire_len,
        })
    } else {
        decode_muxed_frame(bytes)
    }
}

// Static buffer specialization preserves the existing borrowed terminal reader's
// bulk throughput. Owned video opts into immutable shared storage on first use;
// both storage modes execute the same parser, bounds and deadline implementation.
/// The receive buffer of one [`ReadState`]: a plain `Vec` for borrowed frames,
/// or shared `BytesMut` storage once owned packets are handed out.
trait WireBuffer: std::ops::Deref<Target = [u8]> {
    /// Drops the first `count` bytes, which the previous frame consumed.
    fn release(&mut self, count: usize);
    /// Appends freshly read bytes at the end.
    fn append(&mut self, bytes: &[u8]);
}
impl WireBuffer for Vec<u8> {
    fn release(&mut self, count: usize) {
        self.drain(..count);
    }
    fn append(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}
#[cfg(feature = "native-streams")]
impl WireBuffer for BytesMut {
    fn release(&mut self, count: usize) {
        self.advance(count);
    }
    fn append(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// What one receiver keeps between calls: buffered bytes, how many of them the
/// last returned frame used, the reusable 16 KiB read chunk, and the deadline
/// of a partly received frame together with the arrival time it came from.
struct ReadState<B> {
    bytes: B,
    consumed: usize,
    chunk: Box<[u8]>,
    deadline: Option<tokio::time::Instant>,
    last_arrival: Option<tokio::time::Instant>,
}
/// Which buffer kind a [`Receive`] uses. It starts `Borrowed` and moves to
/// `Shared` on the first owned read; `Moving` exists only inside that move.
enum Storage {
    Borrowed(ReadState<Vec<u8>>),
    #[cfg(feature = "native-streams")]
    Shared(ReadState<BytesMut>),
    // First owned use moves the state synchronously, before any await/cancellation.
    #[cfg(feature = "native-streams")]
    Moving,
}
/// One retained raw or mux frame plus at most one 16 KiB read of coalesced suffixes.
/// Borrowed reads retain their original storage; owned packets share allocations.
pub struct Receive {
    storage: Storage,
}
impl Default for Receive {
    fn default() -> Self {
        Self {
            storage: Storage::Borrowed(ReadState {
                bytes: Vec::new(),
                consumed: 0,
                deadline: None,
                last_arrival: None,
                chunk: vec![0; 16 * 1024].into_boxed_slice(),
            }),
        }
    }
}
impl Receive {
    /// Read until a complete borrowed frame is available.
    /// # Errors
    /// Rejects invalid codec data, EOF inside a frame, and excessive storage.
    pub async fn next(&mut self, socket: &impl Channel) -> io::Result<DecodedMuxedFrame<'_>> {
        match &mut self.storage {
            Storage::Borrowed(state) => state.next(socket).await,
            #[cfg(feature = "native-streams")]
            Storage::Shared(state) => state.next(socket).await,
            #[cfg(feature = "native-streams")]
            Storage::Moving => Err(io::ErrorKind::Other.into()),
        }
    }
    /// Transfer exactly one validated packet without copying its access unit.
    /// Raw/mux envelopes and partial-read deadlines are preserved. First owned use
    /// migrates any borrowed buffer once; native lanes start with an empty buffer.
    /// # Errors
    /// Returns the same bounded codec, channel and incomplete-frame failures as `next`.
    #[cfg(feature = "native-streams")]
    pub async fn next_wire(&mut self, socket: &impl Channel) -> io::Result<Bytes> {
        if matches!(self.storage, Storage::Borrowed(_))
            && let Storage::Borrowed(state) = std::mem::replace(&mut self.storage, Storage::Moving)
        {
            self.storage = Storage::Shared(ReadState {
                bytes: BytesMut::from(state.bytes.as_slice()),
                consumed: state.consumed,
                chunk: state.chunk,
                deadline: state.deadline,
                last_arrival: state.last_arrival,
            });
        }
        let Storage::Shared(state) = &mut self.storage else {
            return Err(io::ErrorKind::Other.into());
        };
        let count = state.next(socket).await?.wire_len;
        let packet = state.bytes.split_to(count).freeze();
        state.consumed = 0;
        Ok(packet)
    }
}
impl<B: WireBuffer> ReadState<B> {
    /// Fails with `TimedOut`, and retires the channel, once a partly received
    /// frame has passed its deadline.
    fn reject_expired(&self, socket: &impl Channel) -> io::Result<()> {
        if self
            .deadline
            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            socket.retire();
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }

    /// Read until a complete borrowed frame is available.
    /// # Errors
    /// Rejects invalid codec data, EOF inside a frame, and excessive storage.
    pub async fn next(&mut self, socket: &impl Channel) -> io::Result<DecodedMuxedFrame<'_>> {
        // Release the prior borrow without shifting every coalesced suffix.
        // Owned packets share storage; reserve may reclaim only an unshared prefix.
        if self.consumed != 0 {
            self.bytes.release(self.consumed);
            self.consumed = 0;
        }
        loop {
            match decode_channel(&self.bytes, socket) {
                Ok(_) => break,
                Err(DecodeError::Incomplete) => {}
                Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidData, error)),
            }
            // The first byte arms one deadline retained across select cancellation.
            // An empty channel has no timer; traffic cannot refresh a partial frame.
            self.reject_expired(socket)?;
            let n = if let Some(deadline) = self.deadline {
                if let Ok(result) =
                    tokio::time::timeout_at(deadline, socket.read(&mut self.chunk)).await
                {
                    result?
                } else {
                    socket.retire();
                    return Err(io::ErrorKind::TimedOut.into());
                }
            } else {
                socket.read(&mut self.chunk).await?
            };
            // A ready read is polled before Tokio checks its timer. Recheck
            // after the read so scheduling delays cannot accept an expired suffix.
            self.reject_expired(socket)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            // Header validation happens before body retention. The codec rejects
            // an oversized prefix as soon as it arrives, independently of this cap.
            if self.bytes.len() + n > MAX_FRAME_LEN + 10 + self.chunk.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "leg B receive bound exceeded",
                ));
            }
            // Inherited channels do not pay for clock reads or deadline storage.
            let timeout = socket.frame_timeout();
            self.last_arrival = timeout.map(|_| tokio::time::Instant::now());
            if self.bytes.is_empty() {
                self.deadline = self
                    .last_arrival
                    .zip(timeout)
                    .map(|(arrival, timeout)| arrival + timeout);
            }
            self.bytes.append(&self.chunk[..n]);
        }
        let decoded = decode_channel(&self.bytes, socket)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        self.consumed = decoded.wire_len;
        // Any suffix first arrived in the final read that completed this frame.
        // Retain that arrival while complete coalesced frames are consumed, so
        // delaying the next call cannot postpone a buffered partial-frame expiry.
        self.deadline = if self.consumed < self.bytes.len() {
            self.last_arrival
                .zip(socket.frame_timeout())
                .map(|(at, timeout)| at + timeout)
        } else {
            None
        };
        Ok(decoded)
    }
}

/// Reuse one transmit allocation; callers serialize writes to avoid interleaving.
#[derive(Default)]
pub struct Transmit {
    bytes: Vec<u8>,
}
impl Transmit {
    /// Encode using the shared codec and flush exactly one muxed frame.
    /// # Errors
    /// Returns codec or socket errors.
    pub async fn send(
        &mut self,
        socket: &impl Channel,
        stream: u32,
        frame: &Frame<'_>,
    ) -> io::Result<()> {
        if let Some(writer_id) = socket.native_stream_id() {
            if writer_id != stream {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            encode_frame_into(frame, &mut self.bytes).map_err(io::Error::other)?;
        } else {
            encode_muxed_frame_into(stream, frame, &mut self.bytes).map_err(io::Error::other)?;
        }
        socket.write(&self.bytes).await
    }
}

#[cfg(feature = "test-support")]
impl Receive {
    /// Test hook: the bytes a borrowed receiver holds and whether a frame
    /// deadline is armed, or `None` once it moved to shared storage. Lets
    /// cancellation tests check what a cancelled read kept.
    #[must_use]
    pub fn borrowed_partial(&self) -> Option<(&[u8], bool)> {
        match &self.storage {
            Storage::Borrowed(state) => Some((&state.bytes, state.deadline.is_some())),
            _ => None,
        }
    }
}
