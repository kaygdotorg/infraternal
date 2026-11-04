//! Event-driven inherited leg-B socket IO with reusable bounded wire buffers [9][41].
//!
//! Readiness owns a CLOEXEC duplicate of the inherited socket. Closing or
//! replacing the caller's descriptor cannot redirect this registration. Every
//! operation is nonblocking regardless of the spawning server's fd flags.

use crate::channel::Channel;
#[cfg(any(test, feature = "native-streams"))]
use bytes::{Buf, Bytes, BytesMut};
use infraternal_protocol::{
    DecodeError, DecodedMuxedFrame, Frame, MAX_FRAME_LEN, decode_frame, decode_muxed_frame,
    encode_frame_into, encode_muxed_frame_into,
};
use infraternal_shim::readiness::{Registration, duplicate_inherited};
use nix::sys::socket::{MsgFlags, recv, send};
use std::{
    io,
    os::fd::{AsRawFd, OwnedFd, RawFd},
};

/// An independently owned socket descriptor; the inherited fd flags stay unchanged.
pub struct Socket {
    descriptor: Registration<OwnedFd>,
}
#[cfg(target_os = "linux")]
#[inline]
fn nonblocking_send_flags() -> MsgFlags {
    MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL
}
#[cfg(target_os = "macos")]
#[inline]
fn nonblocking_send_flags() -> MsgFlags {
    MsgFlags::MSG_DONTWAIT
}
impl Socket {
    /// Register readiness once on the runtime's reactor.
    /// # Errors
    /// Rejects invalid descriptors and reactor registration errors.
    pub fn inherited(fd: RawFd) -> io::Result<Self> {
        if fd < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "leg B requires an inherited fd >= 3",
            ));
        }
        let descriptor = duplicate_inherited(fd)?;
        #[cfg(target_os = "macos")]
        socket2::SockRef::from(&descriptor).set_nosigpipe(true)?;
        Ok(Self {
            descriptor: Registration::new(descriptor)?,
        })
    }

    /// Read ready bytes without blocking an executor or allocating.
    /// # Errors
    /// Returns socket errors. Zero means the server closed leg B.
    pub async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = self.descriptor.readable().await?;
            match ready.try_io(|fd| {
                recv(fd.as_raw_fd(), bytes, MsgFlags::MSG_DONTWAIT).map_err(io::Error::from)
            }) {
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
                Ok(result) => return result,
                Err(_) => {}
            }
        }
    }

    /// Flush one encoded bounded frame, retaining progress across readiness waits.
    /// # Errors
    /// Returns socket errors or a closed peer without raising SIGPIPE.
    /// Do not cancel this future during a partial frame: close leg B instead.
    pub async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let mut sent = 0;
        while sent < bytes.len() {
            let mut ready = self.descriptor.writable().await?;
            match ready.try_io(|fd| {
                send(fd.as_raw_fd(), &bytes[sent..], nonblocking_send_flags())
                    .map_err(io::Error::from)
            }) {
                Ok(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(Ok(n)) => sent += n,
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => {}
            }
        }
        Ok(())
    }
}

impl Channel for Socket {
    async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        Self::read(self, bytes).await
    }

    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        Self::write(self, bytes).await
    }
}

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
trait WireBuffer: std::ops::Deref<Target = [u8]> {
    fn release(&mut self, count: usize);
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
#[cfg(any(test, feature = "native-streams"))]
impl WireBuffer for BytesMut {
    fn release(&mut self, count: usize) {
        self.advance(count);
    }
    fn append(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

struct ReadState<B> {
    bytes: B,
    consumed: usize,
    chunk: Box<[u8]>,
    deadline: Option<tokio::time::Instant>,
    last_arrival: Option<tokio::time::Instant>,
}
enum Storage {
    Borrowed(ReadState<Vec<u8>>),
    #[cfg(any(test, feature = "native-streams"))]
    Shared(ReadState<BytesMut>),
    // First owned use moves the state synchronously, before any await/cancellation.
    #[cfg(any(test, feature = "native-streams"))]
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
            #[cfg(any(test, feature = "native-streams"))]
            Storage::Shared(state) => state.next(socket).await,
            #[cfg(any(test, feature = "native-streams"))]
            Storage::Moving => Err(io::ErrorKind::Other.into()),
        }
    }
    /// Transfer exactly one validated packet without copying its access unit.
    /// Raw/mux envelopes and partial-read deadlines are preserved. First owned use
    /// migrates any borrowed buffer once; native lanes start with an empty buffer.
    /// # Errors
    /// Returns the same bounded codec, channel and incomplete-frame failures as `next`.
    #[cfg(any(test, feature = "native-streams"))]
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

#[cfg(test)]
mod remote_deadline_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    struct RemoteSocket {
        socket: Socket,
        retired: AtomicBool,
    }
    impl Channel for RemoteSocket {
        fn frame_timeout(&self) -> Option<Duration> {
            Some(Duration::from_millis(100))
        }
        fn retire(&self) {
            self.retired.store(true, Ordering::Relaxed);
        }
        async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
            self.socket.read(bytes).await
        }
        async fn write(&self, bytes: &[u8]) -> io::Result<()> {
            self.socket.write(bytes).await
        }
    }
    // Retain the caller descriptor separately to exercise the inherited-fd entry point.
    fn pair() -> (
        std::os::unix::net::UnixStream,
        tokio::net::UnixStream,
        RemoteSocket,
    ) {
        let (owned, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let socket = Socket::inherited(owned.as_raw_fd()).unwrap();
        (
            owned,
            tokio::net::UnixStream::from_std(peer).unwrap(),
            RemoteSocket {
                socket,
                retired: AtomicBool::new(false),
            },
        )
    }
    fn ping(nonce: u64) -> Vec<u8> {
        let mut wire = Vec::new();
        encode_muxed_frame_into(0, &Frame::Ping { nonce, sent_us: 0 }, &mut wire).unwrap();
        wire
    }
    #[tokio::test]
    async fn owned_and_borrowed_packets_preserve_coalesced_retained_bytes() {
        let (_owned, mut peer, channel) = pair();
        let mut wire = ping(7);
        wire.extend_from_slice(&ping(8));
        wire.extend_from_slice(&ping(9));
        peer.write_all(&wire).await.unwrap();
        let mut receive = Receive::default();
        let retained = receive.next_wire(&channel).await.unwrap();
        assert!(matches!(
            receive.next(&channel).await.unwrap().frame,
            Frame::Ping { nonce: 8, .. }
        ));
        let last = receive.next_wire(&channel).await.unwrap();
        assert!(matches!(
            decode_muxed_frame(&last).unwrap().frame,
            Frame::Ping { nonce: 9, .. }
        ));
        assert_eq!(retained.as_ref(), ping(7));
    }

    #[tokio::test]
    async fn owned_packet_does_not_refresh_a_coalesced_partial_suffix_deadline() {
        let (_owned, mut peer, channel) = pair();
        let mut wire = ping(7);
        let next = ping(8);
        wire.extend_from_slice(&next[..1]);
        peer.write_all(&wire).await.unwrap();
        let mut receive = Receive::default();
        let retained = receive.next_wire(&channel).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        peer.write_all(&next[1..]).await.unwrap();
        assert_eq!(
            receive.next_wire(&channel).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(channel.retired.load(Ordering::Relaxed));
        assert_eq!(retained.as_ref(), ping(7));
    }

    #[tokio::test]
    async fn remote_partial_frame_deadline_survives_receive_cancellation() {
        let (_owned, mut peer, channel) = pair();
        peer.write_all(&ping(7)[..1]).await.unwrap();
        let mut receive = Receive::default();
        for _ in 0..15 {
            match tokio::time::timeout(Duration::from_millis(20), receive.next(&channel)).await {
                Err(_) => {}
                Ok(Err(error)) => {
                    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                    assert!(channel.retired.load(Ordering::Relaxed));
                    return;
                }
                Ok(Ok(_)) => panic!("partial frame must never decode"),
            }
        }
        panic!("cancellation must not extend the first-byte deadline");
    }
    #[tokio::test(start_paused = true)]
    async fn queued_suffix_cannot_complete_an_expired_cancelled_frame() {
        let (_owned, mut peer, channel) = pair();
        let wire = ping(7);
        peer.write_all(&wire[..1]).await.unwrap();
        let _ = channel.socket.descriptor.readable().await.unwrap();
        let mut receive = Receive::default();
        {
            let mut pending = std::pin::pin!(receive.next(&channel));
            // Consume the first byte and cancel exactly at Pending. Paused time
            // prevents executor scheduling from racing cancellation with expiry.
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(pending.as_mut(), context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        let Storage::Borrowed(state) = &receive.storage else {
            panic!("borrowed read must retain its storage");
        };
        assert_eq!(state.bytes, wire[..1]);
        assert!(state.deadline.is_some());
        tokio::time::advance(Duration::from_millis(150)).await;
        // Tokio polls a ready inner read before its timeout. Supplying the
        // suffix before resuming proves an expired frame cannot use that order.
        peer.write_all(&wire[1..]).await.unwrap();
        // Prime reactor readiness so the inner read completes on its first poll.
        let _ = channel.socket.descriptor.readable().await.unwrap();
        let result = receive.next(&channel).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(channel.retired.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn wholly_idle_remote_channel_has_no_frame_expiry() {
        let (_owned, mut peer, channel) = pair();
        let mut receive = Receive::default();
        assert!(
            tokio::time::timeout(Duration::from_millis(150), receive.next(&channel))
                .await
                .is_err()
        );
        assert!(!channel.retired.load(Ordering::Relaxed));
        peer.write_all(&ping(7)).await.unwrap();
        assert!(matches!(
            receive.next(&channel).await.unwrap().frame,
            Frame::Ping { nonce: 7, .. }
        ));
    }
    #[tokio::test]
    async fn coalesced_partial_suffix_keeps_its_arrival_deadline() {
        let (_owned, mut peer, channel) = pair();
        let mut wire = ping(7);
        wire.extend_from_slice(&ping(9)[..1]);
        peer.write_all(&wire).await.unwrap();
        let mut receive = Receive::default();
        assert!(matches!(
            receive.next(&channel).await.unwrap().frame,
            Frame::Ping { nonce: 7, .. }
        ));
        tokio::time::sleep(Duration::from_millis(150)).await;
        let result = tokio::time::timeout(Duration::from_millis(20), receive.next(&channel))
            .await
            .expect("buffered partial suffix must retain its original arrival deadline");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(channel.retired.load(Ordering::Relaxed));
    }
}
