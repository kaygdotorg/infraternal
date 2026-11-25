//! Event-driven inherited leg-B socket IO with reusable bounded wire buffers [9][41].
//!
//! Readiness owns a CLOEXEC duplicate of the inherited socket. Closing or
//! replacing the caller's descriptor cannot redirect this registration. Every
//! operation is nonblocking regardless of the spawning server's fd flags.

use crate::channel::Channel;
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

/// The frame reader and writer moved to `infraternal-link` (#580, L1); the
/// agent's code keeps using them under this path.
pub use infraternal_link::transport::{Receive, Transmit};

/// Deadline and cancellation tests of the moved frame reader over a real
/// inherited socket, which only the infraternal agent has.
#[cfg(test)]
mod remote_deadline_tests {
    use super::*;
    use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
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
    /// A read cancelled after one byte keeps that byte and its deadline, and a
    /// suffix that arrives after the deadline cannot complete the frame.
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
        let Some((bytes, armed)) = receive.borrowed_partial() else {
            panic!("borrowed read must retain its storage");
        };
        assert_eq!(bytes, &wire[..1]);
        assert!(armed);
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
