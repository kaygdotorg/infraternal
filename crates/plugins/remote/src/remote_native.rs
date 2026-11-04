//! Carries unchanged raw wire frames on one authenticated QUIC stream with a server-assigned writer identity [64][130], #78.

use crate::{channel::Channel, remote_quic::BoundStream};
use std::{io, time::Duration};
use tokio::sync::{Mutex, watch};

/// Time a single frame write may take, and the frame timeout reported to callers. A write that exceeds it fails and the channel is retired.
const ACTIVE_DEADLINE: Duration = Duration::from_secs(5);

/// One native control or terminal stream. Private construction keeps native ids
/// separate from the durable writer id established by transport.bind.
pub struct NativeChannel {
    writer_id: u32,
    send: Mutex<quinn::SendStream>,
    receive: Mutex<quinn::RecvStream>,
    retired: watch::Sender<bool>,
}

impl NativeChannel {
    /// Consume a capability-negotiated, validated writer binding.
    /// # Errors
    /// Refuses reserved writer ids, mismatched halves and a host-initiated stream.
    pub fn terminal(stream: BoundStream) -> io::Result<Self> {
        if stream.writer_id == 0
            || stream.writer_id & 1 != 0
            || stream.send.id() != stream.receive.id()
            || stream.send.id().initiator() != quinn::Side::Server
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(Self::new(stream.send, stream.receive, stream.writer_id))
    }

    /// Wrap the single host-initiated control stream after mutual TLS.
    /// The caller must require native stream zero before passing these halves.
    /// # Errors
    /// Refuses a terminal stream passed as control or mismatched halves.
    pub fn control(send: quinn::SendStream, receive: quinn::RecvStream) -> io::Result<Self> {
        if send.id() != receive.id()
            || send.id().index() != 0
            || send.id().initiator() != quinn::Side::Client
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        send.set_priority(1000).map_err(io::Error::other)?;
        Ok(Self::new(send, receive, 0))
    }

    /// Wraps the two halves with the given writer id.
    fn new(send: quinn::SendStream, receive: quinn::RecvStream, writer_id: u32) -> Self {
        Self {
            writer_id,
            send: Mutex::new(send),
            receive: Mutex::new(receive),
            retired: watch::channel(false).0,
        }
    }
}

/// Guard that retires the channel if a write is cancelled or fails before finishing, because a half-written frame cannot be followed by another.
struct RetireWrite<'a>(&'a watch::Sender<bool>, bool);
impl Drop for RetireWrite<'_> {
    /// Retires the channel unless the write completed.
    fn drop(&mut self) {
        if !self.1 {
            self.0.send_replace(true);
        }
    }
}

impl Channel for NativeChannel {
    /// The writer id established at binding, or 0 for the control stream.
    fn native_stream_id(&self) -> Option<u32> {
        Some(self.writer_id)
    }
    /// Time allowed for one frame.
    fn frame_timeout(&self) -> Option<Duration> {
        Some(ACTIVE_DEADLINE)
    }
    /// Marks the channel finished. Pending and later reads and writes fail with `BrokenPipe`.
    fn retire(&self) {
        self.retired.send_replace(true);
    }

    /// Reads up to `bytes.len()` bytes; returns 0 at the end of the stream. Fails with `BrokenPipe` once retired.
    async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        let mut retired = self.retired.subscribe();
        if *retired.borrow() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        tokio::select! {
            biased;
            _ = retired.changed() => Err(io::ErrorKind::BrokenPipe.into()),
            result = async { self.receive.lock().await.read(bytes).await } => result.map(|count| count.unwrap_or(0)).map_err(io::Error::other),
        }
    }

    /// Writes all of `bytes` within the deadline. Fails with `BrokenPipe` once retired or `TimedOut` on delay; a failed or cancelled write retires the channel.
    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let mut retired = self.retired.subscribe();
        if *retired.borrow() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let mut send = tokio::select! {
            biased;
            _ = retired.changed() => return Err(io::ErrorKind::BrokenPipe.into()),
            send = self.send.lock() => send,
        };
        // A cancelled partial frame cannot be followed by another wire frame.
        let mut guard = RetireWrite(&self.retired, false);
        let result = tokio::select! {
            biased;
            _ = retired.changed() => Err(io::ErrorKind::BrokenPipe.into()),
            result = tokio::time::timeout(ACTIVE_DEADLINE, send.write_all(bytes)) => {
                result.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?.map_err(io::Error::other)
            }
        };
        guard.1 = result.is_ok();
        result
    }
}
