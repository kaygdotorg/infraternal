//! Event-driven inherited leg-B socket IO with reusable bounded wire buffers [9][41].
//!
//! The caller keeps the inherited fd open for the entire run. This module never
//! takes ownership or closes it: nix's safe socket syscalls and `AsyncFd` readiness
//! registration avoid an unsafe fd conversion. Every operation is nonblocking,
//! regardless of the flags chosen by the spawning server.

use infraternal_protocol::{
    DecodeError, DecodedMuxedFrame, Frame, MAX_FRAME_LEN, decode_muxed_frame,
    encode_muxed_frame_into,
};
use nix::sys::socket::{MsgFlags, recv, send};
use std::{
    io,
    os::fd::{AsRawFd, RawFd},
};
use tokio::io::unix::AsyncFd;

struct Descriptor(RawFd);
impl AsRawFd for Descriptor {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// A borrowed inherited socket; no fd flags or ownership are changed.
pub struct Socket {
    descriptor: AsyncFd<Descriptor>,
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
        Ok(Self {
            descriptor: AsyncFd::new(Descriptor(fd))?,
        })
    }

    /// Read ready bytes without blocking an executor or allocating.
    /// # Errors
    /// Returns socket errors. Zero means the server closed leg B.
    pub async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = self.descriptor.readable().await?;
            match ready.try_io(|fd| {
                recv(fd.get_ref().0, bytes, MsgFlags::MSG_DONTWAIT).map_err(io::Error::from)
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
                send(
                    fd.get_ref().0,
                    &bytes[sent..],
                    MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
                )
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

/// One retained mux frame plus at most one 16 KiB read of coalesced suffixes.
pub struct Receive {
    bytes: Vec<u8>,
    consumed: usize,
    chunk: Box<[u8]>,
}
impl Default for Receive {
    fn default() -> Self {
        // Keep scratch out of the async future. One allocation per connection
        // avoids both a 16 KiB future and Box::pin allocation on every message.
        Self {
            bytes: Vec::new(),
            consumed: 0,
            chunk: vec![0; 16 * 1024].into_boxed_slice(),
        }
    }
}
impl Receive {
    /// Read until a complete borrowed frame is available.
    /// # Errors
    /// Rejects invalid codec data, EOF inside a frame, and excessive storage.
    pub async fn next(&mut self, socket: &Socket) -> io::Result<DecodedMuxedFrame<'_>> {
        // Compact once between messages, never once per fragmented read.
        if self.consumed != 0 {
            self.bytes.drain(..self.consumed);
            self.consumed = 0;
        }
        loop {
            match decode_muxed_frame(&self.bytes) {
                Ok(_) => break,
                Err(DecodeError::Incomplete) => {}
                Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidData, error)),
            }
            let n = socket.read(&mut self.chunk).await?;
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
            self.bytes.extend_from_slice(&self.chunk[..n]);
        }
        let decoded = decode_muxed_frame(&self.bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        self.consumed = decoded.wire_len;
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
        socket: &Socket,
        stream: u32,
        frame: &Frame<'_>,
    ) -> io::Result<()> {
        encode_muxed_frame_into(stream, frame, &mut self.bytes).map_err(io::Error::other)?;
        socket.write(&self.bytes).await
    }
}
