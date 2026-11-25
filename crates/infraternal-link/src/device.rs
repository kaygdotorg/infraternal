//! A device's leg-B link: the iPhone's held QUIC connection to the server
//! (#580, slice 1).
//!
//! In slice 1 a device's link carries nothing but its own liveness. The server
//! admits the device's certificate with its device guard and serves it no
//! terminals, sessions, logins, host facts, SSH or mesh actions; the link
//! exists so the device is reachable and its identity is proven on a live
//! connection. Later slices add the mesh node's calls on top of it.
//!
//! How to use it:
//! 1. Build the client config with [`crate::quic::client_config_with_liveness`]
//!    from the device's [`crate::identity::ClientIdentity`] and the CA the join
//!    pinned, and dial with [`crate::quic::connect`], which applies the
//!    server-leaf floor exactly as the infraternal agent does.
//! 2. Call [`DeviceLink::open`] on the connection: it opens control stream 0,
//!    sends this device's Hello and waits for the server's.
//! 3. Hold the [`DeviceLink`]; [`DeviceLink::ping`] measures the round trip,
//!    and [`DeviceLink::closed`] resolves when the server or the network ends
//!    it. Redial (with backoff, `crate::supervisor`) when it does.
//!
//! The wire is the same as a host's: raw protocol frames on a native QUIC
//! control stream (stream id 0), a version-1 Hello from each side first.

use crate::transport::{Receive, Transmit};
use infraternal_plugin_api::channel::Channel;
use infraternal_protocol::Frame;
use std::{io, time::Duration};
use tokio::sync::Mutex;

/// How long the server has to answer the Hello, or a Ping.
pub const REPLY_DEADLINE: Duration = Duration::from_secs(5);

/// The capability bits a slice-1 device offers in its Hello: none. A device
/// takes no writer bindings, renewals over the link, or native lanes yet.
pub const DEVICE_CAPS: u64 = 0;

/// The control stream of one QUIC connection, as a [`Channel`] for the frame
/// codec. Reads and writes each take their own lock, so a reader waiting for
/// the next frame never blocks a write.
struct ControlStream {
    send: Mutex<quinn::SendStream>,
    receive: Mutex<quinn::RecvStream>,
}

impl Channel for ControlStream {
    /// Raw frames on the control stream, whose id is 0.
    fn native_stream_id(&self) -> Option<u32> {
        Some(0)
    }

    /// A frame that starts arriving must finish within the reply deadline.
    fn frame_timeout(&self) -> Option<Duration> {
        Some(REPLY_DEADLINE)
    }

    async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        self.receive
            .lock()
            .await
            .read(bytes)
            .await
            .map(|count| count.unwrap_or(0))
            .map_err(io::Error::other)
    }

    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        tokio::time::timeout(REPLY_DEADLINE, async {
            self.send.lock().await.write_all(bytes).await
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(io::Error::other)
    }
}

/// A device's open link: the QUIC connection and its control stream, after
/// both Hellos were exchanged.
pub struct DeviceLink {
    connection: quinn::Connection,
    control: ControlStream,
    receive: Receive,
    transmit: Transmit,
    server_caps: u64,
    nonce: u64,
}

impl DeviceLink {
    /// Open control stream 0 on `connection`, send this device's Hello
    /// (`client_info` names the client, for example `infraternal-ios/1`) and
    /// read the server's within [`REPLY_DEADLINE`].
    /// # Errors
    /// `TimedOut` when the server does not answer in time, `InvalidData` when
    /// its first frame is not a version-1 Hello on stream 0, or the stream's
    /// own failures (a server that refused the device closes the connection).
    pub async fn open(connection: quinn::Connection, client_info: &str) -> io::Result<Self> {
        let (send, receive) = connection.open_bi().await.map_err(io::Error::other)?;
        let control = ControlStream {
            send: Mutex::new(send),
            receive: Mutex::new(receive),
        };
        let mut link = Self {
            connection,
            control,
            receive: Receive::default(),
            transmit: Transmit::default(),
            server_caps: 0,
            nonce: 0,
        };
        link.send(&Frame::Hello {
            version: 1,
            caps: DEVICE_CAPS,
            client_info,
        })
        .await?;
        let caps = tokio::time::timeout(REPLY_DEADLINE, async {
            let reply = link.receive.next(&link.control).await?;
            match reply.frame {
                Frame::Hello {
                    version: 1, caps, ..
                } if reply.stream_id == 0 => Ok(caps),
                _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
            }
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        link.server_caps = caps;
        Ok(link)
    }

    /// The capability bits the server's Hello offered.
    #[must_use]
    pub fn server_caps(&self) -> u64 {
        self.server_caps
    }

    /// The QUIC connection under this link, for its statistics and peer
    /// identity.
    #[must_use]
    pub fn connection(&self) -> &quinn::Connection {
        &self.connection
    }

    /// Send one frame on the control stream. A slice-1 device sends only
    /// Pings after its Hello; the server closes the link on anything else.
    /// # Errors
    /// Codec or stream failures.
    pub async fn send(&mut self, frame: &Frame<'_>) -> io::Result<()> {
        self.transmit.send(&self.control, 0, frame).await
    }

    /// Ping the server on the control stream and return the round trip.
    /// # Errors
    /// `TimedOut` without a Pong within [`REPLY_DEADLINE`]; `InvalidData`
    /// when the reply is anything else; stream failures.
    pub async fn ping(&mut self) -> io::Result<Duration> {
        self.nonce = self.nonce.wrapping_add(1);
        let nonce = self.nonce;
        let started = tokio::time::Instant::now();
        self.send(&Frame::Ping { nonce, sent_us: 0 }).await?;
        tokio::time::timeout(REPLY_DEADLINE, async {
            let reply = self.receive.next(&self.control).await?;
            match reply.frame {
                Frame::Pong { nonce: echoed, .. } if echoed == nonce => Ok(()),
                _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
            }
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        Ok(started.elapsed())
    }

    /// Wait for the next frame the server sends on the control stream, and
    /// return its encoded form; for tests that check what a refusal answers.
    /// # Errors
    /// End of stream (the server closed the link) or a codec failure.
    pub async fn next_frame(&mut self) -> io::Result<Vec<u8>> {
        let frame = self.receive.next(&self.control).await?;
        let mut bytes = Vec::new();
        infraternal_protocol::encode_frame_into(&frame.frame, &mut bytes)
            .map_err(io::Error::other)?;
        Ok(bytes)
    }

    /// Resolves when the connection ends, with the reason.
    pub async fn closed(&self) -> quinn::ConnectionError {
        self.connection.closed().await
    }
}

impl Drop for DeviceLink {
    fn drop(&mut self) {
        // A dropped link is over: tell the server now instead of letting it
        // wait for the idle timeout.
        self.connection.close(0u32.into(), b"");
    }
}
