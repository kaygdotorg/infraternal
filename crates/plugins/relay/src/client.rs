//! A node's connection to one relay: link requests, notices, DATAGRAMs and probe keys [313].
//!
//! The caller owns the policy (which peers to link, which relay a pair uses);
//! this type only speaks the relay protocol. Sending and receiving relayed
//! ciphertext goes straight through [`Client::connection`] so the data path
//! has no extra queue or lock.

use crate::{
    probe::ProbeKey,
    tls,
    wire::{self, HostId, Notice, Request},
};
use std::{io, net::SocketAddr, time::Duration};

/// One authenticated relay connection.
pub struct Client {
    connection: quinn::Connection,
    control: tokio::sync::Mutex<quinn::SendStream>,
    probe: ProbeKey,
}

/// The relay's notices, read in order by one task.
pub struct Notices {
    recv: quinn::RecvStream,
}

impl Client {
    /// Connect, verify the relay as `name`, and open the control stream.
    /// # Errors
    /// Fails on a refused identity, an unreachable relay or the deadline.
    pub async fn connect(
        endpoint: &quinn::Endpoint,
        config: quinn::ClientConfig,
        address: SocketAddr,
        name: &str,
        deadline: Duration,
    ) -> io::Result<(Self, Notices)> {
        let connecting = endpoint
            .connect_with(config, address, name)
            .map_err(io::Error::other)?;
        let opened = tokio::time::timeout(deadline, async {
            let connection = connecting.await.map_err(io::Error::other)?;
            let (mut send, recv) = connection.open_bi().await.map_err(io::Error::other)?;
            // The stream exists for the relay only once a byte is sent.
            send.write_all(&tls::HELLO)
                .await
                .map_err(io::Error::other)?;
            io::Result::Ok((connection, send, recv))
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
        let (connection, send, recv) = opened?;
        let probe = ProbeKey::from_connection(&connection)?;
        Ok((
            Self {
                connection,
                control: tokio::sync::Mutex::new(send),
                probe,
            },
            Notices { recv },
        ))
    }

    /// Ask the relay to link with `peer`; the link exists once a `Linked` notice arrives.
    /// # Errors
    /// Fails if the control stream is gone.
    pub async fn link(&self, peer: HostId) -> io::Result<()> {
        self.send(Request::Link(peer)).await
    }

    /// Withdraw the request for `peer` and end any link with it.
    /// # Errors
    /// Fails if the control stream is gone.
    pub async fn unlink(&self, peer: HostId) -> io::Result<()> {
        self.send(Request::Unlink(peer)).await
    }

    async fn send(&self, request: Request) -> io::Result<()> {
        self.control
            .lock()
            .await
            .write_all(&request.encode())
            .await
            .map_err(io::Error::other)
    }

    /// The QUIC connection, for `send_datagram`/`read_datagram` on the data path.
    #[must_use]
    pub fn connection(&self) -> &quinn::Connection {
        &self.connection
    }

    /// Keys for address probes sent to this relay's UDP port.
    #[must_use]
    pub fn probe_key(&self) -> &ProbeKey {
        &self.probe
    }

    /// Close the connection; the relay ends every link it had.
    pub fn close(&self) {
        self.connection
            .close(quinn::VarInt::from_u32(0), b"client closed");
    }
}

impl Notices {
    /// Next notice, or `None` when the relay ends the stream or the connection.
    /// A malformed notice also ends it: the caller treats the relay as gone.
    pub async fn next(&mut self) -> Option<Notice> {
        let mut kind = [0; 1];
        self.recv.read_exact(&mut kind).await.ok()?;
        let len = wire::notice_len(kind[0])?;
        let mut body = [0; wire::MAX_MESSAGE];
        self.recv.read_exact(&mut body[..len]).await.ok()?;
        Notice::decode(kind[0], &body[..len])
    }
}
