//! Experiments with physical peer routing below the existing authenticated QUIC connection; test support only until namespace validation [164,243,263].

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// Routes one exact peer tuple while retaining the logical QUIC address. This
/// adapter does not authenticate or authorize a peer: the existing connection
/// still checks packet keys, replay protection and the enrolled identity.
/// Use a fresh underlying socket with `Endpoint::rebind_abstract`, so its retained
/// previous socket and this adapter never compete to poll the same descriptor.
#[derive(Debug)]
pub struct PeerSocket {
    socket: Arc<dyn AsyncUdpSocket>,
    logical: SocketAddr,
    physical: SocketAddr,
}

impl PeerSocket {
    /// The caller supplies trusted routing addresses, not data learned from UDP.
    #[must_use]
    pub fn new(socket: Arc<dyn AsyncUdpSocket>, logical: SocketAddr, physical: SocketAddr) -> Self {
        Self {
            socket,
            logical,
            physical,
        }
    }
}

impl AsyncUdpSocket for PeerSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.socket.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.socket.try_send(&Transmit {
            destination: if transmit.destination == self.logical {
                self.physical
            } else {
                transmit.destination
            },
            ecn: transmit.ecn,
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        match self.socket.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => {
                // Only the exact configured tuple is normalized; another source
                // port remains foreign to Quinn. Datagram length, GRO stride,
                // ECN and destination metadata retain their socket semantics.
                for received in &mut meta[..count] {
                    if received.addr == self.physical {
                        received.addr = self.logical;
                    }
                }
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.socket.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.socket.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.socket.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    //! Exercise actual UDP routing without changing payloads or treating datagrams as authority.
    use super::*;
    use quinn::Runtime as _;
    use std::{io::IoSliceMut, sync::Arc};

    #[tokio::test]
    async fn translated_udp_preserves_payload_and_normalizes_only_the_exact_peer() {
        let physical = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let foreign = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let logical = "127.0.0.2:7443".parse().unwrap();
        let socket = quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let local = socket.local_addr().unwrap();
        let segments = (
            socket.max_transmit_segments(),
            socket.max_receive_segments(),
        );
        let fragment = socket.may_fragment();
        let translated = Arc::new(PeerSocket::new(
            socket,
            logical,
            physical.local_addr().unwrap(),
        ));
        assert_eq!(translated.local_addr().unwrap(), local);
        assert_eq!(
            (
                translated.max_transmit_segments(),
                translated.max_receive_segments()
            ),
            segments
        );
        assert_eq!(translated.may_fragment(), fragment);
        send(translated.clone(), logical, b"public-route-proof").await;
        let mut bytes = [0; 64];
        let (length, peer) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            physical.recv_from(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&bytes[..length], b"public-route-proof");
        assert_eq!(peer, local);
        physical.send_to(b"public-reply", local).await.unwrap();
        let metadata = receive(&translated, &mut bytes).await;
        assert_eq!(metadata.addr, logical);
        assert_eq!(&bytes[..metadata.len], b"public-reply");
        assert_eq!(metadata.dst_ip, Some(local.ip()));
        foreign.send_to(b"foreign-peer", local).await.unwrap();
        let metadata = receive(&translated, &mut bytes).await;
        assert_eq!(metadata.addr, foreign.local_addr().unwrap());
        assert_eq!(&bytes[..metadata.len], b"foreign-peer");
        send(translated, foreign.local_addr().unwrap(), b"unmapped-send").await;
        let (length, peer) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            foreign.recv_from(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&bytes[..length], b"unmapped-send");
        assert_eq!(peer, local);
    }

    async fn send(socket: Arc<PeerSocket>, destination: std::net::SocketAddr, contents: &[u8]) {
        let mut writable = socket.clone().create_io_poller();
        let transmit = quinn::udp::Transmit {
            destination,
            contents,
            ecn: None,
            segment_size: None,
            src_ip: None,
        };
        std::future::poll_fn(|cx| {
            loop {
                match socket.try_send(&transmit) {
                    Ok(()) => return std::task::Poll::Ready(Ok(())),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        match writable.as_mut().poll_writable(cx) {
                            std::task::Poll::Ready(Ok(())) => {}
                            other => return other,
                        }
                    }
                    Err(error) => return std::task::Poll::Ready(Err(error)),
                }
            }
        })
        .await
        .unwrap();
    }

    async fn receive(socket: &PeerSocket, bytes: &mut [u8]) -> quinn::udp::RecvMeta {
        let mut buffers = [IoSliceMut::new(bytes)];
        let mut metadata = [quinn::udp::RecvMeta::default()];
        let count = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            std::future::poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut metadata)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(count, 1);
        metadata[0]
    }
}
