//! Moves an established server connection between its enrolled path and the mesh path below QUIC, keeping every stream and writer [164,215,263], #201.
//!
//! The host's QUIC connection always names the enrolled server address (its
//! logical remote). This socket decides where those datagrams physically go:
//! to that address, or to the server's mesh address. Datagrams from either
//! physical address are reported as coming from the logical one, so the
//! client connection never sees an address change and keeps its streams,
//! writer bindings and congestion state. The server sees the host's new
//! source and validates it with QUIC's own path migration.
//!
//! The mesh address is supplied by the host's own applied mesh configuration
//! (trusted routing), never learned from UDP. A mapped datagram grants no
//! authority: the connection's packet keys still authenticate every byte.
//!
//! Datagrams sent on the mesh are retained in a bounded recent history. A
//! socket cannot identify the packet numbers acknowledged by a reply. Returning
//! to the enrolled path resends the history instead of waiting for loss
//! recovery timers; QUIC discards
//! any duplicate by packet number.

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};

use crate::remote_peer_routes::Recent;

struct Paths {
    mesh: Option<SocketAddr>,
    resend: Recent,
    mesh_heard: Option<Instant>,
    mesh_sent: Option<Instant>,
    enrolled_heard: Option<Instant>,
}

/// Physical routing for one connection's logical server address.
pub struct PathSocket {
    socket: Arc<dyn AsyncUdpSocket>,
    logical: SocketAddr,
    on_mesh: AtomicBool,
    paths: Mutex<Paths>,
    /// Datagrams received from the mesh address, for proof and liveness.
    mesh_datagrams: AtomicU64,
    heard: tokio::sync::Notify,
    sent: tokio::sync::Notify,
}

impl fmt::Debug for PathSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PathSocket")
            .field("logical", &self.logical)
            .field("on_mesh", &self.on_mesh.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// The physical path currently carrying the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    Enrolled,
    Mesh(SocketAddr),
}

impl PathSocket {
    /// `logical` is the enrolled server address the connection was dialed to.
    #[must_use]
    pub fn new(socket: Arc<dyn AsyncUdpSocket>, logical: SocketAddr) -> Arc<Self> {
        Arc::new(Self {
            socket,
            logical,
            on_mesh: AtomicBool::new(false),
            paths: Mutex::new(Paths {
                mesh: None,
                resend: Recent::default(),
                mesh_heard: None,
                mesh_sent: None,
                enrolled_heard: None,
            }),
            mesh_datagrams: AtomicU64::new(0),
            heard: tokio::sync::Notify::new(),
            sent: tokio::sync::Notify::new(),
        })
    }

    /// The enrolled server address that the connection names.
    #[must_use]
    pub fn logical(&self) -> SocketAddr {
        self.logical
    }

    /// Current physical path.
    #[must_use]
    pub fn path(&self) -> Path {
        match self.paths.lock() {
            Ok(paths) if self.on_mesh.load(Ordering::Acquire) => {
                paths.mesh.map_or(Path::Enrolled, Path::Mesh)
            }
            _ => Path::Enrolled,
        }
    }

    /// Send every following datagram to `mesh`. The caller then triggers a
    /// transmission (see [`PathSocket::alias`]) and waits for [`PathSocket::heard_since`].
    pub fn use_mesh(&self, mesh: SocketAddr) {
        // An IPv6 socket reaches an IPv4 mesh address through its mapped form,
        // and reports replies from it the same way.
        let mesh = match (self.logical, mesh) {
            (SocketAddr::V6(_), SocketAddr::V4(v4)) => {
                SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
            }
            _ => mesh,
        };
        if let Ok(mut paths) = self.paths.lock() {
            if paths.mesh != Some(mesh) {
                paths.mesh_heard = None;
            }
            paths.mesh = Some(mesh);
            paths.mesh_sent = None;
            paths.resend.clear();
            self.on_mesh.store(true, Ordering::Release);
        }
    }

    /// Return to the enrolled address and resend the bounded recent mesh history.
    /// The mesh address stays mapped, so its late replies are still accepted.
    pub fn use_enrolled(&self) {
        let pending = match self.paths.lock() {
            Ok(mut paths) => {
                self.on_mesh.store(false, Ordering::Release);
                paths.resend.take()
            }
            Err(_) => return,
        };
        for sent in pending {
            // Best effort: a full socket buffer leaves the rest to QUIC's own recovery.
            let _ = self.socket.try_send(&Transmit {
                destination: self.logical,
                ecn: sent.ecn,
                contents: &sent.contents,
                segment_size: sent.segment_size,
                src_ip: None,
            });
        }
    }

    /// Forget the mesh address entirely (component off or address change).
    pub fn forget_mesh(&self) {
        self.use_enrolled();
        if let Ok(mut paths) = self.paths.lock() {
            paths.mesh = None;
            paths.mesh_heard = None;
        }
    }

    /// Whether a datagram arrived from the mesh address at or after `since`.
    #[must_use]
    pub fn heard_since(&self, since: Instant) -> bool {
        self.paths
            .lock()
            .ok()
            .and_then(|paths| paths.mesh_heard)
            .is_some_and(|heard| heard >= since)
    }

    /// Whether a datagram arrived from the enrolled address at or after
    /// `since`. Late mesh replies stay accepted after a return, so proving the
    /// enrolled path needs its own evidence.
    #[must_use]
    pub fn enrolled_heard_since(&self, since: Instant) -> bool {
        self.paths
            .lock()
            .ok()
            .and_then(|paths| paths.enrolled_heard)
            .is_some_and(|heard| heard >= since)
    }

    /// Datagrams received from the mesh address so far.
    #[must_use]
    pub fn mesh_datagrams(&self) -> u64 {
        self.mesh_datagrams.load(Ordering::Acquire)
    }

    /// Wait for the next datagram from the mesh address.
    pub async fn mesh_heard(&self) {
        self.heard.notified().await;
    }

    /// Wait for a successful socket send after a queued probe. Queueing a
    /// QUIC DATAGRAM alone cannot start its network-response deadline.
    pub async fn mesh_transmitted_after(&self, queued: Instant) -> Instant {
        loop {
            let notified = self.sent.notified();
            tokio::pin!(notified);
            // Register before checking the timestamp, avoiding a lost wake if
            // the endpoint emits between the check and the first await.
            notified.as_mut().enable();
            if let Some(sent) = self.paths.lock().ok().and_then(|paths| paths.mesh_sent)
                && sent >= queued
            {
                return sent;
            }
            notified.await;
        }
    }

    /// A distinct socket handle over the same routing state. Rebinding the
    /// endpoint to it makes the connection announce itself at once (QUIC
    /// sends a PING with a fresh connection ID after a local address change)
    /// without opening a second descriptor; the endpoint may poll both handles
    /// until the new one carries traffic, and both apply the same mapping.
    #[must_use]
    pub fn alias(self: &Arc<Self>) -> Arc<dyn AsyncUdpSocket> {
        Arc::new(Alias(self.clone()))
    }

    fn keep(&self, transmit: &Transmit<'_>) {
        if let Ok(mut paths) = self.paths.lock() {
            paths.resend.keep(transmit);
            paths.mesh_sent = Some(Instant::now());
        }
    }
}

impl AsyncUdpSocket for PathSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.socket.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.destination != self.logical || !self.on_mesh.load(Ordering::Acquire) {
            return self.socket.try_send(transmit);
        }
        let Some(mesh) = self.paths.lock().ok().and_then(|paths| paths.mesh) else {
            return self.socket.try_send(transmit);
        };
        self.socket.try_send(&Transmit {
            destination: mesh,
            ecn: transmit.ecn,
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        })?;
        self.keep(transmit);
        self.sent.notify_waiters();
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = match self.socket.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => count,
            other => return other,
        };
        let Ok(mut paths) = self.paths.lock() else {
            return Poll::Ready(Ok(count));
        };
        let mut heard = false;
        let mut enrolled = false;
        // Only the exact trusted mesh tuple is normalized; any other source
        // stays foreign to the client connection, which drops it.
        for received in &mut meta[..count] {
            if Some(received.addr) == paths.mesh {
                received.addr = self.logical;
                heard = true;
            } else if received.addr == self.logical {
                enrolled = true;
            }
        }
        if enrolled {
            paths.enrolled_heard = Some(Instant::now());
        }
        if heard {
            paths.mesh_heard = Some(Instant::now());
            drop(paths);
            self.mesh_datagrams.fetch_add(1, Ordering::AcqRel);
            self.heard.notify_waiters();
        }
        Poll::Ready(Ok(count))
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

#[derive(Debug)]
struct Alias(Arc<PathSocket>);
impl AsyncUdpSocket for Alias {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.0.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.0.try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_recv(cx, bufs, meta)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.0.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.0.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.0.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    //! Real UDP: mapping, resend on return, and that payloads are never altered.
    use super::*;
    use quinn::Runtime as _;
    use std::{io::IoSliceMut, sync::Arc, time::Duration};

    async fn send(socket: &Arc<PathSocket>, destination: SocketAddr, contents: &[u8]) {
        let transmit = Transmit {
            destination,
            contents,
            ecn: None,
            segment_size: None,
            src_ip: None,
        };
        let mut writable = socket.clone().create_io_poller();
        std::future::poll_fn(|cx| {
            loop {
                match socket.try_send(&transmit) {
                    Ok(()) => return Poll::Ready(Ok(())),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        match writable.as_mut().poll_writable(cx) {
                            Poll::Ready(Ok(())) => {}
                            other => return other,
                        }
                    }
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
        })
        .await
        .unwrap();
    }

    async fn receive(socket: &PathSocket, bytes: &mut [u8]) -> RecvMeta {
        let mut buffers = [IoSliceMut::new(bytes)];
        let mut metadata = [RecvMeta::default()];
        let count = tokio::time::timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut metadata)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(count, 1);
        metadata[0]
    }

    async fn arrival(peer: &tokio::net::UdpSocket) -> Vec<u8> {
        let mut bytes = [0; 256];
        let (length, _) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        bytes[..length].to_vec()
    }

    #[tokio::test]
    async fn segmented_replay_evicts_enough_old_datagrams_to_keep_the_byte_bound() {
        let logical = "127.0.0.1:7443".parse().unwrap();
        let socket = PathSocket::new(
            quinn::TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap(),
            logical,
        );
        for length in [1024, 1024, 1024, 63 * 1024] {
            socket.keep(&Transmit {
                destination: logical,
                contents: &vec![7; length],
                segment_size: Some(1024),
                ecn: None,
                src_ip: None,
            });
        }
        let mut paths = socket.paths.lock().unwrap();
        let pending = paths.resend.take();
        assert!(
            pending
                .iter()
                .map(|sent| sent.contents.len())
                .sum::<usize>()
                <= 64 * 1024
        );
    }

    #[tokio::test]
    async fn an_unrelated_reply_cannot_discard_ciphertext_needed_after_a_cut() {
        let enrolled = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mesh = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let logical = enrolled.local_addr().unwrap();
        let socket = PathSocket::new(
            quinn::TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap(),
            logical,
        );
        socket.use_mesh(mesh.local_addr().unwrap());
        send(&socket, logical, b"input-needing-replay").await;
        assert_eq!(arrival(&mesh).await, b"input-needing-replay");
        // The socket cannot know which packet numbers this reply acknowledges.
        // A delayed ACK for earlier traffic must not erase the current input.
        mesh.send_to(b"earlier-ack", socket.local_addr().unwrap())
            .await
            .unwrap();
        receive(&socket, &mut [0; 64]).await;
        socket.use_enrolled();
        send(&socket, logical, b"marker").await;
        assert_eq!(arrival(&enrolled).await, b"input-needing-replay");
        assert_eq!(arrival(&enrolled).await, b"marker");
    }

    #[tokio::test]
    async fn mesh_route_maps_only_the_trusted_tuple_and_resends_unanswered_datagrams() {
        let enrolled = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mesh = tokio::net::UdpSocket::bind("127.0.0.3:0").await.unwrap();
        let foreign = tokio::net::UdpSocket::bind("127.0.0.4:0").await.unwrap();
        let logical = enrolled.local_addr().unwrap();
        let socket = PathSocket::new(
            quinn::TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.2:0").unwrap())
                .unwrap(),
            logical,
        );
        let local = socket.local_addr().unwrap();
        assert_eq!(socket.path(), Path::Enrolled);
        send(&socket, logical, b"enrolled").await;
        assert_eq!(arrival(&enrolled).await, b"enrolled");

        socket.use_mesh(mesh.local_addr().unwrap());
        assert_eq!(socket.path(), Path::Mesh(mesh.local_addr().unwrap()));
        let switched = Instant::now();
        send(&socket, logical, b"first-mesh").await;
        send(&socket, logical, b"second-mesh").await;
        assert_eq!(arrival(&mesh).await, b"first-mesh");
        assert_eq!(arrival(&mesh).await, b"second-mesh");
        // Unanswered: returning resends both, in order, on the enrolled path.
        socket.use_enrolled();
        assert_eq!(socket.path(), Path::Enrolled);
        assert_eq!(arrival(&enrolled).await, b"first-mesh");
        assert_eq!(arrival(&enrolled).await, b"second-mesh");

        socket.use_mesh(mesh.local_addr().unwrap());
        send(&socket, logical, b"answered").await;
        assert_eq!(arrival(&mesh).await, b"answered");
        mesh.send_to(b"mesh-reply", local).await.unwrap();
        let mut bytes = [0; 64];
        let metadata = receive(&socket, &mut bytes).await;
        assert_eq!(
            metadata.addr, logical,
            "the connection keeps its logical peer"
        );
        assert_eq!(&bytes[..metadata.len], b"mesh-reply");
        assert!(socket.heard_since(switched));
        assert_eq!(socket.mesh_datagrams(), 1);
        // The socket cannot interpret ACK ranges. Replaying this encrypted
        // packet is safe: the QUIC connection owns packet-number deduplication.
        socket.use_enrolled();
        send(&socket, logical, b"marker").await;
        assert_eq!(arrival(&enrolled).await, b"answered");
        assert_eq!(arrival(&enrolled).await, b"marker");
        // A late mesh reply after returning is still the logical peer.
        mesh.send_to(b"late-mesh", local).await.unwrap();
        let metadata = receive(&socket, &mut bytes).await;
        assert_eq!(
            (metadata.addr, &bytes[..metadata.len]),
            (logical, &b"late-mesh"[..])
        );

        // A foreign source keeps its own address and never counts as the mesh.
        foreign.send_to(b"foreign", local).await.unwrap();
        let metadata = receive(&socket, &mut bytes).await;
        assert_eq!(metadata.addr, foreign.local_addr().unwrap());
        assert_eq!(socket.mesh_datagrams(), 2);
    }
}
