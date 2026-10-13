//! Shares one QUIC endpoint across the server's agent address and its leased mesh addresses, so an authenticated connection keeps its identity when a host moves between paths [164,215,263], #201.
//!
//! Each destination address keeps its own bound UDP socket: the operator's
//! explicit agent address is never widened to a wildcard bind. A separate
//! endpoint per address would own a separate connection-ID space, so a host
//! whose packets moved to the mesh address would be unknown there (and answered
//! with a stateless reset). This socket set gives the endpoint every bound
//! socket at once, and Quinn's own server-side path migration then validates
//! the new path of the existing connection.
//!
//! Replies leave through the socket the peer was last heard on. Quinn records a
//! connection's local IP only once, at creation, so its source hint cannot
//! follow a migration; the learned peer route can. Routes are hints, never
//! authority: the connection's keys authenticate every datagram either way.

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    collections::HashMap,
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

/// Learned replies for at most this many peer addresses. A full table is
/// cleared rather than grown: affected peers re-learn on their next datagram,
/// and until then a reply uses the connection's original source.
const MAX_ROUTES: usize = 65_536;

#[derive(Clone)]
struct Lease {
    id: u64,
    ip: IpAddr,
    socket: Arc<dyn AsyncUdpSocket>,
}

/// The primary socket plus leased destination sockets behind one endpoint.
pub struct Bindings {
    primary: Arc<dyn AsyncUdpSocket>,
    /// The primary socket is bound to one address, not a wildcard.
    primary_bound: bool,
    leases: Mutex<Arc<Vec<Lease>>>,
    generation: AtomicU64,
    next_lease: AtomicU64,
    routes: Mutex<HashMap<SocketAddr, u64>>,
    route_count: AtomicUsize,
    cursor: AtomicUsize,
    receiver: Mutex<Option<Waker>>,
}

impl fmt::Debug for Bindings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Bindings")
            .field("routes", &self.route_count.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Removes its socket and every reply route through it when dropped.
pub struct LeasedBinding {
    bindings: Arc<Bindings>,
    id: u64,
}
impl Drop for LeasedBinding {
    fn drop(&mut self) {
        self.bindings.remove(self.id);
    }
}

impl Bindings {
    /// Wrap the endpoint's primary (agent address) socket.
    #[must_use]
    pub fn new(primary: Arc<dyn AsyncUdpSocket>) -> Arc<Self> {
        let primary_bound = primary
            .local_addr()
            .is_ok_and(|address| !address.ip().is_unspecified());
        Arc::new(Self {
            primary,
            primary_bound,
            leases: Mutex::default(),
            generation: AtomicU64::new(0),
            next_lease: AtomicU64::new(0),
            routes: Mutex::default(),
            route_count: AtomicUsize::new(0),
            cursor: AtomicUsize::new(0),
            receiver: Mutex::new(None),
        })
    }

    /// Add one bound destination socket; the endpoint driver is woken to poll it.
    ///
    /// # Errors
    /// Returns the socket's local-address error.
    pub fn lease(self: &Arc<Self>, socket: Arc<dyn AsyncUdpSocket>) -> io::Result<LeasedBinding> {
        let ip = socket.local_addr()?.ip().to_canonical();
        let id = self.next_lease.fetch_add(1, Ordering::Relaxed);
        {
            let mut leases = self.leases.lock().map_err(|_| io::ErrorKind::Other)?;
            let mut next = leases.to_vec();
            next.push(Lease { id, ip, socket });
            *leases = Arc::new(next);
        }
        self.generation.fetch_add(1, Ordering::Release);
        if let Some(waker) = self.receiver.lock().ok().and_then(|mut waker| waker.take()) {
            waker.wake();
        }
        Ok(LeasedBinding {
            bindings: self.clone(),
            id,
        })
    }

    fn remove(&self, id: u64) {
        if let Ok(mut leases) = self.leases.lock() {
            let next: Vec<Lease> = leases
                .iter()
                .filter(|lease| lease.id != id)
                .cloned()
                .collect();
            *leases = Arc::new(next);
        }
        self.generation.fetch_add(1, Ordering::Release);
        if let Ok(mut routes) = self.routes.lock() {
            routes.retain(|_, lease| *lease != id);
            self.route_count.store(routes.len(), Ordering::Relaxed);
        }
    }

    fn snapshot(&self) -> Arc<Vec<Lease>> {
        self.leases
            .lock()
            .map(|leases| leases.clone())
            .unwrap_or_default()
    }

    fn learn(&self, lease: Option<u64>, meta: &[RecvMeta]) {
        // The primary path is the common case: skip the table entirely while
        // no peer is routed through a lease.
        if lease.is_none() && self.route_count.load(Ordering::Relaxed) == 0 {
            return;
        }
        let Ok(mut routes) = self.routes.lock() else {
            return;
        };
        for received in meta {
            match lease {
                Some(lease) => {
                    if routes.len() >= MAX_ROUTES && !routes.contains_key(&received.addr) {
                        routes.clear();
                    }
                    routes.insert(received.addr, lease);
                }
                None => {
                    routes.remove(&received.addr);
                }
            }
        }
        self.route_count.store(routes.len(), Ordering::Relaxed);
    }

    /// The socket that reaches `destination`: its learned lease, else a lease
    /// owning Quinn's source hint, else the primary socket.
    fn outbound(&self, transmit: &Transmit<'_>) -> Option<Arc<dyn AsyncUdpSocket>> {
        let learned = if self.route_count.load(Ordering::Relaxed) == 0 {
            None
        } else {
            self.routes
                .lock()
                .ok()
                .and_then(|routes| routes.get(&transmit.destination).copied())
        };
        if learned.is_none() && transmit.src_ip.is_none() {
            return None;
        }
        let leases = self.snapshot();
        leases
            .iter()
            .find(|lease| {
                learned.map_or_else(
                    || transmit.src_ip.map(|ip| ip.to_canonical()) == Some(lease.ip),
                    |id| lease.id == id,
                )
            })
            .map(|lease| lease.socket.clone())
    }
}

impl AsyncUdpSocket for Bindings {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable {
            primary: self.primary.clone().create_io_poller(),
            leases: Vec::new(),
            generation: u64::MAX,
            bindings: self,
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        match self.outbound(transmit) {
            // A leased socket is bound to its own address: no source override.
            Some(socket) => socket.try_send(&Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: transmit.contents,
                segment_size: transmit.segment_size,
                src_ip: None,
            }),
            // A connection accepted on a lease keeps that lease's address as
            // Quinn's source hint for life. After it moves to the primary path
            // (or its lease is gone) that hint names an address the primary
            // socket is not bound to, and the kernel refuses the datagram.
            // A specifically bound primary chooses its own source.
            None if self.primary_bound => self.primary.try_send(&Transmit {
                destination: transmit.destination,
                ecn: transmit.ecn,
                contents: transmit.contents,
                segment_size: transmit.segment_size,
                src_ip: None,
            }),
            None => self.primary.try_send(transmit),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let generation = self.generation.load(Ordering::Acquire);
        let leases = self.snapshot();
        let sources = leases.len() + 1;
        // Rotate the first socket so a flood on one address cannot starve another.
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % sources;
        for offset in 0..sources {
            let index = (start + offset) % sources;
            let (socket, lease) = if index == 0 {
                (&self.primary, None)
            } else {
                let lease = &leases[index - 1];
                (&lease.socket, Some(lease.id))
            };
            match socket.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(count)) => {
                    self.learn(lease, &meta[..count]);
                    return Poll::Ready(Ok(count));
                }
                // A failing lease must not stop the agent address; the lease
                // owner retires it. The primary socket's errors stay fatal.
                Poll::Ready(Err(error)) if lease.is_none() => return Poll::Ready(Err(error)),
                Poll::Ready(Err(_)) | Poll::Pending => {}
            }
        }
        if let Ok(mut waker) = self.receiver.lock()
            && !waker
                .as_ref()
                .is_some_and(|waker| waker.will_wake(cx.waker()))
        {
            *waker = Some(cx.waker().clone());
        }
        // Installing a lease can race the pending polls before receiver
        // registration. Recheck after registration so neither side can miss
        // the wakeup; the next poll includes the new socket without a timer.
        if self.generation.load(Ordering::Acquire) != generation {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.primary.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.snapshot()
            .iter()
            .map(|lease| lease.socket.max_transmit_segments())
            .fold(self.primary.max_transmit_segments(), usize::min)
    }
    fn max_receive_segments(&self) -> usize {
        // Receive buffers are sized once from the primary; leased sockets are
        // created by the same runtime and report the same capability.
        self.primary.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.primary.may_fragment()
    }
}

/// Write readiness across the set. UDP sockets are almost always writable, so
/// waiting for every socket avoids spinning on a ready one while another is full.
struct Writable {
    bindings: Arc<Bindings>,
    primary: Pin<Box<dyn UdpPoller>>,
    leases: Vec<Pin<Box<dyn UdpPoller>>>,
    generation: u64,
}
impl fmt::Debug for Writable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Writable").finish_non_exhaustive()
    }
}
impl UdpPoller for Writable {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let generation = self.bindings.generation.load(Ordering::Acquire);
        if generation != self.generation {
            let pollers = self
                .bindings
                .snapshot()
                .iter()
                .map(|lease| lease.socket.clone().create_io_poller())
                .collect();
            self.leases = pollers;
            self.generation = generation;
        }
        let mut ready = self.primary.as_mut().poll_writable(cx)?.is_ready();
        for lease in &mut self.leases {
            ready &= lease.as_mut().poll_writable(cx)?.is_ready();
        }
        if ready {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    //! Real UDP sockets: replies follow the address a peer was last heard on.
    use super::*;
    use quinn::Runtime as _;

    fn bound(address: &str) -> Arc<dyn AsyncUdpSocket> {
        quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind(address).unwrap())
            .unwrap()
    }

    async fn receive(socket: &Bindings) -> (RecvMeta, Vec<u8>) {
        let mut bytes = [0u8; 256];
        let mut buffers = [IoSliceMut::new(&mut bytes)];
        let mut meta = [RecvMeta::default()];
        let count = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            std::future::poll_fn(|cx| socket.poll_recv(cx, &mut buffers, &mut meta)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(count, 1);
        let length = meta[0].len;
        (meta[0], bytes[..length].to_vec())
    }

    fn send(socket: &Bindings, destination: SocketAddr, contents: &[u8], src_ip: Option<IpAddr>) {
        socket
            .try_send(&Transmit {
                destination,
                ecn: None,
                contents,
                segment_size: None,
                src_ip,
            })
            .unwrap();
    }

    #[tokio::test]
    async fn replies_follow_the_last_heard_address_and_leases_retire_their_routes() {
        let bindings = Bindings::new(bound("127.0.0.1:0"));
        let primary = bindings.local_addr().unwrap();
        let leased = bound("127.0.0.3:0");
        let leased_address = leased.local_addr().unwrap();
        let lease = bindings.lease(leased).unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let mut reply = [0u8; 64];

        peer.send_to(b"via-primary", primary).await.unwrap();
        let (meta, bytes) = receive(&bindings).await;
        assert_eq!(
            (meta.addr, bytes.as_slice()),
            (peer.local_addr().unwrap(), &b"via-primary"[..])
        );
        send(&bindings, meta.addr, b"reply-1", None);
        let (length, from) = peer.recv_from(&mut reply).await.unwrap();
        assert_eq!((&reply[..length], from), (&b"reply-1"[..], primary));

        // The same peer tuple now arrives on the leased address: replies follow it.
        peer.send_to(b"via-lease", leased_address).await.unwrap();
        let (meta, bytes) = receive(&bindings).await;
        assert_eq!(bytes, b"via-lease");
        assert_eq!(
            meta.dst_ip.map(|ip| ip.to_canonical()),
            Some(leased_address.ip())
        );
        send(&bindings, meta.addr, b"reply-2", Some(primary.ip()));
        let (length, from) = peer.recv_from(&mut reply).await.unwrap();
        assert_eq!((&reply[..length], from), (&b"reply-2"[..], leased_address));

        // Heard on the primary again: the learned route is forgotten.
        peer.send_to(b"back", primary).await.unwrap();
        let _ = receive(&bindings).await;
        send(&bindings, meta.addr, b"reply-3", None);
        let (length, from) = peer.recv_from(&mut reply).await.unwrap();
        assert_eq!((&reply[..length], from), (&b"reply-3"[..], primary));

        peer.send_to(b"lease-again", leased_address).await.unwrap();
        let _ = receive(&bindings).await;
        drop(lease);
        assert_eq!(bindings.route_count.load(Ordering::Relaxed), 0);
        // A connection born on the lease still hints the lease address.
        send(&bindings, meta.addr, b"reply-4", Some(leased_address.ip()));
        let (length, from) = peer.recv_from(&mut reply).await.unwrap();
        assert_eq!((&reply[..length], from), (&b"reply-4"[..], primary));
    }

    /// Runs a lease installation between a pending socket poll and receiver
    /// registration, reproducing the notification race without sleeps.
    struct InstallWhilePending {
        inner: Arc<dyn AsyncUdpSocket>,
        install: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }
    impl fmt::Debug for InstallWhilePending {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("InstallWhilePending")
                .finish_non_exhaustive()
        }
    }
    impl AsyncUdpSocket for InstallWhilePending {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            self.inner.clone().create_io_poller()
        }
        fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
            self.inner.try_send(transmit)
        }
        fn poll_recv(
            &self,
            cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let result = self.inner.poll_recv(cx, bufs, meta);
            if result.is_pending()
                && let Some(install) = self.install.lock().unwrap().take()
            {
                install();
            }
            result
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }
    }

    #[tokio::test]
    async fn lease_installed_during_a_pending_poll_cannot_lose_the_receive_wakeup() {
        let primary = Arc::new(InstallWhilePending {
            inner: bound("127.0.0.1:0"),
            install: Mutex::new(None),
        });
        let bindings = Bindings::new(primary.clone());
        let leased = bound("127.0.0.3:0");
        let destination = leased.local_addr().unwrap();
        let keep = Arc::new(Mutex::new(None));
        let owned = keep.clone();
        let weak = Arc::downgrade(&bindings);
        *primary.install.lock().unwrap() = Some(Box::new(move || {
            *owned.lock().unwrap() = Some(weak.upgrade().unwrap().lease(leased).unwrap());
            std::net::UdpSocket::bind("127.0.0.2:0")
                .unwrap()
                .send_to(b"ready", destination)
                .unwrap();
        }));
        let mut receiver = tokio::spawn(async move {
            let mut bytes = [0; 64];
            let mut buffers = [IoSliceMut::new(&mut bytes)];
            let mut metadata = [RecvMeta::default()];
            // No timer inside this task: an outer timeout must not accidentally
            // repoll the stranded socket and hide the missed notification.
            let count =
                std::future::poll_fn(|cx| bindings.poll_recv(cx, &mut buffers, &mut metadata))
                    .await
                    .unwrap();
            assert_eq!(count, 1);
            assert_eq!(&bytes[..metadata[0].len], b"ready");
        });
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), &mut receiver).await;
        if result.is_err() {
            receiver.abort();
            let _ = receiver.await;
        }
        assert!(
            result.is_ok(),
            "installing a lease lost the endpoint receive wakeup"
        );
        result.unwrap().unwrap();
        drop(keep);
    }
    #[tokio::test]
    async fn a_lease_added_while_waiting_is_polled_without_another_primary_datagram() {
        let bindings = Bindings::new(bound("127.0.0.1:0"));
        let waiting = tokio::spawn({
            let bindings = bindings.clone();
            async move { receive(&bindings).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let leased = bound("127.0.0.3:0");
        let address = leased.local_addr().unwrap();
        let _lease = bindings.lease(leased).unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
        peer.send_to(b"late-lease", address).await.unwrap();
        let (_, bytes) = waiting.await.unwrap();
        assert_eq!(bytes, b"late-lease");
    }
}
