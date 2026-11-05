//! Shares one QUIC endpoint across the server's agent address and its leased mesh addresses, so an authenticated connection keeps its identity when a host moves between paths [164,215,263], #201.
//!
//! Each destination address keeps its own bound UDP socket: the operator's
//! explicit agent address is never widened to a wildcard bind. A separate
//! endpoint per address would own a separate connection-ID space, so a host
//! whose packets moved to the mesh address would be unknown there (and answered
//! with a stateless reset). This socket set gives the endpoint every bound
//! socket at once. Admitted peer aliases preserve the logical tuple; unknown
//! tuples still require Quinn's ordinary server-side path validation.
//!
//! Replies follow the last fresh ciphertext hint. Quinn records a
//! connection's local IP only once, at creation, so its source hint cannot
//! follow a migration; the learned peer route can. Routes are hints, never
//! authority: the connection's keys authenticate every datagram either way.

use crate::{
    remote_path_copies::CopyClock,
    remote_peer_routes::{MeshRoute, Peers},
};
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
pub(super) struct Lease {
    pub id: u64,
    ip: IpAddr,
    pub socket: Arc<dyn AsyncUdpSocket>,
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
    peers: Mutex<Peers>,
    peer_count: AtomicUsize,
    copies: Mutex<CopyClock>,
    proofs: Mutex<HashMap<SocketAddr, Vec<(u64, crate::remote_path_proof::PathKey)>>>,
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

/// An admitted QUIC connection owns its responder independently of mesh leases.
/// Dropping an older generation cannot erase a replacement connection's key.
pub struct ConnectionProof {
    bindings: Arc<Bindings>,
    logical: SocketAddr,
    id: u64,
}
impl Drop for ConnectionProof {
    fn drop(&mut self) {
        if let Ok(mut proofs) = self.bindings.proofs.lock()
            && let Some(keys) = proofs.get_mut(&self.logical)
        {
            keys.retain(|(id, _)| *id != self.id);
            if keys.is_empty() {
                proofs.remove(&self.logical);
            }
        }
    }
}

/// Owns one admitted peer's routing aliases; retirement retains no replay buffer.
pub struct PeerBinding {
    bindings: Arc<Bindings>,
    logical: SocketAddr,
    id: u64,
}
impl PeerBinding {
    /// Only the already admitted peer's Hello enables encrypted backup copies.
    pub fn set_backup(&self, enabled: bool) {
        if let Ok(mut peers) = self.bindings.peers.lock()
            && let Some(peer) = peers.get_mut(self.logical)
            && peer.id == self.id
        {
            peer.backup = enabled;
            if !enabled {
                peer.recent_mut().cancel_copies();
                if peers
                    .iter_mut()
                    .all(|peer| peer.recent().deadline().is_none())
                    && let Ok(mut clock) = self.bindings.copies.lock()
                {
                    if peers.iter_mut().all(|peer| !peer.backup) {
                        clock.clear();
                    } else {
                        clock.cancel_timer();
                    }
                }
            }
        }
    }
}
impl Drop for PeerBinding {
    fn drop(&mut self) {
        self.bindings.remove_peer(self.logical, self.id);
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
            peers: Mutex::default(),
            peer_count: AtomicUsize::new(0),
            copies: Mutex::default(),
            proofs: Mutex::default(),
        })
    }

    /// Register only after durable admission, retaining enrolled path proofs
    /// after mesh disable. The caller owns this lease with its live transport.
    /// # Errors
    /// Refuses unavailable key export, poisoned state or the admitted-host bound.
    pub fn connection_proof(
        self: &Arc<Self>,
        connection: &quinn::Connection,
    ) -> io::Result<ConnectionProof> {
        let key = crate::remote_path_proof::PathKey::from_connection(connection)?;
        let logical = connection.remote_address();
        let id = self.next_lease.fetch_add(1, Ordering::Relaxed);
        let mut proofs = self.proofs.lock().map_err(|_| io::ErrorKind::Other)?;
        if proofs.len() >= 10_000 && !proofs.contains_key(&logical) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        // One UDP tuple may carry multiple admitted QUIC connections while a
        // replacement is queued. Keep their keys independently: cancelling a
        // newer admission must not erase the still-active older session.
        let keys = proofs.entry(logical).or_default();
        if keys.len() >= 4 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        keys.push((id, key));
        Ok(ConnectionProof {
            bindings: self.clone(),
            logical,
            id,
        })
    }

    /// Lease an exact alternative tuple supplied through the admitted peer's
    /// control channel. A NAT mapping may have changed its enrolled source port.
    /// No UDP packet can create an alias or change its identity.
    /// # Errors
    /// Refuses conflicting aliases, unspecified addresses, or poisoned state.
    pub fn route_peer(
        self: &Arc<Self>,
        logical: SocketAddr,
        alternate: SocketAddr,
    ) -> io::Result<PeerBinding> {
        if logical == alternate || alternate.ip().is_unspecified() || alternate.port() == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let id = self.next_lease.fetch_add(1, Ordering::Relaxed);
        let mut peers = self.peers.lock().map_err(|_| io::ErrorKind::Other)?;
        if !peers.insert(id, logical, alternate) {
            return Err(io::ErrorKind::AddrInUse.into());
        }
        self.peer_count.store(peers.len(), Ordering::Release);
        Ok(PeerBinding {
            bindings: self.clone(),
            logical,
            id,
        })
    }

    fn remove_peer(&self, logical: SocketAddr, id: u64) {
        if let Ok(mut peers) = self.peers.lock() {
            peers.remove(logical, id);
            self.peer_count.store(peers.len(), Ordering::Release);
            if let Ok(mut clock) = self.copies.lock() {
                if peers.len() == 0 {
                    clock.clear();
                } else if peers
                    .iter_mut()
                    .all(|peer| peer.recent().deadline().is_none())
                {
                    clock.cancel_timer();
                }
            }
        }
    }

    // The actual receiving socket answers a verified challenge. No ordinary
    // QUIC send, route mutation or replacement lease is involved. Keys belong
    // to admitted connections; aliases only map a physical tuple to that key.
    fn answer_probes(
        &self,
        socket: &dyn AsyncUdpSocket,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) {
        for (buf, received) in bufs.iter_mut().zip(meta.iter_mut()) {
            // Most receives contain only QUIC; avoid routing/key locks entirely.
            if !crate::remote_path_proof::contains_probes(&buf[..received.len], received.stride) {
                continue;
            }
            let logical = if self.peer_count.load(Ordering::Acquire) == 0 {
                received.addr
            } else {
                self.peers
                    .lock()
                    .ok()
                    .and_then(|mut peers| peers.by_physical(received.addr).map(|peer| peer.logical))
                    .unwrap_or(received.addr)
            };
            let physical = received.addr;
            let local = received.dst_ip;
            received.len = crate::remote_path_proof::receive_probes(
                &mut buf[..received.len],
                received.stride,
                |packet| {
                    let response = self.proofs.lock().ok().and_then(|proofs| {
                        proofs
                            .get(&logical)
                            .and_then(|keys| keys.iter().find_map(|(_, key)| key.response(packet)))
                    });
                    if let Some(response) = response {
                        let _ = socket.try_send(&Transmit {
                            destination: physical,
                            src_ip: local,
                            ecn: None,
                            contents: &response,
                            segment_size: None,
                        });
                    }
                },
            );
        }
    }

    /// Normalize only leased tuples and replay encrypted data when the physical
    /// path changes. Packet numbers, not routing hints, own deduplication.
    fn receive_peer(&self, lease: Option<u64>, bufs: &[IoSliceMut<'_>], meta: &mut [RecvMeta]) {
        if self.peer_count.load(Ordering::Acquire) == 0 {
            self.learn(lease, meta);
            return;
        }
        if let Ok(mut peers) = self.peers.lock() {
            for (index, received) in meta.iter_mut().enumerate() {
                if received.len == 0 {
                    continue;
                }
                let physical = received.addr;
                if let Some(peer) = peers.by_physical(physical) {
                    let logical = peer.logical;
                    if physical == peer.alternate {
                        let first_mesh = peer
                            .mesh
                            .replace(MeshRoute {
                                binding: lease,
                                local: received.dst_ip,
                            })
                            .is_none();
                        // Dormant replies can exist only before coordinates
                        // are known. Later replies are armed at insertion;
                        // lease retirement clears both coordinates and replies.
                        if first_mesh
                            && let Some(at) = peer.recent_mut().mesh_ready()
                            && let Ok(mut clock) = self.copies.lock()
                        {
                            clock.arm(at);
                        }
                    }
                    let fresh = bufs
                        .get(index)
                        .and_then(|buf| buf.get(..received.len))
                        .is_some_and(|contents| peer.seen.observe(contents, received.stride));
                    if fresh && (peer.physical != physical || peer.binding != lease) {
                        peer.physical = physical;
                        peer.binding = lease;
                        if physical == logical {
                            // Enrolled selection is immediate; redundant mesh
                            // history drains through the endpoint's existing
                            // fair send budget after QUIC receives this batch.
                            // Each completed return consumes its original.
                            if let Some(at) = peer.recent_mut().replay(received.dst_ip)
                                && let Ok(mut clock) = self.copies.lock()
                            {
                                clock.arm(at);
                            }
                        }
                    }
                    if fresh {
                        peer.local = received.dst_ip;
                    }
                    received.addr = logical;
                    // Peers owns the admitted alias's reply route. Preserve the
                    // generic memo from before admission so retirement restores
                    // that previous path, rather than the last alternative.
                    continue;
                }
                self.learn(lease, std::slice::from_ref(received));
            }
        }
    }

    /// Public physical coordinates for opt-in diagnostics; never identity.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn physical_peer(&self, logical: SocketAddr) -> SocketAddr {
        self.peers
            .lock()
            .ok()
            .and_then(|peers| peers.get(logical).map(|peer| peer.physical))
            .unwrap_or(logical)
    }

    /// Aggregate retained entries, payload bytes, armed entries and return
    /// entries from existing state for opt-in snapshots outside measured windows.
    ///
    /// # Errors
    /// Returns an error if the routing state lock is poisoned.
    // The crate's own probe tests read it too. They also build when a sibling
    // package in the same Cargo run enables only `transport`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn retained_history(&self) -> io::Result<[usize; 4]> {
        let mut peers = self.peers.lock().map_err(|_| io::ErrorKind::Other)?;
        let mut total = [0; 4];
        for peer in peers.iter_mut() {
            for (sum, value) in total.iter_mut().zip(peer.recent().history()) {
                *sum += value;
            }
        }
        Ok(total)
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
        if let Ok(mut peers) = self.peers.lock() {
            for peer in peers.iter_mut() {
                if peer.mesh.is_some_and(|route| route.binding == Some(id)) {
                    peer.mesh = None;
                    peer.recent_mut().cancel_mesh_replies();
                }
            }
            if peers
                .iter_mut()
                .all(|peer| peer.recent().deadline().is_none())
                && let Ok(mut clock) = self.copies.lock()
            {
                clock.cancel_timer();
            }
        }
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
            if received.len == 0 {
                continue;
            }
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
        let mut peers = (self.peer_count.load(Ordering::Acquire) != 0)
            .then(|| self.peers.lock().ok())
            .flatten();
        let peer = peers
            .as_mut()
            .and_then(|peers| peers.get_mut(transmit.destination));
        let physical = peer
            .as_ref()
            .map_or(transmit.destination, |peer| peer.physical);
        // Keep source selection coherent with the alias's physical destination.
        // A wildcard primary must use the packet's local destination: Quinn's
        // connection-local IP is immutable, and a route may own several IPs.
        let (socket, source) = if let Some(peer) = peer.as_ref() {
            (
                peer.binding.and_then(|id| {
                    self.snapshot()
                        .iter()
                        .find(|lease| lease.id == id)
                        .map(|lease| lease.socket.clone())
                }),
                peer.local,
            )
        } else {
            (self.outbound(transmit), transmit.src_ip)
        };
        // Leases and specifically bound primaries choose their own IP. Quinn
        // retains its initial local address across a move, so only a wildcard
        // primary can use the peer's learned local destination as a source.
        let source = if socket.is_some() || self.primary_bound {
            None
        } else {
            source
        };
        let sender = socket.as_deref().unwrap_or(self.primary.as_ref());
        let result = sender.try_send(&Transmit {
            destination: physical,
            src_ip: source,
            ..*transmit
        });
        // Enrolled replies never become mesh recovery history, including
        // replayed ciphertext. A return consumes the queue instead of making
        // old packets eligible for another burst on a later upgrade.
        if result.is_ok()
            && let Some(peer) = peer
        {
            let at = if peer.physical != peer.logical {
                let backup = peer.backup;
                peer.recent_mut().keep_copying(transmit, backup)
            } else if peer.backup {
                // Primary enrolled success is independent of this optional
                // immediate mesh reply. It shares the same bounded history
                // and cannot evict pending enrolled recovery.
                let ready = peer.mesh.is_some();
                peer.recent_mut().mesh_reply(transmit, ready)
            } else {
                None
            };
            if let Some(at) = at
                && let Ok(mut clock) = self.copies.lock()
            {
                clock.arm(at);
            }
        }
        result
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let generation = self.generation.load(Ordering::Acquire);
        let leases = self.snapshot();
        let due = self.peer_count.load(Ordering::Acquire) != 0
            && self.copies.lock().is_ok_and(|mut clock| clock.poll(cx));
        if due
            && let Ok(mut peers) = self.peers.lock()
            && let Some(at) = peers.copies(self.primary.as_ref(), self.primary_bound, &leases)
            && let Ok(mut clock) = self.copies.lock()
        {
            clock.arm(at);
        }
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
                    self.answer_probes(socket.as_ref(), bufs, &mut meta[..count]);
                    self.receive_peer(lease, bufs, &mut meta[..count]);
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

#[cfg(all(test, feature = "test-support"))]
#[path = "remote_receive_cost_tests.rs"]
mod receive_cost_tests;

#[cfg(test)]
mod tests {
    //! Real UDP sockets: replies follow the address a peer was last heard on.
    use super::*;
    use quinn::Runtime as _;

    #[tokio::test]
    async fn admitted_path_proofs_survive_mesh_retirement_and_old_key_lease_drop() {
        use crate::{
            remote_path_socket::PathSocket,
            remote_quic,
            remote_tls::tests::{leaf, root},
        };
        let ca = root();
        let bindings = Bindings::new(bound("127.0.0.1:0"));
        let logical = bindings.local_addr().unwrap();
        let mesh = SocketAddr::new("127.0.0.2".parse().unwrap(), logical.port());
        let mesh_lease = bindings.lease(bound(&mesh.to_string())).unwrap();
        let server = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(
                remote_quic::server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate))
                    .unwrap(),
            ),
            bindings.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let path = PathSocket::new(bound("127.0.0.1:0"), logical);
        let mut client = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            path.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        client.set_default_client_config(
            remote_quic::client_config(&leaf(&ca, false), &[ca.certificate]).unwrap(),
        );
        let (dial, accepted) = tokio::join!(client.connect(logical, "localhost").unwrap(), async {
            server.accept().await.unwrap().await
        });
        let dial = dial.unwrap();
        let accepted = accepted.unwrap();
        let old = bindings.connection_proof(&accepted).unwrap();
        // Both QUIC connections deliberately share one source tuple. A
        // cancelled replacement must not remove the other session's key.
        let (replacement, accepted_replacement) =
            tokio::join!(client.connect(logical, "localhost").unwrap(), async {
                server.accept().await.unwrap().await
            });
        let replacement = replacement.unwrap();
        let accepted_replacement = accepted_replacement.unwrap();
        assert_eq!(
            accepted.remote_address(),
            accepted_replacement.remote_address()
        );
        let cancelled = bindings.connection_proof(&accepted_replacement).unwrap();
        drop(cancelled);
        assert_eq!(
            bindings
                .proofs
                .lock()
                .unwrap()
                .get(&accepted.remote_address())
                .unwrap()
                .len(),
            1
        );
        let current = bindings.connection_proof(&accepted_replacement).unwrap();
        drop(old);
        assert_eq!(bindings.proofs.lock().unwrap().len(), 1);
        path.prepare_proof(&replacement).unwrap();
        path.use_mesh(mesh);
        let identities = (dial.stable_id(), accepted.stable_id());
        for mesh in [true, false] {
            if !mesh {
                // Only the mesh socket retires; the admitted native transport
                // still owns enrolled proof service without a new connection.
                path.use_enrolled();
            }
            let since = std::time::Instant::now();
            let first = path.send_path_proof(mesh).unwrap();
            assert!(
                first == path.send_path_proof(mesh).unwrap(),
                "retransmission replaced the original physical-send clock"
            );
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                while !path.path_authenticated_since(since, mesh) {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!((dial.stable_id(), accepted.stable_id()), identities);
        }
        drop(mesh_lease);
        path.use_enrolled();
        let since = std::time::Instant::now();
        path.send_path_proof(false).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !path.path_authenticated_since(since, false) {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!((dial.stable_id(), accepted.stable_id()), identities);
        drop(current);
        assert!(bindings.proofs.lock().unwrap().is_empty());
        client.close(0u32.into(), b"");
        server.close(0u32.into(), b"");
    }

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
    async fn alias_retirement_restores_the_previous_reply_socket() {
        for original_lease in [false, true] {
            let bindings = Bindings::new(bound("127.0.0.1:0"));
            let primary = bindings.local_addr().unwrap();
            let original = bound("127.0.0.2:0");
            let original_address = original.local_addr().unwrap();
            let _original_lease = bindings.lease(original).unwrap();
            let alternative = bound("127.0.0.5:0");
            let alternative_address = alternative.local_addr().unwrap();
            let _alternative_lease = bindings.lease(alternative).unwrap();
            let mut pair = None;
            for _ in 0..16 {
                let logical = tokio::net::UdpSocket::bind("127.0.0.3:0").await.unwrap();
                let address = SocketAddr::new(
                    "127.0.0.4".parse().unwrap(),
                    logical.local_addr().unwrap().port(),
                );
                match tokio::net::UdpSocket::bind(address).await {
                    Ok(mesh) => {
                        pair = Some((logical, mesh));
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
                    Err(error) => panic!("could not bind owned alternative: {error}"),
                }
            }
            let (logical_socket, mesh_socket) = pair.expect("owned alias tuple pairs collided");
            let logical = logical_socket.local_addr().unwrap();
            let alternate = mesh_socket.local_addr().unwrap();
            let mut writable = bindings.clone().create_io_poller();
            std::future::poll_fn(|cx| writable.as_mut().poll_writable(cx))
                .await
                .unwrap();
            let mut bytes = [0; 64];
            if original_lease {
                // The original path may itself be a leased listener. Its memo
                // must survive an admitted alternative, not be erased at admission.
                logical_socket
                    .send_to(b"original-route", original_address)
                    .await
                    .unwrap();
                assert_eq!(receive(&bindings).await.0.addr, logical);
                send(&bindings, logical, b"original-reply", None);
                let (count, source) = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    logical_socket.recv_from(&mut bytes),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(
                    (&bytes[..count], source),
                    (&b"original-reply"[..], original_address)
                );
            }
            let peer = bindings.route_peer(logical, alternate).unwrap();
            mesh_socket
                .send_to(b"admitted-alternative", alternative_address)
                .await
                .unwrap();
            let (metadata, payload) = receive(&bindings).await;
            assert_eq!(
                (metadata.addr, payload.as_slice()),
                (logical, &b"admitted-alternative"[..])
            );
            drop(peer);
            // Keep both shared listeners for other peers while this peer's
            // routing lease ends. Its next write uses its actual previous path.
            send(&bindings, logical, b"retired-reply", None);
            let (count, source) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                logical_socket.recv_from(&mut bytes),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(&bytes[..count], b"retired-reply");
            assert_eq!(
                source,
                if original_lease {
                    original_address
                } else {
                    primary
                },
                "retired alias left an alternative-sourced reply on its previous path"
            );
            mesh_socket
                .send_to(b"unaliased-mesh", alternative_address)
                .await
                .unwrap();
            assert_eq!(receive(&bindings).await.0.addr, alternate);
            send(&bindings, alternate, b"unaliased-reply", None);
            let (count, source) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                mesh_socket.recv_from(&mut bytes),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                (&bytes[..count], source),
                (&b"unaliased-reply"[..], alternative_address)
            );
        }
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

    #[tokio::test]
    async fn peer_route_preserves_the_logical_tuple_and_replays_on_return() {
        let bindings = Bindings::new(bound("127.0.0.1:0"));
        let primary = bindings.local_addr().unwrap();
        let leased = bound("127.0.0.3:0");
        let destination = leased.local_addr().unwrap();
        let _listener = bindings.lease(leased).unwrap();
        let enrolled = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let logical = enrolled.local_addr().unwrap();
        // Independent ports model an enrolled source rewritten by NAT.
        let mesh = tokio::net::UdpSocket::bind("127.0.0.4:0").await.unwrap();
        let physical = mesh.local_addr().unwrap();
        let peer = bindings.route_peer(logical, physical).unwrap();
        mesh.send_to(b"move", destination).await.unwrap();
        let (meta, _) = receive(&bindings).await;
        assert_eq!(meta.addr, logical);
        send(&bindings, logical, b"outstanding-input", Some(primary.ip()));
        let mut bytes = [0; 64];
        let (n, source) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            mesh.recv_from(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            (&bytes[..n], source),
            (&b"outstanding-input"[..], destination)
        );
        // No acknowledgement came back. Returning replays the exact encrypted
        // datagram to the old tuple without waiting for the loss timer.
        enrolled.send_to(b"return", primary).await.unwrap();
        let (meta, _) = receive(&bindings).await;
        assert_eq!(meta.addr, logical);
        let (n, source) = tokio::select! {
            received = enrolled.recv_from(&mut bytes) => received.unwrap(),
            _ = receive(&bindings) => panic!("no peer sent another datagram"),
        };
        assert_eq!((&bytes[..n], source), (&b"outstanding-input"[..], primary));
        let foreign = tokio::net::UdpSocket::bind("127.0.0.4:0").await.unwrap();
        foreign.send_to(b"wrong-port", destination).await.unwrap();
        let (meta, _) = receive(&bindings).await;
        assert_eq!(
            meta.addr,
            foreign.local_addr().unwrap(),
            "the same mesh IP with a foreign port is not an alias"
        );
        assert!(
            bindings.route_peer(logical, physical).is_err(),
            "conflicting owners cannot replace a live route"
        );
        drop(peer);
        mesh.send_to(b"after-retirement", destination)
            .await
            .unwrap();
        let (meta, _) = receive(&bindings).await;
        assert_eq!(meta.addr, physical, "retired aliases have no mapping");
    }

    #[tokio::test]
    async fn a_negotiated_peer_copies_output_without_a_worker_and_off_cancels_it() {
        let bindings = Bindings::new(bound("127.0.0.1:0"));
        let primary = bindings.local_addr().unwrap();
        let leased = bound("127.0.0.3:0");
        let destination = leased.local_addr().unwrap();
        let _listener = bindings.lease(leased).unwrap();
        let enrolled = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let logical = enrolled.local_addr().unwrap();
        let mesh = tokio::net::UdpSocket::bind("127.0.0.4:0").await.unwrap();
        let peer = bindings
            .route_peer(logical, mesh.local_addr().unwrap())
            .unwrap();
        peer.set_backup(true);
        mesh.send_to(b"move", destination).await.unwrap();
        receive(&bindings).await;
        send(&bindings, logical, b"encrypted-output", Some(primary.ip()));
        let mut mesh_bytes = [0; 64];
        assert_eq!(
            mesh.recv_from(&mut mesh_bytes).await.unwrap().0,
            b"encrypted-output".len()
        );
        let mut enrolled_bytes = [0; 64];
        let received = tokio::select! {
            copy = enrolled.recv_from(&mut enrolled_bytes) => copy.unwrap(),
            _ = receive(&bindings) => panic!("no peer sent a reply"),
            () = tokio::time::sleep(std::time::Duration::from_secs(5)) => panic!("copy did not arrive"),
        };
        assert_eq!(
            (&enrolled_bytes[..received.0], received.1),
            (&b"encrypted-output"[..], primary)
        );
        send(&bindings, logical, b"cancel-this-copy", Some(primary.ip()));
        assert!(!bindings.copies.lock().unwrap().empty());
        peer.set_backup(false);
        assert!(
            bindings.copies.lock().unwrap().empty(),
            "off cancels the timer and receiver reference"
        );
        assert_eq!(bindings.peers.lock().unwrap().len(), 1);
        drop(peer);
        assert_eq!(bindings.peers.lock().unwrap().len(), 0);
        assert!(bindings.copies.lock().unwrap().empty());
    }

    #[tokio::test]
    async fn an_encrypted_duplicate_cannot_move_the_reply_route() {
        let bindings = Bindings::new(bound("127.0.0.1:0"));
        let primary = bindings.local_addr().unwrap();
        let leased = bound("127.0.0.3:0");
        let destination = leased.local_addr().unwrap();
        let _listener = bindings.lease(leased).unwrap();
        let enrolled = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let logical = enrolled.local_addr().unwrap();
        let mesh = tokio::net::UdpSocket::bind("127.0.0.4:0").await.unwrap();
        let _peer = bindings
            .route_peer(logical, mesh.local_addr().unwrap())
            .unwrap();
        let packet = b"identical encrypted datagram";
        mesh.send_to(packet, destination).await.unwrap();
        assert_eq!(receive(&bindings).await.0.addr, logical);
        enrolled.send_to(packet, primary).await.unwrap();
        assert_eq!(receive(&bindings).await.0.addr, logical);
        let peer = bindings.peers.lock().unwrap();
        let peer = peer.get(logical).unwrap();
        assert_eq!(
            peer.physical,
            mesh.local_addr().unwrap(),
            "a duplicate must not steer replies"
        );
        assert!(
            peer.binding.is_some(),
            "a duplicate must not retire the reply socket"
        );
    }

    #[tokio::test]
    async fn wildcard_reply_uses_the_destination_of_the_latest_peer_packet() {
        let bindings = Bindings::new(bound("0.0.0.0:0"));
        let port = bindings.local_addr().unwrap().port();
        let enrolled_destination = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        let mesh_destination = SocketAddr::new("127.0.0.3".parse().unwrap(), port);
        let enrolled = tokio::net::UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let mesh = tokio::net::UdpSocket::bind("127.0.0.4:0").await.unwrap();
        let logical = enrolled.local_addr().unwrap();
        let _peer = bindings
            .route_peer(logical, mesh.local_addr().unwrap())
            .unwrap();
        mesh.send_to(b"move", mesh_destination).await.unwrap();
        let (meta, _) = receive(&bindings).await;
        assert_eq!(meta.addr, logical);
        assert_eq!(meta.dst_ip, Some(mesh_destination.ip()));
        send(
            &bindings,
            logical,
            b"input",
            Some(enrolled_destination.ip()),
        );
        let mut bytes = [0; 64];
        let (_, source) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            mesh.recv_from(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            source, mesh_destination,
            "a wildcard bind must follow the new local destination, not the connection's immutable source hint"
        );
        enrolled
            .send_to(b"return", enrolled_destination)
            .await
            .unwrap();
        let _ = receive(&bindings).await;
        let (_, source) = tokio::select! {
            received = enrolled.recv_from(&mut bytes) => received.unwrap(),
            _ = receive(&bindings) => panic!("no peer sent another datagram"),
        };
        assert_eq!(source, enrolled_destination);
    }

    /// Runs a lease installation between a pending socket poll and receiver
    /// registration, reproducing the notification race without sleeps.
    struct InstallWhilePending {
        inner: Arc<dyn AsyncUdpSocket>,
        install: Mutex<Option<Box<dyn FnOnce() + Send>>>,
        sends: Arc<AtomicU64>,
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
            self.inner.try_send(transmit)?;
            self.sends.fetch_add(1, Ordering::Relaxed);
            Ok(())
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
    async fn a_copy_poll_bounds_work_before_servicing_receive() {
        let sends = Arc::new(AtomicU64::new(0));
        let primary = Arc::new(InstallWhilePending {
            inner: bound("127.0.0.1:0"),
            install: Mutex::new(None),
            sends: sends.clone(),
        });
        let bindings = Bindings::new(primary);
        let mut owned = Vec::new();
        for port in 40000..40100 {
            let logical = SocketAddr::new("127.0.0.2".parse().unwrap(), port);
            let alternate = SocketAddr::new("127.0.0.3".parse().unwrap(), port);
            owned.push(bindings.route_peer(logical, alternate).unwrap());
            bindings
                .peers
                .lock()
                .unwrap()
                .get_mut(logical)
                .unwrap()
                .recent_mut()
                .keep_copying(
                    &Transmit {
                        destination: logical,
                        contents: b"ciphertext",
                        ecn: None,
                        segment_size: None,
                        src_ip: None,
                    },
                    true,
                );
        }
        // Make the owned copy clock ready without measuring elapsed time.
        bindings
            .copies
            .lock()
            .unwrap()
            .arm(tokio::time::Instant::now() - std::time::Duration::from_secs(1));
        // Let every retained entry reach its own deadline as well as publishing
        // the shared clock's readiness; no elapsed duration is asserted.
        tokio::time::sleep(crate::remote_path_copies::COPY_DELAY).await;
        let mut bytes = [0; 64];
        let mut buffers = [IoSliceMut::new(&mut bytes)];
        let mut metadata = [RecvMeta::default()];
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let _ = bindings.poll_recv(&mut cx, &mut buffers, &mut metadata);
        assert!(
            sends.load(Ordering::Relaxed) <= 32,
            "one receive poll emitted the whole peer cohort before reading its sockets: {} sends",
            sends.load(Ordering::Relaxed)
        );
        assert!(
            sends.load(Ordering::Relaxed) > 0,
            "copy clock was not ready"
        );
        let busy = SocketAddr::new("127.0.0.2".parse().unwrap(), 40000);
        for _ in 0..4 {
            // A continuously refilled first slot cannot monopolize the batch.
            for _ in 0..32 {
                bindings
                    .peers
                    .lock()
                    .unwrap()
                    .get_mut(busy)
                    .unwrap()
                    .recent_mut()
                    .keep_copying(
                        &Transmit {
                            destination: busy,
                            contents: b"busy-ciphertext",
                            ecn: None,
                            segment_size: None,
                            src_ip: None,
                        },
                        true,
                    );
            }
            let before = sends.load(Ordering::Relaxed);
            tokio::time::sleep(crate::remote_path_copies::COPY_DELAY).await;
            let _ = bindings.poll_recv(&mut cx, &mut buffers, &mut metadata);
            assert!(sends.load(Ordering::Relaxed) - before <= 32);
        }
        for peer in bindings
            .peers
            .lock()
            .unwrap()
            .iter_mut()
            .filter(|peer| peer.logical != busy)
        {
            let logical = peer.logical;
            assert!(
                peer.recent_mut()
                    .copies(bindings.primary.as_ref(), logical, true, &mut 0)
                    .is_none(),
                "an idle peer's original copy was starved by the busy slot"
            );
        }
    }

    #[tokio::test]
    async fn lease_installed_during_a_pending_poll_cannot_lose_the_receive_wakeup() {
        let primary = Arc::new(InstallWhilePending {
            inner: bound("127.0.0.1:0"),
            install: Mutex::new(None),
            sends: Arc::default(),
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
    async fn alternating_fresh_hints_cannot_amplify_retained_ciphertext() {
        for backup in [false, true] {
            let sends = Arc::new(AtomicU64::new(0));
            let primary = Arc::new(InstallWhilePending {
                inner: bound("127.0.0.1:0"),
                install: Mutex::new(None),
                sends: sends.clone(),
            });
            let bindings = Bindings::new(primary);
            let mesh = Arc::new(InstallWhilePending {
                inner: bound("127.0.0.2:0"),
                install: Mutex::new(None),
                sends: sends.clone(),
            });
            let lease = bindings.lease(mesh.clone()).unwrap();
            let enrolled = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let alternate = std::net::UdpSocket::bind("127.0.0.2:0").unwrap();
            let logical = enrolled.local_addr().unwrap();
            let alternative = alternate.local_addr().unwrap();
            let peer = bindings.route_peer(logical, alternative).unwrap();
            let mut writable = bindings.clone().create_io_poller();
            std::future::poll_fn(|cx| writable.as_mut().poll_writable(cx))
                .await
                .unwrap();
            send(&bindings, logical, b"cold enrolled ciphertext", None);
            let mut initial = [0_u8; 32];
            initial[24..].copy_from_slice(&99_u64.to_le_bytes());
            let buffers = [IoSliceMut::new(&mut initial)];
            let mut metadata = [RecvMeta {
                addr: alternative,
                len: 32,
                stride: 32,
                dst_ip: Some(mesh.local_addr().unwrap().ip()),
                ..RecvMeta::default()
            }];
            bindings.receive_peer(Some(lease.id), &buffers, &mut metadata);
            assert_eq!(
                sends.load(Ordering::Relaxed),
                1,
                "an upgrade must not replay cold enrolled history"
            );
            // Negotiate only after the cold send so this fixture counts
            // original-history recovery, independently of alternative replies.
            peer.set_backup(backup);
            for index in 0_u64..8 {
                let mut ciphertext = [0_u8; 32];
                ciphertext[24..].copy_from_slice(&index.to_le_bytes());
                send(&bindings, logical, &ciphertext, None);
            }
            // Inject distinct public hints at the adapter boundary. Both real
            // UDP sockets count successful physical writes; return drains share
            // the owned clock and complete before the next route transition.
            for index in 0_u64..6 {
                if index == 4 {
                    assert_eq!(
                        sends.load(Ordering::Relaxed),
                        17,
                        "mesh ciphertext replays once on return; upgrading needs no old enrolled burst"
                    );
                    let mut new_packet = [0_u8; 32];
                    new_packet[24..].copy_from_slice(&8_u64.to_le_bytes());
                    send(&bindings, logical, &new_packet, None);
                }
                let on_mesh = index % 2 != 0;
                let mut hint = [0_u8; 32];
                hint[24..].copy_from_slice(&(100 + index).to_le_bytes());
                let buffers = [IoSliceMut::new(&mut hint)];
                let mut metadata = [RecvMeta {
                    addr: if on_mesh { alternative } else { logical },
                    len: 32,
                    stride: 32,
                    dst_ip: Some(if on_mesh {
                        mesh.local_addr().unwrap().ip()
                    } else {
                        bindings.local_addr().unwrap().ip()
                    }),
                    ..RecvMeta::default()
                }];
                bindings.receive_peer(on_mesh.then_some(lease.id), &buffers, &mut metadata);
                poll_return_replay(&bindings, &sends, if index < 4 { 17 } else { 19 }).await;
            }
            assert_eq!(
                sends.load(Ordering::Relaxed),
                19,
                "new mesh ciphertext remains eligible for fast enrolled return"
            );
        }
    }
    /// Drive a fixed number of owned receive polls. Timer publication is allowed
    /// between polls, but no elapsed-time threshold determines correctness.
    async fn poll_return_replay(bindings: &Bindings, sends: &AtomicU64, expected: u64) {
        for _ in 0..8 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            let before = sends.load(Ordering::Relaxed);
            let mut bytes = [0; 64];
            let mut buffers = [IoSliceMut::new(&mut bytes)];
            let mut metadata = [RecvMeta::default()];
            std::future::poll_fn(|cx| {
                let _ = bindings.poll_recv(cx, &mut buffers, &mut metadata);
                Poll::Ready(())
            })
            .await;
            assert!(
                sends.load(Ordering::Relaxed) - before <= 32,
                "return replay exceeded the shared send budget before receiving"
            );
        }
        assert_eq!(sends.load(Ordering::Relaxed), expected);
    }

    async fn enrolled_return_replay_is_bounded_and_consumed(backup: bool) {
        let sends = Arc::new(AtomicU64::new(0));
        let primary = Arc::new(InstallWhilePending {
            inner: bound("127.0.0.1:0"),
            install: Mutex::new(None),
            sends: sends.clone(),
        });
        let bindings = Bindings::new(primary);
        let mesh = Arc::new(InstallWhilePending {
            inner: bound("127.0.0.2:0"),
            install: Mutex::new(None),
            sends: sends.clone(),
        });
        let lease = bindings.lease(mesh.clone()).unwrap();
        let enrolled = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let alternate = std::net::UdpSocket::bind("127.0.0.2:0").unwrap();
        let logical = enrolled.local_addr().unwrap();
        let alternative = alternate.local_addr().unwrap();
        let peer = bindings.route_peer(logical, alternative).unwrap();
        peer.set_backup(backup);
        let mut writable = bindings.clone().create_io_poller();
        std::future::poll_fn(|cx| writable.as_mut().poll_writable(cx))
            .await
            .unwrap();
        // Inject the physical receive ordering directly. Raw hints prove no
        // identity; the owned clock below only schedules redundant ciphertext.
        let hint = |value: u64, on_mesh: bool| {
            let mut ciphertext = [0_u8; 32];
            ciphertext[24..].copy_from_slice(&value.to_le_bytes());
            let buffers = [IoSliceMut::new(&mut ciphertext)];
            let mut metadata = [RecvMeta {
                addr: if on_mesh { alternative } else { logical },
                len: 32,
                stride: 32,
                dst_ip: Some(if on_mesh {
                    mesh.local_addr().unwrap().ip()
                } else {
                    bindings.local_addr().unwrap().ip()
                }),
                ..RecvMeta::default()
            }];
            bindings.receive_peer(on_mesh.then_some(lease.id), &buffers, &mut metadata);
            assert_eq!(metadata[0].addr, logical);
        };
        hint(1000, true);
        for value in 0_u64..64 {
            let mut ciphertext = [0_u8; 32];
            ciphertext[24..].copy_from_slice(&value.to_le_bytes());
            send(&bindings, logical, &ciphertext, None);
        }
        assert_eq!(sends.load(Ordering::Relaxed), 64);
        hint(1001, false);
        assert_eq!(
            sends.load(Ordering::Relaxed),
            64,
            "a return must hand its receive batch to QUIC before replaying retained history"
        );
        hint(1001, true);
        assert_eq!(sends.load(Ordering::Relaxed), 64);
        {
            let peers = bindings.peers.lock().unwrap();
            let routed = peers.get(logical).unwrap();
            assert_eq!(routed.physical, logical);
            assert_eq!(routed.binding, None);
        }
        // Turning negotiated backups off cannot cancel already requested
        // enrolled recovery, including a return to a legacy-only path.
        peer.set_backup(false);
        poll_return_replay(&bindings, &sends, 128).await;
        // The delayed original cannot safely become a fresh hint: that would
        // also let an arbitrary delayed duplicate move a proven return route.
        // A new mesh transmission can supply a routing hint; authenticated path
        // proof remains the caller's responsibility above this adapter.
        hint(1002, true);
        assert_eq!(sends.load(Ordering::Relaxed), 128);
        {
            let peers = bindings.peers.lock().unwrap();
            let routed = peers.get(logical).unwrap();
            assert_eq!(routed.physical, alternative);
            assert_eq!(routed.binding, Some(lease.id));
        }
        hint(1003, false);
        poll_return_replay(&bindings, &sends, 128).await;
        // Consuming the old return must not make newly sent mesh ciphertext
        // ineligible for its own subsequent enrolled recovery.
        hint(1004, true);
        send(&bindings, logical, b"new mesh ciphertext", None);
        assert_eq!(sends.load(Ordering::Relaxed), 129);
        hint(1005, false);
        assert_eq!(sends.load(Ordering::Relaxed), 129);
        poll_return_replay(&bindings, &sends, 130).await;
        hint(1006, true);
        send(&bindings, logical, b"retired mesh ciphertext", None);
        hint(1007, false);
        drop(peer);
        assert!(bindings.copies.lock().unwrap().empty());
        poll_return_replay(&bindings, &sends, 131).await;
    }

    #[tokio::test]
    async fn negotiated_enrolled_return_replay_is_bounded_and_consumed_once() {
        enrolled_return_replay_is_bounded_and_consumed(true).await;
    }

    #[tokio::test]
    async fn legacy_enrolled_return_replay_is_bounded_and_consumed_once() {
        enrolled_return_replay_is_bounded_and_consumed(false).await;
    }

    /// Both a leased mesh socket and a wildcard primary must preserve enrolled
    /// source selection while sending the optional copy from mesh coordinates.
    #[tokio::test]
    async fn enrolled_dual_replies_preserve_primary_and_mesh_sources() {
        for leased in [false, true] {
            let bindings = Bindings::new(bound(if leased { "127.0.0.1:0" } else { "0.0.0.0:0" }));
            let port = bindings.local_addr().unwrap().port();
            let enrolled_destination = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
            let mesh_destination = SocketAddr::new("127.0.0.2".parse().unwrap(), port);
            let _lease = leased.then(|| {
                bindings
                    .lease(bound(&mesh_destination.to_string()))
                    .unwrap()
            });
            let enrolled = tokio::net::UdpSocket::bind("127.0.0.3:0").await.unwrap();
            let mesh = tokio::net::UdpSocket::bind("127.0.0.4:0").await.unwrap();
            let logical = enrolled.local_addr().unwrap();
            let peer = bindings
                .route_peer(logical, mesh.local_addr().unwrap())
                .unwrap();
            peer.set_backup(true);
            mesh.send_to(b"mesh-first", mesh_destination).await.unwrap();
            receive(&bindings).await;
            enrolled
                .send_to(b"return-fresh", enrolled_destination)
                .await
                .unwrap();
            receive(&bindings).await;
            send(&bindings, logical, b"dual-reply", None);
            let mut bytes = [0; 64];
            let (count, source) = enrolled.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..count], b"dual-reply");
            assert_eq!(source, enrolled_destination);
            let (count, source) = tokio::select! {
                result = mesh.recv_from(&mut bytes) => result.unwrap(),
                _ = receive(&bindings) => panic!("no peer sent another packet"),
            };
            assert_eq!(&bytes[..count], b"dual-reply");
            assert_eq!(source, mesh_destination);
            let peers = bindings.peers.lock().unwrap();
            let selected = peers.get(logical).unwrap();
            assert_eq!(selected.physical, logical);
            assert_eq!(selected.binding, None);
            assert_eq!(selected.local, Some(enrolled_destination.ip()));
        }
    }

    /// An unknown mesh source stays dormant until a real duplicate supplies
    /// coordinates. The duplicate cannot move the selected enrolled primary.
    #[tokio::test]
    async fn unknown_mesh_reply_waits_for_duplicate_coordinates_and_off_retires_it() {
        let bindings = Bindings::new(bound("127.0.0.1:0"));
        let primary = bindings.local_addr().unwrap();
        let mesh_destination = SocketAddr::new("127.0.0.2".parse().unwrap(), primary.port());
        let _lease = bindings
            .lease(bound(&mesh_destination.to_string()))
            .unwrap();
        let enrolled = tokio::net::UdpSocket::bind("127.0.0.3:0").await.unwrap();
        let mesh = tokio::net::UdpSocket::bind("127.0.0.4:0").await.unwrap();
        let logical = enrolled.local_addr().unwrap();
        let peer = bindings
            .route_peer(logical, mesh.local_addr().unwrap())
            .unwrap();
        peer.set_backup(true);
        enrolled.send_to(b"identical", primary).await.unwrap();
        receive(&bindings).await;
        send(&bindings, logical, b"dormant", None);
        let mut bytes = [0; 64];
        assert_eq!(enrolled.recv_from(&mut bytes).await.unwrap().0, 7);
        assert!(!bindings.copies.lock().unwrap().armed());
        assert!(
            bindings
                .peers
                .lock()
                .unwrap()
                .get(logical)
                .unwrap()
                .recent()
                .deadline()
                .is_none()
        );
        mesh.send_to(b"identical", mesh_destination).await.unwrap();
        receive(&bindings).await;
        let (count, source) = tokio::select! {
            result = mesh.recv_from(&mut bytes) => result.unwrap(),
            _ = receive(&bindings) => panic!("no peer sent another packet"),
        };
        assert_eq!(&bytes[..count], b"dormant");
        assert_eq!(source, mesh_destination);
        assert_eq!(
            bindings
                .peers
                .lock()
                .unwrap()
                .get(logical)
                .unwrap()
                .physical,
            logical
        );
        send(&bindings, logical, b"cancel", None);
        assert_eq!(enrolled.recv_from(&mut bytes).await.unwrap().0, 6);
        peer.set_backup(false);
        assert!(bindings.copies.lock().unwrap().empty());
        let mut buffers = [IoSliceMut::new(&mut bytes)];
        let mut metadata = [RecvMeta::default()];
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let _ = bindings.poll_recv(&mut cx, &mut buffers, &mut metadata);
        assert_eq!(
            mesh.try_recv_from(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn retiring_mesh_lease_cancels_only_queued_alternative_reply() {
        let bindings = Bindings::new(bound("127.0.0.1:0"));
        let primary = bindings.local_addr().unwrap();
        let mesh_destination = SocketAddr::new("127.0.0.2".parse().unwrap(), primary.port());
        let lease = bindings
            .lease(bound(&mesh_destination.to_string()))
            .unwrap();
        let enrolled = tokio::net::UdpSocket::bind("127.0.0.3:0").await.unwrap();
        let mesh = tokio::net::UdpSocket::bind("127.0.0.4:0").await.unwrap();
        let logical = enrolled.local_addr().unwrap();
        let peer = bindings
            .route_peer(logical, mesh.local_addr().unwrap())
            .unwrap();
        peer.set_backup(true);
        mesh.send_to(b"mesh", mesh_destination).await.unwrap();
        receive(&bindings).await;
        enrolled.send_to(b"return", primary).await.unwrap();
        receive(&bindings).await;
        send(&bindings, logical, b"survives-on-primary", None);
        drop(lease);
        assert!(
            !bindings.copies.lock().unwrap().armed(),
            "retired mesh lease left an idle copy timer armed"
        );
        let mut bytes = [0; 64];
        let (count, source) = enrolled.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..count], b"survives-on-primary");
        assert_eq!(source, primary);
        {
            let peers = bindings.peers.lock().unwrap();
            let selected = peers.get(logical).unwrap();
            assert!(selected.mesh.is_none());
            assert!(selected.recent().deadline().is_none());
            assert_eq!(selected.physical, logical);
        }
        let mut buffers = [IoSliceMut::new(&mut bytes)];
        let mut metadata = [RecvMeta::default()];
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let _ = bindings.poll_recv(&mut cx, &mut buffers, &mut metadata);
        assert_eq!(
            mesh.try_recv_from(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn dropping_one_peer_removes_alternative_work_while_another_peer_lives() {
        let bindings = Bindings::new(bound("127.0.0.1:0"));
        let primary = bindings.local_addr().unwrap();
        let mesh_destination = SocketAddr::new("127.0.0.2".parse().unwrap(), primary.port());
        let _lease = bindings
            .lease(bound(&mesh_destination.to_string()))
            .unwrap();
        let enrolled = tokio::net::UdpSocket::bind("127.0.0.3:0").await.unwrap();
        let mesh = tokio::net::UdpSocket::bind("127.0.0.4:0").await.unwrap();
        let logical = enrolled.local_addr().unwrap();
        let peer = bindings
            .route_peer(logical, mesh.local_addr().unwrap())
            .unwrap();
        let _survivor = bindings
            .route_peer(
                "127.0.0.5:49999".parse().unwrap(),
                "127.0.0.6:49999".parse().unwrap(),
            )
            .unwrap();
        peer.set_backup(true);
        mesh.send_to(b"mesh", mesh_destination).await.unwrap();
        receive(&bindings).await;
        enrolled.send_to(b"return", primary).await.unwrap();
        receive(&bindings).await;
        send(&bindings, logical, b"primary-before-retirement", None);
        drop(peer);
        assert!(
            !bindings.copies.lock().unwrap().armed(),
            "retired peer left an idle copy timer armed"
        );
        {
            let peers = bindings.peers.lock().unwrap();
            assert_eq!(peers.len(), 1);
            assert!(peers.get(logical).is_none());
        }
        let mut bytes = [0; 64];
        let (count, _) = enrolled.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..count], b"primary-before-retirement");
        // Publish the already-due shared clock; another peer keeps the endpoint
        // alive, but the retired peer owns no payload that it could send.
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        let mut buffers = [IoSliceMut::new(&mut bytes)];
        let mut metadata = [RecvMeta::default()];
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let _ = bindings.poll_recv(&mut cx, &mut buffers, &mut metadata);
        assert_eq!(
            mesh.try_recv_from(&mut bytes).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn retiring_one_route_preserves_another_peers_enrolled_return() {
        for retire_peer in [false, true] {
            let bindings = Bindings::new(bound("127.0.0.1:0"));
            let primary = bindings.local_addr().unwrap();
            let mesh_destination = SocketAddr::new("127.0.0.2".parse().unwrap(), primary.port());
            let lease = bindings
                .lease(bound(&mesh_destination.to_string()))
                .unwrap();
            let enrolled = tokio::net::UdpSocket::bind("127.0.0.3:0").await.unwrap();
            let mesh = tokio::net::UdpSocket::bind("127.0.0.4:0").await.unwrap();
            let logical = enrolled.local_addr().unwrap();
            let peer = bindings
                .route_peer(logical, mesh.local_addr().unwrap())
                .unwrap();
            let survivor_socket = tokio::net::UdpSocket::bind("127.0.0.5:0").await.unwrap();
            let survivor_logical = survivor_socket.local_addr().unwrap();
            let _survivor = bindings
                .route_peer(
                    survivor_logical,
                    SocketAddr::new("127.0.0.6".parse().unwrap(), survivor_logical.port()),
                )
                .unwrap();
            peer.set_backup(true);
            mesh.send_to(b"mesh", mesh_destination).await.unwrap();
            receive(&bindings).await;
            enrolled.send_to(b"return", primary).await.unwrap();
            receive(&bindings).await;
            send(&bindings, logical, b"cancelled-alternative", None);
            let at = {
                let mut peers = bindings.peers.lock().unwrap();
                let survivor = peers.get_mut(survivor_logical).unwrap();
                survivor.recent_mut().keep(&Transmit {
                    destination: survivor_logical,
                    contents: b"surviving-return",
                    ecn: None,
                    segment_size: None,
                    src_ip: None,
                });
                survivor.recent_mut().replay(None).unwrap()
            };
            bindings.copies.lock().unwrap().arm(at);
            if retire_peer {
                drop(peer);
            } else {
                drop(lease);
            }
            assert!(bindings.copies.lock().unwrap().armed());
            let mut bytes = [0; 64];
            let (count, source) = tokio::select! {
                result = survivor_socket.recv_from(&mut bytes) => result.unwrap(),
                _ = receive(&bindings) => panic!("no peer sent another packet"),
            };
            assert_eq!(&bytes[..count], b"surviving-return");
            assert_eq!(source, primary);
        }
    }

    #[tokio::test]
    async fn backup_withdrawal_reconciles_idle_peers_without_canceling_another_return() {
        for pending_return in [false, true] {
            let bindings = Bindings::new(bound("127.0.0.1:0"));
            let primary = bindings.local_addr().unwrap();
            let mesh_destination = SocketAddr::new("127.0.0.2".parse().unwrap(), primary.port());
            let _lease = bindings
                .lease(bound(&mesh_destination.to_string()))
                .unwrap();
            let enrolled = tokio::net::UdpSocket::bind("127.0.0.3:0").await.unwrap();
            let mesh = tokio::net::UdpSocket::bind("127.0.0.4:0").await.unwrap();
            let logical = enrolled.local_addr().unwrap();
            let peer = bindings
                .route_peer(logical, mesh.local_addr().unwrap())
                .unwrap();
            let survivor_socket = tokio::net::UdpSocket::bind("127.0.0.5:0").await.unwrap();
            let survivor_logical = survivor_socket.local_addr().unwrap();
            let survivor = bindings
                .route_peer(
                    survivor_logical,
                    SocketAddr::new("127.0.0.6".parse().unwrap(), survivor_logical.port()),
                )
                .unwrap();
            peer.set_backup(true);
            survivor.set_backup(true);
            mesh.send_to(b"mesh", mesh_destination).await.unwrap();
            receive(&bindings).await;
            enrolled.send_to(b"return", primary).await.unwrap();
            receive(&bindings).await;
            send(&bindings, logical, b"withdrawn-alternative", None);
            if pending_return {
                let at = {
                    let mut peers = bindings.peers.lock().unwrap();
                    let queued = peers.get_mut(survivor_logical).unwrap();
                    queued.recent_mut().keep(&Transmit {
                        destination: survivor_logical,
                        contents: b"surviving-return",
                        ecn: None,
                        segment_size: None,
                        src_ip: None,
                    });
                    queued.recent_mut().replay(None).unwrap()
                };
                bindings.copies.lock().unwrap().arm(at);
            }
            peer.set_backup(false);
            assert_eq!(
                bindings.copies.lock().unwrap().armed(),
                pending_return,
                "withdrawing the last queued alternative must cancel its timer independently of idle peer capabilities"
            );
            let mut bytes = [0; 64];
            if pending_return {
                let (count, source) = tokio::select! {
                    result = survivor_socket.recv_from(&mut bytes) => result.unwrap(),
                    _ = receive(&bindings) => panic!("no peer sent another packet"),
                };
                assert_eq!(&bytes[..count], b"surviving-return");
                assert_eq!(source, primary);
            }
            assert_eq!(
                mesh.try_recv_from(&mut bytes).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
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
