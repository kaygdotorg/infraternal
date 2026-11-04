//! Moves an established server connection between its enrolled path and the mesh path below QUIC, keeping every stream and writer [164,215,263], #201.
//!
//! The host's QUIC connection always names the enrolled server address (its
//! logical remote). This socket decides where those datagrams physically go:
//! to that address, or to the server's mesh address. Datagrams from either
//! physical address are reported as coming from the logical one, so the
//! client connection never sees an address change and keeps its streams,
//! writer bindings and congestion state. Trusted server aliases likewise map
//! the host's admitted physical tuples onto its enrolled logical tuple.
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

use crate::{remote_path_copies::CopyClock, remote_peer_routes::Recent};

/// Per-endpoint state about the mesh route and recent traffic.
struct Paths {
    mesh: Option<SocketAddr>,
    resend: Recent,
    mesh_heard: Option<Instant>,
    /// First receive boundary and most recent successful physical emission.
    #[cfg(test)]
    mesh_sent: Option<(Instant, Instant)>,
    #[cfg(test)]
    probe_generation: u64,
    #[cfg(test)]
    probe_queued: Option<(u64, Instant)>,
    enrolled_heard: Option<Instant>,
}

/// Physical routing for one connection's logical server address.
pub struct PathSocket {
    socket: Arc<dyn AsyncUdpSocket>,
    /// Set before endpoint creation, only after kernel aggregation is disabled.
    single_receive: bool,
    logical: SocketAddr,
    on_mesh: AtomicBool,
    paths: Mutex<Paths>,
    /// Datagrams received from the mesh address, for proof and liveness.
    mesh_datagrams: AtomicU64,
    /// Successful connection transmits, excluding replay/copies beneath QUIC.
    /// The dedicated client endpoint owns exactly one connection.
    #[cfg(test)]
    transmits: AtomicU64,
    heard: tokio::sync::Notify,
    #[cfg(test)]
    sent: tokio::sync::Notify,
    backup: AtomicBool,
    copies: Mutex<CopyClock>,
    proof: Mutex<crate::remote_path_proof::Probe>,
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

/// Owns one pending probe's first successful physical send. Replacing or
/// dropping this request retires its observation without retaining the socket.
#[cfg(test)]
pub struct MeshTransmission<'a> {
    path: &'a PathSocket,
    generation: u64,
}
#[cfg(test)]
impl MeshTransmission<'_> {
    /// Confirm a newly constructed ack-eliciting DATAGRAM has left the socket.
    /// Quinn counts transmits when constructed, including one buffered behind
    /// socket backpressure. Comparing that count with physical completions
    /// prevents an older ACK-only transmit from starting the response deadline.
    /// Connection statistics must be read here, outside the socket callback:
    /// Quinn holds its connection mutex while calling `try_send`.
    #[cfg(test)]
    pub(crate) async fn probe_sent(
        &self,
        connection: &quinn::Connection,
        datagrams_before: u64,
    ) -> io::Result<(Instant, Instant)> {
        loop {
            let notified = self.path.sent.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let stats = connection.stats();
            let (emitted, transmits) = {
                let paths = self.path.paths.lock().map_err(|_| io::ErrorKind::Other)?;
                if paths
                    .probe_queued
                    .is_none_or(|(generation, _)| generation != self.generation)
                {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                (paths.mesh_sent, self.path.transmits.load(Ordering::Acquire))
            };
            if let Some(emitted) = emitted
                && stats.frame_tx.datagram != datagrams_before
                && transmits >= stats.udp_tx.ios
            {
                // Responses may already have arrived while this waiter was
                // unscheduled. Keep their original receive boundary separate
                // from the physical flush clock; waiter delay adds no budget.
                return Ok(emitted);
            }
            notified.await;
        }
    }
    /// Wait for the first successful send after arming this request. A delayed
    /// waiter must not adopt a later ACK-only packet as its response clock.
    ///
    /// # Errors
    /// Returns `Interrupted` if replaced or the mesh path changed, or a socket-state error.
    pub async fn sent(&self) -> io::Result<Instant> {
        loop {
            let notified = self.path.sent.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let sent = {
                let paths = self.path.paths.lock().map_err(|_| io::ErrorKind::Other)?;
                if paths
                    .probe_queued
                    .is_none_or(|(generation, _)| generation != self.generation)
                {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                paths.mesh_sent.map(|(first, _)| first)
            };
            if let Some(sent) = sent {
                return Ok(sent);
            }
            notified.await;
        }
    }
}
#[cfg(test)]
impl Drop for MeshTransmission<'_> {
    fn drop(&mut self) {
        if let Ok(mut paths) = self.path.paths.lock()
            && paths
                .probe_queued
                .is_some_and(|(generation, _)| generation == self.generation)
        {
            paths.probe_queued = None;
            paths.mesh_sent = None;
            drop(paths);
            self.path.sent.notify_waiters();
        }
    }
}

/// One borrowed proof epoch owns its pending sequence. Cancellation retires
/// only that epoch, never a newer proof started on the same live socket.
pub struct PathProofEpoch<'a> {
    path: &'a PathSocket,
    generation: u64,
}
impl Drop for PathProofEpoch<'_> {
    fn drop(&mut self) {
        if let Ok(mut proof) = self.path.proof.lock() {
            proof.retire(self.generation);
        }
    }
}

impl PathSocket {
    /// `logical` is the enrolled server address the connection was dialed to.
    #[must_use]
    pub fn new(socket: Arc<dyn AsyncUdpSocket>, logical: SocketAddr) -> Arc<Self> {
        Self::with_single_receive(socket, logical, false)
    }

    /// Register a fresh outgoing socket for one host connection. Send
    /// segmentation stays enabled; server receive aggregation is independent.
    /// Receive aggregation multiplies the endpoint's per-host scratch space.
    /// Advertise a single-datagram buffer only after the kernel disables it.
    ///
    /// # Errors
    /// Propagates the selected runtime's socket registration errors.
    #[cfg(feature = "agent")]
    pub fn from_udp(
        socket: std::net::UdpSocket,
        logical: SocketAddr,
        runtime: &dyn quinn::Runtime,
    ) -> io::Result<Arc<Self>> {
        #[cfg(target_os = "linux")]
        let control = std::os::fd::AsFd::as_fd(&socket).try_clone_to_owned().ok();
        // Runtime registration enables aggregation. Disable it afterwards,
        // before dialing can queue any authenticated incoming datagrams.
        let socket = runtime.wrap_udp_socket(socket)?;
        #[cfg(target_os = "linux")]
        let single_receive = control.as_ref().is_some_and(|control| {
            nix::sys::socket::setsockopt(control, nix::sys::socket::sockopt::UdpGroSegment, &false)
                .is_ok()
        });
        #[cfg(not(target_os = "linux"))]
        let single_receive = false;
        Ok(Self::with_single_receive(socket, logical, single_receive))
    }

    fn with_single_receive(
        socket: Arc<dyn AsyncUdpSocket>,
        logical: SocketAddr,
        single_receive: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket,
            single_receive,
            logical,
            on_mesh: AtomicBool::new(false),
            paths: Mutex::new(Paths {
                mesh: None,
                resend: Recent::default(),
                mesh_heard: None,
                #[cfg(test)]
                mesh_sent: None,
                #[cfg(test)]
                probe_generation: 0,
                #[cfg(test)]
                probe_queued: None,
                enrolled_heard: None,
            }),
            mesh_datagrams: AtomicU64::new(0),
            #[cfg(test)]
            transmits: AtomicU64::new(0),
            heard: tokio::sync::Notify::new(),
            #[cfg(test)]
            sent: tokio::sync::Notify::new(),
            backup: AtomicBool::new(false),
            copies: Mutex::default(),
            proof: Mutex::default(),
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
        if let Ok(mut proof) = self.proof.lock() {
            proof.cancel();
        }
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
            #[cfg(test)]
            {
                paths.mesh_sent = None;
                paths.probe_queued = None;
            }
            paths.resend.clear();
            self.on_mesh.store(true, Ordering::Release);
        }
        #[cfg(test)]
        self.sent.notify_waiters();
    }

    /// Enable overlap only after the authenticated peer advertises support.
    pub fn set_backup(&self, enabled: bool) {
        self.backup.store(enabled, Ordering::Release);
        if !enabled {
            if let Ok(mut paths) = self.paths.lock() {
                paths.resend.cancel_copies();
            }
            if let Ok(mut clock) = self.copies.lock() {
                clock.clear();
            }
        }
    }

    /// Return to the enrolled address and resend the bounded recent mesh history.
    /// The mesh address stays mapped, so its late replies are still accepted.
    pub fn use_enrolled(&self) {
        if let Ok(mut proof) = self.proof.lock() {
            proof.cancel();
        }
        self.set_backup(false);
        let pending = match self.paths.lock() {
            Ok(mut paths) => {
                self.on_mesh.store(false, Ordering::Release);
                #[cfg(test)]
                {
                    paths.mesh_sent = None;
                    paths.probe_queued = None;
                }
                paths.resend.take()
            }
            Err(_) => return,
        };
        #[cfg(test)]
        self.sent.notify_waiters();
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

    /// Own a fresh challenge epoch; dropping its future retires pending replies.
    /// # Errors
    /// Propagates unavailable key export, poisoned state or generation exhaustion.
    pub fn proof_epoch(&self, connection: &quinn::Connection) -> io::Result<PathProofEpoch<'_>> {
        self.prepare_proof(connection)?;
        let mut proof = self.proof.lock().map_err(|_| io::ErrorKind::Other)?;
        let generation = proof.begin()?;
        Ok(PathProofEpoch {
            path: self,
            generation,
        })
    }

    /// Arm session-specific authentication before probing the physical mesh tuple.
    /// # Errors
    /// Propagates exporter and socket-state errors.
    pub fn prepare_proof(&self, connection: &quinn::Connection) -> io::Result<()> {
        self.prepare_proof_with(connection.stable_id(), || {
            crate::remote_path_proof::PathKey::from_connection(connection)
        })
    }

    fn prepare_proof_with(
        &self,
        id: usize,
        export: impl FnOnce() -> io::Result<crate::remote_path_proof::PathKey>,
    ) -> io::Result<()> {
        if !self
            .proof
            .lock()
            .map_err(|_| io::ErrorKind::Other)?
            .has_key(id)
        {
            // Export locks the connection. Its send callback may need paths,
            // while receive holds paths before proof: never hold proof here.
            let key = export()?;
            self.proof
                .lock()
                .map_err(|_| io::ErrorKind::Other)?
                .install_key(id, key);
        }
        Ok(())
    }

    /// Send a fixed authenticated challenge directly, without copying it to enrolled.
    /// # Errors
    /// Propagates physical send errors; no network clock starts on backpressure.
    pub fn send_proof(&self) -> io::Result<Instant> {
        self.send_path_proof(true)
    }

    /// Probe a selected physical tuple without copying its challenge elsewhere.
    /// # Errors
    /// Propagates authentication, state and physical socket errors.
    pub fn send_path_proof(&self, mesh: bool) -> io::Result<Instant> {
        let destination = if mesh {
            self.paths
                .lock()
                .map_err(|_| io::ErrorKind::Other)?
                .mesh
                .ok_or(io::ErrorKind::NotConnected)?
        } else {
            self.logical
        };
        let mut proof = self.proof.lock().map_err(|_| io::ErrorKind::Other)?;
        let packet = proof.request(destination)?;
        self.socket.try_send(&Transmit {
            destination,
            ecn: None,
            contents: &packet,
            segment_size: None,
            src_ip: None,
        })?;
        let sent = Instant::now();
        Ok(proof.sent(sent))
    }

    /// An exact physical tuple, current challenge and valid session MAC are all required.
    #[must_use]
    pub fn path_authenticated_since(&self, since: Instant, mesh: bool) -> bool {
        let destination = if mesh {
            self.paths.lock().ok().and_then(|paths| paths.mesh)
        } else {
            Some(self.logical)
        };
        destination.is_some_and(|destination| {
            self.proof
                .lock()
                .is_ok_and(|proof| proof.answered_since(since, destination))
        })
    }

    /// Only this mesh tuple's authenticated response can renew its health.
    #[must_use]
    pub fn mesh_authenticated_since(&self, since: Instant) -> bool {
        self.path_authenticated_since(since, true)
    }

    /// Response allowance follows this physical path's authenticated RTT and
    /// variance, rather than the connection's possibly enrolled-copy RTT.
    #[must_use]
    pub fn proof_allowance(
        &self,
        fallback: std::time::Duration,
        margin: std::time::Duration,
    ) -> std::time::Duration {
        self.proof
            .lock()
            .map_or(fallback + margin, |proof| proof.allowance(fallback, margin))
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

    /// Wait for a mesh datagram at or after `since`, including one that arrived
    /// before this future was polled. Registration precedes the clock check so
    /// a concurrent receive cannot disappear between observation and waiting.
    pub async fn mesh_heard(&self, since: Instant) {
        loop {
            let notified = self.heard.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.heard_since(since) {
                return;
            }
            notified.await;
        }
    }

    /// Arm before queueing a probe, then await its first physical transmission.
    /// Ciphertext packet types stay opaque here: this is a send boundary, not
    /// a packet-number acknowledgement. A later send cannot move that boundary.
    ///
    /// # Errors
    /// Returns a socket-state error if routing state is unavailable.
    #[cfg(test)]
    pub fn mesh_transmitted_after(&self, queued: Instant) -> io::Result<MeshTransmission<'_>> {
        let mut paths = self.paths.lock().map_err(|_| io::ErrorKind::Other)?;
        paths.probe_generation = paths.probe_generation.wrapping_add(1);
        paths.probe_queued = Some((paths.probe_generation, queued));
        paths.mesh_sent = None;
        let generation = paths.probe_generation;
        drop(paths);
        // A superseded request must observe cancellation even if no packet follows.
        #[cfg(test)]
        self.sent.notify_waiters();
        Ok(MeshTransmission {
            path: self,
            generation,
        })
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
        // Record the successful send boundary before waiting for routing/history
        // locks; their scheduling delay must not move the response deadline.
        #[cfg(test)]
        let now = Instant::now();
        if let Ok(mut paths) = self.paths.lock() {
            if let Some(at) = paths
                .resend
                .keep_copying(transmit, self.backup.load(Ordering::Acquire))
                && let Ok(mut clock) = self.copies.lock()
            {
                clock.arm(at);
            }
            #[cfg(test)]
            if paths.probe_queued.is_some_and(|(_, queued)| now >= queued) {
                let first = paths.mesh_sent.map_or(now, |(first, _)| first);
                paths.mesh_sent = Some((first, now));
            }
        }
    }
}

impl AsyncUdpSocket for PathSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.socket.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        if transmit.destination != self.logical || !self.on_mesh.load(Ordering::Acquire) {
            self.socket.try_send(transmit)?;
            if transmit.destination == self.logical {
                #[cfg(test)]
                self.transmits.fetch_add(1, Ordering::Release);
                #[cfg(test)]
                self.sent.notify_waiters();
            }
            return Ok(());
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
        // Publish completion after its clock: an observed count can never
        // pair the newly flushed probe with an older ACK-only timestamp.
        #[cfg(test)]
        self.transmits.fetch_add(1, Ordering::Release);
        #[cfg(test)]
        self.sent.notify_waiters();
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let due = self.on_mesh.load(Ordering::Acquire)
            && self.backup.load(Ordering::Acquire)
            && self.copies.lock().is_ok_and(|mut clock| clock.poll(cx));
        let mut copy_budget = crate::remote_path_copies::COPY_BATCH;
        if due
            && let Ok(mut paths) = self.paths.lock()
            && let Some(at) =
                paths
                    .resend
                    .copies(self.socket.as_ref(), self.logical, true, &mut copy_budget)
            && let Ok(mut clock) = self.copies.lock()
        {
            clock.arm(at);
        }
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
        for (index, received) in meta[..count].iter_mut().enumerate() {
            if Some(received.addr) == paths.mesh || received.addr == self.logical {
                // Authentication uses the physical tuple before normalization.
                // A forged enrolled reply can never renew the mesh proof.
                if crate::remote_path_proof::contains_probes(
                    &bufs[index][..received.len],
                    received.stride,
                ) {
                    let physical = received.addr;
                    let mut proof = self.proof.lock().ok();
                    received.len = crate::remote_path_proof::receive_probes(
                        &mut bufs[index][..received.len],
                        received.stride,
                        |packet| {
                            if let Some(proof) = proof.as_mut() {
                                proof.receive(packet, physical);
                            }
                        },
                    );
                }
            }
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
        if self.single_receive {
            1
        } else {
            self.socket.max_receive_segments()
        }
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

    #[cfg(all(feature = "agent", target_os = "linux"))]
    #[tokio::test]
    async fn dedicated_receive_preserves_segmented_sends_in_single_datagram_buffers() {
        const DATAGRAMS: usize = 32;
        const PAYLOAD: usize = 1200;
        let receiving = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = PathSocket::from_udp(
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            receiving.local_addr().unwrap(),
            &quinn::TokioRuntime,
        )
        .unwrap();
        let path = PathSocket::from_udp(
            receiving,
            sender.local_addr().unwrap(),
            &quinn::TokioRuntime,
        )
        .unwrap();
        let mut writable = sender.clone().create_io_poller();
        std::future::poll_fn(|cx| writable.as_mut().poll_writable(cx))
            .await
            .unwrap();
        let mut packets = Vec::new();
        for index in 0..DATAGRAMS {
            packets.extend_from_slice(&[u8::try_from(index).unwrap(); PAYLOAD]);
        }
        let batch = sender.max_transmit_segments().clamp(1, DATAGRAMS);
        for contents in packets.chunks(batch * PAYLOAD) {
            sender
                .try_send(&Transmit {
                    destination: path.local_addr().unwrap(),
                    contents,
                    segment_size: (batch > 1).then_some(PAYLOAD),
                    ecn: None,
                    src_ip: None,
                })
                .unwrap();
        }
        let mut seen = [false; DATAGRAMS];
        let mut bytes = [0; 1472];
        for _ in 0..DATAGRAMS {
            let metadata = receive(&path, &mut bytes).await;
            assert_eq!(metadata.len, PAYLOAD, "aggregated datagram was truncated");
            let index = usize::from(bytes[0]);
            assert!(index < DATAGRAMS && !seen[index]);
            assert_eq!(&bytes[..PAYLOAD], &[u8::try_from(index).unwrap(); PAYLOAD]);
            seen[index] = true;
        }
        assert!(seen.into_iter().all(|received| received));
    }

    #[tokio::test]
    async fn exporting_path_keys_never_holds_the_receive_proof_lock() {
        let socket = quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let path = PathSocket::new(socket, "127.0.0.1:9".parse().unwrap());
        let result = path.prepare_proof_with(1, || {
            // Export acquires the engine's connection lock; a simultaneous
            // receive must remain free to consume proof packets and release
            // its path lock while an encrypted send waits for that path lock.
            assert!(
                path.proof.try_lock().is_ok(),
                "key export holds the receive proof lock and permits a connection/path/proof cycle"
            );
            Err(io::ErrorKind::PermissionDenied.into())
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(!path.proof.lock().unwrap().has_key(1));
    }

    #[derive(Debug)]
    struct CountedSocket {
        inner: Arc<dyn AsyncUdpSocket>,
        sent: Arc<AtomicU64>,
        blocked: Arc<AtomicBool>,
    }
    impl AsyncUdpSocket for CountedSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            self.inner.clone().create_io_poller()
        }
        fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
            if self.blocked.load(Ordering::Acquire) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.inner.try_send(transmit)?;
            self.sent.fetch_add(1, Ordering::Release);
            Ok(())
        }
        fn poll_recv(
            &self,
            cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            self.inner.poll_recv(cx, bufs, meta)
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }
    }

    /// Hold an already-built transmit, then release exactly one physical send.
    /// Frame counters are inspected by the test outside Quinn's driver lock.
    #[derive(Debug, Default)]
    struct SendGate {
        remaining: Option<u64>,
        blocked_polls: u64,
        waker: Option<std::task::Waker>,
    }
    impl SendGate {
        fn limit(gate: &Mutex<Self>, remaining: Option<u64>) {
            let mut state = gate.lock().unwrap();
            state.remaining = remaining;
            let waker = state.waker.take();
            drop(state);
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }
    #[derive(Debug)]
    struct GatedSocket {
        inner: Arc<CountedSocket>,
        gate: Arc<Mutex<SendGate>>,
    }
    #[derive(Debug)]
    struct GatedPoller {
        inner: Pin<Box<dyn UdpPoller>>,
        gate: Arc<Mutex<SendGate>>,
    }
    impl UdpPoller for GatedPoller {
        fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let mut state = this.gate.lock().unwrap();
            if state.remaining == Some(0) {
                state.blocked_polls += 1;
                state.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            drop(state);
            this.inner.as_mut().poll_writable(cx)
        }
    }
    impl AsyncUdpSocket for GatedSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(GatedPoller {
                inner: self.inner.clone().create_io_poller(),
                gate: self.gate.clone(),
            })
        }
        fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
            let mut state = self.gate.lock().unwrap();
            if state.remaining == Some(0) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.inner.try_send(transmit)?;
            if let Some(remaining) = &mut state.remaining {
                *remaining -= 1;
            }
            Ok(())
        }
        fn poll_recv(
            &self,
            cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            self.inner.poll_recv(cx, bufs, meta)
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }
    }

    #[tokio::test]
    async fn send_gate_releases_only_one_successful_transmission() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gate = Arc::new(Mutex::new(SendGate::default()));
        let sent = Arc::new(AtomicU64::new(0));
        let socket = Arc::new(GatedSocket {
            inner: Arc::new(CountedSocket {
                inner: quinn::TokioRuntime
                    .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                    .unwrap(),
                sent: sent.clone(),
                blocked: Arc::default(),
            }),
            gate: gate.clone(),
        });
        let transmit = Transmit {
            destination: peer.local_addr().unwrap(),
            contents: b"unchanged",
            ecn: None,
            segment_size: None,
            src_ip: None,
        };
        let mut writable = socket.clone().create_io_poller();
        let mut context = Context::from_waker(std::task::Waker::noop());
        SendGate::limit(&gate, Some(0));
        assert!(writable.as_mut().poll_writable(&mut context).is_pending());
        assert_eq!(
            socket.try_send(&transmit).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(sent.load(Ordering::Acquire), 0);
        SendGate::limit(&gate, Some(1));
        std::future::poll_fn(|cx| writable.as_mut().poll_writable(cx))
            .await
            .unwrap();
        socket.try_send(&transmit).unwrap();
        assert_eq!(arrival(&peer).await, b"unchanged");
        assert_eq!(sent.load(Ordering::Acquire), 1);
        assert!(writable.as_mut().poll_writable(&mut context).is_pending());
        assert_eq!(
            socket.try_send(&transmit).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(sent.load(Ordering::Acquire), 1);
        SendGate::limit(&gate, None);
        std::future::poll_fn(|cx| writable.as_mut().poll_writable(cx))
            .await
            .unwrap();
        socket.try_send(&transmit).unwrap();
        assert_eq!(arrival(&peer).await, b"unchanged");
        assert_eq!(sent.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    #[ignore = "timed watchdog ordering proof; run under the perf VM benchmark lock"]
    async fn an_old_ack_only_send_does_not_start_a_backpressured_probe_deadline() {
        old_ack_only_before_probe(true).await;
    }

    #[tokio::test]
    async fn an_old_ack_only_send_cannot_complete_probe_emission() {
        old_ack_only_before_probe(false).await;
    }

    /// Exercise the same retained ACK-only transmit with a functional emission
    /// assertion or the additional deadline assertion on the measurement VM.
    async fn old_ack_only_before_probe(timed: bool) {
        use crate::remote_tls::tests::{leaf, root};
        let ca = root();
        let mut transport = quinn::TransportConfig::default();
        transport.mtu_discovery_config(None);
        transport.datagram_receive_buffer_size(Some(64));
        transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        let transport = Arc::new(transport);
        let mut config = crate::remote_quic::server_config(
            &leaf(&ca, true),
            std::slice::from_ref(&ca.certificate),
        )
        .unwrap();
        config.transport_config(transport.clone());
        let server = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let physical = server.local_addr().unwrap();
        let logical = SocketAddr::new("127.0.0.2".parse().unwrap(), physical.port());
        let sent = Arc::new(AtomicU64::new(0));
        let gate = Arc::new(Mutex::new(SendGate::default()));
        let path = PathSocket::new(
            Arc::new(GatedSocket {
                inner: Arc::new(CountedSocket {
                    inner: quinn::TokioRuntime
                        .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                        .unwrap(),
                    sent: sent.clone(),
                    blocked: Arc::default(),
                }),
                gate: gate.clone(),
            }),
            logical,
        );
        path.use_mesh(physical);
        let mut client = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            path.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let mut config =
            crate::remote_quic::client_config(&leaf(&ca, false), &[ca.certificate]).unwrap();
        config.transport_config(transport);
        client.set_default_client_config(config);
        let (dial, accept) = tokio::join!(client.connect(logical, "localhost").unwrap(), async {
            server.accept().await.unwrap().await
        });
        let dial = dial.unwrap();
        let accept = accept.unwrap();
        dial.send_datagram(bytes::Bytes::from_static(b"before"))
            .unwrap();
        assert_eq!(accept.read_datagram().await.unwrap().as_ref(), b"before");

        // Close only once all already-built handshake traffic has physically
        // left. This adapter permits one UDP segment and has no backup copies,
        // so protocol I/O count equals the counted successful physical sends.
        let before = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                SendGate::limit(&gate, Some(0));
                let stats = dial.stats();
                if stats.udp_tx.ios == sent.load(Ordering::Acquire) {
                    break stats.frame_tx;
                }
                SendGate::limit(&gate, None);
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let physical_before = sent.load(Ordering::Acquire);
        let blocked_before = gate.lock().unwrap().blocked_polls;
        accept
            .send_datagram(bytes::Bytes::from_static(b"ready"))
            .unwrap();
        assert_eq!(dial.read_datagram().await.unwrap().as_ref(), b"ready");
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if dial.stats().frame_tx.acks > before.acks
                    && gate.lock().unwrap().blocked_polls > blocked_before
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut buffered = dial.stats().frame_tx;
        buffered.acks = before.acks;
        assert_eq!(format!("{buffered:?}"), format!("{before:?}"));
        assert_eq!(sent.load(Ordering::Acquire), physical_before);

        // Poll the production watcher: its immediate tick arms the request
        // and queues a fresh DATAGRAM behind Quinn's retained ACK-only transmit.
        let mut watcher = std::pin::pin!(crate::remote_quic::quic_path_interrupted(
            &dial,
            &path,
            Duration::from_millis(15),
            Duration::from_millis(30),
        ));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                assert!(
                    std::future::poll_fn(|cx| Poll::Ready(
                        std::future::Future::poll(watcher.as_mut(), cx).is_pending()
                    ))
                    .await
                );
                if path.paths.lock().unwrap().probe_queued.is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(path.paths.lock().unwrap().mesh_sent.is_none());
        assert_eq!(dial.stats().frame_tx.datagram, before.datagram);
        let blocked_before = gate.lock().unwrap().blocked_polls;
        SendGate::limit(&gate, Some(1));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if sent.load(Ordering::Acquire) == physical_before + 1
                    && dial.stats().frame_tx.datagram > before.datagram
                    && gate.lock().unwrap().blocked_polls > blocked_before
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Only the previously classified ACK-only packet reached the socket.
        // The fresh ack-eliciting packet exists, but remains behind backpressure.
        assert!(path.paths.lock().unwrap().mesh_sent.is_some());
        assert_eq!(gate.lock().unwrap().remaining, Some(0));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(
                std::future::Future::poll(watcher.as_mut(), cx).is_pending()
            ))
            .await
        );
        assert!(
            path.paths.lock().unwrap().probe_queued.is_some(),
            "ACK-only transmission completed the fresh probe's emission waiter"
        );
        let interrupted = if timed {
            Some(tokio::time::timeout(Duration::from_secs(3), watcher.as_mut()).await)
        } else {
            None
        };
        assert_eq!(sent.load(Ordering::Acquire), physical_before + 1);
        if let Some(Ok(result)) = &interrupted {
            assert_eq!(result.as_ref().unwrap_err().kind(), io::ErrorKind::TimedOut);
        }
        assert!(dial.close_reason().is_none());
        assert!(accept.close_reason().is_none());

        // Prove the same authenticated connection still works after releasing
        // local backpressure; no route, listener, or peer was interrupted.
        SendGate::limit(&gate, None);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), accept.read_datagram())
                .await
                .unwrap()
                .unwrap()
                .as_ref(),
            &[0]
        );
        accept
            .send_datagram(bytes::Bytes::from_static(b"still-live"))
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), dial.read_datagram())
                .await
                .unwrap()
                .unwrap()
                .as_ref(),
            b"still-live"
        );
        client.close(0u32.into(), b"");
        server.close(0u32.into(), b"");
        assert!(
            interrupted.as_ref().is_none_or(Result::is_err),
            "watcher completed while only an old ACK-only packet was transmitted: {interrupted:?}"
        );
    }

    #[tokio::test]
    async fn a_delayed_probe_waiter_keeps_first_send_clock_after_ack_only_traffic() {
        use crate::remote_tls::tests::{leaf, root};
        let ca = root();
        // Suppress unrelated MTU probes only in this fixture, so Quinn's own
        // frame counters can prove that the later physical send is ACK-only.
        let mut transport = quinn::TransportConfig::default();
        transport.mtu_discovery_config(None);
        transport.datagram_receive_buffer_size(Some(64));
        transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        let transport = Arc::new(transport);
        let mut config = crate::remote_quic::server_config(
            &leaf(&ca, true),
            std::slice::from_ref(&ca.certificate),
        )
        .unwrap();
        config.transport_config(transport.clone());
        let server = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let physical = server.local_addr().unwrap();
        let logical = SocketAddr::new("127.0.0.2".parse().unwrap(), physical.port());
        let sent = Arc::new(AtomicU64::new(0));
        let path = PathSocket::new(
            Arc::new(CountedSocket {
                inner: quinn::TokioRuntime
                    .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                    .unwrap(),
                sent: sent.clone(),
                blocked: Arc::default(),
            }),
            logical,
        );
        path.use_mesh(physical);
        let mut client = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            path.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let mut config =
            crate::remote_quic::client_config(&leaf(&ca, false), &[ca.certificate]).unwrap();
        config.transport_config(transport);
        client.set_default_client_config(config);
        let (dial, accept) = tokio::join!(client.connect(logical, "localhost").unwrap(), async {
            server.accept().await.unwrap().await
        });
        let dial = dial.unwrap();
        let accept = accept.unwrap();
        let queued = Instant::now();
        let request = path.mesh_transmitted_after(queued).unwrap();
        let mut delayed = std::pin::pin!(request.sent());
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(
                std::future::Future::poll(delayed.as_mut(), cx).is_pending()
            ))
            .await
        );
        dial.send_datagram(bytes::Bytes::from_static(b"probe"))
            .unwrap();
        assert_eq!(accept.read_datagram().await.unwrap().as_ref(), b"probe");
        let first = path.paths.lock().unwrap().mesh_sent.unwrap().0;
        let before = dial.stats().frame_tx;
        let sends = sent.load(Ordering::Acquire);
        accept
            .send_datagram(bytes::Bytes::from_static(b"response"))
            .unwrap();
        assert_eq!(dial.read_datagram().await.unwrap().as_ref(), b"response");
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if dial.stats().frame_tx.acks > before.acks && sent.load(Ordering::Acquire) > sends
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut after = dial.stats().frame_tx;
        assert!(after.acks > before.acks);
        after.acks = before.acks;
        assert_eq!(
            format!("{after:?}"),
            format!("{before:?}"),
            "later physical send contained an ack-eliciting frame"
        );
        assert!(
            path.heard_since(first),
            "authenticated response did not arrive on the mesh tuple"
        );
        let observed = delayed.await.unwrap();
        client.close(0u32.into(), b"");
        server.close(0u32.into(), b"");
        assert_eq!(
            observed, first,
            "an ACK-only send replaced the queued probe's first transmission clock"
        );
    }

    #[tokio::test]
    async fn a_probe_request_latches_before_its_waiter_is_polled() {
        let mesh = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let logical = SocketAddr::new(
            "127.0.0.2".parse().unwrap(),
            mesh.local_addr().unwrap().port(),
        );
        let path = PathSocket::new(
            quinn::TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap(),
            logical,
        );
        path.use_mesh(mesh.local_addr().unwrap());
        let request = path.mesh_transmitted_after(Instant::now()).unwrap();
        send(&path, logical, b"first").await;
        assert_eq!(arrival(&mesh).await, b"first");
        let first = path.paths.lock().unwrap().mesh_sent.unwrap().0;
        send(&path, logical, b"later").await;
        assert_eq!(arrival(&mesh).await, b"later");
        assert_eq!(request.sent().await.unwrap(), first);
    }

    #[tokio::test]
    async fn backpressure_never_starts_or_replaces_the_probe_send_clock() {
        let mesh = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let logical = SocketAddr::new(
            "127.0.0.2".parse().unwrap(),
            mesh.local_addr().unwrap().port(),
        );
        let blocked = Arc::new(AtomicBool::new(true));
        let path = PathSocket::new(
            Arc::new(CountedSocket {
                inner: quinn::TokioRuntime
                    .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                    .unwrap(),
                sent: Arc::default(),
                blocked: blocked.clone(),
            }),
            logical,
        );
        path.use_mesh(mesh.local_addr().unwrap());
        let request = path.mesh_transmitted_after(Instant::now()).unwrap();
        let transmit = Transmit {
            destination: logical,
            contents: b"probe",
            ecn: None,
            segment_size: None,
            src_ip: None,
        };
        assert_eq!(
            path.try_send(&transmit).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(path.paths.lock().unwrap().mesh_sent.is_none());
        {
            let mut waiter = std::pin::pin!(request.sent());
            assert!(
                std::future::poll_fn(|cx| Poll::Ready(
                    std::future::Future::poll(waiter.as_mut(), cx).is_pending()
                ))
                .await
            );
        }
        // Cancelling one poll future does not cancel the owning request.
        blocked.store(false, Ordering::Release);
        send(&path, logical, b"probe").await;
        let first = request.sent().await.unwrap();
        assert_eq!(arrival(&mesh).await, b"probe");
        blocked.store(true, Ordering::Release);
        assert_eq!(
            path.try_send(&transmit).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        blocked.store(false, Ordering::Release);
        send(&path, logical, b"probe").await;
        assert_eq!(request.sent().await.unwrap(), first);
    }

    #[tokio::test]
    async fn cancelling_old_requests_cannot_clear_a_new_probe_generation() {
        let mesh = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let logical = SocketAddr::new(
            "127.0.0.2".parse().unwrap(),
            mesh.local_addr().unwrap().port(),
        );
        let path = PathSocket::new(
            quinn::TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap(),
            logical,
        );
        path.use_mesh(mesh.local_addr().unwrap());
        let old = path.mesh_transmitted_after(Instant::now()).unwrap();
        let current = path.mesh_transmitted_after(Instant::now()).unwrap();
        assert_eq!(
            old.sent().await.unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        drop(old);
        send(&path, logical, b"new generation").await;
        assert_eq!(arrival(&mesh).await, b"new generation");
        assert!(current.sent().await.is_ok());
        drop(current);
        send(&path, logical, b"unobserved").await;
        assert_eq!(arrival(&mesh).await, b"unobserved");
        assert!(path.paths.lock().unwrap().mesh_sent.is_none());
        let retired = path.mesh_transmitted_after(Instant::now()).unwrap();
        path.use_enrolled();
        assert_eq!(
            retired.sent().await.unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
    }

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
    async fn negotiated_copies_use_the_enrolled_socket_and_retire_on_return() {
        let enrolled = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mesh = tokio::net::UdpSocket::bind("127.0.0.3:0").await.unwrap();
        let logical = enrolled.local_addr().unwrap();
        let socket = PathSocket::new(
            quinn::TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.2:0").unwrap())
                .unwrap(),
            logical,
        );
        socket.use_mesh(mesh.local_addr().unwrap());
        send(&socket, logical, b"legacy").await;
        assert_eq!(arrival(&mesh).await, b"legacy");
        assert!(
            socket.copies.lock().unwrap().empty(),
            "legacy peers arm no backup clock"
        );
        socket.set_backup(true);
        send(&socket, logical, b"ciphertext-copy").await;
        assert_eq!(arrival(&mesh).await, b"ciphertext-copy");
        // The owning endpoint's pending receive drives the clock. There is no
        // worker that could outlive this socket or the applied mesh path.
        let mut receive_bytes = [0; 64];
        tokio::select! {
            copy = arrival(&enrolled) => assert_eq!(copy, b"ciphertext-copy"),
            _ = receive(&socket, &mut receive_bytes) => panic!("no peer sent a reply"),
        }
        socket.use_enrolled();
        assert!(socket.copies.lock().unwrap().empty());
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
