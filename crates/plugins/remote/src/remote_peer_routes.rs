//! Leases trusted alternative peer tuples and bounded encrypted replay below the existing QUIC endpoint [198,215,263], #201.
use crate::{
    remote_bindings::Lease,
    remote_path_copies::{COPY_BATCH, COPY_DELAY},
};
use quinn::{
    AsyncUdpSocket,
    udp::{EcnCodepoint, Transmit},
};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
};

const MAX_BYTES: usize = 64 * 1024;
const MAX_DATAGRAMS: usize = 64;

pub(super) struct Datagram {
    pub contents: Vec<u8>,
    pub segment_size: Option<usize>,
    pub ecn: Option<EcnCodepoint>,
    source: Option<IpAddr>,
    copy_at: Option<tokio::time::Instant>,
    /// The purpose survives later routing hints; redundant mesh replies must
    /// never become enrolled recovery history.
    kind: CopyKind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CopyKind {
    Original,
    Return,
    MeshReply,
}

#[derive(Clone, Copy)]
struct CopyRoute<'a> {
    socket: &'a dyn AsyncUdpSocket,
    destination: SocketAddr,
    source: Option<IpAddr>,
}

#[derive(Clone, Copy)]
pub(super) struct MeshRoute {
    pub binding: Option<u64>,
    pub local: Option<IpAddr>,
}

#[derive(Default)]
pub(super) struct Recent {
    datagrams: VecDeque<Datagram>,
    bytes: usize,
}
impl Recent {
    /// Read existing bounds and scheduling state without hot-path counters.
    #[cfg(any(test, feature = "test-support"))]
    pub fn history(&self) -> [usize; 4] {
        [
            self.datagrams.len(),
            self.bytes,
            self.datagrams
                .iter()
                .filter(|sent| sent.copy_at.is_some())
                .count(),
            self.datagrams
                .iter()
                .filter(|sent| sent.kind == CopyKind::Return)
                .count(),
        ]
    }

    #[cfg(test)]
    pub fn keep(&mut self, transmit: &Transmit<'_>) {
        self.keep_copying(transmit, false);
    }
    pub fn keep_copying(
        &mut self,
        transmit: &Transmit<'_>,
        backup: bool,
    ) -> Option<tokio::time::Instant> {
        if transmit.contents.len() > MAX_BYTES {
            return None;
        }
        while self.datagrams.len() >= MAX_DATAGRAMS
            || self.bytes + transmit.contents.len() > MAX_BYTES
        {
            let Some(old) = self.datagrams.pop_front() else {
                break;
            };
            self.bytes -= old.contents.len();
        }
        self.bytes += transmit.contents.len();
        let copy_at = backup.then(|| tokio::time::Instant::now() + COPY_DELAY);
        self.datagrams.push_back(Datagram {
            contents: transmit.contents.to_vec(),
            segment_size: transmit.segment_size,
            ecn: transmit.ecn,
            source: transmit.src_ip,
            copy_at,
            kind: CopyKind::Original,
        });
        copy_at
    }
    /// A successful enrolled primary may also answer through the known mesh
    /// ingress. Redundancy shares the existing storage, but cannot evict pending
    /// enrolled recovery. Unknown coordinates keep it dormant without a clock.
    pub fn mesh_reply(
        &mut self,
        transmit: &Transmit<'_>,
        ready: bool,
    ) -> Option<tokio::time::Instant> {
        if transmit.contents.len() > MAX_BYTES {
            return None;
        }
        let mut bytes = self.bytes;
        let mut count = self.datagrams.len();
        let mut evict = 0;
        for old in &self.datagrams {
            if count < MAX_DATAGRAMS && bytes + transmit.contents.len() <= MAX_BYTES {
                break;
            }
            if old.kind == CopyKind::Return {
                return None;
            }
            bytes -= old.contents.len();
            count -= 1;
            evict += 1;
        }
        for _ in 0..evict {
            self.datagrams.pop_front();
        }
        self.bytes = bytes + transmit.contents.len();
        let copy_at = ready.then(tokio::time::Instant::now);
        self.datagrams.push_back(Datagram {
            contents: transmit.contents.to_vec(),
            segment_size: transmit.segment_size,
            ecn: transmit.ecn,
            source: None,
            copy_at,
            kind: CopyKind::MeshReply,
        });
        copy_at
    }
    /// A duplicate supplies coordinates only: it neither selects a primary
    /// route nor retires recovery. Repeated hints preserve backpressure clocks.
    pub fn mesh_ready(&mut self) -> Option<tokio::time::Instant> {
        let mut armed = None;
        for sent in &mut self.datagrams {
            if sent.kind == CopyKind::MeshReply && sent.copy_at.is_none() {
                let now = tokio::time::Instant::now();
                sent.copy_at = Some(now);
                armed = Some(armed.map_or(now, |old: tokio::time::Instant| old.min(now)));
            }
        }
        armed
    }
    pub fn cancel_mesh_replies(&mut self) {
        let bytes = &mut self.bytes;
        self.datagrams.retain(|sent| {
            if sent.kind == CopyKind::MeshReply {
                *bytes -= sent.contents.len();
                false
            } else {
                true
            }
        });
    }

    /// Select enrolled recovery without moving ciphertext into another queue.
    /// Existing return entries retain their backpressure deadline; only new
    /// mesh originals become immediately eligible. Their source follows the
    /// enrolled packet's local destination, including wildcard-bound endpoints.
    pub fn replay(&mut self, source: Option<IpAddr>) -> Option<tokio::time::Instant> {
        let now = tokio::time::Instant::now();
        for sent in &mut self.datagrams {
            if sent.kind == CopyKind::Original {
                sent.kind = CopyKind::Return;
                sent.copy_at = Some(now);
            }
            if sent.kind == CopyKind::Return {
                sent.source = source;
            }
        }
        self.deadline()
    }
    pub fn deadline(&self) -> Option<tokio::time::Instant> {
        self.datagrams.iter().filter_map(|sent| sent.copy_at).min()
    }
    /// At the socket's earliest copy deadline, send up to the shared poll budget.
    /// Each retained entry owns its deadline: another peer's clock or an evicted
    /// older entry must not send a backup before its mesh original can arrive.
    /// Exhaustion retains unsent entries and requests the next poll immediately.
    /// A full socket defers a copy; other errors leave recovery to QUIC.
    pub fn copies(
        &mut self,
        socket: &dyn AsyncUdpSocket,
        destination: SocketAddr,
        bound: bool,
        remaining: &mut usize,
    ) -> Option<tokio::time::Instant> {
        self.copies_to(socket, destination, bound, None, remaining)
    }
    fn copies_to(
        &mut self,
        socket: &dyn AsyncUdpSocket,
        destination: SocketAddr,
        bound: bool,
        mesh: Option<CopyRoute<'_>>,
        remaining: &mut usize,
    ) -> Option<tokio::time::Instant> {
        let now = tokio::time::Instant::now();
        let bytes = &mut self.bytes;
        let mut next = None;
        self.datagrams.retain_mut(|sent| {
            if sent.copy_at.is_some_and(|deadline| deadline <= now) && *remaining != 0 {
                let route = if sent.kind == CopyKind::MeshReply {
                    mesh
                } else {
                    Some(CopyRoute {
                        socket,
                        destination,
                        source: if bound { None } else { sent.source },
                    })
                };
                if let Some(route) = route {
                    *remaining -= 1;
                    let result = route.socket.try_send(&Transmit {
                        destination: route.destination,
                        contents: &sent.contents,
                        ecn: sent.ecn,
                        segment_size: sent.segment_size,
                        src_ip: route.source,
                    });
                    if result
                        .as_ref()
                        .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
                    {
                        sent.copy_at = Some(now + COPY_DELAY);
                    } else {
                        sent.copy_at = None;
                        // A successful backup already sent this ciphertext on the
                        // enrolled path. Consume it instead of replaying a second
                        // burst on a later routing hint. Other send errors keep
                        // uncopied originals available for explicit recovery.
                        if result.is_ok() || sent.kind != CopyKind::Original {
                            *bytes -= sent.contents.len();
                            return false;
                        }
                    }
                } else {
                    // No usable mesh coordinates: wait for real ingress rather
                    // than repeatedly waking an endpoint that cannot send.
                    sent.copy_at = None;
                }
            }
            if let Some(at) = sent.copy_at {
                next = Some(next.map_or(at, |old: tokio::time::Instant| old.min(at)));
            }
            true
        });
        next
    }
    pub fn cancel_copies(&mut self) {
        self.cancel_mesh_replies();
        for sent in &mut self.datagrams {
            // Legacy enrolled recovery is independent of negotiated backups.
            if sent.kind == CopyKind::Original {
                sent.copy_at = None;
            }
        }
    }
    pub fn clear(&mut self) {
        self.bytes = 0;
        self.datagrams.clear();
    }
    pub fn take(&mut self) -> VecDeque<Datagram> {
        self.bytes = 0;
        std::mem::take(&mut self.datagrams)
    }
}

/// Recent ciphertext fingerprints protect routing hints from delayed copies.
/// They never authenticate or discard a datagram: QUIC still sees every packet.
/// A fingerprint collision conservatively keeps the current reply route. The
/// 256-entry ring costs at most 4096 bytes per active peer (4 MiB at 1000 peers).
/// Fingerprints are the final 16 ciphertext bytes, including the integrity
/// tag for the established encrypted packets used here. This is only a
/// conservative hint filter: different packets sharing a suffix retain the
/// current route, and both still reach QUIC. It neither parses packet numbers
/// nor reads packet keys or plaintext.
#[derive(Default)]
pub(super) struct Seen {
    fingerprints: Vec<[u8; 16]>,
    next: usize,
}
impl Seen {
    pub fn observe(&mut self, contents: &[u8], stride: usize) -> bool {
        let mut fresh = false;
        // GRO batches must compare individual UDP datagrams, since a backup
        // can arrive unbatched or in a differently sized batch.
        for datagram in contents.chunks(stride.max(1)) {
            let mut fingerprint = [0; 16];
            let suffix = &datagram[datagram.len().saturating_sub(16)..];
            fingerprint[..suffix.len()].copy_from_slice(suffix);
            if self.fingerprints.contains(&fingerprint) {
                continue;
            }
            fresh = true;
            if self.fingerprints.len() < 256 {
                self.fingerprints.push(fingerprint);
            } else {
                self.fingerprints[self.next] = fingerprint;
                self.next = (self.next + 1) % 256;
            }
        }
        fresh
    }
}

pub(super) struct Peer {
    pub id: u64,
    pub logical: SocketAddr,
    pub alternate: SocketAddr,
    pub physical: SocketAddr,
    pub binding: Option<u64>,
    pub local: Option<IpAddr>,
    /// Last real ingress on the trusted alternative, including duplicates.
    /// This never replaces the primary reply hint.
    pub mesh: Option<MeshRoute>,
    recent: Recent,
    pub seen: Seen,
    pub backup: bool,
    /// Mutable history access invalidates this derived hint. A clean None
    /// means no queued copy; this owns no timer or allocation.
    copy_deadline: Option<tokio::time::Instant>,
    copy_dirty: bool,
}
impl Peer {
    /// Retained ciphertext belongs to this peer's bounded queue.
    pub fn recent(&self) -> &Recent {
        &self.recent
    }
    /// Keep externally initiated queue mutations at one peer boundary.
    pub fn recent_mut(&mut self) -> &mut Recent {
        self.copy_dirty = true;
        &mut self.recent
    }
    fn copy_deadline(&mut self) -> Option<tokio::time::Instant> {
        if self.copy_dirty {
            self.copy_deadline = self.recent.deadline();
            self.copy_dirty = false;
        }
        self.copy_deadline
    }
}
/// Both trusted tuple keys share one bounded slot. Use the same address/u64
/// map representation as reply routing rather than monomorphising separate
/// maps for full peer state and alternative addresses. Slot reuse never
/// reuses a lease identity, so a stale drop cannot retire a replacement.
#[derive(Default)]
pub(super) struct Peers {
    keys: HashMap<SocketAddr, u64>,
    slots: Vec<Option<Peer>>,
    free: Vec<usize>,
    count: usize,
    /// Resume after the last serviced slot so a busy peer cannot own the batch.
    copy_cursor: usize,
}
impl Peers {
    /// Interleave bounded backup batches with the endpoint's receive work.
    pub fn copies(
        &mut self,
        socket: &dyn AsyncUdpSocket,
        bound: bool,
        leases: &[Lease],
    ) -> Option<tokio::time::Instant> {
        let len = self.slots.len();
        if len == 0 {
            return None;
        }
        // Classify future/empty peers from one poll snapshot. Due sends still
        // check each entry against a fresh clock in the existing drain below.
        let now = tokio::time::Instant::now();
        let start = self.copy_cursor % len;
        let (before, after) = self.slots.split_at_mut(start);
        let mut remaining = COPY_BATCH;
        let mut deadline = None;
        for (index, slot) in after.iter_mut().chain(before.iter_mut()).enumerate() {
            if let Some(peer) = slot {
                let next = peer.copy_deadline();
                let next = if next.is_some_and(|at| at <= now) {
                    let mesh = peer.mesh.and_then(|route| {
                        let (socket, source) = if let Some(id) = route.binding {
                            (
                                leases.iter().find(|lease| lease.id == id)?.socket.as_ref(),
                                None,
                            )
                        } else {
                            (socket, if bound { None } else { route.local })
                        };
                        Some(CopyRoute {
                            socket,
                            destination: peer.alternate,
                            source,
                        })
                    });
                    if peer.mesh.is_some() && mesh.is_none() {
                        peer.recent_mut().cancel_mesh_replies();
                        peer.mesh = None;
                    }
                    let logical = peer.logical;
                    peer.recent_mut()
                        .copies_to(socket, logical, bound, mesh, &mut remaining)
                } else {
                    next
                };
                if let Some(at) = next {
                    deadline = Some(deadline.map_or(at, |old: tokio::time::Instant| old.min(at)));
                }
            }
            if remaining == 0 {
                self.copy_cursor = (start + index + 1) % len;
                // Remaining slots may have due copies. The same owned clock
                // schedules the next batch, after sockets get a receive poll.
                return Some(tokio::time::Instant::now());
            }
        }
        deadline
    }
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Peer> {
        self.slots.iter_mut().filter_map(Option::as_mut)
    }
    fn index(&self, address: SocketAddr) -> Option<usize> {
        usize::try_from(*self.keys.get(&address)?).ok()
    }
    #[cfg(test)]
    pub fn logical_for(&self, physical: SocketAddr) -> SocketAddr {
        self.index(physical)
            .and_then(|index| self.slots.get(index)?.as_ref())
            .map_or(physical, |peer| peer.logical)
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn get(&self, logical: SocketAddr) -> Option<&Peer> {
        self.slots
            .get(self.index(logical)?)?
            .as_ref()
            .filter(|peer| peer.logical == logical)
    }
    /// Resolve either leased tuple once, before updating its physical hint.
    pub fn by_physical(&mut self, physical: SocketAddr) -> Option<&mut Peer> {
        let index = self.index(physical)?;
        self.slots.get_mut(index)?.as_mut()
    }
    pub fn get_mut(&mut self, logical: SocketAddr) -> Option<&mut Peer> {
        let index = self.index(logical)?;
        self.slots
            .get_mut(index)?
            .as_mut()
            .filter(|peer| peer.logical == logical)
    }
    pub fn insert(&mut self, id: u64, logical: SocketAddr, alternate: SocketAddr) -> bool {
        if self.count >= 10_000
            || logical == alternate
            || self.keys.contains_key(&logical)
            || self.keys.contains_key(&alternate)
        {
            return false;
        }
        let index = self.free.last().copied().unwrap_or(self.slots.len());
        let Ok(key) = u64::try_from(index) else {
            return false;
        };
        let peer = Some(Peer {
            id,
            logical,
            alternate,
            physical: logical,
            binding: None,
            local: None,
            mesh: None,
            recent: Recent::default(),
            seen: Seen::default(),
            backup: false,
            copy_deadline: None,
            copy_dirty: true,
        });
        if self.free.pop().is_some() {
            self.slots[index] = peer;
        } else {
            self.slots.push(peer);
        }
        self.keys.insert(logical, key);
        self.keys.insert(alternate, key);
        self.count += 1;
        true
    }
    pub fn remove(&mut self, logical: SocketAddr, id: u64) {
        let Some(index) = self.index(logical) else {
            return;
        };
        let slot = &mut self.slots[index];
        if !slot
            .as_ref()
            .is_some_and(|peer| peer.logical == logical && peer.id == id)
        {
            return;
        }
        if let Some(peer) = slot.take() {
            self.keys.remove(&logical);
            self.keys.remove(&peer.alternate);
            self.free.push(index);
            self.count -= 1;
        }
        // A mesh role that retires its final alias leaves no replay or slot
        // allocation behind in the otherwise still-running remote endpoint.
        if self.count == 0 {
            *self = Self::default();
        }
    }
}

#[cfg(test)]
#[path = "remote_copy_scan_tests.rs"]
mod copy_scan_tests;

#[cfg(test)]
mod tests {
    //! GSO batches remain within both replay bounds even when many old packets must retire.
    use super::*;
    #[tokio::test]
    async fn alternative_backpressure_keeps_one_copy_and_hints_preserve_its_deadline() {
        use quinn::Runtime as _;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        #[derive(Debug)]
        struct Gate {
            inner: Arc<dyn AsyncUdpSocket>,
            blocked: AtomicBool,
        }
        impl AsyncUdpSocket for Gate {
            fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
                self.inner.clone().create_io_poller()
            }
            fn try_send(&self, transmit: &Transmit<'_>) -> std::io::Result<()> {
                if self.blocked.load(Ordering::Relaxed) {
                    return Err(std::io::ErrorKind::WouldBlock.into());
                }
                self.inner.try_send(transmit)
            }
            fn poll_recv(
                &self,
                cx: &mut std::task::Context<'_>,
                bufs: &mut [std::io::IoSliceMut<'_>],
                meta: &mut [quinn::udp::RecvMeta],
            ) -> std::task::Poll<std::io::Result<usize>> {
                self.inner.poll_recv(cx, bufs, meta)
            }
            fn local_addr(&self) -> std::io::Result<SocketAddr> {
                self.inner.local_addr()
            }
        }
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr().unwrap();
        let socket = Arc::new(Gate {
            inner: quinn::TokioRuntime
                .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
                .unwrap(),
            blocked: AtomicBool::new(true),
        });
        let mut writable = socket.clone().create_io_poller();
        std::future::poll_fn(|cx| writable.as_mut().poll_writable(cx))
            .await
            .unwrap();
        let transmit = Transmit {
            destination,
            contents: b"one-alternative",
            ecn: None,
            segment_size: None,
            src_ip: None,
        };
        let mut recent = Recent::default();
        assert!(recent.mesh_reply(&transmit, true).is_some());
        let route = Some(CopyRoute {
            socket: socket.as_ref(),
            destination,
            source: None,
        });
        let mut remaining = 1;
        let deadline = recent
            .copies_to(socket.as_ref(), destination, true, route, &mut remaining)
            .unwrap();
        assert_eq!(remaining, 0);
        assert_eq!(recent.datagrams.len(), 1);
        assert!(recent.mesh_ready().is_none());
        recent.replay(None);
        assert_eq!(recent.deadline(), Some(deadline));
        assert!(
            recent
                .datagrams
                .iter()
                .all(|sent| sent.kind == CopyKind::MeshReply)
        );
        // Publish retry readiness explicitly; no elapsed-time threshold is
        // asserted, and the production retry deadline above remains unchanged.
        recent.datagrams.front_mut().unwrap().copy_at = Some(tokio::time::Instant::now());
        socket.blocked.store(false, Ordering::Relaxed);
        let mut remaining = 1;
        assert!(
            recent
                .copies_to(socket.as_ref(), destination, true, route, &mut remaining)
                .is_none()
        );
        assert_eq!(remaining, 0);
        assert!(recent.datagrams.is_empty());
        assert_eq!(recent.bytes, 0);
        let mut bytes = [0; 64];
        let (count, _) = receiver.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..count], transmit.contents);
    }

    #[tokio::test]
    async fn alternative_admission_never_evicts_pending_enrolled_return() {
        let mut recent = Recent::default();
        let transmit = Transmit {
            destination: "127.0.0.1:40001".parse().unwrap(),
            contents: b"retained",
            ecn: None,
            segment_size: None,
            src_ip: None,
        };
        for _ in 0..MAX_DATAGRAMS {
            recent.keep(&transmit);
        }
        let deadline = recent.replay(None);
        let bytes = recent.bytes;
        assert!(recent.mesh_reply(&transmit, true).is_none());
        assert_eq!(recent.datagrams.len(), MAX_DATAGRAMS);
        assert_eq!(recent.bytes, bytes);
        assert_eq!(recent.deadline(), deadline);
        assert!(
            recent
                .datagrams
                .iter()
                .all(|sent| sent.kind == CopyKind::Return)
        );
        recent.clear();
        let large = vec![7; MAX_BYTES];
        recent.keep(&Transmit {
            contents: &large,
            ..transmit
        });
        recent.replay(None);
        assert!(recent.mesh_reply(&transmit, true).is_none());
        assert_eq!(recent.datagrams.len(), 1);
        assert_eq!(recent.bytes, MAX_BYTES);
    }

    #[tokio::test]
    async fn alternative_queue_shares_bounds_and_never_becomes_return_history() {
        let mut recent = Recent::default();
        let transmit = Transmit {
            destination: "127.0.0.1:40001".parse().unwrap(),
            contents: b"reply",
            ecn: None,
            segment_size: None,
            src_ip: None,
        };
        for _ in 0..MAX_DATAGRAMS * 2 {
            assert!(recent.mesh_reply(&transmit, true).is_some());
            assert!(recent.datagrams.len() <= MAX_DATAGRAMS);
            assert!(recent.bytes <= MAX_BYTES);
        }
        let deadlines: Vec<_> = recent.datagrams.iter().map(|sent| sent.copy_at).collect();
        recent.replay(Some("127.0.0.9".parse().unwrap()));
        assert_eq!(
            recent
                .datagrams
                .iter()
                .map(|sent| sent.copy_at)
                .collect::<Vec<_>>(),
            deadlines
        );
        assert!(
            recent
                .datagrams
                .iter()
                .all(|sent| sent.kind == CopyKind::MeshReply)
        );
        recent.cancel_copies();
        assert!(recent.datagrams.is_empty());
        assert_eq!(recent.bytes, 0);
    }

    #[tokio::test]
    async fn completed_backup_copies_cannot_be_replayed_as_a_second_return_burst() {
        use quinn::Runtime as _;
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr().unwrap();
        let socket = quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let mut writable = socket.clone().create_io_poller();
        std::future::poll_fn(|cx| writable.as_mut().poll_writable(cx))
            .await
            .unwrap();
        let mut recent = Recent::default();
        for index in 0..MAX_DATAGRAMS {
            recent.keep_copying(
                &Transmit {
                    destination,
                    contents: &[u8::try_from(index).unwrap(); 32],
                    ecn: None,
                    segment_size: None,
                    src_ip: None,
                },
                true,
            );
        }
        // Publish eligibility directly; this checks retirement, not elapsed time.
        for datagram in &mut recent.datagrams {
            datagram.copy_at = Some(tokio::time::Instant::now());
        }
        for _ in 0..2 {
            let mut budget = COPY_BATCH;
            recent.copies(socket.as_ref(), destination, true, &mut budget);
            assert_eq!(budget, 0);
        }
        assert!(
            recent.replay(None).is_none(),
            "completed backups were queued for a second return burst"
        );
        assert!(recent.datagrams.is_empty());
        assert_eq!(recent.bytes, 0);
        let mut seen = [false; MAX_DATAGRAMS];
        let mut bytes = [0; 64];
        for _ in 0..MAX_DATAGRAMS {
            let (length, _) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                receiver.recv_from(&mut bytes),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(length, 32);
            let index = usize::from(bytes[0]);
            assert!(index < MAX_DATAGRAMS && !seen[index]);
            assert_eq!(&bytes[..length], &[u8::try_from(index).unwrap(); 32]);
            seen[index] = true;
        }
        assert!(seen.into_iter().all(|received| received));
        assert_eq!(
            receiver.try_recv_from(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        // An original without a negotiated backup still needs legacy recovery.
        recent.keep(&Transmit {
            destination,
            contents: b"uncopied",
            ecn: None,
            segment_size: None,
            src_ip: None,
        });
        assert!(recent.replay(None).is_some());
        let mut budget = 1;
        assert!(
            recent
                .copies(socket.as_ref(), destination, true, &mut budget)
                .is_none()
        );
        let (length, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            receiver.recv_from(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&bytes[..length], b"uncopied");
        assert!(recent.datagrams.is_empty());
    }

    #[tokio::test]
    async fn unsuccessful_backups_preserve_originals_for_explicit_recovery() {
        use quinn::Runtime as _;
        #[derive(Debug)]
        struct Reject {
            inner: std::sync::Arc<dyn AsyncUdpSocket>,
            kind: std::io::ErrorKind,
        }
        impl AsyncUdpSocket for Reject {
            fn create_io_poller(
                self: std::sync::Arc<Self>,
            ) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
                self.inner.clone().create_io_poller()
            }
            fn try_send(&self, _: &Transmit<'_>) -> std::io::Result<()> {
                Err(self.kind.into())
            }
            fn poll_recv(
                &self,
                cx: &mut std::task::Context<'_>,
                bufs: &mut [std::io::IoSliceMut<'_>],
                meta: &mut [quinn::udp::RecvMeta],
            ) -> std::task::Poll<std::io::Result<usize>> {
                self.inner.poll_recv(cx, bufs, meta)
            }
            fn local_addr(&self) -> std::io::Result<SocketAddr> {
                self.inner.local_addr()
            }
        }
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let destination = receiver.local_addr().unwrap();
        let inner = quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let mut writable = inner.clone().create_io_poller();
        std::future::poll_fn(|cx| writable.as_mut().poll_writable(cx))
            .await
            .unwrap();
        for kind in [
            std::io::ErrorKind::WouldBlock,
            std::io::ErrorKind::ConnectionRefused,
        ] {
            let socket = Reject {
                inner: inner.clone(),
                kind,
            };
            let mut recent = Recent::default();
            recent.keep_copying(
                &Transmit {
                    destination,
                    contents: b"not-copied",
                    ecn: None,
                    segment_size: None,
                    src_ip: None,
                },
                true,
            );
            recent.datagrams.front_mut().unwrap().copy_at = Some(tokio::time::Instant::now());
            let mut budget = 1;
            let next = recent.copies(&socket, destination, true, &mut budget);
            assert_eq!(next.is_some(), kind == std::io::ErrorKind::WouldBlock);
            assert_eq!(recent.datagrams.len(), 1);
            assert!(recent.replay(None).is_some());
            let mut budget = 1;
            assert!(
                recent
                    .copies(inner.as_ref(), destination, true, &mut budget)
                    .is_none()
            );
            assert!(recent.datagrams.is_empty());
            assert_eq!(recent.bytes, 0);
        }
    }

    #[tokio::test]
    async fn completed_return_entries_stay_consumed_when_new_mesh_history_arrives() {
        use quinn::Runtime as _;
        fn transmit(destination: SocketAddr, contents: &[u8]) -> Transmit<'_> {
            Transmit {
                destination,
                contents,
                ecn: None,
                segment_size: None,
                src_ip: None,
            }
        }
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let destination = receiver.local_addr().unwrap();
        let socket = quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let mut writable = socket.clone().create_io_poller();
        std::future::poll_fn(|cx| writable.as_mut().poll_writable(cx))
            .await
            .unwrap();
        let mut recent = Recent::default();
        recent.keep(&transmit(destination, b"old-one"));
        recent.keep(&transmit(destination, b"old-two"));
        assert!(recent.replay(None).is_some());
        let mut budget = 1;
        assert!(
            recent
                .copies(socket.as_ref(), destination, true, &mut budget)
                .is_some()
        );
        assert_eq!(budget, 0);
        assert_eq!(recent.datagrams.len(), 1);
        assert_eq!(recent.datagrams[0].contents, b"old-two");
        recent.keep(&transmit(destination, b"new-mesh"));
        let mut budget = 1;
        assert!(
            recent
                .copies(socket.as_ref(), destination, true, &mut budget)
                .is_none()
        );
        assert_eq!(budget, 0);
        assert_eq!(recent.datagrams.len(), 1);
        assert_eq!(recent.datagrams[0].contents, b"new-mesh");
        assert_eq!(recent.bytes, b"new-mesh".len());
        assert!(recent.replay(None).is_some());
        let mut budget = 1;
        assert!(
            recent
                .copies(socket.as_ref(), destination, true, &mut budget)
                .is_none()
        );
        assert_eq!(recent.bytes, 0);
        assert!(recent.datagrams.is_empty());
    }
    #[tokio::test]
    async fn shared_copy_clock_preserves_each_datagrams_deadline() {
        use quinn::Runtime as _;
        let socket = quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let destination = "127.0.0.1:40001".parse().unwrap();
        let mut recent = Recent::default();
        recent.keep_copying(
            &Transmit {
                destination,
                contents: b"fresh ciphertext",
                ecn: None,
                segment_size: None,
                src_ip: None,
            },
            true,
        );
        // Another peer's expired clock cannot advance this peer's deadline.
        // Set a distant deadline explicitly; no wall-clock timing is asserted.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3600);
        recent.datagrams.front_mut().unwrap().copy_at = Some(deadline);
        let mut budget = COPY_BATCH;
        assert_eq!(
            recent.copies(socket.as_ref(), destination, true, &mut budget),
            Some(deadline)
        );
        assert_eq!(budget, COPY_BATCH);
        assert_eq!(recent.datagrams.front().unwrap().copy_at, Some(deadline));
    }
    #[tokio::test]
    async fn output_evicting_the_oldest_copy_still_copies_one_bounded_batch() {
        use quinn::Runtime as _;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let destination = receiver.local_addr().unwrap();
        // Kernel accounting includes skb overhead. Size this fixture socket
        // for the complete bounded batch instead of relying on host defaults.
        let state = quinn::udp::UdpSocketState::new((&receiver).into()).unwrap();
        state
            .set_recv_buffer_size((&receiver).into(), 256 * 1024)
            .unwrap();
        let receiver = quinn::TokioRuntime.wrap_udp_socket(receiver).unwrap();
        let socket = quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap();
        let mut writable = socket.clone().create_io_poller();
        std::future::poll_fn(|cx| writable.as_mut().poll_writable(cx))
            .await
            .unwrap();
        let mut recent = Recent::default();
        for index in 0_u32..32 {
            let mut contents = [7; 4096];
            contents[..4].copy_from_slice(&index.to_le_bytes());
            recent.keep_copying(
                &Transmit {
                    destination,
                    contents: &contents,
                    ecn: None,
                    segment_size: None,
                    src_ip: None,
                },
                true,
            );
        }
        // Eviction leaves the retained deadlines intact. Once those deadlines
        // expire, the complete bounded batch remains eligible for copying.
        let due = tokio::time::Instant::now();
        for sent in &mut recent.datagrams {
            sent.copy_at = Some(due);
        }
        let mut copy_budget = COPY_BATCH;
        assert!(
            recent
                .copies(socket.as_ref(), destination, true, &mut copy_budget)
                .is_none()
        );
        let mut bytes = vec![0; MAX_BYTES];
        let mut index = 16_u32;
        while index < 32 {
            let mut bufs = [std::io::IoSliceMut::new(&mut bytes)];
            let mut meta = [quinn::udp::RecvMeta::default()];
            let count = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                std::future::poll_fn(|cx| receiver.poll_recv(cx, &mut bufs, &mut meta)),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(count, 1);
            for datagram in bytes[..meta[0].len].chunks(meta[0].stride) {
                assert_eq!(datagram.len(), 4096);
                assert_eq!(&datagram[..4], &index.to_le_bytes());
                index += 1;
            }
        }
        assert_eq!(index, 32);
        assert!(
            recent
                .copies(socket.as_ref(), destination, true, &mut copy_budget)
                .is_none()
        );
        assert!(recent.datagrams.is_empty());
        assert_eq!(recent.bytes, 0);
    }

    #[test]
    fn ciphertext_history_normalizes_gro_batches_and_stays_bounded() {
        let mut seen = Seen::default();
        assert!(seen.observe(b"aaaabbbb", 4));
        assert!(!seen.observe(b"aaaa", 4));
        assert!(!seen.observe(b"bbbb", 4));
        assert!(!seen.observe(b"bbbbaaaa", 4));
        assert!(seen.observe(b"ccccaaaa", 4));
        for value in 0_u32..1000 {
            assert!(seen.observe(&value.to_le_bytes(), 4));
            assert!(seen.fingerprints.len() <= 256);
        }
        assert!(!seen.observe(&999_u32.to_le_bytes(), 4));
    }

    #[test]
    #[ignore = "Measure only on the perf VM: 31 batches of 20000 fresh/duplicate pairs across 1000 peers."]
    fn ciphertext_history_at_1000_peers() {
        let mut peers: Vec<Seen> = (0..1000).map(|_| Seen::default()).collect();
        let mut packet = [0_u8; 1352];
        for peer in &mut peers {
            for value in 0_u32..256 {
                packet[1348..].copy_from_slice(&value.to_le_bytes());
                assert!(peer.observe(&packet, packet.len()));
            }
        }
        let load = std::fs::read_to_string("/proc/loadavg").unwrap();
        let mut samples = Vec::new();
        for batch in 0_u32..31 {
            let started = std::time::Instant::now();
            for value in 0_u32..20000 {
                packet[1348..].copy_from_slice(&(256 + batch * 20000 + value).to_le_bytes());
                let peer = &mut peers[value as usize % 1000];
                assert!(peer.observe(std::hint::black_box(&packet), packet.len()));
                assert!(!peer.observe(std::hint::black_box(&packet), packet.len()));
            }
            samples.push(started.elapsed().as_nanos());
        }
        samples.sort_unstable();
        println!(
            "ciphertext_history peers=1000 batches=31 pairs_per_batch=20000 bytes_per_datagram=1352 batch_p50_ns={} batch_p99_ns={} pair_p50_ns={} pair_p99_ns={} fingerprint_capacity_bytes={} machine={} load={}",
            samples[15],
            samples[30],
            samples[15] / 20000,
            samples[30] / 20000,
            peers
                .iter()
                .map(|peer| peer.fingerprints.capacity() * 16)
                .sum::<usize>(),
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap()
                .trim(),
            load.trim()
        );
    }

    #[test]
    fn retiring_an_old_lease_cannot_remove_a_reused_tuple() {
        let logical = "127.0.0.1:40001".parse().unwrap();
        let alternate = "127.0.0.2:40002".parse().unwrap();
        let mut peers = Peers::default();
        assert!(peers.insert(1, logical, alternate));
        assert_eq!(peers.logical_for(alternate), logical);
        peers.remove(logical, 1);
        assert_eq!(peers.logical_for(alternate), alternate);
        assert!(peers.insert(2, logical, alternate));
        peers.remove(logical, 1);
        assert_eq!(peers.get(logical).unwrap().id, 2);
        assert_eq!(peers.len(), 1);
        peers.remove(logical, 2);
        assert_eq!(peers.len(), 0);
        assert_eq!(peers.logical_for(alternate), alternate);
    }

    #[test]
    fn replay_is_bounded_for_large_segmented_transmits() {
        let destination = "127.0.0.1:7443".parse().unwrap();
        let mut recent = Recent::default();
        for length in [1024, 1024, 1024, 63 * 1024, 64 * 1024, 64 * 1024 + 1] {
            let bytes = vec![7; length];
            recent.keep(&Transmit {
                destination,
                contents: &bytes,
                segment_size: Some(1024),
                ecn: None,
                src_ip: None,
            });
            assert!(recent.bytes <= MAX_BYTES);
            assert!(recent.datagrams.len() <= MAX_DATAGRAMS);
        }
        let pending = recent.take();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].contents.len(), MAX_BYTES);
        assert_eq!(recent.bytes, 0);
    }
}

#[cfg(test)]
#[path = "remote_peer_routes_bench.rs"]
mod bench;
