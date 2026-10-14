//! Leases trusted alternative peer tuples and bounded encrypted replay below the existing QUIC endpoint [198,215,263], #201.
use crate::remote_path_copies::{COPY_BATCH, COPY_DELAY};
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
    /// Return replay consumes an original; an ordinary backup retains it.
    /// Keep this identity across another route change while draining.
    returning: bool,
}

#[derive(Default)]
pub(super) struct Recent {
    datagrams: VecDeque<Datagram>,
    bytes: usize,
}
impl Recent {
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
            returning: false,
        });
        copy_at
    }
    /// Select enrolled recovery without moving ciphertext into another queue.
    /// Existing return entries retain their backpressure deadline; only new
    /// mesh originals become immediately eligible. Their source follows the
    /// enrolled packet's local destination, including wildcard-bound endpoints.
    pub fn replay(&mut self, source: Option<IpAddr>) -> Option<tokio::time::Instant> {
        let now = tokio::time::Instant::now();
        for sent in &mut self.datagrams {
            if !sent.returning {
                sent.returning = true;
                sent.copy_at = Some(now);
            }
            sent.source = source;
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
        let now = tokio::time::Instant::now();
        for sent in &mut self.datagrams {
            if sent.copy_at.is_some_and(|deadline| deadline <= now) {
                if *remaining == 0 {
                    break;
                }
                *remaining -= 1;
                let result = socket.try_send(&Transmit {
                    destination,
                    contents: &sent.contents,
                    ecn: sent.ecn,
                    segment_size: sent.segment_size,
                    src_ip: if bound { None } else { sent.source },
                });
                sent.copy_at = match result {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        Some(now + COPY_DELAY)
                    }
                    _ => None,
                };
            }
        }
        // Remove completed returns even when this poll exhausts its budget.
        // Leaving them until a later poll would let a route change re-arm old
        // ciphertext. New mesh sends share the same existing storage bounds.
        let bytes = &mut self.bytes;
        self.datagrams.retain(|sent| {
            let keep = !sent.returning || sent.copy_at.is_some();
            if !keep {
                *bytes -= sent.contents.len();
            }
            keep
        });
        self.deadline()
    }
    pub fn cancel_copies(&mut self) {
        for sent in &mut self.datagrams {
            // Legacy enrolled recovery is independent of negotiated backups.
            if !sent.returning {
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
    pub recent: Recent,
    pub seen: Seen,
    pub backup: bool,
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
    ) -> Option<tokio::time::Instant> {
        let len = self.slots.len();
        if len == 0 {
            return None;
        }
        let start = self.copy_cursor % len;
        let (before, after) = self.slots.split_at_mut(start);
        let mut remaining = COPY_BATCH;
        let mut deadline = None;
        for (index, slot) in after.iter_mut().chain(before.iter_mut()).enumerate() {
            if let Some(peer) = slot
                && let Some(at) = peer
                    .recent
                    .copies(socket, peer.logical, bound, &mut remaining)
            {
                deadline = Some(deadline.map_or(at, |old: tokio::time::Instant| old.min(at)));
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
            recent: Recent::default(),
            seen: Seen::default(),
            backup: false,
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
mod tests {
    //! GSO batches remain within both replay bounds even when many old packets must retire.
    use super::*;
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
        assert!(recent.datagrams.iter().all(|sent| sent.copy_at.is_none()));
        assert_eq!(recent.bytes, MAX_BYTES);
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
