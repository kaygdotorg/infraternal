//! Drops handshake initiations from keys the node has not granted, before `GotaTun` sees them.
//!
//! `GotaTun` answers a MAC1-valid initiation with a cookie once its per-source limiter is under
//! load, and it does so before it looks up the sender's key. MAC1 needs only the node's public
//! key, which mesh members can see, so without this guard a stranger could make the node reply.
//! The guard sits between the UDP socket and `GotaTun` on both node platforms (Linux and macOS):
//! it validates MAC1, decrypts the sender's static key, and passes the initiation on only when
//! that key belongs to a peer the node has installed. Every other packet passes unchanged, and
//! admitted peers still reach `GotaTun`'s own limiter and cookie path.
//!
//! Decrypting the sender's key costs one X25519 key agreement, far more than the MAC1 check, and
//! it runs in the single receive task that also carries every peer's data packets. So the guard
//! checks budgets before any key agreement (J555 F1). Per source (an IPv4 address or an IPv6
//! /64) and second: at most [`REFUSED_SOURCE_BUDGET`] key agreements that admitted nobody, and at
//! most [`SOURCE_BUDGET`] in all. For the whole node: at most [`NODE_BUDGET`] a second. Past any
//! budget an initiation is dropped silently: ungranted keys still never get a reply, and a flood
//! costs one MAC1 check per packet, as it did before the guard existed.
//!
//! The total per-source budget is twice `GotaTun`'s own per-source limit, so a granted peer's
//! burst still reaches `GotaTun`'s cookie reply and its MAC2 retry, as without the guard.
//!
//! Trade-off: a granted peer that shares a source with a flood, or that arrives while a
//! spoofed-source flood holds the node budget, loses that initiation and retries five seconds
//! later. Established sessions keep their keys and their data path meanwhile. The alternative,
//! letting over-budget initiations reach `GotaTun`'s cookie reply, would answer ungranted keys.

use gotatun::{
    noise::{handshake::parse_handshake_anon, rate_limiter::RateLimiter},
    packet::{Packet, PacketBufPool, WgKind, WgPacketType},
    udp::{UdpRecv, socket::UdpSocket as GotaUdpSocket},
    x25519::{PublicKey as X25519PublicKey, StaticSecret},
};
use std::{
    collections::{BTreeSet, HashMap},
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use crate::policy::model::PublicKey;

/// Why the guard kept an initiation away from `GotaTun`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The packet is not a well-formed initiation with a valid MAC1 for this node.
    InvalidMac,
    /// The source already used its [`REFUSED_SOURCE_BUDGET`] or [`SOURCE_BUDGET`] this second;
    /// no key agreement ran.
    SourceBudget,
    /// The node already used its [`NODE_BUDGET`] this second; no key agreement ran.
    NodeBudget,
    /// The key agreement ran and the sender's static key did not decrypt.
    Undecryptable,
    /// The sender's static key decrypted, and it is not an installed peer.
    UnknownKey,
}

/// Key agreements per second and source that may end in a refusal (an unknown or undecryptable
/// key).
///
/// This is `GotaTun`'s own per-source handshake limit (`HANDSHAKE_RATE_LIMIT`): a stranger costs
/// no more key agreements than it could cause before the guard existed.
pub(crate) const REFUSED_SOURCE_BUDGET: u32 = 100;

/// Key agreements per second and source, admitted or not.
///
/// Twice `GotaTun`'s per-source limit, so `GotaTun`'s limiter, not the guard, is what a granted
/// peer's burst meets first: it gets the standard cookie and can retry with MAC2. The guard still
/// bounds a granted peer's flood.
pub(crate) const SOURCE_BUDGET: u32 = 2 * REFUSED_SOURCE_BUDGET;

/// Key agreements the guard runs per second for the whole node.
///
/// It bounds floods from many (possibly spoofed) sources, and it bounds the per-source map: a
/// source is recorded only when it spends from this budget. Sizing (J572, #483): one key
/// agreement costs about 26 µs of CPU (the flood bench below, on dev-02, aarch64), so the guard
/// spends at most about 2.6% of one core on them. A mesh of 4,096 hosts rekeys about 34 times a
/// second (every two minutes per peer), and even if every peer reconnects at once, `WireGuard`'s
/// five-second retry spreads 4,096 initiations over about four seconds of budget.
pub(crate) const NODE_BUDGET: u32 = 1_000;

/// How long one budget window lasts; both budgets refill at its start.
const BUDGET_WINDOW: Duration = Duration::from_secs(1);

/// Who a per-source budget belongs to. IPv6 is keyed by /64, because one host can use every
/// address in its /64; IPv4-mapped IPv6 addresses (from the dual-stack socket) count as IPv4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SourceKey {
    V4([u8; 4]),
    V6([u8; 8]),
}

impl SourceKey {
    /// Key one packet source by its IPv4 address or IPv6 /64.
    fn of(address: IpAddr) -> Self {
        match address.to_canonical() {
            IpAddr::V4(v4) => Self::V4(v4.octets()),
            IpAddr::V6(v6) => {
                let mut prefix = [0; 8];
                prefix.copy_from_slice(&v6.octets()[..8]);
                Self::V6(prefix)
            }
        }
    }
}

/// One source's key agreements in the current window.
#[derive(Clone, Copy, Debug, Default)]
struct SourceSpend {
    /// Every key agreement this source caused.
    total: u32,
    /// Those that admitted nobody.
    refused: u32,
}

/// The key agreements spent in the current one-second window.
///
/// Invariant: `sources` holds at most [`NODE_BUDGET`] entries, because a source is inserted only
/// when it spends from the node budget, and both reset together. Its memory is therefore bounded
/// (about 40 KiB at most) whatever a flood sends.
#[derive(Debug, Default)]
struct Budget {
    window_start: Option<Instant>,
    node: u32,
    sources: HashMap<SourceKey, SourceSpend>,
}

impl Budget {
    /// Spend one key agreement for `source` at `now`, or say which budget is used up.
    fn spend(&mut self, source: IpAddr, now: Instant) -> Result<(), Refusal> {
        if self
            .window_start
            .is_none_or(|start| now.saturating_duration_since(start) >= BUDGET_WINDOW)
        {
            self.window_start = Some(now);
            self.node = 0;
            self.sources.clear();
        }
        let key = SourceKey::of(source);
        let spent = self.sources.get(&key).copied().unwrap_or_default();
        if spent.refused >= REFUSED_SOURCE_BUDGET || spent.total >= SOURCE_BUDGET {
            return Err(Refusal::SourceBudget);
        }
        if self.node >= NODE_BUDGET {
            return Err(Refusal::NodeBudget);
        }
        self.node += 1;
        self.sources.entry(key).or_default().total += 1;
        Ok(())
    }

    /// Record that a key agreement `source` spent at `now` admitted nobody.
    ///
    /// A window that rolled over between [`Self::spend`] and this call has nothing to correct.
    fn refused(&mut self, source: IpAddr, now: Instant) {
        if self
            .window_start
            .is_some_and(|start| now.saturating_duration_since(start) < BUDGET_WINDOW)
            && let Some(spent) = self.sources.get_mut(&SourceKey::of(source))
        {
            spent.refused += 1;
        }
    }
}

/// Holds the live mesh identities allowed to reach `GotaTun`'s handshake cookie limiter.
///
/// The peer list changes only after the device accepts a snapshot, while both key checks follow
/// live local-key rotation.
pub(crate) struct PeerAdmission {
    private_key: StaticSecret,
    public_key: X25519PublicKey,
    /// Checks MAC1 only; its own load limit is unused (see [`Self::check`]).
    mac1: RateLimiter,
    peers: BTreeSet<PublicKey>,
    /// Spent before every key agreement. A plain mutex: it is held for one map update and
    /// never across an `.await`.
    budget: Mutex<Budget>,
}

impl PeerAdmission {
    /// Create an empty admission set for the node's current `WireGuard` identity.
    pub(crate) fn new(private_key: StaticSecret) -> Self {
        let public_key = X25519PublicKey::from(&private_key);
        let mac1 = RateLimiter::new(&public_key, u64::MAX);
        Self {
            private_key,
            public_key,
            mac1,
            peers: BTreeSet::new(),
            budget: Mutex::default(),
        }
    }

    /// Replace the identities accepted by the most recently applied device snapshot.
    pub(crate) fn set_peers(&mut self, peers: impl IntoIterator<Item = PublicKey>) {
        self.peers = peers.into_iter().collect();
    }

    /// Replace the local identity after `GotaTun` accepts a key rotation.
    pub(crate) fn set_private_key(&mut self, private_key: StaticSecret) {
        self.public_key = X25519PublicKey::from(&private_key);
        self.mac1 = RateLimiter::new(&self.public_key, u64::MAX);
        self.private_key = private_key;
    }

    /// Mark only handshake initiations for cryptographic peer admission.
    pub(crate) fn needs_admission(packet: &Packet) -> bool {
        packet.as_ref().first() == Some(&WgPacketType::HandshakeInit.0)
    }

    /// Decide whether one packet from `source`, received at `now`, may reach `GotaTun`.
    ///
    /// Non-initiation traffic always passes. An initiation must carry a valid MAC1 and then
    /// fit both budgets before its sender's key is decrypted. `now` is a parameter so tests
    /// control the clock.
    /// # Errors
    /// Returns why an initiation was kept away from `GotaTun`; the caller drops it silently.
    pub(crate) fn check(
        &self,
        packet: &Packet,
        source: SocketAddr,
        now: Instant,
    ) -> Result<(), Refusal> {
        if !Self::needs_admission(packet) {
            return Ok(());
        }
        // Keep malformed traffic out of the static-key decryption path and out of the real
        // limiter. MAC1 does not depend on the source address, so keep the validator's per-IP
        // counter on one fixed key instead of letting spoofed sources grow a second map.
        self.mac1.try_reset_count();
        let validation_source = SocketAddr::from(([0, 0, 0, 0], 0));
        let validation_packet: Packet = Packet::copy_from(packet.as_ref());
        let Ok(WgKind::HandshakeInit(initiation)) = self
            .mac1
            .verify_packet(validation_source, validation_packet)
        else {
            return Err(Refusal::InvalidMac);
        };
        // The budget is spent only after MAC1, so junk cannot use up a granted peer's budget.
        self.budget
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .spend(source.ip(), now)?;
        let verdict = match parse_handshake_anon(&self.private_key, &self.public_key, &initiation) {
            Ok(sender) if self.peers.contains(&PublicKey(sender.peer_static_public)) => Ok(()),
            Ok(_) => Err(Refusal::UnknownKey),
            Err(_) => Err(Refusal::Undecryptable),
        };
        if verdict.is_err() {
            self.budget
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .refused(source.ip(), now);
        }
        verdict
    }
}

/// Keeps the socket's batched receive path while filtering unregistered handshakes before `GotaTun`.
pub(crate) struct PeerAdmissionUdpReceiver {
    socket: GotaUdpSocket,
    admission: Arc<RwLock<PeerAdmission>>,
}

impl PeerAdmissionUdpReceiver {
    /// Wrap a bound receive socket with the node's shared admission state.
    pub(crate) fn new(socket: GotaUdpSocket, admission: Arc<RwLock<PeerAdmission>>) -> Self {
        Self { socket, admission }
    }

    /// The address the wrapped socket is bound to, for the Mac tests that check socket reuse.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Run the guard on one received datagram.
    async fn admits(&self, packet: &Packet, source: SocketAddr) -> bool {
        !PeerAdmission::needs_admission(packet)
            || self
                .admission
                .read()
                .await
                .check(packet, source, Instant::now())
                .is_ok()
    }
}

impl UdpRecv for PeerAdmissionUdpReceiver {
    type RecvManyBuf = <GotaUdpSocket as UdpRecv>::RecvManyBuf;

    /// Receive one packet and suppress any valid-MAC1 initiation from an unknown peer key.
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        loop {
            let packet = self.socket.recv_from(pool).await?;
            if self.admits(&packet.0, packet.1).await {
                return Ok(packet);
            }
        }
    }

    /// Preserve `GotaTun`'s socket batch receive and remove only rejected handshake initiations.
    async fn recv_many_from(
        &mut self,
        recv_buf: &mut Self::RecvManyBuf,
        pool: &mut PacketBufPool,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        let first_new_packet = packets.len();
        self.socket.recv_many_from(recv_buf, pool, packets).await?;
        let mut read = first_new_packet;
        let mut write = first_new_packet;
        while read < packets.len() {
            let (packet, source) = &packets[read];
            if self.admits(packet, *source).await {
                if write != read {
                    packets.swap(write, read);
                }
                write += 1;
            }
            read += 1;
        }
        packets.truncate(write);
        Ok(())
    }

    /// Pass `GotaTun`'s idle-time release through to the socket, so an idle node gives its
    /// batch receive pages back. The trait's default does nothing, which would keep them.
    fn release_recv_buf(&self, recv_buf: &mut Self::RecvManyBuf) {
        self.socket.release_recv_buf(recv_buf);
    }

    /// Keep the underlying socket's UDP GRO support available to `GotaTun`.
    fn enable_udp_gro(&self) -> io::Result<()> {
        self.socket.enable_udp_gro()
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::expect_used,
        reason = "a broken fixture (bad address, key or clock) must stop the test loudly"
    )]
    use super::{NODE_BUDGET, PeerAdmission, REFUSED_SOURCE_BUDGET, Refusal, SOURCE_BUDGET};
    use crate::policy::model::PublicKey;
    use gotatun::{
        noise::{Tunn, index_table::IndexTable, rate_limiter::RateLimiter},
        packet::Packet,
        x25519::{PublicKey as X25519PublicKey, StaticSecret},
    };
    use std::{
        net::SocketAddr,
        sync::Arc,
        time::{Duration, Instant},
    };

    /// The node's fixed test identity.
    const NODE: [u8; 32] = [0x31; 32];

    /// Format one MAC1-valid handshake initiation from `sender` to the test node.
    fn initiation(sender: [u8; 32]) -> Vec<u8> {
        let node_public = X25519PublicKey::from(&StaticSecret::from(NODE));
        let sender = StaticSecret::from(sender);
        let sender_public = X25519PublicKey::from(&sender);
        let mut initiator = Tunn::new(
            sender,
            node_public,
            None,
            None,
            IndexTable::from_os_rng(),
            Arc::new(RateLimiter::new(&sender_public, 100)),
        );
        initiator
            .format_handshake_initiation(false)
            .expect("a MAC1-valid initiation")
            .into_bytes()
            .as_ref()
            .to_vec()
    }

    /// Parse a test source address.
    fn source(text: &str) -> SocketAddr {
        text.parse().expect("test source address")
    }

    /// J555 F1 (#483): the admission guard must not do unbounded X25519 work per source.
    ///
    /// Anyone who knows a node's public key can compute MAC1. Before J510c, `GotaTun`'s limiter
    /// answered the 101st initiation from one address within a second with a cookie, so a
    /// flood cost one MAC check each and never reached Diffie-Hellman. The J510c guard ran
    /// `parse_handshake_anon` (an X25519 and an AEAD open) for every valid-MAC1 initiation,
    /// before `GotaTun`'s limiter and inside the single UDP receive task, so one unspoofed sender
    /// could drive unbounded key agreement on the path that carries every peer's data. Past
    /// `GotaTun`'s own 100-per-second budget, the guard must drop without decrypting.
    /// `Refusal::UnknownKey` is the only verdict that proves the key exchange ran.
    #[test]
    fn j555_admission_guard_stops_x25519_after_the_handshake_budget() {
        let admission = PeerAdmission::new(StaticSecret::from(NODE));
        let flood = initiation([0x55; 32]);
        let sender = source("198.51.100.7:40000");
        let now = Instant::now();
        for _ in 0..100 {
            assert_eq!(
                admission.check(&Packet::copy_from(&flood), sender, now),
                Err(Refusal::UnknownKey)
            );
        }
        let next = admission.check(&Packet::copy_from(&flood), sender, now);
        assert_ne!(
            next,
            Err(Refusal::UnknownKey),
            "after 100 initiations in one second the guard still ran X25519 for the next one"
        );
        assert!(next.is_err(), "an unknown key must never be admitted");
    }

    /// A registered peer's initiation still reaches `GotaTun`, and other packet types pass.
    #[test]
    fn installed_peers_pass_and_other_packets_are_untouched() {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        let peer = [0x66; 32];
        admission.set_peers([PublicKey(
            *X25519PublicKey::from(&StaticSecret::from(peer)).as_bytes(),
        )]);
        let now = Instant::now();
        let sender = source("198.51.100.8:40000");
        assert_eq!(
            admission.check(&Packet::copy_from(&initiation(peer)), sender, now),
            Ok(())
        );
        let data = [4_u8, 0, 0, 0, 1, 2, 3, 4];
        assert_eq!(
            admission.check(&Packet::copy_from(&data), sender, now),
            Ok(())
        );
        let mut forged = initiation(peer);
        forged[120] ^= 1;
        assert_eq!(
            admission.check(&Packet::copy_from(&forged), sender, now),
            Err(Refusal::InvalidMac)
        );
    }

    /// Past the source budget the guard refuses without key agreement, and the next window
    /// refills it. IPv6 sources share a budget per /64; IPv4-mapped sources count as IPv4.
    #[test]
    fn the_source_budget_is_per_ipv4_address_or_ipv6_prefix_and_refills() {
        let admission = PeerAdmission::new(StaticSecret::from(NODE));
        let flood = initiation([0x55; 32]);
        let now = Instant::now();
        let spend =
            |text: &str, at: Instant| admission.check(&Packet::copy_from(&flood), source(text), at);
        for index in 0..REFUSED_SOURCE_BUDGET {
            let address = format!("[2001:db8:1:2::{:x}]:40000", index + 1);
            assert_eq!(spend(&address, now), Err(Refusal::UnknownKey));
        }
        assert_eq!(
            spend("[2001:db8:1:2:ffff::9]:1", now),
            Err(Refusal::SourceBudget),
            "one /64 shares one source budget"
        );
        assert_eq!(
            spend("[2001:db8:1:3::1]:40000", now),
            Err(Refusal::UnknownKey),
            "another /64 has its own budget"
        );
        for _ in 0..REFUSED_SOURCE_BUDGET {
            assert_eq!(
                spend("[::ffff:192.0.2.1]:40000", now),
                Err(Refusal::UnknownKey)
            );
        }
        assert_eq!(
            spend("192.0.2.1:40001", now),
            Err(Refusal::SourceBudget),
            "an IPv4-mapped source and its IPv4 form share one budget"
        );
        assert_eq!(
            spend("[::ffff:192.0.2.2]:40000", now),
            Err(Refusal::UnknownKey),
            "IPv4-mapped sources are not grouped by the mapped /64"
        );
        assert_eq!(
            spend("192.0.2.1:40001", now + Duration::from_secs(1)),
            Err(Refusal::UnknownKey),
            "the next window refills the source budget"
        );
    }

    /// A granted peer's burst passes the guard past `GotaTun`'s own limit of 100, so `GotaTun`
    /// answers it with the standard cookie, and the guard stops it only at twice that. A stranger
    /// on the same source is still cut off after 100 refusals.
    #[test]
    fn a_granted_peer_burst_reaches_gotatun_cookie_limit_before_the_guard() {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        let peer = [0x66; 32];
        admission.set_peers([PublicKey(
            *X25519PublicKey::from(&StaticSecret::from(peer)).as_bytes(),
        )]);
        let granted = initiation(peer);
        let shared = source("198.51.100.20:40000");
        let now = Instant::now();
        for _ in 0..SOURCE_BUDGET {
            assert_eq!(
                admission.check(&Packet::copy_from(&granted), shared, now),
                Ok(())
            );
        }
        assert_eq!(
            admission.check(&Packet::copy_from(&granted), shared, now),
            Err(Refusal::SourceBudget)
        );
        let stranger = initiation([0x55; 32]);
        let other = source("198.51.100.21:40000");
        for _ in 0..REFUSED_SOURCE_BUDGET {
            assert_eq!(
                admission.check(&Packet::copy_from(&stranger), other, now),
                Err(Refusal::UnknownKey)
            );
        }
        assert_eq!(
            admission.check(&Packet::copy_from(&granted), other, now),
            Err(Refusal::SourceBudget),
            "a source that used its refusals is cut off for everyone on it"
        );
    }

    /// A spoofed-source flood stops at the node budget without key agreement, and a granted
    /// peer is admitted again once the window refills.
    #[test]
    fn the_node_budget_bounds_floods_from_many_sources() {
        let mut admission = PeerAdmission::new(StaticSecret::from(NODE));
        let peer = [0x66; 32];
        admission.set_peers([PublicKey(
            *X25519PublicKey::from(&StaticSecret::from(peer)).as_bytes(),
        )]);
        let flood = initiation([0x55; 32]);
        let now = Instant::now();
        for index in 0..NODE_BUDGET {
            let [_, _, high, low] = index.to_be_bytes();
            let spoofed = SocketAddr::from(([198, 18, high, low], 40000));
            assert_eq!(
                admission.check(&Packet::copy_from(&flood), spoofed, now),
                Err(Refusal::UnknownKey)
            );
        }
        let granted = initiation(peer);
        let peer_source = source("203.0.113.9:51000");
        assert_eq!(
            admission.check(&Packet::copy_from(&granted), peer_source, now),
            Err(Refusal::NodeBudget)
        );
        assert_eq!(
            admission.check(
                &Packet::copy_from(&granted),
                peer_source,
                now + Duration::from_secs(1)
            ),
            Ok(())
        );
    }

    /// CPU per received initiation under a flood (J572, #483); run by hand, it asserts nothing.
    ///
    /// `cargo test -p infraternal-plugin-mesh --features agent --release --lib
    /// bench_handshake_flood_cpu -- --ignored --nocapture` floods the guard on the calling
    /// thread with real time, once from one source and once from 65,536 spoofed sources, and
    /// prints this thread's CPU time per initiation and how many key agreements ran. The receive
    /// task is single-threaded, so CPU per initiation sets the flood rate that saturates it.
    #[test]
    #[ignore = "measurement; run by hand on a build VM"]
    fn bench_handshake_flood_cpu() {
        /// This thread's consumed CPU time.
        fn thread_cpu() -> Duration {
            let time = nix::time::clock_gettime(nix::time::ClockId::CLOCK_THREAD_CPUTIME_ID)
                .expect("thread CPU clock");
            Duration::from(time)
        }
        let admission = PeerAdmission::new(StaticSecret::from(NODE));
        let flood = initiation([0x55; 32]);
        let packets = 200_000_u32;
        for (name, spoofed) in [("one source", false), ("65,536 spoofed sources", true)] {
            let started = Instant::now();
            let cpu = thread_cpu();
            let mut key_agreements = 0_u32;
            for index in 0..packets {
                let [_, _, high, low] = if spoofed {
                    index.to_be_bytes()
                } else {
                    [0, 0, 0, 1]
                };
                let from = SocketAddr::from(([198, 18, high, low], 40000));
                let verdict = admission.check(&Packet::copy_from(&flood), from, Instant::now());
                if verdict == Err(Refusal::UnknownKey) {
                    key_agreements += 1;
                }
            }
            let cpu = thread_cpu().saturating_sub(cpu);
            let wall = started.elapsed();
            println!(
                "J572 flood ({name}): {packets} initiations, {key_agreements} key agreements, \
                 thread CPU {:.3} s, wall {:.3} s, {:.2} us CPU per initiation, \
                 saturates one core at {:.0} initiations/s",
                cpu.as_secs_f64(),
                wall.as_secs_f64(),
                cpu.as_secs_f64() * 1e6 / f64::from(packets),
                f64::from(packets) / cpu.as_secs_f64(),
            );
        }
    }
}
