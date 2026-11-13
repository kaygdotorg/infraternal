//! Drops handshake initiations from keys the node has not granted, before `GotaTun` sees them.
//!
//! `GotaTun` answers a MAC1-valid initiation with a cookie once its per-source limiter is under
//! load, and it does so before it looks up the sender's key. MAC1 needs only the node's public
//! key, which mesh members can see, so without this guard a stranger could make the node reply.
//! The guard sits between the UDP socket and `GotaTun` on both node platforms (Linux and macOS):
//! it validates MAC1, decrypts the sender's static key, and passes the initiation on only when
//! that key belongs to a peer the node has installed. Every other packet passes unchanged, and
//! admitted peers still reach `GotaTun`'s own limiter and cookie path.

use gotatun::{
    noise::{handshake::parse_handshake_anon, rate_limiter::RateLimiter},
    packet::{Packet, PacketBufPool, WgKind, WgPacketType},
    udp::{UdpRecv, socket::UdpSocket as GotaUdpSocket},
    x25519::{PublicKey as X25519PublicKey, StaticSecret},
};
use std::{collections::BTreeSet, io, net::SocketAddr, sync::Arc, time::Instant};
use tokio::sync::RwLock;

use crate::policy::model::PublicKey;

/// Why the guard kept an initiation away from `GotaTun`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The packet is not a well-formed initiation with a valid MAC1 for this node.
    InvalidMac,
    /// The sender's static key decrypted, and it is not an installed peer.
    UnknownKey,
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
    /// Non-initiation traffic always passes. `now` is a parameter so tests control the clock.
    /// # Errors
    /// Returns why an initiation was kept away from `GotaTun`; the caller drops it silently.
    pub(crate) fn check(
        &self,
        packet: &Packet,
        source: SocketAddr,
        now: Instant,
    ) -> Result<(), Refusal> {
        let _ = (source, now);
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
        let Ok(sender) = parse_handshake_anon(&self.private_key, &self.public_key, &initiation)
        else {
            return Err(Refusal::InvalidMac);
        };
        if self.peers.contains(&PublicKey(sender.peer_static_public)) {
            Ok(())
        } else {
            Err(Refusal::UnknownKey)
        }
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
    use super::{PeerAdmission, Refusal};
    use crate::policy::model::PublicKey;
    use gotatun::{
        noise::{Tunn, index_table::IndexTable, rate_limiter::RateLimiter},
        packet::Packet,
        x25519::{PublicKey as X25519PublicKey, StaticSecret},
    };
    use std::{net::SocketAddr, sync::Arc, time::Instant};

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
}
