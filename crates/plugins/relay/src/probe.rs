//! Authenticated address probes: which public IP:port a relay saw for a node's `WireGuard` port [196,313].
//!
//! A node sends a probe from its kernel `WireGuard` port to a relay's UDP port
//! and the relay answers to the source it observed. Both packets carry an
//! HMAC-SHA256 tag keyed from the TLS exporter of that node's authenticated
//! relay connection, so the relay answers only enrolled nodes and an off-path
//! sender cannot plant a mapping: a reply is accepted only with a valid tag
//! and an outstanding transaction id.
//! On the relay, each transaction stays bound to its first observed source in
//! a 64-entry, 30-second session window. Transaction IDs carry their issue
//! time, so an expired or evicted ID cannot be rebound to a new source.
//!
//! The first byte is 0x2a. QUIC sets the fixed bit (0x40) in every packet it
//! accepts and `WireGuard` messages start with a type 1–4 followed by three zero
//! bytes, so neither engine mistakes a probe for its own traffic and a probe
//! that reaches the kernel `WireGuard` socket is dropped by its header check
//! before any peer state changes. Request and reply have the same length, so
//! a relay never amplifies.

use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

/// Every probe and reply is exactly this long.
pub const LEN: usize = 84;
/// First four bytes of every probe and reply.
pub const MAGIC: [u8; 4] = [0x2a, b'I', b'F', b'1'];
const REQUEST: u8 = 1;
const REPLY: u8 = 2;
const SIGNED: usize = 52;
const LABEL: &[u8] = b"infraternal relay probe v1";
const PROBE_REPLAY_WINDOW: usize = 64;
const PROBE_REPLAY_WINDOW_AGE_MS: u64 = 30_000;

#[derive(Default)]
struct ReplayWindow {
    entries: VecDeque<([u8; 16], SocketAddr)>,
    retired_through_ms: Option<u64>,
}

impl ReplayWindow {
    /// Bind a transaction to its first source without allowing retired IDs to rebind.
    fn bind_source(&mut self, transaction: [u8; 16], source: SocketAddr) -> bool {
        if let Some((_, original)) = self.entries.iter().find(|(seen, _)| *seen == transaction) {
            return *original == source;
        }
        let issued_at_ms = transaction_timestamp(&transaction);
        if self
            .retired_through_ms
            .is_some_and(|retired| issued_at_ms <= retired)
        {
            return false;
        }
        if self.entries.len() == PROBE_REPLAY_WINDOW {
            let Some((retired, _)) = self.entries.pop_front() else {
                return false;
            };
            let retired_at_ms = transaction_timestamp(&retired);
            self.retired_through_ms = Some(
                self.retired_through_ms
                    .map_or(retired_at_ms, |previous| previous.max(retired_at_ms)),
            );
        }
        if self
            .retired_through_ms
            .is_some_and(|retired| issued_at_ms <= retired)
        {
            return false;
        }
        self.entries.push_back((transaction, source));
        true
    }
}

fn transaction_timestamp(transaction: &[u8; 16]) -> u64 {
    let mut timestamp = [0; 8];
    timestamp.copy_from_slice(&transaction[..8]);
    u64::from_be_bytes(timestamp)
}

/// Per-connection probe credentials, derived identically by node and relay.
pub struct ProbeKey {
    session: u64,
    key: ring::hmac::Key,
    replay: Mutex<ReplayWindow>,
}

impl ProbeKey {
    /// Derive from an established connection's TLS exporter.
    /// # Errors
    /// Fails if the connection cannot export keying material.
    pub fn from_connection(connection: &quinn::Connection) -> io::Result<Self> {
        let mut material = [0_u8; 40];
        connection
            .export_keying_material(&mut material, LABEL, b"")
            .map_err(|_| io::Error::other("relay connection cannot export probe keys"))?;
        let key = Self::from_material(&material);
        material.fill(0);
        Ok(key)
    }

    fn from_material(material: &[u8; 40]) -> Self {
        let mut session = [0; 8];
        session.copy_from_slice(&material[..8]);
        Self {
            session: u64::from_be_bytes(session),
            key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &material[8..]),
            replay: Mutex::new(ReplayWindow::default()),
        }
    }

    /// Public session number that tells the relay which key signs a probe.
    #[must_use]
    pub fn session(&self) -> u64 {
        self.session
    }

    /// Build a signed request for this transaction.
    #[must_use]
    pub fn request(&self, transaction: [u8; 16]) -> [u8; LEN] {
        let mut out = [0; LEN];
        out[..4].copy_from_slice(&MAGIC);
        out[4] = REQUEST;
        out[8..16].copy_from_slice(&self.session.to_be_bytes());
        out[16..32].copy_from_slice(&transaction);
        self.sign(&mut out);
        out
    }

    /// Relay side: verify a request and build the reply naming `observed`.
    #[must_use]
    pub fn answer(&self, request: &[u8], observed: SocketAddr) -> Option<[u8; LEN]> {
        let request: &[u8; LEN] = request.try_into().ok()?;
        if request[4] != REQUEST || request[5..8] != [0; 3] || request[32..SIGNED] != [0; 20] {
            return None;
        }
        self.verify(request)?;
        let mut transaction = [0; 16];
        transaction.copy_from_slice(&request[16..32]);
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_millis(),
        )
        .ok()?;
        if now_ms.saturating_sub(transaction_timestamp(&transaction)) > PROBE_REPLAY_WINDOW_AGE_MS {
            return None;
        }
        let source = SocketAddr::new(canonical(observed.ip()), observed.port());
        if !self
            .replay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .bind_source(transaction, source)
        {
            return None;
        }
        let mut out = *request;
        out[4] = REPLY;
        match source.ip() {
            IpAddr::V4(ip) => {
                out[32] = 4;
                out[36..40].copy_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out[32] = 6;
                out[36..52].copy_from_slice(&ip.octets());
            }
        }
        out[34..36].copy_from_slice(&source.port().to_be_bytes());
        self.sign(&mut out);
        Some(out)
    }

    /// Node side: verify a reply; returns its transaction id and observed source.
    #[must_use]
    pub fn reply(&self, reply: &[u8]) -> Option<([u8; 16], SocketAddr)> {
        let reply: &[u8; LEN] = reply.try_into().ok()?;
        if reply[4] != REPLY || reply[5..8] != [0; 3] || reply[33] != 0 {
            return None;
        }
        self.verify(reply)?;
        let port = u16::from_be_bytes([reply[34], reply[35]]);
        let ip = match reply[32] {
            4 if reply[40..52] == [0; 12] => {
                IpAddr::V4(Ipv4Addr::new(reply[36], reply[37], reply[38], reply[39]))
            }
            6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&reply[36..52]).ok()?)),
            _ => return None,
        };
        let mut transaction = [0; 16];
        transaction.copy_from_slice(&reply[16..32]);
        Some((transaction, SocketAddr::new(ip, port)))
    }

    fn sign(&self, packet: &mut [u8; LEN]) {
        let tag = ring::hmac::sign(&self.key, &packet[..SIGNED]);
        packet[SIGNED..].copy_from_slice(tag.as_ref());
    }

    fn verify(&self, packet: &[u8; LEN]) -> Option<()> {
        if packet[..4] != MAGIC || session(packet) != Some(self.session) {
            return None;
        }
        ring::hmac::verify(&self.key, &packet[..SIGNED], &packet[SIGNED..]).ok()
    }
}

/// Cheap first check on a received UDP payload, before any key lookup.
#[must_use]
pub fn is_probe(payload: &[u8]) -> bool {
    payload.len() == LEN && payload[..4] == MAGIC
}

/// The session number a probe claims; the tag decides whether it is true.
#[must_use]
pub fn session(payload: &[u8]) -> Option<u64> {
    is_probe(payload).then(|| {
        let mut session = [0; 8];
        session.copy_from_slice(&payload[8..16]);
        u64::from_be_bytes(session)
    })
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Fresh time-stamped transaction id with an unpredictable nonce.
/// # Errors
/// Fails if the clock precedes the Unix epoch, the timestamp does not fit, or
/// the system random source fails.
pub fn transaction() -> io::Result<[u8; 16]> {
    use ring::rand::SecureRandom;
    let issued_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock precedes Unix epoch"))?;
    let issued_at_ms = u64::try_from(issued_at_ms.as_millis())
        .map_err(|_| io::Error::other("probe transaction timestamp does not fit"))?;
    let mut out = [0; 16];
    out[..8].copy_from_slice(&issued_at_ms.to_be_bytes());
    ring::rand::SystemRandom::new()
        .fill(&mut out[8..])
        .map_err(|_| io::Error::other("system random source failed"))?;
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! Property checks: valid probes round trip, and any single-bit change or wrong key is refused.
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn key(seed: u8) -> ProbeKey {
        ProbeKey::from_material(&[seed; 40])
    }

    fn transaction_at(issued_at: SystemTime, nonce: u64) -> [u8; 16] {
        let issued_ms =
            u64::try_from(issued_at.duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap();
        let mut transaction = [0; 16];
        transaction[..8].copy_from_slice(&issued_ms.to_be_bytes());
        transaction[8..].copy_from_slice(&nonce.to_be_bytes());
        transaction
    }

    #[test]
    fn a_signed_request_gets_a_reply_naming_the_observed_source() {
        let key = key(3);
        for (index, observed) in [
            "198.51.100.7:40123".parse::<SocketAddr>().unwrap(),
            "[2001:db8::7]:40123".parse().unwrap(),
            "[::ffff:198.51.100.7]:9".parse().unwrap(),
        ]
        .into_iter()
        .enumerate()
        {
            let transaction = transaction_at(SystemTime::now(), u64::try_from(index).unwrap());
            let request = key.request(transaction);
            assert!(is_probe(&request));
            assert_eq!(session(&request), Some(key.session()));
            let reply = key.answer(&request, observed).unwrap();
            assert_eq!(reply.len(), request.len());
            let expected = SocketAddr::new(canonical(observed.ip()), observed.port());
            assert_eq!(key.reply(&reply), Some((transaction, expected)));
            // A request is never accepted as a reply, nor a reply as a request.
            assert_eq!(key.reply(&request), None);
            assert_eq!(key.answer(&reply, observed), None);
        }
    }

    #[test]
    fn a_captured_request_cannot_be_replayed_to_a_different_source() {
        let key = key(4);
        let request = key.request(transaction_at(SystemTime::now(), 7));
        let original: SocketAddr = "198.51.100.7:40123".parse().unwrap();
        let spoofed: SocketAddr = "198.51.100.99:40123".parse().unwrap();

        assert!(key.answer(&request, original).is_some());
        assert!(
            key.answer(&request, original).is_some(),
            "same-source retry"
        );
        assert!(
            key.answer(&request, spoofed).is_none(),
            "captured request was reflected to a different source"
        );
    }

    #[test]
    fn an_evicted_probe_transaction_cannot_be_rebound_to_another_source() {
        let key = key(6);
        let source: SocketAddr = "198.51.100.7:40123".parse().unwrap();
        let spoofed: SocketAddr = "198.51.100.99:40123".parse().unwrap();
        let now = SystemTime::now();
        let evicted = key.request(transaction_at(now - Duration::from_secs(1), 1));

        assert!(key.answer(&evicted, source).is_some());
        for value in 1..=PROBE_REPLAY_WINDOW {
            let newer = key.request(transaction_at(
                now + Duration::from_nanos(u64::try_from(value).unwrap()),
                u64::try_from(value).unwrap() + 1,
            ));
            assert!(key.answer(&newer, source).is_some());
        }

        assert!(
            key.answer(&evicted, spoofed).is_none(),
            "evicted transaction was rebound to a new source"
        );
    }

    #[test]
    fn a_probe_transaction_older_than_the_time_window_is_refused() {
        let key = key(7);
        let stale = key.request(transaction_at(
            SystemTime::now() - Duration::from_secs(31),
            1,
        ));
        let source: SocketAddr = "198.51.100.7:40123".parse().unwrap();

        assert!(
            key.answer(&stale, source).is_none(),
            "stale probe was answered"
        );
    }

    #[test]
    fn every_single_bit_change_is_refused() {
        let key = key(5);
        let observed: SocketAddr = "203.0.113.4:1".parse().unwrap();
        let request = key.request(transaction_at(SystemTime::now(), 1));
        let reply = key.answer(&request, observed).unwrap();
        for bit in 0..LEN * 8 {
            let mut changed = request;
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(key.answer(&changed, observed), None, "request bit {bit}");
            let mut changed = reply;
            changed[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(key.reply(&changed), None, "reply bit {bit}");
        }
    }

    #[test]
    fn another_connection_key_or_length_is_refused() {
        let observed: SocketAddr = "203.0.113.4:1".parse().unwrap();
        let request = key(1).request(transaction_at(SystemTime::now(), 1));
        assert_eq!(key(2).answer(&request, observed), None);
        let reply = key(1).answer(&request, observed).unwrap();
        assert_eq!(key(2).reply(&reply), None);
        assert!(!is_probe(&request[..LEN - 1]));
        let mut longer = request.to_vec();
        longer.push(0);
        assert!(!is_probe(&longer));
        assert_eq!(key(1).answer(&longer, observed), None);
    }

    #[test]
    fn probes_are_neither_quic_nor_wireguard() {
        let request = key(1).request([0; 16]);
        assert_eq!(request[0] & 0x40, 0, "QUIC fixed bit must be clear");
        assert!(
            !(1..=4).contains(&request[0]),
            "not a WireGuard message type"
        );
    }

    #[test]
    fn transactions_are_distinct() {
        assert_ne!(transaction().unwrap(), transaction().unwrap());
    }
}
