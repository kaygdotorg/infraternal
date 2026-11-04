//! Authenticates physical path replies with the existing QUIC session's TLS exporter [215,263], #201.
//!
//! Connection-wide QUIC counters cannot attribute authentication to a physical
//! tuple after aliases and encrypted backups merge. These fixed-size probes are
//! independent of terminal framing and authority. Only a live admitted tuple
//! receives a responder key; every reply echoes one outstanding sequence with a
//! separate direction tag. No timer, task, socket or connection is created here.
use std::{
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

// The direction byte completes unsupported QUIC versions 0x69703100/01.
// A greased fixed bit can be zero, so a short-header-looking prefix is unsafe.
/// First bytes of every path-proof packet. The leading `0x80` and the `ip1` text make it look like a QUIC long header with an unsupported version, so QUIC drops it if it ever reaches it.
const PREFIX: &[u8; 4] = b"\x80ip1";
/// Direction byte for a request.
const REQUEST: u8 = 0;
/// Direction byte for a response.
const RESPONSE: u8 = 1;
/// Bytes before the authenticator: prefix (4), direction (1) and sequence (8).
const HEADER: usize = 13;
/// Fixed wire bound: prefix, direction, sequence and SHA-256 authenticator.
pub const PACKET_SIZE: usize = HEADER + 32;

/// True if any `stride`-sized packet in a received batch starts with the proof prefix.
pub(crate) fn contains_probes(bytes: &[u8], stride: usize) -> bool {
    bytes
        .chunks(stride.max(1))
        .any(|packet| packet.starts_with(PREFIX))
}

/// Remove only reserved proof datagrams from a possibly aggregated receive.
/// Retained QUIC segments stay byte-exact and ordered; a mixed batch must not
/// forward proofs into QUIC or discard the neighboring transport packets.
pub(crate) fn receive_probes(
    bytes: &mut [u8],
    stride: usize,
    mut receive: impl FnMut(&[u8]),
) -> usize {
    let mut kept = 0;
    for start in (0..bytes.len()).step_by(stride.max(1)) {
        let end = start.saturating_add(stride.max(1)).min(bytes.len());
        if bytes[start..end].starts_with(PREFIX) {
            receive(&bytes[start..end]);
        } else {
            if kept != start {
                bytes.copy_within(start..end, kept);
            }
            kept += end - start;
        }
    }
    kept
}

/// Parse only the fixed public envelope; this grants no authentication or health.
#[must_use]
pub fn path_probe_header(bytes: &[u8]) -> Option<(bool, u64)> {
    if bytes.len() != PACKET_SIZE || &bytes[..4] != PREFIX || bytes[4] > RESPONSE {
        return None;
    }
    Some((
        bytes[4] == RESPONSE,
        u64::from_be_bytes(bytes[5..HEADER].try_into().ok()?),
    ))
}

/// Clones share the existing QUIC provider's key; raw exporter bytes are cleared.
#[derive(Clone)]
pub(crate) struct PathKey(Arc<ring::hmac::Key>);
impl PathKey {
    /// Derive a session-bound key without exporting it to files, logs or argv.
    /// # Errors
    /// Refuses unavailable TLS exporters.
    pub fn from_connection(connection: &quinn::Connection) -> io::Result<Self> {
        let mut bytes = Zeroizing::new([0; 32]);
        connection
            .export_keying_material(&mut bytes[..], b"EXPORTER-infraternal-path-v1", b"")
            .map_err(|_| io::ErrorKind::PermissionDenied)?;
        Ok(Self(Arc::new(ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            &bytes[..],
        ))))
    }
    /// Builds a packet for `direction` and `sequence`, with an HMAC-SHA256 over the header as the authenticator.
    fn packet(&self, direction: u8, sequence: u64) -> [u8; PACKET_SIZE] {
        let mut packet = [0; PACKET_SIZE];
        packet[..4].copy_from_slice(PREFIX);
        packet[4] = direction;
        packet[5..HEADER].copy_from_slice(&sequence.to_be_bytes());
        let tag = ring::hmac::sign(&self.0, &packet[..HEADER]);
        packet[HEADER..].copy_from_slice(tag.as_ref());
        packet
    }

    /// Returns the sequence number if `bytes` is a correctly authenticated packet in `direction`; `None` for anything else.
    fn sequence(&self, bytes: &[u8], direction: u8) -> Option<u64> {
        let (response, sequence) = path_probe_header(bytes)?;
        if response != (direction == RESPONSE) {
            return None;
        }
        ring::hmac::verify(&self.0, &bytes[..HEADER], &bytes[HEADER..])
            .ok()
            .map(|()| sequence)
    }
    /// Answer only an authenticated request on the caller's admitted exact tuple.
    #[must_use]
    pub fn response(&self, request: &[u8]) -> Option<[u8; PACKET_SIZE]> {
        Some(self.packet(RESPONSE, self.sequence(request, REQUEST)?))
    }
}

/// One socket's sequence survives health-watch cancellation and route changes.
#[derive(Default)]
pub(crate) struct Probe {
    key: Option<(usize, PathKey)>,
    sequence: u64,
    generation: u64,
    destination: Option<SocketAddr>,
    pending: Option<(u64, Instant)>,
    answered: Option<(SocketAddr, Instant)>,
    timing: Option<(Duration, Duration)>,
}
impl Probe {
    /// True if the key for connection `id` is already installed.
    pub fn has_key(&self, id: usize) -> bool {
        self.key.as_ref().is_some_and(|(current, _)| *current == id)
    }
    /// Installs the key for connection `id`. Ignored if that connection's key is already there, so a concurrent second install cannot reset state.
    pub fn install_key(&mut self, id: usize, key: PathKey) {
        // A concurrent exporter for this same connection must not reset the
        // pending sequence or authenticated timing installed by the winner.
        if !self.has_key(id) {
            self.key = Some((id, key));
            self.pending = None;
            self.answered = None;
            self.timing = None;
        }
    }
    /// Starts a new watch and clears any pending request. Returns its generation number, which [`retire`](Self::retire) needs. Fails only if the counter would overflow.
    pub fn begin(&mut self) -> io::Result<u64> {
        self.generation = self.generation.checked_add(1).ok_or(io::ErrorKind::Other)?;
        self.pending = None;
        self.answered = None;
        self.destination = None;
        Ok(self.generation)
    }
    /// Ends the watch `generation` started. Ignored if a newer watch has begun.
    pub fn retire(&mut self, generation: u64) {
        if self.generation == generation {
            self.pending = None;
            self.answered = None;
            self.destination = None;
        }
    }
    /// Builds a request for `destination`. A new destination clears earlier state. A new sequence number is used only when no earlier request is still pending. Fails if no key is installed.
    pub fn request(&mut self, destination: SocketAddr) -> io::Result<[u8; PACKET_SIZE]> {
        if self.destination != Some(destination) {
            self.pending = None;
            self.answered = None;
            self.destination = Some(destination);
        }
        if self.pending.is_none() {
            self.sequence = self.sequence.checked_add(1).ok_or(io::ErrorKind::Other)?;
        }
        Ok(self
            .key
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .1
            .packet(REQUEST, self.sequence))
    }

    /// Publish only after successful physical send; an unsent request cannot time out.
    /// Every retransmission returns the same first clock to its health watcher.
    pub fn sent(&mut self, at: Instant) -> Instant {
        self.pending.get_or_insert((self.sequence, at)).1
    }
    /// Handles a received packet. It counts only if it comes from the current destination, is authenticated as a response, and matches the pending sequence. Then it updates the smoothed round-trip time and variation.
    pub fn receive(&mut self, bytes: &[u8], source: SocketAddr) {
        if self.destination != Some(source) {
            return;
        }
        let Some((_, key)) = &self.key else { return };
        if let Some(sequence) = key.sequence(bytes, RESPONSE)
            && self.pending.is_some_and(|(pending, _)| pending == sequence)
        {
            let sample = self
                .pending
                .map_or(Duration::ZERO, |(_, sent)| sent.elapsed());
            self.timing = Some(
                self.timing
                    .map_or((sample, sample / 2), |(rtt, variation)| {
                        (
                            (rtt * 7 + sample) / 8,
                            (variation * 3 + rtt.abs_diff(sample)) / 4,
                        )
                    }),
            );
            self.pending = None;
            self.answered = Some((source, Instant::now()));
        }
    }
    /// True if an authenticated response from `source` arrived at or after `since`.
    pub fn answered_since(&self, since: Instant, source: SocketAddr) -> bool {
        self.answered
            .is_some_and(|(physical, at)| physical == source && at >= since)
    }
    /// How long to wait for an answer: smoothed round trip plus four times its variation plus `margin`. Without a measurement it is `fallback` plus 200 ms.
    pub fn allowance(&self, fallback: Duration, margin: Duration) -> Duration {
        self.timing
            .map_or(fallback + Duration::from_millis(200), |(rtt, variation)| {
                rtt + variation * 4 + margin
            })
    }
    /// Forgets the pending request, answer, destination and timing.
    pub fn cancel(&mut self) {
        self.pending = None;
        self.answered = None;
        self.destination = None;
        self.timing = None;
    }
}

#[cfg(test)]
mod tests {
    //! Cryptographic controls use two distinct keys, stale sequences and both direction tags.
    use super::*;
    fn fixture_key(byte: u8) -> PathKey {
        PathKey(Arc::new(ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            &[byte; 32],
        )))
    }
    #[test]
    fn mixed_aggregation_preserves_all_neighboring_quic_bytes() {
        let key = fixture_key(1);
        let first = vec![0x40; PACKET_SIZE];
        let second = vec![0x41; PACKET_SIZE];
        let last = vec![0x42; 21];
        let mut bytes = [
            first.clone(),
            key.packet(REQUEST, 1).to_vec(),
            second.clone(),
            key.packet(RESPONSE, 1).to_vec(),
            last.clone(),
        ]
        .concat();
        let mut probes = 0;
        let retained = receive_probes(&mut bytes, PACKET_SIZE, |_| probes += 1);
        assert_eq!(probes, 2);
        assert_eq!(&bytes[..retained], [first, second, last].concat());
    }

    #[test]
    fn fixed_header_mac_matches_independent_sha256_vectors() {
        let key = fixture_key(1);
        for (direction, tag) in [
            (
                0,
                [
                    116, 251, 251, 212, 136, 16, 119, 238, 103, 4, 33, 150, 160, 175, 91, 216, 238,
                    54, 148, 170, 138, 132, 255, 99, 54, 68, 1, 222, 110, 177, 111, 236,
                ],
            ),
            (
                1,
                [
                    168, 44, 221, 68, 229, 180, 64, 251, 207, 23, 141, 106, 106, 151, 82, 211, 167,
                    183, 17, 51, 227, 96, 39, 97, 188, 211, 160, 210, 234, 181, 126, 45,
                ],
            ),
        ] {
            let packet = key.packet(direction, 42);
            assert_eq!(&packet[HEADER..], tag);
        }
    }

    #[test]
    fn only_current_session_response_answers_a_sent_probe() {
        let key = fixture_key(1);
        let mut probe = Probe {
            key: Some((1, key.clone())),
            ..Probe::default()
        };
        let address = "127.0.0.1:1234".parse().unwrap();
        let request = probe.request(address).unwrap();
        probe.sent(Instant::now());
        let response = key.response(&request).unwrap();
        let since = Instant::now();
        probe.receive(&request, address);
        probe.receive(&key.packet(RESPONSE, 0), address);
        probe.receive(&fixture_key(2).packet(RESPONSE, 1), address);
        let mut unexpected = response;
        unexpected[20] ^= 1;
        probe.receive(&unexpected, address);
        probe.receive(&response, "127.0.0.2:1234".parse().unwrap());
        assert!(!probe.answered_since(since, address));
        probe.receive(&response, address);
        assert!(probe.answered_since(since, address));
        let next = Instant::now();
        probe.receive(&response, address);
        assert!(
            !probe.answered_since(next, address),
            "a replay refreshed health"
        );
        let request = probe.request(address).unwrap();
        probe.sent(Instant::now());
        probe.cancel();
        probe.receive(&key.response(&request).unwrap(), address);
        assert!(
            !probe.answered_since(since, address),
            "retired proof refreshed health"
        );
        assert!(key.response(&response).is_none());
        assert!(key.response(&request[..10]).is_none());
        let old = probe.begin().unwrap();
        let _ = probe.request(address).unwrap();
        probe.sent(Instant::now());
        let replacement = probe.begin().unwrap();
        let current = probe.request(address).unwrap();
        probe.sent(Instant::now());
        probe.retire(old);
        let since = Instant::now();
        probe.receive(&key.response(&request).unwrap(), address);
        assert!(
            !probe.answered_since(since, address),
            "a prior epoch answered the replacement"
        );
        probe.receive(&key.response(&current).unwrap(), address);
        assert!(probe.answered_since(since, address));
        probe.retire(replacement);
        assert!(!probe.answered_since(since, address));
    }
}
