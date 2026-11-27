//! Round-trip probes on the direct path, sent from the `WireGuard` UDP port (#220, D185, D313 Q5).
//!
//! The path rule ([`infraternal_mesh::path_choice`]) can compare a direct path with a relay,
//! but it needs round-trip samples of the direct path. This module produces them without a
//! second socket and without any `GotaTun` change:
//!
//! - **Same port.** A probe leaves through the clone of the engine's own bound send socket, and
//!   its answer comes back to the engine's receive socket. The NAT mapping a probe uses is
//!   therefore the very one the peer's `WireGuard` packets use, so the number describes the path
//!   the data takes (a probe from another port could be mapped differently, or not at all).
//! - **Never mistaken for `WireGuard`.** A probe is 12 bytes: a kind byte (`0xF2` ping, `0xF3`
//!   pong), three zero bytes, and a big-endian 64-bit token. `WireGuard` message types are 1 to 4
//!   in the first byte, so the receive guard ([`crate::handshake_admission`]) recognises a probe
//!   by shape and consumes it before `GotaTun` sees it. A ping and its pong are the same size, so
//!   a probe can never amplify.
//! - **Only known peers get answers.** A ping is answered only when its source is an endpoint
//!   the node knows for an installed peer (configured or confirmed), at most
//!   [`PONGS_PER_SECOND`] a second. A stranger therefore learns nothing: the port stays as silent
//!   as `WireGuard` itself, and a spoofed source can make the node send at most that many
//!   12-byte datagrams, to an endpoint that already belongs to a peer.
//! - **No timers while idle (D81).** Nothing here runs on a schedule. The path owner asks for a
//!   round with [`DirectProbes::want_round_in`]; the receive task, which already runs for every
//!   inbound batch, compares one atomic with the clock and wakes the owner once the time has
//!   come ([`DirectProbes::note_traffic`]). A pair with no inbound traffic never wakes anything,
//!   and the only timer that exists is the loss timeout of a probe that is actually in flight.
//!
//! The module measures; it does not decide. Answers (and probes that were never answered) go to
//! the path owner through a channel as [`Answer`]s.

use bytes::BytesMut;
use gotatun::{
    packet::Packet,
    udp::{UdpSend, socket::UdpSocket as GotaUdpSocket},
};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Notify, mpsc};

/// First byte of a direct-path probe. `WireGuard` types are 1 to 4, so this is never ciphertext.
pub const PING: u8 = 0xF2;
/// First byte of the answer to a probe; like [`PING`], never a `WireGuard` type.
pub const PONG: u8 = 0xF3;
/// A fresh probe-token seed from the clock. Tokens only match an answer to its probe; they are not
/// secret, so the clock is enough. Both engines (Linux and macOS) start their probes with this.
#[must_use]
pub fn token_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |since| {
            since.as_secs().rotate_left(32) ^ u64::from(since.subsec_nanos())
        })
}
/// Length of every probe: kind, three zero bytes, a big-endian 64-bit token.
pub const PROBE_LEN: usize = 12;
/// Length of a `WireGuard` keepalive: a data packet with an empty payload, a 16-byte header
/// and a 16-byte tag.
pub const KEEPALIVE_LEN: usize = 32;
/// First byte of a `WireGuard` data message (handshakes are 1 to 3).
const WG_DATA: u8 = 4;

/// Whether `payload` is a data packet that carries something: longer than a keepalive. Only
/// such packets start probe rounds, so an idle pair's keepalives and its rekey handshakes never
/// do (D81), and a pair moving data does.
#[must_use]
pub fn is_traffic(payload: &[u8]) -> bool {
    payload.first() == Some(&WG_DATA) && payload.len() > KEEPALIVE_LEN
}
/// Pongs this node sends per second at most, however many pings arrive.
pub const PONGS_PER_SECOND: u32 = 64;
/// Probes in flight at once, across all peers; the oldest is forgotten past this.
const MAX_OUTSTANDING: usize = 64;
/// A probe unanswered for this long counts as a sample of this round trip, so a direct path that
/// silently stopped forwarding loses the comparison instead of keeping its old samples.
pub const PROBE_LOST: Duration = Duration::from_secs(2);

/// One finished probe: the endpoint it went to and how long the answer took. A probe that was
/// never answered is reported with [`PROBE_LOST`] as its round trip and `lost` set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The peer endpoint the probe was sent to.
    pub endpoint: SocketAddr,
    /// The measured round trip, or [`PROBE_LOST`] for a loss.
    pub rtt: Duration,
    /// Whether this is a timeout rather than an answer.
    pub lost: bool,
}

/// Build one probe frame of `kind` carrying `token`.
#[must_use]
pub fn frame(kind: u8, token: u64) -> [u8; PROBE_LEN] {
    let mut out = [0_u8; PROBE_LEN];
    out[0] = kind;
    out[4..].copy_from_slice(&token.to_be_bytes());
    out
}

/// Read a probe frame: its kind and token, or `None` when `payload` is anything else.
#[must_use]
pub fn parse(payload: &[u8]) -> Option<(u8, u64)> {
    let [kind, 0, 0, 0, token @ ..] = payload else {
        return None;
    };
    if !matches!(*kind, PING | PONG) {
        return None;
    }
    Some((*kind, u64::from_be_bytes(token.try_into().ok()?)))
}

/// Whether `payload` has a probe's shape. The receive guard uses it to consume probes.
#[must_use]
pub fn is_probe(payload: &[u8]) -> bool {
    // The length test comes first: nearly every datagram is a full data packet, and this is
    // the whole cost the receive path pays for it.
    payload.len() == PROBE_LEN && parse(payload).is_some()
}

/// An address with an IPv4-mapped IPv6 form turned back into IPv4, so the source of an answer
/// compares equal to the endpoint the probe was sent to however the socket reports it.
#[must_use]
pub fn canonical(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(address, |v4| {
            SocketAddr::new(IpAddr::V4(v4), address.port())
        }),
        IpAddr::V4(_) => address,
    }
}

/// A probe on its way: its token, where it went, and when.
struct InFlight {
    token: u64,
    endpoint: SocketAddr,
    sent: Instant,
}

/// The state every clone of a [`DirectProbes`] shares.
struct Inner {
    /// A clone of the engine's bound send socket: probes leave from the `WireGuard` port.
    socket: GotaUdpSocket,
    /// Zero of the millisecond clock behind `due_ms`.
    epoch: Instant,
    /// Source of tokens. They only match answers to probes; they are not secret.
    tokens: AtomicU64,
    /// Probes sent and not yet answered or timed out, oldest first.
    in_flight: Mutex<VecDeque<InFlight>>,
    /// Where finished probes go. A full channel drops the answer, as a busy path owner would.
    answers: mpsc::Sender<Answer>,
    /// Milliseconds on the `epoch` clock at which the owner wants its next round; `u64::MAX` when
    /// it wants none. Read by the receive task for every inbound batch.
    due_ms: AtomicU64,
    /// Wakes the owner when `due_ms` has passed.
    wake: Notify,
    /// Wakes whoever watches for lost probes, so a probe sent while it idled gets its timeout.
    pinged: Notify,
    /// The second the pong budget currently counts, and the pongs sent in it.
    pong_window: Mutex<(u64, u32)>,
    /// Pings sent, answers matched, losses and pongs sent, for diagnostics and tests.
    sent: AtomicU64,
    matched: AtomicU64,
    lost: AtomicU64,
    ponged: AtomicU64,
}

/// Counters of one [`DirectProbes`], for diagnostics and fixtures.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Pings this node sent.
    pub sent: u64,
    /// Answers that matched an outstanding ping.
    pub matched: u64,
    /// Pings that timed out unanswered.
    pub lost: u64,
    /// Peers' pings this node answered.
    pub ponged: u64,
}

/// The handle to one node's direct-path probes. Clones share everything; keep one in the
/// admission guard (it answers and matches) and one with the path owner (it asks).
#[derive(Clone)]
pub struct DirectProbes {
    inner: Arc<Inner>,
}

impl DirectProbes {
    /// Probes for the engine socket `socket` (a clone of the one `WireGuard` sends from).
    /// Finished probes arrive on the returned receiver.
    #[must_use]
    pub fn new(socket: GotaUdpSocket, seed: u64) -> (Self, mpsc::Receiver<Answer>) {
        let (answers, receiver) = mpsc::channel(64);
        let inner = Inner {
            socket,
            epoch: Instant::now(),
            tokens: AtomicU64::new(seed),
            in_flight: Mutex::new(VecDeque::new()),
            answers,
            due_ms: AtomicU64::new(u64::MAX),
            wake: Notify::new(),
            pinged: Notify::new(),
            pong_window: Mutex::new((0, 0)),
            sent: AtomicU64::new(0),
            matched: AtomicU64::new(0),
            lost: AtomicU64::new(0),
            ponged: AtomicU64::new(0),
        };
        (
            Self {
                inner: Arc::new(inner),
            },
            receiver,
        )
    }

    /// The counters so far.
    #[must_use]
    pub fn counts(&self) -> Counts {
        let inner = &self.inner;
        Counts {
            sent: inner.sent.load(Ordering::Relaxed),
            matched: inner.matched.load(Ordering::Relaxed),
            lost: inner.lost.load(Ordering::Relaxed),
            ponged: inner.ponged.load(Ordering::Relaxed),
        }
    }

    /// Milliseconds on this handle's clock; the unit of `due_ms`.
    fn now_ms(&self) -> u64 {
        u64::try_from(self.inner.epoch.elapsed().as_millis()).unwrap_or(u64::MAX - 1)
    }

    /// Ask to be woken in `delay`, if that is sooner than a wake already asked for. The owner
    /// calls this after a round to say when it wants the next one; it never needs a timer for it,
    /// because inbound traffic carries the clock (see [`DirectProbes::note_traffic`]).
    pub fn want_round_in(&self, delay: Duration) {
        let at = self
            .now_ms()
            .saturating_add(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX - 1));
        self.inner.due_ms.fetch_min(at, Ordering::Relaxed);
    }

    /// Called by the receive task for every inbound batch that carries more than keepalives. When a round is
    /// due it wakes the owner once and clears the request. The idle cost is one relaxed load
    /// while nothing is wanted, and a load plus a clock read while a round is pending.
    pub fn note_traffic(&self) {
        let due = self.inner.due_ms.load(Ordering::Relaxed);
        if due == u64::MAX || self.now_ms() < due {
            return;
        }
        if self
            .inner
            .due_ms
            .compare_exchange(due, u64::MAX, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.inner.wake.notify_one();
        }
    }

    /// Wait until the receive task says a round is due. Sleeps for ever while the pair is idle.
    pub async fn round_due(&self) {
        self.inner.wake.notified().await;
    }

    /// Wait until a ping was sent since the last call. The loss watcher sleeps on this while
    /// nothing is in flight, and arms [`DirectProbes::expire`]'s timeout when it wakes.
    pub async fn pinged(&self) {
        self.inner.pinged.notified().await;
    }

    /// Send one ping to `endpoint` from the `WireGuard` port and remember it.
    ///
    /// # Errors
    /// Returns the socket's send error; the ping is then forgotten.
    pub async fn ping(&self, endpoint: SocketAddr) -> io::Result<()> {
        let inner = &self.inner;
        let token = inner.tokens.fetch_add(1, Ordering::Relaxed);
        {
            let mut flight = inner
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if flight.len() >= MAX_OUTSTANDING {
                flight.pop_front();
            }
            flight.push_back(InFlight {
                token,
                endpoint: canonical(endpoint),
                sent: Instant::now(),
            });
        }
        inner.pinged.notify_one();
        let sent = inner
            .socket
            .send_to(
                Packet::from_bytes(BytesMut::from(&frame(PING, token)[..])),
                endpoint,
            )
            .await;
        match sent {
            Ok(()) => {
                inner.sent.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(error) => {
                let mut flight = inner
                    .in_flight
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                flight.retain(|probe| probe.token != token);
                Err(error)
            }
        }
    }

    /// Handle one probe the receive guard consumed: answer a ping from a known endpoint, or match
    /// a pong against the outstanding pings. `known` says whether `source` is an endpoint of an
    /// installed peer.
    pub async fn handle(&self, payload: &[u8], source: SocketAddr, known: bool) {
        let Some((kind, token)) = parse(payload) else {
            return;
        };
        if kind == PING {
            if known && self.pong_allowed() {
                let reply = Packet::from_bytes(BytesMut::from(&frame(PONG, token)[..]));
                if self.inner.socket.send_to(reply, source).await.is_ok() {
                    self.inner.ponged.fetch_add(1, Ordering::Relaxed);
                }
            }
            return;
        }
        let source = canonical(source);
        let now = Instant::now();
        let matched = {
            let mut flight = self
                .inner
                .in_flight
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            // An answer must come from the endpoint the ping went to, so a stranger cannot make
            // up a round trip for a peer by guessing a token.
            flight
                .iter()
                .position(|probe| probe.token == token && probe.endpoint == source)
                .and_then(|index| flight.remove(index))
        };
        if let Some(probe) = matched {
            self.inner.matched.fetch_add(1, Ordering::Relaxed);
            let _ = self.inner.answers.try_send(Answer {
                endpoint: probe.endpoint,
                rtt: now.saturating_duration_since(probe.sent),
                lost: false,
            });
        }
    }

    /// Whether one more pong fits this second's budget; counts it if so.
    fn pong_allowed(&self) -> bool {
        let second = self.inner.epoch.elapsed().as_secs();
        let mut window = self
            .inner
            .pong_window
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if window.0 != second {
            *window = (second, 0);
        }
        if window.1 >= PONGS_PER_SECOND {
            return false;
        }
        window.1 += 1;
        true
    }

    /// Report every ping older than [`PROBE_LOST`] as a loss, and say how long until the next
    /// one in flight would time out (`None` when nothing is in flight, so the owner needs no
    /// timer at all).
    pub fn expire(&self) -> Option<Duration> {
        let now = Instant::now();
        let mut flight = self
            .inner
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        while let Some(front) = flight.front() {
            let age = now.saturating_duration_since(front.sent);
            if age < PROBE_LOST {
                return Some(PROBE_LOST.saturating_sub(age));
            }
            let probe = flight.pop_front()?;
            self.inner.lost.fetch_add(1, Ordering::Relaxed);
            let _ = self.inner.answers.try_send(Answer {
                endpoint: probe.endpoint,
                rtt: PROBE_LOST,
                lost: true,
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    //! The wire shape, and the answer rules and demand-driven wake on real loopback sockets.
    #![expect(
        clippy::expect_used,
        reason = "a broken fixture (bad socket or address) must stop the test loudly"
    )]
    use super::{
        Answer, DirectProbes, KEEPALIVE_LEN, PING, PONG, PROBE_LEN, canonical, frame, is_probe,
        is_traffic, parse,
    };
    use crate::handshake_admission::{PeerAdmission, PeerAdmissionUdpReceiver};
    use gotatun::{
        packet::PacketBufPool,
        udp::{UdpRecv, UdpTransportFactory, UdpTransportFactoryParams, socket::UdpSocketFactory},
        x25519::StaticSecret,
    };
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };
    use tokio::{sync::RwLock, sync::mpsc, time::timeout};

    /// A frame parses back to its kind and token, and anything else is not a probe.
    #[test]
    fn frames_round_trip_and_nothing_else_parses() {
        let ping = frame(PING, 0x0102_0304_0506_0708);
        assert_eq!(ping.len(), PROBE_LEN);
        assert_eq!(parse(&ping), Some((PING, 0x0102_0304_0506_0708)));
        assert_eq!(parse(&frame(PONG, 7)), Some((PONG, 7)));
        assert!(!is_probe(&[]));
        assert!(!is_probe(&ping[..11]));
        let mut longer = ping.to_vec();
        longer.push(0);
        assert!(!is_probe(&longer));
        let mut dirty = ping;
        dirty[2] = 1;
        assert!(!is_probe(&dirty), "the three padding bytes must be zero");
        // Every WireGuard message type starts with 1 to 4 and three zero bytes.
        for kind in 1..=4_u8 {
            assert!(!is_probe(&frame(kind, 9)));
        }
    }

    /// Only a data packet longer than a keepalive counts as traffic: not a keepalive, not a
    /// handshake of any size, not a probe.
    #[test]
    fn only_data_longer_than_a_keepalive_is_traffic() {
        let packet = |kind: u8, len: usize| {
            let mut bytes = vec![0_u8; len];
            bytes[0] = kind;
            bytes
        };
        assert!(!is_traffic(&packet(4, KEEPALIVE_LEN)), "a keepalive");
        assert!(is_traffic(&packet(4, KEEPALIVE_LEN + 1)));
        assert!(is_traffic(&packet(4, 1_400)));
        assert!(!is_traffic(&packet(1, 148)), "a handshake initiation");
        assert!(!is_traffic(&packet(2, 92)), "a handshake response");
        assert!(!is_traffic(&frame(PING, 1)), "a probe");
        assert!(!is_traffic(&[]));
    }

    /// An IPv4-mapped IPv6 source compares equal to its IPv4 form.
    #[test]
    fn mapped_addresses_compare_as_ipv4() {
        let v4: SocketAddr = "127.0.0.7:51820".parse().expect("address");
        let mapped: SocketAddr = "[::ffff:127.0.0.7]:51820".parse().expect("address");
        assert_eq!(canonical(mapped), v4);
        assert_eq!(canonical(v4), v4);
    }

    /// One test node: its address, probes, answers, and how many datagrams reached `GotaTun`.
    struct Node {
        address: SocketAddr,
        probes: DirectProbes,
        answers: mpsc::Receiver<Answer>,
        admission: Arc<RwLock<PeerAdmission>>,
        forwarded: Arc<AtomicU64>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Node {
        /// Bind a loopback socket pair as the node's own bind does and run its guarded receiver.
        async fn start(identity: u8) -> Self {
            let params = UdpTransportFactoryParams {
                addr: Some(Ipv4Addr::LOCALHOST.into()),
                port: 0,
                #[cfg(target_os = "linux")]
                fwmark: None,
            };
            let (send, receive) = UdpSocketFactory::default()
                .bind(&params)
                .await
                .expect("bind");
            let address = send.local_addr().expect("address");
            let admission = Arc::new(RwLock::new(PeerAdmission::new(StaticSecret::from(
                [identity; 32],
            ))));
            let (probes, answers) = DirectProbes::new(send, 1);
            admission.write().await.set_probes(probes.clone());
            let forwarded = Arc::new(AtomicU64::new(0));
            let mut receiver = PeerAdmissionUdpReceiver::new(receive, Arc::clone(&admission));
            let count = Arc::clone(&forwarded);
            let task = tokio::spawn(async move {
                let mut buffer = <PeerAdmissionUdpReceiver as UdpRecv>::RecvManyBuf::default();
                let mut pool = PacketBufPool::new(8);
                let mut packets = Vec::new();
                while receiver
                    .recv_many_from(&mut buffer, &mut pool, &mut packets)
                    .await
                    .is_ok()
                {
                    count.fetch_add(packets.len() as u64, Ordering::Relaxed);
                    packets.clear();
                }
            });
            Self {
                address,
                probes,
                answers,
                admission,
                forwarded,
                task,
            }
        }
    }

    impl Drop for Node {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// A ping from a known endpoint is answered from the `WireGuard` port, the round trip is
    /// measured, and neither datagram reaches the engine.
    #[tokio::test]
    async fn a_known_peer_answers_and_nothing_reaches_the_engine() {
        let mut a = Node::start(0x11).await;
        let b = Node::start(0x22).await;
        a.admission
            .write()
            .await
            .set_configured_endpoints([b.address]);
        b.admission
            .write()
            .await
            .set_configured_endpoints([a.address]);
        a.probes.ping(b.address).await.expect("ping");
        let answer = timeout(Duration::from_secs(2), a.answers.recv())
            .await
            .expect("an answer arrives")
            .expect("channel open");
        assert_eq!(answer.endpoint, b.address);
        assert!(!answer.lost);
        assert!(answer.rtt < Duration::from_millis(500), "{:?}", answer.rtt);
        let (counts_a, counts_b) = (a.probes.counts(), b.probes.counts());
        assert_eq!((counts_a.sent, counts_a.matched), (1, 1));
        assert_eq!(counts_b.ponged, 1);
        // sleep: let any wrongly forwarded datagram reach the counter before it is read.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(a.forwarded.load(Ordering::Relaxed), 0);
        assert_eq!(b.forwarded.load(Ordering::Relaxed), 0);
    }

    /// A ping from an endpoint the node does not know gets no answer: the port stays silent.
    #[tokio::test]
    async fn a_stranger_gets_no_answer() {
        let mut a = Node::start(0x11).await;
        let b = Node::start(0x22).await;
        a.probes.ping(b.address).await.expect("ping");
        let answer = timeout(Duration::from_millis(300), a.answers.recv()).await;
        assert!(answer.is_err(), "a stranger's ping must not be answered");
        assert_eq!(b.probes.counts().ponged, 0);
        assert_eq!(a.probes.counts().matched, 0);
    }

    /// An answer must come from the endpoint the ping went to, and match its token.
    #[tokio::test]
    async fn an_answer_from_the_wrong_source_is_ignored() {
        let mut a = Node::start(0x11).await;
        let target: SocketAddr = "127.0.0.1:9".parse().expect("address");
        let other: SocketAddr = "127.0.0.2:9".parse().expect("address");
        // The ping goes to a port nobody listens on; the loopback may report a refusal.
        let _ = a.probes.ping(target).await;
        let token = {
            let flight = a.probes.inner.in_flight.lock().expect("lock");
            flight.front().map(|probe| probe.token)
        };
        let Some(token) = token else { return };
        a.probes.handle(&frame(PONG, token), other, true).await;
        a.probes.handle(&frame(PONG, token ^ 1), target, true).await;
        assert!(a.answers.try_recv().is_err(), "neither answer may match");
        a.probes.handle(&frame(PONG, token), target, true).await;
        assert_eq!(a.answers.try_recv().expect("matched").endpoint, target);
    }

    /// The owner is woken by inbound traffic once its round is due, never before, and never
    /// when it asked for nothing.
    #[tokio::test]
    async fn rounds_wake_only_on_traffic_after_they_are_due() {
        let (probes, _answers) = {
            let a = Node::start(0x11).await;
            (a.probes.clone(), a)
        };
        probes.note_traffic();
        assert!(
            timeout(Duration::from_millis(50), probes.round_due())
                .await
                .is_err(),
            "nothing wanted, nothing woken"
        );
        probes.want_round_in(Duration::from_millis(80));
        probes.note_traffic();
        assert!(
            timeout(Duration::from_millis(30), probes.round_due())
                .await
                .is_err(),
            "not due yet"
        );
        // sleep: let the requested round come due; no traffic yet, so still no wake.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            timeout(Duration::from_millis(30), probes.round_due())
                .await
                .is_err(),
            "due, but no traffic has arrived to carry the clock"
        );
        probes.note_traffic();
        timeout(Duration::from_millis(200), probes.round_due())
            .await
            .expect("traffic after the due time wakes the owner");
        probes.note_traffic();
        assert!(
            timeout(Duration::from_millis(30), probes.round_due())
                .await
                .is_err(),
            "one request wakes once"
        );
    }

    /// Hold an idle guarded receiver for `seconds`, with or without probes installed. Measurement
    /// for D81 (#220, J1206), see [`idle_receiver`].
    async fn idle_hold(with_probes: bool, seconds: u64) {
        let params = UdpTransportFactoryParams {
            addr: Some(Ipv4Addr::LOCALHOST.into()),
            port: 0,
            #[cfg(target_os = "linux")]
            fwmark: None,
        };
        let (send, receive) = UdpSocketFactory::default()
            .bind(&params)
            .await
            .expect("bind");
        let admission = Arc::new(RwLock::new(PeerAdmission::new(StaticSecret::from([9; 32]))));
        let _answers = if with_probes {
            let (probes, answers) = DirectProbes::new(send, 1);
            admission.write().await.set_probes(probes);
            Some(answers)
        } else {
            None
        };
        let mut receiver = PeerAdmissionUdpReceiver::new(receive, Arc::clone(&admission));
        let task = tokio::spawn(async move {
            let mut buffer = <PeerAdmissionUdpReceiver as UdpRecv>::RecvManyBuf::default();
            let mut pool = PacketBufPool::new(8);
            let mut packets = Vec::new();
            while receiver
                .recv_many_from(&mut buffer, &mut pool, &mut packets)
                .await
                .is_ok()
            {
                packets.clear();
            }
        });
        // sleep: the idle window itself is what is measured.
        tokio::time::sleep(Duration::from_secs(seconds)).await;
        task.abort();
    }

    /// Holds an idle guarded receiver for `IDLE_SECONDS` (default 30), with probes installed
    /// unless `IDLE_PROBES=0`. Run it under `/usr/bin/time -l` (macOS) or `-v` (Linux) at two
    /// window lengths and subtract the voluntary context switches: the difference over the
    /// difference in seconds is the idle rate, free of start-up cost.
    #[tokio::test]
    #[ignore = "measurement"]
    async fn idle_receiver() {
        let seconds = std::env::var("IDLE_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(30);
        let with_probes = std::env::var("IDLE_PROBES").as_deref() != Ok("0");
        idle_hold(with_probes, seconds).await;
    }
}
