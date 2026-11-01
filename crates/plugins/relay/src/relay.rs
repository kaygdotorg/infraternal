//! The relay service: forwards `WireGuard` ciphertext between linked hosts as QUIC DATAGRAMs [131,163,313].
//!
//! Any node with a server-purpose identity can run it (D313 Q3). It never holds
//! a mesh key: it sees only the 4-byte link id and opaque ciphertext. A link
//! forms only when both hosts asked for each other; the relay then hands both
//! the same id and forwards each frame unchanged to the other end, so
//! forwarding is one table read and one `send_datagram` with no copy.
//!
//! Everything is bounded: pre-authentication handshakes, hosts, requests per
//! host, the control writer queue, per-connection QUIC buffers (see `tls`) and
//! shared global, per-host and per-pair DATAGRAM forwarding budgets. A host
//! that reconnects replaces its previous connection; its links end and form
//! again from the new requests.
//! The same UDP port answers authenticated address probes (`probe`), which are
//! taken out in front of quinn so a relay needs one port.

use crate::{
    probe::{self, ProbeKey},
    tls,
    wire::{self, HostId, LinkId, Notice, Request},
};
use quinn::{AsyncUdpSocket, UdpPoller, udp};
use std::{
    collections::{HashMap, HashSet},
    fmt, io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::sync::mpsc;

const QUEUE_ACCOUNTING_UNIT_BYTES: usize = 1024;
const QUEUE_ENTRY_OVERHEAD_BYTES: usize = 128;
const GLOBAL_FORWARD_QUEUE_BYTES: usize = 64 * 1024 * 1024;
const PAIR_FORWARD_QUEUE_BYTES: usize = 256 * 1024;
/// One source host may retain at most one sixteenth of the global queue.
const HOST_FORWARD_QUEUE_BYTES: usize = 4 * 1024 * 1024;
const GLOBAL_FORWARD_QUEUE_UNITS: usize = GLOBAL_FORWARD_QUEUE_BYTES / QUEUE_ACCOUNTING_UNIT_BYTES;
const PAIR_FORWARD_QUEUE_UNITS: usize = PAIR_FORWARD_QUEUE_BYTES / QUEUE_ACCOUNTING_UNIT_BYTES;
const HOST_FORWARD_QUEUE_UNITS: usize = HOST_FORWARD_QUEUE_BYTES / QUEUE_ACCOUNTING_UNIT_BYTES;
const MAX_HANDSHAKES: usize = 256;
const MAX_HANDSHAKES_PER_IP: usize = 8;

/// Resource bounds; every table and queue in the relay has one.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Connected hosts.
    pub hosts: usize,
    /// Outstanding link requests per host.
    pub requests_per_host: usize,
    /// In-flight QUIC handshakes and control hellos across the relay.
    pub handshakes: usize,
    /// In-flight QUIC handshakes and control hellos from one source IP.
    pub handshakes_per_ip: usize,
    /// Time allowed for the QUIC handshake and the control hello.
    pub handshake: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            hosts: 4_096,
            requests_per_host: 1_024,
            handshakes: MAX_HANDSHAKES,
            handshakes_per_ip: MAX_HANDSHAKES_PER_IP,
            handshake: Duration::from_secs(5),
        }
    }
}

/// Decides whether a verified host may use this relay (membership, revocation).
pub type Admission = Arc<dyn Fn(HostId) -> bool + Send + Sync>;

/// Cumulative counters, read without locks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub hosts: usize,
    pub links: usize,
    pub forwarded: u64,
    pub dropped: u64,
    pub probes_answered: u64,
    pub probes_refused: u64,
}

#[derive(Default)]
struct Counters {
    forwarded: AtomicU64,
    dropped: AtomicU64,
    probes_answered: AtomicU64,
    probes_refused: AtomicU64,
}

#[derive(Default)]
struct PreAuthCounts {
    total: usize,
    by_ip: HashMap<IpAddr, usize>,
}

/// Caps tasks that have not completed the authenticated control hello.
struct PreAuthLimiter {
    max_total: usize,
    max_per_ip: usize,
    counts: Mutex<PreAuthCounts>,
}

impl PreAuthLimiter {
    fn new(max_total: usize, max_per_ip: usize) -> Arc<Self> {
        Arc::new(Self {
            max_total,
            max_per_ip,
            counts: Mutex::new(PreAuthCounts::default()),
        })
    }

    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PreAuthPermit> {
        let ip = canonical_ip(ip);
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let source_count = counts.by_ip.get(&ip).copied().unwrap_or_default();
        if counts.total >= self.max_total || source_count >= self.max_per_ip {
            return None;
        }
        counts.total += 1;
        *counts.by_ip.entry(ip).or_default() += 1;
        Some(PreAuthPermit {
            limiter: self.clone(),
            ip,
        })
    }
}

/// Releases one global and one source-IP handshake slot when dropped.
struct PreAuthPermit {
    limiter: Arc<PreAuthLimiter>,
    ip: IpAddr,
}

impl Drop for PreAuthPermit {
    fn drop(&mut self) {
        let mut counts = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(counts.total > 0, "pre-auth handshake count underflow");
        counts.total = counts.total.saturating_sub(1);
        let remove_source = if let Some(source_count) = counts.by_ip.get_mut(&self.ip) {
            debug_assert!(*source_count > 0, "source-IP handshake count underflow");
            *source_count = source_count.saturating_sub(1);
            *source_count == 0
        } else {
            false
        };
        if remove_source {
            counts.by_ip.remove(&self.ip);
        }
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

struct Host {
    connection: quinn::Connection,
    notices: mpsc::Sender<Notice>,
    wants: HashSet<HostId>,
    datagrams: Arc<QueueBudget>,
}

/// A nonblocking byte budget. Reservations travel with queued `Bytes` owners,
/// so a capacity limit reflects memory still retained by Quinn's send queue.
struct QueueBudget {
    max_units: usize,
    queued_units: AtomicUsize,
}

impl QueueBudget {
    fn new(max_units: usize) -> Self {
        Self {
            max_units,
            queued_units: AtomicUsize::new(0),
        }
    }

    fn reserve(self: &Arc<Self>, units: usize) -> Option<QueueReservation> {
        if units == 0 {
            return None;
        }
        let mut queued = self.queued_units.load(Ordering::Relaxed);
        loop {
            let next = queued.checked_add(units)?;
            if next > self.max_units {
                return None;
            }
            match self.queued_units.compare_exchange_weak(
                queued,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(QueueReservation {
                        budget: self.clone(),
                        units,
                    });
                }
                Err(observed) => queued = observed,
            }
        }
    }
}

/// Releases a budget reservation when its forwarded datagram is no longer queued.
struct QueueReservation {
    budget: Arc<QueueBudget>,
    units: usize,
}

impl Drop for QueueReservation {
    fn drop(&mut self) {
        let previous = self
            .budget
            .queued_units
            .fetch_sub(self.units, Ordering::Relaxed);
        debug_assert!(previous >= self.units, "queue reservation released twice");
    }
}

/// Adds budget ownership to an existing payload without copying its bytes.
struct ForwardedDatagram {
    payload: bytes::Bytes,
    _global: QueueReservation,
    _host: QueueReservation,
    _pair: QueueReservation,
}

impl AsRef<[u8]> for ForwardedDatagram {
    fn as_ref(&self) -> &[u8] {
        self.payload.as_ref()
    }
}

fn queue_units(datagram_len: usize) -> Option<usize> {
    datagram_len
        .checked_add(QUEUE_ENTRY_OVERHEAD_BYTES)?
        .checked_add(QUEUE_ACCOUNTING_UNIT_BYTES - 1)
        .map(|rounded| rounded / QUEUE_ACCOUNTING_UNIT_BYTES)
}

fn queue_forward_datagram(
    global: &Arc<QueueBudget>,
    host: &Arc<QueueBudget>,
    pair: &Arc<QueueBudget>,
    payload: bytes::Bytes,
) -> Option<bytes::Bytes> {
    let units = queue_units(payload.len())?;
    let pair_reservation = pair.reserve(units)?;
    let host_reservation = host.reserve(units)?;
    let global_reservation = global.reserve(units)?;
    Some(bytes::Bytes::from_owner(ForwardedDatagram {
        payload,
        _global: global_reservation,
        _host: host_reservation,
        _pair: pair_reservation,
    }))
}

struct Link {
    ends: [(HostId, quinn::Connection); 2],
    datagrams: Arc<QueueBudget>,
}

#[derive(Default)]
struct Table {
    hosts: HashMap<HostId, Host>,
    links: HashMap<LinkId, Link>,
    pairs: HashMap<(HostId, HostId), LinkId>,
    retired_datagrams: HashMap<(HostId, HostId), Weak<QueueBudget>>,
    retired_host_datagrams: HashMap<HostId, Weak<QueueBudget>>,
    next: u32,
}

fn pair(a: HostId, b: HostId) -> (HostId, HostId) {
    if a <= b { (a, b) } else { (b, a) }
}

impl Table {
    fn current(&self, host: HostId, connection: usize) -> Option<&Host> {
        self.hosts
            .get(&host)
            .filter(|entry| entry.connection.stable_id() == connection)
    }

    fn allocate(&mut self) -> LinkId {
        loop {
            self.next = self.next.wrapping_add(1);
            if self.next != 0 && !self.links.contains_key(&LinkId(self.next)) {
                return LinkId(self.next);
            }
        }
    }

    fn datagrams_for_pair(&mut self, key: (HostId, HostId)) -> Arc<QueueBudget> {
        self.retired_datagrams
            .remove(&key)
            .and_then(|budget| budget.upgrade())
            .unwrap_or_else(|| Arc::new(QueueBudget::new(PAIR_FORWARD_QUEUE_UNITS)))
    }

    fn datagrams_for_host(&mut self, host: HostId) -> Arc<QueueBudget> {
        self.retired_host_datagrams
            .remove(&host)
            .and_then(|budget| budget.upgrade())
            .unwrap_or_else(|| Arc::new(QueueBudget::new(HOST_FORWARD_QUEUE_UNITS)))
    }

    /// Retain a weak lookup while old forwarded datagrams still own this host's budget.
    fn retire_host_datagrams(&mut self, host: HostId, budget: &Arc<QueueBudget>) {
        if Arc::strong_count(budget) <= 1 {
            return;
        }
        self.retired_host_datagrams
            .insert(host, Arc::downgrade(budget));
        if self.retired_host_datagrams.len() > GLOBAL_FORWARD_QUEUE_UNITS {
            self.retired_host_datagrams
                .retain(|_, budget| budget.strong_count() > 0);
        }
    }

    /// Retain only a weak lookup while old QUIC datagrams still own this pair's budget.
    fn retire_datagrams(&mut self, key: (HostId, HostId), budget: &Arc<QueueBudget>) {
        if Arc::strong_count(budget) <= 1 {
            return;
        }
        self.retired_datagrams.insert(key, Arc::downgrade(budget));
        if self.retired_datagrams.len() > GLOBAL_FORWARD_QUEUE_UNITS {
            self.retired_datagrams
                .retain(|_, budget| budget.strong_count() > 0);
        }
    }

    /// Remove the link between two hosts, telling each end that is still current.
    fn unlink(&mut self, a: HostId, b: HostId) {
        let key = pair(a, b);
        let Some(id) = self.pairs.remove(&key) else {
            return;
        };
        if let Some(link) = self.links.remove(&id) {
            self.retire_datagrams(key, &link.datagrams);
            for (index, (host, connection)) in link.ends.iter().enumerate() {
                let peer = link.ends[1 - index].0;
                if let Some(entry) = self.current(*host, connection.stable_id()) {
                    notify(entry, Notice::Unlinked { peer });
                }
            }
        }
    }

    fn try_link(&mut self, a: HostId, b: HostId) {
        if a == b || self.pairs.contains_key(&pair(a, b)) {
            return;
        }
        let (Some(first), Some(second)) = (self.hosts.get(&a), self.hosts.get(&b)) else {
            return;
        };
        if !first.wants.contains(&b) || !second.wants.contains(&a) {
            return;
        }
        let ends = [
            (a, first.connection.clone()),
            (b, second.connection.clone()),
        ];
        let datagrams = self.datagrams_for_pair(pair(a, b));
        let id = self.allocate();
        self.pairs.insert(pair(a, b), id);
        self.links.insert(id, Link { ends, datagrams });
        if let Some(entry) = self.hosts.get(&a) {
            notify(entry, Notice::Linked { peer: b, id });
        }
        if let Some(entry) = self.hosts.get(&b) {
            notify(entry, Notice::Linked { peer: a, id });
        }
    }

    fn remove_host(&mut self, host: HostId) {
        if let Some(entry) = self.hosts.remove(&host) {
            self.retire_host_datagrams(host, &entry.datagrams);
            for peer in entry.wants {
                self.unlink(host, peer);
            }
        }
    }
}

/// A host whose notice queue is full is not reading its control stream;
/// closing it is the only bounded choice.
fn notify(host: &Host, notice: Notice) {
    if host.notices.try_send(notice).is_err() {
        host.connection
            .close(quinn::VarInt::from_u32(2), b"control queue full");
    }
}

struct Shared {
    table: RwLock<Table>,
    probes: RwLock<HashMap<u64, ProbeKey>>,
    counters: Counters,
    datagrams: Arc<QueueBudget>,
    pre_auth: Arc<PreAuthLimiter>,
    limits: Limits,
    admission: Admission,
}

impl fmt::Debug for Shared {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("relay")
    }
}

impl Shared {
    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Table> {
        self.table
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Table> {
        self.table
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn register(
        &self,
        host: HostId,
        connection: &quinn::Connection,
        notices: mpsc::Sender<Notice>,
    ) -> bool {
        let mut table = self.write();
        if let Some(previous) = table.hosts.get(&host) {
            previous.connection.close(
                quinn::VarInt::from_u32(3),
                b"replaced by a newer connection",
            );
            table.remove_host(host);
        } else if table.hosts.len() >= self.limits.hosts {
            return false;
        }
        let datagrams = table.datagrams_for_host(host);
        table.hosts.insert(
            host,
            Host {
                connection: connection.clone(),
                notices,
                wants: HashSet::new(),
                datagrams,
            },
        );
        true
    }

    fn request(&self, host: HostId, connection: usize, request: Request) -> bool {
        let mut table = self.write();
        let Some(entry) = table.hosts.get_mut(&host) else {
            return false;
        };
        if entry.connection.stable_id() != connection {
            return false;
        }
        match request {
            Request::Link(peer) => {
                if !entry.wants.contains(&peer)
                    && entry.wants.len() >= self.limits.requests_per_host
                {
                    return false;
                }
                entry.wants.insert(peer);
                table.try_link(host, peer);
            }
            Request::Unlink(peer) => {
                entry.wants.remove(&peer);
                table.unlink(host, peer);
            }
        }
        true
    }

    fn unregister(&self, host: HostId, connection: usize) {
        let mut table = self.write();
        if table.current(host, connection).is_some() {
            table.remove_host(host);
        }
    }

    fn forward(&self, connection: usize, datagram: bytes::Bytes) {
        let Some((id, _)) = wire::split(&datagram) else {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let table = self.read();
        let target = table.links.get(&id).and_then(|link| {
            let [(first_host, first), (second_host, second)] = &link.ends;
            if first.stable_id() == connection {
                Some((*first_host, second, &link.datagrams))
            } else if second.stable_id() == connection {
                Some((*second_host, first, &link.datagrams))
            } else {
                None
            }
        });
        // A frame for a link the sender is not part of, or one that ended,
        // is dropped: forwarding is never a way to reach an unlinked host.
        let forwarded = target.is_some_and(|(source, target, pair_budget)| {
            table.hosts.get(&source).is_some_and(|host| {
                queue_forward_datagram(&self.datagrams, &host.datagrams, pair_budget, datagram)
                    .is_some_and(|datagram| target.send_datagram(datagram).is_ok())
            })
        });
        let counter = if forwarded {
            &self.counters.forwarded
        } else {
            &self.counters.dropped
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn answer(&self, payload: &[u8], source: SocketAddr) -> Option<[u8; probe::LEN]> {
        let session = probe::session(payload)?;
        let probes = self
            .probes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let reply = probes.get(&session)?.answer(payload, source);
        let counter = if reply.is_some() {
            &self.counters.probes_answered
        } else {
            &self.counters.probes_refused
        };
        counter.fetch_add(1, Ordering::Relaxed);
        reply
    }
}

/// The UDP socket under quinn; it answers probes and hides them from QUIC.
#[derive(Debug)]
struct ProbeSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    shared: Arc<Shared>,
}

impl AsyncUdpSocket for ProbeSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &udp::Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = ready!(self.inner.poll_recv(cx, bufs, meta))?;
        for (meta, buf) in meta.iter_mut().zip(bufs.iter()).take(count) {
            // A probe never shares a 4-tuple with QUIC, so a coalesced
            // receive of probe-sized segments that starts with one is all probes.
            if meta.stride != probe::LEN || !probe::is_probe(&buf[..probe::LEN.min(meta.len)]) {
                continue;
            }
            for segment in buf[..meta.len].chunks(probe::LEN) {
                if let Some(reply) = self.shared.answer(segment, meta.addr) {
                    // A full socket buffer drops the reply; the node retries.
                    let _ = self.inner.try_send(&udp::Transmit {
                        destination: meta.addr,
                        ecn: None,
                        contents: &reply,
                        segment_size: None,
                        src_ip: meta.dst_ip,
                    });
                }
            }
            // quinn skips a zero-length receive.
            meta.len = 0;
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// A running relay. Dropping it without [`Relay::close`] also stops it.
pub struct Relay {
    endpoint: quinn::Endpoint,
    shared: Arc<Shared>,
    accept: tokio::task::JoinHandle<()>,
}

impl Relay {
    /// Bind `listen` and start accepting authenticated hosts.
    /// # Errors
    /// Fails on bind errors or an invalid identity.
    pub fn start(
        listen: SocketAddr,
        credentials: tls::Credentials,
        limits: Limits,
        admission: Admission,
    ) -> io::Result<Self> {
        let config = tls::server_config(credentials)?;
        let shared = Arc::new(Shared {
            table: RwLock::new(Table::default()),
            probes: RwLock::new(HashMap::new()),
            counters: Counters::default(),
            datagrams: Arc::new(QueueBudget::new(GLOBAL_FORWARD_QUEUE_UNITS)),
            pre_auth: PreAuthLimiter::new(limits.handshakes, limits.handshakes_per_ip),
            limits,
            admission,
        });
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let socket = Arc::new(ProbeSocket {
            inner: runtime.wrap_udp_socket(std::net::UdpSocket::bind(listen)?)?,
            shared: shared.clone(),
        });
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(config),
            socket,
            runtime,
        )?;
        let accept = tokio::spawn(accept(endpoint.clone(), shared.clone()));
        Ok(Self {
            endpoint,
            shared,
            accept,
        })
    }

    /// The bound UDP address.
    /// # Errors
    /// Fails if the socket address cannot be read.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Current table sizes and cumulative counters.
    #[must_use]
    pub fn stats(&self) -> Stats {
        let table = self.shared.read();
        let counters = &self.shared.counters;
        Stats {
            hosts: table.hosts.len(),
            links: table.links.len(),
            forwarded: counters.forwarded.load(Ordering::Relaxed),
            dropped: counters.dropped.load(Ordering::Relaxed),
            probes_answered: counters.probes_answered.load(Ordering::Relaxed),
            probes_refused: counters.probes_refused.load(Ordering::Relaxed),
        }
    }

    /// Stop accepting, close every connection and wait briefly for the close to send.
    pub async fn close(self) {
        self.accept.abort();
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"relay stopped");
        let _ = tokio::time::timeout(Duration::from_secs(1), self.endpoint.wait_idle()).await;
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.accept.abort();
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"relay stopped");
    }
}

async fn accept(endpoint: quinn::Endpoint, shared: Arc<Shared>) {
    while let Some(incoming) = endpoint.accept().await {
        let Some(permit) = shared.pre_auth.try_acquire(incoming.remote_address().ip()) else {
            incoming.refuse();
            continue;
        };
        tokio::spawn(serve(incoming, shared.clone(), permit));
    }
}

async fn serve(incoming: quinn::Incoming, shared: Arc<Shared>, pre_auth: PreAuthPermit) {
    let limit = shared.limits.handshake;
    let Ok(Ok(connection)) = tokio::time::timeout(limit, incoming).await else {
        return;
    };
    let Some(host) = tls::peer_host(&connection).filter(|host| (shared.admission)(*host)) else {
        connection.close(quinn::VarInt::from_u32(1), b"not admitted");
        return;
    };
    let Ok(key) = ProbeKey::from_connection(&connection) else {
        connection.close(quinn::VarInt::from_u32(1), b"no probe key");
        return;
    };
    let opened = tokio::time::timeout(limit, async {
        let (send, mut recv) = connection.accept_bi().await.ok()?;
        let mut hello = [0; 4];
        recv.read_exact(&mut hello).await.ok()?;
        (hello == tls::HELLO).then_some((send, recv))
    })
    .await;
    let Ok(Some((mut send, mut recv))) = opened else {
        connection.close(quinn::VarInt::from_u32(1), b"no control hello");
        return;
    };
    let (notices, mut queue) = mpsc::channel::<Notice>(64);
    if !shared.register(host, &connection, notices) {
        connection.close(quinn::VarInt::from_u32(4), b"relay full");
        return;
    }
    drop(pre_auth);
    let session = key.session();
    // A colliding 64-bit session only leaves the newer connection without probes.
    let owns_session = match shared
        .probes
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entry(session)
    {
        std::collections::hash_map::Entry::Vacant(slot) => {
            slot.insert(key);
            true
        }
        std::collections::hash_map::Entry::Occupied(_) => false,
    };
    let id = connection.stable_id();
    let writer = async {
        while let Some(notice) = queue.recv().await {
            let (bytes, len) = notice.encode();
            if send.write_all(&bytes[..len]).await.is_err() {
                break;
            }
        }
    };
    let control = async {
        let mut kind = [0; 1];
        let mut body = [0; wire::MAX_MESSAGE];
        loop {
            if recv.read_exact(&mut kind).await.is_err() {
                break;
            }
            let Some(len) = wire::request_len(kind[0]) else {
                break;
            };
            if recv.read_exact(&mut body[..len]).await.is_err() {
                break;
            }
            let Some(request) = Request::decode(kind[0], &body[..len]) else {
                break;
            };
            if !shared.request(host, id, request) {
                break;
            }
        }
    };
    let datagrams = async {
        while let Ok(datagram) = connection.read_datagram().await {
            shared.forward(id, datagram);
        }
    };
    tokio::select! {
        () = writer => {}
        () = control => {}
        () = datagrams => {}
    }
    shared.unregister(host, id);
    if owns_session {
        shared
            .probes
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&session);
    }
    connection.close(quinn::VarInt::from_u32(0), b"control ended");
}

#[cfg(test)]
/// Regressions for global and per-pair forwarding memory reservations.
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod datagram_budget_tests {
    use super::*;

    #[test]
    fn forwarded_datagrams_share_storage_and_hold_global_and_pair_budgets_until_released() {
        let global = Arc::new(QueueBudget::new(4));
        let first_host = Arc::new(QueueBudget::new(4));
        let second_host = Arc::new(QueueBudget::new(2));
        let third_host = Arc::new(QueueBudget::new(2));
        let first_pair = Arc::new(QueueBudget::new(2));
        let second_pair = Arc::new(QueueBudget::new(2));
        let third_pair = Arc::new(QueueBudget::new(2));
        let frame = || bytes::Bytes::from_static(&[0x5a; 900]);

        let first_frame = frame();
        let first_pointer = first_frame.as_ptr();
        let first = queue_forward_datagram(&global, &first_host, &first_pair, first_frame)
            .expect("first pair can reserve its queue budget");
        assert_eq!(
            first.as_ptr(),
            first_pointer,
            "the payload buffer is shared"
        );
        assert_eq!(global.queued_units.load(Ordering::Relaxed), 2);
        assert_eq!(first_pair.queued_units.load(Ordering::Relaxed), 2);
        assert!(queue_forward_datagram(&global, &first_host, &first_pair, frame()).is_none());

        let shared = first.clone();
        drop(first);
        assert_eq!(global.queued_units.load(Ordering::Relaxed), 2);
        assert_eq!(first_pair.queued_units.load(Ordering::Relaxed), 2);

        let second = queue_forward_datagram(&global, &second_host, &second_pair, frame())
            .expect("another pair can use the remaining global budget");
        assert_eq!(global.queued_units.load(Ordering::Relaxed), 4);
        assert!(queue_forward_datagram(&global, &third_host, &third_pair, frame()).is_none());
        assert_eq!(third_host.queued_units.load(Ordering::Relaxed), 0);

        drop(shared);
        assert_eq!(global.queued_units.load(Ordering::Relaxed), 2);
        assert_eq!(first_pair.queued_units.load(Ordering::Relaxed), 0);
        let third = queue_forward_datagram(&global, &third_host, &third_pair, frame())
            .expect("dropping the final shared buffer releases its reservation");
        assert_eq!(global.queued_units.load(Ordering::Relaxed), 4);

        drop((second, third));
        assert_eq!(global.queued_units.load(Ordering::Relaxed), 0);
        assert_eq!(second_pair.queued_units.load(Ordering::Relaxed), 0);
        assert_eq!(third_pair.queued_units.load(Ordering::Relaxed), 0);
        assert_eq!(first_host.queued_units.load(Ordering::Relaxed), 0);
        assert_eq!(second_host.queued_units.load(Ordering::Relaxed), 0);
        assert_eq!(third_host.queued_units.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn relinking_same_pair_keeps_its_cap_while_old_datagrams_remain_queued() {
        let pair = (HostId([1; 16]), HostId([2; 16]));
        let mut table = Table::default();
        let first = table.datagrams_for_pair(pair);
        let held = first
            .reserve(PAIR_FORWARD_QUEUE_UNITS - 1)
            .expect("first link can reserve all but one unit");
        table.retire_datagrams(pair, &first);
        drop(first);

        let relinked = table.datagrams_for_pair(pair);
        assert_eq!(
            relinked.queued_units.load(Ordering::Relaxed),
            PAIR_FORWARD_QUEUE_UNITS - 1
        );
        assert!(relinked.reserve(2).is_none());

        drop(held);
        assert_eq!(relinked.queued_units.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn one_host_cannot_exhaust_global_budget_across_256_backpressured_pairs() {
        let global = Arc::new(QueueBudget::new(GLOBAL_FORWARD_QUEUE_UNITS));
        let attacker = Arc::new(QueueBudget::new(HOST_FORWARD_QUEUE_UNITS));
        let pairs = (0..256)
            .map(|_| Arc::new(QueueBudget::new(PAIR_FORWARD_QUEUE_UNITS)))
            .collect::<Vec<_>>();
        let frame = || bytes::Bytes::from_static(&[0x5a; 1_400]);
        let mut held = Vec::new();

        loop {
            let mut queued_in_round = false;
            for pair in &pairs {
                if let Some(datagram) = queue_forward_datagram(&global, &attacker, pair, frame()) {
                    held.push(datagram);
                    queued_in_round = true;
                }
            }
            if !queued_in_round {
                break;
            }
        }

        assert_eq!(
            attacker.queued_units.load(Ordering::Relaxed),
            HOST_FORWARD_QUEUE_UNITS,
            "the source host should stop at its aggregate quota"
        );
        assert_eq!(
            global.queued_units.load(Ordering::Relaxed),
            HOST_FORWARD_QUEUE_UNITS,
            "all queue budgets must charge the same forwarded storage"
        );
        assert!(global.queued_units.load(Ordering::Relaxed) < GLOBAL_FORWARD_QUEUE_UNITS);
        let unrelated_host = Arc::new(QueueBudget::new(HOST_FORWARD_QUEUE_UNITS));
        let unrelated_pair = Arc::new(QueueBudget::new(PAIR_FORWARD_QUEUE_UNITS));
        assert!(
            queue_forward_datagram(&global, &unrelated_host, &unrelated_pair, frame()).is_some(),
            "one host holding 256 pairs consumed the budget for unrelated pairs"
        );
    }

    #[test]
    fn reconnecting_host_reuses_its_budget_while_old_datagrams_remain_queued() {
        let host = HostId([1; 16]);
        let mut table = Table::default();
        let first = table.datagrams_for_host(host);
        let held = first
            .reserve(HOST_FORWARD_QUEUE_UNITS - 1)
            .expect("first connection can reserve all but one unit");
        table.retire_host_datagrams(host, &first);
        drop(first);

        let reconnected = table.datagrams_for_host(host);
        assert_eq!(
            reconnected.queued_units.load(Ordering::Relaxed),
            HOST_FORWARD_QUEUE_UNITS - 1
        );
        assert!(reconnected.reserve(2).is_none());

        drop(held);
        assert_eq!(reconnected.queued_units.load(Ordering::Relaxed), 0);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod pre_auth_limit_tests {
    use super::*;

    #[test]
    fn pending_handshakes_are_bounded_globally_and_per_source_ip() {
        let limiter = PreAuthLimiter::new(2, 1);
        let first_ip = "192.0.2.1".parse().unwrap();
        let mapped_first_ip = "::ffff:192.0.2.1".parse().unwrap();
        let second_ip = "192.0.2.2".parse().unwrap();
        let third_ip = "192.0.2.3".parse().unwrap();

        let first = limiter
            .try_acquire(first_ip)
            .expect("first source is below both caps");
        assert!(limiter.try_acquire(first_ip).is_none());
        assert!(limiter.try_acquire(mapped_first_ip).is_none());
        let second = limiter
            .try_acquire(second_ip)
            .expect("another source may use the global capacity");
        assert!(limiter.try_acquire(third_ip).is_none());

        drop(first);
        let replacement = limiter
            .try_acquire(first_ip)
            .expect("dropping a permit releases its source and global slots");
        drop((second, replacement));
    }
}
