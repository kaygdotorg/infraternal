//! The relay service: forwards `WireGuard` ciphertext between linked hosts as QUIC DATAGRAMs [131,163,313].
//!
//! Any node with a server-purpose identity can run it (D313 Q3). It never holds
//! a mesh key: it sees only the 4-byte link id and opaque ciphertext. A link
//! forms only when both hosts asked for each other; the relay then hands both
//! the same id and forwards each frame unchanged to the other end, so
//! forwarding is one table read and one `send_datagram` with no copy.
//!
//! Everything is bounded: hosts, requests per host, the control writer queue
//! and the DATAGRAM buffers (see `tls`). A host that reconnects replaces its
//! previous connection; its links end and form again from the new requests.
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
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::sync::mpsc;

/// Resource bounds; every table and queue in the relay has one.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Connected hosts.
    pub hosts: usize,
    /// Outstanding link requests per host.
    pub requests_per_host: usize,
    /// Time allowed for the QUIC handshake and the control hello.
    pub handshake: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            hosts: 4_096,
            requests_per_host: 1_024,
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

struct Host {
    connection: quinn::Connection,
    notices: mpsc::Sender<Notice>,
    wants: HashSet<HostId>,
}

struct Link {
    ends: [(HostId, quinn::Connection); 2],
}

#[derive(Default)]
struct Table {
    hosts: HashMap<HostId, Host>,
    links: HashMap<LinkId, Link>,
    pairs: HashMap<(HostId, HostId), LinkId>,
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

    /// Remove the link between two hosts, telling each end that is still current.
    fn unlink(&mut self, a: HostId, b: HostId) {
        let Some(id) = self.pairs.remove(&pair(a, b)) else {
            return;
        };
        if let Some(link) = self.links.remove(&id) {
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
        let id = self.allocate();
        self.pairs.insert(pair(a, b), id);
        self.links.insert(id, Link { ends });
        if let Some(entry) = self.hosts.get(&a) {
            notify(entry, Notice::Linked { peer: b, id });
        }
        if let Some(entry) = self.hosts.get(&b) {
            notify(entry, Notice::Linked { peer: a, id });
        }
    }

    fn remove_host(&mut self, host: HostId) {
        if let Some(entry) = self.hosts.remove(&host) {
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
        table.hosts.insert(
            host,
            Host {
                connection: connection.clone(),
                notices,
                wants: HashSet::new(),
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
            let [(_, first), (_, second)] = &link.ends;
            if first.stable_id() == connection {
                Some(second)
            } else if second.stable_id() == connection {
                Some(first)
            } else {
                None
            }
        });
        // A frame for a link the sender is not part of, or one that ended,
        // is dropped: forwarding is never a way to reach an unlinked host.
        match target.map(|target| target.send_datagram(datagram)) {
            Some(Ok(())) => self.counters.forwarded.fetch_add(1, Ordering::Relaxed),
            _ => self.counters.dropped.fetch_add(1, Ordering::Relaxed),
        };
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
        tokio::spawn(serve(incoming, shared.clone()));
    }
}

async fn serve(incoming: quinn::Incoming, shared: Arc<Shared>) {
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
