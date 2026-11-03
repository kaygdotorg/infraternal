//! Relayed pairs through the userspace shim, and relay address observation, for seam C [163,185,313].
//!
//! Only pairs that cannot go direct come here. For each relayed peer the shim
//! binds one loopback UDP socket and points the selected data plane's endpoint
//! at it. The engine sends peer ciphertext to that socket; the shim prefixes
//! the relay link id and sends it as one QUIC DATAGRAM. Ciphertext arriving
//! from the relay is sent from the same socket to the engine's UDP port, so the
//! engine authenticates it. The shim never sees plaintext and never holds a
//! mesh key.
//!
//! Relay choice in this slice: every node gets the same ordered relay list.
//! A pair without a link asks every live relay; when links exist on several,
//! both ends keep the lowest-indexed one and withdraw the others. Both ends
//! see the same links (the relay announces a link to both at once), so they
//! settle on the same relay without talking to each other. A linked pair
//! stays where it is until that relay is lost, then asks every live relay
//! again; nothing moves back, so a recovering relay causes no switch.
//! Ranking by measured end-to-end RTT (D185) and the #201 selector replace
//! the static order in later slices.

use crate::{
    dataplane,
    seam::{Received, Seam},
    wireguard,
};
use bytes::{BufMut, BytesMut};
use infraternal_plugin_relay::{
    client::{Client, Notices},
    probe::{self, ProbeKey},
    quinn,
    tls::Credentials,
    wire::{self, HostId, LinkId, Notice},
};
use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle};

/// Largest `WireGuard` packet the shim reads: a mesh-MTU data packet is 1412.
const PACKET: usize = 1_500;
/// Reconnect backoff for a lost relay, doubling up to the maximum.
const BACKOFF: Duration = Duration::from_millis(250);
const BACKOFF_MAX: Duration = Duration::from_secs(5);
const BACKOFF_RECENT_MAX: Duration = Duration::from_millis(250);
const RECENT_HEALTH: Duration = Duration::from_secs(60);
const CONNECT: Duration = Duration::from_secs(5);
/// Avoid letting a failed handshake wait through QUIC's longer idle timeout during quick recovery.
const CONNECT_RECENT: Duration = Duration::from_millis(750);
/// How long a new link may still change before the session start (`settle`).
const SETTLE: Duration = Duration::from_millis(25);
/// Probe retransmissions after the first send (#220 design §2: 250/750 ms).
const PROBE_WAITS: [Duration; 3] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_millis(1_000),
];

/// Whether a pair cannot go direct after its endpoint-install grace period.
/// The kernel and caller timestamps share wall-clock time, so compare both
/// seconds and nanoseconds: an equal or older handshake cannot prove freshness,
/// while a later handshake (including one in the same second) proves the
/// direct path. One `WireGuard` handshake attempt is 5 s.
/// Hole punching (slice 3) and the #201 selector (slice 4) replace this with
/// proven candidates and measured paths; until then an unproven pair is
/// relayed.
#[must_use]
pub fn direct_failed(
    counters: Option<&wireguard::Counters>,
    endpoint_installed_at: SystemTime,
) -> bool {
    counters
        .and_then(|counters| {
            (counters.handshake_secs != 0).then(|| {
                UNIX_EPOCH.checked_add(Duration::new(
                    counters.handshake_secs,
                    counters.handshake_nanos,
                ))
            })
        })
        .flatten()
        .is_none_or(|handshake| handshake <= endpoint_installed_at)
}

/// One relay in the shared, ordered list.
#[derive(Clone, Debug)]
pub struct RelaySpec {
    pub address: SocketAddr,
    /// The DNS name in the relay's server-purpose certificate.
    pub name: String,
}

/// Path changes, reported in the order they happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    RelayUp {
        relay: usize,
    },
    RelayDown {
        relay: usize,
    },
    /// The relay a peer's packets now use; `None` while no relay links it.
    Active {
        peer: HostId,
        relay: Option<usize>,
    },
}

/// Data-path counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub sent: u64,
    pub received: u64,
    /// Kernel packets for a peer with no active link.
    pub unlinked: u64,
    /// Packets larger than the relay connection's current DATAGRAM size.
    pub too_large: u64,
}

#[derive(Default)]
struct Counters {
    sent: AtomicU64,
    received: AtomicU64,
    unlinked: AtomicU64,
    too_large: AtomicU64,
}

struct Live {
    client: Client,
    links: RwLock<HashMap<LinkId, HostId>>,
}

struct Peer {
    host: HostId,
    /// Starts a handshake through the engine that owns this peer.
    handshake_starter: Arc<dyn Fn() + Send + Sync>,
    socket: UdpSocket,
    /// A delayed session start is pending (see `settle`).
    starting: std::sync::atomic::AtomicBool,
    state: Mutex<PeerState>,
    active: RwLock<Option<(Arc<Live>, LinkId)>>,
}

#[derive(Default)]
struct PeerState {
    /// Per relay index: the link there, and whether a request is outstanding.
    links: Vec<Option<LinkId>>,
    requested: Vec<bool>,
    /// The relay index and link id the data path uses.
    active: Option<(usize, LinkId)>,
}

struct Shared {
    /// This node's host id; it decides which end of a pair starts a session.
    local: HostId,
    wg_port: u16,
    endpoint: quinn::Endpoint,
    config: quinn::ClientConfig,
    relays: Vec<RelaySpec>,
    live: Vec<RwLock<Option<Arc<Live>>>>,
    peers: RwLock<HashMap<HostId, Arc<Peer>>>,
    events: mpsc::Sender<Event>,
    counters: Counters,
}

fn read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The relayed pairs of one node, over an ordered list of relays.
pub struct RelayPaths {
    shared: Arc<Shared>,
    drivers: Vec<JoinHandle<()>>,
    shims: Mutex<HashMap<HostId, JoinHandle<()>>>,
}

/// Updates one configured peer endpoint while the relay shim owns its loopback socket.
pub trait EndpointUpdater {
    /// # Errors
    /// Reports a selected data-plane update failure.
    fn set_peer_endpoint(&mut self, peer: &dataplane::Peer, endpoint: SocketAddr)
    -> io::Result<()>;

    /// Return a callback that starts a handshake through the selected data plane.
    /// # Errors
    /// Reports a stopped or unavailable data plane.
    fn handshake_starter(
        &self,
        peer: &dataplane::Peer,
    ) -> io::Result<Arc<dyn Fn() + Send + Sync>>;
}

impl EndpointUpdater for wireguard::Client {
    fn set_peer_endpoint(
        &mut self,
        peer: &dataplane::Peer,
        endpoint: SocketAddr,
    ) -> io::Result<()> {
        self.endpoint(peer.key, endpoint)
    }

    fn handshake_starter(
        &self,
        peer: &dataplane::Peer,
    ) -> io::Result<Arc<dyn Fn() + Send + Sync>> {
        let peer = peer.clone();
        Ok(Arc::new(move || {
            let _ = start_kernel_handshake(&peer);
        }))
    }
}

impl EndpointUpdater for crate::node::Node {
    fn set_peer_endpoint(
        &mut self,
        peer: &dataplane::Peer,
        endpoint: SocketAddr,
    ) -> io::Result<()> {
        self.set_endpoint(peer.key, endpoint)
    }

    fn handshake_starter(
        &self,
        peer: &dataplane::Peer,
    ) -> io::Result<Arc<dyn Fn() + Send + Sync>> {
        self.relay_handshake_starter(peer)
    }
}

impl RelayPaths {
    /// Start connecting to every relay. Events go to `events`; a full queue drops them.
    /// # Errors
    /// Fails on an invalid identity or if no client socket can be bound.
    pub fn start(
        local: HostId,
        wg_port: u16,
        relays: Vec<RelaySpec>,
        credentials: Credentials,
        events: mpsc::Sender<Event>,
    ) -> io::Result<Self> {
        let config = infraternal_plugin_relay::tls::client_config(credentials)?;
        let endpoint = quinn::Endpoint::client((Ipv4Addr::UNSPECIFIED, 0).into())?;
        let shared = Arc::new(Shared {
            local,
            wg_port,
            endpoint,
            config,
            live: relays.iter().map(|_| RwLock::new(None)).collect(),
            relays,
            peers: RwLock::new(HashMap::new()),
            events,
            counters: Counters::default(),
        });
        let drivers = (0..shared.relays.len())
            .map(|index| tokio::spawn(drive(shared.clone(), index)))
            .collect();
        Ok(Self {
            shared,
            drivers,
            shims: Mutex::new(HashMap::new()),
        })
    }

    /// Relay `peer` through the legacy kernel data plane.
    /// # Errors
    /// Fails if the socket cannot be bound or the kernel refuses the endpoint.
    pub async fn relay(&self, peer: HostId, kernel: &dataplane::Peer) -> io::Result<SocketAddr> {
        let mut client = wireguard::Client::new()?;
        self.relay_with_endpoint(&mut client, peer, kernel).await
    }

    /// Relay `peer`: bind its shim socket, update the selected data plane's peer endpoint,
    /// and ask the live relays for a link. The ciphertext framing and relay protocol are unchanged.
    /// # Errors
    /// Fails if the socket cannot be bound or the selected data plane refuses the endpoint.
    pub async fn relay_with_endpoint(
        &self,
        endpoint_updater: &mut impl EndpointUpdater,
        peer: HostId,
        kernel: &dataplane::Peer,
    ) -> io::Result<SocketAddr> {
        if let Some(existing) = read(&self.shared.peers).get(&peer) {
            return existing.socket.local_addr();
        }
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        // Connected: only the selected engine's UDP socket can feed this shim.
        socket
            .connect((Ipv4Addr::LOCALHOST, self.shared.wg_port))
            .await?;
        let local = socket.local_addr()?;
        endpoint_updater.set_peer_endpoint(kernel, local)?;
        let relayed_peer = dataplane::Peer {
            endpoint: Some(local),
            ..kernel.clone()
        };
        let handshake_starter = endpoint_updater.handshake_starter(&relayed_peer)?;
        let relays = self.shared.relays.len();
        let shim = Arc::new(Peer {
            host: peer,
            handshake_starter,
            socket,
            starting: std::sync::atomic::AtomicBool::new(false),
            state: Mutex::new(PeerState {
                links: vec![None; relays],
                requested: vec![false; relays],
                active: None,
            }),
            active: RwLock::new(None),
        });
        write(&self.shared.peers).insert(peer, shim.clone());
        let task = tokio::spawn(outbound(self.shared.clone(), shim.clone()));
        lock(&self.shims).insert(peer, task);
        request_everywhere(&self.shared, &shim).await;
        Ok(local)
    }

    /// Stop relaying `peer`: withdraw its requests and close its shim socket.
    /// The caller installs whatever endpoint replaces the shim.
    pub async fn release(&self, peer: HostId) {
        let Some(shim) = write(&self.shared.peers).remove(&peer) else {
            return;
        };
        if let Some(task) = lock(&self.shims).remove(&peer) {
            task.abort();
        }
        let requested: Vec<usize> = {
            let state = lock(&shim.state);
            (0..self.shared.relays.len())
                .filter(|&index| state.requested[index] || state.links[index].is_some())
                .collect()
        };
        for index in requested {
            if let Some(live) = live(&self.shared, index) {
                let _ = live.client.unlink(peer).await;
            }
        }
    }

    /// The relay index a peer's packets use now.
    #[must_use]
    pub fn active(&self, peer: HostId) -> Option<usize> {
        read(&self.shared.peers)
            .get(&peer)
            .and_then(|shim| lock(&shim.state).active.map(|(index, _)| index))
    }

    /// Ask relay `index` which public address it sees for this node's
    /// `WireGuard` port, through `observer`.
    /// # Errors
    /// Fails if the relay is not connected, is not IPv4, or never answers.
    pub async fn observe(&self, observer: &Observer, index: usize) -> io::Result<SocketAddr> {
        let live = self
            .shared
            .live
            .get(index)
            .and_then(|slot| read(slot).clone())
            .ok_or(io::ErrorKind::NotConnected)?;
        let SocketAddr::V4(address) = self.shared.relays[index].address else {
            return Err(io::ErrorKind::Unsupported.into());
        };
        observer.observe(live.client.probe_key(), address).await
    }

    /// Data-path counters so far.
    #[must_use]
    pub fn stats(&self) -> Stats {
        let counters = &self.shared.counters;
        Stats {
            sent: counters.sent.load(Ordering::Relaxed),
            received: counters.received.load(Ordering::Relaxed),
            unlinked: counters.unlinked.load(Ordering::Relaxed),
            too_large: counters.too_large.load(Ordering::Relaxed),
        }
    }

    /// Stop every task and close every relay connection.
    pub async fn close(self) {
        for task in &self.drivers {
            task.abort();
        }
        for (_, task) in lock(&self.shims).drain() {
            task.abort();
        }
        for slot in &self.shared.live {
            if let Some(live) = write(slot).take() {
                live.client.close();
            }
        }
        let _ =
            tokio::time::timeout(Duration::from_secs(1), self.shared.endpoint.wait_idle()).await;
    }
}

impl Drop for RelayPaths {
    fn drop(&mut self) {
        for task in &self.drivers {
            task.abort();
        }
        for (_, task) in lock(&self.shims).drain() {
            task.abort();
        }
    }
}

/// The live connection of relay `index`, with no lock held afterwards.
fn live(shared: &Shared, index: usize) -> Option<Arc<Live>> {
    let slot = read(&shared.live[index]);
    slot.clone()
}

fn emit(shared: &Shared, event: Event) {
    let _ = shared.events.try_send(event);
}

/// Kernel ciphertext for one peer, out through its active link.
async fn outbound(shared: Arc<Shared>, peer: Arc<Peer>) {
    loop {
        if peer.socket.readable().await.is_err() {
            return;
        }
        let mut buffer = BytesMut::with_capacity(wire::HEADER + PACKET);
        buffer.put_u32(0);
        match peer.socket.try_recv_buf(&mut buffer) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            // A refused send from an earlier datagram surfaces here; keep going.
            Err(_) => continue,
        }
        let Some((live, id)) = read(&peer.active).clone() else {
            shared.counters.unlinked.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        buffer[..wire::HEADER].copy_from_slice(&id.0.to_be_bytes());
        match live.client.connection().send_datagram(buffer.freeze()) {
            Ok(()) => shared.counters.sent.fetch_add(1, Ordering::Relaxed),
            Err(quinn::SendDatagramError::TooLarge) => {
                shared.counters.too_large.fetch_add(1, Ordering::Relaxed)
            }
            Err(_) => shared.counters.unlinked.fetch_add(1, Ordering::Relaxed),
        };
    }
}

/// Relayed ciphertext from one relay connection, into the kernel.
async fn inbound(shared: Arc<Shared>, live: Arc<Live>) {
    while let Ok(datagram) = live.client.connection().read_datagram().await {
        let Some((id, payload)) = wire::split(&datagram) else {
            continue;
        };
        let Some(host) = read(&live.links).get(&id).copied() else {
            continue;
        };
        let Some(peer) = read(&shared.peers).get(&host).cloned() else {
            continue;
        };
        // A full loopback buffer drops the packet, as a congested path would.
        if peer.socket.try_send(payload).is_ok() {
            shared.counters.received.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Ask every live relay where this peer has no request yet, if it has no link.
async fn request_everywhere(shared: &Arc<Shared>, peer: &Arc<Peer>) {
    for index in 0..shared.relays.len() {
        let Some(live) = live(shared, index) else {
            continue;
        };
        let send = {
            let mut state = lock(&peer.state);
            let send = state.active.is_none() && !state.requested[index];
            if send {
                state.requested[index] = true;
            }
            send
        };
        if send {
            let _ = live.client.link(peer.host).await;
        }
    }
}

/// Keep the lowest-indexed link, withdraw the others, publish the choice.
async fn settle(shared: &Arc<Shared>, peer: &Arc<Peer>) {
    let (changed, withdraw) = {
        let mut state = lock(&peer.state);
        let active = state
            .links
            .iter()
            .enumerate()
            .find_map(|(index, link)| link.map(|id| (index, id)));
        let mut withdraw = Vec::new();
        for index in active.map_or(0, |(found, _)| found + 1)..state.links.len() {
            // Taking the link first marks the coming Unlinked notice as our own echo.
            if state.links[index].take().is_some() {
                state.requested[index] = false;
                withdraw.push(index);
            }
        }
        let changed = state.active != active;
        state.active = active;
        (changed.then_some(active), withdraw)
    };
    for index in withdraw {
        if let Some(live) = live(shared, index) {
            let _ = live.client.unlink(peer.host).await;
        }
    }
    let Some(active) = changed else {
        return;
    };
    let installed = active.and_then(|(index, id)| live(shared, index).map(|live| (live, id)));
    let linked = installed.is_some();
    *write(&peer.active) = installed;
    // Only the end with the lower host id starts the session: two
    // initiations crossing on the relay each replace the other's handshake
    // state, and both sides then wait out the retry. Start through the
    // selected engine only after the link exists, so the initiation is not
    // dropped before the relay is ready.
    if linked && shared.local < peer.host && !peer.starting.swap(true, Ordering::AcqRel) {
        let peer = peer.clone();
        let handshake_starter = peer.handshake_starter.clone();
        tokio::spawn(async move {
            tokio::time::sleep(SETTLE).await;
            peer.starting.store(false, Ordering::Release);
            if read(&peer.active).is_some() {
                let _ = tokio::task::spawn_blocking(move || handshake_starter()).await;
            }
        });
    }
    emit(
        shared,
        Event::Active {
            peer: peer.host,
            relay: active.map(|(index, _)| index),
        },
    );
    if active.is_none() {
        request_everywhere(shared, peer).await;
    }
}

/// Start a kernel-backed peer's first session through a new link (see `settle`).
/// A peer with an existing handshake is left alone so endpoint changes keep its session.
pub(crate) fn start_kernel_handshake(peer: &dataplane::Peer) -> io::Result<()> {
    let counters = wireguard::Device::counters()?;
    if counters
        .get(&peer.key)
        .is_some_and(|counters| counters.handshake_secs != 0)
    {
        return Ok(());
    }
    let mut client = wireguard::Client::new()?;
    client.peers(&[], &[peer.key])?;
    client.peers(std::slice::from_ref(peer), &[])
}

/// Keep one relay connected, apply its notices, and repair pairs when it goes.
async fn drive(shared: Arc<Shared>, index: usize) {
    let mut failures = 0_u32;
    let mut last_healthy = None;
    loop {
        let spec = &shared.relays[index];
        let recently_healthy =
            last_healthy.is_some_and(|healthy: Instant| healthy.elapsed() < RECENT_HEALTH);
        let connect_deadline = if recently_healthy {
            CONNECT_RECENT
        } else {
            CONNECT
        };
        if let Ok((client, notices)) = Client::connect(
            &shared.endpoint,
            shared.config.clone(),
            spec.address,
            &spec.name,
            connect_deadline,
        )
        .await
        {
            serve(&shared, index, client, notices).await;
            last_healthy = Some(Instant::now());
            failures = 0;
            continue;
        }
        failures = failures.saturating_add(1);
        let exponent = failures.saturating_sub(1).min(5);
        let backoff = (BACKOFF * 2_u32.pow(exponent)).min(if recently_healthy {
            BACKOFF_RECENT_MAX
        } else {
            BACKOFF_MAX
        });
        tokio::time::sleep(backoff).await;
    }
}

async fn serve(shared: &Arc<Shared>, index: usize, client: Client, mut notices: Notices) {
    let live = Arc::new(Live {
        client,
        links: RwLock::new(HashMap::new()),
    });
    *write(&shared.live[index]) = Some(live.clone());
    emit(shared, Event::RelayUp { relay: index });
    let reader = tokio::spawn(inbound(shared.clone(), live.clone()));
    let peers: Vec<Arc<Peer>> = read(&shared.peers).values().cloned().collect();
    for peer in &peers {
        request_everywhere(shared, peer).await;
    }
    while let Some(notice) = notices.next().await {
        let (host, link) = match notice {
            Notice::Linked { peer, id } => (peer, Some(id)),
            Notice::Unlinked { peer } => (peer, None),
        };
        let Some(peer) = read(&shared.peers).get(&host).cloned() else {
            // A link for a peer this node no longer relays: withdraw it.
            if link.is_some() {
                let _ = live.client.unlink(host).await;
            }
            continue;
        };
        {
            let mut links = write(&live.links);
            links.retain(|_, linked| *linked != host);
            if let Some(id) = link {
                links.insert(id, host);
            }
        }
        {
            let mut state = lock(&peer.state);
            if link.is_none() {
                // A link we still held ended from the peer's side, so our
                // request stays pending at the relay. A link we already
                // dropped is the echo of our own withdrawal: nothing pending.
                state.requested[index] = state.links[index].is_some();
            }
            state.links[index] = link;
        }
        settle(shared, &peer).await;
    }
    reader.abort();
    *write(&shared.live[index]) = None;
    emit(shared, Event::RelayDown { relay: index });
    let peers: Vec<Arc<Peer>> = read(&shared.peers).values().cloned().collect();
    for peer in &peers {
        {
            let mut state = lock(&peer.state);
            state.links[index] = None;
            state.requested[index] = false;
        }
        settle(shared, peer).await;
        request_everywhere(shared, peer).await;
    }
}

/// Dispatches tapped probe replies to the observation waiting for them.
pub struct Observer {
    seam: Arc<Seam>,
    waiting: Arc<Mutex<HashMap<[u8; 16], mpsc::Sender<Received>>>>,
    reader: JoinHandle<()>,
}

impl Observer {
    /// Take over `seam`'s receive side.
    #[must_use]
    pub fn new(seam: Seam) -> Self {
        let seam = Arc::new(seam);
        let waiting: Arc<Mutex<HashMap<[u8; 16], mpsc::Sender<Received>>>> = Arc::default();
        let reader = tokio::spawn({
            let seam = seam.clone();
            let waiting = waiting.clone();
            async move {
                while let Ok(received) = seam.recv().await {
                    if !probe::is_probe(&received.payload) {
                        continue;
                    }
                    let mut transaction = [0; 16];
                    transaction.copy_from_slice(&received.payload[16..32]);
                    // The id is not authenticated yet: the waiter checks the tag
                    // and keeps waiting after a forgery.
                    if let Some(waiter) = lock(&waiting).get(&transaction) {
                        let _ = waiter.try_send(received);
                    }
                }
            }
        });
        Self {
            seam,
            waiting,
            reader,
        }
    }

    /// Packets the seam's filter passed to userspace so far.
    #[must_use]
    pub fn delivered(&self) -> u64 {
        self.seam.delivered()
    }

    /// Probe `relay` from the `WireGuard` port and return the source it saw.
    /// # Errors
    /// Fails if sending fails or no valid reply arrives after the retries.
    pub async fn observe(&self, key: &ProbeKey, relay: SocketAddrV4) -> io::Result<SocketAddr> {
        let transaction = probe::transaction()?;
        let (sender, mut replies) = mpsc::channel(4);
        lock(&self.waiting).insert(transaction, sender);
        let request = key.request(transaction);
        let mut result = Err(io::ErrorKind::TimedOut.into());
        'attempts: for wait in PROBE_WAITS {
            if let Err(error) = self.seam.send(relay, &request) {
                result = Err(error);
                break;
            }
            let deadline = tokio::time::Instant::now() + wait;
            while let Ok(Some(reply)) = tokio::time::timeout_at(deadline, replies.recv()).await {
                if reply.source != relay {
                    continue;
                }
                if let Some((echoed, observed)) = key.reply(&reply.payload)
                    && echoed == transaction
                {
                    result = Ok(observed);
                    break 'attempts;
                }
            }
        }
        lock(&self.waiting).remove(&transaction);
        result
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

#[cfg(test)]
mod tests {
    //! The slice-1 relay trigger; the data path itself runs in the namespace proof.
    use super::direct_failed;
    use crate::wireguard::Counters;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn timestamp(seconds: u64, nanoseconds: u32) -> SystemTime {
        UNIX_EPOCH + Duration::new(seconds, nanoseconds)
    }

    #[test]
    fn a_pair_is_relayed_only_without_a_handshake_since_its_endpoint() {
        let since = 1_800_000_000;
        let installed_at = timestamp(since, 500_000_000);
        assert!(direct_failed(None, installed_at), "unknown peer");
        let never = Counters::default();
        assert!(direct_failed(Some(&never), installed_at));
        let stale = Counters {
            handshake_secs: since - 1,
            ..Counters::default()
        };
        assert!(
            direct_failed(Some(&stale), installed_at),
            "a handshake before the endpoint"
        );
        for fresh in [since + 1, since + 3] {
            let counters = Counters {
                handshake_secs: fresh,
                ..Counters::default()
            };
            assert!(!direct_failed(Some(&counters), installed_at));
        }
    }

    #[test]
    fn a_same_second_handshake_cannot_prove_it_followed_the_endpoint_update() {
        let since = 1_800_000_000;
        // The endpoint can be installed later in the same second than the
        // previous handshake. Compare the kernel's nanoseconds to the precise
        // install time rather than treating every equal second as ambiguous.
        let before_endpoint_in_same_second = Counters {
            handshake_secs: since,
            handshake_nanos: 100_000_000,
            ..Counters::default()
        };
        assert!(
            direct_failed(
                Some(&before_endpoint_in_same_second),
                timestamp(since, 500_000_000),
            ),
            "an ambiguous same-second handshake must not suppress relay fallback"
        );
    }

    #[test]
    fn a_fresh_same_second_handshake_keeps_the_direct_path() {
        let since = 1_800_000_000;
        let after_endpoint_install = Counters {
            handshake_secs: since,
            handshake_nanos: 800_000_000,
            ..Counters::default()
        };
        assert!(
            !direct_failed(Some(&after_endpoint_install), timestamp(since, 200_000_000),),
            "a handshake later in the install second proves the direct path"
        );
    }

    #[test]
    fn a_handshake_equal_to_the_endpoint_install_time_is_not_fresh() {
        let installed_at = timestamp(1_800_000_000, 500_000_000);
        let counters = Counters {
            handshake_secs: 1_800_000_000,
            handshake_nanos: 500_000_000,
            ..Counters::default()
        };
        assert!(
            direct_failed(Some(&counters), installed_at),
            "equal timestamps do not establish ordering"
        );
    }
}
