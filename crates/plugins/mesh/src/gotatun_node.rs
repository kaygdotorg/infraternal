//! Linux userspace mesh engine using the `GotaTun` device API and an owned TUN.
//!
//! ## The engine bounds its own queue (D397)
//!
//! A TUN device hides the engine's queue from the kernel's TCP Small Queues, so without a bound
//! a loaded flow parks its whole congestion window inside the engine and every other packet on
//! the link waits behind it. The pinned `GotaTun` therefore runs a `CoDel` controller on its Linux
//! receive path: it measures each packet's time from the kernel's UDP receive stamp to the TUN
//! write and, once that stays above 1 ms for 10 ms, marks ECN-capable packets CE and drops only
//! packets of queue-heavy flows that can't be marked. Light flows (probes, keystrokes, DNS, pure
//! ACKs) are exempt. On backup01 this took cubic 8-flow loaded p99 from 22.4 ms to about 6 ms
//! (#260, J711 and J747).
//!
//! It is on by default. The one thing it needs from this crate: the socket wrapper in front of
//! `GotaTun` (`PeerAdmissionUdpReceiver`) must hand each packet's receive stamp on with the
//! packet, or the bound sees no stamps and never acts. For diagnosis, `GOTATUN_AQM=off` in
//! the infraternal agent's environment turns it off (read once when the engine starts);
//! `GOTATUN_AQM=drop` drops instead of marking. See `docs/user/40-mesh/index.md`.

use gotatun::{
    device::{Device as WireGuardDevice, DeviceBuilder, Peer as WireGuardPeer},
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    udp::{
        UdpTransportFactory, UdpTransportFactoryParams,
        socket::{UdpSocket as GotaUdpSocket, UdpSocketFactory},
    },
    x25519::{PublicKey as X25519PublicKey, StaticSecret},
};
use ipnetwork::IpNetwork;
use nix::sys::prctl::{get_thp_disable, set_thp_disable};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        mpsc as sync,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    runtime::Builder as RuntimeBuilder,
    sync::{
        Notify, RwLock,
        mpsc::{self, UnboundedReceiver, UnboundedSender},
    },
    task::JoinSet,
    time::Instant,
};

use crate::handshake_admission::{ConfirmedEndpointFeed, PeerAdmission, PeerAdmissionUdpReceiver};
use crate::listen_port::Request as ListenPortRequest;
use crate::{
    dataplane::Config,
    gotatun_tun::LinuxTun,
    packet_filter::{Direction, PacketFilter, PreparedPolicy},
    policy::model::PublicKey,
};
use infraternal_mesh::proxy_ports::MeshProxyIngress;

type GotaDevice = WireGuardDevice<(BoundUdpFactory, LinuxPacketIo, LinuxPacketIo)>;
type CounterMap = BTreeMap<PublicKey, crate::wireguard::Counters>;

/// Refresh Linux host-route budgets from live authenticated `GotaTun` endpoints.
pub(crate) type RouteEndpointUpdater =
    Arc<dyn Fn(&[(PublicKey, Option<SocketAddr>)]) -> io::Result<()> + Send + Sync>;

/// Coalesces traffic and authenticated-endpoint notifications into bounded route refreshes.
///
/// Packets in either direction request a refresh: an inbound packet may have taught `GotaTun` a
/// new endpoint, and an outbound one is about to use a route whose underlay MTU may have changed
/// since the last refresh (#489 J549 P1). A peer that only receives from this host, with a stable
/// endpoint, would otherwise keep an oversized route budget and black-hole bulk transfers.
///
/// The packet path pays one relaxed load while a refresh is already queued, and one swap plus a
/// wakeup otherwise; it never allocates. The worker clears `pending` before it reads endpoints
/// and route MTUs, so traffic that arrives during that read queues exactly one more refresh.
#[derive(Default)]
pub(crate) struct EndpointRefreshSignal {
    /// Set from the first request until the worker starts the refresh that will observe it.
    pending: AtomicBool,
    notify: Notify,
}

impl EndpointRefreshSignal {
    /// Tell the `GotaTun` worker that a packet crossed the mesh link, in either direction.
    ///
    /// Call it after the packet is handed on. It is cheap enough for every packet.
    pub(crate) fn traffic(&self) {
        // A queued refresh will read state after this packet, so it already covers it.
        if self.pending.load(Ordering::Relaxed) {
            return;
        }
        self.request_refresh();
    }

    /// Tell the worker that its authenticated endpoint snapshot changed.
    pub(crate) fn endpoint_changed(&self) {
        self.request_refresh();
    }

    /// Queue one refresh unless one is already queued.
    fn request_refresh(&self) {
        if !self.pending.swap(true, Ordering::AcqRel) {
            self.notify.notify_one();
        }
    }

    /// Wait for the next coalesced refresh request.
    async fn notified(&self) {
        self.notify.notified().await;
    }

    /// Re-arm the signal right before the worker reads endpoints and route MTUs.
    ///
    /// A request after this point is not covered by the read that follows, so it must queue
    /// another refresh; clearing the flag first guarantees that it does.
    fn begin_refresh(&self) {
        self.pending.store(false, Ordering::Release);
    }
}

/// Wait for a scheduled route refresh, or stay asleep until traffic requests one.
async fn endpoint_refresh_due(at: Option<tokio::time::Instant>) {
    if let Some(at) = at {
        tokio::time::sleep_until(at).await;
    } else {
        std::future::pending::<()>().await;
    }
}

/// Coalesce closely spaced packet deliveries before reading all live peer endpoints.
const ENDPOINT_REFRESH_DEBOUNCE: Duration = Duration::from_millis(25);
/// Bound route refreshes and authenticated endpoint scans to four per second.
const ENDPOINT_REFRESH_MIN_INTERVAL: Duration = Duration::from_millis(250);

/// How long a forced relay handshake may wait; `GotaTun`'s own wait has no deadline.
/// One `WireGuard` handshake attempt is 5 s, after which the peer timers retry.
#[cfg(feature = "relay")]
const HANDSHAKE_WAIT: Duration = Duration::from_secs(5);

/// Selects the node's data plane. `GotaTun` is the Linux default (D346), so the product runs on
/// it and its bugs surface; kernel `WireGuard` stays an explicit per-machine opt-out. Reaching
/// kernel throughput and loss-aware latency is still the goal (D331, D332), not a gate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineKind {
    #[default]
    GotaTun,
    Kernel,
}

/// Why a node runs its engine, shown by `mesh status` (D346).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineReason {
    /// Nothing was chosen on this machine.
    #[default]
    Default,
    /// The machine's `INFRATERNAL_MESH_ENGINE` names the engine.
    Chosen,
}

/// The engine a node runs and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineSelection {
    pub engine: EngineKind,
    pub reason: EngineReason,
}

impl EngineKind {
    /// Parse the per-node `INFRATERNAL_MESH_ENGINE` override.
    /// # Errors
    /// Refuses unknown values instead of silently selecting a different engine.
    pub fn parse(value: Option<&str>) -> io::Result<Self> {
        match value {
            None => Ok(Self::default()),
            Some("gotatun") => Ok(Self::GotaTun),
            Some("kernel") => Ok(Self::Kernel),
            Some(_) => Err(io::ErrorKind::InvalidInput.into()),
        }
    }

    /// Read the optional per-node transition override.
    /// # Errors
    /// Refuses non-UTF8 and unknown values rather than silently choosing an engine.
    pub fn from_environment() -> io::Result<Option<Self>> {
        let Some(value) = std::env::var_os("INFRATERNAL_MESH_ENGINE") else {
            return Ok(None);
        };
        let value = value.to_str().ok_or(io::ErrorKind::InvalidInput)?;
        Self::parse(Some(value)).map(Some)
    }
}

/// Holds the already-bound UDP sockets and live peer-admission state for `GotaTun`.
///
/// Clones share the listener and admission guard so a device restart keeps its actual port and
/// uses the latest accepted peer snapshot.
#[derive(Clone)]
struct BoundUdpFactory {
    send: GotaUdpSocket,
    receive: GotaUdpSocket,
    port: u16,
    admission: Arc<RwLock<PeerAdmission>>,
}

impl UdpTransportFactory for BoundUdpFactory {
    type Send = GotaUdpSocket;
    type Recv = PeerAdmissionUdpReceiver;

    // The trait returns a future; these sockets are already bound, so complete it immediately.
    fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> impl std::future::Future<Output = io::Result<(Self::Send, Self::Recv)>> + Send {
        if params.addr.is_some() || params.port != self.port {
            return std::future::ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        std::future::ready(Ok((
            self.send.clone(),
            PeerAdmissionUdpReceiver::new(self.receive.clone(), Arc::clone(&self.admission)),
        )))
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeInfo {
    interface: String,
    port: u16,
    thp_disabled: bool,
    offloads_enabled: bool,
}

/// Commands serialized by the Linux `GotaTun` worker; each request has a synchronous result channel.
enum WorkerCommand {
    Apply {
        /// Keeps the larger snapshot out of the enum's inline command payload.
        config: Box<Config>,
        reply: sync::SyncSender<io::Result<RuntimeInfo>>,
    },
    SetMtu {
        mtu: u16,
        reply: sync::SyncSender<io::Result<()>>,
    },
    SetPrivateKey {
        private_key: StaticSecret,
        reply: sync::SyncSender<io::Result<()>>,
    },
    Counters(sync::SyncSender<io::Result<CounterMap>>),
    #[cfg(feature = "relay")]
    PrepareHandshake {
        key: PublicKey,
        endpoint: SocketAddr,
        reply: sync::SyncSender<io::Result<()>>,
    },
    #[cfg(feature = "relay")]
    ForceHandshake {
        key: PublicKey,
        endpoint: SocketAddr,
        reply: sync::SyncSender<io::Result<()>>,
    },
    Stop(sync::SyncSender<()>),
}

/// Synchronous handle to the dedicated `GotaTun` runtime thread.
pub(crate) struct Engine {
    commands: UnboundedSender<WorkerCommand>,
    join: Option<JoinHandle<()>>,
    info: RuntimeInfo,
    health: Arc<Health>,
    filter: Arc<PacketFilter>,
}

/// How long a stopped engine waits before it is rebuilt. A cause that persists, such as a deleted
/// TUN, then costs one rebuild a second instead of a busy loop.
const RESTART_DELAY: Duration = Duration::from_secs(1);

/// Engine health shared between the worker and `mesh status`.
#[derive(Default)]
struct Health {
    /// Times the worker rebuilt the device after a fatal error.
    restarts: AtomicU64,
    /// The device stopped on a fatal error and is not rebuilt yet.
    stopped: AtomicBool,
    /// Outbound frames the TUN adapter could not decode and dropped.
    refused: Arc<AtomicU64>,
    /// The TUN's transmit queue length after start, in packets; 0 when unreadable.
    tx_queue_len: AtomicU32,
}

impl Health {
    fn snapshot(&self) -> EngineHealth {
        EngineHealth {
            stopped: self.stopped.load(Ordering::Relaxed),
            restarts: self.restarts.load(Ordering::Relaxed),
            refused_frames: self.refused.load(Ordering::Relaxed),
            tx_queue_len: Some(self.tx_queue_len.load(Ordering::Relaxed)),
        }
    }
}

/// The public view of [`Health`], reported by `mesh status` for the `GotaTun` engine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineHealth {
    pub stopped: bool,
    pub restarts: u64,
    pub refused_frames: u64,
    /// The TUN transmit queue in packets: below [`TUN_TX_QUEUE_LEN`] when the agent could not
    /// raise it, 0 when it could not read it. `None` from an agent that does not report it.
    #[serde(default)]
    pub tx_queue_len: Option<u32>,
}

/// The TUN transmit queue the engine needs, in packets. `GotaTun` raises it only on a TUN it
/// creates itself; this engine's adapter creates the TUN, so the agent raises it (#260 J88e:
/// with 1,024 the 1 h soak lost no probe and ring drops fell from 1.14 M to 304).
pub const TUN_TX_QUEUE_LEN: u32 = 1024;

impl Engine {
    /// Start `GotaTun` with the fork's Linux TUN adapter and offload handling.
    /// The worker thread disables THP before constructing the runtime or engine state.
    /// `route_endpoint_updater` applies authenticated endpoint budgets only to routes the node
    /// owns. TUN deliveries and the bounded peer snapshot scan can request a refresh.
    ///
    /// The TUN is persistent (D332): it outlives this process, as a kernel `WireGuard` link does,
    /// so the addresses, the routes a person added and open flows survive an infraternal agent
    /// restart. `adopt` names the live link that the caller proved is this installation's
    /// (`Node::restore`); it is reattached only while it still has that index and owner. With no
    /// `adopt`, any marked link refuses the start. A new TUN becomes persistent only once it is
    /// marked and the engine is up, so a failed start leaves no interface behind.
    /// # Errors
    /// Reports TUN registration, UDP bind, runtime or device initialization failures, and
    /// `AlreadyExists` for a link this start may not take, including one another process holds.
    pub(crate) fn start(
        private_key: StaticSecret,
        local_public_key: PublicKey,
        requested_port: ListenPortRequest,
        config: Option<Config>,
        proxy_ingress: &MeshProxyIngress,
        adopt: Option<u32>,
        route_endpoint_updater: RouteEndpointUpdater,
    ) -> io::Result<Self> {
        crate::packet_filter::warn_about_sysctl_gaps();
        let filter = Arc::new(match config.as_ref() {
            Some(config) => PacketFilter::new(config, proxy_ingress.clone())?,
            None => PacketFilter::empty(),
        });
        let worker_filter = Arc::clone(&filter);
        let (info_tx, info_rx) = sync::sync_channel(1);
        let (commands, receiver) = mpsc::unbounded_channel();
        let health = Arc::new(Health::default());
        let worker_health = Arc::clone(&health);
        let refused = Arc::clone(&health.refused);
        let endpoint_refresh = Arc::new(EndpointRefreshSignal::default());
        let initialize_refresh = Arc::clone(&endpoint_refresh);
        let worker_refresh = Arc::clone(&endpoint_refresh);
        let join = thread::Builder::new()
            .name("infraternal-mesh-gotatun".to_owned())
            .spawn(move || {
                let (runtime, thp_disabled) = match engine_runtime() {
                    Ok(setup) => setup,
                    Err(error) => {
                        let _ = info_tx.send(Err(error));
                        return;
                    }
                };
                let initialized = runtime.block_on(initialize(
                    private_key,
                    local_public_key,
                    requested_port,
                    config.as_ref(),
                    worker_filter,
                    refused,
                    thp_disabled,
                    adopt,
                    initialize_refresh,
                ));
                let Started {
                    tx_queue_len,
                    tun,
                    device,
                    pending,
                    info,
                } = match initialized {
                    Ok(initialized) => initialized,
                    Err(error) => {
                        let _ = info_tx.send(Err(error));
                        return;
                    }
                };
                worker_health
                    .tx_queue_len
                    .store(tx_queue_len, Ordering::Relaxed);
                if info_tx.send(Ok(info.clone())).is_err() {
                    if let Some(device) = device.and_then(Arc::into_inner) {
                        runtime.block_on(device.stop());
                    }
                    return;
                }
                let state = RuntimeState {
                    tun: Some(tun),
                    device,
                    handshakes: JoinSet::new(),
                    pending,
                    config,
                    info,
                    health: worker_health,
                    restart_at: None,
                };
                runtime.block_on(run_worker(
                    receiver,
                    state,
                    worker_refresh,
                    route_endpoint_updater,
                ));
            })?;
        let info = match info_rx.recv().map_err(|_| io::ErrorKind::BrokenPipe)? {
            Ok(info) => info,
            Err(error) => {
                let _ = join.join();
                return Err(error);
            }
        };
        Ok(Self {
            commands,
            join: Some(join),
            info,
            health,
            filter,
        })
    }

    /// Whether the engine is running, how often it was rebuilt, and what it dropped.
    #[must_use]
    pub(crate) fn health(&self) -> EngineHealth {
        self.health.snapshot()
    }

    /// The assigned TUN name, bound UDP port and THP state of the worker thread.
    #[must_use]
    pub(crate) fn info(&self) -> (&str, u16, bool, bool) {
        (
            &self.info.interface,
            self.info.port,
            self.info.thp_disabled,
            self.info.offloads_enabled,
        )
    }

    /// Apply a complete coordinator snapshot while retaining established peer sessions.
    /// # Errors
    /// Reports a stopped worker or peer update failure.
    pub(crate) fn apply(&self, config: Config) -> io::Result<RuntimeInfo> {
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::Apply {
                config: Box::new(config),
                reply,
            })
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        result.recv().map_err(|_| io::ErrorKind::BrokenPipe)?
    }

    /// Compile a new snapshot before changing the firewall or accepted node state.
    /// # Errors
    /// Refuses duplicate peer addresses or an unindexable policy snapshot.
    pub(crate) fn prepare_policy(
        config: &Config,
        proxy_ingress: MeshProxyIngress,
    ) -> io::Result<PreparedPolicy> {
        PacketFilter::prepare_policy(config, proxy_ingress)
    }

    /// Publish a previously compiled snapshot with one lock swap.
    pub(crate) fn publish_policy(&self, policy: PreparedPolicy) {
        self.filter.publish_policy(policy);
    }

    /// Test seam (#265 J618): judge one packet with the live filter, exactly as the packet
    /// path would, so a namespace test can see which grants are published right now.
    #[cfg(feature = "test-support")]
    pub(crate) fn check_packet(&self, packet: &mut [u8], direction: Direction) -> bool {
        self.filter.check(packet, direction)
    }

    /// Stop admitting the listed peers' addresses before the peer set changes; see
    /// [`PacketFilter::withdraw_peers`].
    pub(crate) fn withdraw_peers(
        &self,
        withdrawn: &std::collections::BTreeSet<crate::policy::model::NodeId>,
    ) {
        self.filter.withdraw_peers(withdrawn);
    }

    /// Set the mesh MTU on the worker that owns the TUN and its packet-size watcher.
    /// # Errors
    /// Reports a stopped worker or a link update failure.
    pub(crate) fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::SetMtu { mtu, reply })
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        result.recv().map_err(|_| io::ErrorKind::BrokenPipe)?
    }

    /// Switch the userspace device and its rebuild key to one journaled rotation identity.
    /// # Errors
    /// Reports a stopped worker or a failed device reconfiguration.
    pub(crate) fn set_private_key(&self, private_key: StaticSecret) -> io::Result<()> {
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::SetPrivateKey { private_key, reply })
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        result.recv().map_err(|_| io::ErrorKind::BrokenPipe)?
    }

    /// Read the current `GotaTun` peer counters.
    /// # Errors
    /// Reports a stopped worker or device read error.
    pub(crate) fn counters(&self) -> io::Result<CounterMap> {
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::Counters(reply))
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        result.recv().map_err(|_| io::ErrorKind::BrokenPipe)?
    }

    /// Return a relay callback that forces the selected `GotaTun` peer to start a handshake.
    #[cfg(feature = "relay")]
    pub(crate) fn handshake_starter(
        &self,
        key: PublicKey,
        endpoint: SocketAddr,
    ) -> Arc<dyn Fn() + Send + Sync> {
        let commands = self.commands.clone();
        Arc::new(move || {
            let (reply, result) = sync::sync_channel(1);
            if commands
                .send(WorkerCommand::ForceHandshake {
                    key,
                    endpoint,
                    reply,
                })
                .is_ok()
            {
                let _ = result.recv();
            }
        })
    }

    /// Return a relay callback that clears an incomplete peer handshake without initiating one.
    #[cfg(feature = "relay")]
    pub(crate) fn handshake_preparer(
        &self,
        key: PublicKey,
        endpoint: SocketAddr,
    ) -> Arc<dyn Fn() -> io::Result<()> + Send + Sync> {
        let commands = self.commands.clone();
        Arc::new(move || {
            let (reply, result) = sync::sync_channel(1);
            commands
                .send(WorkerCommand::PrepareHandshake {
                    key,
                    endpoint,
                    reply,
                })
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            result.recv().map_err(|_| io::ErrorKind::BrokenPipe)?
        })
    }

    /// Stop the `WireGuard` engine and join its runtime thread.
    /// # Errors
    /// Reports a worker shutdown failure.
    pub(crate) fn stop(&mut self) -> io::Result<()> {
        if let Some(join) = self.join.take() {
            let (reply, result) = sync::sync_channel(1);
            self.commands
                .send(WorkerCommand::Stop(reply))
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            result.recv().map_err(|_| io::ErrorKind::BrokenPipe)?;
            join.join().map_err(|_| io::ErrorKind::Other)?;
        }
        Ok(())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// What a successful start hands to the worker loop.
struct Started {
    tx_queue_len: u32,
    tun: LinuxPacketIo,
    device: Option<Arc<GotaDevice>>,
    pending: Option<PendingDevice>,
    info: RuntimeInfo,
}

/// Open and activate the TUN, bind the engine socket, and build the device when the startup
/// config already has peers. New TUNs get a marker here; adopted TUNs were re-proven by index.
/// Runs on the engine's runtime, which also runs the TUN writer.
async fn initialize(
    private_key: StaticSecret,
    local_public_key: PublicKey,
    requested_port: ListenPortRequest,
    config: Option<&Config>,
    filter: Arc<PacketFilter>,
    refused: Arc<AtomicU64>,
    thp_disabled: bool,
    adopt: Option<u32>,
    endpoint_refresh: Arc<EndpointRefreshSignal>,
) -> io::Result<Started> {
    let ours = |link: Option<crate::wireguard::ActiveLink>| {
        adopt.is_some()
            && link.is_some_and(|link| {
                link.engine == EngineKind::GotaTun
                    && Some(link.ifindex) == adopt
                    && link.owner == Some(local_public_key)
            })
    };
    let before = crate::wireguard::Device::active_link()?;
    if before.is_some() && !ours(before) {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    // Keep a fresh TUN large enough for Linux to install its IPv6 address. The first coordinator
    // snapshot applies the smaller route-derived MTU after Node::apply has installed addresses.
    let mtu = crate::mesh_mtu::for_config(config).max(crate::mesh_mtu::IPV6_MINIMUM_MTU);
    // A persistent TUN another process holds refuses this attach with EBUSY.
    let tun = LinuxTun::create(
        crate::wireguard::INTERFACE,
        mtu,
        local_public_key,
        refused,
        endpoint_refresh,
    )
    .map_err(|error| match error.raw_os_error() {
        Some(code) if code == nix::libc::EBUSY => io::Error::from(io::ErrorKind::AlreadyExists),
        _ => error,
    })?;
    // The check above and the attach are two steps: confirm the attached link is still the
    // proven one, or a fresh one under this name.
    let attached = crate::wireguard::Device::active_link();
    let fresh = adopt.is_none()
        && attached
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::AlreadyExists);
    if !fresh && !attached.is_ok_and(ours) {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    let interface = tun.name().to_owned();
    if interface != crate::wireguard::INTERFACE {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let offloads_enabled = tun.offloads_enabled();
    if !offloads_enabled {
        return Err(io::Error::other(
            "Linux TUN checksum and TCP segmentation offloads are unavailable.",
        ));
    }
    if adopt.is_none() {
        crate::wireguard::Device::mark_tun(local_public_key)?;
    }
    crate::wireguard::Device::activate_tun(tun.owned_ifindex()?, mtu)?;
    // Raised on a new and on a reattached TUN alike. A refusal does not stop the engine: the
    // length it really has goes to `mesh status`.
    let tx_queue_len = crate::wireguard::Device::raise_tx_queue_len(TUN_TX_QUEUE_LEN)
        .or_else(|_| crate::wireguard::Device::tx_queue_len())
        .unwrap_or(0);
    let tun = LinuxPacketIo::new(tun, filter);
    let (factory, port) = bind_udp(requested_port, private_key.clone()).await?;
    let peers = config
        .map(peers_for_config)
        .transpose()?
        .unwrap_or_default();
    let admitted_peers = config.map(admitted_peer_keys).unwrap_or_default();
    // GotaTun starts its packet workers only when the builder has peers.
    // Node::up precedes the coordinator's first snapshot, so the bound
    // transport and key wait for that first nonempty peer set; they also stay
    // for rebuilding a device that stops on a fatal error.
    let device = if peers.is_empty() {
        None
    } else {
        Some(Arc::new(
            build_device(
                factory.clone(),
                private_key.clone(),
                port,
                peers,
                admitted_peers,
                tun.clone(),
            )
            .await?,
        ))
    };
    let pending = Some(PendingDevice {
        factory,
        private_key,
    });
    let info = RuntimeInfo {
        interface,
        port,
        thp_disabled,
        offloads_enabled,
    };
    // Marked and running: from here the interface outlives this process (D332).
    tun.tun.persist()?;
    Ok(Started {
        tx_queue_len,
        tun,
        device,
        pending,
        info,
    })
}

/// Most worker threads the engine runtime uses. `GotaTun` runs UDP receive and decryption, TUN
/// reads, TUN writes, and encryption as separate tasks joined by channels; on one thread those
/// hand-offs only add work (#260 R4b). The bound keeps a large host from giving the mesh every
/// core.
const ENGINE_WORKERS_MAX: usize = 4;

fn engine_runtime() -> io::Result<(tokio::runtime::Runtime, bool)> {
    // Transparent huge pages are disabled for the whole process before any engine thread or
    // buffer exists.
    set_thp_disable(true).map_err(io::Error::from)?;
    let thp_disabled = get_thp_disable().map_err(io::Error::from)?;
    if !thp_disabled {
        return Err(io::ErrorKind::Unsupported.into());
    }
    let workers = thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(ENGINE_WORKERS_MAX);
    let runtime = RuntimeBuilder::new_multi_thread()
        .worker_threads(workers)
        .thread_name("infraternal-mesh-gotatun")
        .enable_all()
        .build()?;
    Ok((runtime, thp_disabled))
}

struct RuntimeState {
    tun: Option<LinuxPacketIo>,
    /// Shared only with forced-handshake tasks, which `stop` ends before stopping the device.
    /// Device operations take `GotaTun`'s own lock briefly; no command waits on a session.
    device: Option<Arc<GotaDevice>>,
    handshakes: JoinSet<()>,
    /// Kept for the worker's life: a device that stopped on a fatal error is rebuilt from it.
    /// The live device holds its own copy of the key; `stop` drops this one (zeroized on drop).
    pending: Option<PendingDevice>,
    config: Option<Config>,
    info: RuntimeInfo,
    health: Arc<Health>,
    /// When a device that stopped on a fatal error is rebuilt.
    restart_at: Option<Instant>,
}

struct PendingDevice {
    factory: BoundUdpFactory,
    private_key: StaticSecret,
}

/// Wait for the device's fatal error. `GotaTun` reports it only through `wait(&mut self)`, so this
/// waits only while no handshake task shares the device. An error raised in the meantime is
/// still seen afterwards: `wait` returns at once for an error that is already set.
async fn fatal_error(device: Option<&mut Arc<GotaDevice>>) {
    match device.and_then(Arc::get_mut) {
        Some(device) => device.wait().await,
        None => std::future::pending().await,
    }
}

async fn restart_due(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Serializes device, relay, endpoint-refresh, health-recovery, and shutdown work on the worker.
///
/// A bounded peer snapshot scan detects control-only authenticated roaming, while TUN traffic in
/// either direction requests re-derivation after underlay changes. Both use one coalesced signal, and route-netlink
/// writes run on Tokio's blocking pool.
async fn run_worker(
    mut commands: UnboundedReceiver<WorkerCommand>,
    mut state: RuntimeState,
    endpoint_refresh: Arc<EndpointRefreshSignal>,
    route_endpoint_updater: RouteEndpointUpdater,
) {
    let mut endpoint_refresh_at = None;
    let mut last_endpoint_refresh = None;
    let mut endpoint_scan = tokio::time::interval(ENDPOINT_REFRESH_MIN_INTERVAL);
    endpoint_scan.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut observed_endpoints = Some(state.configured_peer_endpoint_snapshot());
    // Hands the peers' confirmed endpoints to the admission guard's reserve on a change.
    let mut confirmed_feed = ConfirmedEndpointFeed::default();
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(WorkerCommand::Apply { config, reply }) => {
                    let result = state.apply(*config).await;
                    if result.is_ok() {
                        observed_endpoints = Some(state.configured_peer_endpoint_snapshot());
                    }
                    let _ = reply.send(result);
                }
                Some(WorkerCommand::SetMtu { mtu, reply }) => {
                    let _ = reply.send(state.update_mtu(mtu));
                }
                Some(WorkerCommand::SetPrivateKey { private_key, reply }) => {
                    let _ = reply.send(state.set_private_key(private_key).await);
                }
                Some(WorkerCommand::Counters(reply)) => {
                    let _ = reply.send(state.counters().await);
                }
                #[cfg(feature = "relay")]
                Some(WorkerCommand::PrepareHandshake { key, endpoint, reply }) => {
                    let _ = reply.send(state.prepare_handshake(key, endpoint).await);
                }
                #[cfg(feature = "relay")]
                Some(WorkerCommand::ForceHandshake { key, endpoint, reply }) => {
                    let _ = reply.send(state.force_handshake(key, endpoint).await);
                }
                Some(WorkerCommand::Stop(reply)) => {
                    state.stop().await;
                    let _ = reply.send(());
                    return;
                }
                None => {
                    state.stop().await;
                    return;
                }
            },
            () = endpoint_refresh.notified(), if endpoint_refresh_at.is_none() => {
                let now = tokio::time::Instant::now();
                let debounce = now + ENDPOINT_REFRESH_DEBOUNCE;
                let minimum = last_endpoint_refresh
                    .map_or(now, |last| last + ENDPOINT_REFRESH_MIN_INTERVAL);
                endpoint_refresh_at = Some(debounce.max(minimum));
            }
            () = endpoint_refresh_due(endpoint_refresh_at) => {
                endpoint_refresh_at = None;
                endpoint_refresh.begin_refresh();
                match state.refresh_live_peer_endpoints(&route_endpoint_updater).await {
                    Ok(endpoints) => observed_endpoints = Some(endpoints),
                    Err(error) => tracing::warn!(error = %error, "could not refresh mesh routes from live peer endpoints"),
                }
                last_endpoint_refresh = Some(tokio::time::Instant::now());
            }
            _ = endpoint_scan.tick() => {
                let endpoints = state.live_peer_endpoint_snapshot().await;
                state
                    .admit_confirmed_endpoints(&mut confirmed_feed, &endpoints)
                    .await;
                let changed = observed_endpoints
                    .as_ref()
                    .is_some_and(|previous| previous != &endpoints);
                if changed {
                    endpoint_refresh.endpoint_changed();
                } else if observed_endpoints.is_none() {
                    observed_endpoints = Some(endpoints);
                }
            }
            // Reap finished handshake tasks; their result is visible in the peer counters.
            Some(_) = state.handshakes.join_next(), if !state.handshakes.is_empty() => {}
            // A packet task that ends on an error ends that direction of traffic for good while
            // the node still looks up (#260 J143 P2-1). Stop the device and rebuild it.
            () = fatal_error(state.device.as_mut()), if state.handshakes.is_empty() => {
                state.engine_stopped().await;
            }
            () = restart_due(state.restart_at), if state.restart_at.is_some() => {
                state.restart().await;
            }
        }
    }
}

impl RuntimeState {
    /// Give the admission guard the peers' confirmed endpoints through `feed`, so those exact
    /// sources keep the guard's reserved budget under a flood.
    ///
    /// Runs on the 250 ms endpoint scan. The shared feed takes the guard's write lock only on a
    /// change, because the receive task takes its read lock for every initiation.
    async fn admit_confirmed_endpoints(
        &self,
        feed: &mut ConfirmedEndpointFeed,
        endpoints: &BTreeMap<PublicKey, Option<SocketAddr>>,
    ) {
        let Some(pending) = self.pending.as_ref() else {
            return;
        };
        feed.offer(
            &pending.factory.admission,
            endpoints.values().flatten().copied(),
        )
        .await;
    }

    /// Read authenticated live endpoints and refresh their route budgets away from the runtime.
    ///
    /// Only active identities own host routes. The stable peer key is passed to the node so
    /// rotation overlap and relay overrides keep using the same route-state entry.
    /// # Errors
    /// Reports a blocking-pool join failure or a route-netlink update failure.
    async fn refresh_live_peer_endpoints(
        &self,
        updater: &RouteEndpointUpdater,
    ) -> io::Result<BTreeMap<PublicKey, Option<SocketAddr>>> {
        let endpoints = self.live_peer_endpoint_snapshot().await;
        if endpoints.is_empty() {
            return Ok(endpoints);
        }
        let route_endpoints: Vec<_> = endpoints
            .iter()
            .map(|(key, endpoint)| (*key, *endpoint))
            .collect();
        let updater = Arc::clone(updater);
        tokio::task::spawn_blocking(move || updater(&route_endpoints))
            .await
            .map_err(|_| io::Error::other("mesh route refresh task stopped"))??;
        Ok(endpoints)
    }

    /// Read each installed peer's confirmed endpoint for bounded change detection.
    ///
    /// This is `GotaTun`'s `confirmed_endpoint`: the source of the latest packet that proved the
    /// peer's key (transport data, or the response to our own initiation). The send endpoint is
    /// not used, because an accepted handshake initiation moves it before its sender proves
    /// anything, and a replayed initiation could then choose our route MTU (#489 J549 P1).
    /// `None` means no proof yet, and routes keep the coordinator's configured endpoint.
    async fn live_peer_endpoint_snapshot(&self) -> BTreeMap<PublicKey, Option<SocketAddr>> {
        let (Some(device), Some(config)) = (self.device.as_ref(), self.config.as_ref()) else {
            return BTreeMap::new();
        };
        let route_keys: BTreeMap<_, _> = config
            .peers
            .values()
            .map(|policy| (active_peer_key(&policy.peer), policy.peer.key))
            .collect();
        if route_keys.is_empty() {
            return BTreeMap::new();
        }
        let peers = device.read(async |read| read.peers().await).await;
        let mut endpoints = BTreeMap::new();
        for peer in peers {
            if peer.peer.allowed_ips.is_empty() {
                continue;
            }
            let active_key = PublicKey(*peer.peer.public_key.as_bytes());
            if let Some(route_key) = route_keys.get(&active_key) {
                endpoints.insert(*route_key, peer.stats.confirmed_endpoint);
            }
        }
        endpoints
    }

    /// Return the snapshot that matches routes freshly derived from the configured endpoints.
    ///
    /// No peer has a confirmed endpoint in that state, so every value is `None`. The scan then
    /// requests a refresh as soon as any peer proves a path, including one it proved before this
    /// configuration was applied.
    fn configured_peer_endpoint_snapshot(&self) -> BTreeMap<PublicKey, Option<SocketAddr>> {
        self.config.as_ref().map_or_else(BTreeMap::new, |config| {
            config
                .peers
                .values()
                .map(|policy| (policy.peer.key, None))
                .collect()
        })
    }

    /// Change the live device key and retain that key for a later device rebuild.
    ///
    /// The pending key changes only after the device accepts the new key, so a failed update
    /// cannot make a later rebuild silently use an identity the live device never accepted.
    /// # Errors
    /// Reports an absent runtime or a failed userspace device reconfiguration.
    async fn set_private_key(&mut self, private_key: StaticSecret) -> io::Result<()> {
        let admission = Arc::clone(
            &self
                .pending
                .as_ref()
                .ok_or(io::ErrorKind::NotConnected)?
                .factory
                .admission,
        );
        if let Some(device) = self.device.as_ref() {
            device
                .set_private_key(private_key.clone())
                .await
                .map_err(|_| io::Error::other("GotaTun private key could not be updated."))?;
        }
        admission.write().await.set_private_key(private_key.clone());
        self.pending
            .as_mut()
            .ok_or(io::ErrorKind::NotConnected)?
            .private_key = private_key;
        Ok(())
    }

    /// Install a relay endpoint on the peer whose key currently owns its host routes.
    #[cfg(feature = "relay")]
    async fn set_endpoint(&mut self, key: PublicKey, endpoint: SocketAddr) -> io::Result<()> {
        let policy = self
            .config
            .as_ref()
            .and_then(|config| {
                config
                    .peers
                    .values()
                    .find(|policy| active_peer_key(&policy.peer) == key)
            })
            .ok_or(io::ErrorKind::NotFound)?;
        let mut peers = peer_for_policy(policy)?;
        let active = peers
            .iter_mut()
            .find(|peer| peer.public_key.as_bytes() == &key.0)
            .ok_or(io::ErrorKind::NotFound)?;
        active.endpoint = Some(endpoint);
        self.device
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .write(async |device| device.add_or_update_peers(peers).await)
            .await
            .map_err(|_| io::Error::other("GotaTun relay endpoint could not be installed."))
    }

    /// Prepare a peer for relayed traffic while preserving any session it already established.
    #[cfg(feature = "relay")]
    async fn prepare_handshake(&mut self, key: PublicKey, endpoint: SocketAddr) -> io::Result<()> {
        // GotaTun records a handshake as soon as either side derives a session, including a
        // responder that has just answered a relayed initiation. Keep that session.
        let has_session = self
            .counters()
            .await?
            .get(&key)
            .is_some_and(|counters| counters.handshake_secs != 0);
        if has_session {
            return self.set_endpoint(key, endpoint).await;
        }
        let policy =
            self.config
                .as_ref()
                .and_then(|config| {
                    config.peers.values().find(|policy| {
                        policy.peer.key == key || policy.peer.previous_key == Some(key)
                    })
                })
                .ok_or(io::ErrorKind::NotFound)?;
        let mut peers = peer_for_policy(policy)?;
        // Drop the direct-path attempt still in flight: GotaTun's forced handshake would wait
        // for it rather than send a fresh initiation. An endpoint-less responder learns the
        // relay shim's address from the authenticated initiation, so only one side initiates.
        if let Some(active) = peers.iter_mut().find(|peer| !peer.allowed_ips.is_empty()) {
            active.endpoint = None;
        }
        let public_key = X25519PublicKey::from(key.0);
        self.device
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .write(async |device| {
                device.remove_peer(&public_key).await;
                device.add_or_update_peers(peers).await;
            })
            .await
            .map_err(|_| io::Error::other("GotaTun relay peer could not be reset."))
    }

    #[cfg(feature = "relay")]
    async fn force_handshake(&mut self, key: PublicKey, endpoint: SocketAddr) -> io::Result<()> {
        self.set_endpoint(key, endpoint).await?;
        let device = Arc::clone(self.device.as_ref().ok_or(io::ErrorKind::NotConnected)?);
        let key = X25519PublicKey::from(key.0);
        // GotaTun sends the initiation, then waits for the session without holding its device
        // lock. Wait in a task: callers of this serialized loop block their own threads, and
        // the relay shim that must deliver the response may run on one of them.
        self.handshakes.spawn(async move {
            let _ = tokio::time::timeout(HANDSHAKE_WAIT, device.force_handshake(&key)).await;
        });
        Ok(())
    }

    /// Build the device for `config` from the retained key, sockets and TUN. `GotaTun` runs packet
    /// workers only with peers, so an empty peer set leaves no device.
    async fn start_device(&mut self, config: &Config) -> io::Result<()> {
        let peers = peers_for_config(config)?;
        if peers.is_empty() {
            // Nothing left to rebuild: a stopped engine with no peers carries no traffic.
            self.restart_at = None;
            self.health.stopped.store(false, Ordering::Relaxed);
            return Ok(());
        }
        let pending = self.pending.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let tun = self
            .tun
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .clone();
        let device = build_device(
            pending.factory.clone(),
            pending.private_key.clone(),
            self.info.port,
            peers,
            admitted_peer_keys(config),
            tun,
        )
        .await?;
        self.device = Some(Arc::new(device));
        self.restart_at = None;
        if self.health.stopped.swap(false, Ordering::Relaxed) {
            self.health.restarts.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    /// The device reported a fatal error: one of its packet tasks has ended. Stop the rest and
    /// schedule a rebuild; `mesh status` shows the engine stopped until then.
    async fn engine_stopped(&mut self) {
        // Called only while no handshake task holds a clone, so this handle is the last one.
        if let Some(device) = self.device.take().and_then(Arc::into_inner) {
            device.stop().await;
        }
        self.health.stopped.store(true, Ordering::Relaxed);
        self.restart_at = Some(Instant::now() + RESTART_DELAY);
    }

    async fn restart(&mut self) {
        self.restart_at = None;
        let Some(config) = self.config.clone() else {
            return;
        };
        if self.start_device(&config).await.is_err() {
            self.restart_at = Some(Instant::now() + RESTART_DELAY);
        }
    }

    /// Apply a coordinator snapshot while keeping the shared link above IPv6's minimum.
    ///
    /// The caller installs the new per-peer route MTUs before lowering the shared interface.
    /// # Errors
    /// Reports a missing TUN, route-netlink failure, or peer update failure.
    async fn apply(&mut self, config: Config) -> io::Result<RuntimeInfo> {
        let mtu = crate::mesh_mtu::for_config(Some(&config));
        let previous_mtu = self
            .tun
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .tun
            .current_mtu()?;
        if self.device.is_none() {
            self.update_mtu(mtu)?;
            if let Err(error) = self.start_device(&config).await {
                let _ = self.update_mtu(previous_mtu);
                return Err(error);
            }
            self.config = Some(config);
            return Ok(self.info.clone());
        }
        let desired = peer_keys_with_network_access(&config);
        let admitted_peers = admitted_peer_keys(&config);
        let admission = Arc::clone(
            &self
                .pending
                .as_ref()
                .ok_or(io::ErrorKind::NotConnected)?
                .factory
                .admission,
        );
        let device = self.device.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let changed_policies = config
            .peers
            .iter()
            .filter(|(id, policy)| {
                policy.has_network_access()
                    && self
                        .config
                        .as_ref()
                        .and_then(|old| old.peers.get(id))
                        .is_none_or(|old| !old.has_network_access() || old.peer != policy.peer)
            })
            .map(|(_, policy)| peer_for_policy(policy))
            .collect::<io::Result<Vec<_>>>()?;
        let changed: Vec<_> = changed_policies.into_iter().flatten().collect();
        let previous_keys = self
            .config
            .as_ref()
            .map(peer_keys_with_network_access)
            .unwrap_or_default();
        let retired: Vec<_> = previous_keys
            .difference(&desired)
            .copied()
            .map(|key| X25519PublicKey::from(key.0))
            .collect();
        // Keep the larger link limit until the caller has replaced the peer route metrics.
        self.update_mtu(previous_mtu.max(mtu))?;
        if !changed.is_empty() || !retired.is_empty() {
            // One device transaction: packet workers never see a half-applied snapshot.
            //
            // Known limit (J555 note, #483): `add_or_update_peers` overwrites every field of a
            // changed peer, including the endpoint. When a snapshot changes a peer for another
            // reason (its access, addresses or rotation keys), the coordinator's endpoint, or
            // none, replaces an endpoint the device learned from that peer's authenticated
            // traffic after a NAT rebinding. The peer's next keepalive (at most 25 s) or data
            // packet moves it back, so a rebinding that coincides with such a snapshot can take
            // up to 25 s to recover. Peers the snapshot leaves unchanged keep their endpoint.
            if let Err(error) = device
                .write(async |device| {
                    device.add_or_update_peers(changed).await;
                    for key in &retired {
                        device.remove_peer(key).await;
                    }
                })
                .await
                .map_err(|_| io::Error::other("GotaTun peers could not be updated."))
            {
                let _ = self.update_mtu(previous_mtu);
                return Err(error);
            }
        }
        // The receive guard follows only snapshots the live device accepted. The configured
        // endpoints are the ones that snapshot installs: only active identities carry one.
        let configured_endpoints = config
            .peers
            .values()
            .filter(|policy| policy.has_network_access())
            .filter_map(|policy| policy.peer.endpoint);
        let mut guard = admission.write().await;
        guard.set_peers(admitted_peers);
        guard.set_configured_endpoints(configured_endpoints);
        drop(guard);
        self.config = Some(config);
        Ok(self.info.clone())
    }

    /// Set both the kernel link MTU and the packet workers' live MTU watcher.
    ///
    /// The link changes first so the host network stack stops creating packets that the
    /// userspace tunnel would reject. The watcher is published only after that succeeds.
    /// # Errors
    /// Reports a missing TUN or a route-netlink failure.
    fn update_mtu(&self, mtu: u16) -> io::Result<()> {
        self.tun
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .set_mtu(mtu)
    }

    async fn counters(&self) -> io::Result<CounterMap> {
        let Some(device) = self.device.as_ref() else {
            return Ok(CounterMap::new());
        };
        let peers = device.read(async |read| read.peers().await).await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut counters = CounterMap::new();
        for peer in peers {
            let age = peer.stats.last_handshake.unwrap_or_default();
            let timestamp = if peer.stats.last_handshake.is_some() {
                now.checked_sub(age).unwrap_or_default()
            } else {
                Duration::ZERO
            };
            let key = PublicKey(*peer.peer.public_key.as_bytes());
            counters.insert(
                key,
                crate::wireguard::Counters {
                    persistent_keepalive_secs: peer.peer.keepalive.unwrap_or(0),
                    handshake_secs: timestamp.as_secs(),
                    #[cfg(feature = "relay")]
                    handshake_nanos: timestamp.subsec_nanos(),
                    received_bytes: u64::try_from(peer.stats.rx_bytes).unwrap_or(u64::MAX),
                    sent_bytes: u64::try_from(peer.stats.tx_bytes).unwrap_or(u64::MAX),
                    endpoint: peer.peer.endpoint,
                },
            );
        }
        Ok(counters)
    }

    async fn stop(&mut self) {
        // Ending every handshake task drops its device handle, so this one is the last.
        self.handshakes.abort_all();
        while self.handshakes.join_next().await.is_some() {}
        if let Some(device) = self.device.take().and_then(Arc::into_inner) {
            device.stop().await;
        }
        self.pending.take();
        self.tun.take();
        self.config = None;
        self.restart_at = None;
    }
}

/// Build a `GotaTun` device from a retained listener, identity, peers and TUN.
///
/// Install the admission set before the device starts receiving, so its first initiation sees the
/// same peers as the device configuration.
/// # Errors
/// Reports a failure to start `GotaTun` with these sockets, peers or TUN.
async fn build_device(
    factory: BoundUdpFactory,
    private_key: StaticSecret,
    port: u16,
    peers: Vec<WireGuardPeer>,
    admitted_peers: BTreeSet<PublicKey>,
    tun: LinuxPacketIo,
) -> io::Result<GotaDevice> {
    let admission = Arc::clone(&factory.admission);
    {
        let mut admission = admission.write().await;
        admission.set_private_key(private_key.clone());
        admission.install(admitted_peers, &peers);
    }
    DeviceBuilder::new()
        .with_udp(factory)
        .with_private_key(private_key)
        .with_listen_port(port)
        .with_ip_pair(tun.clone(), tun)
        .with_peers(peers)
        .build()
        .await
        .map_err(|_| io::Error::other("GotaTun device could not start."))
}

/// UDP socket buffers for the engine, the same request as the `GotaTun` CLI. With
/// `CAP_NET_ADMIN` the fork forces them past `net.core.rmem_max`/`wmem_max` (D331); without it
/// the kernel clamps them as before. The kernel default overflowed at the receiver under load
/// (#260 R4b), losing packets that SSH must retransmit. The memory is kernel socket memory,
/// used only while packets queue.
const UDP_BUFFER_BYTES: usize = 7 * 1024 * 1024;

/// Bind the requested port, falling back to a stable ephemeral choice only for automatic requests.
///
/// A fallback socket remains bound for the life of the engine, and its actual port is returned
/// for identity publication and durable restart state. Explicit operator ports fail on collision.
/// Every bound socket sends IPv4 with Don't Fragment clear (#483).
/// # Errors
/// Returns socket errors, rejects the reserved port, or reports bounded ephemeral allocation failure.
async fn bind_udp(
    request: ListenPortRequest,
    private_key: StaticSecret,
) -> io::Result<(BoundUdpFactory, u16)> {
    if request.port == 51_820 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let admission = Arc::new(RwLock::new(PeerAdmission::new(private_key)));
    let mut factory = UdpSocketFactory {
        recv_buffer_size: Some(UDP_BUFFER_BYTES),
        send_buffer_size: Some(UDP_BUFFER_BYTES),
    };
    if request.port != 0 {
        let params = UdpTransportFactoryParams {
            addr: None,
            port: request.port,
            fwmark: None,
        };
        match factory.bind(&params).await {
            Ok((send, receive)) => {
                // Routers may fragment our IPv4 packets, as with kernel WireGuard (#483 PMTU black hole).
                #[cfg(target_os = "linux")]
                infraternal_linux_tun::allow_ipv4_fragmentation(&send)?;
                let port = send.local_addr()?.port();
                if port == 0 || port == 51_820 {
                    return Err(io::ErrorKind::AddrInUse.into());
                }
                return Ok((
                    BoundUdpFactory {
                        send,
                        receive,
                        port,
                        admission: Arc::clone(&admission),
                    },
                    port,
                ));
            }
            Err(error) if request.allow_fallback && error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error),
        }
    }
    for _ in 0..16 {
        let params = UdpTransportFactoryParams {
            addr: None,
            port: 0,
            fwmark: None,
        };
        let (send, receive) = factory.bind(&params).await?;
        // Routers may fragment our IPv4 packets, as with kernel WireGuard (#483 PMTU black hole).
        #[cfg(target_os = "linux")]
        infraternal_linux_tun::allow_ipv4_fragmentation(&send)?;
        let port = send.local_addr()?.port();
        if port != 0 && port != 51820 {
            return Ok((
                BoundUdpFactory {
                    send,
                    receive,
                    port,
                    admission: Arc::clone(&admission),
                },
                port,
            ));
        }
    }
    Err(io::ErrorKind::AddrInUse.into())
}

/// Keeps local service delivery as an explicit boundary while forwarding packets to the TUN.
#[derive(Clone)]
struct LinuxPacketIo {
    tun: LinuxTun,
    filter: Arc<PacketFilter>,
}

impl LinuxPacketIo {
    /// Wrap the opened TUN for `GotaTun` packet delivery and its live MTU watcher.
    fn new(tun: LinuxTun, filter: Arc<PacketFilter>) -> Self {
        Self { tun, filter }
    }

    /// Keep the link MTU and `GotaTun`'s packet-size watcher in step.
    /// # Errors
    /// Reports a missing interface or route-netlink configuration failure.
    fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        self.tun.set_mtu(mtu)
    }

    /// Future mesh-local services consume selected decrypted packets here before host delivery.
    // This boundary stays stateful and fallible so the future service dispatcher can inspect and
    // reject packets without changing the transport's send path. For now, it preserves the packet.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn local_service_hook(&self, packet: Packet<Ip>) -> io::Result<Option<Packet<Ip>>> {
        // Service termination is intentionally not enabled in this slice.
        Ok(Some(packet))
    }
}

/// Check a typed `GotaTun` IP packet without copying its backing buffer.
///
/// `GotaTun` exposes mutable bytes on `Packet<[u8]>`, not `Packet<Ip>`. Converting to bytes and
/// back is a zero-copy type cast; the filter owns the only packet parser and the second cast
/// revalidates the type after a possible mesh SSH port rewrite.
fn filter_ip_packet(
    packet: Packet<Ip>,
    filter: &PacketFilter,
    direction: Direction,
) -> Option<Packet<Ip>> {
    let mut packet = packet.into_bytes();
    if !filter.check(packet.buf_mut(), direction) {
        return None;
    }
    packet.try_into_ip().ok()
}

impl IpSend for LinuxPacketIo {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let Some(packet) = filter_ip_packet(packet, &self.filter, Direction::MeshToHost) else {
            return Ok(());
        };
        let Some(packet) = self.local_service_hook(packet)? else {
            return Ok(());
        };
        self.tun.send(packet).await
    }
}

impl IpRecv for LinuxPacketIo {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packets = self.tun.recv(pool).await?;
        let filter = &self.filter;
        Ok(packets
            .filter_map(move |packet| filter_ip_packet(packet, filter, Direction::HostToMesh)))
    }

    fn mtu(&self) -> MtuWatcher {
        self.tun.mtu()
    }
}

/// Build the device's peer list from peers with network access, retaining both keys during a
/// rotation overlap.
/// # Errors
/// Rejects invalid host routes before changing the live device.
fn peers_for_config(config: &Config) -> io::Result<Vec<WireGuardPeer>> {
    let peers = config
        .peers
        .values()
        .filter(|peer| peer.has_network_access())
        .map(peer_for_policy)
        .collect::<io::Result<Vec<_>>>()?;
    Ok(peers.into_iter().flatten().collect())
}

/// Convert each configured peer to one live identity or its journaled overlap pair.
///
/// Only the active identity owns allowed IPs and the endpoint, so the second identity can accept
/// a handshake during overlap without stealing routes or initiating a competing path.
/// # Errors
/// Rejects invalid host routes before they reach the userspace device.
fn peer_for_policy(policy: &crate::dataplane::PeerPolicy) -> io::Result<Vec<WireGuardPeer>> {
    let peer = &policy.peer;
    let addresses = vec![
        IpNetwork::new(IpAddr::V4(peer.addresses.ipv4), 32)
            .map_err(|_| io::ErrorKind::InvalidData)?,
        IpNetwork::new(IpAddr::V6(peer.addresses.ipv6), 128)
            .map_err(|_| io::ErrorKind::InvalidData)?,
    ];
    let Some(previous) = peer.previous_key.filter(|key| *key != peer.key) else {
        let mut current =
            WireGuardPeer::new(X25519PublicKey::from(peer.key.0)).with_allowed_ips(addresses);
        current.endpoint = peer.endpoint;
        // The first due keepalive initiates a handshake after endpoint discovery,
        // before user traffic exists.
        current.keepalive = Some(25);
        return Ok(vec![current]);
    };
    let previous_active = peer.previous_active;
    let mut previous_peer = WireGuardPeer::new(X25519PublicKey::from(previous.0)).with_allowed_ips(
        if previous_active {
            addresses.clone()
        } else {
            Vec::new()
        },
    );
    let mut current_peer = WireGuardPeer::new(X25519PublicKey::from(peer.key.0)).with_allowed_ips(
        if previous_active {
            Vec::new()
        } else {
            addresses
        },
    );
    let active = if previous_active {
        &mut previous_peer
    } else {
        &mut current_peer
    };
    active.endpoint = peer.endpoint;
    // Both peers initiate after learning the endpoint to open conntrack state
    // through strict input firewalls.
    active.keepalive = Some(25);
    Ok(vec![previous_peer, current_peer])
}

/// Select the identity that currently owns this peer's host routes.
fn active_peer_key(peer: &crate::dataplane::Peer) -> PublicKey {
    if peer.previous_active {
        peer.previous_key.unwrap_or(peer.key)
    } else {
        peer.key
    }
}

/// Include every configured identity so cleanup removes only keys no longer in overlap.
fn policy_keys(policy: &crate::dataplane::PeerPolicy) -> impl Iterator<Item = PublicKey> {
    std::iter::once(policy.peer.key).chain(policy.peer.previous_key)
}

/// Return configured `WireGuard` identities whose peers have network access in either direction.
///
/// `GotaTun` must not install a peer with no access: a configured endpoint and keepalive would let
/// the node initiate a handshake to that peer even though inbound handshake admission rejects it.
pub(crate) fn peer_keys_with_network_access(config: &Config) -> BTreeSet<PublicKey> {
    config
        .peers
        .values()
        .filter(|peer| peer.has_network_access())
        .flat_map(policy_keys)
        .collect()
}

/// Return identities whose effective network access permits traffic in at least one direction.
fn admitted_peer_keys(config: &Config) -> BTreeSet<PublicKey> {
    peer_keys_with_network_access(config)
}

pub(crate) fn secret_from_bytes(bytes: &[u8]) -> io::Result<(StaticSecret, PublicKey)> {
    let raw: [u8; 32] = bytes.try_into().map_err(|_| io::ErrorKind::InvalidData)?;
    let raw = zeroize::Zeroizing::new(raw);
    let secret = StaticSecret::from(*raw);
    let public = X25519PublicKey::from(&secret);
    Ok((secret, PublicKey(*public.as_bytes())))
}

/// Checks engine selection, `GotaTun` peer conversion, and mesh-link lifecycle behavior.
#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::{EngineKind, admitted_peer_keys, peer_keys_with_network_access, peers_for_config};
    use crate::listen_port::Request;
    use crate::{
        dataplane::{Config, DefaultPolicy, Peer, PeerPolicy},
        policy::{
            model::{Addresses, NodeId, PublicKey},
            rules::TrafficPolicy,
        },
    };
    use std::{collections::BTreeMap, net::SocketAddr};

    /// D346: `GotaTun` is the Linux default; kernel `WireGuard` stays selectable per machine.
    #[test]
    fn linux_defaults_to_gotatun_and_kernel_stays_selectable() {
        assert_eq!(EngineKind::default(), EngineKind::GotaTun);
        assert_eq!(
            EngineKind::parse(None).expect("default"),
            EngineKind::GotaTun
        );
        assert_eq!(
            EngineKind::parse(Some("kernel")).expect("selectable engine"),
            EngineKind::Kernel
        );
    }

    /// `GotaTun`'s packet tasks are joined by channels and need worker threads to run in
    /// parallel; the process keeps transparent huge pages off (#260 R4b).
    #[test]
    fn engine_runtime_runs_packet_tasks_on_worker_threads() {
        let (runtime, thp_disabled) = super::engine_runtime().expect("engine runtime");
        assert!(thp_disabled, "transparent huge pages stay disabled");
        assert_eq!(
            runtime.handle().runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        );
    }

    /// The engine socket asks for the large buffers (D331). The kernel doubles only an explicit
    /// request, so a socket left at its default stays below a clamped request of the same size,
    /// even where `rmem_default` equals `rmem_max`. With `CAP_NET_ADMIN` the request is forced.
    #[tokio::test]
    async fn engine_udp_socket_requests_the_large_buffers() {
        use gotatun::x25519::StaticSecret;
        use nix::sys::socket::{getsockopt, setsockopt, sockopt};
        let (factory, _) = super::bind_udp(
            Request {
                port: 0,
                allow_fallback: true,
            },
            StaticSecret::from([1; 32]),
        )
        .await
        .expect("bound engine socket");
        let reference = std::net::UdpSocket::bind("127.0.0.1:0").expect("reference socket");
        setsockopt(&reference, sockopt::RcvBuf, &super::UDP_BUFFER_BYTES).expect("receive request");
        setsockopt(&reference, sockopt::SndBuf, &super::UDP_BUFFER_BYTES).expect("send request");
        let requested = (
            getsockopt(&reference, sockopt::RcvBuf).expect("reference receive buffer"),
            getsockopt(&reference, sockopt::SndBuf).expect("reference send buffer"),
        );
        let engine = (
            getsockopt(&factory.receive, sockopt::RcvBuf).expect("engine receive buffer"),
            getsockopt(&factory.send, sockopt::SndBuf).expect("engine send buffer"),
        );
        assert!(
            engine.0 >= requested.0 && engine.1 >= requested.1,
            "engine buffers {engine:?} are below an explicit request {requested:?}"
        );
    }

    /// An automatic listener falls back when its preferred UDP port is held; an explicit choice fails.
    #[tokio::test]
    async fn occupied_listener_falls_back_only_for_automatic_selection() {
        use gotatun::x25519::StaticSecret;
        let occupied = std::net::UdpSocket::bind("0.0.0.0:0").expect("reserve test port");
        let preferred = occupied.local_addr().expect("reserved port").port();
        assert_ne!(
            preferred, 51_820,
            "the fallback test does not use the reserved port"
        );

        let (factory, actual) = super::bind_udp(
            Request {
                port: preferred,
                allow_fallback: true,
            },
            StaticSecret::from([2; 32]),
        )
        .await
        .expect("automatic listener falls back");
        assert_ne!(actual, preferred, "the occupied preference was not reused");
        assert_eq!(
            factory.port, actual,
            "the reported port matches the bound socket"
        );
        assert_eq!(
            factory.send.local_addr().expect("bound listener").port(),
            actual
        );
        drop(factory);

        let Err(error) = super::bind_udp(
            Request {
                port: preferred,
                allow_fallback: false,
            },
            StaticSecret::from([2; 32]),
        )
        .await
        else {
            panic!("an explicit occupied port unexpectedly succeeded")
        };
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    }

    #[test]
    fn kernel_engine_is_selectable() {
        assert_eq!(
            EngineKind::parse(Some("kernel")).expect("known engine"),
            EngineKind::Kernel
        );
    }

    /// Poll one refresh notification without sleeping or measuring wall-clock time.
    fn review_endpoint_refresh_ready(signal: &super::EndpointRefreshSignal) -> bool {
        use std::{
            future::Future,
            task::{Context, Waker},
        };
        let mut notification = Box::pin(signal.notified());
        notification
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    }

    /// A packet burst uses one wakeup until the worker starts its refresh.
    #[test]
    fn review_endpoint_refresh_coalesces_a_packet_burst() {
        let signal = super::EndpointRefreshSignal::default();
        for _ in 0..10_000 {
            signal.traffic();
        }
        assert!(review_endpoint_refresh_ready(&signal));
        assert!(!review_endpoint_refresh_ready(&signal));
        signal.begin_refresh();
        assert!(!signal.pending.load(std::sync::atomic::Ordering::Acquire));
        assert!(!review_endpoint_refresh_ready(&signal));
        signal.traffic();
        assert!(review_endpoint_refresh_ready(&signal));
    }

    /// Packets arriving during a refresh's read request exactly one subsequent refresh.
    #[test]
    fn review_endpoint_refresh_retains_a_burst_during_the_snapshot() {
        let signal = super::EndpointRefreshSignal::default();
        signal.traffic();
        assert!(review_endpoint_refresh_ready(&signal));
        signal.begin_refresh();
        for _ in 0..10_000 {
            signal.traffic();
        }
        assert!(review_endpoint_refresh_ready(&signal));
        assert!(!review_endpoint_refresh_ready(&signal));
        signal.begin_refresh();
        assert!(!signal.pending.load(std::sync::atomic::Ordering::Acquire));
    }

    /// The worker rebuilds a device whose packet task ended on a fatal error, and `mesh status`
    /// sees it stopped in between (#260 J143 P2-1). A sequenced-packet pair plays the TUN; closing
    /// the kernel's side ends `GotaTun`'s TUN reader with EOF, its fatal TUN error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn worker_rebuilds_the_device_after_a_fatal_error() {
        use super::{
            EndpointRefreshSignal, Health, LinuxPacketIo, PacketFilter, PendingDevice,
            RouteEndpointUpdater, RuntimeInfo, RuntimeState, WorkerCommand, bind_udp, build_device,
            run_worker,
        };
        use gotatun::x25519::StaticSecret;
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
        use std::sync::{Arc, mpsc as sync};
        let private_key = StaticSecret::from([7; 32]);
        let (kernel, device) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        )
        .expect("TUN stand-in");
        let health = Arc::new(Health::default());
        let config = one_peer_config(None);
        let filter = Arc::new(
            PacketFilter::new(
                &config,
                infraternal_mesh::proxy_ports::MeshProxyIngress::default(),
            )
            .expect("compile filter"),
        );
        let tun = LinuxPacketIo::new(
            crate::gotatun_tun::LinuxTun::from_fd(device, true, Arc::clone(&health.refused))
                .expect("TUN stand-in registers"),
            filter,
        );
        let (factory, port) = bind_udp(
            Request {
                port: 0,
                allow_fallback: true,
            },
            private_key.clone(),
        )
        .await
        .expect("engine socket");
        let peers = peers_for_config(&config).expect("peers");
        let device = build_device(
            factory.clone(),
            private_key.clone(),
            port,
            peers,
            admitted_peer_keys(&config),
            tun.clone(),
        )
        .await
        .expect("device");
        let state = RuntimeState {
            tun: Some(tun),
            device: Some(Arc::new(device)),
            handshakes: tokio::task::JoinSet::new(),
            pending: Some(PendingDevice {
                factory,
                private_key,
            }),
            config: Some(config),
            info: RuntimeInfo {
                interface: "test-tun".to_owned(),
                port,
                thp_disabled: true,
                offloads_enabled: true,
            },
            health: Arc::clone(&health),
            restart_at: None,
        };
        let (commands, receiver) = tokio::sync::mpsc::unbounded_channel();
        let endpoint_refresh = Arc::new(EndpointRefreshSignal::default());
        let updater: RouteEndpointUpdater = Arc::new(|_| Ok(()));
        let worker = tokio::spawn(run_worker(receiver, state, endpoint_refresh, updater));
        let initial = health.snapshot();
        assert!(!initial.stopped && initial.restarts == 0 && initial.refused_frames == 0);

        drop(kernel);
        let mut seen_stopped = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while health.snapshot().restarts == 0 {
            seen_stopped |= health.snapshot().stopped;
            assert!(
                tokio::time::Instant::now() < deadline,
                "the worker never rebuilt the stopped device: {:?}",
                health.snapshot()
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            seen_stopped,
            "mesh status sees the engine stopped before it is rebuilt"
        );

        let (reply, stopped) = sync::sync_channel(1);
        commands
            .send(WorkerCommand::Stop(reply))
            .map_err(|_| "worker ended")
            .expect("stop");
        worker.await.expect("worker");
        stopped.recv().expect("stop reply");
    }

    /// A configuration with one peer at `endpoint`.
    fn one_peer_config(endpoint: Option<SocketAddr>) -> Config {
        Config {
            authority_epoch: None,
            rotation_operation: None,
            local_key: Some(PublicKey([1; 32])),
            server: Some(NodeId(1)),
            node: NodeId(2),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            version: 7,
            addresses: Addresses {
                ipv4: "10.254.0.2".parse().expect("local IPv4"),
                ipv6: "fd01::2".parse().expect("local IPv6"),
            },
            default_policy: DefaultPolicy::Deny,
            exposure: None,
            peers: BTreeMap::from([(
                NodeId(1),
                PeerPolicy {
                    peer: Peer {
                        key: PublicKey([3; 32]),
                        previous_key: None,
                        previous_active: false,
                        addresses: Addresses {
                            ipv4: "10.254.0.1".parse().expect("peer IPv4"),
                            ipv6: "fd01::1".parse().expect("peer IPv6"),
                        },
                        endpoint,
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                    access_ssh: None,
                },
            )]),
            #[cfg(feature = "mesh-dns")]
            peer_names: BTreeMap::new(),
        }
    }

    /// The Linux typed-packet adapter applies grants before returning packets to `GotaTun`.
    #[test]
    fn typed_ip_packets_pass_through_the_mesh_filter() {
        use super::{Direction, PacketFilter, filter_ip_packet};
        use gotatun::packet::Packet;

        let config = one_peer_config(None);
        let filter = PacketFilter::new(
            &config,
            infraternal_mesh::proxy_ports::MeshProxyIngress::default(),
        )
        .expect("compile filter");
        let mut bytes = vec![0_u8; 40];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&40_u16.to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 6;
        bytes[12..16].copy_from_slice(&config.addresses.ipv4.octets());
        bytes[16..20].copy_from_slice(
            &"10.254.0.1"
                .parse::<std::net::Ipv4Addr>()
                .expect("peer")
                .octets(),
        );
        bytes[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&443_u16.to_be_bytes());
        bytes[32] = 0x50;
        bytes[33] = 0x02;

        let mut packet = Packet::<[u8]>::default();
        packet.buf_mut().extend_from_slice(&bytes);
        let packet = packet.try_into_ip().expect("typed IP packet");
        assert!(filter_ip_packet(packet, &filter, Direction::HostToMesh).is_some());

        bytes[12..16].copy_from_slice(
            &"10.254.0.99"
                .parse::<std::net::Ipv4Addr>()
                .expect("spoofed address")
                .octets(),
        );
        let mut packet = Packet::<[u8]>::default();
        packet.buf_mut().extend_from_slice(&bytes);
        let packet = packet.try_into_ip().expect("typed spoofed IP packet");
        assert!(filter_ip_packet(packet, &filter, Direction::HostToMesh).is_none());
    }

    #[test]
    fn peer_conversion_uses_coordinator_keys_endpoints_and_host_allowed_ips() {
        let endpoint: SocketAddr = "192.0.2.4:51831".parse().expect("endpoint");
        let config = one_peer_config(Some(endpoint));
        let peers = peers_for_config(&config).expect("convert coordinator peer");

        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].public_key.as_bytes(), &[3; 32]);
        assert_eq!(peers[0].endpoint, Some(endpoint));
        assert_eq!(peers[0].keepalive, Some(25));
        assert_eq!(
            peers[0]
                .allowed_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.254.0.1/32", "fd01::1/128"]
        );
    }

    /// A peer with no network access cannot trigger an unsolicited userspace handshake.
    #[test]
    fn peer_without_network_access_is_not_installed() {
        let mut config = one_peer_config(None);
        let policy = config.peers.get_mut(&NodeId(1)).expect("configured peer");
        policy.inbound = TrafficPolicy::None;
        policy.outbound = TrafficPolicy::None;

        assert!(peers_for_config(&config).expect("convert peers").is_empty());
        assert!(peer_keys_with_network_access(&config).is_empty());
    }

    /// Keep both rotation keys installed while routing only through the currently active one.
    #[test]
    fn peer_conversion_keeps_the_inactive_rotation_key_without_routes_or_endpoint() {
        let endpoint: SocketAddr = "192.0.2.4:51831".parse().expect("endpoint");
        let mut config = one_peer_config(Some(endpoint));
        let policy = config.peers.get_mut(&NodeId(1)).expect("configured peer");
        policy.peer.previous_key = Some(PublicKey([4; 32]));
        policy.peer.previous_active = true;
        let peers = peers_for_config(&config).expect("convert both rotation keys");

        assert_eq!(peers.len(), 2, "the peer accepts both overlap identities");
        let candidate = peers
            .iter()
            .find(|peer| peer.public_key.as_bytes() == &[3; 32])
            .expect("candidate identity");
        let previous = peers
            .iter()
            .find(|peer| peer.public_key.as_bytes() == &[4; 32])
            .expect("previous identity");
        assert_eq!(candidate.allowed_ips.as_slice(), &[]);
        assert_eq!(candidate.endpoint, None);
        assert!(
            previous
                .allowed_ips
                .iter()
                .any(|ip| ip.to_string() == "10.254.0.1/32")
        );
        assert_eq!(previous.endpoint, Some(endpoint));
    }
}
