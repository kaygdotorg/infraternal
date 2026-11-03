//! Linux userspace mesh engine using the `GotaTun` device API and an owned TUN.

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
#[cfg(feature = "relay")]
use std::net::SocketAddr;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc as sync,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    runtime::Builder as RuntimeBuilder,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task::JoinSet,
    time::Instant,
};

use crate::{dataplane::Config, gotatun_tun::LinuxTun, policy::model::PublicKey};

type GotaDevice = WireGuardDevice<(BoundUdpFactory, LinuxPacketIo, LinuxPacketIo)>;
type CounterMap = BTreeMap<PublicKey, crate::wireguard::Counters>;

/// How long a forced relay handshake may wait; `GotaTun`'s own wait has no deadline.
/// One `WireGuard` handshake attempt is 5 s, after which the peer timers retry.
#[cfg(feature = "relay")]
const HANDSHAKE_WAIT: Duration = Duration::from_secs(5);

/// Selects the node's data plane. Kernel `WireGuard` stays the default until the integrated
/// `GotaTun` engine reaches kernel throughput in R4b (#260); `GotaTun` is selectable per node.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineKind {
    GotaTun,
    #[default]
    Kernel,
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

#[derive(Clone)]
struct BoundUdpFactory {
    send: GotaUdpSocket,
    receive: GotaUdpSocket,
    port: u16,
}

impl UdpTransportFactory for BoundUdpFactory {
    type Send = GotaUdpSocket;
    type Recv = GotaUdpSocket;

    // The trait returns a future; these sockets are already bound, so complete it immediately.
    fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> impl std::future::Future<Output = io::Result<(Self::Send, Self::Recv)>> + Send {
        if params.addr.is_some() || params.port != self.port {
            return std::future::ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        std::future::ready(Ok((self.send.clone(), self.receive.clone())))
    }
}

#[derive(Clone)]
pub(crate) struct RuntimeInfo {
    interface: String,
    port: u16,
    thp_disabled: bool,
    offloads_enabled: bool,
}

enum WorkerCommand {
    Apply {
        config: Config,
        reply: sync::SyncSender<io::Result<RuntimeInfo>>,
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
}

impl Health {
    fn snapshot(&self) -> EngineHealth {
        EngineHealth {
            stopped: self.stopped.load(Ordering::Relaxed),
            restarts: self.restarts.load(Ordering::Relaxed),
            refused_frames: self.refused.load(Ordering::Relaxed),
        }
    }
}

/// The public view of [`Health`], reported by `mesh status` for the `GotaTun` engine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineHealth {
    pub stopped: bool,
    pub restarts: u64,
    pub refused_frames: u64,
}

impl Engine {
    /// Start `GotaTun` with the fork's Linux TUN adapter and offload handling.
    /// The worker thread disables THP before constructing the runtime or engine state.
    /// # Errors
    /// Reports TUN registration, UDP bind, runtime or device initialization failures.
    pub(crate) fn start(
        private_key: StaticSecret,
        local_public_key: PublicKey,
        requested_port: u16,
        config: Option<Config>,
    ) -> io::Result<Self> {
        let (info_tx, info_rx) = sync::sync_channel(1);
        let (commands, receiver) = mpsc::unbounded_channel();
        let health = Arc::new(Health::default());
        let worker_health = Arc::clone(&health);
        let refused = Arc::clone(&health.refused);
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
                    refused,
                    thp_disabled,
                ));
                let Started {
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
                runtime.block_on(run_worker(receiver, state));
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
            .send(WorkerCommand::Apply { config, reply })
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
    tun: LinuxPacketIo,
    device: Option<Arc<GotaDevice>>,
    pending: Option<PendingDevice>,
    info: RuntimeInfo,
}

/// Open, mark and activate the TUN, bind the engine socket, and build the device when the startup
/// config already has peers. Runs on the engine's runtime, which also runs the TUN writer.
async fn initialize(
    private_key: StaticSecret,
    local_public_key: PublicKey,
    requested_port: u16,
    config: Option<&Config>,
    refused: Arc<AtomicU64>,
    thp_disabled: bool,
) -> io::Result<Started> {
    let kernel_owned = crate::wireguard::Device::owned()?;
    let tun_owned = crate::wireguard::Device::owned_tun()?;
    if kernel_owned || tun_owned {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    let tun = LinuxTun::create(crate::wireguard::INTERFACE, refused)?;
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
    crate::wireguard::Device::mark_tun(local_public_key)?;
    crate::wireguard::Device::activate_tun()?;
    let tun = LinuxPacketIo::new(tun);
    let (factory, port) = bind_udp(requested_port).await?;
    let peers = config
        .map(peers_for_config)
        .transpose()?
        .unwrap_or_default();
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
    Ok(Started {
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

async fn run_worker(mut commands: UnboundedReceiver<WorkerCommand>, mut state: RuntimeState) {
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(WorkerCommand::Apply { config, reply }) => {
                    let _ = reply.send(state.apply(config).await);
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
    #[cfg(feature = "relay")]
    async fn set_endpoint(&mut self, key: PublicKey, endpoint: SocketAddr) -> io::Result<()> {
        let policy = self
            .config
            .as_ref()
            .and_then(|config| config.peers.values().find(|peer| peer.peer.key == key))
            .ok_or(io::ErrorKind::NotFound)?;
        let mut peer = peer_for_policy(policy)?;
        peer.endpoint = Some(endpoint);
        self.device
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .write(async |device| device.add_or_update_peers([peer]).await)
            .await
            .map_err(|_| io::Error::other("GotaTun relay endpoint could not be installed."))
    }

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
        let policy = self
            .config
            .as_ref()
            .and_then(|config| config.peers.values().find(|peer| peer.peer.key == key))
            .ok_or(io::ErrorKind::NotFound)?;
        let mut peer = peer_for_policy(policy)?;
        // Drop the direct-path attempt still in flight: GotaTun's forced handshake would wait
        // for it rather than send a fresh initiation. An endpoint-less responder learns the
        // relay shim's address from the authenticated initiation, so only one side initiates.
        peer.endpoint = None;
        let public_key = X25519PublicKey::from(key.0);
        self.device
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .write(async |device| {
                device.remove_peer(&public_key).await;
                device.add_or_update_peers([peer]).await;
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

    async fn apply(&mut self, config: Config) -> io::Result<RuntimeInfo> {
        if self.device.is_none() {
            self.start_device(&config).await?;
            self.config = Some(config);
            return Ok(self.info.clone());
        }
        let desired: BTreeSet<_> = config
            .peers
            .values()
            .map(|policy| policy.peer.key)
            .collect();
        let device = self.device.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let changed = config
            .peers
            .iter()
            .filter(|(id, policy)| {
                self.config
                    .as_ref()
                    .and_then(|old| old.peers.get(id))
                    .is_none_or(|old| old.peer != policy.peer)
            })
            .map(|(_, policy)| peer_for_policy(policy))
            .collect::<io::Result<Vec<_>>>()?;
        let retired: Vec<_> = self
            .config
            .iter()
            .flat_map(|old| old.peers.values())
            .map(|policy| policy.peer.key)
            .filter(|key| !desired.contains(key))
            .map(|key| X25519PublicKey::from(key.0))
            .collect();
        if !changed.is_empty() || !retired.is_empty() {
            // One device transaction: packet workers never see a half-applied snapshot.
            device
                .write(async |device| {
                    device.add_or_update_peers(changed).await;
                    for key in &retired {
                        device.remove_peer(key).await;
                    }
                })
                .await
                .map_err(|_| io::Error::other("GotaTun peers could not be updated."))?;
        }
        self.config = Some(config);
        Ok(self.info.clone())
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

async fn build_device(
    factory: BoundUdpFactory,
    private_key: StaticSecret,
    port: u16,
    peers: Vec<WireGuardPeer>,
    tun: LinuxPacketIo,
) -> io::Result<GotaDevice> {
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

async fn bind_udp(requested_port: u16) -> io::Result<(BoundUdpFactory, u16)> {
    let mut factory = UdpSocketFactory {
        recv_buffer_size: Some(UDP_BUFFER_BYTES),
        send_buffer_size: Some(UDP_BUFFER_BYTES),
    };
    for _ in 0..16 {
        let params = UdpTransportFactoryParams {
            addr: None,
            port: requested_port,
            fwmark: None,
        };
        let (send, receive) = factory.bind(&params).await?;
        let port = send.local_addr()?.port();
        if port != 0 && port != 51820 {
            return Ok((
                BoundUdpFactory {
                    send,
                    receive,
                    port,
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
}

impl LinuxPacketIo {
    fn new(tun: LinuxTun) -> Self {
        Self { tun }
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

impl IpSend for LinuxPacketIo {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
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
        self.tun.recv(pool).await
    }

    fn mtu(&self) -> MtuWatcher {
        self.tun.mtu()
    }
}

fn peers_for_config(config: &Config) -> io::Result<Vec<WireGuardPeer>> {
    config.peers.values().map(peer_for_policy).collect()
}

fn peer_for_policy(policy: &crate::dataplane::PeerPolicy) -> io::Result<WireGuardPeer> {
    let peer = &policy.peer;
    let addresses = [
        IpNetwork::new(IpAddr::V4(peer.addresses.ipv4), 32)
            .map_err(|_| io::ErrorKind::InvalidData)?,
        IpNetwork::new(IpAddr::V6(peer.addresses.ipv6), 128)
            .map_err(|_| io::ErrorKind::InvalidData)?,
    ];
    let mut wireguard_peer =
        WireGuardPeer::new(X25519PublicKey::from(peer.key.0)).with_allowed_ips(addresses);
    wireguard_peer.endpoint = peer.endpoint;
    wireguard_peer.keepalive = Some(25);
    Ok(wireguard_peer)
}

pub(crate) fn secret_from_bytes(bytes: &[u8]) -> io::Result<(StaticSecret, PublicKey)> {
    let raw: [u8; 32] = bytes.try_into().map_err(|_| io::ErrorKind::InvalidData)?;
    let raw = zeroize::Zeroizing::new(raw);
    let secret = StaticSecret::from(*raw);
    let public = X25519PublicKey::from(&secret);
    Ok((secret, PublicKey(*public.as_bytes())))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::{EngineKind, peers_for_config};
    use crate::{
        dataplane::{Config, DefaultPolicy, Peer, PeerPolicy},
        policy::{
            model::{Addresses, NodeId, PublicKey},
            rules::TrafficPolicy,
        },
    };
    use std::{collections::BTreeMap, net::SocketAddr};

    #[test]
    fn linux_defaults_to_kernel_until_gotatun_reaches_parity() {
        assert_eq!(EngineKind::default(), EngineKind::Kernel);
        assert_eq!(
            EngineKind::parse(None).expect("default"),
            EngineKind::Kernel
        );
        assert_eq!(
            EngineKind::parse(Some("gotatun")).expect("selectable engine"),
            EngineKind::GotaTun
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
        use nix::sys::socket::{getsockopt, setsockopt, sockopt};
        let (factory, _) = super::bind_udp(0).await.expect("bound engine socket");
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

    #[test]
    fn kernel_engine_is_selectable() {
        assert_eq!(
            EngineKind::parse(Some("kernel")).expect("known engine"),
            EngineKind::Kernel
        );
    }

    /// The worker rebuilds a device whose packet task ended on a fatal error, and `mesh status`
    /// sees it stopped in between (#260 J143 P2-1). A sequenced-packet pair plays the TUN; closing
    /// the kernel's side ends `GotaTun`'s TUN reader with EOF, its fatal TUN error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn worker_rebuilds_the_device_after_a_fatal_error() {
        use super::{
            Health, LinuxPacketIo, PendingDevice, RuntimeInfo, RuntimeState, WorkerCommand,
            bind_udp, build_device, run_worker,
        };
        use gotatun::x25519::StaticSecret;
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
        use std::sync::{Arc, mpsc as sync};
        let (kernel, device) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        )
        .expect("TUN stand-in");
        let health = Arc::new(Health::default());
        let tun = LinuxPacketIo::new(
            crate::gotatun_tun::LinuxTun::from_fd(device, true, Arc::clone(&health.refused))
                .expect("TUN stand-in registers"),
        );
        let (factory, port) = bind_udp(0).await.expect("engine socket");
        let private_key = StaticSecret::from([7; 32]);
        let config = one_peer_config(None);
        let peers = peers_for_config(&config).expect("peers");
        let device = build_device(
            factory.clone(),
            private_key.clone(),
            port,
            peers,
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
        let worker = tokio::spawn(run_worker(receiver, state));
        assert_eq!(health.snapshot(), super::EngineHealth::default());

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

    fn one_peer_config(endpoint: Option<SocketAddr>) -> Config {
        Config {
            local_key: Some(PublicKey([1; 32])),
            server: Some(NodeId(1)),
            node: NodeId(2),
            #[cfg(feature = "mesh-dns-spike")]
            name: None,
            #[cfg(feature = "mesh-dns-spike")]
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
                        addresses: Addresses {
                            ipv4: "10.254.0.1".parse().expect("peer IPv4"),
                            ipv6: "fd01::1".parse().expect("peer IPv6"),
                        },
                        endpoint,
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                },
            )]),
            #[cfg(feature = "mesh-dns-spike")]
            peer_names: BTreeMap::new(),
        }
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
}
