//! Linux userspace mesh engine using the `GotaTun` device API and an owned TUN.
//!
//! ## The engine bounds its own queue (D397)
//!
//! A TUN device hides the engine's queue from the kernel's TCP Small Queues, so without a bound
//! a loaded flow parks its whole congestion window inside the engine and every other packet on
//! the link waits behind it. The pinned `GotaTun` therefore runs a `CoDel` controller on its Linux
//! receive path: it measures each packet's time from the kernel's UDP receive stamp to the TUN
//! write and, once that stays above 1 ms for 10 ms, marks ECN-capable packets CE and drops only
//! selected packets that cannot be marked. Authenticated frames up to 256 bytes share a per-peer
//! allowance of 32 KiB per 10 ms with a 64 KiB burst, including padding before IP length trimming.
//! This covers measured interactive packets, ACKs and probes; larger frames and small traffic
//! exceeding the allowance remain subject to the controller. Flow keys never affect eligibility.
//! J711's earlier prototype on backup01 took cubic 8-flow loaded p99 from 22.4 ms to about 6 ms;
//! current-head measurements are recorded on #260.
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
    net::SocketAddr,
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
        RwLock,
        mpsc::{self, UnboundedReceiver, UnboundedSender},
    },
    task::JoinSet,
    time::Instant,
};

use crate::listen_port::Request as ListenPortRequest;
/// The node's route listener and the worker share this; see [`crate::underlay_announce`].
pub(crate) use crate::underlay_announce::UnderlayAnnounce;
use crate::underlay_announce::{
    AnnouncementWaiter, CoalescedSchedule, CoalescedWake, confirmed_changed,
};
use crate::{
    candidate_walks::{
        EngineEndpoint, HANDSHAKE_WAIT, Observed, Walks, active_peer_key, engine_endpoint,
        kept_address,
    },
    dataplane::Config,
    gotatun_tun::LinuxTun,
    packet_filter::{Direction, PacketFilter, PreparedPolicy},
    policy::model::PublicKey,
};
use crate::{
    direct_probe::DirectProbes,
    handshake_admission::{ConfirmedEndpointFeed, PeerAdmission, PeerAdmissionUdpReceiver},
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
/// The worker clears the request before it reads endpoints and route MTUs, so traffic that
/// arrives during that read queues exactly one more refresh (see [`CoalescedWake`]).
#[derive(Default)]
pub(crate) struct EndpointRefreshSignal {
    wake: CoalescedWake,
}

impl EndpointRefreshSignal {
    /// Tell the `GotaTun` worker that a packet crossed the mesh link, in either direction.
    ///
    /// Call it after the packet is handed on. It is cheap enough for every packet.
    pub(crate) fn traffic(&self) {
        // A queued refresh will read state after this packet, so it already covers it.
        if self.wake.is_pending() {
            return;
        }
        self.wake.request();
    }

    /// Tell the worker that its authenticated endpoint snapshot changed.
    pub(crate) fn endpoint_changed(&self) {
        self.wake.request();
    }

    /// Wait for the next coalesced refresh request.
    async fn notified(&self) {
        self.wake.notified().await;
    }

    /// Re-arm the signal right before the worker reads endpoints and route MTUs.
    fn begin_refresh(&self) {
        self.wake.begin();
    }
}

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
    /// Round-trip probes that leave from, and are answered on, this same bound port. The admission
    /// guard holds a clone and consumes probe-shaped datagrams before `GotaTun` sees them.
    probes: DirectProbes,
    /// The finished probes, until the path owner takes them (see [`Engine::direct_probes`]).
    probe_answers:
        Arc<std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<crate::direct_probe::Answer>>>>,
}

impl BoundUdpFactory {
    /// Bind the node's direct-path probes to this factory's send socket and give the admission
    /// guard its half. The factory starts the probes before the device receives anything, so the
    /// guard's receive task finds them on its first datagram.
    async fn with_probes(
        send: GotaUdpSocket,
        receive: GotaUdpSocket,
        port: u16,
        admission: Arc<RwLock<PeerAdmission>>,
    ) -> Self {
        let token_seed = crate::direct_probe::token_seed();
        let (probes, answers) = DirectProbes::new(send.clone(), token_seed);
        admission.write().await.set_probes(probes.clone());
        Self {
            send,
            receive,
            port,
            admission,
            probes,
            probe_answers: Arc::new(std::sync::Mutex::new(Some(answers))),
        }
    }
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

    /// The second socket for small data datagrams (#260, J1211): an ephemeral port beside the mesh
    /// port, with the same family set-up. Its receive half runs the same admission guard as the
    /// main one, so a stranger cannot use the second port to skip it. The direct-path probes stay
    /// on the main socket.
    async fn bind_side(
        &mut self,
        main: &Self::Send,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<Option<(Self::Send, Self::Recv)>> {
        if params.addr.is_some() || params.port != self.port {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let Some((send, receive)) = UdpSocketFactory::default().bind_side(main, params).await?
        else {
            return Ok(None);
        };
        Ok(Some((
            send,
            PeerAdmissionUdpReceiver::new(receive, Arc::clone(&self.admission)),
        )))
    }
}

/// What the worker thread reports about its running engine: the TUN, the bound port, the
/// offload state and the direct-path probes of that port.
#[derive(Clone)]
pub(crate) struct RuntimeInfo {
    interface: String,
    port: u16,
    thp_disabled: bool,
    offloads_enabled: bool,
    /// The direct-path probes of the bound port and where their finished answers wait for the
    /// path owner (see [`Engine::direct_probes`]). `None` in the tests that build no socket.
    #[cfg_attr(
        not(feature = "relay"),
        expect(dead_code, reason = "only the relay path owner reads the probes")
    )]
    probes: Option<(DirectProbes, ProbeAnswers)>,
}

/// The finished direct-path probes, held until the path owner takes them once.
pub(crate) type ProbeAnswers =
    Arc<std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<crate::direct_probe::Answer>>>>;

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
    SetOwner {
        /// Public key already committed to the shared TUN owner marker.
        owner: PublicKey,
        reply: sync::SyncSender<io::Result<()>>,
    },
    Counters(sync::SyncSender<io::Result<CounterMap>>),
    /// Read the installed keys for reconciliation without touching per-peer statistics.
    PeerKeys(sync::SyncSender<Vec<PublicKey>>),
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
    /// `underlay_announce` is woken by the node's route listener; each announcement sends one
    /// keepalive to every peer with a live session (#483).
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
        underlay_announce: Arc<UnderlayAnnounce>,
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
                    walks: Walks::default(),
                    relayed: BTreeMap::new(),
                };
                runtime.block_on(run_worker(
                    receiver,
                    state,
                    worker_refresh,
                    route_endpoint_updater,
                    underlay_announce,
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

    /// The direct-path probes of this engine's `WireGuard` port, and the receiver of their finished
    /// answers. The receiver can be taken once; a second call returns the probes only.
    #[cfg_attr(
        not(feature = "relay"),
        expect(dead_code, reason = "only the relay path owner asks for the probes")
    )]
    #[must_use]
    pub(crate) fn direct_probes(
        &self,
    ) -> Option<(
        DirectProbes,
        Option<tokio::sync::mpsc::Receiver<crate::direct_probe::Answer>>,
    )> {
        let (probes, answers) = self.info.probes.as_ref()?;
        let taken = answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        Some((probes.clone(), taken))
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

    /// Let the packet filter forward for this node's served networks, or stop it (D197 M3); see
    /// [`PacketFilter::set_forwarding`].
    pub(crate) fn set_forwarding(&self, on: bool) {
        self.filter.set_forwarding(on);
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

    /// Update the TUN owner's proof after the node commits a rotated interface marker.
    /// # Errors
    /// Reports a stopped worker that can no longer update its cloned TUN handles.
    pub(crate) fn set_owner(&self, owner: PublicKey) -> io::Result<()> {
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::SetOwner { owner, reply })
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

    /// Read actual device membership, including either key of a rotating peer.
    /// # Errors
    /// Reports a stopped worker.
    pub(crate) fn peer_keys(&self) -> io::Result<Vec<PublicKey>> {
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::PeerKeys(reply))
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        result.recv().map_err(|_| io::ErrorKind::BrokenPipe.into())
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
    let probes = Some((factory.probes.clone(), Arc::clone(&factory.probe_answers)));
    let pending = Some(PendingDevice {
        factory,
        private_key,
    });
    let info = RuntimeInfo {
        interface,
        port,
        thp_disabled,
        offloads_enabled,
        probes,
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

/// Most worker threads the engine runtime uses. `GotaTun` runs its receive path (UDP receive,
/// decryption, TUN write) and its send path (TUN read, encryption, UDP send) as two tasks, each
/// writing to an idle device itself and queueing only behind a busy one (#260, J1122); bulk
/// crypto runs on its own worker threads. On one thread the two paths would take turns (#260
/// R4b). The bound keeps a large host from giving the mesh every core.
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

/// Everything the engine worker owns: the TUN, the live device, its rebuild material, the applied
/// configuration and each peer's candidate walk (#515).
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
    /// Each peer's walk through its direct-path candidates (#515), by the key that owns its
    /// endpoint, with the peer it was started for: a re-installed peer starts a new walk.
    walks: Walks,
    /// The relay address each relayed peer was last pointed at, by device key (J699 P3-1).
    /// While the engine sends a peer's packets there (or nowhere, mid-preparation), no walk runs
    /// for it and a re-install keeps it there ([`on_relay`], [`kept_address`]): D391 makes the
    /// relay the fallback once direct paths failed, and moving back to a direct path is the
    /// relay controller's decision. Only relay builds fill it; an entry goes when its peer
    /// leaves the configuration.
    relayed: BTreeMap<PublicKey, SocketAddr>,
}

/// Whether a peer sits on its relay: the worker pointed it at `relay`, and the engine still
/// sends there, or nowhere because the relay is preparing its handshake (J699 P3-1).
fn on_relay(engine_at: Option<SocketAddr>, relay: Option<SocketAddr>) -> bool {
    relay.is_some() && (engine_at.is_none() || engine_at == relay)
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

/// What the candidate walks need from the engine's counters ([`crate::candidate_walks::observe`]).
fn observed(counters: &CounterMap) -> Observed {
    let unix = crate::candidate_walks::unix_now();
    counters
        .iter()
        .map(|(key, stats)| {
            let seen = crate::candidate_walks::observe(
                stats.received_bytes,
                stats.handshake_secs,
                stats.endpoint,
                unix,
            );
            (*key, seen)
        })
        .collect()
}

/// Runs device commands, relay operations, coalesced endpoint work, candidate walks and recovery.
///
/// The bounded scan reads confirmed endpoints. A candidate walk changes where we send, but the
/// peer route follows only after an authenticated packet confirms the new address. The route
/// listener requests a keepalive for each live session when our own underlay changes.
async fn run_worker(
    mut commands: UnboundedReceiver<WorkerCommand>,
    mut state: RuntimeState,
    endpoint_refresh: Arc<EndpointRefreshSignal>,
    route_endpoint_updater: RouteEndpointUpdater,
    underlay_announce: Arc<UnderlayAnnounce>,
) {
    let mut announcements = AnnouncementWaiter::new(underlay_announce);
    let mut endpoint_refresh_schedule = CoalescedSchedule::default();
    // The endpoint scan runs only on a reason to: `GotaTun` reports a changed confirmed
    // endpoint, the receive path saw a source it has not confirmed, or something rebuilt the
    // engine's peers. There is no timer: an idle node costs no wakeup for it (D81, #260 J1253).
    let sources = match state.pending.as_ref() {
        Some(pending) => pending.factory.admission.read().await.sources(),
        None => Arc::default(),
    };
    let mut scan_schedule = CoalescedSchedule::default();
    sources.wake.request();
    let mut observed_endpoints = Some(state.configured_peer_endpoint_snapshot());
    // A restored configuration may already carry candidates; no session predates it.
    state.refresh_walks(&BTreeMap::new()).await;
    // Hands the peers' confirmed endpoints to the admission guard's reserve on a change.
    let mut confirmed_feed = ConfirmedEndpointFeed::default();
    loop {
        let next_walk = state.walks.next_due();
        // The running engine's change signal; a rebuilt engine brings its own, and the rebuild
        // asks for a scan itself.
        let confirmed = state
            .device
            .as_ref()
            .map(|device| device.confirmed_endpoint_changes());
        tokio::select! {
            command = commands.recv() => match command {
                Some(WorkerCommand::Apply { config, reply }) => {
                    let before = state.engine_addresses(&config).await;
                    let result = state.apply(*config, &before).await;
                    let applied = result.is_ok();
                    if applied {
                        observed_endpoints = Some(state.configured_peer_endpoint_snapshot());
                    }
                    let _ = reply.send(result);
                    sources.wake.request();
                    // After the reply: a walk reads the counters once, off the apply path.
                    if applied {
                        state.refresh_walks(&before).await;
                    }
                }
                Some(WorkerCommand::SetMtu { mtu, reply }) => {
                    let _ = reply.send(state.update_mtu(mtu));
                }
                Some(WorkerCommand::SetPrivateKey { private_key, reply }) => {
                    let _ = reply.send(state.set_private_key(private_key).await);
                }
                Some(WorkerCommand::SetOwner { owner, reply }) => {
                    let _ = reply.send(state.set_owner(owner));
                }
                Some(WorkerCommand::PeerKeys(reply)) => {
                    let _ = reply.send(state.peer_keys().await);
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
            () = endpoint_refresh.notified(), if !endpoint_refresh_schedule.is_armed() => {
                endpoint_refresh_schedule.arm(Instant::now());
            }
            () = endpoint_refresh_schedule.wait() => {
                endpoint_refresh_schedule.start();
                endpoint_refresh.begin_refresh();
                match state.refresh_live_peer_endpoints(&route_endpoint_updater).await {
                    Ok(endpoints) => {
                        // Traffic-driven refreshes read every peer anyway; the guard's list
                        // follows for free instead of waiting for the next scan.
                        state
                            .admit_confirmed_endpoints(&mut confirmed_feed, &endpoints)
                            .await;
                        observed_endpoints = Some(endpoints);
                    }
                    Err(error) => tracing::warn!(error = %error, "could not refresh mesh routes from live peer endpoints"),
                }
                endpoint_refresh_schedule.finish(Instant::now());
            }
            () = sources.wake.notified(), if !scan_schedule.is_armed() => {
                scan_schedule.arm(Instant::now());
            }
            () = confirmed_changed(confirmed), if !scan_schedule.is_armed() => {
                scan_schedule.arm(Instant::now());
            }
            () = scan_schedule.wait() => {
                scan_schedule.start();
                sources.wake.begin();
                scan_endpoints(&state, &mut confirmed_feed, &mut observed_endpoints, &endpoint_refresh).await;
                scan_schedule.finish(Instant::now());
            }
            () = announcements.next() => {
                if let Some(device) = &state.device {
                    let sessions = device.request_keepalives().await;
                    tracing::debug!(sessions, "underlay changed; live sessions announce our endpoint");
                }
            }
            // Reap finished handshake tasks; their result is visible in the peer counters.
            Some(_) = state.handshakes.join_next(), if !state.handshakes.is_empty() => {}
            // A packet task that ends on an error ends that direction of traffic for good while
            // the node still looks up (#260 J143 P2-1). Stop the device and rebuild it.
            () = fatal_error(state.device.as_mut()), if state.handshakes.is_empty() => {
                state.engine_stopped().await;
                sources.wake.request();
            }
            () = restart_due(state.restart_at), if state.restart_at.is_some() => {
                state.restart().await;
                sources.wake.request();
            }
            () = crate::candidate_walks::walk_due(next_walk), if next_walk.is_some() => {
                state.step_walks().await;
                // A walk moves where we send; the answer may come from an address that is
                // already confirmed for another peer, which the receive path cannot tell apart.
                sources.wake.request();
            }
        }
    }
}

/// One endpoint scan: read the peers' confirmed endpoints, hand them to the admission guard, and
/// ask for a route refresh when they differ from the last snapshot the routes were derived from.
async fn scan_endpoints(
    state: &RuntimeState,
    feed: &mut ConfirmedEndpointFeed,
    observed_endpoints: &mut Option<BTreeMap<PublicKey, Option<SocketAddr>>>,
    endpoint_refresh: &EndpointRefreshSignal,
) {
    let endpoints = state.live_peer_endpoint_snapshot().await;
    state.admit_confirmed_endpoints(feed, &endpoints).await;
    let changed = observed_endpoints
        .as_ref()
        .is_some_and(|previous| previous != &endpoints);
    if changed {
        endpoint_refresh.endpoint_changed();
    } else if observed_endpoints.is_none() {
        *observed_endpoints = Some(endpoints);
    }
}

impl RuntimeState {
    /// Give the admission guard the peers' confirmed endpoints through `feed`, so those exact
    /// sources keep the guard's reserved budget under a flood.
    ///
    /// Runs on every endpoint scan. The shared feed takes the guard's write lock only on a
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
    /// When a peer has no proof from a live session, routes use the coordinator's endpoint.
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

    /// Replace the creation-time key used to prove ownership of every cloned TUN handle.
    ///
    /// The node calls this only after the live link marker names the committed key.
    /// # Errors
    /// Reports an engine runtime that no longer owns a TUN.
    fn set_owner(&self, owner: PublicKey) -> io::Result<()> {
        self.tun
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .set_owner(owner);
        Ok(())
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

    /// Install `endpoint` on the peer whose key currently owns its host routes: a relay address,
    /// or the next direct-path candidate of a walk (#515). Keys, routes and keepalive stay as the
    /// configuration says; only the address the next packet goes to changes. Check a candidate
    /// inside an approved subnet against its current kernel route before installing it.
    async fn set_endpoint(&mut self, key: PublicKey, endpoint: SocketAddr) -> io::Result<()> {
        let address = endpoint.ip().to_canonical();
        if self.config.as_ref().is_some_and(|config| {
            config.peers.values().any(|peer| {
                peer.networks.through.iter().any(|route| {
                    route.network.contains(address)
                        && route.outbound != crate::policy::rules::TrafficPolicy::None
                })
            })
        }) && tokio::task::spawn_blocking(move || crate::wireguard::is_tunnel_endpoint(address))
            .await
            .map_err(io::Error::other)??
        {
            // A walk can still remember an old endpoint after its exception was withdrawn.
            return Err(io::ErrorKind::AddrInUse.into());
        }
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
            .map_err(|_| io::Error::other("GotaTun peer endpoint could not be installed."))
    }

    /// Bring the candidate walks in line with the applied configuration (#515): drop walks whose
    /// peer left, start one for each peer that is new or changed, and start again for a peer
    /// whose walk once found it and whose path has since gone silent.
    ///
    /// A peer that is unchanged keeps its walk, finished or not (J585 F4). `apply` re-installs a
    /// peer, and with it the first candidate, only when the peer itself changed, so an unrelated
    /// snapshot never sends a working peer back through its list. `before` holds where the engine
    /// sent each peer's packets before that apply ([`Self::engine_addresses`]). A re-installed
    /// peer's live session proves its first candidate only if the engine was already there: after
    /// a change to the rest of its list, the session may live on a later candidate (J602 F1).
    /// `apply` keeps the engine on a candidate the new list still holds (J699 P3-3), or on a
    /// recent authenticated endpoint even if the snapshot dropped it (#483), and moves it to
    /// the first candidate otherwise.
    ///
    /// A relayed peer gets no walk while the engine sends to its relay (J699 P3-1, [`on_relay`]).
    ///
    /// Each walk that starts running begins with a real handshake on its address
    /// ([`Self::rehandshake_all`]); a walk that starts finished sends nothing.
    ///
    /// Cost: at most one counter read per applied snapshot, on the worker after the apply reply;
    /// [`Self::engine_addresses`] adds one before the apply when the snapshot changes any
    /// installed peer (#483, J1025). No timer runs for a finished walk, so an idle node stays idle
    /// (D81). Known follow-up (J699 P3-2, D393): once any walk has found its peer, `watching` is
    /// true, so every applied snapshot reads every peer's counters, an O(peers) read not yet
    /// measured at 1,000 and 4,096 peers. #515 holds the measurement plan; a per-walk "earliest
    /// silent deadline" would skip the read until a found walk can actually have gone silent.
    async fn refresh_walks(&mut self, before: &BTreeMap<PublicKey, EngineEndpoint>) {
        let Some(config) = self.config.as_ref() else {
            self.walks.clear();
            self.relayed.clear();
            return;
        };
        let members: BTreeSet<PublicKey> = config
            .peers
            .values()
            .map(|policy| active_peer_key(&policy.peer))
            .collect();
        self.relayed.retain(|key, _| members.contains(key));
        // `walking_peers` keeps only peers with network access, the ones `peers_for_config`
        // installs.
        let mut wanted = crate::candidate_walks::walking_peers(config.peers.values());
        if !self.walks.prepare(&wanted) {
            return;
        }
        let Ok(counters) = self.counters().await else {
            return;
        };
        let observed = observed(&counters);
        // A relayed peer is not walked off its relay (J699 P3-1).
        wanted.retain(|key, _| {
            let engine_at = observed.get(key).and_then(|seen| seen.endpoint);
            let relayed = on_relay(engine_at, self.relayed.get(key).copied());
            if relayed {
                self.walks.abandon(*key);
            }
            !relayed
        });
        let started = self
            .walks
            .start(wanted, &observed, before, std::time::Instant::now());
        // A walk starts on the engine's address when that is on the list (J602 F2), else on the
        // first candidate, which a re-installed peer already has. Anything else is moved there,
        // or the walk's first tick would read the engine's address as the peer having roamed.
        // Then the walk's address gets a real handshake, so a working one answers at once.
        let mut moved = Vec::with_capacity(started.len());
        for walk in started {
            if walk.engine_at != Some(walk.address)
                && self.set_endpoint(walk.key, walk.address).await.is_err()
            {
                // The engine could not be moved; the next applied snapshot starts the walk again.
                self.walks.abandon(walk.key);
                continue;
            }
            moved.push(walk.key);
        }
        let _ = self.rehandshake_all(moved);
    }

    /// Each peer's send and recent confirmed endpoints before `next` is applied, by device key,
    /// for [`Self::refresh_walks`] (J602 F1).
    ///
    /// Read whenever `next` changes any installed peer: `apply` rewrites a changed peer whole and
    /// can keep its address only from this read ([`kept_address`]). Every other snapshot reads
    /// nothing here.
    async fn engine_addresses(&self, next: &Config) -> BTreeMap<PublicKey, EngineEndpoint> {
        if !crate::candidate_walks::engine_read_needed(self.config.as_ref(), next) {
            return BTreeMap::new();
        }
        let Some(device) = self.device.as_ref() else {
            return BTreeMap::new();
        };
        device
            .read(async |read| read.peers().await)
            .await
            .into_iter()
            .filter(|peer| !peer.peer.allowed_ips.is_empty())
            .map(|peer| {
                let key = PublicKey(*peer.peer.public_key.as_bytes());
                let endpoint = engine_endpoint(
                    peer.peer.endpoint,
                    peer.stats.confirmed_endpoint,
                    peer.stats.last_handshake,
                );
                (key, endpoint)
            })
            .collect()
    }

    /// Step every due walk with the peers' counters and install the addresses they move to. A
    /// stopped device has no counters to judge by, so nothing moves until it is back.
    async fn step_walks(&mut self) {
        if self.device.is_none() {
            return;
        }
        let Ok(counters) = self.counters().await else {
            return;
        };
        let moves = self
            .walks
            .step(std::time::Instant::now(), &observed(&counters));
        let mut installed = Vec::with_capacity(moves.len());
        for (key, endpoint) in moves {
            match self.set_endpoint(key, endpoint).await {
                Ok(()) => installed.push(key),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => self.walks.abandon(key),
                // The engine still holds the old address; the walk's next step tries again.
                Err(_) => self.walks.install_failed(key),
            }
        }
        let _ = self.rehandshake_all(installed);
    }

    /// Prepare a peer for relayed traffic while preserving any session it already established.
    #[cfg(feature = "relay")]
    async fn prepare_handshake(&mut self, key: PublicKey, endpoint: SocketAddr) -> io::Result<()> {
        // From here the relay owns this peer's address: no walk moves it (J699 P3-1).
        self.walks.abandon(key);
        self.relayed.insert(key, endpoint);
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

    /// Point `key` at a relay `endpoint` and start a handshake through it at once.
    #[cfg(feature = "relay")]
    async fn force_handshake(&mut self, key: PublicKey, endpoint: SocketAddr) -> io::Result<()> {
        self.walks.abandon(key);
        self.relayed.insert(key, endpoint);
        self.set_endpoint(key, endpoint).await?;
        self.initiate(key)
    }

    /// Send a handshake initiation to `key`'s current address now, unless it has a live session
    /// or an initiation is already in flight, without waiting for it. Only the relay path uses it.
    #[cfg(feature = "relay")]
    fn initiate(&mut self, key: PublicKey) -> io::Result<()> {
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

    /// Send a new handshake initiation to each of `keys` at its current address now, even over a
    /// live session, without waiting for any answer (#515, J604; #260, J1253).
    ///
    /// A new address on a peer sends nothing by itself: the engine only uses it for the next
    /// packet, and an idle peer has none for up to a keepalive interval. Behind a filtering NAT
    /// that first packet is what opens this side for the peer's replies, so a changed or walked
    /// address starts a handshake at once. `initiate` cannot do it: the engine's forced
    /// handshake sends nothing while the session is younger than two minutes, which is exactly
    /// the rebind case (J587's finding). The engine's `rehandshake_all` sends the initiation its
    /// rekey retry would send, and keeps each session carrying data until the new one is up, so
    /// a working session is never dropped. An unanswered initiation is retried by the engine's
    /// own rekey timer, to wherever the endpoint is by then; nothing new is scheduled here.
    ///
    /// One task sends them all: a waiting task and deadline per peer woke an idle node hundreds
    /// of times a second while it walked thousands of unreachable peers (J1253, D81). The task
    /// only keeps this serialized loop free while the sends queue.
    fn rehandshake_all(&mut self, keys: Vec<PublicKey>) -> io::Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        let device = Arc::clone(self.device.as_ref().ok_or(io::ErrorKind::NotConnected)?);
        let keys: Vec<_> = keys
            .into_iter()
            .map(|key| X25519PublicKey::from(key.0))
            .collect();
        self.handshakes.spawn(async move {
            let _ = tokio::time::timeout(HANDSHAKE_WAIT, device.rehandshake_all(&keys)).await;
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
    async fn apply(
        &mut self,
        config: Config,
        before: &BTreeMap<PublicKey, EngineEndpoint>,
    ) -> io::Result<RuntimeInfo> {
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
        // Re-installed peers that stay where the engine already sends ([`kept_address`]).
        let mut kept = BTreeSet::new();
        let changed_policies = config
            .peers
            .iter()
            .filter(|(id, policy)| {
                policy.has_network_access()
                    && self
                        .config
                        .as_ref()
                        .and_then(|old| old.peers.get(id))
                        .is_none_or(|old| {
                            !old.has_network_access()
                                || old.peer != policy.peer
                                // Networks behind the peer are its allowed IPs too (D197 M3).
                                || old.networks.through != policy.networks.through
                        })
            })
            .map(|(_, policy)| {
                let mut peers = peer_for_policy(policy)?;
                let key = active_peer_key(&policy.peer);
                let engine_at = before.get(&key).copied().unwrap_or_default();
                let relay = self.relayed.get(&key).copied();
                if let Some(at) = kept_address(&policy.peer, engine_at, relay)
                    && let Some(active) = peers
                        .iter_mut()
                        .find(|peer| peer.public_key.as_bytes() == &key.0)
                {
                    active.endpoint = Some(at);
                    kept.insert(key);
                }
                Ok(peers)
            })
            .collect::<io::Result<Vec<_>>>()?;
        let changed: Vec<_> = changed_policies.into_iter().flatten().collect();
        // Peers that keep their access but get a new first address: tell them at once
        // (`rehandshake_all`, which sends even over the live session the old address carried). A peer
        // with candidates gets that handshake when its new walk starts (`refresh_walks`).
        let readdressed: Vec<PublicKey> = config
            .peers
            .iter()
            .filter(|(id, policy)| {
                policy.has_network_access()
                    && policy.peer.endpoint.is_some()
                    && policy.peer.candidates.is_empty()
                    && self
                        .config
                        .as_ref()
                        .and_then(|old| old.peers.get(id))
                        .is_some_and(|old| {
                            old.has_network_access() && old.peer.endpoint != policy.peer.endpoint
                        })
            })
            .map(|(_, policy)| active_peer_key(&policy.peer))
            .filter(|key| !kept.contains(key))
            .collect();
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
            // `add_or_update_peers` overwrites every field of a changed peer, including the
            // endpoint. `kept_address` preserves a listed walk address, a relay, or a recent
            // authenticated endpoint so a stale snapshot cannot undo a NAT roam (#483).
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
        let _ = self.rehandshake_all(readdressed);
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

    /// List the live device's keys. A worker waiting to rebuild has no installed peers.
    async fn peer_keys(&self) -> Vec<PublicKey> {
        let Some(device) = self.device.as_ref() else {
            return Vec::new();
        };
        device
            .read(async |read| {
                read.peer_keys()
                    .map(|key| PublicKey(*key.as_bytes()))
                    .collect()
            })
            .await
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

    /// Stop the device and drop the TUN, the configuration and every walk.
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
        self.walks.clear();
        self.relayed.clear();
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
        .with_side_socket(crate::side_socket::enabled())
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
        ..UdpSocketFactory::default()
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
                    BoundUdpFactory::with_probes(send, receive, port, Arc::clone(&admission)).await,
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
                BoundUdpFactory::with_probes(send, receive, port, Arc::clone(&admission)).await,
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

    /// Change the owner proof shared by the packet device and the worker's control handle.
    fn set_owner(&self, owner: PublicKey) {
        self.tun.set_owner(owner);
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

    /// Filter and hook each packet of a decrypted run as [`IpSend::send`] does, then hand the
    /// survivors to the TUN as one run, so it can merge them into GSO frames and write them
    /// in this task (#260, J1122). `packets` is empty afterwards.
    async fn send_many(&mut self, packets: &mut Vec<Packet<Ip>>) -> io::Result<()> {
        let mut kept = Vec::with_capacity(packets.len());
        for packet in packets.drain(..) {
            let Some(packet) = filter_ip_packet(packet, &self.filter, Direction::MeshToHost) else {
                continue;
            };
            if let Some(packet) = self.local_service_hook(packet)? {
                kept.push(packet);
            }
        }
        self.tun.send_many(&mut kept).await
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

/// Convert one configured peer to its `GotaTun` identities, and decide whether small datagrams to
/// it may leave from the device's second socket (#260, J1211).
///
/// That is only for a peer whose own node advertised the side-mark receive rule through the
/// coordinator (`Peer::side_port`), and only while this node's switch is on. Everything else,
/// including every peer of a mesh whose coordinator never heard the capability, gets an explicit
/// `false`, so no mark is ever sent to a peer that did not say it takes them (kernel `WireGuard`
/// and plain `GotaTun` drop marked packets).
/// # Errors
/// Rejects invalid host routes before they reach the userspace device.
fn peer_for_policy(policy: &crate::dataplane::PeerPolicy) -> io::Result<Vec<WireGuardPeer>> {
    peer_for_policy_with(policy, crate::side_socket::enabled())
}

/// [`peer_for_policy`] with this node's side-socket switch given, so tests can set it.
/// # Errors
/// Rejects invalid host routes before they reach the userspace device.
fn peer_for_policy_with(
    policy: &crate::dataplane::PeerPolicy,
    side_socket: bool,
) -> io::Result<Vec<WireGuardPeer>> {
    let side_port = side_socket && policy.peer.side_port;
    let mut peers = identities_for_policy(policy)?;
    for peer in &mut peers {
        peer.side_port = Some(side_port);
    }
    Ok(peers)
}

/// Convert each configured peer to one live identity or its journaled overlap pair.
///
/// Only the active identity owns allowed IPs and the endpoint, so the second identity can accept
/// a handshake during overlap without stealing routes or initiating a competing path.
/// # Errors
/// Rejects invalid host routes before they reach the userspace device.
fn identities_for_policy(policy: &crate::dataplane::PeerPolicy) -> io::Result<Vec<WireGuardPeer>> {
    let peer = &policy.peer;
    let mut addresses = peer
        .routed_addresses()
        .map(|address| {
            IpNetwork::new(address, if address.is_ipv4() { 32 } else { 128 })
                .map_err(|_| io::ErrorKind::InvalidData.into())
        })
        .collect::<io::Result<Vec<_>>>()?;
    // Networks behind this router peer (D197 M3): the device sends packets for them to the peer
    // and accepts replies from their hosts only from it. The packet filter still decides which
    // flows may start.
    for network in &policy.networks.through {
        addresses.push(
            IpNetwork::new(network.network.address(), network.network.prefix())
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
        );
    }
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

/// The networks each router peer carries in its allowed IPs (D197 M3), so a change to them
/// reconfigures the device even when the set of installed peers stays the same.
pub(crate) fn networks_behind_peers(
    config: &Config,
) -> BTreeMap<crate::policy::model::NodeId, Vec<infraternal_mesh::networks::Network>> {
    config
        .peers
        .iter()
        .filter(|(_, peer)| !peer.networks.through.is_empty())
        .map(|(id, peer)| {
            (
                *id,
                peer.networks
                    .through
                    .iter()
                    .map(|network| network.network)
                    .collect(),
            )
        })
        .collect()
}

/// Return identities whose effective network access permits traffic in at least one direction.
fn admitted_peer_keys(config: &Config) -> BTreeSet<PublicKey> {
    peer_keys_with_network_access(config)
}

/// Turn a stored 32-byte private key into the engine's secret and this node's public key.
///
/// The raw bytes are copied into a zeroizing buffer, so the copy made for the conversion is
/// wiped when it drops.
/// # Errors
/// Returns `InvalidData` when `bytes` is not exactly 32 bytes long.
pub(crate) fn secret_from_bytes(bytes: &[u8]) -> io::Result<(StaticSecret, PublicKey)> {
    let raw: [u8; 32] = bytes.try_into().map_err(|_| io::ErrorKind::InvalidData)?;
    let raw = zeroize::Zeroizing::new(raw);
    let secret = StaticSecret::from(*raw);
    let public = X25519PublicKey::from(&secret);
    Ok((secret, PublicKey(*public.as_bytes())))
}

/// Checks the two rules that keep a peer where the engine already sends (J699 P3-1, P3-3).
#[cfg(test)]
mod keep_tests {
    #![allow(clippy::expect_used)]
    use super::{kept_address, on_relay};
    use crate::candidate_walks::EngineEndpoint;
    use crate::{
        dataplane::Peer,
        policy::model::{Addresses, PublicKey},
    };
    use std::net::SocketAddr;

    /// Parse a fixture socket address.
    fn at(address: &str) -> SocketAddr {
        address.parse().expect("fixture address")
    }

    /// A walking peer whose list is `first` then `rest`.
    fn walking(first: &str, rest: &[&str]) -> Peer {
        Peer {
            key: PublicKey([3; 32]),
            previous_key: None,
            previous_active: false,
            addresses: Addresses {
                ipv4: "10.254.0.1".parse().expect("peer IPv4"),
                ipv6: "fd01::1".parse().expect("peer IPv6"),
            },
            endpoint: Some(at(first)),
            candidates: rest.iter().map(|address| at(address)).collect(),
            ipv4_only: false,
            side_port: false,
        }
    }

    /// J699 P3-1: a peer on its relay (or mid-preparation, with no address) is not walked; one
    /// the engine has moved elsewhere, or never relayed, is.
    #[test]
    fn a_relayed_peer_is_on_its_relay_until_the_engine_leaves_it() {
        let relay = Some(at("127.0.0.1:40000"));
        assert!(on_relay(relay, relay));
        assert!(on_relay(None, relay), "preparing the relayed handshake");
        assert!(!on_relay(Some(at("192.0.2.2:10254")), relay));
        assert!(!on_relay(Some(at("192.0.2.2:10254")), None));
        assert!(!on_relay(None, None));
    }

    /// J699 P3-1: a re-install keeps a relayed peer on its relay, which no list ever holds.
    #[test]
    fn a_reinstall_keeps_a_relayed_peer_on_its_relay() {
        let relay = at("127.0.0.1:40000");
        let peer = walking("192.0.2.2:10254", &["198.51.100.2:10254"]);
        let engine = EngineEndpoint {
            send: Some(relay),
            ..EngineEndpoint::default()
        };
        assert_eq!(kept_address(&peer, engine, Some(relay)), Some(relay));
        let single = walking("192.0.2.2:10254", &[]);
        assert_eq!(kept_address(&single, engine, Some(relay)), Some(relay));
    }

    /// J699 P3-3: a re-install keeps a walking peer on an address its new list still holds, and
    /// takes the snapshot's first address when the list dropped the engine's or has one entry.
    #[test]
    fn a_reinstall_keeps_a_found_address_the_list_still_holds() {
        let peer = walking("10.0.0.2:10254", &["198.51.100.2:10254", "198.51.100.2:9"]);
        let found = at("198.51.100.2:10254");
        assert_eq!(
            kept_address(
                &peer,
                EngineEndpoint {
                    send: Some(found),
                    ..EngineEndpoint::default()
                },
                None,
            ),
            Some(found)
        );
        assert_eq!(
            kept_address(
                &peer,
                EngineEndpoint {
                    send: Some(at("203.0.113.1:1")),
                    ..EngineEndpoint::default()
                },
                None,
            ),
            None
        );
        assert_eq!(kept_address(&peer, EngineEndpoint::default(), None), None);
        let single = walking("10.0.0.2:10254", &[]);
        assert_eq!(
            kept_address(
                &single,
                EngineEndpoint {
                    send: Some(at("203.0.113.1:1")),
                    ..EngineEndpoint::default()
                },
                None,
            ),
            None
        );
    }
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

    /// A peer is opted in to the second socket only when its node advertised the capability and this
    /// node's own switch is on (#260, J1211); every other peer, including both rotation identities of
    /// one, gets an explicit "no", so the engine never marks a datagram to a peer that did not say it
    /// takes them (kernel `WireGuard` and plain `GotaTun` drop marked packets).
    #[test]
    fn only_advertising_peers_are_opted_in_while_the_switch_is_on() {
        let mut config = one_peer_config(None);
        let policy = config.peers.get_mut(&NodeId(1)).expect("the peer");
        let opted = |policy: &PeerPolicy, on: bool| -> Vec<Option<bool>> {
            super::peer_for_policy_with(policy, on)
                .expect("peer")
                .iter()
                .map(|peer| peer.side_port)
                .collect()
        };
        assert_eq!(
            opted(policy, true),
            [Some(false)],
            "no advertisement, no mark"
        );
        assert_eq!(opted(policy, false), [Some(false)]);
        policy.peer.side_port = true;
        assert_eq!(opted(policy, true), [Some(true)], "advertised and on");
        assert_eq!(
            opted(policy, false),
            [Some(false)],
            "this node's switch off beats the advertisement"
        );
        // Both identities of a peer mid-rotation follow the same rule.
        policy.peer.previous_key = Some(PublicKey([9; 32]));
        assert_eq!(opted(policy, true), [Some(true), Some(true)]);
        policy.peer.side_port = false;
        assert_eq!(opted(policy, true), [Some(false), Some(false)]);
    }

    /// The engine's socket factory binds the second socket on its own port with the admission guard
    /// on its receive half, and never on a different mesh port than asked (#260, J1211).
    #[tokio::test]
    async fn the_factory_binds_a_second_socket_beside_the_mesh_port() {
        use gotatun::{
            udp::{UdpTransportFactory, UdpTransportFactoryParams},
            x25519::StaticSecret,
        };
        let (mut factory, port) = super::bind_udp(
            Request {
                port: 0,
                allow_fallback: true,
            },
            StaticSecret::from([4; 32]),
        )
        .await
        .expect("bound engine socket");
        let params = UdpTransportFactoryParams {
            addr: None,
            port,
            fwmark: None,
        };
        let (main, _receiver) = factory.bind(&params).await.expect("main sockets");
        let (side, _side_receiver) = factory
            .bind_side(&main, &params)
            .await
            .expect("side socket binds")
            .expect("the engine factory has a second socket");
        let side_port = side.local_addr().expect("side address").port();
        assert_ne!(side_port, 0);
        assert_ne!(side_port, port, "its own port");
        let wrong = UdpTransportFactoryParams {
            port: port.wrapping_add(1),
            ..params
        };
        assert!(factory.bind_side(&main, &wrong).await.is_err());
    }

    /// The event bits of every epoll registration, in this process, of the file behind
    /// `socket`: one per registered descriptor, read from `/proc/self/fdinfo`.
    fn epoll_registrations(socket: &impl std::os::fd::AsFd) -> Vec<u32> {
        use std::os::fd::AsRawFd;
        let name = |fd: i32| std::fs::read_link(format!("/proc/self/fd/{fd}")).ok();
        let wanted = name(socket.as_fd().as_raw_fd()).expect("the socket's own name");
        // tokio holds more than one descriptor of its epoll instance, and each one lists every
        // registration: keyed by registered descriptor, they count once.
        let mut found = BTreeMap::new();
        for entry in std::fs::read_dir("/proc/self/fd").expect("descriptor list") {
            let Some(fd) = entry
                .ok()
                .and_then(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
            else {
                continue;
            };
            if name(fd).is_none_or(|link| link.as_os_str() != "anon_inode:[eventpoll]") {
                continue;
            }
            // Another test may close its descriptor between the two reads.
            let Ok(info) = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")) else {
                continue;
            };
            // One line per registration: `tfd: <fd> events: <hex> ...`.
            for line in info.lines() {
                let mut words = line.split_whitespace();
                if words.next() != Some("tfd:") {
                    continue;
                }
                let target: i32 = words.next().and_then(|fd| fd.parse().ok()).expect("tfd");
                assert_eq!(words.next(), Some("events:"), "fdinfo format: {line}");
                let events =
                    u32::from_str_radix(words.next().expect("events"), 16).expect("hex events");
                if name(target).as_ref() == Some(&wanted) {
                    found.insert(target, events);
                }
            }
        }
        found.into_values().collect()
    }

    /// The mesh sockets are registered with the runtime for readability only (#260, J1255, D81).
    ///
    /// A write registration turns every datagram the kernel frees into a wakeup of the parked
    /// engine worker: 82-94% of an idle hub's wakeups (J1253). The engine watches writability
    /// only while a send is blocked. This pins that for the main and the side socket, so an
    /// engine pin that brings the write registration back fails here.
    #[tokio::test]
    async fn mesh_sockets_are_registered_for_readability_only() {
        use gotatun::{
            udp::{UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
            x25519::StaticSecret,
        };
        /// `EPOLLIN` and `EPOLLOUT` of the Linux epoll ABI, as `fdinfo` prints them.
        const EPOLL_IN: u32 = 0x001;
        const EPOLL_OUT: u32 = 0x004;
        let (mut factory, port) = super::bind_udp(
            Request {
                port: 0,
                allow_fallback: true,
            },
            StaticSecret::from([5; 32]),
        )
        .await
        .expect("bound engine socket");
        let params = UdpTransportFactoryParams {
            addr: None,
            port,
            fwmark: None,
        };
        let (main, _receiver) = factory.bind(&params).await.expect("main sockets");
        let (side, _side_receiver) = factory
            .bind_side(&main, &params)
            .await
            .expect("side socket binds")
            .expect("the engine factory has a second socket");
        for (label, socket) in [("main", &main), ("side", &side)] {
            // A send that does not block must not add a writability watch either.
            let sink = std::net::UdpSocket::bind("127.0.0.1:0").expect("loopback sink");
            let pool = gotatun::packet::PacketBufPool::<64>::new(1);
            let mut packet = pool.get();
            packet.truncate(1);
            socket
                .send_to(packet, sink.local_addr().expect("sink address"))
                .await
                .expect("send");
            let masks = epoll_registrations(socket);
            assert_eq!(masks.len(), 1, "{label}: one registration: {masks:x?}");
            assert_ne!(masks[0] & EPOLL_IN, 0, "{label} reads: {masks:x?}");
            assert_eq!(
                masks[0] & EPOLL_OUT,
                0,
                "{label} socket is watched for writability: {masks:x?}"
            );
        }
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
        assert!(
            !signal
                .wake
                .pending
                .load(std::sync::atomic::Ordering::Acquire)
        );
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
        assert!(
            !signal
                .wake
                .pending
                .load(std::sync::atomic::Ordering::Acquire)
        );
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
                probes: None,
            },
            health: Arc::clone(&health),
            restart_at: None,
            walks: crate::candidate_walks::Walks::default(),
            relayed: BTreeMap::new(),
        };
        let (commands, receiver) = tokio::sync::mpsc::unbounded_channel();
        let endpoint_refresh = Arc::new(EndpointRefreshSignal::default());
        let updater: RouteEndpointUpdater = Arc::new(|_| Ok(()));
        let worker = tokio::spawn(run_worker(
            receiver,
            state,
            endpoint_refresh,
            updater,
            Arc::default(),
        ));
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

    /// #483 (J1025) receipt: what one pre-apply engine read costs at mesh scale.
    ///
    /// `engine_addresses` now runs for every snapshot that changes an installed peer, so this
    /// times it on a real device holding `J1025_PEERS` peers (4,096 by default) when one peer's
    /// endpoint changes, plus the no-change case, which must read nothing. It prints a METRIC
    /// line and asserts only that the read saw every peer; speed is never asserted (ENGINEERING
    /// P3). Run: `cargo test -p infraternal-plugin-mesh --features agent,server,relay,test-support
    /// --release --lib engine_address_read_cost -- --ignored --nocapture`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "A measurement, run on demand with --ignored --nocapture."]
    async fn engine_address_read_cost_at_scale() {
        use super::{
            Health, LinuxPacketIo, PacketFilter, PendingDevice, RuntimeInfo, RuntimeState,
            bind_udp, build_device,
        };
        use gotatun::x25519::StaticSecret;
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
        use std::sync::Arc;
        let count: u32 = std::env::var("J1025_PEERS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(4096);
        let (_sink, endpoint) = black_hole();
        let mut config = one_peer_config(Some(endpoint));
        let template = config.peers.remove(&NodeId(1)).expect("template peer");
        for n in 1..=u64::from(count) {
            let mut peer = template.clone();
            let [_, _, high, low] = u32::try_from(n).expect("fixture value").to_be_bytes();
            peer.peer.key = PublicKey({
                let mut key = [3; 32];
                key[..8].copy_from_slice(&n.to_le_bytes());
                key
            });
            peer.peer.addresses = Addresses {
                ipv4: std::net::Ipv4Addr::new(10, 100 + high, high, low),
                ipv6: std::net::Ipv6Addr::new(
                    0xfd01,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0x100 + u16::from(high),
                    u16::from(low),
                ),
            };
            peer.peer.endpoint = Some(SocketAddr::from((
                [198, 51, 100, 1],
                10_000 + u16::try_from(n % 50_000).expect("fixture value"),
            )));
            config.peers.insert(NodeId(n), peer);
        }
        let private_key = StaticSecret::from([7; 32]);
        let (_kernel, tun_fd) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        )
        .expect("TUN stand-in");
        let health = Arc::new(Health::default());
        let filter = Arc::new(
            PacketFilter::new(
                &config,
                infraternal_mesh::proxy_ports::MeshProxyIngress::default(),
            )
            .expect("compile filter"),
        );
        let tun = LinuxPacketIo::new(
            crate::gotatun_tun::LinuxTun::from_fd(tun_fd, true, Arc::clone(&health.refused))
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
        let device = build_device(
            factory.clone(),
            private_key.clone(),
            port,
            peers_for_config(&config).expect("peers"),
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
            config: Some(config.clone()),
            info: RuntimeInfo {
                interface: "test-tun".to_owned(),
                port,
                thp_disabled: true,
                offloads_enabled: true,
                probes: None,
            },
            health,
            restart_at: None,
            walks: crate::candidate_walks::Walks::default(),
            relayed: BTreeMap::new(),
        };
        let mut next = config.clone();
        next.peers
            .get_mut(&NodeId(1))
            .expect("fixture value")
            .peer
            .endpoint = Some("203.0.113.9:10254".parse().expect("fixture value"));
        let unchanged = state.engine_addresses(&config).await;
        assert!(unchanged.is_empty(), "an unchanged snapshot reads nothing");
        let mut samples = Vec::new();
        for _ in 0..21 {
            let started = std::time::Instant::now();
            let read = state.engine_addresses(&next).await;
            samples.push(started.elapsed());
            assert_eq!(read.len(), usize::try_from(count).expect("fixture value"));
        }
        samples.sort();
        eprintln!(
            "METRIC j1025_engine_read peers={count} median_ms={:.2} max_ms={:.2} min_ms={:.2}",
            samples[10].as_secs_f64() * 1e3,
            samples[20].as_secs_f64() * 1e3,
            samples[0].as_secs_f64() * 1e3,
        );
    }

    /// A loopback address that takes datagrams and never answers: a peer that is switched off.
    /// Test endpoints must stay on this host (network hygiene, 2026-11-22), and a closed port
    /// would answer with ICMP errors instead of silence. Keep the socket for the test's length.
    fn black_hole() -> (std::net::UdpSocket, SocketAddr) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("sink socket");
        let address = socket.local_addr().expect("sink address");
        (socket, address)
    }

    /// A configuration with `count` installed peers at `endpoint` that never handshake.
    fn many_peer_config(count: u32, endpoint: SocketAddr) -> Config {
        let mut config = one_peer_config(None);
        let template = config.peers[&NodeId(1)].clone();
        config.peers.clear();
        for index in 0..count {
            let mut policy = template.clone();
            let [a, b, c, d] = index.to_be_bytes();
            let [_, _, high, low] = index.to_be_bytes();
            policy.peer.key = PublicKey([
                a ^ 0x5a,
                b,
                c,
                d.wrapping_add(1),
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
                9,
            ]);
            policy.peer.addresses = Addresses {
                ipv4: std::net::Ipv4Addr::new(10, 100, high, low),
                ipv6: std::net::Ipv6Addr::new(
                    0xfd01,
                    0,
                    0,
                    0,
                    1,
                    0,
                    u16::from(high),
                    u16::from(low),
                ),
            };
            policy.peer.endpoint = Some(endpoint);
            config.peers.insert(NodeId(10 + u64::from(index)), policy);
        }
        config
    }

    /// The voluntary context switches of every thread of this process named `name`: how often
    /// those threads blocked and were woken again.
    fn wakeups_of(name: &str) -> u64 {
        std::fs::read_dir("/proc/self/task")
            .expect("tasks")
            .flatten()
            .filter(|task| {
                std::fs::read_to_string(task.path().join("comm"))
                    .is_ok_and(|comm| comm.trim_end() == name)
            })
            .filter_map(|task| std::fs::read_to_string(task.path().join("status")).ok())
            .flat_map(|status| {
                status
                    .lines()
                    .filter_map(|line| line.strip_prefix("voluntary_ctxt_switches:"))
                    .filter_map(|value| value.trim().parse::<u64>().ok())
                    .collect::<Vec<_>>()
            })
            .sum()
    }

    /// Block until no thread named `name` has blocked and been woken again for a second, and all
    /// of them are asleep. The engine retries far more often than that, so this returns only once
    /// it has given up on every peer and the start-up work has drained, however long a loaded host
    /// takes for that (#597). Panics if the threads are never still.
    fn wait_until_still(name: &str) {
        use std::time::{Duration, Instant};
        const QUIET: Duration = Duration::from_secs(1);
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut previous = wakeups_of(name);
        let mut quiet_since = Instant::now();
        while quiet_since.elapsed() < QUIET {
            assert!(Instant::now() < deadline, "{name} threads never went still");
            // sleep: sample the kernel's counters; nothing is sent to the threads.
            std::thread::sleep(Duration::from_millis(50));
            let current = wakeups_of(name);
            if current != previous || !all_asleep(name) {
                quiet_since = Instant::now();
            }
            previous = current;
        }
    }

    /// Whether every thread of this process named `name` is in interruptible sleep: none is
    /// waiting for a CPU or a disk.
    fn all_asleep(name: &str) -> bool {
        std::fs::read_dir("/proc/self/task")
            .expect("tasks")
            .flatten()
            .filter_map(|task| std::fs::read_to_string(task.path().join("stat")).ok())
            .filter(|stat| stat.contains(&format!("({name})")))
            .all(|stat| {
                stat.rsplit_once(") ")
                    .is_some_and(|(_, rest)| rest.starts_with('S'))
            })
    }

    /// D81 for offline peers (#260 J1253): once the engine has given up on every peer, the
    /// node's worker and engine threads do not wake at all, however many peers there are.
    ///
    /// The engine's attempt time is shortened so the settle takes seconds; the window is longer
    /// than any periodic scan the worker has had. The threads carry their own name, so other
    /// tests in this process do not count. A socket pair stands in for the TUN, and the peers'
    /// endpoint is a loopback socket nothing reads.
    #[test]
    fn an_idle_node_with_offline_peers_never_wakes() {
        use super::{
            EndpointRefreshSignal, Health, LinuxPacketIo, PacketFilter, PendingDevice,
            RouteEndpointUpdater, RuntimeInfo, RuntimeState, WorkerCommand, bind_udp, build_device,
            run_worker,
        };
        use gotatun::{noise::TimerParams, x25519::StaticSecret};
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
        use std::{
            sync::{Arc, mpsc as sync},
            time::Duration,
        };
        const THREADS: &str = "j1253-idle";
        const PEERS: u32 = 200;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name(THREADS)
            .enable_all()
            .build()
            .expect("runtime");
        let (sink, endpoint) = black_hole();
        let (kernel, device) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        )
        .expect("TUN stand-in");
        let (commands, worker) = runtime.block_on(async {
            let private_key = StaticSecret::from([7; 32]);
            let health = Arc::new(Health::default());
            let config = many_peer_config(PEERS, endpoint);
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
            let mut peers = peers_for_config(&config).expect("peers");
            for peer in &mut peers {
                peer.danger_timer_params = Some(TimerParams {
                    rekey_timeout: Duration::from_millis(300)..=Duration::from_millis(300),
                    rekey_attempt_time: Duration::from_secs(2),
                    ..TimerParams::default()
                });
            }
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
                    probes: None,
                },
                health,
                restart_at: None,
                walks: crate::candidate_walks::Walks::default(),
                relayed: BTreeMap::new(),
            };
            let (commands, receiver) = tokio::sync::mpsc::unbounded_channel();
            let updater: RouteEndpointUpdater = Arc::new(|_| Ok(()));
            let worker = tokio::spawn(run_worker(
                receiver,
                state,
                Arc::new(EndpointRefreshSignal::default()),
                updater,
                Arc::default(),
            ));
            (commands, worker)
        });
        wait_until_still(THREADS);
        sink.set_nonblocking(true).expect("sink mode");
        let mut buffer = [0_u8; 256];
        // The sink's buffer keeps only the first initiations; that some arrived shows the
        // attempts really ran.
        let mut initiations = 0_u32;
        while sink.recv(&mut buffer).is_ok() {
            initiations += 1;
        }
        assert!(initiations > 0, "the peers were tried");
        let before = wakeups_of(THREADS);
        // sleep: the idle window under test, longer than the 15 s scan the worker used to run.
        std::thread::sleep(Duration::from_secs(16));
        let woken = wakeups_of(THREADS) - before;
        assert_eq!(woken, 0, "an idle node woke {woken} times in 16 s");
        assert_eq!(sink.recv(&mut buffer).ok(), None, "nothing more was sent");
        drop(kernel);
        let (reply, stopped) = sync::sync_channel(1);
        commands
            .send(WorkerCommand::Stop(reply))
            .map_err(|_| "worker ended")
            .expect("stop");
        runtime.block_on(worker).expect("worker");
        stopped.recv().expect("stop reply");
    }

    /// Hand-run measurement (#260 J1077 finding 3, J1113): what the node's worker costs an
    /// idle node that has `INFRATERNAL_IDLE_PEERS` installed peers. Prints one row of process
    /// wakeups (voluntary context switches over every thread) and CPU per second over
    /// `INFRATERNAL_IDLE_SECS`. Run it as `cargo test -p infraternal-plugin-mesh --features agent
    /// -- --ignored --nocapture idle_cost_with_many_peers`, or copy the test binary to a quiet
    /// machine and run it there. No root is needed: a socket pair stands in for the TUN.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "measurement only: run by hand with INFRATERNAL_IDLE_PEERS and INFRATERNAL_IDLE_SECS"]
    #[expect(
        clippy::cast_precision_loss,
        reason = "counts of a 30 s window convert to a rate"
    )]
    async fn idle_cost_with_many_peers() {
        use super::{
            EndpointRefreshSignal, Health, LinuxPacketIo, PacketFilter, PendingDevice,
            RouteEndpointUpdater, RuntimeInfo, RuntimeState, WorkerCommand, bind_udp, build_device,
            run_worker,
        };
        use gotatun::x25519::StaticSecret;
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
        use std::sync::{Arc, mpsc as sync};
        /// Voluntary context switches and CPU ticks of every thread of this process.
        fn sample() -> (u64, u64) {
            let (mut switches, mut ticks) = (0, 0);
            for task in std::fs::read_dir("/proc/self/task")
                .expect("tasks")
                .flatten()
            {
                let status =
                    std::fs::read_to_string(task.path().join("status")).unwrap_or_default();
                let stat = std::fs::read_to_string(task.path().join("stat")).unwrap_or_default();
                for line in status.lines() {
                    if let Some(rest) = line.strip_prefix("voluntary_ctxt_switches:") {
                        switches += rest.trim().parse::<u64>().unwrap_or(0);
                    }
                }
                if let Some(end) = stat.rfind(')') {
                    let fields: Vec<_> = stat[end + 2..].split_whitespace().collect();
                    let at = |index: usize| {
                        fields
                            .get(index)
                            .and_then(|f| f.parse::<u64>().ok())
                            .unwrap_or(0)
                    };
                    ticks += at(11) + at(12);
                }
            }
            (switches, ticks)
        }
        let env = |name: &str, default: u32| {
            std::env::var(name)
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(default)
        };
        let count = env("INFRATERNAL_IDLE_PEERS", 1);
        let seconds = env("INFRATERNAL_IDLE_SECS", 30);
        let private_key = StaticSecret::from([7; 32]);
        let (kernel, device) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        )
        .expect("TUN stand-in");
        let health = Arc::new(Health::default());
        let (_sink, endpoint) = black_hole();
        let config = many_peer_config(count, endpoint);
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
                probes: None,
            },
            health: Arc::clone(&health),
            restart_at: None,
            walks: crate::candidate_walks::Walks::default(),
            relayed: BTreeMap::new(),
        };
        let (commands, receiver) = tokio::sync::mpsc::unbounded_channel();
        let updater: RouteEndpointUpdater = Arc::new(|_| Ok(()));
        let worker = tokio::spawn(run_worker(
            receiver,
            state,
            Arc::new(EndpointRefreshSignal::default()),
            updater,
            Arc::default(),
        ));
        // Let the start-up work (first scan, first walk step) finish before the window opens.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let (before, started) = (sample(), std::time::Instant::now());
        tokio::time::sleep(std::time::Duration::from_secs(u64::from(seconds))).await;
        let (after, elapsed) = (sample(), started.elapsed().as_secs_f64());
        let hz = 100.0; // sysconf(_SC_CLK_TCK) is 100 on every Linux we run
        eprintln!(
            "idle-cost peers={count} secs={elapsed:.1} wakeups_per_s={:.2} cpu_ms_per_s={:.2}",
            (after.0 - before.0) as f64 / elapsed,
            (after.1 - before.1) as f64 * 1000.0 / hz / elapsed,
        );
        // The status path is a separate command: it must still answer, for every peer, while
        // the scan runs only on wakes (the worker serves it from its select loop).
        let (reply, counters) = sync::sync_channel(1);
        commands
            .send(WorkerCommand::Counters(reply))
            .map_err(|_| "worker ended")
            .expect("counters");
        let counters = tokio::task::spawn_blocking(move || counters.recv())
            .await
            .expect("join")
            .expect("counters reply")
            .expect("counters");
        eprintln!("status-counters peers_reported={}", counters.len());
        assert_eq!(counters.len(), count as usize);
        drop(kernel);
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
                        candidates: Vec::new(),
                        ipv4_only: false,
                        side_port: false,
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                    access_ssh: None,
                    networks: crate::dataplane::PeerNetworks::default(),
                },
            )]),
            #[cfg(feature = "mesh-dns")]
            peer_names: BTreeMap::new(),
        }
    }

    /// #483 (J1025): a peer with no candidate list is still re-installed with its snapshot
    /// endpoint, so the engine's live address must be read before any peer change, or a stale
    /// snapshot overwrites a roamed single-address peer.
    #[test]
    fn a_changed_single_address_peer_needs_the_engine_read() {
        let applied = one_peer_config(Some("198.51.100.1:10254".parse().expect("fixture address")));
        let next = one_peer_config(Some("198.51.100.9:10254".parse().expect("fixture address")));
        assert!(crate::candidate_walks::engine_read_needed(
            Some(&applied),
            &next
        ));
        assert!(!crate::candidate_walks::engine_read_needed(
            Some(&applied),
            &applied
        ));
        assert!(!crate::candidate_walks::engine_read_needed(None, &next));
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

    /// A coordinator peer becomes one `GotaTun` peer with its key, address, host routes and the
    /// keepalive for its role.
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
