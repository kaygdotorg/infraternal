//! Serialize device updates while preserving the order of host effects and rollback.

use super::{
    udp::{BoundUdpFactory, bind_udp},
    utun::{UtunRx, UtunTx},
};
use crate::{
    dataplane::Config,
    handshake_admission::{ConfirmedEndpointFeed, PeerAdmission},
    packet_filter::PacketFilter,
    peer_stats::CounterMap,
    policy::proxy_ports::MeshProxyIngress,
    underlay_announce::{CoalescedSchedule, confirmed_changed},
};
use gotatun::{
    device::{Device as WireGuardDevice, DeviceBuilder, Peer as WireGuardPeer},
    udp::socket::UdpSocket as GotaUdpSocket,
    x25519::{PublicKey as X25519PublicKey, StaticSecret},
};
use ipnetwork::IpNetwork;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    io,
    net::IpAddr,
    sync::{Arc, mpsc as sync},
    thread::JoinHandle,
};
use tokio::{
    runtime::Builder as RuntimeBuilder,
    sync::{
        RwLock,
        mpsc::{self, UnboundedReceiver, UnboundedSender},
    },
    time::Instant,
};

/// The userspace `WireGuard` device using an Apple utun as its packet path.
pub type GotaDevice = WireGuardDevice<(BoundUdpFactory, UtunTx, UtunRx)>;

/// Collect peer counters and authenticated endpoint observations.
mod peer_stats;
/// Candidate walking and live peer updates.
pub mod walks;

/// Platform effects used while applying and rolling back a node snapshot.
pub trait HostNet: Send + Sync + Sized + 'static {
    /// An opened tunnel before its descriptor has been registered with Tokio.
    type OpenTunnel: Send;
    /// The registered tunnel and any host-specific bookkeeping for it.
    type Tunnel: Clone + Send + Sync + 'static;
    /// Shared status for subnet routes installed by this host.
    type NetworkStatus: Clone + Default + Send + Sync;

    /// Register a tunnel with the worker's current runtime.
    /// # Errors
    /// Reports descriptor registration failures.
    fn register(open: Self::OpenTunnel, filter: Arc<PacketFilter>) -> io::Result<Self::Tunnel>;

    /// Name of the host's registered tunnel.
    fn tunnel_name(utun: &Self::Tunnel) -> &str;

    /// Build the packet sender for the device.
    fn sender(utun: &Self::Tunnel) -> UtunTx;

    /// Build the packet receiver for the device.
    fn receiver(utun: &Self::Tunnel) -> UtunRx;

    /// Publish the accepted MTU to the packet adapters.
    fn set_packet_mtu(utun: &Self::Tunnel, mtu: u16);

    /// Return the policy filter shared by the packet adapters.
    fn filter(utun: &Self::Tunnel) -> &PacketFilter;

    /// Whether to use connected per-endpoint UDP sockets.
    fn connected_udp() -> bool;

    /// Whether to send supported small datagrams through the second socket.
    fn side_socket() -> bool;

    /// Host routes that this platform installs individually for the snapshot.
    fn route_addresses(config: &Config) -> BTreeSet<IpAddr>;

    /// Source of coalesced notifications that the underlay changed.
    type Underlay: Send;

    /// Start listening when this host needs source-address invalidation.
    fn start_underlay(tunnel_name: Option<&str>) -> Option<Self::Underlay>;

    /// Wait until the platform has a coalesced change to announce.
    fn underlay_due(listener: &mut Self::Underlay) -> impl Future<Output = ()> + Send;

    /// Reconcile observed routes after this worker changed its own routes.
    fn resync_underlay(listener: &mut Self::Underlay);

    /// Reconcile routes across a newly accepted snapshot or confirmed endpoints.
    fn reconcile_networks<'a>(
        state: &'a mut RuntimeState<Self>,
        confirmed: Option<&'a [(crate::policy::model::PublicKey, std::net::SocketAddr)]>,
    ) -> impl Future<Output = bool> + Send + 'a;

    /// Remove any installed subnet routes before the tunnel closes.
    fn remove_networks(state: &mut RuntimeState<Self>);

    /// A resolver bound to the local mesh address, if the platform uses one.
    #[cfg(feature = "mesh-dns")]
    type Resolver: Send + Sync;

    /// Host split DNS integration owned by the runtime.
    #[cfg(feature = "mesh-dns")]
    type DnsIntegration: Default + Send + Sync;

    /// Publish DNS records to the current resolver.
    #[cfg(feature = "mesh-dns")]
    fn publish_dns(resolver: &Self::Resolver, records: crate::dns::Records);

    /// Release host DNS and the runtime's bound resolver before closing the tunnel.
    /// # Errors
    /// Reports a failed host resolver removal.
    #[cfg(feature = "mesh-dns")]
    fn stop_dns(
        integration: &mut Self::DnsIntegration,
        resolver: &mut Option<Self::Resolver>,
    ) -> io::Result<()>;

    /// Configure the owned tunnel and its optional mesh addresses.
    /// # Errors
    /// Reports a rejected platform networking operation.
    fn configure_interface(
        utun: &Self::Tunnel,
        config: Option<&Config>,
        mtu: u16,
    ) -> io::Result<()>;

    /// Set the MTU after route metrics have been reconciled.
    /// # Errors
    /// Reports a rejected platform networking operation.
    fn set_interface_mtu(utun: &Self::Tunnel, mtu: u16) -> io::Result<()>;

    /// Apply one host route operation on the owned interface.
    /// # Errors
    /// Reports a rejected platform networking operation.
    fn route(interface: &str, address: IpAddr, operation: &str, mtu: Option<u16>)
    -> io::Result<()>;

    /// Delete the specified routes after validating their owning interface.
    /// # Errors
    /// Reports a rejected platform networking operation.
    fn remove_routes(interface: &str, routes: &BTreeSet<IpAddr>) -> io::Result<()>;

    /// Read the effective mesh budget with a fresh, per-snapshot probe cache.
    fn probe_paths(config: Option<&Config>) -> PathBudgets;

    /// Bind a DNS listener for the snapshot's local resolver address.
    #[cfg(feature = "mesh-dns")]
    /// # Errors
    /// Reports a rejected platform networking operation.
    fn bind_dns(config: &Config) -> io::Result<Self::Resolver>;

    /// Publish host split DNS through the tunnel's configured integration.
    #[cfg(feature = "mesh-dns")]
    /// # Errors
    /// Reports a rejected platform networking operation.
    fn configure_dns(
        integration: &mut Self::DnsIntegration,
        utun: &Self::Tunnel,
        records: &crate::dns::Records,
        address: std::net::Ipv6Addr,
    ) -> io::Result<()>;

    /// Clear the previous split DNS integration before restoring a node.
    #[cfg(feature = "mesh-dns")]
    /// # Errors
    /// Reports a rejected platform networking operation.
    fn clear_dns() -> io::Result<()>;
}

/// The identities a peer list installs in `GotaTun`, which are the ones the guard admits.
#[must_use]
pub fn installed_keys(peers: &[WireGuardPeer]) -> BTreeSet<crate::policy::model::PublicKey> {
    peers
        .iter()
        .map(|peer| crate::policy::model::PublicKey(*peer.public_key.as_bytes()))
        .collect()
}

/// The endpoint-derived MTUs for one snapshot: each installed peer host route's budget and
/// the shared interface MTU.
///
/// Reading them costs a `route` and an `ifconfig` process per underlay path (about 6.5 ms
/// each on the Mac VM). The probe therefore runs on the caller's thread before a
/// snapshot is handed to the worker, never on the worker's runtime, which also drives every
/// packet through the utun: probing there stalled traffic for the whole update (#381 J411).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathBudgets {
    /// Route MTU for each installed peer host route.
    pub route_mtus: BTreeMap<IpAddr, u16>,
    /// Shared utun MTU: the largest peer budget, never below IPv6's minimum.
    pub interface_mtu: u16,
}

/// Return retained host routes whose freshly derived MTU differs from the installed metric.
#[must_use]
pub fn route_mtus_to_refresh(
    old_routes: &BTreeSet<IpAddr>,
    new_routes: &BTreeSet<IpAddr>,
    old_mtus: &BTreeMap<IpAddr, u16>,
    new_mtus: &BTreeMap<IpAddr, u16>,
) -> BTreeSet<IpAddr> {
    old_routes
        .intersection(new_routes)
        .copied()
        .filter(|address| old_mtus.get(address).copied() != new_mtus.get(address).copied())
        .collect()
}
/// Refuse endpoints that would be captured by their own tunnel.
/// # Errors
/// Rejects an underlay endpoint routed through this tunnel.
pub fn validate_underlay_routes(config: &Config, routes: &BTreeSet<IpAddr>) -> io::Result<()> {
    if config.peers.values().any(|policy| {
        policy
            .peer
            .endpoint
            .is_some_and(|endpoint| routes.contains(&endpoint.ip()))
    }) {
        Err(io::ErrorKind::InvalidInput.into())
    } else {
        Ok(())
    }
}
/// The configured peers the Mac device installs: those whose grants allow some traffic.
///
/// A peer without network access gets no device entry, so the handshake guard refuses its key
/// and the node keeps no session alive toward it, as on Linux (J781, #483, #515).
pub fn installed_peers(config: &Config) -> impl Iterator<Item = &crate::dataplane::PeerPolicy> {
    config
        .peers
        .values()
        .filter(|policy| policy.has_network_access())
}

/// Convert every installed identity into `GotaTun` peers, keeping both rotation keys installed.
///
/// Only the active overlap key gets routes and an endpoint, so the inactive key can accept an
/// incoming handshake without competing to own the peer's host routes.
/// # Errors
/// Rejects invalid host routes before changing the live device.
pub fn peers_for_config(config: &Config, side_socket: bool) -> io::Result<Vec<WireGuardPeer>> {
    let mut peers = Vec::new();
    for policy in installed_peers(config) {
        peers.extend(peer_for_policy(policy, side_socket)?);
    }
    Ok(peers)
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
pub fn peer_for_policy(
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

/// Convert one peer to its active key or both journaled overlap keys.
/// # Errors
/// Rejects invalid host routes before they reach `GotaTun`.
fn identities_for_policy(policy: &crate::dataplane::PeerPolicy) -> io::Result<Vec<WireGuardPeer>> {
    let peer = &policy.peer;
    let mut addresses = peer
        .routed_addresses()
        .map(|address| {
            IpNetwork::new(address, if address.is_ipv4() { 32 } else { 128 })
                .map_err(|_| io::ErrorKind::InvalidData.into())
        })
        .collect::<io::Result<Vec<_>>>()?;
    // Networks behind this router peer (D197 M3), as on Linux: the device sends packets for them
    // to the peer and accepts their hosts' replies only from it. The packet filter decides which
    // flows may start; whether the utun routes a network at all is the host's subnet plan's call.
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
        current.keepalive = Some(25);
        return Ok(vec![current]);
    };
    let mut previous_peer = WireGuardPeer::new(X25519PublicKey::from(previous.0)).with_allowed_ips(
        if peer.previous_active {
            addresses.clone()
        } else {
            Vec::new()
        },
    );
    let mut current_peer = WireGuardPeer::new(X25519PublicKey::from(peer.key.0)).with_allowed_ips(
        if peer.previous_active {
            Vec::new()
        } else {
            addresses
        },
    );
    let active = if peer.previous_active {
        &mut previous_peer
    } else {
        &mut current_peer
    };
    active.endpoint = peer.endpoint;
    active.keepalive = Some(25);
    Ok(vec![previous_peer, current_peer])
}

/// Live interface details returned after binding or applying a snapshot.
#[derive(Clone)]
pub struct RuntimeInfo {
    /// Name of the device interface.
    pub interface: String,
    /// Actual UDP listener port.
    pub port: u16,
    /// Current set of installed host routes.
    pub routes: BTreeSet<IpAddr>,
}

/// Commands serialized by the Mac `GotaTun` worker. Each reply lets callers
/// wait for the device update before changing durable identity state. Authority replacements and
/// key changes share the same queue, so their runtime transitions cannot interleave.
pub enum WorkerCommand {
    /// Apply an incremental or full snapshot from the current authority.
    Apply {
        /// Keeps the larger snapshot out of the enum's inline command payload.
        config: Box<Config>,
        /// MTUs probed for `config` before it reached the worker.
        budgets: PathBudgets,
        /// Completion and live interface details.
        reply: sync::SyncSender<io::Result<RuntimeInfo>>,
    },
    /// Replace one complete authority snapshot without rolling back to its predecessor.
    ReplaceAuthority {
        /// Keeps the larger snapshot out of the enum's inline command payload.
        config: Box<Config>,
        /// MTUs probed for `config` before it reached the worker (#381).
        budgets: PathBudgets,
        /// Completion and live interface details.
        reply: sync::SyncSender<io::Result<RuntimeInfo>>,
    },
    /// Replace the live `GotaTun` key on its serialized worker thread.
    SetPrivateKey {
        /// Key selected by the durable rotation journal.
        private_key: StaticSecret,
        /// Whether the device accepted the key.
        reply: sync::SyncSender<io::Result<()>>,
    },
    /// Read live counters from the device.
    Counters(sync::SyncSender<CounterMap>),
    /// Request teardown and wait for host cleanup.
    Stop(sync::SyncSender<io::Result<()>>),
    /// Hand a real-Mac test the worker's admission guard, so it can check what the guard
    /// knows and flood it on a simulated clock.
    #[cfg(any(test, feature = "test-support"))]
    Admission(sync::SyncSender<Arc<RwLock<PeerAdmission>>>),
}

/// Handle for the worker thread that owns the live device.
pub struct Worker {
    /// Command queue for the serialized runtime.
    pub commands: UnboundedSender<WorkerCommand>,
    /// Worker thread, joined after shutdown.
    pub join: Option<JoinHandle<()>>,
    /// Probe snapshot MTUs on the caller thread.
    pub probe_paths: fn(Option<&Config>) -> PathBudgets,
}

/// Worker initialization paused until the node commits its startup state.
pub struct PendingWorker<H: HostNet> {
    host: std::marker::PhantomData<H>,
    commands: UnboundedSender<WorkerCommand>,
    join: Option<JoinHandle<()>>,
    gate: Option<sync::SyncSender<bool>>,
    ready: sync::Receiver<io::Result<()>>,
    info: RuntimeInfo,
}

impl<H: HostNet> PendingWorker<H> {
    /// Start the worker behind a gate and return its utun details for approval.
    /// # Errors
    /// Reports utun allocation, worker startup, route setup, or DNS setup failures.
    pub fn begin(
        open: H::OpenTunnel,
        private_key: StaticSecret,
        requested_port: crate::listen_port::Request,
        config: Option<Config>,
        routes: BTreeSet<IpAddr>,
        budgets: PathBudgets,
        network_status: H::NetworkStatus,
    ) -> io::Result<Self> {
        let filter = Arc::new(match config.as_ref() {
            Some(config) => PacketFilter::new(config, MeshProxyIngress::default())?,
            None => PacketFilter::empty(),
        });
        let (info_tx, info_rx) = sync::sync_channel(1);
        let (gate_tx, gate_rx) = sync::sync_channel(1);
        let (ready_tx, ready_rx) = sync::sync_channel(1);
        let (commands, receiver) = mpsc::unbounded_channel();
        let join = std::thread::Builder::new()
            .name("infraternal-mesh-macos".to_owned())
            .spawn(move || {
                let Ok(runtime) = RuntimeBuilder::new_current_thread().enable_all().build() else {
                    let _ = info_tx.send(Err(io::Error::other("Mesh runtime could not start.")));
                    return;
                };
                // The listener's guard gets its own copy; the device takes `private_key` below.
                let guard_key = private_key.clone();
                let initialized = runtime.block_on(async move {
                    let utun = H::register(open, filter)?;
                    let (factory, port) =
                        bind_udp(requested_port, guard_key, H::connected_udp()).await?;
                    let info = RuntimeInfo {
                        interface: H::tunnel_name(&utun).to_owned(),
                        port,
                        routes,
                    };
                    Ok((utun, factory, info))
                });
                let (utun, factory, info) = match initialized {
                    Ok(initialized) => initialized,
                    Err(error) => {
                        let _ = info_tx.send(Err(error));
                        return;
                    }
                };
                let admission = Arc::clone(&factory.admission);
                let udp = factory.send.clone();
                let PathBudgets {
                    route_mtus: initial_route_mtus,
                    interface_mtu,
                } = budgets;
                if info_tx.send(Ok(info.clone())).is_err() || !gate_rx.recv().unwrap_or(false) {
                    return;
                }
                let device = runtime.block_on(async {
                    let mtu = interface_mtu;
                    H::configure_interface(&utun, config.as_ref(), mtu)?;
                    H::set_packet_mtu(&utun, mtu);
                    #[cfg(feature = "mesh-dns")]
                    let mut dns_integration = H::DnsIntegration::default();
                    #[cfg(feature = "mesh-dns")]
                    let mut dns_resolver = None;
                    #[cfg(feature = "mesh-dns")]
                    if let Some(config) = config.as_ref() {
                        let records = crate::dns::Records::from_config(config)?;
                        let resolver = H::bind_dns(config)?;
                        if let Err(error) = H::configure_dns(
                            &mut dns_integration,
                            &utun,
                            &records,
                            config.addresses.ipv6,
                        ) {
                            tracing::warn!(
                                "mesh DNS host resolver integration could not be updated: {error}"
                            );
                        }
                        dns_resolver = Some(resolver);
                    }
                    let peers = config
                        .as_ref()
                        .map(|config| peers_for_config(config, H::side_socket()))
                        .transpose()?
                        .unwrap_or_default();
                    // The guard knows the first peers before the device receives anything.
                    let keys = installed_keys(&peers);
                    admission.write().await.install(keys, &peers);
                    let device = DeviceBuilder::new()
                        .with_udp(factory)
                        .with_private_key(private_key)
                        .with_listen_port(info.port)
                        .with_side_socket(H::side_socket())
                        .with_ip_pair(H::sender(&utun), H::receiver(&utun))
                        .with_peers(peers)
                        .build()
                        .await
                        .map_err(|_| io::Error::other("WireGuard device could not start."))?;
                    let mut installed = BTreeSet::new();
                    for address in &info.routes {
                        let mtu = initial_route_mtus
                            .get(address)
                            .copied()
                            .unwrap_or(crate::mesh_mtu::FALLBACK_MESH_MTU);
                        if let Err(error) = H::route(&info.interface, *address, "add", Some(mtu)) {
                            let _ = H::remove_routes(&info.interface, &installed);
                            device.stop().await;
                            return Err(error);
                        }
                        installed.insert(*address);
                    }
                    #[cfg(feature = "mesh-dns")]
                    {
                        Ok((device, dns_resolver, dns_integration))
                    }
                    #[cfg(not(feature = "mesh-dns"))]
                    {
                        Ok(device)
                    }
                });
                let device = match device {
                    Ok(device) => device,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                #[cfg(feature = "mesh-dns")]
                let (device, dns_resolver, dns_integration) = device;
                if ready_tx.send(Ok(())).is_err() {
                    runtime.block_on(device.stop());
                    return;
                }
                let state = RuntimeState::<H> {
                    udp,
                    utun: Some(utun),
                    device: Some(Arc::new(device)),
                    handshakes: tokio::task::JoinSet::new(),
                    walks: crate::candidate_walks::Walks::default(),
                    config,
                    routes: info.routes,
                    route_mtus: initial_route_mtus,
                    networks: BTreeMap::new(),
                    subnet_exceptions: BTreeSet::new(),
                    admitted_networks: BTreeSet::new(),
                    network_status,
                    interface_mtu,
                    port: info.port,
                    admission,
                    confirmed_feed: ConfirmedEndpointFeed::default(),
                    #[cfg(feature = "mesh-dns")]
                    dns_resolver,
                    #[cfg(feature = "mesh-dns")]
                    dns_integration,
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
            host: std::marker::PhantomData,
            commands,
            join: Some(join),
            gate: Some(gate_tx),
            ready: ready_rx,
            info,
        })
    }

    /// Read actual startup details before authorizing the worker.
    #[must_use]
    pub fn info(&self) -> &RuntimeInfo {
        &self.info
    }

    /// Allow the worker to install initial peers and routes.
    /// # Errors
    /// Reports runtime initialization or host configuration failures.
    pub fn commit(mut self) -> io::Result<(Worker, RuntimeInfo)> {
        self.gate
            .take()
            .ok_or(io::ErrorKind::BrokenPipe)?
            .send(true)
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        let ready = self.ready.recv().map_err(|_| io::ErrorKind::BrokenPipe)?;
        if let Err(error) = ready {
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
            return Err(error);
        }
        let join = self.join.take().ok_or(io::ErrorKind::BrokenPipe)?;
        Ok((
            Worker {
                commands: self.commands.clone(),
                join: Some(join),
                probe_paths: H::probe_paths,
            },
            self.info.clone(),
        ))
    }
}

impl<H: HostNet> Drop for PendingWorker<H> {
    fn drop(&mut self) {
        if let Some(gate) = self.gate.take() {
            let _ = gate.send(false);
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Worker {
    /// Sends a new mesh configuration to the worker and waits for its result.
    ///
    /// Path MTUs are probed here, on the caller's thread, so the packet runtime only installs
    /// the results.
    /// # Errors
    /// Reports an unavailable worker or failure to apply the requested configuration.
    pub fn apply(&self, config: Config) -> io::Result<RuntimeInfo> {
        let budgets = (self.probe_paths)(Some(&config));
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::Apply {
                config: Box::new(config),
                budgets,
                reply,
            })
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        result.recv().map_err(|_| io::ErrorKind::BrokenPipe)?
    }

    /// Apply a complete authority replacement without retaining the previous authority as rollback.
    /// # Errors
    /// Reports a failed peer or route update; callers stop the worker on failure.
    ///
    /// Path MTUs are probed here, on the caller's thread, as for [`Worker::apply`].
    pub fn replace_authority(&self, config: Config) -> io::Result<RuntimeInfo> {
        let budgets = (self.probe_paths)(Some(&config));
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::ReplaceAuthority {
                config: Box::new(config),
                budgets,
                reply,
            })
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        result.recv().map_err(|_| io::ErrorKind::BrokenPipe)?
    }

    /// Read the counters from the serialized device worker.
    /// # Errors
    /// Reports a stopped worker.
    pub fn counters(&self) -> io::Result<CounterMap> {
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::Counters(reply))
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        result
            .recv()
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }

    /// Replace the live `GotaTun` key on its serialized worker thread.
    /// # Errors
    /// Reports a stopped worker or a rejected key update.
    pub fn set_private_key(&self, private_key: StaticSecret) -> io::Result<()> {
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::SetPrivateKey { private_key, reply })
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        result.recv().map_err(|_| io::ErrorKind::BrokenPipe)?
    }

    /// Stop the worker and wait until its device thread has finished teardown.
    /// # Errors
    /// Reports command delivery, route cleanup, or worker-thread failures.
    pub fn stop(&mut self) -> io::Result<()> {
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::Stop(reply))
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        let stopped = result.recv().map_err(|_| io::ErrorKind::BrokenPipe)?;
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| io::Error::other("Mesh worker stopped unexpectedly."))?;
        }
        stopped
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Owns the live utun, peer-route MTUs, accepted snapshot and DNS resolver integration.
/// `route_mtus` mirrors installed metrics so a failed update can restore them.
pub struct RuntimeState<H: HostNet> {
    /// The worker's UDP listener shares connected pools with the device.
    pub udp: GotaUdpSocket,
    /// Registered tunnel kept alive until shutdown is complete.
    pub utun: Option<H::Tunnel>,
    /// Live device, shared with handshake tasks until they stop.
    pub device: Option<Arc<GotaDevice>>,
    /// Tasks sending handshakes without blocking the command loop.
    pub handshakes: tokio::task::JoinSet<()>,
    /// Per-peer candidate walks driven by the worker's event loop.
    pub walks: crate::candidate_walks::Walks,
    /// Snapshot successfully applied to the device.
    pub config: Option<Config>,
    /// Host routes installed for the current snapshot.
    pub routes: BTreeSet<IpAddr>,
    /// MTUs associated with the installed host routes.
    pub route_mtus: BTreeMap<IpAddr, u16>,
    /// Subnet routes installed through the tunnel, with their host MTUs.
    pub networks: BTreeMap<crate::policy::networks::Network, Option<u16>>,
    /// Endpoint addresses excluded in the last successful subnet reconciliation.
    pub subnet_exceptions: BTreeSet<IpAddr>,
    /// Previously approved networks that can be split around a roaming endpoint.
    pub admitted_networks: BTreeSet<crate::policy::networks::Network>,
    /// Status of reachable networks shared with the platform-facing node.
    pub network_status: H::NetworkStatus,
    /// Last accepted tunnel MTU, restored without re-probing after failed updates.
    pub interface_mtu: u16,
    /// Bound UDP listener port.
    pub port: u16,
    /// Receive admission state for the installed identities.
    pub admission: Arc<RwLock<PeerAdmission>>,
    /// Coalesced handoff of authenticated endpoints to the admission guard (#483).
    pub confirmed_feed: ConfirmedEndpointFeed,
    #[cfg(feature = "mesh-dns")]
    /// Bound DNS resolver, when present.
    pub dns_resolver: Option<H::Resolver>,
    #[cfg(feature = "mesh-dns")]
    /// Host split DNS configuration owned by this runtime.
    pub dns_integration: H::DnsIntegration,
}

impl<H: HostNet> RuntimeState<H> {
    /// Change the private identity on the active `WireGuard` device without restarting its utun.
    /// # Errors
    /// Reports a stopped device or a rejected key update.
    pub async fn set_private_key(&mut self, private_key: StaticSecret) -> io::Result<()> {
        self.device
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .set_private_key(private_key.clone())
            .await
            .map_err(|_| io::Error::other("WireGuard private key could not be changed."))?;
        // The guard follows only a key the live device accepted.
        self.admission.write().await.set_private_key(private_key);
        Ok(())
    }

    /// Apply one accepted snapshot, its endpoint-derived route MTUs, and its DNS names.
    /// # Errors
    /// Restores the old peer, route and interface MTU state when one update fails.
    pub async fn apply(
        &mut self,
        config: Config,
        budgets: PathBudgets,
        before: &BTreeMap<crate::policy::model::PublicKey, crate::candidate_walks::EngineEndpoint>,
    ) -> io::Result<RuntimeInfo> {
        self.apply_with_rollback(config, budgets, true, before)
            .await
    }

    /// Replace a complete authority snapshot without restoring the previous authority on failure.
    ///
    /// Matching content and installed peer keys keep their established sessions. Fresh MTUs
    /// update only the routes and interface, under this worker's exclusive route ownership.
    /// Changed peer content uses the full transaction. Any failure stops this worker through
    /// the caller's fail-closed authority handling, without restoring the retired authority.
    /// # Errors
    /// Reports an invalid config, failed peer query, or failed route/device update.
    pub async fn replace_authority(
        &mut self,
        config: Config,
        budgets: PathBudgets,
    ) -> io::Result<RuntimeInfo> {
        let policy = PacketFilter::prepare_policy(&config, MeshProxyIngress::default())?;
        if self
            .config
            .as_ref()
            .is_some_and(|old| crate::dataplane::same_runtime_content(old, &config))
        {
            let expected: BTreeSet<_> = peers_for_config(&config, H::side_socket())?
                .into_iter()
                .map(|peer| crate::policy::model::PublicKey(*peer.public_key.as_bytes()))
                .collect();
            let installed: BTreeSet<_> = self.counters().await?.into_keys().collect();
            if installed == expected {
                let interface = self
                    .utun
                    .as_ref()
                    .map(H::tunnel_name)
                    .ok_or(io::ErrorKind::NotConnected)?
                    .to_owned();
                self.refresh_unchanged_mesh_mtus(budgets).await?;
                H::filter(self.utun.as_ref().ok_or(io::ErrorKind::NotConnected)?)
                    .publish_policy(policy);
                self.config = Some(config);
                return Ok(RuntimeInfo {
                    interface,
                    port: self.port,
                    routes: self.routes.clone(),
                });
            }
        }
        // Full replacement retires the old engine sessions and their walk positions.
        self.handshakes.abort_all();
        self.walks.clear();
        let before = BTreeMap::new();
        self.apply_with_rollback(config, budgets, false, &before)
            .await
    }

    /// Refresh MTUs without suspending the device or replacing any established peer.
    ///
    /// The serialized worker's exclusive `&mut self` is the Mac route lock: apply, removal
    /// and stop cannot interleave while it awaits the blocking pool. The packet reactor keeps
    /// running while the host utilities update the interface and routes (D351). Stage the
    /// larger MTU first so every route fits, then publish the final budgets after success.
    /// Probes have already run on the caller's thread, outside the packet runtime.
    /// # Errors
    /// Reports a failed blocking task, interface or route update; the authority caller stops
    /// the worker instead of restoring the retired authority.
    async fn refresh_unchanged_mesh_mtus(&mut self, budgets: PathBudgets) -> io::Result<()> {
        if budgets.route_mtus == self.route_mtus && budgets.interface_mtu == self.interface_mtu {
            return Ok(());
        }
        let utun = self.utun.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let interface = H::tunnel_name(utun).to_owned();
        let staging = self.interface_mtu.max(budgets.interface_mtu);
        let changed = route_mtus_to_refresh(
            &self.routes,
            &self.routes,
            &self.route_mtus,
            &budgets.route_mtus,
        );
        // The watcher accepts both budgets throughout the host update. Outbound packets are
        // still bounded by the kernel's interface and route MTUs until each utility completes.
        H::set_packet_mtu(utun, staging);
        let host_utun = utun.clone();
        let budgets = tokio::task::spawn_blocking(move || {
            H::set_interface_mtu(&host_utun, staging)?;
            for address in changed {
                let mtu = budgets
                    .route_mtus
                    .get(&address)
                    .copied()
                    .unwrap_or(crate::mesh_mtu::FALLBACK_MESH_MTU);
                H::route(&interface, address, "change", Some(mtu))?;
            }
            H::set_interface_mtu(&host_utun, budgets.interface_mtu)?;
            Ok::<_, io::Error>(budgets)
        })
        .await
        .map_err(|_| io::Error::other("Mesh MTU update worker could not finish."))??;
        H::set_packet_mtu(utun, budgets.interface_mtu);
        self.route_mtus = budgets.route_mtus;
        self.interface_mtu = budgets.interface_mtu;
        Ok(())
    }

    /// Apply a snapshot and its MTUs. With `rollback_on_failure`, a failed step restores the
    /// previous peers, routes and MTUs. Without it (authority replacement), the old authority
    /// is never restored: the caller has already persisted the fenced state and stops the
    /// worker instead.
    /// # Errors
    /// Reports invalid routes or failed device, route or MTU configuration.
    async fn apply_with_rollback(
        &mut self,
        config: Config,
        budgets: PathBudgets,
        rollback_on_failure: bool,
        before: &BTreeMap<crate::policy::model::PublicKey, crate::candidate_walks::EngineEndpoint>,
    ) -> io::Result<RuntimeInfo> {
        let policy = PacketFilter::prepare_policy(&config, MeshProxyIngress::default())?;
        let utun = self.utun.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let interface = H::tunnel_name(utun).to_owned();
        #[cfg(feature = "mesh-dns")]
        let dns_records = crate::dns::Records::from_config(&config)?;
        let new_routes = H::route_addresses(&config);
        validate_underlay_routes(&config, &new_routes)?;
        let peers = peers_for_config(&config, H::side_socket())?;
        let admitted = installed_keys(&peers);
        let admitted_endpoints: Vec<_> = peers.iter().filter_map(|peer| peer.endpoint).collect();
        let old_config = self.config.clone();
        let old_routes = self.routes.clone();
        let device = self.device.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let PathBudgets {
            route_mtus: new_route_mtus,
            interface_mtu: new_mtu,
        } = budgets;
        let old_route_mtus = self.route_mtus.clone();
        let old_mtu = self.interface_mtu;
        let staging_mtu = old_mtu.max(new_mtu).max(crate::mesh_mtu::IPV6_MINIMUM_MTU);
        if let Err(error) = H::configure_interface(utun, Some(&config), staging_mtu) {
            if rollback_on_failure {
                rollback_device::<H>(device, old_config.as_ref(), old_mtu, utun).await;
            }
            return Err(error);
        }
        H::set_packet_mtu(utun, staging_mtu);
        #[cfg(feature = "mesh-dns")]
        let pending_dns_resolver = if self.dns_resolver.is_none() {
            match H::bind_dns(&config) {
                Ok(resolver) => Some(resolver),
                Err(error) => {
                    if rollback_on_failure {
                        rollback_device::<H>(device, old_config.as_ref(), old_mtu, utun).await;
                    }
                    return Err(error);
                }
            }
        } else {
            None
        };
        // Admit newly granted peers before inserting them into `GotaTun` so the device's timer
        // task cannot send an initiation before our own receive guard accepts the peer's
        // simultaneous initiation (#605). Existing peers stay admitted until the apply succeeds.
        let previous_admitted = old_config
            .as_ref()
            .and_then(|old| peers_for_config(old, H::side_socket()).ok())
            .map(|old_peers| installed_keys(&old_peers))
            .unwrap_or_default();
        let mut pre_admitted = false;
        if !admitted.is_subset(&previous_admitted) {
            let mut admission = self.admission.write().await;
            admission.set_peers(previous_admitted.union(&admitted).copied());
            drop(admission);
            pre_admitted = true;
        }
        // An authority replacement may have reached this path because the installed keys
        // disagreed with the snapshot. Rebuild from the complete list in that case.
        let peers_applied = if rollback_on_failure {
            walks::update_peers::<H>(device, old_config.as_ref(), &config, &admitted, before).await
        } else {
            replace_peers(device, peers).await
        };
        if let Err(error) = peers_applied {
            if rollback_on_failure {
                if pre_admitted {
                    let mut admission = self.admission.write().await;
                    admission.set_peers(previous_admitted);
                }
                rollback_device::<H>(device, old_config.as_ref(), old_mtu, utun).await;
            }
            return Err(error);
        }
        let mut added = BTreeSet::new();
        let mut changed = BTreeSet::new();
        let mut removed = BTreeSet::new();
        let routes_applied = (|| {
            for address in new_routes.difference(&old_routes) {
                let mtu = new_route_mtus
                    .get(address)
                    .copied()
                    .unwrap_or(crate::mesh_mtu::FALLBACK_MESH_MTU);
                H::route(&interface, *address, "add", Some(mtu))?;
                added.insert(*address);
            }
            for address in
                route_mtus_to_refresh(&old_routes, &new_routes, &old_route_mtus, &new_route_mtus)
            {
                let mtu = new_route_mtus
                    .get(&address)
                    .copied()
                    .unwrap_or(crate::mesh_mtu::FALLBACK_MESH_MTU);
                H::route(&interface, address, "change", Some(mtu))?;
                changed.insert(address);
            }
            for address in old_routes.difference(&new_routes) {
                H::route(&interface, *address, "delete", None)?;
                removed.insert(*address);
            }
            H::set_interface_mtu(utun, new_mtu)?;
            H::set_packet_mtu(utun, new_mtu);
            Ok(())
        })();
        if let Err(error) = routes_applied {
            let _ = H::remove_routes(&interface, &added);
            if !rollback_on_failure {
                // An authority replacement never restores the retired authority's routes; the
                // caller stops this worker, which tears down the utun and its routes.
                return Err(error);
            }
            for address in &changed {
                let mtu = old_route_mtus
                    .get(address)
                    .copied()
                    .unwrap_or(crate::mesh_mtu::FALLBACK_MESH_MTU);
                let _ = H::route(&interface, *address, "change", Some(mtu));
            }
            for address in &removed {
                let mtu = old_route_mtus
                    .get(address)
                    .copied()
                    .unwrap_or(crate::mesh_mtu::FALLBACK_MESH_MTU);
                let _ = H::route(&interface, *address, "add", Some(mtu));
            }
            if pre_admitted {
                let mut admission = self.admission.write().await;
                admission.set_peers(previous_admitted);
            }
            rollback_device::<H>(device, old_config.as_ref(), old_mtu, utun).await;
            return Err(error);
        }
        self.routes.clone_from(&new_routes);
        self.route_mtus = new_route_mtus;
        self.interface_mtu = new_mtu;
        #[cfg(feature = "mesh-dns")]
        {
            let resolver = self
                .dns_resolver
                .as_ref()
                .or(pending_dns_resolver.as_ref())
                .ok_or(io::ErrorKind::NotConnected)?;
            if let Err(error) = H::configure_dns(
                &mut self.dns_integration,
                utun,
                &dns_records,
                config.addresses.ipv6,
            ) {
                tracing::warn!("mesh DNS host resolver integration could not be updated: {error}");
            }
            H::publish_dns(resolver, dns_records);
            if self.dns_resolver.is_none() {
                self.dns_resolver = pending_dns_resolver;
            }
        }
        // The receive guard follows only snapshots the live device fully accepted. A failure
        // above has restored (or, for an authority replacement, stopped) the old peers.
        let mut admission = self.admission.write().await;
        admission.set_peers(admitted);
        admission.set_configured_endpoints(admitted_endpoints);
        drop(admission);
        H::filter(utun).publish_policy(policy);
        let readdressed = walks::readdressed(old_config.as_ref(), &config);
        self.config = Some(config);
        self.rehandshake_all(readdressed);
        Ok(RuntimeInfo {
            interface,
            port: self.port,
            routes: new_routes,
        })
    }

    /// Removes managed DNS files, peer routes and the owned device before stopping the utun.
    /// # Errors
    /// Returns a DNS or route cleanup error after the device and utun descriptor have been stopped.
    pub async fn stop(&mut self) -> io::Result<()> {
        #[cfg(feature = "mesh-dns")]
        let dns_result = H::stop_dns(&mut self.dns_integration, &mut self.dns_resolver);
        #[cfg(not(feature = "mesh-dns"))]
        let dns_result: io::Result<()> = Ok(());
        let route_result = self.utun.as_ref().map_or(Ok(()), |utun| {
            H::remove_routes(H::tunnel_name(utun), &self.routes)
        });
        // Subnet routes go with the utun; root mode removes them first, as it does host routes.
        H::remove_networks(self);
        // Ending every handshake task drops its device handle, so this one is the last.
        self.handshakes.abort_all();
        while self.handshakes.join_next().await.is_some() {}
        self.walks.clear();
        if let Some(device) = self.device.take().and_then(Arc::into_inner) {
            device.stop().await;
        }
        self.utun.take();
        self.routes.clear();
        self.route_mtus.clear();
        self.config = None;
        dns_result.and(route_result)
    }
}

/// Count full peer replacements in the real-Mac session-preservation regression.
#[cfg(any(test, feature = "test-support"))]
pub static J472_REBUILDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Replace the complete peer inventory, discarding its previous session state.
async fn replace_peers(device: &GotaDevice, peers: Vec<WireGuardPeer>) -> io::Result<()> {
    #[cfg(any(test, feature = "test-support"))]
    J472_REBUILDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    device.suspend().await;
    let result = async {
        device
            .clear_peers()
            .await
            .map_err(|_| io::Error::other("WireGuard peers could not be replaced."))?;
        if !device
            .add_peers(peers)
            .await
            .map_err(|_| io::Error::other("WireGuard peers could not be replaced."))?
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
    .await;
    let resumed = device
        .resume()
        .await
        .map_err(|_| io::Error::other("WireGuard device could not resume."));
    result.and(resumed)
}

/// Restore the old peers and their interface MTU after a failed configuration transaction.
///
/// `mtu` is the MTU recorded for `config` when it was applied, so rollback starts no probes
/// on the packet runtime.
async fn rollback_device<H: HostNet>(
    device: &GotaDevice,
    config: Option<&Config>,
    mtu: u16,
    utun: &H::Tunnel,
) {
    if let Some(config) = config {
        let _ = H::configure_interface(utun, Some(config), mtu);
        if let Ok(peers) = peers_for_config(config, H::side_socket()) {
            let _ = replace_peers(device, peers).await;
        }
    } else {
        let _ = H::set_interface_mtu(utun, mtu);
    }
    H::set_packet_mtu(utun, mtu);
}

/// Run the mesh worker: apply queued commands one at a time, step candidate walks when one is
/// due, and reap finished handshake tasks. It stops cleanly when told to or when its queue
/// closes.
///
/// A walk reads the counters only after the reply to an apply has been sent, so a snapshot's
/// caller never waits on it. Between commands it also hands the device's confirmed endpoints to
/// the admission guard, as the Linux worker does (J736, #483): when the engine reports a change
/// and after a command that changes the peers, at most every 250 ms, and never on a timer, so
/// an idle node costs no wakeup for it (D81, #260 J1253).
///
/// Every walk reads its peers through `installed_peers`, the same filter
/// `peers_for_config` installs with, so a peer without network access is never walked.
///
/// The worker drives the platform's underlay listener for its tunnel. On an underlay change it invalidates cached
/// source addresses, then asks live sessions to announce the new source (D392, #260).
pub async fn run_worker<H: HostNet>(
    mut commands: UnboundedReceiver<WorkerCommand>,
    mut state: RuntimeState<H>,
) {
    let mut announcer = H::start_underlay(state.utun.as_ref().map(H::tunnel_name));
    let mut confirmed_scan = CoalescedSchedule::default();
    confirmed_scan.arm(Instant::now());
    // A restored configuration may carry subnet routes and candidates; no session predates it.
    H::reconcile_networks(&mut state, None).await;
    state.refresh_walks(&BTreeMap::new()).await;
    loop {
        let next_walk = state.walks.next_due();
        let confirmed = state
            .device
            .as_ref()
            .map(|device| device.confirmed_endpoint_changes());
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    break;
                };
                // A command that changes the peers or the device changes what the guard
                // should hold, whether or not any endpoint moved.
                if !confirmed_scan.is_armed()
                    && matches!(
                        command,
                        WorkerCommand::Apply { .. }
                            | WorkerCommand::ReplaceAuthority { .. }
                            | WorkerCommand::SetPrivateKey { .. }
                    )
                {
                    confirmed_scan.arm(Instant::now());
                }
                match command {
                    WorkerCommand::Apply {
                        config,
                        budgets,
                        reply,
                    } => {
                        let before = state.engine_addresses(&config).await;
                        let result = state.apply(*config, budgets, &before).await;
                        // Subnet routes follow the snapshot the device accepted (D197 M3), before
                        // the reply, so `mesh routes` right after it is current.
                        if result.is_ok() {
                            H::reconcile_networks(&mut state, None).await;
                        }
                        // The apply writes routes while the listener is outside the select.
                        if let Some(announcer) = announcer.as_mut() {
                            H::resync_underlay(announcer);
                        }
                        let applied = result.is_ok();
                        let _ = reply.send(result);
                        state.after_apply(applied, &before).await;
                    }
                    WorkerCommand::ReplaceAuthority {
                        config,
                        budgets,
                        reply,
                    } => {
                        let result = state.replace_authority(*config, budgets).await;
                        if result.is_ok() {
                            H::reconcile_networks(&mut state, None).await;
                        }
                        if let Some(announcer) = announcer.as_mut() {
                            H::resync_underlay(announcer);
                        }
                        let applied = result.is_ok();
                        let _ = reply.send(result);
                        if applied {
                            state.refresh_walks(&BTreeMap::new()).await;
                        }
                    }
                    WorkerCommand::SetPrivateKey { private_key, reply } => {
                        let result = state.set_private_key(private_key).await;
                        let _ = reply.send(result);
                    }
                    WorkerCommand::Counters(reply) => {
                        let counters = state.counters().await.unwrap_or_default();
                        let _ = reply.send(counters);
                    }
                    WorkerCommand::Stop(reply) => {
                        let result = state.stop().await;
                        let _ = reply.send(result);
                        return;
                    }
                    #[cfg(any(test, feature = "test-support"))]
                    WorkerCommand::Admission(reply) => {
                        let _ = reply.send(Arc::clone(&state.admission));
                    }
                }
            }
            () = confirmed_changed(confirmed), if !confirmed_scan.is_armed() => {
                confirmed_scan.arm(Instant::now());
            }
            () = confirmed_scan.wait() => {
                confirmed_scan.start();
                let endpoints = state.admit_confirmed_endpoints().await;
                if H::reconcile_networks(&mut state, Some(&endpoints)).await
                    && let Some(announcer) = announcer.as_mut()
                {
                    H::resync_underlay(announcer);
                }
                confirmed_scan.finish(Instant::now());
            }
            () = announcement_due::<H>(announcer.as_mut()) => {
                if let Some(device) = &state.device
                    && let Some(sessions) = announce_underlay_on_route_event(
                        announcer.as_mut(),
                        || state.udp.underlay_changed(),
                        async || device.request_keepalives().await,
                    ).await
                {
                    tracing::debug!(sessions, "underlay changed; live sessions announce our endpoint");
                }
            }
            () = crate::candidate_walks::walk_due(next_walk), if next_walk.is_some() => {
                state.step_walks().await;
            }
            // Reap finished handshake tasks; their result shows in the peer counters.
            Some(_) = state.handshakes.join_next(), if !state.handshakes.is_empty() => {}
        }
    }
    let _ = state.stop().await;
}

/// Handle a coalesced route event when the connected-send listener is active.
///
/// No listener means the event cannot invalidate cached sources or request keepalives. With a
/// listener, invalidate sources before asking live sessions to announce their new endpoint.
pub async fn announce_underlay_on_route_event<T>(
    announcer: Option<&mut T>,
    invalidate_sources: impl FnOnce(),
    request_keepalives: impl AsyncFnOnce() -> usize,
) -> Option<usize> {
    announcer?;
    Some(announce_underlay(invalidate_sources, request_keepalives).await)
}

/// Wait for the listener's next announcement. With no utun, this branch stays pending.
async fn announcement_due<H: HostNet>(announcer: Option<&mut H::Underlay>) {
    match announcer {
        Some(announcer) => H::underlay_due(announcer).await,
        None => std::future::pending().await,
    }
}

/// Invalidate every cached source before walking the live sessions for keepalives (#260).
/// The walk may find no eligible session, and its keepalive sends can only invalidate the
/// endpoints they use. A busy peer must be able to reconnect on its next data send either way.
pub async fn announce_underlay(
    invalidate_sources: impl FnOnce(),
    request_keepalives: impl AsyncFnOnce() -> usize,
) -> usize {
    invalidate_sources();
    request_keepalives().await
}
