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
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, SocketAddr},
    sync::mpsc as sync,
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[cfg(feature = "relay")]
use std::sync::Arc;
use tokio::{
    runtime::Builder as RuntimeBuilder,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
};

use crate::{dataplane::Config, gotatun_tun::LinuxTun, policy::model::PublicKey};

type GotaDevice = WireGuardDevice<(BoundUdpFactory, LinuxPacketIo, LinuxPacketIo)>;
type CounterMap = BTreeMap<PublicKey, crate::wireguard::Counters>;

/// Selects the node's data plane; kernel `WireGuard` remains an explicit migration fallback.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum EngineKind {
    #[default]
    GotaTun,
    Kernel,
}

impl EngineKind {
    /// Parse the per-node `INFRATERNAL_MESH_ENGINE` override.
    /// # Errors
    /// Refuses unknown values instead of silently selecting a different engine.
    pub fn parse(value: Option<&str>) -> io::Result<Self> {
        match value {
            None | Some("gotatun") => Ok(Self::GotaTun),
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
    Endpoint {
        key: PublicKey,
        endpoint: SocketAddr,
        reply: sync::SyncSender<io::Result<()>>,
    },
    #[cfg(feature = "relay")]
    ForceHandshake {
        key: PublicKey,
        reply: sync::SyncSender<io::Result<()>>,
    },
    Stop(sync::SyncSender<()>),
}

/// Synchronous handle to the dedicated `GotaTun` runtime thread.
pub(crate) struct Engine {
    commands: UnboundedSender<WorkerCommand>,
    join: Option<JoinHandle<()>>,
    info: RuntimeInfo,
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
                let startup_config = config.clone();
                let initialized = runtime.block_on(async move {
                    let kernel_owned = crate::wireguard::Device::owned()?;
                    let tun_owned = crate::wireguard::Device::owned_tun()?;
                    if kernel_owned || tun_owned {
                        return Err(io::ErrorKind::AlreadyExists.into());
                    }
                    let tun = LinuxTun::create(crate::wireguard::INTERFACE)?;
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
                    let peers = startup_config
                        .as_ref()
                        .map(peers_for_config)
                        .transpose()?
                        .unwrap_or_default();
                    // GotaTun starts its packet workers only when the builder has peers.
                    // Node::up precedes the coordinator's first snapshot, so keep the bound
                    // transport and key until that first nonempty peer set is available.
                    let (device, pending) = if peers.is_empty() {
                        (
                            None,
                            Some(PendingDevice {
                                factory,
                                private_key,
                            }),
                        )
                    } else {
                        (
                            Some(
                                build_device(factory, private_key, port, peers, tun.clone())
                                    .await?,
                            ),
                            None,
                        )
                    };
                    let info = RuntimeInfo {
                        interface,
                        port,
                        thp_disabled,
                        offloads_enabled,
                    };
                    Ok((tun, device, pending, info))
                });
                let (tun, device, pending, info) = match initialized {
                    Ok(initialized) => initialized,
                    Err(error) => {
                        let _ = info_tx.send(Err(error));
                        return;
                    }
                };
                if info_tx.send(Ok(info.clone())).is_err() {
                    if let Some(device) = device {
                        runtime.block_on(device.stop());
                    }
                    return;
                }
                let state = RuntimeState {
                    tun: Some(tun),
                    device,
                    pending,
                    config,
                    info,
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
        })
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

    /// Redirect one configured peer to the loopback relay shim without changing its key/routes.
    /// # Errors
    /// Reports a stopped worker, an unknown peer, or a failed device update.
    pub(crate) fn set_endpoint(&self, key: PublicKey, endpoint: SocketAddr) -> io::Result<()> {
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::Endpoint {
                key,
                endpoint,
                reply,
            })
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        result.recv().map_err(|_| io::ErrorKind::BrokenPipe)?
    }

    /// Return a relay callback that forces the selected `GotaTun` peer to start a handshake.
    #[cfg(feature = "relay")]
    pub(crate) fn handshake_starter(&self, key: PublicKey) -> Arc<dyn Fn() + Send + Sync> {
        let commands = self.commands.clone();
        Arc::new(move || {
            let (reply, result) = sync::sync_channel(1);
            if commands
                .send(WorkerCommand::ForceHandshake { key, reply })
                .is_ok()
            {
                let _ = result.recv();
            }
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

fn engine_runtime() -> io::Result<(tokio::runtime::Runtime, bool)> {
    set_thp_disable(true).map_err(io::Error::from)?;
    let thp_disabled = get_thp_disable().map_err(io::Error::from)?;
    if !thp_disabled {
        return Err(io::ErrorKind::Unsupported.into());
    }
    let runtime = RuntimeBuilder::new_current_thread().enable_all().build()?;
    Ok((runtime, thp_disabled))
}

struct RuntimeState {
    tun: Option<LinuxPacketIo>,
    device: Option<GotaDevice>,
    pending: Option<PendingDevice>,
    config: Option<Config>,
    info: RuntimeInfo,
}

struct PendingDevice {
    factory: BoundUdpFactory,
    private_key: StaticSecret,
}

async fn run_worker(mut commands: UnboundedReceiver<WorkerCommand>, mut state: RuntimeState) {
    while let Some(command) = commands.recv().await {
        match command {
            WorkerCommand::Apply { config, reply } => {
                let _ = reply.send(state.apply(config).await);
            }
            WorkerCommand::Counters(reply) => {
                let _ = reply.send(state.counters().await);
            }
            WorkerCommand::Endpoint {
                key,
                endpoint,
                reply,
            } => {
                let _ = reply.send(state.set_endpoint(key, endpoint).await);
            }
            #[cfg(feature = "relay")]
            WorkerCommand::ForceHandshake { key, reply } => {
                let _ = reply.send(state.force_handshake(key).await);
            }
            WorkerCommand::Stop(reply) => {
                state.stop().await;
                let _ = reply.send(());
                break;
            }
        }
    }
}

impl RuntimeState {
    async fn set_endpoint(&mut self, key: PublicKey, endpoint: SocketAddr) -> io::Result<()> {
        let policy = self
            .config
            .as_ref()
            .and_then(|config| config.peers.values().find(|peer| peer.peer.key == key))
            .ok_or(io::ErrorKind::NotFound)?;
        let mut peer = peer_for_policy(policy)?;
        peer.endpoint = Some(endpoint);
        self.device
            .as_mut()
            .ok_or(io::ErrorKind::NotConnected)?
            .add_or_update_peers(vec![peer])
            .await
            .map_err(|_| io::Error::other("GotaTun relay endpoint could not be installed."))
    }

    #[cfg(feature = "relay")]
    async fn force_handshake(&self, key: PublicKey) -> io::Result<()> {
        let device = self.device.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let key = X25519PublicKey::from(key.0);
        tokio::time::timeout(Duration::from_secs(5), device.force_handshake(&key))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "GotaTun relay handshake did not complete within five seconds.",
                )
            })?
            .map_err(|_| io::Error::other("GotaTun relay handshake failed."))
    }

    async fn apply(&mut self, config: Config) -> io::Result<RuntimeInfo> {
        if self.device.is_none() {
            let peers = peers_for_config(&config)?;
            if peers.is_empty() {
                self.config = Some(config);
                return Ok(self.info.clone());
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
            self.device = Some(device);
            // The live device owns its copies; drop deferred startup material.
            self.pending.take();
            self.config = Some(config);
            return Ok(self.info.clone());
        }
        let desired: BTreeSet<_> = config
            .peers
            .values()
            .map(|policy| policy.peer.key)
            .collect();
        let device = self.device.as_mut().ok_or(io::ErrorKind::NotConnected)?;
        let old_config = self.config.clone();
        let changed = config
            .peers
            .iter()
            .filter(|(id, policy)| {
                old_config
                    .as_ref()
                    .and_then(|old| old.peers.get(id))
                    .is_none_or(|old| old.peer != policy.peer)
            })
            .map(|(_, policy)| peer_for_policy(policy))
            .collect::<io::Result<Vec<_>>>()?;
        if !changed.is_empty() {
            device
                .add_or_update_peers(changed)
                .await
                .map_err(|_| io::Error::other("GotaTun peers could not be updated."))?;
        }
        if let Some(old) = &old_config {
            for previous in old.peers.values().map(|policy| policy.peer.key) {
                if !desired.contains(&previous) {
                    let key = X25519PublicKey::from(previous.0);
                    device
                        .remove_peer(&key)
                        .await
                        .map_err(|_| io::Error::other("GotaTun peers could not be retired."))?;
                }
            }
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
        if let Some(device) = self.device.take() {
            device.stop().await;
        }
        self.pending.take();
        self.tun.take();
        self.config = None;
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

async fn bind_udp(requested_port: u16) -> io::Result<(BoundUdpFactory, u16)> {
    let mut factory = UdpSocketFactory::default();
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
    fn linux_defaults_to_gotatun() {
        assert_eq!(EngineKind::default(), EngineKind::GotaTun);
    }

    #[test]
    fn kernel_engine_is_available_as_a_transition_fallback() {
        assert_eq!(
            EngineKind::parse(Some("kernel")).expect("known engine"),
            EngineKind::Kernel
        );
    }

    #[test]
    fn peer_conversion_uses_coordinator_keys_endpoints_and_host_allowed_ips() {
        let endpoint: SocketAddr = "192.0.2.4:51831".parse().expect("endpoint");
        let config = Config {
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
                        endpoint: Some(endpoint),
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                },
            )]),
            #[cfg(feature = "mesh-dns-spike")]
            peer_names: BTreeMap::new(),
        };
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
