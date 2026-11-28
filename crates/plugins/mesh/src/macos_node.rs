//! Restores the Mac userspace Mesh node and its utun routes across daemon lifetimes.

use crate::dataplane::Config;
#[cfg(test)]
use crate::handshake_admission::PeerAdmission;
use crate::packet_filter::PacketFilter;
use gotatun::x25519::StaticSecret;
#[cfg(test)]
use gotatun::{
    device::Peer as WireGuardPeer,
    udp::{UdpTransportFactoryParams, socket::UdpSocketFactory},
};
use infraternal_mesh_node::engine::node::{NodeHost, NodeStore, SavedState};
#[cfg(test)]
use infraternal_mesh_node::engine::udp::BoundUdpFactory;
use infraternal_mesh_node::engine::utun::{UtunRx as MacUtunRx, UtunTx as MacUtunTx};
#[cfg(test)]
use infraternal_mesh_node::engine::utun::{parse_utun_payload, utun_family};
use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    sys::socket::{
        AddressFamily, SockFlag, SockProtocol, SockType, SysControlAddr, connect, getsockopt,
        socket, sockopt::UtunIfname,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::IpAddr,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};
use tokio::io::unix::AsyncFd;
#[cfg(test)]
use tokio::sync::mpsc;
use tokio::sync::watch;
#[cfg(test)]
use tokio::{runtime::Builder as RuntimeBuilder, sync::RwLock};
use zeroize::Zeroizing;

/// Subnet routes on the utun: the worker's reconcile and its published status (D197 M3, #580).
mod subnet;
/// User-mode helper requests for the utun, its routes and the resolver (#146).
mod user_mode;
/// The Mac routing socket and connected UDP setting (#515).
mod walks;
#[cfg(feature = "mesh-dns")]
use infraternal_mesh_node::engine::utun::TunnelDns;
#[cfg(feature = "mesh-dns")]
use user_mode::configure_host_dns;
use user_mode::{HelperApplied, configure_through_helper, user_mode_interface_mtu};

const UTUN_CONTROL: &str = "com.apple.net.utun_control";
const PUBLIC_STATE: &str = "mesh-public.json";
const MAX_PUBLIC_STATE_BYTES: u64 = 16 * 1024 * 1024;

/// Pause a Mac rotation child at a durable boundary so its parent can send SIGKILL.
#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "Test-only crash checkpoint panics when the harness omits its readiness path."
)]
pub(crate) fn rotation_crash_checkpoint(name: &str) {
    if std::env::var("INFRATERNAL_MAC_ROTATION_CRASH_POINT").as_deref() != Ok(name) {
        return;
    }
    let ready = std::env::var_os("INFRATERNAL_MAC_ROTATION_CRASH_READY")
        .expect("the crash proof supplies a readiness path");
    fs::write(ready, name).expect("publish the reached Mac rotation boundary");
    loop {
        std::thread::park();
    }
}

/// Pause a Mac authority replacement after durable state is written but before peers are swapped.
#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "Test-only crash checkpoint panics when the readiness file cannot be written."
)]
pub(crate) fn authority_replacement_crash_checkpoint() {
    let Some(ready) = std::env::var_os("INFRATERNAL_MAC_AUTHORITY_REPLACEMENT_READY") else {
        return;
    };
    fs::write(ready, b"replacement persisted; worker swap not entered")
        .expect("publish the reached Mac authority boundary");
    loop {
        std::thread::park();
    }
}

/// The routing-socket listener that announces underlay changes to live sessions (#483).
mod underlay;

/// Shared device runtime specialized with the Mac host effects.
type RuntimeState = infraternal_mesh_node::engine::runtime::RuntimeState<MacHostNet>;

use infraternal_mesh_node::engine::runtime::{HostNet, PathBudgets, installed_peers};

#[cfg(test)]
use infraternal_mesh_node::engine::{
    config::stage_chunk,
    node::{
        NodeState, reconcile,
        snapshot_binding_is_authorized as macos_snapshot_binding_is_authorized, validate_config,
    },
    runtime::{
        J472_REBUILDS, RuntimeInfo, Worker, WorkerCommand, installed_keys, route_mtus_to_refresh,
        validate_underlay_routes,
    },
};

/// Convert test snapshots with the shipping second-socket switch.
#[cfg(test)]
fn peers_for_config(config: &Config) -> io::Result<Vec<WireGuardPeer>> {
    infraternal_mesh_node::engine::runtime::peers_for_config(config, MacHostNet::side_socket())
}

/// Convert one peer with a test-selected second-socket switch.
#[cfg(test)]
fn peer_for_policy_with(
    policy: &crate::dataplane::PeerPolicy,
    side_socket: bool,
) -> io::Result<Vec<WireGuardPeer>> {
    infraternal_mesh_node::engine::runtime::peer_for_policy(policy, side_socket)
}

#[cfg(test)]
use infraternal_mesh_node::peer_stats::CounterMap;
/// Peer counters exposed by the Mac node.
pub use infraternal_mesh_node::peer_stats::Counters;

/// One utun control socket and the interface name the kernel gave it.
pub struct OpenUtun {
    /// The non-blocking, close-on-exec utun control socket; closing it destroys the interface.
    pub(crate) fd: OwnedFd,
    /// The interface name, such as `utun7`.
    pub(crate) name: String,
}

impl OpenUtun {
    /// Get one fresh utun: from the kernel when root, from the helper in user mode (#146).
    /// # Errors
    /// Returns socket-control, interface lookup or helper failures.
    fn open() -> io::Result<Self> {
        if crate::macos_helper::user_mode() {
            let (fd, name) = crate::macos_helper::open_utun()?;
            return Ok(Self { fd, name });
        }
        Self::open_kernel()
    }

    /// Ask the kernel for one fresh utun and read back the assigned interface unit.
    ///
    /// Needs root. The user-mode helper calls this on the agent's behalf.
    /// # Errors
    /// Returns socket-control or interface lookup failures.
    pub(crate) fn open_kernel() -> io::Result<Self> {
        let fd = socket(
            AddressFamily::System,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::KextControl,
        )
        .map_err(|error| utun_setup_error("PF_SYSTEM socket", error))?;
        fcntl(&fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
            .map_err(|error| utun_setup_error("nonblocking setup", error))?;
        fcntl(&fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|error| utun_setup_error("close-on-exec setup", error))?;
        let control = SysControlAddr::from_name(fd.as_raw_fd(), UTUN_CONTROL, 0)
            .map_err(|error| utun_setup_error("control lookup", error))?;
        connect(fd.as_raw_fd(), &control)
            .map_err(|error| utun_setup_error("control connect", error))?;
        let name = getsockopt(&fd, UtunIfname)
            .map_err(|error| utun_setup_error("interface name lookup", error))?
            .into_string()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "utun interface name is not valid UTF-8.",
                )
            })?;
        if !valid_utun_name(&name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "utun interface name is invalid.",
            ));
        }
        Ok(Self { fd, name })
    }
}

fn utun_setup_error(stage: &str, error: nix::errno::Errno) -> io::Error {
    let error = io::Error::from(error);
    io::Error::new(error.kind(), format!("utun {stage}: {error}"))
}

/// Owns one dynamically assigned utun control socket and its exact interface name.
#[derive(Clone)]
pub struct MacUtun {
    fd: Arc<AsyncFd<OwnedFd>>,
    name: Arc<str>,
    mtu: watch::Sender<u16>,
    filter: Arc<PacketFilter>,
    /// The last address and resolver requests the user-mode helper carried out for this utun.
    ///
    /// Every accepted snapshot reapplies the interface and resolver, but each helper request
    /// costs a launchd start and several system tools, so an identical request is skipped
    /// (#146). Root mode leaves this empty.
    helper_applied: Arc<std::sync::Mutex<HelperApplied>>,
    /// The mesh resolver address and the names to answer there from the tunnel (user mode,
    /// #146, J1027 F2); empty until the first snapshot with DNS, and always empty in root mode.
    #[cfg(feature = "mesh-dns")]
    tunnel_dns: TunnelDns,
}

impl MacUtun {
    /// Register one previously opened utun descriptor with this daemon's tokio runtime.
    /// # Errors
    /// Returns readiness registration failures.
    fn from_open(open: OpenUtun, filter: Arc<PacketFilter>) -> io::Result<Self> {
        // Tokio's safe constructor is deprecated but remains the only safe API;
        // the replacement requires unsafe code, which this crate forbids.
        #[allow(deprecated)]
        let fd = AsyncFd::new(open.fd)?;
        let (mtu, _) = watch::channel(crate::mesh_mtu::IPV6_MINIMUM_MTU);
        Ok(Self {
            fd: Arc::new(fd),
            name: Arc::from(open.name),
            mtu,
            filter,
            helper_applied: Arc::default(),
            #[cfg(feature = "mesh-dns")]
            tunnel_dns: Arc::default(),
        })
    }

    fn name(&self) -> &str {
        &self.name
    }

    /// Build the send adapter with a watcher for this utun's current shared interface MTU.
    fn sender(&self) -> MacUtunTx {
        MacUtunTx::new(
            Arc::clone(&self.fd),
            self.mtu.subscribe().into(),
            Arc::clone(&self.filter),
        )
    }

    /// Build the receive adapter with a watcher for this utun's current shared interface MTU.
    fn receiver(&self) -> MacUtunRx {
        MacUtunRx::new(
            Arc::clone(&self.fd),
            self.mtu.subscribe().into(),
            Arc::clone(&self.filter),
            #[cfg(feature = "mesh-dns")]
            Arc::clone(&self.tunnel_dns),
        )
    }

    /// Publish an MTU change to the utun send and receive packet workers.
    fn set_mtu(&self, mtu: u16) {
        self.mtu.send_replace(mtu);
    }
}

/// Add, change or remove one peer host route through our allocated utun.
///
/// Add and change operations carry an unlocked route MTU so the system can refine it with later
/// PMTU information. Deletes carry no MTU.
/// # Errors
/// Reports invalid operation arguments, routing command failures, or an unexpected missing route.
fn route(interface: &str, address: IpAddr, operation: &str, mtu: Option<u16>) -> io::Result<()> {
    if operation != "delete" && mtu.is_none() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let family = if address.is_ipv4() { "-inet" } else { "-inet6" };
    let mut command = Command::new("/sbin/route");
    command
        .args(["-n", operation, family, "-host"])
        .arg(address.to_string())
        .args(["-interface", interface]);
    let mtu_argument = mtu.map(|mtu| mtu.to_string());
    if let Some(mtu) = mtu_argument.as_deref() {
        command.args(["-mtu", mtu]);
    }
    let output = command.output()?;
    if output.status.success()
        || (operation == "delete"
            && String::from_utf8_lossy(&output.stderr)
                .to_ascii_lowercase()
                .contains("not in table"))
    {
        Ok(())
    } else {
        Err(io::ErrorKind::AddrInUse.into())
    }
}

/// Whether `name` is a utun interface name (`utun` and decimal digits).
pub(crate) fn valid_utun_name(name: &str) -> bool {
    name.strip_prefix("utun")
        .is_some_and(|unit| !unit.is_empty() && unit.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Delete only peer host routes installed through the validated utun interface.
/// # Errors
/// Rejects a malformed utun name or reports a route deletion failure.
fn remove_routes(interface: &str, routes: &BTreeSet<IpAddr>) -> io::Result<()> {
    if !valid_utun_name(interface) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    for address in routes {
        route(interface, *address, "delete", None)?;
    }
    Ok(())
}

/// Configure this owned utun at an IPv6-safe MTU and install its local addresses.
///
/// Callers pass a staging MTU no smaller than either the old or new peer budget until route
/// metrics have been updated. No other tunnel or resolver is changed. In user mode the helper
/// does it, given the utun itself, and also routes the mesh prefixes there (#146).
fn configure_interface(utun: &MacUtun, config: Option<&Config>, mtu: u16) -> io::Result<()> {
    if crate::macos_helper::user_mode() {
        return configure_through_helper(utun, config, mtu);
    }
    configure_owned_interface(utun.name(), config, mtu)
}

/// Root mode's half of [`configure_interface`]: set the MTU, bring the named utun up and add
/// the mesh addresses, all from this (root) process.
/// # Errors
/// Reports a rejected kernel request or `ifconfig` run.
fn configure_owned_interface(interface: &str, config: Option<&Config>, mtu: u16) -> io::Result<()> {
    // Kernel ioctls, not an `ifconfig` process: the spawn cost about 3.5 ms per start (#221).
    crate::macos_utun_ioctl::set_mtu_and_up(interface, mtu)?;
    if let Some(config) = config {
        run_ifconfig([
            interface,
            "inet",
            &config.addresses.ipv4.to_string(),
            &config.addresses.ipv4.to_string(),
            "netmask",
            "255.255.255.255",
        ])?;
        run_ifconfig([
            interface,
            "inet6",
            &config.addresses.ipv6.to_string(),
            "prefixlen",
            "128",
            "alias",
        ])?;
    }
    Ok(())
}

/// Change the packet size on the already-owned utun interface (through the helper in user mode).
/// # Errors
/// Reports a rejected kernel request (`SIOCSIFMTU`) or helper request.
fn set_interface_mtu(utun: &MacUtun, mtu: u16) -> io::Result<()> {
    if crate::macos_helper::user_mode() {
        return configure_through_helper(utun, None, mtu);
    }
    crate::macos_utun_ioctl::set_mtu(utun.name(), mtu)
}

fn run_ifconfig<'a>(arguments: impl IntoIterator<Item = &'a str>) -> io::Result<()> {
    let output = Command::new("/sbin/ifconfig").args(arguments).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::ErrorKind::Other.into())
    }
}

/// The portable node specialized for the Mac host.
pub type Node = infraternal_mesh_node::engine::node::Node<MacHostNet>;

impl NodeHost for MacHostNet {
    type Store = crate::node_state::Store;

    fn check_enrolled_machine(state: &Path) -> io::Result<()> {
        crate::macos_machine::check_existing(state)
    }

    fn prepare_restore(state: &Path, enrolment: Option<&Enrolment>) -> io::Result<()> {
        // Refuse copied state before opening the old key or starting a runtime (#221).
        if enrolment.is_some() {
            crate::macos_machine::bind(state, crate::macos_machine::fingerprint())?;
        }
        Ok(())
    }

    fn public_state_path(state: &Path) -> PathBuf {
        state.join(PUBLIC_STATE)
    }

    fn valid_interface_name(name: &str) -> bool {
        valid_utun_name(name)
    }

    fn open_tunnel() -> io::Result<OpenUtun> {
        OpenUtun::open()
    }

    fn listen_port(saved: Option<u16>) -> io::Result<crate::listen_port::Request> {
        crate::listen_port::from_environment(saved)
    }

    fn network_route_state(
        status: &Self::NetworkStatus,
        network: crate::policy::networks::Network,
    ) -> serde_json::Value {
        status.route_json(network)
    }

    fn dns_state() -> serde_json::Value {
        #[cfg(feature = "mesh-dns")]
        {
            serde_json::json!(crate::dns_integration::macos_installed_state())
        }
        #[cfg(not(feature = "mesh-dns"))]
        {
            serde_json::Value::Null
        }
    }

    #[cfg(test)]
    fn rotation_checkpoint(name: &str) {
        rotation_crash_checkpoint(name);
    }

    #[cfg(test)]
    fn authority_replacement_checkpoint() {
        authority_replacement_crash_checkpoint();
    }
}

/// Applies node networking through the macOS kernel or the user-mode helper.
pub struct MacHostNet;

impl HostNet for MacHostNet {
    type OpenTunnel = OpenUtun;
    type Tunnel = MacUtun;
    type NetworkStatus = subnet::NetworkStatus;

    fn register(open: OpenUtun, filter: Arc<PacketFilter>) -> io::Result<MacUtun> {
        MacUtun::from_open(open, filter)
    }

    fn tunnel_name(utun: &MacUtun) -> &str {
        utun.name()
    }

    fn sender(utun: &MacUtun) -> MacUtunTx {
        utun.sender()
    }

    fn receiver(utun: &MacUtun) -> MacUtunRx {
        utun.receiver()
    }

    fn set_packet_mtu(utun: &MacUtun, mtu: u16) {
        utun.set_mtu(mtu);
    }

    fn filter(utun: &MacUtun) -> &PacketFilter {
        &utun.filter
    }

    fn connected_udp() -> bool {
        walks::mac_connected_sends_enabled()
    }

    fn side_socket() -> bool {
        crate::side_socket::enabled()
    }

    fn route_addresses(config: &Config) -> BTreeSet<IpAddr> {
        route_addresses(config)
    }

    type Underlay = underlay::UnderlayAnnouncer;

    fn start_underlay(tunnel_name: Option<&str>) -> Option<Self::Underlay> {
        walks::start_underlay_listener(tunnel_name, Self::connected_udp())
    }

    async fn underlay_due(listener: &mut Self::Underlay) {
        listener.due().await;
    }

    fn resync_underlay(listener: &mut Self::Underlay) {
        listener.resync();
    }

    async fn reconcile_networks<'a>(
        state: &'a mut RuntimeState,
        confirmed: Option<&'a [(crate::policy::model::PublicKey, std::net::SocketAddr)]>,
    ) -> bool {
        subnet::RuntimeNetworks::reconcile_networks(state, confirmed).await
    }

    fn remove_networks(state: &mut RuntimeState) {
        subnet::RuntimeNetworks::remove_networks(state);
    }

    #[cfg(feature = "mesh-dns")]
    type Resolver = crate::dns::Resolver;

    #[cfg(feature = "mesh-dns")]
    type DnsIntegration = crate::dns_integration::DnsIntegration;

    #[cfg(feature = "mesh-dns")]
    fn publish_dns(resolver: &Self::Resolver, records: crate::dns::Records) {
        resolver.publish(records);
    }

    #[cfg(feature = "mesh-dns")]
    fn stop_dns(
        integration: &mut Self::DnsIntegration,
        resolver: &mut Option<Self::Resolver>,
    ) -> io::Result<()> {
        if crate::macos_helper::user_mode() {
            *resolver = None;
            return crate::macos_helper::request(
                &crate::macos_user_mode::Request::ClearResolver,
                None,
            )
            .map(|_| ());
        }
        integration.remove()?;
        *resolver = None;
        Ok(())
    }

    fn configure_interface(utun: &MacUtun, config: Option<&Config>, mtu: u16) -> io::Result<()> {
        configure_interface(utun, config, mtu)
    }

    fn set_interface_mtu(utun: &MacUtun, mtu: u16) -> io::Result<()> {
        set_interface_mtu(utun, mtu)
    }

    fn route(
        interface: &str,
        address: IpAddr,
        operation: &str,
        mtu: Option<u16>,
    ) -> io::Result<()> {
        route(interface, address, operation, mtu)
    }

    fn remove_routes(interface: &str, routes: &BTreeSet<IpAddr>) -> io::Result<()> {
        remove_routes(interface, routes)
    }

    fn probe_paths(config: Option<&Config>) -> PathBudgets {
        probe_paths(config)
    }

    #[cfg(feature = "mesh-dns")]
    fn bind_dns(config: &Config) -> io::Result<crate::dns::Resolver> {
        crate::dns::Resolver::bind(config)
    }

    #[cfg(feature = "mesh-dns")]
    fn configure_dns(
        integration: &mut crate::dns_integration::DnsIntegration,
        utun: &MacUtun,
        records: &crate::dns::Records,
        address: std::net::Ipv6Addr,
    ) -> io::Result<()> {
        configure_host_dns(integration, utun, records, address)
    }

    #[cfg(feature = "mesh-dns")]
    fn clear_dns() -> io::Result<()> {
        crate::dns_integration::DnsIntegration::default().remove()
    }
}

impl NodeStore for crate::node_state::Store {
    fn load_public(path: &Path) -> io::Result<Option<SavedState>> {
        read_public_state(path)
    }

    fn store_public(path: &Path, state: &SavedState) -> io::Result<()> {
        write_public_state(path, state)
    }

    fn fence_public(path: &Path, state: &SavedState) -> io::Result<()> {
        write_public_state_in_place(path, state)
    }

    fn replace_public(path: &Path, state: &SavedState, expected: &Config) -> io::Result<()> {
        write_public_state_full_snapshot(path, state, expected)
    }

    fn load_private(&self) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        self.read_private_key()
    }

    fn open_private(state: &Path) -> io::Result<(StaticSecret, crate::policy::model::PublicKey)> {
        crate::macos_key::load_or_create(state)
    }

    fn record_rotation_identity(
        &self,
        operation: &str,
        sequence: u64,
        private: &[u8],
        public: &crate::policy::model::PublicKey,
    ) -> io::Result<()> {
        Self::record_rotation_identity(self, operation, sequence, private, public)
    }

    fn retire_private(state: &Path) -> io::Result<()> {
        crate::macos_key::retire_key(state, crate::macos_key::RotationReason::EnrolmentChanged)
    }

    fn open(state: &Path) -> io::Result<Self> {
        Self::open_for_macos(state)
    }

    fn discard_rotation_state(&self) -> io::Result<()> {
        Self::discard_rotation_state(self)
    }

    fn recorded_interface(&self) -> io::Result<Option<crate::policy::model::PublicKey>> {
        Self::recorded_interface(self)
    }

    fn record_interface(&self, key: &crate::policy::model::PublicKey) -> io::Result<()> {
        Self::record_interface(self, key)
    }

    fn recorded_listen_port(&self) -> io::Result<Option<u16>> {
        Self::recorded_listen_port(self)
    }

    fn record_listen_port(&self, port: u16) -> io::Result<()> {
        Self::record_listen_port(self, port)
    }

    fn rotation_secret(&self) -> io::Result<Option<crate::node_state::RotationSecret>> {
        Self::rotation_secret(self)
    }

    fn save_rotation_secret(&self, state: &crate::node_state::RotationSecret) -> io::Result<()> {
        Self::save_rotation_secret(self, state)
    }

    fn rotation_matches(
        &self,
        operation: Option<&crate::dataplane::RotationContinuation>,
    ) -> io::Result<bool> {
        Self::rotation_matches(self, operation)
    }

    fn complete_rotation_secret(&self, operation_id: &str, sequence: u64) -> io::Result<()> {
        Self::complete_rotation_secret(self, operation_id, sequence)
    }

    fn discard_rotation_journal(&self) -> io::Result<()> {
        Self::discard_rotation_journal(self)
    }
}

pub use crate::enrolment::{Enrolment, MachineBindingError};

/// Forget this node's mesh state and key so the next start registers afresh (`agent join`).
/// # Errors
/// Refuses an exposed state directory and reports failed removals.
pub fn forget(state: &Path) -> io::Result<()> {
    match fs::symlink_metadata(state) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    crate::node_state::Store::open_for_macos(state)?.discard_rotation_state()?;
    <crate::node_state::Store as NodeStore>::retire_private(state)?;
    match fs::remove_file(state.join(PUBLIC_STATE)) {
        Ok(()) => File::open(state)?.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// How this node enforces D164 access rules, as `mesh status` reports it.
pub const ENFORCEMENT: &str = "userspace";

/// Return every configured peer address for the utun; the packet filter applies its grants.
///
/// User mode adds no per-peer host routes: the helper routes the whole mesh prefix to the
/// utun once (#146), so the set is empty and every per-peer route step is skipped.
fn route_addresses(config: &Config) -> BTreeSet<IpAddr> {
    if crate::macos_helper::user_mode() {
        return BTreeSet::new();
    }
    config
        .peers
        .values()
        .flat_map(|policy| policy.peer.routed_addresses())
        .collect()
}

/// Probe each distinct underlay path once. `None` means no peers yet.
fn probe_paths(config: Option<&Config>) -> PathBudgets {
    let mut probe = crate::mesh_mtu::EndpointProbe::default();
    let mut route_mtus = BTreeMap::new();
    let mut peer_mtus = Vec::new();
    if let Some(config) = config {
        for policy in config.peers.values() {
            let mtu = probe.mesh_mtu(policy.peer.endpoint);
            for address in policy.peer.routed_addresses() {
                route_mtus.insert(address, mtu);
            }
        }
        peer_mtus.extend(
            config
                .peers
                .values()
                .map(|policy| probe.mesh_mtu(policy.peer.endpoint)),
        );
    }
    let interface_mtu = if crate::macos_helper::user_mode() {
        user_mode_interface_mtu(&peer_mtus)
    } else {
        crate::mesh_mtu::interface_mtu(&peer_mtus)
    };
    PathBudgets {
        route_mtus,
        interface_mtu,
    }
}

/// Refuse an endpoint that a host route would send back into this tunnel.
/// Read one bounded public snapshot without following links or accepting exposed files.
/// # Errors
/// Refuses an unsafe parent, file owner or mode and malformed public state.
fn read_public_state(path: &Path) -> io::Result<Option<SavedState>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > MAX_PUBLIC_STATE_BYTES
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut body = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.read_to_end(&mut body)?;
    let mut state: SavedState =
        serde_json::from_slice(&body).map_err(|_| io::ErrorKind::InvalidData)?;
    if state.authority_reset_pending
        && state.config.as_ref().is_none_or(|config| {
            !config.peers.is_empty()
                || config.default_policy != crate::dataplane::DefaultPolicy::Deny
        })
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    crate::node_state::merge_authority(
        state.config.as_mut(),
        &mut state.authority_reset_pending,
        crate::node_state::read_authority(&authority_path(path)),
    );
    Ok(Some(state))
}

/// The authority record beside a Mac public snapshot (see [`crate::node_state::AuthorityRecord`]).
fn authority_path(path: &Path) -> PathBuf {
    path.with_file_name(crate::node_state::AUTHORITY_FILE)
}

/// Encode `state` in the shape the previous release parses (D295), plus its authority record.
/// # Errors
/// Reports a serialization failure.
fn encode_public_state(
    state: &SavedState,
) -> io::Result<(Vec<u8>, crate::node_state::AuthorityRecord)> {
    let (config, authority) = infraternal_mesh_node::node_state::split_authority(
        state.config.as_ref(),
        state.authority_reset_pending,
    );
    let mut legacy = state.clone();
    legacy.config = config;
    legacy.authority_reset_pending = false;
    Ok((
        serde_json::to_vec(&legacy).map_err(io::Error::other)?,
        authority,
    ))
}

/// Atomically persist a bounded public snapshot with root-only file permissions.
/// # Errors
/// Refuses an unsafe directory or replacement file and reports failed durable writes.
fn write_public_state(path: &Path, state: &SavedState) -> io::Result<()> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let directory = fs::symlink_metadata(parent)?;
    let uid = nix::unistd::Uid::effective().as_raw();
    if !directory.is_dir() || directory.uid() != uid || directory.mode() & 0o777 != 0o700 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    validate_state_file(path, uid)?;
    let (body, authority) = encode_public_state(state)?;
    if body.len() as u64 > MAX_PUBLIC_STATE_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // A restart usually saves the snapshot it already has; skip the replacement then (#221).
    if crate::node_state::existing_matches(path, &body) {
        return crate::node_state::write_authority(&authority_path(path), &authority);
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temporary = parent.join(format!(".mesh-public.{}.{}.new", std::process::id(), nonce));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(&body)?;
        file.sync_all()?;
        validate_state_file(path, uid)?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    // The snapshot goes first; an older record left by a stop here is honoured only where safe.
    result.and_then(|()| crate::node_state::write_authority(&authority_path(path), &authority))
}

/// Compare and replace one lower-revision full snapshot under the mesh state update lock.
///
/// This transaction is for a same-authority rollback only. Authority changes continue through
/// the peer-free checkpoint path, which carries its own durable reset marker.
/// # Errors
/// Refuses a stale base, changed authority, reset state, or a failed atomic write.
fn write_public_state_full_snapshot(
    path: &Path,
    state: &SavedState,
    expected: &Config,
) -> io::Result<()> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    // Not an exclusive directory lock: this node's own open Store holds a shared lease on it.
    let _guard = crate::node_state::lock_mesh_state_update(parent)?;
    let previous = read_public_state(path)?.ok_or(io::ErrorKind::InvalidData)?;
    let old = previous.config.as_ref().ok_or(io::ErrorKind::InvalidData)?;
    let next = state.config.as_ref().ok_or(io::ErrorKind::InvalidData)?;
    if !previous.enabled
        || previous.authority_reset_pending
        || state.authority_reset_pending
        || old != expected
        || old.authority_epoch != next.authority_epoch
        || next.version >= old.version
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    write_public_state(path, state)
}

/// Overwrite an existing private Mac snapshot when atomic replacement cannot complete.
///
/// This is the last safe write when a directory rename fails. A torn write leaves malformed state
/// that restore refuses instead of replaying the old peer set; atomic replacement stays the normal
/// path.
/// # Errors
/// Refuses unsafe parent/file metadata, oversized state or failed durable writes.
fn write_public_state_in_place(path: &Path, state: &SavedState) -> io::Result<()> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let directory_metadata = fs::symlink_metadata(parent)?;
    let uid = nix::unistd::Uid::effective().as_raw();
    if !directory_metadata.is_dir()
        || directory_metadata.uid() != uid
        || directory_metadata.mode() & 0o077 != 0
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let (body, authority) = encode_public_state(state)?;
    if body.len() as u64 > MAX_PUBLIC_STATE_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(parent)?;
    // Shared: the node's own Store holds a shared lease here, and only migration locks it
    // exclusively. The writer lock file can't be used, since this directory may be read-only.
    let _lease = nix::fcntl::Flock::lock(directory, nix::fcntl::FlockArg::LockShared)
        .map_err(|(_, error)| error)?;
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o777 != 0o600 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    file.set_len(0)?;
    file.write_all(&body)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    // The peer-free snapshot is the safety-critical write; a missing record only makes restore
    // wait for the server's next full snapshot.
    if let Err(error) = crate::node_state::write_authority(&authority_path(path), &authority) {
        tracing::warn!(
            error_kind = ?error.kind(),
            "Mac mesh authority record not updated after an in-place fail-closed write"
        );
    }
    Ok(())
}

fn validate_state_file(path: &Path, uid: u32) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file() && metadata.uid() == uid && metadata.mode() & 0o777 == 0o600 =>
        {
            Ok(())
        }
        Ok(_) => Err(io::ErrorKind::PermissionDenied.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Select the address-family header macOS requires for a complete IP packet.
/// # Errors
/// Rejects empty packets and unsupported IP versions.
#[cfg(test)]
/// Bind the listener using the host's connected-send setting.
async fn bind_udp(
    request: crate::listen_port::Request,
    private_key: StaticSecret,
) -> io::Result<(BoundUdpFactory, u16)> {
    infraternal_mesh_node::engine::udp::bind_udp(
        request,
        private_key,
        walks::mac_connected_sends_enabled(),
    )
    .await
}

/// Checks Mac peer routing, configuration validation, and atomic snapshot staging.
#[cfg(test)]
mod tests;
