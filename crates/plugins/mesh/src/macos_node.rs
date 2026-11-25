//! Restores the Mac userspace Mesh node and its utun routes across daemon lifetimes.

use crate::dataplane::Config;
use crate::handshake_admission::{ConfirmedEndpointFeed, PeerAdmission, PeerAdmissionUdpReceiver};
use crate::packet_filter::{Direction, PacketFilter};
use bytes::Buf;
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
use infraternal_mesh::proxy_ports::MeshProxyIngress;
use ipnetwork::IpNetwork;
use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    sys::socket::{
        AddressFamily, SockFlag, SockProtocol, SockType, SysControlAddr, connect, getsockopt,
        socket, sockopt::UtunIfname,
    },
    unistd::{read, write},
};
use serde::{Deserialize, Serialize};
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
    sync::{Arc, mpsc as sync},
    thread::JoinHandle,
};
use tokio::io::unix::AsyncFd;
use tokio::{
    runtime::Builder as RuntimeBuilder,
    sync::{
        RwLock,
        mpsc::{self, UnboundedSender},
        watch,
    },
};
use zeroize::Zeroizing;

/// Mac DNS status.
mod dns_state;
/// Subnet routes on the utun: the worker's reconcile and its published status (D197 M3, #580).
mod subnet;
/// User-mode helper requests for the utun, its routes and the resolver (#146).
mod user_mode;
/// The worker loop, session-keeping peer updates and candidate walks (#515).
mod walks;
#[cfg(feature = "mesh-dns")]
use user_mode::TunnelDns;
#[cfg(feature = "mesh-dns")]
use user_mode::configure_host_dns;
use user_mode::{HelperApplied, configure_through_helper, user_mode_interface_mtu};

const UTUN_AF_INET: u32 = 2;
const UTUN_AF_INET6: u32 = 30;
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

type GotaDevice = WireGuardDevice<(BoundUdpFactory, MacUtunTx, MacUtunRx)>;

/// A temporary Mac rotation key that clears its private bytes when dropped.
struct RotationKey(Zeroizing<[u8; 32]>);

impl RotationKey {
    /// Generate a candidate identity with the system random source.
    /// # Errors
    /// Reports an unavailable random source or an invalid X25519 key.
    fn generate() -> io::Result<(Self, crate::policy::model::PublicKey)> {
        let mut private = Zeroizing::new([0_u8; 32]);
        openssl::rand::rand_bytes(&mut *private)
            .map_err(|_| io::Error::other("System random generator unavailable."))?;
        Self::from_private(&private[..])
    }

    /// Rebuild a temporary key from the private rotation journal.
    /// # Errors
    /// Refuses a private key with any length other than 32 bytes.
    fn from_private(bytes: &[u8]) -> io::Result<(Self, crate::policy::model::PublicKey)> {
        let private =
            Zeroizing::new(<[u8; 32]>::try_from(bytes).map_err(|_| io::ErrorKind::InvalidData)?);
        let secret = StaticSecret::from(*private);
        let public = X25519PublicKey::from(&secret);
        Ok((
            Self(private),
            crate::policy::model::PublicKey(*public.as_bytes()),
        ))
    }

    /// Borrow private bytes only long enough to write the protected key file.
    #[must_use]
    fn private_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Copy this key into `GotaTun`'s zeroizing secret type for a live update.
    fn gotatun_secret(&self) -> StaticSecret {
        StaticSecret::from(*self.0)
    }
}

/// Holds the already-bound UDP sockets and the live handshake admission state for `GotaTun`.
///
/// Every receive half it hands out runs the shared admission guard (J555 F2), so an initiation
/// from a key this Mac has not installed gets no reply, the same as on Linux. Clones share the
/// listener and the guard.
#[derive(Clone)]
struct BoundUdpFactory {
    send: GotaUdpSocket,
    receive: GotaUdpSocket,
    port: u16,
    admission: Arc<RwLock<PeerAdmission>>,
}

impl BoundUdpFactory {
    /// Bind the Mac node's direct-path probes to this factory's send socket and give the admission
    /// guard its half, as the Linux engine does (#220, D185, J1194).
    ///
    /// Without this the guard has no probes, so a probe-shaped datagram would reach `GotaTun` as
    /// garbage and no ping would ever be answered: a Linux peer measuring its direct path to this
    /// Mac would see a peer that never answers. With it the guard consumes pings from known peer
    /// endpoints (at most 64 pongs a second) and sends nothing on its own, so an idle Mac gains no
    /// wakeups (D81). The Mac has no path owner yet, so the finished answers go nowhere: the
    /// receiver is dropped and the probes never start a round of their own.
    async fn with_probes(
        send: GotaUdpSocket,
        receive: GotaUdpSocket,
        port: u16,
        admission: Arc<RwLock<PeerAdmission>>,
    ) -> Self {
        let (probes, _answers) =
            crate::direct_probe::DirectProbes::new(send.clone(), crate::direct_probe::token_seed());
        admission.write().await.set_probes(probes);
        Self {
            send,
            receive,
            port,
            admission,
        }
    }
}

impl UdpTransportFactory for BoundUdpFactory {
    type Send = GotaUdpSocket;
    type Recv = PeerAdmissionUdpReceiver;

    fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> impl std::future::Future<Output = io::Result<(Self::Send, Self::Recv)>> {
        if params.addr.is_some() || params.port != self.port {
            return std::future::ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        std::future::ready(Ok((
            self.send.clone(),
            PeerAdmissionUdpReceiver::new(self.receive.clone(), Arc::clone(&self.admission)),
        )))
    }
}

/// The identities a peer list installs in `GotaTun`, which are the ones the guard admits.
fn installed_keys(peers: &[WireGuardPeer]) -> BTreeSet<crate::policy::model::PublicKey> {
    peers
        .iter()
        .map(|peer| crate::policy::model::PublicKey(*peer.public_key.as_bytes()))
        .collect()
}

/// Peer statistics use the same public shape as the Linux kernel adapter.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    #[serde(default)]
    pub persistent_keepalive_secs: u16,
    pub handshake_secs: u64,
    #[cfg(feature = "relay")]
    #[serde(skip)]
    pub handshake_nanos: u32,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<std::net::SocketAddr>,
}

type CounterMap = BTreeMap<crate::policy::model::PublicKey, Counters>;

/// One utun control socket and the interface name the kernel gave it.
pub(crate) struct OpenUtun {
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
struct MacUtun {
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
        MacUtunTx {
            fd: self.fd.clone(),
            mtu: self.mtu.subscribe().into(),
            frame: Vec::with_capacity(usize::from(crate::mesh_mtu::IPV6_MINIMUM_MTU) + 4),
            filter: Arc::clone(&self.filter),
        }
    }

    /// Build the receive adapter with a watcher for this utun's current shared interface MTU.
    fn receiver(&self) -> MacUtunRx {
        MacUtunRx {
            fd: self.fd.clone(),
            mtu: self.mtu.subscribe().into(),
            filter: Arc::clone(&self.filter),
            #[cfg(feature = "mesh-dns")]
            tunnel_dns: Arc::clone(&self.tunnel_dns),
        }
    }

    /// Publish an MTU change to the utun send and receive packet workers.
    fn set_mtu(&self, mtu: u16) {
        self.mtu.send_replace(mtu);
    }
}

/// Sends packets from `GotaTun` to one owned utun using its live interface MTU.
struct MacUtunTx {
    fd: Arc<AsyncFd<OwnedFd>>,
    mtu: MtuWatcher,
    frame: Vec<u8>,
    filter: Arc<PacketFilter>,
}

impl IpSend for MacUtunTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let mut packet = packet.into_bytes();
        if !self.filter.check(packet.buf_mut(), Direction::MeshToHost) {
            return Ok(());
        }
        let family = utun_family(packet.as_ref())?;
        if packet.len() > usize::from(self.mtu.get()) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.frame.clear();
        self.frame.extend_from_slice(&family.to_be_bytes());
        self.frame.extend_from_slice(packet.as_ref());
        loop {
            let mut ready = self.fd.writable().await?;
            match ready.try_io(|fd| write(fd.get_ref(), &self.frame).map_err(io::Error::from)) {
                Err(_) => {}
                Ok(Err(error)) => return Err(error),
                Ok(Ok(written)) if written == self.frame.len() => return Ok(()),
                Ok(Ok(_)) => return Err(io::ErrorKind::WriteZero.into()),
            }
        }
    }
}

/// Receives packets from one owned utun and rejects frames above its live interface MTU.
struct MacUtunRx {
    fd: Arc<AsyncFd<OwnedFd>>,
    mtu: MtuWatcher,
    filter: Arc<PacketFilter>,
    /// Shared with [`MacUtun`]; see [`user_mode::answer_resolver_query`].
    #[cfg(feature = "mesh-dns")]
    tunnel_dns: TunnelDns,
}

impl IpRecv for MacUtunRx {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        loop {
            let mut packet = pool.get();
            let mut ready = self.fd.readable().await?;
            let result =
                ready.try_io(|fd| read(fd.get_ref(), &mut packet[..]).map_err(io::Error::from));
            match result {
                Err(_) => {}
                Ok(Err(error)) => return Err(error),
                Ok(Ok(0)) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(Ok(length)) => {
                    packet.truncate(length);
                    parse_utun_payload(packet.as_ref(), self.mtu.get())?;
                    packet.buf_mut().advance(4);
                    #[cfg(feature = "mesh-dns")]
                    if user_mode::answer_resolver_query(self, packet.as_ref()) {
                        continue;
                    }
                    if !self.filter.check(packet.buf_mut(), Direction::HostToMesh) {
                        continue;
                    }
                    let packet = packet
                        .try_into_ip()
                        .map_err(|_| io::ErrorKind::InvalidData)?;
                    return Ok(std::iter::once(packet));
                }
            }
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
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

/// Public durable intent shared with the Linux node journal; the `WireGuard` secret is never serialized.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedState {
    enabled: bool,
    config: Option<crate::dataplane::Config>,
    /// True while a peer-free reset snapshot awaits the new authority's full config.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    authority_reset_pending: bool,
    #[serde(default)]
    routes: BTreeSet<IpAddr>,
    #[serde(default)]
    interface: Option<String>,
    #[serde(default)]
    port: u16,
    /// Linux-only legacy metadata is accepted as an opaque public value for cross-platform state reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backend: Option<serde_json::Value>,
    /// The enrolment that issued `config`; absent only in state written by slice-1 builds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<Enrolment>,
}

pub use crate::enrolment::{Enrolment, MachineBindingError};

/// Apply the binding rule to saved state; `true` means the key must rotate.
///
/// Saved state that is not bound to the current enrolment loses its
/// configuration and the key; the node then registers a new key with its
/// coordinator. That includes unbound state: a slice-1 build wrote none, and a
/// slice-1 Mac may have been joined to another coordinator before upgrading,
/// so its peers cannot be trusted to be this enrolment's (J162 F3). Its key is
/// a fresh one anyway, because the slice-1 key is retired (`macos_key`), so
/// discarding the peers costs one coordinator round trip. A first start has no
/// saved state and is not passed here. Without a current enrolment (no
/// `identity.json`), nothing is compared.
fn reconcile(mut state: SavedState, enrolment: Option<&Enrolment>) -> (SavedState, bool) {
    let Some(enrolment) = enrolment else {
        return (state, false);
    };
    let rotate = state.binding.as_ref() != Some(enrolment);
    if rotate {
        state.config = None;
        state.authority_reset_pending = false;
        // The old utun closed with the old process, which retired its routes.
        state.routes.clear();
        state.interface = None;
    }
    state.binding = Some(enrolment.clone());
    (state, rotate)
}

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
    crate::macos_key::retire_key(state, crate::macos_key::RotationReason::EnrolmentChanged)?;
    match fs::remove_file(state.join(PUBLIC_STATE)) {
        Ok(()) => File::open(state)?.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

impl Default for SavedState {
    fn default() -> Self {
        Self {
            enabled: true,
            config: None,
            authority_reset_pending: false,
            routes: BTreeSet::new(),
            interface: None,
            port: 0,
            backend: None,
            binding: None,
        }
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

/// The endpoint-derived MTUs for one snapshot: each installed peer host route's budget and
/// the shared interface MTU.
///
/// Reading them costs a `route` and an `ifconfig` process per underlay path (about 6.5 ms
/// each on the Mac VM). [`PathBudgets::probe`] therefore runs on the caller's thread before a
/// snapshot is handed to the worker, never on the worker's runtime, which also drives every
/// packet through the utun: probing there stalled traffic for the whole update (#381 J411).
#[derive(Clone, Debug, PartialEq, Eq)]
struct PathBudgets {
    /// Route MTU for each installed peer host route.
    route_mtus: BTreeMap<IpAddr, u16>,
    /// Shared utun MTU: the largest peer budget, never below IPv6's minimum.
    interface_mtu: u16,
}

impl PathBudgets {
    /// Probe each distinct underlay path of `config` once. `None` means no peers yet.
    fn probe(config: Option<&Config>) -> Self {
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
        Self {
            route_mtus,
            interface_mtu,
        }
    }
}

/// Return retained host routes whose freshly derived MTU differs from the installed metric.
fn route_mtus_to_refresh(
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

/// Refuse an endpoint that a host route would send back into this tunnel.
fn validate_underlay_routes(config: &Config, routes: &BTreeSet<IpAddr>) -> io::Result<()> {
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
    let (config, authority) =
        crate::node_state::split_authority(state.config.as_ref(), state.authority_reset_pending);
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
fn utun_family(packet: &[u8]) -> io::Result<u32> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => Ok(UTUN_AF_INET),
        Some(6) => Ok(UTUN_AF_INET6),
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}

/// Validate and strip the network-order address-family header from one utun frame.
///
/// `mtu` is the live shared interface limit reported to the `GotaTun` packet workers.
/// # Errors
/// Rejects truncated, unsupported, oversized or family-mismatched frames.
fn parse_utun_payload(frame: &[u8], mtu: u16) -> io::Result<&[u8]> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(io::ErrorKind::InvalidData)?
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidData)?;
    let payload = frame.get(4..).ok_or(io::ErrorKind::InvalidData)?;
    let family = u32::from_be_bytes(prefix);
    if payload.is_empty() || payload.len() > usize::from(mtu) || utun_family(payload)? != family {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(payload)
}

/// The configured peers the Mac device installs: those whose grants allow some traffic.
///
/// A peer without network access gets no device entry, so the handshake guard refuses its key
/// and the node keeps no session alive toward it, as on Linux (J781, #483, #515).
fn installed_peers(config: &Config) -> impl Iterator<Item = &crate::dataplane::PeerPolicy> {
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
fn peers_for_config(config: &Config) -> io::Result<Vec<WireGuardPeer>> {
    let mut peers = Vec::new();
    for policy in installed_peers(config) {
        peers.extend(peer_for_policy(policy)?);
    }
    Ok(peers)
}

/// Convert one peer to its active key or both journaled overlap keys.
/// # Errors
/// Rejects invalid host routes before they reach `GotaTun`.
fn peer_for_policy(policy: &crate::dataplane::PeerPolicy) -> io::Result<Vec<WireGuardPeer>> {
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
    // flows may start; whether the utun routes a network at all is the [`subnet`] plan's call.
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

struct Pending {
    server: Option<crate::policy::model::NodeId>,
    next: u32,
    version: u64,
    from_version: Option<u64>,
    default_policy: crate::dataplane::DefaultPolicy,
    config: Config,
}

/// Stage a contiguous Mac snapshot, allowing a changed authority only in a fresh full snapshot.
/// A lower same-authority revision needs the persisted replacement transaction.
/// # Errors
/// Refuses incomplete, stale, unbound, or inconsistent chunks.
fn stage_chunk(
    pending: &mut Option<Pending>,
    current: Option<&Config>,
    identity: &crate::dataplane::Identity,
    allow_lower_revision_replacement: bool,
    chunk: crate::dataplane::Chunk,
) -> io::Result<Option<Config>> {
    if chunk
        .authority_epoch
        .as_deref()
        .is_some_and(|epoch| !crate::dataplane::valid_authority_epoch(epoch))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if !chunk.access_updates.is_empty()
        && (chunk.from_version.is_none()
            || chunk.index != 0
            || !chunk.last
            || !chunk.upserted.is_empty()
            || !chunk.merged.is_empty()
            || !chunk.removed.is_empty()
            || current.is_none_or(|old| old.server != chunk.server))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if chunk
        .local_key
        .is_some_and(|key| key != identity.public_key)
        || current.is_some_and(|old| {
            old.node != chunk.node
                && (chunk.local_key.is_none()
                    || chunk.from_version.is_some()
                    || old.authority_epoch == chunk.authority_epoch && chunk.version <= old.version)
        })
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if chunk.index == 0 {
        let current_version = current.map(|config| config.version);
        if !allow_lower_revision_replacement
            && current.is_some_and(|old| {
                chunk.from_version.is_none()
                    && old.authority_epoch == chunk.authority_epoch
                    && chunk.version < old.version
            })
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if chunk.from_version.is_some() && chunk.from_version != current_version
            || current_version
                .is_some_and(|version| chunk.from_version.is_some() && chunk.version <= version)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let config = if chunk.from_version.is_some() {
            current.cloned().ok_or(io::ErrorKind::InvalidData)?
        } else {
            Config {
                authority_epoch: chunk.authority_epoch.clone(),
                rotation_operation: chunk.rotation_operation.clone(),
                local_key: chunk.local_key,
                server: chunk.server,
                node: chunk.node,
                #[cfg(feature = "mesh-dns")]
                name: chunk.name.clone(),
                #[cfg(feature = "mesh-dns")]
                dns_suffix: chunk.dns_suffix.clone(),
                version: chunk.version,
                addresses: chunk.addresses,
                default_policy: chunk.default_policy,
                exposure: chunk.exposure.clone(),
                peers: std::collections::BTreeMap::new(),
                #[cfg(feature = "mesh-dns")]
                peer_names: std::collections::BTreeMap::new(),
            }
        };
        let mut config = config;
        config
            .rotation_operation
            .clone_from(&chunk.rotation_operation);
        #[cfg(feature = "mesh-dns")]
        let config = {
            let mut config = config;
            config.name.clone_from(&chunk.name);
            config.dns_suffix.clone_from(&chunk.dns_suffix);
            config
        };
        *pending = Some(Pending {
            server: chunk.server,
            next: 0,
            version: chunk.version,
            from_version: chunk.from_version,
            default_policy: chunk.default_policy,
            config,
        });
    }
    let staged = pending.as_mut().ok_or(io::ErrorKind::InvalidData)?;
    #[cfg(feature = "mesh-dns")]
    let names_changed = staged.config.name != chunk.name;
    #[cfg(feature = "mesh-dns")]
    let dns_suffix_changed = staged.config.dns_suffix != chunk.dns_suffix;
    #[cfg(not(feature = "mesh-dns"))]
    let names_changed = false;
    #[cfg(not(feature = "mesh-dns"))]
    let dns_suffix_changed = false;
    if staged.server != chunk.server
        || staged.config.authority_epoch != chunk.authority_epoch
        || staged.config.rotation_operation != chunk.rotation_operation
        || staged.next != chunk.index
        || staged.config.local_key != chunk.local_key
        || staged.config.node != chunk.node
        || names_changed
        || dns_suffix_changed
        || staged.config.addresses != chunk.addresses
        || staged.version != chunk.version
        || staged.from_version != chunk.from_version
        || staged.default_policy != chunk.default_policy
        // As on Linux (#281): a delta cannot change the exposure identity.
        || staged.config.exposure != chunk.exposure
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    staged.next = staged
        .next
        .checked_add(1)
        .ok_or(io::ErrorKind::InvalidData)?;
    staged.config.version = chunk.version;
    staged.config.default_policy = chunk.default_policy;
    staged.config.server = chunk.server;
    crate::access_updates::apply(&mut staged.config, &chunk.access_updates)?;
    for node in chunk.removed {
        staged.config.peers.remove(&node);
        #[cfg(feature = "mesh-dns")]
        staged.config.peer_names.remove(&node);
    }
    staged.config.peers.extend(chunk.upserted);
    for (node, partial) in chunk.merged {
        let peer = staged
            .config
            .peers
            .get_mut(&node)
            .ok_or(io::ErrorKind::InvalidData)?;
        if !partial.continues(peer) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        peer.inbound.union(&partial.inbound);
        peer.outbound.union(&partial.outbound);
    }
    #[cfg(feature = "mesh-dns")]
    {
        for node in chunk.removed_peer_names {
            if !staged.config.peers.contains_key(&node)
                || staged.config.peer_names.remove(&node).is_none()
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        for (node, name) in chunk.peer_names {
            if !staged.config.peers.contains_key(&node)
                || name.is_empty()
                || name.len() > 63
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || name.starts_with('-')
                || name.ends_with('-')
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            staged.config.peer_names.insert(node, name);
        }
    }
    if chunk.last {
        Ok(Some(
            pending.take().ok_or(io::ErrorKind::InvalidData)?.config,
        ))
    } else {
        Ok(None)
    }
}

/// Check whether an incoming chunk carries a different authenticated server process epoch.
fn needs_authority_reset(current: Option<&Config>, chunk: &crate::dataplane::Chunk) -> bool {
    current.is_some_and(|old| old.authority_epoch != chunk.authority_epoch)
}

#[derive(Clone)]
struct RuntimeInfo {
    interface: String,
    port: u16,
    routes: BTreeSet<IpAddr>,
}

/// Commands serialized by the Mac `GotaTun` worker. Each reply lets callers
/// wait for the device update before changing durable identity state. Authority replacements and
/// key changes share the same queue, so their runtime transitions cannot interleave.
enum WorkerCommand {
    Apply {
        /// Keeps the larger snapshot out of the enum's inline command payload.
        config: Box<Config>,
        /// MTUs probed for `config` before it reached the worker.
        budgets: PathBudgets,
        reply: sync::SyncSender<io::Result<RuntimeInfo>>,
    },
    /// Replace one complete authority snapshot without rolling back to its predecessor.
    ReplaceAuthority {
        /// Keeps the larger snapshot out of the enum's inline command payload.
        config: Box<Config>,
        /// MTUs probed for `config` before it reached the worker (#381).
        budgets: PathBudgets,
        reply: sync::SyncSender<io::Result<RuntimeInfo>>,
    },
    /// Replace the live `GotaTun` key on its serialized worker thread.
    SetPrivateKey {
        private_key: gotatun::x25519::StaticSecret,
        reply: sync::SyncSender<io::Result<()>>,
    },
    Counters(sync::SyncSender<CounterMap>),
    Stop(sync::SyncSender<io::Result<()>>),
    /// Hand a real-Mac test the worker's admission guard, so it can check what the guard
    /// knows and flood it on a simulated clock.
    #[cfg(test)]
    Admission(sync::SyncSender<Arc<RwLock<PeerAdmission>>>),
}

struct Worker {
    commands: UnboundedSender<WorkerCommand>,
    join: Option<JoinHandle<()>>,
}

struct PendingWorker {
    commands: UnboundedSender<WorkerCommand>,
    join: Option<JoinHandle<()>>,
    gate: Option<sync::SyncSender<bool>>,
    ready: sync::Receiver<io::Result<()>>,
    info: RuntimeInfo,
}

impl PendingWorker {
    /// Start the worker behind a gate and return its utun details for approval.
    /// # Errors
    /// Reports utun allocation, worker startup, route setup, or DNS setup failures.
    fn begin(
        open: OpenUtun,
        private_key: gotatun::x25519::StaticSecret,
        requested_port: crate::listen_port::Request,
        config: Option<Config>,
        routes: BTreeSet<IpAddr>,
        budgets: PathBudgets,
        network_status: subnet::NetworkStatus,
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
                    let utun = MacUtun::from_open(open, filter)?;
                    let (factory, port) = bind_udp(requested_port, guard_key).await?;
                    let info = RuntimeInfo {
                        interface: utun.name().to_owned(),
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
                    configure_interface(&utun, config.as_ref(), mtu)?;
                    utun.set_mtu(mtu);
                    #[cfg(feature = "mesh-dns")]
                    let mut dns_integration = crate::dns_integration::DnsIntegration::default();
                    #[cfg(feature = "mesh-dns")]
                    let mut dns_resolver = None;
                    #[cfg(feature = "mesh-dns")]
                    if let Some(config) = config.as_ref() {
                        let records = crate::dns::Records::from_config(config)?;
                        let resolver = crate::dns::Resolver::bind(config)?;
                        if let Err(error) = configure_host_dns(
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
                        .map(peers_for_config)
                        .transpose()?
                        .unwrap_or_default();
                    // The guard knows the first peers before the device receives anything.
                    let keys = installed_keys(&peers);
                    admission.write().await.install(keys, &peers);
                    let device = DeviceBuilder::new()
                        .with_udp(factory)
                        .with_private_key(private_key)
                        .with_listen_port(info.port)
                        .with_ip_pair(utun.sender(), utun.receiver())
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
                        if let Err(error) = route(&info.interface, *address, "add", Some(mtu)) {
                            let _ = remove_routes(&info.interface, &installed);
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
                let state = RuntimeState {
                    udp,
                    utun: Some(utun),
                    device: Some(Arc::new(device)),
                    handshakes: tokio::task::JoinSet::new(),
                    walks: crate::candidate_walks::Walks::default(),
                    config,
                    routes: info.routes,
                    route_mtus: initial_route_mtus,
                    networks: BTreeMap::new(),
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
                runtime.block_on(walks::run_worker(receiver, state));
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
            gate: Some(gate_tx),
            ready: ready_rx,
            info,
        })
    }

    fn info(&self) -> &RuntimeInfo {
        &self.info
    }

    fn commit(mut self) -> io::Result<(Worker, RuntimeInfo)> {
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
            },
            self.info.clone(),
        ))
    }
}

/// Bind the requested Mac UDP port, using one automatic fallback when that listener is occupied.
///
/// The bound socket remains owned by the worker, and the returned port is persisted and advertised
/// so coordinator peers target the actual listener. An explicit operator override stays exact.
/// The returned factory carries a handshake admission guard for `private_key` with no peers
/// yet; the worker installs its peers before the device receives anything.
/// # Errors
/// Returns socket errors, rejects the reserved kernel `WireGuard` port, or reports allocation failure.
async fn bind_udp(
    request: crate::listen_port::Request,
    private_key: StaticSecret,
) -> io::Result<(BoundUdpFactory, u16)> {
    if request.port == 51_820 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let admission = Arc::new(RwLock::new(PeerAdmission::new(private_key)));
    // The product's S choice, the same one the worker starts its route listener with.
    let mut factory = UdpSocketFactory {
        mac_connected: Some(walks::mac_connected_sends_enabled()),
        ..UdpSocketFactory::default()
    };
    if request.port != 0 {
        let params = UdpTransportFactoryParams {
            addr: None,
            port: request.port,
        };
        match factory.bind(&params).await {
            Ok((send, receive)) => {
                let port = send.local_addr()?.port();
                if port == 0 || port == 51_820 {
                    return Err(io::ErrorKind::AddrInUse.into());
                }
                return Ok((
                    BoundUdpFactory::with_probes(send, receive, port, admission).await,
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
        };
        let (send, receive) = factory.bind(&params).await?;
        let port = send.local_addr()?.port();
        if port != 0 && port != 51_820 {
            return Ok((
                BoundUdpFactory::with_probes(send, receive, port, admission).await,
                port,
            ));
        }
    }
    Err(io::ErrorKind::AddrInUse.into())
}

impl Drop for PendingWorker {
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
    fn apply(&self, config: Config) -> io::Result<RuntimeInfo> {
        let budgets = PathBudgets::probe(Some(&config));
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
    fn replace_authority(&self, config: Config) -> io::Result<RuntimeInfo> {
        let budgets = PathBudgets::probe(Some(&config));
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

    fn counters(&self) -> io::Result<CounterMap> {
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
    fn set_private_key(&self, private_key: gotatun::x25519::StaticSecret) -> io::Result<()> {
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::SetPrivateKey { private_key, reply })
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        result.recv().map_err(|_| io::ErrorKind::BrokenPipe)?
    }

    /// Stop the worker and wait until its device thread has finished teardown.
    /// # Errors
    /// Reports command delivery, route cleanup, or worker-thread failures.
    fn stop(&mut self) -> io::Result<()> {
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

/// Reads per-peer statistics from the live device for the worker: counters and the
/// confirmed endpoints the admission guard learns from.
mod peer_stats;

/// Owns the live utun, peer-route MTUs, accepted snapshot and DNS resolver integration.
/// `route_mtus` mirrors installed metrics so a failed update can restore them.
struct RuntimeState {
    /// The worker's live UDP listener; clones share the connected pools with the device.
    udp: GotaUdpSocket,
    utun: Option<MacUtun>,
    /// Shared only with handshake tasks, which `stop` ends before stopping the device.
    device: Option<Arc<GotaDevice>>,
    /// Running `rehandshake` waits ([`walks`]).
    handshakes: tokio::task::JoinSet<()>,
    /// Each peer's direct-path candidate walk (#515).
    walks: crate::candidate_walks::Walks,
    config: Option<Config>,
    routes: BTreeSet<IpAddr>,
    route_mtus: BTreeMap<IpAddr, u16>,
    /// The subnet routes on the utun now, each with the MTU root mode gave it ([`subnet`]).
    networks: BTreeMap<crate::policy::networks::Network, Option<u16>>,
    /// What happened to each reachable network, shared with the node for `mesh routes`.
    network_status: subnet::NetworkStatus,
    /// The utun MTU of the applied snapshot; a failed update restores it without re-probing.
    interface_mtu: u16,
    port: u16,
    /// The receive guard; it follows the peers and key the live device accepted.
    admission: Arc<RwLock<PeerAdmission>>,
    /// Feeds the endpoints `GotaTun` confirmed into `admission`'s known set (J736).
    confirmed_feed: ConfirmedEndpointFeed,
    #[cfg(feature = "mesh-dns")]
    dns_resolver: Option<crate::dns::Resolver>,
    #[cfg(feature = "mesh-dns")]
    dns_integration: crate::dns_integration::DnsIntegration,
}

impl RuntimeState {
    /// Change the private identity on the active `WireGuard` device without restarting its utun.
    /// # Errors
    /// Reports a stopped device or a rejected key update.
    async fn set_private_key(
        &mut self,
        private_key: gotatun::x25519::StaticSecret,
    ) -> io::Result<()> {
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
    async fn apply(
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
    async fn replace_authority(
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
            let expected: BTreeSet<_> = peers_for_config(&config)?
                .into_iter()
                .map(|peer| crate::policy::model::PublicKey(*peer.public_key.as_bytes()))
                .collect();
            let installed: BTreeSet<_> = self.counters().await?.into_keys().collect();
            if installed == expected {
                let interface = self
                    .utun
                    .as_ref()
                    .map(MacUtun::name)
                    .ok_or(io::ErrorKind::NotConnected)?
                    .to_owned();
                self.refresh_unchanged_mesh_mtus(budgets).await?;
                self.utun
                    .as_ref()
                    .ok_or(io::ErrorKind::NotConnected)?
                    .filter
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
        let interface = utun.name().to_owned();
        let staging = self.interface_mtu.max(budgets.interface_mtu);
        let changed = route_mtus_to_refresh(
            &self.routes,
            &self.routes,
            &self.route_mtus,
            &budgets.route_mtus,
        );
        // The watcher accepts both budgets throughout the host update. Outbound packets are
        // still bounded by the kernel's interface and route MTUs until each utility completes.
        utun.set_mtu(staging);
        let host_utun = utun.clone();
        let budgets = tokio::task::spawn_blocking(move || {
            set_interface_mtu(&host_utun, staging)?;
            for address in changed {
                let mtu = budgets
                    .route_mtus
                    .get(&address)
                    .copied()
                    .unwrap_or(crate::mesh_mtu::FALLBACK_MESH_MTU);
                route(&interface, address, "change", Some(mtu))?;
            }
            set_interface_mtu(&host_utun, budgets.interface_mtu)?;
            Ok::<_, io::Error>(budgets)
        })
        .await
        .map_err(|_| io::Error::other("Mesh MTU update worker could not finish."))??;
        utun.set_mtu(budgets.interface_mtu);
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
        let interface = utun.name().to_owned();
        #[cfg(feature = "mesh-dns")]
        let dns_records = crate::dns::Records::from_config(&config)?;
        let new_routes = route_addresses(&config);
        validate_underlay_routes(&config, &new_routes)?;
        let peers = peers_for_config(&config)?;
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
        if let Err(error) = configure_interface(utun, Some(&config), staging_mtu) {
            if rollback_on_failure {
                rollback_device(device, old_config.as_ref(), old_mtu, utun).await;
            }
            return Err(error);
        }
        utun.set_mtu(staging_mtu);
        #[cfg(feature = "mesh-dns")]
        let pending_dns_resolver = if self.dns_resolver.is_none() {
            match crate::dns::Resolver::bind(&config) {
                Ok(resolver) => Some(resolver),
                Err(error) => {
                    if rollback_on_failure {
                        rollback_device(device, old_config.as_ref(), old_mtu, utun).await;
                    }
                    return Err(error);
                }
            }
        } else {
            None
        };
        // An authority replacement may have reached this path because the installed keys
        // disagreed with the snapshot. Rebuild from the complete list in that case.
        let peers_applied = if rollback_on_failure {
            walks::update_peers(device, old_config.as_ref(), &config, &admitted, before).await
        } else {
            replace_peers(device, peers).await
        };
        if let Err(error) = peers_applied {
            if rollback_on_failure {
                rollback_device(device, old_config.as_ref(), old_mtu, utun).await;
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
                route(&interface, *address, "add", Some(mtu))?;
                added.insert(*address);
            }
            for address in
                route_mtus_to_refresh(&old_routes, &new_routes, &old_route_mtus, &new_route_mtus)
            {
                let mtu = new_route_mtus
                    .get(&address)
                    .copied()
                    .unwrap_or(crate::mesh_mtu::FALLBACK_MESH_MTU);
                route(&interface, address, "change", Some(mtu))?;
                changed.insert(address);
            }
            for address in old_routes.difference(&new_routes) {
                route(&interface, *address, "delete", None)?;
                removed.insert(*address);
            }
            set_interface_mtu(utun, new_mtu)?;
            utun.set_mtu(new_mtu);
            Ok(())
        })();
        if let Err(error) = routes_applied {
            let _ = remove_routes(&interface, &added);
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
                let _ = route(&interface, *address, "change", Some(mtu));
            }
            for address in &removed {
                let mtu = old_route_mtus
                    .get(address)
                    .copied()
                    .unwrap_or(crate::mesh_mtu::FALLBACK_MESH_MTU);
                let _ = route(&interface, *address, "add", Some(mtu));
            }
            rollback_device(device, old_config.as_ref(), old_mtu, utun).await;
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
            if let Err(error) = configure_host_dns(
                &mut self.dns_integration,
                utun,
                &dns_records,
                config.addresses.ipv6,
            ) {
                tracing::warn!("mesh DNS host resolver integration could not be updated: {error}");
            }
            resolver.publish(dns_records);
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
        utun.filter.publish_policy(policy);
        let readdressed = walks::readdressed(old_config.as_ref(), &config);
        self.config = Some(config);
        for key in readdressed {
            self.rehandshake(key);
        }
        Ok(RuntimeInfo {
            interface,
            port: self.port,
            routes: new_routes,
        })
    }

    /// Removes the host resolver route and listener before the Mac mesh device stops.
    #[cfg(feature = "mesh-dns")]
    fn stop_dns(&mut self) -> io::Result<()> {
        if crate::macos_helper::user_mode() {
            self.dns_resolver = None;
            return crate::macos_helper::request(
                &crate::macos_user_mode::Request::ClearResolver,
                None,
            )
            .map(|_| ());
        }
        self.dns_integration.remove()?;
        self.dns_resolver = None;
        Ok(())
    }

    /// Keeps Mac node cleanup available when this build omits mesh DNS.
    #[cfg(not(feature = "mesh-dns"))]
    fn stop_dns(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Removes managed DNS files, peer routes and the owned device before stopping the utun.
    /// # Errors
    /// Returns a DNS or route cleanup error after the device and utun descriptor have been stopped.
    async fn stop(&mut self) -> io::Result<()> {
        let dns_result = self.stop_dns();
        let route_result = self
            .utun
            .as_ref()
            .map_or(Ok(()), |utun| remove_routes(utun.name(), &self.routes));
        // Subnet routes go with the utun; root mode removes them first, as it does host routes.
        self.remove_networks();
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
#[cfg(test)]
static J472_REBUILDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Replace the complete peer inventory, discarding its previous session state.
async fn replace_peers(device: &GotaDevice, peers: Vec<WireGuardPeer>) -> io::Result<()> {
    #[cfg(test)]
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
async fn rollback_device(device: &GotaDevice, config: Option<&Config>, mtu: u16, utun: &MacUtun) {
    if let Some(config) = config {
        let _ = configure_interface(utun, Some(config), mtu);
        if let Ok(peers) = peers_for_config(config) {
            let _ = replace_peers(device, peers).await;
        }
    } else {
        let _ = set_interface_mtu(utun, mtu);
    }
    utun.set_mtu(mtu);
}

/// Owns one macOS mesh runtime, accepted configuration and durable identity state.
/// The serialized worker mutates the tunnel; enrollment binding scopes restored config to one host.
pub struct Node {
    enabled: bool,
    worker: Option<Worker>,
    identity: Option<crate::dataplane::Identity>,
    store: Option<crate::node_state::Store>,
    config: Option<Config>,
    /// Marks the peer-free snapshot left by an authority fence until its full replacement arrives.
    authority_reset_pending: bool,
    pending: Option<Pending>,
    routes: BTreeSet<IpAddr>,
    interface: Option<String>,
    port: u16,
    path: Option<PathBuf>,
    binding: Option<Enrolment>,
    /// What the worker did with each reachable subnet route, for `mesh routes` (D197 M3).
    network_status: subnet::NetworkStatus,
}

impl Default for Node {
    fn default() -> Self {
        Self {
            enabled: true,
            worker: None,
            identity: None,
            store: None,
            config: None,
            authority_reset_pending: false,
            pending: None,
            routes: BTreeSet::new(),
            interface: None,
            port: 0,
            path: None,
            binding: None,
            network_status: subnet::NetworkStatus::default(),
        }
    }
}

/// Recover the Mac identity selected by a prepared or committed rotation journal.
///
/// A pending commit selects the candidate on restart even if the key file or identity record was
/// the last write to reach disk. Only the predecessor and candidate from this journal are valid.
/// # Errors
/// Refuses a key file or identity record outside the journal's authorized phase.
fn recover_macos_rotation_key(
    store: &crate::node_state::Store,
    rotation: &crate::node_state::RotationSecret,
) -> io::Result<(RotationKey, crate::policy::model::PublicKey)> {
    let (candidate, candidate_public) = RotationKey::from_private(&rotation.candidate)?;
    let recorded = store
        .recorded_interface()?
        .ok_or(io::ErrorKind::InvalidData)?;
    let saved = store
        .read_private_key()?
        .ok_or(io::ErrorKind::InvalidData)?;
    let saved_public = RotationKey::from_private(&saved)?.1;
    if rotation.completed {
        if recorded != candidate_public || saved_public != candidate_public {
            return Err(io::ErrorKind::InvalidData.into());
        }
        return Ok((candidate, candidate_public));
    }

    let (previous, previous_public) = RotationKey::from_private(&rotation.previous)?;
    if !rotation.commit_requested {
        if recorded != previous_public || saved_public != previous_public {
            return Err(io::ErrorKind::InvalidData.into());
        }
        return Ok((previous, previous_public));
    }

    let legal_partial_write = (recorded == previous_public && saved_public == previous_public)
        || (recorded == candidate_public
            && (saved_public == previous_public || saved_public == candidate_public));
    if !legal_partial_write {
        return Err(io::ErrorKind::InvalidData.into());
    }
    store.record_rotation_identity(
        &rotation.operation_id,
        rotation.sequence,
        candidate.private_bytes(),
        &candidate_public,
    )?;
    Ok((candidate, candidate_public))
}

/// Check that a saved Mac key names only an identity from its durable rotation journal.
/// # Errors
/// Refuses unsafe key records and mismatched journal state.
fn validate_macos_rotation_proof(
    store: &crate::node_state::Store,
    rotation: &crate::node_state::RotationSecret,
    current: crate::policy::model::PublicKey,
) -> io::Result<()> {
    let candidate_public = RotationKey::from_private(&rotation.candidate)?.1;
    let recorded = store
        .recorded_interface()?
        .ok_or(io::ErrorKind::InvalidData)?;
    let saved = store
        .read_private_key()?
        .ok_or(io::ErrorKind::InvalidData)?;
    let saved_public = RotationKey::from_private(&saved)?.1;
    if rotation.completed {
        if current != candidate_public
            || recorded != candidate_public
            || saved_public != candidate_public
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        return Ok(());
    }
    let previous_public = RotationKey::from_private(&rotation.previous)?.1;
    let valid = if rotation.commit_requested {
        ((current == previous_public || current == candidate_public)
            && recorded == previous_public
            && saved_public == previous_public)
            || (current == candidate_public
                && recorded == candidate_public
                && (saved_public == previous_public || saved_public == candidate_public))
    } else {
        current == previous_public && recorded == previous_public && saved_public == previous_public
    };
    if !valid {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

/// Verify an accepted local-key binding against the key file and any open rotation journal.
fn macos_snapshot_binding_is_authorized(
    store: &crate::node_state::Store,
    bound: crate::policy::model::PublicKey,
) -> io::Result<bool> {
    let Some(private) = store.read_private_key()? else {
        return Ok(false);
    };
    let private_public = RotationKey::from_private(&private)?.1;
    let Some(rotation) = store.rotation_secret()? else {
        return Ok(store.recorded_interface()? == Some(private_public) && private_public == bound);
    };
    let candidate_public = RotationKey::from_private(&rotation.candidate)?.1;
    let Some(recorded) = store.recorded_interface()? else {
        return Ok(false);
    };
    if rotation.completed {
        // The candidate files prove the active identity; the marker bounds any stale snapshot to
        // this rotation's predecessor or candidate.
        return Ok(private_public == candidate_public
            && recorded == candidate_public
            && rotation.completed_binding_matches(bound, candidate_public));
    }
    let previous_public = RotationKey::from_private(&rotation.previous)?.1;
    let bound_authorized =
        bound == previous_public || (rotation.commit_requested && bound == candidate_public);
    let key_state_authorized = if rotation.commit_requested {
        (private_public == previous_public
            && (recorded == previous_public || recorded == candidate_public))
            || (private_public == candidate_public && recorded == candidate_public)
    } else {
        private_public == previous_public && recorded == previous_public
    };
    Ok(bound_authorized && key_state_authorized)
}

/// Check the coordinator's rotation identifier before creating any private state.
fn valid_rotation_request(operation_id: &str, sequence: u64) -> bool {
    sequence != 0
        && operation_id.len() == 36
        && operation_id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

impl Node {
    /// Refuse a folder bound to another Mac before the supervisor starts (see `macos_machine`).
    /// # Errors
    /// `PermissionDenied` carrying a [`MachineBindingError`].
    pub fn check_enrolled_machine(state_directory: &Path) -> io::Result<()> {
        crate::macos_machine::check_existing(state_directory)
    }

    /// Restore accepted public intent, clean only old utun routes, and resume before coordinator dialing.
    ///
    /// State that another enrolment issued is discarded first (see [`reconcile`]).
    /// # Errors
    /// Refuses unsafe state, an unreadable node key or failed utun/device startup.
    pub fn restore(state_directory: &Path, enrolment: Option<&Enrolment>) -> io::Result<Self> {
        // An enrolled node belongs to one Mac: refuse a copied folder first (#221).
        if enrolment.is_some() {
            crate::macos_machine::bind(state_directory, crate::macos_machine::fingerprint())?;
        }
        #[cfg(feature = "mesh-dns")]
        crate::dns_integration::DnsIntegration::default().remove()?;
        let path = state_directory.join(PUBLIC_STATE);
        let (state, rotate) = match read_public_state(&path)? {
            Some(saved) => reconcile(saved, enrolment),
            None => (
                SavedState {
                    binding: enrolment.cloned(),
                    ..SavedState::default()
                },
                false,
            ),
        };
        let store = crate::node_state::Store::open_for_macos(state_directory)?;
        if rotate {
            tracing::warn!(
                "Mesh state is not bound to this enrolment; discarding its peers and starting with a new WireGuard key"
            );
            store.discard_rotation_state()?;
            crate::macos_key::retire_key(
                state_directory,
                crate::macos_key::RotationReason::EnrolmentChanged,
            )?;
        }
        let mut stale_routes = state.routes.clone();
        if let Some(config) = &state.config {
            stale_routes.extend(route_addresses(config));
        }
        match state.interface.as_deref() {
            Some(interface) if valid_utun_name(interface) => {
                // The old control socket's close retires its routes. Its utun unit may already
                // belong to another tunnel, so persisted names are never used to delete routes.
            }
            Some(_) => return Err(io::ErrorKind::InvalidData.into()),
            None if !stale_routes.is_empty() => return Err(io::ErrorKind::InvalidData.into()),
            None => {}
        }
        let mut node = Self {
            enabled: state.enabled,
            config: state.config,
            authority_reset_pending: state.authority_reset_pending,
            port: state.port,
            path: Some(path),
            binding: state.binding,
            store: Some(store),
            ..Self::default()
        };
        if node.enabled {
            node.up()?;
        } else {
            node.persist(false, None, BTreeSet::new(), None)?;
        }
        Ok(node)
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Whether the enabled node has its authenticated identity and runtime worker available.
    #[must_use]
    pub fn active(&self) -> bool {
        self.enabled && self.identity.is_some() && self.worker.is_some()
    }

    /// Return the active UDP listener port advertised by this node's mesh identity.
    ///
    /// `None` means the worker has not bound a socket. The value is the actual port after an
    /// automatic fallback, so `mesh status` reports the endpoint peers should reach.
    #[must_use]
    pub fn listen_port(&self) -> Option<u16> {
        self.identity.as_ref().map(|identity| identity.port)
    }

    /// Whether a retired authority still needs a complete snapshot from the enrolled server.
    #[must_use]
    pub fn awaiting_server_snapshot(&self) -> bool {
        self.authority_reset_pending
    }

    #[must_use]
    pub fn stopping(&self) -> bool {
        !self.enabled && self.worker.is_some()
    }

    /// The public key this node currently presents as its identity, once it is up.
    pub(crate) fn interface_key(&self) -> Option<crate::policy::model::PublicKey> {
        self.identity.as_ref().map(|identity| identity.public_key)
    }
    #[must_use]
    pub fn config(&self) -> Option<&Config> {
        self.config.as_ref()
    }

    /// Return the persistent key's current public identity and the stable UDP listen port.
    /// # Errors
    /// Refuses a non-root caller, a missing state directory or any failed utun, UDP bind or state update.
    pub fn up(&mut self) -> io::Result<crate::dataplane::Identity> {
        if !self.enabled && self.worker.is_some() {
            self.down()?;
        }
        if let Some(identity) = &self.identity {
            return Ok(identity.clone());
        }
        // The key and its rotation journal live beside the platform's public state.
        let state = self
            .path
            .as_deref()
            .and_then(Path::parent)
            .ok_or(io::ErrorKind::NotFound)?;
        let store = self.store.as_ref().ok_or(io::ErrorKind::NotFound)?;
        let saved_port = store.recorded_listen_port()?;
        let listen_port = crate::listen_port::from_environment(saved_port)?;
        let (private_key, public_key) = if let Some(rotation) = store.rotation_secret()? {
            let (journal_key, journal_public) = recover_macos_rotation_key(store, &rotation)?;
            let (secret, keychain_public) = crate::macos_key::load_or_create(state)?;
            if keychain_public != journal_public
                || RotationKey::from_private(journal_key.private_bytes())?.1 != journal_public
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            (secret, journal_public)
        } else {
            if store.recorded_interface()?.is_some() && store.read_private_key()?.is_none() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let (secret, keychain_public) = crate::macos_key::load_or_create(state)?;
            let bytes = store.read_private_key()?.ok_or(io::ErrorKind::NotFound)?;
            let (_, file_public) = RotationKey::from_private(&bytes)?;
            if file_public != keychain_public {
                return Err(io::ErrorKind::InvalidData.into());
            }
            match store.recorded_interface()? {
                Some(recorded) if recorded != file_public => {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                Some(_) => {}
                None => store.record_interface(&file_public)?,
            }
            (secret, file_public)
        };
        if let Some(config) = self.config.as_mut()
            && let Some(bound) = config.local_key
        {
            if !macos_snapshot_binding_is_authorized(store, bound)? {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if bound != public_key {
                config.local_key = Some(public_key);
            }
        }
        let open = OpenUtun::open()?;
        let desired_routes = self
            .config
            .as_ref()
            .map_or_else(BTreeSet::new, route_addresses);
        if let Some(config) = &self.config {
            validate_underlay_routes(config, &desired_routes)?;
        }
        let startup = PendingWorker::begin(
            open,
            private_key,
            listen_port,
            self.config.clone(),
            desired_routes.clone(),
            PathBudgets::probe(self.config.as_ref()),
            self.network_status.clone(),
        )?;
        let info = startup.info().clone();
        let saved_port = if listen_port.allow_fallback {
            info.port
        } else {
            crate::listen_port::DEFAULT_PORT
        };
        store.record_listen_port(saved_port)?;
        self.interface = Some(info.interface.clone());
        self.port = info.port;
        self.routes.clone_from(&desired_routes);
        self.enabled = true;
        self.persist(
            true,
            self.config.as_ref(),
            desired_routes,
            self.interface.clone(),
        )?;
        match startup.commit() {
            Ok((worker, started)) => {
                self.interface = Some(started.interface);
                self.port = started.port;
                self.routes = started.routes;
                self.worker = Some(worker);
            }
            Err(error) => {
                if let Some(interface) = self.interface.as_deref() {
                    let _ = remove_routes(interface, &self.routes);
                }
                self.interface = None;
                self.routes.clear();
                let _ = self.persist(true, self.config.as_ref(), BTreeSet::new(), None);
                return Err(error);
            }
        }
        let identity = crate::dataplane::Identity {
            public_key,
            port: self.port,
            compact_access: true,
            #[cfg(feature = "mesh-dns")]
            dns_names: true,
            // macOS GotaTun supports journaled key rotation (#367) and authenticated authority epochs.
            key_rotation: true,
            authority_epoch: true,
            rotation_continuity: true,
        };
        self.identity = Some(identity.clone());
        Ok(identity)
    }

    /// Start an enabled node before the coordinator reconnect loop uses its saved Mesh route.
    /// # Errors
    /// Reports node key, utun, persistent state, and `WireGuard` setup errors.
    pub fn ensure(&mut self) -> io::Result<Option<crate::dataplane::Identity>> {
        if self.enabled {
            self.up().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Return the identity only while this node owns a running `GotaTun` worker and utun.
    /// # Errors
    /// Refuses rotation when the node or its live interface is unavailable.
    fn rotation_identity(&self) -> io::Result<crate::dataplane::Identity> {
        if !self.enabled || self.worker.is_none() || self.interface.is_none() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        self.identity
            .clone()
            .ok_or(io::ErrorKind::NotConnected.into())
    }

    /// Settle an older open journal before accepting a higher coordinator sequence.
    ///
    /// The active identity is authoritative after a superseded operation: an accepted candidate
    /// is retained, while an uncommitted predecessor stays selected and the unused candidate is
    /// erased from the completion marker.
    /// # Errors
    /// Refuses a journal that does not describe the active key or any failed durable update.
    fn settle_superseded_rotation(
        &mut self,
        rotation: &crate::node_state::RotationSecret,
    ) -> io::Result<()> {
        if rotation.completed {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let current = self.rotation_identity()?.public_key;
        let store = self.store.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        validate_macos_rotation_proof(store, rotation, current)?;
        let (candidate, candidate_public) = RotationKey::from_private(&rotation.candidate)?;
        let (_, previous_public) = RotationKey::from_private(&rotation.previous)?;
        if rotation.commit_requested && current == candidate_public {
            store.record_rotation_identity(
                &rotation.operation_id,
                rotation.sequence,
                candidate.private_bytes(),
                &candidate_public,
            )?;
            if let Some(identity) = self.identity.as_mut() {
                identity.public_key = candidate_public;
            }
            if let Some(config) = self.config.as_mut() {
                config.local_key = Some(candidate_public);
            }
            store.complete_rotation_secret(&rotation.operation_id, rotation.sequence)?;
        } else if current == previous_public {
            store.save_rotation_secret(&crate::node_state::RotationSecret {
                operation_id: rotation.operation_id.clone(),
                sequence: rotation.sequence,
                previous: previous_public.0,
                candidate: rotation.previous,
                commit_requested: true,
                completed: true,
            })?;
        } else {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }

    /// Prepare a local Mac identity without changing the live `GotaTun` worker (#285, D166).
    /// The predecessor and candidate are durable before the coordinator may publish overlap.
    /// # Errors
    /// Refuses an inactive node, invalid request, conflicting operation, unsafe state or failed write.
    pub(crate) fn prepare_rotation(
        &mut self,
        operation_id: &str,
        sequence: u64,
    ) -> io::Result<crate::policy::model::PublicKey> {
        if !valid_rotation_request(operation_id, sequence) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let current = self.rotation_identity()?.public_key;
        let store = self.store.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let existing = store.rotation_secret()?;
        if let Some(existing) = existing.as_ref() {
            if existing.completed {
                validate_macos_rotation_proof(store, existing, current)?;
                let completed_key = RotationKey::from_private(&existing.candidate)?.1;
                if current != completed_key
                    || existing.operation_id == operation_id
                    || sequence <= existing.sequence
                {
                    return Err(io::ErrorKind::InvalidData.into());
                }
            } else if existing.operation_id == operation_id && existing.sequence == sequence {
                validate_macos_rotation_proof(store, existing, current)?;
                return Ok(RotationKey::from_private(&existing.candidate)?.1);
            } else if existing.operation_id != operation_id && sequence > existing.sequence {
                self.settle_superseded_rotation(existing)?;
            } else {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }

        let existing = self
            .store
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .rotation_secret()?;
        if let Some(existing) = existing.as_ref() {
            let current = self.rotation_identity()?.public_key;
            validate_macos_rotation_proof(
                self.store.as_ref().ok_or(io::ErrorKind::NotConnected)?,
                existing,
                current,
            )?;
            if !existing.completed
                || existing.operation_id == operation_id
                || sequence <= existing.sequence
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }

        let store = self.store.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let private = store
            .read_private_key()?
            .ok_or(io::ErrorKind::InvalidData)?;
        let (previous, previous_public) = RotationKey::from_private(&private)?;
        if previous_public != current || store.recorded_interface()? != Some(current) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let (candidate, candidate_public) = loop {
            let pair = RotationKey::generate()?;
            if pair.1 != previous_public {
                break pair;
            }
        };
        store.save_rotation_secret(&crate::node_state::RotationSecret {
            operation_id: operation_id.to_owned(),
            sequence,
            previous: previous
                .private_bytes()
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidData)?,
            candidate: candidate
                .private_bytes()
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidData)?,
            commit_requested: false,
            completed: false,
        })?;
        #[cfg(test)]
        rotation_crash_checkpoint("rotation_prepared");
        Ok(candidate_public)
    }

    /// Commit the candidate after durably recording intent and changing the live worker key.
    /// Retries complete the identity record and key file after any process stop.
    /// # Errors
    /// Refuses a stale operation, an unproven key or any failed worker or durable update.
    pub(crate) fn commit_rotation(
        &mut self,
        operation_id: &str,
        sequence: u64,
    ) -> io::Result<crate::dataplane::Identity> {
        let mut identity = self.rotation_identity()?;
        let store = self.store.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let mut rotation = store.rotation_secret()?.ok_or(io::ErrorKind::NotFound)?;
        if rotation.operation_id != operation_id || rotation.sequence != sequence {
            return Err(io::ErrorKind::InvalidData.into());
        }
        validate_macos_rotation_proof(store, &rotation, identity.public_key)?;
        let (candidate, candidate_public) = RotationKey::from_private(&rotation.candidate)?;
        if rotation.completed {
            return Ok(identity);
        }
        let previous_public = RotationKey::from_private(&rotation.previous)?.1;
        if identity.public_key == previous_public {
            if !rotation.commit_requested {
                rotation.commit_requested = true;
                store.save_rotation_secret(&rotation)?;
                #[cfg(test)]
                rotation_crash_checkpoint("rotation_commit_requested");
            }
            self.worker
                .as_ref()
                .ok_or(io::ErrorKind::NotConnected)?
                .set_private_key(candidate.gotatun_secret())?;
            identity.public_key = candidate_public;
            self.identity = Some(identity.clone());
            #[cfg(test)]
            rotation_crash_checkpoint("rotation_device_key_changed");
        } else if identity.public_key != candidate_public || !rotation.commit_requested {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if let Some(config) = self.config.as_mut() {
            config.local_key = Some(candidate_public);
        }
        store.record_rotation_identity(
            operation_id,
            sequence,
            candidate.private_bytes(),
            &candidate_public,
        )?;
        Ok(self.identity.clone().ok_or(io::ErrorKind::NotConnected)?)
    }

    /// Finish an acknowledged rotation after saving its new local binding.
    /// The retained journal makes completion safe to retry and clears predecessor private bytes.
    /// # Errors
    /// Refuses a stale or uncommitted operation, an identity mismatch or a failed durable write.
    pub(crate) fn finish_rotation(&mut self, operation_id: &str, sequence: u64) -> io::Result<()> {
        let identity = self.rotation_identity()?;
        let store = self.store.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let rotation = store.rotation_secret()?.ok_or(io::ErrorKind::NotFound)?;
        if rotation.operation_id != operation_id || rotation.sequence != sequence {
            return Err(io::ErrorKind::InvalidData.into());
        }
        validate_macos_rotation_proof(store, &rotation, identity.public_key)?;
        let candidate_public = RotationKey::from_private(&rotation.candidate)?.1;
        if identity.public_key != candidate_public
            || (!rotation.completed && !rotation.commit_requested)
            || store.recorded_interface()? != Some(candidate_public)
            || store
                .read_private_key()?
                .map(|private| RotationKey::from_private(&private).map(|(_, public)| public))
                .transpose()?
                != Some(candidate_public)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if let Some(config) = self.config.as_mut() {
            config.local_key = Some(candidate_public);
        }
        store.complete_rotation_secret(operation_id, sequence)?;
        #[cfg(test)]
        rotation_crash_checkpoint("rotation_finished");
        Ok(())
    }
    /// Persist disabled intent before retiring routes and the owned utun descriptor.
    /// # Errors
    /// Keeps the old route inventory when cleanup cannot be completed.
    pub fn down(&mut self) -> io::Result<()> {
        self.persist(
            false,
            self.config.as_ref(),
            self.routes.clone(),
            self.interface.clone(),
        )?;
        self.enabled = false;
        if let Some(worker) = self.worker.as_mut() {
            worker.stop()?;
        }
        self.worker = None;
        self.identity = None;
        self.config = None;
        self.authority_reset_pending = false;
        self.pending = None;
        self.routes.clear();
        self.interface = None;
        self.persist(false, None, BTreeSet::new(), None)
    }

    /// Whether the route to `network`, reachable through a router peer, is on the utun, and why
    /// not, for `mesh routes` (D197 M3).
    #[must_use]
    pub fn network_route_state(
        &self,
        network: crate::policy::networks::Network,
    ) -> serde_json::Value {
        self.network_status.route_json(network)
    }

    /// Read current `GotaTun` peer counters without exposing private key material.
    /// # Errors
    /// Reports an unavailable worker thread.
    pub fn counters(&self) -> io::Result<BTreeMap<crate::policy::model::PublicKey, Counters>> {
        self.worker
            .as_ref()
            .map_or_else(|| Ok(CounterMap::new()), Worker::counters)
    }

    /// Apply only a complete, authenticated configuration revision and persist its public intent.
    /// # Errors
    /// Refuses wrong identity bindings, incomplete chunks, unsafe routes, or failed engine updates.
    pub fn chunk(&mut self, chunk: crate::dataplane::Chunk) -> io::Result<bool> {
        let Some(identity) = self.identity.clone() else {
            self.pending = None;
            tracing::warn!("Mac mesh configuration chunk refused while the node is not up");
            return Err(io::ErrorKind::NotConnected.into());
        };
        if !self.enabled || self.worker.is_none() || chunk.local_key != Some(identity.public_key) {
            self.pending = None;
            tracing::warn!(
                error_kind = ?io::ErrorKind::InvalidData,
                "Mac mesh configuration chunk refused"
            );
            return Err(io::ErrorKind::InvalidData.into());
        }
        if chunk
            .authority_epoch
            .as_deref()
            .is_some_and(|epoch| !crate::dataplane::valid_authority_epoch(epoch))
        {
            self.pending = None;
            tracing::warn!("Mac mesh configuration chunk refused: authority epoch is malformed");
            return Err(io::ErrorKind::InvalidData.into());
        }
        let authority_changed = needs_authority_reset(self.config.as_ref(), &chunk);
        if authority_changed {
            let old_epoch = self
                .config
                .as_ref()
                .and_then(|old| old.authority_epoch.as_deref());
            if old_epoch.is_some() && chunk.authority_epoch.is_none() && chunk.index == 0 {
                // A server rolled back to a release without epochs (D295) is one more authority
                // change: its full snapshot replaces the old peer set like any other (#382 P2).
                tracing::warn!(
                    old_epoch,
                    "Mac mesh server stopped sending an authority epoch, likely a rollback; adopting its full snapshot"
                );
            }
            let pending_new_authority = self.pending.as_ref().is_some_and(|pending| {
                pending.config.authority_epoch == chunk.authority_epoch
                    && pending.from_version.is_none()
            });
            if chunk.index == 0 {
                if chunk.from_version.is_some() {
                    self.pending = None;
                    tracing::warn!(
                        "Mac mesh configuration chunk refused: a new authority must start with a full snapshot"
                    );
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.pending = None;
                tracing::warn!(
                    old_epoch = ?old_epoch,
                    new_epoch = ?chunk.authority_epoch,
                    old_version = ?self.config.as_ref().map(|config| config.version),
                    new_version = chunk.version,
                    "staging a full Mac mesh snapshot from the changed authority"
                );
            } else if !pending_new_authority {
                self.pending = None;
                tracing::warn!(
                    "Mac mesh configuration chunk refused: a new authority must start with a full snapshot"
                );
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        if self.authority_reset_pending && chunk.from_version.is_some() {
            self.pending = None;
            tracing::warn!(
                error_kind = ?io::ErrorKind::InvalidData,
                "Mac mesh configuration chunk refused: an authority reset needs a full snapshot"
            );
            return Err(io::ErrorKind::InvalidData.into());
        }
        // With a Store, a lower same-epoch revision is accepted on purpose: a database restored
        // under a running server keeps its epoch but rewinds revisions (#382, J418 P3-a). The
        // exact-base write (`write_public_state_full_snapshot`) keeps that swap atomic.
        let result = stage_chunk(
            &mut self.pending,
            self.config.as_ref(),
            &identity,
            self.store.is_some() || self.authority_reset_pending,
            chunk,
        );
        if let Err(error) = &result {
            self.pending = None;
            tracing::warn!(
                error_kind = ?error.kind(),
                "Mac mesh configuration chunk refused"
            );
        }
        let Some(config) = result? else {
            return Ok(false);
        };
        let validation = (|| {
            validate_config(&config, identity.public_key)?;
            // A complete snapshot may replay its revision only with identical contents. Authority
            // reset is handled separately because the new epoch may reuse a revision.
            if !self.authority_reset_pending
                && self.config.as_ref().is_some_and(|accepted| {
                    accepted.authority_epoch == config.authority_epoch
                        && accepted.version == config.version
                        && !crate::dataplane::same_runtime_content(accepted, &config)
                })
            {
                tracing::warn!(
                    authority_epoch = ?config.authority_epoch,
                    version = config.version,
                    "Mac mesh configuration conflict at an accepted authority revision"
                );
                return Err(io::ErrorKind::InvalidData.into());
            }
            if self
                .config
                .as_ref()
                .is_some_and(|old| old.node == config.node && old.addresses != config.addresses)
            {
                return Err(io::ErrorKind::Unsupported.into());
            }
            let desired_routes = route_addresses(&config);
            validate_underlay_routes(&config, &desired_routes)?;
            if authority_changed || self.authority_reset_pending {
                #[cfg(feature = "mesh-dns")]
                crate::dns::Records::from_config(&config)?;
                PacketFilter::prepare_policy(&config, MeshProxyIngress::default())?;
            }
            Ok::<_, io::Error>(desired_routes)
        })();
        let desired_routes = match validation {
            Ok(routes) => routes,
            Err(error) if authority_changed => {
                return self.stop_after_retirement_failure(error, &config);
            }
            Err(error) => return Err(error),
        };
        // Preserve the receipt through incomplete or rejected snapshots. Only the fully
        // validated incoming operation can authorize continuity or journal retirement.
        if authority_changed {
            self.prepare_authority_replacement(&config)?;
        } else if self.authority_reset_pending {
            self.retire_settled_authority_rotation(config.rotation_operation.as_ref())?;
        }
        let completes_authority_reset = self.authority_reset_pending;
        let reset_config = completes_authority_reset
            .then(|| self.config.clone())
            .flatten();
        if completes_authority_reset {
            self.authority_reset_pending = false;
        }
        let lower_revision_base = (!completes_authority_reset)
            .then(|| {
                self.config
                    .as_ref()
                    .filter(|old| {
                        old.authority_epoch == config.authority_epoch
                            && config.version < old.version
                    })
                    .cloned()
            })
            .flatten();
        let mut cleanup_routes = self.routes.clone();
        cleanup_routes.extend(desired_routes.iter().copied());
        let persistence = if let Some(base) = lower_revision_base.as_ref() {
            self.persist_full_snapshot(&config, cleanup_routes, self.interface.clone(), base)
        } else {
            self.persist(true, Some(&config), cleanup_routes, self.interface.clone())
        };
        if let Err(error) = persistence {
            if let Some(denied) = reset_config.as_ref() {
                self.authority_reset_pending = true;
                return self.stop_after_retirement_failure(error, denied);
            }
            return Err(error);
        }
        let applied = self
            .worker
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
            .and_then(|worker| {
                if reset_config.is_some() {
                    worker.replace_authority(config.clone())
                } else {
                    worker.apply(config.clone())
                }
            });
        let info = match applied {
            Ok(info) => info,
            Err(error) => {
                if let Some(denied) = reset_config.as_ref() {
                    self.authority_reset_pending = true;
                    return self.stop_after_retirement_failure(error, denied);
                }
                return Err(error);
            }
        };
        self.config = Some(config);
        self.routes = info.routes;
        self.interface = Some(info.interface);
        self.port = info.port;
        self.persist(
            true,
            self.config.as_ref(),
            self.routes.clone(),
            self.interface.clone(),
        )?;
        Ok(true)
    }

    /// Persist a complete authority change while leaving the current Mac peers untouched.
    ///
    /// The full replacement has already been authenticated and staged. This peer-free durable
    /// checkpoint is therefore crash-safe, while the serialized worker receives the complete
    /// replacement only after the checkpoint succeeds. Only an exact operation match retains
    /// the rotation journal for commit or finish retries.
    /// # Errors
    /// Stops the worker if snapshot persistence or rotation-journal retirement fails.
    fn prepare_authority_replacement(&mut self, replacement: &Config) -> io::Result<()> {
        let mut denied = replacement.clone();
        denied.default_policy = crate::dataplane::DefaultPolicy::Deny;
        denied.peers.clear();
        #[cfg(feature = "mesh-dns")]
        denied.peer_names.clear();
        self.pending = None;
        let continuity = self
            .store
            .as_ref()
            .map(|store| store.rotation_matches(replacement.rotation_operation.as_ref()))
            .transpose()
            .map(|matched| matched.unwrap_or(false));
        let continues_rotation = matches!(continuity, Ok(true));
        let rotation_error = match continuity {
            Ok(true) => None,
            Ok(false) => self.settle_authority_rotation().err(),
            Err(error) => Some(error),
        };
        if let Some(identity) = &self.identity {
            denied.local_key = Some(identity.public_key);
        }
        self.config = Some(denied.clone());
        self.authority_reset_pending = true;
        let persistence_error = self.persist_retired_snapshot(&denied).err();
        let journal_error =
            if persistence_error.is_none() && rotation_error.is_none() && !continues_rotation {
                self.store
                    .as_ref()
                    .map(crate::node_state::Store::discard_rotation_journal)
                    .transpose()
                    .err()
            } else {
                None
            };
        if let Some(error) = persistence_error.or(rotation_error).or(journal_error) {
            return self.stop_after_retirement_failure(error, &denied);
        }
        #[cfg(test)]
        authority_replacement_crash_checkpoint();
        Ok(())
    }

    /// Settle an open rotation on the active Mac key before retiring the old authority journal.
    ///
    /// The journal sequence belongs to the previous server. The current worker key and private key
    /// file remain the enrolled machine identity, so they stay selected while the journal is erased.
    /// # Errors
    /// Refuses an unproven key transition or a failed durable update.
    fn settle_authority_rotation(&mut self) -> io::Result<()> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let Some(rotation) = store.rotation_secret()? else {
            return Ok(());
        };
        let current = self.rotation_identity()?.public_key;
        validate_macos_rotation_proof(store, &rotation, current)?;
        if !rotation.completed {
            self.settle_superseded_rotation(&rotation)?;
        }
        if let (Some(config), Some(identity)) = (&mut self.config, &self.identity) {
            config.local_key = Some(identity.public_key);
        }
        Ok(())
    }

    /// Retry journal retirement after validating a full snapshot for an interrupted reset.
    ///
    /// The peer-free reset record makes startup safe. This retry saves the settled live key binding
    /// before removing the previous authority's rotation journal. An exact operation match from
    /// the incoming full snapshot retains it; cached metadata alone never proves continuity.
    /// # Errors
    /// Refuses a journal that does not prove the active key or a failed state write.
    fn retire_settled_authority_rotation(
        &mut self,
        operation: Option<&crate::dataplane::RotationContinuation>,
    ) -> io::Result<()> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        if store.rotation_secret()?.is_none() || store.rotation_matches(operation)? {
            return Ok(());
        }
        self.settle_authority_rotation()?;
        let config = self.config.clone().ok_or(io::ErrorKind::InvalidData)?;
        self.persist(
            self.enabled,
            Some(&config),
            self.routes.clone(),
            self.interface.clone(),
        )?;
        self.store
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .discard_rotation_journal()
    }

    /// Persist peer-free authority state before the Mac worker removes old peers.
    /// # Errors
    /// Reports when neither atomic replacement nor the in-place fail-closed write succeeds.
    fn persist_retired_snapshot(&self, denied: &Config) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let state = SavedState {
            enabled: self.enabled,
            config: Some(denied.clone()),
            authority_reset_pending: true,
            routes: self.routes.clone(),
            interface: self.interface.clone(),
            port: self.port,
            backend: None,
            binding: self.binding.clone(),
        };
        match write_public_state(path, &state) {
            Ok(()) => Ok(()),
            Err(atomic_error) => write_public_state_in_place(path, &state).inspect_err(|error| {
                tracing::error!(
                    atomic_error_kind = ?atomic_error.kind(),
                    fallback_error_kind = ?error.kind(),
                    "atomic and in-place peer-free Mac state writes both failed before retirement"
                );
            }),
        }
    }

    /// Stop the node without restoring peers when a retirement step cannot be completed.
    /// # Errors
    /// Returns the reset cause unless shutdown reports a more immediate failure.
    fn stop_after_retirement_failure<T>(
        &mut self,
        reset_error: io::Error,
        denied: &Config,
    ) -> io::Result<T> {
        // A complete but rejected new authority retires peers without retiring its receipt.
        let mut denied = denied.clone();
        denied.default_policy = crate::dataplane::DefaultPolicy::Deny;
        denied.peers.clear();
        #[cfg(feature = "mesh-dns")]
        denied.peer_names.clear();
        // Fence restore first; the disabled write below retries any failure.
        let _ = self.persist_retired_snapshot(&denied);
        self.enabled = false;
        let stop_result = self
            .worker
            .take()
            .map_or(Ok(()), |mut worker| worker.stop());
        self.identity = None;
        self.config = Some(denied.clone());
        self.authority_reset_pending = true;
        self.pending = None;
        self.routes.clear();
        self.interface = None;
        let state = SavedState {
            enabled: false,
            config: Some(denied.clone()),
            authority_reset_pending: true,
            routes: BTreeSet::new(),
            interface: None,
            port: self.port,
            backend: None,
            binding: self.binding.clone(),
        };
        let persistence = self.path.as_ref().map_or(Ok(()), |path| {
            match write_public_state(path, &state) {
                Ok(()) => Ok(()),
                Err(atomic_error) => write_public_state_in_place(path, &state).inspect_err(|error| {
                    tracing::error!(
                        atomic_error_kind = ?atomic_error.kind(),
                        fallback_error_kind = ?error.kind(),
                        "could not persist peer-free disabled Mac mesh state after retirement failed"
                    );
                }),
            }
        });
        if let Err(error) = persistence {
            tracing::error!(
                error_kind = ?error.kind(),
                "could not persist stopped Mac mesh state after peer retirement failed"
            );
        }
        match stop_result {
            Ok(()) => {
                tracing::warn!(
                    error_kind = ?reset_error.kind(),
                    "Mac mesh stopped because stale peers could not be retired"
                );
                Err(reset_error)
            }
            Err(stop_error) => {
                tracing::error!(
                    reset_error_kind = ?reset_error.kind(),
                    stop_error_kind = ?stop_error.kind(),
                    "Mac mesh peer retirement and fail-closed shutdown both failed"
                );
                Err(stop_error)
            }
        }
    }

    /// Save enabled state, accepted public config, and route ownership for restart recovery.
    fn persist(
        &self,
        enabled: bool,
        config: Option<&Config>,
        routes: BTreeSet<IpAddr>,
        interface: Option<String>,
    ) -> io::Result<()> {
        if let Some(path) = &self.path {
            write_public_state(
                path,
                &SavedState {
                    enabled,
                    config: config.cloned(),
                    authority_reset_pending: self.authority_reset_pending,
                    routes,
                    interface,
                    port: self.port,
                    backend: None,
                    binding: self.binding.clone(),
                },
            )?;
        }
        Ok(())
    }

    /// Save a lower-revision full snapshot only against the exact accepted durable base.
    ///
    /// This Store-backed compare-and-set is the explicit same-authority replacement transaction;
    /// an in-memory config alone cannot authorize lowering the revision fence.
    /// # Errors
    /// Refuses an absent or changed base and reports failed durable writes.
    fn persist_full_snapshot(
        &self,
        config: &Config,
        routes: BTreeSet<IpAddr>,
        interface: Option<String>,
        expected: &Config,
    ) -> io::Result<()> {
        let path = self.path.as_ref().ok_or(io::ErrorKind::InvalidData)?;
        write_public_state_full_snapshot(
            path,
            &SavedState {
                enabled: true,
                config: Some(config.clone()),
                authority_reset_pending: self.authority_reset_pending,
                routes,
                interface,
                port: self.port,
                backend: None,
                binding: self.binding.clone(),
            },
            expected,
        )
    }
}

fn validate_config(config: &Config, identity: crate::policy::model::PublicKey) -> io::Result<()> {
    if config.local_key != Some(identity) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut keys = BTreeSet::new();
    let mut ipv4 = BTreeSet::new();
    let mut ipv6 = BTreeSet::new();
    for (node, peer) in &config.peers {
        if *node == config.node
            || peer.peer.key == identity
            || !keys.insert(peer.peer.key)
            || peer.peer.addresses.ipv4 == config.addresses.ipv4
            || peer.peer.addresses.ipv6 == config.addresses.ipv6
            || !ipv4.insert(peer.peer.addresses.ipv4)
            || !ipv6.insert(peer.peer.addresses.ipv6)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok(())
}

/// Checks Mac peer routing, configuration validation, and atomic snapshot staging.
#[cfg(test)]
mod tests;
