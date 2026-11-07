//! Restores the Mac userspace Mesh node and its utun routes across daemon lifetimes.

use crate::dataplane::Config;
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
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::unix::AsyncFd;
use tokio::{
    runtime::Builder as RuntimeBuilder,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
};
use zeroize::Zeroizing;

const UTUN_AF_INET: u32 = 2;
const UTUN_AF_INET6: u32 = 30;
const UTUN_CONTROL: &str = "com.apple.net.utun_control";
const UTUN_MTU: usize = 1280;
const PUBLIC_STATE: &str = "mesh-public.json";
const MAX_PUBLIC_STATE_BYTES: u64 = 16 * 1024 * 1024;

/// Pause a Mac rotation child at a durable boundary so its parent can send SIGKILL.
#[cfg(test)]
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

    /// Copy this key into GotaTun's zeroizing secret type for a live update.
    fn gotatun_secret(&self) -> StaticSecret {
        StaticSecret::from(*self.0)
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

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<(Self::Send, Self::Recv)> {
        if params.addr.is_some() || params.port != self.port {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok((self.send.clone(), self.receive.clone()))
    }
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

struct OpenUtun {
    fd: OwnedFd,
    name: String,
}

impl OpenUtun {
    /// Ask the kernel for one fresh utun and read back the assigned interface unit.
    /// # Errors
    /// Returns socket-control or interface lookup failures.
    fn open() -> io::Result<Self> {
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
}

impl MacUtun {
    /// Register one previously opened utun descriptor with this daemon's tokio runtime.
    /// # Errors
    /// Returns readiness registration failures.
    fn from_open(open: OpenUtun) -> io::Result<Self> {
        // Tokio's safe constructor is deprecated but remains the only safe API;
        // the replacement requires unsafe code, which this crate forbids.
        #[allow(deprecated)]
        let fd = AsyncFd::new(open.fd)?;
        Ok(Self {
            fd: Arc::new(fd),
            name: Arc::from(open.name),
        })
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn sender(&self) -> MacUtunTx {
        MacUtunTx {
            fd: self.fd.clone(),
            frame: Vec::with_capacity(UTUN_MTU + 4),
        }
    }

    fn receiver(&self) -> MacUtunRx {
        MacUtunRx {
            fd: self.fd.clone(),
            mtu: MtuWatcher::new(UTUN_MTU as u16),
        }
    }
}

struct MacUtunTx {
    fd: Arc<AsyncFd<OwnedFd>>,
    frame: Vec<u8>,
}

impl IpSend for MacUtunTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let packet = packet.into_bytes();
        let family = utun_family(packet.as_ref())?;
        if packet.len() > UTUN_MTU {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.frame.clear();
        self.frame.extend_from_slice(&family.to_be_bytes());
        self.frame.extend_from_slice(packet.as_ref());
        loop {
            let mut ready = self.fd.writable().await?;
            match ready.try_io(|fd| write(fd.get_ref(), &self.frame).map_err(io::Error::from)) {
                Err(_) => continue,
                Ok(Err(error)) => return Err(error),
                Ok(Ok(written)) if written == self.frame.len() => return Ok(()),
                Ok(Ok(_)) => return Err(io::ErrorKind::WriteZero.into()),
            }
        }
    }
}

struct MacUtunRx {
    fd: Arc<AsyncFd<OwnedFd>>,
    mtu: MtuWatcher,
}

impl IpRecv for MacUtunRx {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let mut packet = pool.get();
        loop {
            let mut ready = self.fd.readable().await?;
            let result =
                ready.try_io(|fd| read(fd.get_ref(), &mut packet[..]).map_err(io::Error::from));
            match result {
                Err(_) => continue,
                Ok(Err(error)) => return Err(error),
                Ok(Ok(0)) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(Ok(length)) => {
                    packet.truncate(length);
                    let payload = parse_utun_payload(packet.as_ref())?;
                    if payload.len() > UTUN_MTU {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    packet.buf_mut().advance(4);
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

/// Add or remove one exact peer host route through our allocated utun.
fn route(interface: &str, address: IpAddr, operation: &str) -> io::Result<()> {
    let family = if address.is_ipv4() { "-inet" } else { "-inet6" };
    let output = Command::new("/sbin/route")
        .args(["-n", operation, family, "-host"])
        .arg(address.to_string())
        .args(["-interface", interface])
        .output()?;
    if output.status.success() {
        Ok(())
    } else if operation == "delete"
        && String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("not in table")
    {
        Ok(())
    } else {
        Err(io::ErrorKind::AddrInUse.into())
    }
}

fn valid_utun_name(name: &str) -> bool {
    name.strip_prefix("utun")
        .is_some_and(|unit| !unit.is_empty() && unit.bytes().all(|byte| byte.is_ascii_digit()))
}

fn remove_routes(interface: &str, routes: &BTreeSet<IpAddr>) -> io::Result<()> {
    if !valid_utun_name(interface) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    for address in routes {
        route(interface, *address, "delete")?;
    }
    Ok(())
}

/// Configure only this owned utun interface; no other tunnel or resolver is changed.
fn configure_interface(interface: &str, config: Option<&Config>) -> io::Result<()> {
    run_ifconfig([interface, "mtu", &UTUN_MTU.to_string(), "up"])?;
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

fn run_ifconfig<'a>(arguments: impl IntoIterator<Item = &'a str>) -> io::Result<()> {
    let output = Command::new("/sbin/ifconfig").args(arguments).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::ErrorKind::Other.into())
    }
}

/// Public durable intent shared with the Linux node journal; the WireGuard secret is never serialized.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedState {
    enabled: bool,
    config: Option<crate::dataplane::Config>,
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

/// The enrolment a saved configuration belongs to (#265 P2-1, #325).
///
/// A configuration is trusted only for the coordinator, host and infraternal
/// agent identity that received it. If the Mac is re-enrolled (another
/// coordinator, another host id or a new agent key) while its state directory
/// survives, restoring the old peers would re-install another mesh's keys and
/// routes and refuse every update from the new coordinator. Each field is
/// public: a SHA-256 of a certificate or public key, or the host id.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrolment {
    /// SHA-256 (hex) of the issuing coordinator's CA certificate, DER.
    coordinator: String,
    /// Host id the coordinator issued at enrolment.
    host: String,
    /// SHA-256 (hex) of the infraternal agent's mTLS public key, DER.
    agent_key: String,
}

impl Enrolment {
    /// Bind to the identity in `identity.json`, given its public parts.
    #[must_use]
    pub fn new(coordinator_ca_der: &[u8], host: &str, agent_public_key_der: &[u8]) -> Self {
        Self {
            coordinator: hex(&openssl::sha::sha256(coordinator_ca_der)),
            host: host.to_owned(),
            agent_key: hex(&openssl::sha::sha256(agent_public_key_der)),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

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
            routes: BTreeSet::new(),
            interface: None,
            port: 0,
            backend: None,
            binding: None,
        }
    }
}

/// How this node enforces D164 access rules, as `mesh status` reports it.
///
/// The Mac node has no packet filter yet (#265 slice 3), so it cannot narrow
/// what a peer may reach. Until it can, it fails closed: see [`installed_peers`].
pub const ENFORCEMENT: &str = "unavailable";

/// The peers this node may connect to while it cannot enforce access rules.
///
/// The coordinator also distributes a peer when only the opposite direction is
/// granted (`inbound` is `None`) or when the grant is narrowed to ports. A
/// `WireGuard` peer would reach every port on this Mac in both cases, so only a
/// peer that may open connections to every port here (`inbound` is `All`) is
/// installed. The coordinator is always installed: every node may reach it
/// (D164). Its own inbound policy is not checked, so the server host can reach
/// every port on this Mac, which a Linux node would deny without an arrow.
/// The owner accepted that gap until the slice-3 filter (#265, J162 F1), and
/// `mesh status` says so. The cost is that an arrow from this Mac to a node
/// without the reverse arrow does not work until enforcement arrives.
fn installed_peers(config: &Config) -> impl Iterator<Item = &crate::dataplane::PeerPolicy> {
    config.peers.iter().filter_map(|(node, policy)| {
        (config.server == Some(*node)
            || matches!(policy.inbound, crate::policy::rules::TrafficPolicy::All))
        .then_some(policy)
    })
}

/// Return only the installed peers' host addresses that belong on the utun interface.
fn route_addresses(config: &Config) -> BTreeSet<IpAddr> {
    installed_peers(config)
        .flat_map(|policy| {
            [
                IpAddr::V4(policy.peer.addresses.ipv4),
                IpAddr::V6(policy.peer.addresses.ipv6),
            ]
        })
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
    let mut body = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut body)?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|_| io::ErrorKind::InvalidData.into())
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
    let body = serde_json::to_vec(state).map_err(io::Error::other)?;
    if body.len() as u64 > MAX_PUBLIC_STATE_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
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
    result
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
/// # Errors
/// Rejects truncated, unsupported or family-mismatched frames.
fn parse_utun_payload(frame: &[u8]) -> io::Result<&[u8]> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(io::ErrorKind::InvalidData)?
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidData)?;
    let payload = frame.get(4..).ok_or(io::ErrorKind::InvalidData)?;
    let family = u32::from_be_bytes(prefix);
    if payload.is_empty() || payload.len() > UTUN_MTU || utun_family(payload)? != family {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(payload)
}

/// Convert every configured identity into GotaTun peers, keeping both rotation keys installed.
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
/// Rejects invalid host routes before they reach GotaTun.
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

fn stage_chunk(
    pending: &mut Option<Pending>,
    current: Option<&Config>,
    identity: &crate::dataplane::Identity,
    chunk: crate::dataplane::Chunk,
) -> io::Result<Option<Config>> {
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
                    || chunk.version <= old.version)
        })
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if chunk.index == 0 {
        let current_version = current.map(|config| config.version);
        if chunk.from_version.is_some() && chunk.from_version != current_version
            || current_version.is_some_and(|version| {
                chunk.version < version || chunk.from_version.is_some() && chunk.version == version
            })
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let config = if chunk.from_version.is_some() {
            current.cloned().ok_or(io::ErrorKind::InvalidData)?
        } else {
            Config {
                local_key: chunk.local_key,
                server: chunk.server,
                node: chunk.node,
                #[cfg(feature = "mesh-dns-spike")]
                name: chunk.name.clone(),
                #[cfg(feature = "mesh-dns-spike")]
                dns_suffix: chunk.dns_suffix.clone(),
                version: chunk.version,
                addresses: chunk.addresses,
                default_policy: chunk.default_policy,
                exposure: chunk.exposure.clone(),
                peers: std::collections::BTreeMap::new(),
                #[cfg(feature = "mesh-dns-spike")]
                peer_names: std::collections::BTreeMap::new(),
            }
        };
        #[cfg(feature = "mesh-dns-spike")]
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
    #[cfg(feature = "mesh-dns-spike")]
    let names_changed = staged.config.name != chunk.name;
    #[cfg(feature = "mesh-dns-spike")]
    let dns_suffix_changed = staged.config.dns_suffix != chunk.dns_suffix;
    #[cfg(not(feature = "mesh-dns-spike"))]
    let names_changed = false;
    #[cfg(not(feature = "mesh-dns-spike"))]
    let dns_suffix_changed = false;
    if staged.server != chunk.server
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
        #[cfg(feature = "mesh-dns-spike")]
        staged.config.peer_names.remove(&node);
    }
    staged.config.peers.extend(chunk.upserted);
    for (node, partial) in chunk.merged {
        let peer = staged
            .config
            .peers
            .get_mut(&node)
            .ok_or(io::ErrorKind::InvalidData)?;
        if peer.peer != partial.peer
            || matches!(partial.inbound, crate::policy::rules::TrafficPolicy::All)
            || matches!(partial.outbound, crate::policy::rules::TrafficPolicy::All)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        peer.inbound.union(&partial.inbound);
        peer.outbound.union(&partial.outbound);
    }
    #[cfg(feature = "mesh-dns-spike")]
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

#[derive(Clone)]
struct RuntimeInfo {
    interface: String,
    port: u16,
    routes: BTreeSet<IpAddr>,
}

/// A serialized request for the Mac `GotaTun` worker. Each request has a reply channel so callers
/// can wait for the device update before changing durable identity state.
enum WorkerCommand {
    Apply {
        config: Config,
        reply: sync::SyncSender<io::Result<RuntimeInfo>>,
    },
    SetPrivateKey {
        private_key: gotatun::x25519::StaticSecret,
        reply: sync::SyncSender<io::Result<()>>,
    },
    Counters(sync::SyncSender<CounterMap>),
    Stop(sync::SyncSender<io::Result<()>>),
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
    fn begin(
        open: OpenUtun,
        private_key: gotatun::x25519::StaticSecret,
        requested_port: u16,
        config: Option<Config>,
        routes: BTreeSet<IpAddr>,
    ) -> io::Result<Self> {
        let (info_tx, info_rx) = sync::sync_channel(1);
        let (gate_tx, gate_rx) = sync::sync_channel(1);
        let (ready_tx, ready_rx) = sync::sync_channel(1);
        let (commands, receiver) = mpsc::unbounded_channel();
        let join = std::thread::Builder::new()
            .name("infraternal-mesh-macos".to_owned())
            .spawn(move || {
                let runtime = match RuntimeBuilder::new_current_thread().enable_all().build() {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        let _ =
                            info_tx.send(Err(io::Error::other("Mesh runtime could not start.")));
                        return;
                    }
                };
                let initialized = runtime.block_on(async move {
                    let utun = MacUtun::from_open(open)?;
                    let mut factory = UdpSocketFactory::default();
                    let params = UdpTransportFactoryParams {
                        addr: None,
                        port: requested_port,
                    };
                    let (send, receive) = factory.bind(&params).await?;
                    let port = send.local_addr()?.port();
                    let info = RuntimeInfo {
                        interface: utun.name().to_owned(),
                        port,
                        routes,
                    };
                    Ok((
                        utun,
                        BoundUdpFactory {
                            send,
                            receive,
                            port,
                        },
                        info,
                    ))
                });
                let (utun, factory, info) = match initialized {
                    Ok(initialized) => initialized,
                    Err(error) => {
                        let _ = info_tx.send(Err(error));
                        return;
                    }
                };
                if info_tx.send(Ok(info.clone())).is_err() || !gate_rx.recv().unwrap_or(false) {
                    return;
                }
                let device = runtime.block_on(async {
                    configure_interface(&info.interface, config.as_ref())?;
                    let peers = config
                        .as_ref()
                        .map(peers_for_config)
                        .transpose()?
                        .unwrap_or_default();
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
                        if let Err(error) = route(&info.interface, *address, "add") {
                            let _ = remove_routes(&info.interface, &installed);
                            device.stop().await;
                            return Err(error);
                        }
                        installed.insert(*address);
                    }
                    Ok(device)
                });
                let device = match device {
                    Ok(device) => device,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                if ready_tx.send(Ok(())).is_err() {
                    let _ = runtime.block_on(device.stop());
                    return;
                }
                let state = RuntimeState {
                    utun: Some(utun),
                    device: Some(device),
                    config,
                    routes: info.routes,
                    port: info.port,
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
    fn apply(&self, config: Config) -> io::Result<RuntimeInfo> {
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::Apply { config, reply })
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

    /// Replace the live GotaTun key on its serialized worker thread.
    /// # Errors
    /// Reports a stopped worker or a rejected key update.
    fn set_private_key(&self, private_key: gotatun::x25519::StaticSecret) -> io::Result<()> {
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::SetPrivateKey { private_key, reply })
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        result.recv().map_err(|_| io::ErrorKind::BrokenPipe)?
    }

    fn stop(&mut self) -> io::Result<()> {
        let (reply, result) = sync::sync_channel(1);
        self.commands
            .send(WorkerCommand::Stop(reply))
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
        let stopped = result.recv().map_err(|_| io::ErrorKind::BrokenPipe)?;
        if stopped.is_ok()
            && let Some(join) = self.join.take()
        {
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

struct RuntimeState {
    utun: Option<MacUtun>,
    device: Option<GotaDevice>,
    config: Option<Config>,
    routes: BTreeSet<IpAddr>,
    port: u16,
}

/// Runs the Mac `GotaTun` device loop, applying requests in order and stopping when its queue closes.
async fn run_worker(mut commands: UnboundedReceiver<WorkerCommand>, mut state: RuntimeState) {
    while let Some(command) = commands.recv().await {
        match command {
            WorkerCommand::Apply { config, reply } => {
                let result = state.apply(config).await;
                let _ = reply.send(result);
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
                let stop = result.is_ok();
                let _ = reply.send(result);
                if stop {
                    return;
                }
            }
        }
    }
    let _ = state.stop().await;
}

impl RuntimeState {
    /// Change the private identity on the active WireGuard device without restarting its utun.
    /// # Errors
    /// Reports a stopped device or a rejected key update.
    async fn set_private_key(
        &mut self,
        private_key: gotatun::x25519::StaticSecret,
    ) -> io::Result<()> {
        self.device
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .set_private_key(private_key)
            .await
            .map_err(|_| io::Error::other("WireGuard private key could not be changed."))
    }

    async fn apply(&mut self, config: Config) -> io::Result<RuntimeInfo> {
        let interface = self
            .utun
            .as_ref()
            .map(MacUtun::name)
            .ok_or(io::ErrorKind::NotConnected)?
            .to_owned();
        let new_routes = route_addresses(&config);
        validate_underlay_routes(&config, &new_routes)?;
        let peers = peers_for_config(&config)?;
        let old_config = self.config.clone();
        let old_routes = self.routes.clone();
        configure_interface(&interface, Some(&config))?;
        let device = self.device.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        if let Err(error) = replace_peers(device, peers).await {
            if let Some(old) = old_config.as_ref() {
                let _ = configure_interface(&interface, Some(old));
                let old_peers = peers_for_config(old).unwrap_or_default();
                let _ = replace_peers(device, old_peers).await;
            }
            return Err(error);
        }
        let mut added = BTreeSet::new();
        for address in new_routes.difference(&old_routes) {
            if let Err(error) = route(&interface, *address, "add") {
                let _ = remove_routes(&interface, &added);
                rollback_device(device, &interface, old_config.as_ref()).await;
                return Err(error);
            }
            added.insert(*address);
        }
        let mut removed = BTreeSet::new();
        for address in old_routes.difference(&new_routes) {
            if let Err(error) = route(&interface, *address, "delete") {
                let _ = remove_routes(&interface, &added);
                for restored in &removed {
                    let _ = route(&interface, *restored, "add");
                }
                rollback_device(device, &interface, old_config.as_ref()).await;
                return Err(error);
            }
            removed.insert(*address);
        }
        self.routes.clone_from(&new_routes);
        self.config = Some(config);
        Ok(RuntimeInfo {
            interface,
            port: self.port,
            routes: new_routes,
        })
    }

    async fn counters(&self) -> io::Result<CounterMap> {
        let device = self.device.as_ref().ok_or(io::ErrorKind::NotConnected)?;
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
            let key = crate::policy::model::PublicKey(*peer.peer.public_key.as_bytes());
            counters.insert(
                key,
                Counters {
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

    async fn stop(&mut self) -> io::Result<()> {
        let interface = self
            .utun
            .as_ref()
            .map(MacUtun::name)
            .ok_or(io::ErrorKind::NotConnected)?
            .to_owned();
        remove_routes(&interface, &self.routes)?;
        if let Some(device) = self.device.take() {
            device.stop().await;
        }
        self.utun.take();
        self.routes.clear();
        self.config = None;
        Ok(())
    }
}

async fn replace_peers(device: &GotaDevice, peers: Vec<WireGuardPeer>) -> io::Result<()> {
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

async fn rollback_device(device: &GotaDevice, interface: &str, config: Option<&Config>) {
    if let Some(config) = config {
        let _ = configure_interface(interface, Some(config));
        if let Ok(peers) = peers_for_config(config) {
            let _ = replace_peers(device, peers).await;
        }
    }
}

/// Owns a Mac node's `GotaTun` worker, accepted configuration and durable identity state.
pub struct Node {
    enabled: bool,
    worker: Option<Worker>,
    identity: Option<crate::dataplane::Identity>,
    store: Option<crate::node_state::Store>,
    config: Option<Config>,
    pending: Option<Pending>,
    routes: BTreeSet<IpAddr>,
    interface: Option<String>,
    port: u16,
    path: Option<PathBuf>,
    binding: Option<Enrolment>,
}

impl Default for Node {
    fn default() -> Self {
        Self {
            enabled: true,
            worker: None,
            identity: None,
            store: None,
            config: None,
            pending: None,
            routes: BTreeSet::new(),
            interface: None,
            port: 0,
            path: None,
            binding: None,
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
    let valid = if !rotation.commit_requested {
        current == previous_public && recorded == previous_public && saved_public == previous_public
    } else {
        (current == previous_public
            && recorded == previous_public
            && saved_public == previous_public)
            || (current == candidate_public
                && recorded == previous_public
                && saved_public == previous_public)
            || (current == candidate_public
                && recorded == candidate_public
                && (saved_public == previous_public || saved_public == candidate_public))
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
        // The completion marker selects exactly one key; a saved public snapshot can still carry
        // its predecessor until a new coordinator revision arrives.
        return Ok(private_public == candidate_public && recorded == candidate_public);
    }
    let previous_public = RotationKey::from_private(&rotation.previous)?.1;
    let bound_authorized =
        bound == previous_public || (rotation.commit_requested && bound == candidate_public);
    let key_state_authorized = if !rotation.commit_requested {
        private_public == previous_public && recorded == previous_public
    } else {
        (private_public == previous_public && recorded == previous_public)
            || (private_public == previous_public && recorded == candidate_public)
            || (private_public == candidate_public && recorded == candidate_public)
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
    /// Restore accepted public intent, clean only old utun routes, and resume before coordinator dialing.
    ///
    /// State that another enrolment issued is discarded first (see [`reconcile`]).
    /// # Errors
    /// Refuses unsafe state, an unreadable node key or failed utun/device startup.
    pub fn restore(state_directory: &Path, enrolment: Option<&Enrolment>) -> io::Result<Self> {
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

    #[must_use]
    pub fn active(&self) -> bool {
        self.enabled && self.identity.is_some() && self.worker.is_some()
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
            self.port,
            self.config.clone(),
            desired_routes.clone(),
        )?;
        let info = startup.info().clone();
        self.interface = Some(info.interface.clone());
        self.port = info.port;
        self.routes = desired_routes.clone();
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
            #[cfg(feature = "mesh-dns-spike")]
            dns_names: false,
            key_rotation: true,
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

    /// Return the identity only while this node owns a running GotaTun worker and utun.
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
                previous: [0; 32],
                candidate: rotation.previous,
                commit_requested: true,
                completed: true,
            })?;
        } else {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }

    /// Prepare a local Mac identity without changing the live GotaTun worker (#285, D166).
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
    /// The retained journal makes completion safe to retry and erases the predecessor key.
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
        self.pending = None;
        self.routes.clear();
        self.interface = None;
        self.persist(false, None, BTreeSet::new(), None)
    }

    /// Read current GotaTun peer counters without exposing private key material.
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
        let identity = self.identity.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        if !self.enabled || self.worker.is_none() || chunk.local_key != Some(identity.public_key) {
            self.pending = None;
            return Err(io::ErrorKind::InvalidData.into());
        }
        let result = stage_chunk(&mut self.pending, self.config.as_ref(), identity, chunk);
        let Some(config) = result? else {
            return Ok(false);
        };
        validate_config(&config, identity.public_key)?;
        if self
            .config
            .as_ref()
            .is_some_and(|old| old.node == config.node && old.addresses != config.addresses)
        {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let desired_routes = route_addresses(&config);
        validate_underlay_routes(&config, &desired_routes)?;
        let mut cleanup_routes = self.routes.clone();
        cleanup_routes.extend(desired_routes.iter().copied());
        self.persist(true, Some(&config), cleanup_routes, self.interface.clone())?;
        let info = self
            .worker
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .apply(config.clone())?;
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

#[cfg(test)]
mod tests {
    //! Checks that the Mac adapter maps authenticated peers to `WireGuard` host routes.
    #![allow(clippy::expect_used)]

    use super::{
        BoundUdpFactory, Enrolment, Node, PUBLIC_STATE, SavedState, UdpSocketFactory,
        UdpTransportFactoryParams, parse_utun_payload, peers_for_config, read_public_state,
        reconcile, rotation_crash_checkpoint, route_addresses, stage_chunk, utun_family,
        valid_utun_name, validate_config, validate_underlay_routes, write_public_state,
    };
    use crate::{
        dataplane::{Config, DefaultPolicy, Identity, Peer, PeerPolicy},
        policy::{
            model::{Addresses, NodeId, PublicKey},
            rules::TrafficPolicy,
        },
    };
    use gotatun::udp::UdpTransportFactory;
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        os::unix::{
            fs::{PermissionsExt, symlink},
            process::ExitStatusExt,
        },
        path::PathBuf,
        process::{Command, Stdio},
        sync::{
            Arc, Barrier,
            atomic::{AtomicU64, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    /// A one-peer configuration for the macOS node tests.
    fn config() -> Config {
        Config {
            local_key: Some(PublicKey([1; 32])),
            server: Some(NodeId(1)),
            node: NodeId(2),
            #[cfg(feature = "mesh-dns-spike")]
            name: None,
            #[cfg(feature = "mesh-dns-spike")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            version: 3,
            addresses: Addresses {
                ipv4: Ipv4Addr::new(10, 254, 0, 1),
                ipv6: "fd01::1".parse().expect("local IPv6"),
            },
            default_policy: DefaultPolicy::Allow,
            exposure: None,
            peers: BTreeMap::from([(
                NodeId(4),
                PeerPolicy {
                    peer: Peer {
                        key: PublicKey([2; 32]),
                        previous_key: None,
                        previous_active: false,
                        addresses: Addresses {
                            ipv4: Ipv4Addr::new(10, 254, 0, 4),
                            ipv6: "fd01::4".parse().expect("peer IPv6"),
                        },
                        endpoint: Some("192.0.2.4:51820".parse::<SocketAddr>().expect("endpoint")),
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                    access_ssh: None,
                },
            )]),
            #[cfg(feature = "mesh-dns-spike")]
            peer_names: BTreeMap::new(),
        }
    }

    /// Verifies that a normal active peer gets host routes, an endpoint and a keepalive.
    #[test]
    fn peer_conversion_uses_host_routes_and_keepalive() {
        let config = config();
        let peers = peers_for_config(&config).expect("convert peers");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].public_key.as_bytes(), &[2; 32]);
        assert_eq!(peers[0].endpoint, config.peers[&NodeId(4)].peer.endpoint);
        assert_eq!(peers[0].keepalive, Some(25));
        assert_eq!(
            peers[0]
                .allowed_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.254.0.4/32", "fd01::4/128"]
        );
    }

    /// Install both keys during overlap and leave routes only on the active key.
    #[test]
    fn peer_conversion_keeps_the_inactive_rotation_key_without_routes_or_endpoint() {
        let endpoint: SocketAddr = "192.0.2.4:51820".parse().expect("endpoint");
        let mut config = config();
        let policy = config.peers.get_mut(&NodeId(4)).expect("configured peer");
        policy.peer.previous_key = Some(PublicKey([7; 32]));
        policy.peer.previous_active = true;
        policy.peer.endpoint = Some(endpoint);
        let peers = peers_for_config(&config).expect("convert both rotation keys");

        assert_eq!(peers.len(), 2, "the peer accepts both overlap identities");
        let candidate = peers
            .iter()
            .find(|peer| peer.public_key.as_bytes() == &[2; 32])
            .expect("candidate identity");
        let previous = peers
            .iter()
            .find(|peer| peer.public_key.as_bytes() == &[7; 32])
            .expect("previous identity");
        assert_eq!(candidate.allowed_ips.as_slice(), &[]);
        assert_eq!(candidate.endpoint, None);
        assert!(
            previous
                .allowed_ips
                .iter()
                .any(|ip| ip.to_string() == "10.254.0.4/32")
        );
        assert_eq!(previous.endpoint, Some(endpoint));
    }

    /// A test peer `id` with the given inbound policy.
    fn peer_policy(id: u8, inbound: TrafficPolicy) -> PeerPolicy {
        PeerPolicy {
            peer: Peer {
                key: PublicKey([id; 32]),
                previous_key: None,
                previous_active: false,
                addresses: Addresses {
                    ipv4: Ipv4Addr::new(10, 254, 0, id),
                    ipv6: format!("fd01::{id}").parse().expect("peer IPv6"),
                },
                endpoint: None,
            },
            inbound,
            outbound: TrafficPolicy::All,
            access_ssh: None,
        }
    }

    fn installed_keys(config: &Config) -> BTreeSet<[u8; 32]> {
        peers_for_config(config)
            .expect("convert peers")
            .iter()
            .map(|peer| *peer.public_key.as_bytes())
            .collect()
    }

    /// D164 deny-by-default must hold while the Mac has no packet filter (#265 P1-2).
    #[test]
    fn peers_without_full_inbound_access_are_not_installed() {
        let mut config = config();
        config.peers = BTreeMap::from([
            // The coordinator is reachable by every node, whatever its inbound grant.
            (NodeId(1), peer_policy(11, TrafficPolicy::None)),
            (NodeId(4), peer_policy(4, TrafficPolicy::All)),
            // Only this Mac → 5 is granted; 5 must not reach the Mac.
            (NodeId(5), peer_policy(5, TrafficPolicy::None)),
            // 6 → Mac is narrowed to one port, which this node cannot enforce.
            (
                NodeId(6),
                peer_policy(
                    6,
                    TrafficPolicy::Ports(BTreeSet::from([crate::policy::rules::Port {
                        protocol: crate::policy::rules::Protocol::Tcp,
                        number: 22,
                    }])),
                ),
            ),
        ]);

        assert_eq!(installed_keys(&config), BTreeSet::from([[11; 32], [4; 32]]));
        let routes = route_addresses(&config);
        for absent in [5, 6] {
            assert!(!routes.contains(&IpAddr::V4(Ipv4Addr::new(10, 254, 0, absent))));
        }
        assert!(routes.contains(&IpAddr::V4(Ipv4Addr::new(10, 254, 0, 4))));
        assert_eq!(super::ENFORCEMENT, "unavailable");
    }

    /// Revoking a peer's arrow removes it from the installed peer set.
    #[test]
    fn revoking_an_arrow_removes_the_installed_peer() {
        let old = config();
        let identity = Identity {
            public_key: old.local_key.expect("bound key"),
            port: 51820,
            compact_access: true,
            #[cfg(feature = "mesh-dns-spike")]
            dns_names: false,
            key_rotation: false,
        };
        assert_eq!(installed_keys(&old), BTreeSet::from([[2; 32]]));

        // The coordinator keeps the peer because Mac → 4 is still granted.
        let mut revoked = old.clone();
        revoked.version += 1;
        revoked.peers.get_mut(&NodeId(4)).expect("peer 4").inbound = TrafficPolicy::None;
        let mut pending = None;
        let mut applied = None;
        for chunk in crate::configuration::chunks(Some(&old), &revoked).expect("delta") {
            applied = stage_chunk(&mut pending, Some(&old), &identity, chunk).expect("stage delta");
        }
        let applied = applied.expect("complete revision");

        assert!(applied.peers.contains_key(&NodeId(4)));
        assert!(installed_keys(&applied).is_empty());
        assert!(route_addresses(&applied).is_empty());
    }

    #[test]
    fn accepted_configuration_rejects_duplicate_peer_identity_and_addresses() {
        let mut config = config();
        let peer = config.peers[&NodeId(4)].clone();
        config.peers.insert(NodeId(5), peer);

        assert_eq!(
            validate_config(&config, PublicKey([1; 32]))
                .expect_err("duplicate peer data must be rejected")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    /// A staged configuration is accepted only with its last chunk.
    #[test]
    fn staged_configuration_is_not_accepted_until_its_last_chunk() {
        let config = config();
        let identity = Identity {
            public_key: config.local_key.expect("bound key"),
            port: 51820,
            compact_access: true,
            #[cfg(feature = "mesh-dns-spike")]
            dns_names: false,
            key_rotation: false,
        };
        let mut chunks = crate::configuration::chunks(None, &config).expect("full snapshot");
        assert_eq!(chunks.len(), 1);
        let mut first = chunks.pop().expect("first part");
        first.last = false;
        let mut last = first.clone();
        last.index = 1;
        last.last = true;
        last.upserted.clear();
        last.merged.clear();
        last.removed.clear();
        last.access_updates.clear();
        #[cfg(feature = "mesh-dns-spike")]
        {
            last.peer_names.clear();
            last.removed_peer_names.clear();
        }

        let mut pending = None;
        assert!(
            stage_chunk(&mut pending, None, &identity, first)
                .expect("stage first part")
                .is_none()
        );
        assert_eq!(
            stage_chunk(&mut pending, None, &identity, last).expect("finish snapshot"),
            Some(config)
        );
    }

    #[test]
    fn utun_frame_uses_kernel_family_prefix_and_checks_ip_version() {
        let ipv4 = [0, 0, 0, 2, 0x45];
        let ipv6 = [0, 0, 0, 30, 0x60];

        assert_eq!(utun_family(&ipv4[4..]).expect("IPv4 family"), 2);
        assert_eq!(utun_family(&ipv6[4..]).expect("IPv6 family"), 30);
        assert_eq!(parse_utun_payload(&ipv4).expect("IPv4 payload"), &ipv4[4..]);
        assert_eq!(parse_utun_payload(&ipv6).expect("IPv6 payload"), &ipv6[4..]);
    }

    #[test]
    fn utun_frame_rejects_truncation_unknown_family_and_mismatch() {
        assert!(parse_utun_payload(&[0, 0, 0]).is_err());
        assert!(parse_utun_payload(&[0, 0, 0, 99, 0x45]).is_err());
        assert!(parse_utun_payload(&[0, 0, 0, 2, 0x60]).is_err());
        assert!(utun_family(&[]).is_err());
        assert!(utun_family(&[0x75]).is_err());
        let mut oversized = vec![0, 0, 0, 2];
        oversized.resize(4 + 1281, 0);
        oversized[4] = 0x45;
        assert!(parse_utun_payload(&oversized).is_err());
    }

    #[test]
    fn saved_public_config_restores_without_private_key_material() {
        let directory = test_directory();
        let path = directory.join(PUBLIC_STATE);
        let state = SavedState {
            enabled: true,
            config: Some(config()),
            routes: route_addresses(&config()),
            interface: Some("utun7".to_owned()),
            port: 51831,
            backend: None,
            binding: None,
        };

        write_public_state(&path, &state).expect("persist public config");
        let restored = read_public_state(&path)
            .expect("read public config")
            .expect("saved config");
        assert_eq!(restored.config, state.config);
        assert_eq!(restored.routes, state.routes);
        assert_eq!(restored.interface, state.interface);
        assert_eq!(restored.port, state.port);
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
        let body = fs::read_to_string(path).expect("read public bytes");
        assert!(!body.contains("private_key"));
        assert!(!body.contains("secret"));
    }

    #[test]
    fn absent_state_defaults_to_enabled_without_a_saved_config() {
        let state = SavedState::default();
        assert!(state.enabled);
        assert!(state.config.is_none());
        assert_eq!(state.port, 0);
        assert!(state.interface.is_none());
        assert!(state.routes.is_empty());
    }

    /// Restore the saved node state from its agent state directory.
    #[test]
    fn restore_uses_the_agent_state_directory() {
        let directory = test_directory();
        let state = SavedState {
            enabled: false,
            config: None,
            routes: BTreeSet::new(),
            interface: None,
            port: 0,
            backend: None,
            binding: None,
        };
        write_public_state(&directory.join(PUBLIC_STATE), &state).expect("write public state");

        let restored =
            Node::restore(&directory.0, None).expect("restore from agent state directory");

        assert!(!restored.enabled());
        assert!(directory.join(PUBLIC_STATE).is_file());
    }

    /// A committed Mac journal authorizes only its candidate binding at the same policy revision.
    #[test]
    fn macos_store_accepts_a_journal_proven_same_revision_binding_advance() {
        let directory = test_directory();
        let previous = [0x11; 32];
        let candidate = [0x22; 32];
        let previous_secret = gotatun::x25519::StaticSecret::from(previous);
        let candidate_secret = gotatun::x25519::StaticSecret::from(candidate);
        let previous_public =
            PublicKey(*gotatun::x25519::PublicKey::from(&previous_secret).as_bytes());
        let candidate_public =
            PublicKey(*gotatun::x25519::PublicKey::from(&candidate_secret).as_bytes());
        let mut accepted = config();
        accepted.local_key = Some(previous_public);
        accepted.version = 7;
        let mut state = crate::node_state::State {
            enabled: true,
            config: Some(accepted),
        };
        let (store, _) = crate::node_state::Store::open(&directory.0).expect("open node state");
        store
            .save(&state)
            .expect("save accepted predecessor binding");
        store
            .save_rotation_secret(&crate::node_state::RotationSecret {
                operation_id: "00000000-0000-4000-8000-000000000367".to_owned(),
                sequence: 1,
                previous,
                candidate,
                commit_requested: true,
                completed: false,
            })
            .expect("save commit intent");
        store
            .record_interface(&candidate_public)
            .expect("record candidate interface identity");
        store
            .write_private_key(&candidate)
            .expect("save candidate private key");
        state.config.as_mut().expect("accepted config").local_key = Some(candidate_public);

        store
            .save(&state)
            .expect("advance only the journal-proven binding");
        let (_, restored) =
            crate::node_state::Store::open(&directory.0).expect("restore candidate binding");
        assert_eq!(
            restored.config.and_then(|config| config.local_key),
            Some(candidate_public)
        );
    }

    /// The macOS GotaTun node advertises and completes the durable key-rotation protocol.
    #[test]
    #[ignore = "Run on the macOS VM with system service privileges."]
    fn macos_gotatun_node_supports_key_rotation() {
        let directory = test_directory();
        let mut node = Node::restore(&directory.0, None).expect("restore Mac node");
        let previous = node.up().expect("start GotaTun");
        assert!(previous.key_rotation, "macOS offers durable rotation");

        let operation = "00000000-0000-4000-8000-000000000051";
        let candidate = node
            .prepare_rotation(operation, 1)
            .expect("prepare rotation");
        assert_ne!(candidate, previous.public_key);
        assert_eq!(
            node.prepare_rotation(operation, 1)
                .expect("retry prepare rotation"),
            candidate,
            "a retry returns the journaled candidate"
        );
        assert_eq!(
            node.finish_rotation(operation, 1)
                .expect_err("an uncommitted candidate cannot finish")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(
            node.commit_rotation(operation, 2)
                .expect_err("a stale sequence cannot commit")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        let committed = node.commit_rotation(operation, 1).expect("commit rotation");
        assert_eq!(committed.public_key, candidate);
        assert_eq!(
            node.commit_rotation(operation, 1)
                .expect("retry commit rotation")
                .public_key,
            candidate,
            "a retry leaves the committed identity stable"
        );
        let (_, persisted) = crate::macos_key::load_or_create(&directory.0).expect("read key file");
        assert_eq!(persisted, candidate);
        node.finish_rotation(operation, 1).expect("finish rotation");
        node.finish_rotation(operation, 1)
            .expect("retry finish rotation");
        node.down().expect("stop GotaTun");
    }

    /// Preparing the same Mac rotation twice returns its original journaled candidate.
    #[test]
    #[ignore = "Run on the macOS VM with system service privileges."]
    fn macos_gotatun_rotation_prepare_is_retryable() {
        let directory = test_directory();
        let mut node = Node::restore(&directory.0, None).expect("restore Mac node");
        node.up().expect("start GotaTun");

        let operation = "00000000-0000-4000-8000-000000000052";
        let first = node.prepare_rotation(operation, 1);
        let second = first
            .as_ref()
            .ok()
            .map(|_| node.prepare_rotation(operation, 1));
        node.down().expect("stop GotaTun");

        let candidate = first.expect("prepare rotation");
        assert_eq!(
            second
                .expect("retry was attempted")
                .expect("retry prepare rotation"),
            candidate
        );
    }

    /// Exercise the child side of [`macos_rotation_recovers_after_sigkill_at_each_durable_step`].
    #[test]
    #[ignore = "launched by the macOS GotaTun SIGKILL recovery proof"]
    fn macos_rotation_crash_child() {
        let state = std::env::var_os("INFRATERNAL_MAC_ROTATION_STATE")
            .expect("the parent supplies an isolated Mac state directory");
        let state = PathBuf::from(state);
        let mut node = Node::restore(&state, None).expect("restore Mac rotation child");
        let previous = node.up().expect("start the Mac GotaTun node");
        assert!(previous.key_rotation, "macOS offers durable rotation");
        fs::write(
            state.join("rotation-crash-previous-public"),
            previous.public_key.0,
        )
        .expect("save the public predecessor for the parent proof");
        let operation = "00000000-0000-4000-8000-000000000367";
        node.prepare_rotation(operation, 1)
            .expect("prepare Mac key rotation");
        rotation_crash_checkpoint("rotation_prepared");
        node.commit_rotation(operation, 1)
            .expect("commit Mac key rotation");
        node.finish_rotation(operation, 1)
            .expect("finish Mac key rotation");
        rotation_crash_checkpoint("rotation_finished");
        panic!("the requested Mac crash boundary was never reached");
    }

    /// SIGKILL at every Mac rotation write leaves a journal that restarts on an authorized key.
    #[test]
    #[ignore = "Run on the macOS VM with system service privileges."]
    fn macos_rotation_recovers_after_sigkill_at_each_durable_step() {
        let stages = [
            "rotation_prepared",
            "rotation_commit_requested",
            "rotation_device_key_changed",
            "rotation_interface_recorded",
            "rotation_private_key_saved",
            "rotation_finished",
        ];
        for stage in stages {
            let directory = test_directory();
            let ready = directory.join("rotation-crash-ready");
            let mut child = Command::new(std::env::current_exe().expect("test binary"))
                .args(["--ignored", "macos_rotation_crash_child", "--nocapture"])
                .env("INFRATERNAL_MAC_ROTATION_STATE", &directory.0)
                .env("INFRATERNAL_MAC_ROTATION_CRASH_POINT", stage)
                .env("INFRATERNAL_MAC_ROTATION_CRASH_READY", &ready)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start the Mac rotation child");
            let deadline = Instant::now() + Duration::from_secs(20);
            while !ready.exists() {
                if let Some(status) = child.try_wait().expect("check the Mac rotation child") {
                    let output = child
                        .wait_with_output()
                        .expect("collect the Mac child's failure");
                    panic!(
                        "Mac child exited before {stage}: {status}\n{}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                assert!(Instant::now() < deadline, "Mac child did not reach {stage}");
                // sleep: let the child publish its next durable rotation boundary.
                thread::sleep(Duration::from_millis(10));
            }
            child.kill().expect("send SIGKILL at the Mac boundary");
            let status = child.wait().expect("reap the killed Mac child");
            assert_eq!(status.signal(), Some(nix::libc::SIGKILL), "stage {stage}");

            let previous: [u8; 32] = fs::read(directory.join("rotation-crash-previous-public"))
                .expect("child recorded the predecessor")
                .try_into()
                .expect("public key length");
            let journal = zeroize::Zeroizing::new(
                fs::read(directory.join("mesh-key-rotation.bin"))
                    .expect("prepared Mac journal survives SIGKILL"),
            );
            assert_eq!(journal.len(), 117, "stage {stage}");
            assert_eq!(&journal[..8], b"IMKEYV1\0", "stage {stage}");
            assert_eq!(
                u64::from_le_bytes(journal[9..17].try_into().expect("sequence bytes")),
                1,
                "stage {stage}"
            );
            assert_eq!(
                &journal[17..53],
                b"00000000-0000-4000-8000-000000000367",
                "stage {stage}"
            );
            let completed = stage == "rotation_finished";
            assert_eq!(
                journal[8],
                if completed {
                    2
                } else if stage == "rotation_prepared" {
                    0
                } else {
                    1
                }
            );
            if completed {
                assert_eq!(&journal[53..85], &[0; 32], "finish erases the predecessor");
            }
            let previous_public = if completed {
                PublicKey(previous)
            } else {
                mac_private_public(&journal[53..85])
            };
            let candidate_public = mac_private_public(&journal[85..117]);
            assert_eq!(previous_public.0, previous, "stage {stage}");

            let key_file = zeroize::Zeroizing::new(
                fs::read(directory.join(crate::macos_key::KEY_FILE))
                    .expect("Mac key file survives SIGKILL"),
            );
            let expected_file =
                if matches!(stage, "rotation_private_key_saved" | "rotation_finished") {
                    candidate_public
                } else {
                    previous_public
                };
            assert_eq!(
                mac_private_public(&key_file),
                expected_file,
                "key file at {stage}"
            );
            let recorded: PublicKey = serde_json::from_slice(
                &fs::read(directory.join("mesh-interface.json")).expect("recorded Mac identity"),
            )
            .expect("valid recorded Mac identity");
            let expected_record = if matches!(
                stage,
                "rotation_interface_recorded" | "rotation_private_key_saved" | "rotation_finished"
            ) {
                candidate_public
            } else {
                previous_public
            };
            assert_eq!(recorded, expected_record, "interface record at {stage}");

            let expected_live = if stage == "rotation_prepared" {
                previous_public
            } else {
                candidate_public
            };
            let mut restored =
                Node::restore(&directory.0, None).expect("restore after Mac SIGKILL");
            let identity = restored.up().expect("restart the Mac GotaTun node");
            assert!(
                identity.key_rotation,
                "Mac rotation support survives restart"
            );
            assert_eq!(
                identity.public_key, expected_live,
                "recovered key at {stage}"
            );
            restored
                .commit_rotation("00000000-0000-4000-8000-000000000367", 1)
                .expect("retry Mac commit after restart");
            restored
                .finish_rotation("00000000-0000-4000-8000-000000000367", 1)
                .expect("retry Mac finish after restart");
            restored.down().expect("stop restored Mac node");
        }
    }

    /// Derive a public identity from a private crash-fixture key without formatting its bytes.
    fn mac_private_public(bytes: &[u8]) -> PublicKey {
        let raw: [u8; 32] = bytes.try_into().expect("32-byte private key");
        let secret = gotatun::x25519::StaticSecret::from(raw);
        PublicKey(*gotatun::x25519::PublicKey::from(&secret).as_bytes())
    }

    fn enrolment(coordinator: &[u8]) -> Enrolment {
        Enrolment::new(coordinator, "8c1f0d2e-host", b"agent public key")
    }

    fn bound_state(binding: Option<Enrolment>) -> SavedState {
        SavedState {
            enabled: false,
            config: Some(config()),
            routes: route_addresses(&config()),
            interface: Some("utun7".to_owned()),
            port: 51831,
            backend: None,
            binding,
        }
    }

    fn write_key(directory: &TestDirectory) {
        let path = directory.join(crate::macos_key::KEY_FILE);
        fs::write(&path, [9_u8; 32]).expect("write key");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("key mode");
    }

    /// #265 P2-1 / #325: another coordinator's peers must never be restored.
    #[test]
    fn state_from_another_enrolment_is_discarded_and_the_key_rotates() {
        let old = enrolment(b"coordinator A");
        let new = enrolment(b"coordinator B");
        let (state, rotate) = reconcile(bound_state(Some(old.clone())), Some(&new));
        assert!(rotate);
        assert!(state.config.is_none());
        assert!(state.routes.is_empty());
        assert!(state.interface.is_none());
        assert_eq!(state.binding, Some(new.clone()));

        for changed in [
            Enrolment::new(b"coordinator A", "another-host", b"agent public key"),
            Enrolment::new(b"coordinator A", "8c1f0d2e-host", b"new agent key"),
        ] {
            assert!(reconcile(bound_state(Some(old.clone())), Some(&changed)).1);
        }

        let (same, rotate) = reconcile(bound_state(Some(old.clone())), Some(&old));
        assert!(!rotate);
        assert_eq!(same.config, Some(config()));
    }

    /// J162 F3: unbound (slice-1) state may hold another coordinator's peers.
    #[test]
    fn unbound_state_is_discarded_like_another_enrolment() {
        let current = enrolment(b"coordinator B");
        let (state, rotate) = reconcile(bound_state(None), Some(&current));
        assert!(rotate);
        assert!(state.config.is_none());
        assert!(state.routes.is_empty());
        assert!(state.interface.is_none());
        assert_eq!(state.binding, Some(current));
        // Without identity.json there is nothing to compare against.
        let (state, rotate) = reconcile(bound_state(None), None);
        assert!(!rotate);
        assert!(state.binding.is_none());
    }

    fn rotation_reasons(directory: &TestDirectory) -> Vec<String> {
        fs::read_to_string(directory.join(crate::macos_key::ROTATION_LOG))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| {
                line.split(' ')
                    .find_map(|field| field.strip_prefix("reason="))
            })
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn restoring_unbound_state_removes_the_key_and_logs_why() {
        let directory = test_directory();
        let current = enrolment(b"coordinator B");
        write_public_state(&directory.join(PUBLIC_STATE), &bound_state(None))
            .expect("write slice-1 state");
        write_key(&directory);

        Node::restore(&directory.0, Some(&current)).expect("restore unbound state");
        assert!(!directory.join(crate::macos_key::KEY_FILE).exists());
        assert_eq!(rotation_reasons(&directory), ["enrolment_changed"]);
        let persisted = read_public_state(&directory.join(PUBLIC_STATE))
            .expect("read state")
            .expect("state persisted");
        assert!(persisted.config.is_none());
        assert_eq!(persisted.binding, Some(current.clone()));

        // Once bound, a restart keeps everything and logs nothing more.
        write_key(&directory);
        Node::restore(&directory.0, Some(&current)).expect("restore bound state");
        assert!(directory.join(crate::macos_key::KEY_FILE).is_file());
        assert_eq!(rotation_reasons(&directory), ["enrolment_changed"]);
    }

    #[test]
    fn restore_under_a_new_enrolment_removes_the_old_key_and_records_the_binding() {
        let directory = test_directory();
        let old = enrolment(b"coordinator A");
        let new = enrolment(b"coordinator B");
        write_public_state(
            &directory.join(PUBLIC_STATE),
            &bound_state(Some(old.clone())),
        )
        .expect("write old state");
        write_key(&directory);

        Node::restore(&directory.0, Some(&old)).expect("restore same enrolment");
        assert!(directory.join(crate::macos_key::KEY_FILE).is_file());

        Node::restore(&directory.0, Some(&new)).expect("restore new enrolment");
        assert!(!directory.join(crate::macos_key::KEY_FILE).exists());
        assert_eq!(rotation_reasons(&directory), ["enrolment_changed"]);
        let persisted = read_public_state(&directory.join(PUBLIC_STATE))
            .expect("read state")
            .expect("state persisted");
        assert_eq!(persisted.binding, Some(new));
        assert!(persisted.config.is_none());
    }

    #[test]
    fn forgetting_removes_the_public_state_and_the_key() {
        let directory = test_directory();
        write_public_state(&directory.join(PUBLIC_STATE), &bound_state(None)).expect("state");
        write_key(&directory);
        super::forget(&directory.0).expect("forget");
        assert!(!directory.join(PUBLIC_STATE).exists());
        assert!(!directory.join(crate::macos_key::KEY_FILE).exists());
        // J162 F4: the coordinator must learn the new key, so the rotation is logged once.
        assert_eq!(rotation_reasons(&directory), ["enrolment_changed"]);
        super::forget(&directory.0).expect("forgetting twice succeeds");
        super::forget(&directory.join("absent")).expect("an absent directory is fine");
    }

    #[test]
    fn public_config_reader_refuses_a_symlink() {
        let directory = test_directory();
        let target = directory.join("target");
        fs::write(&target, b"{}").expect("target");
        let path = directory.join(PUBLIC_STATE);
        symlink(&target, &path).expect("state symlink");

        assert!(read_public_state(&path).is_err());
    }

    #[test]
    fn route_inventory_contains_only_peer_host_addresses() {
        let routes = route_addresses(&config());
        assert_eq!(
            routes,
            [
                IpAddr::V4(Ipv4Addr::new(10, 254, 0, 4)),
                IpAddr::V6("fd01::4".parse().expect("peer IPv6")),
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn stale_route_cleanup_accepts_only_kernel_assigned_utun_names() {
        assert!(valid_utun_name("utun0"));
        assert!(valid_utun_name("utun42"));
        assert!(!valid_utun_name("utun"));
        assert!(!valid_utun_name("utun1;rm"));
        assert!(!valid_utun_name("en0"));
    }

    #[test]
    fn restore_does_not_delete_routes_using_a_released_utun_name() {
        let directory = test_directory();
        let state = SavedState {
            enabled: false,
            config: None,
            routes: ["192.0.2.1".parse().expect("stale route")].into(),
            interface: Some("utun99999".to_owned()),
            port: 0,
            backend: None,
            binding: None,
        };
        write_public_state(&directory.join(PUBLIC_STATE), &state).expect("save old intent");

        let restored = Node::restore(&directory.0, None).expect("restore after utun release");

        assert!(!restored.enabled());
        let persisted = read_public_state(&directory.join(PUBLIC_STATE))
            .expect("read state")
            .expect("persist disabled state");
        assert!(persisted.routes.is_empty());
        assert!(persisted.interface.is_none());
    }

    #[test]
    fn wireguard_underlay_endpoints_never_recurse_through_mesh_host_routes() {
        let mut config = config();
        let routes = route_addresses(&config);
        assert!(validate_underlay_routes(&config, &routes).is_ok());
        config
            .peers
            .get_mut(&NodeId(4))
            .expect("server peer")
            .peer
            .endpoint = Some("10.254.0.4:51820".parse().expect("mesh endpoint"));
        assert!(validate_underlay_routes(&config, &routes).is_err());
    }

    #[tokio::test]
    async fn prebound_wireguard_socket_keeps_the_advertised_port_on_reconfiguration() {
        let mut factory = UdpSocketFactory::default();
        let params = UdpTransportFactoryParams {
            addr: None,
            port: 0,
        };
        let (send, receive) = factory.bind(&params).await.expect("prebind UDP");
        let port = send.local_addr().expect("UDP address").port();
        let mut bound = BoundUdpFactory {
            send,
            receive,
            port,
        };
        let (reused_send, reused_receive) = bound
            .bind(&UdpTransportFactoryParams { addr: None, port })
            .await
            .expect("reuse the prebound UDP socket");
        assert_eq!(reused_send.local_addr().expect("send address").port(), port);
        assert_eq!(
            reused_receive.local_addr().expect("receive address").port(),
            port
        );
    }

    struct TestDirectory(PathBuf);
    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    impl TestDirectory {
        fn join(&self, path: &str) -> PathBuf {
            self.0.join(path)
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_directory() -> TestDirectory {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "infraternal-mac-mesh-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            sequence
        ));
        fs::create_dir(&path).expect("test directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("test mode");
        TestDirectory(path)
    }

    #[test]
    fn parallel_test_directories_have_unique_paths() {
        let barrier = Arc::new(Barrier::new(32));
        let workers = (0..32)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    test_directory()
                })
            })
            .collect::<Vec<_>>();
        let directories = workers
            .into_iter()
            .map(|worker| worker.join().expect("create fixture without collision"))
            .collect::<Vec<_>>();
        let paths = directories
            .iter()
            .map(|directory| directory.0.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(paths.len(), directories.len());
    }
}
