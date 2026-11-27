//! Drives Linux kernel `WireGuard` through checked generic and route netlink [163,165,169], #129.
use crate::{
    mesh_mtu,
    netlink::{self, NESTED, Socket, attribute},
    policy::model::{Addresses, PublicKey},
};
use nix::{
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::socket::{
        AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, socket,
    },
};
use openssl::pkey::PKey;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// Kernel-side suppression of route additions sent by this node.
#[path = "wireguard_route_filter.rs"]
mod route_filter;
use route_filter::RouteQueue;

/// A node-local ephemeral secret. It cannot be serialized, cloned or debug printed.
pub struct Key(Zeroizing<Vec<u8>>);
impl Key {
    /// Generate locally using the existing cryptographic provider; only the public part is returned.
    /// # Errors
    /// Returns fixed-text errors, never provider diagnostics containing private data.
    pub fn generate() -> io::Result<(Self, PublicKey)> {
        // X25519 generation does not initialize OpenSSL itself; without this a first key made
        // here registers OpenSSL's exit-time cleanup, which can free its tables under a thread
        // still using them while the process exits (#578).
        openssl::init();
        let key = PKey::generate_x25519().map_err(|_| io::ErrorKind::Other)?;
        let private = Zeroizing::new(key.raw_private_key().map_err(|_| io::ErrorKind::Other)?);
        let public: [u8; 32] = key
            .raw_public_key()
            .map_err(|_| io::ErrorKind::Other)?
            .try_into()
            .map_err(|_| io::ErrorKind::Other)?;
        Ok((Self(private), PublicKey(public)))
    }

    /// Rebuild an ephemeral wrapper from a local root-only state record.
    /// The private bytes are copied into zeroizing memory and never formatted.
    /// # Errors
    /// Refuses a non-X25519 or malformed private key.
    pub(crate) fn from_private(bytes: &[u8]) -> io::Result<(Self, PublicKey)> {
        if bytes.len() != 32 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // Initialize before the first OpenSSL call, as in `generate` (#578).
        openssl::init();
        let key = PKey::private_key_from_raw_bytes(bytes, openssl::pkey::Id::X25519)
            .map_err(|_| io::ErrorKind::InvalidData)?;
        let public: [u8; 32] = key
            .raw_public_key()
            .map_err(|_| io::ErrorKind::InvalidData)?
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?;
        Ok((Self(Zeroizing::new(bytes.to_vec())), PublicKey(public)))
    }

    /// Reconstruct the node-local key from the checked private state file.
    /// # Errors
    /// Refuses every key size other than the X25519 private-key size.
    pub(crate) fn from_private_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != 32 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    /// Borrow the key only long enough to place it in the protected node state file.
    #[must_use]
    pub(crate) fn private_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Copy the zeroized key buffer into `GotaTun`'s zeroizing secret type.
    /// # Errors
    /// Refuses a malformed OpenSSL key length.
    pub(crate) fn gotatun_secret(&self) -> io::Result<gotatun::x25519::StaticSecret> {
        let bytes: [u8; 32] = self
            .0
            .as_slice()
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?;
        let bytes = Zeroizing::new(bytes);
        Ok(gotatun::x25519::StaticSecret::from(*bytes))
    }
}
pub use crate::dataplane::Peer;
/// Public counters read from the kernel peer table.
pub use infraternal_mesh_node::peer_stats::Counters;
/// Interface name is fixed: ownership never includes an operator's other interfaces.
pub const INTERFACE: &str = "infraternal0";
/// The unbound kernel marker that links created before D340 carry.
const KERNEL_ALIAS: &[u8] = b"infraternal.mesh.v1\0";
/// The kernel marker since D340: it names the creating node's public key, so even a link that has
/// no key yet says whose it is.
const KERNEL_OWNER_PREFIX: &[u8] = b"infraternal.mesh.v2:";
const GOTATUN_ALIAS: &[u8] = b"infraternal.mesh.gotatun.v1\0";
const GOTATUN_OWNER_PREFIX: &[u8] = b"infraternal.mesh.gotatun.v2:";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// One marked mesh link observed in a single route-netlink reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ActiveLink {
    pub(crate) engine: crate::gotatun_node::EngineKind,
    pub(crate) ifindex: u32,
    /// The public key the link's marker names; `None` for the legacy unbound kernel and
    /// `GotaTun` markers.
    pub(crate) owner: Option<PublicKey>,
    /// The TUN's owner uid, which alone may attach it (#260 J213 P1); `None` when unset, and
    /// always `None` for kernel links.
    pub(crate) tun_owner: Option<u32>,
    /// The TUN's group, read the same way as [`ActiveLink::tun_owner`].
    pub(crate) tun_group: Option<u32>,
}

/// Put only the public node identity in the marker because the link name is shared across installs.
fn owner_alias(prefix: &[u8], owner: PublicKey) -> Vec<u8> {
    let mut alias = Vec::with_capacity(prefix.len() + owner.0.len() * 2 + 1);
    alias.extend_from_slice(prefix);
    for byte in owner.0 {
        alias.push(HEX[usize::from(byte >> 4)]);
        alias.push(HEX[usize::from(byte & 0x0f)]);
    }
    alias.push(0);
    alias
}

fn parse_owner(prefix: &[u8], alias: &[u8]) -> Option<PublicKey> {
    let encoded = alias.strip_prefix(prefix)?;
    if encoded.len() != 65 || encoded[64] != 0 {
        return None;
    }
    let mut owner = [0; 32];
    for (index, pair) in encoded[..64].as_chunks::<2>().0.iter().enumerate() {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        owner[index] = (high << 4) | low;
    }
    Some(PublicKey(owner))
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

/// The hook type of [`AFTER_LINK_CREATED`]: it receives the new link's temporary name.
#[cfg(feature = "test-support")]
pub type LinkCreatedHook = Box<dyn FnOnce(&str) + Send>;

/// Test seam (#260 J213 P2, J220 P2): runs once in [`Device::create`], right after the new link
/// exists under its temporary name and before anything else addresses it, so a namespace test
/// can race another creator into every later step.
#[cfg(feature = "test-support")]
pub static AFTER_LINK_CREATED: std::sync::Mutex<Option<LinkCreatedHook>> =
    std::sync::Mutex::new(None);

/// A link name no other caller uses: `infr` and 10 hex digits from the process id, a per-process
/// counter and the clock, under the 15-byte limit. A collision only fails one creation (`EEXIST`).
fn temporary_name() -> Vec<u8> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    let mixed = (u64::from(std::process::id()) << 20)
        ^ (u64::from(NEXT.fetch_add(1, Ordering::Relaxed)) << 8)
        ^ u64::from(nanos);
    let mut name = format!("infr{:010x}", mixed & 0xff_ffff_ffff).into_bytes();
    name.push(0);
    name
}

/// An interface index for a new link, chosen by us so that a successful creation proves which
/// link is ours without a second lookup (#260 J220 P2). It comes from the same mix as
/// [`temporary_name`], kept within `1 << 20 ..= i32::MAX`, well above the kernel's own counter.
/// A taken index only fails one attempt (`EEXIST`), and creation retries.
fn chosen_index() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.subsec_nanos());
    let mixed = std::process::id().rotate_left(13).wrapping_mul(0x9e37_79b9)
        ^ NEXT.fetch_add(0x6d2b_79f5, Ordering::Relaxed)
        ^ nanos;
    (1 << 20) + mixed % (0x7fff_ffff - (1 << 20))
}

/// Route operations use short-lived sockets; the node's optional route repair worker listens for
/// deletion notifications while the mesh is up.
pub struct Device;
impl Device {
    /// Create our interface, marked with `owner`, the public key the caller will configure, and
    /// return its index. An existing interface under the shared name is refused, never taken over.
    ///
    /// The link is created under a temporary name with an interface index we chose, so the
    /// creation itself proves which link is ours. Every later step addresses that index, never a
    /// name: the claim renames it to the shared name and sets the owner marker in one request,
    /// and a failed claim deletes only that index. A link another process puts under either name
    /// in between is never claimed or deleted (#260 J213 P2, J220 P2, D340).
    /// # Errors
    /// Returns kernel errors including insufficient privileges and a taken name (`AlreadyExists`).
    pub fn create(owner: PublicKey) -> io::Result<u32> {
        let mut socket = Socket::open(SockProtocol::NetlinkRoute)?;
        let (temporary, ifindex) = Self::create_with_chosen_index(&mut socket)?;
        #[cfg(feature = "test-support")]
        if let Some(hook) = AFTER_LINK_CREATED
            .lock()
            .ok()
            .and_then(|mut hook| hook.take())
        {
            hook(std::str::from_utf8(&temporary[..temporary.len() - 1]).unwrap_or_default());
        }
        #[cfg(not(feature = "test-support"))]
        let _ = temporary;
        // Creation does not run the generic alias setter, so the marker is set here, with the
        // name, before a later process may adopt the link; never leave an unmarked success. The
        // owner key lets a restart prove the link is ours before its key is set (D340).
        let mut claim = vec![0; 16];
        claim[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        attribute(&mut claim, 3, b"infraternal0\0")?;
        attribute(&mut claim, 20, &owner_alias(KERNEL_OWNER_PREFIX, owner))?;
        if let Err(error) = socket.request(16, 4, &claim) {
            Self::delete_ifindex(ifindex)?;
            return Err(if error.raw_os_error() == Some(17) {
                io::ErrorKind::AlreadyExists.into()
            } else {
                error
            });
        }
        Ok(ifindex)
    }
    /// Move this link's owner marker after either engine accepts a rotation key. The old marker is
    /// re-verified on the link at `ifindex` first, and the change is addressed by that index alone,
    /// so a link substituted under the shared name is never re-marked. The new marker is verified
    /// before this returns.
    /// # Errors
    /// Refuses a link whose marker does not name `from`, and reports kernel errors.
    pub(crate) fn remark(ifindex: u32, from: PublicKey, to: PublicKey) -> io::Result<()> {
        let engine = Self::active_link()?
            .filter(|link| link.ifindex == ifindex)
            .map(|link| link.engine)
            .ok_or(io::ErrorKind::InvalidData)?;
        verify_engine_owner(ifindex, engine, from)?;
        let prefix = match engine {
            crate::gotatun_node::EngineKind::Kernel => KERNEL_OWNER_PREFIX,
            crate::gotatun_node::EngineKind::GotaTun => GOTATUN_OWNER_PREFIX,
        };
        let mut claim = vec![0; 16];
        claim[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        attribute(&mut claim, 20, &owner_alias(prefix, to))?;
        Socket::open(SockProtocol::NetlinkRoute)?.request(16, 4, &claim)?;
        verify_engine_owner(ifindex, engine, to)
    }
    /// Create a `WireGuard` link under a fresh temporary name with an index we chose, retrying a
    /// few times when that name or index is already taken. Returns the name and the index.
    fn create_with_chosen_index(socket: &mut Socket) -> io::Result<(Vec<u8>, u32)> {
        let mut last = io::Error::from(io::ErrorKind::AlreadyExists);
        for _ in 0..8 {
            let temporary = temporary_name();
            let ifindex = chosen_index();
            let mut payload = vec![0; 16];
            payload[4..8].copy_from_slice(&ifindex.to_ne_bytes());
            attribute(&mut payload, 3, &temporary)?;
            let mut linkinfo = Vec::new();
            attribute(&mut linkinfo, 1, b"wireguard\0")?;
            attribute(&mut payload, 0x12 | NESTED, &linkinfo)?;
            match socket.request(16, 4 | 0x200 | 0x400, &payload) {
                Ok(_) => return Ok((temporary, ifindex)),
                // EEXIST: the index or the temporary name is taken. EBUSY: a late recheck in
                // device registration found the index taken.
                Err(error) if matches!(error.raw_os_error(), Some(16 | 17)) => last = error,
                Err(error) => return Err(error),
            }
        }
        Err(last)
    }
    /// Verify the ownership marker before adopting kernel state after a process restart.
    /// # Errors
    /// Reports route-netlink errors or an unrelated interface with the same name.
    pub fn owned() -> io::Result<bool> {
        Ok(Self::active_engine()?.is_some())
    }
    /// Mark a fresh TUN as this component's userspace data plane.
    /// # Errors
    /// Refuses a non-TUN interface or any route-netlink failure.
    pub fn mark_tun(owner: PublicKey) -> io::Result<()> {
        let mut payload = vec![0; 16];
        attribute(&mut payload, 3, b"infraternal0\0")?;
        attribute(&mut payload, 20, &owner_alias(GOTATUN_OWNER_PREFIX, owner))?;
        Socket::open(SockProtocol::NetlinkRoute)?.request(16, 4, &payload)?;
        Ok(())
    }
    /// Verify the TUN marker and link kind before adopting or retiring the engine.
    /// # Errors
    /// Reports an unrelated interface with the shared name or malformed link metadata.
    pub fn owned_tun() -> io::Result<bool> {
        Ok(Self::active_link()?
            .is_some_and(|link| link.engine == crate::gotatun_node::EngineKind::GotaTun))
    }
    /// Read which owned data-plane link currently holds the shared mesh interface name.
    /// # Errors
    /// Refuses unmarked or unrelated interfaces rather than treating their name as ownership.
    pub(crate) fn active_engine() -> io::Result<Option<crate::gotatun_node::EngineKind>> {
        Ok(Self::active_link()?.map(|link| link.engine))
    }
    /// Read the link kind, interface index and `GotaTun` owner from one kernel snapshot.
    /// # Errors
    /// Treats a missing name as no link and refuses malformed or unrelated link metadata.
    pub(crate) fn active_link() -> io::Result<Option<ActiveLink>> {
        let mut payload = vec![0; 16];
        attribute(&mut payload, 3, b"infraternal0\0")?;
        let replies = match Socket::open(SockProtocol::NetlinkRoute)?.request(18, 4, &payload) {
            Ok(replies) => replies,
            Err(error) if matches!(error.raw_os_error(), Some(2 | 19)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some(reply) = replies.into_iter().next() else {
            return Ok(None);
        };
        let ifindex = netlink::u32_at(&reply, 4)?;
        let mut alias = None;
        let mut kind = None;
        let (mut tun_owner, mut tun_group) = (None, None);
        for field in netlink::attributes(reply.get(16..).ok_or(io::ErrorKind::InvalidData)?)? {
            match field.kind {
                20 => alias = Some(field.payload),
                18 => {
                    for info in netlink::attributes(field.payload)? {
                        match info.kind {
                            1 => kind = Some(info.payload),
                            // IFLA_INFO_DATA: a TUN reports IFLA_TUN_OWNER (1) and
                            // IFLA_TUN_GROUP (2) only when they are set.
                            2 => {
                                for data in netlink::attributes(info.payload)? {
                                    match data.kind {
                                        1 => tun_owner = Some(netlink::u32_at(data.payload, 0)?),
                                        2 => tun_group = Some(netlink::u32_at(data.payload, 0)?),
                                        _ => {}
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        // A marker names the engine; only an owner-bound one names the installation.
        let engine = match kind {
            Some(b"wireguard\0") => Some((
                crate::gotatun_node::EngineKind::Kernel,
                KERNEL_ALIAS,
                KERNEL_OWNER_PREFIX,
            )),
            Some(b"tun\0") => Some((
                crate::gotatun_node::EngineKind::GotaTun,
                GOTATUN_ALIAS,
                GOTATUN_OWNER_PREFIX,
            )),
            _ => None,
        };
        if let (Some((engine, unbound, prefix)), Some(alias)) = (engine, alias) {
            let owner = parse_owner(prefix, alias);
            if alias == unbound || owner.is_some() {
                return Ok(Some(ActiveLink {
                    engine,
                    ifindex,
                    owner,
                    tun_owner,
                    tun_group,
                }));
            }
        }
        Err(io::ErrorKind::AlreadyExists.into())
    }
    /// Delete the exact link observed by index, treating an already-removed link as complete.
    /// # Errors
    /// Reports route-netlink errors other than a missing link.
    pub(crate) fn delete_ifindex(ifindex: u32) -> io::Result<()> {
        let mut payload = vec![0; 16];
        payload[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        match Socket::open(SockProtocol::NetlinkRoute)?.request(17, 4, &payload) {
            Ok(_) => Ok(()),
            Err(error) if matches!(error.raw_os_error(), Some(2 | 19)) => Ok(()),
            Err(error) => Err(error),
        }
    }
    /// Remove the owned interface, including all its addresses/routes and kernel secrets.
    /// # Errors
    /// Returns kernel deletion errors.
    pub fn delete() -> io::Result<()> {
        let mut payload = vec![0; 16];
        attribute(&mut payload, 3, b"infraternal0\0")?;
        Socket::open(SockProtocol::NetlinkRoute)?.request(17, 4, &payload)?;
        Ok(())
    }
    /// Install the local key and listen port on the link at `ifindex`, which this node created
    /// for `owner`. The secret lives only in zeroized netlink buffers.
    ///
    /// The device is addressed by index, never by the shared name, and the link at that index
    /// must still carry `owner`'s marker right before the key is sent, so a link put under the
    /// shared name after our claim never receives the key (#260 J220 P2).
    /// # Errors
    /// Returns a kernel configuration error without key material, or `InvalidData` when the
    /// link at `ifindex` is not this owner's.
    pub fn configure(ifindex: u32, owner: PublicKey, key: &Key, port: u16) -> io::Result<()> {
        // Reserve the coexistence port before entering the kernel, including
        // for explicit callers. Ephemeral allocation is checked after binding.
        if port == 51820 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        verify_owner(ifindex, owner)?;
        let mut payload = Zeroizing::new(header_at(ifindex));
        attribute(&mut payload, 3, &key.0)?;
        attribute(&mut payload, 6, &port.to_ne_bytes())?;
        // A zero listen port is bound only when the kernel device is running.
        // Preserve the link MTU through key setup: the first IPv6 address must
        // be installed before the route-derived packet ceiling is applied.
        send(&payload)?;
        activate(ifindex, None)?;
        if identity_at(ifindex)?.1 == 51820 {
            Self::allocate_port(ifindex)?;
        }
        Ok(())
    }
    /// Allocate an unreserved kernel socket on the link at `ifindex` without replacing its key.
    /// # Errors
    /// Reports kernel errors or bounded allocation exhaustion.
    pub fn allocate_port(ifindex: u32) -> io::Result<u16> {
        let mut payload = header_at(ifindex);
        attribute(&mut payload, 6, &0_u16.to_ne_bytes())?;
        for _ in 0..16 {
            // Port zero asks the kernel to allocate again. Never reserve a
            // userspace socket and release it into a bind race with WireGuard.
            send(&payload)?;
            activate(ifindex, None)?;
            let port = identity_at(ifindex)?.1;
            if port != 0 && port != 51820 {
                return Ok(port);
            }
        }
        Err(io::ErrorKind::AddrInUse.into())
    }
    /// Move the already-proven running link at `ifindex` to exactly `port`, keeping its key,
    /// peers and sessions.
    ///
    /// The kernel opens the new socket before it closes the old one, so a taken port fails and
    /// leaves the link on its old port. Used when a restarted node adopts a retained link whose
    /// port differs from the requested one (D391, J555 F3).
    /// # Errors
    /// Refuses port 0 and the reserved 51820; reports `AddrInUse` for a taken port, other
    /// kernel errors, or `InvalidData` when the link did not end up on `port`.
    pub fn set_listen_port(ifindex: u32, port: u16) -> io::Result<()> {
        if port == 0 || port == 51820 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut payload = header_at(ifindex);
        attribute(&mut payload, 6, &port.to_ne_bytes())?;
        send(&payload)?;
        if identity_at(ifindex)?.1 != port {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
    /// Make the subnet routes on the mesh link exactly the reachable `networks` this machine can take
    /// (D197 M3), and say what happened to each.
    ///
    /// The routes are ordinary main-table IPv4 routes on the marked mesh link, with the mesh route
    /// protocol and this node's mesh address as preferred source. The preferred source is what
    /// tells them from the peer host routes, which share the link, table, protocol and scope but
    /// never carry one ([`peer_route_payload`]); the prefix cannot, because an approved network may
    /// be a single /32 host. So they need no journal: whatever such route sits on our link and is
    /// no longer wanted is removed, including one an earlier run left behind (a crash between
    /// saving a revoking snapshot and this call, #580 J1179), and the kernel drops them all with
    /// the link. Any preferred source counts, so a route from before a mesh address change goes
    /// too.
    ///
    /// A network that overlaps any other main-table route (except the default route) is left out and
    /// reported as [`RouteState::Overlaps`]: a more specific mesh route would take over traffic this
    /// machine already sends elsewhere, such as its own LAN. Per-network install errors are reported,
    /// not returned, so one bad network does not hold up the others.
    ///
    /// The caller supplies the allowed prefixes for each approved network, with exact endpoint
    /// exclusions already applied. Remove obsolete prefixes first so a failed write cannot
    /// leave the broader tunnel route covering an excluded address.
    ///
    /// [`RouteState::Overlaps`]: crate::subnet_routes::RouteState::Overlaps
    /// # Errors
    /// A missing mesh link, a failed route dump, or a failed removal.
    pub(crate) fn sync_network_routes(
        networks: &crate::subnet_routes::RouteTargets,
        source: std::net::Ipv4Addr,
        proven: Option<ActiveLink>,
        underlay: Option<&UnderlayWatch>,
    ) -> io::Result<BTreeMap<crate::policy::networks::Network, crate::subnet_routes::RouteState>>
    {
        use crate::{policy::networks::Network, subnet_routes::RouteState};
        let index = match proven {
            Some(link) => {
                Self::verify_repair_link(&link)?;
                link.ifindex
            }
            None => {
                Self::active_link()?
                    .ok_or(io::ErrorKind::NotConnected)?
                    .ifindex
            }
        };
        let mut socket = Socket::open(SockProtocol::NetlinkRoute)?;
        let mut ours = BTreeMap::<Network, bool>::new();
        let mut foreign = Vec::new();
        let dump = vec![2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for reply in socket.request(26, 0x300, &dump)? {
            let header = reply.get(..12).ok_or(io::ErrorKind::InvalidData)?;
            if header[0] != 2 {
                continue;
            }
            let mut destination = std::net::Ipv4Addr::UNSPECIFIED;
            let mut interface = None;
            let mut table = u32::from(header[4]);
            let mut preferred_source = None;
            for field in netlink::attributes(&reply[12..])? {
                match field.kind {
                    RTA_PREFSRC => preferred_source = Some(field.payload),
                    1 if field.payload.len() == 4 => {
                        destination = std::net::Ipv4Addr::new(
                            field.payload[0],
                            field.payload[1],
                            field.payload[2],
                            field.payload[3],
                        );
                    }
                    4 => interface = Some(netlink::u32_at(field.payload, 0)?),
                    15 => table = netlink::u32_at(field.payload, 0)?,
                    _ => {}
                }
            }
            if table != 254 || header[1] == 0 {
                continue;
            }
            let Ok(network) = Network::new(destination.into(), header[1]) else {
                continue;
            };
            if interface == Some(index) {
                if header[5] == RTPROT_INFRATERNAL
                    && let Some(preferred) = preferred_source
                {
                    ours.insert(network, preferred == source.octets());
                }
            } else {
                foreign.push(network);
            }
        }
        let mut states = BTreeMap::new();
        let mut allowed = BTreeMap::new();
        for (network, parts) in networks {
            if let Some(other) = foreign
                .iter()
                .find(|other| parts.iter().any(|part| other.overlaps(*part)))
            {
                states.insert(*network, RouteState::Overlaps(*other));
            } else {
                allowed.extend(parts.iter().map(|part| (*part, *network)));
                states.insert(*network, RouteState::Installed);
            }
        }
        for (&network, &same_source) in &ours {
            if same_source && allowed.contains_key(&network) {
                continue;
            }
            let payload = network_route_payload(network, index, None)?;
            if let Err(error) = socket.request(25, 4, &payload)
                && !matches!(error.raw_os_error(), Some(2 | 3))
            {
                return Err(error);
            }
        }
        if let Some(underlay) = underlay
            && allowed.keys().any(|part| ours.get(part) != Some(&true))
        {
            underlay.ignore_route_adds(&socket);
        }
        for (part, network) in allowed {
            if ours.get(&part) == Some(&true) {
                continue;
            }
            let payload = network_route_payload(part, index, Some(source))?;
            // Create exclusively: another route may have appeared since the dump.
            if let Err(error) = socket.request(24, 4 | 0x200 | 0x400, &payload) {
                states.insert(network, RouteState::Failed(error.to_string()));
            }
        }
        Ok(states)
    }
    /// Refuse host-route overlap on another interface before touching addresses or packet policy [165].
    /// # Errors
    /// Reports malformed route dumps or an existing route covering a proposed address.
    pub fn check_routes(addresses: &[Addresses]) -> io::Result<()> {
        RouteValidation::default().check(addresses)
    }

    /// Install local /32+/128 addresses while the link meets IPv6's minimum MTU, then apply the
    /// safe fallback until the node can derive a route-specific packet ceiling.
    ///
    /// When IPv6 is off on the mesh link (`net.ipv6.conf.*.disable_ipv6`, or no IPv6 in the
    /// kernel), only the IPv4 /32 is installed and this returns `false`: the node runs IPv4-only
    /// instead of refusing the whole configuration (#578). It returns `true` when both
    /// addresses are installed. A stale IPv6 alias is still reconciled away either way.
    /// # Errors
    /// Returns address, interface lookup or route-netlink errors.
    pub fn addresses(addresses: Addresses) -> io::Result<bool> {
        let index = index()?;
        // Linux rejects IPv6 address installation below 1280 bytes. A prior
        // route update may already have narrowed this owned link to 1200, so
        // temporarily raise only that link before changing either address.
        if link_mtu(index)? < u32::from(crate::mesh_mtu::IPV6_MINIMUM_MTU) {
            set_link_mtu(index, u32::from(crate::mesh_mtu::IPV6_MINIMUM_MTU))?;
        }
        let mut route = Socket::open(SockProtocol::NetlinkRoute)?;
        let mut ipv6 = ipv6_enabled_on(&mut route, index)?;
        for (family, prefix, address) in [
            (2_u8, 32, addresses.ipv4.octets().to_vec()),
            (10, 128, addresses.ipv6.octets().to_vec()),
        ] {
            if family == 10 && !ipv6 {
                continue;
            }
            let mut payload = vec![family, prefix, 0, 0];
            payload.extend(index.to_ne_bytes());
            attribute(&mut payload, 1, &address)?;
            attribute(&mut payload, 2, &address)?;
            // IPv6 must be usable immediately; private /128 addresses are unique by coordinator allocation.
            attribute(&mut payload, 8, &0x02_u32.to_ne_bytes())?;
            if let Err(error) = route.request(20, 4 | 0x100 | 0x400, &payload) {
                if !ipv6_turned_off(&mut route, index, family, &error)? {
                    return Err(error);
                }
                ipv6 = false;
            }
        }
        // A removed identity can be explicitly re-enrolled at new host addresses.
        // Reconcile the owned interface on every replay as well, so an abrupt
        // stop during replacement cannot leave an old /32 or /128 alias live.
        // Kernel-managed link-local prefixes are outside this host-address set.
        for address in Self::host_addresses()? {
            let (family, prefix, bytes, retained) = match address {
                IpAddr::V4(address) => {
                    (2, 32, address.octets().to_vec(), address == addresses.ipv4)
                }
                IpAddr::V6(address) => (
                    10,
                    128,
                    address.octets().to_vec(),
                    address == addresses.ipv6,
                ),
            };
            if !retained {
                let mut payload = vec![family, prefix, 0, 0];
                payload.extend(index.to_ne_bytes());
                attribute(&mut payload, 1, &bytes)?;
                attribute(&mut payload, 2, &bytes)?;
                if let Err(error) = route.request(21, 4, &payload)
                    && error.raw_os_error() != Some(99)
                {
                    return Err(error);
                }
            }
        }
        activate(index, Some(crate::mesh_mtu::IPV6_MINIMUM_MTU))?;
        Ok(ipv6)
    }
    /// Whether the mesh link `infraternal0` currently carries IPv6 (#578). It resolves the shared
    /// name like [`Device::addresses`], for the node's check that IPv6 is back and for the mesh
    /// SSH listener's address list.
    ///
    /// A missing link or an unreadable reply reports an error; callers that only filter what
    /// they bind should then keep both families, the behaviour before IPv6-off support.
    /// # Errors
    /// Reports a missing interface or malformed link metadata.
    pub fn mesh_ipv6_enabled() -> io::Result<bool> {
        ipv6_enabled_on(&mut Socket::open(SockProtocol::NetlinkRoute)?, index()?)
    }
    /// Raise the proven `GotaTun` interface by index with its derived mesh MTU.
    /// # Errors
    /// Reports link configuration errors.
    pub fn activate_tun(ifindex: u32, mtu: u16) -> io::Result<()> {
        activate(ifindex, Some(mtu))
    }
    /// Set the already-proven mesh link's packet size by index after peer routes are known.
    ///
    /// Callers keep the owner proof and index together so a shared-name replacement is never
    /// modified by an MTU update.
    /// # Errors
    /// Reports a missing link or route-netlink errors.
    pub(crate) fn set_mtu(ifindex: u32, mtu: u16) -> io::Result<()> {
        set_link_mtu(ifindex, u32::from(mtu))
    }
    /// Read one already-proven link MTU so a peer update can preserve its current packet ceiling.
    /// # Errors
    /// Reports a missing interface, malformed link reply, or an MTU wider than this engine can use.
    pub(crate) fn mtu(ifindex: u32) -> io::Result<u16> {
        u16::try_from(link_mtu(ifindex)?).map_err(|_| io::ErrorKind::InvalidData.into())
    }
    /// Raise the mesh TUN's transmit queue (`txqueuelen`) to at least `len` packets and return the
    /// length it has afterwards. A shorter queue drops bursts the host writes faster than the
    /// engine reads (#260 J88e: ring drops fell from 1.14 M to 304 at 1,024). An already longer
    /// queue is left alone.
    /// # Errors
    /// Reports a missing interface or a refused change, for example without `CAP_NET_ADMIN`.
    pub(crate) fn raise_tx_queue_len(len: u32) -> io::Result<u32> {
        let index = index()?;
        if tx_queue_len_of(index)? >= len {
            return tx_queue_len_of(index);
        }
        let mut payload = vec![0; 16];
        payload[4..8].copy_from_slice(&index.to_ne_bytes());
        attribute(&mut payload, IFLA_TXQLEN, &len.to_ne_bytes())?;
        Socket::open(SockProtocol::NetlinkRoute)?.request(16, 4, &payload)?;
        tx_queue_len_of(index)
    }
    /// The mesh TUN's transmit queue length, in packets.
    /// # Errors
    /// Reports a missing interface or malformed link metadata.
    pub(crate) fn tx_queue_len() -> io::Result<u32> {
        tx_queue_len_of(index()?)
    }
    /// Read only local /32 and /128 aliases on the owned interface for recovery fencing.
    pub(crate) fn host_addresses() -> io::Result<BTreeSet<IpAddr>> {
        let index = index()?;
        let mut route = Socket::open(SockProtocol::NetlinkRoute)?;
        let mut addresses = BTreeSet::new();
        for reply in route.request(22, 0x300, &[0; 8])? {
            let header = reply.get(..8).ok_or(io::ErrorKind::InvalidData)?;
            if netlink::u32_at(header, 4)? != index
                || !matches!((header[0], header[1]), (2, 32) | (10, 128))
            {
                continue;
            }
            let mut local = None;
            let mut address = None;
            for field in netlink::attributes(&reply[8..])? {
                match field.kind {
                    1 => address = Some(field.payload),
                    2 => local = Some(field.payload),
                    _ => {}
                }
            }
            let bytes = local.or(address).ok_or(io::ErrorKind::InvalidData)?;
            let address = match header[0] {
                2 => IpAddr::V4(std::net::Ipv4Addr::from(
                    <[u8; 4]>::try_from(bytes).map_err(|_| io::ErrorKind::InvalidData)?,
                )),
                10 => IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(bytes).map_err(|_| io::ErrorKind::InvalidData)?,
                )),
                _ => return Err(io::ErrorKind::InvalidData.into()),
            };
            addresses.insert(address);
        }
        Ok(addresses)
    }
    /// Apply peers through a temporary client; persistent node owners reuse `Client`.
    /// # Errors
    /// Reports encoding and kernel errors without changing unrelated peers.
    pub fn peers(upserted: &[Peer], removed: &[PublicKey]) -> io::Result<()> {
        Client::new()?.peers(upserted, removed)
    }
    /// Install/remove only peer host routes with the mesh-owned route protocol; no subnet or default route.
    /// # Errors
    /// Returns route-netlink errors.
    pub fn routes(peers: &[Peer], remove: bool) -> io::Result<()> {
        Self::routes_with_mtu_overrides(peers, &BTreeMap::new(), remove, None)
    }

    /// Install peer routes using live relay MTUs where one is active, otherwise the direct route.
    /// # Errors
    /// Returns route-netlink errors.
    pub(crate) fn routes_with_mtu_overrides(
        peers: &[Peer],
        overrides: &BTreeMap<PublicKey, u16>,
        remove: bool,
        underlay: Option<&UnderlayWatch>,
    ) -> io::Result<()> {
        if peers.is_empty() {
            return Ok(());
        }
        let mut socket = Socket::open(SockProtocol::NetlinkRoute)?;
        // Resolve the marked link and keep its ifindex for the whole batch. A name-only lookup
        // could route through an unrelated interface substituted under `infraternal0`.
        let index = Self::active_link()?
            .ok_or(io::ErrorKind::NotConnected)?
            .ifindex;
        // An IPv6-off link takes no IPv6 routes (#578). Removal still tries both families: the
        // kernel already dropped any IPv6 route there, and a missing route is tolerated below.
        let mut ipv6 = remove || ipv6_enabled_on(&mut socket, index)?;
        if !remove && let Some(underlay) = underlay {
            underlay.ignore_route_adds(&socket);
        }
        for peer in peers {
            let mtu = (!remove).then(|| {
                overrides
                    .get(&peer.key)
                    .copied()
                    .unwrap_or_else(|| crate::mesh_mtu::for_endpoint(peer.endpoint))
            });
            for (family, prefix, address) in [
                (2_u8, 32, peer.addresses.ipv4.octets().to_vec()),
                (10, 128, peer.addresses.ipv6.octets().to_vec()),
            ] {
                // An IPv4-only peer (#578, J1142) gets no IPv6 route either.
                if family == 10 && (!ipv6 || peer.ipv4_only) {
                    continue;
                }
                let mut payload = peer_route_payload(family, prefix, &address, index, mtu)?;
                let result = socket.request(
                    if remove { 25 } else { 24 },
                    if remove { 4 } else { 4 | 0x100 | 0x400 },
                    &payload,
                );
                if let Err(error) = &result
                    && !remove
                    && ipv6_turned_off(&mut socket, index, family, error)?
                {
                    ipv6 = false;
                    continue;
                }
                if let Err(error) = result {
                    // A newer node can stop after replacing an old static route but before its
                    // next restart. Try that legacy owner only after the mesh protocol is absent.
                    if remove && matches!(error.raw_os_error(), Some(2 | 3)) {
                        payload[5] = RTPROT_LEGACY_STATIC;
                        if let Err(error) = socket.request(25, 4, &payload)
                            && !matches!(error.raw_os_error(), Some(2 | 3))
                        {
                            return Err(error);
                        }
                    } else {
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }

    /// Replace peer host routes on one proven link with explicit packet budgets.
    ///
    /// Unlike [`Device::routes_with_mtu_overrides`], which resolves whichever marked link holds the
    /// shared name at write time, this writes only to `link`, the identity the route-repair worker
    /// captured (J485). Its index, engine and owner are checked again right before the batch, and
    /// every write uses that index, so a replacement link, even one carrying this node's marker,
    /// is never written (#489 J549 P2).
    /// # Errors
    /// Refuses a missing or changed link before any write; returns route-netlink errors.
    ///
    /// Returns whether the link still carried IPv6 when the batch ended, so the caller can record
    /// which routes now exist (an IPv6-off link holds no IPv6 route at all, #578).
    pub(crate) fn replace_peer_routes_on(
        link: &ActiveLink,
        routes: &[(&Peer, u16)],
        underlay: Option<std::sync::Arc<UnderlayWatch>>,
    ) -> io::Result<bool> {
        if routes.is_empty() {
            return Ok(true);
        }
        Self::verify_repair_link(link)?;
        let mut writer = PeerRouteWriter::open(link.ifindex, underlay)?;
        for (peer, mtu) in routes {
            writer.replace(peer, *mtu)?;
        }
        Ok(writer.ipv6())
    }

    /// Open a [`PeerRouteWriter`] on the marked mesh link that holds the shared name now.
    ///
    /// This is the link a snapshot's route writes go to, resolved once so every write of one
    /// batch uses the same index (a name-only lookup per write could follow a substituted link).
    /// # Errors
    /// Reports a missing marked link, or a socket or link-read error.
    pub(crate) fn peer_route_writer(
        underlay: Option<std::sync::Arc<UnderlayWatch>>,
    ) -> io::Result<PeerRouteWriter> {
        let index = Self::active_link()?
            .ok_or(io::ErrorKind::NotConnected)?
            .ifindex;
        PeerRouteWriter::open(index, underlay)
    }

    /// Re-add one missing route only when no route already occupies its destination, and say
    /// whether it was added.
    ///
    /// The caller has matched the deleted address against the currently installed peer set. The
    /// exclusive create flag makes a concurrent or foreign route a no-op instead of replacing it;
    /// then this returns `false`, since nothing at that destination changed (#483 J780).
    /// # Errors
    /// Returns route-netlink errors other than `AlreadyExists`, which means there is nothing safe
    /// to change at that destination.
    pub(crate) fn repair_peer_route(
        link: &ActiveLink,
        peer: &Peer,
        address: IpAddr,
        mtu: u16,
        underlay: Option<&UnderlayWatch>,
    ) -> io::Result<bool> {
        Self::verify_repair_link(link)?;
        let (family, prefix, destination) = match address {
            IpAddr::V4(address) if address == peer.addresses.ipv4 => {
                (2, 32, address.octets().to_vec())
            }
            IpAddr::V6(address) if address == peer.addresses.ipv6 && !peer.ipv4_only => {
                (10, 128, address.octets().to_vec())
            }
            _ => return Err(io::ErrorKind::InvalidInput.into()),
        };
        let payload = peer_route_payload(family, prefix, &destination, link.ifindex, Some(mtu))?;
        let mut socket = Socket::open(SockProtocol::NetlinkRoute)?;
        // Turning IPv6 off drops every IPv6 route on the link; those deletions are not damage
        // to repair, and the kernel would refuse the write anyway (#578).
        if family == 10 && !ipv6_enabled_on(&mut socket, link.ifindex)? {
            return Ok(false);
        }
        if let Some(underlay) = underlay {
            underlay.ignore_route_adds(&socket);
        }
        match socket.request(24, 4 | 0x200 | 0x400, &payload) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) if ipv6_turned_off(&mut socket, link.ifindex, family, &error)? => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Open a passive listener for route deletions on the current mesh interface.
    ///
    /// The same listener reports every other link and route change to `underlay`, so peer route
    /// budgets are re-derived only after the underlay can have changed (#489 J552 P2-2), and
    /// every change that can move our own endpoint to `announce` (#483).
    /// # Errors
    /// Returns socket, binding, or interface lookup errors before the worker starts.
    pub(crate) fn route_monitor(
        link: &ActiveLink,
        underlay: std::sync::Arc<UnderlayWatch>,
        announce: std::sync::Arc<crate::gotatun_node::UnderlayAnnounce>,
    ) -> io::Result<RouteMonitor> {
        Self::verify_repair_link(link)?;
        RouteMonitor::open(link.ifindex, underlay, announce)
    }
    /// Refuse repair if the shared name, original index, engine, or public ownership changed.
    /// Writes still use the original index, so a name replacement cannot redirect them.
    /// # Errors
    /// Reports missing, foreign, or changed links before any route write.
    pub(crate) fn verify_repair_link(link: &ActiveLink) -> io::Result<()> {
        let owner = link.owner.ok_or(io::ErrorKind::PermissionDenied)?;
        let active = Self::active_link().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "mesh route repair skipped: cannot verify original interface {}: {error}",
                    link.ifindex
                ),
            )
        })?;
        if active.is_none_or(|active| {
            active.ifindex != link.ifindex
                || active.engine != link.engine
                || active.owner != Some(owner)
        }) {
            return Err(io::Error::other(
                "mesh route repair skipped: interface identity changed",
            ));
        }
        verify_engine_owner(link.ifindex, link.engine, owner)
    }

    /// Find accepted destinations missing from the actual kernel route table on this proven link.
    /// The returned set is bounded by the input (two addresses per accepted peer); streaming the
    /// host dump avoids retaining unrelated routes. Allowed IPs are not evidence of a route.
    /// # Errors
    /// Refuses changed ownership, malformed route replies, and failed kernel dumps.
    pub(crate) fn missing_peer_routes(
        link: &ActiveLink,
        mut missing: BTreeSet<IpAddr>,
    ) -> io::Result<BTreeSet<IpAddr>> {
        Self::verify_repair_link(link)?;
        let mut socket = Socket::open(SockProtocol::NetlinkRoute)?;
        // An IPv6-off link never holds the IPv6 routes, so they are not missing (#578).
        if !ipv6_enabled_on(&mut socket, link.ifindex)? {
            missing.retain(IpAddr::is_ipv4);
        }
        socket.visit(26, 0x300, &[0; 12], |reply| {
            if let Some(address) = mesh_peer_route_destination(reply, link.ifindex)? {
                missing.remove(&address);
            }
            Ok(())
        })?;
        Ok(missing)
    }

    /// Read the unique public-prefix owner for every retained peer route.
    /// # Errors
    /// Refuses malformed or multiply-owned `AllowedIPs`. All dump buffers,
    /// including unparsed secret fields in later replies, are zeroized together.
    pub fn peer_route_owners() -> io::Result<BTreeMap<IpAddr, PublicKey>> {
        let mut socket = Socket::open(SockProtocol::NetlinkGeneric)?;
        let family = socket.family("wireguard")?;
        let mut payload = header();
        payload[0] = 0;
        let replies = Zeroizing::new(socket.request(family, 0x300, &payload)?);
        let mut routes = BTreeMap::new();
        for reply in replies.iter() {
            for device in netlink::attributes(reply.get(4..).ok_or(io::ErrorKind::InvalidData)?)? {
                if device.kind != 8 {
                    continue;
                }
                for peer in netlink::attributes(device.payload)? {
                    let mut key = None;
                    let mut prefixes = Vec::new();
                    for field in netlink::attributes(peer.payload)? {
                        match field.kind {
                            1 => {
                                key = Some(PublicKey(
                                    field
                                        .payload
                                        .try_into()
                                        .map_err(|_| io::ErrorKind::InvalidData)?,
                                ));
                            }
                            9 => {
                                for prefix in netlink::attributes(field.payload)? {
                                    if let Some(address) = netlink::host_address(prefix.payload)? {
                                        prefixes.push(address);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    let key = key.ok_or(io::ErrorKind::InvalidData)?;
                    for address in prefixes {
                        if routes.insert(address, key).is_some() {
                            return Err(io::ErrorKind::InvalidData.into());
                        }
                    }
                }
            }
        }
        Ok(routes)
    }
    /// Recover public host prefixes from retained peers before removing orphan keys.
    /// # Errors
    /// Refuses malformed or multiply-owned `AllowedIPs`.
    pub fn peer_routes() -> io::Result<BTreeSet<IpAddr>> {
        Ok(Self::peer_route_owners()?.into_keys().collect())
    }
    /// Retire orphan mesh host routes after adopting durable peer state, including legacy routes [206,228].
    /// # Errors
    /// Reports malformed route dumps or kernel deletion errors.
    pub fn retain_routes(addresses: &[Addresses]) -> io::Result<()> {
        let retained: Vec<IpAddr> = addresses
            .iter()
            .flat_map(|address| [IpAddr::V4(address.ipv4), IpAddr::V6(address.ipv6)])
            .collect();
        Self::retain_recorded_routes(&Self::peer_routes()?, &retained)
    }
    /// Retire only journaled peer host routes with the exact shape we install.
    /// # Errors
    /// Reports checked dump or deletion failures, preserving foreign route shapes.
    ///
    /// `retained` lists the destinations that stay. It is a list of addresses, not of
    /// [`Addresses`] pairs, because an IPv4-only peer keeps only its IPv4 route (#578, J1142).
    pub fn retain_recorded_routes(
        inventory: &BTreeSet<IpAddr>,
        retained: &[IpAddr],
    ) -> io::Result<()> {
        Self::retire_routes(inventory, retained)
    }
    /// Remove stale peer routes owned by this mesh while preserving foreign routes.
    fn retire_routes(inventory: &BTreeSet<IpAddr>, retained: &[IpAddr]) -> io::Result<()> {
        let desired: BTreeSet<IpAddr> = retained.iter().copied().collect();
        let owned = index()?;
        let mut socket = Socket::open(SockProtocol::NetlinkRoute)?;
        for reply in socket.request(26, 0x300, &[0; 12])? {
            let header = reply.get(..12).ok_or(io::ErrorKind::InvalidData)?;
            // New mesh routes use a private protocol so NetworkManager can leave them alone
            // during DNS reapply. Keep recognizing the old static protocol for upgrades.
            // Linux normalizes IPv6 scope-link host routes to universe scope; IPv4 keeps link scope.
            if header[4] != 254
                || (header[5] != RTPROT_INFRATERNAL && header[5] != RTPROT_LEGACY_STATIC)
                || header[7] != 1
                || header[2] != 0
                || header[3] != 0
                || header[8..12] != [0; 4]
                || !matches!(
                    (header[0], header[1], header[6]),
                    (2, 32, 253) | (10, 128, 0)
                )
            {
                continue;
            }
            let mut interface = None;
            let mut destination = None;
            let mut table = 254;
            let mut exact_shape = true;
            let mut route_mtu_seen = false;
            for field in netlink::attributes(&reply[12..])? {
                match field.kind {
                    1 => destination = Some(field.payload),
                    4 => interface = Some(netlink::u32_at(field.payload, 0)?),
                    15 => table = netlink::u32_at(field.payload, 0)?,
                    6 if header[0] == 10 && field.payload == 1024_u32.to_ne_bytes() => {}
                    12 if header[0] == 10 && field.payload.len() == 32 => {}
                    20 if header[0] == 10 && field.payload == [0] => {}
                    8 if !route_mtu_seen && mesh_route_metrics_are_owned(field) => {
                        route_mtu_seen = true;
                    }
                    _ => exact_shape = false,
                }
            }
            if !exact_shape || interface != Some(owned) || table != 254 {
                continue;
            }
            let address = match (header[0], header[1]) {
                (2, 32) => IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(destination.ok_or(io::ErrorKind::InvalidData)?)
                        .map_err(io::Error::other)?,
                )),
                (10, 128) => IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(destination.ok_or(io::ErrorKind::InvalidData)?)
                        .map_err(io::Error::other)?,
                )),
                _ => continue,
            };
            // Reuse the dumped attributes so route priority and IPv6 kernel
            // normalization remain exact. A replay may already have removed it.
            if inventory.contains(&address)
                && !desired.contains(&address)
                && let Err(error) = socket.request(25, 4, &reply)
                && !matches!(error.raw_os_error(), Some(2 | 3))
            {
                return Err(error);
            }
        }
        Ok(())
    }
    /// Read only the public device key and actual listen port from a zeroized kernel dump.
    /// # Errors
    /// Refuses unavailable or malformed device identity; secret fields never leave this method.
    pub fn identity() -> io::Result<(PublicKey, u16)> {
        identity_from(header())
    }
    /// The public key and listen port of the `WireGuard` device at `ifindex`, for a link whose
    /// index is already known, so the read is bound to that link rather than to the shared name.
    /// # Errors
    /// The same as [`Device::identity`].
    pub(crate) fn identity_at(ifindex: u32) -> io::Result<(PublicKey, u16)> {
        identity_at(ifindex)
    }
    /// Read the kernel device's private key, only to carry this node's identity to `GotaTun`
    /// when it leaves kernel `WireGuard` (D346). The caller must have proven the link is ours.
    /// Every reply buffer is zeroized on drop, and so is the returned key.
    /// # Errors
    /// Refuses a device without a key, or a malformed dump.
    pub(crate) fn private_key_at(ifindex: u32) -> io::Result<Zeroizing<[u8; 32]>> {
        let mut socket = Socket::open(SockProtocol::NetlinkGeneric)?;
        let family = socket.family("wireguard")?;
        let mut payload = header_at(ifindex);
        payload[0] = 0;
        let mut key = Zeroizing::new([0; 32]);
        let mut found = false;
        for reply in socket.request(family, 0x300, &payload)? {
            let reply = Zeroizing::new(reply);
            for field in netlink::attributes(reply.get(4..).ok_or(io::ErrorKind::InvalidData)?)? {
                if field.kind == 3 && field.payload.len() == 32 {
                    key.copy_from_slice(field.payload);
                    found = true;
                }
            }
        }
        if !found || *key == [0; 32] {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(key)
    }
    /// Read public peer counters only. Private fields in the kernel dump are zeroized.
    /// # Errors
    /// Reports dump or malformed counter errors.
    pub fn counters() -> io::Result<BTreeMap<PublicKey, Counters>> {
        let mut socket = Socket::open(SockProtocol::NetlinkGeneric)?;
        let family = socket.family("wireguard")?;
        let mut payload = header();
        payload[0] = 0;
        let mut counters: BTreeMap<PublicKey, Counters> = BTreeMap::new();
        // The kernel includes its key in a device dump; every reply buffer is zeroized on drop.
        let replies = socket.request(family, 0x300, &payload)?;
        for reply in replies {
            let reply = Zeroizing::new(reply);
            for device in netlink::attributes(reply.get(4..).ok_or(io::ErrorKind::InvalidData)?)? {
                if device.kind != 8 {
                    continue;
                }
                for peer in netlink::attributes(device.payload)? {
                    let mut key = None;
                    let mut keepalive = None;
                    let mut handshake = None;
                    #[cfg(feature = "relay")]
                    let mut nanos = None;
                    let mut received = None;
                    let mut sent = None;
                    let mut endpoint = None;
                    for field in netlink::attributes(peer.payload)? {
                        match field.kind {
                            1 if field.payload.len() == 32 => {
                                key = Some(PublicKey(
                                    field.payload.try_into().map_err(io::Error::other)?,
                                ));
                            }
                            #[cfg(feature = "relay")]
                            6 => {
                                handshake = Some(scalar64(field.payload)?);
                                nanos = Some(handshake_nanos(field.payload)?);
                            }
                            #[cfg(not(feature = "relay"))]
                            6 => {
                                handshake = Some(scalar64(field.payload)?);
                            }
                            5 => {
                                keepalive = Some(u16::from_ne_bytes(
                                    field.payload.try_into().map_err(io::Error::other)?,
                                ));
                            }
                            4 => endpoint = Some(decode_sockaddr(field.payload)?),
                            7 => received = Some(scalar64(field.payload)?),
                            8 => sent = Some(scalar64(field.payload)?),
                            _ => {}
                        }
                    }
                    if let Some(key) = key {
                        // Multipart dumps repeat a key with only remaining
                        // AllowedIPs. Absence must retain the earlier metadata;
                        // a present zero is still an authoritative value.
                        let stats = counters.entry(key).or_default();
                        if let Some(value) = keepalive {
                            stats.persistent_keepalive_secs = value;
                        }
                        if let Some(value) = handshake {
                            stats.handshake_secs = value;
                        }
                        #[cfg(feature = "relay")]
                        if let Some(value) = nanos {
                            stats.handshake_nanos = value;
                        }
                        if let Some(value) = received {
                            stats.received_bytes = value;
                        }
                        if let Some(value) = sent {
                            stats.sent_bytes = value;
                        }
                        if endpoint.is_some() {
                            stats.endpoint = endpoint;
                        }
                    }
                }
            }
        }
        Ok(counters)
    }
}

/// Why the route listener yielded control to the repair worker.
pub(crate) enum RouteWake {
    /// One accepted route may need immediate repair.
    Deleted(IpAddr),
    /// The independent deadline requires a complete inventory check.
    Reconcile,
    /// A completed overflow recovery invalidated the underlay and needs an inventory check.
    Overflow,
    /// Link teardown requested the worker to stop.
    Cancelled,
}

/// Tells peer-route refreshes whether the underlay may have changed since they last looked.
///
/// Deriving a peer's route budget costs two route-netlink requests, so a refresh that re-derived
/// every peer cost about 70 µs per peer, under the shared route-state lock, up to four times a
/// second (#489 J552 P2-2: 288 ms at 4,096 peers). The underlay only changes when a link or route
/// does, and the kernel announces both. The route listener bumps `generation` on every such
/// announcement that is not about our own mesh link or its peer routes, except a route notice
/// that changed neither where the route sends nor its MTU metric (a lifetime refresh, #483
/// J780), and a refresh re-derives all peers only when the generation moved.
///
/// `watched` is false while no listener runs (it failed, or never started). Then no change can
/// be trusted to arrive, and every refresh re-derives every peer, as before this watch existed.
/// A lost notification (`ENOBUFS`) bumps the generation too, and so does the route-repair worker's
/// periodic inventory check, which bounds how long an unannounced change (a cached path-MTU
/// exception) can go unseen.
///
/// A snapshot apply asks for [`UnderlayWatch::settled_generation`] instead (#260 J1240): it must
/// not reuse a budget across a change the listener has been told about but not yet counted.
#[derive(Debug, Default)]
pub(crate) struct UnderlayWatch {
    /// Counts underlay announcements; only equality with an earlier reading matters.
    generation: std::sync::atomic::AtomicU64,
    /// Whether a listener is subscribed and will bump `generation` on the next change.
    watched: std::sync::atomic::AtomicBool,
    /// A duplicate of the running listener's socket, which shares its receive queue, so
    /// [`UnderlayWatch::settled_generation`] can see whether notifications are still waiting.
    queue: std::sync::Mutex<Option<RouteQueue>>,
    /// Whether the listener is between taking a notification off its socket and counting it,
    /// or is inside the quiet period after lost notifications, which it counts only at the end.
    reading: std::sync::atomic::AtomicBool,
}

impl UnderlayWatch {
    /// Record that the underlay may have changed.
    pub(crate) fn changed(&self) {
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Mark whether a listener now reports changes. Starting to watch also counts as a change,
    /// since nothing reported what happened while no listener ran.
    pub(crate) fn set_watched(&self, watched: bool) {
        if watched {
            self.changed();
        }
        self.watched
            .store(watched, std::sync::atomic::Ordering::Release);
        if !watched {
            self.changed();
        }
    }

    /// The current generation, or `None` while no listener runs and nothing can be trusted.
    pub(crate) fn generation(&self) -> Option<u64> {
        self.watched
            .load(std::sync::atomic::Ordering::Acquire)
            .then(|| self.generation.load(std::sync::atomic::Ordering::Acquire))
    }

    /// The generation, but only when it already counts every change the kernel announced before
    /// this call; `None` otherwise, and while no listener runs (#260 J1240).
    ///
    /// The kernel queues a change's notification before the system call that made the change
    /// returns, so a change that happened before this call is either still queued, being read,
    /// or already counted. This checks those in that order: nothing waits on the listener's
    /// socket, then the listener is not reading, then the generation is read. A listener that
    /// takes a notification sets `reading` before its `recv` and clears it only after counting,
    /// so a notification that left the queue before the first check is counted by the time the
    /// second one sees `reading` clear. A busy listener only costs the caller fresh lookups.
    pub(crate) fn settled_generation(&self) -> Option<u64> {
        {
            let queue = self
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let queue = queue.as_ref()?;
            let mut waiting = [PollFd::new(queue.fd.as_fd(), PollFlags::POLLIN)];
            if !matches!(poll(&mut waiting, PollTimeout::ZERO), Ok(0)) {
                return None;
            }
        }
        if self.reading.load(std::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        self.generation()
    }

    /// Publish (or, with `None`, withdraw) the duplicate of the listener's socket that
    /// [`UnderlayWatch::settled_generation`] polls.
    fn attach_queue(&self, queue: Option<OwnedFd>) {
        *self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = queue.map(RouteQueue::new);
    }

    /// Suppress additions from a bound request socket before it starts writing. If the kernel
    /// or sandbox refuses the filter, keep using the listener and handle echoes as usual.
    fn ignore_route_adds(&self, writer: &Socket) {
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(queue) = queue.as_mut()
            && let Err(error) = queue.ignore_adds_from(writer.as_fd())
        {
            tracing::debug!(%error, "mesh route notification filter unavailable");
        }
    }

    /// Mark whether the listener holds notifications it has not counted yet.
    fn set_reading(&self, reading: bool) {
        self.reading
            .store(reading, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Listens for kernel route deletions while a node is up, so only a known mesh peer route is
/// offered back to the kernel after an interface manager reconfigures the link. It also reports
/// other link and route changes to an [`UnderlayWatch`], and every change that can move our own
/// endpoint to an [`UnderlayAnnounce`](crate::gotatun_node::UnderlayAnnounce).
///
/// This is the node's only route-netlink subscription (#483 J633 P1): the endpoint announce
/// reads the same queue as the route repair and the MTU watch. A socket filter keeps echoes
/// of the node's own route additions out of that queue.
pub(crate) struct RouteMonitor {
    /// The route multicast socket subscribed in the node's network namespace.
    fd: OwnedFd,
    /// The interface index proven when the listener starts.
    interface_index: u32,
    /// Reused storage for kernel notifications; route messages contain no private key material.
    buffer: Vec<u8>,
    /// Bumped for every link, route, policy-rule or nexthop change that is not our own link or
    /// peer route and not a route lifetime refresh.
    underlay: std::sync::Arc<UnderlayWatch>,
    /// Woken for every change that can move our own endpoint as peers see it.
    announce: std::sync::Arc<crate::gotatun_node::UnderlayAnnounce>,
    /// The host's addresses, routes and policy outside the mesh link, to tell a real change from
    /// a lifetime refresh.
    books: EndpointBooks,
}

impl RouteMonitor {
    /// Subscribe to the notifications that can move a peer endpoint's underlay path or our own
    /// endpoint: links, IPv4 and IPv6 addresses, routes and policy rules, and nexthop objects.
    ///
    /// Rules and nexthops have their own groups (#489 J609): a VPN or interface manager that adds
    /// its table routes first and the `ip rule` that selects them second moves endpoints with
    /// no route announcement at all, and so does replacing a nexthop object routes refer to
    /// while `net.ipv4.nexthop_compat_mode` is off. The mesh writes neither, so these groups
    /// carry no echo of our own writes. Addresses are the endpoint itself (#483): a new source
    /// address must reach peers before they can send to it.
    ///
    /// Opening wakes `announce` once: nothing reported what changed while no listener ran. The
    /// current addresses and routes are read after the subscription exists (see
    /// [`EndpointBooks::dump`]); if a read fails, that book starts empty and each entry counts
    /// once when next refreshed.
    /// # Errors
    /// Returns socket, bind, or interface lookup errors before the node becomes active.
    fn open(
        interface_index: u32,
        underlay: std::sync::Arc<UnderlayWatch>,
        announce: std::sync::Arc<crate::gotatun_node::UnderlayAnnounce>,
    ) -> io::Result<Self> {
        let fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::NetlinkRoute,
        )?;
        bind(
            fd.as_raw_fd(),
            &NetlinkAddr::new(
                0,
                RTMGRP_LINK
                    | RTMGRP_IPV4_IFADDR
                    | RTMGRP_IPV6_IFADDR
                    | RTMGRP_IPV4_ROUTE
                    | RTMGRP_IPV6_ROUTE
                    | RTMGRP_IPV4_RULE
                    | RTMGRP_IPV6_RULE
                    | RTMGRP_NEXTHOP,
            ),
        )?;
        announce.changed();
        underlay.set_reading(false);
        underlay.attach_queue(Some(fd.try_clone()?));
        Ok(Self {
            fd,
            interface_index,
            buffer: vec![0; netlink::DATAGRAM_BYTES],
            underlay,
            announce,
            books: EndpointBooks::dump(interface_index).0,
        })
    }

    /// Wait until a deletion, cancellation, or the full-inventory reconciliation deadline.
    ///
    /// Only unicast `/32` and `/128` routes in the main table, with this interface and protocol
    /// 250, are reported. Every other link, route, rule or nexthop change bumps the underlay watch
    /// (a route only when it really changed, see [`RouteBook`]) and is not reported. Those changes, and address changes, also wake the announce. A
    /// notification overflow (`ENOBUFS`) may have dropped a deletion or an address change, so it
    /// discards the rest of the burst before resyncing and requesting one full inventory check.
    /// # Errors
    /// Returns poll, receive, or malformed-netlink-message errors.
    pub(crate) fn wait_for_deleted_peer_route(
        &mut self,
        cancel: BorrowedFd<'_>,
        deadline: Instant,
    ) -> io::Result<RouteWake> {
        let mut loss: Option<NotificationLoss> = None;
        loop {
            let next = loss.map_or(deadline, |loss| loss.due().min(deadline));
            let remaining = next.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                if loss.is_some() {
                    self.lost_notifications();
                    return Ok(RouteWake::Overflow);
                }
                return Ok(RouteWake::Reconcile);
            }
            // Everything taken off the socket so far is counted, unless a loss is still to be
            // recovered (#260 J1240, see `UnderlayWatch::settled_generation`).
            self.underlay.set_reading(loss.is_some());
            // PollTimeout rounds down to whole milliseconds. Check the clock again on a
            // timeout, using at least one millisecond so the last fraction does not spin.
            let timeout = PollTimeout::try_from(remaining.max(Duration::from_millis(1)))
                .map_err(io::Error::other)?;
            let mut descriptors = [
                PollFd::new(self.fd.as_fd(), PollFlags::POLLIN),
                PollFd::new(cancel, PollFlags::POLLIN),
            ];
            match poll(&mut descriptors, timeout) {
                Ok(0) | Err(nix::errno::Errno::EINTR) => continue,
                Ok(_) => {}
                Err(error) => return Err(error.into()),
            }
            if descriptors[1].revents().is_some_and(|flags| {
                flags.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
            }) {
                return Ok(RouteWake::Cancelled);
            }
            let route_events = descriptors[0].revents().unwrap_or_else(PollFlags::empty);
            if route_events.intersects(PollFlags::POLLHUP | PollFlags::POLLNVAL) {
                return Err(io::Error::other("route notification socket disconnected"));
            }
            // An overflow shows as `POLLERR` (with `POLLIN` when notifications are still
            // queued), and only `recv` reports and clears it as `ENOBUFS` (#483 J707 P2). Treating
            // `POLLERR` as a dead socket dropped the listener until the 30 s recheck, so a route
            // storm hid our own endpoint change for that long. The read never blocks: `POLLERR`
            // can be the only event.
            if route_events.intersects(PollFlags::POLLIN | PollFlags::POLLERR) {
                // Before the notification leaves the queue; cleared once it is counted.
                self.underlay.set_reading(true);
                let length = match recv(
                    self.fd.as_raw_fd(),
                    &mut self.buffer,
                    MsgFlags::MSG_DONTWAIT,
                ) {
                    Ok(length) => length,
                    Err(nix::errno::Errno::ENOBUFS) => {
                        let now = Instant::now();
                        let pending = loss.get_or_insert_with(|| NotificationLoss::new(now));
                        // Clear the stale queue in one batch. Traffic arriving after the
                        // drain still belongs to this recovery until the quiet deadline.
                        self.discard_queued_notifications();
                        pending.received(Instant::now());
                        continue;
                    }
                    Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => continue,
                    Err(error) => return Err(error.into()),
                };
                if length == 0 || length == self.buffer.len() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                if let Some(loss) = loss.as_mut() {
                    // Until the books are resynced, a queued add can predate an unobserved
                    // delete. The inventory check covers peer deletions discarded here too.
                    loss.received(Instant::now());
                    continue;
                }
                let mut deleted = None;
                let mut change = UnderlayChange::default();
                for message in netlink::messages(&self.buffer[..length])? {
                    if deleted.is_none() {
                        deleted = deleted_mesh_peer_route(&message, self.interface_index)?;
                    }
                    change |= self.books.observe(&message, self.interface_index)?;
                }
                // Bump before waking the repair, so no refresh misses a change in this datagram.
                if change.route_budgets {
                    self.underlay.changed();
                }
                if change.endpoint {
                    self.announce.changed();
                }
                if let Some(address) = deleted {
                    return Ok(RouteWake::Deleted(address));
                }
            }
        }
    }

    /// Recover from a notification overflow (`ENOBUFS`): some notifications are gone, so what
    /// the listener knows may be stale.
    ///
    /// Notifications still queued are discarded, because applying an old
    /// "added" after a fresh dump could book an address or route the lost notifications had
    /// removed, and the next real re-add would then look like a refresh. The books are then read
    /// again, and the announce wakes only if the host's addresses, routes, rules or nexthops
    /// differ from what the listener last knew (D81: a storm that ends where it started moved
    /// nothing). Route budgets are always re-derived, and the caller asks for a full inventory
    /// check, since a lost notification may have been a deleted peer route.
    fn lost_notifications(&mut self) {
        self.discard_queued_notifications();
        if self.books.resync(self.interface_index) {
            self.announce.changed();
        }
        self.underlay.changed();
        #[cfg(test)]
        OVERFLOW_RECOVERIES.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    /// Drop stale datagrams in one bounded batch before returning to poll or rebuilding state.
    fn discard_queued_notifications(&mut self) {
        // Bounded, so a storm that refills the queue as fast as it drains cannot hold us here.
        for _ in 0..LOST_NOTIFICATION_DRAIN_LIMIT {
            match recv(
                self.fd.as_raw_fd(),
                &mut self.buffer,
                MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(_) | Err(nix::errno::Errno::ENOBUFS | nix::errno::Errno::EINTR) => {}
                Err(_) => break,
            }
        }
        #[cfg(test)]
        if let Some(after) = AFTER_NOTIFICATION_DRAIN.take() {
            after();
        }
    }
}

impl Drop for RouteMonitor {
    /// Withdraw the socket duplicate, so the closed listener's queue is never trusted and the
    /// socket really closes with the listener.
    fn drop(&mut self) {
        self.underlay.attach_queue(None);
        self.underlay.set_reading(false);
    }
}

/// Deadline for rebuilding state after netlink dropped notifications. Recent activity extends
/// the quiet period, while a sustained burst still gets a recovery within the maximum window.
#[derive(Clone, Copy)]
struct NotificationLoss {
    /// Latest time a datagram or another overflow was seen.
    last: Instant,
    /// Absolute limit from the first overflow, independent of later traffic.
    limit: Instant,
}

impl NotificationLoss {
    /// Begin a recovery window using the same bounds as the endpoint announcement scheduler.
    fn new(now: Instant) -> Self {
        Self {
            last: now,
            limit: now + crate::underlay_announce::COALESCE_MIN_INTERVAL,
        }
    }

    /// Keep receiving and discarding until the burst is quiet or the recovery is due.
    fn due(self) -> Instant {
        (self.last + crate::underlay_announce::COALESCE_DEBOUNCE).min(self.limit)
    }

    /// Extend the quiet deadline while notifications are still arriving.
    fn received(&mut self, now: Instant) {
        self.last = now;
    }
}

/// Test probe: how many overflow recoveries ([`RouteMonitor`]'s `lost_notifications`) have
/// finished in this process, so namespace tests can distinguish completed overflow recoveries
/// from ordinary deletion repairs (#483 J780).
#[cfg(test)]
pub(crate) static OVERFLOW_RECOVERIES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// How many queued datagrams an overflow recovery discards at most before it re-reads the host.
/// The default receive buffer holds a few hundred; the bound only matters in an endless storm.
const LOST_NOTIFICATION_DRAIN_LIMIT: usize = 4096;

#[cfg(test)]
thread_local! {
    /// Run the trailing portion of a namespace fixture's burst after the socket drains.
    static AFTER_NOTIFICATION_DRAIN: std::cell::Cell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::Cell::new(None) };
}

/// What one or more kernel notifications mean for the mesh.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct UnderlayChange {
    /// A link, route, rule or nexthop moved: peer route budgets may need re-deriving.
    route_budgets: bool,
    /// Our own endpoint may have moved as peers see it: live sessions should hear from us.
    endpoint: bool,
}

impl std::ops::BitOrAssign for UnderlayChange {
    fn bitor_assign(&mut self, other: Self) {
        self.route_budgets |= other.route_budgets;
        self.endpoint |= other.endpoint;
    }
}

/// What the route listener knows about the host outside the mesh link: its addresses, its
/// routes, and whether its policy rules and nexthop objects are as last read. Together they
/// tell a change that can move our endpoint from a refresh that moved nothing (#483, D81).
#[derive(Debug, Default)]
struct EndpointBooks {
    /// The host's interface addresses and their flags.
    addresses: AddressBook,
    /// The host's routes, by what decides where they send.
    routes: RouteBook,
    /// A fingerprint of the host's policy rules and nexthop objects as last dumped, or `None`
    /// once a rule or nexthop notification arrived since (or the dump failed). Only overflow
    /// recovery reads it: rule and nexthop notifications always announce, so between dumps the
    /// listener only needs to know that the fingerprint is stale.
    policy: Option<u64>,
}

impl EndpointBooks {
    /// Read the host's current addresses, routes, rules and nexthops. Open the subscription
    /// first: a change between the two is then either in the dump or delivered after it.
    ///
    /// Never fails: a book whose read fails starts empty, and the returned flag is false, so a
    /// caller comparing against it knows the read was incomplete.
    fn dump(interface_index: u32) -> (Self, bool) {
        let addresses = AddressBook::dump(interface_index);
        let routes = RouteBook::dump(interface_index);
        let policy = policy_fingerprint();
        let complete = addresses.is_ok() && routes.is_ok() && policy.is_some();
        (
            Self {
                addresses: addresses.unwrap_or_default(),
                routes: routes.unwrap_or_default(),
                policy,
            },
            complete,
        )
    }

    /// Classify one notification: whether it moves peer route budgets, our own endpoint, or both.
    ///
    /// Everything that moves a route budget can also move our endpoint: a new route or rule can
    /// pick another source address or interface, and Linux installs an address's connected
    /// route only after it announces the address (J561 measured a keepalive sent on the address
    /// notice alone failing with `ENETUNREACH`), so the route notice must announce again. A
    /// route notice announces only when the [`RouteBook`] says the route really changed: an
    /// IPv6 router advertisement handled in user space re-installs the default route with a new
    /// lifetime every time (#483 J707 P2). Route budgets follow the same book, so that
    /// refresh doesn't make the next live refresh re-derive every peer either (#483 J780); the
    /// book also counts a change of the route's MTU metric for budgets, since budgets read it.
    /// An address change moves the endpoint only; route budgets follow the routes it brings.
    /// Our own link never counts.
    /// # Errors
    /// Returns `InvalidData` for a truncated link, address or route message.
    fn observe(
        &mut self,
        message: &netlink::Message<'_>,
        interface_index: u32,
    ) -> io::Result<UnderlayChange> {
        let mut route_budgets = is_underlay_change(message, interface_index)?;
        let address = self.addresses.observe(message, interface_index)?;
        let endpoint = match message.kind {
            RTM_NEWROUTE | RTM_DELROUTE => {
                let change = self.routes.observe(message, interface_index)?;
                route_budgets = change.route_budgets;
                change.endpoint
            }
            RTM_NEWLINK | RTM_DELLINK => {
                if route_budgets {
                    self.routes
                        .forget_link(netlink::u32_at(message.payload, 4)?);
                }
                route_budgets
            }
            RTM_NEWNEXTHOP | RTM_DELNEXTHOP => {
                self.routes.forget_link(0);
                self.policy = None;
                true
            }
            RTM_NEWRULE | RTM_DELRULE => {
                self.policy = None;
                true
            }
            _ => route_budgets,
        };
        Ok(UnderlayChange {
            route_budgets,
            endpoint: endpoint || address,
        })
    }

    /// Notifications were lost (`ENOBUFS`), so the books may miss changes: read them again and
    /// say whether anything that can move our endpoint differs from what was known. An
    /// incomplete read counts as a change, which costs an extra announcement, never a missed
    /// one.
    ///
    /// Known limit: every overflow recovery re-dumps every route table, even when the route book is
    /// `untracked` (past 65,536 routes). A host carrying a full BGP table would re-dump about a
    /// million routes per overflow cycle under sustained churn; a mesh node is not that host.
    /// If it matters, skip the route dump while untracked.
    fn resync(&mut self, interface_index: u32) -> bool {
        let (fresh, complete) = Self::dump(interface_index);
        let changed = !complete
            || self.policy.is_none()
            || fresh.policy != self.policy
            || fresh.addresses != self.addresses
            || !fresh.routes.same_endpoints(&self.routes);
        *self = fresh;
        changed
    }
}

/// Hash the host's policy rules and nexthop objects as the kernel dumps them, or `None` if a
/// dump fails. Neither carries lifetimes or counters, so equal state hashes equal. Kernels
/// without nexthop objects (before 5.3) refuse that dump; they have none to hash.
fn policy_fingerprint() -> Option<u64> {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let mut socket = Socket::open(SockProtocol::NetlinkRoute).ok()?;
    socket
        .visit(RTM_GETRULE, NLM_F_DUMP, &[0; 12], |reply| {
            reply.hash(&mut hasher);
            Ok(())
        })
        .ok()?;
    0xff_u8.hash(&mut hasher);
    match socket.visit(RTM_GETNEXTHOP, NLM_F_DUMP, &[0; 8], |reply| {
        reply.hash(&mut hasher);
        Ok(())
    }) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(nix::libc::EOPNOTSUPP) => {}
        Err(_) => return None,
    }
    Some(hasher.finish())
}

/// The host's routes outside the mesh link, as the kernel last reported them (#483 J707 P2).
///
/// The kernel sends `RTM_NEWROUTE` for a new route and also when a route is replaced by an
/// identical one with a new lifetime. A user-space IPv6 router-advertisement client (the
/// default on many server distributions) does that to its default route on every
/// advertisement, so counting every route notice woke every live session per advertisement.
/// The book keys each route by what identifies it to the kernel (family, table, destination and
/// source prefixes, type of service, metric, and whether it is a cached exception) and keeps a
/// fingerprint of what decides where it sends: its type, gateway or `via`, output link,
/// preferred source, router preference, nexthop flags, nexthop object or multipath set, and
/// encapsulation. Lifetimes (`RTA_EXPIRES`, `RTA_CACHEINFO`), metrics such as the MTU, and the
/// protocol that installed the route are left out: none of them moves our endpoint.
///
/// Peer route budgets read one more thing, the route's MTU metric (`RTAX_MTU`), so the book
/// keeps it beside the fingerprint and reports a change of it as a budget change only (#483
/// J780). A lifetime refresh moves neither.
///
/// Both are kept as 64-bit hashes, about 24 bytes a route (the MTU metric fills what was
/// padding), so the book costs kilobytes on a normal host. A router with a full table would
/// cost more, so past [`ROUTE_BOOK_LIMIT`] routes the book stops tracking and every route
/// notice counts again, as before the book existed.
///
/// IPv4 removes the routes of a link that goes down without telling anyone, so a link notice
/// forgets the routes out of that link; the next time one is added, it counts. Routes that
/// leave through several links or a nexthop object are forgotten on any link or nexthop
/// notice, for the same reason.
#[derive(Debug, Default)]
struct RouteBook {
    /// Route identity hash → what the book knows about that route. Siblings added to one route
    /// (multipath appends) fold into one entry.
    known: std::collections::HashMap<u64, KnownRoute>,
    /// Set once the host had more than [`ROUTE_BOOK_LIMIT`] routes: then every notice counts.
    untracked: bool,
}

/// What a [`RouteBook`] keeps for one route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KnownRoute {
    /// Its one output link, or 0 when it leaves through a nexthop object or several links.
    link: u32,
    /// Its `RTAX_MTU` metric, or 0 without one: a peer route budget is capped by it.
    mtu: u32,
    /// The fingerprint of where it sends (see [`RouteBook`]).
    target: u64,
}

/// The most routes a [`RouteBook`] tracks, about 3 MB at the limit. Far above a mesh node's
/// own few dozen routes; a host past it is a router carrying a large table.
const ROUTE_BOOK_LIMIT: usize = 65_536;

impl RouteBook {
    /// Read every current route outside the mesh link, in every table and both families.
    /// # Errors
    /// Returns socket, dump (including an interrupted dump) or malformed-reply errors.
    fn dump(interface_index: u32) -> io::Result<Self> {
        let mut book = Self::default();
        Socket::open(SockProtocol::NetlinkRoute)?.visit(
            RTM_GETROUTE,
            NLM_F_DUMP,
            &[0; 12],
            |reply| book.record(true, 0, reply, interface_index).map(|_| ()),
        )?;
        Ok(book)
    }

    /// Record one route notification and say what it changed outside the mesh link: where a
    /// route sends (our endpoint and peer budgets) or only its MTU metric (budgets only).
    /// # Errors
    /// Returns `InvalidData` for a truncated route message.
    fn observe(
        &mut self,
        message: &netlink::Message<'_>,
        interface_index: u32,
    ) -> io::Result<UnderlayChange> {
        self.record(
            message.kind == RTM_NEWROUTE,
            message.flags,
            message.payload,
            interface_index,
        )
    }

    /// Apply one `rtmsg` payload with its netlink `flags`: an add, refresh or replace when
    /// `present`, a removal otherwise. Returns what it changed.
    ///
    /// A removal always counts and forgets the whole route, siblings included, so a later add
    /// of any of them counts too. A replace (`NLM_F_REPLACE`, which every kernel replace
    /// notice carries) moves the endpoint only if the fingerprint differs, and budgets only if
    /// the fingerprint or the MTU metric differs; a lifetime refresh moves neither. A notice
    /// for a known route without `NLM_F_REPLACE` and with another fingerprint is a sibling
    /// joining a multipath route. Our own link's routes and other families change nothing.
    fn record(
        &mut self,
        present: bool,
        flags: u16,
        payload: &[u8],
        interface_index: u32,
    ) -> io::Result<UnderlayChange> {
        /// Both kinds of change: anything the book can't rule out.
        const EVERYTHING: UnderlayChange = UnderlayChange {
            route_budgets: true,
            endpoint: true,
        };
        use std::hash::{Hash, Hasher};
        let header = payload.get(..12).ok_or(io::ErrorKind::InvalidData)?;
        if !matches!(header[0], 2 | 10) {
            // Multicast route tables (in a dump only) and other families carry no endpoint.
            return Ok(UnderlayChange::default());
        }
        let route_flags = netlink::u32_at(header, 8)?;
        let mut table = u32::from(header[4]);
        let (mut destination, mut source, mut priority) = (None, None, None);
        let (mut link, mut fanout, mut mtu) = (None, false, 0);
        let mut target = std::collections::hash_map::DefaultHasher::new();
        // The type and the nexthop flags that make a route unusable or bind it to its link.
        (header[7], route_flags & RTNH_LIVENESS_FLAGS).hash(&mut target);
        for field in netlink::attributes(&payload[12..])? {
            match field.kind {
                RTA_DST => destination = Some(field.payload),
                RTA_SRC => source = Some(field.payload),
                RTA_PRIORITY => priority = Some(field.payload),
                RTA_TABLE => table = netlink::u32_at(field.payload, 0)?,
                RTA_OIF => {
                    let index = netlink::u32_at(field.payload, 0)?;
                    if index == interface_index {
                        return Ok(UnderlayChange::default());
                    }
                    link = Some(index);
                    (field.kind, index).hash(&mut target);
                }
                RTA_MULTIPATH | RTA_NH_ID => {
                    fanout = true;
                    (field.kind, field.payload).hash(&mut target);
                }
                RTA_GATEWAY | RTA_PREFSRC | RTA_VIA | RTA_PREF | RTA_ENCAP_TYPE | RTA_ENCAP => {
                    (field.kind, field.payload).hash(&mut target);
                }
                RTA_METRICS => mtu = route_mtu_metric(field.payload)?,
                _ => {}
            }
        }
        let mut identity = std::collections::hash_map::DefaultHasher::new();
        (header[0], header[1], header[2], header[3], table).hash(&mut identity);
        (destination, source, priority).hash(&mut identity);
        (route_flags & RTM_F_CLONED).hash(&mut identity);
        let route = KnownRoute {
            link: if fanout { 0 } else { link.unwrap_or(0) },
            mtu,
            target: target.finish(),
        };
        let identity = identity.finish();
        if self.untracked {
            return Ok(EVERYTHING);
        }
        if !present {
            self.known.remove(&identity);
            return Ok(EVERYTHING);
        }
        let known_count = self.known.len();
        match self.known.entry(identity) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let known = *entry.get();
                if known.target == route.target {
                    entry.insert(route);
                    Ok(UnderlayChange {
                        route_budgets: known.mtu != route.mtu,
                        endpoint: false,
                    })
                } else if flags & NLM_F_REPLACE != 0 {
                    entry.insert(route);
                    Ok(EVERYTHING)
                } else {
                    entry.insert(KnownRoute {
                        link: if known.link == route.link {
                            route.link
                        } else {
                            0
                        },
                        mtu: known.mtu.max(route.mtu),
                        target: known.target.wrapping_add(route.target),
                    });
                    Ok(EVERYTHING)
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                if known_count >= ROUTE_BOOK_LIMIT {
                    self.known = std::collections::HashMap::new();
                    self.untracked = true;
                } else {
                    entry.insert(route);
                }
                Ok(EVERYTHING)
            }
        }
    }

    /// Whether `self` and `other` hold the same routes sending to the same places, ignoring MTU
    /// metrics: what the overflow resync compares, since only that moves our endpoint (D81).
    fn same_endpoints(&self, other: &Self) -> bool {
        self.untracked == other.untracked
            && self.known.len() == other.known.len()
            && self.known.iter().all(|(identity, route)| {
                other
                    .known
                    .get(identity)
                    .is_some_and(|known| (known.link, known.target) == (route.link, route.target))
            })
    }

    /// Forget the routes out of `link`, and every route that leaves through several links or a
    /// nexthop object, so their next add counts. `link` 0 forgets only the latter.
    fn forget_link(&mut self, link: u32) {
        self.known
            .retain(|_, known| known.link != 0 && known.link != link);
    }
}

/// One interface address as the kernel identifies it: link, family, prefix length, the local
/// address (`IFA_LOCAL`) and the address or point-to-point peer (`IFA_ADDRESS`).
type AddressKey = (u32, u8, u8, Option<IpAddr>, Option<IpAddr>);

/// The host's interface addresses outside the mesh link, with their flags, as the kernel last
/// reported them (#483 J633 P1).
///
/// The kernel sends `RTM_NEWADDR` both for a new address and for every lifetime refresh of an
/// existing one, which DHCP renewals and IPv6 router advertisements do all day. Only a new
/// address, a flag change (such as the end of IPv6 duplicate address detection, or an address
/// becoming deprecated) or a removal can move our endpoint, so only those count. The book is
/// seeded from a dump when the listener opens and rebuilt after lost notifications. Adding host
/// addresses needs `CAP_NET_ADMIN`, so its size is the host's own address count.
#[derive(Debug, Default, PartialEq, Eq)]
struct AddressBook {
    /// Each known address's flags (`IFA_FLAGS`, or the header's 8-bit flags without it), in the
    /// change book both platforms share.
    known: crate::underlay_announce::ChangeBook<AddressKey, u32>,
}

impl AddressBook {
    /// Read every current address outside the mesh link, so a later refresh of one of them is
    /// recognised as a refresh. Open the subscription first: a change between the two is then
    /// either in the dump or delivered after it.
    /// # Errors
    /// Returns socket, dump or malformed-reply errors.
    fn dump(interface_index: u32) -> io::Result<Self> {
        let mut book = Self::default();
        Socket::open(SockProtocol::NetlinkRoute)?.visit(
            RTM_GETADDR,
            NLM_F_DUMP,
            &[0; 8],
            |reply| book.record(true, reply, interface_index).map(|_| ()),
        )?;
        Ok(book)
    }

    /// Record one notification and say whether it changed an address outside the mesh link.
    /// # Errors
    /// Returns `InvalidData` for a truncated address message.
    fn observe(
        &mut self,
        message: &netlink::Message<'_>,
        interface_index: u32,
    ) -> io::Result<bool> {
        match message.kind {
            RTM_NEWADDR => self.record(true, message.payload, interface_index),
            RTM_DELADDR => self.record(false, message.payload, interface_index),
            _ => Ok(false),
        }
    }

    /// Apply one `ifaddrmsg` payload: an add or update when `present`, a removal otherwise.
    /// Returns whether it changed anything; a removal always counts, known or not.
    fn record(&mut self, present: bool, payload: &[u8], interface_index: u32) -> io::Result<bool> {
        let header = payload.get(..8).ok_or(io::ErrorKind::InvalidData)?;
        let index = netlink::u32_at(header, 4)?;
        if index == interface_index {
            return Ok(false);
        }
        let (family, prefix) = (header[0], header[1]);
        let mut flags = u32::from(header[2]);
        let (mut local, mut address) = (None, None);
        for field in netlink::attributes(&payload[8..])? {
            match field.kind {
                IFA_ADDRESS => address = interface_ip(family, field.payload),
                IFA_LOCAL => local = interface_ip(family, field.payload),
                IFA_FLAGS => flags = netlink::u32_at(field.payload, 0)?,
                _ => {}
            }
        }
        let key = (index, family, prefix, local, address);
        if present {
            Ok(self.known.present(key, flags))
        } else {
            Ok(self.known.absent(&key))
        }
    }
}

/// Decode an interface address attribute of `family`; anything else is `None`.
fn interface_ip(family: u8, bytes: &[u8]) -> Option<IpAddr> {
    match family {
        2 => <[u8; 4]>::try_from(bytes).ok().map(IpAddr::from),
        10 => <[u8; 16]>::try_from(bytes).ok().map(IpAddr::from),
        _ => None,
    }
}

/// Builds the payload of one subnet route (D197 M3): `network` through the mesh link `interface_index`
/// in the main table, link scope, the mesh route protocol, and `source` (this node's mesh IPv4) as the
/// preferred source, so connections to the network leave with the address the router's peers know.
/// # Errors
/// Only attribute encoding errors; IPv6 networks are never routed in this slice.
fn network_route_payload(
    network: crate::policy::networks::Network,
    interface_index: u32,
    source: Option<std::net::Ipv4Addr>,
) -> io::Result<Vec<u8>> {
    let std::net::IpAddr::V4(destination) = network.address() else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    let mut payload = vec![
        2,
        network.prefix(),
        0,
        0,
        254,
        RTPROT_INFRATERNAL,
        253,
        1,
        0,
        0,
        0,
        0,
    ];
    attribute(&mut payload, 1, &destination.octets())?;
    attribute(&mut payload, 4, &interface_index.to_ne_bytes())?;
    if let Some(source) = source {
        attribute(&mut payload, RTA_PREFSRC, &source.octets())?;
    }
    Ok(payload)
}

/// Writes peer host routes (both families, one MTU metric) on one mesh link index.
///
/// One writer serves one batch: it shares a route-netlink socket across the batch and reads the
/// link's IPv6 state once at the start. When the kernel refuses an IPv6 route because IPv6 was
/// turned off on the link meanwhile (#578), the writer stops writing IPv6 routes for the rest
/// of the batch instead of failing it. Each write is a create-or-replace of a route with the
/// mesh route protocol, so writing the same route again is harmless, only wasted work.
pub(crate) struct PeerRouteWriter {
    /// The route-netlink socket every write of the batch uses.
    socket: Socket,
    /// Registers the socket with the listener on the first write, if the batch writes anything.
    underlay: Option<std::sync::Arc<UnderlayWatch>>,
    /// The link index every route of the batch goes to.
    ifindex: u32,
    /// Whether the link carries IPv6, as last observed by this writer.
    ipv6: bool,
}

impl PeerRouteWriter {
    /// Open a writer for link `ifindex` and read whether that link carries IPv6.
    /// # Errors
    /// Reports a socket error or an unreadable link.
    fn open(ifindex: u32, underlay: Option<std::sync::Arc<UnderlayWatch>>) -> io::Result<Self> {
        let mut socket = Socket::open(SockProtocol::NetlinkRoute)?;
        let ipv6 = ipv6_enabled_on(&mut socket, ifindex)?;
        Ok(Self {
            socket,
            underlay,
            ifindex,
            ipv6,
        })
    }

    /// The link index this writer writes to.
    pub(crate) fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Whether the link carried IPv6 at the last observation; while it does not, no IPv6 route
    /// is written and none exists on the link.
    pub(crate) fn ipv6(&self) -> bool {
        self.ipv6
    }

    /// Whether a route write for `peer` installs its IPv6 host route too: only on an IPv6 link,
    /// and never for an IPv4-only peer (#578, J1142).
    pub(crate) fn writes_ipv6_for(&self, peer: &Peer) -> bool {
        self.ipv6 && !peer.ipv4_only
    }

    /// Create or replace `peer`'s IPv4 host route, and its IPv6 one where
    /// [`PeerRouteWriter::writes_ipv6_for`] says so, with the MTU metric `mtu`.
    /// # Errors
    /// Returns route-netlink errors; IPv6 being turned off during the write is not one.
    pub(crate) fn replace(&mut self, peer: &Peer, mtu: u16) -> io::Result<()> {
        if let Some(underlay) = self.underlay.take() {
            underlay.ignore_route_adds(&self.socket);
        }
        for (family, prefix, address) in [
            (2_u8, 32, peer.addresses.ipv4.octets().to_vec()),
            (10, 128, peer.addresses.ipv6.octets().to_vec()),
        ] {
            if family == 10 && !self.writes_ipv6_for(peer) {
                continue;
            }
            let payload = peer_route_payload(family, prefix, &address, self.ifindex, Some(mtu))?;
            if let Err(error) = self.socket.request(24, 4 | 0x100 | 0x400, &payload) {
                if !ipv6_turned_off(&mut self.socket, self.ifindex, family, &error)? {
                    return Err(error);
                }
                self.ipv6 = false;
            }
        }
        Ok(())
    }
}

/// Builds the exact host-route payload used for installing, removing, or repairing a peer route.
///
/// The IPv6 scope is sent as link scope, which the kernel normalizes to universe scope for host
/// routes. The MTU remains unlocked so later path-MTU information can refine it.
/// # Errors
/// Rejects an address family and byte length that do not describe an IPv4 or IPv6 host route.
fn peer_route_payload(
    family: u8,
    prefix: u8,
    destination: &[u8],
    interface_index: u32,
    mtu: Option<u16>,
) -> io::Result<Vec<u8>> {
    if !matches!(
        (family, prefix, destination.len()),
        (2, 32, 4) | (10, 128, 16)
    ) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut payload = vec![
        family,
        prefix,
        0,
        0,
        254,
        RTPROT_INFRATERNAL,
        253,
        1,
        0,
        0,
        0,
        0,
    ];
    attribute(&mut payload, 1, destination)?;
    attribute(&mut payload, 4, &interface_index.to_ne_bytes())?;
    if let Some(mtu) = mtu {
        let mut metrics = Vec::new();
        attribute(&mut metrics, RTAX_MTU, &u32::from(mtu).to_ne_bytes())?;
        attribute(&mut payload, RTA_METRICS | NLA_F_NESTED, &metrics)?;
    }
    Ok(payload)
}

/// Whether one link, route, policy-rule or nexthop notification may change a peer endpoint's
/// underlay MTU.
///
/// Our own link's announcements (its MTU follows the peer budgets) and routes out of our own link
/// (our peer host routes, whatever flags the kernel reports on them, such as `linkdown`) are the
/// results of a refresh, not inputs to it: counting them would make each refresh that writes
/// schedule a full re-derivation. A route out of the mesh link cannot carry the underlay to a
/// peer endpoint either. Everything else counts, because any other link or route can sit on the
/// path to some peer's endpoint. Every rule and nexthop change counts too (#489 J609): a rule
/// can send an endpoint to another table, and a nexthop replacement re-points every route that
/// refers to it; the mesh writes neither, so no refresh can feed back into the watch.
/// # Errors
/// Returns `InvalidData` for a truncated link or route message.
fn is_underlay_change(message: &netlink::Message<'_>, interface_index: u32) -> io::Result<bool> {
    match message.kind {
        // RTM_NEWLINK, RTM_DELLINK: `ifinfomsg` holds the link index at bytes 4..8.
        16 | 17 => Ok(netlink::u32_at(message.payload, 4)? != interface_index),
        // RTM_NEWROUTE, RTM_DELROUTE: `rtmsg` is 12 bytes, then attributes; RTA_OIF is type 4.
        24 | 25 => {
            let attributes = message
                .payload
                .get(12..)
                .ok_or(io::ErrorKind::InvalidData)?;
            for field in netlink::attributes(attributes)? {
                if field.kind == 4 && netlink::u32_at(field.payload, 0)? == interface_index {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        // RTM_NEWRULE, RTM_DELRULE, RTM_NEWNEXTHOP, RTM_DELNEXTHOP.
        32 | 33 | 104 | 105 => Ok(true),
        _ => Ok(false),
    }
}

/// Returns the destination from a protocol-250 host-route deletion on the active mesh interface.
/// # Errors
/// Returns `InvalidData` for a truncated route header or malformed route attributes.
fn deleted_mesh_peer_route(
    message: &netlink::Message<'_>,
    interface_index: u32,
) -> io::Result<Option<IpAddr>> {
    if message.kind != 25 {
        return Ok(None);
    }
    mesh_peer_route_destination(message.payload, interface_index)
}

/// Decode the owned host-route shape shared by deletion events and actual kernel route dumps.
/// Both paths require protocol 250, main table, exact host prefix, scope and original ifindex.
///
/// The route flags must be empty apart from [`ROUTE_CARRIER_FLAGS`]: the kernel marks every
/// route of a link without carrier `linkdown` (and `dead` when it ignores such routes), but the
/// route is still ours and still installed. Refusing it made every full inventory check of a
/// carrier-less link see all peer routes as missing and re-add each one under the route-state
/// lock, and made deletions of such routes go unrepaired (#483 J780). Every other flag, such as
/// a cached exception's `RTM_F_CLONED`, still means the route is not ours.
fn mesh_peer_route_destination(payload: &[u8], interface_index: u32) -> io::Result<Option<IpAddr>> {
    let Some(header) = payload.get(..12) else {
        return Err(io::ErrorKind::InvalidData.into());
    };
    let (address_len, prefix, scope) = match header[0] {
        2 => (4, 32, 253),
        10 => (16, 128, 0),
        _ => return Ok(None),
    };
    if header[1] != prefix
        || header[2] != 0
        || header[3] != 0
        || header[5] != RTPROT_INFRATERNAL
        || header[6] != scope
        || header[7] != 1
        || netlink::u32_at(header, 8)? & !ROUTE_CARRIER_FLAGS != 0
    {
        return Ok(None);
    }
    let mut table = u32::from(header[4]);
    let mut destination = None;
    let mut route_interface = None;
    for field in netlink::attributes(&payload[12..])? {
        match field.kind {
            1 => destination = Some(field.payload),
            4 => route_interface = Some(netlink::u32_at(field.payload, 0)?),
            15 => table = netlink::u32_at(field.payload, 0)?,
            // A subnet fragment can be /32 too. It is never a peer host route.
            RTA_PREFSRC => return Ok(None),
            _ => {}
        }
    }
    if table != 254 || route_interface != Some(interface_index) {
        return Ok(None);
    }
    let Some(destination) = destination.filter(|bytes| bytes.len() == address_len) else {
        return Ok(None);
    };
    let address = match header[0] {
        2 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(destination).map_err(|_| io::ErrorKind::InvalidData)?,
        )),
        10 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(destination).map_err(|_| io::ErrorKind::InvalidData)?,
        )),
        _ => return Ok(None),
    };
    Ok(Some(address))
}

/// Recognize only the single MTU metric this mesh writes on a peer host route.
///
/// Routes from before per-peer MTUs may have no metrics at all; callers accept
/// that legacy shape separately. Extra, repeated, malformed or out-of-range
/// metrics stay foreign so restart cleanup cannot delete an operator route.
/// Linux clears `NLA_F_NESTED` in route dumps, so the `RTA_METRICS` type identifies
/// the nested payload even when that flag is absent.
fn mesh_route_metrics_are_owned(field: netlink::Attribute<'_>) -> bool {
    if field.kind != RTA_METRICS {
        return false;
    }
    let Ok(metrics) = netlink::attributes(field.payload) else {
        return false;
    };
    let [metric] = metrics.as_slice() else {
        return false;
    };
    if metric.kind != RTAX_MTU || metric.nested || metric.payload.len() != 4 {
        return false;
    }
    let Ok(mtu) = netlink::u32_at(metric.payload, 0) else {
        return false;
    };
    (u32::from(mesh_mtu::MIN_MESH_MTU)..=u32::from(u16::MAX)).contains(&mtu)
}

/// Identifies mesh-owned routes so `NetworkManager` can distinguish them from generic static routes.
/// Linux preserves unknown protocol values end to end; value 250 is reserved by infraternal.
const RTPROT_INFRATERNAL: u8 = 250;
/// Identifies generic static routes written by earlier mesh versions during upgrade cleanup.
const RTPROT_LEGACY_STATIC: u8 = 4;
/// Subscribes to link creation, removal and attribute changes, including MTU.
const RTMGRP_LINK: u32 = 0x1;
/// Subscribes to IPv4 address changes: `RTNLGRP_IPV4_IFADDR` (group 5).
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
/// Subscribes to IPv6 address changes: `RTNLGRP_IPV6_IFADDR` (group 9).
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
/// `RTM_NEWADDR`: an address was added, or its flags or lifetimes changed.
const RTM_NEWADDR: u16 = 20;
/// `RTM_DELADDR`: an address was removed.
const RTM_DELADDR: u16 = 21;
/// `RTM_GETADDR`: dump the current addresses.
const RTM_GETADDR: u16 = 22;
/// `IFA_ADDRESS`: the interface address, or the peer's on a point-to-point link.
const IFA_ADDRESS: u16 = 1;
/// `IFA_LOCAL`: the local address on a point-to-point link (IPv4 always sends it).
const IFA_LOCAL: u16 = 2;
/// `IFA_FLAGS`: the full 32-bit address flags; the header holds only the low 8 bits.
const IFA_FLAGS: u16 = 8;
/// `RTM_NEWLINK`: a link appeared or changed.
const RTM_NEWLINK: u16 = 16;
/// `RTM_DELLINK`: a link was removed.
const RTM_DELLINK: u16 = 17;
/// `RTM_NEWROUTE`: a route was added, replaced or refreshed.
const RTM_NEWROUTE: u16 = 24;
/// `RTM_DELROUTE`: a route was removed.
const RTM_DELROUTE: u16 = 25;
/// `RTM_GETROUTE`: asks for the route table (with [`NLM_F_DUMP`]).
const RTM_GETROUTE: u16 = 26;
/// `RTM_NEWRULE`: a policy rule was added.
const RTM_NEWRULE: u16 = 32;
/// `RTM_DELRULE`: a policy rule was removed.
const RTM_DELRULE: u16 = 33;
/// `RTM_GETRULE`: asks for the policy rules (with [`NLM_F_DUMP`]).
const RTM_GETRULE: u16 = 34;
/// `RTM_NEWNEXTHOP`: a nexthop object was added or replaced.
const RTM_NEWNEXTHOP: u16 = 104;
/// `RTM_DELNEXTHOP`: a nexthop object was removed.
const RTM_DELNEXTHOP: u16 = 105;
/// `RTM_GETNEXTHOP`: asks for the nexthop objects (with [`NLM_F_DUMP`]).
const RTM_GETNEXTHOP: u16 = 106;
/// `NLM_F_REPLACE`: on a route notice, the route replaced an existing one with the same key.
const NLM_F_REPLACE: u16 = 0x100;
/// `NLM_F_DUMP` (`NLM_F_ROOT | NLM_F_MATCH`): return every object of the requested kind.
const NLM_F_DUMP: u16 = 0x300;
/// `RTM_F_CLONED`: the route is a cached exception (a learned path MTU or redirect).
const RTM_F_CLONED: u32 = 0x200;
/// `RTNH_F_DEAD | RTNH_F_ONLINK | RTNH_F_LINKDOWN`: the nexthop flags in `rtm_flags` that make a
/// route unusable or bind it to its link. The offload and trap flags are hardware bookkeeping.
const RTNH_LIVENESS_FLAGS: u32 = 0x1 | 0x4 | 0x10;
/// `RTNH_F_DEAD | RTNH_F_LINKDOWN`: the flags the kernel sets on every route of a link without
/// carrier. They say the link can't carry traffic now, not that the route is someone else's.
const ROUTE_CARRIER_FLAGS: u32 = 0x1 | 0x10;
/// Read the `RTAX_MTU` metric from a route's `RTA_METRICS` payload, or 0 when it has none.
/// # Errors
/// Returns `InvalidData` for malformed nested metrics.
fn route_mtu_metric(metrics: &[u8]) -> io::Result<u32> {
    for metric in netlink::attributes(metrics)? {
        if metric.kind == RTAX_MTU {
            return netlink::u32_at(metric.payload, 0);
        }
    }
    Ok(0)
}
/// `RTA_DST`: the route's destination prefix.
const RTA_DST: u16 = 1;
/// `RTA_SRC`: the route's source prefix (IPv6 source routing).
const RTA_SRC: u16 = 2;
/// `RTA_OIF`: the route's output link index.
const RTA_OIF: u16 = 4;
/// `RTA_GATEWAY`: the route's next-hop address.
const RTA_GATEWAY: u16 = 5;
/// `RTA_PRIORITY`: the route's metric.
const RTA_PRIORITY: u16 = 6;
/// `RTA_PREFSRC`: the source address the route prefers.
const RTA_PREFSRC: u16 = 7;
/// `RTA_MULTIPATH`: the route's nexthops when it has several.
const RTA_MULTIPATH: u16 = 9;
/// `RTA_TABLE`: the route's table, when it does not fit the header's 8 bits.
const RTA_TABLE: u16 = 15;
/// `RTA_VIA`: a next hop in another address family.
const RTA_VIA: u16 = 18;
/// `RTA_PREF`: the IPv6 router preference from a router advertisement.
const RTA_PREF: u16 = 20;
/// `RTA_ENCAP_TYPE`: the lightweight tunnel encapsulation type.
const RTA_ENCAP_TYPE: u16 = 21;
/// `RTA_ENCAP`: the lightweight tunnel encapsulation.
const RTA_ENCAP: u16 = 22;
/// `RTA_NH_ID`: the nexthop object the route uses.
const RTA_NH_ID: u16 = 30;
/// Subscribes to IPv4 unicast route changes in the main route table.
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
/// Subscribes to IPv6 unicast route changes in the main route table.
const RTMGRP_IPV6_ROUTE: u32 = 0x400;
/// Subscribes to IPv4 policy-rule changes: `RTNLGRP_IPV4_RULE` (group 8), bit `1 << 7`.
const RTMGRP_IPV4_RULE: u32 = 0x80;
/// Subscribes to IPv6 policy-rule changes: `RTNLGRP_IPV6_RULE` (group 19), bit `1 << 18`. The
/// legacy `RTMGRP_*` macros stop before it, so it is derived from the group number.
const RTMGRP_IPV6_RULE: u32 = 1 << (19 - 1);
/// Subscribes to nexthop object changes: `RTNLGRP_NEXTHOP` (group 32), the last group the
/// 32-bit bind mask can still express, bit `1 << 31`.
const RTMGRP_NEXTHOP: u32 = 1 << (32 - 1);
/// `RTA_METRICS`: nested per-route metrics accepted by rtnetlink.
const RTA_METRICS: u16 = 8;
/// `RTAX_MTU`: the per-peer inner packet limit stored on a mesh host route.
const RTAX_MTU: u16 = 2;
/// Marks the route metrics payload as a nested netlink attribute.
const NLA_F_NESTED: u16 = 1 << 15;
/// Decode `WGPEER_A_ENDPOINT`: a kernel `sockaddr_in` (16 bytes) or
/// `sockaddr_in6` (28 bytes). Family and scope are native-endian, port and
/// flow information network order. Any other size or family is refused.
fn decode_sockaddr(payload: &[u8]) -> io::Result<SocketAddr> {
    let family = u16::from_ne_bytes(
        payload
            .get(..2)
            .ok_or(io::ErrorKind::InvalidData)?
            .try_into()
            .map_err(io::Error::other)?,
    );
    let port = u16::from_be_bytes(
        payload
            .get(2..4)
            .ok_or(io::ErrorKind::InvalidData)?
            .try_into()
            .map_err(io::Error::other)?,
    );
    match (family, payload.len()) {
        (2, 16) => {
            let octets: [u8; 4] = payload[4..8].try_into().map_err(io::Error::other)?;
            Ok(SocketAddr::new(Ipv4Addr::from(octets).into(), port))
        }
        (10, 28) => {
            let octets: [u8; 16] = payload[8..24].try_into().map_err(io::Error::other)?;
            let flow = u32::from_be_bytes(payload[4..8].try_into().map_err(io::Error::other)?);
            let scope = u32::from_ne_bytes(payload[24..28].try_into().map_err(io::Error::other)?);
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                flow,
                scope,
            )))
        }
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}
fn scalar64(payload: &[u8]) -> io::Result<u64> {
    Ok(u64::from_ne_bytes(
        payload
            .get(..8)
            .ok_or(io::ErrorKind::InvalidData)?
            .try_into()
            .map_err(io::Error::other)?,
    ))
}

/// Kernel timespec64 has two native-endian 64-bit fields.
#[cfg(feature = "relay")]
fn handshake_nanos(payload: &[u8]) -> io::Result<u32> {
    if payload.len() != 16 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let nanos = u32::try_from(scalar64(&payload[8..])?).map_err(|_| io::ErrorKind::InvalidData)?;
    if nanos >= 1_000_000_000 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(nanos)
}

#[cfg(all(test, feature = "relay"))]
mod timestamp_tests {
    //! Checks kernel handshake precision without accepting truncated or invalid timespecs.
    use super::*;

    #[test]
    fn handshake_timestamp_keeps_subsecond_precision() {
        let mut payload = 1_791_870_000_u64.to_ne_bytes().to_vec();
        payload.extend_from_slice(&987_654_321_u64.to_ne_bytes());
        assert_eq!(handshake_nanos(&payload).ok(), Some(987_654_321));
    }

    #[test]
    fn handshake_timestamp_refuses_invalid_timespecs() {
        assert!(handshake_nanos(&[0; 8]).is_err());
        assert!(handshake_nanos(&[0; 17]).is_err());
        for nanos in [1_000_000_000_u64, u64::MAX] {
            let mut payload = 0_u64.to_ne_bytes().to_vec();
            payload.extend_from_slice(&nanos.to_ne_bytes());
            assert!(handshake_nanos(&payload).is_err());
        }
    }
}
/// Bring one link up and optionally set its MTU in the same route-netlink request.
///
/// Passing `None` preserves the current MTU, which is useful while reallocating a listen port.
/// # Errors
/// Reports route-netlink encoding or kernel configuration failures.
fn activate(index: u32, mtu: Option<u16>) -> io::Result<()> {
    let mut payload = vec![0; 16];
    payload[4..8].copy_from_slice(&index.to_ne_bytes());
    payload[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    payload[12..16].copy_from_slice(&1_u32.to_ne_bytes());
    if let Some(mtu) = mtu {
        attribute(&mut payload, IFLA_MTU, &u32::from(mtu).to_ne_bytes())?;
    }
    Socket::open(SockProtocol::NetlinkRoute)?.request(16, 4, &payload)?;
    Ok(())
}
/// `IFLA_MTU`: the interface's link-layer packet size.
const IFLA_MTU: u16 = 4;
/// Change the MTU on one link index without resolving its shared name again.
fn set_link_mtu(index: u32, mtu: u32) -> io::Result<()> {
    let mut payload = vec![0; 16];
    payload[4..8].copy_from_slice(&index.to_ne_bytes());
    attribute(&mut payload, IFLA_MTU, &mtu.to_ne_bytes())?;
    Socket::open(SockProtocol::NetlinkRoute)?.request(16, 4, &payload)?;
    Ok(())
}
/// Look up the effective route MTU for a peer endpoint, falling back to its egress link MTU.
///
/// An explicit route MTU may be smaller than the interface, so use the lower value. A larger
/// metric is not a usable packet budget because the egress link cannot carry it. `RTM_GETROUTE`
/// and `RTM_GETLINK` are acknowledged requests on `socket`, so a batch of lookups shares one
/// route-netlink socket instead of opening two per peer (#489 J552 P2-2).
/// # Errors
/// Reports an unreachable endpoint, a missing egress link, or malformed kernel replies.
pub(crate) fn route_mtu_on(socket: &mut Socket, endpoint: SocketAddr) -> io::Result<u32> {
    let reply = route_to(socket, endpoint.ip())?;
    let mut output_index = None;
    let mut route_mtu = None;
    for field in netlink::attributes(reply.get(12..).ok_or(io::ErrorKind::InvalidData)?)? {
        match field.kind {
            4 => output_index = Some(netlink::u32_at(field.payload, 0)?),
            8 => {
                for metric in netlink::attributes(field.payload)? {
                    if metric.kind == 2 {
                        route_mtu = Some(netlink::u32_at(metric.payload, 0)?);
                    }
                }
            }
            _ => {}
        }
    }
    let link_mtu = link_mtu_on(socket, output_index.ok_or(io::ErrorKind::NotFound)?)?;
    Ok(route_mtu
        .filter(|mtu| *mtu > 0)
        .map_or(link_mtu, |mtu| mtu.min(link_mtu)))
}

/// The route the kernel currently uses for this destination, including its resolved next hop.
fn route_to(socket: &mut Socket, address: IpAddr) -> io::Result<Zeroizing<Vec<u8>>> {
    let (family, prefix, address) = match address {
        IpAddr::V4(address) => (2_u8, 32_u8, address.octets().to_vec()),
        IpAddr::V6(address) => (10_u8, 128_u8, address.octets().to_vec()),
    };
    let mut request = vec![family, prefix, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    attribute(&mut request, 1, &address)?;
    socket
        .request(RTM_GETROUTE, 4, &request)?
        .into_iter()
        .next()
        .ok_or_else(|| io::ErrorKind::NotFound.into())
}

/// Check whether a prospective direct endpoint would send this tunnel's packets into itself.
/// # Errors
/// Reports a failed route lookup or a missing mesh link.
pub(crate) fn is_tunnel_endpoint(address: IpAddr) -> io::Result<bool> {
    let index = Device::active_link()?
        .ok_or(io::ErrorKind::NotConnected)?
        .ifindex;
    let mut socket = Socket::open(SockProtocol::NetlinkRoute)?;
    let reply = route_to(&mut socket, address.to_canonical())?;
    for field in netlink::attributes(reply.get(12..).ok_or(io::ErrorKind::InvalidData)?)? {
        if field.kind == RTA_OIF {
            return Ok(netlink::u32_at(field.payload, 0)? == index);
        }
    }
    Ok(false)
}

/// Read one link's MTU on a fresh route-netlink socket.
fn link_mtu(index: u32) -> io::Result<u32> {
    link_mtu_on(&mut Socket::open(SockProtocol::NetlinkRoute)?, index)
}

/// Read one egress link's MTU on `socket`, for a route that has no explicit MTU metric.
fn link_mtu_on(socket: &mut Socket, index: u32) -> io::Result<u32> {
    let mut request = vec![0; 16];
    request[4..8].copy_from_slice(&index.to_ne_bytes());
    let replies = socket.request(18, 4, &request)?;
    let reply = replies.first().ok_or(io::ErrorKind::NotFound)?;
    netlink::attributes(reply.get(16..).ok_or(io::ErrorKind::InvalidData)?)?
        .into_iter()
        .find(|field| field.kind == IFLA_MTU)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
        .and_then(|field| netlink::u32_at(field.payload, 0))
}
/// `IFLA_AF_SPEC`: a link's per-address-family settings, one nested block per family.
const IFLA_AF_SPEC: u16 = 26;
/// `AF_INET6`: the IPv6 block inside `IFLA_AF_SPEC`, and the IPv6 address family elsewhere.
const AF_INET6: u16 = 10;
/// `IFLA_INET6_CONF`: inside the IPv6 block, the link's IPv6 sysctls as an `i32` array indexed
/// by `DEVCONF_*`.
const IFLA_INET6_CONF: u16 = 2;
/// `DEVCONF_DISABLE_IPV6`: the slot of `net.ipv6.conf.<link>.disable_ipv6` in that array.
const DEVCONF_DISABLE_IPV6: usize = 26;
/// `EACCES`: the kernel's answer to an IPv6 address or route on a link with IPv6 disabled.
const EACCES: i32 = 13;

/// Whether the link at `ifindex` can carry IPv6 (#578).
///
/// Many hosts turn IPv6 off (`net.ipv6.conf.all.disable_ipv6=1`, which new links inherit
/// through `default`), and the kernel then refuses every IPv6 address and route on the mesh
/// link with `EACCES`. The mesh then runs IPv4-only. The link's own setting is read by index
/// on `socket`, so it is the value for exactly the link we write to, in the caller's network
/// namespace, and never a name lookup that could reach another link.
/// # Errors
/// Reports a missing link or a malformed reply.
fn ipv6_enabled_on(socket: &mut Socket, ifindex: u32) -> io::Result<bool> {
    let mut request = vec![0; 16];
    request[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    let replies = socket.request(18, 4, &request)?;
    let reply = replies.first().ok_or(io::ErrorKind::NotFound)?;
    link_carries_ipv6(reply.get(16..).ok_or(io::ErrorKind::InvalidData)?)
}

/// Read IPv6 availability from a link message's attributes (everything after `ifinfomsg`).
///
/// IPv6 is usable when the `AF_INET6` block's `disable_ipv6` slot is zero. A link message with
/// no `AF_INET6` block means the kernel has no IPv6 at all (`ipv6.disable=1`), which also reads
/// as off. A block without its sysctl array, or an array too short to hold the slot, is
/// malformed: guessing either way could silently drop IPv6 from a host that has it.
/// # Errors
/// Returns `InvalidData` for malformed attributes.
fn link_carries_ipv6(attributes: &[u8]) -> io::Result<bool> {
    for spec in netlink::attributes(attributes)? {
        if spec.kind != IFLA_AF_SPEC {
            continue;
        }
        for family in netlink::attributes(spec.payload)? {
            if family.kind != AF_INET6 {
                continue;
            }
            let conf = netlink::attributes(family.payload)?
                .into_iter()
                .find(|field| field.kind == IFLA_INET6_CONF)
                .ok_or(io::ErrorKind::InvalidData)?;
            return Ok(netlink::u32_at(conf.payload, DEVCONF_DISABLE_IPV6 * 4)? == 0);
        }
    }
    Ok(false)
}

/// Whether a failed IPv6 write failed only because IPv6 was turned off on the link meanwhile.
///
/// The node checks the link before it writes, but `disable_ipv6` can change between the
/// check and the write. A refused IPv6 write that the link now confirms as IPv6-off is
/// skipped like the checked case, rather than refusing the configuration (#578).
/// # Errors
/// Reports a failed re-check of the link.
fn ipv6_turned_off(
    socket: &mut Socket,
    ifindex: u32,
    family: u8,
    error: &io::Error,
) -> io::Result<bool> {
    Ok(u16::from(family) == AF_INET6
        && error.raw_os_error() == Some(EACCES)
        && !ipv6_enabled_on(socket, ifindex)?)
}
/// `IFLA_TXQLEN`: a link's transmit queue length, in packets.
const IFLA_TXQLEN: u16 = 13;
fn tx_queue_len_of(index: u32) -> io::Result<u32> {
    let mut payload = vec![0; 16];
    payload[4..8].copy_from_slice(&index.to_ne_bytes());
    let replies = Socket::open(SockProtocol::NetlinkRoute)?.request(18, 4, &payload)?;
    let reply = replies.first().ok_or(io::ErrorKind::NotFound)?;
    netlink::attributes(reply.get(16..).ok_or(io::ErrorKind::InvalidData)?)?
        .into_iter()
        .find(|field| field.kind == IFLA_TXQLEN)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
        .and_then(|field| netlink::u32_at(field.payload, 0))
}
/// A foreign route's address test, independent of table, interface and other route metadata.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum RoutePrefix {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl RoutePrefix {
    /// Decode a non-default route outside the mesh interface, preserving route dump errors.
    fn from_route(reply: &[u8], owned: u32) -> io::Result<Option<Self>> {
        let header = reply.get(..12).ok_or(io::ErrorKind::InvalidData)?;
        let bits = header[1];
        if bits == 0 {
            return Ok(None);
        }
        let mut interface = None;
        let mut destination = None;
        for field in netlink::attributes(&reply[12..])? {
            match field.kind {
                1 => destination = Some(field.payload),
                4 => interface = Some(netlink::u32_at(field.payload, 0)?),
                _ => {}
            }
        }
        if interface == Some(owned) {
            return Ok(None);
        }
        let destination = destination.ok_or(io::ErrorKind::InvalidData)?;
        match header[0] {
            2 if bits <= 32 && destination.len() == 4 => {
                let mask = u32::MAX << (32 - bits);
                let address = u32::from_be_bytes(destination.try_into().map_err(io::Error::other)?);
                Ok(Some(Self::V4 {
                    network: address & mask,
                    mask,
                }))
            }
            10 if bits <= 128 && destination.len() == 16 => {
                let mask = u128::MAX << (128 - bits);
                let address =
                    u128::from_be_bytes(destination.try_into().map_err(io::Error::other)?);
                Ok(Some(Self::V6 {
                    network: address & mask,
                    mask,
                }))
            }
            2 | 10 => Err(io::ErrorKind::InvalidData.into()),
            _ => Ok(None),
        }
    }

    /// Report whether this route covers the proposed address of its own IP family.
    fn covers(self, address: Addresses) -> bool {
        match self {
            Self::V4 { network, mask } => u32::from(address.ipv4) & mask == network,
            Self::V6 { network, mask } => u128::from(address.ipv6) & mask == network,
        }
    }
}

/// Cache at most a D393 scale snapshot (4,096 peers and the local address) and as many prefixes.
const ROUTE_VALIDATION_CACHE_LIMIT: usize = 4096 + 1;

/// The addresses and foreign prefixes that were checked together on the last successful dump.
///
/// This records validation only, so it stays sound even if apply fails later. Each check rereads
/// the live routes. A new foreign prefix is checked against all proposed addresses even when a
/// snapshot keeps every peer, so an underlay change can still cause the same refusal as a full scan.
/// Larger snapshots use a full scan. Prefixes past the cache limit also get a full scan.
#[derive(Default)]
pub(crate) struct RouteValidation {
    /// Address pairs validated together against every stored prefix.
    addresses: HashSet<Addresses>,
    /// A bounded set of prefixes witnessed in the last successful live dump.
    prefixes: HashSet<RoutePrefix>,
}

impl RouteValidation {
    /// Refuse overlap against the current foreign routes, reusing successful address checks.
    pub(crate) fn check(&mut self, addresses: &[Addresses]) -> io::Result<()> {
        let owned = index()?;
        let cache_addresses = addresses.len() <= ROUTE_VALIDATION_CACHE_LIMIT;
        let mut prefixes = HashSet::new();
        let changed = std::cell::OnceCell::new();
        let mut validation: io::Result<()> = Ok(());
        Socket::open(SockProtocol::NetlinkRoute)?.visit(26, 0x300, &[0; 12], |reply| {
            // Keep the first route error in reply order, but finish the dump. As with
            // a collected dump, a netlink framing error or interruption takes precedence.
            if validation.is_ok() {
                validation = (|| {
                    let Some(prefix) = RoutePrefix::from_route(reply, owned)? else {
                        return Ok(());
                    };
                    let candidates: &[Addresses] =
                        if cache_addresses && self.prefixes.contains(&prefix) {
                            changed.get_or_init(|| {
                                addresses
                                    .iter()
                                    .copied()
                                    .filter(|address| !self.addresses.contains(address))
                                    .collect::<Vec<_>>()
                            })
                        } else {
                            addresses
                        };
                    if candidates.iter().any(|address| prefix.covers(*address)) {
                        return Err(io::ErrorKind::AddrInUse.into());
                    }
                    if cache_addresses && prefixes.len() < ROUTE_VALIDATION_CACHE_LIMIT {
                        prefixes.insert(prefix);
                    }
                    Ok(())
                })();
            }
            Ok(())
        })?;
        validation?;
        self.prefixes = prefixes;
        self.addresses.clear();
        if !self.prefixes.is_empty() {
            self.addresses.extend(addresses.iter().copied());
        }
        Ok(())
    }
}

fn index() -> io::Result<u32> {
    Ok(nix::net::if_::if_nametoindex(INTERFACE)?)
}
fn header() -> Vec<u8> {
    let mut payload = vec![1, 1, 0, 0];
    // This fixed byte string fits the attribute length, so no fallible generic encoder is needed.
    payload.extend(17_u16.to_ne_bytes());
    payload.extend(2_u16.to_ne_bytes());
    payload.extend(b"infraternal0\0");
    payload.resize(24, 0);
    payload
}
/// A `WireGuard` generic-netlink header that addresses the device by interface index
/// (`WGDEVICE_A_IFINDEX`), not by name.
fn header_at(ifindex: u32) -> Vec<u8> {
    let mut payload = vec![1, 1, 0, 0];
    payload.extend(8_u16.to_ne_bytes());
    payload.extend(1_u16.to_ne_bytes());
    payload.extend(ifindex.to_ne_bytes());
    payload
}

/// The public key and listen port of the `WireGuard` device at `ifindex`.
pub(crate) fn identity_at(ifindex: u32) -> io::Result<(PublicKey, u16)> {
    identity_from(header_at(ifindex))
}

/// The public key and listen port from a device dump addressed by `header`. The kernel includes
/// the private key in the dump, so every reply buffer is zeroized on drop.
fn identity_from(mut payload: Vec<u8>) -> io::Result<(PublicKey, u16)> {
    let mut socket = Socket::open(SockProtocol::NetlinkGeneric)?;
    let family = socket.family("wireguard")?;
    payload[0] = 0;
    let mut key = None;
    let mut port = None;
    for reply in socket.request(family, 0x300, &payload)? {
        let reply = Zeroizing::new(reply);
        for field in netlink::attributes(reply.get(4..).ok_or(io::ErrorKind::InvalidData)?)? {
            match field.kind {
                4 if field.payload.len() == 32 => {
                    key = Some(PublicKey(
                        field.payload.try_into().map_err(io::Error::other)?,
                    ));
                }
                6 if field.payload.len() == 2 => {
                    port = Some(u16::from_ne_bytes([field.payload[0], field.payload[1]]));
                }
                _ => {}
            }
        }
    }
    Ok((
        key.ok_or(io::ErrorKind::InvalidData)?,
        port.ok_or(io::ErrorKind::InvalidData)?,
    ))
}

/// Refuse unless the link at `ifindex` is a `WireGuard` link carrying `owner`'s marker.
fn verify_owner(ifindex: u32, owner: PublicKey) -> io::Result<()> {
    verify_engine_owner(ifindex, crate::gotatun_node::EngineKind::Kernel, owner)
}

/// Refuse unless the link at `ifindex` has the selected engine marker for `owner`.
fn verify_engine_owner(
    ifindex: u32,
    engine: crate::gotatun_node::EngineKind,
    owner: PublicKey,
) -> io::Result<()> {
    let (expected_kind, prefix) = match engine {
        crate::gotatun_node::EngineKind::Kernel => (b"wireguard\0".as_slice(), KERNEL_OWNER_PREFIX),
        crate::gotatun_node::EngineKind::GotaTun => (b"tun\0".as_slice(), GOTATUN_OWNER_PREFIX),
    };
    let mut payload = vec![0; 16];
    payload[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    let replies = match Socket::open(SockProtocol::NetlinkRoute)?.request(18, 4, &payload) {
        Ok(replies) => replies,
        Err(error) if error.raw_os_error() == Some(19) => {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Err(error) => return Err(error),
    };
    let reply = replies
        .into_iter()
        .next()
        .ok_or(io::ErrorKind::InvalidData)?;
    let mut alias = None;
    let mut kind = None;
    for field in netlink::attributes(reply.get(16..).ok_or(io::ErrorKind::InvalidData)?)? {
        match field.kind {
            20 => alias = Some(field.payload.to_vec()),
            18 => {
                for info in netlink::attributes(field.payload)? {
                    if info.kind == 1 {
                        kind = Some(info.payload.to_vec());
                    }
                }
            }
            _ => {}
        }
    }
    if netlink::u32_at(&reply, 4)? == ifindex
        && kind.as_deref() == Some(expected_kind)
        && alias.as_deref() == Some(owner_alias(prefix, owner).as_slice())
    {
        Ok(())
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
}

fn send(payload: &[u8]) -> io::Result<()> {
    let mut socket = Socket::open(SockProtocol::NetlinkGeneric)?;
    let family = socket.family("wireguard")?;
    socket.request(family, 4, payload)?;
    Ok(())
}
fn flush(socket: &mut Socket, family: u16, peers: &[u8]) -> io::Result<()> {
    let mut payload = header();
    attribute(&mut payload, 8 | NESTED, peers)?;
    socket.request(family, 4, &payload)?;
    Ok(())
}
fn sockaddr(endpoint: SocketAddr) -> Vec<u8> {
    let mut result = Vec::new();
    match endpoint {
        SocketAddr::V4(addr) => {
            result.extend(2_u16.to_ne_bytes());
            result.extend(addr.port().to_be_bytes());
            result.extend(addr.ip().octets());
            result.resize(16, 0);
        }
        SocketAddr::V6(addr) => {
            result.extend(10_u16.to_ne_bytes());
            result.extend(addr.port().to_be_bytes());
            result.extend(addr.flowinfo().to_be_bytes());
            result.extend(addr.ip().octets());
            result.extend(addr.scope_id().to_ne_bytes());
        }
    }
    result
}

/// Reuses the generic family/socket for incremental updates; idle holds no reader or timer.
pub struct Client {
    socket: Socket,
    family: u16,
}
impl Client {
    /// Resolve `WireGuard` once while enabling the node component.
    /// # Errors
    /// Reports an unavailable kernel family or socket error.
    pub fn new() -> io::Result<Self> {
        let mut socket = Socket::open(SockProtocol::NetlinkGeneric)?;
        let family = socket.family("wireguard")?;
        Ok(Self { socket, family })
    }
    /// Retire every peer on the owned interface, preserving its identity and routes.
    /// # Errors
    /// Reports a failed kernel replacement; callers must retain disabled intent for replay.
    pub fn clear_peers(&mut self) -> io::Result<()> {
        let mut payload = header();
        // WGDEVICE_F_REPLACE_PEERS with no peer list uses the kernel's bulk
        // retirement under the route lock. Deleting a populated link drops
        // that lock before retirement and makes quiescence costly at scale.
        attribute(&mut payload, 5, &1_u32.to_ne_bytes())?;
        self.socket.request(self.family, 4, &payload)?;
        Ok(())
    }
    /// Update only an authenticated peer's direct endpoint, preserving routes and handshake state.
    /// # Errors
    /// Reports a failed kernel update.
    pub fn endpoint(&mut self, key: PublicKey, endpoint: SocketAddr) -> io::Result<()> {
        let mut peer = Vec::new();
        attribute(&mut peer, 1, &key.0)?;
        attribute(&mut peer, 3, &4_u32.to_ne_bytes())?;
        attribute(&mut peer, 4, &sockaddr(endpoint))?;
        let mut peers = Vec::new();
        attribute(&mut peers, 1 | NESTED, &peer)?;
        flush(&mut self.socket, self.family, &peers)
    }
    /// Apply bounded changed/removed peers without replacing unrelated handshake state.
    /// # Errors
    /// Returns kernel or encoding errors; callers fence multi-datagram policy changes.
    pub fn peers(&mut self, upserted: &[Peer], removed: &[PublicKey]) -> io::Result<()> {
        let mut peers = Vec::new();
        for (key, peer) in removed
            .iter()
            .map(|k| (k, None))
            .chain(upserted.iter().flat_map(|peer| {
                peer.previous_key
                    .as_ref()
                    .filter(|previous| **previous != peer.key)
                    .map(|previous| (previous, Some((peer, false))))
                    .into_iter()
                    .chain(std::iter::once((&peer.key, Some((peer, true)))))
            }))
        {
            let mut encoded = Vec::new();
            attribute(&mut encoded, 1, &key.0)?;
            attribute(
                &mut encoded,
                3,
                &if peer.is_some() { 2_u32 } else { 1_u32 }.to_ne_bytes(),
            )?;
            if let Some((peer, current)) = peer {
                // Until the local candidate key is active, keep the route on
                // the old peer identity. The inactive key is still installed
                // so the key switch never precedes its peer configuration.
                let active = current != peer.previous_active;
                // Both ends send, preserving stateful firewall mappings even
                // when only one side currently has application traffic [228].
                if active {
                    attribute(&mut encoded, 5, &25_u16.to_ne_bytes())?;
                    if let Some(endpoint) = peer.endpoint {
                        attribute(&mut encoded, 4, &sockaddr(endpoint))?;
                    }
                }
                if active {
                    let mut allowed = Vec::new();
                    for (family, prefix, address) in [
                        (2_u16, 32, peer.addresses.ipv4.octets().to_vec()),
                        (10, 128, peer.addresses.ipv6.octets().to_vec()),
                    ] {
                        // An IPv4-only peer (#578, J1142) owns no IPv6 allowed IP.
                        if family == 10 && peer.ipv4_only {
                            continue;
                        }
                        let mut ip = Vec::new();
                        attribute(&mut ip, 1, &family.to_ne_bytes())?;
                        attribute(&mut ip, 2, &address)?;
                        attribute(&mut ip, 3, &[prefix])?;
                        attribute(&mut allowed, 1 | NESTED, &ip)?;
                    }
                    attribute(&mut encoded, 9 | NESTED, &allowed)?;
                }
            }
            if peers.len() + encoded.len() + 80 > netlink::DATAGRAM_BYTES {
                flush(&mut self.socket, self.family, &peers)?;
                peers.clear();
            }
            attribute(&mut peers, 1 | NESTED, &encoded)?;
        }
        if !peers.is_empty() {
            flush(&mut self.socket, self.family, &peers)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod endpoint_tests {
    //! The kernel endpoint decoder accepts exactly what `sockaddr` encodes and refuses every other shape.
    use super::*;

    #[test]
    fn kernel_endpoints_round_trip_through_the_encoder() {
        for endpoint in [
            "198.51.100.7:51000".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
            SocketAddr::V6(std::net::SocketAddrV6::new(
                "2001:db8::7".parse().unwrap(),
                65_535,
                0x000a_bcde,
                3,
            )),
        ] {
            assert_eq!(decode_sockaddr(&sockaddr(endpoint)).unwrap(), endpoint);
        }
    }

    /// Endpoint encodings of any other size or family are refused.
    #[test]
    fn other_sizes_and_families_are_refused() {
        let v4 = sockaddr("198.51.100.7:1".parse().unwrap());
        let v6 = sockaddr("[2001:db8::7]:1".parse().unwrap());
        for bad in [&v4[..15], &v6[..27], &v6[..16], &[][..], &[2, 0][..]] {
            assert!(decode_sockaddr(bad).is_err());
        }
        let mut wrong = v4.clone();
        wrong.extend([0; 12]);
        assert!(decode_sockaddr(&wrong).is_err(), "IPv4 family at IPv6 size");
        let mut unknown = v4;
        unknown[..2].copy_from_slice(&1_u16.to_ne_bytes());
        assert!(decode_sockaddr(&unknown).is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod link_ipv6_tests {
    //! Reading a link's IPv6 availability from its `RTM_NEWLINK` attributes (#578).
    use super::*;

    /// Link attributes as the kernel sends them: an MTU, then `IFLA_AF_SPEC` holding an IPv4
    /// block and, when `disable_ipv6` is given, an IPv6 block whose sysctl array has that value
    /// in its `DEVCONF_DISABLE_IPV6` slot (`slots` entries long).
    fn link(disable_ipv6: Option<i32>, slots: usize) -> Vec<u8> {
        let mut families = Vec::new();
        attribute(&mut families, 2, &[0; 8]).unwrap();
        if let Some(disabled) = disable_ipv6 {
            let mut conf = vec![0_u8; slots * 4];
            if slots > DEVCONF_DISABLE_IPV6 {
                conf[DEVCONF_DISABLE_IPV6 * 4..DEVCONF_DISABLE_IPV6 * 4 + 4]
                    .copy_from_slice(&disabled.to_ne_bytes());
            }
            let mut inet6 = Vec::new();
            attribute(&mut inet6, 1, &0_u32.to_ne_bytes()).unwrap();
            attribute(&mut inet6, IFLA_INET6_CONF, &conf).unwrap();
            attribute(&mut families, AF_INET6, &inet6).unwrap();
        }
        let mut attributes = Vec::new();
        attribute(&mut attributes, IFLA_MTU, &1420_u32.to_ne_bytes()).unwrap();
        attribute(&mut attributes, IFLA_AF_SPEC, &families).unwrap();
        attributes
    }

    /// The link's own `disable_ipv6` slot alone decides.
    #[test]
    fn the_disable_ipv6_slot_decides() {
        assert!(link_carries_ipv6(&link(Some(0), 60)).unwrap());
        assert!(!link_carries_ipv6(&link(Some(1), 60)).unwrap());
    }

    /// A link message without an IPv6 block reads as IPv6 off.
    #[test]
    fn a_kernel_without_ipv6_reads_as_off() {
        // `ipv6.disable=1`: the kernel sends no IPv6 block at all.
        assert!(!link_carries_ipv6(&link(None, 0)).unwrap());
    }

    /// A broken IPv6 block is an error, never a guess either way.
    #[test]
    fn a_malformed_ipv6_block_is_refused_rather_than_guessed() {
        // The sysctl array is too short to hold the slot.
        assert!(link_carries_ipv6(&link(Some(0), DEVCONF_DISABLE_IPV6)).is_err());
        // An IPv6 block without its sysctl array.
        let mut inet6 = Vec::new();
        attribute(&mut inet6, 1, &0_u32.to_ne_bytes()).unwrap();
        let mut families = Vec::new();
        attribute(&mut families, AF_INET6, &inet6).unwrap();
        let mut attributes = Vec::new();
        attribute(&mut attributes, IFLA_AF_SPEC, &families).unwrap();
        assert!(link_carries_ipv6(&attributes).is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod peer_route_shape_tests {
    //! Which route messages count as one of our peer host routes, in dumps and deletions.
    use super::*;

    /// Our IPv4 and IPv6 peer route payloads on link 7, with `flags` in `rtm_flags`.
    fn our_routes(flags: u32) -> [Vec<u8>; 2] {
        [
            (2, 32, vec![10, 200, 0, 1]),
            (
                10,
                128,
                "fd02::2".parse::<Ipv6Addr>().unwrap().octets().to_vec(),
            ),
        ]
        .map(|(family, prefix, address)| {
            let mut payload = peer_route_payload(family, prefix, &address, 7, Some(1408)).unwrap();
            // The kernel reports IPv6 host routes at universe scope.
            if family == 10 {
                payload[6] = 0;
            }
            payload[8..12].copy_from_slice(&flags.to_ne_bytes());
            payload
        })
    }

    /// A carrier-less link's routes (`linkdown`, `dead`) are still ours (#483 J780): refusing
    /// them made each full inventory check re-add every peer route under the state lock.
    #[test]
    fn carrier_flags_keep_a_route_ours() {
        for flags in [0, 0x10, 0x1 | 0x10] {
            for payload in our_routes(flags) {
                assert!(
                    mesh_peer_route_destination(&payload, 7).unwrap().is_some(),
                    "flags {flags:#x}"
                );
                assert!(mesh_peer_route_destination(&payload, 8).unwrap().is_none());
            }
        }
    }

    /// Any other flag still marks a route that isn't ours: a cached exception, an on-link
    /// nexthop we never write, or hardware offload bookkeeping.
    #[test]
    fn other_flags_stay_foreign() {
        for flags in [RTM_F_CLONED, 0x4, 0x4000, 0x10 | RTM_F_CLONED] {
            for payload in our_routes(flags) {
                assert!(
                    mesh_peer_route_destination(&payload, 7).unwrap().is_none(),
                    "flags {flags:#x}"
                );
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod route_metric_tests {
    //! Route retirement accepts its one valid mesh MTU metric and preserves other metric shapes.
    use super::*;

    /// Encode route metrics in the same nested format used by rtnetlink route dumps.
    fn encoded_metrics(
        outer_kind: u16,
        outer_nested: bool,
        metrics: &[(u16, bool, Vec<u8>)],
    ) -> Vec<u8> {
        let mut inner = Vec::new();
        for (kind, nested, value) in metrics {
            attribute(&mut inner, *kind | if *nested { NESTED } else { 0 }, value).unwrap();
        }
        let mut outer = Vec::new();
        attribute(
            &mut outer,
            outer_kind | if outer_nested { NESTED } else { 0 },
            &inner,
        )
        .unwrap();
        outer
    }

    /// Decode one top-level attribute and check whether it is an owned MTU metric.
    fn owns_encoded_metrics(bytes: &[u8]) -> bool {
        let Ok(fields) = netlink::attributes(bytes) else {
            return false;
        };
        let [field] = fields.as_slice() else {
            return false;
        };
        mesh_route_metrics_are_owned(*field)
    }

    /// Accept the nested MTU payload when the kernel clears `NLA_F_NESTED` on route dumps.
    #[test]
    fn route_retirement_accepts_kernel_normalized_metrics() {
        let encoded = encoded_metrics(
            RTA_METRICS,
            false,
            &[(RTAX_MTU, false, 1200_u32.to_ne_bytes().to_vec())],
        );
        assert!(owns_encoded_metrics(&encoded));
    }

    /// Route cleanup recognizes exactly one nested MTU in the range the mesh can install.
    #[test]
    fn route_retirement_accepts_only_our_exact_mtu_metric() {
        for mtu in [u32::from(mesh_mtu::MIN_MESH_MTU), u32::from(u16::MAX), 1200] {
            let encoded = encoded_metrics(
                RTA_METRICS,
                true,
                &[(RTAX_MTU, false, mtu.to_ne_bytes().to_vec())],
            );
            assert!(owns_encoded_metrics(&encoded));
        }

        for mtu in [0_u32, 67, 65_536] {
            let encoded = encoded_metrics(
                RTA_METRICS,
                true,
                &[(RTAX_MTU, false, mtu.to_ne_bytes().to_vec())],
            );
            assert!(!owns_encoded_metrics(&encoded));
        }

        let valid_mtu = (1200_u32).to_ne_bytes().to_vec();
        for foreign in [
            encoded_metrics(7, true, &[(RTAX_MTU, false, valid_mtu.clone())]),
            encoded_metrics(RTA_METRICS, true, &[(1, false, valid_mtu.clone())]),
            encoded_metrics(RTA_METRICS, true, &[(RTAX_MTU, true, valid_mtu.clone())]),
            encoded_metrics(RTA_METRICS, true, &[(RTAX_MTU, false, vec![0; 3])]),
            encoded_metrics(RTA_METRICS, true, &[]),
            encoded_metrics(
                RTA_METRICS,
                true,
                &[
                    (RTAX_MTU, false, valid_mtu.clone()),
                    (RTAX_MTU, false, valid_mtu.clone()),
                ],
            ),
            encoded_metrics(
                RTA_METRICS,
                true,
                &[(RTAX_MTU, false, valid_mtu.clone()), (3, false, vec![1])],
            ),
        ] {
            assert!(!owns_encoded_metrics(&foreign));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod underlay_change_tests {
    //! Which route-netlink notifications move the underlay watch (#489 J552 P2-2, J609).
    use super::*;

    /// Wrap `payload` as one received notification of `kind`.
    fn message(kind: u16, payload: &[u8]) -> netlink::Message<'_> {
        netlink::Message {
            kind,
            flags: 0,
            sequence: 0,
            payload,
        }
    }

    /// Policy-rule and nexthop announcements can move a peer endpoint to another path, so each
    /// one moves the watch, whatever it says: the mesh writes neither (#489 J609).
    #[test]
    fn policy_rule_and_nexthop_changes_move_the_underlay_watch() {
        // RTM_NEWRULE / RTM_DELRULE carry a 12-byte `fib_rule_hdr`; RTM_NEWNEXTHOP /
        // RTM_DELNEXTHOP an 8-byte `nhmsg`.
        let rule = [0_u8; 12];
        let nexthop = [0_u8; 8];
        for (kind, payload) in [
            (32, rule.as_slice()),
            (33, rule.as_slice()),
            (104, nexthop.as_slice()),
            (105, nexthop.as_slice()),
        ] {
            assert!(
                is_underlay_change(&message(kind, payload), 7).unwrap(),
                "message type {kind} must move the underlay watch"
            );
        }
    }

    /// Our own link's announcements follow our writes and never count; any other link does.
    #[test]
    fn only_foreign_links_move_the_underlay_watch() {
        // `ifinfomsg` is 16 bytes with the link index at bytes 4..8.
        let mut link = [0_u8; 16];
        link[4..8].copy_from_slice(&7_u32.to_ne_bytes());
        assert!(!is_underlay_change(&message(16, &link), 7).unwrap());
        assert!(is_underlay_change(&message(16, &link), 8).unwrap());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod endpoint_announce_tests {
    //! Which route-netlink notifications announce our endpoint to peers (#483, J633's findings
    //! on J561's address watch, ported onto the node's one route subscription).
    use super::*;
    use std::sync::Arc;

    /// Wrap `payload` as one received notification of `kind`.
    fn message(kind: u16, payload: &[u8]) -> netlink::Message<'_> {
        netlink::Message {
            kind,
            flags: 0,
            sequence: 0,
            payload,
        }
    }

    /// `IFA_F_TENTATIVE`: IPv6 duplicate address detection has not finished.
    const TENTATIVE: u32 = 0x40;

    /// An `ifaddrmsg` notification payload for `address/prefix` on link `index`, with `flags`
    /// and a `valid` lifetime in seconds, laid out as the kernel sends it.
    fn address(index: u32, address: IpAddr, prefix: u8, flags: u32, valid: u32) -> Vec<u8> {
        let (family, bytes) = match address {
            IpAddr::V4(address) => (2, address.octets().to_vec()),
            IpAddr::V6(address) => (10, address.octets().to_vec()),
        };
        let mut payload = vec![family, prefix, u8::try_from(flags & 0xff).unwrap(), 0];
        payload.extend(index.to_ne_bytes());
        netlink::attribute(&mut payload, 1, &bytes).unwrap();
        if family == 2 {
            netlink::attribute(&mut payload, 2, &bytes).unwrap();
        }
        // IFA_CACHEINFO: preferred, valid, created and updated stamps.
        let mut cache = Vec::new();
        for value in [valid, valid, 100, valid.saturating_add(200)] {
            cache.extend(value.to_ne_bytes());
        }
        netlink::attribute(&mut payload, 6, &cache).unwrap();
        netlink::attribute(&mut payload, 8, &flags.to_ne_bytes()).unwrap();
        payload
    }

    /// Classify one notification for a node whose mesh link is index 7.
    fn endpoint(book: &mut EndpointBooks, kind: u16, payload: &[u8]) -> bool {
        book.observe(&message(kind, payload), 7).unwrap().endpoint
    }

    /// Like [`endpoint`], for a notice carrying netlink `flags` (such as `NLM_F_REPLACE`).
    fn endpoint_flagged(book: &mut EndpointBooks, kind: u16, flags: u16, payload: &[u8]) -> bool {
        let mut notice = message(kind, payload);
        notice.flags = flags;
        book.observe(&notice, 7).unwrap().endpoint
    }

    /// An `rtmsg` notice payload for an IPv6 default route via `gateway` on link `link` with
    /// `metric`, installed by a router advertisement and expiring in `expires` seconds, laid out
    /// as the kernel sends it (with `RTA_CACHEINFO` and `RTA_EXPIRES`).
    fn default_route_v6(gateway: Ipv6Addr, link: u32, metric: u32, expires: u32) -> Vec<u8> {
        // family, dst_len, src_len, tos, table main, protocol ra (9), scope universe, unicast.
        let mut payload = vec![10, 0, 0, 0, 254, 9, 0, 1, 0, 0, 0, 0];
        netlink::attribute(&mut payload, RTA_TABLE, &254_u32.to_ne_bytes()).unwrap();
        netlink::attribute(&mut payload, RTA_PRIORITY, &metric.to_ne_bytes()).unwrap();
        netlink::attribute(&mut payload, RTA_GATEWAY, &gateway.octets()).unwrap();
        netlink::attribute(&mut payload, RTA_OIF, &link.to_ne_bytes()).unwrap();
        // RTA_CACHEINFO: clntref, lastuse, expires (in clock ticks), error, used, id, ts, tsage.
        let mut cache = Vec::new();
        for value in [0, 5, expires.saturating_mul(100), 0, 0, 0, 0, 0] {
            cache.extend(value.to_ne_bytes());
        }
        netlink::attribute(&mut payload, 12, &cache).unwrap();
        netlink::attribute(&mut payload, 23, &u64::from(expires).to_ne_bytes()).unwrap();
        netlink::attribute(&mut payload, 20, &[0]).unwrap();
        payload
    }

    /// #483 J707 P2 (D81): a router advertisement handled in user space re-installs the default
    /// route with only a new lifetime, and the kernel reports it as a replacing `RTM_NEWROUTE`.
    /// Nothing moved, so nothing is announced. A new gateway, another link, another metric and
    /// a removal are real changes, and so is a route that comes back after its link went down
    /// (IPv4 drops a downed link's routes without a notice).
    #[test]
    fn a_route_lifetime_refresh_is_not_a_change() {
        let mut book = EndpointBooks::default();
        let router: Ipv6Addr = "fe80::1".parse().unwrap();
        let other: Ipv6Addr = "fe80::2".parse().unwrap();
        let first = default_route_v6(router, 3, 1024, 1800);
        assert!(
            endpoint(&mut book, RTM_NEWROUTE, &first),
            "a new route counts"
        );
        assert!(
            !endpoint_flagged(
                &mut book,
                RTM_NEWROUTE,
                NLM_F_REPLACE,
                &default_route_v6(router, 3, 1024, 1700)
            ),
            "a router advertisement's lifetime refresh must not wake every live session"
        );
        assert!(
            endpoint_flagged(
                &mut book,
                RTM_NEWROUTE,
                NLM_F_REPLACE,
                &default_route_v6(other, 3, 1024, 1700)
            ),
            "a new default gateway moves our endpoint"
        );
        assert!(
            endpoint_flagged(
                &mut book,
                RTM_NEWROUTE,
                NLM_F_REPLACE,
                &default_route_v6(other, 4, 1024, 1700)
            ),
            "the default route moving to another link moves our endpoint"
        );
        assert!(
            endpoint(
                &mut book,
                RTM_NEWROUTE,
                &default_route_v6(other, 4, 512, 1700)
            ),
            "a route with another metric is another route"
        );
        let mut link = [0_u8; 16];
        link[4..8].copy_from_slice(&4_u32.to_ne_bytes());
        assert!(endpoint(&mut book, RTM_NEWLINK, &link));
        assert!(
            endpoint(
                &mut book,
                RTM_NEWROUTE,
                &default_route_v6(other, 4, 512, 1600)
            ),
            "a route re-added after its link changed counts: IPv4 drops them silently"
        );
        assert!(endpoint(
            &mut book,
            RTM_DELROUTE,
            &default_route_v6(other, 4, 512, 1600)
        ));
        assert!(
            endpoint(
                &mut book,
                RTM_NEWROUTE,
                &default_route_v6(other, 4, 512, 1600)
            ),
            "a removed route that comes back counts"
        );
    }

    /// #483 J780: route budgets follow the same book. A lifetime refresh re-derives no budget
    /// (it used to make the next live refresh look up every peer's underlay), a new MTU metric
    /// re-derives budgets without announcing (the endpoint didn't move), and a new gateway does
    /// both.
    #[test]
    fn route_budgets_skip_lifetime_refreshes_but_not_mtu_changes() {
        /// `default_route_v6` with an `RTAX_MTU` metric of `mtu`.
        fn with_mtu(mut payload: Vec<u8>, mtu: u32) -> Vec<u8> {
            let mut metrics = Vec::new();
            netlink::attribute(&mut metrics, RTAX_MTU, &mtu.to_ne_bytes()).unwrap();
            netlink::attribute(&mut payload, RTA_METRICS, &metrics).unwrap();
            payload
        }
        let mut book = EndpointBooks::default();
        let router: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut notice = |payload: &[u8]| {
            let mut message = message(RTM_NEWROUTE, payload);
            message.flags = NLM_F_REPLACE;
            book.observe(&message, 7).unwrap()
        };
        let both = UnderlayChange {
            route_budgets: true,
            endpoint: true,
        };
        assert_eq!(
            notice(&with_mtu(default_route_v6(router, 3, 1024, 1800), 1500)),
            both
        );
        assert_eq!(
            notice(&with_mtu(default_route_v6(router, 3, 1024, 1700), 1500)),
            UnderlayChange::default(),
            "a lifetime refresh moves no budget"
        );
        assert_eq!(
            notice(&with_mtu(default_route_v6(router, 3, 1024, 1600), 1400)),
            UnderlayChange {
                route_budgets: true,
                endpoint: false,
            },
            "a new MTU metric caps every budget through this route"
        );
        assert_eq!(
            notice(&default_route_v6(router, 3, 1024, 1500)),
            UnderlayChange {
                route_budgets: true,
                endpoint: false,
            },
            "so does dropping it"
        );
        assert_eq!(
            notice(&default_route_v6("fe80::2".parse().unwrap(), 3, 1024, 1500)),
            both
        );
        // A route on the mesh link is our own write, and a removal always counts.
        assert_eq!(
            notice(&default_route_v6(router, 7, 1024, 1500)),
            UnderlayChange::default()
        );
        let removal = default_route_v6("fe80::2".parse().unwrap(), 3, 1024, 1);
        assert_eq!(
            book.observe(&message(RTM_DELROUTE, &removal), 7).unwrap(),
            both
        );
    }

    /// Past [`ROUTE_BOOK_LIMIT`] routes the book stops tracking, and every route notice counts
    /// again, refreshes included: memory stays bounded and no change is ever missed.
    #[test]
    fn a_route_book_past_its_limit_counts_every_notice() {
        let mut book = RouteBook::default();
        for index in 0..=u32::try_from(ROUTE_BOOK_LIMIT).unwrap() {
            let mut payload = vec![2, 32, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0];
            netlink::attribute(&mut payload, RTA_DST, &index.to_be_bytes()).unwrap();
            netlink::attribute(&mut payload, RTA_OIF, &3_u32.to_ne_bytes()).unwrap();
            assert!(book.record(true, 0, &payload, 7).unwrap().endpoint);
        }
        assert!(book.untracked && book.known.is_empty());
        let mut payload = vec![2, 32, 0, 0, 254, 3, 0, 1, 0, 0, 0, 0];
        netlink::attribute(&mut payload, RTA_DST, &1_u32.to_be_bytes()).unwrap();
        netlink::attribute(&mut payload, RTA_OIF, &3_u32.to_ne_bytes()).unwrap();
        let refresh = book.record(true, NLM_F_REPLACE, &payload, 7).unwrap();
        assert!(refresh.endpoint && refresh.route_budgets);
    }

    /// J633 P1/P2: a policy rule or nexthop swap that moves our source address must announce
    /// it. Under J561's separate watch these changes woke nothing, so the 15 s stall stayed for
    /// the #489 J609 VPN case.
    #[test]
    fn rule_and_nexthop_changes_announce() {
        let mut book = EndpointBooks::default();
        for (kind, payload) in [
            (32, [0_u8; 12].as_slice()),
            (33, [0_u8; 12].as_slice()),
            (104, [0_u8; 8].as_slice()),
            (105, [0_u8; 8].as_slice()),
        ] {
            assert!(
                endpoint(&mut book, kind, payload),
                "message type {kind} must announce our endpoint"
            );
        }
    }

    /// Our own link's addresses and peer routes follow our writes; they never announce, or each
    /// apply at 1,000 peers would wake every live session.
    #[test]
    fn own_link_changes_never_announce() {
        let mut book = EndpointBooks::default();
        let mesh_address = address(7, IpAddr::from([100, 64, 0, 1]), 32, 0x80, u32::MAX);
        assert!(!endpoint(&mut book, RTM_NEWADDR, &mesh_address));
        assert!(!endpoint(&mut book, RTM_DELADDR, &mesh_address));
        let mut route = vec![2, 32, 0, 0, 254, RTPROT_INFRATERNAL, 253, 1, 0, 0, 0, 0];
        netlink::attribute(&mut route, 4, &7_u32.to_ne_bytes()).unwrap();
        assert!(!endpoint(&mut book, 24, &route));
        let mut link = [0_u8; 16];
        link[4..8].copy_from_slice(&7_u32.to_ne_bytes());
        assert!(!endpoint(&mut book, 16, &link));
    }

    /// J633 P1 (D81, D393): a DHCP renewal or IPv6 router advertisement refreshes an address's
    /// lifetimes, and the kernel reports each refresh as `RTM_NEWADDR`. Nothing moved, so
    /// nothing is announced. A new address, a flag change such as the end of duplicate address
    /// detection, and a removal are real changes.
    #[test]
    fn an_address_lifetime_refresh_is_not_a_change() {
        let mut book = EndpointBooks::default();
        let v4 = IpAddr::from([10, 9, 0, 2]);
        let v6: IpAddr = "2001:db8::2".parse().unwrap();
        assert!(endpoint(
            &mut book,
            RTM_NEWADDR,
            &address(3, v4, 24, 0, 300)
        ));
        assert!(
            !endpoint(&mut book, RTM_NEWADDR, &address(3, v4, 24, 0, 200)),
            "an IPv4 lease renewal must not wake every live session"
        );
        assert!(endpoint(
            &mut book,
            RTM_NEWADDR,
            &address(3, v6, 64, TENTATIVE, 300)
        ));
        assert!(!endpoint(
            &mut book,
            RTM_NEWADDR,
            &address(3, v6, 64, TENTATIVE, 250)
        ));
        assert!(
            endpoint(&mut book, RTM_NEWADDR, &address(3, v6, 64, 0, 250)),
            "the end of duplicate address detection makes the address usable"
        );
        assert!(
            !endpoint(&mut book, RTM_NEWADDR, &address(3, v6, 64, 0, 200)),
            "a router advertisement's refresh must not wake every live session"
        );
        assert!(endpoint(
            &mut book,
            RTM_DELADDR,
            &address(3, v4, 24, 0, 200)
        ));
        assert!(endpoint(
            &mut book,
            RTM_NEWADDR,
            &address(3, v4, 24, 0, 300)
        ));
        assert!(
            endpoint(&mut book, RTM_NEWADDR, &address(4, v4, 24, 0, 300)),
            "the same address on another link is a change"
        );
    }

    /// Run `ip` with `args` in the test's namespace and fail the test if it fails.
    fn ip(args: &[&str]) {
        let status = std::process::Command::new("ip")
            .args(args)
            .status()
            .expect("ip runs");
        assert!(status.success(), "ip {args:?} failed: {status}");
    }

    /// A listener for a dummy mesh link, the announce it wakes, and the cancellation pair its
    /// waits poll (both ends stay open, so a wait ends only at its deadline).
    struct Listener {
        monitor: RouteMonitor,
        announce: Arc<crate::gotatun_node::UnderlayAnnounce>,
        cancel: std::os::unix::net::UnixStream,
        _cancel_peer: std::os::unix::net::UnixStream,
    }

    impl Listener {
        /// Let the listener read everything the kernel sends within 300 ms.
        fn pump(&mut self) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
            while !matches!(
                self.monitor
                    .wait_for_deleted_peer_route(self.cancel.as_fd(), deadline),
                Ok(RouteWake::Reconcile | RouteWake::Cancelled)
            ) {}
        }
    }

    /// A private namespace with an up dummy underlay `d0` (`10.9.0.2/24` and `2001:db8::2/64`,
    /// with finite lifetimes as a DHCP or SLAAC client sets them) and an up dummy `m0` that plays
    /// the mesh link, plus a listener for `m0` drained of the setup's notifications.
    ///
    /// The calling test thread enters a fresh network namespace first, so each test starts from
    /// an empty one even when the harness runs several tests in one process (the `ip` children
    /// inherit the thread's namespace). Neither link gets an IPv6 link-local address: its
    /// duplicate address detection would end about a second later, a real flag change that
    /// would announce in the middle of a test that expects silence.
    fn namespace() -> Listener {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
            .expect("a fresh network namespace");
        ip(&["link", "add", "d0", "type", "dummy"]);
        ip(&["link", "set", "d0", "addrgenmode", "none"]);
        ip(&["link", "set", "d0", "up"]);
        ip(&[
            "addr",
            "add",
            "10.9.0.2/24",
            "dev",
            "d0",
            "valid_lft",
            "300",
            "preferred_lft",
            "300",
        ]);
        ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8::2/64",
            "dev",
            "d0",
            "nodad",
            "valid_lft",
            "300",
            "preferred_lft",
            "300",
        ]);
        ip(&["link", "add", "m0", "type", "dummy"]);
        ip(&["link", "set", "m0", "addrgenmode", "none"]);
        ip(&["link", "set", "m0", "up"]);
        let mesh = nix::net::if_::if_nametoindex("m0").unwrap();
        let announce = Arc::new(crate::gotatun_node::UnderlayAnnounce::default());
        let monitor = RouteMonitor::open(mesh, Arc::default(), Arc::clone(&announce)).unwrap();
        let (cancel, cancel_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut listener = Listener {
            monitor,
            announce,
            cancel,
            _cancel_peer: cancel_peer,
        };
        listener.pump();
        listener.announce.take_for_test();
        listener
    }

    /// Apply `change` in the namespace and report whether the listener woke the announce.
    fn announces(change: impl FnOnce()) -> bool {
        let mut listener = namespace();
        change();
        listener.pump();
        listener.announce.take_for_test()
    }

    /// J633 P2, end to end: an `ip rule` that moves our source wakes the announce.
    #[test]
    #[ignore = "needs a private network namespace: run the test binary under unshare -Urnm"]
    fn namespace_rule_change_announces() {
        assert!(announces(|| ip(&[
            "rule", "add", "from", "10.9.0.2", "table", "100", "priority", "100"
        ])));
    }

    /// A new underlay address is announced.
    #[test]
    #[ignore = "needs a private network namespace: run the test binary under unshare -Urnm"]
    fn namespace_new_address_announces() {
        assert!(announces(|| ip(&[
            "addr",
            "add",
            "10.9.1.2/24",
            "dev",
            "d0"
        ])));
    }

    /// J633 P1, end to end: lifetime refreshes of both families announce nothing. The IPv6
    /// refresh repeats `nodad`: `ip addr change` replaces the address flags, and dropping
    /// `IFA_F_NODAD` is a real flag change, which a router advertisement's refresh never makes.
    #[test]
    #[ignore = "needs a private network namespace: run the test binary under unshare -Urnm"]
    fn namespace_lifetime_refresh_does_not_announce() {
        assert!(!announces(|| {
            ip(&[
                "addr",
                "change",
                "10.9.0.2/24",
                "dev",
                "d0",
                "valid_lft",
                "200",
                "preferred_lft",
                "200",
            ]);
            ip(&[
                "-6",
                "addr",
                "change",
                "2001:db8::2/64",
                "dev",
                "d0",
                "nodad",
                "valid_lft",
                "200",
                "preferred_lft",
                "200",
            ]);
        }));
    }

    /// A namespace whose underlay `d0` also has an IPv6 default route via `2001:db8::1` that a
    /// router advertisement installed, expiring in 1,800 s, with the listener drained.
    fn namespace_with_ra_default_route() -> Listener {
        let mut listener = namespace();
        ip(&[
            "-6",
            "route",
            "add",
            "default",
            "via",
            "2001:db8::1",
            "dev",
            "d0",
            "proto",
            "ra",
            "metric",
            "1024",
            "expires",
            "1800",
        ]);
        listener.pump();
        listener.announce.take_for_test();
        listener
    }

    /// Replace the IPv6 default route with one via `gateway`, expiring in `expires` seconds, as
    /// a user-space router-advertisement client does on every advertisement.
    fn replace_ra_default_route(gateway: &str, expires: &str) {
        ip(&[
            "-6", "route", "replace", "default", "via", gateway, "dev", "d0", "proto", "ra",
            "metric", "1024", "expires", expires,
        ]);
    }

    /// #483 J707 P2 (D81), end to end: a lifetime-only replace of the IPv6 default route (what
    /// systemd-networkd does on every router advertisement) announces nothing. Before the route
    /// book every such replace woke every live session.
    #[test]
    #[ignore = "needs a private network namespace: run the test binary under unshare -Urnm"]
    fn namespace_ra_default_route_refresh_does_not_announce() {
        let mut listener = namespace_with_ra_default_route();
        for expires in ["1700", "1600", "1500"] {
            replace_ra_default_route("2001:db8::1", expires);
            listener.pump();
            assert!(
                !listener.announce.take_for_test(),
                "the lifetime refresh to {expires} s announced"
            );
        }
    }

    /// The same replace with a new gateway is a real change and announces.
    #[test]
    #[ignore = "needs a private network namespace: run the test binary under unshare -Urnm"]
    fn namespace_ra_default_gateway_change_announces() {
        let mut listener = namespace_with_ra_default_route();
        replace_ra_default_route("2001:db8::3", "1700");
        listener.pump();
        assert!(listener.announce.take_for_test());
    }

    /// IPv4 drops a downed link's routes without a notice, so a default route a DHCP client
    /// re-adds after the link comes back must still count as new.
    #[test]
    #[ignore = "needs a private network namespace: run the test binary under unshare -Urnm"]
    fn namespace_default_route_back_after_link_down_announces() {
        let mut listener = namespace();
        ip(&["route", "add", "default", "via", "10.9.0.1", "dev", "d0"]);
        ip(&["link", "set", "d0", "down"]);
        ip(&["link", "set", "d0", "up"]);
        listener.pump();
        listener.announce.take_for_test();
        ip(&["route", "add", "default", "via", "10.9.0.1", "dev", "d0"]);
        listener.pump();
        assert!(listener.announce.take_for_test());
    }

    /// Read for 300 ms, through overflow recoveries too (they end a wait with `Overflow`), and
    /// fail on any listener error: an error drops the listener until the 30 s recheck.
    fn read_everything(listener: &mut Listener) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
        while std::time::Instant::now() < deadline {
            if let Err(error) = listener
                .monitor
                .wait_for_deleted_peer_route(listener.cancel.as_fd(), deadline)
            {
                panic!("the route listener failed: {error}");
            }
        }
    }

    /// Run one `ip -batch` for unrelated /32 routes via `d0`, as a routing daemon loading or
    /// dropping a table does.
    fn route_storm(verb: &str, count: u32) {
        use std::fmt::Write as _;
        let mut batch = String::new();
        for index in 0..count {
            let [_, high, middle, low] = index.to_be_bytes();
            writeln!(
                batch,
                "route {verb} 172.{}.{middle}.{low}/32 via 10.9.0.1 dev d0",
                16 + high
            )
            .unwrap();
        }
        let path = std::env::temp_dir().join(format!("route-storm-{}", std::process::id()));
        std::fs::write(&path, batch).unwrap();
        ip(&["-batch", path.to_str().unwrap()]);
        std::fs::remove_file(path).unwrap();
    }

    /// A later notification in the same burst postpones recovery, but continuous traffic
    /// cannot postpone the inventory past the hard limit.
    #[test]
    fn notification_loss_coalesces_the_trailing_edge_with_a_hard_limit() {
        let start = Instant::now();
        let mut loss = NotificationLoss::new(start);
        assert_eq!(loss.due(), start + Duration::from_millis(25));
        for elapsed in [20, 40, 50] {
            loss.received(start + Duration::from_millis(elapsed));
        }
        assert_eq!(loss.due(), start + Duration::from_millis(75));
        for elapsed in (70..250).step_by(20) {
            loss.received(start + Duration::from_millis(elapsed));
        }
        assert_eq!(loss.due(), start + Duration::from_millis(250));
    }

    /// A second overflow after the first drain belongs to the same burst until recovery
    /// starts. The two phases add and remove the same routes, so only one inventory pass
    /// is due and there is no endpoint change to announce.
    #[test]
    #[ignore = "needs a private network namespace: run the test binary under unshare -Urnm"]
    fn overflow_coalesces_when_the_burst_refills_the_queue() {
        use nix::sys::socket::{setsockopt, sockopt};
        use std::sync::atomic::Ordering;

        let mut listener = namespace();
        setsockopt(&listener.monitor.fd, sockopt::RcvBuf, &4096).unwrap();
        route_storm("add", 256);
        let before = OVERFLOW_RECOVERIES.load(Ordering::Acquire);
        AFTER_NOTIFICATION_DRAIN.set(Some(Box::new(|| route_storm("del", 256))));
        read_everything(&mut listener);
        assert!(
            AFTER_NOTIFICATION_DRAIN.take().is_none(),
            "the socket overflowed"
        );
        assert_eq!(
            OVERFLOW_RECOVERIES.load(Ordering::Acquire) - before,
            1,
            "the queue refill is part of the same burst"
        );
        assert!(!listener.announce.take_for_test());
    }

    /// #483 J707 P2: a route storm overflows the notification socket while the listener is
    /// busy. The overflow is reported as `POLLERR`; the listener must read it as `ENOBUFS`,
    /// recover, and announce, both when the storm adds routes and when it removes them (the
    /// trailing edge), then stay quiet. Before the fix the first overflow ended the listener
    /// ("route notification socket disconnected"), and the change went unannounced for 30 s.
    ///
    /// The listener does not read during each storm, so the kernel's queue (a few hundred
    /// kilobytes) must overflow: 20,000 route notifications are about 2 MB.
    #[test]
    #[ignore = "needs a private network namespace: run the test binary under unshare -Urnm"]
    fn namespace_route_storm_overflow_still_announces() {
        let mut listener = namespace();
        route_storm("add", 20_000);
        read_everything(&mut listener);
        assert!(
            listener.announce.take_for_test(),
            "the storm that added routes was not announced"
        );
        read_everything(&mut listener);
        assert!(
            !listener.announce.take_for_test(),
            "the listener kept announcing after the storm ended"
        );
        route_storm("del", 20_000);
        read_everything(&mut listener);
        assert!(
            listener.announce.take_for_test(),
            "the storm that removed routes (the trailing edge) was not announced"
        );
        read_everything(&mut listener);
        assert!(!listener.announce.take_for_test());
    }

    /// A storm that adds and removes the same routes
    /// while the listener is not reading overflows, and the resync finds nothing moved (D81).
    #[test]
    #[ignore = "needs a private network namespace: run the test binary under unshare -Urnm"]
    fn overflow_with_no_net_change_is_quiet() {
        let mut listener = namespace();
        route_storm("add", 20_000);
        route_storm("del", 20_000);
        read_everything(&mut listener);
        assert!(
            !listener.announce.take_for_test(),
            "a storm that ended where it started announced"
        );
    }

    /// An address change lost inside an overflow, with
    /// routes back where they started, is still announced by the resync (only the address book
    /// differs: deprecating an address adds and removes no route).
    #[test]
    #[ignore = "needs a private network namespace: run the test binary under unshare -Urnm"]
    fn address_change_lost_in_overflow_announces() {
        let mut listener = namespace();
        route_storm("add", 20_000);
        ip(&[
            "-6",
            "addr",
            "change",
            "2001:db8::2/64",
            "dev",
            "d0",
            "nodad",
            "valid_lft",
            "300",
            "preferred_lft",
            "0",
        ]);
        route_storm("del", 20_000);
        read_everything(&mut listener);
        assert!(
            listener.announce.take_for_test(),
            "an address change lost in the overflow was not announced"
        );
    }

    /// Acknowledged writes from both peer route batches leave the listener socket unreadable.
    /// Another process can still change or remove the same tagged route, and an underlay change
    /// still reaches the underlay watch and endpoint announcer.
    #[test]
    #[ignore = "needs a private network namespace: run the test binary under unshare -Urnm"]
    fn namespace_filters_only_route_additions_from_the_mesh_writer() {
        let mut listener = namespace();
        let underlay = Arc::clone(&listener.monitor.underlay);
        underlay.set_watched(true);
        let generation = underlay.generation();
        let peer = Peer {
            key: PublicKey([1; 32]),
            previous_key: None,
            previous_active: false,
            addresses: Addresses {
                ipv4: "10.88.0.2".parse().unwrap(),
                ipv6: "fd88::2".parse().unwrap(),
            },
            endpoint: None,
            candidates: Vec::new(),
            ipv4_only: false,
            side_port: false,
        };
        for mtu in [1232, 1408] {
            let mut writer = PeerRouteWriter::open(
                listener.monitor.interface_index,
                Some(Arc::clone(&underlay)),
            )
            .unwrap();
            assert!(writer.writes_ipv6_for(&peer));
            writer.replace(&peer, mtu).unwrap();
            // The kernel multicasts before acknowledging each write. No reader has drained the
            // socket, so a zero-time poll proves the notifications never made it readable.
            assert_eq!(underlay.settled_generation(), generation, "own MTU {mtu}");
        }

        ip(&[
            "route",
            "replace",
            "10.88.0.2/32",
            "dev",
            "m0",
            "proto",
            "250",
            "mtu",
            "1280",
        ]);
        assert_eq!(underlay.settled_generation(), None, "foreign mesh change");
        ip(&[
            "-6",
            "route",
            "del",
            "fd88::2/128",
            "dev",
            "m0",
            "proto",
            "250",
        ]);
        let wake = listener
            .monitor
            .wait_for_deleted_peer_route(
                listener.cancel.as_fd(),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
        assert!(
            matches!(wake, RouteWake::Deleted(address) if address == IpAddr::V6(peer.addresses.ipv6))
        );

        ip(&["route", "add", "10.89.0.0/24", "dev", "d0", "proto", "250"]);
        assert_eq!(underlay.settled_generation(), None, "underlay route queued");
        listener.pump();
        assert_ne!(underlay.settled_generation(), generation);
        assert!(
            listener.announce.take_for_test(),
            "underlay change announced"
        );
    }

    /// Routes out of the mesh link are our own writes and announce nothing.
    #[test]
    #[ignore = "needs a private network namespace: run the test binary under unshare -Urnm"]
    fn namespace_mesh_link_route_does_not_announce() {
        assert!(!announces(|| ip(&[
            "route",
            "add",
            "10.88.0.0/24",
            "dev",
            "m0"
        ])));
    }
}
