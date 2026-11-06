//! Drives Linux kernel `WireGuard` through checked generic and route netlink [163,165,169], #129.
use crate::{
    netlink::{self, NESTED, Socket, attribute},
    policy::model::{Addresses, PublicKey},
};
use nix::sys::socket::SockProtocol;
use openssl::pkey::PKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use zeroize::Zeroizing;

/// A node-local ephemeral secret. It cannot be serialized, cloned or debug printed.
pub struct Key(Zeroizing<Vec<u8>>);
impl Key {
    /// Generate locally using the existing cryptographic provider; only the public part is returned.
    /// # Errors
    /// Returns fixed-text errors, never provider diagnostics containing private data.
    pub fn generate() -> io::Result<(Self, PublicKey)> {
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
/// Public kernel peer status, available even while the coordinator is unreachable.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    #[serde(default)]
    pub persistent_keepalive_secs: u16,
    pub handshake_secs: u64,
    /// Subsecond precision used to order handshakes against endpoint updates.
    #[cfg(feature = "relay")]
    #[serde(skip)]
    pub handshake_nanos: u32,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    /// Where the kernel currently sends this peer's packets: the configured
    /// endpoint, or the source of its latest authenticated packet (roaming).
    /// It is not discovery evidence by itself (contracts/mesh-discovery.md).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<SocketAddr>,
}
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

/// No timer or background thread: the socket exists only during one operation.
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
    /// Move this link's owner marker from `from` to `to` after a kernel key rotation (#285). The
    /// old marker is re-verified on the link at `ifindex` first, and the change is addressed by that
    /// index alone, so a link substituted under the shared name is never re-marked. The new
    /// marker is verified before this returns.
    /// # Errors
    /// Refuses a link whose marker does not name `from`, and reports kernel errors.
    pub(crate) fn remark(ifindex: u32, from: PublicKey, to: PublicKey) -> io::Result<()> {
        verify_owner(ifindex, from)?;
        let mut claim = vec![0; 16];
        claim[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        attribute(&mut claim, 20, &owner_alias(KERNEL_OWNER_PREFIX, to))?;
        Socket::open(SockProtocol::NetlinkRoute)?.request(16, 4, &claim)?;
        verify_owner(ifindex, to)
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
    /// Refuse host-route overlap on another interface before touching addresses or packet policy [165].
    /// # Errors
    /// Reports malformed route dumps or an existing route covering a proposed address.
    pub fn check_routes(addresses: &[Addresses]) -> io::Result<()> {
        let owned = index()?;
        let payload = vec![0; 12];
        for reply in Socket::open(SockProtocol::NetlinkRoute)?.request(26, 0x300, &payload)? {
            let header = reply.get(..12).ok_or(io::ErrorKind::InvalidData)?;
            if header[1] == 0 {
                continue;
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
                continue;
            }
            let destination = destination.ok_or(io::ErrorKind::InvalidData)?;
            let conflict = match header[0] {
                2 if header[1] <= 32 && destination.len() == 4 => {
                    let network =
                        u32::from_be_bytes(destination.try_into().map_err(io::Error::other)?);
                    let mask = u32::MAX << (32 - header[1]);
                    addresses
                        .iter()
                        .any(|address| u32::from(address.ipv4) & mask == network & mask)
                }
                10 if header[1] <= 128 && destination.len() == 16 => {
                    let network =
                        u128::from_be_bytes(destination.try_into().map_err(io::Error::other)?);
                    let mask = u128::MAX << (128 - header[1]);
                    addresses
                        .iter()
                        .any(|address| u128::from(address.ipv6) & mask == network & mask)
                }
                2 | 10 => return Err(io::ErrorKind::InvalidData.into()),
                _ => false,
            };
            if conflict {
                return Err(io::ErrorKind::AddrInUse.into());
            }
        }
        Ok(())
    }
    /// Install local /32+/128 addresses while the link meets IPv6's minimum MTU, then apply the
    /// safe fallback until the node can derive a route-specific packet ceiling.
    /// # Errors
    /// Returns address, interface lookup or route-netlink errors.
    pub fn addresses(addresses: Addresses) -> io::Result<()> {
        let index = index()?;
        // Linux rejects IPv6 address installation below 1280 bytes. A prior
        // route update may already have narrowed this owned link to 1200, so
        // temporarily raise only that link before changing either address.
        if link_mtu(index)? < u32::from(crate::mesh_mtu::IPV6_MINIMUM_MTU) {
            set_link_mtu(index, u32::from(crate::mesh_mtu::IPV6_MINIMUM_MTU))?;
        }
        let mut route = Socket::open(SockProtocol::NetlinkRoute)?;
        for (family, prefix, address) in [
            (2_u8, 32, addresses.ipv4.octets().to_vec()),
            (10, 128, addresses.ipv6.octets().to_vec()),
        ] {
            let mut payload = vec![family, prefix, 0, 0];
            payload.extend(index.to_ne_bytes());
            attribute(&mut payload, 1, &address)?;
            attribute(&mut payload, 2, &address)?;
            // IPv6 must be usable immediately; private /128 addresses are unique by coordinator allocation.
            attribute(&mut payload, 8, &0x02_u32.to_ne_bytes())?;
            route.request(20, 4 | 0x100 | 0x400, &payload)?;
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
        activate(index, Some(crate::mesh_mtu::IPV6_MINIMUM_MTU))
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
    /// Install/remove only peer host routes; no subnet routes or default route.
    /// # Errors
    /// Returns route-netlink errors.
    pub fn routes(peers: &[Peer], remove: bool) -> io::Result<()> {
        let mut socket = Socket::open(SockProtocol::NetlinkRoute)?;
        let index = index()?;
        for peer in peers {
            let mtu = (!remove).then(|| crate::mesh_mtu::for_endpoint(peer.endpoint));
            for (family, prefix, address) in [
                (2_u8, 32, peer.addresses.ipv4.octets().to_vec()),
                (10, 128, peer.addresses.ipv6.octets().to_vec()),
            ] {
                let mut payload = vec![family, prefix, 0, 0, 254, 4, 253, 1, 0, 0, 0, 0];
                attribute(&mut payload, 1, &address)?;
                attribute(&mut payload, 4, &index.to_ne_bytes())?;
                if let Some(mtu) = mtu {
                    let mut metrics = Vec::new();
                    attribute(&mut metrics, RTAX_MTU, &u32::from(mtu).to_ne_bytes())?;
                    // RTAX_LOCK is deliberately absent so later PMTU information can refine this.
                    attribute(&mut payload, RTA_METRICS | NLA_F_NESTED, &metrics)?;
                }
                let result = socket.request(
                    if remove { 25 } else { 24 },
                    if remove { 4 } else { 4 | 0x100 | 0x400 },
                    &payload,
                );
                // Restart/rollback can replay a removal after an interrupted
                // batch. Only absence is success; privilege and other errors remain visible.
                if let Err(error) = result
                    && (!remove || !matches!(error.raw_os_error(), Some(2 | 3)))
                {
                    return Err(error);
                }
            }
        }
        Ok(())
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
    /// Retire orphan static host routes after adopting durable peer state [206,228].
    /// # Errors
    /// Reports malformed route dumps or kernel deletion errors.
    pub fn retain_routes(addresses: &[Addresses]) -> io::Result<()> {
        Self::retain_recorded_routes(&Self::peer_routes()?, addresses)
    }
    /// Retire only journaled peer host routes with the exact shape we install.
    /// # Errors
    /// Reports checked dump or deletion failures, preserving foreign route shapes.
    pub fn retain_recorded_routes(
        inventory: &BTreeSet<IpAddr>,
        addresses: &[Addresses],
    ) -> io::Result<()> {
        Self::retire_routes(inventory, addresses)
    }
    fn retire_routes(inventory: &BTreeSet<IpAddr>, addresses: &[Addresses]) -> io::Result<()> {
        let desired: BTreeSet<IpAddr> = addresses
            .iter()
            .flat_map(|address| [IpAddr::V4(address.ipv4), IpAddr::V6(address.ipv6)])
            .collect();
        let owned = index()?;
        let mut socket = Socket::open(SockProtocol::NetlinkRoute)?;
        for reply in socket.request(26, 0x300, &[0; 12])? {
            let header = reply.get(..12).ok_or(io::ErrorKind::InvalidData)?;
            // Linux normalizes IPv6 scope-link host routes to universe scope.
            // IPv4 keeps link scope. Reject source/TOS/flags and every routing
            // modifier: a gateway, onlink or multipath static route is foreign.
            if header[4] != 254
                || header[5] != 4
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
            for field in netlink::attributes(&reply[12..])? {
                match field.kind {
                    1 => destination = Some(field.payload),
                    4 => interface = Some(netlink::u32_at(field.payload, 0)?),
                    15 => table = netlink::u32_at(field.payload, 0)?,
                    6 if header[0] == 10 && field.payload == 1024_u32.to_ne_bytes() => {}
                    12 if header[0] == 10 && field.payload.len() == 32 => {}
                    20 if header[0] == 10 && field.payload == [0] => {}
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
/// The route may carry a smaller MTU than the interface, so prefer `RTAX_MTU` when present.
/// `RTM_GETROUTE` and `RTM_GETLINK` are acknowledged requests and each uses one short-lived
/// route-netlink socket.
/// # Errors
/// Reports an unreachable endpoint, a missing egress link, or malformed kernel replies.
pub(crate) fn route_mtu(endpoint: SocketAddr) -> io::Result<u32> {
    let (family, prefix, address) = match endpoint.ip() {
        IpAddr::V4(address) => (2_u8, 32_u8, address.octets().to_vec()),
        IpAddr::V6(address) => (10_u8, 128_u8, address.octets().to_vec()),
    };
    let mut request = vec![family, prefix, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    attribute(&mut request, 1, &address)?;
    let replies = Socket::open(SockProtocol::NetlinkRoute)?.request(26, 4, &request)?;
    let reply = replies.first().ok_or(io::ErrorKind::NotFound)?;
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
    if let Some(mtu) = route_mtu.filter(|mtu| *mtu > 0) {
        return Ok(mtu);
    }
    link_mtu(output_index.ok_or(io::ErrorKind::NotFound)?)
}

/// Read one egress link's MTU when the route has no explicit MTU metric.
fn link_mtu(index: u32) -> io::Result<u32> {
    let mut request = vec![0; 16];
    request[4..8].copy_from_slice(&index.to_ne_bytes());
    let replies = Socket::open(SockProtocol::NetlinkRoute)?.request(18, 4, &request)?;
    let reply = replies.first().ok_or(io::ErrorKind::NotFound)?;
    netlink::attributes(reply.get(16..).ok_or(io::ErrorKind::InvalidData)?)?
        .into_iter()
        .find(|field| field.kind == IFLA_MTU)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))
        .and_then(|field| netlink::u32_at(field.payload, 0))
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
        && kind.as_deref() == Some(b"wireguard\0")
        && alias.as_deref() == Some(owner_alias(KERNEL_OWNER_PREFIX, owner).as_slice())
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
