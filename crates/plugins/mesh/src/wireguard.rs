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
const KERNEL_ALIAS: &[u8] = b"infraternal.mesh.v1\0";
const GOTATUN_ALIAS: &[u8] = b"infraternal.mesh.gotatun.v1\0";
const GOTATUN_OWNER_PREFIX: &[u8] = b"infraternal.mesh.gotatun.v2:";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// One marked mesh link observed in a single route-netlink reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ActiveLink {
    pub(crate) engine: crate::gotatun_node::EngineKind,
    pub(crate) ifindex: u32,
    /// `None` for kernel links and legacy unbound `GotaTun` markers.
    pub(crate) gotatun_owner: Option<PublicKey>,
}

/// Put only the public node identity in the marker because the TUN name is shared across installs.
fn gotatun_alias(owner: PublicKey) -> Vec<u8> {
    let mut alias = Vec::with_capacity(GOTATUN_OWNER_PREFIX.len() + owner.0.len() * 2 + 1);
    alias.extend_from_slice(GOTATUN_OWNER_PREFIX);
    for byte in owner.0 {
        alias.push(HEX[usize::from(byte >> 4)]);
        alias.push(HEX[usize::from(byte & 0x0f)]);
    }
    alias.push(0);
    alias
}

fn parse_gotatun_owner(alias: &[u8]) -> Option<PublicKey> {
    let encoded = alias.strip_prefix(GOTATUN_OWNER_PREFIX)?;
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

/// No timer or background thread: the socket exists only during one operation.
pub struct Device;
impl Device {
    /// Create our interface only; an existing interface must already be owned by the caller.
    /// # Errors
    /// Returns kernel errors including insufficient privileges and duplicate interface.
    pub fn create() -> io::Result<()> {
        let mut payload = vec![0; 16];
        attribute(&mut payload, 3, b"infraternal0\0")?;
        let mut linkinfo = Vec::new();
        attribute(&mut linkinfo, 1, b"wireguard\0")?;
        attribute(&mut payload, 0x12 | NESTED, &linkinfo)?;
        let mut socket = Socket::open(SockProtocol::NetlinkRoute)?;
        socket.request(16, 4 | 0x200 | 0x400, &payload)?;
        // Creation does not run the generic alias setter. Mark the new link
        // explicitly before a later process may adopt it; never leave an unmarked success.
        let mut marker = vec![0; 16];
        attribute(&mut marker, 3, b"infraternal0\0")?;
        attribute(&mut marker, 20, KERNEL_ALIAS)?;
        if let Err(error) = socket.request(16, 4, &marker) {
            Self::delete()?;
            return Err(error);
        }
        Ok(())
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
        attribute(&mut payload, 20, &gotatun_alias(owner))?;
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
        for field in netlink::attributes(reply.get(16..).ok_or(io::ErrorKind::InvalidData)?)? {
            match field.kind {
                20 => alias = Some(field.payload),
                18 => {
                    for info in netlink::attributes(field.payload)? {
                        if info.kind == 1 {
                            kind = Some(info.payload);
                        }
                    }
                }
                _ => {}
            }
        }
        if alias == Some(KERNEL_ALIAS) && kind.is_some_and(|kind| kind == b"wireguard\0") {
            return Ok(Some(ActiveLink {
                engine: crate::gotatun_node::EngineKind::Kernel,
                ifindex,
                gotatun_owner: None,
            }));
        }
        if kind.is_some_and(|kind| kind == b"tun\0") {
            let gotatun_owner = match alias {
                Some(alias) if alias == GOTATUN_ALIAS => None,
                Some(alias) => parse_gotatun_owner(alias),
                None => None,
            };
            if alias == Some(GOTATUN_ALIAS) || gotatun_owner.is_some() {
                return Ok(Some(ActiveLink {
                    engine: crate::gotatun_node::EngineKind::GotaTun,
                    ifindex,
                    gotatun_owner,
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
    /// Install the local key and listen port. The secret lives only in zeroized netlink buffers.
    /// # Errors
    /// Returns a kernel configuration error without key material.
    pub fn configure(key: &Key, port: u16) -> io::Result<()> {
        // Reserve the coexistence port before entering the kernel, including
        // for explicit callers. Ephemeral allocation is checked after binding.
        if port == 51820 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut payload = Zeroizing::new(header());
        attribute(&mut payload, 3, &key.0)?;
        attribute(&mut payload, 6, &port.to_ne_bytes())?;
        // A zero listen port is bound only when the kernel device is running.
        // Activate before advertising the public endpoint to the coordinator.
        send(&payload)?;
        activate(index()?)?;
        if Self::identity()?.1 == 51820 {
            Self::allocate_port()?;
        }
        Ok(())
    }
    /// Allocate an unreserved kernel socket without replacing the retained key.
    /// # Errors
    /// Reports kernel errors or bounded allocation exhaustion.
    pub fn allocate_port() -> io::Result<u16> {
        let mut payload = header();
        attribute(&mut payload, 6, &0_u16.to_ne_bytes())?;
        for _ in 0..16 {
            // Port zero asks the kernel to allocate again. Never reserve a
            // userspace socket and release it into a bind race with WireGuard.
            send(&payload)?;
            activate(index()?)?;
            let port = Self::identity()?.1;
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
    /// Install local /32+/128 addresses and bring the interface up with conservative direct-path MTU.
    /// # Errors
    /// Returns address, interface lookup or route-netlink errors.
    pub fn addresses(addresses: Addresses) -> io::Result<()> {
        let index = index()?;
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
        activate(index)
    }
    /// Raise a fresh `GotaTun` interface with the mesh MTU.
    /// # Errors
    /// Reports link configuration errors.
    pub fn activate_tun() -> io::Result<()> {
        activate(index()?)
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
            for (family, prefix, address) in [
                (2_u8, 32, peer.addresses.ipv4.octets().to_vec()),
                (10, 128, peer.addresses.ipv6.octets().to_vec()),
            ] {
                let mut payload = vec![family, prefix, 0, 0, 254, 4, 253, 1, 0, 0, 0, 0];
                attribute(&mut payload, 1, &address)?;
                attribute(&mut payload, 4, &index.to_ne_bytes())?;
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
    /// Recover public host prefixes from retained peers before removing orphan keys.
    /// # Errors
    /// Refuses malformed `AllowedIPs`. All dump buffers, including unparsed secret
    /// fields in later replies, are zeroized together even on an early error.
    pub fn peer_routes() -> io::Result<BTreeSet<IpAddr>> {
        let mut socket = Socket::open(SockProtocol::NetlinkGeneric)?;
        let family = socket.family("wireguard")?;
        let mut payload = header();
        payload[0] = 0;
        let replies = Zeroizing::new(socket.request(family, 0x300, &payload)?);
        let mut routes = BTreeSet::new();
        for reply in replies.iter() {
            for device in netlink::attributes(reply.get(4..).ok_or(io::ErrorKind::InvalidData)?)? {
                if device.kind != 8 {
                    continue;
                }
                for peer in netlink::attributes(device.payload)? {
                    for field in netlink::attributes(peer.payload)? {
                        if field.kind != 9 {
                            continue;
                        }
                        for prefix in netlink::attributes(field.payload)? {
                            if let Some(address) = netlink::host_address(prefix.payload)? {
                                routes.insert(address);
                            }
                        }
                    }
                }
            }
        }
        Ok(routes)
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
        let mut socket = Socket::open(SockProtocol::NetlinkGeneric)?;
        let family = socket.family("wireguard")?;
        let mut payload = header();
        payload[0] = 0;
        let mut key = None;
        let mut port = None;
        for reply in socket.request(family, 0x300, &payload)? {
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
fn activate(index: u32) -> io::Result<()> {
    let mut payload = vec![0; 16];
    payload[4..8].copy_from_slice(&index.to_ne_bytes());
    payload[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    payload[12..16].copy_from_slice(&1_u32.to_ne_bytes());
    attribute(&mut payload, 4, &1380_u32.to_ne_bytes())?;
    Socket::open(SockProtocol::NetlinkRoute)?.request(16, 4, &payload)?;
    Ok(())
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
            .chain(upserted.iter().map(|p| (&p.key, Some(p))))
        {
            let mut encoded = Vec::new();
            attribute(&mut encoded, 1, &key.0)?;
            attribute(
                &mut encoded,
                3,
                &if peer.is_some() { 2_u32 } else { 1_u32 }.to_ne_bytes(),
            )?;
            if let Some(peer) = peer {
                // Both ends send, preserving stateful firewall mappings even
                // when only one side currently has application traffic [228].
                attribute(&mut encoded, 5, &25_u16.to_ne_bytes())?;
                if let Some(endpoint) = peer.endpoint {
                    attribute(&mut encoded, 4, &sockaddr(endpoint))?;
                }
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
