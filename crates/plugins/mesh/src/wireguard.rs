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
}
pub use crate::dataplane::Peer;
/// Kernel counters, available even while the coordinator is unreachable.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub handshake_secs: u64,
    pub received_bytes: u64,
    pub sent_bytes: u64,
}
/// Interface name is fixed: ownership never includes an operator's other interfaces.
pub const INTERFACE: &str = "infraternal0";

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
        attribute(&mut marker, 20, b"infraternal.mesh.v1\0")?;
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
        let mut payload = vec![0; 16];
        attribute(&mut payload, 3, b"infraternal0\0")?;
        let replies = match Socket::open(SockProtocol::NetlinkRoute)?.request(18, 4, &payload) {
            Ok(replies) => replies,
            Err(error) if error.raw_os_error() == Some(19) => return Ok(false),
            Err(error) => return Err(error),
        };
        for reply in replies {
            for field in netlink::attributes(reply.get(16..).ok_or(io::ErrorKind::InvalidData)?)? {
                if field.kind == 20 && field.payload == b"infraternal.mesh.v1\0" {
                    return Ok(true);
                }
            }
        }
        Err(io::ErrorKind::AlreadyExists.into())
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
        let mut payload = Zeroizing::new(header());
        attribute(&mut payload, 3, &key.0)?;
        attribute(&mut payload, 6, &port.to_ne_bytes())?;
        send(&payload)?;
        // A zero listen port is bound only when the kernel device is running.
        // Activate before advertising the public endpoint to the coordinator.
        activate(index()?)
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
        let mut counters = BTreeMap::new();
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
                    let mut stats = Counters::default();
                    for field in netlink::attributes(peer.payload)? {
                        match field.kind {
                            1 if field.payload.len() == 32 => {
                                key = Some(PublicKey(
                                    field.payload.try_into().map_err(io::Error::other)?,
                                ));
                            }
                            6 => stats.handshake_secs = scalar64(field.payload)?,
                            7 => stats.received_bytes = scalar64(field.payload)?,
                            8 => stats.sent_bytes = scalar64(field.payload)?,
                            _ => {}
                        }
                    }
                    if let Some(key) = key {
                        counters.insert(key, stats);
                    }
                }
            }
        }
        Ok(counters)
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
fn activate(index: u32) -> io::Result<()> {
    let mut payload = vec![0; 16];
    payload[4..8].copy_from_slice(&index.to_ne_bytes());
    payload[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    payload[12..16].copy_from_slice(&1_u32.to_ne_bytes());
    attribute(&mut payload, 4, &1380_u32.to_ne_bytes())?;
    Socket::open(SockProtocol::NetlinkRoute)?.request(16, 4, &payload)?;
    Ok(())
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
