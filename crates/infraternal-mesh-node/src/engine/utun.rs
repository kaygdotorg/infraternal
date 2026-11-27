//! Packet adapters for an already-open Apple utun file descriptor.

use crate::packet_filter::{Direction, PacketFilter};
use bytes::Buf;
use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
};
use nix::unistd::{read, write};
use std::{io, os::fd::OwnedFd, sync::Arc};
use tokio::io::unix::AsyncFd;

/// The Apple utun header value for IPv4.
const UTUN_AF_INET: u32 = 2;
/// The Apple utun header value for IPv6.
const UTUN_AF_INET6: u32 = 30;

/// Sends packets from `GotaTun` to one owned utun using its live interface MTU.
pub struct UtunTx {
    fd: Arc<AsyncFd<OwnedFd>>,
    mtu: MtuWatcher,
    frame: Vec<u8>,
    filter: Arc<PacketFilter>,
}

impl UtunTx {
    /// Send through the registered tunnel using its current MTU and inbound grant filter.
    #[must_use]
    pub fn new(fd: Arc<AsyncFd<OwnedFd>>, mtu: MtuWatcher, filter: Arc<PacketFilter>) -> Self {
        Self {
            fd,
            mtu,
            frame: Vec::with_capacity(usize::from(crate::mesh_mtu::IPV6_MINIMUM_MTU) + 4),
            filter,
        }
    }
}

impl IpSend for UtunTx {
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
pub struct UtunRx {
    fd: Arc<AsyncFd<OwnedFd>>,
    mtu: MtuWatcher,
    filter: Arc<PacketFilter>,
    /// Shared with the host's resolver integration.
    #[cfg(feature = "mesh-dns")]
    tunnel_dns: TunnelDns,
}

impl UtunRx {
    /// Receive from the registered tunnel using its current MTU and outbound grant filter.
    #[must_use]
    pub fn new(
        fd: Arc<AsyncFd<OwnedFd>>,
        mtu: MtuWatcher,
        filter: Arc<PacketFilter>,
        #[cfg(feature = "mesh-dns")] tunnel_dns: TunnelDns,
    ) -> Self {
        Self {
            fd,
            mtu,
            filter,
            #[cfg(feature = "mesh-dns")]
            tunnel_dns,
        }
    }
}

impl IpRecv for UtunRx {
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
                    if answer_resolver_query(self, packet.as_ref()) {
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

/// Return the utun address family for an IP packet.
/// # Errors
/// Rejects bytes without an IPv4 or IPv6 version nibble.
pub fn utun_family(packet: &[u8]) -> io::Result<u32> {
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
/// Validate the address-family header and return the IP payload.
///
/// # Errors
/// Rejects short frames, incorrect address families, and payloads above the current MTU.
pub fn parse_utun_payload(frame: &[u8], mtu: u16) -> io::Result<&[u8]> {
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

/// What the receive path needs to answer queries to the mesh resolver address: the address
/// and the current name snapshot, replaced as a whole on every accepted snapshot.
#[cfg(feature = "mesh-dns")]
pub type TunnelDns =
    std::sync::Arc<std::sync::RwLock<Option<(std::net::Ipv6Addr, crate::dns::Records)>>>;

/// Answer `packet` when it is a query to the mesh resolver address (#146, J1027 F2).
///
/// Returns whether the packet was consumed. The reply goes straight back into the utun, so
/// the query never reaches the packet filter or a peer. A reply that cannot be written at
/// once is dropped like any lost datagram; the system resolver asks again. Root mode, and
/// user mode before the first DNS snapshot, consume nothing.
#[cfg(feature = "mesh-dns")]
fn answer_resolver_query(rx: &mut UtunRx, packet: &[u8]) -> bool {
    if !crate::tunnel_dns::looks_like_resolver_query(packet) {
        return false;
    }
    let mtu = usize::from(rx.mtu.get());
    let guard = rx
        .tunnel_dns
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some((resolver, records)) = guard.as_ref() else {
        return false;
    };
    let Some(reply) = crate::tunnel_dns::answer(packet, *resolver, records, mtu) else {
        // A packet to the resolver address is never for a peer; drop it either way.
        return packet[24..40] == resolver.octets();
    };
    drop(guard);
    let mut frame = Vec::with_capacity(reply.len() + 4);
    frame.extend_from_slice(&UTUN_AF_INET6.to_be_bytes());
    frame.extend_from_slice(&reply);
    let _ = nix::unistd::write(rx.fd.get_ref(), &frame);
    true
}
