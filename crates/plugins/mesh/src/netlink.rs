//! Typed, bounded Linux netlink framing and synchronous kernel transactions [169], #129.
//!
//! No struct casts or unsafe pointers: native-endian scalar fields are checked
//! before reading. Payloads are borrowed; malformed padding cannot desynchronize
//! the next record. Only a kernel-origin reply for this request is accepted.
#![cfg_attr(test, allow(clippy::unwrap_used))]
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recvfrom, sendto,
    socket,
};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, OwnedFd},
};

const HEADER: usize = 16;
/// Kernel netlink attributes use two high flag bits, outside the type number.
pub const NESTED: u16 = 1 << 15;
const TYPE_MASK: u16 = 0x3fff;
/// Bounded datagram size; peer batching reserves the headers and never exceeds it.
pub const DATAGRAM_BYTES: usize = 60 * 1024;

/// A parsed netlink attribute; nested content is parsed with the same iterator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attribute<'a> {
    pub kind: u16,
    pub nested: bool,
    pub payload: &'a [u8],
}
/// Parse checked aligned attributes without allocation.
/// # Errors
/// Refuses truncated headers/payloads, short lengths and nonzero padding.
pub fn attributes(mut bytes: &[u8]) -> io::Result<Vec<Attribute<'_>>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return invalid();
        }
        let length = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]);
        let aligned = align(length);
        if length < 4
            || aligned < length
            || aligned > bytes.len()
            || bytes[length..aligned].iter().any(|b| *b != 0)
        {
            return invalid();
        }
        result.push(Attribute {
            kind: kind & TYPE_MASK,
            nested: kind & NESTED != 0,
            payload: &bytes[4..length],
        });
        bytes = &bytes[aligned..];
    }
    Ok(result)
}
/// Decode one `WireGuard` `AllowedIP`; only host prefixes can own peer routes.
/// # Errors
/// Refuses missing/duplicate fields, invalid scalar widths and family/prefix mismatches.
pub fn host_address(bytes: &[u8]) -> io::Result<Option<IpAddr>> {
    let mut family = None;
    let mut address = None;
    let mut prefix = None;
    for field in attributes(bytes)? {
        match field.kind {
            1 if family.is_none() => {
                family = Some(u16::from_ne_bytes(
                    field.payload.try_into().map_err(io::Error::other)?,
                ));
            }
            2 if address.is_none() => address = Some(field.payload),
            3 if prefix.is_none() => {
                prefix = Some(<[u8; 1]>::try_from(field.payload).map_err(io::Error::other)?[0]);
            }
            1..=3 => return invalid(),
            _ => {}
        }
    }
    match (family, prefix, address) {
        (Some(2), Some(prefix @ 0..=32), Some(bytes)) => {
            let address = IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(bytes).map_err(io::Error::other)?,
            ));
            Ok((prefix == 32).then_some(address))
        }
        (Some(10), Some(prefix @ 0..=128), Some(bytes)) => {
            let address = IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes).map_err(io::Error::other)?,
            ));
            Ok((prefix == 128).then_some(address))
        }
        _ => invalid(),
    }
}
/// Initiating endpoint and service from a checked connection-state tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionTuple {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub destination_port: Option<u16>,
}
/// Decode nested connection-state tuple attributes without assuming a protocol layout.
/// # Errors
/// Refuses duplicate selectors, mixed address families and invalid scalar widths.
pub fn connection_tuple(bytes: &[u8]) -> io::Result<ConnectionTuple> {
    let mut ip = None;
    let mut protocol = None;
    for field in attributes(bytes)? {
        match field.kind {
            1 if ip.is_none() => ip = Some(field.payload),
            2 if protocol.is_none() => protocol = Some(field.payload),
            1 | 2 => return invalid(),
            _ => {}
        }
    }
    let mut source = None;
    let mut destination = None;
    for field in attributes(ip.ok_or(io::ErrorKind::InvalidData)?)? {
        let (slot, address) = match field.kind {
            1 | 2 => (
                if field.kind == 1 {
                    &mut source
                } else {
                    &mut destination
                },
                IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(field.payload).map_err(io::Error::other)?,
                )),
            ),
            3 | 4 => (
                if field.kind == 3 {
                    &mut source
                } else {
                    &mut destination
                },
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(field.payload).map_err(io::Error::other)?,
                )),
            ),
            _ => continue,
        };
        if slot.replace(address).is_some() {
            return invalid();
        }
    }
    let mut number = None;
    let mut port = None;
    for field in attributes(protocol.ok_or(io::ErrorKind::InvalidData)?)? {
        match field.kind {
            1 if number.is_none() => {
                number = Some(<[u8; 1]>::try_from(field.payload).map_err(io::Error::other)?[0]);
            }
            3 if port.is_none() => {
                port = Some(u16::from_be_bytes(
                    field.payload.try_into().map_err(io::Error::other)?,
                ));
            }
            1 | 3 => return invalid(),
            _ => {}
        }
    }
    let source = source.ok_or(io::ErrorKind::InvalidData)?;
    let destination = destination.ok_or(io::ErrorKind::InvalidData)?;
    let protocol = number.ok_or(io::ErrorKind::InvalidData)?;
    if source.is_ipv4() != destination.is_ipv4() || (matches!(protocol, 6 | 17) && port.is_none()) {
        return invalid();
    }
    Ok(ConnectionTuple {
        source,
        destination,
        protocol,
        destination_port: port,
    })
}

/// Parsed kernel message. Unknown types remain available for generic families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message<'a> {
    pub kind: u16,
    pub flags: u16,
    pub sequence: u32,
    pub payload: &'a [u8],
}
/// Parse complete datagrams; a partial final message is never accepted.
/// # Errors
/// Refuses invalid lengths, unaligned truncation and nonzero padding.
pub fn messages(mut bytes: &[u8]) -> io::Result<Vec<Message<'_>>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < HEADER {
            return invalid();
        }
        let length = usize::try_from(u32_at(bytes, 0)?).map_err(io::Error::other)?;
        let aligned = align(length);
        if length < HEADER
            || aligned < length
            || aligned > bytes.len()
            || bytes[length..aligned].iter().any(|b| *b != 0)
        {
            return invalid();
        }
        result.push(Message {
            kind: u16::from_ne_bytes([bytes[4], bytes[5]]),
            flags: u16::from_ne_bytes([bytes[6], bytes[7]]),
            sequence: u32_at(bytes, 8)?,
            payload: &bytes[HEADER..length],
        });
        bytes = &bytes[aligned..];
    }
    Ok(result)
}
/// Write one attribute with checked kernel-width length and zero alignment.
/// # Errors
/// Refuses payloads too large for the netlink u16 attribute length.
pub fn attribute(target: &mut Vec<u8>, kind: u16, payload: &[u8]) -> io::Result<()> {
    let length = u16::try_from(payload.len().saturating_add(4)).map_err(io::Error::other)?;
    target.extend(length.to_ne_bytes());
    target.extend(kind.to_ne_bytes());
    target.extend(payload);
    target.resize(align(target.len()), 0);
    Ok(())
}
fn align(size: usize) -> usize {
    size.saturating_add(3) & !3
}
fn invalid<T>() -> io::Result<T> {
    Err(io::ErrorKind::InvalidData.into())
}
/// Read a checked native-endian u32 from a kernel payload.
/// # Errors
/// Refuses missing or truncated fields.
pub fn u32_at(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let field = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(io::ErrorKind::InvalidData)?;
    Ok(u32::from_ne_bytes(
        field.try_into().map_err(io::Error::other)?,
    ))
}

/// One owned kernel socket. Requests complete with an ACK, never by guessed timing.
pub struct Socket {
    fd: OwnedFd,
    sequence: u32,
    wire: zeroize::Zeroizing<Vec<u8>>,
    buffer: zeroize::Zeroizing<Vec<u8>>,
}
impl Socket {
    /// Open and bind a route or generic netlink socket in the current namespace.
    /// # Errors
    /// Reports kernel socket/bind errors.
    pub fn open(protocol: SockProtocol) -> io::Result<Self> {
        let fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC,
            protocol,
        )?;
        bind(fd.as_raw_fd(), &NetlinkAddr::new(0, 0))?;
        nix::sys::socket::setsockopt(
            &fd,
            nix::sys::socket::sockopt::ReceiveTimeout,
            &nix::sys::time::TimeVal::new(5, 0),
        )?;
        Ok(Self {
            fd,
            sequence: 0,
            wire: zeroize::Zeroizing::new(Vec::with_capacity(DATAGRAM_BYTES)),
            buffer: zeroize::Zeroizing::new(vec![0; 64 * 1024]),
        })
    }
    /// Execute one bounded request and collect matching kernel payloads until ACK/DONE.
    /// # Errors
    /// Refuses oversized requests, exhausted sequence numbers, malformed replies,
    /// foreign senders, interrupted dumps and negative kernel ACKs.
    pub fn request(
        &mut self,
        kind: u16,
        flags: u16,
        payload: &[u8],
    ) -> io::Result<Vec<zeroize::Zeroizing<Vec<u8>>>> {
        let mut replies = Vec::new();
        self.visit(kind, flags, payload, |reply| {
            replies.push(zeroize::Zeroizing::new(reply.to_vec()));
            Ok(())
        })?;
        Ok(replies)
    }
    /// Stream matching replies through a bounded buffer, without retaining a host-wide dump.
    /// # Errors
    /// Reports the same framing/kernel failures as request, or a visitor failure.
    pub fn visit(
        &mut self,
        kind: u16,
        flags: u16,
        payload: &[u8],
        mut visitor: impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        if payload.len().saturating_add(HEADER) > DATAGRAM_BYTES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.sequence = self.sequence.checked_add(1).ok_or(io::ErrorKind::Other)?;
        let wire = &mut self.wire;
        wire.clear();
        wire.extend(
            u32::try_from(HEADER + payload.len())
                .map_err(io::Error::other)?
                .to_ne_bytes(),
        );
        wire.extend(kind.to_ne_bytes());
        wire.extend((flags | 1).to_ne_bytes());
        wire.extend(self.sequence.to_ne_bytes());
        wire.extend(0_u32.to_ne_bytes());
        wire.extend(payload);
        sendto(
            self.fd.as_raw_fd(),
            wire,
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )?;
        let buffer = &mut self.buffer;
        loop {
            let (length, sender) = recvfrom::<NetlinkAddr>(self.fd.as_raw_fd(), buffer)?;
            if sender.is_none_or(|addr| addr.pid() != 0) || length == buffer.len() {
                return invalid();
            }
            for message in messages(&buffer[..length])? {
                if message.sequence != self.sequence || message.flags & 0x10 != 0 {
                    return invalid();
                }
                match message.kind {
                    2 => {
                        let error = i32::from_ne_bytes(u32_at(message.payload, 0)?.to_ne_bytes());
                        if error != 0 {
                            return Err(io::Error::from_raw_os_error(
                                error.checked_neg().ok_or(io::ErrorKind::InvalidData)?,
                            ));
                        }
                        return Ok(());
                    }
                    3 => {
                        if !message.payload.is_empty() && u32_at(message.payload, 0)? != 0 {
                            return invalid();
                        }
                        return Ok(());
                    }
                    1 => {}
                    _ => visitor(message.payload)?,
                }
            }
        }
    }
    /// Resolve the kernel's dynamic generic-netlink family identifier.
    /// # Errors
    /// Reports an unavailable family or malformed control reply.
    pub fn family(&mut self, name: &str) -> io::Result<u16> {
        if name.as_bytes().contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut payload = vec![3, 2, 0, 0];
        let mut name = name.as_bytes().to_vec();
        name.push(0);
        attribute(&mut payload, 2, &name)?;
        for reply in self.request(0x10, 4, &payload)? {
            let body = reply.get(4..).ok_or(io::ErrorKind::InvalidData)?;
            for attr in attributes(body)? {
                if attr.kind == 1 && attr.payload.len() == 2 {
                    return Ok(u16::from_ne_bytes([attr.payload[0], attr.payload[1]]));
                }
            }
        }
        Err(io::ErrorKind::NotFound.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_lengths_and_padding_are_rejected() {
        for bad in [
            &[0][..],
            &[3, 0, 1, 0],
            &[5, 0, 1, 0, 7],
            &[5, 0, 1, 0, 7, 0, 0, 1],
        ] {
            assert!(attributes(bad).is_err());
        }
        for n in 0_u32..32 {
            let mut bad = vec![0; 16];
            bad[..4].copy_from_slice(&n.to_ne_bytes());
            assert_eq!(messages(&bad).is_ok(), n == 16);
        }
    }
    #[test]
    fn nested_attributes_roundtrip_without_copying_payloads() {
        let mut inner = Vec::new();
        attribute(&mut inner, 1, &[1, 2, 3]).unwrap();
        let mut outer = Vec::new();
        attribute(&mut outer, 8 | NESTED, &inner).unwrap();
        let attr = attributes(&outer).unwrap();
        assert!(attr[0].nested);
        assert_eq!(attributes(attr[0].payload).unwrap()[0].payload, &[1, 2, 3]);
    }
    fn connection(protocol: u8, ip: &[(u16, &[u8])], port: Option<&[u8]>) -> Vec<u8> {
        let mut addresses = Vec::new();
        for (kind, bytes) in ip {
            attribute(&mut addresses, *kind, bytes).unwrap();
        }
        let mut service = Vec::new();
        attribute(&mut service, 1, &[protocol]).unwrap();
        if let Some(port) = port {
            attribute(&mut service, 3, port).unwrap();
        }
        let mut tuple = Vec::new();
        attribute(&mut tuple, 1 | NESTED, &addresses).unwrap();
        attribute(&mut tuple, 2 | NESTED, &service).unwrap();
        tuple
    }
    #[test]
    fn connection_tuple_uses_initiating_service_and_refuses_ambiguous_selectors() {
        let source = [10, 254, 0, 1];
        let destination = [10, 254, 0, 2];
        let ip = [(1, source.as_slice()), (2, destination.as_slice())];
        for protocol in [6, 17] {
            assert_eq!(
                connection_tuple(&connection(protocol, &ip, Some(&[0x15, 0xa4]))).unwrap(),
                ConnectionTuple {
                    source: "10.254.0.1".parse().unwrap(),
                    destination: "10.254.0.2".parse().unwrap(),
                    protocol,
                    destination_port: Some(5540),
                }
            );
        }
        assert!(connection_tuple(&connection(6, &ip, None)).is_err());
        assert!(connection_tuple(&connection(17, &ip, Some(&[0]))).is_err());
        assert!(
            connection_tuple(&connection(
                6,
                &[(1, &source), (1, &destination), (2, &destination)],
                Some(&[0, 1])
            ))
            .is_err()
        );
        assert!(
            connection_tuple(&connection(
                6,
                &[(1, &source), (4, &[0; 16])],
                Some(&[0, 1])
            ))
            .is_err()
        );
        assert!(
            connection_tuple(&connection(1, &ip, None))
                .unwrap()
                .destination_port
                .is_none()
        );
        let v6 = [(3, [0_u8; 16].as_slice()), (4, [1_u8; 16].as_slice())];
        assert!(
            connection_tuple(&connection(17, &v6, Some(&[0xff, 0xff])))
                .unwrap()
                .source
                .is_ipv6()
        );
    }
    fn allowed_ip(family: u16, address: &[u8], prefix: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        attribute(&mut bytes, 1, &family.to_ne_bytes()).unwrap();
        attribute(&mut bytes, 2, address).unwrap();
        attribute(&mut bytes, 3, &[prefix]).unwrap();
        bytes
    }
    #[test]
    fn public_host_prefixes_decode_both_families_without_claiming_subnets() {
        let ipv4 = [10, 254, 0, 2];
        let ipv6 = "fd01::2".parse::<Ipv6Addr>().unwrap().octets();
        assert_eq!(
            host_address(&allowed_ip(2, &ipv4, 32)).unwrap(),
            Some("10.254.0.2".parse().unwrap())
        );
        assert_eq!(
            host_address(&allowed_ip(10, &ipv6, 128)).unwrap(),
            Some("fd01::2".parse().unwrap())
        );
        assert_eq!(host_address(&allowed_ip(2, &ipv4, 24)).unwrap(), None);
        assert_eq!(host_address(&allowed_ip(10, &ipv6, 64)).unwrap(), None);
    }
    #[test]
    fn host_prefix_decoder_refuses_ambiguous_or_malformed_ownership() {
        for bytes in [
            allowed_ip(2, &[10, 254, 0], 32),
            allowed_ip(10, &[0; 4], 128),
            allowed_ip(2, &[10, 254, 0, 2], 33),
            allowed_ip(10, &[0; 16], 129),
            allowed_ip(1, &[0; 4], 32),
        ] {
            assert!(host_address(&bytes).is_err());
        }
        let mut duplicate = allowed_ip(2, &[10, 254, 0, 2], 32);
        attribute(&mut duplicate, 1, &2_u16.to_ne_bytes()).unwrap();
        assert!(host_address(&duplicate).is_err());
        let mut short_family = Vec::new();
        attribute(&mut short_family, 1, &[2]).unwrap();
        assert!(host_address(&short_family).is_err());
        let mut missing_prefix = Vec::new();
        attribute(&mut missing_prefix, 1, &2_u16.to_ne_bytes()).unwrap();
        attribute(&mut missing_prefix, 2, &[10, 254, 0, 2]).unwrap();
        assert!(host_address(&missing_prefix).is_err());
    }
}
