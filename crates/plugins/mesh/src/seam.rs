//! Seam C side channel on the kernel `WireGuard` port: send-only raw probes out, a filtered packet tap in [313].
//!
//! The kernel owns the `WireGuard` UDP socket, so a probe from any other socket
//! would learn another NAT mapping (#220 design §1). Probes therefore leave
//! with the `WireGuard` port as their UDP source:
//!
//! - **Send:** an `IPPROTO_RAW` socket. It is send-only by definition, so it
//!   never receives a copy of the port's traffic (an `IPPROTO_UDP` raw
//!   socket would be handed every incoming UDP packet). The NAT and local
//!   conntrack see the same 5-tuple as the kernel's own `WireGuard` packets.
//! - **Receive:** one `AF_PACKET` socket with a classic BPF filter that passes
//!   only unfragmented IPv4 UDP to the `WireGuard` port whose payload starts
//!   with the probe magic. The filter runs in the kernel before any copy, so
//!   `WireGuard` data never reaches userspace; the kernel `WireGuard` socket
//!   still sees the probe and drops it at its header check.
//!
//! IPv4 only in this slice; IPv6 needs `IPV6_HDRINCL` and its own filter.
//! Both sockets need `CAP_NET_RAW`, which the root mesh component has (D163).

use socket2::{Domain, Protocol, SockAddr, SockFilter, Socket, Type};
use std::{
    io::{self, Read},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::atomic::{AtomicU64, Ordering},
};

/// Probe payloads start with these bytes (`infraternal_plugin_relay::probe::MAGIC`).
pub const MAGIC: [u8; 4] = [0x2a, b'I', b'F', b'1'];
/// Bytes of each matching packet copied to userspace; a probe needs 112.
const SNAP: u32 = 256;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_RAW: i32 = 255;

/// One received probe datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    pub source: SocketAddrV4,
    pub payload: Vec<u8>,
}

/// The raw send socket and the filtered tap for one `WireGuard` port.
pub struct Seam {
    port: u16,
    raw: Socket,
    /// The packet tap, registered with tokio through the safe UDP socket
    /// wrapper: only `recv` is used, which any datagram socket supports.
    tap: tokio::net::UdpSocket,
    delivered: AtomicU64,
}

/// The classic BPF program: accept only incoming, unfragmented IPv4 UDP to
/// `port` whose payload starts with [`MAGIC`]. Offsets start at the IP header
/// because the tap is a `SOCK_DGRAM` packet socket. Each entry is
/// `(code, jump if true, jump if false, constant)`; a jump counts the
/// instructions after the current one.
#[must_use]
pub fn instructions(port: u16) -> [(u16, u8, u8, u32); 16] {
    const LD_W_ABS: u16 = 0x20;
    const LD_H_ABS: u16 = 0x28;
    const LD_B_ABS: u16 = 0x30;
    const LD_W_IND: u16 = 0x40;
    const LD_H_IND: u16 = 0x48;
    const LDX_B_MSH: u16 = 0xb1;
    const AND_K: u16 = 0x54;
    const JEQ_K: u16 = 0x15;
    const JSET_K: u16 = 0x45;
    const RET_K: u16 = 0x06;
    // SKF_AD_OFF + SKF_AD_PKTTYPE: the packet type, not packet bytes.
    const PKTTYPE: u32 = 0xffff_f004;
    const PACKET_OUTGOING: u32 = 4;
    const DROP: u8 = 15;
    let to_drop = |at: u8| DROP - at - 1;
    [
        (LD_W_ABS, 0, 0, PKTTYPE),
        (JEQ_K, to_drop(1), 0, PACKET_OUTGOING),
        (LD_B_ABS, 0, 0, 0),
        (AND_K, 0, 0, 0xf0),
        (JEQ_K, 0, to_drop(4), 0x40),
        (LD_B_ABS, 0, 0, 9),
        (JEQ_K, 0, to_drop(6), 17),
        // More-fragments flag or a fragment offset: never a whole probe.
        (LD_H_ABS, 0, 0, 6),
        (JSET_K, to_drop(8), 0, 0x3fff),
        (LDX_B_MSH, 0, 0, 0),
        (LD_H_IND, 0, 0, 2),
        (JEQ_K, 0, to_drop(11), u32::from(port)),
        (LD_W_IND, 0, 0, 8),
        (JEQ_K, 0, to_drop(13), u32::from_be_bytes(MAGIC)),
        (RET_K, 0, 0, SNAP),
        (RET_K, 0, 0, 0),
    ]
}

fn program(port: u16) -> Vec<SockFilter> {
    instructions(port)
        .iter()
        .map(|&(code, jt, jf, k)| SockFilter::new(code, jt, jf, k))
        .collect()
}

impl Seam {
    /// Open both sockets for the kernel `WireGuard` listen `port`. Call inside a tokio runtime.
    /// # Errors
    /// Fails without `CAP_NET_RAW` or if the filter is refused.
    pub fn open(port: u16) -> io::Result<Self> {
        if port == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
        raw.set_nonblocking(true)?;
        raw.set_cloexec(true)?;
        let tap = Socket::new(
            Domain::PACKET,
            Type::DGRAM,
            Some(Protocol::from(i32::from(ETH_P_IP.to_be()))),
        )?;
        tap.set_cloexec(true)?;
        tap.attach_filter(&program(port))?;
        tap.set_nonblocking(true)?;
        // Packets queued between socket() and the filter were not filtered.
        let mut scratch = [0_u8; SNAP as usize];
        while (&tap).read(&mut scratch).is_ok() {}
        Ok(Self {
            port,
            raw,
            tap: tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(
                std::os::fd::OwnedFd::from(tap),
            ))?,
            delivered: AtomicU64::new(0),
        })
    }

    /// The `WireGuard` port this seam speaks for.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Packets the filter passed to userspace so far, valid or not.
    #[must_use]
    pub fn delivered(&self) -> u64 {
        self.delivered.load(Ordering::Relaxed)
    }

    /// Send `payload` as one UDP datagram from the `WireGuard` port.
    /// # Errors
    /// Fails if no route exists or the raw send fails.
    pub fn send(&self, destination: SocketAddrV4, payload: &[u8]) -> io::Result<()> {
        // The route decides the source address; connecting a UDP socket asks
        // the kernel without sending anything.
        let route = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        route.connect(destination)?;
        let SocketAddr::V4(source) = route.local_addr()? else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        let packet = datagram(*source.ip(), self.port, destination, payload)?;
        self.raw
            .send_to(&packet, &SockAddr::from(SocketAddr::V4(destination)))?;
        Ok(())
    }

    /// Wait for the next probe-shaped datagram to the `WireGuard` port.
    /// # Errors
    /// Fails only if the tap socket fails.
    pub async fn recv(&self) -> io::Result<Received> {
        let mut buffer = [0_u8; SNAP as usize];
        loop {
            let len = self.tap.recv(&mut buffer).await?;
            self.delivered.fetch_add(1, Ordering::Relaxed);
            if let Some(received) = parse(&buffer[..len], self.port) {
                return Ok(received);
            }
        }
    }
}

/// IPv4 header plus UDP header plus payload. The kernel fills the IP
/// identification and header checksum for an `IPPROTO_RAW` socket; the UDP
/// checksum is ours, so middleboxes that check it accept the probe.
fn datagram(
    source: Ipv4Addr,
    port: u16,
    destination: SocketAddrV4,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let udp_len = u16::try_from(8 + payload.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    let total = udp_len.checked_add(20).ok_or(io::ErrorKind::InvalidInput)?;
    let mut packet = Vec::with_capacity(usize::from(total));
    packet.extend_from_slice(&[0x45, 0]);
    packet.extend_from_slice(&total.to_be_bytes());
    // Identification 0 (kernel fills), don't-fragment, TTL 64, UDP.
    packet.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&destination.ip().octets());
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(&destination.port().to_be_bytes());
    packet.extend_from_slice(&udp_len.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(payload);
    let checksum = udp_checksum(source, *destination.ip(), &packet[20..]);
    packet[26..28].copy_from_slice(&checksum.to_be_bytes());
    Ok(packet)
}

fn udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |bytes: &[u8]| {
        for pair in bytes.chunks(2) {
            let word = u16::from_be_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]);
            sum += u32::from(word);
        }
    };
    add(&source.octets());
    add(&destination.octets());
    add(&[0, 17]);
    add(&u16::try_from(segment.len())
        .unwrap_or(u16::MAX)
        .to_be_bytes());
    add(segment);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // A computed zero is sent as all ones; zero means "no checksum" in IPv4.
    match !u16::try_from(sum).unwrap_or(0) {
        0 => 0xffff,
        checksum => checksum,
    }
}

/// Parse one tapped IPv4 UDP datagram; `None` for anything malformed or not to `port`.
fn parse(packet: &[u8], port: u16) -> Option<Received> {
    let header = usize::from(packet.first()? & 0x0f) * 4;
    if packet.first()? >> 4 != 4 || header < 20 || packet.get(9)? != &17 {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
    let udp = packet.get(header..total.min(packet.len()))?;
    let udp_len = usize::from(u16::from_be_bytes([*udp.get(4)?, *udp.get(5)?]));
    if u16::from_be_bytes([*udp.get(2)?, *udp.get(3)?]) != port || udp_len < 8 {
        return None;
    }
    let source = SocketAddrV4::new(
        Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        u16::from_be_bytes([udp[0], udp[1]]),
    );
    Some(Received {
        source,
        payload: udp.get(8..udp_len)?.to_vec(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! Packet construction and parsing; the kernel filter itself runs in the namespace proof.
    use super::*;

    #[test]
    fn built_datagrams_parse_back_with_a_valid_checksum() {
        let source = Ipv4Addr::new(10, 0, 0, 2);
        let destination = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 7777);
        for payload in [&b""[..], b"x", &[0x2a; 84][..]] {
            let packet = datagram(source, 51_001, destination, payload).unwrap();
            assert_eq!(packet.len(), 28 + payload.len());
            let mut udp = packet[20..].to_vec();
            let stored = u16::from_be_bytes([udp[6], udp[7]]);
            udp[6..8].copy_from_slice(&[0, 0]);
            assert_eq!(udp_checksum(source, *destination.ip(), &udp), stored);
            let received = parse(&packet, 7777).unwrap();
            assert_eq!(received.payload, payload);
            assert_eq!(received.source, SocketAddrV4::new(source, 51_001));
        }
    }

    #[test]
    fn malformed_or_foreign_packets_are_ignored() {
        let packet = datagram(
            Ipv4Addr::new(10, 0, 0, 2),
            1000,
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 2000),
            b"payload",
        )
        .unwrap();
        assert!(parse(&packet, 2000).is_some());
        assert!(parse(&packet, 2001).is_none(), "another port");
        for len in 0..packet.len() {
            // Truncated captures never panic; short ones are refused.
            let _ = parse(&packet[..len], 2000);
        }
        let mut lying = packet.clone();
        lying[25] = 200;
        assert!(parse(&lying, 2000).is_none(), "UDP length past the packet");
        let mut options = packet.clone();
        options[0] = 0x44;
        assert!(parse(&options, 2000).is_none(), "header shorter than 20");
        let mut v6 = packet;
        v6[0] = 0x65;
        assert!(parse(&v6, 2000).is_none());
    }

    #[test]
    fn every_filter_path_ends_in_a_return() {
        let program = instructions(51_820);
        for (at, &(code, jt, jf, _)) in program.iter().enumerate() {
            let class = code & 0x07;
            if class == 0x05 {
                for jump in [jt, jf] {
                    let target = at + 1 + usize::from(jump);
                    assert!(target < program.len(), "jump from {at} leaves the program");
                    assert!(target > at, "jumps only go forward");
                }
            }
        }
        assert_eq!(program[14], (0x06, 0, 0, SNAP));
        assert_eq!(program[15], (0x06, 0, 0, 0));
        assert_eq!(program[11].3, 51_820);
    }
}
