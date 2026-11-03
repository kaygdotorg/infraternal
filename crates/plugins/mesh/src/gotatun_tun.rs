//! Linux TUN I/O for `GotaTun`, including virtio TSO metadata without the bundled TUN crate.
//!
//! One non-persistent queue is attached to the owned mesh interface. The kernel sends coalesced
//! TCP packets with virtio metadata; this adapter validates and segments them before `GotaTun` sees
//! them. The same interface writes complete IP packets back to the host stack.

use bytes::BytesMut;
use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
};
use infraternal_linux_tun::Device as TunDevice;
use std::{fs::File, io, sync::Arc};
use tokio::{io::unix::AsyncFd, sync::Mutex};

const VNET_HEADER_LEN: usize = 10;
const MESH_MTU: u16 = 1380;
const MAX_IP_PACKET_LEN: usize = 40 + u16::MAX as usize;
const MAX_TUN_FRAME_LEN: usize = VNET_HEADER_LEN + MAX_IP_PACKET_LEN;

/// Owns the TUN descriptor, its async registration, and reusable packet buffers.
#[derive(Clone)]
pub(crate) struct LinuxTun {
    fd: Arc<AsyncFd<File>>,
    name: Arc<str>,
    vnet_header: bool,
    offloads_enabled: bool,
    mtu: MtuWatcher,
    read_buffer: Arc<Mutex<Vec<u8>>>,
    write_buffer: Arc<Mutex<Vec<u8>>>,
}

impl LinuxTun {
    /// Create one non-persistent Linux TUN queue, preferring virtio TSO offloads.
    ///
    /// # Errors
    /// Reports device, ioctl, and async-registration failures. Permission errors name the
    /// `CAP_NET_ADMIN` requirement and the existing rootless own-traffic limit.
    pub(crate) fn create(name: &str) -> io::Result<Self> {
        let device = TunDevice::open(name).map_err(rootless_tun_error)?;
        let name = device.name().to_owned();
        let vnet_header = device.has_vnet_header();
        let offloads_enabled = device.offloads_enabled();
        // The safe Tokio constructor remains the adapter's only API under the workspace's
        // unsafe-code prohibition; the underlying descriptor was opened nonblocking.
        #[allow(deprecated)]
        let fd = AsyncFd::new(device.into_file())?;
        Ok(Self {
            fd: Arc::new(fd),
            name: Arc::from(name),
            vnet_header,
            offloads_enabled,
            mtu: MtuWatcher::new(MESH_MTU),
            read_buffer: Arc::new(Mutex::new(vec![0; MAX_TUN_FRAME_LEN])),
            write_buffer: Arc::new(Mutex::new(Vec::with_capacity(
                MESH_MTU as usize + VNET_HEADER_LEN,
            ))),
        })
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn offloads_enabled(&self) -> bool {
        self.offloads_enabled
    }

    /// The authenticated, decrypted packet delivery seam for future in-process services.
    /// Any interception belongs before the final TUN write; relay framing remains ciphertext-only.
    async fn send_packet(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let packet = packet.into_bytes();
        let mut mtu = self.mtu.clone();
        if packet.len() > usize::from(mtu.get()) {
            // GotaTun treats adapter errors as fatal to its packet workers. A decrypted oversized
            // packet cannot be delivered, but dropping it must not stop later valid traffic.
            return Ok(());
        }
        let mut buffer = self.write_buffer.lock().await;
        buffer.clear();
        if self.vnet_header {
            buffer.extend_from_slice(&[0; VNET_HEADER_LEN]);
        }
        buffer.extend_from_slice(packet.as_ref());
        loop {
            let mut ready = self.fd.writable().await?;
            match ready
                .try_io(|fd| nix::unistd::write(fd.get_ref(), &buffer).map_err(io::Error::from))
            {
                Err(_) => {}
                Ok(Err(error)) => return Err(error),
                Ok(Ok(written)) if written == buffer.len() => return Ok(()),
                Ok(Ok(_)) => return Err(io::ErrorKind::WriteZero.into()),
            }
        }
    }

    async fn recv_packets(
        &mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<std::vec::IntoIter<Packet<Ip>>> {
        let mut buffer = self.read_buffer.lock().await;
        loop {
            let mut ready = self.fd.readable().await?;
            let result = ready
                .try_io(|fd| nix::unistd::read(fd.get_ref(), &mut buffer).map_err(io::Error::from));
            match result {
                Err(_) => {}
                Ok(Err(error)) => return Err(error),
                Ok(Ok(0)) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(Ok(length)) => {
                    let packets = decode_frame(&buffer[..length], self.vnet_header, pool)?;
                    return Ok(packets.into_iter());
                }
            }
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}

impl IpSend for LinuxTun {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.send_packet(packet).await
    }
}

impl IpRecv for LinuxTun {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        self.recv_packets(pool).await
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu()
    }
}

fn rootless_tun_error(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::PermissionDenied {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "creating the mesh TUN requires CAP_NET_ADMIN; rootless mode today supports only infraternal agent own traffic through the local proxy",
        )
    } else {
        error
    }
}

fn decode_frame(
    frame: &[u8],
    vnet_header: bool,
    pool: &PacketBufPool,
) -> io::Result<Vec<Packet<Ip>>> {
    if !vnet_header {
        return Ok(vec![packet_from_pool(frame, pool)?]);
    }
    if frame.len() < VNET_HEADER_LEN {
        return Err(invalid_tun("truncated virtio network header"));
    }
    let header = &frame[..VNET_HEADER_LEN];
    let flags = header[0];
    let raw_gso_type = header[1];
    let gso_type = raw_gso_type & !0x80;
    let header_len = usize::from(u16::from_ne_bytes([header[2], header[3]]));
    let gso_size = usize::from(u16::from_ne_bytes([header[4], header[5]]));
    let csum_start = usize::from(u16::from_ne_bytes([header[6], header[7]]));
    let csum_offset = usize::from(u16::from_ne_bytes([header[8], header[9]]));
    if flags & !0x07 != 0 || flags & 0x04 != 0 || flags & 0x03 == 0x03 {
        return Err(invalid_tun("unsupported virtio network header flags"));
    }
    let packet = &frame[VNET_HEADER_LEN..];
    match gso_type {
        0 => {
            if raw_gso_type & 0x80 != 0 || gso_size != 0 {
                return Err(invalid_tun("invalid metadata for a non-GSO packet"));
            }
            let mut packet = packet.to_vec();
            let details = ip_details(&packet)?;
            packet.truncate(details.total_len);
            if flags & 0x01 != 0 {
                complete_partial_checksum(&mut packet, details, csum_start, csum_offset)?;
            }
            Ok(vec![packet_from_pool(&packet, pool)?])
        }
        1 | 4 => segment_tcp(
            packet,
            gso_type == 1,
            header_len,
            gso_size,
            flags & 0x01 != 0,
            csum_start,
            csum_offset,
        ),
        _ => Err(invalid_tun("unsupported TUN GSO type")),
    }
}

#[derive(Clone, Copy)]
struct IpDetails {
    version: u8,
    ip_header_len: usize,
    transport_offset: usize,
    total_len: usize,
    protocol: u8,
    fragmented: bool,
}

fn ip_details(packet: &[u8]) -> io::Result<IpDetails> {
    let version = packet
        .first()
        .map(|first| first >> 4)
        .ok_or_else(|| invalid_tun("empty IP packet"))?;
    match version {
        4 => {
            if packet.len() < 20 {
                return Err(invalid_tun("truncated IPv4 header"));
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            let fragment = u16::from_be_bytes([packet[6], packet[7]]);
            if header_len < 20
                || header_len > packet.len()
                || total_len < header_len
                || total_len > packet.len()
            {
                return Err(invalid_tun("invalid IPv4 lengths"));
            }
            Ok(IpDetails {
                version,
                ip_header_len: header_len,
                transport_offset: header_len,
                total_len,
                protocol: packet[9],
                fragmented: fragment & 0x3fff != 0,
            })
        }
        6 => {
            if packet.len() < 40 {
                return Err(invalid_tun("truncated IPv6 header"));
            }
            let total_len = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if total_len > packet.len() {
                return Err(invalid_tun("invalid IPv6 length"));
            }
            let mut protocol = packet[6];
            let mut transport_offset = 40;
            let mut fragmented = false;
            loop {
                let extension_len = match protocol {
                    0 | 43 | 60 | 135 | 139 | 140 => {
                        if transport_offset + 2 > total_len {
                            return Err(invalid_tun("truncated IPv6 extension header"));
                        }
                        (usize::from(packet[transport_offset + 1]) + 1) * 8
                    }
                    44 => {
                        fragmented = true;
                        8
                    }
                    51 => {
                        if transport_offset + 2 > total_len {
                            return Err(invalid_tun("truncated IPv6 authentication header"));
                        }
                        (usize::from(packet[transport_offset + 1]) + 2) * 4
                    }
                    _ => break,
                };
                let next = *packet
                    .get(transport_offset)
                    .ok_or_else(|| invalid_tun("truncated IPv6 extension header"))?;
                let next_offset = transport_offset
                    .checked_add(extension_len)
                    .ok_or_else(|| invalid_tun("IPv6 extension length overflow"))?;
                if extension_len == 0 || next_offset > total_len {
                    return Err(invalid_tun("invalid IPv6 extension length"));
                }
                protocol = next;
                transport_offset = next_offset;
            }
            Ok(IpDetails {
                version,
                ip_header_len: 40,
                transport_offset,
                total_len,
                protocol,
                fragmented,
            })
        }
        _ => Err(invalid_tun("unsupported IP version")),
    }
}

fn complete_partial_checksum(
    packet: &mut [u8],
    details: IpDetails,
    csum_start: usize,
    csum_offset: usize,
) -> io::Result<()> {
    if csum_start != details.transport_offset || details.fragmented {
        return Err(invalid_tun("invalid partial checksum start"));
    }
    let expected_offset = match details.protocol {
        6 => 16,
        17 => 6,
        _ => return Err(invalid_tun("unsupported partial checksum protocol")),
    };
    if csum_offset != expected_offset {
        return Err(invalid_tun("invalid partial checksum offset"));
    }
    recompute_transport_checksum(packet, details, csum_start, csum_offset)?;
    recompute_ipv4_checksum(packet, details);
    Ok(())
}

#[derive(Clone, Copy)]
struct TcpSegmentation {
    details: IpDetails,
    ipv4: bool,
    tcp_offset: usize,
    header_len: usize,
    payload_len: usize,
    segment_payload_len: usize,
    sequence: u32,
    identification: u16,
}

fn segment_tcp(
    packet: &[u8],
    ipv4: bool,
    header_len: usize,
    segment_payload_len: usize,
    needs_checksum: bool,
    csum_start: usize,
    csum_offset: usize,
) -> io::Result<Vec<Packet<Ip>>> {
    if segment_payload_len == 0 {
        return Err(invalid_tun("TCP GSO size must be nonzero"));
    }
    let details = ip_details(packet)?;
    if (details.version == 4) != ipv4 || details.protocol != 6 || details.fragmented {
        return Err(invalid_tun("TCP GSO metadata does not match the IP packet"));
    }
    let tcp_offset = details.transport_offset;
    let tcp_bytes = packet
        .get(tcp_offset..details.total_len)
        .ok_or_else(|| invalid_tun("truncated TCP packet"))?;
    if tcp_bytes.len() < 20 {
        return Err(invalid_tun("truncated TCP header"));
    }
    let tcp_header_len = usize::from(tcp_bytes[12] >> 4) * 4;
    if tcp_header_len < 20 || tcp_header_len > tcp_bytes.len() {
        return Err(invalid_tun("invalid TCP data offset"));
    }
    let packet_header_len = tcp_offset + tcp_header_len;
    if header_len != packet_header_len {
        return Err(invalid_tun("invalid TCP GSO header length"));
    }
    if needs_checksum && (csum_start != tcp_offset || csum_offset != 16) {
        return Err(invalid_tun("invalid TCP GSO checksum metadata"));
    }
    let payload_len = details.total_len - packet_header_len;
    let sequence = u32::from_be_bytes(
        packet[tcp_offset + 4..tcp_offset + 8]
            .try_into()
            .map_err(|_| invalid_tun("invalid TCP sequence number"))?,
    );
    let identification = if ipv4 {
        u16::from_be_bytes([packet[4], packet[5]])
    } else {
        0
    };
    segment_tcp_packets(
        packet,
        TcpSegmentation {
            details,
            ipv4,
            tcp_offset,
            header_len: packet_header_len,
            payload_len,
            segment_payload_len,
            sequence,
            identification,
        },
    )
}

fn segment_tcp_packets(packet: &[u8], plan: TcpSegmentation) -> io::Result<Vec<Packet<Ip>>> {
    let segment_count = plan.payload_len.max(1).div_ceil(plan.segment_payload_len);
    let output_capacity = plan
        .header_len
        .checked_mul(segment_count)
        .and_then(|headers| headers.checked_add(plan.payload_len))
        .ok_or_else(|| invalid_tun("TCP GSO packet size overflow"))?;
    let mut output = BytesMut::with_capacity(output_capacity);
    let mut segment_lengths = Vec::with_capacity(segment_count);
    let mut payload_offset = 0;
    for index in 0..segment_count {
        let current_payload_len = plan
            .payload_len
            .saturating_sub(payload_offset)
            .min(plan.segment_payload_len);
        let start = output.len();
        append_tcp_segment(
            &mut output,
            packet,
            plan,
            index,
            payload_offset,
            current_payload_len,
        )?;
        segment_lengths.push(output.len() - start);
        payload_offset += current_payload_len;
    }
    let mut packets = Vec::with_capacity(segment_count);
    for length in segment_lengths {
        let segment = output.split_to(length);
        let packet = Packet::from_bytes(segment)
            .try_into_ip()
            .map_err(|error| invalid_tun_owned(error.to_string()))?;
        packets.push(packet);
    }
    Ok(packets)
}

fn append_tcp_segment(
    output: &mut BytesMut,
    packet: &[u8],
    plan: TcpSegmentation,
    index: usize,
    payload_offset: usize,
    payload_len: usize,
) -> io::Result<()> {
    let start = output.len();
    output.extend_from_slice(&packet[..plan.header_len]);
    if payload_len != 0 {
        output.extend_from_slice(
            &packet
                [plan.header_len + payload_offset..plan.header_len + payload_offset + payload_len],
        );
    }
    let end = output.len();
    let segment = &mut output[start..end];
    let sequence_offset =
        u32::try_from(payload_offset).map_err(|_| invalid_tun("TCP sequence offset overflow"))?;
    segment[plan.tcp_offset + 4..plan.tcp_offset + 8]
        .copy_from_slice(&plan.sequence.wrapping_add(sequence_offset).to_be_bytes());
    let segment_count = plan.payload_len.max(1).div_ceil(plan.segment_payload_len);
    if index + 1 != segment_count {
        segment[plan.tcp_offset + 13] &= !(0x01 | 0x08);
    }
    if plan.ipv4 {
        let total = u16::try_from(segment.len())
            .map_err(|_| invalid_tun("IPv4 TSO segment is too large"))?;
        segment[2..4].copy_from_slice(&total.to_be_bytes());
        let identification_offset =
            u16::try_from(index).map_err(|_| invalid_tun("IPv4 TSO segment count overflow"))?;
        segment[4..6].copy_from_slice(
            &plan
                .identification
                .wrapping_add(identification_offset)
                .to_be_bytes(),
        );
    } else {
        let payload = u16::try_from(segment.len() - 40)
            .map_err(|_| invalid_tun("IPv6 TSO segment is too large"))?;
        segment[4..6].copy_from_slice(&payload.to_be_bytes());
    }
    recompute_transport_checksum(
        segment,
        IpDetails {
            total_len: segment.len(),
            ..plan.details
        },
        plan.tcp_offset,
        16,
    )?;
    recompute_ipv4_checksum(
        segment,
        IpDetails {
            total_len: segment.len(),
            ..plan.details
        },
    );
    Ok(())
}

fn recompute_transport_checksum(
    packet: &mut [u8],
    details: IpDetails,
    transport_offset: usize,
    checksum_offset: usize,
) -> io::Result<()> {
    let transport_len = details
        .total_len
        .checked_sub(transport_offset)
        .ok_or_else(|| invalid_tun("invalid transport length"))?;
    let checksum_start = transport_offset
        .checked_add(checksum_offset)
        .ok_or_else(|| invalid_tun("checksum offset overflow"))?;
    if checksum_start + 2 > details.total_len || details.total_len > packet.len() {
        return Err(invalid_tun("checksum field exceeds packet"));
    }
    packet[checksum_start..checksum_start + 2].fill(0);
    let checksum = if details.version == 4 {
        let length =
            u16::try_from(transport_len).map_err(|_| invalid_tun("IPv4 transport is too large"))?;
        let mut pseudo = [0_u8; 12];
        pseudo[..4].copy_from_slice(&packet[12..16]);
        pseudo[4..8].copy_from_slice(&packet[16..20]);
        pseudo[9] = details.protocol;
        pseudo[10..12].copy_from_slice(&length.to_be_bytes());
        internet_checksum(&[&pseudo, &packet[transport_offset..details.total_len]])
    } else {
        let length =
            u32::try_from(transport_len).map_err(|_| invalid_tun("IPv6 transport is too large"))?;
        let mut pseudo = [0_u8; 40];
        pseudo[..32].copy_from_slice(&packet[8..40]);
        pseudo[32..36].copy_from_slice(&length.to_be_bytes());
        pseudo[39] = details.protocol;
        internet_checksum(&[&pseudo, &packet[transport_offset..details.total_len]])
    };
    let checksum = if details.protocol == 17 && checksum == 0 {
        u16::MAX
    } else {
        checksum
    };
    packet[checksum_start..checksum_start + 2].copy_from_slice(&checksum.to_be_bytes());
    Ok(())
}

fn recompute_ipv4_checksum(packet: &mut [u8], details: IpDetails) {
    if details.version != 4 || details.ip_header_len < 20 || details.ip_header_len > packet.len() {
        return;
    }
    packet[10..12].fill(0);
    let checksum = internet_checksum(&[&packet[..details.ip_header_len]]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn internet_checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u64;
    for bytes in parts {
        let (chunks, remainder) = bytes.as_chunks::<2>();
        for word in chunks {
            sum += u64::from(u16::from_be_bytes(*word));
        }
        if let [last] = remainder {
            sum += u64::from(u16::from_be_bytes([*last, 0]));
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let folded = sum.to_be_bytes();
    !u16::from_be_bytes([folded[6], folded[7]])
}

fn packet_from_pool(bytes: &[u8], pool: &PacketBufPool) -> io::Result<Packet<Ip>> {
    let mut packet = pool.get();
    packet.buf_mut().clear();
    packet.buf_mut().extend_from_slice(bytes);
    packet
        .try_into_ip()
        .map_err(|error| invalid_tun_owned(error.to_string()))
}

fn invalid_tun(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_tun_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::{LinuxTun, decode_frame, internet_checksum};
    use gotatun::{
        packet::{Ip, Packet, PacketBufPool},
        tun::MtuWatcher,
    };
    use std::{fs::File, io::Read as _, os::unix::net::UnixStream, sync::Arc};
    use tokio::{io::unix::AsyncFd, sync::Mutex};

    fn ipv4_packet(length: usize) -> Packet<Ip> {
        let mut bytes = vec![0; length];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
        bytes[8] = 64;
        bytes[9] = 17;
        Packet::from_bytes(bytes::BytesMut::from(bytes.as_slice()))
            .try_into_ip()
            .unwrap()
    }

    #[tokio::test]
    async fn oversized_decrypted_packet_does_not_stop_the_next_valid_send() {
        let (mut reader, writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        let writer: std::os::fd::OwnedFd = writer.into();
        #[allow(deprecated)]
        let fd = AsyncFd::new(File::from(writer)).unwrap();
        let mut tun = LinuxTun {
            fd: Arc::new(fd),
            name: Arc::from("test-tun"),
            vnet_header: false,
            offloads_enabled: true,
            mtu: MtuWatcher::new(1380),
            read_buffer: Arc::new(Mutex::new(Vec::new())),
            write_buffer: Arc::new(Mutex::new(Vec::new())),
        };

        assert!(
            tun.send_packet(ipv4_packet(1381)).await.is_ok(),
            "an oversized decrypted packet should be dropped without stopping GotaTun"
        );
        let expected = ipv4_packet(20).into_bytes().to_vec();
        tun.send_packet(ipv4_packet(20)).await.unwrap();

        let mut actual = vec![0; expected.len()];
        reader.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected);
    }

    fn ipv4_tcp_frame(payload_len: usize) -> Vec<u8> {
        let mut frame = vec![0_u8; 10 + 20 + 20 + payload_len];
        frame[0] = 1;
        frame[1] = 1;
        frame[2..4].copy_from_slice(&40_u16.to_ne_bytes());
        frame[4..6].copy_from_slice(&1000_u16.to_ne_bytes());
        frame[6..8].copy_from_slice(&20_u16.to_ne_bytes());
        frame[8..10].copy_from_slice(&16_u16.to_ne_bytes());
        let packet = &mut frame[10..];
        packet[0] = 0x45;
        let packet_len = u16::try_from(packet.len()).unwrap();
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[4..6].copy_from_slice(&37_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 1, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 1, 0, 2]);
        packet[20..22].copy_from_slice(&40000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[24..28].copy_from_slice(&50_000_u32.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = 0x19;
        for (index, byte) in packet[40..].iter_mut().enumerate() {
            *byte = u8::try_from(index % 251).unwrap();
        }
        frame
    }

    fn ipv6_hop_by_hop_tcp_frame(payload_len: usize) -> Vec<u8> {
        let mut frame = vec![0_u8; 10 + 40 + 8 + 20 + payload_len];
        frame[0] = 1;
        frame[1] = 4;
        frame[2..4].copy_from_slice(&68_u16.to_ne_bytes());
        frame[4..6].copy_from_slice(&1000_u16.to_ne_bytes());
        frame[6..8].copy_from_slice(&48_u16.to_ne_bytes());
        frame[8..10].copy_from_slice(&16_u16.to_ne_bytes());
        let packet = &mut frame[10..];
        packet[0] = 0x60;
        let payload_size = u16::try_from(packet.len() - 40).unwrap();
        packet[4..6].copy_from_slice(&payload_size.to_be_bytes());
        packet[6] = 0;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[40] = 6;
        packet[48..50].copy_from_slice(&40000_u16.to_be_bytes());
        packet[50..52].copy_from_slice(&443_u16.to_be_bytes());
        packet[52..56].copy_from_slice(&50_000_u32.to_be_bytes());
        packet[60] = 0x50;
        packet[61] = 0x19;
        for (index, byte) in packet[68..].iter_mut().enumerate() {
            *byte = u8::try_from(index % 251).unwrap();
        }
        frame
    }

    fn tcp_checksum_v4(packet: &[u8]) -> u16 {
        let transport_len = u16::try_from(packet.len() - 20).unwrap();
        let mut pseudo = [0_u8; 12];
        pseudo[..4].copy_from_slice(&packet[12..16]);
        pseudo[4..8].copy_from_slice(&packet[16..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&transport_len.to_be_bytes());
        internet_checksum(&[&pseudo, &packet[20..]])
    }

    #[test]
    fn ipv4_tso_segments_tcp_and_repairs_lengths_sequences_and_checksums() {
        let pool = PacketBufPool::new(1);
        let packets = decode_frame(&ipv4_tcp_frame(2300), true, &pool).unwrap();
        assert_eq!(packets.len(), 3);
        let expected_lengths = [1040, 1040, 340];
        for (index, (packet, expected_len)) in packets.into_iter().zip(expected_lengths).enumerate()
        {
            let bytes = packet.into_bytes();
            assert_eq!(bytes.len(), expected_len);
            assert_eq!(
                usize::from(u16::from_be_bytes([bytes[2], bytes[3]])),
                expected_len
            );
            assert_eq!(
                u16::from_be_bytes([bytes[4], bytes[5]]),
                37 + u16::try_from(index).unwrap()
            );
            assert_eq!(
                u32::from_be_bytes(bytes[24..28].try_into().unwrap()),
                50_000 + u32::try_from(index).unwrap() * 1000
            );
            assert_eq!(internet_checksum(&[&bytes[..20]]), 0);
            assert_eq!(tcp_checksum_v4(&bytes), 0);
            if index < 2 {
                assert_eq!(bytes[33] & (0x01 | 0x08), 0);
            } else {
                assert_eq!(bytes[33] & (0x01 | 0x08), 0x01 | 0x08);
            }
        }
    }

    #[test]
    fn ipv6_hop_by_hop_tso_segments_tcp_and_repairs_lengths_sequences_and_checksums() {
        let pool = PacketBufPool::new(1);
        let packets = decode_frame(&ipv6_hop_by_hop_tcp_frame(2300), true, &pool).unwrap();
        assert_eq!(packets.len(), 3);
        let expected_lengths = [1068, 1068, 368];
        for (index, (packet, expected_len)) in packets.into_iter().zip(expected_lengths).enumerate()
        {
            let bytes = packet.into_bytes();
            assert_eq!(bytes.len(), expected_len);
            assert_eq!(
                usize::from(u16::from_be_bytes([bytes[4], bytes[5]])),
                expected_len - 40
            );
            assert_eq!(bytes[6], 0);
            assert_eq!(bytes[40], 6);
            assert_eq!(
                u32::from_be_bytes(bytes[52..56].try_into().unwrap()),
                50_000 + u32::try_from(index).unwrap() * 1000
            );
            let transport_len = u32::try_from(bytes.len() - 48).unwrap();
            let mut pseudo = [0_u8; 40];
            pseudo[..32].copy_from_slice(&bytes[8..40]);
            pseudo[32..36].copy_from_slice(&transport_len.to_be_bytes());
            pseudo[39] = 6;
            assert_eq!(internet_checksum(&[&pseudo, &bytes[48..]]), 0);
        }
    }

    #[test]
    fn malformed_virtio_header_is_rejected_before_packet_delivery() {
        let pool = PacketBufPool::new(1);
        let mut frame = ipv4_tcp_frame(100);
        frame[0] |= 0x80;
        assert!(decode_frame(&frame, true, &pool).is_err());
    }
}
