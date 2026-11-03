//! Linux TUN I/O for `GotaTun`, including virtio TSO metadata without the bundled TUN crate.
//!
//! One non-persistent queue is attached to the owned mesh interface. The kernel sends coalesced
//! TCP packets with virtio metadata; this adapter validates and segments them before `GotaTun` sees
//! them. Decrypted packets go back to the host stack through one writer task, which merges
//! consecutive segments of a TCP flow into virtio GSO frames (GRO), so the kernel takes a run of
//! segments in one write and one pass through its stack.

use bytes::BytesMut;
use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
};
use infraternal_linux_tun::Device as TunDevice;
use nix::errno::Errno;
use std::{
    fs::File,
    io,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    io::unix::AsyncFd,
    sync::{Mutex, mpsc},
};

const VNET_HEADER_LEN: usize = 10;
const MESH_MTU: u16 = 1380;
const MAX_IP_PACKET_LEN: usize = 40 + u16::MAX as usize;
const MAX_TUN_FRAME_LEN: usize = VNET_HEADER_LEN + MAX_IP_PACKET_LEN;
/// Decrypted packets queued for the TUN writer.
const WRITE_QUEUE: usize = 256;
/// Most queued packets the writer takes in one pass.
const GRO_BATCH: usize = 64;
/// Most TCP segments merged into one GSO frame.
const GRO_MAX_SEGMENTS: usize = 64;
const TCP_FIN: u8 = 0x01;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const TCP_CWR: u8 = 0x80;
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 0x01;
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;

/// Owns the TUN descriptor, its async registration, and reusable packet buffers.
#[derive(Clone)]
pub(crate) struct LinuxTun {
    fd: Arc<AsyncFd<File>>,
    name: Arc<str>,
    vnet_header: bool,
    offloads_enabled: bool,
    mtu: MtuWatcher,
    read_buffer: Arc<Mutex<Vec<u8>>>,
    writer: TunWriter,
    refused: Arc<AtomicU64>,
}

impl LinuxTun {
    /// Create one non-persistent Linux TUN queue, preferring virtio TSO offloads. Must run inside
    /// the engine's Tokio runtime, which also runs the TUN writer task.
    ///
    /// # Errors
    /// Reports device, ioctl, and async-registration failures. Permission errors name the
    /// `CAP_NET_ADMIN` requirement and the existing rootless own-traffic limit.
    pub(crate) fn create(name: &str, refused: Arc<AtomicU64>) -> io::Result<Self> {
        let device = TunDevice::open(name).map_err(rootless_tun_error)?;
        let name = device.name().to_owned();
        let vnet_header = device.has_vnet_header();
        let offloads_enabled = device.offloads_enabled();
        // The safe Tokio constructor remains the adapter's only API under the workspace's
        // unsafe-code prohibition; the underlying descriptor was opened nonblocking.
        #[allow(deprecated)]
        let fd = Arc::new(AsyncFd::new(device.into_file())?);
        Ok(Self {
            writer: TunWriter::spawn(Arc::clone(&fd), vnet_header),
            fd,
            name: Arc::from(name),
            vnet_header,
            offloads_enabled,
            mtu: MtuWatcher::new(MESH_MTU),
            read_buffer: Arc::new(Mutex::new(vec![0; MAX_TUN_FRAME_LEN])),
            refused,
        })
    }

    /// A `LinuxTun` over any nonblocking descriptor, so tests can play the kernel's side.
    #[cfg(test)]
    pub(crate) fn from_fd(
        device: std::os::fd::OwnedFd,
        vnet_header: bool,
        refused: Arc<AtomicU64>,
    ) -> io::Result<Self> {
        #[allow(deprecated)]
        let fd = Arc::new(AsyncFd::new(File::from(device))?);
        Ok(Self {
            writer: TunWriter::spawn(Arc::clone(&fd), vnet_header),
            fd,
            name: Arc::from("test-tun"),
            vnet_header,
            offloads_enabled: true,
            mtu: MtuWatcher::new(MESH_MTU),
            read_buffer: Arc::new(Mutex::new(vec![0; MAX_TUN_FRAME_LEN])),
            refused,
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
        self.writer.send(packet).await
    }

    /// Read the next decodable frame from the host stack.
    ///
    /// `GotaTun` treats any error from here as the TUN being deleted and stops all outbound
    /// traffic for good, and it counts `InvalidData`, which every decode refusal uses, among those.
    /// Anything on the host that can write a raw packet to a mesh route can produce a frame this
    /// adapter refuses (#260 J143 P2-1). So a refused frame is dropped and counted, as the kernel
    /// would drop a malformed packet, and only EOF or a device-gone errno reaches `GotaTun`.
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
                Ok(Err(error)) if device_gone(&error).is_some() => return Err(error),
                // Any other read error concerns one frame; the next read decides again.
                Ok(Err(_)) => {
                    self.refused.fetch_add(1, Ordering::Relaxed);
                }
                Ok(Ok(0)) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(Ok(length)) => match decode_frame(&buffer[..length], self.vnet_header, pool) {
                    Ok(packets) => return Ok(packets.into_iter()),
                    Err(_) => {
                        self.refused.fetch_add(1, Ordering::Relaxed);
                    }
                },
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

/// Hands decrypted packets to the task that owns every TUN write.
///
/// `GotaTun` calls the adapter one packet at a time from its own send task, so the adapter cannot
/// see what follows a packet. The writer takes whatever is queued when it runs: a busy link fills
/// a batch for GRO, and a single packet on an idle link is written at once, without a timer.
#[derive(Clone)]
struct TunWriter {
    packets: mpsc::Sender<Packet<[u8]>>,
    /// The device error that ended the writer; `GotaTun` stops its send task on it too.
    failure: Arc<OnceLock<Errno>>,
}

impl TunWriter {
    /// Spawn the writer on the current Tokio runtime.
    fn spawn(fd: Arc<AsyncFd<File>>, vnet_header: bool) -> Self {
        let (packets, queue) = mpsc::channel(WRITE_QUEUE);
        let failure = Arc::new(OnceLock::new());
        tokio::spawn(write_queued(fd, vnet_header, queue, Arc::clone(&failure)));
        Self { packets, failure }
    }

    /// Queue one packet; its pool buffer returns once the writer has written it.
    async fn send(&self, packet: Packet<[u8]>) -> io::Result<()> {
        if self.packets.send(packet).await.is_ok() {
            return Ok(());
        }
        Err(self
            .failure
            .get()
            .map_or_else(|| io::ErrorKind::BrokenPipe.into(), |errno| (*errno).into()))
    }
}

async fn write_queued(
    fd: Arc<AsyncFd<File>>,
    vnet_header: bool,
    mut queue: mpsc::Receiver<Packet<[u8]>>,
    failure: Arc<OnceLock<Errno>>,
) {
    let mut batch = Vec::with_capacity(GRO_BATCH);
    let mut frame = Vec::with_capacity(MAX_TUN_FRAME_LEN);
    while queue.recv_many(&mut batch, GRO_BATCH).await != 0 {
        if let Err(errno) = write_batch(&fd, vnet_header, &batch, &mut frame).await {
            let _ = failure.set(errno);
            return;
        }
        batch.clear();
    }
}

/// Write one batch in order. A frame the kernel refuses is dropped, as on a congested link; only a
/// device that is gone ends the writer.
async fn write_batch(
    fd: &AsyncFd<File>,
    vnet_header: bool,
    batch: &[Packet<[u8]>],
    frame: &mut Vec<u8>,
) -> Result<(), Errno> {
    let mut start = 0;
    while start < batch.len() {
        let run = if vnet_header {
            coalescible_run(batch, start)
        } else {
            1
        };
        let segments = &batch[start..start + run];
        let result = if run == 1 {
            frame.clear();
            if vnet_header {
                frame.extend_from_slice(&[0; VNET_HEADER_LEN]);
            }
            frame.extend_from_slice(&segments[0]);
            write_frame(fd, frame).await
        } else {
            match build_gso_frame(segments, frame) {
                Ok(()) => match write_frame(fd, frame).await {
                    // The kernel refused the merged frame: deliver its segments one at a time.
                    Err(error) if error.raw_os_error() == Some(Errno::EINVAL as i32) => {
                        write_each(fd, segments, frame).await
                    }
                    written => written,
                },
                Err(_) => write_each(fd, segments, frame).await,
            }
        };
        if let Err(error) = result
            && let Some(errno) = device_gone(&error)
        {
            return Err(errno);
        }
        start += run;
    }
    Ok(())
}

async fn write_each(
    fd: &AsyncFd<File>,
    segments: &[Packet<[u8]>],
    frame: &mut Vec<u8>,
) -> io::Result<()> {
    for segment in segments {
        frame.clear();
        frame.extend_from_slice(&[0; VNET_HEADER_LEN]);
        frame.extend_from_slice(segment);
        if let Err(error) = write_frame(fd, frame).await
            && device_gone(&error).is_some()
        {
            return Err(error);
        }
    }
    Ok(())
}

async fn write_frame(fd: &AsyncFd<File>, frame: &[u8]) -> io::Result<()> {
    loop {
        let mut ready = fd.writable().await?;
        match ready.try_io(|fd| nix::unistd::write(fd.get_ref(), frame).map_err(io::Error::from)) {
            Err(_) => {}
            Ok(Err(error)) => return Err(error),
            Ok(Ok(written)) if written == frame.len() => return Ok(()),
            Ok(Ok(_)) => return Err(io::ErrorKind::WriteZero.into()),
        }
    }
}

/// The TUN write errors after which the device takes no more packets, as `GotaTun` judges them.
fn device_gone(error: &io::Error) -> Option<Errno> {
    let errno = Errno::from_raw(error.raw_os_error()?);
    matches!(errno, Errno::EBADF | Errno::EBADFD | Errno::ENODEV).then_some(errno)
}

/// The fields of one decrypted TCP segment that decide whether it can join a GSO frame.
#[derive(Clone, Copy)]
struct GroSegment {
    ipv4: bool,
    ip_header_len: usize,
    /// IP and TCP headers together.
    header_len: usize,
    payload_len: usize,
    sequence: u32,
    /// The IPv4 identification; zero for IPv6, which has none outside a fragment header.
    identification: u16,
    flags: u8,
}

/// A segment the writer may merge: TCP over IPv4 without options or fragmentation, or over IPv6
/// without extension headers, carrying payload, with only ACK and PSH set. SYN, FIN, RST, URG,
/// ECE and CWR change connection state or carry congestion signals, so those go out alone.
fn gro_segment(packet: &[u8]) -> Option<GroSegment> {
    let (ipv4, ip_header_len, total_len, protocol) = match packet.first()? >> 4 {
        4 if packet.len() >= 20 && packet[0] & 0x0f == 5 => {
            // A merged frame gets a fresh header checksum, so a bad one must not merge: alone, the
            // segment reaches the kernel's IP input, which drops it (#260 J143 P3-2).
            if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0
                || internet_checksum(&[&packet[..20]]) != 0
            {
                return None;
            }
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            (true, 20, total, packet[9])
        }
        6 if packet.len() >= 40 => {
            let total = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            (false, 40, total, packet[6])
        }
        _ => return None,
    };
    if protocol != 6 || total_len != packet.len() {
        return None;
    }
    let tcp = &packet[ip_header_len..];
    let tcp_header_len = usize::from(*tcp.get(12)? >> 4) * 4;
    if tcp_header_len < 20 || tcp_header_len >= tcp.len() {
        return None;
    }
    let flags = tcp[13];
    if flags & !(TCP_ACK | TCP_PSH) != 0 || flags & TCP_ACK == 0 {
        return None;
    }
    Some(GroSegment {
        ipv4,
        ip_header_len,
        header_len: ip_header_len + tcp_header_len,
        payload_len: tcp.len() - tcp_header_len,
        sequence: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        identification: if ipv4 {
            u16::from_be_bytes([packet[4], packet[5]])
        } else {
            0
        },
        flags,
    })
}

/// Whether `next` carries `first`'s flow with every header byte that re-segmentation copies from
/// the first segment equal. Re-segmentation rewrites only the IP lengths, the IPv4 identification
/// (the caller checks it counts up) and header checksum, the sequence number, PSH and the TCP
/// checksum. This covers what the kernel's own GRO compares (TOS or traffic class and flow label,
/// TTL or hop limit, the IPv4 flags, addresses, ports, acknowledgement, data offset, window and
/// options) plus the urgent pointer, so differing ECN marks or a window update never merge.
fn continues_flow(first: &[u8], head: GroSegment, next: &[u8], segment: GroSegment) -> bool {
    if head.ipv4 != segment.ipv4 || head.header_len != segment.header_len {
        return false;
    }
    // IPv4: TOS; flags, fragment offset, TTL and protocol; addresses. IPv6: version, traffic
    // class and flow label; next header, hop limit and addresses.
    let ip_matches = if head.ipv4 {
        first[1] == next[1] && first[6..10] == next[6..10] && first[12..20] == next[12..20]
    } else {
        first[..4] == next[..4] && first[6..40] == next[6..40]
    };
    let tcp = head.ip_header_len;
    ip_matches
        && first[tcp..tcp + 4] == next[tcp..tcp + 4]
        && first[tcp + 8..tcp + 13] == next[tcp + 8..tcp + 13]
        && first[tcp + 14..tcp + 16] == next[tcp + 14..tcp + 16]
        && first[tcp + 18..head.header_len] == next[tcp + 18..head.header_len]
}

/// How many packets from `start` form one GSO frame: consecutive in-sequence segments of one flow,
/// each the size of the first except a shorter or pushed last one, within one IP packet's length.
///
/// The kernel re-segments a GSO frame by copying the first segment's headers and counting the
/// IPv4 identification up by one per segment, so an IPv4 run also needs consecutive
/// identifications, as the kernel's own GRO requires. Re-segmentation then gives back every
/// original segment byte for byte. Senders that randomise the identification do not merge.
fn coalescible_run(batch: &[Packet<[u8]>], start: usize) -> usize {
    let first = &batch[start];
    let Some(head) = gro_segment(first) else {
        return 1;
    };
    if head.flags & TCP_PSH != 0 {
        return 1;
    }
    let mut length = head.header_len + head.payload_len;
    let mut next_sequence = head
        .sequence
        .wrapping_add(payload_sequence(head.payload_len));
    let mut next_identification = head.identification.wrapping_add(1);
    let mut run = 1;
    for next in &batch[start + 1..] {
        if run == GRO_MAX_SEGMENTS {
            break;
        }
        let Some(segment) = gro_segment(next) else {
            break;
        };
        if !continues_flow(first, head, next, segment)
            || segment.sequence != next_sequence
            || (head.ipv4 && segment.identification != next_identification)
            || segment.payload_len > head.payload_len
            || length + segment.payload_len > usize::from(u16::MAX)
        {
            break;
        }
        length += segment.payload_len;
        next_sequence = next_sequence.wrapping_add(payload_sequence(segment.payload_len));
        next_identification = next_identification.wrapping_add(1);
        run += 1;
        if segment.payload_len < head.payload_len || segment.flags & TCP_PSH != 0 {
            break;
        }
    }
    run
}

/// A segment payload fits in one IP packet, so its length always fits the sequence space.
fn payload_sequence(payload_len: usize) -> u32 {
    u32::try_from(payload_len).unwrap_or(u32::MAX)
}

/// Lay out `segments`, a run from `coalescible_run`, as one virtio GSO frame: the first segment's
/// headers with the lengths, the IPv4 header checksum and the last segment's PSH updated, then
/// every payload in order. The TCP checksum holds the pseudo-header sum for the kernel to complete
/// (`NEEDS_CSUM`), as for any GSO frame; `WireGuard` already authenticated every payload.
fn build_gso_frame(segments: &[Packet<[u8]>], frame: &mut Vec<u8>) -> io::Result<()> {
    let first = segments
        .first()
        .ok_or_else(|| invalid_tun("empty GRO run"))?;
    let head = gro_segment(first).ok_or_else(|| invalid_tun("GRO run without a TCP segment"))?;
    let field =
        |value: usize| u16::try_from(value).map_err(|_| invalid_tun("GSO frame is too large"));
    frame.clear();
    frame.push(VIRTIO_NET_HDR_F_NEEDS_CSUM);
    frame.push(if head.ipv4 {
        VIRTIO_NET_HDR_GSO_TCPV4
    } else {
        VIRTIO_NET_HDR_GSO_TCPV6
    });
    frame.extend_from_slice(&field(head.header_len)?.to_ne_bytes());
    frame.extend_from_slice(&field(head.payload_len)?.to_ne_bytes());
    frame.extend_from_slice(&field(head.ip_header_len)?.to_ne_bytes());
    frame.extend_from_slice(&16_u16.to_ne_bytes());
    frame.extend_from_slice(&first[..head.header_len]);
    for segment in segments {
        let payload = segment
            .get(head.header_len..)
            .ok_or_else(|| invalid_tun("GRO segment is shorter than the run's headers"))?;
        frame.extend_from_slice(payload);
    }
    let length = frame.len() - VNET_HEADER_LEN;
    let packet = &mut frame[VNET_HEADER_LEN..];
    let tcp = head.ip_header_len;
    let last_flags = segments.last().map_or(0, |last| last[tcp + 13]);
    packet[tcp + 13] |= last_flags & TCP_PSH;
    let transport_len = length - tcp;
    let pseudo_sum = if head.ipv4 {
        packet[2..4].copy_from_slice(&field(length)?.to_be_bytes());
        packet[10..12].fill(0);
        let checksum = internet_checksum(&[&packet[..20]]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        let mut pseudo = [0_u8; 12];
        pseudo[..8].copy_from_slice(&packet[12..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&field(transport_len)?.to_be_bytes());
        !internet_checksum(&[&pseudo])
    } else {
        packet[4..6].copy_from_slice(&field(transport_len)?.to_be_bytes());
        let mut pseudo = [0_u8; 40];
        pseudo[..32].copy_from_slice(&packet[8..40]);
        pseudo[34..36].copy_from_slice(&field(transport_len)?.to_be_bytes());
        pseudo[39] = 6;
        !internet_checksum(&[&pseudo])
    };
    packet[tcp + 16..tcp + 18].copy_from_slice(&pseudo_sum.to_be_bytes());
    Ok(())
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
    // As the kernel's own TCP segmentation does: FIN and PSH stay on the last segment, and CWR
    // only on the first, so a receiver sees one congestion-window reduction per burst.
    if index + 1 != segment_count {
        segment[plan.tcp_offset + 13] &= !(TCP_FIN | TCP_PSH);
    }
    if index > 0 {
        segment[plan.tcp_offset + 13] &= !TCP_CWR;
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

    use super::{
        GRO_MAX_SEGMENTS, LinuxTun, TCP_ACK, TCP_PSH, TunWriter, build_gso_frame, coalescible_run,
        decode_frame, internet_checksum, ip_details, recompute_ipv4_checksum,
        recompute_transport_checksum,
    };
    use bytes::BytesMut;
    use gotatun::packet::{Ip, Packet, PacketBufPool};
    use std::{
        fs::File,
        io::Read as _,
        os::{
            fd::OwnedFd,
            unix::net::{UnixDatagram, UnixStream},
        },
        sync::Arc,
    };
    use tokio::io::unix::AsyncFd;

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

    fn test_tun(device: OwnedFd, vnet_header: bool) -> LinuxTun {
        LinuxTun::from_fd(device, vnet_header, Arc::default()).unwrap()
    }

    /// The frame J143 had the 6.12 kernel hand to this adapter's TUN: a raw IPv6 packet whose
    /// destination-options header claims (200 + 1) × 8 = 1,608 bytes while 8 are present, behind an
    /// all-zero virtio header.
    fn truncated_destination_options_frame() -> Vec<u8> {
        let mut frame = vec![0_u8; 10 + 40 + 8];
        let packet = &mut frame[10..];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
        packet[6] = 60;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0xfd, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0xfd, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[40] = 59;
        packet[41] = 200;
        frame
    }

    #[tokio::test]
    async fn refused_outbound_frame_is_dropped_and_the_next_valid_frame_is_read() {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};
        // A sequenced-packet pair keeps frame boundaries, as a TUN does, and reads EOF once the
        // kernel's side closes.
        let (kernel, device) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        let mut tun = test_tun(device, true);
        let bad = truncated_destination_options_frame();
        assert!(
            decode_frame(&bad, true, &PacketBufPool::new(1)).is_err(),
            "the fixture is a frame the adapter refuses"
        );
        let good = ipv4_packet(20).into_bytes().to_vec();
        let mut good_frame = vec![0_u8; 10];
        good_frame.extend_from_slice(&good);
        nix::unistd::write(&kernel, &bad).unwrap();
        nix::unistd::write(&kernel, &good_frame).unwrap();

        let mut pool = PacketBufPool::new(4);
        let packets: Vec<_> = match tun.recv_packets(&mut pool).await {
            Ok(packets) => packets.map(|packet| packet.into_bytes().to_vec()).collect(),
            Err(error) => panic!("a refused frame must not end GotaTun's TUN reader: {error:?}"),
        };
        assert_eq!(packets, [good]);
        assert_eq!(tun.refused.load(std::sync::atomic::Ordering::Relaxed), 1);

        drop(kernel);
        let closed = tun.recv_packets(&mut pool).await.map(|_| ()).unwrap_err();
        assert_eq!(closed.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn oversized_decrypted_packet_does_not_stop_the_next_valid_send() {
        let (mut reader, writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        let mut tun = test_tun(writer.into(), false);

        assert!(
            tun.send_packet(ipv4_packet(1381)).await.is_ok(),
            "an oversized decrypted packet should be dropped without stopping GotaTun"
        );
        let expected = ipv4_packet(20).into_bytes().to_vec();
        tun.send_packet(ipv4_packet(20)).await.unwrap();

        // Read off the runtime thread so the writer task can run.
        let length = expected.len();
        let actual = tokio::task::spawn_blocking(move || {
            let mut actual = vec![0; length];
            reader.read_exact(&mut actual).unwrap();
            actual
        })
        .await
        .unwrap();
        assert_eq!(actual, expected);
    }

    /// One TCP segment with valid checksums, 40000 -> 443 on the documentation addresses, with a
    /// payload that continues the flow's byte stream at `sequence`.
    fn tcp_segment(ipv4: bool, sequence: u32, payload_len: usize, flags: u8, id: u16) -> BytesMut {
        let tcp = if ipv4 { 20 } else { 40 };
        let mut packet = vec![0_u8; tcp + 20 + payload_len];
        if ipv4 {
            packet[0] = 0x45;
            let length = u16::try_from(packet.len()).unwrap();
            packet[2..4].copy_from_slice(&length.to_be_bytes());
            packet[4..6].copy_from_slice(&id.to_be_bytes());
            packet[6] = 0x40;
            packet[8] = 64;
            packet[9] = 6;
            packet[12..16].copy_from_slice(&[10, 1, 0, 1]);
            packet[16..20].copy_from_slice(&[10, 1, 0, 2]);
        } else {
            packet[0] = 0x60;
            let length = u16::try_from(packet.len() - 40).unwrap();
            packet[4..6].copy_from_slice(&length.to_be_bytes());
            packet[6] = 6;
            packet[7] = 64;
            packet[8..24]
                .copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            packet[24..40]
                .copy_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        }
        packet[tcp..tcp + 2].copy_from_slice(&40000_u16.to_be_bytes());
        packet[tcp + 2..tcp + 4].copy_from_slice(&443_u16.to_be_bytes());
        packet[tcp + 4..tcp + 8].copy_from_slice(&sequence.to_be_bytes());
        packet[tcp + 8..tcp + 12].copy_from_slice(&7_u32.to_be_bytes());
        packet[tcp + 12] = 0x50;
        packet[tcp + 13] = flags;
        packet[tcp + 14..tcp + 16].copy_from_slice(&1024_u16.to_be_bytes());
        for (index, byte) in packet[tcp + 20..].iter_mut().enumerate() {
            *byte = u8::try_from((usize::try_from(sequence).unwrap() + index) % 251).unwrap();
        }
        let details = ip_details(&packet).unwrap();
        recompute_transport_checksum(&mut packet, details, tcp, 16).unwrap();
        recompute_ipv4_checksum(&mut packet, details);
        BytesMut::from(packet.as_slice())
    }

    fn packets(segments: &[BytesMut]) -> Vec<Packet<[u8]>> {
        segments.iter().cloned().map(Packet::from_bytes).collect()
    }

    fn flow(ipv4: bool, count: u32) -> Vec<BytesMut> {
        (0..count)
            .map(|index| {
                let flags = if index + 1 == count {
                    TCP_ACK | TCP_PSH
                } else {
                    TCP_ACK
                };
                let id = 37 + u16::try_from(index).unwrap();
                tcp_segment(ipv4, 50_000 + 1000 * index, 1000, flags, id)
            })
            .collect()
    }

    #[test]
    fn gro_frame_resegments_to_the_original_segments() {
        for ipv4 in [true, false] {
            let segments = flow(ipv4, 3);
            assert_eq!(coalescible_run(&packets(&segments), 0), 3);
            let mut frame = Vec::new();
            build_gso_frame(&packets(&segments), &mut frame).unwrap();
            let ip = if ipv4 { 20 } else { 40 };
            let header =
                |offset: usize| usize::from(u16::from_ne_bytes([frame[offset], frame[offset + 1]]));
            assert_eq!(frame[0], 1, "the checksum is left partial");
            assert_eq!(frame[1], if ipv4 { 1 } else { 4 });
            assert_eq!(header(2), ip + 20);
            assert_eq!(header(4), 1000);
            assert_eq!(header(6), ip);
            assert_eq!(header(8), 16);
            let packet = &frame[10..];
            if ipv4 {
                assert_eq!(
                    internet_checksum(&[&packet[..20]]),
                    0,
                    "IPv4 header checksum"
                );
            }
            // The kernel completes the partial checksum over the TCP bytes; that must equal the
            // checksum of the merged segment computed from scratch.
            let mut full = packet.to_vec();
            let details = ip_details(&full).unwrap();
            recompute_transport_checksum(&mut full, details, ip, 16).unwrap();
            assert_eq!(
                internet_checksum(&[&packet[ip..]]).to_be_bytes(),
                full[ip + 16..ip + 18]
            );
            let pool = PacketBufPool::new(4);
            let resegmented = decode_frame(&frame, true, &pool).unwrap();
            assert_eq!(resegmented.len(), 3);
            for (packet, original) in resegmented.into_iter().zip(&segments) {
                assert_eq!(packet.into_bytes().as_ref(), original.as_ref());
            }
        }
    }

    /// IPv4 segments of one flow as a sender emits them, with consecutive identifications from 1:
    /// `(sequence, payload length, flags)` each.
    fn ipv4_run(shape: &[(u32, usize, u8)]) -> Vec<Packet<[u8]>> {
        shape
            .iter()
            .zip(1_u16..)
            .map(|(&(sequence, length, flags), id)| {
                Packet::from_bytes(tcp_segment(true, sequence, length, flags, id))
            })
            .collect()
    }

    #[test]
    fn gro_merges_only_in_sequence_segments_of_one_flow() {
        let ack = TCP_ACK;
        let pair = |second| ipv4_run(&[(0, 1000, ack), second]);
        assert_eq!(coalescible_run(&pair((1000, 1000, ack)), 0), 2);
        assert_eq!(
            coalescible_run(&pair((1001, 1000, ack)), 0),
            1,
            "a sequence gap ends the frame"
        );
        // Every header byte that re-segmentation copies from the first segment must match, and
        // the IPv4 identification must count up.
        let header_changes: [(&str, usize, &[u8]); 8] = [
            ("port", 22, &444_u16.to_be_bytes()),
            ("acknowledgement", 28, &8_u32.to_be_bytes()),
            ("ECN mark", 1, &[0x03]),
            ("don't-fragment bit", 6, &[0x00]),
            ("TTL", 8, &[63]),
            ("window", 34, &2048_u16.to_be_bytes()),
            ("urgent pointer", 38, &1_u16.to_be_bytes()),
            ("identification", 4, &5_u16.to_be_bytes()),
        ];
        for (field, offset, value) in header_changes {
            let mut run = pair((1000, 1000, ack));
            run[1][offset..offset + value.len()].copy_from_slice(value);
            // Keep the header checksum valid, so the field itself is what ends the frame.
            let details = ip_details(&run[1]).unwrap();
            recompute_ipv4_checksum(&mut run[1], details);
            assert_eq!(
                coalescible_run(&run, 0),
                1,
                "a different {field} ends the frame"
            );
        }
        assert_eq!(coalescible_run(&packets(&flow(false, 2)), 0), 2);
        for (field, offset) in [("flow label", 3), ("hop limit", 7)] {
            let mut run = packets(&flow(false, 2));
            run[1][offset] ^= 1;
            assert_eq!(
                coalescible_run(&run, 0),
                1,
                "a different IPv6 {field} ends the frame"
            );
        }
        let wrapping = packets(&[
            tcp_segment(true, u32::MAX - 999, 1000, ack, u16::MAX),
            tcp_segment(true, 0, 1000, ack, 0),
        ]);
        assert_eq!(
            coalescible_run(&wrapping, 0),
            2,
            "sequence numbers and identifications wrap"
        );
        let short = ipv4_run(&[
            (0, 1000, ack),
            (1000, 1000, ack),
            (2000, 500, ack),
            (2500, 1000, ack),
        ]);
        assert_eq!(
            coalescible_run(&short, 0),
            3,
            "a shorter segment ends the frame"
        );
        assert_eq!(coalescible_run(&short, 3), 1);
        let pushed = ipv4_run(&[
            (0, 1000, ack),
            (1000, 1000, ack | TCP_PSH),
            (2000, 1000, ack),
        ]);
        assert_eq!(
            coalescible_run(&pushed, 0),
            2,
            "a pushed segment ends the frame"
        );
        assert_eq!(
            coalescible_run(&ipv4_run(&[(0, 500, ack), (500, 1000, ack)]), 0),
            1
        );
        for state in [0x01, 0x02, 0x04, 0x20, 0x40, 0x80] {
            assert_eq!(
                coalescible_run(&pair((1000, 1000, ack | state)), 0),
                1,
                "flag {state:#x} never merges"
            );
        }
        assert_eq!(
            coalescible_run(&ipv4_run(&[(0, 0, ack), (0, 1000, ack)]), 0),
            1
        );
        let many: Vec<_> = (0..70).map(|index| (index * 1000, 1000, ack)).collect();
        assert_eq!(coalescible_run(&ipv4_run(&many), 0), GRO_MAX_SEGMENTS);
        let large: Vec<_> = (0..64).map(|index| (index * 1380, 1380, ack)).collect();
        assert_eq!(
            coalescible_run(&ipv4_run(&large), 0),
            47,
            "a frame stays within one IP packet"
        );
    }

    /// A merged frame gets a fresh IPv4 header checksum, so a segment with a bad one goes out
    /// alone for the kernel to judge (#260 J143 P3-2).
    #[test]
    fn gro_never_merges_a_bad_ipv4_header_checksum() {
        for corrupted in [0, 1] {
            let mut run = ipv4_run(&[(0, 1000, TCP_ACK), (1000, 1000, TCP_ACK)]);
            assert_eq!(coalescible_run(&run, 0), 2, "the intact pair merges");
            run[corrupted][10] ^= 0x01;
            assert_eq!(
                coalescible_run(&run, 0),
                1,
                "a bad IPv4 header checksum on segment {corrupted} never merges"
            );
        }
    }

    #[tokio::test]
    async fn writer_merges_queued_segments_and_writes_a_lone_packet_unchanged() {
        let (reader, writer) = UnixDatagram::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        let writer: OwnedFd = writer.into();
        #[allow(deprecated)]
        let fd = Arc::new(AsyncFd::new(File::from(writer)).unwrap());
        let tun_writer = TunWriter::spawn(Arc::clone(&fd), true);
        let segments = flow(true, 3);
        let lone = tcp_segment(true, 90_000, 10, TCP_ACK | TCP_PSH, 9);
        // The writer runs only once this task waits, so it finds all four queued.
        for packet in packets(&segments)
            .into_iter()
            .chain(packets(std::slice::from_ref(&lone)))
        {
            tun_writer.send(packet).await.unwrap();
        }
        let frames = tokio::task::spawn_blocking(move || {
            (0..2)
                .map(|_| {
                    let mut frame = vec![0; 70_000];
                    let length = reader.recv(&mut frame).unwrap();
                    frame.truncate(length);
                    frame
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap();
        let mut merged = Vec::new();
        build_gso_frame(&packets(&segments), &mut merged).unwrap();
        assert_eq!(frames[0], merged);
        let mut plain = vec![0; 10];
        plain.extend_from_slice(&lone);
        assert_eq!(frames[1], plain);
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

    /// A GSO frame with ECN (virtio's GSO ECN bit) and CWR set: only the first segment keeps CWR,
    /// as the kernel's `tcp_gso_segment` leaves it (#260 J143 P3-1).
    #[test]
    fn tso_keeps_cwr_only_on_the_first_segment() {
        let pool = PacketBufPool::new(1);
        let mut frame = ipv4_tcp_frame(2300);
        frame[1] |= 0x80;
        frame[10 + 33] |= 0x80;
        let flags: Vec<u8> = decode_frame(&frame, true, &pool)
            .unwrap()
            .into_iter()
            .map(|packet| packet.into_bytes()[33])
            .collect();
        assert_eq!(flags, [0x90, 0x10, 0x19]);
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
