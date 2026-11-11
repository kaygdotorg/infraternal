//! Serves one node's accepted, policy-filtered mesh name snapshot on its mesh address [#266].
//!
//! A node's own snapshot contains only names it may reach. Queries from another source are treated
//! as nonexistent inside the zone, so this listener never reveals names from its broader view.
use crate::{dataplane::Config, policy::model::validate_dns};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{DNSClass, Name, RData, Record, RecordType, rdata::SOA},
};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::{
    collections::BTreeMap,
    io::{self, Read as _, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::{fd::AsFd, unix::net::UnixStream},
    sync::{Arc, RwLock},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// The UDP port the resolver listens on. It is a high port so no privilege is
/// needed; the host's split-DNS setup sends queries for the mesh suffix here.
pub const DNS_PORT: u16 = 1053;
/// The standard DNS port used by `NetworkManager`'s split-DNS forwarding.
pub const DNS_SYSTEM_PORT: u16 = 53;
/// Cache lifetime, in seconds, of answers that exist.
const POSITIVE_TTL: u32 = 30;
/// Cache lifetime, in seconds, of "no such name" and "no such record type"
/// answers. Short, so a new node becomes reachable quickly.
const NEGATIVE_TTL: u32 = 5;
/// Largest query accepted, in bytes. Longer datagrams are dropped.
const MAX_PACKET: usize = 4096;
/// Maximum number of TCP DNS clients held by the resolver at once.
const TCP_CONNECTION_LIMIT: usize = 64;
/// Maximum number of TCP DNS clients held for one source address.
const TCP_SOURCE_CONNECTION_LIMIT: usize = 8;
/// Maximum time a TCP DNS client may remain idle between reads or writes.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum time from accept (or the previous complete answer) to read one whole DNS frame.
const TCP_MESSAGE_TIMEOUT: Duration = Duration::from_secs(2);
/// Malformed DNS messages are counted for the lifetime of a connection.
const TCP_MALFORMED_FRAME_LIMIT: usize = 16;
/// Maximum number of queued TCP accepts serviced before polling clients again.
const TCP_ACCEPT_BUDGET: usize = 64;

/// The addresses one name resolves to.
#[derive(Clone, Copy)]
struct Addresses {
    ipv4: Ipv4Addr,
    ipv6: std::net::Ipv6Addr,
}

/// All names the resolver can answer, taken from one accepted policy revision.
///
/// Names are stored as lowercase host labels, without the suffix. A name
/// resolves under the configured suffix and also under the default `internal`
/// suffix, so the old name keeps working after a user picks their own. Treat a
/// value as immutable: updates build a new `Records` and swap it in.
#[derive(Clone)]
pub(crate) struct Records {
    local_address: Ipv4Addr,
    suffixes: Vec<String>,
    names: BTreeMap<String, Addresses>,
}

impl Records {
    /// No names yet, only the default suffix. Every query in the zone gets
    /// "no such name" until real records are published.
    #[cfg(target_os = "linux")]
    fn empty(local_address: Ipv4Addr) -> Self {
        Self {
            local_address,
            suffixes: vec![crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned()],
            names: BTreeMap::new(),
        }
    }

    /// Builds the name set from a node's configuration: the node's own name
    /// and the names of its peers.
    ///
    /// # Errors
    /// Returns `InvalidData` if the suffix is not valid, a name is not a valid
    /// label or would exceed 253 bytes with a suffix, two nodes share a name,
    /// or a name refers to a peer that is not in the configuration.
    pub(crate) fn from_config(config: &Config) -> io::Result<Self> {
        validate_dns(&config.dns_suffix, false).map_err(|_| invalid_config())?;
        let mut suffixes = vec![config.dns_suffix.clone()];
        if config.dns_suffix != crate::dataplane::DEFAULT_DNS_SUFFIX {
            suffixes.push(crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned());
        }
        suffixes.sort_unstable_by_key(|suffix| std::cmp::Reverse(suffix.len()));
        let mut records = Self {
            local_address: config.addresses.ipv4,
            suffixes,
            names: BTreeMap::new(),
        };
        if let Some(name) = &config.name {
            records.insert(
                name,
                Addresses {
                    ipv4: config.addresses.ipv4,
                    ipv6: config.addresses.ipv6,
                },
            )?;
        }
        for (node, name) in &config.peer_names {
            let peer = config.peers.get(node).ok_or_else(invalid_config)?;
            records.insert(
                name,
                Addresses {
                    ipv4: peer.peer.addresses.ipv4,
                    ipv6: peer.peer.addresses.ipv6,
                },
            )?;
        }
        Ok(records)
    }

    /// Adds one name. Fails with `InvalidData` for an invalid, too long or
    /// duplicate name.
    fn insert(&mut self, label: &str, addresses: Addresses) -> io::Result<()> {
        if self
            .suffixes
            .iter()
            .any(|suffix| label.len() + suffix.len() + 1 > 253)
        {
            return Err(invalid_config());
        }
        let label = canonical_label(label).ok_or_else(invalid_config)?;
        if self.names.insert(label, addresses).is_some() {
            return Err(invalid_config());
        }
        Ok(())
    }

    /// The node's local mesh address used by the DNS socket and host route.
    pub(crate) const fn local_address(&self) -> Ipv4Addr {
        self.local_address
    }

    /// The default and custom DNS zones this snapshot answers.
    pub(crate) fn suffixes(&self) -> &[String] {
        &self.suffixes
    }
}

/// The error for a configuration with an unusable or duplicate name.
fn invalid_config() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or duplicate mesh DNS name",
    )
}

/// Lowercases a host label and checks it: ASCII letters, digits and hyphens,
/// 1 to 63 bytes, not starting or ending with a hyphen. `None` if it fails.
fn canonical_label(label: &str) -> Option<String> {
    if label.is_empty() || !label.is_ascii() || label.len() > 63 {
        return None;
    }
    let canonical = label.to_ascii_lowercase();
    if canonical.starts_with('-')
        || canonical.ends_with('-')
        || !canonical
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        None
    } else {
        Some(canonical)
    }
}

/// Bounded state for one TCP client, including one in-flight DNS frame in each direction.
struct TcpClient {
    stream: TcpStream,
    source: SocketAddr,
    input: Vec<u8>,
    expected_message_length: Option<usize>,
    output: Vec<u8>,
    output_offset: usize,
    last_activity: Instant,
    frame_deadline: Option<Instant>,
    malformed_frames: usize,
}

impl TcpClient {
    /// Reserves at most one capped DNS request frame for a newly accepted stream.
    fn new(stream: TcpStream, source: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            stream,
            source,
            input: Vec::with_capacity(MAX_PACKET + 2),
            expected_message_length: None,
            output: Vec::new(),
            output_offset: 0,
            last_activity: now,
            frame_deadline: Some(now + TCP_MESSAGE_TIMEOUT),
            malformed_frames: 0,
        }
    }

    /// Clears the in-flight request after it receives no local answer.
    fn clear_request(&mut self) {
        self.input.clear();
        self.expected_message_length = None;
    }

    /// Returns the earlier of the idle timeout and the whole-frame deadline.
    fn deadline(&self) -> Instant {
        let idle_deadline = self.last_activity + TCP_IDLE_TIMEOUT;
        self.frame_deadline.map_or(idle_deadline, |frame_deadline| {
            frame_deadline.min(idle_deadline)
        })
    }

    /// Reports whether this connection has exhausted either bounded wait.
    fn expired_at(&self, now: Instant) -> bool {
        self.deadline() <= now
    }
}

/// Selects the next TCP deadline, blocking indefinitely when no clients are connected.
fn tcp_poll_timeout(clients: &[TcpClient]) -> PollTimeout {
    let now = Instant::now();
    clients
        .iter()
        .map(|client| client.deadline().saturating_duration_since(now))
        .min()
        .map_or(PollTimeout::NONE, |remaining| {
            PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX)
        })
}

/// Accepts a bounded batch so a flood of TCP handshakes cannot starve UDP queries.
fn accept_tcp_connections(listener: &TcpListener, clients: &mut Vec<TcpClient>) -> io::Result<()> {
    for _ in 0..TCP_ACCEPT_BUDGET {
        match listener.accept() {
            Ok((stream, source)) => {
                let source_connections = clients
                    .iter()
                    .filter(|client| client.source.ip() == source.ip())
                    .count();
                if clients.len() >= TCP_CONNECTION_LIMIT
                    || source_connections >= TCP_SOURCE_CONNECTION_LIMIT
                    || stream.set_nonblocking(true).is_err()
                {
                    continue;
                }
                clients.push(TcpClient::new(stream, source));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Reads at most one capped, length-prefixed query fragment and queues its UDP-equivalent answer.
fn read_tcp_request(client: &mut TcpClient, records: &Arc<RwLock<Records>>) -> bool {
    let mut buffer = [0_u8; MAX_PACKET + 2];
    let target_length = client
        .expected_message_length
        .map_or(2, |message_length| message_length + 2);
    let remaining = target_length - client.input.len();
    let read_length = remaining.min(buffer.len());
    match client.stream.read(&mut buffer[..read_length]) {
        Ok(0) => false,
        Ok(length) => {
            client.last_activity = Instant::now();
            client.input.extend_from_slice(&buffer[..length]);
            if client.expected_message_length.is_none() && client.input.len() == 2 {
                let message_length =
                    usize::from(u16::from_be_bytes([client.input[0], client.input[1]]));
                if !(12..=MAX_PACKET).contains(&message_length) {
                    return false;
                }
                client.expected_message_length = Some(message_length);
            }

            let Some(message_length) = client.expected_message_length else {
                return true;
            };
            if client.input.len() < message_length + 2 {
                return true;
            }

            let response = {
                let snapshot = records
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                response_for_source(&client.input[2..], &snapshot, client.source.ip())
            };
            client.clear_request();
            match response {
                Ok(Some(response)) if response.len() <= MAX_PACKET => {
                    let Ok(response_length) = u16::try_from(response.len()) else {
                        return false;
                    };
                    client.output.clear();
                    client
                        .output
                        .extend_from_slice(&response_length.to_be_bytes());
                    client.output.extend_from_slice(&response);
                    client.output_offset = 0;
                    client.frame_deadline = None;
                    true
                }
                Ok(Some(_)) => false,
                Ok(None) => {
                    client.frame_deadline = Some(Instant::now() + TCP_MESSAGE_TIMEOUT);
                    true
                }
                Err(_) => {
                    client.malformed_frames += 1;
                    if client.malformed_frames >= TCP_MALFORMED_FRAME_LIMIT {
                        return false;
                    }
                    client.frame_deadline = Some(Instant::now() + TCP_MESSAGE_TIMEOUT);
                    true
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::Interrupted => true,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => true,
        Err(_) => false,
    }
}

/// Writes a queued length-prefixed response without blocking the shared DNS worker.
fn write_tcp_response(client: &mut TcpClient) -> bool {
    while client.output_offset < client.output.len() {
        match client.stream.write(&client.output[client.output_offset..]) {
            Ok(0) => return false,
            Ok(length) => {
                client.output_offset += length;
                client.last_activity = Instant::now();
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return true,
            Err(_) => return false,
        }
    }
    client.output.clear();
    client.output_offset = 0;
    client.frame_deadline = Some(Instant::now() + TCP_MESSAGE_TIMEOUT);
    true
}

/// Applies one poll result to a TCP client, preserving a half-closed client's pending answer.
fn service_tcp_client(
    client: &mut TcpClient,
    ready: PollFlags,
    records: &Arc<RwLock<Records>>,
) -> bool {
    if ready.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
        return false;
    }
    if client.output.is_empty() {
        if ready.contains(PollFlags::POLLIN) && !read_tcp_request(client, records) {
            return false;
        }
    } else if ready.contains(PollFlags::POLLOUT) && !write_tcp_response(client) {
        return false;
    }
    !(ready.contains(PollFlags::POLLHUP) && client.output.is_empty())
}

/// Answers one DNS query packet from `config`'s names, as if it came from this
/// node itself. Mainly for tests and tools; the running service uses
/// [`Resolver`].
///
/// Returns the encoded reply, or `None` if the name is outside the mesh
/// suffix. Such names are left to the operating system's other DNS routes, so
/// the split-DNS setup must send only the mesh suffix here.
///
/// # Errors
/// Rejects malformed packets, packets that are not plain single-question
/// queries, and configurations with invalid names.
pub fn response(packet: &[u8], config: &Config) -> io::Result<Option<Vec<u8>>> {
    let records = Records::from_config(config)?;
    response_for_records(packet, &records)
}

/// Like [`response`], but with names that are already built.
fn response_for_records(packet: &[u8], records: &Records) -> io::Result<Option<Vec<u8>>> {
    response_for_source(packet, records, IpAddr::V4(records.local_address))
}

/// Builds the reply to `packet` received from `source`.
///
/// The outcomes, in order:
/// - `Err` for an oversized or malformed packet, or one that is not a single
///   plain query.
/// - `Ok(None)` if the name is outside every configured suffix.
/// - `REFUSED` for a class other than `IN`.
/// - `NXDOMAIN` plus a short-lived SOA if `source` is not this node's own mesh
///   address or the host is absent (a name with multiple host labels never exists).
/// - An `A` or `AAAA` answer for existing hosts; any other record type gets an
///   empty answer plus the SOA (NODATA).
fn response_for_source(
    packet: &[u8],
    records: &Records,
    source: IpAddr,
) -> io::Result<Option<Vec<u8>>> {
    if packet.len() > MAX_PACKET {
        return Err(invalid_packet());
    }
    let request = Message::from_vec(packet).map_err(|_| invalid_packet())?;
    if request.metadata.message_type != MessageType::Query
        || request.metadata.op_code != OpCode::Query
        || request.queries.len() != 1
        || !request.answers.is_empty()
        || !request.authorities.is_empty()
        || !request.additionals.is_empty()
        || request.signature.is_some()
    {
        return Err(invalid_packet());
    }

    let question = request.queries[0].clone();
    let mut reply = Message::response(request.metadata.id, request.metadata.op_code);
    reply.queries.push(question.clone());
    reply.edns.clone_from(&request.edns);
    // Responses copy RD, while the response constructor clears other query flags.
    reply.metadata.recursion_desired = request.metadata.recursion_desired;

    let qname = question
        .name()
        .to_ascii()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let Some((suffix, label)) = matching_zone(&qname, &records.suffixes) else {
        return Ok(None);
    };
    reply.metadata.authoritative = true;

    if question.query_class() != DNSClass::IN {
        reply.metadata.response_code = ResponseCode::Refused;
        return encode(&reply).map(Some);
    }
    if source != IpAddr::V4(records.local_address) {
        // A peer asking this node directly sees no names from its broader local view. Treat every
        // such in-zone query as missing, so the answer cannot reveal whether the name exists here.
        return negative_response(reply, suffix).map(Some);
    }

    let address = if label.contains('.') {
        None
    } else {
        records.names.get(label).copied()
    };
    let Some(address) = address else {
        return negative_response(reply, suffix).map(Some);
    };
    let rdata = match question.query_type() {
        RecordType::A => Some(RData::A(address.ipv4.into())),
        RecordType::AAAA => Some(RData::AAAA(address.ipv6.into())),
        _ => None,
    };
    if let Some(rdata) = rdata {
        reply.answers.push(Record::from_rdata(
            question.name().clone(),
            POSITIVE_TTL,
            rdata,
        ));
    } else {
        // NODATA is negative cache data too; advertise the same bounded TTL as NXDOMAIN.
        reply.authorities.push(negative_soa(suffix)?);
    }
    encode(&reply).map(Some)
}

/// Builds the negative answer shared by filtered queries and missing names.
/// Keeping one path gives both cases the same NXDOMAIN response and SOA data.
fn negative_response(mut reply: Message, suffix: &str) -> io::Result<Vec<u8>> {
    reply.metadata.response_code = ResponseCode::NXDomain;
    reply.authorities.push(negative_soa(suffix)?);
    encode(&reply)
}

/// Finds which configured suffix `qname` (lowercase, no trailing dot) falls
/// under and the host part before it.
///
/// Returns the suffix and the host part, which is empty if `qname` is the
/// suffix itself (the zone apex). Returns `None` if no suffix matches. A name
/// with a real host part always wins over a zone apex: with suffixes
/// `a.internal` and `internal`, `a.internal` is host `a` in `internal`.
fn matching_zone<'zone, 'query>(
    qname: &'query str,
    suffixes: &'zone [String],
) -> Option<(&'zone str, &'query str)> {
    let mut empty_label = None;
    let mut zone_apex = None;
    for suffix in suffixes {
        if qname == suffix {
            zone_apex.get_or_insert((suffix.as_str(), ""));
            continue;
        }
        let Some(prefix) = qname.strip_suffix(suffix.as_str()) else {
            continue;
        };
        let Some(label) = prefix.strip_suffix('.') else {
            continue;
        };
        if label.is_empty() {
            empty_label.get_or_insert((suffix.as_str(), label));
        } else {
            // A hostname under a shorter alias zone must beat a longer zone's apex.
            return Some((suffix.as_str(), label));
        }
    }
    empty_label.or(zone_apex)
}

/// The error for an unusable query packet.
fn invalid_packet() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid DNS query packet")
}

/// Serializes a reply, mapping failures to the packet error.
fn encode(message: &Message) -> io::Result<Vec<u8>> {
    message.to_vec().map_err(|_| invalid_packet())
}

/// The SOA record for `suffix`, attached to negative answers so resolvers
/// cache them for [`NEGATIVE_TTL`] seconds.
fn negative_soa(suffix: &str) -> io::Result<Record> {
    // Records validates the configured suffix before constructing Hickory's owned DNS name.
    let zone = Name::from_ascii(suffix).map_err(|_| invalid_config())?;
    Ok(Record::from_rdata(
        zone.clone(),
        NEGATIVE_TTL,
        RData::SOA(SOA::new(zone.clone(), zone, 1, 30, 5, 60, NEGATIVE_TTL)),
    ))
}

/// Serves UDP on its own worker so TCP framing and clients cannot delay datagrams.
fn run_udp_worker(
    sockets: &[UdpSocket],
    shutdown_reader: &UnixStream,
    records: &Arc<RwLock<Records>>,
) {
    let mut query = [0_u8; MAX_PACKET + 1];
    'worker: loop {
        let shutdown_index = sockets.len();
        let mut descriptors = Vec::with_capacity(shutdown_index + 1);
        descriptors.extend(
            sockets
                .iter()
                .map(|socket| PollFd::new(socket.as_fd(), PollFlags::POLLIN)),
        );
        descriptors.push(PollFd::new(shutdown_reader.as_fd(), PollFlags::POLLIN));
        match poll(&mut descriptors, PollTimeout::NONE) {
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break,
        }
        let ready = descriptors
            .iter()
            .map(|descriptor| descriptor.revents().unwrap_or_else(PollFlags::empty))
            .collect::<Vec<_>>();
        drop(descriptors);
        if ready[shutdown_index]
            .intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
        {
            break;
        }
        for (index, socket) in sockets.iter().enumerate() {
            if !ready[index].contains(PollFlags::POLLIN) {
                continue;
            }
            let (length, source) = match socket.recv_from(&mut query) {
                Ok(result) => result,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(_) => break 'worker,
            };
            if length > MAX_PACKET {
                continue;
            }
            let response = {
                let snapshot = records
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                response_for_source(&query[..length], &snapshot, source.ip())
            };
            if let Ok(Some(reply)) = response {
                let _ = socket.send_to(&reply, source);
            }
        }
    }
}

/// Serves TCP independently, with bounded accepts, reads and per-connection state.
fn run_tcp_worker(
    listeners: &[TcpListener],
    shutdown_reader: &UnixStream,
    records: &Arc<RwLock<Records>>,
) {
    let mut clients = Vec::<TcpClient>::new();
    'worker: loop {
        let now = Instant::now();
        clients.retain(|client| !client.expired_at(now));
        let clients_start = listeners.len();
        let polled_client_count = clients.len();
        let shutdown_index = clients_start + polled_client_count;
        let mut descriptors = Vec::with_capacity(shutdown_index + 1);
        descriptors.extend(
            listeners
                .iter()
                .map(|listener| PollFd::new(listener.as_fd(), PollFlags::POLLIN)),
        );
        descriptors.extend(clients.iter().map(|client| {
            let flags = if client.output.is_empty() {
                PollFlags::POLLIN
            } else {
                PollFlags::POLLOUT
            };
            PollFd::new(client.stream.as_fd(), flags)
        }));
        descriptors.push(PollFd::new(shutdown_reader.as_fd(), PollFlags::POLLIN));
        match poll(&mut descriptors, tcp_poll_timeout(&clients)) {
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break 'worker,
        }
        let ready = descriptors
            .iter()
            .map(|descriptor| descriptor.revents().unwrap_or_else(PollFlags::empty))
            .collect::<Vec<_>>();
        drop(descriptors);
        if ready[shutdown_index]
            .intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
        {
            break;
        }
        // One read per ready client per poll turn bounds parser work and lets other clients run.
        for index in (0..polled_client_count).rev() {
            if !service_tcp_client(&mut clients[index], ready[clients_start + index], records) {
                clients.swap_remove(index);
            }
        }
        for (index, listener) in listeners.iter().enumerate() {
            if ready[index].contains(PollFlags::POLLIN)
                && accept_tcp_connections(listener, &mut clients).is_err()
            {
                break 'worker;
            }
        }
        // The poll can return immediately while hostile TCP clients stay ready.
        thread::yield_now();
    }
}

/// The mesh DNS server of one node.
///
/// By default it listens on UDP and TCP port [`DNS_PORT`] of the node's mesh IPv4 address, with separate
/// `mesh-dns-udp` and `mesh-dns-tcp` workers. TCP clients have bounded connection state and share
/// the UDP source-privacy rules. Queries from another source receive the same NXDOMAIN as an
/// absent name (see [`response`]). Names can be replaced while it runs; each query sees a whole
/// snapshot, never a half-updated one. Dropping the resolver stops both workers and waits for them.
pub struct Resolver {
    address: Ipv4Addr,
    #[cfg(target_os = "linux")]
    system_port: bool,
    records: Arc<RwLock<Records>>,
    udp_shutdown: UnixStream,
    tcp_shutdown: UnixStream,
    udp_worker: Option<JoinHandle<()>>,
    tcp_worker: Option<JoinHandle<()>>,
}

impl Resolver {
    /// Starts serving the names in `config` on the node's mesh address.
    ///
    /// # Errors
    /// Fails if the names are invalid, if the port is already in use, or if the
    /// mesh address is not available on this host yet.
    pub fn bind(config: &Config) -> io::Result<Self> {
        let records = Records::from_config(config)?;
        Self::bind_records(config.addresses.ipv4, records, false)
    }

    /// Serves the snapshot through already-bound UDP and TCP sockets, taking ownership of both.
    ///
    /// Callers may bind each protocol to port zero and read its assigned destination before
    /// handing it over. Ports may differ; both sockets must use the snapshot's mesh IPv4 address.
    /// No socket is closed and rebound, so a concurrent listener cannot steal a reserved port.
    /// This constructor does not add the optional standard-port listeners.
    ///
    /// # Errors
    /// Rejects invalid records or socket addresses that differ from the snapshot's address,
    /// and reports failures configuring the listener or starting either worker.
    pub fn from_sockets(
        config: &Config,
        socket: UdpSocket,
        listener: TcpListener,
    ) -> io::Result<Self> {
        let records = Records::from_config(config)?;
        let address = IpAddr::V4(config.addresses.ipv4);
        if socket.local_addr()?.ip() != address || listener.local_addr()?.ip() != address {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS sockets must bind the configured mesh IPv4 address",
            ));
        }
        Self::serve_sockets(records, socket, listener, None)
    }

    /// Starts serving one node snapshot and, on root Linux nodes, also claims port 53 when free.
    ///
    /// Port 53 is optional because systemd-resolved accepts the high port directly. The extra
    /// listener is only needed by `NetworkManager`'s dnsmasq split-DNS forwarding.
    /// # Errors
    /// Fails if the high mesh DNS port cannot be bound or the snapshot is invalid.
    pub fn bind_for_node(config: &Config) -> io::Result<Self> {
        let records = Records::from_config(config)?;
        #[cfg(target_os = "linux")]
        {
            Self::bind_records(config.addresses.ipv4, records, system_port_for_node())
        }
        #[cfg(target_os = "macos")]
        {
            Self::bind_records(config.addresses.ipv4, records, false)
        }
    }

    /// Starts serving on `address` with no names, so both protocols and eligible ports are held before publish.
    #[cfg(target_os = "linux")]
    pub(crate) fn bind_empty_for_node(address: Ipv4Addr) -> io::Result<Self> {
        Self::bind_records(address, Records::empty(address), system_port_for_node())
    }

    /// The mesh address the resolver is bound to on Linux.
    #[cfg(target_os = "linux")]
    pub(crate) const fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Reports whether the node also owns the standard DNS port on its mesh address.
    #[cfg(target_os = "linux")]
    pub(crate) const fn has_system_port(&self) -> bool {
        self.system_port
    }

    /// Binds the UDP and TCP sockets and starts independent protocol workers.
    ///
    /// UDP gets its own poll loop. TCP state is capped by global and per-source connection count,
    /// frame size, whole-message time and idle time; each ready client gets one bounded read per
    /// poll turn. Packets over the size limit and queries outside the zone get no reply; malformed
    /// TCP messages are counted and eventually close that connection.
    fn bind_records(
        address: Ipv4Addr,
        initial: Records,
        try_system_port: bool,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::from((address, DNS_PORT)))?;
        let listener = TcpListener::bind(SocketAddr::from((address, DNS_PORT)))?;
        #[cfg(target_os = "linux")]
        let system_pair = if try_system_port {
            match (
                UdpSocket::bind(SocketAddr::from((address, DNS_SYSTEM_PORT))),
                TcpListener::bind(SocketAddr::from((address, DNS_SYSTEM_PORT))),
            ) {
                (Ok(system_socket), Ok(system_listener))
                    if system_listener.set_nonblocking(true).is_ok() =>
                {
                    Some((system_socket, system_listener))
                }
                _ => None,
            }
        } else {
            None
        };
        #[cfg(target_os = "macos")]
        let system_pair = {
            let _ = try_system_port;
            None::<(UdpSocket, TcpListener)>
        };
        Self::serve_sockets(initial, socket, listener, system_pair)
    }

    /// Starts workers with continuous ownership of all bound sockets and joins them on shutdown.
    fn serve_sockets(
        initial: Records,
        socket: UdpSocket,
        listener: TcpListener,
        system_pair: Option<(UdpSocket, TcpListener)>,
    ) -> io::Result<Self> {
        let address = initial.local_address;
        listener.set_nonblocking(true)?;
        #[cfg(target_os = "linux")]
        let system_port = system_pair.is_some();
        let mut worker_sockets = vec![socket];
        let mut worker_listeners = vec![listener];
        if let Some((system_socket, system_listener)) = system_pair {
            worker_sockets.push(system_socket);
            worker_listeners.push(system_listener);
        }
        let (mut udp_shutdown, udp_shutdown_reader) = UnixStream::pair()?;
        let (tcp_shutdown, tcp_shutdown_reader) = UnixStream::pair()?;
        let records = Arc::new(RwLock::new(initial));
        let udp_records = Arc::clone(&records);
        let udp_worker = thread::Builder::new()
            .name("mesh-dns-udp".to_owned())
            .spawn(move || run_udp_worker(&worker_sockets, &udp_shutdown_reader, &udp_records))?;
        let tcp_records = Arc::clone(&records);
        let tcp_worker = match thread::Builder::new()
            .name("mesh-dns-tcp".to_owned())
            .spawn(move || run_tcp_worker(&worker_listeners, &tcp_shutdown_reader, &tcp_records))
        {
            Ok(worker) => worker,
            Err(error) => {
                let _ = udp_shutdown.write(&[0]);
                let _ = udp_worker.join();
                return Err(error);
            }
        };
        Ok(Self {
            address,
            #[cfg(target_os = "linux")]
            system_port,
            records,
            udp_shutdown,
            tcp_shutdown,
            udp_worker: Some(udp_worker),
            tcp_worker: Some(tcp_worker),
        })
    }

    /// Swaps in the names of a newly accepted snapshot. Takes effect for the
    /// next query.
    ///
    /// # Errors
    /// Rejects malformed names, references to absent peers and duplicate
    /// names, and returns `Unsupported` if the node's mesh address changed:
    /// that needs a new resolver. The old names stay active on error.
    pub fn replace(&self, config: &Config) -> io::Result<()> {
        if config.addresses.ipv4 != self.address {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "mesh DNS address changes require resolver replacement",
            ));
        }
        let next = Records::from_config(config)?;
        *self
            .records
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = next;
        Ok(())
    }

    /// Swaps in records that are already validated.
    pub(crate) fn publish(&self, records: Records) {
        *self
            .records
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = records;
    }
}

/// Root Linux nodes try port 53 for `NetworkManager`; other nodes stay high-port-only.
#[cfg(target_os = "linux")]
fn system_port_for_node() -> bool {
    nix::unistd::Uid::effective().is_root()
}

impl Drop for Resolver {
    fn drop(&mut self) {
        // The independent pipes wake both poll loops without touching DNS sockets.
        let _ = self.udp_shutdown.write(&[0]);
        let _ = self.tcp_shutdown.write(&[0]);
        if let Some(worker) = self.udp_worker.take() {
            let _ = worker.join();
        }
        if let Some(worker) = self.tcp_worker.take() {
            let _ = worker.join();
        }
    }
}
