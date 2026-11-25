//! Serves one node's accepted, policy-filtered mesh name snapshot on its mesh address [#266].
//!
//! A node's own snapshot contains only names it may reach. Queries from another source are treated
//! as nonexistent inside the zone, so this listener never reveals names from its broader view.
//!
//! Every query that parses gets an answer, never silence (#580, J1183): a name outside the mesh
//! zones gets `REFUSED`, so a client's stub resolver moves on at once instead of waiting out its
//! timeout. A message that parses but is not one plain question gets `FORMERR` or `NOTIMP`. Only
//! bytes that do not parse as DNS, oversized packets and response messages (which must never be
//! answered, or two resolvers could bounce replies forever) are dropped; each drop is counted in a
//! rate-limited log line that names no queried name (see [`DropLog`]).
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
    sync::{Arc, Mutex, RwLock},
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
/// Shortest time between two "dropped queries" log lines. Drops in between are counted and
/// reported by the next line, so a flood of junk costs one line a minute, not one per packet.
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Why the resolver sent nothing back for something it received.
///
/// The log reports only this reason and a count, never the queried name: names are private to
/// the peers allowed to reach them (D327), and junk traffic must not be able to fill the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DropReason {
    /// The datagram or TCP frame was larger than [`MAX_PACKET`], or a TCP length prefix was
    /// outside the allowed range.
    Oversized,
    /// The bytes do not parse as a DNS message.
    Malformed,
    /// The message is a response, not a query. Answering it could start a reply loop.
    NotAQuery,
    /// The answer would not fit in one TCP frame of at most [`MAX_PACKET`] bytes.
    AnswerTooLarge,
    /// The reply could not be encoded. This points at a bug or an invalid zone, not the client.
    Unencodable,
    /// A new TCP connection went over the global or per-source connection limit.
    ConnectionLimit,
}

impl DropReason {
    /// A short, stable word for the log line.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Oversized => "oversized",
            Self::Malformed => "malformed",
            Self::NotAQuery => "not-a-query",
            Self::AnswerTooLarge => "answer-too-large",
            Self::Unencodable => "unencodable",
            Self::ConnectionLimit => "tcp-connection-limit",
        }
    }
}

/// Counts dropped queries and logs them at most once per [`DROP_LOG_INTERVAL`].
///
/// The first drop is logged at once, so an operator sees the problem while reproducing it.
/// Later drops inside the interval are only counted; the next line after the interval reports
/// how many there were. Both protocol workers share one log through an [`Arc`].
#[derive(Default)]
struct DropLog {
    window: Mutex<DropWindow>,
}

/// The mutable part of [`DropLog`]: when it last logged and what it has counted since.
#[derive(Default)]
struct DropWindow {
    logged_at: Option<Instant>,
    unreported: u64,
}

impl DropLog {
    /// Records one drop for `reason` and writes the log line when the interval allows it.
    fn record(&self, reason: DropReason) {
        if let Some(dropped) = self.note(Instant::now()) {
            tracing::info!(
                dropped,
                reason = reason.as_str(),
                "mesh DNS dropped queries it could not answer"
            );
        }
    }

    /// Counts one drop at `now`. Returns the number of drops to report when a line is due
    /// (this one included), or `None` while the previous line is younger than the interval.
    fn note(&self, now: Instant) -> Option<u64> {
        let mut window = self
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        window.unreported += 1;
        if window
            .logged_at
            .is_some_and(|logged_at| now.saturating_duration_since(logged_at) < DROP_LOG_INTERVAL)
        {
            return None;
        }
        window.logged_at = Some(now);
        Some(std::mem::take(&mut window.unreported))
    }
}

/// The addresses one name resolves to.
///
/// `ipv6` is `None` for a node that runs IPv4-only (#578, J1142): its name then has an `A`
/// record and an empty `AAAA` answer, so a client that tries IPv6 first learns at once that
/// there is nothing to try instead of timing out on an address nothing answers.
#[derive(Clone, Copy)]
struct Addresses {
    ipv4: Ipv4Addr,
    ipv6: Option<std::net::Ipv6Addr>,
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
                    ipv6: Some(config.addresses.ipv6),
                },
            )?;
        }
        for (node, name) in &config.peer_names {
            let peer = config.peers.get(node).ok_or_else(invalid_config)?;
            records.insert(
                name,
                Addresses {
                    ipv4: peer.peer.addresses.ipv4,
                    ipv6: (!peer.peer.ipv4_only).then_some(peer.peer.addresses.ipv6),
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

    /// Every name as `(host label, IPv4 address, IPv6 address)`, in label order.
    ///
    /// The hosts-file fallback uses it to publish the same names the resolver answers when the
    /// host has no resolver that can route one suffix. The IPv6 address is `None` for an
    /// IPv4-only node (#578), so no line is written for an address nothing answers on.
    #[cfg(target_os = "linux")]
    pub(crate) fn host_entries(&self) -> Vec<(&str, Ipv4Addr, Option<std::net::Ipv6Addr>)> {
        self.names
            .iter()
            .map(|(label, addresses)| (label.as_str(), addresses.ipv4, addresses.ipv6))
            .collect()
    }

    /// The default and custom DNS zones this snapshot answers.
    pub(crate) fn suffixes(&self) -> &[String] {
        &self.suffixes
    }

    /// A snapshot for tests: this node at `local_address` under the default suffix, plus
    /// `names` as IPv4-only hosts.
    #[cfg(test)]
    #[allow(clippy::expect_used)]
    pub(crate) fn for_tests(local_address: Ipv4Addr, names: &[(&str, Ipv4Addr)]) -> Self {
        let mut records = Self {
            local_address,
            suffixes: vec![crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned()],
            names: BTreeMap::new(),
        };
        for (label, ipv4) in names {
            records
                .insert(
                    label,
                    Addresses {
                        ipv4: *ipv4,
                        ipv6: None,
                    },
                )
                .expect("valid test name");
        }
        records
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
///
/// A connection over the global or per-source limit is closed at once and counted in `drops`.
fn accept_tcp_connections(
    listener: &TcpListener,
    clients: &mut Vec<TcpClient>,
    drops: &DropLog,
) -> io::Result<()> {
    for _ in 0..TCP_ACCEPT_BUDGET {
        match listener.accept() {
            Ok((stream, source)) => {
                let source_connections = clients
                    .iter()
                    .filter(|client| client.source.ip() == source.ip())
                    .count();
                if clients.len() >= TCP_CONNECTION_LIMIT
                    || source_connections >= TCP_SOURCE_CONNECTION_LIMIT
                {
                    drops.record(DropReason::ConnectionLimit);
                    continue;
                }
                if stream.set_nonblocking(true).is_err() {
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
///
/// Returns `false` when the connection should close. A frame that gets no answer is counted in
/// `drops`; too many of them on one connection close it.
fn read_tcp_request(
    client: &mut TcpClient,
    records: &Arc<RwLock<Records>>,
    drops: &DropLog,
) -> bool {
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
                    drops.record(DropReason::Oversized);
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
                Ok(response) if response.len() <= MAX_PACKET => {
                    // FORMERR and NOTIMP are answered, but still spend the malformed-frame
                    // budget, so a stream of junk headers is cut off as before.
                    if is_protocol_error(&response) {
                        client.malformed_frames += 1;
                        if client.malformed_frames >= TCP_MALFORMED_FRAME_LIMIT {
                            return false;
                        }
                    }
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
                Ok(_) => {
                    drops.record(DropReason::AnswerTooLarge);
                    false
                }
                Err(reason) => {
                    drops.record(reason);
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

/// Reports whether `reply` is a `FORMERR` or `NOTIMP` answer: the client sent a message that
/// parsed but was not one plain query. Reads the response code from the fixed DNS header.
fn is_protocol_error(reply: &[u8]) -> bool {
    reply.get(3).is_some_and(|flags| {
        let code = u16::from(flags & 0x0f);
        code == u16::from(ResponseCode::FormErr) || code == u16::from(ResponseCode::NotImp)
    })
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
    drops: &DropLog,
) -> bool {
    if ready.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
        return false;
    }
    if client.output.is_empty() {
        if ready.contains(PollFlags::POLLIN) && !read_tcp_request(client, records, drops) {
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
/// Returns the encoded reply. A name outside every mesh suffix gets `REFUSED`, so a host whose
/// split-DNS setup sends it here by mistake learns at once to ask elsewhere (#580).
///
/// # Errors
/// Rejects oversized packets, bytes that do not parse as DNS, response messages, and
/// configurations with invalid names. The running resolver sends nothing back in those cases.
pub fn response(packet: &[u8], config: &Config) -> io::Result<Vec<u8>> {
    let records = Records::from_config(config)?;
    response_for_records(packet, &records)
}

/// Like [`response`], but with names that are already built. The query counts as the node's
/// own, as [`crate::tunnel_dns`] needs for queries the host wrote into its tunnel.
pub(crate) fn response_for_records(packet: &[u8], records: &Records) -> io::Result<Vec<u8>> {
    response_for_source(packet, records, IpAddr::V4(records.local_address)).map_err(|reason| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("DNS packet not answered: {}", reason.as_str()),
        )
    })
}

/// Builds the reply to `packet` received from `source`.
///
/// The outcomes, in order:
/// - `Err` (nothing is sent) for an oversized packet, bytes that do not parse as DNS, or a
///   response message. A response is never answered, so two resolvers cannot loop.
/// - `NOTIMP` for an opcode other than a standard query.
/// - `FORMERR` for a query without exactly one question, with records in the answer,
///   authority or additional sections, or with a signature.
/// - `REFUSED`, not authoritative, if the name is outside every configured suffix. Silence here
///   made a mistyped zone look like a dead resolver (#580, J1183); `REFUSED` reveals nothing
///   about mesh names (D327) and tells the client to try its other servers.
/// - `REFUSED` for a class other than `IN`.
/// - `NXDOMAIN` plus a short-lived SOA if `source` is not this node's own mesh
///   address or the host is absent (a name with multiple host labels never exists).
/// - An `A` or `AAAA` answer for existing hosts; any other record type gets an
///   empty answer plus the SOA (NODATA). So does `AAAA` for a host that runs IPv4-only
///   (#578, J1142): the name exists, it just has no IPv6 address.
fn response_for_source(
    packet: &[u8],
    records: &Records,
    source: IpAddr,
) -> Result<Vec<u8>, DropReason> {
    if packet.len() > MAX_PACKET {
        return Err(DropReason::Oversized);
    }
    let request = Message::from_vec(packet).map_err(|_| DropReason::Malformed)?;
    if request.metadata.message_type != MessageType::Query {
        return Err(DropReason::NotAQuery);
    }
    if request.metadata.op_code != OpCode::Query {
        return error_response(&request, ResponseCode::NotImp);
    }
    if request.queries.len() != 1
        || !request.answers.is_empty()
        || !request.authorities.is_empty()
        || !request.additionals.is_empty()
        || request.signature.is_some()
    {
        return error_response(&request, ResponseCode::FormErr);
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
        // Not our zone, so not authoritative: the client should ask its other servers.
        reply.metadata.response_code = ResponseCode::Refused;
        return encode(&reply);
    };
    reply.metadata.authoritative = true;

    if question.query_class() != DNSClass::IN {
        reply.metadata.response_code = ResponseCode::Refused;
        return encode(&reply);
    }
    if source != IpAddr::V4(records.local_address) {
        // A peer asking this node directly sees no names from its broader local view. Treat every
        // such in-zone query as missing, so the answer cannot reveal whether the name exists here.
        return negative_response(reply, suffix);
    }

    let address = if label.contains('.') {
        None
    } else {
        records.names.get(label).copied()
    };
    let Some(address) = address else {
        return negative_response(reply, suffix);
    };
    let rdata = match question.query_type() {
        RecordType::A => Some(RData::A(address.ipv4.into())),
        RecordType::AAAA => address.ipv6.map(|ipv6| RData::AAAA(ipv6.into())),
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
    encode(&reply)
}

/// A bare error reply to a query this resolver cannot handle, with `code` and the query's id.
///
/// It echoes the question only when there is exactly one, and never EDNS or other sections, so
/// the reply is never larger than a minimal query and cannot amplify traffic.
fn error_response(request: &Message, code: ResponseCode) -> Result<Vec<u8>, DropReason> {
    let mut reply = Message::response(request.metadata.id, request.metadata.op_code);
    reply.metadata.recursion_desired = request.metadata.recursion_desired;
    reply.metadata.response_code = code;
    if let [question] = request.queries.as_slice() {
        reply.queries.push(question.clone());
    }
    encode(&reply)
}

/// Builds the negative answer shared by filtered queries and missing names.
/// Keeping one path gives both cases the same NXDOMAIN response and SOA data.
fn negative_response(mut reply: Message, suffix: &str) -> Result<Vec<u8>, DropReason> {
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

/// Serializes a reply. A failure means the reply itself is unusable, so nothing is sent.
fn encode(message: &Message) -> Result<Vec<u8>, DropReason> {
    message.to_vec().map_err(|_| DropReason::Unencodable)
}

/// The SOA record for `suffix`, attached to negative answers so resolvers
/// cache them for [`NEGATIVE_TTL`] seconds.
fn negative_soa(suffix: &str) -> Result<Record, DropReason> {
    // Records validates the configured suffix before constructing Hickory's owned DNS name.
    let zone = Name::from_ascii(suffix).map_err(|_| DropReason::Unencodable)?;
    Ok(Record::from_rdata(
        zone.clone(),
        NEGATIVE_TTL,
        RData::SOA(SOA::new(zone.clone(), zone, 1, 30, 5, 60, NEGATIVE_TTL)),
    ))
}

/// Serves UDP on its own worker so TCP framing and clients cannot delay datagrams.
///
/// Every datagram that gets no reply is counted in `drops`.
fn run_udp_worker(
    sockets: &[UdpSocket],
    shutdown_reader: &UnixStream,
    records: &Arc<RwLock<Records>>,
    drops: &DropLog,
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
                drops.record(DropReason::Oversized);
                continue;
            }
            let response = {
                let snapshot = records
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                response_for_source(&query[..length], &snapshot, source.ip())
            };
            match response {
                Ok(reply) => {
                    let _ = socket.send_to(&reply, source);
                }
                Err(reason) => drops.record(reason),
            }
        }
    }
}

/// Serves TCP independently, with bounded accepts, reads and per-connection state.
fn run_tcp_worker(
    listeners: &[TcpListener],
    shutdown_reader: &UnixStream,
    records: &Arc<RwLock<Records>>,
    drops: &DropLog,
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
            if !service_tcp_client(
                &mut clients[index],
                ready[clients_start + index],
                records,
                drops,
            ) {
                clients.swap_remove(index);
            }
        }
        for (index, listener) in listeners.iter().enumerate() {
            if ready[index].contains(PollFlags::POLLIN)
                && accept_tcp_connections(listener, &mut clients, drops).is_err()
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
/// absent name, and names outside the mesh zones receive `REFUSED` (see [`response`]). Names can be replaced while it runs; each query sees a whole
/// snapshot, never a half-updated one. Dropping the resolver stops both workers and waits for them.
pub struct Resolver {
    address: Ipv4Addr,
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
    /// Port 53 is optional because host DNS forwarding can target [`DNS_PORT`] directly. A root
    /// Linux node also offers it as a compatibility listener when the address and port are free.
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

    /// Binds the UDP and TCP sockets and starts independent protocol workers.
    ///
    /// UDP gets its own poll loop. TCP state is capped by global and per-source connection count,
    /// frame size, whole-message time and idle time; each ready client gets one bounded read per
    /// poll turn. Packets over the size limit and bytes that do not parse get no reply and are
    /// logged (rate-limited); malformed TCP messages also count toward closing that connection.
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
        let mut worker_sockets = vec![socket];
        let mut worker_listeners = vec![listener];
        if let Some((system_socket, system_listener)) = system_pair {
            worker_sockets.push(system_socket);
            worker_listeners.push(system_listener);
        }
        let (mut udp_shutdown, udp_shutdown_reader) = UnixStream::pair()?;
        let (tcp_shutdown, tcp_shutdown_reader) = UnixStream::pair()?;
        let records = Arc::new(RwLock::new(initial));
        // One drop log for both workers, so its rate limit covers the whole resolver.
        let drops = Arc::new(DropLog::default());
        let udp_records = Arc::clone(&records);
        let udp_drops = Arc::clone(&drops);
        let udp_worker = thread::Builder::new()
            .name("mesh-dns-udp".to_owned())
            .spawn(move || {
                run_udp_worker(
                    &worker_sockets,
                    &udp_shutdown_reader,
                    &udp_records,
                    &udp_drops,
                );
            })?;
        let tcp_records = Arc::clone(&records);
        let tcp_worker = match thread::Builder::new()
            .name("mesh-dns-tcp".to_owned())
            .spawn(move || {
                run_tcp_worker(
                    &worker_listeners,
                    &tcp_shutdown_reader,
                    &tcp_records,
                    &drops,
                );
            }) {
            Ok(worker) => worker,
            Err(error) => {
                let _ = udp_shutdown.write(&[0]);
                let _ = udp_worker.join();
                return Err(error);
            }
        };
        Ok(Self {
            address,
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

/// Root Linux nodes also offer the optional port 53 compatibility listener.
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

/// Source rules and the never-silent reply rules, checked without sockets.
#[cfg(test)]
mod source_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// One plain `A` query for `web.internal`, built by hand.
    fn query() -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["web", "internal"] {
            packet.push(u8::try_from(label.len()).unwrap());
            packet.extend_from_slice(label.as_bytes());
        }
        packet.extend_from_slice(&[0, 0, 1, 0, 1]);
        packet
    }

    /// The node's own address gets the answer; a peer asking directly, or a loopback source,
    /// sees the name as absent (#146: user mode answers from the tunnel, never on loopback).
    #[test]
    fn only_the_node_itself_is_answered() {
        let own = Ipv4Addr::new(10, 254, 0, 7);
        let mut names = BTreeMap::new();
        names.insert(
            "web".to_owned(),
            Addresses {
                ipv4: Ipv4Addr::new(10, 254, 0, 9),
                ipv6: Some("fd00::9".parse().unwrap()),
            },
        );
        let records = Records {
            local_address: own,
            suffixes: vec!["internal".to_owned()],
            names,
        };
        let answers = |source: IpAddr| {
            let reply = response_for_source(&query(), &records, source).unwrap();
            Message::from_vec(&reply).unwrap().answers.len()
        };
        assert_eq!(answers(IpAddr::V4(own)), 1);
        assert_eq!(answers(IpAddr::V4(Ipv4Addr::LOCALHOST)), 0);
        assert_eq!(answers(IpAddr::V4(Ipv4Addr::new(10, 254, 0, 9))), 0);
    }

    /// The response code and answer count of a reply the resolver built.
    fn outcome(reply: &[u8]) -> (ResponseCode, usize, bool) {
        let message = Message::from_vec(reply).unwrap();
        (
            message.metadata.response_code,
            message.answers.len(),
            message.metadata.authoritative,
        )
    }

    /// A query for `name` (dot-separated labels) with record type `A`.
    fn query_for(name: &str) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(u8::try_from(label.len()).unwrap());
            packet.extend_from_slice(label.as_bytes());
        }
        packet.extend_from_slice(&[0, 0, 1, 0, 1]);
        packet
    }

    /// #580 (J1183): prod's own host asked for names outside its zones and got silence, which
    /// looked like a dead resolver. Out-of-zone names now get a non-authoritative `REFUSED` from
    /// every source, while the node's own name still resolves for the node itself.
    #[test]
    fn names_outside_the_zones_are_refused_not_ignored() {
        let own = Ipv4Addr::new(10, 254, 0, 2);
        let records = Records::for_tests(own, &[("ssh", own)]);
        for source in [IpAddr::V4(own), IpAddr::V4(Ipv4Addr::new(10, 254, 0, 4))] {
            for name in ["prod.mesh", "nonexistent.invalid", "ssh.internal.example"] {
                let reply = response_for_source(&query_for(name), &records, source).unwrap();
                assert_eq!(
                    outcome(&reply),
                    (ResponseCode::Refused, 0, false),
                    "{name} from {source}"
                );
                let message = Message::from_vec(&reply).unwrap();
                assert_eq!(message.metadata.id, 0x1234);
                assert!(message.metadata.recursion_desired);
                assert_eq!(message.queries.len(), 1);
            }
        }
        let own_name = response_for_source(&query_for("ssh.internal"), &records, IpAddr::V4(own));
        assert_eq!(
            outcome(&own_name.unwrap()),
            (ResponseCode::NoError, 1, true)
        );
    }

    /// A message that parses but is not one plain question gets an error code, not silence. A
    /// response message is never answered, so two resolvers cannot bounce replies forever.
    #[test]
    fn parseable_non_queries_get_error_codes_and_responses_get_nothing() {
        let own = Ipv4Addr::new(10, 254, 0, 2);
        let records = Records::for_tests(own, &[]);
        let source = IpAddr::V4(own);

        let mut notify = query_for("ssh.internal");
        notify[2] = 0x20; // opcode 4 (NOTIFY)
        let reply = response_for_source(&notify, &records, source).unwrap();
        assert_eq!(outcome(&reply).0, ResponseCode::NotImp);

        let mut two_questions = query_for("ssh.internal");
        two_questions[5] = 2;
        let question = two_questions[12..].to_vec();
        two_questions.extend_from_slice(&question);
        let reply = response_for_source(&two_questions, &records, source).unwrap();
        let message = Message::from_vec(&reply).unwrap();
        assert_eq!(message.metadata.response_code, ResponseCode::FormErr);
        assert_eq!(message.queries.len(), 0);
        assert!(reply.len() <= two_questions.len());

        let no_question = vec![0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let reply = response_for_source(&no_question, &records, source).unwrap();
        assert_eq!(outcome(&reply).0, ResponseCode::FormErr);
        assert!(is_protocol_error(&reply));
        let refused = response_for_source(&query_for("prod.mesh"), &records, source).unwrap();
        assert!(!is_protocol_error(&refused));

        let mut response = query_for("ssh.internal");
        response[2] |= 0x80;
        assert_eq!(
            response_for_source(&response, &records, source),
            Err(DropReason::NotAQuery)
        );
        assert_eq!(
            response_for_source(&[0xff; 5], &records, source),
            Err(DropReason::Malformed)
        );
        assert_eq!(
            response_for_source(&[0; MAX_PACKET + 1], &records, source),
            Err(DropReason::Oversized)
        );
    }

    /// The first drop is logged at once; drops inside the interval are counted and reported by
    /// the first line after it, so a flood writes one line a minute.
    #[test]
    fn drop_log_reports_the_first_drop_then_one_count_per_interval() {
        let log = DropLog::default();
        let start = Instant::now();
        assert_eq!(log.note(start), Some(1));
        for second in 1..=59 {
            assert_eq!(log.note(start + Duration::from_secs(second)), None);
        }
        assert_eq!(log.note(start + DROP_LOG_INTERVAL), Some(60));
        assert_eq!(log.note(start + DROP_LOG_INTERVAL), None);
    }
}
