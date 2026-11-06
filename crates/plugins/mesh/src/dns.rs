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
    io::{self, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    os::{fd::AsFd, unix::net::UnixStream},
    sync::{Arc, RwLock},
    thread::{self, JoinHandle},
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

/// The mesh DNS server of one node.
///
/// It listens on UDP port [`DNS_PORT`] of the node's mesh IPv4 address only,
/// with a background thread named `mesh-dns`. Queries from any other source
/// receive the same NXDOMAIN as an absent name (see [`response`]). Names can be replaced while it runs
/// ([`replace`](Resolver::replace)); each query sees a whole snapshot, never a
/// half-updated one. Dropping the resolver stops the thread and waits for it.
pub struct Resolver {
    address: Ipv4Addr,
    #[cfg(target_os = "linux")]
    system_port: bool,
    records: Arc<RwLock<Records>>,
    shutdown: UnixStream,
    worker: Option<JoinHandle<()>>,
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

    /// Starts serving on `address` with no names, so both eligible ports are held before publish.
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

    /// Binds the socket and starts the worker thread.
    ///
    /// The thread waits on the socket and on a shutdown pipe at once, so it
    /// needs no timer to notice shutdown. Packets over the size limit,
    /// unparseable queries and queries outside the zone get no reply; send
    /// errors are ignored because UDP gives no delivery guarantee anyway.
    fn bind_records(
        address: Ipv4Addr,
        initial: Records,
        try_system_port: bool,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::from((address, DNS_PORT)))?;
        #[cfg(target_os = "linux")]
        let system_socket = if try_system_port {
            UdpSocket::bind(SocketAddr::from((address, DNS_SYSTEM_PORT))).ok()
        } else {
            None
        };
        #[cfg(target_os = "macos")]
        let system_socket = {
            let _ = try_system_port;
            None::<UdpSocket>
        };
        #[cfg(target_os = "linux")]
        let system_port = system_socket.is_some();
        let mut worker_sockets = vec![socket];
        if let Some(system_socket) = system_socket {
            worker_sockets.push(system_socket);
        }
        let (shutdown, shutdown_reader) = UnixStream::pair()?;
        let records = Arc::new(RwLock::new(initial));
        let worker_records = Arc::clone(&records);
        let worker = thread::Builder::new()
            .name("mesh-dns".to_owned())
            .spawn(move || {
                // The sentinel byte exposes recv_from truncation at the protocol size limit.
                let mut query = [0_u8; MAX_PACKET + 1];
                let mut descriptors = worker_sockets
                    .iter()
                    .map(|socket| PollFd::new(socket.as_fd(), PollFlags::POLLIN))
                    .collect::<Vec<_>>();
                let shutdown_index = descriptors.len();
                descriptors.push(PollFd::new(shutdown_reader.as_fd(), PollFlags::POLLIN));
                'worker: loop {
                    match poll(&mut descriptors, PollTimeout::NONE) {
                        Ok(_) => {}
                        Err(nix::errno::Errno::EINTR) => continue,
                        Err(_) => break 'worker,
                    }
                    let shutdown_ready = descriptors[shutdown_index]
                        .revents()
                        .unwrap_or_else(PollFlags::empty);
                    if shutdown_ready
                        .intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
                    {
                        break;
                    }
                    for (index, worker_socket) in worker_sockets.iter().enumerate() {
                        let socket_ready = descriptors[index]
                            .revents()
                            .unwrap_or_else(PollFlags::empty);
                        if !socket_ready.contains(PollFlags::POLLIN) {
                            continue;
                        }
                        let (length, source) = match worker_socket.recv_from(&mut query) {
                            Ok(result) => result,
                            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                            Err(_) => break 'worker,
                        };
                        if length > MAX_PACKET {
                            continue;
                        }
                        let records = worker_records
                            .read()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Ok(Some(reply)) =
                            response_for_source(&query[..length], &records, source.ip())
                        {
                            let _ = worker_socket.send_to(&reply, source);
                        }
                    }
                }
            })?;
        Ok(Self {
            address,
            #[cfg(target_os = "linux")]
            system_port,
            records,
            shutdown,
            worker: Some(worker),
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
        // The pipe wakes poll independently of the mesh address, without an idle timer.
        let _ = self.shutdown.write(&[0]);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
