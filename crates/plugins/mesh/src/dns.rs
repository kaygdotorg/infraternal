//! Serves one node's accepted mesh name snapshot on its Linux mesh address [#266].
//!
//! Slice 1 answers only queries sourced from this node's own mesh address. Other sources receive
//! `REFUSED` without records, so a node cannot use another resolver's broader visibility. Remote
//! DNS service needs a per-asker snapshot path and belongs to a later slice.
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

/// The host split-DNS integration sends the configured mesh suffix to this service's high port.
pub const DNS_PORT: u16 = 1053;
const POSITIVE_TTL: u32 = 30;
const NEGATIVE_TTL: u32 = 5;
const MAX_PACKET: usize = 4096;

#[derive(Clone, Copy)]
struct Addresses {
    ipv4: Ipv4Addr,
    ipv6: std::net::Ipv6Addr,
}

/// A canonical, immutable-by-convention view of names from one accepted revision.
#[derive(Clone)]
pub(crate) struct Records {
    local_address: Ipv4Addr,
    suffixes: Vec<String>,
    names: BTreeMap<String, Addresses>,
}

impl Records {
    fn empty(local_address: Ipv4Addr) -> Self {
        Self {
            local_address,
            suffixes: vec![crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned()],
            names: BTreeMap::new(),
        }
    }

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
}

fn invalid_config() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or duplicate mesh DNS name",
    )
}

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

/// Build one authoritative response, or return `None` for names outside the configured suffix.
///
/// Names outside this zone are left to the operating system's other DNS routes. The
/// split-DNS installer must therefore direct only this suffix's queries here.
/// # Errors
/// Rejects malformed packets, non-query opcodes, multiple questions and invalid snapshots.
pub fn response(packet: &[u8], config: &Config) -> io::Result<Option<Vec<u8>>> {
    let records = Records::from_config(config)?;
    response_for_records(packet, &records)
}

fn response_for_records(packet: &[u8], records: &Records) -> io::Result<Option<Vec<u8>>> {
    response_for_source(packet, records, IpAddr::V4(records.local_address))
}

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
    if source != IpAddr::V4(records.local_address) {
        // Each resolver has only its local node's filtered view. Never answer another node from it.
        reply.metadata.response_code = ResponseCode::Refused;
        return encode(&reply).map(Some);
    }
    reply.metadata.authoritative = true;

    let qname = question
        .name()
        .to_ascii()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let Some((suffix, label)) = matching_zone(&qname, &records.suffixes) else {
        return Ok(None);
    };

    if question.query_class() != DNSClass::IN {
        reply.metadata.response_code = ResponseCode::Refused;
        return encode(&reply).map(Some);
    }

    let address = if label.contains('.') {
        None
    } else {
        records.names.get(label).copied()
    };
    let Some(address) = address else {
        reply.metadata.response_code = ResponseCode::NXDomain;
        reply.authorities.push(negative_soa(suffix)?);
        return encode(&reply).map(Some);
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

fn invalid_packet() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid DNS query packet")
}

fn encode(message: &Message) -> io::Result<Vec<u8>> {
    message.to_vec().map_err(|_| invalid_packet())
}

fn negative_soa(suffix: &str) -> io::Result<Record> {
    // Records validates the configured suffix before constructing Hickory's owned DNS name.
    let zone = Name::from_ascii(suffix).map_err(|_| invalid_config())?;
    Ok(Record::from_rdata(
        zone.clone(),
        NEGATIVE_TTL,
        RData::SOA(SOA::new(zone.clone(), zone, 1, 30, 5, 60, NEGATIVE_TTL)),
    ))
}

/// A UDP listener bound only to a mesh IPv4 address, with an atomically replaced snapshot.
pub struct Resolver {
    address: Ipv4Addr,
    records: Arc<RwLock<Records>>,
    shutdown: UnixStream,
    worker: Option<JoinHandle<()>>,
}

impl Resolver {
    /// Bind the DNS UDP high port on the mesh address and publish the accepted snapshot.
    /// # Errors
    /// Reports an invalid name snapshot, an occupied DNS port or an unavailable mesh address.
    pub fn bind(config: &Config) -> io::Result<Self> {
        let records = Records::from_config(config)?;
        Self::bind_records(config.addresses.ipv4, records)
    }

    pub(crate) fn bind_empty(address: Ipv4Addr) -> io::Result<Self> {
        Self::bind_records(address, Records::empty(address))
    }

    pub(crate) const fn address(&self) -> Ipv4Addr {
        self.address
    }

    fn bind_records(address: Ipv4Addr, initial: Records) -> io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::from((address, DNS_PORT)))?;
        let worker_socket = socket.try_clone()?;
        let (shutdown, shutdown_reader) = UnixStream::pair()?;
        let records = Arc::new(RwLock::new(initial));
        let worker_records = Arc::clone(&records);
        let worker = thread::Builder::new()
            .name("mesh-dns".to_owned())
            .spawn(move || {
                // The sentinel byte exposes recv_from truncation at the protocol size limit.
                let mut query = [0_u8; MAX_PACKET + 1];
                let mut descriptors = [
                    PollFd::new(worker_socket.as_fd(), PollFlags::POLLIN),
                    PollFd::new(shutdown_reader.as_fd(), PollFlags::POLLIN),
                ];
                loop {
                    match poll(&mut descriptors, PollTimeout::NONE) {
                        Ok(_) => {}
                        Err(nix::errno::Errno::EINTR) => continue,
                        Err(_) => break,
                    }
                    let shutdown_ready = descriptors[1].revents().unwrap_or_else(PollFlags::empty);
                    if shutdown_ready
                        .intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
                    {
                        break;
                    }
                    let socket_ready = descriptors[0].revents().unwrap_or_else(PollFlags::empty);
                    if !socket_ready.contains(PollFlags::POLLIN) {
                        continue;
                    }
                    let (length, source) = match worker_socket.recv_from(&mut query) {
                        Ok(result) => result,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
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
            })?;
        Ok(Self {
            address,
            records,
            shutdown,
            worker: Some(worker),
        })
    }

    /// Replace records after a complete coordinator snapshot has been accepted.
    /// # Errors
    /// Rejects malformed names, references to absent peers, and duplicate labels.
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

    pub(crate) fn publish(&self, records: Records) {
        *self
            .records
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = records;
    }
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
