//! Serves the accepted mesh name snapshot on the Linux mesh address [#266].
use crate::{dataplane::Config, policy::model::validate_dns};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use simple_dns::{
    CLASS, Name, OPCODE, Packet, PacketFlag, QCLASS, QTYPE, RCODE, ResourceRecord, TYPE,
    rdata::{A, AAAA, RData, SOA},
};
use std::{
    collections::BTreeMap,
    io::{self, Write as _},
    net::{Ipv4Addr, SocketAddr, UdpSocket},
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
    suffix: String,
    names: BTreeMap<String, Addresses>,
}

impl Default for Records {
    fn default() -> Self {
        Self {
            suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            names: BTreeMap::new(),
        }
    }
}

impl Records {
    pub(crate) fn from_config(config: &Config) -> io::Result<Self> {
        validate_dns(&config.dns_suffix, false).map_err(|_| invalid_config())?;
        let mut records = Self {
            suffix: config.dns_suffix.clone(),
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
        if label.len() + self.suffix.len() + 1 > 253 {
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
    if packet.len() > MAX_PACKET {
        return Err(invalid_packet());
    }
    let request = Packet::parse(packet).map_err(|_| invalid_packet())?;
    if request.has_flags(PacketFlag::RESPONSE)
        || request.opcode() != OPCODE::StandardQuery
        || request.questions.len() != 1
        || !request.answers.is_empty()
        || !request.name_servers.is_empty()
        || !request.additional_records.is_empty()
    {
        return Err(invalid_packet());
    }

    let question = request
        .questions
        .first()
        .ok_or_else(invalid_packet)?
        .clone();
    let qname = question
        .qname
        .to_string()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let label = if qname == records.suffix {
        ""
    } else {
        let Some(prefix) = qname.strip_suffix(&records.suffix) else {
            return Ok(None);
        };
        let Some(label) = prefix.strip_suffix('.') else {
            return Ok(None);
        };
        label
    };

    let opt = request.opt().cloned();
    let mut reply = request.into_reply();
    // `into_reply` replaces the DNS header, so preserve EDNS capabilities from the request.
    *reply.opt_mut() = opt;
    reply.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
    if request_had_rd(packet) {
        reply.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    if question.qclass != QCLASS::CLASS(CLASS::IN) {
        *reply.rcode_mut() = RCODE::Refused;
        return encode(&reply).map(Some);
    }

    let address = if label.contains('.') {
        None
    } else {
        records.names.get(label).copied()
    };
    let Some(address) = address else {
        *reply.rcode_mut() = RCODE::NameError;
        reply.name_servers.push(negative_soa(&records.suffix));
        return encode(&reply).map(Some);
    };
    let rdata = match question.qtype {
        QTYPE::TYPE(TYPE::A) => Some(RData::A(A::from(address.ipv4))),
        QTYPE::TYPE(TYPE::AAAA) => Some(RData::AAAA(AAAA::from(address.ipv6))),
        _ => None,
    };
    if let Some(rdata) = rdata {
        reply.answers.push(ResourceRecord::new(
            question.qname,
            CLASS::IN,
            POSITIVE_TTL,
            rdata,
        ));
    } else {
        // NODATA is negative cache data too; advertise the same bounded TTL as NXDOMAIN.
        reply.name_servers.push(negative_soa(&records.suffix));
    }
    encode(&reply).map(Some)
}

fn request_had_rd(packet: &[u8]) -> bool {
    packet.get(2).is_some_and(|flags| flags & 1 != 0)
}

fn invalid_packet() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid DNS query packet")
}

fn encode(packet: &Packet<'_>) -> io::Result<Vec<u8>> {
    packet
        .build_bytes_vec_compressed()
        .map_err(|_| invalid_packet())
}

fn negative_soa(suffix: &str) -> ResourceRecord<'static> {
    // Records validated the configurable zone before using unchecked name construction.
    let zone = Name::new_unchecked(suffix).into_owned();
    ResourceRecord::new(
        zone.clone(),
        CLASS::IN,
        NEGATIVE_TTL,
        RData::SOA(SOA {
            mname: zone.clone(),
            rname: zone,
            serial: 1,
            refresh: 30,
            retry: 5,
            expire: 60,
            minimum: NEGATIVE_TTL,
        }),
    )
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
        Self::bind_records(address, Records::default())
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
                    if let Ok(Some(reply)) = response_for_records(&query[..length], &records) {
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
