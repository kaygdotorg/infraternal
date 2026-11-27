//! Mesh name records and DNS replies for socket and tunnel clients.

use crate::{dataplane::Config, policy::model::validate_dns};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{DNSClass, Name, RData, Record, RecordType, rdata::SOA},
};
use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, Ipv4Addr},
};

/// Cache lifetime, in seconds, of answers that exist.
const POSITIVE_TTL: u32 = 30;
/// Cache lifetime, in seconds, of "no such name" and "no such record type"
/// answers. Short, so a new node becomes reachable quickly.
const NEGATIVE_TTL: u32 = 5;
/// Largest query accepted, in bytes. Longer datagrams are dropped.
pub const MAX_PACKET: usize = 4096;
/// Why the resolver sent nothing back for something it received.
///
/// The log reports only this reason and a count, never the queried name: names are private to
/// the peers allowed to reach them (D327), and junk traffic must not be able to fill the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
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
    #[must_use]
    pub const fn as_str(self) -> &'static str {
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
pub struct Records {
    local_address: Ipv4Addr,
    suffixes: Vec<String>,
    names: BTreeMap<String, Addresses>,
}

impl Records {
    /// No names yet, only the default suffix. Every query in the zone gets
    /// "no such name" until real records are published.
    #[must_use]
    pub fn empty(local_address: Ipv4Addr) -> Self {
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
    pub fn from_config(config: &Config) -> io::Result<Self> {
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
    #[must_use]
    pub const fn local_address(&self) -> Ipv4Addr {
        self.local_address
    }

    /// Every name as `(host label, IPv4 address, IPv6 address)`, in label order.
    ///
    /// The hosts-file fallback uses it to publish the same names the resolver answers when the
    /// host has no resolver that can route one suffix. The IPv6 address is `None` for an
    /// IPv4-only node (#578), so no line is written for an address nothing answers on.
    #[must_use]
    pub fn host_entries(&self) -> Vec<(&str, Ipv4Addr, Option<std::net::Ipv6Addr>)> {
        self.names
            .iter()
            .map(|(label, addresses)| (label.as_str(), addresses.ipv4, addresses.ipv6))
            .collect()
    }

    /// The default and custom DNS zones this snapshot answers.
    #[must_use]
    pub fn suffixes(&self) -> &[String] {
        &self.suffixes
    }

    /// A snapshot for tests: this node at `local_address` under the default suffix, plus
    /// `names` as IPv4-only hosts.
    ///
    /// # Panics
    /// Panics if the fixture supplies an invalid or duplicate name.
    #[cfg(any(test, all(feature = "test-support", target_os = "macos")))]
    #[allow(
        clippy::expect_used,
        reason = "invalid names should fail a DNS fixture immediately"
    )]
    #[must_use]
    pub fn for_tests(local_address: Ipv4Addr, names: &[(&str, Ipv4Addr)]) -> Self {
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

/// Answers one DNS query packet from `config`'s names, as if it came from this
/// node itself. Mainly for tests and tools; the running host service uses [`response_for_source`].
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
///
/// # Errors
/// Refuses malformed, oversized or unencodable DNS messages.
pub fn response_for_records(packet: &[u8], records: &Records) -> io::Result<Vec<u8>> {
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
///
/// # Errors
/// Reports why the resolver must drop a packet when it cannot send a reply.
pub fn response_for_source(
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

/// Reports whether `reply` is a `FORMERR` or `NOTIMP` answer: the client sent a message that
/// parsed but was not one plain query. Reads the response code from the fixed DNS header.
#[must_use]
pub fn is_protocol_error(reply: &[u8]) -> bool {
    reply.get(3).is_some_and(|flags| {
        let code = u16::from(flags & 0x0f);
        code == u16::from(ResponseCode::FormErr) || code == u16::from(ResponseCode::NotImp)
    })
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
}
