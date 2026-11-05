//! Mesh-only DNS records, snapshot replacement and real UDP delivery [#266].
#![cfg(all(feature = "agent", feature = "mesh-dns-spike", target_os = "linux"))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::RData,
};
use infraternal_plugin_mesh::{
    dataplane::{Config, DefaultPolicy, Peer, PeerPolicy},
    dns::{self, DNS_PORT, Resolver},
    policy::{
        model::{Addresses, NodeId, PublicKey},
        rules::TrafficPolicy,
    },
};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    process::Command,
};

fn query(name: &str, qtype: u16) -> Vec<u8> {
    let mut wire = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        wire.push(u8::try_from(label.len()).unwrap());
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire.extend_from_slice(&qtype.to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes());
    wire
}

/// A one-peer mesh configuration under the `internal` DNS suffix, shared by the DNS tests.
fn config() -> Config {
    let peer = NodeId(1);
    Config {
        local_key: Some(PublicKey([2; 32])),
        server: Some(peer),
        node: NodeId(2),
        name: Some("laptop".to_owned()),
        dns_suffix: "internal".to_owned(),
        version: 1,
        addresses: Addresses {
            ipv4: Ipv4Addr::new(10, 254, 0, 2),
            ipv6: "fd66:6821:bc63:834e::2".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: BTreeMap::from([(
            peer,
            PeerPolicy {
                peer: Peer {
                    key: PublicKey([1; 32]),
                    addresses: Addresses {
                        ipv4: Ipv4Addr::new(10, 254, 0, 1),
                        ipv6: "fd66:6821:bc63:834e::1".parse().unwrap(),
                    },
                    endpoint: None,
                },
                inbound: TrafficPolicy::All,
                outbound: TrafficPolicy::All,
            },
        )]),
        peer_names: BTreeMap::from([(peer, "build-01".to_owned())]),
    }
}

fn response_wire(name: &str, qtype: u16) -> Vec<u8> {
    dns::response(&query(name, qtype), &config())
        .unwrap()
        .expect("mesh suffix is authoritative")
}

#[test]
fn peer_and_local_names_answer_a_and_aaaa_with_positive_ttl() {
    let a_wire = response_wire("BUILD-01.INTERNAL", 1);
    let a = Message::from_vec(&a_wire).unwrap();
    assert_eq!(a.metadata.message_type, MessageType::Response);
    assert!(a.metadata.authoritative);
    assert_eq!(a.answers.len(), 1);
    assert_eq!(a.answers[0].ttl, 30);
    match &a.answers[0].data {
        RData::A(address) => {
            assert_eq!(address.0, Ipv4Addr::new(10, 254, 0, 1));
        }
        other => panic!("unexpected A response: {other:?}"),
    }

    let local_a_wire = response_wire("laptop.internal", 1);
    let local_a = Message::from_vec(&local_a_wire).unwrap();
    match &local_a.answers[0].data {
        RData::A(address) => {
            assert_eq!(address.0, Ipv4Addr::new(10, 254, 0, 2));
        }
        other => panic!("unexpected local A response: {other:?}"),
    }

    let aaaa_wire = response_wire("laptop.internal", 28);
    let aaaa = Message::from_vec(&aaaa_wire).unwrap();
    assert_eq!(aaaa.answers.len(), 1);
    assert_eq!(aaaa.answers[0].ttl, 30);
    match &aaaa.answers[0].data {
        RData::AAAA(address) => {
            assert_eq!(
                address.0,
                "fd66:6821:bc63:834e::2".parse::<Ipv6Addr>().unwrap()
            );
        }
        other => panic!("unexpected AAAA response: {other:?}"),
    }

    let peer_aaaa_wire = response_wire("build-01.internal", 28);
    let peer_aaaa = Message::from_vec(&peer_aaaa_wire).unwrap();
    match &peer_aaaa.answers[0].data {
        RData::AAAA(address) => {
            assert_eq!(
                address.0,
                "fd66:6821:bc63:834e::1".parse::<Ipv6Addr>().unwrap()
            );
        }
        other => panic!("unexpected peer AAAA response: {other:?}"),
    }
}

#[test]
fn unknown_internal_names_get_nxdomain_and_five_second_negative_ttl() {
    let response_wire = response_wire("missing.internal", 1);
    let response = Message::from_vec(&response_wire).unwrap();
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(response.answers.len(), 0);
    assert_eq!(response.authorities.len(), 1);
    assert_eq!(response.authorities[0].ttl, 5);
    match &response.authorities[0].data {
        RData::SOA(soa) => assert_eq!(soa.minimum, 5),
        other => panic!("unexpected negative cache record: {other:?}"),
    }
}

#[test]
fn resolver_does_not_claim_external_names() {
    assert!(
        dns::response(&query("outside.example", 1), &config())
            .unwrap()
            .is_none()
    );
    assert!(
        dns::response(&query("outside.internal.example", 1), &config())
            .unwrap()
            .is_none()
    );
}

#[test]
fn configured_custom_suffix_is_authoritative_and_owns_its_negative_soa() {
    let mut snapshot = config();
    snapshot.dns_suffix = "mesh.kayg.org".to_owned();

    let answer_wire = dns::response(&query("build-01.mesh.kayg.org", 1), &snapshot)
        .unwrap()
        .expect("configured suffix is authoritative");
    let answer = Message::from_vec(&answer_wire).unwrap();
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(
        answer.answers[0].name.to_string().trim_end_matches('.'),
        "build-01.mesh.kayg.org"
    );

    let missing_wire = dns::response(&query("missing.mesh.kayg.org", 1), &snapshot)
        .unwrap()
        .expect("unknown names below the configured zone are authoritative");
    let missing = Message::from_vec(&missing_wire).unwrap();
    assert_eq!(missing.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(
        missing.authorities[0]
            .name
            .to_string()
            .trim_end_matches('.'),
        "mesh.kayg.org"
    );
    let internal_alias = dns::response(&query("build-01.internal", 1), &snapshot)
        .unwrap()
        .expect(".internal remains an authoritative alias");
    let internal_alias = Message::from_vec(&internal_alias).unwrap();
    assert_eq!(internal_alias.answers.len(), 1);
    assert_eq!(
        internal_alias.answers[0]
            .name
            .to_string()
            .trim_end_matches('.'),
        "build-01.internal"
    );
}

#[test]
fn origin_derived_suffix_and_internal_alias_both_resolve() {
    let mut snapshot = config();
    snapshot.dns_suffix = "ssh.kayg.org".to_owned();

    for name in ["build-01.ssh.kayg.org", "build-01.internal"] {
        let wire = dns::response(&query(name, 1), &snapshot)
            .unwrap()
            .expect("both configured and internal mesh suffixes are authoritative");
        let response = Message::from_vec(&wire).unwrap();
        assert_eq!(response.answers.len(), 1, "{name}");
        assert_eq!(
            response.answers[0].name.to_string().trim_end_matches('.'),
            name
        );
    }
}

#[test]
fn unsupported_record_types_return_a_five_second_negative_ttl() {
    let srv_wire = response_wire("build-01.internal", 33);
    let srv = Message::from_vec(&srv_wire).unwrap();
    assert_eq!(srv.answers.len(), 0);
    assert_eq!(srv.metadata.response_code, ResponseCode::NoError);
    assert_eq!(srv.authorities.len(), 1);
    assert_eq!(srv.authorities[0].ttl, 5);
    match &srv.authorities[0].data {
        RData::SOA(soa) => assert_eq!(soa.minimum, 5),
        other => panic!("unexpected NODATA cache record: {other:?}"),
    }
}

#[test]
fn accepted_snapshot_replacement_retires_renamed_records_together() {
    let old = config();
    let mut renamed = old.clone();
    renamed
        .peer_names
        .insert(NodeId(1), "build-renamed".to_owned());

    let old_wire = dns::response(&query("build-01.internal", 1), &old)
        .unwrap()
        .unwrap();
    let old_record = Message::from_vec(&old_wire).unwrap();
    assert_eq!(old_record.answers.len(), 1);
    let retired_wire = dns::response(&query("build-01.internal", 1), &renamed)
        .unwrap()
        .unwrap();
    let retired = Message::from_vec(&retired_wire).unwrap();
    assert_eq!(retired.metadata.response_code, ResponseCode::NXDomain);
    let current_wire = dns::response(&query("build-renamed.internal", 1), &renamed)
        .unwrap()
        .unwrap();
    let current = Message::from_vec(&current_wire).unwrap();
    assert_eq!(current.answers.len(), 1);

    let mut revoked = old;
    revoked.peer_names.remove(&NodeId(1));
    let retired_wire = dns::response(&query("build-01.internal", 1), &revoked)
        .unwrap()
        .unwrap();
    assert_eq!(
        Message::from_vec(&retired_wire)
            .unwrap()
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
}

#[test]
fn conflicting_or_invalid_snapshot_names_are_rejected() {
    let mut duplicate = config();
    duplicate.name = Some("build-01".to_owned());
    assert!(dns::response(&query("build-01.internal", 1), &duplicate).is_err());

    let mut invalid = config();
    invalid.name = Some("bad.name".to_owned());
    assert!(dns::response(&query("laptop.internal", 1), &invalid).is_err());

    let mut overlong = config();
    overlong.dns_suffix = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(60)
    );
    assert!(dns::response(&query("laptop.internal", 1), &overlong).is_err());
}

#[test]
fn malformed_dns_packets_are_rejected() {
    let config = config();
    let valid = query("laptop.internal", 1);
    assert!(dns::response(&[], &config).is_err());

    let mut response = valid.clone();
    response[2] |= 0x80;
    assert!(dns::response(&response, &config).is_err());

    let mut nonstandard_opcode = valid.clone();
    nonstandard_opcode[2] |= 0x08;
    assert!(dns::response(&nonstandard_opcode, &config).is_err());

    let mut no_question = valid.clone();
    no_question[4] = 0;
    no_question[5] = 0;
    assert!(dns::response(&no_question, &config).is_err());

    let mut multiple_questions = valid.clone();
    multiple_questions[5] = 2;
    multiple_questions.extend_from_slice(&valid[12..]);
    assert!(dns::response(&multiple_questions, &config).is_err());

    let mut oversized = valid;
    oversized.resize(4097, 0);
    assert!(dns::response(&oversized, &config).is_err());
}

#[test]
fn edns0_opt_queries_still_receive_mesh_answers() {
    let mut request = query("build-01.internal", 1);
    request[10..12].copy_from_slice(&1_u16.to_be_bytes());
    request.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);

    let response = dns::response(&request, &config())
        .unwrap()
        .expect("EDNS does not make an internal query external");
    let parsed = Message::from_vec(&response).unwrap();
    assert_eq!(parsed.answers.len(), 1);
    assert_eq!(parsed.answers[0].ttl, 30);
    assert!(parsed.edns.is_some(), "EDNS replies retain an OPT record");
}

#[tokio::test]
#[ignore = "Run as root inside a disposable network namespace; #266"]
async fn udp_resolver_answers_on_the_mesh_address_inside_a_network_namespace() {
    let parent = std::env::var("INFRATERNAL_DNS_TEST_PARENT_NETNS")
        .expect("network test must be launched by the isolated namespace runner");
    let current = std::fs::read_link("/proc/self/ns/net").unwrap();
    assert_ne!(current.to_string_lossy(), parent);
    assert_eq!(nix::unistd::Uid::effective().as_raw(), 0);

    assert!(
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("ip")
            .args(["address", "add", "10.254.0.2/32", "dev", "lo"])
            .status()
            .unwrap()
            .success()
    );

    let snapshot = config();
    let resolver = Resolver::bind(&snapshot).unwrap();
    let client = tokio::net::UdpSocket::bind("10.254.0.2:0").await.unwrap();
    let mut response = [0; 512];
    let (len, _) = exchange(&client, &snapshot, "build-01.internal", &mut response).await;
    assert_eq!(
        Message::from_vec(&response[..len]).unwrap().answers.len(),
        1,
        "the DNS socket must answer from the configured mesh address"
    );

    let mut renamed = snapshot.clone();
    renamed
        .peer_names
        .insert(NodeId(1), "build-renamed".to_owned());
    resolver.replace(&renamed).unwrap();
    let (len, _) = exchange(&client, &renamed, "build-01.internal", &mut response).await;
    assert_eq!(
        Message::from_vec(&response[..len])
            .unwrap()
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    let (len, _) = exchange(&client, &renamed, "build-renamed.internal", &mut response).await;
    assert_eq!(
        Message::from_vec(&response[..len]).unwrap().answers.len(),
        1
    );

    client
        .send_to(
            &query("outside.example", 1),
            SocketAddr::from((snapshot.addresses.ipv4, DNS_PORT)),
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            client.recv_from(&mut response),
        )
        .await
        .is_err()
    );

    let mut oversized = query("build-01.internal", 1);
    oversized.resize(4097, 0);
    client
        .send_to(
            &oversized,
            SocketAddr::from((snapshot.addresses.ipv4, DNS_PORT)),
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            client.recv_from(&mut response),
        )
        .await
        .is_err(),
        "a truncated oversized datagram must not be parsed as its valid prefix"
    );

    assert!(
        Command::new("ip")
            .args(["address", "del", "10.254.0.2/32", "dev", "lo"])
            .status()
            .unwrap()
            .success()
    );
    drop(resolver);
}

async fn exchange(
    client: &tokio::net::UdpSocket,
    snapshot: &Config,
    name: &str,
    response: &mut [u8],
) -> (usize, SocketAddr) {
    client
        .send_to(
            &query(name, 1),
            SocketAddr::from((snapshot.addresses.ipv4, DNS_PORT)),
        )
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(response),
    )
    .await
    .unwrap()
    .unwrap()
}

// Keep the coordinator policy and both sides of the UDP boundary in one regression.
#[test]
fn review_j68_remote_resolver_must_not_disclose_a_name_denied_to_the_asker() {
    use infraternal_plugin_mesh::{
        configuration,
        policy::{
            coordinator::Coordinator,
            model::{MeshSettings, Node},
            rules::{Arrow, Endpoint, RuleId},
        },
    };
    let member = |id| Node {
        id: NodeId(id),
        public_key: PublicKey([u8::try_from(id).unwrap(); 32]),
        host: format!("host-{id}"),
        tags: std::collections::BTreeSet::new(),
    };
    let mut coordinator = Coordinator::new(MeshSettings::new([1; 5]), &[], member(1)).unwrap();
    coordinator.join(member(2)).unwrap();
    coordinator.join(member(3)).unwrap();
    coordinator
        .add_arrow(Arrow {
            id: RuleId(1),
            from: Endpoint::Node(NodeId(1)),
            to: Endpoint::Node(NodeId(3)),
            both_ways: false,
            ports: TrafficPolicy::All,
        })
        .unwrap();
    let compile = |id| {
        configuration::compile(
            &coordinator,
            NodeId(id),
            DefaultPolicy::Deny,
            &BTreeMap::new(),
        )
        .unwrap()
    };
    let asker = compile(2);
    let mut server = compile(1);
    assert_eq!(asker.peers[&NodeId(3)].outbound, TrafficPolicy::None);
    assert!(!asker.peer_names.contains_key(&NodeId(3)));
    assert_eq!(asker.peers[&NodeId(1)].outbound, TrafficPolicy::All);
    assert_eq!(server.peers[&NodeId(2)].inbound, TrafficPolicy::All);
    let own_reply = dns::response(&query("host-3.internal", 1), &asker)
        .unwrap()
        .unwrap();
    assert_eq!(
        Message::from_vec(&own_reply)
            .unwrap()
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );

    // Loopback addresses isolate the UDP boundary without requiring kernel mesh setup.
    server.addresses.ipv4 = Ipv4Addr::new(127, 68, 0, 1);
    server
        .peers
        .get_mut(&NodeId(2))
        .unwrap()
        .peer
        .addresses
        .ipv4 = Ipv4Addr::new(127, 68, 0, 2);
    let resolver = Resolver::bind(&server).unwrap();
    let client = std::net::UdpSocket::bind("127.68.0.2:0").unwrap();
    client
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    client
        .send_to(
            &query("host-3.internal", 1),
            (server.addresses.ipv4, DNS_PORT),
        )
        .unwrap();
    let mut buffer = [0; 512];
    let (length, _) = client.recv_from(&mut buffer).unwrap();
    let reply = Message::from_vec(&buffer[..length]).unwrap();
    let remote_rcode = reply.metadata.response_code;
    let remote_answer_count = reply.answers.len();
    let remote_authority_count = reply.authorities.len();
    eprintln!(
        "asker 2 -> target 3: denied; asker 2 -> server 1 DNS: permitted; remote response: {remote_rcode:?}, {remote_answer_count} answers"
    );

    let local_client = std::net::UdpSocket::bind("127.68.0.1:0").unwrap();
    local_client
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    local_client
        .send_to(
            &query("host-3.internal", 1),
            (server.addresses.ipv4, DNS_PORT),
        )
        .unwrap();
    let (local_length, _) = local_client.recv_from(&mut buffer).unwrap();
    let local_reply = Message::from_vec(&buffer[..local_length]).unwrap();

    drop(resolver);
    assert_eq!(
        remote_rcode,
        ResponseCode::Refused,
        "remote mesh sources must not inherit the resolver host's broader policy"
    );
    assert_eq!(remote_answer_count, 0, "a remote refusal has no names");
    assert_eq!(remote_authority_count, 0, "a remote refusal has no names");
    assert_eq!(local_reply.metadata.response_code, ResponseCode::NoError);
    assert_eq!(local_reply.answers.len(), 1);
}

#[test]
fn review_j68b_nested_suffix_preserves_internal_hostname_alias() {
    let mut snapshot = config();
    snapshot.dns_suffix = "laptop.internal".to_owned();
    for name in ["laptop.laptop.internal", "laptop.internal"] {
        let wire = dns::response(&query(name, 1), &snapshot).unwrap().unwrap();
        let reply = Message::from_vec(&wire).unwrap();
        eprintln!(
            "{name}: {:?}, {} answers",
            reply.metadata.response_code,
            reply.answers.len()
        );
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "the configured suffix must preserve every .internal alias"
        );
        assert_eq!(reply.answers.len(), 1);
    }
}

#[test]
fn review_j78_ascii_punycode_labels_keep_resolving() {
    for (name, suffix, qname) in [
        ("xn--bcher-kva", "internal", "xn--bcher-kva.internal"),
        (
            "laptop",
            "xn--bcher-kva.example",
            "laptop.xn--bcher-kva.example",
        ),
    ] {
        let mut snapshot = config();
        snapshot.name = Some(name.to_owned());
        snapshot.dns_suffix = suffix.to_owned();
        let wire = dns::response(&query(qname, 1), &snapshot)
            .unwrap()
            .expect("a valid ASCII mesh suffix remains authoritative");
        let reply = Message::from_vec(&wire).unwrap();
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "{qname}"
        );
        assert_eq!(reply.answers.len(), 1, "{qname}");
    }
}
