//! Mesh-only DNS records, snapshot replacement and real UDP delivery [#266].
#![cfg(all(feature = "agent", feature = "mesh-dns-spike", target_os = "linux"))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    dataplane::{Config, DefaultPolicy, Peer, PeerPolicy},
    dns::{self, DNS_PORT, Resolver},
    policy::{
        model::{Addresses, NodeId, PublicKey},
        rules::TrafficPolicy,
    },
};
use simple_dns::{CLASS, Packet, PacketFlag, RCODE, rdata::RData};
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
    wire.extend_from_slice(&u16::from(CLASS::IN).to_be_bytes());
    wire
}

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
    let a = Packet::parse(&a_wire).unwrap();
    assert!(a.has_flags(PacketFlag::RESPONSE | PacketFlag::AUTHORITATIVE_ANSWER));
    assert_eq!(a.answers.len(), 1);
    assert_eq!(a.answers[0].ttl, 30);
    match &a.answers[0].rdata {
        RData::A(address) => {
            assert_eq!(
                Ipv4Addr::from(address.address),
                Ipv4Addr::new(10, 254, 0, 1)
            );
        }
        other => panic!("unexpected A response: {other:?}"),
    }

    let local_a_wire = response_wire("laptop.internal", 1);
    let local_a = Packet::parse(&local_a_wire).unwrap();
    match &local_a.answers[0].rdata {
        RData::A(address) => {
            assert_eq!(
                Ipv4Addr::from(address.address),
                Ipv4Addr::new(10, 254, 0, 2)
            );
        }
        other => panic!("unexpected local A response: {other:?}"),
    }

    let aaaa_wire = response_wire("laptop.internal", 28);
    let aaaa = Packet::parse(&aaaa_wire).unwrap();
    assert_eq!(aaaa.answers.len(), 1);
    assert_eq!(aaaa.answers[0].ttl, 30);
    match &aaaa.answers[0].rdata {
        RData::AAAA(address) => {
            assert_eq!(
                Ipv6Addr::from(address.address),
                "fd66:6821:bc63:834e::2".parse::<Ipv6Addr>().unwrap()
            );
        }
        other => panic!("unexpected AAAA response: {other:?}"),
    }

    let peer_aaaa_wire = response_wire("build-01.internal", 28);
    let peer_aaaa = Packet::parse(&peer_aaaa_wire).unwrap();
    match &peer_aaaa.answers[0].rdata {
        RData::AAAA(address) => {
            assert_eq!(
                Ipv6Addr::from(address.address),
                "fd66:6821:bc63:834e::1".parse::<Ipv6Addr>().unwrap()
            );
        }
        other => panic!("unexpected peer AAAA response: {other:?}"),
    }
}

#[test]
fn unknown_internal_names_get_nxdomain_and_five_second_negative_ttl() {
    let response_wire = response_wire("missing.internal", 1);
    let response = Packet::parse(&response_wire).unwrap();
    assert_eq!(response.rcode(), RCODE::NameError);
    assert_eq!(response.answers.len(), 0);
    assert_eq!(response.name_servers.len(), 1);
    assert_eq!(response.name_servers[0].ttl, 5);
    match &response.name_servers[0].rdata {
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
    let answer = Packet::parse(&answer_wire).unwrap();
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(answer.answers[0].name.to_string(), "build-01.mesh.kayg.org");

    let missing_wire = dns::response(&query("missing.mesh.kayg.org", 1), &snapshot)
        .unwrap()
        .expect("unknown names below the configured zone are authoritative");
    let missing = Packet::parse(&missing_wire).unwrap();
    assert_eq!(missing.rcode(), RCODE::NameError);
    assert_eq!(missing.name_servers[0].name.to_string(), "mesh.kayg.org");
    let internal_alias = dns::response(&query("build-01.internal", 1), &snapshot)
        .unwrap()
        .expect(".internal remains an authoritative alias");
    let internal_alias = Packet::parse(&internal_alias).unwrap();
    assert_eq!(internal_alias.answers.len(), 1);
    assert_eq!(
        internal_alias.answers[0].name.to_string(),
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
        let response = Packet::parse(&wire).unwrap();
        assert_eq!(response.answers.len(), 1, "{name}");
        assert_eq!(response.answers[0].name.to_string(), name);
    }
}

#[test]
fn unsupported_record_types_return_a_five_second_negative_ttl() {
    let srv_wire = response_wire("build-01.internal", 33);
    let srv = Packet::parse(&srv_wire).unwrap();
    assert_eq!(srv.answers.len(), 0);
    assert_eq!(srv.rcode(), RCODE::NoError);
    assert_eq!(srv.name_servers.len(), 1);
    assert_eq!(srv.name_servers[0].ttl, 5);
    match &srv.name_servers[0].rdata {
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
    let old_record = Packet::parse(&old_wire).unwrap();
    assert_eq!(old_record.answers.len(), 1);
    let retired_wire = dns::response(&query("build-01.internal", 1), &renamed)
        .unwrap()
        .unwrap();
    let retired = Packet::parse(&retired_wire).unwrap();
    assert_eq!(retired.rcode(), RCODE::NameError);
    let current_wire = dns::response(&query("build-renamed.internal", 1), &renamed)
        .unwrap()
        .unwrap();
    let current = Packet::parse(&current_wire).unwrap();
    assert_eq!(current.answers.len(), 1);

    let mut revoked = old;
    revoked.peer_names.remove(&NodeId(1));
    let retired_wire = dns::response(&query("build-01.internal", 1), &revoked)
        .unwrap()
        .unwrap();
    assert_eq!(
        Packet::parse(&retired_wire).unwrap().rcode(),
        RCODE::NameError
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
    let parsed = Packet::parse(&response).unwrap();
    assert_eq!(parsed.answers.len(), 1);
    assert_eq!(parsed.answers[0].ttl, 30);
    assert!(parsed.opt().is_some(), "EDNS replies retain an OPT record");
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
        Packet::parse(&response[..len]).unwrap().answers.len(),
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
        Packet::parse(&response[..len]).unwrap().rcode(),
        RCODE::NameError
    );
    let (len, _) = exchange(&client, &renamed, "build-renamed.internal", &mut response).await;
    assert_eq!(Packet::parse(&response[..len]).unwrap().answers.len(), 1);

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
