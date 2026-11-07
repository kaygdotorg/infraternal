//! Adversarial DNS privacy, parser recovery and TCP interoperability review for #266.
#![cfg(all(feature = "agent", feature = "mesh-dns", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use hickory_proto::{
    op::{Message, ResponseCode},
    rr::RecordType,
};
use infraternal_plugin_mesh::{
    dataplane::Config,
    dns::{self, DNS_PORT, Resolver},
};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, TcpStream, UdpSocket},
    sync::Mutex,
    time::Duration,
};

/// Serializes tests that bind the resolver's fixed high DNS port.
static DNS_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Builds a local-only resolver with a name that a remote caller must never discover.
fn snapshot() -> Config {
    serde_json::from_value(serde_json::json!({
        "node": 2, "server": 1, "name": "secret", "version": 1,
        "addresses": {"ipv4": "127.69.54.1", "ipv6": "fd00::2"},
        "default_policy": "Deny", "peers": {}, "peer_names": {}
    }))
    .unwrap()
}

/// Builds a standard question, normalizing the presentation-only final dot.
fn question(name: &str, kind: u16) -> Vec<u8> {
    let mut bytes = vec![0x35, 0x40, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        bytes.push(u8::try_from(label.len()).unwrap());
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes
}

/// Queries the running UDP worker and retains its complete wire response.
fn exchange(socket: &UdpSocket, bytes: &[u8]) -> Vec<u8> {
    socket
        .send_to(bytes, (snapshot().addresses.ipv4, DNS_PORT))
        .unwrap();
    let mut buf = [0; 8192];
    let len = socket.recv(&mut buf).unwrap();
    buf[..len].to_vec()
}

/// Sends one length-prefixed DNS message and reads its complete framed answer.
fn exchange_tcp(stream: &mut TcpStream, bytes: &[u8]) -> Vec<u8> {
    let request_len = u16::try_from(bytes.len()).unwrap();
    stream.write_all(&request_len.to_be_bytes()).unwrap();
    stream.write_all(bytes).unwrap();
    let mut response_len = [0; 2];
    stream.read_exact(&mut response_len).unwrap();
    let mut response = vec![0; usize::from(u16::from_be_bytes(response_len))];
    stream.read_exact(&mut response).unwrap();
    response
}

/// Compares all header and record fields, excluding only the question chosen by the caller.
#[test]
fn review_j354_remote_denied_and_missing_wire_matrix() {
    let _guard = DNS_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let resolver = Resolver::bind(&snapshot()).unwrap();
    for source in ["127.69.54.2:0", "127.0.0.1:0"] {
        let socket = UdpSocket::bind(source).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        for kind in [1, 28, 255, 12] {
            for (denied, missing) in [
                ("secret.internal", "absent.internal"),
                ("SeCrEt.InTeRnAl.", "AbSeNt.InTeRnAl."),
            ] {
                let a = exchange(&socket, &question(denied, kind));
                let b = exchange(&socket, &question(missing, kind));
                assert_eq!(a.len(), b.len());
                let mut a = Message::from_vec(&a).unwrap();
                let mut b = Message::from_vec(&b).unwrap();
                assert_eq!(a.metadata.response_code, ResponseCode::NXDomain);
                a.queries.clear();
                b.queries.clear();
                assert_eq!(a.to_vec().unwrap(), b.to_vec().unwrap());
                assert_eq!(a.authorities[0].ttl, 5);
            }
        }
    }
    // An ordinary self-source query is the positive control.
    let socket = UdpSocket::bind("127.69.54.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    assert_eq!(
        Message::from_vec(&exchange(&socket, &question("secret.internal", 1)))
            .unwrap()
            .answers
            .len(),
        1
    );
    drop(resolver);
    eprintln!("J354: 16 remote denied/missing pairs match; self-source positive control passes");
}

/// Exercises cyclic compression, declared-count extremes, oversized packets and random parser inputs.
#[test]
fn review_j354_parser_corpus_and_recovery() {
    let config = snapshot();
    let mut cycle = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1];
    assert!(dns::response(&cycle, &config).is_err());
    cycle[13] = 14;
    cycle[14] = 0xc0;
    cycle[15] = 12;
    assert!(dns::response(&cycle, &config).is_err());
    let mut counts = question("secret.internal", 1);
    counts[4..12].fill(255);
    assert!(dns::response(&counts, &config).is_err());
    let mut huge = question("secret.internal", 1);
    huge.resize(65535, 0);
    assert!(dns::response(&huge, &config).is_err());
    let mut state = 354u64;
    for i in 0..100_000 {
        let mut data = vec![0; i % 4097];
        for byte in &mut data {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state.to_le_bytes()[0];
        }
        let _ = dns::response(&data, &config);
    }
    assert_eq!(
        Message::from_vec(
            &dns::response(
                &question("secret.internal", u16::from(RecordType::A)),
                &config
            )
            .unwrap()
            .unwrap()
        )
        .unwrap()
        .answers
        .len(),
        1
    );
    eprintln!(
        "J354: 100000 random packets plus compression/count/oversize corpus completed; positive recovery passes"
    );
}

/// DNS clients using TCP must be able to contact the default-on resolver.
#[test]
fn review_j354_tcp_dns_is_available() {
    let _guard = DNS_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let resolver = Resolver::bind(&snapshot()).unwrap();
    let connection = TcpStream::connect_timeout(
        &(snapshot().addresses.ipv4, DNS_PORT).into(),
        Duration::from_secs(2),
    );
    drop(resolver);
    assert!(
        connection.is_ok(),
        "TCP DNS listener missing: {connection:?}"
    );
}

/// TCP framing preserves allowed answers and gives denied names the absent-name answer.
#[test]
fn review_j254_tcp_frames_reuse_the_udp_privacy_policy() {
    let _guard = DNS_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut allowed_config = snapshot();
    allowed_config.addresses.ipv4 = Ipv4Addr::LOCALHOST;
    let allowed_resolver = Resolver::bind(&allowed_config).unwrap();
    let mut allowed = TcpStream::connect((Ipv4Addr::LOCALHOST, DNS_PORT)).unwrap();
    allowed
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let allowed_reply = exchange_tcp(&mut allowed, &question("secret.internal", 1));
    assert_eq!(
        Message::from_vec(&allowed_reply).unwrap().answers.len(),
        1,
        "a local source may resolve a configured peer"
    );
    drop(allowed);
    drop(allowed_resolver);

    let denied_config = snapshot();
    let denied_resolver = Resolver::bind(&denied_config).unwrap();
    let mut denied = TcpStream::connect((denied_config.addresses.ipv4, DNS_PORT)).unwrap();
    denied
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let private = exchange_tcp(&mut denied, &question("secret.internal", 1));
    let absent = exchange_tcp(&mut denied, &question("absent.internal", 1));
    assert_eq!(private.len(), absent.len());
    let mut private_message = Message::from_vec(&private).unwrap();
    let mut absent_message = Message::from_vec(&absent).unwrap();
    assert_eq!(
        private_message.metadata.response_code,
        ResponseCode::NXDomain
    );
    private_message.queries.clear();
    absent_message.queries.clear();
    assert_eq!(
        private_message.to_vec().unwrap(),
        absent_message.to_vec().unwrap()
    );
    assert_eq!(private_message.authorities[0].ttl, 5);
    drop(denied);
    drop(denied_resolver);
    eprintln!("J254: TCP answers match the UDP source privacy policy and negative SOA");
}

/// TCP closes idle connections and rejects a frame above the shared DNS packet cap.
#[test]
fn review_j254_tcp_bounds_idle_and_oversized_connections() {
    let _guard = DNS_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut config = snapshot();
    config.addresses.ipv4 = Ipv4Addr::LOCALHOST;
    let resolver = Resolver::bind(&config).unwrap();

    let mut idle = TcpStream::connect((config.addresses.ipv4, DNS_PORT)).unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let mut byte = [0];
    assert_eq!(
        idle.read(&mut byte).unwrap(),
        0,
        "idle TCP connections close"
    );

    let mut oversized = TcpStream::connect((config.addresses.ipv4, DNS_PORT)).unwrap();
    oversized
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let oversized_len = u16::try_from(4097).unwrap();
    oversized.write_all(&oversized_len.to_be_bytes()).unwrap();
    assert_eq!(
        oversized.read(&mut byte).unwrap(),
        0,
        "the resolver rejects frames above its packet cap"
    );
    drop(resolver);
}

/// Refuses a connection above the fixed active-client bound without growing the worker's state.
#[test]
fn review_j254_tcp_rejects_connections_over_the_bound() {
    let _guard = DNS_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut config = snapshot();
    config.addresses.ipv4 = Ipv4Addr::LOCALHOST;
    let resolver = Resolver::bind(&config).unwrap();
    let mut clients = Vec::new();
    for _ in 0..64 {
        let client = TcpStream::connect((config.addresses.ipv4, DNS_PORT)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        clients.push(client);
    }
    for client in &mut clients {
        assert_eq!(
            Message::from_vec(&exchange_tcp(client, &question("secret.internal", 1)))
                .unwrap()
                .answers
                .len(),
            1,
            "each connection at the configured bound remains usable"
        );
    }
    let mut excess = TcpStream::connect((config.addresses.ipv4, DNS_PORT)).unwrap();
    excess
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut byte = [0];
    assert_eq!(
        excess.read(&mut byte).unwrap(),
        0,
        "the connection above the active-client bound is closed"
    );
    drop(clients);
    drop(resolver);
}

/// Reverse zones stay outside the mesh authority for present and absent addresses alike.
#[test]
fn review_j354_reverse_queries_are_unclaimed() {
    for name in [
        "1.54.69.127.in-addr.arpa",
        "2.54.69.127.in-addr.arpa",
        "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
    ] {
        for kind in [1, 28, 255, 12] {
            assert!(
                dns::response(&question(name, kind), &snapshot())
                    .unwrap()
                    .is_none()
            );
        }
    }
}

/// Concurrent clients exercise queue pressure without a functional wall-clock performance assertion.
#[test]
fn review_j354_udp_query_flood_preserves_service() {
    let _guard = DNS_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let resolver = Resolver::bind(&snapshot()).unwrap();
    let workers: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| {
                let client = UdpSocket::bind("127.69.54.1:0").unwrap();
                client
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                for _ in 0..1000 {
                    let wire = exchange(&client, &question("secret.internal", 1));
                    assert_eq!(Message::from_vec(&wire).unwrap().answers.len(), 1);
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    drop(resolver);
    eprintln!(
        "J354: 4000 UDP queries across four concurrent clients answered; resolver stopped cleanly"
    );
}
