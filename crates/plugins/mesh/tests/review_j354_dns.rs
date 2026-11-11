//! Adversarial DNS privacy, parser recovery and TCP interoperability review for #266.
#![cfg(all(feature = "agent", feature = "mesh-dns", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use hickory_proto::{
    op::{Message, ResponseCode},
    rr::RecordType,
};
use infraternal_plugin_mesh::{dataplane::Config, dns};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    time::Duration,
};

/// Shared socket ownership fixture for parallel DNS tests.
#[path = "support/dns.rs"]
mod dns_support;

use dns_support::TestResolver;

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
fn exchange(socket: &UdpSocket, destination: SocketAddr, bytes: &[u8]) -> Vec<u8> {
    socket.send_to(bytes, destination).unwrap();
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

/// Connects from an explicit loopback source address to exercise per-source accounting.
fn tcp_stream_from(source: Ipv4Addr, destination: SocketAddr) -> TcpStream {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .unwrap();
    socket
        .bind(&socket2::SockAddr::from(SocketAddr::from((source, 0))))
        .unwrap();
    socket
        .connect(&socket2::SockAddr::from(destination))
        .unwrap();
    socket.into()
}

/// Compares all header and record fields, excluding only the question chosen by the caller.
#[test]
fn review_j354_remote_denied_and_missing_wire_matrix() {
    let resolver = TestResolver::bind(&snapshot()).unwrap();
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
                let a = exchange(&socket, resolver.udp_address, &question(denied, kind));
                let b = exchange(&socket, resolver.udp_address, &question(missing, kind));
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
        Message::from_vec(&exchange(
            &socket,
            resolver.udp_address,
            &question("secret.internal", 1)
        ))
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
    let resolver = TestResolver::bind(&snapshot()).unwrap();
    let connection = TcpStream::connect_timeout(&resolver.tcp_address, Duration::from_secs(2));
    drop(resolver);
    assert!(
        connection.is_ok(),
        "TCP DNS listener missing: {connection:?}"
    );
}

/// TCP framing preserves allowed answers and gives denied names the absent-name answer.
#[test]
fn review_j254_tcp_frames_reuse_the_udp_privacy_policy() {
    let mut allowed_config = snapshot();
    allowed_config.addresses.ipv4 = Ipv4Addr::LOCALHOST;
    let allowed_resolver = TestResolver::bind(&allowed_config).unwrap();
    let mut allowed = TcpStream::connect(allowed_resolver.tcp_address).unwrap();
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
    let denied_resolver = TestResolver::bind(&denied_config).unwrap();
    let mut denied = TcpStream::connect(denied_resolver.tcp_address).unwrap();
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
    let mut config = snapshot();
    config.addresses.ipv4 = Ipv4Addr::LOCALHOST;
    let resolver = TestResolver::bind(&config).unwrap();

    let mut idle = TcpStream::connect(resolver.tcp_address).unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let mut byte = [0];
    assert_eq!(
        idle.read(&mut byte).unwrap(),
        0,
        "idle TCP connections close"
    );

    let mut oversized = TcpStream::connect(resolver.tcp_address).unwrap();
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

/// Refuses a connection above the global active-client bound across distinct source addresses.
#[test]
fn review_j254_tcp_rejects_connections_over_the_bound() {
    let mut config = snapshot();
    config.addresses.ipv4 = Ipv4Addr::LOCALHOST;
    let resolver = TestResolver::bind(&config).unwrap();
    let mut clients = Vec::new();
    for source_last_octet in 1..=8 {
        let source = Ipv4Addr::new(127, 0, 0, source_last_octet);
        for _ in 0..8 {
            let mut client = tcp_stream_from(source, resolver.tcp_address);
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let response =
                Message::from_vec(&exchange_tcp(&mut client, &question("secret.internal", 1)))
                    .unwrap();
            if source == Ipv4Addr::LOCALHOST {
                assert_eq!(response.answers.len(), 1);
            } else {
                assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
            }
            clients.push(client);
        }
    }
    let mut excess = tcp_stream_from(Ipv4Addr::new(127, 0, 0, 9), resolver.tcp_address);
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

/// One source cannot consume the global listener's entire TCP connection budget.
#[test]
fn review_j360_tcp_limits_connections_per_source() {
    let mut config = snapshot();
    config.addresses.ipv4 = Ipv4Addr::LOCALHOST;
    let resolver = TestResolver::bind(&config).unwrap();
    let mut clients = Vec::new();
    for _ in 0..8 {
        let mut client = tcp_stream_from(Ipv4Addr::LOCALHOST, resolver.tcp_address);
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(
            Message::from_vec(&exchange_tcp(&mut client, &question("secret.internal", 1)))
                .unwrap()
                .answers
                .len(),
            1
        );
        clients.push(client);
    }

    let mut excess = tcp_stream_from(Ipv4Addr::LOCALHOST, resolver.tcp_address);
    excess
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut byte = [0];
    let result = excess.read(&mut byte);
    drop(clients);
    drop(resolver);
    assert_eq!(result.unwrap(), 0, "the ninth same-source client is closed");
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
    let resolver = TestResolver::bind(&snapshot()).unwrap();
    let destination = resolver.udp_address;
    let workers: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(move || {
                let client = UdpSocket::bind("127.69.54.1:0").unwrap();
                client
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                for _ in 0..1000 {
                    let wire = exchange(&client, destination, &question("secret.internal", 1));
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

/// A partial frame must expire even when a client drips bytes below the idle timeout (#266).
#[test]
fn review_j360_partial_frame_has_an_absolute_read_deadline() {
    let mut config = snapshot();
    config.addresses.ipv4 = Ipv4Addr::LOCALHOST;
    let resolver = TestResolver::bind(&config).unwrap();
    let mut client = TcpStream::connect(resolver.tcp_address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client.write_all(&4096u16.to_be_bytes()).unwrap();
    for _ in 0..6 {
        // sleep: drip every 500 ms to stay inside the five-second idle timeout while crossing the two-second frame deadline.
        std::thread::sleep(Duration::from_millis(500));
        let _ = client.write_all(&[0]);
    }
    let mut byte = [0];
    let result = client.read(&mut byte);
    eprintln!("J360 after three seconds of incomplete frame: read={result:?}");
    drop(resolver);
    assert!(
        matches!(result, Ok(0))
            || result
                .as_ref()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset),
        "partial frame survives the whole-message deadline: {result:?}"
    );
}

/// A TCP peer is disconnected after repeatedly sending malformed DNS frames.
#[test]
fn review_j360_tcp_drops_repeated_malformed_frames() {
    let resolver = TestResolver::bind(&snapshot()).unwrap();
    let mut stream = TcpStream::connect(resolver.tcp_address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut frames = Vec::new();
    for _ in 0..32 {
        frames.extend_from_slice(&12u16.to_be_bytes());
        frames.extend_from_slice(&[0; 12]);
    }
    stream.write_all(&frames).unwrap();
    let mut byte = [0];
    let result = stream.read(&mut byte);
    drop(resolver);
    assert!(
        matches!(result, Ok(0))
            || result
                .as_ref()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset),
        "the malformed-frame budget closes TCP: {result:?}"
    );
}

/// A continuously readable invalid TCP stream must not delay UDP answers (#266).
#[test]
fn review_j360_invalid_tcp_stream_yields_to_udp() {
    let resolver = TestResolver::bind(&snapshot()).unwrap();
    let mut stream = TcpStream::connect(resolver.tcp_address).unwrap();
    stream
        .set_write_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer_stop = std::sync::Arc::clone(&stop);
    let writer = std::thread::spawn(move || {
        let mut batch = Vec::new();
        for _ in 0..4096 {
            batch.extend_from_slice(&12u16.to_be_bytes());
            batch.extend_from_slice(&[0; 12]);
        }
        while !writer_stop.load(std::sync::atomic::Ordering::Relaxed) {
            if stream.write_all(&batch).is_err() {
                break;
            }
        }
    });
    // sleep: let the shared worker enter TCP draining before checking UDP liveness.
    std::thread::sleep(Duration::from_millis(200));
    let socket = UdpSocket::bind("127.69.54.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    socket
        .send_to(&question("secret.internal", 1), resolver.udp_address)
        .unwrap();
    let mut bytes = [0; 4096];
    let during_flood = socket.recv(&mut bytes);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    writer.join().unwrap();
    let after_flood = if during_flood.is_err() {
        socket.recv(&mut bytes)
    } else {
        Ok(0)
    };
    eprintln!(
        "J360 UDP liveness during invalid TCP flood={during_flood:?}; after stopping writer={after_flood:?}"
    );
    drop(resolver);
    assert!(
        during_flood.is_ok(),
        "a continuously readable malformed TCP client starves UDP: {during_flood:?}"
    );
}
