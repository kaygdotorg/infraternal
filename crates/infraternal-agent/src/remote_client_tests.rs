//! Real-QUIC regressions for retained greeting bytes and rootless uid admission [64], #78.
use super::*;
use crate::remote_tls::tests::{leaf, root};
use infraternal_protocol::Frame;

/// Reserve both fixture transports before publishing their common address.
/// The protocols allocate ports independently, so either reservation can collide.
async fn reserve_transport_pair() -> (tokio::net::TcpListener, tokio::net::UdpSocket) {
    for _ in 0..16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        match tokio::net::UdpSocket::bind(listener.local_addr().unwrap()).await {
            Ok(socket) => return (listener, socket),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => panic!("cannot reserve the fixture UDP socket: {error}"),
        }
    }
    panic!("fixture transport reservations collided repeatedly");
}

struct StateDirectory(PathBuf);
impl StateDirectory {
    fn new() -> Self {
        let parent = crate::test_state_root();
        let path = parent.join(format!("c{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        Self(path)
    }
}
impl Drop for StateDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[tokio::test]
async fn rootless_uid_mismatch_is_refused_before_dial() {
    let ca = root();
    let identity = RemoteIdentity {
        host_id: uuid::Uuid::new_v4(),
        identity: leaf(&ca, false),
        roots: vec![ca.certificate],
        endpoint: Some("127.0.0.1:1".parse().unwrap()),
        server_name: "localhost".into(),
        public_origin: None,
        https_root: None,
        https_system_roots: false,
        execution_uid: nix::unistd::Uid::effective().as_raw().wrapping_add(1),
    };
    let result = run(&identity, None).await.unwrap_err();
    assert_eq!(result.kind(), io::ErrorKind::PermissionDenied);
}

#[tokio::test]
async fn prefixed_control_keeps_coalesced_suffix_and_suppresses_only_its_greeting() {
    let ca = root();
    let server_identity = leaf(&ca, true);
    let client_identity = leaf(&ca, false);
    let server = quinn::Endpoint::server(
        remote_quic::server_config(&server_identity, std::slice::from_ref(&ca.certificate))
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(
        remote_quic::client_config(&client_identity, &[ca.certificate]).unwrap(),
    );
    let (dialed, admitted) = tokio::join!(
        client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap(),
        async { server.accept().await.unwrap().await.unwrap() }
    );
    let dialed = dialed.unwrap();
    let (mut send, recv) = dialed.open_bi().await.unwrap();
    let greeting = Frame::Hello {
        version: 1,
        caps: remote_quic::REMOTE_WRITER_BINDING,
        client_info: "fixture",
    };
    let mut greeting_bytes = Vec::new();
    encode_frame_into(&greeting, &mut greeting_bytes).unwrap();
    send.write_all(&greeting_bytes).await.unwrap();
    let (peer_send, peer_recv) = admitted.accept_bi().await.unwrap();
    let peer = NativeChannel::control(peer_send, peer_recv).unwrap();
    let mut peer_rx = Receive::default();
    assert!(matches!(
        peer_rx.next(&peer).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    let mut combined = greeting_bytes.clone();
    let ping = Frame::Ping {
        nonce: 42,
        sent_us: 17,
    };
    let mut ping_bytes = Vec::new();
    encode_frame_into(&ping, &mut ping_bytes).unwrap();
    combined.extend_from_slice(&ping_bytes);
    peer.write(&combined).await.unwrap();
    let channel = NativeChannel::control(send, recv).unwrap();
    let mut receive = Receive::default();
    let hello = receive.next(&channel).await.unwrap();
    let mut prefix = Vec::new();
    encode_frame_into(&hello.frame, &mut prefix).unwrap();
    let control = PrefixedControl {
        channel,
        prefix: Mutex::new(prefix),
        sent_greeting: Mutex::new(Some(greeting_bytes.clone())),
        receive: Mutex::new(receive),
    };
    control.write(&greeting_bytes).await.unwrap();
    control.write(&ping_bytes).await.unwrap();
    let mut consumer = Receive::default();
    assert!(matches!(
        consumer.next(&control).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    assert!(matches!(
        consumer.next(&control).await.unwrap().frame,
        Frame::Ping { nonce: 42, .. }
    ));
    assert!(matches!(
        peer_rx.next(&peer).await.unwrap().frame,
        Frame::Ping { nonce: 42, .. }
    ));
    dialed.close(0u32.into(), b"");
    server.close(0u32.into(), b"");
    client.close(0u32.into(), b"");
}
/// Detects a hang only. These fixtures start a whole supervisor, whose startup
/// before the first dial has no bound on a loaded host, so no assertion below
/// may depend on how much of this bound a passing run uses (#334).
const HANG: Duration = Duration::from_secs(30);

/// Destination connection ID of a QUIC long-header datagram. A client keeps
/// it for every Initial retransmission of one attempt until the server replies.
fn initial_connection_id(datagram: &[u8]) -> Option<&[u8]> {
    let (&first, rest) = datagram.split_first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let length = usize::from(*rest.get(4)?);
    rest.get(5..5 + length)
}

/// A silent UDP path must not put QUIC's handshake timeout in front of TCP.
/// The proof is ordering, not a stopwatch: TCP connects while the same QUIC
/// attempt is still retransmitting, so TCP was dialled during that attempt
/// rather than after it gave up.
#[tokio::test]
async fn unavailable_udp_does_not_add_seconds_before_tcp_admission() {
    let ca = root();
    let server_identity = leaf(&ca, true);
    let client_identity = leaf(&ca, false);
    // The bound UDP socket never answers: QUIC stays pending until its own
    // timeout, exactly as on a black-holed path.
    let (listener, silent) = reserve_transport_pair().await;
    let address = listener.local_addr().unwrap();
    let tls =
        remote_tls::server_config(&server_identity, std::slice::from_ref(&ca.certificate)).unwrap();
    let identity = RemoteIdentity {
        host_id: uuid::Uuid::new_v4(),
        identity: client_identity,
        roots: vec![ca.certificate],
        endpoint: Some(address),
        server_name: "localhost".into(),
        public_origin: None,
        https_root: None,
        https_system_roots: false,
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let state = StateDirectory::new();
    let state_path = state.0.clone();
    let spawned = tokio::time::Instant::now();
    let supervisor = tokio::spawn(async move { run(&identity, Some(state_path)).await });
    let admitted = tokio::time::timeout(HANG, async {
        let mut datagram = vec![0; 65535];
        let mut attempt = None;
        let mut first_initial = None;
        // Biased: consume queued datagrams before the listener, so an Initial
        // sent before TCP connected is never counted as evidence after it.
        let (socket, _) = loop {
            tokio::select! {
                biased;
                received = silent.recv_from(&mut datagram) => {
                    let (count, _) = received.unwrap();
                    if attempt.is_none() {
                        attempt = initial_connection_id(&datagram[..count]).map(<[u8]>::to_vec);
                        first_initial = Some(tokio::time::Instant::now());
                    }
                }
                accepted = listener.accept() => break accepted.unwrap(),
            }
        };
        // Diagnostics only; neither number is asserted.
        if let Some(started) = first_initial {
            println!(
                "spawn_to_first_initial_us={} quic_to_tcp_connect_us={}",
                (started - spawned).as_micros(),
                started.elapsed().as_micros()
            );
        }
        // TCP before any Initial cannot have waited for QUIC. Otherwise the
        // attempt must still be alive: TLS stays unanswered until then, so the
        // client cannot have dropped QUIC for a won TCP race either.
        if let Some(attempt) = attempt {
            loop {
                let (count, _) = silent.recv_from(&mut datagram).await.unwrap();
                if initial_connection_id(&datagram[..count]) == Some(&attempt[..]) {
                    break;
                }
            }
        }
        remote_tls::accept(socket, &tls).await.unwrap()
    })
    .await;
    supervisor.abort();
    let _ = supervisor.await;
    assert!(
        admitted.is_ok(),
        "TCP was dialled only after the silent QUIC attempt gave up"
    );
}

#[tokio::test]
async fn winning_quic_drops_the_unfinished_tls_dial_before_control_dispatch() {
    use tokio::io::AsyncReadExt;
    let ca = root();
    let server_identity = leaf(&ca, true);
    let client_identity = leaf(&ca, false);
    let server = quinn::Endpoint::server(
        remote_quic::server_config(&server_identity, std::slice::from_ref(&ca.certificate))
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let (tcp, socket) = reserve_transport_pair().await;
    let socket = std::sync::Arc::new(socket);
    let proxy_address = socket.local_addr().unwrap();
    let identity = RemoteIdentity {
        host_id: uuid::Uuid::new_v4(),
        identity: client_identity,
        roots: vec![ca.certificate],
        endpoint: Some(proxy_address),
        server_name: "localhost".into(),
        public_origin: None,
        https_root: None,
        https_system_roots: false,
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let state = StateDirectory::new();
    let state_path = state.0.clone();
    let supervisor = tokio::spawn(async move { run(&identity, Some(state_path)).await });
    // QUIC Initials queue unanswered in the reserved socket until TCP has
    // dialled and sent its ClientHello. Only then does the proxy forward them,
    // so QUIC wins over an unfinished TLS dial by construction rather than by
    // racing the client's grace timer against a loaded scheduler.
    let (mut fallback, _) = tokio::time::timeout(HANG, tcp.accept())
        .await
        .unwrap()
        .unwrap();
    let mut hello = [0; 4096];
    assert!(fallback.read(&mut hello).await.unwrap() > 0);
    let (_, proxy) =
        crate::transport_diagnostics::udp_proxy_on(socket, server.local_addr().unwrap());
    let connection = tokio::time::timeout(HANG, async {
        server.accept().await.unwrap().await.unwrap()
    })
    .await
    .unwrap();
    // Accepting control proves QUIC won. Withhold the server Hello so dispatch
    // stays live while the losing TCP socket must already have been dropped.
    let control = tokio::time::timeout(HANG, connection.accept_bi())
        .await
        .unwrap()
        .unwrap();
    // The client closes the losing socket before it opens control, and control
    // then crosses the proxy's delay, so EOF is already queued here. The window
    // stays well below the 5 s Hello timeout that would end dispatch (and drop
    // a retained socket) anyway, or a leak could pass unnoticed.
    let eof = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if fallback.read(&mut hello).await.unwrap() == 0 {
                return;
            }
        }
    })
    .await;
    supervisor.abort();
    let _ = supervisor.await;
    proxy.abort();
    let _ = proxy.await;
    drop(control);
    connection.close(0u32.into(), b"");
    server.close(0u32.into(), b"");
    assert!(
        eof.is_ok(),
        "losing TLS dial survived the winning QUIC dispatch"
    );
}

async fn native_greeting(server: &quinn::Endpoint) -> &'static str {
    let connection = server.accept().await.unwrap().await.unwrap();
    let (send, receive) = connection.accept_bi().await.unwrap();
    let channel = NativeChannel::control(send, receive).unwrap();
    let mut receive = Receive::default();
    assert!(matches!(
        receive.next(&channel).await.unwrap().frame,
        infraternal_protocol::Frame::Hello { .. }
    ));
    connection.close(0u32.into(), b"");
    "quic"
}
async fn tcp_greeting(
    listener: &tokio::net::TcpListener,
    tls: &openssl::ssl::SslAcceptor,
) -> &'static str {
    loop {
        let (socket, _) = listener.accept().await.unwrap();
        let Ok(connection) = remote_tls::accept(socket, tls).await else {
            continue;
        };
        let mut receive = Receive::default();
        if let Ok(frame) = receive.next(&connection.channel).await {
            assert!(matches!(
                frame.frame,
                infraternal_protocol::Frame::Hello { .. }
            ));
            return "tcp";
        }
    }
}
fn supervisor_identity(
    ca: &Identity,
    client: &Identity,
    endpoint: std::net::SocketAddr,
) -> RemoteIdentity {
    RemoteIdentity {
        host_id: uuid::Uuid::new_v4(),
        identity: Identity {
            certificate: client.certificate.clone(),
            key: client.key.clone(),
        },
        roots: vec![ca.certificate.clone()],
        endpoint: Some(endpoint),
        server_name: "localhost".into(),
        public_origin: None,
        https_root: None,
        https_system_roots: false,
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    }
}
#[tokio::test]
#[ignore = "supervisor establishment diagnostic; run alone without builds or browsers"]
async fn supervisor_300ms_quic_and_blocked_udp_fallback() {
    use crate::transport_diagnostics::{tcp_proxy_at, udp_proxy};
    let ca = root();
    let server_identity = leaf(&ca, true);
    let client_identity = leaf(&ca, false);
    let quic = quinn::Endpoint::server(
        remote_quic::server_config(&server_identity, std::slice::from_ref(&ca.certificate))
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let tcp = tokio::net::TcpListener::bind(quic.local_addr().unwrap())
        .await
        .unwrap();
    let tls =
        remote_tls::server_config(&server_identity, std::slice::from_ref(&ca.certificate)).unwrap();
    let (proxy_address, mut udp) = udp_proxy(quic.local_addr().unwrap()).await;
    let (_, proxy_tcp) = tcp_proxy_at(tcp.local_addr().unwrap(), proxy_address).await;
    let state = StateDirectory::new();
    for blocked_udp in [false, true] {
        if blocked_udp {
            udp.abort();
            let _ = (&mut udp).await;
        }
        let mut timings = Vec::new();
        for _ in 0..25 {
            let identity = supervisor_identity(&ca, &client_identity, proxy_address);
            let state_path = state.0.clone();
            let started = tokio::time::Instant::now();
            let supervisor = tokio::spawn(async move { run(&identity, Some(state_path)).await });
            // Ignore abandoned TLS races: admission means an application Hello,
            // rather than only successful TLS establishment.
            let observed = tokio::time::timeout(Duration::from_secs(3), async {
                tokio::select! {
                    result = native_greeting(&quic) => result,
                    result = tcp_greeting(&tcp,&tls) => result,
                }
            })
            .await;
            timings.push(started.elapsed().as_micros());
            supervisor.abort();
            let _ = supervisor.await;
            assert_eq!(observed.unwrap(), if blocked_udp { "tcp" } else { "quic" });
        }
        timings.sort_unstable();
        println!(
            "supervisor_diagnostic rtt_ms=300 udp_blocked={blocked_udp} n=25 first_hello_p50_us={} p99_us={} machine={} load={} excludes=session_open,live_renewal",
            timings[12],
            timings[24],
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap()
                .trim(),
            std::fs::read_to_string("/proc/loadavg").unwrap().trim()
        );
    }
    proxy_tcp.abort();
    let _ = proxy_tcp.await;
    quic.close(0u32.into(), b"");
}

#[tokio::test]
async fn delayed_proxy_keeps_replies_bound_to_the_original_udp_client() {
    use tokio::net::UdpSocket;
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (address, proxy) =
        crate::transport_diagnostics::udp_proxy(upstream.local_addr().unwrap()).await;
    let echo = tokio::spawn(async move {
        let mut received = Vec::new();
        for _ in 0..2 {
            let mut bytes = [0; 16];
            let (count, peer) = upstream.recv_from(&mut bytes).await.unwrap();
            received.push((bytes[..count].to_vec(), peer));
        }
        for (bytes, peer) in received {
            upstream.send_to(&bytes, peer).await.unwrap();
        }
    });
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.send_to(b"first", address).await.unwrap();
    b.send_to(b"second", address).await.unwrap();
    let receive = async |socket: &UdpSocket| {
        let mut bytes = [0; 16];
        let (count, peer) = socket.recv_from(&mut bytes).await.unwrap();
        assert_eq!(peer, address);
        bytes[..count].to_vec()
    };
    let replies = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(receive(&a), receive(&b))
    })
    .await;
    proxy.abort();
    let _ = proxy.await;
    echo.abort();
    let _ = echo.await;
    let replies = replies.expect("the UDP relay reassigned an earlier client's response");
    assert_eq!(replies.0, b"first");
    assert_eq!(replies.1, b"second");
}

/// Reports relay consumption so virtual flight times start at known packet arrivals.
struct ObservedProxyInput {
    reader: tokio::io::DuplexStream,
    arrivals: tokio::sync::mpsc::UnboundedSender<()>,
}
impl tokio::io::AsyncRead for ObservedProxyInput {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result =
            tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut this.reader), cx, buffer);
        if matches!(&result, std::task::Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            this.arrivals.send(()).unwrap();
        }
        result
    }
}

#[tokio::test(start_paused = true)]
async fn tcp_proxy_preserves_spacing_between_packets_already_in_flight() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Exercise the TCP proxy's actual queued flight scheduler without making
    // host CPU scheduling part of the assertion. The real-socket flood test
    // below separately proves byte integrity and half-close forwarding.
    let (mut source, reader) = tokio::io::duplex(1024);
    let (writer, mut target) = tokio::io::duplex(1024);
    let (arrivals, mut received) = tokio::sync::mpsc::unbounded_channel();
    let proxy = tokio::spawn(crate::transport_diagnostics::delayed_copy(
        ObservedProxyInput { reader, arrivals },
        writer,
    ));
    source.write_all(b"a").await.unwrap();
    received.recv().await.unwrap();
    tokio::time::advance(Duration::from_millis(20)).await;
    source.write_all(b"b").await.unwrap();
    received.recv().await.unwrap();
    source.shutdown().await.unwrap();
    let mut byte = [0; 1];
    let spacing = tokio::time::timeout(Duration::from_secs(2), async {
        target.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"a");
        let first = tokio::time::Instant::now();
        target.read_exact(&mut byte).await.unwrap();
        assert_eq!(&byte, b"b");
        first.elapsed()
    })
    .await
    .unwrap();
    proxy.await.unwrap().unwrap();
    assert_eq!(spacing, Duration::from_millis(20));
}

#[tokio::test]
async fn tcp_proxy_flushes_bounded_flood_before_half_close() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (address, proxy) = crate::transport_diagnostics::tcp_proxy_at(
        upstream.local_addr().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;
    let mut source = TcpStream::connect(address).await.unwrap();
    source.set_nodelay(true).unwrap();
    let (mut target, _) = upstream.accept().await.unwrap();
    let expected: Vec<u8> = (0..1_500_000)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect();
    let payload = expected.clone();
    let sender = tokio::spawn(async move {
        source.write_all(&payload).await.unwrap();
        source.shutdown().await.unwrap();
    });
    let received = tokio::time::timeout(Duration::from_secs(5), async {
        let mut received = Vec::new();
        target.read_to_end(&mut received).await.unwrap();
        received
    })
    .await;
    proxy.abort();
    let _ = proxy.await;
    sender.abort();
    let _ = sender.await;
    let received = received.unwrap();
    assert_eq!(received.len(), expected.len());
    assert!(
        received == expected,
        "relay flood lost, duplicated or reordered bytes"
    );
    println!(
        "tcp_proxy_flood_bytes={} lost=0 duplicated=0 reordered=0",
        received.len()
    );
}

#[tokio::test]
async fn tcp_winner_cancels_silent_udp_drivers_without_waiting_for_drain() {
    let ca = root();
    let identity = leaf(&ca, false);
    // A real bound UDP socket absorbs Initial packets without answering them.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let runtime = dial_runtime::DialRuntime::new();
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        runtime.runtime(),
    )
    .unwrap();
    endpoint.set_default_client_config(
        remote_quic::client_config(&identity, &[ca.certificate]).unwrap(),
    );
    let connecting = endpoint
        .connect(silent.local_addr().unwrap(), "localhost")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    drop(runtime);
    let result = tokio::time::timeout(Duration::from_millis(100), connecting)
        .await
        .expect("losing UDP driver survived cancellation until its drain timer");
    assert!(
        result.is_err(),
        "cancelled UDP connection unexpectedly authenticated"
    );
}

#[tokio::test]
async fn unavailable_local_credentials_retry_without_creating_state() {
    let ca = root();
    let key = openssl::pkey::PKey::generate_ed25519().unwrap();
    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    certificate
        .set_subject_name(ca.certificate.subject_name())
        .unwrap();
    certificate
        .set_issuer_name(ca.certificate.subject_name())
        .unwrap();
    certificate.set_pubkey(&key).unwrap();
    certificate
        .set_not_before(&openssl::asn1::Asn1Time::from_unix(1).unwrap())
        .unwrap();
    certificate
        .set_not_after(&openssl::asn1::Asn1Time::from_unix(2).unwrap())
        .unwrap();
    certificate
        .sign(&ca.key, openssl::hash::MessageDigest::null())
        .unwrap();
    let identity = RemoteIdentity {
        host_id: uuid::Uuid::new_v4(),
        identity: Identity {
            certificate: certificate.build(),
            key,
        },
        roots: vec![ca.certificate],
        endpoint: Some("127.0.0.1:1".parse().unwrap()),
        server_name: "localhost".into(),
        public_origin: None,
        https_root: None,
        https_system_roots: false,
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    let directory = StateDirectory::new();
    let result = tokio::time::timeout(
        Duration::from_millis(200),
        run(&identity, Some(directory.0.clone())),
    )
    .await;
    assert!(
        result.is_err(),
        "unavailable credentials stopped the server link"
    );
    assert_eq!(
        std::fs::read_dir(&directory.0).unwrap().count(),
        0,
        "expired identity must be refused before opening local control or session state"
    );
}

#[path = "remote_mesh_idle_tests.rs"]
mod idle_timers;

#[tokio::test]
async fn raw_tcp_control_preserves_mux_envelopes_and_buffered_suffix() {
    let ca = root();
    let server = leaf(&ca, true);
    let client = leaf(&ca, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor =
        remote_tls::server_config(&server, std::slice::from_ref(&ca.certificate)).unwrap();
    let peer = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        remote_tls::accept(socket, &acceptor).await.unwrap()
    });
    let connector =
        remote_tls::client_config(&client, std::slice::from_ref(&ca.certificate)).unwrap();
    let connection = remote_tls::dial(address, "localhost", &connector)
        .await
        .unwrap();
    let peer = peer.await.unwrap();
    let mut combined = Vec::new();
    for (stream, nonce) in [(0, 11), (7, 12)] {
        let mut frame = Vec::new();
        infraternal_protocol::encode_muxed_frame_into(
            stream,
            &Frame::Ping { nonce, sent_us: 0 },
            &mut frame,
        )
        .unwrap();
        combined.extend_from_slice(&frame);
    }
    peer.channel.write(&combined).await.unwrap();
    let control = ControlChannel::Tcp(&connection.channel);
    let mut receive = Receive::default();
    assert_eq!(receive.next(&control).await.unwrap().stream_id, 0);
    let frame = receive.next(&control).await.unwrap();
    assert_eq!(frame.stream_id, 7);
    assert_eq!(
        frame.frame,
        Frame::Ping {
            nonce: 12,
            sent_us: 0
        }
    );
}

#[tokio::test]
async fn server_path_capability_is_advertised_on_native_and_fallback_transports() {
    let ca = root();
    let server_identity = leaf(&ca, true);
    let client_identity = leaf(&ca, false);
    for native in [true, false] {
        let (server, listener) = bind_capability_test_transports(
            remote_quic::server_config(&server_identity, std::slice::from_ref(&ca.certificate))
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let address = server.local_addr().unwrap();
        let tls =
            remote_tls::server_config(&server_identity, std::slice::from_ref(&ca.certificate))
                .unwrap();
        if !native {
            server.close(0u32.into(), b"");
        }
        let identity = supervisor_identity(&ca, &client_identity, address);
        let state = StateDirectory::new();
        let path = state.0.clone();
        let supervisor = tokio::spawn(async move { run(&identity, Some(path)).await });
        // Capabilities only: supervisor latency belongs to the ignored
        // supervisor_300ms diagnostic, measured on a quiet machine.
        let caps = tokio::time::timeout(HANG, async {
            if native {
                let connection = server.accept().await.unwrap().await.unwrap();
                let (send, receive) = connection.accept_bi().await.unwrap();
                let channel = NativeChannel::control(send, receive).unwrap();
                let mut receive = Receive::default();
                let first = receive.next(&channel).await.unwrap();
                let Frame::Hello {
                    version: 1, caps, ..
                } = first.frame
                else {
                    panic!("invalid greeting");
                };
                connection.close(0u32.into(), b"");
                caps
            } else {
                loop {
                    let (socket, _) = listener.accept().await.unwrap();
                    let Ok(connection) = remote_tls::accept(socket, &tls).await else {
                        continue;
                    };
                    let mut receive = Receive::default();
                    let first = receive.next(&connection.channel).await.unwrap();
                    let Frame::Hello {
                        version: 1, caps, ..
                    } = first.frame
                    else {
                        panic!("invalid greeting");
                    };
                    break caps;
                }
            }
        })
        .await;
        supervisor.abort();
        let _ = supervisor.await;
        server.close(0u32.into(), b"");
        let caps = caps.unwrap();
        assert_ne!(
            caps & infraternal_plugin_api::channel::SERVER_PATH_PROPOSALS,
            0
        );
        assert_eq!(caps & remote_quic::REMOTE_WRITER_BINDING != 0, native);
    }
}

#[cfg(target_os = "linux")]
struct CapabilityProbe(std::sync::Arc<std::sync::atomic::AtomicU64>);
#[cfg(target_os = "linux")]
static PROBE_DESCRIPTOR: infraternal_plugin_api::PluginDescriptor =
    infraternal_plugin_api::PluginDescriptor {
        id: "example",
        api: infraternal_plugin_api::API_VERSION,
        actions: &[],
        topics: &[],
        settings: None,
        events: &[],
        defaults: &[],
        dependencies: &[],
        can_enable_components: &[],
        roles: &[infraternal_plugin_api::RoleDef {
            id: "node",
            requires: &[],
            default_enabled: true,
        }],
        streams: &[infraternal_plugin_api::StreamDef {
            id: "example.native",
            schema: infraternal_plugin_api::SchemaRef("example.wire"),
            resumable: false,
            wire: Some(crate::remote_native_tests::PLUGIN_WIRE),
        }],
        max_frame_len: 8192,
        unavailable: b"{}",
        unavailable_event: b"{}",
    };
#[cfg(target_os = "linux")]
impl infraternal_plugin_api::AgentPlugin for CapabilityProbe {
    fn descriptor(&self) -> &'static infraternal_plugin_api::PluginDescriptor {
        &PROBE_DESCRIPTOR
    }
    fn call(&mut self, _: &str, _: &[u8]) -> Result<Vec<u8>, infraternal_plugin_api::PluginError> {
        Err(infraternal_plugin_api::PluginError::UnknownAction)
    }
    fn wire_provider(
        &self,
    ) -> Option<std::sync::Arc<dyn infraternal_plugin_api::streams::WireProvider>> {
        Some(std::sync::Arc::new(Self(self.0.clone())))
    }
    fn transport_capabilities(&mut self, caps: u64) {
        self.0.store(caps, std::sync::atomic::Ordering::SeqCst);
    }
}
#[cfg(target_os = "linux")]
impl infraternal_plugin_api::streams::WireProvider for CapabilityProbe {
    fn serve(
        &self,
        _: &'static infraternal_plugin_api::streams::WireStreamDef,
        _: bytes::Bytes,
        _: std::sync::Arc<dyn infraternal_plugin_api::streams::WireLane>,
    ) -> infraternal_plugin_api::Operation<'static, Result<(), ()>> {
        Box::pin(async { Err(()) })
    }
}
#[cfg(target_os = "linux")]
#[tokio::test]
async fn cancelled_connection_withdraws_retained_registry_capabilities() {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    };
    let ca = root();
    let server = quinn::Endpoint::server(
        remote_quic::server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate))
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let identity = supervisor_identity(&ca, &leaf(&ca, false), server.local_addr().unwrap());
    let caps = Arc::new(AtomicU64::new(0));
    let mut registry = infraternal_plugin_api::PluginRegistry::default();
    registry
        .register(Box::new(CapabilityProbe(caps.clone())))
        .unwrap();
    let registry = Arc::new(Mutex::new(registry));
    let runner_registry = registry.clone();
    let state = StateDirectory::new();
    let state_path = state.0.clone();
    let runner = tokio::spawn(async move {
        Box::pin(run_with_registry(
            &identity,
            Some(state_path),
            runner_registry,
        ))
        .await
    });
    let connection = tokio::time::timeout(Duration::from_secs(5), async {
        server.accept().await.unwrap().await.unwrap()
    })
    .await
    .unwrap();
    let (send, receive) = connection.accept_bi().await.unwrap();
    let channel = NativeChannel::control(send, receive).unwrap();
    let mut receive = Receive::default();
    assert!(
        matches!(receive.next(&channel).await.unwrap().frame,Frame::Hello{caps,..} if caps&infraternal_protocol::desktop::NATIVE_CAPABILITY!=0)
    );
    crate::transport::Transmit::default()
        .send(
            &channel,
            0,
            &Frame::Hello {
                version: 1,
                caps: infraternal_protocol::desktop::NATIVE_CAPABILITY | 2,
                client_info: "test",
            },
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while caps.load(Ordering::SeqCst) != infraternal_protocol::desktop::NATIVE_CAPABILITY {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    runner.abort();
    let _ = runner.await;
    assert_eq!(
        caps.load(Ordering::SeqCst),
        0,
        "cancelled native connection retained provider availability"
    );
    drop(registry);
    server.close(0u32.into(), b"");
}

/// Reserve both protocols before either supervisor path can start.
async fn bind_capability_test_transports(
    config: quinn::ServerConfig,
    candidate: SocketAddr,
) -> io::Result<(quinn::Endpoint, tokio::net::TcpListener)> {
    let mut candidate = candidate;
    // The kernel allocates UDP and TCP ports independently. Keep the original
    // protocol assertions, but move to another candidate if either is occupied.
    for _ in 0..16 {
        let server = match quinn::Endpoint::server(config.clone(), candidate) {
            Ok(server) => server,
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                candidate.set_port(0);
                continue;
            }
            Err(error) => return Err(error),
        };
        match tokio::net::TcpListener::bind(server.local_addr()?).await {
            Ok(listener) => return Ok((server, listener)),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                server.close(0u32.into(), b"fixture candidate occupied");
                candidate.set_port(0);
            }
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no shared test TCP/UDP port available",
    ))
}

#[tokio::test]
async fn capability_fixture_retries_a_port_held_by_the_other_transport() {
    let ca = root();
    let identity = leaf(&ca, true);
    let held = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied = held.local_addr().unwrap();
    let (endpoint, listener) = bind_capability_test_transports(
        remote_quic::server_config(&identity, std::slice::from_ref(&ca.certificate)).unwrap(),
        occupied,
    )
    .await
    .unwrap();
    assert_eq!(
        endpoint.local_addr().unwrap(),
        listener.local_addr().unwrap()
    );
    assert_ne!(listener.local_addr().unwrap(), occupied);
    assert_eq!(held.local_addr().unwrap(), occupied);
}
