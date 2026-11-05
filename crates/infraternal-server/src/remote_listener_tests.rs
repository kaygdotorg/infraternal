//! Verifies owned additional listeners and separates observed tunnel addresses from underlay discovery [168,198,215].
use super::*;
use infraternal_agent::remote_native::NativeChannel;

async fn control(
    address: SocketAddr,
    local: &str,
    identity: &Identity,
    root: &X509,
) -> (quinn::Endpoint, quinn::Connection, NativeChannel) {
    let mut endpoint = quinn::Endpoint::client(local.parse().unwrap()).unwrap();
    endpoint.set_default_client_config(
        remote_quic::client_config(identity, std::slice::from_ref(root)).unwrap(),
    );
    let connection = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(address, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (send, receive) = connection.open_bi().await.unwrap();
    let channel = NativeChannel::control(send, receive).unwrap();
    Transmit::default()
        .send(
            &channel,
            0,
            &Frame::Hello {
                version: 1,
                caps: remote_quic::REMOTE_WRITER_BINDING,
                client_info: "fixture",
            },
        )
        .await
        .unwrap();
    let mut receive = Receive::default();
    let response = tokio::time::timeout(Duration::from_secs(3), receive.next(&channel))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(response.frame, Frame::Hello { version: 1, .. }));
    (endpoint, connection, channel)
}

#[tokio::test]
async fn additional_listener_keeps_underlay_address_and_retires_with_its_lease() {
    let (server, node, root, _) = identities();
    let (store, _pool, host_id, _) = super::revocation::admitted_store(&node, &root).await;
    let hosts = RemoteHosts::default();
    let primary = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store,
        hosts.clone(),
    )
    .await
    .unwrap();
    let direct = control(primary.local_addr().unwrap(), "127.0.0.1:0", &node, &root).await;
    assert_eq!(
        hosts.0.lock().await[&host_id].ip,
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    let additional = hosts
        .listen("127.0.0.3".parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    let address = additional.local_addr().unwrap();
    assert_eq!(address.port(), primary.local_addr().unwrap().port());
    let overlay = control(address, "127.0.0.2:0", &node, &root).await;
    assert_eq!(
        hosts.0.lock().await[&host_id].ip,
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        "tunnel source must not replace WireGuard underlay discovery"
    );
    drop(additional);
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    let replacement = control(primary.local_addr().unwrap(), "127.0.0.1:0", &node, &root).await;
    drop((replacement, overlay, direct));
}

#[tokio::test]
async fn initial_overlay_admission_has_no_underlay_guess() {
    let (server, node, root, _) = identities();
    let (store, _pool, host_id, _) = super::revocation::admitted_store(&node, &root).await;
    let hosts = RemoteHosts::default();
    let primary = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store,
        hosts.clone(),
    )
    .await
    .unwrap();
    let additional = hosts
        .listen("127.0.0.3".parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    let overlay = control(
        additional.local_addr().unwrap(),
        "127.0.0.2:0",
        &node,
        &root,
    )
    .await;
    assert!(hosts.0.lock().await[&host_id].ip.is_unspecified());
    drop((overlay, additional, primary));
}

#[tokio::test]
async fn additional_listener_refuses_unenrolled_certificate_before_proof_reply() {
    let (server, node, root, _) = identities();
    let (store, _pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let hosts = RemoteHosts::default();
    let _primary = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store,
        hosts.clone(),
    )
    .await
    .unwrap();
    let additional = hosts
        .listen("127.0.0.3".parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.2:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(remote_quic::client_config(&node, &[root]).unwrap());
    if let Ok(connection) = endpoint
        .connect(additional.local_addr().unwrap(), "localhost")
        .unwrap()
        .await
        && let Ok((send, receive)) = connection.open_bi().await
    {
        let control = NativeChannel::control(send, receive).unwrap();
        let _ = Transmit::default()
            .send(
                &control,
                0,
                &Frame::Ping {
                    nonce: 31,
                    sent_us: 0,
                },
            )
            .await;
        let mut decoder = Receive::default();
        let response = tokio::time::timeout(Duration::from_secs(3), decoder.next(&control)).await;
        assert!(
            !matches!(response, Ok(Ok(_))),
            "certificate chain alone cannot prove ledger authority"
        );
    }
    assert!(hosts.0.lock().await.is_empty());
}

async fn wildcard_binding(listen: SocketAddr) {
    let (server, node, root, _) = identities();
    let (store, _pool, host_id, _) = super::revocation::admitted_store(&node, &root).await;
    let hosts = RemoteHosts::default();
    let primary = RemoteListeners::start(
        listen,
        &server,
        std::slice::from_ref(&root),
        store,
        hosts.clone(),
    )
    .await
    .unwrap();
    let address = SocketAddr::new(
        "127.0.0.1".parse().unwrap(),
        primary.local_addr().unwrap().port(),
    );
    let direct = control(address, "127.0.0.1:0", &node, &root).await;
    let additional = hosts
        .listen("127.0.0.3".parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(additional.listener.is_none());
    let second = hosts
        .listen("127.0.0.3".parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    let overlay = control(
        additional.local_addr().unwrap(),
        "127.0.0.2:0",
        &node,
        &root,
    )
    .await;
    assert_eq!(hosts.0.lock().await[&host_id].ip, address.ip());
    drop(additional);
    assert!(hosts.for_local(Some("127.0.0.3".parse().unwrap())).4);
    drop(second);
    assert!(!hosts.for_local(Some("127.0.0.3".parse().unwrap())).4);
    let replacement = control(address, "127.0.0.1:0", &node, &root).await;
    drop((replacement, overlay, direct));
}

#[tokio::test]
async fn wildcard_listener_reuses_binding_and_tracks_destination_lease_counts() {
    wildcard_binding("0.0.0.0:0".parse().unwrap()).await;
}
#[tokio::test]
async fn ipv6_wildcard_listener_reuses_binding_and_preserves_ipv4_discovery() {
    wildcard_binding("[::]:0".parse().unwrap()).await;
}

/// Real leased TCP/mTLS uses the current ledger and actor, releases its listen
/// sockets on drop, and cannot retire the primary listener's TLS configuration.
#[tokio::test]
async fn leased_tcp_admits_current_identity_releases_lease_and_keeps_primary_usable() {
    let (server, node, root, _) = identities();
    let (store, _pool, host_id, fingerprint) =
        super::revocation::admitted_store(&node, &root).await;
    let hosts = RemoteHosts::default();
    let primary = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store.clone(),
        hosts.clone(),
    )
    .await
    .unwrap();
    let additional = hosts
        .listen("127.0.0.3".parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    let leased = additional.local_addr().unwrap();
    let mut lease = Some(additional);
    let mut peers = Vec::new();
    // Both addresses must complete actual TLS, Hello and an actor request. The
    // existing peer fixture checks that terminal.open carries the enrolled uid.
    for (address, retire_lease) in [(leased, false), (primary.local_addr().unwrap(), true)] {
        if retire_lease {
            drop(lease.take());
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert!(
                tokio::net::TcpStream::connect(leased).await.is_err(),
                "retired lease still accepts TCP connections"
            );
            drop(
                std::net::UdpSocket::bind(leased).expect("retired lease retained its UDP binding"),
            );
            let peer: tokio::task::JoinHandle<()> = peers.pop().unwrap();
            peer.abort();
            assert!(peer.await.unwrap_err().is_cancelled());
            // An ordinary disconnect retains the durable actor. Wait until
            // its first transport retires so the next open must use primary.
            tokio::time::timeout(Duration::from_secs(3), async {
                while hosts.online(host_id).await {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        }
        let config = remote_tls::client_config(&node, std::slice::from_ref(&root)).unwrap();
        let (completed, completion) = tokio::sync::oneshot::channel();
        peers.push(tokio::spawn(async move {
            let connection = remote_tls::dial(address, "localhost", &config)
                .await
                .unwrap();
            respond(&connection.channel).await;
            // Online means an authenticated session census is available, not
            // merely that TLS/Hello registered an actor. The existing response
            // fixture does not publish that separate control event.
            let census = serde_json::json!({
                "type": "terminal.sessions.snapshot",
                "session_ids": [Uuid::from_u128(7)],
            })
            .to_string();
            Transmit::default()
                .send(
                    &connection.channel,
                    0,
                    &Frame::Event {
                        sub_id: 0,
                        event_json: census.as_bytes(),
                    },
                )
                .await
                .unwrap();
            completed.send(()).unwrap();
            std::future::pending::<()>().await;
        }));
        let actor = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(actor) = hosts.actor(host_id).await {
                    break actor;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let session = tokio::time::timeout(
            Duration::from_secs(3),
            actor.open(crate::embedded::TerminalSize {
                cols: 80,
                rows: 24,
                px_w: 0,
                px_h: 0,
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(session, *Uuid::from_u128(7).as_bytes());
        tokio::time::timeout(Duration::from_secs(3), completion)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !hosts.online(host_id).await {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("authenticated session census never became available");
    }

    // The certificate retains the same TLS settings after durable revocation,
    // but it must never receive an application Hello or register an actor.
    let additional = hosts
        .listen("127.0.0.3".parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    let leased = additional.local_addr().unwrap();
    store
        .revoke("owner", host_id, now().unwrap())
        .await
        .unwrap();
    assert!(store.admit(&fingerprint, now().unwrap()).await.is_err());
    tokio::time::timeout(Duration::from_secs(3), async {
        while hosts.actor(host_id).await.is_some() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let config = remote_tls::client_config(&node, std::slice::from_ref(&root)).unwrap();
    if let Ok(connection) = remote_tls::dial(leased, "localhost", &config).await {
        let sent = Transmit::default()
            .send(
                &connection.channel,
                0,
                &Frame::Hello {
                    version: 1,
                    caps: remote_quic::REMOTE_WRITER_BINDING,
                    client_info: "fixture",
                },
            )
            .await;
        if sent.is_ok() {
            let mut receive = Receive::default();
            let denied =
                tokio::time::timeout(Duration::from_secs(3), receive.next(&connection.channel))
                    .await
                    .expect("revoked identity's leased TLS channel was not retired");
            assert!(
                denied.is_err(),
                "revoked certificate received application bytes on leased TLS"
            );
        }
    }
    assert!(
        hosts.actor(host_id).await.is_none(),
        "revoked certificate registered a new actor"
    );
    drop(additional);
    for peer in peers {
        peer.abort();
        assert!(peer.await.unwrap_err().is_cancelled());
    }
    drop(primary);
}

/// Round-trips one control Ping on the admitted connection.
async fn ping(channel: &NativeChannel, receive: &mut Receive, nonce: u64) {
    Transmit::default()
        .send(channel, 0, &Frame::Ping { nonce, sent_us: 0 })
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(3), receive.next(channel))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply.frame, Frame::Pong { nonce, sent_us: 0 });
}

/// #201: an admitted connection moves to a leased server address and back
/// without re-admission. The client keeps naming the enrolled address; the
/// shared endpoint recognizes the same connection on either socket and answers
/// through the one it was reached on.
#[tokio::test]
async fn admitted_connection_moves_to_a_leased_address_and_back_without_readmission() {
    use infraternal_plugin_remote::remote_path_socket::{Path, PathSocket};
    use quinn::Runtime as _;
    let (server, node, root, _) = identities();
    let (store, _pool, host_id, _) = super::revocation::admitted_store(&node, &root).await;
    let hosts = RemoteHosts::default();
    let primary = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store,
        hosts.clone(),
    )
    .await
    .unwrap();
    let enrolled = primary.local_addr().unwrap();
    let lease = hosts
        .listen("127.0.0.3".parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    let leased = lease.local_addr().unwrap();
    let path = PathSocket::new(
        quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.2:0").unwrap())
            .unwrap(),
        enrolled,
    );
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        path.clone(),
        std::sync::Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    endpoint.set_default_client_config(
        remote_quic::client_config(&node, std::slice::from_ref(&root)).unwrap(),
    );
    let connection = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(enrolled, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (send, receive) = connection.open_bi().await.unwrap();
    let channel = NativeChannel::control(send, receive).unwrap();
    Transmit::default()
        .send(
            &channel,
            0,
            &Frame::Hello {
                version: 1,
                caps: remote_quic::REMOTE_WRITER_BINDING,
                client_info: "fixture",
            },
        )
        .await
        .unwrap();
    let mut receive = Receive::default();
    let hello = tokio::time::timeout(Duration::from_secs(3), receive.next(&channel))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(hello.frame, Frame::Hello { version: 1, .. }));
    ping(&channel, &mut receive, 1).await;
    let generation = hosts.0.lock().await[&host_id].generation;

    let moved = std::time::Instant::now();
    path.use_mesh(leased);
    endpoint.rebind_abstract(path.alias()).unwrap();
    ping(&channel, &mut receive, 2).await;
    assert_eq!(path.path(), Path::Mesh(leased));
    assert!(
        path.heard_since(moved),
        "replies must come from the leased address"
    );

    path.use_enrolled();
    endpoint.rebind_abstract(path.alias()).unwrap();
    ping(&channel, &mut receive, 3).await;
    let heard = path.mesh_datagrams();
    drop(lease);
    ping(&channel, &mut receive, 4).await;
    assert_eq!(
        path.mesh_datagrams(),
        heard,
        "the enrolled path carried the last exchange"
    );
    assert_eq!(connection.remote_address(), enrolled);
    assert!(connection.close_reason().is_none());
    assert_eq!(
        hosts.0.lock().await[&host_id].generation,
        generation,
        "the host was never re-admitted"
    );
    drop((channel, connection, endpoint, primary));
}

/// Both a leased listener and the primary listener must expose actual TCP/mTLS
/// admission and a decoded nonempty terminal Output. A fresh authenticated tuple
/// isolates each assertion from other tests; no current-route hint proves an
/// earliest unrestricted mesh byte here.
#[cfg(feature = "mesh-transport-proof")]
#[tokio::test]
async fn tcp_observer_counts_leased_and_primary_admission_and_nonempty_output() {
    use crate::embedded::{TerminalOutput, TerminalSize};
    use crate::remote_autoswitch_probe::{Capture, Kind, TEST_SERIAL};
    const WRITER: u32 = 0x2010_0002;
    const MARKER: &[u8] = b"public-tcp-observer";
    let _owner = TEST_SERIAL.lock().await;
    let capture = Capture::start(|peer| peer.ip().is_loopback());
    let (server, node, root, _) = identities();
    let (store, _pool, host_id, _) = super::revocation::admitted_store(&node, &root).await;
    let hosts = RemoteHosts::default();
    let primary = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store,
        hosts.clone(),
    )
    .await
    .unwrap();
    let lease = hosts
        .listen("127.0.0.3".parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    let mut seen = Vec::new();
    for (index, address) in [lease.local_addr().unwrap(), primary.local_addr().unwrap()]
        .into_iter()
        .enumerate()
    {
        let writer = WRITER + u32::try_from(index).unwrap() * 2;
        let previous_generation = hosts
            .0
            .lock()
            .await
            .get(&host_id)
            .map(|host| host.generation);
        let started = std::time::Instant::now();
        let config = remote_tls::client_config(&node, std::slice::from_ref(&root)).unwrap();
        let (release, released) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let connection = remote_tls::dial(address, "localhost", &config)
                .await
                .unwrap();
            respond(&connection.channel).await;
            let mut receive = Receive::default();
            let attached = receive.next(&connection.channel).await.unwrap();
            assert_eq!(attached.stream_id, writer);
            assert!(matches!(attached.frame, Frame::AttachTerm { .. }));
            let credit = receive.next(&connection.channel).await.unwrap();
            assert_eq!(credit.stream_id, writer);
            assert!(matches!(credit.frame, Frame::Credit { .. }));
            for bytes in [&b""[..], MARKER] {
                Transmit::default()
                    .send(
                        &connection.channel,
                        writer,
                        &Frame::Output { out_seq: 0, bytes },
                    )
                    .await
                    .unwrap();
            }
            let census = serde_json::json!({
                "type": "terminal.sessions.snapshot",
                "session_ids": [Uuid::from_u128(7)],
            })
            .to_string();
            Transmit::default()
                .send(
                    &connection.channel,
                    0,
                    &Frame::Event {
                        sub_id: 0,
                        event_json: census.as_bytes(),
                    },
                )
                .await
                .unwrap();
            let _ = released.await;
        });
        let actor = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let registered = hosts
                    .0
                    .lock()
                    .await
                    .get(&host_id)
                    .is_some_and(|host| Some(host.generation) != previous_generation);
                if registered && let Some(actor) = hosts.actor(host_id).await {
                    break actor;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        let session = tokio::time::timeout(
            Duration::from_secs(5),
            actor.open(TerminalSize {
                cols: 80,
                rows: 24,
                px_w: 0,
                px_h: 0,
            }),
        )
        .await
        .unwrap()
        .unwrap();
        let (handle, mut output) = actor.attach(session, 0, 0, writer).await.unwrap().split();
        let mut credit = Vec::new();
        infraternal_protocol::encode_muxed_frame_into(1, &Frame::Credit { bytes: 64 }, &mut credit)
            .unwrap();
        handle.send_frame(bytes::Bytes::from(credit)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let TerminalOutput::Output { bytes, .. } = output.recv().await.unwrap()
                    && !bytes.is_empty()
                {
                    assert_eq!(&bytes[..], MARKER);
                    break;
                }
            }
        })
        .await
        .unwrap();
        let events = capture.events();
        let first = events
            .iter()
            .find(|event| {
                event.kind == Kind::TerminalByte
                    && event.stream == writer
                    && event.monotonic >= started
            })
            .expect("authenticated TCP Output is missing from transport observation");
        // TCP may reuse a source port against a different destination. The
        // fresh writer distinguishes Output events; header counts still grow.
        let occurrence = seen.iter().filter(|peer| **peer == first.peer).count() + 1;
        seen.push(first.peer);
        for kind in [
            Kind::TlsHandshake,
            Kind::LedgerAdmission,
            Kind::ControlReady,
            Kind::TerminalByte,
        ] {
            assert_eq!(
                capture.count_peer(kind, first.peer),
                occurrence,
                "TCP {kind:?} callback absent or duplicated"
            );
            assert!(
                capture.count(kind) >= seen.len(),
                "TCP callbacks absent from total {kind:?} count"
            );
        }
        assert_eq!(
            capture.count_peer(Kind::TerminalByte, first.peer),
            occurrence,
            "empty Output was counted as a terminal byte"
        );
        // The durable actor survives disconnects. Use its authenticated census
        // and retirement state to synchronize churn independently of callbacks.
        tokio::time::timeout(Duration::from_secs(5), async {
            while !hosts.online(host_id).await {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("authenticated session census never became available");
        drop(handle);
        release.send(()).unwrap();
        peer.await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while hosts.online(host_id).await {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("previous TCP transport did not retire");
    }
    drop((lease, primary));
}
