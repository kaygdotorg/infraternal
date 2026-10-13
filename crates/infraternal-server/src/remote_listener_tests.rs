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
