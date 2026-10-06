//! Real WebSocket regressions for upgrade reservation, revoked idle sockets and clean Close.
use super::*;

async fn socket_fixture() -> (Fixture, SocketAddr, tokio::task::JoinHandle<()>) {
    let f = fixture().await;
    let (socket, _peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    );
    let app = crate::websocket::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (f, address, server)
}

#[tokio::test]
async fn revoked_idle_socket_loses_all_authority() {
    let _guard = SERIAL.lock().await;
    let (f, address, server) = socket_fixture().await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "revocation",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    f.auth.logout(&f.session).await.unwrap();
    let next = tokio::time::timeout(Duration::from_millis(1500), socket.next()).await;
    assert!(
        next.is_ok(),
        "revoked idle socket remained open past revocation deadline"
    );
    if let Some(Ok(Message::Binary(bytes))) = next.unwrap() {
        assert!(
            !matches!(
                decode_muxed_frame(&bytes).unwrap().frame,
                Frame::Pong { .. }
            ),
            "revoked socket retained terminal/control authority"
        );
    }
    server.abort();
}

/// Local-network overhead with the real router, real SQLite authority and 16 simultaneous sockets.
#[tokio::test]
#[ignore = "release-only measurement without concurrent compilation"]
async fn socket_authority_latency_at_user_capacity() {
    let _guard = SERIAL.lock().await;
    let (f, address, server) = socket_fixture().await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let mut sockets = Vec::new();
    for _ in 0..16 {
        let (mut socket, _) = connect_async(test_ws_request(address, &cookie))
            .await
            .unwrap();
        assert_server_hello(&mut socket).await;
        client_ws_send(
            &mut socket,
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "capacity-bench",
            },
        )
        .await;
        read_welcome(&mut socket).await;
        sockets.push(socket);
    }
    let mut samples = Vec::new();
    let load = std::fs::read_to_string("/proc/loadavg").unwrap();
    for nonce in 0..200 {
        let durations = futures_util::future::join_all(sockets.iter_mut().map(async |socket| {
            let start = Instant::now();
            client_ws_send(socket, 0, &Frame::Ping { nonce, sent_us: 0 }).await;
            let wire = read_client_frame(socket).await;
            assert!(matches!(decode_muxed_frame(&wire).unwrap().frame, Frame::Pong { nonce: got, .. } if got == nonce));
            start.elapsed()
        })).await;
        samples.extend(durations);
    }
    let (p50, p99) = latency_us(&mut samples);
    println!(
        "socket authority: sockets=16 simultaneous_per_round=16 rounds=200 n={} p50={p50}us p99={p99}us arch={} load={}",
        samples.len(),
        std::env::consts::ARCH,
        load.trim()
    );
    assert!(
        p99 < 5000,
        "authority/control overhead exceeds local 5ms budget"
    );
    server.abort();
}

#[tokio::test]
async fn half_open_sockets_obey_user_limit() {
    let _guard = SERIAL.lock().await;
    let (f, address, server) = socket_fixture().await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let mut sockets = Vec::new();
    for _ in 0..16 {
        let (mut socket, _) = connect_async(test_ws_request(address, &cookie))
            .await
            .unwrap();
        assert_server_hello(&mut socket).await;
        sockets.push(socket);
    }
    let seventeenth = connect_async(test_ws_request(address, &cookie)).await;
    assert!(
        matches!(seventeenth, Err(tokio_tungstenite::tungstenite::Error::Http(ref response))
        if response.status() == axum::http::StatusCode::SERVICE_UNAVAILABLE),
        "17 sockets without Hello bypassed the per-user admission limit"
    );
    server.abort();
}

#[tokio::test]
async fn expired_handshake_releases_user_permits() {
    let _guard = SERIAL.lock().await;
    let (f, address, server) = socket_fixture().await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let mut held = Vec::new();
    for _ in 0..16 {
        let (socket, _) = connect_async(test_ws_request(address, &cookie))
            .await
            .unwrap();
        held.push(socket);
    }
    tokio::time::sleep(Duration::from_millis(5250)).await;
    let reopened = connect_async(test_ws_request(address, &cookie)).await;
    assert!(reopened.is_ok(), "expired Hello retained per-user capacity");
    server.abort();
}

#[tokio::test]
async fn fragmented_wire_frame_has_a_completion_deadline() {
    let _guard = SERIAL.lock().await;
    let (f, address, server) = socket_fixture().await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "partial-frame",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    socket
        .send(Message::Binary(Bytes::from_static(&[0x80])))
        .await
        .unwrap();
    let start = Instant::now();
    let ended = tokio::time::timeout(Duration::from_secs(6), socket.next()).await;
    assert!(
        ended.is_ok(),
        "fragmented frame never completed or timed out"
    );
    println!(
        "partial frame removed after {}ms (configured 5000ms)",
        start.elapsed().as_millis()
    );
    server.abort();
}
