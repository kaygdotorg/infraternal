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
    let schema_live: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='sessions')",
    )
    .fetch_one(&f.auth.pool)
    .await
    .unwrap();
    assert!(
        schema_live,
        "cancelled acquire dropped the fixture's sole in-memory database connection"
    );
    let reopened = connect_async(test_ws_request(address, &cookie)).await;
    let status = match &reopened {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => response.status().as_u16(),
        _ => 0,
    };
    assert!(
        reopened.is_ok(),
        "expired Hello retained per-user capacity; upgrade HTTP status={status}"
    );
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

#[tokio::test]
async fn clean_control_close_is_not_an_internal_error() {
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
            client_info: "close",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Close {
            code: 1000,
            reason: "done",
        },
    )
    .await;
    if let Some(Ok(Message::Binary(bytes))) = socket.next().await {
        assert!(
            !matches!(
                decode_muxed_frame(&bytes).unwrap().frame,
                Frame::Close { code: 1011, .. }
            ),
            "clean Close became an internal error"
        );
    }
    server.abort();
}

#[tokio::test]
async fn authenticated_idle_socket_survives_the_former_read_timeout() {
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
            client_info: "idle-lifetime",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    tokio::time::sleep(Duration::from_secs(31)).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 34,
            sent_us: 0,
        },
    )
    .await;
    let wire = tokio::time::timeout(Duration::from_secs(2), read_client_frame(&mut socket))
        .await
        .unwrap();
    assert!(
        matches!(
            decode_muxed_frame(&wire).unwrap().frame,
            Frame::Pong { nonce: 34, .. }
        ),
        "healthy authenticated idle socket closed after 30 seconds"
    );
    server.abort();
}

#[tokio::test]
async fn incomplete_rfc_message_still_loses_authority_on_revocation() {
    use tokio_tungstenite::tungstenite::protocol::frame::{
        Frame as WebSocketFrame,
        coding::{Data, OpCode},
    };
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
            client_info: "partial-rfc-revocation",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    // A nonfinal RFC binary fragment stays hidden inside Axum's message stream.
    socket
        .send(Message::Frame(WebSocketFrame::message(
            Bytes::from_static(&[0x80]),
            OpCode::Data(Data::Binary),
            false,
        )))
        .await
        .unwrap();
    f.auth.logout(&f.session).await.unwrap();
    let next = tokio::time::timeout(Duration::from_millis(1500), socket.next()).await;
    assert!(
        next.is_ok(),
        "incomplete RFC message masked committed revocation"
    );
    assert!(
        !matches!(next.unwrap(), Some(Ok(Message::Binary(_)))),
        "revoked fragmented socket received authority-bearing output"
    );
    server.abort();
}
