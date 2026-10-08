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

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep full-capacity and cross-account events in one real fixture.
async fn recovery_subscription_updates_every_signed_in_socket() {
    let _guard = SERIAL.lock().await;
    let (f, address, server) = socket_fixture().await;
    let now = crate::websocket::now_seconds().unwrap();
    let other_user = uuid::Uuid::new_v4().to_string();
    let other_session = random();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'other',0,'unused','other','Other')")
        .bind(&other_user).execute(&f.auth.pool).await.unwrap();
    let mut tx = f.auth.pool.begin().await.unwrap();
    insert_session(&mut tx, &other_session, &other_user, "other", now, None)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut devices = Vec::new();
    // Exercise the full 16-device account cap plus an independently signed-in account.
    for index in 0..17 {
        let session = if index == 16 {
            &other_session
        } else {
            &f.session
        };
        let cookie = format!("__Host-infraternal={session}");
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
                client_info: "recovery-notice",
            },
        )
        .await;
        read_welcome(&mut socket).await;
        client_ws_send(
            &mut socket,
            0,
            &Frame::Subscribe {
                sub_id: 45,
                filter_json: br#"{"topic":"auth.recovery"}"#,
            },
        )
        .await;
        let bytes = read_client_frame(&mut socket).await;
        let decoded = decode_muxed_frame(&bytes).unwrap();
        let Frame::Event {
            sub_id: 45,
            event_json,
        } = decoded.frame
        else {
            panic!("missing recovery snapshot")
        };
        assert!(serde_json::from_slice::<Value>(event_json).unwrap()["pending"].is_null());
        devices.push(socket);
    }
    let mut other = devices.pop().unwrap();
    let (_, ready) = f
        .auth
        .recovery_resume(&f.user, f.words.clone(), now)
        .await
        .unwrap();
    assert!(ready >= now + DAY);
    for socket in &mut devices {
        let bytes = read_client_frame(socket).await;
        let Frame::Event {
            sub_id: 45,
            event_json,
        } = decode_muxed_frame(&bytes).unwrap().frame
        else {
            panic!("missing start event")
        };
        assert_eq!(
            serde_json::from_slice::<Value>(event_json).unwrap()["pending"]["ready_at"],
            ready
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(250), other.next())
            .await
            .is_err(),
        "another account received recovery start state"
    );
    f.auth.recovery_cancel(&f.session, now).await.unwrap();
    for socket in &mut devices {
        let bytes = read_client_frame(socket).await;
        let Frame::Event {
            sub_id: 45,
            event_json,
        } = decode_muxed_frame(&bytes).unwrap().frame
        else {
            panic!("missing cancel event")
        };
        assert!(serde_json::from_slice::<Value>(event_json).unwrap()["pending"].is_null());
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(250), other.next())
            .await
            .is_err(),
        "another account received recovery cancel state"
    );
    println!(
        "Recovery events: 16/16 signed-in devices received start and cancel; other account received 0 events."
    );
    server.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep one real socket's handshake, snapshot, edits, and invalidations ordered.
async fn mesh_calls_and_subscriptions_deliver_scoped_live_inventory() {
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
            client_info: "mesh-api",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Subscribe {
            sub_id: 72,
            filter_json: br#"{"topic":"mesh"}"#,
        },
    )
    .await;
    let snapshot = read_client_frame(&mut socket).await;
    let Frame::Event {
        sub_id: 72,
        event_json,
    } = decode_muxed_frame(&snapshot).unwrap().frame
    else {
        panic!("missing initial Mesh snapshot")
    };
    let snapshot: Value = serde_json::from_slice(event_json).unwrap();
    assert_eq!(snapshot["type"], "snapshot");
    assert_eq!(snapshot["snapshot"]["revision"], 0);
    assert_eq!(snapshot["snapshot"]["nodes"], json!([]));

    let node_input = serde_json::to_vec(&json!({
        "name":"db-1",
        "public_key":vec![1_u8; 32],
    }))
    .unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 1,
            action_id: "mesh.node.enroll",
            input_json: &node_input,
        },
    )
    .await;
    let result = read_client_frame(&mut socket).await;
    let Frame::Result {
        call_id: 1,
        ok: true,
        json: result_json,
    } = decode_muxed_frame(&result).unwrap().frame
    else {
        panic!("mesh.node.enroll did not return a successful Result")
    };
    let result: Value = serde_json::from_slice(result_json).unwrap();
    let node_id = result["node_id"].as_u64().unwrap();
    assert_eq!(result["revision"], 1);
    let change = read_client_frame(&mut socket).await;
    let Frame::Event {
        sub_id: 72,
        event_json,
    } = decode_muxed_frame(&change).unwrap().frame
    else {
        panic!("mesh.node.enroll did not notify its subscriber")
    };
    let change: Value = serde_json::from_slice(event_json).unwrap();
    assert_eq!(change, json!({"type":"changed","revision":1}));

    let tag_input = serde_json::to_vec(&json!({"name":"ops"})).unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 2,
            action_id: "mesh.tag.create",
            input_json: &tag_input,
        },
    )
    .await;
    let result = read_client_frame(&mut socket).await;
    let Frame::Result {
        call_id: 2,
        ok: true,
        json: result_json,
    } = decode_muxed_frame(&result).unwrap().frame
    else {
        panic!("mesh.tag.create did not return a successful Result")
    };
    let result: Value = serde_json::from_slice(result_json).unwrap();
    assert_eq!(result["revision"], 2);
    let change = read_client_frame(&mut socket).await;
    let Frame::Event {
        sub_id: 72,
        event_json,
    } = decode_muxed_frame(&change).unwrap().frame
    else {
        panic!("mesh.tag.create did not notify its subscriber")
    };
    assert_eq!(
        serde_json::from_slice::<Value>(event_json).unwrap(),
        json!({"type":"changed","revision":2})
    );

    let member_input = serde_json::to_vec(&json!({"tag":"ops","node_id":node_id})).unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 3,
            action_id: "mesh.tag.member.add",
            input_json: &member_input,
        },
    )
    .await;
    let result = read_client_frame(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&result).unwrap().frame,
        Frame::Result {
            call_id: 3,
            ok: true,
            ..
        }
    ));
    let change = read_client_frame(&mut socket).await;
    let Frame::Event {
        sub_id: 72,
        event_json,
    } = decode_muxed_frame(&change).unwrap().frame
    else {
        panic!("membership edit did not notify its subscriber")
    };
    assert_eq!(
        serde_json::from_slice::<Value>(event_json).unwrap(),
        json!({"type":"changed","revision":3})
    );

    let list_input = b"{}";
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 4,
            action_id: "mesh.list",
            input_json: list_input,
        },
    )
    .await;
    let list = read_client_frame(&mut socket).await;
    let Frame::Result {
        call_id: 4,
        ok: true,
        json: list_json,
    } = decode_muxed_frame(&list).unwrap().frame
    else {
        panic!("mesh.list did not return a successful Result")
    };
    let list: Value = serde_json::from_slice(list_json).unwrap();
    assert_eq!(list["nodes"][0]["node"]["id"], node_id);
    assert_eq!(list["tags"][0]["members"][0], node_id);
    server.abort();
}
