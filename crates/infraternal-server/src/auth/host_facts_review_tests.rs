//! Verifies that pending host-facts requests preserve unrelated control dispatch on the real router.
use super::*;

/// A slow host read must not serialize every other mux stream behind its Result (wire.md section 6).
#[tokio::test(start_paused = true)]
async fn pending_host_facts_read_keeps_control_ping_responsive() {
    let _guard = SERIAL.lock().await;
    let clock = FrozenSocketTime::new().await;
    let f = fixture().await;
    let (socket, mut peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap()
    .with_plugin_descriptors(super::socket_tests::HOST_FACTS_DESCRIPTORS);
    let app = crate::websocket::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut receive = BytesMut::new();
    let hello = read_leg_b_frame(&mut peer, &mut receive).await.unwrap();
    assert!(matches!(
        decode_muxed_frame(&hello).unwrap().frame,
        Frame::Hello { .. }
    ));
    leg_b_send(
        &mut peer,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "pending-read-fixture",
        },
    )
    .await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut browser, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut browser).await;
    client_ws_send(
        &mut browser,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "pending-read-fixture",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    client_ws_send(
        &mut browser,
        0,
        &Frame::Call {
            call_id: 144,
            action_id: "host.facts.read",
            input_json: br#"{"includeLive":true}"#,
        },
    )
    .await;
    let call = loop {
        let wire = read_leg_b_frame(&mut peer, &mut receive).await.unwrap();
        if let Frame::Call {
            action_id: "terminal.login.prepare",
            call_id,
            ..
        } = decode_muxed_frame(&wire).unwrap().frame
        {
            // Opportunistic login work shares this real one-connection pool.
            // Completing its fixture reply does not complete the facts request.
            leg_b_send(
                &mut peer,
                0,
                &Frame::Result {
                    call_id,
                    ok: true,
                    json: br#"{"prepared":true}"#,
                },
            )
            .await;
            continue;
        }
        break wire;
    };
    assert!(matches!(
        decode_muxed_frame(&call).unwrap().frame,
        Frame::Call {
            action_id: "host.facts.read",
            ..
        }
    ));
    // Real I/O has reached the pending call; resume time for the bounded response check.
    drop(clock);
    // Hold the Result on leg B. A Ping is independent of that outstanding request.
    client_ws_send(
        &mut browser,
        0,
        &Frame::Ping {
            nonce: 144,
            sent_us: 0,
        },
    )
    .await;
    let reply = tokio::time::timeout(Duration::from_secs(1), read_client_frame(&mut browser)).await;
    server.abort();
    assert!(
        reply.is_ok(),
        "pending host facts blocked control dispatch for one second"
    );
    assert!(matches!(
        decode_muxed_frame(&reply.unwrap()).unwrap().frame,
        Frame::Pong { nonce: 144, .. }
    ));
}
