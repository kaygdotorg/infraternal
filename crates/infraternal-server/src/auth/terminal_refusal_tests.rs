//! Public open refusal reasons survive the authenticated local control channel and browser routing [D214], #151.
use super::*;

#[tokio::test(start_paused = true)]
async fn memory_refusal_preserves_reason_and_counters_to_browser() {
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
    .unwrap();
    let app = crate::websocket::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut receive = BytesMut::new();
    read_leg_b_frame(&mut peer, &mut receive).await.unwrap();
    leg_b_send(
        &mut peer,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "memory-refusal-fixture",
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
            client_info: "memory-refusal-fixture",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    client_ws_send(
        &mut browser,
        0,
        &Frame::Call {
            call_id: 151,
            action_id: "ssh.session.open",
            input_json: b"{}",
        },
    )
    .await;
    let call = read_terminal_open(&mut peer, &mut receive).await;
    let Frame::Call {
        call_id,
        action_id: "terminal.open",
        ..
    } = decode_muxed_frame(&call).unwrap().frame
    else {
        panic!("expected authenticated terminal open");
    };
    leg_b_send(&mut peer, 0, &Frame::Result { call_id, ok: false, json: br#"{"error":"terminal unavailable","reason":"host_memory_low","available_mib":180,"session_count":212}"# }).await;
    // Keep timer advancement out of the observed reply: real SQLite/network I/O
    // must finish before unrelated heartbeat frames can enter this assertion.
    let response = read_client_frame(&mut browser).await;
    drop(clock);
    let Frame::Result {
        call_id: 151,
        ok: false,
        json,
    } = decode_muxed_frame(&response).unwrap().frame
    else {
        panic!("expected refused browser open");
    };
    let body: serde_json::Value = serde_json::from_slice(json).unwrap();
    server.abort();
    assert_eq!(body["reason"], "host_memory_low");
    assert_eq!(body["available_mib"], 180);
    assert_eq!(body["session_count"], 212);
}
