//! Independent #199 review: pending terminal creation must not retire an otherwise responsive multiplexed socket.
use super::*;

enum Observation {
    Warm,
    Opened,
    ProbeAfterOpen,
    Closed,
}

/// The selected session and both control transports remain responsive while one action reply is held.
async fn responsive_backend(
    mut peer: UnixStream,
    entered: tokio::sync::oneshot::Sender<()>,
    mut release: tokio::sync::oneshot::Receiver<()>,
) {
    let initial = [1; 16];
    let created = [2; 16];
    let mut encoded = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "restart open review",
        },
        &mut encoded,
    )
    .unwrap();
    peer.write_all(&encoded).await.unwrap();
    let inventory = serde_json::to_vec(&json!({
        "type": "terminal.sessions.snapshot", "session_ids": [Uuid::from_bytes(initial).to_string()],
    })).unwrap();
    encode_muxed_frame_into(
        0,
        &Frame::Event {
            sub_id: 0,
            event_json: &inventory,
        },
        &mut encoded,
    )
    .unwrap();
    peer.write_all(&encoded).await.unwrap();
    let mut entered = Some(entered);
    let mut pending = None;
    let mut buffer = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        tokio::select! {
            _ = &mut release, if pending.is_some() => {
                let call_id = pending.take().unwrap();
                let inventory = serde_json::to_vec(&json!({
                    "type": "terminal.sessions.snapshot", "session_ids": [Uuid::from_bytes(initial).to_string(), Uuid::from_bytes(created).to_string()],
                })).unwrap();
                encode_muxed_frame_into(0, &Frame::Event { sub_id: 0, event_json: &inventory }, &mut encoded).unwrap();
                peer.write_all(&encoded).await.unwrap();
                let result = serde_json::to_vec(&json!({"session_id": Uuid::from_bytes(created).to_string()})).unwrap();
                encode_muxed_frame_into(0, &Frame::Result { call_id, ok: true, json: &result }, &mut encoded).unwrap();
                peer.write_all(&encoded).await.unwrap();
            }
            read = peer.read(&mut chunk) => {
                let read = read.unwrap();
                if read == 0 { return; }
                buffer.extend_from_slice(&chunk[..read]);
                while let Ok(decoded) = decode_muxed_frame(&buffer) {
                    let stream = decoded.stream_id;
                    let length = decoded.wire_len;
                    let reply = match decoded.frame {
                        Frame::Ping { nonce, sent_us } => Some(Frame::Pong { nonce, sent_us }),
                        Frame::AttachTerm { .. } => Some(Frame::Ack { in_seq_acked: 0 }),
                        Frame::Call { call_id, action_id: "terminal.open", .. } => {
                            pending = Some(call_id);
                            entered.take().unwrap().send(()).unwrap();
                            None
                        }
                        _ => None,
                    };
                    if let Some(reply) = reply {
                        encode_muxed_frame_into(stream, &reply, &mut encoded).unwrap();
                        if peer.write_all(&encoded).await.is_err() { return; }
                    }
                    buffer.drain(..length);
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Independent #199 regression: run explicitly with --ignored"]
#[allow(clippy::too_many_lines)]
async fn responsive_socket_survives_a_held_terminal_open_with_an_existing_attachment() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let existing = [1; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)")
        .bind(existing.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let (socket, peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap()
    .with_authority_read_timeout(Duration::from_secs(2));
    let (entered, held) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let backend = tokio::spawn(responsive_backend(peer, entered, released));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = crate::websocket::router(state);
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
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
            client_info: "restart open review",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    client_ws_send(
        &mut socket,
        1,
        &Frame::AttachTerm {
            session_id: &existing,
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    let (commands, mut command_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (observations, mut observation_rx) = tokio::sync::mpsc::channel(8);
    let client = tokio::spawn(async move {
        let mut sampled = false;
        let mut opened = false;
        loop {
            tokio::select! {
                command = command_rx.recv() => {
                    if command.is_none() { return; }
                    client_ws_send(&mut socket, 0, &Frame::Call {
                        call_id: 901, action_id: "terminal.open", input_json: br#"{"cols":80,"rows":24,"px_w":0,"px_h":0}"#,
                    }).await;
                }
                message = socket.next() => {
                    let Some(Ok(Message::Binary(wire))) = message else {
                        let _ = observations.send(Observation::Closed).await;
                        return;
                    };
                    let decoded = decode_muxed_frame(&wire).unwrap();
                    match decoded.frame {
                        Frame::Ping { nonce, sent_us } => {
                            client_ws_send(&mut socket, decoded.stream_id, &Frame::Pong { nonce, sent_us }).await;
                            if opened { let _ = observations.send(Observation::ProbeAfterOpen).await; }
                            else if !sampled {
                                sampled = true;
                                // TCP ordering makes this response a barrier: the server
                                // consumed the correlated Pong before replying to our Ping.
                                client_ws_send(&mut socket, 0, &Frame::Ping { nonce: 991, sent_us: 0 }).await;
                            }
                        }
                        Frame::Pong { nonce: 991, .. } => { let _ = observations.send(Observation::Warm).await; }
                        Frame::Result { call_id: 901, ok: true, .. } => {
                            opened = true;
                            let _ = observations.send(Observation::Opened).await;
                        }
                        Frame::Close { .. } => {
                            let _ = observations.send(Observation::Closed).await;
                            return;
                        }
                        _ => {}
                    }
                }
            }
        }
    });
    let warm = tokio::time::timeout(Duration::from_secs(20), observation_rx.recv())
        .await
        .unwrap();
    assert!(
        matches!(warm, Some(Observation::Warm)),
        "fixture must establish a sampled healthy route"
    );
    commands.send(()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(20), held)
        .await
        .unwrap()
        .unwrap();
    // Hold the operation rather than either transport. No latency is measured;
    // both peers keep answering every probe while the action remains pending.
    tokio::time::sleep(Duration::from_millis(350)).await;
    release.send(()).unwrap();
    let opened = tokio::time::timeout(Duration::from_secs(20), observation_rx.recv())
        .await
        .unwrap();
    let next = tokio::time::timeout(Duration::from_secs(20), observation_rx.recv())
        .await
        .unwrap();
    client.abort();
    backend.abort();
    server.abort();
    assert!(
        matches!(opened, Some(Observation::Opened)),
        "held operation must complete successfully"
    );
    assert!(
        matches!(next, Some(Observation::ProbeAfterOpen)),
        "responsive socket stopped after a successful ordinary operation"
    );
}
