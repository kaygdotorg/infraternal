//! Real browser and agent close records across terminal stream failure paths.
use super::*;
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use std::{
    io::Write,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};

#[derive(Clone, Default)]
struct Capture(Arc<StdMutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

impl Capture {
    fn start() -> (Self, tracing::subscriber::DefaultGuard) {
        let capture = Self::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_writer(capture.clone())
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (capture, guard)
    }

    fn events(&self, name: &str) -> Vec<serde_json::Value> {
        crate::stream_close::settled();
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .filter(|event: &serde_json::Value| event["fields"]["event"] == name)
            .collect()
    }
}

#[tokio::test]
async fn rootless_attach_without_a_live_peer_logs_the_host_and_keeps_the_socket_up() {
    let _serial = SERIAL.lock().await;
    let (capture, _subscriber) = Capture::start();
    let f = fixture().await;
    let host_id = Uuid::new_v4();
    let session_id = [0x73; 16];
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootless',1002,1)")
        .bind(host_id.as_bytes().as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,remote_host_id) VALUES(?,?,1,1,?)")
        .bind(session_id.as_slice())
        .bind(&f.user)
        .bind(host_id.as_bytes().as_slice())
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let (f, address, server) = socket_fixture_from_fixture(f, None).await;
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
            client_info: "rootless-close-log",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    client_ws_send(
        &mut browser,
        1,
        &Frame::AttachTerm {
            session_id: &session_id,
            last_out_seq: 128,
            last_in_seq: 0,
        },
    )
    .await;
    let close = read_client_frame(&mut browser).await;
    assert!(matches!(
        decode_muxed_frame(&close).unwrap().frame,
        Frame::Close {
            code: 1013,
            reason: "the host could not accept the terminal attachment"
        }
    ));
    client_ws_send(
        &mut browser,
        0,
        &Frame::Ping {
            nonce: 227,
            sent_us: 0,
        },
    )
    .await;
    assert!(matches!(
        decode_muxed_frame(&read_client_frame(&mut browser).await)
            .unwrap()
            .frame,
        Frame::Pong { nonce: 227, .. }
    ));

    let events = capture.events("terminal_stream_closed");
    assert_eq!(events.len(), 1);
    let fields = &events[0]["fields"];
    assert_eq!(fields["who"], "server");
    assert_eq!(fields["reason_category"], "agent_connection_refused");
    assert_eq!(fields["reason"], "terminal_attach_unavailable");
    assert_eq!(fields["host_id"], host_id.to_string());
    assert_eq!(
        fields["session_id"],
        Uuid::from_bytes(session_id).to_string()
    );
    assert_eq!(fields["out_seq"], 128);
    assert_eq!(fields["input_acked"], 0);
    assert_eq!(fields["input_sent"], 0);
    assert_eq!(capture.events("terminal_stream_close_summary").len(), 0);
    server.abort();
}

#[tokio::test]
async fn agent_stream_loss_logs_its_safe_close_reason_and_reaches_the_browser() {
    let _serial = SERIAL.lock().await;
    let (capture, _subscriber) = Capture::start();
    let f = fixture().await;
    let session_id = [0x74; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)")
        .bind(session_id.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let (socket, mut host) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = crate::websocket::router(state);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (close_observed, browser_observed_close) = tokio::sync::oneshot::channel();
    let agent = tokio::spawn(async move {
        let mut encoded = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "close-log-fixture",
            },
            &mut encoded,
        )
        .unwrap();
        host.write_all(&encoded).await.unwrap();
        let mut buffer = Vec::new();
        loop {
            let mut chunk = [0_u8; 4096];
            let read = host.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0);
            buffer.extend_from_slice(&chunk[..read]);
            while let Ok(decoded) = decode_muxed_frame(&buffer) {
                let (stream, wire_len) = (decoded.stream_id, decoded.wire_len);
                if matches!(decoded.frame, Frame::AttachTerm { .. }) {
                    encoded.clear();
                    encode_muxed_frame_into(
                        stream,
                        &Frame::Close {
                            code: 1013,
                            reason: "remote stream unavailable",
                        },
                        &mut encoded,
                    )
                    .unwrap();
                    host.write_all(&encoded).await.unwrap();
                    // Keep the host connection until this stream Close reaches
                    // the browser. Transport EOF may instead start reconnecting
                    // before an unread stream Close has been dispatched.
                    let _ = browser_observed_close.await;
                    return;
                }
                buffer.drain(..wire_len);
            }
        }
    });
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
            client_info: "agent-close-log",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    client_ws_send(
        &mut browser,
        1,
        &Frame::AttachTerm {
            session_id: &session_id,
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    let close = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let wire = read_client_frame(&mut browser).await;
            if matches!(
                decode_muxed_frame(&wire).unwrap().frame,
                Frame::Close { .. }
            ) {
                break wire;
            }
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        decode_muxed_frame(&close).unwrap().frame,
        Frame::Close {
            code: 1013,
            reason: "remote stream unavailable"
        }
    ));
    let events = capture.events("terminal_stream_closed");
    assert_eq!(events.len(), 1);
    let fields = &events[0]["fields"];
    assert_eq!(fields["who"], "infraternal_agent");
    assert_eq!(fields["reason_category"], "agent_connection_dropped");
    assert_eq!(fields["reason"], "server_link_lost");
    assert_eq!(
        fields["session_id"],
        Uuid::from_bytes(session_id).to_string()
    );
    assert_eq!(fields["agent_close_code"], 1013);
    assert_eq!(fields["agent_close_reason"], "remote stream unavailable");
    close_observed.send(()).unwrap();
    agent.await.unwrap();
    server.abort();
}

#[tokio::test]
async fn browser_websocket_close_logs_its_code_and_safe_reason_for_attached_sessions() {
    let _serial = SERIAL.lock().await;
    let (capture, _subscriber) = Capture::start();
    let f = fixture().await;
    let session_id = [0x75; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)")
        .bind(session_id.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let (socket, mut host) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = crate::websocket::router(state);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let agent = tokio::spawn(async move {
        let mut encoded = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "close-log-fixture",
            },
            &mut encoded,
        )
        .unwrap();
        host.write_all(&encoded).await.unwrap();
        let mut buffer = Vec::new();
        loop {
            let mut chunk = [0_u8; 4096];
            let read = host.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0);
            buffer.extend_from_slice(&chunk[..read]);
            while let Ok(decoded) = decode_muxed_frame(&buffer) {
                let wire_len = decoded.wire_len;
                let attached = matches!(decoded.frame, Frame::AttachTerm { .. });
                buffer.drain(..wire_len);
                if attached {
                    std::future::pending::<()>().await;
                }
            }
        }
    });
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
            client_info: "browser-close-log",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    client_ws_send(
        &mut browser,
        1,
        &Frame::AttachTerm {
            session_id: &session_id,
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    assert!(matches!(
        decode_muxed_frame(&read_client_frame(&mut browser).await)
            .unwrap()
            .frame,
        Frame::Ack { in_seq_acked: 0 }
    ));
    browser
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Normal,
            reason: "window closed".into(),
        })))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if !capture.events("terminal_stream_closed").is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let events = capture.events("terminal_stream_closed");
    assert_eq!(events.len(), 1);
    let fields = &events[0]["fields"];
    assert_eq!(fields["who"], "browser");
    assert_eq!(fields["reason_category"], "client_went_away");
    assert_eq!(fields["websocket_code"], 1000);
    assert_eq!(fields["websocket_reason"], "window closed");
    assert_eq!(
        fields["session_id"],
        Uuid::from_bytes(session_id).to_string()
    );
    agent.abort();
    server.abort();
}

#[tokio::test]
async fn failed_client_resume_attempt_logs_each_retained_session() {
    let _serial = SERIAL.lock().await;
    let (capture, _subscriber) = Capture::start();
    let f = fixture().await;
    let session_id = [0x76; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)")
        .bind(session_id.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let (socket, mut host) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = crate::websocket::router(state);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let agent = tokio::spawn(async move {
        let mut encoded = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "close-log-fixture",
            },
            &mut encoded,
        )
        .unwrap();
        host.write_all(&encoded).await.unwrap();
        let mut buffer = Vec::new();
        loop {
            let mut chunk = [0_u8; 4096];
            let read = host.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0);
            buffer.extend_from_slice(&chunk[..read]);
            while let Ok(decoded) = decode_muxed_frame(&buffer) {
                let wire_len = decoded.wire_len;
                let attached = matches!(decoded.frame, Frame::AttachTerm { .. });
                buffer.drain(..wire_len);
                if attached {
                    std::future::pending::<()>().await;
                }
            }
        }
    });
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
            client_info: "resume-close-log",
        },
    )
    .await;
    let (connection_id, _) = read_welcome(&mut browser).await;
    client_ws_send(
        &mut browser,
        1,
        &Frame::AttachTerm {
            session_id: &session_id,
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    assert!(matches!(
        decode_muxed_frame(&read_client_frame(&mut browser).await)
            .unwrap()
            .frame,
        Frame::Ack { in_seq_acked: 0 }
    ));
    browser
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Normal,
            reason: "window closed".into(),
        })))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let active: Option<i64> = sqlx::query_scalar(
                "SELECT active FROM websocket_connections WHERE connection_id=?",
            )
            .bind(connection_id.as_slice())
            .fetch_optional(&f.auth.pool)
            .await
            .unwrap();
            if active == Some(0) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    server.abort();
    agent.abort();

    let (unused_socket, _unused_peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(unused_socket),
    )
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = crate::websocket::router(state);
    let resumed_server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (mut retry, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut retry).await;
    // Hello (with the resume capability) and Resume travel in one message, as the
    // browser sends them; the server reads them as an adjacent pair.
    let invalid_resume_token = [0xFF; 32];
    let mut wire = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Hello {
            version: 1,
            caps: 1,
            client_info: "failed-resume-close-log",
        },
        &mut wire,
    )
    .unwrap();
    let mut resume = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Resume {
            connection_id: &connection_id,
            resume_token: &invalid_resume_token,
        },
        &mut resume,
    )
    .unwrap();
    wire.extend_from_slice(&resume);
    retry.send(Message::Binary(wire.into())).await.unwrap();
    let refusal = read_client_frame(&mut retry).await;
    let refusal = decode_muxed_frame(&refusal).unwrap().frame;
    assert!(
        matches!(
            refusal,
            Frame::Close {
                code: 1008,
                reason: "the server refused to resume the connection"
            }
        ),
        "unexpected refusal frame: {refusal:?}"
    );
    // The server names the refused sessions after it has closed the socket.
    let resumed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(event) = capture
                .events("terminal_stream_closed")
                .into_iter()
                .find(|event| event["fields"]["reason"] == "connection_resume_refused")
            {
                break event;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(resumed["fields"]["who"], "server");
    assert_eq!(resumed["fields"]["reason_category"], "auth_resume_refusal");
    assert_eq!(
        resumed["fields"]["session_id"],
        Uuid::from_bytes(session_id).to_string()
    );
    assert_eq!(resumed["fields"]["browser_stream_id"], 1);
    resumed_server.abort();
}

/// A frame whose authority read misses its bound is a busy server, not a bad frame.
/// Holding the test pool's one connection stalls every read; the socket must log the
/// stall as `authority_unavailable` and never as an invalid protocol frame.
#[tokio::test]
async fn authority_read_timeout_during_a_frame_logs_authority_unavailable() {
    let _serial = SERIAL.lock().await;
    let (capture, _subscriber) = Capture::start();
    let f = fixture().await;
    let session_id = [0x75; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)")
        .bind(session_id.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let (socket, mut host) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap()
    .with_authority_read_timeout(Duration::from_millis(100));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = crate::websocket::router(state);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    // The host accepts the attach and answers link probes; it never closes the stream.
    let agent = tokio::spawn(async move {
        let mut encoded = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "authority-busy-fixture",
            },
            &mut encoded,
        )
        .unwrap();
        host.write_all(&encoded).await.unwrap();
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let read = host.read(&mut chunk).await.unwrap();
            if read == 0 {
                return;
            }
            buffer.extend_from_slice(&chunk[..read]);
            while let Ok(decoded) = decode_muxed_frame(&buffer) {
                let (stream, wire_len) = (decoded.stream_id, decoded.wire_len);
                let reply = match decoded.frame {
                    Frame::AttachTerm { .. } => Some(Frame::Ack { in_seq_acked: 0 }),
                    Frame::Ping { nonce, sent_us } => Some(Frame::Pong { nonce, sent_us }),
                    _ => None,
                };
                if let Some(reply) = reply {
                    encode_muxed_frame_into(stream, &reply, &mut encoded).unwrap();
                    host.write_all(&encoded).await.unwrap();
                }
                buffer.drain(..wire_len);
            }
        }
    });
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
            client_info: "authority-busy",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    client_ws_send(
        &mut browser,
        1,
        &Frame::AttachTerm {
            session_id: &session_id,
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let wire = read_client_frame(&mut browser).await;
            let decoded = decode_muxed_frame(&wire).unwrap();
            if decoded.stream_id == 1 {
                assert!(matches!(decoded.frame, Frame::Ack { .. }));
                break;
            }
        }
    })
    .await
    .unwrap();
    // The pool has one connection: holding it makes every authority read wait out its bound.
    let held = f.auth.pool.acquire().await.unwrap();
    client_ws_send(
        &mut browser,
        1,
        &Frame::Resize {
            cols: 100,
            rows: 30,
            px_w: 0,
            px_h: 0,
        },
    )
    .await;
    let events = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let events = capture.events("terminal_stream_closed");
            if !events.is_empty() {
                break events;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the stalled socket must log its close");
    drop(held);
    assert_eq!(events.len(), 1);
    let fields = &events[0]["fields"];
    assert_eq!(fields["who"], "server");
    assert_eq!(fields["reason_category"], "server_busy", "{fields}");
    assert_eq!(fields["reason"], "authority_unavailable", "{fields}");
    assert_eq!(
        fields["session_id"],
        Uuid::from_bytes(session_id).to_string()
    );
    agent.abort();
    server.abort();
}

/// A store that cannot answer the attach's session lookup is a busy server, not a bad frame.
#[tokio::test]
async fn session_lookup_store_error_logs_authority_unavailable() {
    let _serial = SERIAL.lock().await;
    let (capture, _subscriber) = Capture::start();
    let f = fixture().await;
    let session_id = [0x76; 16];
    let (socket, _host) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = crate::websocket::router(state);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
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
            client_info: "lookup-error",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    // The lookup reads this table; renaming it makes the query fail while authority still reads live.
    sqlx::query("ALTER TABLE terminal_sessions RENAME TO terminal_sessions_gone")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    client_ws_send(
        &mut browser,
        1,
        &Frame::AttachTerm {
            session_id: &session_id,
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    let events = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let events = capture.events("terminal_stream_closed");
            if !events.is_empty() {
                break events;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the failed lookup must log its close");
    let fields = &events[0]["fields"];
    assert_eq!(fields["reason"], "authority_unavailable", "{fields}");
    server.abort();
}

/// Audit 9.3 (#240): a revocation wake that meets a busy store is a busy server, not
/// a refused resume. The session here is never revoked; only the store is slow.
#[tokio::test]
async fn revocation_wake_on_busy_store_logs_authority_unavailable_not_resume_refused() {
    revocation_stall(RevocationStall::Unavailable).await;
}

#[tokio::test(start_paused = true)]
async fn unrelated_logout_during_transient_stall_keeps_the_terminal_socket() {
    revocation_stall(RevocationStall::OtherAccount).await;
}

#[tokio::test(start_paused = true)]
async fn revoked_session_during_transient_stall_logs_resume_refused() {
    revocation_stall(RevocationStall::Revoked).await;
}

/// A missed wake read already exhausted its authority wait. Stream cleanup
/// must not inherit an additional classification read before releasing it.
#[tokio::test(start_paused = true)]
async fn revoked_busy_wake_records_stream_end_within_the_existing_wait() {
    revocation_stall(RevocationStall::RevokedEndDeadline).await;
}

#[derive(Clone, Copy)]
enum RevocationStall {
    Unavailable,
    OtherAccount,
    Revoked,
    RevokedEndDeadline,
}

/// Share the attached-terminal fixture so the only varying inputs are whose
/// session is deleted and whether the store recovers within the authority wait.
async fn revocation_stall(stall: RevocationStall) {
    let _serial = SERIAL.lock().await;
    let clock = if matches!(stall, RevocationStall::Unavailable) {
        None
    } else {
        Some(FrozenSocketTime::new().await)
    };
    let (capture, _subscriber) = Capture::start();
    let f = fixture().await;
    let session_id = [0x75; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)")
        .bind(session_id.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let (socket, mut host) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap()
    .with_authority_read_timeout(Duration::from_millis(100));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let pending_reads = state.authority_read_monitor();
    let app = crate::websocket::router(state);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    // The host accepts the attach and answers link probes; it never closes the stream.
    let agent = tokio::spawn(async move {
        let mut encoded = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "authority-busy-fixture",
            },
            &mut encoded,
        )
        .unwrap();
        host.write_all(&encoded).await.unwrap();
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let read = host.read(&mut chunk).await.unwrap();
            if read == 0 {
                return;
            }
            buffer.extend_from_slice(&chunk[..read]);
            while let Ok(decoded) = decode_muxed_frame(&buffer) {
                let (stream, wire_len) = (decoded.stream_id, decoded.wire_len);
                let reply = match decoded.frame {
                    Frame::AttachTerm { .. } => Some(Frame::Ack { in_seq_acked: 0 }),
                    Frame::Ping { nonce, sent_us } => Some(Frame::Pong { nonce, sent_us }),
                    _ => None,
                };
                if let Some(reply) = reply {
                    encode_muxed_frame_into(stream, &reply, &mut encoded).unwrap();
                    host.write_all(&encoded).await.unwrap();
                }
                buffer.drain(..wire_len);
            }
        }
    });
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
            caps: if clock.is_some() { 4 } else { 0 },
            client_info: "authority-busy",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    client_ws_send(
        &mut browser,
        1,
        &Frame::AttachTerm {
            session_id: &session_id,
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let wire = read_client_frame(&mut browser).await;
            let decoded = decode_muxed_frame(&wire).unwrap();
            if decoded.stream_id == 1 {
                assert!(matches!(decoded.frame, Frame::Ack { .. }));
                break;
            }
        }
    })
    .await
    .unwrap();
    // A result after the attach is a main-loop barrier: its guarded attach work
    // is complete before the stall, so this tests the wake rather than that work.
    authorized_result(&mut browser, 241).await;
    if clock.is_some() {
        // Park probes to isolate session authority from the independent liveness
        // clock. The correlated proof fences consumption of the visibility notice.
        client_ws_send(
            &mut browser,
            0,
            &Frame::Event {
                sub_id: 0,
                event_json: br#"{"topic":"connection.visibility","hidden":true}"#,
            },
        )
        .await;
        client_ws_send(
            &mut browser,
            0,
            &Frame::Ping {
                nonce: 240,
                sent_us: 0,
            },
        )
        .await;
        // Attached-terminal notices can precede the correlated control reply.
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let wire = read_client_frame(&mut browser).await;
                let decoded = decode_muxed_frame(&wire).unwrap();
                match decoded.frame {
                    Frame::Pong { nonce: 240, .. } if decoded.stream_id == 0 => break,
                    Frame::Close { .. } => {
                        panic!("the terminal closed before the visibility fence")
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("the visibility proof must complete before the stall");
    }
    // The pool has one connection: holding it makes every authority read wait out its bound.
    let mut held = f.auth.pool.acquire().await.unwrap();
    if matches!(stall, RevocationStall::OtherAccount) {
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash) VALUES('other-account','other',0,'unused')")
            .execute(&mut *held).await.unwrap();
        sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES('other-session','other-account','test',unixepoch()+600,unixepoch(),1)")
            .execute(&mut *held).await.unwrap();
    }
    // Perform the same committed DELETE then publication as logout, on the held
    // connection: no pool-release race can let a socket read before the stall.
    let user = if matches!(stall, RevocationStall::OtherAccount) {
        "other-account"
    } else {
        &f.user
    };
    if matches!(
        stall,
        RevocationStall::OtherAccount
            | RevocationStall::Revoked
            | RevocationStall::RevokedEndDeadline
    ) {
        let deleted = sqlx::query("DELETE FROM sessions WHERE user_id=?")
            .bind(user)
            .execute(&mut *held)
            .await
            .unwrap()
            .rows_affected();
        assert_eq!(deleted, 1);
    }
    f.auth.revocations.publish(user, None);
    if matches!(stall, RevocationStall::RevokedEndDeadline) {
        while pending_reads() == 0 {
            tokio::task::yield_now().await;
        }
        let started = tokio::time::Instant::now();
        while started.elapsed() < Duration::from_secs(1) {
            tokio::time::advance(Duration::from_millis(5)).await;
            for _ in 0..32 {
                tokio::task::yield_now().await;
            }
        }
        let events = capture.events("terminal_stream_closed");
        drop(held);
        agent.abort();
        server.abort();
        assert!(
            !events.is_empty(),
            "stream cleanup waited beyond the existing authority wait for another classification read"
        );
        return;
    }
    let release = if matches!(stall, RevocationStall::OtherAccount) {
        // The unrelated account cannot start an authority read while storage is held.
        for _ in 0..60 {
            tokio::time::advance(Duration::from_millis(5)).await;
            for _ in 0..32 {
                tokio::task::yield_now().await;
            }
            assert_eq!(pending_reads(), 0);
        }
        drop(held);
        None
    } else if clock.is_some() {
        tokio::time::timeout(Duration::from_secs(1), async {
            while pending_reads() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the revocation wake must begin an authority read");
        let started = tokio::time::Instant::now();
        // There are at most two socket checkers. Three held queries prove that
        // a missed attempt was retried, while the explicit clock stays below
        // the one-second authority wait. Freeze again as soon as a retry starts
        // so real SQL completion cannot lose its budget to host scheduling.
        while pending_reads() < 3 {
            assert!(
                started.elapsed() < Duration::from_millis(300),
                "no retry before the short stall ended"
            );
            tokio::time::advance(Duration::from_millis(5)).await;
            tokio::task::yield_now().await;
        }
        drop(held);
        None
    } else {
        Some(tokio::spawn(async move {
            std::future::pending::<()>().await;
            drop(held);
        }))
    };
    if matches!(stall, RevocationStall::OtherAccount) {
        // An action result proves application authority recovered; a transport
        // pong alone would bypass SQL and could conceal a closed terminal loop.
        authorized_result(&mut browser, 240).await;
        assert_eq!(
            capture.events("terminal_stream_closed"),
            Vec::<serde_json::Value>::new()
        );
        agent.abort();
        server.abort();
        return;
    }
    let events = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let events = capture.events("terminal_stream_closed");
            if !events.is_empty() {
                break events;
            }
            if clock.is_some() {
                tokio::task::yield_now().await;
            } else {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    })
    .await
    .expect("the stalled socket must log its close");
    if let Some(release) = release {
        release.abort();
        let _ = release.await;
    }
    assert_eq!(events.len(), 1);
    let fields = &events[0]["fields"];
    assert_eq!(fields["who"], "server");
    let (category, reason) = if matches!(stall, RevocationStall::Revoked) {
        ("auth_resume_refusal", "connection_resume_refused")
    } else {
        ("server_busy", "authority_unavailable")
    };
    assert_eq!(fields["reason_category"], category, "{fields}");
    assert_eq!(fields["reason"], reason, "{fields}");
    assert_eq!(
        fields["session_id"],
        Uuid::from_bytes(session_id).to_string()
    );
    agent.abort();
    server.abort();
}

/// Application progress is a stronger barrier than a content-free proof: the
/// result requires authority and runs after previously queued terminal work.
pub(super) async fn authorized_result(
    browser: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    call_id: u32,
) {
    client_ws_send(
        browser,
        0,
        &Frame::Call {
            call_id,
            action_id: "test.not.an.action",
            input_json: b"{}",
        },
    )
    .await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let wire = read_client_frame(browser).await;
            match decode_muxed_frame(&wire).unwrap().frame {
                Frame::Result {
                    call_id: actual, ..
                } if actual == call_id => break,
                Frame::Close { .. } => panic!("authority wake closed the terminal socket"),
                _ => {}
            }
        }
    })
    .await
    .unwrap();
}
