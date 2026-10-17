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
#[allow(clippy::too_many_lines)] // Keep the real agent socket exchange and structured assertions together.
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
    agent.abort();
    server.abort();
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep the real browser close exchange and log assertions together.
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
#[allow(clippy::too_many_lines)] // Keep resume setup, failed handshake, and retained-session assertions together.
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
    client_ws_send(
        &mut retry,
        0,
        &Frame::Hello {
            version: 1,
            caps: 1,
            client_info: "failed-resume-close-log",
        },
    )
    .await;
    let invalid_resume_token = [0xFF; 32];
    client_ws_send(
        &mut retry,
        0,
        &Frame::Resume {
            connection_id: &connection_id,
            resume_token: &invalid_resume_token,
        },
    )
    .await;
    assert!(matches!(
        decode_muxed_frame(&read_client_frame(&mut retry).await)
            .unwrap()
            .frame,
        Frame::Close {
            code: 1008,
            reason: "the server refused to resume the connection"
        }
    ));
    let events = capture.events("terminal_stream_closed");
    let resumed = events
        .iter()
        .find(|event| event["fields"]["reason"] == "connection_resume_refused")
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
