//! Final and transient host closes absorb late terminal frames while the shared socket stays up (#158, #250).
//!
//! Before this, the browser's attach either closed the whole socket (a session whose
//! exit was recorded), so the page reconnected and attached again at once, or reached
//! the infraternal agent, which failed its whole channel and was restarted by the
//! server about twice a second while the window looked live and stayed blank.
use super::*;
use infraternal_protocol::{CLOSE_SESSION_GONE, SESSION_GONE_REASON};

/// Opens an authenticated, welcomed browser socket.
async fn welcomed(
    address: SocketAddr,
    session: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
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
            client_info: "gone",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    socket
}

/// Sends what a browser sends to attach (`AttachTerm`, `Credit`, `Resize`), then a late
/// `Input` and its own `Close`, then a control `Ping`. Returns the frames up to the Pong.
async fn attach_and_fence<S>(
    socket: &mut S,
    session: &[u8; 16],
    expected_code: u16,
    expected_reason: &str,
) -> Vec<(u32, String)>
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    client_ws_send(
        socket,
        1,
        &Frame::AttachTerm {
            session_id: session,
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    client_ws_send(socket, 1, &Frame::Credit { bytes: 65_536 }).await;
    client_ws_send(
        socket,
        1,
        &Frame::Resize {
            cols: 80,
            rows: 24,
            px_w: 0,
            px_h: 0,
        },
    )
    .await;
    let mut seen = Vec::new();
    loop {
        let wire = read_client_frame(socket).await;
        let decoded = decode_muxed_frame(&wire).unwrap();
        match decoded.frame {
            Frame::Close { code, reason } => {
                assert_eq!(
                    code, expected_code,
                    "the close must retain its typed reason"
                );
                assert_eq!(reason, expected_reason);
                seen.push((decoded.stream_id, "gone".to_owned()));
                break;
            }
            Frame::Ack { .. } => seen.push((decoded.stream_id, "ack".to_owned())),
            other => panic!("unexpected frame before the final close: {other:?}"),
        }
    }
    // Credit and geometry can already be in flight when the host closes.
    client_ws_send(socket, 1, &Frame::Credit { bytes: 4096 }).await;
    client_ws_send(
        socket,
        1,
        &Frame::Resize {
            cols: 80,
            rows: 24,
            px_w: 0,
            px_h: 0,
        },
    )
    .await;
    // Typing that crossed the Close, then the browser's own Close: all are absorbed.
    client_ws_send(
        socket,
        1,
        &Frame::Input {
            in_seq: 0,
            bytes: b"ls\r",
        },
    )
    .await;
    client_ws_send(
        socket,
        1,
        &Frame::Close {
            code: 1000,
            reason: "window closed",
        },
    )
    .await;
    client_ws_send(
        socket,
        0,
        &Frame::Ping {
            nonce: 158,
            sent_us: 0,
        },
    )
    .await;
    let pong = read_client_frame(socket).await;
    assert!(
        matches!(
            decode_muxed_frame(&pong).unwrap().frame,
            Frame::Pong { nonce: 158, .. }
        ),
        "the socket must stay up after a final stream close"
    );
    seen
}

#[tokio::test]
async fn an_ended_or_unknown_session_gets_the_final_close_without_losing_the_socket() {
    let _guard = SERIAL.lock().await;
    let (f, address, server) = socket_fixture().await;
    // A shell whose exit the server recorded, and an id this account never had.
    let ended = [0x51_u8; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,closed_at,exit_status) VALUES(?,?,1,1,2,0)")
        .bind(ended.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    for session in [ended, [0x52_u8; 16]] {
        let mut socket = welcomed(address, &f.session).await;
        let seen = attach_and_fence(
            &mut socket,
            &session,
            CLOSE_SESSION_GONE,
            SESSION_GONE_REASON,
        )
        .await;
        assert_eq!(
            seen,
            vec![(1, "gone".to_owned())],
            "no attach may reach the infraternal agent"
        );
    }
    server.abort();
}

#[tokio::test]
async fn the_infraternal_agent_saying_gone_reaches_the_browser_as_the_final_close() {
    host_close_preserves_socket(CLOSE_SESSION_GONE, SESSION_GONE_REASON).await;
}

#[tokio::test]
async fn transient_host_close_absorbs_inflight_credit_resize_and_input() {
    host_close_preserves_socket(1, "terminal shim disconnected").await;
}

/// Exercise the real socket with one deterministic host-side close before late browser frames.
async fn host_close_preserves_socket(code: u16, reason: &'static str) {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let (socket, mut agent) = UnixStream::pair().unwrap();
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
    // A session the database still calls live, whose shim is gone on the host.
    let session = [0x53_u8; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)")
        .bind(session.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    // The fake infraternal agent: greet, then answer the AttachTerm as the real one does.
    let host = tokio::spawn(async move {
        let mut buffer = Vec::new();
        let mut encoded = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "agent",
            },
            &mut encoded,
        )
        .unwrap();
        agent.write_all(&encoded).await.unwrap();
        loop {
            let mut chunk = [0_u8; 4096];
            let read = agent.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0);
            buffer.extend_from_slice(&chunk[..read]);
            while let Ok(decoded) = decode_muxed_frame(&buffer) {
                let (stream, wire_len) = (decoded.stream_id, decoded.wire_len);
                if let Frame::AttachTerm { session_id, .. } = decoded.frame {
                    assert_eq!(session_id, &[0x53_u8; 16]);
                    encoded.clear();
                    let gone = Frame::Close { code, reason };
                    encode_muxed_frame_into(stream, &gone, &mut encoded).unwrap();
                    agent.write_all(&encoded).await.unwrap();
                }
                buffer.drain(..wire_len);
            }
        }
    });
    let mut socket = welcomed(address, &f.session).await;
    let seen = attach_and_fence(&mut socket, &session, code, reason).await;
    assert_eq!(seen, vec![(1, "ack".to_owned()), (1, "gone".to_owned())]);
    host.abort();
    server.abort();
}
