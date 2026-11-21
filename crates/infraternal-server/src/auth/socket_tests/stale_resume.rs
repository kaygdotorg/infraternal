//! A resume whose window ran out is welcomed fresh on the same socket (#569, D265).
//!
//! Coming back after more than the resume window used to cost a Close 1008, a backoff and a second handshake before
//! the page could attach again. The server now answers a stale Resume with a fresh Welcome on the socket it arrived
//! on: a new connection id and token, never the old connection's writers. These tests drive the real socket handler.
//! An ended cookie session is not stale and still closes without a Welcome; `review3_tests` covers that path.
use super::*;
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Opens a socket, sends Hello with the resume capability and the given Resume in one message, as the browser does.
async fn resume_on_new_socket(
    address: SocketAddr,
    cookie: &str,
    connection_id: &[u8; 16],
    resume_token: &[u8; 32],
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let (mut socket, _) = connect_async(test_ws_request(address, cookie))
        .await
        .unwrap();
    assert_server_hello(&mut socket).await;
    let mut wire = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Hello {
            version: 1,
            caps: 1,
            client_info: "stale-resume",
        },
        &mut wire,
    )
    .unwrap();
    let mut resume = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Resume {
            connection_id,
            resume_token,
        },
        &mut resume,
    )
    .unwrap();
    wire.extend_from_slice(&resume);
    socket.send(Message::Binary(wire.into())).await.unwrap();
    socket
}

/// Waits until the server has marked a dropped connection resumable (inactive, with an expiry).
async fn wait_inactive(pool: &sqlx::SqlitePool, connection_id: &[u8; 16]) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let active: Option<i64> = sqlx::query_scalar(
                "SELECT active FROM websocket_connections WHERE connection_id=?",
            )
            .bind(connection_id.as_slice())
            .fetch_optional(pool)
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
}

/// The right token after the window: one socket, one fresh Welcome with a new id; the old connection is never revived.
#[tokio::test]
async fn expired_resume_is_welcomed_fresh_on_the_same_socket() {
    let _serial = SERIAL.lock().await;
    let (f, address, server) = socket_fixture().await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut first, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut first).await;
    client_ws_send(
        &mut first,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "stale-resume-first",
        },
    )
    .await;
    let (old_id, old_token) = read_welcome(&mut first).await;
    first.close(None).await.unwrap();
    wait_inactive(&f.auth.pool, &old_id).await;
    // The window ran out: the stored expiry is in the past.
    sqlx::query("UPDATE websocket_connections SET expires_at=1 WHERE connection_id=?")
        .bind(old_id.as_slice())
        .execute(&f.auth.pool)
        .await
        .unwrap();

    let mut socket = resume_on_new_socket(address, &cookie, &old_id, &old_token).await;
    let (fresh_id, fresh_token) = read_welcome(&mut socket).await;
    assert_ne!(
        fresh_id, old_id,
        "a stale resume must never continue the old connection"
    );
    assert_ne!(fresh_token, old_token);
    // A fresh connection first deletes retired rows whose window ran out, so the old row is gone; it is never revived.
    let old_active: Option<i64> =
        sqlx::query_scalar("SELECT active FROM websocket_connections WHERE connection_id=?")
            .bind(old_id.as_slice())
            .fetch_optional(&f.auth.pool)
            .await
            .unwrap();
    assert_ne!(old_active, Some(1), "the expired connection stays retired");
    let fresh_active: i64 =
        sqlx::query_scalar("SELECT active FROM websocket_connections WHERE connection_id=?")
            .bind(fresh_id.as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(fresh_active, 1);

    // The fresh connection is a normal one: a ping on the control stream is answered on the same socket.
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 9,
            sent_us: 0,
        },
    )
    .await;
    loop {
        let wire = read_client_frame(&mut socket).await;
        if matches!(
            decode_muxed_frame(&wire).unwrap().frame,
            Frame::Pong { nonce: 9, .. }
        ) {
            break;
        }
    }
    server.abort();
}

/// The browser sends its `AttachTerm` right behind the Resume, before it sees the Welcome, naming the input its old
/// writer had acknowledged. When the resume is stale, that attach must reach the fresh writer and get its Ack at
/// zero, not close the socket as an input cursor ahead of the writer.
#[tokio::test]
async fn attach_sent_behind_a_stale_resume_gets_the_fresh_writer() {
    let _serial = SERIAL.lock().await;
    let f = fixture().await;
    let session_id = [0x93; 16];
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
    // A stand-in infraternal agent: it answers Hello and then holds every attach open.
    let agent = tokio::spawn(async move {
        let mut encoded = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "stale-resume-agent",
            },
            &mut encoded,
        )
        .unwrap();
        host.write_all(&encoded).await.unwrap();
        let mut chunk = [0_u8; 4096];
        while host.read(&mut chunk).await.unwrap_or(0) != 0 {}
    });
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut first, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut first).await;
    client_ws_send(
        &mut first,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "stale-resume-first",
        },
    )
    .await;
    let (old_id, old_token) = read_welcome(&mut first).await;
    first.close(None).await.unwrap();
    wait_inactive(&f.auth.pool, &old_id).await;
    sqlx::query("UPDATE websocket_connections SET expires_at=1 WHERE connection_id=?")
        .bind(old_id.as_slice())
        .execute(&f.auth.pool)
        .await
        .unwrap();

    // Hello, Resume, AttachTerm and Credit in one message, as the browser pipelines them.
    let (mut socket, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut socket).await;
    let mut wire = Vec::new();
    for (stream, frame) in [
        (
            0,
            Frame::Hello {
                version: 1,
                caps: 1,
                client_info: "stale-resume",
            },
        ),
        (
            0,
            Frame::Resume {
                connection_id: &old_id,
                resume_token: &old_token,
            },
        ),
        (
            1,
            Frame::AttachTerm {
                session_id: &session_id,
                last_out_seq: 0,
                last_in_seq: 7,
            },
        ),
        (1, Frame::Credit { bytes: 65_536 }),
    ] {
        let mut one = Vec::new();
        encode_muxed_frame_into(stream, &frame, &mut one).unwrap();
        wire.extend_from_slice(&one);
    }
    socket.send(Message::Binary(wire.into())).await.unwrap();
    let (fresh_id, _) = read_welcome(&mut socket).await;
    assert_ne!(fresh_id, old_id);
    let answer = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let wire = read_client_frame(&mut socket).await;
            let decoded = decode_muxed_frame(&wire).unwrap();
            if decoded.stream_id == 1 {
                break format!("{:?}", decoded.frame);
            }
        }
    })
    .await
    .expect("the pipelined attach must be answered");
    assert_eq!(answer, format!("{:?}", Frame::Ack { in_seq_acked: 0 }));
    agent.abort();
    server.abort();
}
