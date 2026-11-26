//! A host at its terminal bound counts only the terminals of sockets that still answer (D214, #562).
//!
//! A browser that vanishes without closing its socket (a phone that changed networks, a tab the
//! system killed in the background) keeps its terminals attached until the server notices. A page
//! that last reported itself hidden gets no liveness probes (#317), so nothing noticed: a new page
//! was told the host was full for as long as the dead socket stayed open. When an attach is refused
//! for that reason, the server now asks the account's sockets to answer once and ends the ones
//! that do not.
//!
//! Everything here is real except the infraternal agent, which is a stand-in that acknowledges
//! every attach and answers every probe.
use super::*;
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Hello bit 2: this page reports its visibility on control Event 0.
const VIEWER_VISIBILITY: u64 = 1 << 2;
/// The reason of a `Close 1013` for an attach past the host's bound (`stream_close.rs`).
const HOST_FULL_TEXT: &str =
    "this host already shows as many terminals as it can; close one to open another";
/// How long a new page keeps retrying before the test calls the host stuck full.
const RETRY_BOUND: Duration = Duration::from_secs(15);

/// The infraternal agent's side of the local socket: greet, acknowledge every attach and answer
/// every probe, so the host link and its routes stay healthy for the whole test.
async fn answering_agent(mut agent: UnixStream) {
    let mut encoded = Vec::new();
    let hello = Frame::Hello {
        version: 1,
        caps: 0,
        client_info: "host full agent",
    };
    encode_muxed_frame_into(0, &hello, &mut encoded).unwrap();
    agent.write_all(&encoded).await.unwrap();
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let read = agent.read(&mut chunk).await.unwrap_or(0);
        if read == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..read]);
        let mut replies = Vec::new();
        while let Ok(decoded) = decode_muxed_frame(&buffer) {
            let reply = match decoded.frame {
                Frame::AttachTerm { last_in_seq, .. } => Some(Frame::Ack {
                    in_seq_acked: last_in_seq,
                }),
                Frame::Ping { nonce, sent_us } => Some(Frame::Pong { nonce, sent_us }),
                _ => None,
            };
            if let Some(reply) = reply {
                encode_muxed_frame_into(decoded.stream_id, &reply, &mut encoded).unwrap();
                replies.extend_from_slice(&encoded);
            }
            let used = decoded.wire_len;
            buffer.drain(..used);
        }
        if agent.write_all(&replies).await.is_err() {
            return;
        }
    }
}

/// A welcomed socket that reports its visibility.
async fn viewer(
    address: SocketAddr,
    cookie: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let (mut socket, _) = connect_async(test_ws_request(address, cookie))
        .await
        .unwrap();
    assert_server_hello(&mut socket).await;
    let hello = Frame::Hello {
        version: 1,
        caps: VIEWER_VISIBILITY,
        client_info: "host full",
    };
    client_ws_send(&mut socket, 0, &hello).await;
    read_welcome(&mut socket).await;
    socket
}

/// Ask for `session` on browser stream 1 and say whether the server attached it. `Err` carries
/// the reason of the stream's `Close`.
async fn attach<S>(socket: &mut S, session: &[u8; 16]) -> std::result::Result<(), String>
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    let request = Frame::AttachTerm {
        session_id: session,
        last_out_seq: 0,
        last_in_seq: 0,
    };
    client_ws_send(socket, 1, &request).await;
    loop {
        let wire = read_client_frame(socket).await;
        let decoded = decode_muxed_frame(&wire).unwrap();
        match decoded.frame {
            Frame::Ping { nonce, sent_us } if decoded.stream_id == 0 => {
                client_ws_send(socket, 0, &Frame::Pong { nonce, sent_us }).await;
            }
            Frame::Ack { .. } if decoded.stream_id == 1 => return Ok(()),
            Frame::Close { reason, .. } if decoded.stream_id == 1 => return Err(reason.to_owned()),
            _ => {}
        }
    }
}

/// A hidden page whose browser vanished holds the host's last terminal place. A new page is told
/// the host is full, and the retry it makes by itself succeeds once the dead socket has failed to
/// answer. A hidden page that is still there keeps its socket.
#[tokio::test]
async fn a_vanished_hidden_socket_gives_its_terminal_place_to_a_new_page() {
    let _serial = SERIAL.lock().await;
    let f = fixture().await;
    let sessions = [[0xa1_u8; 16], [0xa2_u8; 16]];
    for session in sessions {
        sqlx::query(
            "INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)",
        )
        .bind(session.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    }
    let (socket, agent) = UnixStream::pair().unwrap();
    let agent = tokio::spawn(answering_agent(agent));
    let host = EmbeddedAgent::from_test_socket(socket);
    let state =
        crate::websocket::WebSocketState::new(f.auth.clone(), f.auth.pool.clone(), host.clone())
            .await
            .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = crate::websocket::router(state);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    // Other pages' terminals fill the host but for one place.
    let mut others = Vec::new();
    for index in 1..infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS {
        let stream = 1_000_000 + 2 * u32::try_from(index).unwrap();
        others.push(host.attach([0xee; 16], 0, 0, stream).await.unwrap());
    }
    let cookie = format!("__Host-infraternal={}", f.session);

    // A hidden page that stays: its socket is read, so it answers whatever the server asks.
    let mut staying = viewer(address, &cookie).await;
    let hidden = br#"{"topic":"connection.visibility","hidden":true}"#;
    let hide = Frame::Event {
        sub_id: 0,
        event_json: hidden,
    };
    client_ws_send(&mut staying, 0, &hide).await;
    let (mut staying_send, mut staying_receive) = staying.split();
    let (frames, mut staying_frames) = tokio::sync::mpsc::unbounded_channel();
    let reading = tokio::spawn(async move {
        while let Some(Ok(message)) = staying_receive.next().await {
            if let Message::Binary(wire) = message
                && frames.send(wire).is_err()
            {
                return;
            }
        }
    });

    // The page that vanishes: it takes the last place, goes hidden, and is never read again. Its
    // TCP connection stays open, as after a change of network.
    let mut vanished = viewer(address, &cookie).await;
    attach(&mut vanished, &sessions[0]).await.unwrap();
    client_ws_send(&mut vanished, 0, &hide).await;

    let mut fresh = viewer(address, &cookie).await;
    assert_eq!(
        attach(&mut fresh, &sessions[1]).await,
        Err(HOST_FULL_TEXT.to_owned()),
        "the host is at its bound while the other socket is not yet known to be gone"
    );
    let asked = std::time::Instant::now();
    tokio::time::timeout(RETRY_BOUND, async {
        loop {
            // sleep: the browser waits before it attaches a refused terminal again.
            tokio::time::sleep(Duration::from_millis(250)).await;
            match attach(&mut fresh, &sessions[1]).await {
                Ok(()) => break,
                Err(reason) => assert_eq!(reason, HOST_FULL_TEXT),
            }
        }
    })
    .await
    .expect("the vanished socket kept its terminal place");
    println!(
        "METRIC host_full_dead_socket_reclaimed_ms {}",
        asked.elapsed().as_millis()
    );

    // The hidden page that answered is still connected and served.
    let mut ping = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Ping {
            nonce: 77,
            sent_us: 0,
        },
        &mut ping,
    )
    .unwrap();
    staying_send
        .send(Message::Binary(ping.into()))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let wire = staying_frames
                .recv()
                .await
                .expect("the live hidden socket closed");
            if matches!(
                decode_muxed_frame(&wire).unwrap().frame,
                Frame::Pong { nonce: 77, .. }
            ) {
                break;
            }
        }
    })
    .await
    .expect("the live hidden socket stopped answering");
    drop((others, vanished));
    reading.abort();
    server.abort();
    agent.abort();
}
