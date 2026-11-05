//! A slow authority read is not a refusal (#146). One SQLite read that misses its
//! deadline holds the socket's work and is retried within a bounded wait; frames
//! queued meanwhile are answered in order. A stall past that wait still closes.
use super::*;

/// The fixture pool has one SQLite connection: holding it stalls every authority
/// read for exactly as long as the test chooses, without revoking the login.
async fn welcomed_with_short_reads(
    label: &str,
) -> (
    Fixture,
    tokio::task::JoinHandle<()>,
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
) {
    let (f, address, server) =
        socket_fixture_from_fixture(fixture().await, Some(Duration::from_millis(25))).await;
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
            client_info: label,
        },
    )
    .await;
    read_welcome(&mut socket).await;
    (f, server, socket)
}

/// Transport pings are answered without SQL (D265); an action call is application
/// work: its refusal is still sent only after an authority read.
fn call(call_id: u32) -> Frame<'static> {
    Frame::Call {
        call_id,
        action_id: "test.not.an.action",
        input_json: b"{}",
    }
}

async fn next_reply(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Option<u64> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), socket.next()).await {
            Ok(Some(Ok(Message::Binary(bytes)))) => {
                if let Frame::Result { call_id, .. } = decode_muxed_frame(&bytes).unwrap().frame {
                    return Some(u64::from(call_id));
                }
            }
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            _ => return None,
        }
    }
}

#[tokio::test]
async fn authority_read_stall_shorter_than_the_wait_keeps_the_socket_and_its_order() {
    let _guard = SERIAL.lock().await;
    let (f, server, mut socket) = welcomed_with_short_reads("transient stall").await;
    let held = f.auth.pool.acquire().await.unwrap();
    for call_id in 1..=3_u32 {
        client_ws_send(&mut socket, 0, &call(call_id)).await;
    }
    // Several 25 ms read deadlines pass while the store is busy.
    tokio::time::sleep(Duration::from_millis(150)).await;
    drop(held);
    for call_id in 1..=3_u32 {
        assert_eq!(
            next_reply(&mut socket).await,
            Some(u64::from(call_id)),
            "a slow authority read closed the socket or reordered its frames"
        );
    }
    server.abort();
}

#[tokio::test]
async fn authority_read_stall_beyond_the_wait_still_fails_closed() {
    let _guard = SERIAL.lock().await;
    let (f, server, mut socket) = welcomed_with_short_reads("lasting stall").await;
    let _held = f.auth.pool.acquire().await.unwrap();
    client_ws_send(&mut socket, 0, &call(9)).await;
    assert_eq!(
        next_reply(&mut socket).await,
        None,
        "work ran without a completed authority read"
    );
    server.abort();
}

/// A terminal-only socket (no desktop, no action calls) keeps its stream through
/// authority stalls up to 800 ms: input typed during the stall reaches the host in
/// order, output the host wrote during it reaches the browser in order, and the
/// socket stays open. Production read deadline (25 ms) throughout.
#[tokio::test]
async fn terminal_stream_survives_authority_stalls_without_loss_or_reorder() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let session = [83_u8; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,unixepoch(),unixepoch())")
        .bind(session.as_slice()).bind(&f.user).execute(&f.auth.pool).await.unwrap();
    let (socket, peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap()
    .with_authority_read_timeout(Duration::from_millis(25));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, crate::websocket::router(state))
            .await
            .unwrap();
    });
    let (inputs_tx, mut inputs) = tokio::sync::mpsc::unbounded_channel();
    let (emit, emits) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let backend = tokio::spawn(echo_host(peer, inputs_tx, emits));
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
            client_info: "terminal stall",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    client_ws_send(
        &mut browser,
        1,
        &Frame::AttachTerm {
            session_id: &session,
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    client_ws_send(&mut browser, 1, &Frame::Credit { bytes: 1 << 20 }).await;
    let (mut in_seq, mut out_seq) = (0_u64, 0_u64);
    for stall_ms in [100_u64, 300, 800] {
        let held = f.auth.pool.acquire().await.unwrap();
        let mut typed = Vec::new();
        let mut written = Vec::new();
        for n in 0..5 {
            let key = format!("k{stall_ms}.{n};").into_bytes();
            client_ws_send(
                &mut browser,
                1,
                &Frame::Input {
                    in_seq,
                    bytes: &key,
                },
            )
            .await;
            in_seq += key.len() as u64;
            typed.extend_from_slice(&key);
            let line = format!("o{stall_ms}.{n}\r\n").into_bytes();
            written.extend_from_slice(&line);
            emit.send(line).unwrap();
        }
        // Release the store from another task: the browser keeps reading and
        // answering liveness probes through the stall, as a real one does.
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(stall_ms)).await;
            drop(held);
        });
        // Output: contiguous offsets, exact bytes, socket still open.
        let mut received = Vec::new();
        while received.len() < written.len() {
            let wire = tokio::time::timeout(Duration::from_secs(5), browser.next())
                .await
                .unwrap_or_else(|_| panic!("no output after a {stall_ms} ms stall"));
            // Answer native liveness probes as a browser does [#317].
            if let Some(Ok(Message::Ping(payload))) = wire {
                browser.send(Message::Pong(payload)).await.unwrap();
                continue;
            }
            let Some(Ok(Message::Binary(bytes))) = wire else {
                panic!("a {stall_ms} ms authority stall closed the terminal socket: {wire:?}");
            };
            let decoded = decode_muxed_frame(&bytes).unwrap();
            match decoded.frame {
                Frame::Output { out_seq: at, bytes } => {
                    assert_eq!(at, out_seq, "terminal output reordered or lost");
                    out_seq += bytes.len() as u64;
                    received.extend_from_slice(bytes);
                }
                Frame::Close { code, reason } => {
                    panic!("a {stall_ms} ms stall closed the socket: {code} {reason}")
                }
                // Answer liveness probes as a browser does.
                Frame::Ping { nonce, sent_us } => {
                    client_ws_send(
                        &mut browser,
                        decoded.stream_id,
                        &Frame::Pong { nonce, sent_us },
                    )
                    .await;
                }
                _ => {}
            }
        }
        assert_eq!(received, written);
        release.await.unwrap();
        // Input: every key, once, in order, at its own offset.
        let mut host = Vec::new();
        while host.len() < typed.len() {
            let (at, bytes) = tokio::time::timeout(Duration::from_secs(5), inputs.recv())
                .await
                .unwrap_or_else(|_| panic!("input lost after a {stall_ms} ms stall"))
                .unwrap();
            assert_eq!(at, (in_seq - typed.len() as u64) + host.len() as u64);
            host.extend_from_slice(&bytes);
        }
        assert_eq!(host, typed);
    }
    server.abort();
    backend.abort();
}

/// Host side of one terminal: acknowledges attach and every input, reports input
/// to the test, and writes each output chunk the test hands it once the browser
/// has granted output credit.
async fn echo_host(
    mut peer: UnixStream,
    inputs: tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>,
    mut emits: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) {
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
            client_info: "terminal-stall-host",
        },
    )
    .await;
    let mut stream = None;
    let mut out_seq = 0_u64;
    let mut parked: Vec<Vec<u8>> = Vec::new();
    loop {
        tokio::select! {
            wire = read_leg_b_frame(&mut peer, &mut receive) => {
                let Some(wire) = wire else { return };
                let decoded = decode_muxed_frame(&wire).unwrap();
                match decoded.frame {
                    Frame::Ping { nonce, sent_us } => {
                        leg_b_send(&mut peer, decoded.stream_id, &Frame::Pong { nonce, sent_us }).await;
                    }
                    Frame::AttachTerm { .. } => {
                        leg_b_send(&mut peer, decoded.stream_id, &Frame::Ack { in_seq_acked: 0 }).await;
                    }
                    // The server forwards credit after granting it, so output
                    // written from here on is never dropped for lack of credit.
                    Frame::Credit { .. } => {
                        stream = Some(decoded.stream_id);
                        for line in parked.drain(..) {
                            leg_b_send(&mut peer, decoded.stream_id, &Frame::Output { out_seq, bytes: &line }).await;
                            out_seq += line.len() as u64;
                        }
                    }
                    Frame::Input { in_seq, bytes } => {
                        let end = in_seq + bytes.len() as u64;
                        inputs.send((in_seq, bytes.to_vec())).unwrap();
                        leg_b_send(&mut peer, decoded.stream_id, &Frame::Ack { in_seq_acked: end }).await;
                    }
                    _ => {}
                }
            }
            Some(line) = emits.recv() => match stream {
                Some(id) => {
                    leg_b_send(&mut peer, id, &Frame::Output { out_seq, bytes: &line }).await;
                    out_seq += line.len() as u64;
                }
                None => parked.push(line),
            },
        }
    }
}

/// Wait for the server to end the socket and return how long it took. Control
/// frames sent on the way out are drained.
async fn closed_after(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Duration {
    let started = tokio::time::Instant::now();
    loop {
        match tokio::time::timeout(Duration::from_secs(5), socket.next()).await {
            Ok(Some(Ok(Message::Close(_)) | Err(_)) | None) => return started.elapsed(),
            Ok(Some(Ok(_))) => {}
            Err(elapsed) => panic!("the socket did not end within 5 s: {elapsed}"),
        }
    }
}

/// A socket ending on a protocol error asks once whether its browser may still
/// hear why. With a busy store that one attempt misses its deadline and the
/// socket ends at once: teardown never takes the one-second authority wait
/// while it holds the transport (#240, review P2).
#[tokio::test]
async fn teardown_with_a_busy_store_does_not_wait_for_authority() {
    let _guard = SERIAL.lock().await;
    let (f, server, mut socket) = welcomed_with_short_reads("teardown busy").await;
    let held = f.auth.pool.acquire().await.unwrap();
    socket
        .send(Message::Binary(vec![0xff; 16].into()))
        .await
        .unwrap();
    let took = closed_after(&mut socket).await;
    drop(held);
    server.abort();
    assert!(
        took < Duration::from_millis(500),
        "teardown held the socket {took:?} waiting on a busy store"
    );
}

/// Ending a socket is not activity: teardown reads authority without renewing
/// the session, even when the session is due for its renewal (#240, review P2).
#[tokio::test]
async fn teardown_does_not_renew_the_session() {
    let _guard = SERIAL.lock().await;
    let (f, server, mut socket) = welcomed_with_short_reads("teardown renew").await;
    let due = crate::websocket::now_seconds().unwrap() + 600;
    sqlx::query("UPDATE sessions SET expires=? WHERE user_id=?")
        .bind(due)
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    socket
        .send(Message::Binary(vec![0xff; 16].into()))
        .await
        .unwrap();
    closed_after(&mut socket).await;
    // A renewal would run in the background: give it time to land.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let expires: i64 = sqlx::query_scalar("SELECT expires FROM sessions WHERE user_id=?")
        .bind(&f.user)
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    server.abort();
    assert_eq!(expires, due, "teardown renewed the session");
}
