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
/// socket stays open. A stall past the one-second wait still closes the socket,
/// and input typed during it never reaches the host. Production read deadline
/// (25 ms) throughout.
///
/// Count the application's held read before releasing SQLite so the test
/// catches retries queueing behind their own missed reads (#525). The
/// browser parks its keepalive probes using the regular hidden-viewer
/// control. This keeps the paused clock from treating a real loopback
/// Pong delay as loss of the connection during an authority stall.
///
/// Runtime time is paused and moves 1 ms at a time, only while the store is
/// held or no authority read is in flight (#525). A SELECT runs on its worker
/// thread in real time while the runtime clock stands still, so the test
/// measures the protocol, not the host: in real time, on a host at load 70,
/// one 25 ms attempt was observed late often enough that both the old and the
/// fixed retry closed the socket.
#[tokio::test(start_paused = true)]
async fn terminal_stream_survives_authority_stalls_without_loss_or_reorder() {
    use futures_util::FutureExt;

    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
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
    let pending_reads = state.authority_read_monitor();
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
            caps: 1 << 2, // Viewer visibility notices.
            client_info: "terminal stall",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    client_ws_send(
        &mut browser,
        0,
        &Frame::Event {
            sub_id: 0,
            event_json: br#"{"topic":"connection.visibility","hidden":true}"#,
        },
    )
    .await;
    // The transport handles control frames in order. Its reply confirms
    // that it parked automatic probes before the clock starts moving.
    client_ws_send(
        &mut browser,
        0,
        &Frame::Ping {
            nonce: 244,
            sent_us: 244,
        },
    )
    .await;
    let reply = read_client_frame(&mut browser).await;
    assert!(matches!(
        decode_muxed_frame(&reply).unwrap().frame,
        Frame::Pong { nonce: 244, .. }
    ));
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
    let mut acked = 0;
    for stall_ms in [100_u64, 300, 800] {
        let stall = Duration::from_millis(stall_ms);
        let mut held = Some(f.auth.pool.acquire().await.unwrap());
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
        let typed_from = in_seq - typed.len() as u64;
        let (mut received, mut host) = (Vec::new(), Vec::new());
        // Only a hang bound: runtime time, not this, decides every deadline.
        let real = std::time::Instant::now();
        while pending_reads() == 0 {
            assert!(
                real.elapsed() < Duration::from_secs(60),
                "no authority read began for the {stall_ms} ms stall"
            );
            tokio::task::yield_now().await;
        }
        let started = tokio::time::Instant::now();
        // Wait for the last acknowledgement too. Observing the key at the
        // host only proves delivery; its reply may still need the store.
        while held.is_some()
            || received.len() < written.len()
            || host.len() < typed.len()
            || acked < in_seq
        {
            assert!(
                real.elapsed() < Duration::from_secs(60),
                "the socket made no progress after a {stall_ms} ms stall"
            );
            assert!(
                started.elapsed() < stall + Duration::from_secs(2),
                "no output or input within the authority wait after a {stall_ms} ms stall"
            );
            // Drain the browser's socket while driving the stall clock.
            if let Some(wire) = browser.next().now_or_never() {
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
                    // Output: contiguous offsets, exact bytes, socket still open.
                    Frame::Output { out_seq: at, bytes } => {
                        assert_eq!(at, out_seq, "terminal output reordered or lost");
                        out_seq += bytes.len() as u64;
                        received.extend_from_slice(bytes);
                    }
                    Frame::Ack { in_seq_acked } if decoded.stream_id == 1 => {
                        assert!(in_seq_acked <= in_seq, "terminal acknowledged unsent input");
                        acked = acked.max(in_seq_acked);
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
                continue;
            }
            // Input: every key, once, in order, at its own offset.
            if let Ok((at, bytes)) = inputs.try_recv() {
                assert_eq!(at, typed_from + host.len() as u64);
                host.extend_from_slice(&bytes);
                continue;
            }
            // Enough turns for the I/O driver and every socket task to run
            // before the clock moves again.
            for _ in 0..64 {
                tokio::task::yield_now().await;
            }
            if held.is_some() {
                let reads = pending_reads();
                assert!(
                    reads <= 1,
                    "the stalled terminal socket held {reads} authority read places"
                );
            }
            if held.is_some() && started.elapsed() >= stall {
                held = None;
            } else if held.is_some() || pending_reads() == 0 {
                tokio::time::advance(Duration::from_millis(1)).await;
            }
        }
        assert_eq!(received, written);
        assert_eq!(host, typed);
    }
    // The rule still holds after the stalls: a stall past the one-second wait
    // closes the socket, and the key typed during it never reaches the host.
    let held = f.auth.pool.acquire().await.unwrap();
    client_ws_send(
        &mut browser,
        1,
        &Frame::Input {
            in_seq,
            bytes: b"after the wait;",
        },
    )
    .await;
    let started = tokio::time::Instant::now();
    let real = std::time::Instant::now();
    let close = loop {
        assert!(
            real.elapsed() < Duration::from_secs(60) && started.elapsed() < Duration::from_secs(3),
            "a stall past the authority wait kept the terminal socket open"
        );
        match browser.next().now_or_never() {
            Some(Some(Ok(Message::Ping(payload)))) => {
                browser.send(Message::Pong(payload)).await.unwrap();
            }
            Some(Some(Ok(Message::Binary(bytes)))) => {
                let decoded = decode_muxed_frame(&bytes).unwrap();
                match decoded.frame {
                    Frame::Close { code, .. } => break Some(code),
                    Frame::Output { .. } => panic!("output was served without authority"),
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
            Some(Some(Ok(Message::Close(_)) | Err(_)) | None) => break None,
            Some(Some(Ok(_))) | None => {
                for _ in 0..64 {
                    tokio::task::yield_now().await;
                }
                tokio::time::advance(Duration::from_millis(1)).await;
            }
        }
    };
    // The wait may end one retry pause (at most 100 ms) before its full second.
    assert!(
        started.elapsed() >= Duration::from_millis(800),
        "the socket closed before its authority wait: {:?}",
        started.elapsed()
    );
    if let Some(code) = close {
        assert_eq!(code, 1013, "a busy store must close as server busy");
    }
    // The socket is gone, so nothing can still be on its way to the host.
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    assert!(
        inputs.try_recv().is_err(),
        "input typed during a stall past the wait reached the host"
    );
    drop(held);
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
