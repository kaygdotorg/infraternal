//! Tests browser control and content-free proof authority while input or SQL is blocked [128,215,265], #199.
use super::*;
use std::{
    io::Write,
    sync::{Arc, Mutex as StdMutex},
};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

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

#[tokio::test(start_paused = true)]
async fn review_full_input_writer_preserves_browser_control_progress() {
    browser_credit_case(false).await;
}

#[tokio::test(start_paused = true)]
async fn browser_input_overload_retires_only_the_terminal_stream() {
    browser_credit_case(true).await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep the socket exchange and log assertions in one integration case.
async fn browser_output_credit_refusal_logs_the_stream_reason() {
    let _serial = SERIAL.lock().await;
    let (capture, _subscriber) = Capture::start();
    let f = fixture().await;
    let session = [72_u8; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,unixepoch(),unixepoch())")
        .bind(session.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let (socket, peer) = UnixStream::pair().unwrap();
    let (address, server) = credit_server(&f, socket).await;
    let (observed, _inputs) = tokio::sync::mpsc::channel(4);
    let backend = tokio::spawn(input_backend(peer, observed));
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
            client_info: "output-credit-close-log",
        },
    )
    .await;
    let initial_wire = read_client_frame(&mut browser).await;
    let initial = decode_muxed_frame(&initial_wire).unwrap();
    let refusal_code = match &initial.frame {
        Frame::Close { code, .. } => Some(*code),
        _ => None,
    };
    assert!(
        matches!(initial.frame, Frame::Welcome { .. }),
        "server did not send Welcome; control close code={refusal_code:?}"
    );
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
    assert!(matches!(
        decode_muxed_frame(&read_client_frame(&mut browser).await)
            .unwrap()
            .frame,
        Frame::Ack { in_seq_acked: 0 }
    ));
    client_ws_send(
        &mut browser,
        1,
        &Frame::Credit {
            bytes: 8 * 1024 * 1024 + 1,
        },
    )
    .await;
    let close = tokio::time::timeout(Duration::from_secs(2), async {
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
        decode_muxed_frame(&close).unwrap(),
        infraternal_protocol::DecodedMuxedFrame {
            stream_id: 1,
            frame: Frame::Close {
                code: 1013,
                reason: "terminal output credit exceeded its limit"
            },
            ..
        }
    ));
    client_ws_send(
        &mut browser,
        0,
        &Frame::Ping {
            nonce: 228,
            sent_us: 0,
        },
    )
    .await;
    assert!(matches!(
        decode_muxed_frame(&read_client_frame(&mut browser).await)
            .unwrap()
            .frame,
        Frame::Pong { nonce: 228, .. }
    ));
    let events = capture.events("terminal_stream_closed");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["fields"]["who"], "server");
    assert_eq!(
        events[0]["fields"]["reason_category"],
        "flow_control_refusal"
    );
    assert_eq!(events[0]["fields"]["reason"], "credit_exceeded");
    assert_eq!(
        events[0]["fields"]["session_id"],
        Uuid::from_bytes(session).to_string()
    );
    server.abort();
    backend.abort();
}

/// Share the actual full-window setup between progress and stream-overload checks.
async fn browser_credit_case(overload: bool) {
    let _guard = SERIAL.lock().await;
    // These assert frame ordering under backpressure, not the host's ability
    // to schedule SQLite and multi-megabyte writes inside a learned lease.
    // Keep production deadlines stationary across the real I/O, as in the
    // other socket ordering fixtures; unexpected reconnects still fail.
    let _clock = FrozenSocketTime::new().await;
    let (capture, _subscriber) = Capture::start();
    let f = fixture().await;
    let session = [71_u8; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,unixepoch(),unixepoch())")
        .bind(session.as_slice()).bind(&f.user).execute(&f.auth.pool).await.unwrap();
    let (socket, peer) = UnixStream::pair().unwrap();
    let (address, server) = credit_server(&f, socket).await;
    let (observed, mut inputs) = tokio::sync::mpsc::channel(4);
    // The real actor receives each byte, but the PTY write acknowledgement stays
    // at zero. This is valid backpressure, not an invalid browser offset.
    let backend = tokio::spawn(input_backend(peer, observed));
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
            client_info: "input-credit-review",
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
    let attached = read_client_frame(&mut browser).await;
    assert!(matches!(
        decode_muxed_frame(&attached).unwrap().frame,
        Frame::Ack { in_seq_acked: 0 }
    ));
    fill_browser_input(&mut browser, &mut inputs).await;
    client_ws_send(
        &mut browser,
        1,
        &Frame::Input {
            in_seq: infraternal_protocol::MAX_FRAME_LEN as u64,
            bytes: b"z",
        },
    )
    .await;
    client_ws_send(
        &mut browser,
        0,
        &Frame::Ping {
            nonce: 129,
            sent_us: 0,
        },
    )
    .await;
    // This is a functional liveness guard. It does not measure a latency budget.
    let control = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let wire = read_client_frame(&mut browser).await;
            if matches!(
                decode_muxed_frame(&wire).unwrap().frame,
                Frame::Pong { nonce: 129, .. }
            ) {
                return;
            }
        }
    })
    .await;
    assert!(
        control.is_ok(),
        "a writer awaiting durable input credit stops the browser control stream"
    );
    if overload {
        assert_overload_isolation(&mut browser).await;
        let events = capture.events("terminal_stream_closed");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["fields"]["who"], "server");
        assert_eq!(
            events[0]["fields"]["reason_category"],
            "flow_control_refusal"
        );
        assert_eq!(events[0]["fields"]["reason"], "input_queue_full");
    } else {
        assert_credit_and_order(&mut browser, &mut inputs).await;
    }
    server.abort();
    backend.abort();
}

/// A visible browser route is probed only with native WebSocket Ping control frames, and native
/// Pongs alone keep it past the startup ceiling. A hidden route gets no probe of any kind and is
/// not retired by that silence; becoming visible again restarts native probing [#317, D300].
#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)]
async fn browser_route_probes_natively_while_visible_and_not_at_all_while_hidden() {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let f = fixture().await;
    let session = [73_u8; 16];
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,unixepoch(),unixepoch())")
        .bind(session.as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let (socket, peer) = UnixStream::pair().unwrap();
    let (address, server) = credit_server(&f, socket).await;
    let (observed, _inputs) = tokio::sync::mpsc::channel(4);
    let backend = tokio::spawn(input_backend(peer, observed));
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
            caps: 4,
            client_info: "native-liveness",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    // Probing starts once a terminal is attached.
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
    assert!(matches!(
        decode_muxed_frame(&read_client_frame(&mut browser).await)
            .unwrap()
            .frame,
        Frame::Ack { in_seq_acked: 0 }
    ));

    // Visible: 3 s of 30 ms steps outlasts the 2 s startup ceiling and D300's
    // two-miss retirement many times, so only correlated native Pongs keep it.
    // Each fence proves the server read that Pong before time moves again.
    let mut last = 0;
    for step in 0..100 {
        tokio::time::advance(Duration::from_millis(30)).await;
        let probe = receive_native_probe(&mut browser).await;
        assert_eq!(probe.len(), 16);
        let nonce = u64::from_le_bytes(probe[..8].try_into().unwrap());
        assert_eq!(nonce, u64::from_le_bytes(probe[8..].try_into().unwrap()));
        assert!(nonce > last, "probe correlations must increase");
        last = nonce;
        browser.send(Message::Pong(probe)).await.unwrap();
        fence(&mut browser, 1000 + step).await;
    }

    // Hidden: the notice parks the lease. Probes the server wrote before reading
    // it are answered while waiting for the first fence.
    client_ws_send(
        &mut browser,
        0,
        &Frame::Event {
            sub_id: 0,
            event_json: br#"{"topic":"connection.visibility","hidden":true}"#,
        },
    )
    .await;
    fence(&mut browser, 2).await;
    for _ in 0..100 {
        tokio::time::advance(Duration::from_millis(30)).await;
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }
    // Any probe sent while hidden precedes this Pong on the ordered socket, and an
    // unanswered one would have retired the route and closed it.
    client_ws_send(
        &mut browser,
        0,
        &Frame::Ping {
            nonce: 3,
            sent_us: 3,
        },
    )
    .await;
    loop {
        match browser
            .next()
            .await
            .expect("websocket message")
            .expect("websocket frame")
        {
            Message::Binary(wire) => match decode_muxed_frame(&wire).unwrap().frame {
                Frame::Pong { nonce: 3, .. } => break,
                Frame::Ping { .. } => panic!("hidden route got an application probe"),
                _ => {}
            },
            other => panic!("hidden route was probed or closed: {other:?}"),
        }
    }

    // Visible again: a fresh lease probes natively at once.
    client_ws_send(
        &mut browser,
        0,
        &Frame::Event {
            sub_id: 0,
            event_json: br#"{"topic":"connection.visibility","hidden":false}"#,
        },
    )
    .await;
    tokio::time::advance(Duration::from_millis(30)).await;
    let probe = receive_native_probe(&mut browser).await;
    assert_eq!(probe.len(), 16);
    browser.send(Message::Pong(probe)).await.unwrap();
    fence(&mut browser, 4).await;
    server.abort();
    backend.abort();
}

/// Wait for the server's next probe. A muxed application Ping on a browser route is a regression.
async fn receive_native_probe(
    browser: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
) -> bytes::Bytes {
    loop {
        match browser
            .next()
            .await
            .expect("websocket message")
            .expect("websocket frame")
        {
            Message::Ping(payload) => return payload,
            Message::Binary(wire) => {
                if let Ok(decoded) = decode_muxed_frame(&wire)
                    && let Frame::Ping { .. } = decoded.frame
                {
                    panic!("browser route sent an application Ping instead of a native one");
                }
            }
            Message::Pong(_) | Message::Frame(_) => {}
            other => panic!("unexpected frame while waiting for a native probe: {other:?}"),
        }
    }
}

/// Round-trip one client Ping, answering native probes on the way: the route is still open and
/// every earlier client frame has been read.
async fn fence(browser: &mut WebSocketStream<MaybeTlsStream<TcpStream>>, nonce: u64) {
    client_ws_send(
        browser,
        0,
        &Frame::Ping {
            nonce,
            sent_us: nonce,
        },
    )
    .await;
    // Attachment traffic (replay notices, output) may still be in flight; only the reply matters.
    loop {
        let reply = read_client_frame(browser).await;
        if let Frame::Pong { nonce: n, .. } = decode_muxed_frame(&reply).unwrap().frame {
            assert_eq!(n, nonce, "fence answered out of order");
            return;
        }
    }
}

/// Withhold durable input Ack after forwarding, without blocking transport reads.
async fn input_backend(mut peer: UnixStream, observed: tokio::sync::mpsc::Sender<Observed>) {
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
            client_info: "input-credit-fixture",
        },
    )
    .await;
    while let Some(wire) = read_leg_b_frame(&mut peer, &mut receive).await {
        let decoded = decode_muxed_frame(&wire).unwrap();
        match decoded.frame {
            // Withhold only durable input acknowledgment. Transport liveness
            // remains responsive while that input window is intentionally full.
            Frame::Ping { nonce, sent_us } => {
                leg_b_send(
                    &mut peer,
                    decoded.stream_id,
                    &Frame::Pong { nonce, sent_us },
                )
                .await;
            }
            Frame::AttachTerm { .. } => {
                leg_b_send(
                    &mut peer,
                    decoded.stream_id,
                    &Frame::Ack { in_seq_acked: 0 },
                )
                .await;
            }
            Frame::Input { in_seq, bytes } => {
                observed
                    .send(Observed::Input(in_seq, bytes.len()))
                    .await
                    .unwrap();
            }
            Frame::Credit { bytes: 17 } => {
                observed.send(Observed::Credit).await.unwrap();
                leg_b_send(
                    &mut peer,
                    decoded.stream_id,
                    &Frame::Ack {
                        in_seq_acked: infraternal_protocol::MAX_FRAME_LEN as u64,
                    },
                )
                .await;
            }
            Frame::Resize { cols: 91, .. } => {
                observed.send(Observed::Resize).await.unwrap();
            }
            _ => {}
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Observed {
    Input(u64, usize),
    Credit,
    Resize,
}

/// Output credit bypasses a parked Input, whose following Resize stays ordered.
async fn assert_credit_and_order(
    browser: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    inputs: &mut tokio::sync::mpsc::Receiver<Observed>,
) {
    client_ws_send(
        browser,
        1,
        &Frame::Resize {
            cols: 91,
            rows: 24,
            px_w: 0,
            px_h: 0,
        },
    )
    .await;
    client_ws_send(browser, 1, &Frame::Credit { bytes: 17 }).await;
    for expected in [
        Observed::Credit,
        Observed::Input(infraternal_protocol::MAX_FRAME_LEN as u64, 1),
        Observed::Resize,
    ] {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), inputs.recv())
                .await
                .unwrap()
                .unwrap(),
            expected
        );
    }
}

/// Bind an isolated real router and return its task for unconditional cleanup.
async fn credit_server(
    f: &Fixture,
    socket: UnixStream,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap()
    .with_authority_read_timeout(Duration::from_secs(5));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, crate::websocket::router(state))
            .await
            .unwrap();
    });
    (address, server)
}

/// Exercise bounded/cancellable storage against the real Unix actor at its durable-Ack limit.
async fn saturated_handle() -> (
    crate::embedded::AttachmentHandle,
    tokio::sync::mpsc::Receiver<Observed>,
    tokio::sync::mpsc::Receiver<crate::embedded::TerminalOutput>,
    tokio::task::JoinHandle<()>,
) {
    let (socket, peer) = UnixStream::pair().unwrap();
    let agent = EmbeddedAgent::from_test_socket(socket);
    let (observed, mut inputs) = tokio::sync::mpsc::channel(4);
    let backend = tokio::spawn(input_backend(peer, observed));
    let attachment = agent.attach([71; 16], 0, 0, 2).await.unwrap();
    let (handle, output) = attachment.split();
    let half = infraternal_protocol::MAX_FRAME_LEN / 2;
    let bytes = vec![b'x'; half];
    for sequence in [0, half as u64] {
        handle
            .send_frame(input_wire(sequence, &bytes))
            .await
            .unwrap();
        assert_eq!(
            inputs.recv().await.unwrap(),
            Observed::Input(sequence, half)
        );
    }
    (handle, inputs, output, backend)
}

/// Encode actual leg-A wire storage, so the byte bound includes framing overhead.
fn input_wire(sequence: u64, bytes: &[u8]) -> bytes::Bytes {
    let mut wire = Vec::new();
    encode_muxed_frame_into(
        1,
        &Frame::Input {
            in_seq: sequence,
            bytes,
        },
        &mut wire,
    )
    .unwrap();
    wire.into()
}

#[tokio::test]
async fn pending_browser_input_counts_against_slots_and_cancels_on_drop() {
    let (handle, mut inputs, _output, backend) = saturated_handle().await;
    let (output, _events) = tokio::sync::mpsc::channel(4);
    let queue = crate::websocket_input::InputQueue::new(handle.clone(), 1, output);
    let sequence = infraternal_protocol::MAX_FRAME_LEN as u64;
    for offset in 0..8 {
        queue.enqueue(input_wire(sequence + offset, b"z")).unwrap();
    }
    tokio::task::yield_now().await;
    assert!(queue.enqueue(input_wire(sequence + 8, b"z")).is_err());
    drop(queue);
    // Abort is observed before releasing credit: pending and buffered writes
    // must never outlive their browser attachment.
    tokio::task::yield_now().await;
    let mut credit = Vec::new();
    encode_muxed_frame_into(1, &Frame::Credit { bytes: 17 }, &mut credit).unwrap();
    handle.send_frame(credit.into()).await.unwrap();
    assert_eq!(inputs.recv().await.unwrap(), Observed::Credit);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), inputs.recv())
            .await
            .is_err()
    );
    backend.abort();
}

#[tokio::test]
async fn pending_browser_input_has_a_wire_byte_bound() {
    let (handle, _inputs, _output, backend) = saturated_handle().await;
    let (output, _events) = tokio::sync::mpsc::channel(4);
    let queue = crate::websocket_input::InputQueue::new(handle, 1, output);
    let half = infraternal_protocol::MAX_FRAME_LEN / 2;
    let bytes = vec![b'x'; half];
    let sequence = infraternal_protocol::MAX_FRAME_LEN as u64;
    queue.enqueue(input_wire(sequence, &bytes)).unwrap();
    queue
        .enqueue(input_wire(sequence + half as u64, &bytes))
        .unwrap();
    tokio::task::yield_now().await;
    assert!(
        queue
            .enqueue(input_wire(sequence + 2 * half as u64, &bytes))
            .is_err()
    );
    drop(queue);
    backend.abort();
}

/// The ninth pending request closes stream 1 and its trailing frames remain harmless.
async fn assert_overload_isolation(browser: &mut WebSocketStream<MaybeTlsStream<TcpStream>>) {
    let sequence = infraternal_protocol::MAX_FRAME_LEN as u64;
    for offset in 1..=9 {
        client_ws_send(
            browser,
            1,
            &Frame::Input {
                in_seq: sequence + offset,
                bytes: b"z",
            },
        )
        .await;
    }
    client_ws_send(
        browser,
        1,
        &Frame::Resize {
            cols: 91,
            rows: 24,
            px_w: 0,
            px_h: 0,
        },
    )
    .await;
    client_ws_send(browser, 1, &Frame::Credit { bytes: 17 }).await;
    client_ws_send(
        browser,
        0,
        &Frame::Ping {
            nonce: 130,
            sent_us: 0,
        },
    )
    .await;
    let mut closed = false;
    let mut responsive = false;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !closed || !responsive {
            let wire = read_client_frame(browser).await;
            let decoded = decode_muxed_frame(&wire).unwrap();
            match decoded.frame {
                Frame::Close { code: 1013, .. } => {
                    assert_eq!(decoded.stream_id, 1);
                    assert!(!closed);
                    closed = true;
                }
                // Control proofs are independent of terminal admission. As in
                // the browser, observe both results without treating a latency
                // Pong on stream 0 as a fence for stream 1's queued input.
                Frame::Pong { nonce: 130, .. } => responsive = true,
                other => panic!("unexpected overload response: {other:?}"),
            }
        }
    })
    .await
    .unwrap();
}

/// Fill exactly the actor window, confirming both accepted halves before the probe.
async fn fill_browser_input(
    browser: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
    inputs: &mut tokio::sync::mpsc::Receiver<Observed>,
) {
    let half = infraternal_protocol::MAX_FRAME_LEN / 2;
    let bytes = vec![b'x'; half];
    for sequence in [0, half as u64] {
        client_ws_send(
            browser,
            1,
            &Frame::Input {
                in_seq: sequence,
                bytes: &bytes,
            },
        )
        .await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), inputs.recv())
                .await
                .unwrap()
                .unwrap(),
            Observed::Input(sequence, half)
        );
    }
}

/// A cached content-free proof must neither renew idle authority nor poll a busy database.
#[tokio::test]
async fn idle_server_probes_do_not_renew_session_authority() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let (socket, _peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap()
    .with_authority_read_timeout(Duration::from_millis(50));
    let expiry = crate::websocket::now_seconds().unwrap() + 600;
    sqlx::query("UPDATE sessions SET expires=? WHERE token_hash=?")
        .bind(expiry)
        .bind(hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let mut authority = crate::websocket::probe_authority::Lease::new(&state, &f.user, &f.session)
        .await
        .unwrap();
    let after: i64 = sqlx::query_scalar("SELECT expires FROM sessions WHERE token_hash=?")
        .bind(hash(&f.session))
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(
        after, expiry,
        "idle server proofs renewed session authority"
    );
    let held = f.auth.pool.acquire().await.unwrap();
    for _ in 0..128 {
        assert!(
            authority
                .run(&state, &f.user, &f.session, async { Ok::<(), ()>(()) })
                .await
                .is_ok(),
            "content-free proofs polled SQLite"
        );
    }
    drop(held);
}

/// A committed logout cancels an already waiting proof before its write can resume.
#[tokio::test]
async fn idle_probe_authority_cancels_waiting_write_on_committed_revocation() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let (socket, _peer) = UnixStream::pair().unwrap();
    let state = std::sync::Arc::new(
        crate::websocket::WebSocketState::new(
            f.auth.clone(),
            f.auth.pool.clone(),
            EmbeddedAgent::from_test_socket(socket),
        )
        .await
        .unwrap()
        .with_authority_read_timeout(Duration::from_secs(2)),
    );
    let mut authority = crate::websocket::probe_authority::Lease::new(&state, &f.user, &f.session)
        .await
        .unwrap();
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let wrote = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker = {
        let state = state.clone();
        let entered = entered.clone();
        let release = release.clone();
        let wrote = wrote.clone();
        let user = f.user.clone();
        let token = f.session.clone();
        tokio::spawn(async move {
            authority
                .run(&state, &user, &token, async {
                    entered.notify_one();
                    release.notified().await;
                    wrote.store(true, std::sync::atomic::Ordering::Relaxed);
                    Ok(())
                })
                .await
        })
    };
    entered.notified().await;
    f.auth.logout(&f.session).await.unwrap();
    release.notify_one();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), worker)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(!wrote.load(std::sync::atomic::Ordering::Relaxed));
}

/// A cached deadline must reread authorized renewal before it closes an active socket.
#[tokio::test(start_paused = true)]
async fn idle_probe_authority_refreshes_expiry_after_authorized_activity() {
    use futures_util::FutureExt;
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let f = fixture().await;
    let (socket, _peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap()
    .with_authority_read_timeout(Duration::from_secs(2));
    let now = crate::websocket::now_seconds().unwrap();
    sqlx::query("UPDATE sessions SET expires=? WHERE token_hash=?")
        .bind(now + 5)
        .bind(hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let mut authority = crate::websocket::probe_authority::Lease::new(&state, &f.user, &f.session)
        .await
        .unwrap();
    f.auth.renewal(&f.session, &f.user, ()).await;
    let renewed: i64 = sqlx::query_scalar("SELECT expires FROM sessions WHERE token_hash=?")
        .bind(hash(&f.session))
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert!(renewed > now + 5);
    tokio::time::advance(Duration::from_secs(6)).await;
    authority
        .run(&state, &f.user, &f.session, async { Ok::<(), ()>(()) })
        .await
        .unwrap();
    let held = f.auth.pool.acquire().await.unwrap();
    assert!(
        authority
            .run(&state, &f.user, &f.session, async { Ok::<(), ()>(()) })
            .now_or_never()
            .unwrap()
            .is_ok(),
        "renewed expiry was not cached"
    );
    drop(held);
}

/// Incoming content-free proofs keep the real socket responsive without renewing or polling SQL.
#[tokio::test]
async fn idle_browser_probes_do_not_renew_or_poll_session_authority() {
    let _guard = SERIAL.lock().await;
    let (f, address, server) =
        socket_fixture_from_fixture(fixture().await, Some(Duration::from_secs(5))).await;
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
            client_info: "idle-proof-fixture",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    let expiry = crate::websocket::now_seconds().unwrap() + 600;
    sqlx::query("UPDATE sessions SET expires=? WHERE token_hash=?")
        .bind(expiry)
        .bind(hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 200,
            sent_us: 200,
        },
    )
    .await;
    let wire = read_client_frame(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&wire).unwrap().frame,
        Frame::Pong {
            nonce: 200,
            sent_us: 200
        }
    ));
    let after: i64 = sqlx::query_scalar("SELECT expires FROM sessions WHERE token_hash=?")
        .bind(hash(&f.session))
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(
        after, expiry,
        "idle browser proofs renewed session authority"
    );
    // With no attachments there are no server-generated probes. Every response
    // below therefore exercises the incoming browser proof path specifically.
    let held = f.auth.pool.acquire().await.unwrap();
    for nonce in 201..209 {
        client_ws_send(
            &mut socket,
            0,
            &Frame::Ping {
                nonce,
                sent_us: nonce,
            },
        )
        .await;
        let wire = read_client_frame(&mut socket).await;
        assert!(matches!(decode_muxed_frame(&wire).unwrap().frame,
            Frame::Pong { nonce: got, sent_us } if got == nonce && sent_us == nonce));
    }
    drop(held);
    server.abort();
}
