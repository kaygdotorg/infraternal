//! Verifies wire outcomes of shared authority wakes without an active proof writer (#240).

use super::*;
use futures_util::FutureExt;

type Browser =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn idle_browser(address: SocketAddr, f: &Fixture) -> Browser {
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
            client_info: "busy-wake-review",
        },
    )
    .await;
    read_welcome(&mut browser).await;
    browser
}

/// An idle socket has no active proof writer to supply the correct close code
/// on behalf of the main loop. Observe both application and WebSocket closes.
#[tokio::test(start_paused = true)]
async fn idle_busy_revocation_wake_sends_server_busy_close_code() {
    let _serial = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let (f, address, server) = socket_fixture().await;
    let mut browser = idle_browser(address, &f).await;
    super::close_logging::authorized_result(&mut browser, 239).await;
    let held = f.auth.pool.acquire().await.unwrap();
    f.auth.revocations.publish(&f.user, None);
    let mut codes = Vec::new();
    let mut closed = false;
    // Only explicit runtime time passes. Real SQL/network work gets runnable
    // turns, and cannot consume the production one-second retry budget.
    for _ in 0..300 {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        while let Some(message) = browser.next().now_or_never() {
            match message {
                Some(Ok(Message::Binary(wire))) => {
                    if let Frame::Close { code, .. } = decode_muxed_frame(&wire).unwrap().frame {
                        codes.push(code);
                    }
                }
                Some(Ok(Message::Close(frame))) => {
                    if let Some(frame) = frame {
                        codes.push(u16::from(frame.code));
                    }
                    closed = true;
                    break;
                }
                None | Some(Err(_)) => {
                    closed = true;
                    break;
                }
                _ => {}
            }
        }
        if closed {
            break;
        }
        tokio::time::advance(Duration::from_millis(5)).await;
    }
    drop(held);
    server.abort();
    assert!(closed, "the unavailable socket did not fail closed");
    assert!(
        codes.contains(&1013),
        "busy wake did not communicate server_busy (1013); close codes: {codes:?}"
    );
}

/// A shared wake at the per-person ceiling must preserve every live socket,
/// even when several callers queue behind the four retained read places.
#[tokio::test(start_paused = true)]
async fn sixteen_woken_sockets_recover_application_authority_after_a_short_stall() {
    let _serial = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let f = fixture().await;
    let (socket, _peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap();
    let pending_reads = state.authority_read_monitor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, crate::websocket::router(state))
            .await
            .unwrap();
    });
    let mut browsers = Vec::new();
    for _ in 0..16 {
        let mut browser = idle_browser(address, &f).await;
        super::close_logging::authorized_result(&mut browser, 239).await;
        browsers.push(browser);
    }
    let held = f.auth.pool.acquire().await.unwrap();
    f.auth.revocations.publish(&f.user, None);
    while pending_reads() < 4 {
        tokio::task::yield_now().await;
    }
    for _ in 0..60 {
        tokio::time::advance(Duration::from_millis(5)).await;
        tokio::task::yield_now().await;
        assert_eq!(pending_reads(), 4);
    }
    drop(held);
    // Let detached reads finish at stationary time before releasing the next
    // retry wave. No worker competes against the host's physical scheduler.
    while pending_reads() != 0 {
        tokio::task::yield_now().await;
    }
    let recovered = async {
        for browser in &mut browsers {
            client_ws_send(
                browser,
                0,
                &Frame::Call {
                    call_id: 240,
                    action_id: "test.not.an.action",
                    input_json: b"{}",
                },
            )
            .await;
        }
        for browser in &mut browsers {
            let wire = read_client_frame(browser).await;
            assert!(matches!(
                decode_muxed_frame(&wire).unwrap().frame,
                Frame::Result { call_id: 240, .. }
            ));
        }
    };
    tokio::pin!(recovered);
    let recovering = tokio::time::Instant::now();
    while recovered.as_mut().now_or_never().is_none() {
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        if pending_reads() == 0 {
            tokio::time::advance(Duration::from_millis(1)).await;
        }
        assert!(recovering.elapsed() < Duration::from_secs(1));
    }
    while pending_reads() != 0 {
        tokio::task::yield_now().await;
    }
    drop(f.auth.pool.acquire().await.unwrap());
    server.abort();
}
