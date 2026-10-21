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
    f.auth.revocations.send_replace(());
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
