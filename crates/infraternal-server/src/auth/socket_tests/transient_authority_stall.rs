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
