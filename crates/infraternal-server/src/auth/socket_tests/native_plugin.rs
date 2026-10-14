//! Exercises declared native routing on the real SQLite-authenticated production WebSocket router [D208,D232,#146].
use super::*;
use infraternal_protocol::desktop::{Delivery, Message as Desktop};

#[tokio::test]
async fn native_bulk_keeps_authenticated_control_live_and_logout_retires_worker() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let (socket, _peer) = UnixStream::pair().unwrap();
    let mut state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap()
    .with_authority_read_timeout(Duration::from_secs(2));
    state.plugins = crate::plugins::PluginRuntime::new(
        vec![Arc::new(crate::plugins::retirement_tests::NativeEcho(
            100 * 1024,
        ))],
        "server",
    )
    .with_store(f.auth.pool.clone())
    .await
    .unwrap();
    let runtime = state.plugins.clone();
    runtime.set_enabled("desktop", true).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(axum::serve(listener, crate::websocket::router(state)).into_future());
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
            caps: 8,
            client_info: "native-routing",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    client_ws_send(
        &mut socket,
        1,
        &Frame::Desktop(Desktop::Attach {
            session_id: &[9; 16],
            delivery: Delivery::Reliable,
        }),
    )
    .await;
    let video = read_client_frame(&mut socket).await;
    let decoded = decode_muxed_frame(&video).unwrap();
    assert_eq!(decoded.stream_id, 1);
    assert!(
        matches!(decoded.frame, Frame::Desktop(Desktop::Video { bytes, .. }) if bytes.len() == 100 * 1024)
    );
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 146,
            sent_us: 1,
        },
    )
    .await;
    let pong = read_client_frame(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&pong).unwrap().frame,
        Frame::Pong { nonce: 146, .. }
    ));
    assert_eq!(runtime.active_workers("desktop"), 1);
    f.auth.logout(&f.session).await.unwrap();
    let next = tokio::time::timeout(Duration::from_secs(3), socket.next())
        .await
        .unwrap();
    assert!(matches!(next, None | Some(Ok(Message::Close(_)) | Err(_))));
    tokio::time::timeout(Duration::from_secs(2), async {
        while runtime.active_workers("desktop") != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    server.abort();
    f.auth.pool.close().await;
}
