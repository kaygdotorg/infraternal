//! Independent #244 checks that parking browser probes never parks session revocation or expiry.
use super::*;

type Browser =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Set short expiry after upgrade renewal but before proof authority is created.
/// The hidden notice and subsequent correlated reply never renew that expiry.
async fn parked_socket(
    expire: bool,
) -> (Fixture, Browser, tokio::task::JoinHandle<()>, Option<i64>) {
    let (f, address, server) = socket_fixture().await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut socket).await;
    let expiry = if expire {
        Some(
            sqlx::query_scalar::<_, i64>(
                "UPDATE sessions SET expires=unixepoch()+2 WHERE user_id=? RETURNING expires",
            )
            .bind(&f.user)
            .fetch_one(&f.auth.pool)
            .await
            .unwrap(),
        )
    } else {
        None
    };
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 4,
            client_info: "mobile visibility review",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Event {
            sub_id: 0,
            event_json: br#"{"topic":"connection.visibility","hidden":true}"#,
        },
    )
    .await;
    // A correlated response fences consumption of the preceding hidden notice.
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 244,
            sent_us: 244,
        },
    )
    .await;
    let reply = read_client_frame(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&reply).unwrap().frame,
        Frame::Pong { nonce: 244, .. }
    ));
    (f, socket, server, expiry)
}

async fn closes_without_application_data(socket: &mut Browser) {
    loop {
        match socket.next().await {
            None | Some(Err(_) | Ok(Message::Close(_))) => break,
            Some(Ok(Message::Binary(wire))) => assert!(
                matches!(
                    decode_muxed_frame(&wire).unwrap().frame,
                    Frame::Close { .. }
                ),
                "hidden unauthorized socket emitted an application frame"
            ),
            Some(Ok(_)) => {}
        }
    }
}

#[tokio::test(start_paused = true)]
async fn review_hidden_socket_cannot_park_logout_revocation() {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let (f, mut socket, server, _) = parked_socket(false).await;
    f.auth.logout(&f.session).await.unwrap();
    let result = tokio::time::timeout(
        Duration::from_millis(1500),
        closes_without_application_data(&mut socket),
    )
    .await;
    server.abort();
    assert!(
        result.is_ok(),
        "hidden socket retained revoked session authority"
    );
}

#[tokio::test(start_paused = true)]
async fn review_hidden_socket_cannot_park_absolute_session_expiry() {
    let _guard = SERIAL.lock().await;
    let clock = FrozenSocketTime::new().await;
    let (f, mut socket, server, expiry) = parked_socket(true).await;
    let expiry = expiry.unwrap();
    let persisted: i64 = sqlx::query_scalar("SELECT expires FROM sessions WHERE user_id=?")
        .bind(&f.user)
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(
        persisted, expiry,
        "hidden notice or proof renewed the session"
    );
    clock.reach_wall_deadline(expiry).await;
    tokio::time::advance(Duration::from_secs(3)).await;
    let result = tokio::time::timeout(
        Duration::from_millis(1500),
        closes_without_application_data(&mut socket),
    )
    .await;
    server.abort();
    assert!(
        result.is_ok(),
        "hidden socket retained expired session authority"
    );
}
