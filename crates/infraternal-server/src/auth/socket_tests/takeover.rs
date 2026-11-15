//! A full account's new page takes over its longest-hidden tab, never another account's (#523, owner decision B).
use super::*;

/// Hello bit 2: this page reports its visibility on control Event 0.
const VIEWER_VISIBILITY: u64 = 1 << 2;
/// The reason a taken-over tab is closed with (stream_close.rs `TAKEN_OVER`).
const TAKEN_OVER_TEXT: &str = "another tab of this account is using this connection";

/// Opens one welcomed socket for `cookie` that reports its visibility.
async fn welcomed_viewer(
    address: SocketAddr,
    cookie: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let (mut socket, _) = connect_async(test_ws_request(address, cookie))
        .await
        .unwrap();
    assert_server_hello(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: VIEWER_VISIBILITY,
            client_info: "takeover",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    socket
}

/// Tells the server the page is `hidden` (or visible again), then waits for a Pong behind it, so the server has
/// read the notice before the test goes on.
async fn report_visibility<S>(socket: &mut S, hidden: bool, nonce: u64)
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    let notice = format!(r#"{{"topic":"connection.visibility","hidden":{hidden}}}"#);
    client_ws_send(
        socket,
        0,
        &Frame::Event {
            sub_id: 0,
            event_json: notice.as_bytes(),
        },
    )
    .await;
    client_ws_send(socket, 0, &Frame::Ping { nonce, sent_us: 0 }).await;
    loop {
        let wire = read_client_frame(socket).await;
        if matches!(decode_muxed_frame(&wire).unwrap().frame, Frame::Pong { nonce: got, .. } if got == nonce)
        {
            return;
        }
    }
}

/// Reads until the server's protocol Close and returns its code and reason.
async fn read_close<S>(socket: &mut S) -> (u16, String)
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    loop {
        let wire = read_client_frame(socket).await;
        if let Frame::Close { code, reason } = decode_muxed_frame(&wire).unwrap().frame {
            return (code, reason.to_owned());
        }
    }
}

/// The 17th page takes over the longest-hidden tab of its own account; the next takes the next one; another
/// account's hidden tab (hidden before all of them) is never touched; with no hidden tab left, the limit refusal
/// from option A still applies.
#[tokio::test(start_paused = true)]
async fn a_full_account_takes_over_its_own_longest_hidden_tab() {
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let (f, address, server) = socket_fixture().await;
    let now = crate::websocket::now_seconds().unwrap();
    let other_user = uuid::Uuid::new_v4().to_string();
    let other_session = random();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'other',0,'unused','other','Other')")
        .bind(&other_user).execute(&f.auth.pool).await.unwrap();
    let mut tx = f.auth.pool.begin().await.unwrap();
    insert_session(&mut tx, &other_session, &other_user, "other", now, None)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let other_cookie = format!("__Host-infraternal={other_session}");
    let mut other = welcomed_viewer(address, &other_cookie).await;
    report_visibility(&mut other, true, 1).await;

    let cookie = format!("__Host-infraternal={}", f.session);
    let mut tabs = Vec::new();
    for _ in 0..16 {
        tabs.push(welcomed_viewer(address, &cookie).await);
    }
    // Hide the tabs newest first, so "hidden the longest" differs from "opened first": tab 15 goes hidden first.
    for (nonce, tab) in (10_u64..).zip(tabs.iter_mut().rev()) {
        tokio::time::advance(Duration::from_millis(1)).await;
        report_visibility(tab, true, nonce).await;
    }

    let _seventeenth = welcomed_viewer(address, &cookie).await;
    assert_eq!(read_close(&mut tabs[15]).await, (1000, TAKEN_OVER_TEXT.to_owned()));
    let _eighteenth = welcomed_viewer(address, &cookie).await;
    assert_eq!(read_close(&mut tabs[14]).await, (1000, TAKEN_OVER_TEXT.to_owned()));

    // The other account's tab, hidden before any of them, still answers.
    report_visibility(&mut other, true, 100).await;

    // Every remaining tab comes back into view: nothing is hidden, so the next page hears the limit instead.
    for (nonce, tab) in (200_u64..).zip(tabs[..14].iter_mut()) {
        report_visibility(tab, false, nonce).await;
    }
    assert_refused_over_limit(address, &cookie).await;
    server.abort();
}
