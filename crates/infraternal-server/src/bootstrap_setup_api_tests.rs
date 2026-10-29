//! Pins retained setup replay, exact host/window projection and live revocation over real `WebSockets`.
use super::*;
use infraternal_plugin_ssh::setup::{Stage, State};

fn setup_request(
    address: SocketAddr,
    origin: &str,
    cookie: Option<&str>,
) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let mut value = request(address, origin, cookie);
    *value.uri_mut() = format!("ws://{address}/v1/bootstrap/setup/ws")
        .parse()
        .unwrap();
    value
}

#[tokio::test]
async fn review_account_scope_lost_setup_source_reports_unavailable_and_retires() {
    let (auth, owner, cookie, _, address, serving, pool, api) = fixture(false).await;
    let host = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootless',1002,1)")
        .bind(host.as_bytes().as_slice()).bind(&owner).execute(&pool).await.unwrap();
    let status = api.runner.setup_status();
    status.begin(&owner, host, uuid::Uuid::new_v4()).unwrap();
    status
        .emit(&owner, host, Stage::Install, State::Done, None)
        .unwrap();
    let (mut socket, _) = connect_async(setup_request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    socket
        .send(ClientMessage::Text(
            serde_json::json!({"action":"subscribe","host_id":host,"window_id":"source-loss","after":0})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    // Receiving replay fences subscription installation and entry authority.
    let _ = setup_event(&mut socket).await;
    let source = auth.revocation_events(&owner);
    source.close_source_for_test();
    let closed = tokio::time::timeout(Duration::from_secs(2), socket.next()).await;
    // Explicit cleanup also retires a faulty upgrade before asserting the result.
    auth.logout(cookie.split_once('=').unwrap().1)
        .await
        .unwrap();
    let retired = tokio::time::timeout(Duration::from_secs(6), async {
        while api.setup_sockets.available_permits()
            != infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS
        {
            tokio::task::yield_now().await;
        }
    })
    .await;
    serving.abort();
    assert!(
        retired.is_ok(),
        "setup upgrade retained its admission permit"
    );
    assert!(matches!(
        closed.unwrap(),
        Some(Ok(ClientMessage::Close(Some(frame)))) if u16::from(frame.code) == 1013
    ));
}

#[tokio::test]
async fn setup_replay_outlives_its_socket_and_logout_retires_delivery() {
    let (auth, owner, cookie, _, address, serving, pool, api) = fixture(false).await;
    rejection(
        setup_request(address, "https://foreign.example.test", Some(&cookie)),
        StatusCode::FORBIDDEN,
    )
    .await;
    rejection(
        setup_request(address, ORIGIN, None),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let host = uuid::Uuid::new_v4();
    let session = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootless',1002,1)")
        .bind(host.as_bytes().as_slice()).bind(&owner).execute(&pool).await.unwrap();
    let status = api.runner.setup_status();
    status.begin(&owner, host, session).unwrap();
    status
        .emit(&owner, host, Stage::Install, State::Done, None)
        .unwrap();
    let (mut socket, _) = connect_async(setup_request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    socket
        .send(ClientMessage::Text(
            serde_json::json!({"action":"subscribe","host_id":host,"window_id":"first","after":0})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let first: serde_json::Value =
        serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
    assert_eq!(first["setup"]["session_id"], session.to_string());
    assert_eq!(first["setup"]["window_id"], "first");
    socket.close(None).await.unwrap();
    status
        .emit(&owner, host, Stage::Join, State::Done, None)
        .unwrap();
    let (mut socket, _) = connect_async(setup_request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    socket
        .send(ClientMessage::Text(
            serde_json::json!({"action":"subscribe","host_id":host,"window_id":"second","after":1})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let second: serde_json::Value =
        serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
    assert_eq!(second["setup"]["session_id"], session.to_string());
    assert_eq!(second["setup"]["window_id"], "second");
    assert_eq!(second["setup"]["sequence"], 2);
    auth.logout(cookie.split_once('=').unwrap().1)
        .await
        .unwrap();
    status
        .emit(&owner, host, Stage::Start, State::Done, None)
        .unwrap();
    let event = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap();
    assert!(
        !matches!(event, Some(Ok(ClientMessage::Text(_)))),
        "logout leaked retained setup"
    );
    serving.abort();
}

/// A window can subscribe after publication and must still see later failure,
/// retry eligibility and completion, with the original session coordinates.
#[tokio::test]
async fn late_setup_subscriber_receives_failure_and_retry_completion() {
    let (_, owner, cookie, _, address, serving, pool, api) = fixture(false).await;
    let host = uuid::Uuid::new_v4();
    let session = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootless',1002,1)")
        .bind(host.as_bytes().as_slice()).bind(&owner).execute(&pool).await.unwrap();
    let status = api.runner.setup_status();
    status.begin(&owner, host, session).unwrap();
    status
        .emit(&owner, host, Stage::Install, State::Done, None)
        .unwrap();
    status
        .emit(&owner, host, Stage::Join, State::Running, None)
        .unwrap();
    let (mut socket, _) = connect_async(setup_request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    socket.send(ClientMessage::Text(serde_json::json!({"action":"subscribe","host_id":host,"window_id":"late-window","after":0}).to_string().into())).await.unwrap();
    for (sequence, stage) in [(1, "install"), (2, "join")] {
        let event = setup_event(&mut socket).await;
        assert_eq!(event["sequence"], sequence);
        assert_eq!(event["stage"], stage);
        assert_eq!(event["session_id"], session.to_string());
        assert_eq!(event["window_id"], "late-window");
        assert_eq!(event["retry_available"], false);
    }
    let failure =
        infraternal_plugin_ssh::model::Failure::install("The host could not join. Try again.")
            .at(infraternal_plugin_ssh::model::InstallStep::Join);
    status
        .emit(&owner, host, Stage::Join, State::Failed, Some(&failure))
        .unwrap();
    let event = setup_event(&mut socket).await;
    assert_eq!(event["state"], "failed");
    assert_eq!(event["failed_step"], "join");
    assert_eq!(event["message"], failure.message);
    assert_eq!(event["retry_available"], true);
    socket.close(None).await.unwrap();
    let (mut socket, _) = connect_async(setup_request(address, ORIGIN, Some(&cookie)))
        .await
        .unwrap();
    socket.send(ClientMessage::Text(serde_json::json!({"action":"subscribe","host_id":host,"window_id":"reopened","after":2}).to_string().into())).await.unwrap();
    assert_eq!(setup_event(&mut socket).await["state"], "failed");
    // The trusted worker owns progress; retry preserves the existing session.
    status.begin(&owner, host, session).unwrap();
    for stage in [Stage::Install, Stage::Join, Stage::Start, Stage::Ready] {
        status.emit(&owner, host, stage, State::Done, None).unwrap();
        let event = setup_event(&mut socket).await;
        assert_eq!(event["attempt"], 2);
        assert_eq!(event["session_id"], session.to_string());
        assert_eq!(event["state"], "done");
        assert_eq!(event["retry_available"], false);
    }
    socket.close(None).await.unwrap();
    serving.abort();
}

async fn setup_event(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> serde_json::Value {
    let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serde_json::from_str::<serde_json::Value>(message.to_text().unwrap()).unwrap()["setup"].clone()
}
