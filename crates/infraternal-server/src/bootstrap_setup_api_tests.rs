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
