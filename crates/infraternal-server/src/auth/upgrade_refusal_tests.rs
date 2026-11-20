//! While a root upgrade holds a host (D376), opening a shell on it tells only the host's owner that it
//! is being upgraded (D393, #399). The host ID in `ssh.session.open` comes from the browser, so a
//! signed-in account that names someone else's host must get the same `unavailable` reply as for a
//! host that does not exist, and learn nothing about its upgrade.
//!
//! These drive the real websocket and `open_terminal`, so they fail if the server stops refusing
//! with `host_upgrading`, or if it checks the upgrade state before ownership.
use super::*;
use crate::remote_runtime::RemoteHosts;

/// Insert a root remote host owned by `owner`, with no live link (the rootless link can be gone
/// mid-upgrade, which is exactly when the person must not be told "offline").
async fn remote_host(pool: &sqlx::SqlitePool, owner: &str) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootful',0,unixepoch())")
        .bind(id.as_bytes().as_slice())
        .bind(owner)
        .execute(pool)
        .await
        .unwrap();
    id
}

/// Insert a second, non-owner account that owns hosts of its own.
async fn other_person(pool: &sqlx::SqlitePool) -> &'static str {
    let id = "someone-else";
    sqlx::query("INSERT INTO users(id,name,username,owner,recovery_hash) VALUES (?,?,?,0,'test')")
        .bind(id)
        .bind(id)
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    id
}

/// Sign the fixture's owner in over a real websocket, ask `ssh.session.open` for each host in
/// `asks` (in order) while `upgrading` holds its upgrade guard, and return each reply's `reason`.
async fn reasons_while_upgrading(
    f: &Fixture,
    upgrading: uuid::Uuid,
    asks: &[uuid::Uuid],
) -> Vec<serde_json::Value> {
    let (socket, mut peer) = UnixStream::pair().unwrap();
    let hosts = RemoteHosts::default();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap()
    .with_remote_hosts(hosts.clone());
    let app = crate::websocket::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut receive = BytesMut::new();
    read_leg_b_frame(&mut peer, &mut receive).await.unwrap();
    leg_b_send(
        &mut peer,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "upgrade-refusal-fixture",
        },
    )
    .await;
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
            client_info: "upgrade-refusal-fixture",
        },
    )
    .await;
    read_welcome(&mut browser).await;

    // The same guard a real promotion holds for its whole lifetime (host_promotion.rs).
    let promotion = hosts.block_terminal_opens(upgrading).await.unwrap();
    let mut reasons = Vec::new();
    for (call, host) in (700_u32..).zip(asks) {
        let input = serde_json::json!({ "host_id": host }).to_string();
        client_ws_send(
            &mut browser,
            0,
            &Frame::Call {
                call_id: call,
                action_id: "ssh.session.open",
                input_json: input.as_bytes(),
            },
        )
        .await;
        let body = loop {
            let response = read_client_frame(&mut browser).await;
            if let Frame::Result { call_id, ok, json } =
                decode_muxed_frame(&response).unwrap().frame
                && call_id == call
            {
                assert!(!ok, "a shell opened on a host that is being upgraded");
                break serde_json::from_slice::<serde_json::Value>(json).unwrap();
            }
        };
        reasons.push(body["reason"].clone());
    }
    drop(promotion);
    server.abort();
    reasons
}

/// The host's owner is told the host is being upgraded, even though its rootless link is gone.
#[tokio::test]
async fn owner_hears_the_host_is_being_upgraded() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let host = remote_host(&f.auth.pool, &f.user).await;
    let reasons = reasons_while_upgrading(&f, host, &[host]).await;
    assert_eq!(reasons, [serde_json::json!("host_upgrading")]);
}

/// Another account's host that is being upgraded reads exactly like a host that does not exist.
#[tokio::test]
async fn non_owner_learns_nothing_about_an_upgrade() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let other = other_person(&f.auth.pool).await;
    let theirs = remote_host(&f.auth.pool, other).await;
    let missing = uuid::Uuid::new_v4();
    let reasons = reasons_while_upgrading(&f, theirs, &[theirs, missing]).await;
    assert_eq!(
        reasons,
        [
            serde_json::json!("unavailable"),
            serde_json::json!("unavailable")
        ]
    );
}
