//! Real mTLS confirms person cleanup precedes host-channel retirement after SQL authority.
use super::*;

struct LoginHost {
    store: EnrollmentStore,
    pool: sqlx::SqlitePool,
    host: Uuid,
    person: Uuid,
    listeners: RemoteListeners,
    observed: tokio::sync::oneshot::Receiver<serde_json::Value>,
    peer: tokio::task::JoinHandle<()>,
}
async fn login_host(reply: Option<bool>) -> LoginHost {
    login_host_action(reply, "terminal.login.revoke").await
}
async fn login_host_action(reply: Option<bool>, expected_action: &'static str) -> LoginHost {
    let (server, host_identity, root, _) = identities();
    let (store, pool, host, _) = admitted_store(&host_identity, &root).await;
    let person = Uuid::new_v4();
    sqlx::query("UPDATE users SET owner=0 WHERE id='owner'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,name,username,owner,recovery_hash) VALUES (?,'person','person',1,'test')").bind(person.to_string()).execute(&pool).await.unwrap();
    sqlx::query("UPDATE remote_hosts SET owner_id=? WHERE id=?")
        .bind(person.to_string())
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let hosts = RemoteHosts::default();
    let listeners = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store.clone(),
        hosts.clone(),
    )
    .await
    .unwrap();
    let address = listeners.local_addr().unwrap();
    let config = remote_tls::client_config(&host_identity, &[root]).unwrap();
    let (seen, observed) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let connection = remote_tls::dial(address, "localhost", &config)
            .await
            .unwrap();
        let mut receive = Receive::default();
        Transmit::default()
            .send(
                &connection.channel,
                0,
                &Frame::Hello {
                    version: 1,
                    caps: remote_quic::REMOTE_WRITER_BINDING,
                    client_info: "login-revocation-fixture",
                },
            )
            .await
            .unwrap();
        receive.next(&connection.channel).await.unwrap();
        if let Ok(request) = receive.next(&connection.channel).await
            && let Frame::Call {
                call_id,
                action_id,
                input_json,
            } = request.frame
        {
            assert_eq!(action_id, expected_action);
            seen.send(serde_json::from_slice(input_json).unwrap())
                .unwrap();
            if let Some(revoked) = reply {
                let json = serde_json::json!({"revoked":revoked}).to_string();
                let _ = Transmit::default()
                    .send(
                        &connection.channel,
                        0,
                        &Frame::Result {
                            call_id,
                            ok: true,
                            json: json.as_bytes(),
                        },
                    )
                    .await;
            }
        }
        let _ = receive.next(&connection.channel).await;
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if hosts.actor(host).await.is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    LoginHost {
        store,
        pool,
        host,
        person,
        listeners,
        observed,
        peer,
    }
}

#[tokio::test]
async fn authorized_host_revocation_sends_person_cleanup_before_retirement() {
    let mut fixture = login_host(Some(true)).await;
    assert!(
        fixture
            .store
            .revoke("foreign", fixture.host, now().unwrap())
            .await
            .is_err()
    );
    assert!(
        matches!(
            fixture.observed.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "foreign owner caused host cleanup"
    );
    let started = std::time::Instant::now();
    fixture
        .store
        .revoke(&fixture.person.to_string(), fixture.host, now().unwrap())
        .await
        .unwrap();
    let input = fixture
        .observed
        .await
        .expect("host retired without requesting person login cleanup");
    assert_eq!(input, serde_json::json!({"person":fixture.person}));
    let denied: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
            .bind(fixture.host.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(denied);
    fixture.peer.await.unwrap();
    println!(
        "login_revocation peer_reply=true authority_cut_ms={:.3}",
        started.elapsed().as_secs_f64() * 1000.0
    );
}

#[tokio::test]
async fn unconfirmed_person_cleanup_does_not_block_host_authority_cut() {
    let fixture = login_host(None).await;
    let started = std::time::Instant::now();
    fixture
        .store
        .revoke(&fixture.person.to_string(), fixture.host, now().unwrap())
        .await
        .unwrap();
    let input = fixture
        .observed
        .await
        .expect("cleanup was not attempted on a live host");
    assert_eq!(input, serde_json::json!({"person":fixture.person}));
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "unconfirmed login cleanup delayed authority retirement"
    );
    assert!(
        fixture
            .listeners
            .diagnostic_hosts
            .actor(fixture.host)
            .await
            .is_none()
    );
    fixture.peer.await.unwrap();
    println!(
        "login_revocation confirmed=false authority_cut_ms={:.3}",
        started.elapsed().as_secs_f64() * 1000.0
    );
}

/// Preferred host overrides reach an admitted remote actor before any terminal opens.
#[cfg(feature = "ssh")]
#[tokio::test]
async fn connected_remote_host_prepares_its_persons_preferred_account() {
    let fixture = login_host_action(Some(true), "terminal.login.prepare").await;
    let token = "remote-login-preparation-fixture";
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES(?,?,'fixture',unixepoch()+60,unixepoch(),1)")
        .bind(crate::auth::hash(token)).bind(fixture.person.to_string()).execute(&fixture.pool).await.unwrap();
    sqlx::query(
        "INSERT INTO preferred_host_accounts(user_id,host_id,account) VALUES(?,?,'deploy')",
    )
    .bind(fixture.person.to_string())
    .bind(fixture.host.as_bytes().as_slice())
    .execute(&fixture.pool)
    .await
    .unwrap();
    let auth = crate::auth::Auth::new(
        fixture.pool.clone(),
        "login.example.test",
        "https://login.example.test",
    )
    .await
    .unwrap();
    let (local, _peer) = tokio::net::UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        auth,
        fixture.pool.clone(),
        EmbeddedAgent::from_test_socket(local),
    )
    .await
    .unwrap()
    .with_remote_hosts(fixture.listeners.diagnostic_hosts.clone());
    let preparation = tokio::spawn(crate::websocket::prepare_preferred_login(
        Arc::new(state),
        fixture.person.to_string(),
        token.to_owned(),
    ));
    let input = tokio::time::timeout(Duration::from_secs(3), fixture.observed)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(input["person"], fixture.person.to_string());
    assert_eq!(input["account"], "deploy");
    preparation.await.unwrap();
    fixture.peer.abort();
}
