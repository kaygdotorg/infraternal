//! Real mTLS proves durable cleanup replay cannot restore retired host authority.
use super::*;

/// A real enrolled TLS host and the durable server store used to retire it.
struct LoginHost {
    store: EnrollmentStore,
    pool: sqlx::SqlitePool,
    host: Uuid,
    person: Uuid,
    listeners: RemoteListeners,
    observed: tokio::sync::oneshot::Receiver<serde_json::Value>,
    peer: tokio::task::JoinHandle<()>,
    /// Exact enrolled credentials reused to prove cleanup-only reconnect admission.
    config: openssl::ssl::SslConnector,
}
/// Enroll a real TLS fixture whose initial control channel accepts no grants.
async fn login_host(reply: Option<bool>) -> LoginHost {
    login_host_action(reply, "terminal.login.revoke").await
}
/// Start an enrolled peer and retain its exact TLS identity for reconnect proof.
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
    let peer_config = config.clone();
    let peer = tokio::spawn(async move {
        let connection = remote_tls::dial(address, "localhost", &peer_config)
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
        config,
    }
}

/// Persist retirement and its cleanup together, then confirm only a durable reconnect reply.
#[tokio::test]
async fn authorized_host_revocation_retains_cleanup_after_authority_retirement() {
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
    fixture
        .store
        .revoke(&fixture.person.to_string(), fixture.host, now().unwrap())
        .await
        .unwrap();
    let pending: (String, bool) =
        sqlx::query_as("SELECT person_id,confirmed FROM remote_login_cleanup WHERE host_id=?")
            .bind(fixture.host.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(pending, (fixture.person.to_string(), false));
    reconnect_cleanup(&fixture, Some(true)).await;
    let denied: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
            .bind(fixture.host.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(denied);
    fixture.peer.await.unwrap();
    eprintln!("login_cleanup pending_after_retirement=true durable_reconnect_confirmed=true");
}

/// An offline cleanup remains unconfirmed while server authority retires durably.
#[tokio::test]
async fn unconfirmed_person_cleanup_does_not_block_host_authority_cut() {
    let fixture = login_host(None).await;
    fixture
        .store
        .revoke(&fixture.person.to_string(), fixture.host, now().unwrap())
        .await
        .unwrap();
    // Authority retirement closes the old transport; cleanup is delivered on
    // the next authenticated cleanup-only connection from the retained outbox.
    let confirmed: bool =
        sqlx::query_scalar("SELECT confirmed FROM remote_login_cleanup WHERE host_id=?")
            .bind(fixture.host.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(!confirmed, "a finite timeout must not confirm durability");
    assert!(
        fixture
            .listeners
            .diagnostic_hosts
            .actor(fixture.host)
            .await
            .is_none()
    );
    fixture.peer.await.unwrap();
    eprintln!("login_cleanup confirmed=false authority_retired=true");
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

/// Reconnect a tombstoned host using its real enrolled mTLS identity. The only
/// admitted request must be the persisted person's cleanup, never a new login.
async fn reconnect_cleanup(fixture: &LoginHost, durable: Option<bool>) {
    let connection = remote_tls::dial(
        fixture.listeners.local_addr().unwrap(),
        "localhost",
        &fixture.config,
    )
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
                client_info: "cleanup-reconnect-fixture",
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        receive.next(&connection.channel).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    for _ in 0..if durable == Some(false) { 3 } else { 1 } {
        let request = receive.next(&connection.channel).await.unwrap();
        let Frame::Call {
            call_id,
            action_id,
            input_json,
        } = request.frame
        else {
            panic!("cleanup request missing")
        };
        assert_eq!(action_id, "terminal.login.revoke");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(input_json).unwrap(),
            serde_json::json!({"person": fixture.person})
        );
        let Some(durable) = durable else {
            // Dropping the socket after receipt models a lost acknowledgement.
            return;
        };
        let json = serde_json::json!({"revoked": durable}).to_string();
        Transmit::default()
            .send(
                &connection.channel,
                0,
                &Frame::Result {
                    call_id,
                    ok: true,
                    json: json.as_bytes(),
                },
            )
            .await
            .unwrap();
    }
    // Completion closes the private cleanup actor and never publishes it.
    assert!(receive.next(&connection.channel).await.is_err());
}

/// Unconfirmed cleanup survives a server store restart and a refused reply;
/// only a later durable acknowledgement retires it, without restoring authority.
#[tokio::test]
async fn unconfirmed_cleanup_replays_after_restart_without_granting_remote_access() {
    let fixture = login_host(None).await;
    fixture
        .store
        .revoke(&fixture.person.to_string(), fixture.host, now().unwrap())
        .await
        .unwrap();
    let restarted = EnrollmentStore::new(fixture.pool.clone());
    let fingerprint: Vec<u8> =
        sqlx::query_scalar("SELECT fingerprint FROM remote_certificates WHERE host_id=?")
            .bind(fixture.host.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    let fingerprint: [u8; 32] = fingerprint.try_into().unwrap();
    assert!(
        AuthorityGuard::admit(restarted.clone(), fingerprint)
            .await
            .is_err()
    );
    let cleanup = AuthorityGuard::admit_transport(restarted.clone(), fingerprint)
        .await
        .unwrap();
    assert_eq!(cleanup.cleanup_person(), Some(fixture.person));
    assert!(cleanup.admit_operation().await.is_err());
    reconnect_cleanup(&fixture, None).await;
    reconnect_cleanup(&fixture, Some(false)).await;
    let confirmed: bool =
        sqlx::query_scalar("SELECT confirmed FROM remote_login_cleanup WHERE host_id=?")
            .bind(fixture.host.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(
        !confirmed,
        "a refused reply discarded the server's durable intent"
    );
    reconnect_cleanup(&fixture, Some(true)).await;
    let confirmed: bool =
        sqlx::query_scalar("SELECT confirmed FROM remote_login_cleanup WHERE host_id=?")
            .bind(fixture.host.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(confirmed);
    assert!(
        AuthorityGuard::admit_transport(restarted, fingerprint)
            .await
            .is_err()
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
}
