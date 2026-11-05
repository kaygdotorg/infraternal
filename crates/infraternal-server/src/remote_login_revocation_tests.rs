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
    /// Exact current leaf, distinct from the expired enrollment fixture record.
    fingerprint: [u8; 32],
}
/// Enroll a real TLS fixture whose initial control channel accepts no grants.
async fn login_host(reply: Option<bool>) -> LoginHost {
    login_host_action(reply, "terminal.login.revoke").await
}
/// Start an enrolled peer and retain its exact TLS identity for reconnect proof.
async fn login_host_action(reply: Option<bool>, expected_action: &'static str) -> LoginHost {
    let (server, host_identity, root, _) = identities();
    let (store, pool, host, fingerprint) = admitted_store(&host_identity, &root).await;
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
        fingerprint,
    }
}

/// Start retirement and wait for its committed denial while retaining its
/// receipt waiter. The test controls reconnect and durability independently.
async fn pending_retirement(
    fixture: &LoginHost,
) -> tokio::task::JoinHandle<Result<(), crate::enrollment::EnrollmentError>> {
    let store = fixture.store.clone();
    let owner = fixture.person.to_string();
    let host = fixture.host;
    let request = tokio::spawn(async move { store.revoke(&owner, host, now().unwrap()).await });
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let pending: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM remote_login_cleanup WHERE host_id=? AND confirmed=0)",
            )
            .bind(host.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
            if pending {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    request
}

/// Persist denial first and complete retirement only after a durable reconnect reply.
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
    let retirement = pending_retirement(&fixture).await;
    let pending: (String, bool) =
        sqlx::query_as("SELECT person_id,confirmed FROM remote_login_cleanup WHERE host_id=?")
            .bind(fixture.host.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(pending, (fixture.person.to_string(), false));
    reconnect_cleanup(&fixture, Some(true)).await;
    retirement.await.unwrap().unwrap();
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

/// Offline cleanup cuts normal authority but cannot complete retirement.
#[tokio::test]
async fn unconfirmed_person_cleanup_does_not_block_host_authority_cut() {
    let fixture = login_host(None).await;
    let retirement = pending_retirement(&fixture).await;
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
    assert!(
        !retirement.is_finished(),
        "offline retirement reported success"
    );
    retirement.abort();
    let _ = retirement.await;
    fixture.peer.await.unwrap();
    eprintln!("login_cleanup confirmed=false authority_cut=true retirement_pending=true");
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

/// Wait until the server observes a test peer's disconnect and releases its
/// unique host claim. This fences reconnect ordering without a timing assertion.
async fn cleanup_disconnected(host: Uuid) {
    // A generous deadlock guard, not a response-time assertion. Completion is
    // ordered by the server releasing its host claim after the socket closes.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let held = crate::remote_runtime::LOGIN_CLEANUPS
                .hosts
                .lock()
                .unwrap()
                .contains(&host);
            if !held {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("disconnected cleanup retained its host claim");
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
            drop(connection);
            cleanup_disconnected(fixture.host).await;
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
    if durable == Some(false) {
        // Busy replies retain the operation. Disconnect to model a retryable
        // transport loss instead of expecting a finite retry budget to close it.
        drop(connection);
        cleanup_disconnected(fixture.host).await;
        return;
    }
    // Completion closes the private cleanup actor and never publishes it.
    assert!(receive.next(&connection.channel).await.is_err());
}

/// Unconfirmed cleanup survives a server store restart and a refused reply;
/// only a later durable acknowledgement retires it, without restoring authority.
#[tokio::test]
async fn unconfirmed_cleanup_replays_after_restart_without_granting_remote_access() {
    let fixture = login_host(None).await;
    let retirement = pending_retirement(&fixture).await;
    retirement.abort();
    let _ = retirement.await;
    let restarted = EnrollmentStore::new(fixture.pool.clone());
    let fingerprint = fixture.fingerprint;
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

/// An authoritative revocation cannot finish retirement before a durable host
/// receipt. Reconnection delivers only cleanup while normal authority stays shut.
#[tokio::test]
async fn retirement_waits_for_durable_acceptance_on_reconnect() {
    let fixture = login_host(None).await;
    let store = fixture.store.clone();
    let owner = fixture.person.to_string();
    let host = fixture.host;
    let mut retirement =
        tokio::spawn(async move { store.revoke(&owner, host, now().unwrap()).await });
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let pending: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM remote_login_cleanup WHERE host_id=? AND confirmed=0)",
            )
            .bind(host.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
            if pending {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
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
                client_info: "durable-retirement-fixture",
            },
        )
        .await
        .unwrap();
    let greeting = receive.next(&connection.channel).await.unwrap();
    assert!(matches!(greeting.frame, Frame::Hello { .. }));
    let request = tokio::select! {
        biased;
        completed = &mut retirement => panic!("retirement completed without a durable agent receipt: {completed:?}"),
        request = receive.next(&connection.channel) => request.unwrap(),
    };
    let Frame::Call {
        call_id,
        action_id: "terminal.login.revoke",
        input_json,
    } = request.frame
    else {
        panic!("cleanup-only reconnect did not deliver the retained refusal");
    };
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(input_json).unwrap()["person"],
        fixture.person.to_string()
    );
    let retired: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(!retired, "server retired access before durable acceptance");
    Transmit::default()
        .send(
            &connection.channel,
            0,
            &Frame::Result {
                call_id,
                ok: true,
                json: br#"{"revoked":true}"#,
            },
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), retirement)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let confirmed: bool =
        sqlx::query_scalar("SELECT confirmed FROM remote_login_cleanup WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert!(confirmed);
    fixture.peer.await.unwrap();
}

/// A committed pending refusal survives closing every server database connection;
/// reopening must allow cleanup only, without pretending retirement was confirmed.
#[tokio::test]
async fn pending_revocation_survives_database_reopen_before_acceptance() {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    let path = std::path::PathBuf::from(
        std::env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into()),
    )
    .join(format!("pending-login-{}.sqlite", Uuid::new_v4()));
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap();
    let (store, pool, host) = crate::enrollment::authority::tests::enrolled_with_pool(pool).await;
    let person = Uuid::new_v4();
    sqlx::query("UPDATE users SET owner=0 WHERE id='owner'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,name,username,owner,recovery_hash) VALUES (?,'person','person',1,'test')")
        .bind(person.to_string()).execute(&pool).await.unwrap();
    sqlx::query("UPDATE remote_hosts SET owner_id=? WHERE id=?")
        .bind(person.to_string())
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let owner = person.to_string();
    let pending_store = store.clone();
    let request = tokio::spawn(async move { pending_store.revoke(&owner, host, 101).await });
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let present: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM remote_login_cleanup WHERE host_id=? AND confirmed=0)",
            )
            .bind(host.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
            if present {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    request.abort();
    let _ = request.await;
    drop(store);
    pool.close().await;
    let reopened = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let restarted = EnrollmentStore::new(reopened.clone());
    let retired: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&reopened)
            .await
            .unwrap();
    assert!(
        !retired,
        "restart found retirement without durable host acceptance"
    );
    assert!(restarted.admit(&[1; 32], 101).await.is_err());
    let (_, cleanup_person) = restarted.admit_cleanup(&[1; 32], 101).await.unwrap();
    assert_eq!(cleanup_person, person);
    restarted.confirm_login_cleanup(host, person).await.unwrap();
    let confirmed: bool =
        sqlx::query_scalar("SELECT confirmed FROM remote_login_cleanup WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&reopened)
            .await
            .unwrap();
    assert!(confirmed);
    drop(restarted);
    reopened.close().await;
    std::fs::remove_file(path).unwrap();
}

/// Queued cleanup must not consume the reserve used by ordinary reconnects.
/// Count actual owned permits instead of relying on handshake response timing.
#[tokio::test]
async fn cleanup_delivery_returns_handshake_admission_before_waiting() {
    let fixture = login_host(None).await;
    let normal = AuthorityGuard::admit(fixture.store.clone(), fixture.fingerprint)
        .await
        .unwrap();
    let retirement = pending_retirement(&fixture).await;
    let cleanup = AuthorityGuard::admit_transport(fixture.store.clone(), fixture.fingerprint)
        .await
        .unwrap();
    for authority in [normal, cleanup] {
        let is_cleanup = authority.cleanup_person().is_some();
        let slots = Arc::new(tokio::sync::Semaphore::new(2));
        let permits = (
            slots.clone().acquire_owned().await.unwrap(),
            slots.clone().acquire_owned().await.unwrap(),
        );
        let mut admission =
            crate::remote_standby::Admission::new(authority, permits, Arc::default());
        assert_eq!(slots.available_permits(), 0);
        admission.release_cleanup_handshake();
        assert_eq!(
            slots.available_permits(),
            if is_cleanup { 2 } else { 0 },
            "cleanup retained normal handshake admission"
        );
    }
    retirement.abort();
    let _ = retirement.await;
    fixture.peer.abort();
}
