//! The removal outbox asks the host to uninstall itself on its cleanup-only reconnect (#409).
//!
//! A removed host's infraternal agent reconnects after its link is cut: at
//! once when it was online, or when it comes back after being offline. That
//! reconnect is admitted only to deliver the retained cleanup. These tests play
//! the agent's side of a real WebSocket link, with leg-B TLS inside it, to the
//! production admission path
//! and pin the order the outbox keeps: the login revocation and its receipt
//! (D352) first, then the uninstall request, then one transaction that records
//! the answer and retires the entry. An answer that never arrives retires
//! nothing, so the next reconnect asks again.
use super::tests::{HostLink, Route, hello, route};
use super::*;
use infraternal_agent::remote_tls::Identity;
use infraternal_protocol::Frame;
use openssl::x509::X509;
use uuid::Uuid;

/// The host side of one agent link.
type Socket = HostLink;

/// A host removed by its owner, `person`, with an uninstall still to deliver,
/// and a server whose agent route admits its cleanup-only reconnect.
struct Removed {
    /// The server's database, read to check the removal's ledger.
    pool: sqlx::SqlitePool,
    /// A clone of the server's own enrollment store: it shares the change
    /// signal a removal waits on.
    store: crate::enrollment::EnrollmentStore,
    /// Live host registry shared with the removal publisher.
    hosts: RemoteHosts,
    /// The removed host.
    host: Uuid,
    /// The host's CA-issued identity, still valid and individually unrevoked.
    identity: Identity,
    /// The CA root both sides trust.
    root: X509,
    /// The server's agent route, stopped when the fixture is dropped.
    route: Route,
}

/// Enrol a host, then record its removal the way `publish` commits it for a
/// person's host: the cleanup row plus a removal row whose uninstall is
/// `pending`.
async fn removed() -> Removed {
    let (leaf, identity, root, _) = crate::remote_runtime::tests::identities();
    let fingerprint = openssl::sha::sha256(&identity.certificate.to_der().unwrap());
    // The shared fixture gives every test the same host id, but the cleanup
    // lane is process-wide and admits one cleanup per host at a time. So each
    // test enrolls a host of its own, with its own certificate, or parallel
    // tests refuse each other's reconnects.
    let (store, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let host = Uuid::new_v4();
    let now = crate::runtime::unix_seconds().unwrap();
    sqlx::query("INSERT INTO remote_hosts (id, owner_id, mode, execution_uid, created_at) VALUES (?, 'owner', 'rootless', 1002, ?)")
        .bind(host.as_bytes().as_slice())
        .bind(now - 1)
        .execute(&pool)
        .await
        .unwrap();
    let token = store
        .issue(
            "owner",
            host,
            crate::enrollment::Mode::Rootless,
            now,
            &openssl::sha::sha256(&[3u8; 32]),
        )
        .await
        .unwrap();
    store
        .redeem(
            token.secret(),
            host,
            crate::enrollment::Mode::Rootless,
            now,
            &crate::enrollment::CertificateRecord {
                fingerprint,
                issuer_fingerprint: openssl::sha::sha256(&root.to_der().unwrap()),
                public_key: crate::identity_key::IdentityKey::Ed25519([3; 32]),
                not_before: now - 1,
                not_after: now - 1 + 604_800,
            },
        )
        .await
        .unwrap();
    let person = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,name,username,owner,recovery_hash) VALUES (?,'cleanup','cleanup',0,'test')")
        .bind(person.to_string()).execute(&pool).await.unwrap();
    sqlx::query("UPDATE remote_hosts SET owner_id=? WHERE id=?")
        .bind(person.to_string())
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO remote_login_cleanup(host_id,person_id) VALUES (?,?)")
        .bind(host.as_bytes().as_slice())
        .bind(person.to_string())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO remote_host_removals(host_id,owner_id,requested_at,uninstall,host_cleanup) VALUES(?,?,unixepoch(),1,'pending')")
        .bind(host.as_bytes().as_slice())
        .bind(person.to_string())
        .execute(&pool)
        .await
        .unwrap();
    let waiter = store.clone();
    let hosts = RemoteHosts::default();
    let route = route(
        store,
        hosts.clone(),
        Arc::new(Semaphore::new(4)),
        Arc::new(crate::remote_admission::SourceSlots::new(4)),
        &leaf,
        &root,
    )
    .await;
    Removed {
        pool,
        store: waiter,
        hosts,
        host,
        identity,
        root,
        route,
    }
}

impl Removed {
    /// Reconnect as the removed host's infraternal agent: leg-B TLS inside
    /// the WebSocket, then Hello.
    async fn reconnect(&self) -> Socket {
        let link = HostLink::dial(self.route.endpoint, &self.identity, &self.root)
            .await
            .unwrap();
        link.send(&hello("removal-outbox-test")).await.unwrap();
        link
    }

    /// The removal's ledger: (receipt confirmed, entry retired, uninstall state).
    async fn ledger(&self) -> (bool, bool, String) {
        sqlx::query_as("SELECT q.confirmed=1, h.revoked_at IS NOT NULL, r.host_cleanup FROM remote_hosts h JOIN remote_login_cleanup q ON q.host_id=h.id JOIN remote_host_removals r ON r.host_id=h.id WHERE h.id=?")
            .bind(self.host.as_bytes().as_slice())
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    /// The kernel objects the removal recorded as left, as stored.
    async fn retained(&self) -> Option<String> {
        sqlx::query_scalar("SELECT retained FROM remote_host_removals WHERE host_id=?")
            .bind(self.host.as_bytes().as_slice())
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    /// Wait until the ledger matches `expected`, or fail after a bound.
    async fn settles(&self, expected: (bool, bool, &str)) {
        let reached = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (confirmed, retired, cleanup) = self.ledger().await;
                if (confirmed, retired, cleanup.as_str()) == expected {
                    return;
                }
                // sleep: the receipt commits on the server's task; poll the ledger briefly.
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            reached.is_ok(),
            "ledger stayed {:?}, expected {expected:?}",
            self.ledger().await
        );
    }
}

/// Write one control-stream frame from the host's side.
async fn send(socket: &mut Socket, frame: &Frame<'_>) {
    socket.send(frame).await.unwrap();
}

/// The next control call the server sends, as (call id, action, input), or
/// `None` if the server closes the link or sends nothing within `wait`.
async fn try_next_call(socket: &mut Socket, wait: Duration) -> Option<(u32, String, Vec<u8>)> {
    tokio::time::timeout(wait, async {
        loop {
            let decoded = socket.next().await.ok()?;
            if let Frame::Call {
                call_id,
                action_id,
                input_json,
            } = decoded.frame
            {
                assert_eq!(decoded.stream_id, 0, "cleanup calls use the control stream");
                return Some((call_id, action_id.to_owned(), input_json.to_vec()));
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// The next control call the server sends, as (call id, action, input).
async fn next_call(socket: &mut Socket) -> (u32, String, Vec<u8>) {
    try_next_call(socket, Duration::from_secs(3))
        .await
        .expect("the server sent no control call")
}

/// Answer the login revocation with a durable receipt.
async fn receipt(socket: &mut Socket) {
    let (call_id, action, _) = next_call(socket).await;
    answer_receipt(socket, call_id, &action).await;
}

/// Reply to a `terminal.login.revoke` call with a durable receipt.
async fn answer_receipt(socket: &mut Socket, call_id: u32, action: &str) {
    answer_receipt_reporting(socket, call_id, action, None).await;
}

/// Keep the host's access report in the same reply as its durable receipt.
async fn answer_receipt_reporting(
    socket: &mut Socket,
    call_id: u32,
    action: &str,
    report: Option<&crate::access_report::AccessReport>,
) {
    assert_eq!(action, "terminal.login.revoke", "the receipt comes first");
    let mut reply = serde_json::json!({"revoked":true});
    if let Some(report) = report {
        reply["access"] = serde_json::to_value(report).unwrap();
    }
    let json = serde_json::to_vec(&reply).unwrap();
    send(
        socket,
        &Frame::Result {
            call_id,
            ok: true,
            json: &json,
        },
    )
    .await;
}

impl Removed {
    /// Reconnect the way a real infraternal agent does after losing its link:
    /// retry until the server takes the reconnect and asks for the receipt,
    /// then give it. Until the server's previous cleanup task has seen the
    /// old link go, it refuses a second one for the same host.
    async fn reconnect_until_receipt(&self) -> Socket {
        self.reconnect_until_receipt_reporting(None).await
    }

    /// Retry the authenticated reconnect and attach optional access evidence.
    async fn reconnect_until_receipt_reporting(
        &self,
        report: Option<&crate::access_report::AccessReport>,
    ) -> Socket {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let mut socket = self.reconnect().await;
            if let Some((call_id, action, input)) =
                try_next_call(&mut socket, Duration::from_secs(2)).await
            {
                // D398: a removal asks the host for no access report.
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&input).unwrap()["report"],
                    false,
                    "the removal asked the host for an access report"
                );
                answer_receipt_reporting(&mut socket, call_id, &action, report).await;
                return socket;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the server never took the host's reconnect"
            );
        }
    }
}

/// After the receipt, the outbox asks for exactly this host's uninstall, and
/// the host's acceptance and the receipt retire the entry together.
#[tokio::test]
async fn outbox_asks_for_the_uninstall_after_the_receipt_then_retires() {
    let removed = removed().await;
    let mut socket = removed.reconnect().await;
    receipt(&mut socket).await;
    let (call_id, action, input) = next_call(&mut socket).await;
    assert_eq!(action, infraternal_plugin_remote::UNINSTALL.id);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&input).unwrap(),
        serde_json::json!({"host": removed.host.simple().to_string(), "dry_run": false})
    );
    // Nothing is retired while the uninstall answer is outstanding.
    assert_eq!(removed.ledger().await, (false, false, "pending".to_owned()));
    // A removal waiting for the answer, as `publish` does for a connected host.
    let store = removed.store.clone();
    let host = removed.host;
    let waiting = tokio::spawn(async move {
        store
            .wait_removal_outcome(host, Duration::from_secs(5))
            .await
            .unwrap()
    });
    // The host reports one object the server knows and one string of its own.
    send(
        &mut socket,
        &Frame::Result {
            call_id,
            ok: true,
            json: br#"{"state":"accepted","cleanup":"pending","left":["infraternal0","run me"]}"#,
        },
    )
    .await;
    removed.settles((true, true, "requested")).await;
    // Only the server-known name is kept, and the waiter gets it (#235, #409).
    assert_eq!(
        removed.retained().await.as_deref(),
        Some(r#"["infraternal0"]"#)
    );
    assert_eq!(
        waiting.await.unwrap(),
        Some(("requested".to_owned(), vec!["infraternal0".to_owned()]))
    );
    drop(removed);
}

/// A removal whose host does not answer in time gets no outcome, and the
/// wait changes nothing: the removal stays pending for the outbox.
#[tokio::test]
async fn an_unanswered_removal_wait_ends_without_an_outcome() {
    let removed = removed().await;
    let answered = removed
        .store
        .wait_removal_outcome(removed.host, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(answered, None);
    assert_eq!(removed.ledger().await, (false, false, "pending".to_owned()));
    drop(removed);
}

/// A host that goes away before it answers the uninstall retires nothing; its
/// next reconnect gets the receipt request and the uninstall again.
#[tokio::test]
async fn lost_uninstall_answer_is_asked_again_on_the_next_reconnect() {
    let removed = removed().await;
    let mut socket = removed.reconnect().await;
    receipt(&mut socket).await;
    let (_, action, _) = next_call(&mut socket).await;
    assert_eq!(action, infraternal_plugin_remote::UNINSTALL.id);
    drop(socket);
    assert_eq!(removed.ledger().await, (false, false, "pending".to_owned()));
    let mut socket = removed.reconnect_until_receipt().await;
    // Still nothing retired: the uninstall is asked again before that.
    assert_eq!(removed.ledger().await, (false, false, "pending".to_owned()));
    let (call_id, action, _) = next_call(&mut socket).await;
    assert_eq!(action, infraternal_plugin_remote::UNINSTALL.id);
    send(
        &mut socket,
        &Frame::Result {
            call_id,
            ok: true,
            json: br#"{"state":"accepted","cleanup":"pending","left":[]}"#,
        },
    )
    .await;
    removed.settles((true, true, "requested")).await;
    drop(removed);
}

/// A host that answers no still gives its receipt: the entry retires, and the
/// removal records that the install stayed (`unreachable`).
#[tokio::test]
async fn refused_uninstall_retires_with_the_install_recorded_as_left() {
    let removed = removed().await;
    let mut socket = removed.reconnect().await;
    receipt(&mut socket).await;
    let (call_id, action, _) = next_call(&mut socket).await;
    assert_eq!(action, infraternal_plugin_remote::UNINSTALL.id);
    send(
        &mut socket,
        &Frame::Result {
            call_id,
            ok: false,
            json: b"{}",
        },
    )
    .await;
    removed.settles((true, true, "unreachable")).await;
    drop(removed);
}

/// Give the fixture's host owner a live admin window for the removal service.
async fn owner_removal(removed: &Removed) -> (crate::remote_removal::Removal, &'static str, i64) {
    let person: String = sqlx::query_scalar("SELECT owner_id FROM remote_hosts WHERE id=?")
        .bind(removed.host.as_bytes().as_slice())
        .fetch_one(&removed.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET owner=0")
        .execute(&removed.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET owner=1 WHERE id=?")
        .bind(&person)
        .execute(&removed.pool)
        .await
        .unwrap();
    let auth = crate::auth::Auth::new(
        removed.pool.clone(),
        "removal.test",
        "https://removal.test/",
    )
    .await
    .unwrap();
    let now = crate::runtime::unix_seconds().unwrap();
    let token = "outbox-removal-test-session";
    sqlx::query(
        "INSERT INTO sessions(token_hash,user_id,device,expires,fresh) VALUES(?,?,'test',?,?)",
    )
    .bind(crate::auth::hash(token))
    .bind(&person)
    .bind(now + 300)
    .bind(now)
    .execute(&removed.pool)
    .await
    .unwrap();
    let service = crate::remote_removal::Removal::new(
        auth,
        removed.pool.clone(),
        removed.store.clone(),
        removed.hosts.clone(),
        std::path::PathBuf::new(),
    );
    (service, token, now)
}

/// Forget must stop delivery after acknowledgement of the first cleanup step.
#[tokio::test]
async fn forget_stops_an_admitted_cleanup_before_its_next_step() {
    let removed = removed().await;
    let (service, token, now) = owner_removal(&removed).await;
    let mut socket = removed.reconnect().await;
    let (call_id, action, _) = next_call(&mut socket).await;
    assert_eq!(action, "terminal.login.revoke");

    let result = service
        .forget_browser(token, removed.host, now)
        .await
        .unwrap();
    assert_eq!(result["state"], "forgotten");

    let fingerprint = openssl::sha::sha256(&removed.identity.certificate.to_der().unwrap());
    assert!(removed.store.admit(&fingerprint, now).await.is_err());
    assert!(removed.store.admit_cleanup(&fingerprint, now).await.is_err());

    // The first cleanup call preceded Forget. Its late reply must never
    // cause a new uninstall call on the already admitted connection.
    let _ = socket
        .send(&Frame::Result {
            call_id,
            ok: true,
            json: br#"{"revoked":true}"#,
        })
        .await;
    let next = try_next_call(&mut socket, Duration::from_secs(3)).await;
    assert!(next.is_none(), "cleanup continued after Forget: {next:?}");
}

/// A connected removal must leave its receipt pending until the reconnect has
/// requested uninstall. An early receipt would retire that delivery forever.
#[tokio::test]
async fn connected_publish_keeps_uninstall_pending_until_reconnect() {
    let removed = removed().await;
    sqlx::query("DELETE FROM remote_login_cleanup WHERE host_id=?")
        .bind(removed.host.as_bytes().as_slice())
        .execute(&removed.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM remote_host_removals WHERE host_id=?")
        .bind(removed.host.as_bytes().as_slice())
        .execute(&removed.pool)
        .await
        .unwrap();
    let (service, token, now) = owner_removal(&removed).await;
    let mut original = removed.reconnect().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while removed.hosts.actor(removed.host).await.is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let review = service.start(token, removed.host, true, now).await.unwrap();
    let host = removed.host;
    let review = review["review"].as_str().unwrap().to_owned();
    let publishing =
        tokio::spawn(async move { service.finish_host(token, host, &review, now).await });
    // A broken early-revoke path asks on the old link. Give it a durable
    // reply, so the regression cannot pass merely because the host is quiet.
    if let Some((id, action, _)) = try_next_call(&mut original, Duration::from_secs(2)).await {
        answer_receipt(&mut original, id, &action).await;
    }
    drop(original);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let committed: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM remote_host_removals WHERE host_id=?)",
            )
            .bind(removed.host.as_bytes().as_slice())
            .fetch_one(&removed.pool)
            .await
            .unwrap();
            if committed {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        !removed.ledger().await.0,
        "early revoke retired the uninstall outbox before reconnect"
    );
    let report = crate::access_report::AccessReport {
        accounts: vec![crate::access_report::AccountReport {
            account: "fixture".to_owned(),
            files: vec![crate::access_report::AccessFile {
                path: "~/.ssh/authorized_keys".to_owned(),
                change: crate::access_report::ChangeKind::Added,
                lines: vec!["fixture access retained".to_owned()],
                note: None,
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut reconnected = removed
        .reconnect_until_receipt_reporting(Some(&report))
        .await;
    assert_eq!(removed.ledger().await, (false, false, "pending".to_owned()));
    let (call_id, action, _) = next_call(&mut reconnected).await;
    assert_eq!(action, infraternal_plugin_remote::UNINSTALL.id);
    send(
        &mut reconnected,
        &Frame::Result {
            call_id,
            ok: true,
            json: br#"{"state":"accepted","cleanup":"pending","left":[]}"#,
        },
    )
    .await;
    removed.settles((true, true, "requested")).await;
    let result = publishing.await.unwrap().unwrap();
    assert_eq!(result["state"], "removed");
    assert_eq!(result["host_cleanup"], "requested");
    // D398: a removal keeps no access report, even when the host sent one.
    assert!(
        crate::access_report::inbox(&removed.pool, &person)
            .await
            .unwrap()
            .reports
            .is_empty(),
        "a removal kept the access report"
    );
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_access_reports")
        .fetch_one(&removed.pool)
        .await
        .unwrap();
    assert_eq!(kept, 0);
    drop(removed);
}
