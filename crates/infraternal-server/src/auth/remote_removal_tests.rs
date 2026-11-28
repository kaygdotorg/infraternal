//! SQLite regression for host removal binding and offline revocation (#87). In the browser a
//! removal is a dry run, then the removal itself, inside the 15-minute admin window (D339).
use super::*;

/// A host owned by the fixture's owner, installed by setup at `root@host.example`.
async fn owned_host(f: &Fixture) -> Uuid {
    let host = Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootful',0,1)").bind(host.as_bytes().as_slice()).bind(&f.user).execute(&f.auth.pool).await.unwrap();
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'root@host.example',NULL)")
        .bind(host.as_bytes().as_slice())
        .execute(&f.auth.pool)
        .await
        .unwrap();
    host
}

/// Build one shared removal admission pool for this fixture.
fn removal(f: &Fixture) -> crate::remote_removal::Removal {
    crate::remote_removal::Removal::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        crate::enrollment::EnrollmentStore::new(f.auth.pool.clone()),
        crate::remote_runtime::RemoteHosts::default(),
        PathBuf::new(),
    )
}

/// Read the final retirement tombstone, distinct from a pending denial.
async fn live(f: &Fixture, host: Uuid) -> bool {
    sqlx::query_scalar("SELECT revoked_at IS NULL FROM remote_hosts WHERE id=?")
        .bind(host.as_bytes().as_slice())
        .fetch_one(&f.auth.pool)
        .await
        .unwrap()
}

/// Offline removal survives a service restart and a second request until the host confirms it.
#[tokio::test]
async fn reviewed_removal_revokes_offline_host_and_cannot_replay() {
    let f = fixture().await;
    let host = owned_host(&f).await;
    let service = removal(&f);
    let start = service.start(&f.session, host, true, NOW).await.unwrap();
    // The dry run says what will happen and changes nothing.
    assert_eq!(start["action"]["host_id"], json!(host));
    assert_eq!(start["action"]["host"], "root@host.example");
    assert_eq!(start["review_expires_in"], 120);
    assert!(start.get("ceremony").is_none(), "D339: no passkey ceremony");
    assert!(live(&f, host).await);
    let review = str_field(&start, "review");
    assert!(
        service
            .finish_host(&f.session, Uuid::new_v4(), review, NOW)
            .await
            .is_err(),
        "a review is bound to its host"
    );
    let result = service
        .finish_host(&f.session, host, review, NOW)
        .await
        .unwrap();
    // #409: the removal outbox asks the host when it next connects; the
    // removal itself makes no network call.
    assert_eq!(result["host_cleanup"], "pending");
    // #235: the toast still hands over the commands that remove the rootful
    // install on the machine itself, for a host that never comes back.
    let message = result["message"].as_str().unwrap();
    assert_eq!(result["state"], "pending");
    assert!(message.contains("revoked, cleanup pending"));
    let command = result["manual"].as_str().unwrap();
    assert!(
        message.contains(command),
        "pending response hid the manual command: {message}"
    );
    assert!(
        !message.contains("must reconnect"),
        "online cleanup need not reconnect"
    );
    // The commands run the installed binary's own ownership-checked uninstall
    // for exactly this host; they delete nothing by name.
    assert_eq!(
        result["manual"],
        format!(
            "/usr/local/bin/infraternal --bootstrap-uninstall {}",
            host.simple()
        )
    );
    assert!(
        service
            .finish_host(&f.session, host, review, NOW)
            .await
            .is_err(),
        "a review is single use"
    );
    assert!(
        live(&f, host).await,
        "pending denial is not a durable receipt"
    );
    // A service restart drops review tokens and in-memory delivery state. A new
    // review must leave the original offline request in charge of cleanup.
    drop(service);
    let restarted = removal(&f);
    let repeat = restarted.start(&f.session, host, false, NOW).await.unwrap();
    let repeated = restarted
        .finish_host(&f.session, host, str_field(&repeat, "review"), NOW)
        .await
        .expect("a repeat must return the already-pending uninstall");
    assert_eq!(
        repeated["host_id"],
        json!(host),
        "the host is the stable request id"
    );
    assert_eq!(repeated["state"], result["state"]);
    assert_eq!(repeated["host_cleanup"], result["host_cleanup"]);
    assert_eq!(repeated["message"], result["message"]);
    assert_eq!(repeated["manual"], result["manual"]);
    let pending: bool =
        sqlx::query_scalar("SELECT confirmed=0 FROM remote_login_cleanup WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert!(
        pending,
        "only the original host receipt can complete cleanup"
    );
    crate::enrollment::EnrollmentStore::new(f.auth.pool.clone())
        .confirm_login_cleanup(host, Uuid::parse_str(&f.user).unwrap())
        .await
        .unwrap();
    assert!(!live(&f, host).await);
    assert!(
        restarted.start(&f.session, host, true, NOW).await.is_err(),
        "a completed removal refuses a fresh review"
    );
    let coordinates: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_host_bootstrap")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(coordinates, 0);
    // The removal is recorded, as before D339.
    let recorded: (String, i64) =
        sqlx::query_as("SELECT owner_id,uninstall FROM remote_host_removals WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(recorded, (f.user.clone(), 1));
}

/// D339 (owner, 2026-11-04: "yes it should"): removing a host in the browser falls under the
/// 15-minute admin window (D333), as removal through a key does. It asks for no passkey of its
/// own, but it still needs a live dry run from the same session, inside the window.
#[tokio::test]
async fn browser_removal_runs_inside_the_admin_window_without_its_own_passkey() {
    let window = infraternal_plugin_api::ADMIN_WINDOW_SECONDS;
    // Late in the window, with no new tap: the dry run and the removal both run.
    let f = fixture().await;
    let host = owned_host(&f).await;
    let service = removal(&f);
    let start = service
        .start(&f.session, host, true, NOW + window - 60)
        .await
        .unwrap();
    service
        .finish_host(
            &f.session,
            host,
            str_field(&start, "review"),
            NOW + window - 1,
        )
        .await
        .expect("inside the admin window a reviewed removal needs no passkey");
    assert!(live(&f, host).await);
    let pending: bool =
        sqlx::query_scalar("SELECT confirmed=0 FROM remote_login_cleanup WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert!(pending);

    // After the window, the dry run is refused.
    let host = owned_host(&f).await;
    assert!(
        service
            .start(&f.session, host, true, NOW + window)
            .await
            .is_err()
    );

    // The window closes between the dry run and the removal: refused, the host stays.
    let start = service
        .start(&f.session, host, true, NOW + window - 30)
        .await
        .unwrap();
    assert!(
        service
            .finish_host(&f.session, host, str_field(&start, "review"), NOW + window)
            .await
            .is_err()
    );
    assert!(live(&f, host).await);

    // A review expires 120 s after its dry run.
    let f = fixture().await;
    let host = owned_host(&f).await;
    let service = removal(&f);
    let start = service.start(&f.session, host, true, NOW).await.unwrap();
    assert!(
        service
            .finish_host(&f.session, host, str_field(&start, "review"), NOW + 120)
            .await
            .is_err()
    );
    assert!(live(&f, host).await);

    // Another session cannot finish this session's review.
    let start = service.start(&f.session, host, true, NOW).await.unwrap();
    let other = tapped_session(&f.auth, &f.user, json!({"kind":"passkey.add"}), NOW).await;
    assert!(
        service
            .finish_host(&other, host, str_field(&start, "review"), NOW)
            .await
            .is_err()
    );
    assert!(live(&f, host).await);
}

#[tokio::test]
async fn logout_or_role_loss_after_removal_start_preserves_host() {
    for logout in [true, false] {
        let f = fixture().await;
        let host = owned_host(&f).await;
        let service = removal(&f);
        let start = service.start(&f.session, host, false, NOW).await.unwrap();
        if logout {
            f.auth.logout(&f.session).await.unwrap();
        } else {
            sqlx::query("UPDATE users SET owner=0")
                .execute(&f.auth.pool)
                .await
                .unwrap();
        }
        assert!(
            service
                .finish_host(&f.session, host, str_field(&start, "review"), NOW)
                .await
                .is_err()
        );
        assert!(live(&f, host).await);
    }
}

/// D333: inside its `hosts:write` scope a key removes a host with no further tap. The dry run
/// changes nothing; the removal revokes the host and completes the key's audit row in the same
/// transaction.
#[tokio::test]
async fn a_hosts_write_key_dry_runs_then_removes_without_a_tap() {
    let f = fixture().await;
    let host = Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootful',0,1)").bind(host.as_bytes().as_slice()).bind(&f.user).execute(&f.auth.pool).await.unwrap();
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'root@host.example',NULL)")
        .bind(host.as_bytes().as_slice())
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let key_hash = hash("fixture-removal-key-never-print");
    let now = crate::runtime::unix_seconds().unwrap();
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'fixture-cli','[\"hosts:write\"]',?,?,0)")
        .bind(&key_hash).bind(&f.user).bind(now).bind(now + 3600)
        .execute(&f.auth.pool).await.unwrap();
    let audit_id: i64 = sqlx::query_scalar("INSERT INTO api_action_audit(key_id,person_id,action_id,target_id,state,occurred_at) VALUES(?,?,'remote.host.remove',?,'pending',?) RETURNING id")
        .bind(&key_hash).bind(&f.user).bind(host.to_string()).bind(now)
        .fetch_one(&f.auth.pool).await.unwrap();
    let service = crate::remote_removal::Removal::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        crate::enrollment::EnrollmentStore::new(f.auth.pool.clone()),
        crate::remote_runtime::RemoteHosts::default(),
        PathBuf::new(),
    );

    let review = service.review_with_key(&f.user, host).await.unwrap();
    assert_eq!(review["dry_run"], true);
    assert_eq!(review["host"], "host.example");
    assert_eq!(review["uninstall"], true);
    let revoked = |pool: sqlx::SqlitePool| async move {
        sqlx::query_scalar::<_, bool>("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    assert!(
        !revoked(f.auth.pool.clone()).await,
        "a dry run changes nothing"
    );

    let result = service
        .remove_with_key(&key_hash, &f.user, host, audit_id, now)
        .await
        .unwrap();
    assert_eq!(result["state"], "pending");
    assert!(!revoked(f.auth.pool.clone()).await);
    crate::enrollment::EnrollmentStore::new(f.auth.pool.clone())
        .confirm_login_cleanup(host, Uuid::parse_str(&f.user).unwrap())
        .await
        .unwrap();
    assert!(revoked(f.auth.pool.clone()).await);
    let audit: (String, Option<String>) =
        sqlx::query_as("SELECT state,result FROM api_action_audit WHERE id=?")
            .bind(audit_id)
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(
        audit,
        (
            "complete".to_owned(),
            Some("revoked, cleanup pending".to_owned())
        )
    );
    assert!(
        service
            .remove_with_key(&key_hash, &f.user, host, audit_id, now)
            .await
            .is_err(),
        "a removed host cannot be removed again"
    );
}

/// The key path rechecks the key, its owner and the host inside the removal transaction.
#[tokio::test]
async fn key_removal_refuses_revoked_keys_foreign_hosts_and_missing_scope() {
    let f = fixture().await;
    let host = Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootful',0,1)").bind(host.as_bytes().as_slice()).bind(&f.user).execute(&f.auth.pool).await.unwrap();
    let now = crate::runtime::unix_seconds().unwrap();
    let service = crate::remote_removal::Removal::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        crate::enrollment::EnrollmentStore::new(f.auth.pool.clone()),
        crate::remote_runtime::RemoteHosts::default(),
        PathBuf::new(),
    );
    for (name, scopes, dead) in [
        ("fixture-dead-removal-key", "[\"hosts:write\"]", 1),
        ("fixture-read-removal-key", "[\"hosts:read\"]", 0),
    ] {
        sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'fixture-cli',?,?,?,?)")
            .bind(hash(name)).bind(&f.user).bind(scopes).bind(now).bind(now + 3600).bind(dead)
            .execute(&f.auth.pool).await.unwrap();
        assert!(
            service
                .remove_with_key(&hash(name), &f.user, host, 0, now)
                .await
                .is_err(),
            "{name}"
        );
    }
    let live = hash("fixture-live-removal-key");
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'fixture-cli','[\"hosts:write\"]',?,?,0)")
        .bind(&live).bind(&f.user).bind(now).bind(now + 3600)
        .execute(&f.auth.pool).await.unwrap();
    assert!(
        service
            .review_with_key(&f.user, Uuid::new_v4())
            .await
            .is_err()
    );
    assert!(
        service
            .remove_with_key(&live, &f.user, Uuid::new_v4(), 0, now)
            .await
            .is_err(),
        "a host the owner does not have"
    );
    assert!(
        service
            .remove_with_key(&live, "someone-else", host, 0, now)
            .await
            .is_err(),
        "the key's own account only"
    );
    let still: bool = sqlx::query_scalar("SELECT revoked_at IS NULL FROM remote_hosts WHERE id=?")
        .bind(host.as_bytes().as_slice())
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert!(still);
}

/// Eight offline hosts must not retain admission after their durable denial rows
/// commit. Observe those commits, then require the ninth request to be recorded.
#[tokio::test]
async fn offline_removals_do_not_block_other_revocations() {
    let f = fixture().await;
    let service = removal(&f);
    let mut requests = Vec::new();
    for index in 0..9 {
        let host = owned_host(&f).await;
        let start = service.start(&f.session, host, false, NOW).await.unwrap();
        let review = str_field(&start, "review").to_owned();
        let service = service.clone();
        let session = f.session.clone();
        let mut request =
            tokio::spawn(async move { service.finish_host(&session, host, &review, NOW).await });
        tokio::select! {
            biased;
            result = &mut request => {
                let result = result.unwrap().expect("offline removal must record denial");
                assert_eq!(result["state"], "pending");
            }
            () = async {
                loop {
                    let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_login_cleanup WHERE host_id=? AND confirmed=0)")
                        .bind(host.as_bytes().as_slice()).fetch_one(&f.auth.pool).await.unwrap();
                    if pending { break; }
                    tokio::task::yield_now().await;
                }
            } => { requests.push(request); }
        }
        let committed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM remote_login_cleanup WHERE host_id=? AND confirmed=0)",
        )
        .bind(host.as_bytes().as_slice())
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
        assert!(committed, "removal {index} was not recorded");
    }
    for request in requests {
        let result = request.await.unwrap().unwrap();
        assert_eq!(result["state"], "pending");
    }
    eprintln!("J196 offline removal flood: nine distinct denials committed, cleanup pending");
}

/// Bootstrap coordinates remain available while denial is pending, and only
/// the exact person's durable receipt may remove them.
#[tokio::test]
async fn pending_removal_retains_bootstrap_until_durable_receipt() {
    let f = fixture().await;
    let host = owned_host(&f).await;
    let service = removal(&f);
    let start = service.start(&f.session, host, true, NOW).await.unwrap();
    let result = service
        .finish_host(&f.session, host, str_field(&start, "review"), NOW)
        .await
        .unwrap();
    assert_eq!(result["state"], "pending");
    let coordinates: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_host_bootstrap WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(
        coordinates, 1,
        "pending cleanup discarded its bootstrap coordinates"
    );
    let store = crate::enrollment::EnrollmentStore::new(f.auth.pool.clone());
    store
        .confirm_login_cleanup(host, Uuid::new_v4())
        .await
        .unwrap();
    let coordinates: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_host_bootstrap WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(
        coordinates, 1,
        "foreign receipt discarded bootstrap coordinates"
    );
    store
        .confirm_login_cleanup(host, Uuid::parse_str(&f.user).unwrap())
        .await
        .unwrap();
    let coordinates: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_host_bootstrap WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(coordinates, 0);
}

/// Pending describes a missing durable receipt, independently of whether the
/// host is connected or whether its installation is retained.
#[tokio::test]
async fn pending_removal_does_not_claim_a_reconnect_is_required() {
    let f = fixture().await;
    let host = owned_host(&f).await;
    let service = removal(&f);
    let start = service.start(&f.session, host, false, NOW).await.unwrap();
    let result = service
        .finish_host(&f.session, host, str_field(&start, "review"), NOW)
        .await
        .unwrap();
    assert_eq!(result["state"], "pending");
    assert!(
        !result["message"]
            .as_str()
            .unwrap()
            .contains("must reconnect")
    );
    assert!(
        result["message"]
            .as_str()
            .unwrap()
            .contains("stays installed")
    );
}

/// J269 reproducer: after a pending removal, the production duplicate-address
/// queries (`bootstrap_remote.rs` `existing_host`, `remote_http.rs` `occupied`,
/// and `check_stuck_install`'s ownership row) are evaluated verbatim.
#[tokio::test]
async fn pending_removal_releases_its_bootstrap_coordinates() {
    let f = fixture().await;
    let host = owned_host(&f).await;
    let service = removal(&f);
    let start = service.start(&f.session, host, true, NOW).await.unwrap();
    let result = service
        .finish_host(&f.session, host, str_field(&start, "review"), NOW)
        .await
        .unwrap();
    assert_eq!(result["state"], "pending");
    let lookup: Option<&str> = None;
    let existing: Option<Vec<u8>> = sqlx::query_scalar("SELECT h.id FROM remote_host_bootstrap b JOIN remote_hosts h ON h.id=b.host_id WHERE h.owner_id=? AND h.revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM remote_host_removals r WHERE r.host_id=h.id) AND (b.address=? OR (? IS NOT NULL AND b.trust_lookup=?)) ORDER BY (b.address=?) DESC, h.id LIMIT 1")
        .bind(&f.user).bind("root@host.example").bind(lookup).bind(lookup).bind("root@host.example")
        .fetch_optional(&f.auth.pool).await.unwrap();
    let occupied: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_host_bootstrap b JOIN remote_hosts h ON h.id=b.host_id WHERE h.owner_id=? AND h.revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM remote_host_removals r WHERE r.host_id=h.id) AND (b.address=? OR (? IS NOT NULL AND b.trust_lookup=?)))")
        .bind(&f.user).bind("root@host.example").bind(lookup).bind(lookup)
        .fetch_one(&f.auth.pool).await.unwrap();
    let row: Option<(String, bool, bool)> = sqlx::query_as("SELECT h.owner_id, h.revoked_at IS NOT NULL, EXISTS(SELECT 1 FROM remote_host_bootstrap b WHERE b.host_id=h.id AND (b.address=? OR (? IS NOT NULL AND b.trust_lookup=?))) FROM remote_hosts h WHERE h.id=? AND NOT EXISTS(SELECT 1 FROM remote_host_removals r WHERE r.host_id=h.id)")
        .bind("root@host.example").bind(lookup).bind(lookup).bind(host.as_bytes().as_slice())
        .fetch_optional(&f.auth.pool).await.unwrap();
    let stuck_ours =
        row.is_some_and(|(owner, revoked, matches)| owner == f.user && !revoked && matches);
    let message = result["message"].as_str().unwrap();
    eprintln!(
        "J269 pending removal: already_added_host={} issue_occupied={occupied} stuck_install_ours={stuck_ours} message={message:?}",
        existing.is_some()
    );
    assert_eq!(
        (existing.is_some(), occupied, stuck_ours),
        (false, false, false),
        "pending removal still owns bootstrap coordinates"
    );
}

/// Pending cleanup names the host once and does not claim its inventory row is gone.
#[tokio::test]
async fn pending_removal_describes_one_host_without_claiming_completion() {
    for uninstall in [false, true] {
        let f = fixture().await;
        let host = owned_host(&f).await;
        let service = removal(&f);
        let start = service
            .start(&f.session, host, uninstall, NOW)
            .await
            .unwrap();
        let result = service
            .finish_host(&f.session, host, str_field(&start, "review"), NOW)
            .await
            .unwrap();
        let message = result["message"].as_str().unwrap();
        assert_eq!(message.matches("host.example").count(), 1, "{message}");
        assert!(!message.contains("was removed"), "{message}");
        assert!(message.contains("revoked, cleanup pending"), "{message}");
        if let Some(manual) = result["manual"].as_str() {
            assert!(
                message.ends_with(manual),
                "the copied command must end the message unchanged: {message}"
            );
        }
    }
}

/// A changed report with one planted key, as the host would send it.
fn changed_report(line: &str) -> crate::access_report::AccessReport {
    use crate::access_report::{AccessFile, AccessReport, AccountReport, ChangeKind, State};
    AccessReport {
        state: State::Changed,
        reason: None,
        omitted_accounts: 0,
        accounts: vec![AccountReport {
            account: "deploy".to_owned(),
            recorded_at: 1,
            root_checks: infraternal_agent::access_files::root_check_names(),
            state: State::Changed,
            reason: None,
            files: vec![AccessFile {
                path: "~/.ssh/authorized_keys".to_owned(),
                change: ChangeKind::Changed,
                lines: vec![line.to_owned()],
                note: None,
            }],
            ..AccountReport::default()
        }],
        warning: None,
    }
}

/// Start a revocation of `host`'s person that leaves the host in place: its
/// login cleanup waits for the host's receipt, and no removal exists (D398).
async fn revoke_pending(f: &Fixture, host: Uuid) -> Uuid {
    let person = Uuid::parse_str(&f.user).unwrap();
    sqlx::query("INSERT INTO remote_login_cleanup(host_id,person_id) VALUES(?,?)")
        .bind(host.as_bytes().as_slice())
        .bind(person.to_string())
        .execute(&f.auth.pool)
        .await
        .unwrap();
    person
}

/// D398: revoking a person while the host stays puts the host's report in the
/// owner's Inbox once the host confirms. A foreign receipt stores nothing, a
/// repeated receipt replaces nothing, the owner dismisses it once, and a
/// signed-out request is refused.
#[tokio::test]
async fn a_revoked_persons_report_waits_in_the_owners_inbox() {
    let f = fixture().await;
    let host = owned_host(&f).await;
    let service = removal(&f);
    let waiting = |value: serde_json::Value| value["reports"].as_array().unwrap().len();
    assert_eq!(
        waiting(service.access_reports(&f.session, NOW).await.unwrap()),
        0
    );
    let person = revoke_pending(&f, host).await;
    let store = crate::enrollment::EnrollmentStore::new(f.auth.pool.clone());
    store
        .confirm_login_cleanup_with_report(host, Uuid::new_v4(), Some(&changed_report("foreign")))
        .await
        .unwrap();
    assert_eq!(
        waiting(service.access_reports(&f.session, NOW).await.unwrap()),
        0,
        "a foreign receipt stored a report"
    );
    store
        .confirm_login_cleanup_with_report(
            host,
            person,
            Some(&changed_report("ssh-ed25519 AAAAleft left")),
        )
        .await
        .unwrap();
    let value = service.access_reports(&f.session, NOW).await.unwrap();
    assert_eq!(value["more"], 0);
    let shown = &value["reports"][0];
    assert_eq!(shown["host_id"], json!(host));
    assert_eq!(shown["person_id"], json!(person));
    // J323 (84303): the owner sees who, not only an id.
    let expected: String = sqlx::query_scalar(
        "SELECT COALESCE(NULLIF(display_name,''), NULLIF(name,''), username) FROM users WHERE id=?",
    )
    .bind(person.to_string())
    .fetch_one(&f.auth.pool)
    .await
    .unwrap();
    assert_eq!(shown["person_name"], json!(expected));
    assert_eq!(shown["outcome"], "changed");
    assert!(
        shown["headline"].as_str().unwrap().contains("changed"),
        "{shown}"
    );
    let lines: Vec<&str> = shown["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| line.as_str().unwrap())
        .collect();
    assert!(lines.contains(&"  ~/.ssh/authorized_keys"), "{lines:?}");
    assert!(
        lines.contains(&"    + ssh-ed25519 AAAAleft left"),
        "{lines:?}"
    );
    assert!(shown.get("report").is_none(), "the raw report was sent");
    store
        .confirm_login_cleanup_with_report(host, person, Some(&changed_report("replayed")))
        .await
        .unwrap();
    assert_eq!(
        service.access_reports(&f.session, NOW).await.unwrap(),
        value,
        "a duplicate receipt replaced the report"
    );
    // Dismissing: not another host's, then once, then never again.
    assert!(
        !service
            .dismiss_access_report(&f.session, Uuid::new_v4(), person, NOW)
            .await
            .unwrap()
    );
    assert!(
        service
            .dismiss_access_report(&f.session, host, person, NOW)
            .await
            .unwrap()
    );
    assert!(
        !service
            .dismiss_access_report(&f.session, host, person, NOW)
            .await
            .unwrap()
    );
    assert_eq!(
        waiting(service.access_reports(&f.session, NOW).await.unwrap()),
        0
    );
    assert!(service.access_reports("signed-out", NOW).await.is_err());
}

/// D398 (owner, 2026-11-21): removing a host deletes infraternal and its state
/// and nothing else, so it keeps no report: not for a removal that uninstalls,
/// and not for one that retains the install. The host's reply is ignored.
#[tokio::test]
async fn a_host_removal_keeps_no_access_report() {
    for uninstall in [true, false] {
        let f = fixture().await;
        let host = owned_host(&f).await;
        let service = removal(&f);
        let start = service
            .start(&f.session, host, uninstall, NOW)
            .await
            .unwrap();
        let review = str_field(&start, "review").to_owned();
        service
            .finish_host(&f.session, host, &review, NOW)
            .await
            .unwrap();
        let person = Uuid::parse_str(&f.user).unwrap();
        let store = crate::enrollment::EnrollmentStore::new(f.auth.pool.clone());
        assert!(
            store.removal_requested(host).await.unwrap(),
            "the removal left no record"
        );
        store
            .confirm_login_cleanup_with_report(
                host,
                person,
                Some(&changed_report("ssh-ed25519 AAAAleft left")),
            )
            .await
            .unwrap();
        let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_access_reports")
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
        assert_eq!(kept, 0, "a removal kept a report (uninstall={uninstall})");
        assert_eq!(
            service.access_reports(&f.session, NOW).await.unwrap()["reports"],
            json!([])
        );
    }
}

/// D398: only the server owner reads the Inbox reports, and the admin window
/// is not needed: a revoked host cannot start the passkey renewal it would
/// ask for (#498), and a signed-in owner already reads these files by
/// opening a terminal. A stale window still reads; a non-owner does not.
#[tokio::test]
async fn the_inbox_is_for_the_owner_and_needs_no_admin_window() {
    let f = fixture().await;
    let service = removal(&f);
    assert!(service.access_reports(&f.session, NOW + 899).await.is_ok());
    assert!(
        service.access_reports(&f.session, NOW + 900).await.is_ok(),
        "an expired admin window refused the Inbox"
    );
    sqlx::query("UPDATE users SET owner=0 WHERE id=?")
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert!(matches!(
        service.access_reports(&f.session, NOW).await,
        Err(crate::auth::Error::Denied)
    ));
}

/// With more reports than the Inbox shows, the newest come first and the rest
/// are counted.
#[tokio::test]
async fn waiting_reports_beyond_the_shown_ones_are_counted() {
    use crate::access_report::{AccessReport, AccountReport, State};
    let f = fixture().await;
    let host = owned_host(&f).await;
    let service = removal(&f);
    let mut transaction = f.auth.pool.acquire().await.unwrap();
    let clean = AccessReport {
        state: State::Unchanged,
        accounts: vec![AccountReport {
            account: "new".to_owned(),
            state: State::Unchanged,
            ..AccountReport::default()
        }],
        ..AccessReport::default()
    };
    for index in 0..21 {
        crate::access_report::store(&mut transaction, host, Uuid::new_v4(), &clean, 100 + index)
            .await
            .unwrap();
    }
    drop(transaction);
    let value = service.access_reports(&f.session, NOW).await.unwrap();
    assert_eq!(value["reports"].as_array().unwrap().len(), 16);
    assert_eq!(value["more"], 5);
    assert_eq!(value["reports"][0]["recorded_at"], 120, "newest first");
}

/// Record the owner Mac's approval and active certificate without SSH install coordinates.
async fn joined_mac(f: &Fixture, key: &[u8], now: i64) -> (Uuid, [u8; 32]) {
    sqlx::query("UPDATE sessions SET fresh=?,expires=? WHERE token_hash=?")
        .bind(now)
        .bind(now + 3600)
        .bind(hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let host = Uuid::new_v4();
    let fingerprint = openssl::sha::sha256(host.as_bytes());
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at,hostname,device_approved,device_os) VALUES(?,?,'rootless',501,1,'MBP.local',1,'macOS')")
        .bind(host.as_bytes().as_slice()).bind(&f.user).execute(&f.auth.pool).await.unwrap();
    sqlx::query("INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after,execution_uid) VALUES(?,?,zeroblob(32),?,?,?,501)")
        .bind(fingerprint.as_slice()).bind(host.as_bytes().as_slice()).bind(key)
        .bind(now - 604_800 + 3600).bind(now + 3600).execute(&f.auth.pool).await.unwrap();
    (host, fingerprint)
}

/// A Mac uninstalled without notifying its server still offers a named, actionable Forget path.
#[tokio::test]
async fn removing_an_offline_up_install_names_the_mac_and_offers_forget() {
    let f = fixture().await;
    let now = crate::runtime::unix_seconds().unwrap();
    let (host, _) = joined_mac(&f, &[7; 32], now).await;
    let service = removal(&f);
    let start = service.start(&f.session, host, true, now).await.unwrap();
    assert_eq!(start["action"]["host"], "mbp");
    let result = service
        .finish_host(&f.session, host, str_field(&start, "review"), now)
        .await
        .unwrap();
    assert_eq!(result["state"], "pending");
    assert_eq!(result["up_install"], true);
    assert_eq!(result["manual"], Value::Null);
    assert_eq!(
        result["message"],
        "Access revoked for mbp. Already uninstalled infraternal? Choose Forget. If it's still installed, run infraternal uninstall on mbp."
    );
    assert_eq!(forget_request(&f, host).await, axum::http::StatusCode::OK);
    assert!(!live(&f, host).await);
}

/// A cold-locked signer for the retirement route, which needs only the host's proof.
struct RetirementLockedCa;

impl crate::ca::CaKeySource for RetirementLockedCa {
    /// No new certificates may be issued in this fixture.
    fn load(&self) -> std::result::Result<crate::ca::CaMaterial, crate::ca::CaError> {
        Err(crate::ca::CaError)
    }
}

/// A local uninstall signed by the approved Mac retires the row after its ordinary login receipt.
#[tokio::test]
async fn local_uninstall_retires_an_up_install_without_a_browser_remove() {
    use infraternal_plugin_remote::local_retirement::{self, Request, transcript};
    use openssl::{pkey::PKey, sign::Signer};
    use tower::ServiceExt;

    let f = fixture().await;
    let now = crate::runtime::unix_seconds().unwrap();
    let signing = PKey::generate_ed25519().unwrap();
    let (host, fingerprint) = joined_mac(&f, &signing.raw_public_key().unwrap(), now).await;
    let mut request = Request {
        host_id: host,
        fingerprint,
        signed_at: now,
        signature: Vec::new(),
    };
    request.signature = Signer::new_without_digest(&signing)
        .unwrap()
        .sign_oneshot_to_vec(&transcript(&request))
        .unwrap();
    assert!(removal(&f).start(&f.session, host, true, now).await.is_ok());
    let store = crate::enrollment::EnrollmentStore::new(f.auth.pool.clone());
    let app = crate::remote_http::router_with_store(
        f.auth.clone(),
        f.auth.pool.clone(),
        store.clone(),
        std::sync::Arc::new(RetirementLockedCa),
        crate::remote_http::EnrollmentEndpoint {
            ca_der: Vec::new(),
            endpoint: "127.0.0.1:4443".parse().unwrap(),
            server_name: "localhost".into(),
        },
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(local_retirement::PATH)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&request).unwrap(),
        ))
        .unwrap();
    let mut inventory = store.2.subscribe();
    let person = Uuid::parse_str(&f.user).unwrap();
    let (retired, receipt) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(app.oneshot(request), async {
            inventory.changed().await.unwrap();
            assert!(store.removal_requested(host).await.unwrap());
            assert!(!store.pending_uninstall(host).await.unwrap());
            store
                .confirm_removal_cleanup(host, person, None, None)
                .await
        })
    })
    .await
    .unwrap();
    assert_eq!(
        retired.unwrap().status(),
        axum::http::StatusCode::NO_CONTENT
    );
    receipt.unwrap();
    assert!(!live(&f, host).await);
    assert!(
        removal(&f)
            .start(&f.session, host, true, now)
            .await
            .is_err()
    );
}

/// A removed host with its original removal record and a 14-minute-old admin approval.
async fn forget_fixture(f: &Fixture, valid: bool) -> Uuid {
    let host = owned_host(f).await;
    let now = crate::runtime::unix_seconds().unwrap();
    sqlx::query("UPDATE sessions SET fresh=?,expires=? WHERE token_hash=?")
        .bind(now - infraternal_plugin_api::ADMIN_WINDOW_SECONDS + 60)
        .bind(now + 3600)
        .bind(hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after,execution_uid) VALUES(?1,?2,zeroblob(32),zeroblob(32),?3,?4,(SELECT execution_uid FROM remote_hosts WHERE id=?2))")
        .bind(host.as_bytes().repeat(2)).bind(host.as_bytes().as_slice()).bind(now - 604_800 + i64::from(valid) * 3600).bind(now + i64::from(valid) * 3600).execute(&f.auth.pool).await.unwrap();
    sqlx::query("INSERT INTO remote_host_removals(host_id,owner_id,requested_at,uninstall,host_cleanup) VALUES(?,?,1,1,'pending')")
        .bind(host.as_bytes().as_slice()).bind(&f.user).execute(&f.auth.pool).await.unwrap();
    sqlx::query("INSERT INTO remote_login_cleanup(host_id,person_id) VALUES(?,?)")
        .bind(host.as_bytes().as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    host
}

/// Exercise the bounded same-origin browser route, including its session authority.
async fn forget_response(f: &Fixture, host: Uuid) -> axum::response::Response {
    use tower::ServiceExt;
    crate::remote_removal_http::router(f.auth.clone(), removal(f))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/remote/hosts/forget")
                .header("origin", ORIGIN)
                .header("content-type", "application/json")
                .header("cookie", format!("__Host-infraternal={}", f.session))
                .body(axum::body::Body::from(json!({"host_id":host}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Get the browser route's status when the caller does not need its response body.
async fn forget_request(f: &Fixture, host: Uuid) -> axum::http::StatusCode {
    forget_response(f, host).await.status()
}

/// The browser's result uses the inventory label for both reported and fallback names.
#[tokio::test]
async fn forget_message_matches_inventory_name() {
    use infraternal_plugin_remote::inventory::Inventory;

    let f = fixture().await;
    let inventory = crate::remote_inventory::Source {
        pool: f.auth.pool.clone(),
        hosts: crate::remote_runtime::RemoteHosts::default(),
        #[cfg(feature = "mesh")]
        mesh: None,
    };
    for hostname in [None, Some("Workshop.local")] {
        let host = forget_fixture(&f, true).await;
        sqlx::query("DELETE FROM remote_host_bootstrap WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .execute(&f.auth.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE remote_hosts SET hostname=?,reported_os='macOS' WHERE id=?")
            .bind(hostname)
            .bind(host.as_bytes().as_slice())
            .execute(&f.auth.pool)
            .await
            .unwrap();

        let listed = inventory.list(&f.user, None).await.unwrap();
        let name = listed["hosts"][0]["name"].as_str().unwrap();
        let expected = match hostname {
            Some(_) => "workshop".to_owned(),
            None => format!("macos-{}", &host.simple().to_string()[..6]),
        };
        assert_eq!(name, expected);
        let response = forget_response(&f, host).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let result: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result["message"], format!("{name} was forgotten here."));
    }
}

/// Forget removes pending delivery and inventory visibility while preserving denial and audit.
#[tokio::test]
async fn forget_pending_host_keeps_audit_and_denial() {
    let f = fixture().await;
    let host = forget_fixture(&f, true).await;
    sqlx::query("INSERT INTO mesh_audit(user_id,action,resource,revision,occurred_at,detail_json) VALUES(?,'remote.host.remove',?,0,1,'{}')")
        .bind(&f.user).bind(host.to_string()).execute(&f.auth.pool).await.unwrap();
    assert_eq!(forget_request(&f, host).await, axum::http::StatusCode::OK);
    assert!(!live(&f, host).await);
    let inventory = crate::remote_inventory::Source {
        pool: f.auth.pool.clone(),
        hosts: crate::remote_runtime::RemoteHosts::default(),
        #[cfg(feature = "mesh")]
        mesh: None,
    };
    let listed = infraternal_plugin_remote::inventory::Inventory::list(&inventory, &f.user, None)
        .await
        .unwrap();
    assert_eq!(listed["hosts"], json!([]));
    let certificates: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_certificates WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(certificates, 1, "the certificate denial ledger stays");
    let prior_audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mesh_audit WHERE action='remote.host.remove' AND resource=?",
    )
    .bind(host.to_string())
    .fetch_one(&f.auth.pool)
    .await
    .unwrap();
    assert_eq!(prior_audit, 1, "earlier audit records stay unchanged");
    for table in [
        "remote_host_removals",
        "remote_login_cleanup",
        "remote_host_bootstrap",
    ] {
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM {table} WHERE host_id=?"
        )))
        .bind(host.as_bytes().as_slice())
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
        assert_eq!(count, 0, "{table}");
    }
    let detail: String = sqlx::query_scalar(
        "SELECT detail_json FROM mesh_audit WHERE action='remote.host.forget' AND resource=?",
    )
    .bind(host.to_string())
    .fetch_one(&f.auth.pool)
    .await
    .unwrap();
    let detail: Value = serde_json::from_str(&detail).unwrap();
    assert_eq!(detail["host_cleanup"], "pending");
    assert_eq!(detail["requested_at"], 1);
    assert_eq!(
        forget_request(&f, host).await,
        axum::http::StatusCode::FORBIDDEN
    );
}

/// A pending host can renew the same owner's expired admin window and finish Forget.
#[tokio::test]
async fn forget_passkey_renews_admin_window_for_pending_host() {
    let mut f = fixture().await;
    let host = forget_fixture(&f, true).await;
    let now = crate::runtime::unix_seconds().unwrap();
    sqlx::query("UPDATE sessions SET fresh=? WHERE token_hash=?")
        .bind(now - 901)
        .bind(hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(
        forget_request(&f, host).await,
        axum::http::StatusCode::PRECONDITION_REQUIRED
    );

    let service = removal(&f);
    let start = service
        .reauth_start(&f.session, host, now)
        .await
        .expect("the pending host should be eligible for a renewal challenge");
    let proof = f.software.login(&start, ORIGIN, true);
    service
        .reauth_finish(&f.session, host, str_field(&start, "ceremony"), proof, now)
        .await
        .expect("a valid proof should renew the current owner session");
    assert_eq!(forget_request(&f, host).await, axum::http::StatusCode::OK);
}

/// Forget requires pending cleanup, ownership, and a fresh admin window.
#[tokio::test]
async fn forget_rechecks_state_owner_and_admin_window() {
    for rule in [
        "other-owner",
        "non-owner",
        "expired",
        "no-cleanup",
        "confirmed",
    ] {
        let f = fixture().await;
        let host = forget_fixture(&f, true).await;
        match rule {
            "other-owner" => {
                sqlx::query("INSERT INTO users(id,name,owner,recovery_hash) VALUES('other','other',0,'unused')").execute(&f.auth.pool).await.unwrap();
                sqlx::query("UPDATE remote_hosts SET owner_id='other' WHERE id=?")
                    .bind(host.as_bytes().as_slice())
                    .execute(&f.auth.pool)
                    .await
                    .unwrap();
            }
            "non-owner" => {
                sqlx::query("UPDATE users SET owner=0 WHERE id=?")
                    .bind(&f.user)
                    .execute(&f.auth.pool)
                    .await
                    .unwrap();
            }
            "expired" => {
                sqlx::query("UPDATE sessions SET fresh=1")
                    .execute(&f.auth.pool)
                    .await
                    .unwrap();
            }
            "no-cleanup" => {
                sqlx::query("DELETE FROM remote_login_cleanup")
                    .execute(&f.auth.pool)
                    .await
                    .unwrap();
            }
            "confirmed" => {
                sqlx::query("UPDATE remote_login_cleanup SET confirmed=1")
                    .execute(&f.auth.pool)
                    .await
                    .unwrap();
            }
            _ => {}
        }
        // A closed admin window is the one refusal the page can fix with a passkey tap (#563).
        let expected = if rule == "expired" {
            axum::http::StatusCode::PRECONDITION_REQUIRED
        } else {
            axum::http::StatusCode::FORBIDDEN
        };
        assert_eq!(forget_request(&f, host).await, expected, "{rule}");
        assert!(live(&f, host).await, "{rule}");
    }
}

/// Inventory derives retirement from the outbox and certificate expiry, not a removal row.
#[tokio::test]
async fn forget_retired_host_without_removal_record_matches_inventory() {
    let f = fixture().await;
    let host = forget_fixture(&f, false).await;
    sqlx::query("DELETE FROM remote_host_removals WHERE host_id=?")
        .bind(host.as_bytes().as_slice())
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(forget_request(&f, host).await, axum::http::StatusCode::OK);
    assert!(!live(&f, host).await);
}

/// Return the browser removal-start status using this fixture's same-origin owner cookie.
async fn removal_start_status(f: &Fixture, host: Uuid) -> axum::http::StatusCode {
    use tower::ServiceExt;
    crate::remote_removal_http::router(f.auth.clone(), removal(f))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/remote/hosts/remove/start")
                .header("origin", ORIGIN)
                .header("content-type", "application/json")
                .header("cookie", format!("__Host-infraternal={}", f.session))
                .body(axum::body::Body::from(json!({"host_id":host}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// POST `payload` to the browser removal router at `path` as the fixture's
/// same-origin session, returning only the status code.
async fn owner_post_status(
    f: &Fixture,
    path: &str,
    payload: serde_json::Value,
) -> axum::http::StatusCode {
    use tower::ServiceExt;
    crate::remote_removal_http::router(f.auth.clone(), removal(f))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header("origin", ORIGIN)
                .header("content-type", "application/json")
                .header("cookie", format!("__Host-infraternal={}", f.session))
                .body(axum::body::Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

/// Send a same-origin owner request through one browser router and decode its JSON response.
async fn removal_json(
    app: &axum::Router,
    session: &str,
    path: &str,
    payload: serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header("origin", ORIGIN)
                .header("content-type", "application/json")
                .header("cookie", format!("__Host-infraternal={session}"))
                .body(axum::body::Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 32768)
        .await
        .unwrap();
    let value = serde_json::from_slice(&body).unwrap_or_else(|error| {
        panic!(
            "expected JSON from HTTP {status}, got {error}: {}",
            String::from_utf8_lossy(&body)
        )
    });
    (status, value)
}

/// Repeating an offline browser removal returns its existing status and checked uninstall command (#483).
#[tokio::test]
async fn repeated_pending_removal_returns_existing_browser_response() {
    let f = fixture().await;
    // The HTTP adapter uses wall time, so give the fixture session a live admin window.
    let now = crate::runtime::unix_seconds().unwrap();
    sqlx::query("UPDATE sessions SET unlocked=1,fresh=?,expires=? WHERE token_hash=?")
        .bind(now)
        .bind(now + 3600)
        .bind(hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let host = owned_host(&f).await;
    let app = crate::remote_removal_http::router(f.auth.clone(), removal(&f));
    let (status, first_review) = removal_json(
        &app,
        &f.session,
        "/remote/hosts/remove/start",
        json!({"host_id":host,"uninstall":true}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let (status, first) = removal_json(
        &app,
        &f.session,
        "/remote/hosts/remove/finish",
        json!({"host_id":host,"review":str_field(&first_review, "review")}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(first["state"], "pending");

    let (status, repeat_review) = removal_json(
        &app,
        &f.session,
        "/remote/hosts/remove/start",
        json!({"host_id":host,"uninstall":false}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let (status, repeated) = removal_json(
        &app,
        &f.session,
        "/remote/hosts/remove/finish",
        json!({"host_id":host,"review":str_field(&repeat_review, "review")}),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "a repeat must not become 503"
    );
    assert_eq!(repeated["host_id"], first["host_id"]);
    assert_eq!(repeated["state"], first["state"]);
    assert_eq!(repeated["host_cleanup"], first["host_cleanup"]);
    assert_eq!(repeated["message"], first["message"]);
    assert_eq!(repeated["manual"], first["manual"]);

    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_host_removals WHERE host_id=?")
        .bind(host.as_bytes().as_slice())
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(
        rows, 1,
        "the repeat must preserve the first cleanup request"
    );
}

/// An expired admin window asks for a tap while the owner's browser session stays signed in (#498).
#[tokio::test]
async fn expired_removal_window_requests_passkey_instead_of_sign_in() {
    let f = fixture().await;
    let host = owned_host(&f).await;
    sqlx::query("UPDATE sessions SET fresh=1")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(
        removal_start_status(&f, host).await,
        axum::http::StatusCode::PRECONDITION_REQUIRED
    );
    assert!(
        f.auth
            .session(&f.session, crate::runtime::unix_seconds().unwrap())
            .await
            .is_ok()
    );
    sqlx::query("UPDATE users SET owner=0 WHERE id=?")
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(
        removal_start_status(&f, host).await,
        axum::http::StatusCode::FORBIDDEN,
        "a non-owner must not receive the window-expired response"
    );
    sqlx::query("UPDATE users SET owner=1 WHERE id=?")
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM sessions WHERE token_hash=?")
        .bind(crate::auth::hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(
        removal_start_status(&f, host).await,
        axum::http::StatusCode::UNAUTHORIZED,
        "an ended session must not receive the window-expired response"
    );
    assert!(live(&f, host).await);
}

/// A real identity-only tap renews this session, resumes removal and cannot revive a per-action grant (#498).
#[tokio::test]
async fn removal_passkey_renews_same_session_and_cannot_replay() {
    let mut f = fixture().await;
    let host = owned_host(&f).await;
    let service = removal(&f);
    let now = NOW + 901;
    bind_tap(&f.auth, &f.session, json!({"kind":"passkey.add"}), NOW).await;
    let before = f
        .auth
        .session(&f.session, now)
        .await
        .unwrap()
        .session_incarnation;
    let start = service.reauth_start(&f.session, host, now).await.unwrap();
    assert!(
        start["options"]["publicKey"].get("extensions").is_none(),
        "renewal needs no PRF secret"
    );
    let ceremony = str_field(&start, "ceremony");
    let proof = f.software.login(&start, ORIGIN, true);
    let cross_session = crate::auth::random_capability();
    let mut tx = f.auth.pool.begin().await.unwrap();
    insert_session(
        &mut tx,
        &cross_session,
        &f.user,
        "second browser",
        now,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(f.auth.session(&cross_session, now).await.is_ok());
    assert!(
        service
            .reauth_finish(&f.session, Uuid::new_v4(), ceremony, proof.clone(), now)
            .await
            .is_err()
    );
    assert!(
        service
            .reauth_finish(&cross_session, host, ceremony, proof.clone(), now)
            .await
            .is_err()
    );
    service
        .reauth_finish(&f.session, host, ceremony, proof.clone(), now)
        .await
        .unwrap();
    assert_eq!(
        f.auth
            .fresh_session(&f.session, now)
            .await
            .unwrap()
            .session_incarnation,
        before
    );
    assert!(
        f.auth.add_start(&f.session, now).await.is_err(),
        "renewal must not resurrect the old per-action tap"
    );
    assert!(
        service
            .reauth_finish(&f.session, host, ceremony, proof, now)
            .await
            .is_err()
    );
    let review = service.start(&f.session, host, true, now).await.unwrap();
    assert_eq!(
        service
            .finish_host(&f.session, host, str_field(&review, "review"), now)
            .await
            .unwrap()["state"],
        "pending"
    );
}

/// Unrelated ceremonies, stale requests and authority revoked during the prompt never renew a session (#498).
#[tokio::test]
async fn removal_passkey_rechecks_authority_and_rejects_unrelated_ceremonies() {
    for rule in [
        "unrelated",
        "expired",
        "owner-revoked",
        "session-revoked",
        "host-revoked",
        "no-uv",
        "wrong-origin",
        "wrong-rp-id",
    ] {
        let mut f = fixture().await;
        let host = owned_host(&f).await;
        let service = removal(&f);
        let now = NOW + 901;
        let start = if rule == "unrelated" {
            f.auth.login_start(&f.user, now).await.unwrap()
        } else {
            service.reauth_start(&f.session, host, now).await.unwrap()
        };
        let proof = match rule {
            "no-uv" => f.software.login(&start, ORIGIN, false),
            "wrong-origin" => f.software.login(&start, "https://evil.example.test", true),
            "wrong-rp-id" => {
                f.software.rp_id = "evil.example.test";
                f.software.login(&start, ORIGIN, true)
            }
            _ => f.software.login(&start, ORIGIN, true),
        };
        match rule {
            "owner-revoked" => {
                sqlx::query("UPDATE users SET owner=0")
                    .execute(&f.auth.pool)
                    .await
                    .unwrap();
            }
            "session-revoked" => {
                sqlx::query("DELETE FROM sessions")
                    .execute(&f.auth.pool)
                    .await
                    .unwrap();
            }
            "host-revoked" => {
                sqlx::query("UPDATE remote_hosts SET revoked_at=1")
                    .execute(&f.auth.pool)
                    .await
                    .unwrap();
            }
            _ => {}
        }
        assert!(
            service
                .reauth_finish(
                    &f.session,
                    host,
                    str_field(&start, "ceremony"),
                    proof,
                    if rule == "expired" { now + 120 } else { now }
                )
                .await
                .is_err(),
            "{rule}"
        );
        assert!(
            f.auth.fresh_session(&f.session, now).await.is_err(),
            "{rule}"
        );
    }
}

/// Concurrent reviews for one host share one pending request and one removal record (#483).
#[tokio::test]
async fn concurrent_second_removal_returns_existing_pending_response() {
    let f = fixture().await;
    let host = owned_host(&f).await;
    let service = removal(&f);
    let first = service.start(&f.session, host, true, NOW).await.unwrap();
    let second = service.start(&f.session, host, true, NOW).await.unwrap();
    let first_review = str_field(&first, "review").to_owned();
    let second_review = str_field(&second, "review").to_owned();
    let (first, second) = tokio::join!(
        service.finish_host(&f.session, host, &first_review, NOW),
        service.finish_host(&f.session, host, &second_review, NOW),
    );
    let first = first.expect("the first review records the offline cleanup");
    let second = second.expect("the second review returns the existing cleanup");
    assert_eq!(first["host_id"], second["host_id"]);
    assert_eq!(first["state"], second["state"]);
    assert_eq!(first["manual"], second["manual"]);
    let removals: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_host_removals WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(
        removals, 1,
        "the second request cannot publish another removal"
    );
}

/// The Inbox route (D398) answers an expired admin window with the report list
/// (no passkey tap is needed), a non-owner 403 and an ended session 401; the
/// earlier per-host report route is gone.
#[tokio::test]
async fn the_inbox_route_answers_by_who_asks() {
    let f = fixture().await;
    let host = owned_host(&f).await;
    let inbox = || owner_post_status(&f, "/remote/hosts/access-reports", json!({}));
    sqlx::query("UPDATE sessions SET fresh=1")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(inbox().await, axum::http::StatusCode::OK);
    assert_eq!(
        owner_post_status(&f, "/remote/hosts/access-report", json!({"host_id":host})).await,
        axum::http::StatusCode::NOT_FOUND,
        "the per-host report route is still mounted"
    );
    sqlx::query("UPDATE users SET owner=0 WHERE id=?")
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(
        inbox().await,
        axum::http::StatusCode::FORBIDDEN,
        "a non-owner must not read the Inbox"
    );
    sqlx::query("DELETE FROM sessions WHERE token_hash=?")
        .bind(crate::auth::hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(inbox().await, axum::http::StatusCode::UNAUTHORIZED);
}

/// #580: a device has no agent to uninstall and no logins to revoke, so its removal retires
/// it at once. The answer is `removed` (never `pending`), no uninstall obligation is left
/// waiting for a receipt that cannot come, and its mesh node goes with it.
#[tokio::test]
async fn removing_a_device_retires_it_at_once_with_nothing_to_uninstall() {
    let f = fixture().await;
    let host = Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at,device_approved,hostname) VALUES(?,?,'device',NULL,1,1,'kayg-iphone')")
        .bind(host.as_bytes().as_slice()).bind(&f.user).execute(&f.auth.pool).await.unwrap();
    sqlx::query(
        "INSERT INTO mesh_nodes(id,name,public_key,dataplane_host) VALUES (1,'kayg-iphone',?,?)",
    )
    .bind([9_u8; 32].as_slice())
    .bind(host.to_string())
    .execute(&f.auth.pool)
    .await
    .unwrap();
    let service = removal(&f);
    let start = service.start(&f.session, host, true, NOW).await.unwrap();
    assert_eq!(start["action"]["host"], "kayg-iphone");
    let review = str_field(&start, "review");
    let result = service
        .finish_host(&f.session, host, review, NOW)
        .await
        .unwrap();
    assert_eq!(result["state"], "removed");
    assert_eq!(result["host_cleanup"], "none");
    assert!(result["manual"].is_null());
    assert!(
        result["message"]
            .as_str()
            .unwrap()
            .contains("kayg-iphone was removed"),
        "{result}"
    );
    assert!(!live(&f, host).await, "retired at once, not pending");
    let (confirmed, removals, nodes): (bool, i64, i64) = sqlx::query_as(
        "SELECT (SELECT confirmed FROM remote_login_cleanup WHERE host_id=?1), \
                (SELECT count(*) FROM remote_host_removals WHERE host_id=?1), \
                (SELECT count(*) FROM mesh_nodes)",
    )
    .bind(host.as_bytes().as_slice())
    .fetch_one(&f.auth.pool)
    .await
    .unwrap();
    assert!(confirmed, "nothing waits for a host receipt");
    assert_eq!(removals, 0, "no uninstall request was queued");
    assert_eq!(nodes, 0, "the mesh node was retired with the device");
    assert!(
        service
            .finish_host(&f.session, host, review, NOW)
            .await
            .is_err(),
        "a review is single use"
    );
}
