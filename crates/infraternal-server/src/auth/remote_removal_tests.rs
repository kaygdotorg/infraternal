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

/// Offline removal records denial and reports pending; a durable receipt retires it.
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
    assert_eq!(result["host_cleanup"], "unreachable");
    // #235: an uninstall that did not happen is said plainly, by name, with the
    // commands that remove the leftover rootful install on the machine itself.
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
    crate::enrollment::EnrollmentStore::new(f.auth.pool.clone())
        .confirm_login_cleanup(host, Uuid::parse_str(&f.user).unwrap())
        .await
        .unwrap();
    assert!(!live(&f, host).await);
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
/// queries (bootstrap_remote.rs `existing_host`, remote_http.rs `occupied`,
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

