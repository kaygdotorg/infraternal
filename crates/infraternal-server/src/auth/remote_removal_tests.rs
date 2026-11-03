//! Real passkey and SQLite regression for host removal purpose binding and offline revocation (#87).
use super::*;
#[tokio::test]
async fn fresh_removal_revokes_offline_host_and_cannot_replay() {
    let mut f = fixture().await;
    let host = Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootful',0,1)").bind(host.as_bytes().as_slice()).bind(&f.user).execute(&f.auth.pool).await.unwrap();
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'root@host.example',NULL)")
        .bind(host.as_bytes().as_slice())
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let service = crate::remote_removal::Removal::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        crate::enrollment::EnrollmentStore::new(f.auth.pool.clone()),
        crate::remote_runtime::RemoteHosts::default(),
        PathBuf::new(),
    );
    let ordinary = f.auth.login_start(&f.user, NOW).await.unwrap();
    let ordinary_proof = f.software.login(&ordinary, ORIGIN, true);
    assert!(
        service
            .finish(
                &f.session,
                str_field(&ordinary, "ceremony"),
                ordinary_proof,
                NOW
            )
            .await
            .is_err()
    );
    let start = service.start(&f.session, host, true, NOW).await.unwrap();
    let proof = f.software.login(&start, ORIGIN, true);
    let id = str_field(&start, "ceremony");
    assert!(
        service
            .finish_host(&f.session, Uuid::new_v4(), id, proof.clone(), NOW)
            .await
            .is_err()
    );
    let result = service
        .finish(&f.session, id, proof.clone(), NOW)
        .await
        .unwrap();
    assert_eq!(result["host_cleanup"], "unreachable");
    // #235: an uninstall that did not happen is said plainly, by name, with the
    // commands that remove the leftover rootful install on the machine itself.
    let message = result["message"].as_str().unwrap();
    assert!(
        message.starts_with(
            "host.example was removed here, but infraternal is still installed on it."
        )
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
    assert!(service.finish(&f.session, id, proof, NOW).await.is_err());
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert!(revoked);
    let coordinates: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_host_bootstrap")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(coordinates, 0);
}

#[tokio::test]
async fn logout_or_role_loss_after_removal_start_preserves_host() {
    for logout in [true, false] {
        let mut f = fixture().await;
        let host = Uuid::new_v4();
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootful',0,1)").bind(host.as_bytes().as_slice()).bind(&f.user).execute(&f.auth.pool).await.unwrap();
        let service = crate::remote_removal::Removal::new(
            f.auth.clone(),
            f.auth.pool.clone(),
            crate::enrollment::EnrollmentStore::new(f.auth.pool.clone()),
            crate::remote_runtime::RemoteHosts::default(),
            PathBuf::new(),
        );
        let start = service.start(&f.session, host, false, NOW).await.unwrap();
        let proof = f.software.login(&start, ORIGIN, true);
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
                .finish(&f.session, str_field(&start, "ceremony"), proof, NOW)
                .await
                .is_err()
        );
        let live: bool =
            sqlx::query_scalar("SELECT revoked_at IS NULL FROM remote_hosts WHERE id=?")
                .bind(host.as_bytes().as_slice())
                .fetch_one(&f.auth.pool)
                .await
                .unwrap();
        assert!(live);
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
    assert_eq!(result["state"], "removed");
    assert!(revoked(f.auth.pool.clone()).await);
    let audit: (String, Option<String>) =
        sqlx::query_as("SELECT state,result FROM api_action_audit WHERE id=?")
            .bind(audit_id)
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(audit, ("complete".to_owned(), Some("removed".to_owned())));
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
