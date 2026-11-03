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

#[allow(clippy::too_many_lines)] // Keep the fresh-tap, owner-session and one-time assertions in one ordered scenario.
#[tokio::test]
async fn api_key_removal_waits_for_a_fresh_owner_passkey_and_is_one_time() {
    let mut f = fixture().await;
    let host = Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootful',0,1)")
        .bind(host.as_bytes().as_slice())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
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
    let device = f
        .auth
        .device_start("j94-test", vec!["hosts:write".to_owned()], NOW)
        .await
        .unwrap();
    f.auth
        .device_approve(&f.session, str_field(&device, "user_code"), NOW)
        .await
        .unwrap();
    let key = f
        .auth
        .device_redeem(str_field(&device, "poll_token"), NOW)
        .await
        .unwrap();

    let request = service.start_api(&key, host, true, NOW).await.unwrap();
    let request_id = str_field(&request, "request_id").to_owned();
    let code = str_field(&request, "user_code").to_owned();
    assert_eq!(
        code.len(),
        16,
        "the shared device-approval page accepts 16-character codes"
    );
    let review = service
        .inspect_api_approval(&f.session, &code, NOW)
        .await
        .unwrap();
    let ceremony = str_field(&review, "ceremony").to_owned();
    assert!(
        !ceremony.is_empty(),
        "inspection must start a passkey challenge bound to this removal"
    );
    assert!(
        review["options"]["publicKey"]["challenge"]
            .as_str()
            .is_some(),
        "inspection must return the public challenge for that removal"
    );
    assert_eq!(review["action"]["label"], "Remove host.example");
    assert_eq!(review["action"]["uninstall"], true);

    let another = service.start_api(&key, host, false, NOW).await.unwrap();
    let another_code = str_field(&another, "user_code").to_owned();
    let another_review = service
        .inspect_api_approval(&f.session, &another_code, NOW)
        .await
        .unwrap();
    let another_ceremony = str_field(&another_review, "ceremony");
    assert_ne!(
        ceremony, another_ceremony,
        "each removal gets its own challenge"
    );
    let wrong_proof = f.software.login(&another_review, ORIGIN, true);
    assert!(
        service
            .approve_api(&f.session, &code, another_ceremony, wrong_proof, NOW + 1,)
            .await
            .is_err()
    );

    // The API key may initiate and inspect its result, but cannot stand in for
    // the signed-in owner's fresh passkey session.
    let proof = f.software.login(&review, ORIGIN, true);
    assert!(
        service
            .approve_api(&key, &code, &ceremony, proof.clone(), NOW)
            .await
            .is_err()
    );
    let pending = service.api_status(&key, &request_id, NOW).await.unwrap();
    assert_eq!(pending["state"], "pending");

    let result = service
        .approve_api(&f.session, &code, &ceremony, proof.clone(), NOW + 60)
        .await
        .unwrap();
    assert_eq!(result["state"], "removed");
    assert!(
        service
            .approve_api(&f.session, &code, &ceremony, proof, NOW + 60)
            .await
            .is_err()
    );
    let status = service
        .api_status(&key, &request_id, NOW + 60)
        .await
        .unwrap();
    assert_eq!(status["state"], "complete");
    assert_eq!(status["result"]["state"], "removed");
}

#[tokio::test]
async fn api_removal_admission_refusal_keeps_the_request_retryable() {
    let mut f = fixture().await;
    let host = Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootful',0,1)")
        .bind(host.as_bytes().as_slice())
        .bind(&f.user)
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
    let device = f
        .auth
        .device_start("j94-test", vec!["hosts:write".to_owned()], NOW)
        .await
        .unwrap();
    f.auth
        .device_approve(&f.session, str_field(&device, "user_code"), NOW)
        .await
        .unwrap();
    let key = f
        .auth
        .device_redeem(str_field(&device, "poll_token"), NOW)
        .await
        .unwrap();
    let request = service.start_api(&key, host, false, NOW).await.unwrap();
    let request_id = str_field(&request, "request_id").to_owned();
    let code = str_field(&request, "user_code").to_owned();
    let review = service
        .inspect_api_approval(&f.session, &code, NOW + 1)
        .await
        .unwrap();
    let ceremony = str_field(&review, "ceremony").to_owned();
    let proof = f.software.login(&review, ORIGIN, true);

    let full = service.hold_api_admission_for_test().unwrap();
    assert!(
        service
            .approve_api(&f.session, &code, &ceremony, proof.clone(), NOW + 1)
            .await
            .is_err()
    );
    drop(full);

    assert_eq!(
        service
            .approve_api(&f.session, &code, &ceremony, proof, NOW + 1)
            .await
            .unwrap()["state"],
        "removed",
        "temporary admission pressure must not consume the one-time approval"
    );
    assert_eq!(
        service
            .api_status(&key, &request_id, NOW + 1)
            .await
            .unwrap()["state"],
        "complete"
    );
}

#[tokio::test]
async fn api_key_removal_expiry_is_denied_without_a_passkey_or_host_mutation() {
    let mut f = fixture().await;
    let host = Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootful',0,1)")
        .bind(host.as_bytes().as_slice())
        .bind(&f.user)
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
    let device = f
        .auth
        .device_start("j94-test", vec!["hosts:write".to_owned()], NOW)
        .await
        .unwrap();
    f.auth
        .device_approve(&f.session, str_field(&device, "user_code"), NOW)
        .await
        .unwrap();
    let key = f
        .auth
        .device_redeem(str_field(&device, "poll_token"), NOW)
        .await
        .unwrap();
    let started = service.start_api(&key, host, false, NOW).await.unwrap();
    let request_id = str_field(&started, "request_id").to_owned();
    let code = str_field(&started, "user_code").to_owned();
    let review = service
        .inspect_api_approval(&f.session, &code, NOW)
        .await
        .unwrap();
    let ceremony = str_field(&review, "ceremony").to_owned();
    let proof = f.software.login(&review, ORIGIN, true);

    assert!(
        service
            .approve_api(&f.session, &code, &ceremony, proof, NOW + 301,)
            .await
            .is_err()
    );
    let status = service
        .api_status(&key, &request_id, NOW + 301)
        .await
        .unwrap();
    assert_eq!(status["state"], "denied");
    let live: bool = sqlx::query_scalar("SELECT revoked_at IS NULL FROM remote_hosts WHERE id=?")
        .bind(host.as_bytes().as_slice())
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert!(live, "an expired approval must not publish host removal");
}

#[tokio::test]
async fn api_key_revocation_after_removal_start_blocks_passkey_approval() {
    let mut f = fixture().await;
    let host = Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootful',0,1)")
        .bind(host.as_bytes().as_slice())
        .bind(&f.user)
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
    let device = f
        .auth
        .device_start("j94-test", vec!["hosts:write".to_owned()], NOW)
        .await
        .unwrap();
    f.auth
        .device_approve(&f.session, str_field(&device, "user_code"), NOW)
        .await
        .unwrap();
    let key = f
        .auth
        .device_redeem(str_field(&device, "poll_token"), NOW)
        .await
        .unwrap();
    let request = service.start_api(&key, host, false, NOW).await.unwrap();
    let code = str_field(&request, "user_code");
    let review = service
        .inspect_api_approval(&f.session, code, NOW)
        .await
        .unwrap();
    let ceremony = str_field(&review, "ceremony").to_owned();
    let proof = f.software.login(&review, ORIGIN, true);
    let login = f.auth.login_start(&f.user, NOW + 1).await.unwrap();
    let fresh = f
        .auth
        .login_finish(
            str_field(&login, "ceremony"),
            f.software.login(&login, ORIGIN, true),
            "phone",
            NOW + 1,
        )
        .await
        .unwrap();
    f.auth
        .api_revoke(&fresh, &hash(&key), NOW + 1)
        .await
        .unwrap();
    assert!(
        service
            .approve_api(&fresh, code, &ceremony, proof, NOW + 1)
            .await
            .is_err()
    );
    let remains_live: bool =
        sqlx::query_scalar("SELECT revoked_at IS NULL FROM remote_hosts WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert!(remains_live, "a revoked API key cannot publish removal");
}
