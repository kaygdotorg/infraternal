//! Verifies API-key action attribution survives expiry and revocation boundaries.
use super::*;

#[tokio::test]
async fn revoked_api_key_action_retains_its_key_and_person_audit_attribution() {
    let f = fixture().await;
    let token = "fixture-api-key-never-print";
    let token_hash = hash(token);
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?, 'fixture-cli', '[\"status:read\"]', ?, ?, 0)")
        .bind(&token_hash)
        .bind(&f.user)
        .bind(NOW)
        .bind(NOW + 86_400)
        .execute(&f.auth.pool)
        .await
        .unwrap();

    f.auth
        .api_revoke(&f.session, &token_hash, NOW)
        .await
        .unwrap();
    assert_eq!(f.auth.api_list(&f.session, NOW).await.unwrap(), json!([]));
    let guard = crate::api_actions::ActionGuard::new(f.auth.clone(), f.auth.pool.clone());
    assert!(
        guard
            .authorize_token(token, &infraternal_plugin_api::CORE_API_ACTIONS[0])
            .await
            .is_err()
    );

    let row: (String, String, String, String) = sqlx::query_as(
        "SELECT key_id,person_id,action_id,state FROM api_action_audit ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&f.auth.pool)
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            token_hash,
            f.user,
            "server.status".to_owned(),
            "denied".to_owned()
        )
    );
}

#[tokio::test]
async fn missing_expired_revoked_and_out_of_scope_keys_fail_without_disclosing_tokens() {
    use axum::http::StatusCode;

    let f = fixture().await;
    let now = crate::runtime::unix_seconds().unwrap();
    let live = "fixture-live-api-key-never-print";
    let expired = "fixture-expired-api-key-never-print";
    let revoked = "fixture-revoked-api-key-never-print";
    for (token, scopes, expires_at, dead) in [
        (live, "[\"status:read\"]", now + 3600, 0),
        (expired, "[\"status:read\"]", now - 1, 0),
        (revoked, "[\"status:read\"]", now + 3600, 1),
    ] {
        sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'j94-test',?,?,?,?)")
            .bind(hash(token))
            .bind(&f.user)
            .bind(scopes)
            .bind(now)
            .bind(expires_at)
            .bind(dead)
            .execute(&f.auth.pool)
            .await
            .unwrap();
    }

    let guard = crate::api_actions::ActionGuard::new(f.auth.clone(), f.auth.pool.clone());
    assert_eq!(
        guard
            .authorize_token(
                "fixture-missing-api-key-never-print",
                &infraternal_plugin_api::CORE_API_ACTIONS[0],
            )
            .await
            .err(),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        guard
            .authorize_token(expired, &infraternal_plugin_api::CORE_API_ACTIONS[0])
            .await
            .err(),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        guard
            .authorize_token(revoked, &infraternal_plugin_api::CORE_API_ACTIONS[0])
            .await
            .err(),
        Some(StatusCode::FORBIDDEN)
    );
    assert_eq!(
        guard
            .authorize_token(live, &infraternal_plugin_remote::inventory::LIST)
            .await
            .err(),
        Some(StatusCode::FORBIDDEN)
    );

    let rows: Vec<(String, String, String, String)> =
        sqlx::query_as("SELECT key_id,person_id,action_id,state FROM api_action_audit ORDER BY id")
            .fetch_all(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(rows.len(), 3, "unknown credentials have no person to audit");
    assert_eq!(
        rows.iter()
            .map(|(_, _, action, state)| (action.as_str(), state.as_str()))
            .collect::<Vec<_>>(),
        [
            ("server.status", "denied"),
            ("server.status", "denied"),
            ("remote.host.list", "denied")
        ]
    );
    let mut actual_key_ids = rows
        .iter()
        .map(|(key_id, _, _, _)| key_id.clone())
        .collect::<Vec<_>>();
    let mut expected_key_ids = [hash(live), hash(expired), hash(revoked)];
    actual_key_ids.sort();
    expected_key_ids.sort();
    assert_eq!(actual_key_ids, expected_key_ids);
    for (_, person_id, _, _) in &rows {
        assert_eq!(person_id, &f.user);
    }
    let encoded = serde_json::to_string(&rows).unwrap();
    for token in [
        live,
        expired,
        revoked,
        "fixture-missing-api-key-never-print",
    ] {
        assert!(!encoded.contains(token));
    }
}

#[tokio::test]
async fn successful_key_action_audit_keeps_key_id_and_person_only() {
    let f = fixture().await;
    let token = "fixture-successful-action-key-never-print";
    let token_hash = hash(token);
    let now = crate::runtime::unix_seconds().unwrap();
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'fixture-cli','[\"status:read\"]',?,?,0)")
        .bind(&token_hash)
        .bind(&f.user)
        .bind(now)
        .bind(now + 86_400)
        .execute(&f.auth.pool)
        .await
        .unwrap();

    let guard = crate::api_actions::ActionGuard::new(f.auth.clone(), f.auth.pool.clone());
    let identity = guard
        .authorize_token(token, &infraternal_plugin_api::CORE_API_ACTIONS[0])
        .await
        .unwrap();
    let audit_id = guard
        .begin_audit(&identity, "server.status", None, now)
        .await
        .unwrap();
    guard
        .finish_audit(audit_id, "complete", None, now)
        .await
        .unwrap();

    let row: (String, String, String, String) =
        sqlx::query_as("SELECT key_id,person_id,action_id,state FROM api_action_audit WHERE id=?")
            .bind(audit_id)
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(
        row,
        (
            token_hash,
            f.user,
            "server.status".to_owned(),
            "complete".to_owned()
        )
    );
    assert!(!serde_json::to_string(&row).unwrap().contains(token));
}

/// J137 P2-1: a leaked key that the owner revoked must not grow the audit table or hold the
/// writer at the attacker's request rate. The limiter runs before authorization and a key
/// records at most one `denied` row per window.
#[tokio::test]
async fn a_thousand_revoked_key_calls_are_limited_and_audited_once() {
    use axum::http::StatusCode;

    let f = fixture().await;
    let token = "fixture-revoked-flood-key-never-print";
    let now = crate::runtime::unix_seconds().unwrap();
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'fixture-cli','[\"hosts:write\"]',?,?,1)")
        .bind(hash(token))
        .bind(&f.user)
        .bind(now)
        .bind(now + 86_400)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let guard = crate::api_actions::ActionGuard::new(f.auth.clone(), f.auth.pool.clone());
    let mut statuses = std::collections::BTreeMap::<u16, usize>::new();
    for _ in 0..1000 {
        let status = guard
            .authorize_token(token, &infraternal_plugin_remote::REMOVE)
            .await
            .err()
            .expect("a revoked key never authorizes");
        *statuses.entry(status.as_u16()).or_default() += 1;
    }
    assert_eq!(
        statuses,
        [
            (StatusCode::FORBIDDEN.as_u16(), 30),
            (StatusCode::TOO_MANY_REQUESTS.as_u16(), 970)
        ]
        .into(),
        "the per-key limit runs before authorization"
    );
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_action_audit")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(rows, 1, "one denied row per key per window");
}

/// J137 P2-1: an unknown bearer is refused from a read. It neither opens the writer (the
/// persisted key clock stays put) nor writes audit rows, and a global bucket bounds it.
#[tokio::test]
async fn unknown_bearers_never_take_the_writer_and_share_one_bucket() {
    use axum::http::StatusCode;

    let f = fixture().await;
    sqlx::query("UPDATE server_settings SET api_key_time_high_water=0 WHERE id=1")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let guard = crate::api_actions::ActionGuard::new(f.auth.clone(), f.auth.pool.clone());
    let mut limited = 0;
    for index in 0..1000 {
        let status = guard
            .authorize_token(
                &format!("fixture-unknown-key-{index}"),
                &infraternal_plugin_api::CORE_API_ACTIONS[0],
            )
            .await
            .err()
            .expect("an unknown key never authorizes");
        assert!(matches!(
            status,
            StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
        ));
        limited += usize::from(status == StatusCode::TOO_MANY_REQUESTS);
    }
    assert!(limited > 0, "unknown bearers are rate limited too");
    let (high_water, rows): (i64, i64) = sqlx::query_as(
        "SELECT api_key_time_high_water,(SELECT COUNT(*) FROM api_action_audit) FROM server_settings WHERE id=1",
    )
    .fetch_one(&f.auth.pool)
    .await
    .unwrap();
    assert_eq!(
        high_water, 0,
        "no writer transaction ran for an unknown key"
    );
    assert_eq!(rows, 0);
}

/// J137 P2-1: audit rows and revoked keys age out; a live key's rows inside the bound stay.
#[tokio::test]
async fn audit_rows_and_long_revoked_keys_are_pruned() {
    let f = fixture().await;
    let now = crate::runtime::unix_seconds().unwrap();
    let old = now - crate::api_actions::AUDIT_RETENTION_SECONDS - 1;
    for (token, expires_at, dead) in [
        ("fixture-long-dead-key-never-print", old, 1),
        ("fixture-recent-dead-key-never-print", now - 60, 1),
        ("fixture-live-retained-key-never-print", now + 3600, 0),
    ] {
        sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'fixture-cli','[\"status:read\"]',?,?,?)")
            .bind(hash(token))
            .bind(&f.user)
            .bind(now)
            .bind(expires_at)
            .bind(dead)
            .execute(&f.auth.pool)
            .await
            .unwrap();
    }
    for occurred_at in [old, old, now] {
        sqlx::query("INSERT INTO api_action_audit(key_id,person_id,action_id,state,occurred_at) VALUES('k',?,'server.status','complete',?)")
            .bind(&f.user)
            .bind(occurred_at)
            .execute(&f.auth.pool)
            .await
            .unwrap();
    }
    crate::api_actions::prune_audit(&f.auth.pool, now)
        .await
        .unwrap();
    let audit: Vec<i64> = sqlx::query_scalar("SELECT occurred_at FROM api_action_audit")
        .fetch_all(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(audit, [now]);
    let mut keys: Vec<String> = sqlx::query_scalar("SELECT token_hash FROM api_keys")
        .fetch_all(&f.auth.pool)
        .await
        .unwrap();
    keys.sort();
    let mut expected = [
        hash("fixture-recent-dead-key-never-print"),
        hash("fixture-live-retained-key-never-print"),
    ];
    expected.sort();
    assert_eq!(keys, expected);
}

/// Revocation stamps the key's end of life, so retention counts from the revocation.
#[tokio::test]
async fn revocation_stamps_the_key_end_of_life() {
    let f = fixture().await;
    let token_hash = hash("fixture-revoke-stamp-key-never-print");
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'fixture-cli','[\"status:read\"]',?,?,0)")
        .bind(&token_hash)
        .bind(&f.user)
        .bind(NOW)
        .bind(NOW + 86_400)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    f.auth
        .api_revoke(&f.session, &token_hash, NOW)
        .await
        .unwrap();
    let expires_at: i64 = sqlx::query_scalar("SELECT expires_at FROM api_keys WHERE token_hash=?")
        .bind(&token_hash)
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(expires_at, NOW);
}

#[tokio::test]
async fn streamed_actions_share_the_per_key_rate_limit_and_audit_rejection() {
    use axum::http::StatusCode;

    let f = fixture().await;
    let token = "fixture-streamed-action-key-never-print";
    let token_hash = hash(token);
    let now = crate::runtime::unix_seconds().unwrap();
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'fixture-cli','[\"hosts:write\"]',?,?,0)")
        .bind(&token_hash)
        .bind(&f.user)
        .bind(now)
        .bind(now + 86_400)
        .execute(&f.auth.pool)
        .await
        .unwrap();

    let guard = crate::api_actions::ActionGuard::new(f.auth.clone(), f.auth.pool.clone());
    let action = &infraternal_plugin_ssh::manifest::START;
    let identity = guard.authorize_token(token, action).await.unwrap();
    for _ in 0..29 {
        guard.authorize_identity(&identity, action).await.unwrap();
    }
    assert_eq!(
        guard.authorize_identity(&identity, action).await,
        Err(StatusCode::TOO_MANY_REQUESTS)
    );

    let denied: (String, String, String) = sqlx::query_as(
        "SELECT key_id,person_id,state FROM api_action_audit ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&f.auth.pool)
    .await
    .unwrap();
    assert_eq!(denied, (token_hash, f.user, "denied".to_owned()));
    assert!(!serde_json::to_string(&denied).unwrap().contains(token));
}

/// J137 P3-4: revoking a key wakes its owner's live streams, which recheck and close.
#[tokio::test]
async fn revoking_a_key_wakes_its_owner_streams() {
    let f = fixture().await;
    let token_hash = hash("fixture-revoke-wake-key-never-print");
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'fixture-cli','[\"hosts:write\"]',?,?,0)")
        .bind(&token_hash)
        .bind(&f.user)
        .bind(NOW)
        .bind(NOW + 86_400)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let events = f.auth.revocation_events(&f.user);
    f.auth
        .api_revoke(&f.session, &token_hash, NOW)
        .await
        .unwrap();
    assert!(
        events.has_changed().unwrap(),
        "revocation published no event"
    );
}

/// J137 P3-5: an audit row left `pending` (a removal never approved or polled, or a server
/// restart mid-action) is resolved as an expired denial instead of staying pending forever.
#[tokio::test]
async fn pending_audit_rows_that_never_finish_are_expired() {
    let f = fixture().await;
    let now = crate::runtime::unix_seconds().unwrap();
    for occurred_at in [now - 3601, now - 60] {
        sqlx::query("INSERT INTO api_action_audit(key_id,person_id,action_id,state,occurred_at) VALUES('k',?,'remote.host.remove','pending',?)")
            .bind(&f.user)
            .bind(occurred_at)
            .execute(&f.auth.pool)
            .await
            .unwrap();
    }
    crate::api_actions::prune_audit(&f.auth.pool, now)
        .await
        .unwrap();
    let rows: Vec<(String, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT state,result,completed_at FROM api_action_audit ORDER BY occurred_at",
    )
    .fetch_all(&f.auth.pool)
    .await
    .unwrap();
    assert_eq!(
        rows,
        [
            ("denied".to_owned(), Some("expired".to_owned()), Some(now)),
            ("pending".to_owned(), None, None)
        ]
    );
}
