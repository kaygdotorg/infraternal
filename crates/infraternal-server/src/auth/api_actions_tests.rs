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
