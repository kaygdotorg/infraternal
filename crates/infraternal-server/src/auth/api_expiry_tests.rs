//! API key inactivity deadlines, bounded renewal writes and upgrade grace (#269, D311).
use super::*;

async fn key(f: &Fixture) -> String {
    let approval = f
        .auth
        .device_start("cli", vec!["hosts:read".into()], TEST_SOURCE, NOW)
        .await
        .unwrap();
    f.auth
        .device_approve(&f.session, str_field(&approval, "user_code"), NOW)
        .await
        .unwrap();
    f.auth
        .device_redeem(str_field(&approval, "poll_token"), NOW)
        .await
        .unwrap()
}

async fn expiry(auth: &Auth, key: &str) -> i64 {
    sqlx::query_scalar("SELECT expires_at FROM api_keys WHERE token_hash=?")
        .bind(hash(key))
        .fetch_one(&auth.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn api_key_expiry_boundary_and_unknown_have_the_same_error() {
    let f = fixture().await;
    let expired = key(&f).await;
    let live = key(&f).await;
    f.auth.set_test_http_time(NOW + 2_592_000 - 1);
    assert_eq!(
        f.auth.api_authorize(&live, "hosts:read").await.unwrap(),
        f.user
    );
    f.auth.set_test_http_time(NOW + 2_592_000);
    for token in [&expired, &random()] {
        let error = f.auth.api_authorize(token, "hosts:read").await.unwrap_err();
        assert!(matches!(error, Error::Denied));
        assert_eq!(error.to_string(), "authorization failed");
    }
    // An unsuccessful use cannot revive an expired key.
    assert!(f.auth.api_authorize(&expired, "hosts:read").await.is_err());
}

#[tokio::test]
async fn api_key_use_slides_expiry_only_once_per_hour() {
    let f = fixture().await;
    let key = key(&f).await;
    assert_eq!(expiry(&f.auth, &key).await, NOW + 2_592_000);
    // A trigger detects even an UPDATE which writes unchanged values.
    sqlx::raw_sql("CREATE TABLE key_writes(n INTEGER NOT NULL); INSERT INTO key_writes VALUES (0); CREATE TRIGGER count_key_writes AFTER UPDATE ON api_keys BEGIN UPDATE key_writes SET n=n+1; END;")
        .execute(&f.auth.pool).await.unwrap();
    for offset in [0, 1, 3599, 3600, 3601, 7199, 7200] {
        f.auth.set_test_http_time(NOW + offset);
        f.auth.api_authorize(&key, "hosts:read").await.unwrap();
        let writes: i64 = sqlx::query_scalar("SELECT n FROM key_writes")
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
        assert_eq!(writes, offset / 3600);
        assert_eq!(
            expiry(&f.auth, &key).await,
            NOW + 2_592_000 + (offset / 3600) * 3600
        );
    }
    // Passing the original deadline still works after a legitimate renewal.
    f.auth.set_test_http_time(NOW + 2_592_001);
    f.auth.api_authorize(&key, "hosts:read").await.unwrap();
    assert_eq!(expiry(&f.auth, &key).await, NOW + 5_184_001);
}

#[tokio::test]
async fn api_key_denied_scope_never_renews_and_revocation_stays_immediate() {
    let f = fixture().await;
    let key = key(&f).await;
    f.auth.set_test_http_time(NOW + 3600);
    assert!(matches!(
        f.auth.api_authorize(&key, "terminal:connect").await,
        Err(Error::Denied)
    ));
    assert_eq!(expiry(&f.auth, &key).await, NOW + 2_592_000);
    f.auth.api_authorize(&key, "hosts:read").await.unwrap();
    f.auth
        .api_revoke(&f.session, &hash(&key), NOW + 1)
        .await
        .unwrap();
    assert!(matches!(
        f.auth.api_authorize(&key, "hosts:read").await,
        Err(Error::Denied)
    ));
}

#[tokio::test]
async fn api_key_upgrade_starts_thirty_days_at_migration_once() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut old = sqlx::migrate!("./migrations");
    old.migrations = old
        .iter()
        .filter(|m| m.version <= 33)
        .cloned()
        .collect::<Vec<_>>()
        .into();
    old.run(&pool).await.unwrap();
    sqlx::raw_sql("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES ('legacy','legacy',1,'unused','legacy','Legacy'); INSERT INTO api_keys(token_hash,user_id,device,scopes) VALUES ('legacy-hash','legacy','cli','[\"hosts:read\"]');")
        .execute(&pool).await.unwrap();
    let before: i64 = sqlx::query_scalar("SELECT unixepoch()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let auth = Auth::new(pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    let after: i64 = sqlx::query_scalar("SELECT unixepoch()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let deadline: i64 = sqlx::query_scalar("SELECT expires_at FROM api_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!((before + 2_592_000..=after + 2_592_000).contains(&deadline));
    Auth::new(pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT expires_at FROM api_keys")
            .fetch_one(&pool)
            .await
            .unwrap(),
        deadline
    );
    // Check the upgraded record through real authorization without needing its raw secret.
    let key = random();
    sqlx::query("UPDATE api_keys SET token_hash=?")
        .bind(hash(&key))
        .execute(&pool)
        .await
        .unwrap();
    auth.set_test_http_time(deadline - 1);
    auth.api_authorize(&key, "hosts:read").await.unwrap();
}

#[tokio::test]
async fn api_key_lifetime_settings_validate_and_apply_to_existing_keys() {
    use axum::http::StatusCode;
    let f = fixture().await;
    let key = key(&f).await;
    f.auth.set_test_http_time(NOW);
    let app = router(f.auth.clone());
    let cookie = format!("__Host-infraternal={}", f.session);
    let (status, _, body) =
        http_post_json_with_cookie(&app, "security-settings", json!({}), &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["api_key_lifetime_days"], 30);
    for value in [
        json!(0),
        json!(366),
        json!(-1),
        json!(1.5),
        json!("30"),
        Value::Null,
    ] {
        let (status, _, _) = http_post_json_with_cookie(
            &app,
            "security-settings-update",
            json!({"api_key_lifetime_days":value}),
            &cookie,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    for days in [365, 1] {
        let (status, _, body) = http_post_json_with_cookie(
            &app,
            "security-settings-update",
            json!({"api_key_lifetime_days":days}),
            &cookie,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["api_key_lifetime_days"], days);
    }
    f.auth.set_test_http_time(NOW + 86_400);
    assert!(matches!(
        f.auth.api_authorize(&key, "hosts:read").await,
        Err(Error::Denied)
    ));
    assert_eq!(
        expiry(&f.auth, &key).await,
        NOW + 86_400,
        "shortened deadline is persisted without renewal"
    );
}

#[tokio::test]
async fn api_key_settings_require_live_owner_and_fresh_same_origin_mutation() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    let f = fixture().await;
    f.auth.set_test_http_time(NOW);
    let app = router(f.auth.clone());
    let cookie = format!("__Host-infraternal={}", f.session);
    let update = json!({"api_key_lifetime_days":1});
    assert_eq!(
        http_post_json(&app, "security-settings", json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        http_post_json(&app, "security-settings-update", update.clone())
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let foreign = Request::builder()
        .method("POST")
        .uri("/auth/security-settings-update")
        .header("Origin", "https://other.example.test")
        .header("Cookie", &cookie)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&update).unwrap()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(foreign).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    f.auth.set_test_http_time(NOW + FRESH);
    assert_eq!(
        http_post_json_with_cookie(&app, "security-settings-update", update.clone(), &cookie)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    f.auth.set_test_http_time(NOW);
    sqlx::query("UPDATE users SET owner=0")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(
        http_post_json_with_cookie(&app, "security-settings-update", update, &cookie)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        http_post_json_with_cookie(&app, "security-settings", json!({}), &cookie)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn api_key_concurrent_uses_renew_once() {
    let f = fixture().await;
    let key = key(&f).await;
    f.auth.set_test_http_time(NOW + 3600);
    sqlx::raw_sql("CREATE TABLE key_writes(n INTEGER NOT NULL); INSERT INTO key_writes VALUES (0); CREATE TRIGGER count_key_writes AFTER UPDATE ON api_keys BEGIN UPDATE key_writes SET n=n+1; END;")
        .execute(&f.auth.pool).await.unwrap();
    let (a, b) = tokio::join!(
        f.auth.api_authorize(&key, "hosts:read"),
        f.auth.api_authorize(&key, "hosts:read")
    );
    assert_eq!(a.unwrap(), f.user);
    assert_eq!(b.unwrap(), f.user);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT n FROM key_writes")
            .fetch_one(&f.auth.pool)
            .await
            .unwrap(),
        1
    );
}

/// J97's exact day-31 / 30->365 and day-2 / 1->30 policy reproductions,
/// exercised through authorization rather than a copied, potentially stale query.
#[tokio::test]
async fn api_key_policy_increase_cannot_resurrect_expired_keys() {
    for (elapsed_days, shorter, longer) in [(31, 30, 365), (2, 1, 30)] {
        let f = fixture().await;
        let key = key(&f).await;
        sqlx::query("UPDATE server_settings SET api_key_lifetime_days=?")
            .bind(shorter)
            .execute(&f.auth.pool)
            .await
            .unwrap();
        f.auth.set_test_http_time(NOW + elapsed_days * 86400);
        assert!(matches!(
            f.auth.api_authorize(&key, "hosts:read").await,
            Err(Error::Denied)
        ));
        sqlx::query("UPDATE server_settings SET api_key_lifetime_days=?")
            .bind(longer)
            .execute(&f.auth.pool)
            .await
            .unwrap();
        assert!(
            matches!(
                f.auth.api_authorize(&key, "hosts:read").await,
                Err(Error::Denied)
            ),
            "policy increase must not resurrect a dead key"
        );
    }
    // Even without an earlier denied check, lengthening cannot extend an old deadline.
    let f = fixture().await;
    let key = key(&f).await;
    sqlx::query("UPDATE server_settings SET api_key_lifetime_days=365")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    f.auth.set_test_http_time(NOW + 31 * 86400);
    assert!(matches!(
        f.auth.api_authorize(&key, "hosts:read").await,
        Err(Error::Denied)
    ));
}

#[tokio::test]
async fn api_key_shortening_clamps_and_lengthening_requires_successful_renewal() {
    let f = fixture().await;
    let key = key(&f).await;
    sqlx::query("UPDATE server_settings SET api_key_lifetime_days=1")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    f.auth.set_test_http_time(NOW + 1);
    f.auth.api_authorize(&key, "hosts:read").await.unwrap();
    assert_eq!(expiry(&f.auth, &key).await, NOW + 86400);
    sqlx::query("UPDATE server_settings SET api_key_lifetime_days=365")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    f.auth.set_test_http_time(NOW + 3599);
    f.auth.api_authorize(&key, "hosts:read").await.unwrap();
    assert_eq!(expiry(&f.auth, &key).await, NOW + 86400);
    f.auth.set_test_http_time(NOW + 3600);
    f.auth.api_authorize(&key, "hosts:read").await.unwrap();
    assert_eq!(expiry(&f.auth, &key).await, NOW + 3600 + 365 * 86400);
}

/// J97: denied at deadline, then accepted at deadline-1. Also cover a key
/// not yet checked at the high-water time, and reconstruction after restart.
#[tokio::test]
async fn api_key_wall_clock_rollback_never_revives_or_extends_keys() {
    let f = fixture().await;
    let expired = key(&f).await;
    let unchecked = key(&f).await;
    let deadline = NOW + 30 * 86400;
    f.auth.set_test_http_time(deadline);
    assert!(matches!(
        f.auth.api_authorize(&expired, "hosts:read").await,
        Err(Error::Denied)
    ));
    let restarted = Auth::new(f.auth.pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    restarted.set_test_http_time(deadline - 1);
    for key in [expired, unchecked] {
        assert!(
            matches!(
                restarted.api_authorize(&key, "hosts:read").await,
                Err(Error::Denied)
            ),
            "persisted server time must not move backwards"
        );
    }
}

/// J97: sample at deadline-1, resume at deadline+1. Holding the sole pool
/// connection deterministically forces the authorization future to await DB access.
#[tokio::test]
async fn api_key_expiry_is_resampled_after_database_wait() {
    use std::{future::Future, task::Poll};
    let f = fixture().await;
    let key = key(&f).await;
    let deadline = NOW + 30 * 86400;
    let held = f.auth.pool.acquire().await.unwrap();
    f.auth.set_test_http_time(deadline - 1);
    let mut authorization = Box::pin(f.auth.api_authorize(&key, "hosts:read"));
    std::future::poll_fn(|cx| {
        assert!(authorization.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    f.auth.set_test_http_time(deadline + 1);
    drop(held);
    assert!(
        matches!(authorization.await, Err(Error::Denied)),
        "time sampled before waiting must not renew an expired key"
    );
    assert_eq!(expiry(&f.auth, &key).await, deadline);
}
