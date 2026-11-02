//! Recovery attempt lifetimes through the production verifier and both HTTP entry points.
use super::*;

async fn attempt(f: &Fixture, action: &str, now: i64, signed_in: bool) -> Value {
    f.auth.set_test_http_time(now);
    let cookie = if signed_in {
        format!("__Host-infraternal={}", f.session)
    } else {
        String::new()
    };
    let (status, _, body) = http_post_json_with_cookie(
        &router(f.auth.clone()),
        action,
        json!({"user_id":f.user,"verifier":recovery_verifier(&f.words)}),
        &cookie,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    body
}

async fn deadlines(f: &Fixture) -> (i64, i64) {
    sqlx::query_as("SELECT ready,expires FROM recovery WHERE user_id=?")
        .bind(&f.user)
        .fetch_one(&f.auth.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn recovery_restart_after_expiry_starts_a_new_wait_and_notifies() {
    let _guard = SERIAL.lock().await;
    for action in ["recovery-start", "recovery-resume"] {
        let f = fixture_v2().await;
        let mut events = f.auth.recovery_events(&f.user);
        let old = attempt(&f, action, NOW, false).await;
        events.changed().await.unwrap();
        let next = attempt(&f, action, NOW + 2 * DAY, false).await;
        assert!(events.has_changed().unwrap());
        assert_eq!(next["ready_at"], NOW + 3 * DAY);
        assert_eq!(next["delay_seconds"], DAY);
        assert_eq!(deadlines(&f).await, (NOW + 3 * DAY, NOW + 4 * DAY));
        assert!(
            f.auth
                .recovery_ready(str_field(&old, "token"), NOW + 3 * DAY)
                .await
                .is_err()
        );
        assert!(
            f.auth
                .recovery_ready(str_field(&next, "token"), NOW + 3 * DAY - 1)
                .await
                .is_err()
        );
        assert!(
            f.auth
                .recovery_ready(str_field(&next, "token"), NOW + 3 * DAY)
                .await
                .is_ok()
        );
        let starts: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM recovery_audit WHERE event='start'")
                .fetch_one(&f.auth.pool)
                .await
                .unwrap();
        assert_eq!(starts, 2);
    }
}

#[tokio::test]
async fn recovery_restart_while_pending_preserves_both_deadlines_even_with_session() {
    let _guard = SERIAL.lock().await;
    for action in ["recovery-start", "recovery-resume"] {
        let f = fixture_v2().await;
        let old = attempt(&f, action, NOW, false).await;
        let next = attempt(&f, action, NOW + 1, true).await;
        assert_eq!(next["ready_at"], NOW + DAY);
        assert_eq!(next["delay_seconds"], DAY - 1);
        assert_eq!(deadlines(&f).await, (NOW + DAY, NOW + 2 * DAY));
        assert!(
            f.auth
                .recovery_ready(str_field(&old, "token"), NOW + DAY)
                .await
                .is_err()
        );
        assert!(
            f.auth
                .recovery_ready(str_field(&next, "token"), NOW + DAY - 1)
                .await
                .is_err()
        );
        assert!(
            f.auth
                .recovery_ready(str_field(&next, "token"), NOW + DAY)
                .await
                .is_ok()
        );
        let at_ready = attempt(&f, action, NOW + DAY, false).await;
        assert_eq!(at_ready["delay_seconds"], 0);
        assert_eq!(deadlines(&f).await, (NOW + DAY, NOW + 2 * DAY));
        assert!(
            f.auth
                .recovery_ready(str_field(&at_ready, "token"), NOW + 2 * DAY - 1)
                .await
                .is_ok()
        );
        assert!(
            f.auth
                .recovery_ready(str_field(&at_ready, "token"), NOW + 2 * DAY)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn recovery_restart_after_cancel_starts_a_new_wait_and_notifies() {
    let _guard = SERIAL.lock().await;
    let f = fixture_v2().await;
    let old = attempt(&f, "recovery-start", NOW, false).await;
    f.auth.recovery_cancel(&f.session, NOW + DAY).await.unwrap();
    let mut events = f.auth.recovery_events(&f.user);
    let next = attempt(&f, "recovery-resume", NOW + DAY + 1, false).await;
    assert!(events.has_changed().unwrap());
    events.changed().await.unwrap();
    assert_eq!(deadlines(&f).await, (NOW + 2 * DAY + 1, NOW + 3 * DAY + 1));
    assert!(
        f.auth
            .recovery_ready(str_field(&old, "token"), NOW + 2 * DAY + 1)
            .await
            .is_err()
    );
    assert!(
        f.auth
            .recovery_ready(str_field(&next, "token"), NOW + 2 * DAY)
            .await
            .is_err()
    );
    assert!(
        f.auth
            .recovery_ready(str_field(&next, "token"), NOW + 2 * DAY + 1)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn recovery_restart_uses_persisted_server_time_after_clock_rollback() {
    let _guard = SERIAL.lock().await;
    let f = fixture_v2().await;
    attempt(&f, "recovery-start", NOW, false).await;
    // Model a later server observation persisted by API-key authorization before restart.
    sqlx::query("UPDATE server_settings SET api_key_time_high_water=? WHERE id=1")
        .bind(NOW + 2 * DAY)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let restarted = Auth::new(f.auth.pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    let f = Fixture {
        auth: restarted,
        ..f
    };
    let next = attempt(&f, "recovery-resume", NOW + 1, false).await;
    assert_eq!(next["delay_seconds"], DAY);
    assert_eq!(deadlines(&f).await, (NOW + 3 * DAY, NOW + 4 * DAY));
}
