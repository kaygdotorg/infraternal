//! Recovery attempt lifetimes through the production verifier and both HTTP entry points.
use super::*;

const SECOND: i64 = 1_000_000_000;

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
    sqlx::query_as("SELECT ready/1000000000,expires/1000000000 FROM recovery WHERE user_id=?")
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
                .recovery_ready(str_field(&old, "token"), NOW + 2 * DAY)
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
                .recovery_ready(str_field(&old, "token"), NOW + 1)
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
            .recovery_ready(str_field(&old, "token"), NOW + DAY + 1)
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

// Separate elapsed time from wall time: advancing wall time must grant no authority.
#[tokio::test]
async fn recovery_elapsed_forward_step_cannot_release_the_envelope() {
    let _guard = SERIAL.lock().await;
    let f = fixture_v2().await;
    f.auth
        .test_recovery_elapsed
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let old = attempt(&f, "recovery-start", NOW, false).await;
    assert!(
        f.auth
            .recovery_ready(str_field(&old, "token"), NOW + 1)
            .await
            .is_err(),
        "a forward wall-clock step released the envelope before elapsed 24h"
    );
}

#[tokio::test]
async fn recovery_elapsed_status_and_boundaries_ignore_both_clock_steps() {
    let _guard = SERIAL.lock().await;
    let f = fixture_v2().await;
    let elapsed = |seconds| {
        f.auth
            .test_recovery_elapsed
            .store(seconds * SECOND, std::sync::atomic::Ordering::Relaxed);
    };
    elapsed(0);
    attempt(&f, "recovery-start", NOW, false).await;
    elapsed(3600);
    let next = attempt(&f, "recovery-resume", NOW + DAY, false).await;
    assert_eq!(next["delay_seconds"], 82800);
    assert_eq!(
        f.auth
            .session(&f.session, NOW + DAY)
            .await
            .unwrap()
            .recovery_pending
            .unwrap()
            .ready_at,
        next["ready_at"].as_i64().unwrap()
    );
    let next = attempt(&f, "recovery-resume", NOW - DAY, false).await;
    assert_eq!(next["delay_seconds"], 82800);
    elapsed(DAY - 1);
    assert!(
        f.auth
            .recovery_ready(str_field(&next, "token"), NOW)
            .await
            .is_err()
    );
    elapsed(DAY);
    assert!(
        f.auth
            .recovery_ready(str_field(&next, "token"), NOW)
            .await
            .is_ok()
    );
    elapsed(2 * DAY - 1);
    assert!(
        f.auth
            .recovery_ready(str_field(&next, "token"), NOW)
            .await
            .is_ok()
    );
    elapsed(2 * DAY);
    assert!(
        f.auth
            .recovery_ready(str_field(&next, "token"), NOW)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn recovery_elapsed_restart_retains_only_recorded_progress() {
    let _guard = SERIAL.lock().await;
    let f = fixture_v2().await;
    f.auth
        .test_recovery_elapsed
        .store(0, std::sync::atomic::Ordering::Relaxed);
    attempt(&f, "recovery-start", NOW, false).await;
    f.auth
        .test_recovery_elapsed
        .store(3600 * SECOND, std::sync::atomic::Ordering::Relaxed);
    attempt(&f, "recovery-resume", NOW, false).await;
    // A fresh Auth owns a new monotonic origin, loading only the committed progress.
    let restarted = Auth::new(f.auth.pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    restarted
        .test_recovery_elapsed
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let f = Fixture {
        auth: restarted,
        ..f
    };
    let next = attempt(&f, "recovery-resume", NOW + DAY, false).await;
    assert_eq!(next["delay_seconds"], 82800);
    assert!(
        f.auth
            .recovery_ready(str_field(&next, "token"), NOW + DAY)
            .await
            .is_err()
    );
    f.auth
        .test_recovery_elapsed
        .store(82800 * SECOND, std::sync::atomic::Ordering::Relaxed);
    assert!(
        f.auth
            .recovery_ready(str_field(&next, "token"), NOW + DAY)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn recovery_elapsed_completion_rechecks_delay_inside_writer_transaction() {
    let _guard = SERIAL.lock().await;
    let f = fixture_v2().await;
    f.auth
        .test_recovery_elapsed
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let request = attempt(&f, "recovery-start", NOW, false).await;
    // Supply a valid ceremony independently of ready admission, so this probes the
    // final authority check even if a challenge was issued by an earlier buggy path.
    let start = f
        .auth
        .registration(
            f.user.clone(),
            "owner",
            "Owner",
            Authority::Recovery(hash(str_field(&request, "token"))),
            true,
            NOW + DAY,
        )
        .await
        .unwrap();
    let software = Software::new();
    let words = bip39::Mnemonic::generate(24).unwrap().to_string();
    let result = f
        .auth
        .registration_finish_with_verifier(
            str_field(&start, "ceremony"),
            software.registration(&start, ORIGIN, true),
            browser_wrap(&software.prf(&start), &f.dek, &f.user, "passkey"),
            Some(browser_wrap(
                &recovery_material(&words, "wrap"),
                &f.dek,
                &f.user,
                "recovery",
            )),
            Some(recovery_verifier(&words)),
            NOW + DAY,
        )
        .await;
    assert!(
        result.is_err(),
        "completion trusted a wall-clock step instead of elapsed time"
    );
    assert!(f.auth.session(&f.session, NOW + DAY).await.is_ok());
    // After 24 elapsed hours, a backward wall step cannot extend the wait.
    f.auth
        .test_recovery_elapsed
        .store(DAY * SECOND, std::sync::atomic::Ordering::Relaxed);
    let start = f
        .auth
        .recovery_ready(str_field(&request, "token"), NOW - DAY)
        .await
        .unwrap();
    let result = f
        .auth
        .registration_finish_with_verifier(
            str_field(&start, "ceremony"),
            software.registration(&start, ORIGIN, true),
            browser_wrap(&software.prf(&start), &f.dek, &f.user, "passkey"),
            Some(browser_wrap(
                &recovery_material(&words, "wrap"),
                &f.dek,
                &f.user,
                "recovery",
            )),
            Some(recovery_verifier(&words)),
            NOW - DAY,
        )
        .await;
    assert!(
        result.is_ok(),
        "a backward wall-clock step extended the completed elapsed wait"
    );
    assert!(f.auth.session(&f.session, NOW - DAY).await.is_err());
}

#[tokio::test]
async fn recovery_elapsed_subsecond_start_never_rounds_the_wait_down() {
    let _guard = SERIAL.lock().await;
    let f = fixture_v2().await;
    let elapsed = |ticks| {
        f.auth
            .test_recovery_elapsed
            .store(ticks, std::sync::atomic::Ordering::Relaxed);
    };
    elapsed(500_000_000);
    let request = attempt(&f, "recovery-start", NOW, false).await;
    assert_eq!(request["delay_seconds"], DAY);
    elapsed(DAY * SECOND + 499_999_999);
    assert!(
        f.auth
            .recovery_ready(str_field(&request, "token"), NOW)
            .await
            .is_err()
    );
    elapsed(DAY * SECOND + 500_000_000);
    assert!(
        f.auth
            .recovery_ready(str_field(&request, "token"), NOW)
            .await
            .is_ok()
    );
    elapsed(2 * DAY * SECOND + 499_999_999);
    assert!(
        f.auth
            .recovery_ready(str_field(&request, "token"), NOW)
            .await
            .is_ok()
    );
    elapsed(2 * DAY * SECOND + 500_000_000);
    assert!(
        f.auth
            .recovery_ready(str_field(&request, "token"), NOW)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn recovery_status_never_restarts_and_uses_only_server_elapsed_time() {
    let _guard = SERIAL.lock().await;
    let f = fixture_v2().await;
    f.auth
        .test_recovery_elapsed
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let request = attempt(&f, "recovery-start", NOW, false).await;
    let token = str_field(&request, "token");
    let app = router(f.auth.clone());
    for (elapsed, ready, delay) in [(0, false, DAY), (DAY - 1, false, 1), (DAY, true, 0)] {
        f.auth
            .test_recovery_elapsed
            .store(elapsed * SECOND, std::sync::atomic::Ordering::Relaxed);
        f.auth.set_test_http_time(NOW + 2 * DAY);
        let (status, _, body) =
            http_post_json_with_cookie(&app, "recovery-status", json!({"token":token}), "").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body["ready"], ready);
        assert_eq!(body["delay_seconds"], delay);
    }
    let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM recovery_audit WHERE event='start'")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(audit, 1, "status must never start a new request");
    assert!(
        f.auth.recovery_ready(token, NOW).await.is_ok(),
        "status must preserve the bearer"
    );
    f.auth
        .test_recovery_elapsed
        .store(2 * DAY * SECOND, std::sync::atomic::Ordering::Relaxed);
    let (status, _, _) =
        http_post_json_with_cookie(&app, "recovery-status", json!({"token":token}), "").await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    f.auth.recovery_cancel(&f.session, NOW).await.unwrap();
    let (status, _, _) =
        http_post_json_with_cookie(&app, "recovery-status", json!({"token":token}), "").await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM recovery")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}

#[tokio::test]
async fn recovery_elapsed_is_checkpointed_without_client_checks() {
    let _guard = SERIAL.lock().await;
    let f = fixture_v2().await;
    f.auth
        .test_recovery_elapsed
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let _request = attempt(&f, "recovery-start", NOW, false).await;
    tokio::time::pause();
    f.auth
        .test_recovery_elapsed
        .store(60 * SECOND, std::sync::atomic::Ordering::Relaxed);
    tokio::time::advance(std::time::Duration::from_secs(60)).await;
    tokio::time::resume();
    // Await the asynchronous SQLite write; the timeout bounds a hung test, not performance.
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            let saved: i64 =
                sqlx::query_scalar("SELECT elapsed FROM recovery_clock WHERE singleton=1")
                    .fetch_one(&f.auth.pool)
                    .await
                    .unwrap();
            if saved == 60 * SECOND {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("idle recovery progress must survive a restart");
}

#[tokio::test]
async fn recovery_shutdown_flush_and_restarts_credit_only_measured_progress() {
    let _guard = SERIAL.lock().await;
    let f = fixture_v2().await;
    f.auth
        .test_recovery_elapsed
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let request = attempt(&f, "recovery-start", NOW, false).await;
    let token = str_field(&request, "token");
    let mut auth = f.auth.clone();
    let mut saved = 0;
    for measured in [37, 60, 60] {
        // Graceful shutdown flushes even before the first periodic checkpoint.
        auth.test_recovery_elapsed
            .store(measured * SECOND, std::sync::atomic::Ordering::Relaxed);
        auth.checkpoint_recovery_clock().await.unwrap();
        saved += measured;
        let restarted = Auth::new(f.auth.pool.clone(), "auth.example.test", ORIGIN)
            .await
            .unwrap();
        restarted
            .test_recovery_elapsed
            .store(0, std::sync::atomic::Ordering::Relaxed);
        let status = restarted
            .recovery_status(token, NOW + 100 * DAY)
            .await
            .unwrap();
        assert_eq!(status["delay_seconds"], DAY - saved);
        assert_eq!(status["ready"], false);
        auth = restarted;
    }
    // An abrupt restart cannot credit the not-yet-checkpointed 59 seconds or downtime.
    auth.test_recovery_elapsed
        .store(59 * SECOND, std::sync::atomic::Ordering::Relaxed);
    drop(auth);
    let restarted = Auth::new(f.auth.pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    restarted
        .test_recovery_elapsed
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let status = restarted.recovery_status(token, NOW - DAY).await.unwrap();
    assert_eq!(status["delay_seconds"], DAY - saved);
    assert_eq!(status["ready"], false);
}
