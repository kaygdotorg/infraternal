//! Independent disk-SQLite recovery authority probes; diagnostics contain only outcomes.
use super::*;

async fn disk_fixture() -> (Fixture, PathBuf) {
    std::fs::create_dir_all("target/recovery-probes").unwrap();
    let path =
        PathBuf::from("target/recovery-probes").join(format!("review-{}.sqlite", Uuid::new_v4()));
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .busy_timeout(Duration::from_secs(10)),
        )
        .await
        .unwrap();
    let auth = Auth::new(pool, "auth.example.test", ORIGIN).await.unwrap();
    let mut token = String::new();
    auth.bootstrap(NOW, |banner| token = banner.lines().nth(1).unwrap().into())
        .await
        .unwrap();
    let start = auth.setup_start(&token, "owner", NOW).await.unwrap();
    let user = str_field(&start, "user_id").to_owned();
    let words = bip39::Mnemonic::generate(24).unwrap().to_string();
    let software = Software::new();
    let dek = rand::random::<[u8; 32]>();
    let session = auth
        .registration_finish_with_verifier(
            str_field(&start, "ceremony"),
            software.registration(&start, ORIGIN, true),
            browser_wrap(&software.prf(&start), &dek, &user, "passkey"),
            Some(browser_wrap(
                &recovery_material(&words, "wrap"),
                &dek,
                &user,
                "recovery",
            )),
            Some(recovery_verifier(&words)),
            NOW,
        )
        .await
        .unwrap();
    (
        Fixture {
            auth,
            software,
            user,
            session,
            words,
            dek,
        },
        path,
    )
}
async fn v2_start(f: &Fixture, now: i64) -> (String, i64, i64) {
    f.auth
        .recovery_start_clock(
            &f.user,
            super::super::recovery::RecoveryCredential::Verifier(recovery_verifier(&f.words)),
            None,
            || Ok(now),
            true,
        )
        .await
        .unwrap()
}
async fn replacement(f: &Fixture, start: &Value, now: i64) -> Result<String> {
    let software = Software::new();
    let words = bip39::Mnemonic::generate(24).unwrap().to_string();
    f.auth
        .registration_finish_with_verifier(
            str_field(start, "ceremony"),
            software.registration(start, ORIGIN, true),
            browser_wrap(&software.prf(start), &f.dek, &f.user, "passkey"),
            Some(browser_wrap(
                &recovery_material(&words, "wrap"),
                &f.dek,
                &f.user,
                "recovery",
            )),
            Some(recovery_verifier(&words)),
            now,
        )
        .await
}

#[tokio::test]
async fn reviewer_disk_cancel_complete_races() {
    let _guard = SERIAL.lock().await;
    for _ in 0..8 {
        let (f, path) = disk_fixture().await;
        let (token, ready, _) = v2_start(&f, NOW).await;
        let start = f.auth.recovery_ready(&token, ready).await.unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let a = barrier.clone();
        let cancel = async {
            a.wait().await;
            f.auth.recovery_cancel(&f.session, ready).await
        };
        let finish = async {
            barrier.wait().await;
            replacement(&f, &start, ready).await
        };
        let (cancel, finish) = tokio::join!(cancel, finish);
        assert_ne!(
            cancel.is_ok(),
            finish.is_ok(),
            "exactly one cancellation/replacement may commit"
        );
        let events: Vec<String> =
            sqlx::query_scalar("SELECT event FROM recovery_audit ORDER BY id")
                .fetch_all(&f.auth.pool)
                .await
                .unwrap();
        assert_eq!(
            events,
            vec!["start", if finish.is_ok() { "complete" } else { "cancel" }]
        );
        if finish.is_ok() {
            assert!(f.auth.session(&f.session, ready).await.is_err());
        } else {
            assert!(f.auth.session(&f.session, ready).await.is_ok());
        }
        f.auth.pool.close().await;
        std::fs::remove_file(path).unwrap();
    }
    println!("REVIEW disk cancellation/completion: 8 races, exactly one committed outcome each");
}

#[tokio::test]
async fn reviewer_disk_restart_and_concurrent_resume() {
    let _guard = SERIAL.lock().await;
    let (mut f, path) = disk_fixture().await;
    let (old, _, _) = v2_start(&f, NOW).await;
    f.auth.pool.close().await;
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .busy_timeout(Duration::from_secs(10)),
        )
        .await
        .unwrap();
    f.auth = Auth::new(pool, "auth.example.test", ORIGIN).await.unwrap();
    let a = v2_start(&f, NOW + 3 * DAY);
    let b = v2_start(&f, NOW + 3 * DAY);
    let (a, b) = tokio::join!(a, b);
    let ready = NOW + 4 * DAY;
    assert_eq!(a.1, ready);
    assert_eq!(b.1, ready);
    assert!(f.auth.recovery_ready(&old, NOW + 3 * DAY).await.is_err());
    assert!(f.auth.recovery_ready(&a.0, ready - 1).await.is_err());
    assert!(f.auth.recovery_ready(&b.0, ready - 1).await.is_err());
    let live_a = f.auth.recovery_ready(&a.0, ready).await.is_ok();
    let live_b = f.auth.recovery_ready(&b.0, ready).await.is_ok();
    assert_ne!(live_a, live_b);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM recovery_audit WHERE event='start'")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
    f.auth.pool.close().await;
    std::fs::remove_file(path).unwrap();
    println!(
        "REVIEW disk restart: fresh wait after 72h; concurrent resume: one live capability, two start audits"
    );
}

#[tokio::test]
async fn reviewer_http_expired_capability_cannot_complete_after_writer_wait() {
    expired_finish_after_writer_wait(false).await;
}

#[tokio::test]
async fn reviewer_http_expired_ceremony_cannot_complete_after_writer_wait() {
    expired_finish_after_writer_wait(true).await;
}

async fn expired_finish_after_writer_wait(ceremony_expires: bool) {
    let _guard = SERIAL.lock().await;
    let (f, path) = disk_fixture().await;
    f.auth
        .test_recovery_elapsed
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let (token, _, _) = v2_start(&f, NOW).await;
    // Keep test time ahead of SQLite's unixepoch; only explicit advances can cross expiry.
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
        + 30 * DAY;
    f.auth.set_test_http_time(now);
    sqlx::query("UPDATE recovery SET ready=?,expires=?")
        .bind(0_i64)
        .bind(if ceremony_expires {
            60_000_000_000_i64
        } else {
            1_000_000_000
        })
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let app = router(f.auth.clone());
    let (status, headers, start) =
        http_post_json(&app, "recovery-ready", json!({"token":token})).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    if ceremony_expires {
        f.auth
            .pending
            .lock()
            .await
            .registrations
            .get_mut(str_field(&start, "ceremony"))
            .unwrap()
            .expires = now + 1;
    }
    let binding = headers[axum::http::header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let software = Software::new();
    let words = bip39::Mnemonic::generate(24).unwrap().to_string();
    let body = json!({"ceremony":start["ceremony"],"proof":software.registration(&start,ORIGIN,true),"passkey_wrap":browser_wrap(&software.prf(&start),&f.dek,&f.user,"passkey"),"recovery_wrap":browser_wrap(&recovery_material(&words,"wrap"),&f.dek,&f.user,"recovery"),"recovery_verifier":recovery_verifier(&words)});
    let original: (String, String) = sqlx::query_as(
        "SELECT recovery_hash,(SELECT blob FROM wraps WHERE kind='recovery') FROM users",
    )
    .fetch_one(&f.auth.pool)
    .await
    .unwrap();
    let mut lock = f.auth.pool.begin().await.unwrap();
    sqlx::query("UPDATE users SET name=name")
        .execute(&mut *lock)
        .await
        .unwrap();
    let task = tokio::spawn(async move {
        http_post_json_with_cookie(&app, "registration-finish", body, &binding).await
    });
    let ceremony = str_field(&start, "ceremony");
    let timeout = Instant::now() + Duration::from_secs(5);
    while f
        .auth
        .pending
        .lock()
        .await
        .registrations
        .contains_key(ceremony)
    {
        assert!(Instant::now() < timeout);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(2200)).await;
    // The writer stays blocked while logical time advances beyond the relevant expiry.
    f.auth.set_test_http_time(now + 2);
    f.auth
        .test_recovery_elapsed
        .store(2_000_000_000, std::sync::atomic::Ordering::Relaxed);
    lock.commit().await.unwrap();
    let (status, _, _) = task.await.unwrap();
    println!("REVIEW finish after expired capability/writer wait: HTTP {status}");
    assert_eq!(
        status,
        axum::http::StatusCode::UNAUTHORIZED,
        "expired capability must not replace credentials after database wait"
    );
    let current: (String, String) = sqlx::query_as(
        "SELECT recovery_hash,(SELECT blob FROM wraps WHERE kind='recovery') FROM users",
    )
    .fetch_one(&f.auth.pool)
    .await
    .unwrap();
    assert!(
        current == original,
        "denied replacement must preserve verifier and envelope"
    );
    assert!(f.auth.session(&f.session, NOW).await.is_ok());
    let completed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM recovery_audit WHERE event='complete'")
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(completed, 0);
    f.auth.pool.close().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn reviewer_server_clock_rollback_preserves_duration_and_projects_estimated_date() {
    let _guard = SERIAL.lock().await;
    let (f, path) = disk_fixture().await;
    let (_, ready, _) = v2_start(&f, NOW).await;
    let (_, again, delay) = v2_start(&f, NOW - 3600).await;
    assert_eq!(again, ready - 3600);
    assert_eq!(delay, DAY);
    assert!(
        f.auth
            .recovery_ready(&v2_start(&f, NOW - 3600).await.0, NOW - 3600)
            .await
            .is_err()
    );
    f.auth.pool.close().await;
    std::fs::remove_file(path).unwrap();
    println!(
        "REVIEW server clock rollback: estimated date follows wall time, persisted remaining duration = 86400 seconds"
    );
}

#[tokio::test]
async fn reviewer_http_denials_and_recovery_admission() {
    let _guard = SERIAL.lock().await;
    let (f, path) = disk_fixture().await;
    let app = router(f.auth.clone());
    let wrong = B64.encode([7u8; 32]);
    let mut replies = Vec::new();
    for username in ["owner", "missing"] {
        for action in ["recovery-start", "recovery-resume"] {
            let (status, _, body) =
                http_post_json(&app, action, json!({"username":username,"verifier":wrong})).await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
            replies.push(body);
        }
    }
    let _ = v2_start(&f, NOW).await;
    for username in ["owner", "missing"] {
        let (status, _, body) = http_post_json(
            &app,
            "recovery-resume",
            json!({"username":username,"verifier":wrong}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
        replies.push(body);
    }
    assert!(replies.windows(2).all(|pair| pair[0] == pair[1]));
    for _ in 6..120 {
        assert_eq!(
            http_post_json(&app, "recovery-ready", json!({"token":"invalid"}))
                .await
                .0,
            axum::http::StatusCode::UNAUTHORIZED
        );
    }
    for action in [
        "recovery-start",
        "recovery-resume",
        "recovery-upgrade",
        "recovery-ready",
        "recovery-cancel",
    ] {
        let (status, headers, _) = http_post_json(&app, action, json!({})).await;
        assert_eq!(status, axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(headers[axum::http::header::RETRY_AFTER], "60");
    }
    f.auth.pool.close().await;
    std::fs::remove_file(path).unwrap();
    println!(
        "REVIEW admission: six known/unknown/pending denials identical; all five recovery actions blocked after 120 browser actions with Retry-After 60"
    );
}
