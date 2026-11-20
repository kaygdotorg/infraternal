//! Real SQLite logout completion, rollback and publication checks, plus an opt-in perf measurement.

use super::*;

#[tokio::test]
#[ignore = "measurement only; run on a perf VM under perf-run.sh"]
async fn logout_publication_measurement() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let affected: Vec<_> = (0..16).map(|_| f.auth.revocation_events(&f.user)).collect();
    let auth = &f.auth;
    let unrelated: Vec<_> = (0..60)
        .flat_map(|account| {
            let user = format!("unrelated-{account}");
            (0..4).map(move |_| auth.revocation_events(&user))
        })
        .collect();
    let mut samples = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let token = random();
        let mut tx = f.auth.pool.begin().await.unwrap();
        insert_session(&mut tx, &token, &f.user, "measurement", NOW, None)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let began = std::time::Instant::now();
        f.auth.logout(&token).await.unwrap();
        samples.push(began.elapsed().as_micros());
    }
    samples.sort_unstable();
    assert!(affected.iter().all(|events| events.has_changed().unwrap()));
    assert!(
        unrelated
            .iter()
            .all(|events| !events.has_changed().unwrap())
    );
    eprintln!(
        "logout_publication samples={} affected_cursors=16 unrelated_cursors=240 accounts=61 p50_us={} p99_us={}",
        samples.len(),
        samples[500],
        samples[990]
    );
}

#[tokio::test]
async fn logout_commit_failure_does_not_publish_revocation_or_report_success() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let events = f.auth.revocation_events(&f.user);
    // Defer this constraint until statement completion, after RETURNING has produced its row.
    sqlx::query("CREATE TABLE logout_commit_probe(token_hash TEXT REFERENCES sessions(token_hash) DEFERRABLE INITIALLY DEFERRED)")
        .execute(&f.auth.pool).await.unwrap();
    sqlx::query("INSERT INTO logout_commit_probe VALUES(?)")
        .bind(hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let result = f.auth.logout(&f.session).await;
    assert!(
        result.is_err(),
        "a refused commit was reported as logout success"
    );
    assert!(
        !events.has_changed().unwrap(),
        "an uncommitted deletion published revocation"
    );
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE token_hash=?")
        .bind(hash(&f.session))
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(remaining, 1);
}

#[tokio::test]
async fn review_account_scope_statement_rollback_is_quiet_and_later_commit_wakes_once() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let mut events = f.auth.revocation_events(&f.user);
    // SQLite performs the DELETE, then the trigger refuses the statement and
    // rolls it back. A later successful retry must still publish a generation.
    sqlx::query("CREATE TRIGGER refuse_logout AFTER DELETE ON sessions BEGIN SELECT RAISE(ROLLBACK, 'test rollback'); END")
        .execute(&f.auth.pool).await.unwrap();
    assert!(f.auth.logout(&f.session).await.is_err());
    assert!(!events.has_changed().unwrap());
    assert!(
        f.auth
            .live_expiry(&f.session, &f.user, NOW, ())
            .await
            .is_ok()
    );
    sqlx::query("DROP TRIGGER refuse_logout")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    f.auth.logout(&f.session).await.unwrap();
    assert!(events.has_changed().unwrap());
    events.borrow_and_update();
    assert!(
        f.auth
            .live_expiry(&f.session, &f.user, NOW, ())
            .await
            .is_err()
    );
    f.auth.logout(&f.session).await.unwrap();
    assert!(
        !events.has_changed().unwrap(),
        "repeat logout invented a new deletion"
    );
}

/// A committed logout still publishes when its Rust waiter is cancelled.
#[tokio::test]
async fn review_account_scope_committed_logout_keeps_wake_when_waiter_is_cancelled() {
    use futures_util::FutureExt;
    let _guard = SERIAL.lock().await;
    // Real commit visibility is tested independently of build-disk contention.
    let root = std::env::temp_dir().join("review-logout");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join(format!("{}.sqlite", Uuid::new_v4()));
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_secs(10));
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .test_before_acquire(false)
        .connect_with(options.clone())
        .await
        .unwrap();
    let (auth, setup) = empty_with_pool(pool).await;
    let f = fixture_with_bootstrap(auth, setup).await;
    let observer = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let events = f.auth.revocation_events(&f.user);
    let mut writer = observer.begin().await.unwrap();
    sqlx::query("UPDATE users SET name=name")
        .execute(&mut *writer)
        .await
        .unwrap();
    // Fence fixture pool return before deliberately withholding executor polls.
    while f.auth.pool.num_idle() != 1 {
        tokio::task::yield_now().await;
    }
    let mut logout = Box::pin(f.auth.logout(&f.session));
    // Queue the real DELETE behind another writer. Keep its Rust waiter alive but
    // unpolled after release, modelling cancellation at the DB completion boundary.
    loop {
        assert!(logout.as_mut().now_or_never().is_none());
        if f.auth.pool.num_idle() == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    writer.commit().await.unwrap();
    let committed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE token_hash=?")
                .bind(hash(&f.session))
                .fetch_one(&observer)
                .await
                .unwrap();
            if rows == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();
    drop(logout);
    // Acquiring the only connection fences the detached worker and pool return.
    drop(f.auth.pool.acquire().await.unwrap());
    let published = events.has_changed().unwrap();
    f.auth.pool.close().await;
    observer.close().await;
    std::fs::remove_file(path).unwrap();
    assert!(
        committed,
        "fixture did not reach an externally visible logout commit"
    );
    assert!(
        published,
        "committed logout lost its notification when the waiter was cancelled"
    );
}
