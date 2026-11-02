/// Verifies the owned retirement writer retries real SQLite BUSY after its configured timeout (#169).
#[tokio::test]
async fn cancelled_invitation_retires_after_sqlite_busy_timeout() {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
    let root = std::env::temp_dir().join(format!("retire-{}", Uuid::new_v4().simple()));
    std::fs::create_dir(&root).unwrap();
    let pool = SqlitePoolOptions::new().max_connections(2).connect_with(
        SqliteConnectOptions::new().filename(root.join("ledger.sqlite")).create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal).busy_timeout(Duration::from_millis(20))
    ).await.unwrap();
    let (store, pool, prior) = crate::enrollment::authority::tests::enrolled_with_pool(pool).await;
    let f = fixture_with_store(true, store, pool, prior).await;
    let paused = Arc::new(PausedInvitation { inner: f.backend.clone(), committed: tokio::sync::Notify::new(), release: tokio::sync::Notify::new() });
    let batch = start_backend(&f, "owner", paused.clone());
    super::wait_invitation_committed(&batch, &paused).await;
    let mut writer = f.pool.begin().await.unwrap();
    sqlx::query("UPDATE remote_hosts SET created_at=created_at").execute(&mut *writer).await.unwrap();
    let mut changed = batch.subscribe();
    drop(batch);
    // The short storage timeout forces BUSY before the writer is released. The
    // caller may stop waiting; the exact retirement operation must remain owned.
    tokio::time::timeout(super::TEST_HANG_BOUND, async {
        while changed.changed().await.is_ok() {}
    })
    .await
    .expect("cancelled bootstrap batch did not close its event stream");
    writer.rollback().await.unwrap();
    tokio::time::timeout(super::TEST_HANG_BOUND, async {
        loop {
            let live: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_hosts WHERE revoked_at IS NULL").fetch_one(&f.pool).await.unwrap();
            if live == 1 { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("retirement did not complete after the SQLite writer was released");
    assert!(f.backend.attempts.lock().unwrap().is_empty());
    f.pool.close().await;
    std::fs::remove_dir_all(root).unwrap();
}
