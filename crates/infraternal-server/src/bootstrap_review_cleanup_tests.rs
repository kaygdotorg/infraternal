/// Verifies cancellation retires committed host authority after temporary SQLite writer contention (#169).
#[tokio::test]
async fn review_cancelled_committed_invitation_survives_temporary_writer_contention() {
    use super::*;
    let f = fixture(true).await;
    let paused = Arc::new(PausedInvitation {
        inner: f.backend.clone(),
        committed: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let batch = start_backend(&f, "owner", paused.clone());
    tokio::time::timeout(Duration::from_secs(5), paused.committed.notified())
        .await
        .unwrap();
    // Hold a real SQLite write transaction after publication. The fixture's
    // one-connection pool reproduces storage unavailable to the cleanup writer;
    // no admission check, commit, or revocation is replaced with a test double.
    let mut writer = f.pool.begin().await.unwrap();
    sqlx::query("UPDATE remote_hosts SET created_at=created_at")
        .execute(&mut *writer)
        .await
        .unwrap();
    let mut changed = batch.subscribe();
    drop(batch);
    tokio::time::timeout(Duration::from_secs(12), async {
        while changed.changed().await.is_ok() {}
    })
    .await
    .unwrap();
    writer.rollback().await.unwrap();
    let live: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_hosts WHERE revoked_at IS NULL")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(live, 1, "cancelled publication retained durable host authority after the writer became available");
    assert!(f.backend.attempts.lock().unwrap().is_empty());
}
