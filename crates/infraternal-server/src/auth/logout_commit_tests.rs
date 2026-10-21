//! Real SQLite commit refusals must neither acknowledge logout nor publish a revocation.

use super::*;

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
