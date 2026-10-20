//! Verifies receipt-counter upgrades and transaction boundaries against real SQLite [183,248].
#![allow(clippy::unwrap_used)]
use sqlx::SqlitePool;

async fn count(pool: &SqlitePool, account: &str) -> i64 {
    sqlx::query_scalar("SELECT receipt_count FROM canvas_heads WHERE account=?")
        .bind(account)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn historical_receipts_backfill_and_follow_transactions_and_account_removal() {
    let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
    sqlx::raw_sql("PRAGMA foreign_keys=ON; CREATE TABLE users(id TEXT PRIMARY KEY); INSERT INTO users VALUES('a'),('b'),('empty');")
        .execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/0028_canvas_layout.sql"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql("INSERT INTO canvas_heads VALUES('a',2,'original',1),('b',1,'peer',1),('empty',0,'empty',0); INSERT INTO canvas_receipts VALUES('a','first','digest',1),('a','second','digest',2),('b','first','digest',1);")
        .execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/0030_canvas_receipt_count.sql"))
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(count(&pool, "a").await, 2);
    assert_eq!(count(&pool, "b").await, 1);
    assert_eq!(count(&pool, "empty").await, 0);
    let original: (i64, String) =
        sqlx::query_as("SELECT revision,document FROM canvas_heads WHERE account='a'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(original, (2, "original".into()));
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO canvas_receipts VALUES('a','rolled-back','digest',2)")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(count(&pool, "a").await, 2);
    sqlx::query("INSERT INTO canvas_receipts VALUES('a','third','digest',2)")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(count(&pool, "a").await, 3);
    assert!(
        sqlx::query("INSERT INTO canvas_receipts VALUES('a','third','digest',2)")
            .execute(&pool)
            .await
            .is_err()
    );
    assert_eq!(count(&pool, "a").await, 3);
    sqlx::query("UPDATE canvas_receipts SET account='b' WHERE account='a' AND op_id='third'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(count(&pool, "a").await, 2);
    assert_eq!(count(&pool, "b").await, 2);
    sqlx::query("DELETE FROM canvas_receipts WHERE account='a' AND op_id='second'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(count(&pool, "a").await, 1);
    sqlx::query("DELETE FROM users WHERE id='a'")
        .execute(&pool)
        .await
        .unwrap();
    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM canvas_receipts WHERE account='a'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(receipts, 0);
    assert_eq!(count(&pool, "b").await, 2);
    assert!(
        sqlx::query("UPDATE canvas_heads SET receipt_count=-1 WHERE account='b'")
            .execute(&pool)
            .await
            .is_err()
    );
}
