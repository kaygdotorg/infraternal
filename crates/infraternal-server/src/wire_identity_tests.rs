//! Verifies the shared allocator with real SQLite, retired identities, exhaustion and concurrent reservations [D12,D198,D232].
async fn pool() -> sqlx::SqlitePool {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE terminal_writers(writer_id INTEGER PRIMARY KEY AUTOINCREMENT);")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("../migrations/0038_wire_writer_clock.sql"))
        .execute(&pool)
        .await
        .unwrap();
    pool
}
#[tokio::test]
async fn deleted_legacy_high_water_and_explicit_terminal_ids_cannot_alias_plugins() {
    let pool = pool().await;
    sqlx::query("INSERT INTO terminal_writers(writer_id) VALUES (1000)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM terminal_writers")
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    let a = super::reserve(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(a, 2002);
    let mut tx = pool.begin().await.unwrap();
    let b = super::reserve(&mut tx).await.unwrap();
    sqlx::query("INSERT INTO terminal_writers(writer_id) VALUES (?)")
        .bind(b / 2)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(b, 2004);
    let mut tx = pool.begin().await.unwrap();
    assert_eq!(super::reserve(&mut tx).await.unwrap(), 2006);
    tx.commit().await.unwrap();
}
#[tokio::test]
async fn exhaustion_refuses_and_rollback_does_not_publish_an_identity() {
    let pool = pool().await;
    let mut tx = pool.begin().await.unwrap();
    assert_eq!(super::reserve(&mut tx).await.unwrap(), 2);
    tx.rollback().await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    assert_eq!(super::reserve(&mut tx).await.unwrap(), 2);
    tx.commit().await.unwrap();
    sqlx::query("UPDATE wire_writer_clock SET value=2147483646")
        .execute(&pool)
        .await
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    assert_eq!(super::reserve(&mut tx).await.unwrap(), 4_294_967_294);
    tx.commit().await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    assert!(super::reserve(&mut tx).await.is_err());
    tx.rollback().await.unwrap();
}
#[tokio::test]
async fn parallel_reservations_are_distinct_committed_even_ids() {
    let pool = pool().await;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let pool = pool.clone();
        tasks.push(tokio::spawn(async move {
            let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
            let id = super::reserve(&mut tx).await.unwrap();
            tx.commit().await.unwrap();
            id
        }));
    }
    let mut ids = Vec::new();
    for task in tasks {
        ids.push(task.await.unwrap());
    }
    ids.sort_unstable();
    assert_eq!(ids, (1..=16).map(|id| id * 2).collect::<Vec<_>>());
}
