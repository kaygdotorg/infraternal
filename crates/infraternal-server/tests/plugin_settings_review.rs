//! Exercise durable role/plugin settings on migrated SQLite and database reopen [198,201, #108].
#![allow(clippy::unwrap_used)] // Database failures stop the isolated fixture.
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

async fn memory() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn plugin_settings_enforce_boolean_and_role_plugin_identity() {
    let pool = memory().await;
    for (role, enabled) in [("server", true), ("node", false)] {
        sqlx::query("INSERT INTO plugin_settings(role,plugin,enabled) VALUES (?,'mesh',?)")
            .bind(role)
            .bind(enabled)
            .execute(&pool)
            .await
            .unwrap();
    }
    let values: Vec<bool> = sqlx::query_scalar("SELECT enabled FROM plugin_settings ORDER BY role")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(values, [false, true]);
    assert!(
        sqlx::query("INSERT INTO plugin_settings(role,plugin,enabled) VALUES ('server','mesh',0)")
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE plugin_settings SET enabled=2")
            .execute(&pool)
            .await
            .is_err()
    );
    pool.close().await;
}
