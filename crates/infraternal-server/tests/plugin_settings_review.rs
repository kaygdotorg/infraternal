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

#[cfg(feature = "mesh")]
#[tokio::test]
async fn plugin_switches_survive_database_reopen() {
    use infraternal_server::plugins::compiled;
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
    let root = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || std::path::PathBuf::from("target"),
        std::path::PathBuf::from,
    );
    let path = root.join(format!("plugin-settings-{}.sqlite", uuid::Uuid::new_v4()));
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options.clone())
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let first = compiled(&pool).await.unwrap();
    assert_eq!(enabled(&first, "mesh"), true);
    first.set_enabled("mesh", false).await.unwrap();
    drop(first);
    pool.close().await;
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options.clone())
        .await
        .unwrap();
    let second = compiled(&pool).await.unwrap();
    assert_eq!(
        enabled(&second, "mesh"),
        false,
        "disabled plugin reverted to its default on restart"
    );
    assert_eq!(second.active_workers("mesh"), 0);
    second.set_enabled("mesh", true).await.unwrap();
    drop(second);
    pool.close().await;
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .unwrap();
    let third = compiled(&pool).await.unwrap();
    assert_eq!(enabled(&third, "mesh"), true);
    assert_eq!(third.active_workers("mesh"), 0);
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT enabled FROM plugin_settings WHERE role='server' AND plugin='mesh'"
        )
        .fetch_one(&pool)
        .await
        .unwrap()
    );
    drop(third);
    pool.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    println!("plugin_switch_restart disabled=true enabled=true workers=0 reopen_count=2");
}

#[cfg(feature = "mesh")]
#[tokio::test]
async fn failed_plugin_save_restores_previous_state_without_workers() {
    use infraternal_server::plugins::{PluginError, compiled};
    let pool = memory().await;
    let runtime = compiled(&pool).await.unwrap();
    sqlx::query("DROP TABLE plugin_settings")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        runtime.set_enabled("mesh", false).await,
        Err(PluginError::Storage)
    );
    assert_eq!(enabled(&runtime, "mesh"), true);
    assert_eq!(runtime.active_workers("mesh"), 0);
    assert!(
        compiled(&pool).await.is_err(),
        "startup must refuse unreadable settings"
    );
    drop(runtime);
    pool.close().await;
}

/// Discovery ordering is unconstrained; persistence assertions name the feature they mutate.
#[cfg(feature = "mesh")]
fn enabled(runtime: &infraternal_server::plugins::PluginRuntime, id: &str) -> serde_json::Value {
    runtime.list()["plugins"]
        .as_array()
        .unwrap()
        .iter()
        .find(|plugin| plugin["descriptor"]["id"] == id)
        .unwrap()["enabled"]
        .clone()
}
