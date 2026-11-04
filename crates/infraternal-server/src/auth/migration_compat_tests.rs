//! Exercise fresh, dev and production migration histories without weakening checksum validation [19], #169.
use super::*;
use sqlx::migrate::{Migration, MigrationType};
use std::borrow::Cow;

const INDEX: &str = include_str!("../../migrations/0022_terminal_exit_snapshot_index.sql");
const MESH: &str = include_str!("../../migrations/0020_mesh_dataplane.sql");

async fn database() -> SqlitePool {
    sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

async fn history(pool: &SqlitePool, production: bool) {
    let mut migrations = sqlx::migrate!("./migrations");
    migrations.migrations.to_mut().retain(|migration| {
        migration.version < 20
            || (!production && migration.version <= 21 && migration.sql.as_ref() != INDEX)
    });
    if production {
        migrations.migrations.to_mut().push(Migration::new(
            20,
            "terminal exit snapshot index".into(),
            MigrationType::Simple,
            Cow::Borrowed(INDEX),
            false,
        ));
    }
    migrations.run(pool).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES('history-user','history','history','History',1,'synthetic-hash')")
        .execute(pool).await.unwrap();
}

async fn upgrade(pool: &SqlitePool) {
    Auth::new(pool.clone(), "localhost", "https://localhost")
        .await
        .unwrap();
    Auth::new(pool.clone(), "localhost", "https://localhost")
        .await
        .unwrap();
    let objects: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE name IN ('mesh_dataplane','terminal_sessions_closed_exit_user')")
        .fetch_one(pool).await.unwrap();
    assert_eq!(objects, 2);
    let checksum: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version=20")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        checksum,
        Migration::new(
            20,
            "mesh".into(),
            MigrationType::Simple,
            Cow::Borrowed(MESH),
            false
        )
        .checksum
        .as_ref()
    );
}

#[tokio::test]
async fn loopback_https_origin_with_explicit_port_initializes_auth() {
    let pool = database().await;
    Auth::new(pool, "localhost", "https://localhost:443")
        .await
        .unwrap();
}

#[tokio::test]
async fn fresh_history_has_unique_versions_and_both_schemas() {
    let migrations = sqlx::migrate!("./migrations");
    let versions: std::collections::HashSet<_> = migrations
        .iter()
        .map(|migration| migration.version)
        .collect();
    assert_eq!(
        versions.len(),
        migrations.iter().count(),
        "migration versions collide"
    );
    upgrade(&database().await).await;
}

#[tokio::test]
async fn dev_history_keeps_its_mesh_checksum_and_data() {
    let pool = database().await;
    history(&pool, false).await;
    upgrade(&pool).await;
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT id FROM users")
            .fetch_one(&pool)
            .await
            .unwrap(),
        "history-user"
    );
}

#[tokio::test]
async fn production_history_keeps_index_checksum_and_data() {
    let pool = database().await;
    history(&pool, true).await;
    upgrade(&pool).await;
    let checksum: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version=22")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        checksum,
        Migration::new(
            20,
            "index".into(),
            MigrationType::Simple,
            Cow::Borrowed(INDEX),
            false
        )
        .checksum
        .as_ref()
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT id FROM users")
            .fetch_one(&pool)
            .await
            .unwrap(),
        "history-user"
    );
}

#[tokio::test]
async fn unrecognized_checksum_is_refused_without_retagging() {
    let pool = database().await;
    history(&pool, true).await;
    let unknown = vec![42_u8; 48];
    sqlx::query("UPDATE _sqlx_migrations SET checksum=? WHERE version=20")
        .bind(&unknown)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        Auth::new(pool.clone(), "localhost", "https://localhost").await,
        Err(Error::Migration(_))
    ));
    let checksum: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version=20")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(checksum, unknown);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM _sqlx_migrations WHERE version=22")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn dirty_production_migration_is_refused_without_retagging() {
    let pool = database().await;
    history(&pool, true).await;
    sqlx::query("UPDATE _sqlx_migrations SET success=0 WHERE version=20")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        Auth::new(pool.clone(), "localhost", "https://localhost").await,
        Err(Error::Migration(_))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM _sqlx_migrations WHERE version=20 AND success=0"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
}

#[tokio::test]
async fn occupied_destination_leaves_the_production_ledger_unchanged() {
    let pool = database().await;
    history(&pool, true).await;
    sqlx::query("INSERT INTO _sqlx_migrations(version,description,success,checksum,execution_time) VALUES(22,'occupied',1,?,0)")
        .bind(vec![17_u8; 48]).execute(&pool).await.unwrap();
    assert!(matches!(
        Auth::new(pool.clone(), "localhost", "https://localhost").await,
        Err(Error::Migration(_))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM _sqlx_migrations WHERE version=20")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    let checksum: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version=22")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(checksum, vec![17_u8; 48]);
}

#[tokio::test]
async fn committed_retag_can_resume_after_interruption_and_concurrent_startup() {
    let pool = database().await;
    history(&pool, true).await;
    let (first, second) = tokio::join!(
        migration_compat::normalize_production_index(&pool),
        migration_compat::normalize_production_index(&pool),
    );
    first.unwrap();
    second.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM _sqlx_migrations WHERE version=20")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM _sqlx_migrations WHERE version=22")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    upgrade(&pool).await;
}

/// Live production already applied the retirement journal above the dev-only
/// migration gap; retagging its index must preserve that journal and checksum.
#[tokio::test]
async fn live_production_retirement_history_survives_dev_upgrade() {
    let pool = database().await;
    history(&pool, true).await;
    let mut retirement = sqlx::migrate!("./migrations");
    retirement
        .migrations
        .to_mut()
        .retain(|migration| migration.version < 20 || migration.version == 23);
    retirement.migrations.to_mut().push(Migration::new(
        20,
        "terminal exit snapshot index".into(),
        MigrationType::Simple,
        Cow::Borrowed(INDEX),
        false,
    ));
    retirement
        .migrations
        .to_mut()
        .sort_by_key(|migration| migration.version);
    retirement.run(&pool).await.unwrap();
    let host = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'history-user','rootless',1002,100)")
        .bind(host.as_bytes().as_slice()).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO remote_bootstrap_retirement_intents(host_id) VALUES(?)")
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let checksum: Vec<u8> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version=23")
            .fetch_one(&pool)
            .await
            .unwrap();
    upgrade(&pool).await;
    assert_eq!(
        sqlx::query_scalar::<_, Vec<u8>>("SELECT checksum FROM _sqlx_migrations WHERE version=23")
            .fetch_one(&pool)
            .await
            .unwrap(),
        checksum
    );
    assert_eq!(
        sqlx::query_scalar::<_, Vec<u8>>("SELECT host_id FROM remote_bootstrap_retirement_intents")
            .fetch_one(&pool)
            .await
            .unwrap(),
        host.as_bytes().as_slice()
    );
}
