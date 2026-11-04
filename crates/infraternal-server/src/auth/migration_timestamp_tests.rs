//! Prove timestamp upgrades keep numbered history and strict `SQLx` validation [D347, #344].
use super::migration_compat::MIGRATIONS;
use sqlx::{
    SqlitePool,
    migrate::{MigrateError, Migration, MigrationType, Migrator},
};
use std::borrow::Cow;

/// Earlier and later independent branch versions, both beyond the numbered history.
const EARLIER: i64 = 20_261_104_153_000;
/// A branch may reach a database before another branch with an earlier timestamp.
const LATER: i64 = 20_261_104_160_000;

/// Copy the shipping configuration and history; fill not-yet-merged 0041–0048 with no-op fixtures.
/// Once those files merge, their real SQL is exercised automatically instead.
fn numbered_history() -> Migrator {
    let mut migrations = MIGRATIONS
        .iter()
        .filter(|m| m.version <= 48)
        .cloned()
        .collect::<Vec<_>>();
    for version in 41..=48 {
        if !migrations.iter().any(|m| m.version == version) {
            migrations.push(Migration::new(
                version,
                Cow::Borrowed("reserved fixture"),
                MigrationType::Simple,
                Cow::Borrowed("SELECT 1;"),
                false,
            ));
        }
    }
    migrations.sort_by_key(|m| m.version);
    Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: MIGRATIONS.ignore_missing,
        locking: MIGRATIONS.locking,
        no_tx: MIGRATIONS.no_tx,
    }
}

/// Append resolved fixture timestamps using the shipping migrator's validation flags.
fn timestamps(mut history: Migrator) -> Migrator {
    let fixtures = sqlx::migrate!("./tests/fixtures/migration-timestamps");
    history
        .migrations
        .to_mut()
        .extend(fixtures.iter().filter(|m| m.version > 48).cloned());
    history
}

/// Use one real SQLite connection so the in-memory history survives each startup.
async fn database() -> SqlitePool {
    sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

/// Read the complete stored checksums, including the numbered history, in numeric order.
async fn checksums(pool: &SqlitePool) -> Vec<(i64, Vec<u8>)> {
    sqlx::query_as("SELECT version,checksum FROM _sqlx_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .unwrap()
}

#[tokio::test]
/// Filename resolution sorts integer versions, then a fresh database executes that order.
async fn timestamp_versions_sort_after_0048() {
    let fixtures = sqlx::migrate!("./tests/fixtures/migration-timestamps");
    assert_eq!(
        fixtures.iter().map(|m| m.version).collect::<Vec<_>>(),
        [48, EARLIER, LATER]
    );
    let pool = database().await;
    fixtures.run(&pool).await.unwrap();
    let events: Vec<String> =
        sqlx::query_scalar("SELECT name FROM timestamp_events ORDER BY rowid")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(events, ["earlier", "later"]);
}

#[tokio::test]
/// An upgrade executes each new timestamp once and leaves all numbered checksums intact.
async fn timestamp_upgrade_preserves_0001_through_0048() {
    let pool = database().await;
    let history = numbered_history();
    history.run(&pool).await.unwrap();
    let before = checksums(&pool).await;
    assert_eq!(before.len(), 48);
    let upgraded = timestamps(history);
    upgraded.run(&pool).await.unwrap();
    let once = checksums(&pool).await;
    assert_eq!(&once[..48], before);
    assert_eq!(once.len(), 50);
    for ((version, checksum), source) in once.iter().zip(upgraded.iter()) {
        assert_eq!(*version, source.version);
        assert_eq!(checksum.as_slice(), source.checksum.as_ref());
    }
    upgraded.run(&pool).await.unwrap();
    assert_eq!(checksums(&pool).await, once);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM timestamp_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
/// A merged earlier timestamp runs after a later one without ignoring missing files or altered SQL.
async fn timestamp_out_of_order_keeps_missing_and_checksum_checks() {
    let pool = database().await;
    let mut later_branch = timestamps(numbered_history());
    later_branch
        .migrations
        .to_mut()
        .retain(|m| m.version != EARLIER);
    later_branch.run(&pool).await.unwrap();
    let before = checksums(&pool).await;
    let merged = timestamps(numbered_history());
    assert!(!merged.ignore_missing);
    merged.run(&pool).await.unwrap();
    let after = checksums(&pool).await;
    for row in &before {
        assert!(after.contains(row));
    }
    merged.run(&pool).await.unwrap();
    let events: Vec<String> =
        sqlx::query_scalar("SELECT name FROM timestamp_events ORDER BY rowid")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(events, ["later", "earlier"]);
    // Running the old branch again is a downgrade with an absent applied file, not out-of-order apply.
    assert!(matches!(
        later_branch.run(&pool).await,
        Err(MigrateError::VersionMissing(EARLIER))
    ));
    for version in [1, 48, EARLIER, LATER] {
        let original = checksums(&pool).await;
        sqlx::query("UPDATE _sqlx_migrations SET checksum=x'00' WHERE version=?")
            .bind(version)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            matches!(merged.run(&pool).await, Err(MigrateError::VersionMismatch(found)) if found == version)
        );
        let checksum = &original.iter().find(|row| row.0 == version).unwrap().1;
        sqlx::query("UPDATE _sqlx_migrations SET checksum=? WHERE version=?")
            .bind(checksum)
            .bind(version)
            .execute(&pool)
            .await
            .unwrap();
    }
}
