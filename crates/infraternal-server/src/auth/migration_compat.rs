//! Reconcile the exact production version-20 index with dev's immutable migration history [19], #169.
use super::{Error, Result};
use sqlx::{SqlitePool, migrate::MigrateError};

// Reuse compile-time checksums rather than linking or running another hash operation at startup.
pub(super) static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Retag only the shipped, successful index migration; normal `SQLx` validation handles every other history.
/// The immediate writer transaction makes concurrent startup and interruption safe. A committed
/// retag leaves the already-existing index at version 22; missing dev migrations then run normally.
pub(super) async fn normalize_production_index(pool: &SqlitePool) -> Result<()> {
    let mut transaction = infraternal_plugin_api::storage::begin_immediate(pool).await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='_sqlx_migrations')",
    )
    .fetch_one(&mut *transaction)
    .await?;
    if exists {
        let dirty: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE success=0)")
                .fetch_one(&mut *transaction)
                .await?;
        if !dirty {
            let checksum: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT checksum FROM _sqlx_migrations WHERE version=20 AND success=1",
            )
            .fetch_optional(&mut *transaction)
            .await?;
            let shipped = MIGRATIONS
                .iter()
                .find(|migration| migration.version == 22)
                .ok_or(Error::Migration(MigrateError::VersionMissing(22)))?;
            if checksum.as_deref() == Some(shipped.checksum.as_ref()) {
                let occupied: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM _sqlx_migrations WHERE version=22)",
                )
                .fetch_one(&mut *transaction)
                .await?;
                if occupied {
                    return Err(Error::Migration(MigrateError::VersionMismatch(22)));
                }
                // Keep the original checksum, timestamp, description and execution time.
                // No arbitrary mismatch is accepted and no migration SQL is rewritten.
                sqlx::query("UPDATE _sqlx_migrations SET version=22 WHERE version=20 AND success=1 AND checksum=?")
                    .bind(shipped.checksum.as_ref()).execute(&mut *transaction).await?;
            }
        }
    }
    transaction.commit().await?;
    Ok(())
}
