//! Reserves durable, never-reused even writer identities across terminal and plugin lanes [D12,D198,D232].
/// Reserve while holding SQLite's writer transaction, before opening native I/O.
/// Commit before exposing this identity. A rollback may reuse an unpublished
/// reservation; a committed reservation survives dropped streams and restarts.
/// Legacy terminal AUTOINCREMENT remains a lower bound during additive rollout.
/// # Errors
/// Refuses exhaustion and storage failures without wrapping into another writer.
pub(crate) async fn reserve(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<u32, sqlx::Error> {
    let writer: Option<i64> = sqlx::query_scalar(
        "UPDATE wire_writer_clock SET value=MAX(value,COALESCE((SELECT seq FROM sqlite_sequence WHERE name='terminal_writers'),0))+1 WHERE singleton=1 AND MAX(value,COALESCE((SELECT seq FROM sqlite_sequence WHERE name='terminal_writers'),0))<2147483647 RETURNING value",
    )
    .fetch_optional(&mut **tx)
    .await?;
    writer
        .and_then(|id| u32::try_from(id).ok())
        .and_then(|id| id.checked_mul(2))
        .filter(|id| *id != 0)
        .ok_or_else(|| sqlx::Error::Protocol("writer identities exhausted".into()))
}

#[cfg(test)]
#[path = "wire_identity_tests.rs"]
mod tests;
