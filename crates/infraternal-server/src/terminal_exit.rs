//! Records authenticated terminal exits without treating a transport loss as a shell exit [55][91], #87.
//!
//! An exit notice arrives in the socket's output loop, which waits for the
//! write before it publishes any terminal's output on that socket. Under a
//! mass exit (a host reboot, a `kill` of many shells) those writes would fight
//! every other sqlx writer for SQLite's lock in the busy handler (#562), so
//! [`record_on_writer`] runs the same statement on the D379 writer thread
//! when the server has one, with an sqlx fallback for in-memory databases.
use crate::auth::Auth;
use infraternal_db::rusqlite::params;
use serde::Deserialize;
use sqlx::SqlitePool;

/// Mark the session closed with its exit status, only while the login session is live.
const SQL_EXIT: &str = "UPDATE terminal_sessions SET closed_at=COALESCE(closed_at,unixepoch()),exit_status=? WHERE id=? AND user_id=? AND (exit_status IS NULL OR exit_status=?) AND EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>unixepoch())";

/// The exit notice a host sends. Unknown fields are rejected.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exit {
    /// Notice type, sent as `type`.
    #[serde(rename = "type")]
    kind: String,
    /// Terminal session that exited.
    session_id: uuid::Uuid,
    /// Exit status of the shell.
    status: i32,
    /// Last output position the shell produced.
    final_seq: u64,
    /// True if the session was retired rather than exited. Defaults to false.
    #[serde(default)]
    retired: bool,
}

/// Check an exit notice against the attachment that carried it. `Ok(None)`:
/// the event is not an exit and nothing is recorded. `Ok(Some(status))`: a
/// well-formed exit for this session at this output cursor. `Err`: refuse.
fn validate(session: &[u8; 16], cursor: u64, event: &[u8]) -> Result<Option<i32>, ()> {
    if event.len() > 1024 {
        return Err(());
    }
    let value: serde_json::Value = serde_json::from_slice(event).map_err(|_| ())?;
    if value["type"] != "terminal.exited" {
        return Ok(None);
    }
    let exit: Exit = serde_json::from_value(value).map_err(|_| ())?;
    if exit.kind != "terminal.exited"
        || exit.session_id.as_bytes() != session
        // Saved status is authoritative without asserting delivery of missing bytes.
        || if exit.retired { exit.final_seq < cursor } else { exit.final_seq != cursor }
    {
        return Err(());
    }
    Ok(Some(exit.status))
}

/// The caller binds the notice to its admitted attachment and ordered output cursor.
/// A duplicate retains the first closure timestamp; stale authority cannot publish it.
/// This is the sqlx version, used when the server has no D379 writer.
#[cfg(test)]
pub(crate) async fn record(
    pool: &SqlitePool,
    user: &str,
    token: &str,
    session: &[u8; 16],
    cursor: u64,
    event: &[u8],
) -> Result<bool, ()> {
    let Some(status) = validate(session, cursor, event)? else {
        return Ok(false);
    };
    record_status(pool, user, token, session, status).await?;
    Ok(true)
}

/// Store a verified shell status for this account under its current login authority.
async fn record_status(
    pool: &SqlitePool,
    user: &str,
    token: &str,
    session: &[u8; 16],
    status: i32,
) -> Result<(), ()> {
    // The write and authority predicate serialize logout/ownership changes.
    // Transport Close never enters this path: disconnect is resumable.
    // A census can establish closure before saved status arrives. Fill an unknown
    // status once; conflicting later notices still cannot overwrite it.
    let changed = sqlx::query(SQL_EXIT)
        .bind(status)
        .bind(session.as_slice())
        .bind(user)
        .bind(status)
        .bind(crate::auth::hash(token))
        .bind(user)
        .execute(pool)
        .await
        .map_err(|_| ())?;
    if changed.rows_affected() != 1 {
        return Err(());
    }
    Ok(())
}

/// Validate an attached exit notice and store its status on the D379 writer
/// thread (#562) when available, or through the SQL pool otherwise.
pub(crate) async fn record_on_writer(
    auth: &Auth,
    pool: &SqlitePool,
    user: &str,
    token: &str,
    session: &[u8; 16],
    cursor: u64,
    event: &[u8],
) -> Result<bool, ()> {
    let Some(status) = validate(session, cursor, event)? else {
        return Ok(false);
    };
    record_status_on_writer(auth, pool, user, token, session, status).await?;
    Ok(true)
}

/// Persist an exit verified by the caller, including a detached terminal ended explicitly.
pub(crate) async fn record_status_on_writer(
    auth: &Auth,
    pool: &SqlitePool,
    user: &str,
    token: &str,
    session: &[u8; 16],
    status: i32,
) -> Result<(), ()> {
    let Some(db) = auth.database() else {
        return record_status(pool, user, token, session, status).await;
    };
    let (session, user, hash) = (*session, user.to_owned(), crate::auth::hash(token));
    let changed = db
        .write(move |tx| {
            Ok::<_, infraternal_db::Error>(tx.prepare_cached(SQL_EXIT)?.execute(params![
                status,
                session.as_slice(),
                user,
                status,
                hash,
                user,
            ])?)
        })
        .await
        .map_err(|_| ())?;
    if changed != 1 {
        return Err(());
    }
    Ok(())
}
