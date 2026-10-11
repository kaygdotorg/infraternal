//! Records authenticated terminal exits without treating a transport loss as a shell exit [55][91], #87.
use serde::Deserialize;
use sqlx::SqlitePool;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exit {
    #[serde(rename = "type")]
    kind: String,
    session_id: uuid::Uuid,
    status: i32,
    final_seq: u64,
    #[serde(default)]
    retired: bool,
}

/// The caller binds the notice to its admitted attachment and ordered output cursor.
/// A duplicate retains the first closure timestamp; stale authority cannot publish it.
pub(crate) async fn record(
    pool: &SqlitePool,
    user: &str,
    token: &str,
    session: &[u8; 16],
    cursor: u64,
    event: &[u8],
) -> Result<bool, ()> {
    if event.len() > 1024 {
        return Err(());
    }
    let value: serde_json::Value = serde_json::from_slice(event).map_err(|_| ())?;
    if value["type"] != "terminal.exited" {
        return Ok(false);
    }
    let exit: Exit = serde_json::from_value(value).map_err(|_| ())?;
    if exit.kind != "terminal.exited"
        || exit.session_id.as_bytes() != session
        // Saved status is authoritative without asserting delivery of missing bytes.
        || if exit.retired { exit.final_seq < cursor } else { exit.final_seq != cursor }
    {
        return Err(());
    }
    // The write and authority predicate serialize logout/ownership changes.
    // Transport Close never enters this path: disconnect is resumable.
    let changed = sqlx::query("UPDATE terminal_sessions SET closed_at=COALESCE(closed_at,unixepoch()),exit_status=? WHERE id=? AND user_id=? AND (closed_at IS NULL OR exit_status=?) AND EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>unixepoch())")
        .bind(exit.status).bind(session.as_slice()).bind(user).bind(exit.status)
        .bind(crate::auth::hash(token)).bind(user).execute(pool).await.map_err(|_| ())?;
    if changed.rows_affected() != 1 {
        return Err(());
    }
    Ok(true)
}
