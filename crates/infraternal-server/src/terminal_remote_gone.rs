//! Closes a remote host's terminal row once the host reports its shell gone [#588].
//!
//! When a host reboots, its infraternal agent comes back without the terminal
//! shims, and an attach to one of the old sessions is answered with a final
//! `Close { code: 4404 }` (`CLOSE_SESSION_GONE`). Local rows are closed by the
//! census (`terminal_census`, #562); remote rows had no such writer, so a
//! dead remote row stayed `closed_at IS NULL` forever and the retention prune
//! (`terminal_session_prune`) never removed it.
//!
//! [`record_on_writer`] sets `closed_at` on that one row, exactly once, under
//! the same live login-session check the exit notice uses (`terminal_exit`).
//! The browser still gets the same final Close; only the database learns that
//! the session ended, so nothing the browser shows changes.

use crate::auth::Auth;
use infraternal_db::rusqlite::params;
use sqlx::SqlitePool;

/// Sets `closed_at` on one remote row, only while the login session is live.
///
/// The `closed_at IS NULL` guard makes the first report the only write, so a
/// repeat report keeps the first closure time and changes nothing. Local rows
/// (`remote_host_id IS NULL`) are excluded: the census owns them.
const SQL_GONE: &str = "UPDATE terminal_sessions SET closed_at=unixepoch() WHERE id=? AND user_id=? AND remote_host_id IS NOT NULL AND closed_at IS NULL AND EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>unixepoch())";

/// Records that the remote session `session` is gone, on the D379 writer when
/// `auth` has one (#562), otherwise on `pool` (the in-memory test databases).
///
/// Returns `Ok(true)` when this call closed the row, `Ok(false)` when there was
/// nothing to close (a repeat, a local row, or no live login session), and
/// `Err(())` only when the database fails. The caller ignores the error: the
/// browser's Close is sent either way, and a row left open here is only a
/// missed prune, not a wrong view.
pub(crate) async fn record_on_writer(
    auth: &Auth,
    pool: &SqlitePool,
    user: &str,
    token: &str,
    session: &[u8; 16],
) -> Result<bool, ()> {
    let (session, user, hash) = (*session, user.to_owned(), crate::auth::hash(token));
    let closed = match auth.database() {
        Some(db) => {
            db.write(move |tx| {
                Ok::<_, infraternal_db::Error>(tx.prepare_cached(SQL_GONE)?.execute(params![
                    session.as_slice(),
                    user,
                    hash,
                    user,
                ])?)
            })
            .await
            .map_err(|_| ())?
                == 1
        }
        None => {
            sqlx::query(SQL_GONE)
                .bind(session.as_slice())
                .bind(&user)
                .bind(&hash)
                .bind(&user)
                .execute(pool)
                .await
                .map_err(|_| ())?
                .rows_affected()
                == 1
        }
    };
    Ok(closed)
}
