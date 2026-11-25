//! Records a newly opened terminal session in the server's database [D379], #562.
//!
//! After the host's infraternal agent opens a PTY, the server persists a
//! `terminal_sessions` row for it so the session can be listed, attached to,
//! and acknowledged against (#28). The insert is conditional: it only happens
//! while the login session that asked is still live and unlocked, and, for a
//! remote host, while that host still belongs to the account and is not
//! revoked. The open path waits for the insert before it answers the browser.
//!
//! The statement runs on the `infraternal-db` writer thread (D379) so it
//! queues in FIFO order with the other terminal writes (input Acks, writer
//! claims) instead of fighting them for SQLite's write lock in the busy
//! handler (#562). The SQL text and its checks are unchanged. Without a pool
//! (in-memory test databases) the same statement runs on sqlx.

use crate::auth::Auth;
use infraternal_db::rusqlite::params;
use sqlx::SqlitePool;

/// Insert the session row only if the login session is live and, for a remote
/// host, the host is the account's and not revoked.
const SQL_INSERT: &str = "INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,remote_host_id) SELECT ?,?,?,?,? FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>unixepoch() AND (? IS NULL OR EXISTS (SELECT 1 FROM remote_hosts WHERE id=? AND owner_id=? AND revoked_at IS NULL AND mode IN ('rootless','rootful')))";

/// What to record: the new session, who opened it, where, and when.
pub(crate) struct NewSession<'a> {
    /// The session id the host's agent assigned.
    pub(crate) session_id: [u8; 16],
    /// The account that opened it.
    pub(crate) user_id: &'a str,
    /// The remote host's id bytes, or `None` for the local host.
    pub(crate) host: Option<Vec<u8>>,
    /// The opening login session's cookie; only its hash reaches SQL.
    pub(crate) session_token: &'a str,
    /// Unix seconds for `created_at` and `last_seen`.
    pub(crate) now: i64,
}

/// Persist the row. Returns `true` only when exactly one row was inserted; a
/// logged-out session, a revoked or foreign host, a duplicate id, or a storage
/// error all return `false` and the caller refuses the open.
pub(crate) async fn record(auth: &Auth, pool: &SqlitePool, new: NewSession<'_>) -> bool {
    let token_hash = crate::auth::hash(new.session_token);
    if let Some(db) = auth.database() {
        let (session_id, user, host, now) =
            (new.session_id, new.user_id.to_owned(), new.host, new.now);
        return db
            .write(move |tx| {
                let changed = tx.prepare_cached(SQL_INSERT)?.execute(params![
                    session_id.as_slice(),
                    user,
                    now,
                    now,
                    host,
                    token_hash,
                    user,
                    host,
                    host,
                    user,
                ])?;
                Ok::<_, infraternal_db::Error>(changed == 1)
            })
            .await
            .unwrap_or(false);
    }
    let result = sqlx::query(SQL_INSERT)
        .bind(new.session_id.as_slice())
        .bind(new.user_id)
        .bind(new.now)
        .bind(new.now)
        .bind(new.host.clone())
        .bind(&token_hash)
        .bind(new.user_id)
        .bind(new.host.clone())
        .bind(new.host)
        .bind(new.user_id)
        .execute(pool)
        .await;
    matches!(result, Ok(done) if done.rows_affected() == 1)
}
