//! Records a terminal input acknowledgement before the browser sees it [#28, D379], #562.
//!
//! Every Input frame a browser sends comes back as an `Ack` once the shim has
//! written it to the PTY. Before the server forwards that `Ack`, it records
//! the acknowledged offset twice: in the device's durable writer row
//! (`terminal_writers.input_acked`, the authority a resumed attachment
//! replays from, #28) and, for diagnostics, in the session row
//! (`terminal_sessions.input_acked_u64` and `last_seen`). Both statements
//! also require that the login session is still live and unlocked.
//!
//! This happens once per keystroke batch, so it is the server's most frequent
//! write while people type, and the socket's output loop waits for it: every
//! terminal on the same browser socket, including the echo of the very key
//! that was acknowledged, is held until the write returns.
//!
//! # Why the D379 writer thread
//!
//! These two statements used to run as two separate autocommit writes on the
//! eight-connection sqlx pool. With several sockets typing at once, those
//! connections fought for SQLite's single write lock, and the losers slept in
//! SQLite's busy handler (1 ms, 2 ms, 5 ms … 100 ms steps) instead of waiting
//! in line. J1034 measured 20 typing sessions at 8 keys/s on compute01 at
//! key-to-echo p99 500 ms, with about 170 busy sleeps per second in the server
//! (#562). On the `infraternal-db` pool (D379) both statements run as **one**
//! `BEGIN IMMEDIATE` transaction on the single writer thread: writes queue in
//! FIFO order without sleeping, one commit replaces two, and the two rows
//! change together or not at all. That last point is new: before, the writer
//! row could commit while the session row failed.
//!
//! The SQL text and its checks are unchanged. When `Auth` has no pool
//! (in-memory test databases), the same statements run on sqlx as before.

use crate::auth::Auth;
use infraternal_db::rusqlite::params;
use sqlx::SqlitePool;

/// Advance the device's durable writer range to `in_seq_acked`, if the login
/// session is live and the row belongs to this connection, stream and session.
const SQL_WRITER_ACK: &str = "UPDATE terminal_writers SET input_acked=? WHERE connection_id=? AND client_stream=? AND session_id=? AND input_acked<=? AND EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>unixepoch())";

/// Raise the session row's diagnostic acknowledged offset and touch `last_seen`.
/// The legacy signed column only moves while the offset still fits in `i64`.
const SQL_SESSION_ACK: &str = "UPDATE terminal_sessions SET input_acked_u64=CASE WHEN input_acked_u64<? THEN ? ELSE input_acked_u64 END, input_acked=CASE WHEN ?>=0 THEN MAX(input_acked,?) ELSE input_acked END, last_seen=? WHERE id=? AND user_id=? AND EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>unixepoch())";

/// One acknowledgement to record: who sent the input, on which attachment,
/// and how far the shim has written it.
pub(crate) struct InputAck<'a> {
    /// The browser socket's connection id (the writer row's first key).
    pub(crate) connection_id: &'a [u8; 16],
    /// The browser's stream id of the attachment (the writer row's second key).
    pub(crate) client_stream: u32,
    /// The terminal session the input went to.
    pub(crate) session_id: [u8; 16],
    /// The acknowledged input offset: every byte before it is in the PTY.
    pub(crate) in_seq_acked: u64,
    /// The account that owns the socket.
    pub(crate) user_id: &'a str,
    /// The socket's login cookie; only its hash reaches SQL.
    pub(crate) session_token: &'a str,
    /// Unix seconds for `last_seen`.
    pub(crate) now: i64,
}

/// Record `ack` in both rows. Returns `true` only when each statement changed
/// exactly one row; any other outcome (no such writer, an offset that moved
/// backwards, a logged-out or locked session, a storage error) is `false`, and
/// the caller ends the attachment exactly as it did before this module.
pub(crate) async fn record(auth: &Auth, pool: &SqlitePool, ack: InputAck<'_>) -> bool {
    let acked = ack.in_seq_acked.to_be_bytes();
    // The legacy column is signed; -1 tells the statement to leave it alone.
    let legacy = i64::try_from(ack.in_seq_acked).unwrap_or(-1);
    let token_hash = crate::auth::hash(ack.session_token);
    if let Some(db) = auth.database() {
        let connection_id = *ack.connection_id;
        let (stream, session, user, now) = (
            ack.client_stream,
            ack.session_id,
            ack.user_id.to_owned(),
            ack.now,
        );
        return db
            .write(move |tx| {
                let writer = tx.prepare_cached(SQL_WRITER_ACK)?.execute(params![
                    acked.as_slice(),
                    connection_id.as_slice(),
                    stream,
                    session.as_slice(),
                    acked.as_slice(),
                    token_hash,
                    user,
                ])?;
                if writer != 1 {
                    // Roll back: nothing of a refused acknowledgement is kept.
                    return Err(infraternal_db::Error::from(
                        infraternal_db::rusqlite::Error::QueryReturnedNoRows,
                    ));
                }
                let session_row = tx.prepare_cached(SQL_SESSION_ACK)?.execute(params![
                    acked.as_slice(),
                    acked.as_slice(),
                    legacy,
                    legacy,
                    now,
                    session.as_slice(),
                    user,
                    token_hash,
                    user,
                ])?;
                if session_row != 1 {
                    return Err(infraternal_db::Error::from(
                        infraternal_db::rusqlite::Error::QueryReturnedNoRows,
                    ));
                }
                Ok::<_, infraternal_db::Error>(())
            })
            .await
            .is_ok();
    }
    let writer = sqlx::query(SQL_WRITER_ACK)
        .bind(acked.as_slice())
        .bind(ack.connection_id.as_slice())
        .bind(ack.client_stream)
        .bind(ack.session_id.as_slice())
        .bind(acked.as_slice())
        .bind(&token_hash)
        .bind(ack.user_id)
        .execute(pool)
        .await;
    if !matches!(writer, Ok(result) if result.rows_affected() == 1) {
        return false;
    }
    let session_row = sqlx::query(SQL_SESSION_ACK)
        .bind(acked.as_slice())
        .bind(acked.as_slice())
        .bind(legacy)
        .bind(legacy)
        .bind(ack.now)
        .bind(ack.session_id.as_slice())
        .bind(ack.user_id)
        .bind(&token_hash)
        .bind(ack.user_id)
        .execute(pool)
        .await;
    matches!(session_row, Ok(result) if result.rows_affected() == 1)
}
