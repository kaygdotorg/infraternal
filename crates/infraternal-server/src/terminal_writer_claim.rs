//! Claims a device's durable input writer for one terminal attachment [#28, D379], #562.
//!
//! Each `Attach` frame a browser sends needs a **writer row**
//! (`terminal_writers`): the per-device, per-stream record that holds the
//! input offset the shim has acknowledged, so a resumed attachment replays
//! from exactly the right byte (#28). Claiming that row is a small write
//! transaction: check the login session is live, enforce the per-socket
//! writer limit, allocate a fresh writer id if the stream has none yet, then
//! read the row back.
//!
//! # Why the D379 writer thread
//!
//! On the sqlx pool this transaction opened with a no-op `UPDATE` whose only
//! job was to take SQLite's write lock before the reads. With a hundred
//! terminals attaching while others type, those `UPDATE`s fought the other
//! sqlx writers for the lock, and the losers slept in SQLite's busy handler
//! (1, 2, 5 … 100 ms steps) instead of waiting in line (#562). On the
//! `infraternal-db` writer thread (D379) the transaction is `BEGIN IMMEDIATE`
//! already, so the lock probe is unnecessary and writes queue in FIFO order
//! without sleeping. The reads, the limit, the id allocation and the
//! read-back keep their SQL text and their order; the authority check still
//! runs before the work and again before the commit.
//!
//! When `Auth` has no pool (in-memory test databases) the caller falls back
//! to the sqlx version, `owned_writer`, which keeps the same rules.

use crate::auth::Auth;
use infraternal_db::rusqlite::{OptionalExtension, Transaction, params};

/// Whether the login session (identified by its token hash) is live and unlocked.
const SQL_AUTHORITY: &str = "SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>unixepoch())";

/// Whether this socket already holds a writer row for the stream.
const SQL_EXISTS: &str =
    "SELECT EXISTS(SELECT 1 FROM terminal_writers WHERE connection_id=? AND client_stream=?)";

/// How many writer rows this socket holds, for the per-socket limit.
const SQL_COUNT: &str = "SELECT count(*) FROM terminal_writers WHERE connection_id=?";

/// Allocate the next writer id and insert the row. Exhaustion of the 31-bit id
/// space inserts nothing, so the read-back below refuses before an id is published.
const SQL_INSERT: &str = "INSERT INTO terminal_writers(writer_id,connection_id,client_stream,session_id) SELECT MAX(COALESCE((SELECT seq FROM sqlite_sequence WHERE name='terminal_writers'),0),w.value)+1,?,?,t.id FROM terminal_sessions t JOIN websocket_connections c ON c.connection_id=? AND c.user_id=t.user_id AND c.active=1 JOIN wire_writer_clock w ON w.singleton=1 WHERE t.id=? AND t.user_id=? AND t.closed_at IS NULL AND MAX(COALESCE((SELECT seq FROM sqlite_sequence WHERE name='terminal_writers'),0),w.value)<2147483647";

/// Read the row back, but only for a live, owned, open session on an active socket.
const SQL_READ_BACK: &str = "SELECT w.writer_id,w.input_acked FROM terminal_writers w JOIN terminal_sessions t ON t.id=w.session_id JOIN websocket_connections c ON c.connection_id=w.connection_id WHERE w.connection_id=? AND w.client_stream=? AND w.session_id=? AND t.user_id=? AND c.user_id=? AND c.active=1 AND t.closed_at IS NULL";

/// Why a claim was refused. Callers treat every case alike (they end the
/// attachment), so the variants only keep the reason readable in a debugger.
#[derive(Debug)]
enum Refused {
    /// The login session ended, or the socket is at its writer limit, or the
    /// session is closed or not this account's, or ids ran out.
    Rule,
    /// SQLite or the pool failed.
    Storage,
}

impl From<infraternal_db::Error> for Refused {
    fn from(_: infraternal_db::Error) -> Self {
        Self::Storage
    }
}

impl From<infraternal_db::rusqlite::Error> for Refused {
    fn from(_: infraternal_db::rusqlite::Error) -> Self {
        Self::Storage
    }
}

/// Everything a claim needs to know, so the closure can own it on the writer thread.
pub(crate) struct Claim<'a> {
    /// The account that owns the socket.
    pub(crate) user: &'a str,
    /// The browser socket's connection id (the writer row's first key).
    pub(crate) connection: &'a [u8; 16],
    /// The browser's stream id of the attachment (the writer row's second key).
    pub(crate) stream: u32,
    /// The terminal session being attached.
    pub(crate) session: &'a [u8; 16],
    /// Token hash of the login session whose liveness gates the claim.
    pub(crate) authority: Option<&'a str>,
    /// The most writer rows one socket may hold (`MAX_ATTACHMENTS`).
    pub(crate) limit: i64,
}

/// Run the claim as one transaction on the D379 writer. Returns the offset the
/// shim has already acknowledged and the wire writer id (twice the row id, so
/// it is even and never zero), exactly as `owned_writer` does on sqlx, or
/// `Err(())` when the claim is refused or storage fails. Returns `None` only
/// when `auth` has no pool, so the caller must use the sqlx path.
pub(crate) async fn claim(auth: &Auth, claim: Claim<'_>) -> Option<Result<(u64, u32), ()>> {
    let db = auth.database()?;
    let user = claim.user.to_owned();
    let connection = *claim.connection;
    let session = *claim.session;
    let authority = claim.authority.map(str::to_owned);
    let (stream, limit) = (claim.stream, claim.limit);
    let result: Result<(u64, u32), Refused> = db
        .write(move |tx| {
            // The checks run twice, as before: once ahead of the work and once
            // just before the commit, so a logout cannot slip in between.
            require_authority(tx, &user, authority.as_deref())?;
            let existing: bool = tx
                .prepare_cached(SQL_EXISTS)?
                .query_row(params![connection.as_slice(), stream], |row| row.get(0))?;
            let count: i64 = tx
                .prepare_cached(SQL_COUNT)?
                .query_row(params![connection.as_slice()], |row| row.get(0))?;
            if !existing && count >= limit {
                return Err(Refused::Rule);
            }
            if !existing {
                tx.prepare_cached(SQL_INSERT)?.execute(params![
                    connection.as_slice(),
                    stream,
                    connection.as_slice(),
                    session.as_slice(),
                    user,
                ])?;
            }
            let row: Option<(i64, Vec<u8>)> = tx
                .prepare_cached(SQL_READ_BACK)?
                .query_row(
                    params![
                        connection.as_slice(),
                        stream,
                        session.as_slice(),
                        user,
                        user
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let (writer, acked) = row.ok_or(Refused::Rule)?;
            let writer = u32::try_from(writer)
                .ok()
                .and_then(|id| id.checked_mul(2))
                .filter(|id| *id != 0)
                .ok_or(Refused::Rule)?;
            let acked = <[u8; 8]>::try_from(acked.as_slice()).map_err(|_| Refused::Rule)?;
            require_authority(tx, &user, authority.as_deref())?;
            Ok((u64::from_be_bytes(acked), writer))
        })
        .await;
    Some(result.map_err(|_| ()))
}

/// Refuse unless the login session behind `authority` is still live. With no
/// hash (storage-only tests) there is nothing to check.
fn require_authority(
    tx: &Transaction<'_>,
    user: &str,
    authority: Option<&str>,
) -> Result<(), Refused> {
    let Some(hash) = authority else {
        return Ok(());
    };
    let live: bool = tx
        .prepare_cached(SQL_AUTHORITY)?
        .query_row(params![hash, user], |row| row.get(0))?;
    if live { Ok(()) } else { Err(Refused::Rule) }
}
