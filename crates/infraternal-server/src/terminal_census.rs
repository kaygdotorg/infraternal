//! Closes local terminal rows whose shim is gone from the latest census [D379], #562.
//!
//! The embedded infraternal agent publishes a full census of its live shims on
//! a watch channel whenever the set changes: a terminal opens, a shell exits,
//! the agent restarts. Each change runs [`close_ended`], which marks every
//! open local `terminal_sessions` row that the census no longer lists as
//! closed. Remote hosts keep their own census and are not touched here.
//!
//! # Ordering invariant
//!
//! On the ordered leg-B lane the census that lists a new shim arrives before
//! that shim's open Result, and the server inserts the row only after the
//! Result. So a row that is committed when the census is read is either in
//! that census or really gone. Every pass therefore reads the watch *after*
//! its database snapshot is fixed, never before: an older copy of the census
//! must never meet a row inserted later, or a brand-new terminal would be
//! closed (`census_waiting_for_database_does_not_close_a_newly_created_live_session`).
//!
//! # Why the writer
//!
//! The pass used to be an sqlx `BEGIN IMMEDIATE` plus a scan of every local
//! row, once per census change, which is about once per terminal open. During
//! an open storm it fought the D379 writer's inserts for SQLite's write lock
//! and both sides slept in the busy handler (J1056 counted 150-163 sleeps in
//! the open phase, #562). Now the scan and the closes run as one transaction
//! on the D379 writer, queued FIFO with the other terminal writes, with the
//! same SQL.
//!
//! Without a D379 pool (in-memory test databases) [`close_ended_on_sqlx`]
//! runs the original sqlx transaction.

use crate::auth::Auth;
use crate::embedded::SessionInventoryState;
use std::collections::HashSet;
use tokio::sync::watch;

/// The open local rows: the census owns exactly these.
const SQL_OPEN_LOCAL: &str =
    "SELECT id FROM terminal_sessions WHERE remote_host_id IS NULL AND closed_at IS NULL";

/// Close one local row, keeping a closure time set by an earlier exit notice.
const SQL_CLOSE: &str = "UPDATE terminal_sessions SET closed_at=COALESCE(closed_at,unixepoch()) WHERE id=? AND remote_host_id IS NULL AND closed_at IS NULL";

/// The ids in `rows` that the current census does not list, or `None` when
/// the census is not available (then nothing may be closed).
///
/// Reads the watch at call time, so call it only after the database snapshot
/// that produced `rows` is fixed (see the module's ordering invariant).
fn missing_from_census(
    inventory: &watch::Receiver<SessionInventoryState>,
    rows: Vec<Vec<u8>>,
) -> Option<Vec<Vec<u8>>> {
    let SessionInventoryState::Available(session_ids) = inventory.borrow().clone() else {
        return None;
    };
    let live: HashSet<[u8; 16]> = session_ids.iter().copied().collect();
    Some(
        rows.into_iter()
            .filter(|id| <[u8; 16]>::try_from(id.as_slice()).is_ok_and(|id| !live.contains(&id)))
            .collect(),
    )
}

/// The open local rows' ids, read inside `tx` with a cached statement.
fn open_local_rows(
    tx: &infraternal_db::rusqlite::Transaction<'_>,
) -> infraternal_db::rusqlite::Result<Vec<Vec<u8>>> {
    tx.prepare_cached(SQL_OPEN_LOCAL)?
        .query_map([], |row| row.get(0))?
        .collect()
}

/// Close every open local row the latest census no longer lists.
///
/// Call it after each census change. Returns how many rows it closed. A
/// storage error is `Err(())`; the caller logs it and the next census change
/// tries again.
pub(crate) async fn close_ended(
    auth: &Auth,
    pool: &sqlx::SqlitePool,
    inventory: &watch::Receiver<SessionInventoryState>,
) -> Result<usize, ()> {
    let Some(db) = auth.database() else {
        return close_ended_on_sqlx(pool, inventory).await.map_err(|_| ());
    };
    close_ended_on_writer(db, inventory).await
}

/// The write step of [`close_ended`]: one D379 writer transaction that scans
/// the open local rows, then reads the census, then closes what is missing.
///
/// The census is read inside the closure, after `BEGIN IMMEDIATE` holds the
/// write lock, never when the write is queued: a row that commits while this
/// write waits in the queue is always judged against a census at least as new
/// as the one that listed it.
pub(crate) async fn close_ended_on_writer(
    db: &infraternal_db::Database,
    inventory: &watch::Receiver<SessionInventoryState>,
) -> Result<usize, ()> {
    let census = inventory.clone();
    db.write(move |tx| {
        let rows = open_local_rows(tx)?;
        let Some(missing) = missing_from_census(&census, rows) else {
            return Ok(0);
        };
        let mut close = tx.prepare_cached(SQL_CLOSE)?;
        for id in &missing {
            close.execute([id.as_slice()])?;
        }
        Ok::<_, infraternal_db::Error>(missing.len())
    })
    .await
    .map_err(|_| ())
}

/// The sqlx form of [`close_ended`], for databases without a D379 pool.
///
/// One `BEGIN IMMEDIATE` transaction: the census is read only after it holds
/// the write lock, for the module's ordering invariant.
pub(crate) async fn close_ended_on_sqlx(
    pool: &sqlx::SqlitePool,
    inventory: &watch::Receiver<SessionInventoryState>,
) -> Result<usize, sqlx::Error> {
    let mut transaction = infraternal_plugin_api::storage::begin_immediate(pool).await?;
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(SQL_OPEN_LOCAL)
        .fetch_all(&mut *transaction)
        .await?;
    let Some(missing) = missing_from_census(inventory, rows) else {
        return Ok(0);
    };
    for id in &missing {
        sqlx::query(SQL_CLOSE)
            .bind(id.as_slice())
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(missing.len())
}
