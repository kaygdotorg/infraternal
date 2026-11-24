//! Periodically prunes closed `terminal_sessions` rows older than 30 days (#571, #579).
//!
//! Without pruning, every closed terminal session stays in SQLite forever (#571 finding 1).
//! This module removes only rows whose `closed_at` timestamp is strictly older than the
//! 30-day retention window, in bounded batches so each SQLite write transaction stays
//! short and never starves interactive terminal or auth writes.
//!
//! Open sessions (`closed_at IS NULL`), sessions still referenced by a `terminal_writers`
//! row, and sessions still referenced inside their owner's `canvas_heads` layout document
//! are never deleted. When `auth` carries a D379 `infraternal-db` writer, each batch runs
//! on that writer thread; in-memory test databases fall back to `sqlx::SqlitePool`.

use crate::auth::Auth;
use infraternal_db::rusqlite::params;
use sqlx::SqlitePool;
use std::time::Duration;
use tokio::time::{Instant, MissedTickBehavior};

/// Retention window for closed `terminal_sessions` rows: 30 days in whole seconds.
pub(crate) const RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Maximum rows deleted in a single SQLite write transaction.
pub(crate) const DEFAULT_BATCH_SIZE: i64 = 500;

/// Maximum batches executed in a single periodic pass so a large backlog still yields
/// between passes rather than monopolizing the writer.
const MAX_BATCHES_PER_PASS: usize = 200;

/// Delay after server startup before the first prune pass so startup and `server restart`
/// latency budgets are unaffected.
const STARTUP_DELAY: Duration = Duration::from_secs(60);

/// Interval between periodic prune passes (6 hours: 4 wakeups per day).
const PRUNE_INTERVAL: Duration = Duration::from_hours(6);

/// Deletes one bounded batch of closed `terminal_sessions` rows older than `cutoff` that
/// are not referenced by `terminal_writers` or by their owner's `canvas_heads` layout.
///
/// The `WHERE closed_at IS NOT NULL AND closed_at < ?` predicate uses the partial index
/// `terminal_sessions_closed_at` so open sessions are never scanned.
const SQL_PRUNE_BATCH: &str = "DELETE FROM terminal_sessions \
WHERE id IN ( \
    SELECT id \
    FROM terminal_sessions \
    WHERE closed_at IS NOT NULL \
      AND closed_at < ? \
      AND NOT EXISTS ( \
          SELECT 1 \
          FROM terminal_writers w \
          WHERE w.session_id = terminal_sessions.id \
      ) \
      AND NOT EXISTS ( \
          SELECT 1 \
          FROM canvas_heads c \
          WHERE c.account = terminal_sessions.user_id \
            AND instr( \
                lower(c.document), \
                lower( \
                    substr(hex(terminal_sessions.id), 1, 8) || '-' || \
                    substr(hex(terminal_sessions.id), 9, 4) || '-' || \
                    substr(hex(terminal_sessions.id), 13, 4) || '-' || \
                    substr(hex(terminal_sessions.id), 17, 4) || '-' || \
                    substr(hex(terminal_sessions.id), 21, 12) \
                ) \
            ) > 0 \
      ) \
    LIMIT ? \
)";

/// Deletes up to `batch_size` eligible closed `terminal_sessions` rows older than `cutoff`.
///
/// Runs on the D379 writer thread when `auth` provides one; otherwise executes the same
/// statement against `pool`. Returns the number of rows deleted in this batch.
async fn prune_batch(
    auth: Option<&Auth>,
    pool: &SqlitePool,
    cutoff: i64,
    batch_size: i64,
) -> Result<u64, ()> {
    if batch_size <= 0 {
        return Ok(0);
    }
    if let Some(db) = auth.and_then(Auth::database) {
        let deleted = db
            .write(move |tx| {
                let changed = tx
                    .prepare_cached(SQL_PRUNE_BATCH)?
                    .execute(params![cutoff, batch_size])?;
                Ok::<_, infraternal_db::Error>(changed)
            })
            .await
            .map_err(|_| ())?;
        return u64::try_from(deleted).map_err(|_| ());
    }
    let done = sqlx::query(SQL_PRUNE_BATCH)
        .bind(cutoff)
        .bind(batch_size)
        .execute(pool)
        .await
        .map_err(|_| ())?;
    Ok(done.rows_affected())
}

/// Runs one bounded prune pass for closed `terminal_sessions` rows strictly older than
/// `now - RETENTION_SECONDS`, deleting at most `batch_size` rows per transaction and
/// yielding between batches.
///
/// Returns the total number of rows removed across all batches in this pass.
pub(crate) async fn prune_closed_sessions(
    auth: Option<&Auth>,
    pool: &SqlitePool,
    now: i64,
    batch_size: i64,
) -> Result<u64, ()> {
    if batch_size <= 0 {
        return Ok(0);
    }
    let cutoff = now.saturating_sub(RETENTION_SECONDS);
    let batch_limit = u64::try_from(batch_size).map_err(|_| ())?;
    let mut total = 0_u64;
    for _ in 0..MAX_BATCHES_PER_PASS {
        let deleted = prune_batch(auth, pool, cutoff, batch_size).await?;
        total = total.saturating_add(deleted);
        if deleted < batch_limit {
            break;
        }
        tokio::task::yield_now().await;
    }
    Ok(total)
}

/// Starts the background task that periodically prunes closed `terminal_sessions` rows
/// older than 30 days.
///
/// The first pass waits [`STARTUP_DELAY`] so startup and restart paths stay quiet, then
/// repeats every [`PRUNE_INTERVAL`]. Logs only when rows are removed or a pass fails.
pub(crate) fn start(auth: Auth, pool: SqlitePool) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval_at(Instant::now() + STARTUP_DELAY, PRUNE_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let Ok(now) = crate::websocket::now_seconds() else {
                continue;
            };
            match prune_closed_sessions(Some(&auth), &pool, now, DEFAULT_BATCH_SIZE).await {
                Ok(0) => {}
                Ok(deleted) => {
                    tracing::info!(
                        deleted,
                        retention_days = RETENTION_SECONDS / 86_400,
                        "pruned expired closed terminal_sessions rows"
                    );
                }
                Err(()) => {
                    tracing::warn!("periodic terminal_sessions prune pass failed");
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    //! Verifies retention boundaries, reference guards, batching and index usage for
    //! `terminal_sessions` pruning (#579).

    use super::*;
    use sqlx::{Row, sqlite::SqlitePoolOptions};

    /// Creates a migrated in-memory SQLite pool with one owner user and foreign keys on.
    async fn migrated_pool() -> (SqlitePool, String) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();
        Auth::new(
            pool.clone(),
            "auth.example.test",
            "https://auth.example.test",
        )
        .await
        .unwrap();
        let user = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO users(id,name,username,display_name,owner,recovery_hash) \
             VALUES(?,'owner','owner','Owner',1,'test')",
        )
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
        (pool, user)
    }

    /// Inserts a `terminal_sessions` row with explicit timestamps, status and optional remote host.
    async fn insert_session(
        pool: &SqlitePool,
        id: [u8; 16],
        user: &str,
        created_at: i64,
        closed_at: Option<i64>,
        exit_status: Option<i32>,
        remote_host_id: Option<&[u8]>,
    ) {
        sqlx::query(
            "INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,closed_at,exit_status,remote_host_id) \
             VALUES(?,?,?,?,?,?,?)",
        )
        .bind(id.as_slice())
        .bind(user)
        .bind(created_at)
        .bind(created_at)
        .bind(closed_at)
        .bind(exit_status)
        .bind(remote_host_id)
        .execute(pool)
        .await
        .unwrap();
    }

    /// Checks whether a session row still exists in `terminal_sessions`.
    async fn exists(pool: &SqlitePool, id: [u8; 16]) -> bool {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM terminal_sessions WHERE id=?)")
            .bind(id.as_slice())
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// Ensures only closed rows strictly older than 30 days are pruned while open rows,
    /// boundary rows, writer-referenced rows and canvas-referenced rows are preserved.
    #[tokio::test]
    async fn prunes_only_unreferenced_closed_sessions_older_than_thirty_days() {
        let (pool, user) = migrated_pool().await;
        let now = 1_800_000_000_i64;
        let cutoff = now - RETENTION_SECONDS;

        // Remote host for verifying remote closed sessions are also pruned cleanly.
        let remote_host = [0xAA; 16];
        sqlx::query(
            "INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootless',1000,?)",
        )
        .bind(remote_host.as_slice())
        .bind(&user)
        .bind(cutoff - 1_000)
        .execute(&pool)
        .await
        .unwrap();

        let old_local_exited = [1_u8; 16];
        let old_local_census = [2_u8; 16];
        let old_remote_exited = [3_u8; 16];
        let open_old = [4_u8; 16];
        let boundary_exact = [5_u8; 16];
        let recent_closed = [6_u8; 16];
        let old_with_writer = [7_u8; 16];
        let old_in_canvas = [8_u8; 16];

        insert_session(
            &pool,
            old_local_exited,
            &user,
            cutoff - 500,
            Some(cutoff - 1),
            Some(0),
            None,
        )
        .await;
        insert_session(
            &pool,
            old_local_census,
            &user,
            cutoff - 500,
            Some(cutoff - 10),
            None,
            None,
        )
        .await;
        insert_session(
            &pool,
            old_remote_exited,
            &user,
            cutoff - 500,
            Some(cutoff - 100),
            Some(1),
            Some(remote_host.as_slice()),
        )
        .await;
        insert_session(&pool, open_old, &user, cutoff - 5_000, None, None, None).await;
        insert_session(
            &pool,
            boundary_exact,
            &user,
            cutoff - 500,
            Some(cutoff),
            Some(0),
            None,
        )
        .await;
        insert_session(
            &pool,
            recent_closed,
            &user,
            now - 100,
            Some(now - 50),
            Some(0),
            None,
        )
        .await;
        insert_session(
            &pool,
            old_with_writer,
            &user,
            cutoff - 500,
            Some(cutoff - 200),
            Some(0),
            None,
        )
        .await;
        insert_session(
            &pool,
            old_in_canvas,
            &user,
            cutoff - 500,
            Some(cutoff - 300),
            Some(0),
            None,
        )
        .await;

        // Attach a live terminal_writers reference to `old_with_writer`.
        let conn_id = [0xCC; 16];
        let token_hash = [0xDD; 32];
        sqlx::query(
            "INSERT INTO websocket_connections(connection_id,token_hash,user_id,created_at,expires_at,active) \
             VALUES(?,?,?,?,NULL,1)",
        )
        .bind(conn_id.as_slice())
        .bind(token_hash.as_slice())
        .bind(&user)
        .bind(now - 10)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO terminal_writers(connection_id,client_stream,session_id) VALUES(?,1,?)",
        )
        .bind(conn_id.as_slice())
        .bind(old_with_writer.as_slice())
        .execute(&pool)
        .await
        .unwrap();

        // Reference `old_in_canvas` inside the owner's `canvas_heads` document (uppercase to test case insensitivity).
        let canvas_uuid = uuid::Uuid::from_bytes(old_in_canvas)
            .to_string()
            .to_uppercase();
        let canvas_doc = serde_json::json!({
            "format": "infraternal.canvas",
            "version": 1,
            "revision": 1,
            "views": [{
                "id": "console",
                "layout": {
                    "columns": [{
                        "windows": [{
                            "id": "w1",
                            "target": { "type": "session", "id": canvas_uuid }
                        }]
                    }]
                }
            }]
        })
        .to_string();
        sqlx::query(
            "INSERT INTO canvas_heads(account,revision,document,initialized) VALUES(?,1,?,1)",
        )
        .bind(&user)
        .bind(&canvas_doc)
        .execute(&pool)
        .await
        .unwrap();

        let deleted = prune_closed_sessions(None, &pool, now, DEFAULT_BATCH_SIZE)
            .await
            .unwrap();
        assert_eq!(deleted, 3);

        assert!(!exists(&pool, old_local_exited).await);
        assert!(!exists(&pool, old_local_census).await);
        assert!(!exists(&pool, old_remote_exited).await);

        assert!(exists(&pool, open_old).await);
        assert!(exists(&pool, boundary_exact).await);
        assert!(exists(&pool, recent_closed).await);
        assert!(exists(&pool, old_with_writer).await);
        assert!(exists(&pool, old_in_canvas).await);

        // Once the canvas reference is removed, the next pass prunes that session too.
        sqlx::query("UPDATE canvas_heads SET document='{}' WHERE account=?")
            .bind(&user)
            .execute(&pool)
            .await
            .unwrap();
        let deleted_after = prune_closed_sessions(None, &pool, now, DEFAULT_BATCH_SIZE)
            .await
            .unwrap();
        assert_eq!(deleted_after, 1);
        assert!(!exists(&pool, old_in_canvas).await);
    }

    /// Ensures batched pruning deletes across multiple small batches until all eligible rows are gone.
    #[tokio::test]
    async fn batched_prune_deletes_all_eligible_rows_across_multiple_batches() {
        let (pool, user) = migrated_pool().await;
        let now = 1_800_000_000_i64;
        let cutoff = now - RETENTION_SECONDS;

        for i in 0_u8..8 {
            let mut id = [0_u8; 16];
            id[0] = i + 1;
            insert_session(
                &pool,
                id,
                &user,
                cutoff - 1_000,
                Some(cutoff - 10 - i64::from(i)),
                Some(0),
                None,
            )
            .await;
        }
        let open_id = [99_u8; 16];
        insert_session(&pool, open_id, &user, cutoff - 1_000, None, None, None).await;

        let deleted = prune_closed_sessions(None, &pool, now, 3).await.unwrap();
        assert_eq!(deleted, 8);

        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM terminal_sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, 1);
        assert!(exists(&pool, open_id).await);
    }

    /// Confirms the SQLite query planner uses the `terminal_sessions_closed_at` partial index.
    #[tokio::test]
    async fn prune_query_uses_closed_at_partial_index() {
        let (pool, _user) = migrated_pool().await;
        let plan_sql = format!("EXPLAIN QUERY PLAN {SQL_PRUNE_BATCH}");
        let rows = sqlx::query(sqlx::AssertSqlSafe(plan_sql))
            .bind(1_700_000_000_i64)
            .bind(DEFAULT_BATCH_SIZE)
            .fetch_all(&pool)
            .await
            .unwrap();
        let details: Vec<String> = rows
            .into_iter()
            .map(|row| row.get::<String, _>("detail"))
            .collect();
        assert!(
            details
                .iter()
                .any(|line| line.contains("terminal_sessions_closed_at")),
            "expected partial index terminal_sessions_closed_at in query plan, got: {details:?}"
        );
    }
}
