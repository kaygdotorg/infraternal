//! Opens SQLite writer transactions that survive caller cancellation, shared by the server and its plugins [28,198], #201.
//!
//! `Pool::begin_with("BEGIN IMMEDIATE")` is not cancellation safe in sqlx 0.8:
//! after the worker acknowledges the `BEGIN`, the custom-statement path awaits
//! the connection handle again before a `Transaction` exists. A caller dropped
//! at that await (a plugin worker aborted by a disable, a timed-out request)
//! returns the pooled connection with an open writer transaction and no owner
//! to roll it back. That connection then refuses every later custom `BEGIN`,
//! and on a file database its RESERVED lock stalls every other writer until
//! the busy timeout: both surface as `Storage` errors.

/// Starts a writer transaction (`BEGIN IMMEDIATE`) on a pooled connection, safe against the
/// caller being cancelled. Use it instead of `begin_with("BEGIN IMMEDIATE")` anywhere the
/// caller can be dropped mid-way.
///
/// The begin runs to completion in its own task. If the caller goes away, the
/// finished `Transaction` is dropped inside that task, which queues sqlx's
/// normal rollback before the connection returns to the pool.
///
/// # Errors
/// Returns the pool or `BEGIN` error, or `PoolClosed` if the runtime stopped
/// the begin task.
pub async fn begin_immediate(
    pool: &sqlx::SqlitePool,
) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>, sqlx::Error> {
    // A spawned task owns the begin future, so dropping this caller only
    // detaches the JoinHandle. The task's unclaimed output is dropped by the
    // runtime, and Transaction::drop queues the rollback. Rejected: pool-level
    // release checks, which cannot reset sqlx's internal transaction depth
    // without closing the connection (that would also destroy in-memory pools).
    let pool = pool.clone();
    tokio::spawn(async move { pool.begin_with("BEGIN IMMEDIATE").await })
        .await
        .map_err(|_| sqlx::Error::PoolClosed)?
}

#[cfg(test)]
mod tests {
    //! Drops the begin future at every await point a real cancellation can hit.
    use super::*;
    use std::{future::Future, pin::Pin, task::Poll};

    async fn poll_once<F: Future + ?Sized>(future: &mut Pin<Box<F>>) -> bool {
        std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_ready())).await
    }

    #[tokio::test]
    async fn cancelled_begin_never_leaves_an_open_writer_transaction() {
        // One connection makes a leaked transaction observable on the next begin.
        for polls in 1..=8 {
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(1)
                .idle_timeout(None)
                .max_lifetime(None)
                .connect("sqlite::memory:")
                .await
                .unwrap();
            let mut begin = Box::pin(begin_immediate(&pool));
            let mut finished = false;
            for _ in 0..polls {
                if poll_once(&mut begin).await {
                    finished = true;
                    break;
                }
                // Let the connection worker execute and acknowledge the BEGIN.
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            drop(begin);
            let next =
                tokio::time::timeout(std::time::Duration::from_secs(5), begin_immediate(&pool))
                    .await
                    .expect("pool connection never returned");
            let transaction = next.unwrap_or_else(|error| {
                panic!("begin after cancellation at poll {polls} (finished={finished}): {error}")
            });
            transaction.commit().await.unwrap();
        }
    }

    /// Real-engine comparison at the 1000-node scale; deliberately excluded
    /// from build-host gates because every performance number belongs on the VM.
    #[tokio::test]
    #[ignore = "Measure only on the perf VM under its benchmark lock, 31 batches of 1000 writes."]
    async fn writer_begin_at_1000_nodes() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let load = std::fs::read_to_string("/proc/loadavg").unwrap();
        let mut samples = Vec::new();
        // One shared server database serialises writer transactions. The
        // smallest transaction exposes helper overhead without query work
        // obscuring it; 1000 begins represent one write for each live node.
        for _ in 0..31 {
            let started = std::time::Instant::now();
            for _ in 0..1000 {
                begin_immediate(&pool)
                    .await
                    .unwrap()
                    .commit()
                    .await
                    .unwrap();
            }
            samples.push(started.elapsed().as_nanos());
        }
        samples.sort_unstable();
        println!(
            "writer_begin nodes=1000 batches=31 engine=sqlite_memory writers=1 batch_p50_ns={} batch_p99_ns={} per_write_p50_ns={} per_write_p99_ns={} machine={} load={}",
            samples[15],
            samples[30],
            samples[15] / 1000,
            samples[30] / 1000,
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap()
                .trim(),
            load.trim(),
        );
    }
}
