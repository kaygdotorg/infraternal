//! Database pool benchmark: today's sqlx pool against the D379 pool (`infraternal-db`), #473.
//!
//! An opt-in harness for the locked perf VM, ported from J438's scratch
//! benchmark. Both variants run in this one binary on the same SQLite build,
//! the same seeded database and the server's own hot SQL (see `workload.rs`):
//!
//! - `sqlx`: the pool exactly as `runtime.rs::open_database` builds it (eight
//!   connections, WAL, `synchronous=NORMAL`, no acquire ping), and the layout
//!   write as `canvas_store.rs` does it (app writer mutex, `BEGIN IMMEDIATE`
//!   and `COMMIT` on spawned tasks, one worker round trip per statement).
//! - `pool`: `infraternal_db::Database` with one writer thread and seven
//!   readers. Session slides and layout writes go to the writer as one closure
//!   each; host list and layout resume go to the readers.
//!
//! Usage (every command takes the database path last):
//! - `db_pool_bench prepare <db>`: migrate a new file with today's sqlx path and seed it.
//! - `db_pool_bench bench <sqlx|pool> <workload> <tasks> <db>`: one measured run;
//!   workloads are `session`, `hosts`, `events`, `apply` and `mixed`. Run it on a
//!   fresh copy of the prepared file each time.
//! - `db_pool_bench mem <sqlx|pool> <db>`: resident memory and threads, opened and warm.
//! - `db_pool_bench startup <sqlx|pool> <db>`: open and validate every recorded migration.
//! - `db_pool_bench migrate <sqlx|pool> <db>`: migrate an existing database (a
//!   copy of production's, never the live file) and print the history counts.
//!
//! Each command prints one JSON line.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

/// The shared seed, SQL, operation mix and statistics.
mod workload;

use infraternal_db::{
    Database, Options,
    rusqlite::{OptionalExtension, Transaction, params},
};
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use workload::{
    CHECKPOINT, Draw, NOW, Op, Rng, SESSION, SQL_CLOSED, SQL_EVENTS, SQL_HEAD_INSERT,
    SQL_HEAD_SELECT, SQL_HEAD_UPDATE, SQL_HOSTS, SQL_OP_INSERT, SQL_OPS_DELETE, SQL_OWNED,
    SQL_RECEIPT, SQL_RECEIPT_INSERT, SQL_SESSION, SQL_SNAPSHOT, document_json, draw, event_json,
};

/// The server's generated migration lists: `MIGRATIONS` for sqlx and
/// `RUNNER_MIGRATIONS` for the D379 runner.
mod migrations {
    include!(concat!(env!("OUT_DIR"), "/compact_migrations.rs"));
    include!(concat!(env!("OUT_DIR"), "/runner_migrations.rs"));
}

/// Open the pool exactly as `runtime.rs::open_database` does today.
async fn sqlx_pool(path: &Path, create: bool) -> SqlitePool {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(create)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5));
    SqlitePoolOptions::new()
        .max_connections(8)
        .test_before_acquire(false)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(options)
        .await
        .expect("open sqlx pool")
}

/// One of the two front ends under test.
enum Front {
    /// Today's pool plus the layout store's app-level writer mutex.
    Sqlx {
        pool: SqlitePool,
        writes: tokio::sync::Mutex<()>,
    },
    /// The D379 pool.
    Pool(Database),
}

impl Front {
    /// Open `kind` (`sqlx` or `pool`) on an existing database.
    async fn open(kind: &str, path: &Path) -> Self {
        match kind {
            "sqlx" => Self::Sqlx {
                pool: sqlx_pool(path, false).await,
                writes: tokio::sync::Mutex::new(()),
            },
            "pool" => Self::Pool(
                Database::open(
                    path,
                    Options {
                        create_if_missing: false,
                        ..Options::default()
                    },
                )
                .await
                .unwrap(),
            ),
            other => panic!("unknown variant {other}"),
        }
    }

    /// The label printed in results.
    fn label(&self) -> &'static str {
        match self {
            Self::Sqlx { .. } => "sqlx-pool",
            Self::Pool(_) => "infraternal-db",
        }
    }

    /// Run one operation to completion.
    async fn run(&self, op: Op, draw: Draw) {
        match self {
            Self::Sqlx { pool, writes } => match op {
                Op::Session => sqlx_session(pool, &draw).await,
                Op::Hosts => sqlx_hosts(pool, &draw).await,
                Op::Events => sqlx_events(pool, &draw).await,
                Op::Apply => {
                    let _writer = writes.lock().await;
                    sqlx_apply(pool, &draw).await;
                }
            },
            Self::Pool(db) => match op {
                Op::Session => db.write(move |tx| pool_session(tx, &draw)).await.unwrap(),
                Op::Hosts => db.read(move |tx| pool_hosts(tx, &draw)).await.unwrap(),
                Op::Events => db.read(move |tx| pool_events(tx, &draw)).await.unwrap(),
                Op::Apply => db.write(move |tx| pool_apply(tx, &draw)).await.unwrap(),
            },
        }
    }
}

/// The session slide on sqlx.
async fn sqlx_session(pool: &SqlitePool, draw: &Draw) {
    let row = sqlx::query(SQL_SESSION)
        .bind(NOW + SESSION)
        .bind(&draw.token)
        .bind(NOW)
        .bind(false)
        .fetch_optional(pool)
        .await
        .unwrap()
        .expect("live session");
    std::hint::black_box((
        row.get::<String, _>("user_id"),
        row.get::<String, _>("device"),
        row.get::<i64, _>("fresh"),
        row.get::<String, _>("username"),
        row.get::<String, _>("display_name"),
        row.get::<Option<String>, _>("aaguid"),
        row.get::<Option<i64>, _>("recovery_ready"),
        row.get::<bool, _>("recovery_words_need_replacing"),
        row.get::<i64, _>("owner"),
    ));
}

/// One host-list row: id, address, os, hostname, mode, cleanup state.
type HostRow = (
    Vec<u8>,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
);

/// The host list page on sqlx.
async fn sqlx_hosts(pool: &SqlitePool, draw: &Draw) {
    let rows: Vec<HostRow> = sqlx::query_as(SQL_HOSTS)
        .bind(&draw.owner)
        .bind(None::<Vec<u8>>)
        .bind(None::<Vec<u8>>)
        .fetch_all(pool)
        .await
        .unwrap();
    assert_eq!(rows.len(), 100);
}

/// The layout resume on sqlx.
async fn sqlx_events(pool: &SqlitePool, draw: &Draw) {
    let rows = sqlx::query(SQL_EVENTS)
        .bind(&draw.account)
        .bind(&draw.account)
        .bind(32_i64)
        .fetch_all(pool)
        .await
        .unwrap();
    let bytes: usize = rows
        .iter()
        .map(|row| {
            std::hint::black_box((row.get::<i64, _>(0), row.get::<i64, _>(1)));
            row.get::<Option<String>, _>(2).map_or(0, |text| text.len())
                + row.get::<Option<String>, _>(4).map_or(0, |text| text.len())
        })
        .sum();
    assert!(bytes > 0);
}

/// The layout write on sqlx, shaped like `canvas_store.rs`.
async fn sqlx_apply(pool: &SqlitePool, draw: &Draw) {
    let begin = pool.clone();
    let mut tx = tokio::spawn(async move { begin.begin_with("BEGIN IMMEDIATE").await })
        .await
        .unwrap()
        .unwrap();
    sqlx::query(SQL_HEAD_INSERT)
        .bind(&draw.account)
        .bind("{}")
        .execute(&mut *tx)
        .await
        .unwrap();
    let head = sqlx::query(SQL_HEAD_SELECT)
        .bind(&draw.account)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let (document, revision): (String, i64) = (head.get(0), head.get(1));
    assert_ne!(document, "");
    let receipt = sqlx::query(SQL_RECEIPT)
        .bind(&draw.account)
        .bind(&draw.op_id)
        .bind(&draw.account)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert!(receipt.get::<Option<&str>, _>("request").is_none());
    let closed: Vec<String> = sqlx::query_scalar(SQL_CLOSED)
        .bind(&draw.account)
        .bind("w-3")
        .bind("w-1")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    std::hint::black_box(closed);
    let owned: bool = sqlx::query_scalar(SQL_OWNED)
        .bind(draw.terminal.as_slice())
        .bind(&draw.account)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    std::hint::black_box(owned);
    let next = revision + 1;
    let json = document_json(next);
    sqlx::query(SQL_HEAD_UPDATE)
        .bind(next)
        .bind(&json)
        .bind(&draw.account)
        .execute(&mut *tx)
        .await
        .unwrap();
    if next % CHECKPOINT == 0 {
        sqlx::query(SQL_SNAPSHOT)
            .bind(&draw.account)
            .bind(next)
            .bind(&json)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(SQL_OPS_DELETE)
            .bind(&draw.account)
            .execute(&mut *tx)
            .await
            .unwrap();
    } else {
        sqlx::query(SQL_OP_INSERT)
            .bind(&draw.account)
            .bind(next)
            .bind(event_json(next, &draw.op_id))
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    sqlx::query(SQL_RECEIPT_INSERT)
        .bind(&draw.account)
        .bind(&draw.op_id)
        .bind("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        .bind(next)
        .execute(&mut *tx)
        .await
        .unwrap();
    tokio::spawn(async move { tx.commit().await })
        .await
        .unwrap()
        .unwrap();
}

/// The session slide as one pool closure.
fn pool_session(tx: &Transaction<'_>, draw: &Draw) -> Result<(), infraternal_db::Error> {
    let row = tx
        .prepare_cached(SQL_SESSION)?
        .query_row(params![NOW + SESSION, draw.token, NOW, false], |row| {
            Ok((
                row.get::<_, String>("user_id")?,
                row.get::<_, String>("device")?,
                row.get::<_, i64>("fresh")?,
                row.get::<_, String>("username")?,
                row.get::<_, String>("display_name")?,
                row.get::<_, Option<String>>("aaguid")?,
                row.get::<_, Option<i64>>("recovery_ready")?,
                row.get::<_, bool>("recovery_words_need_replacing")?,
                row.get::<_, i64>("owner")?,
            ))
        })
        .optional()?;
    std::hint::black_box(row.expect("live session"));
    Ok(())
}

/// The host list page as one pool closure.
fn pool_hosts(tx: &Transaction<'_>, draw: &Draw) -> Result<(), infraternal_db::Error> {
    let rows: Vec<HostRow> = tx
        .prepare_cached(SQL_HOSTS)?
        .query_map(
            params![draw.owner, None::<Vec<u8>>, None::<Vec<u8>>],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?
        .collect::<Result<_, _>>()?;
    assert_eq!(rows.len(), 100);
    Ok(())
}

/// The layout resume as one pool closure.
fn pool_events(tx: &Transaction<'_>, draw: &Draw) -> Result<(), infraternal_db::Error> {
    let mut statement = tx.prepare_cached(SQL_EVENTS)?;
    let mut rows = statement.query(params![draw.account, draw.account, 32_i64])?;
    let mut bytes = 0;
    while let Some(row) = rows.next()? {
        std::hint::black_box((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?));
        bytes += row
            .get::<_, Option<String>>(2)?
            .map_or(0, |text| text.len());
        bytes += row
            .get::<_, Option<String>>(4)?
            .map_or(0, |text| text.len());
    }
    assert!(bytes > 0);
    Ok(())
}

/// The layout write as one pool closure (the pool supplies `BEGIN IMMEDIATE`).
fn pool_apply(tx: &Transaction<'_>, draw: &Draw) -> Result<(), infraternal_db::Error> {
    tx.prepare_cached(SQL_HEAD_INSERT)?
        .execute(params![draw.account, "{}"])?;
    let (document, revision): (String, i64) = tx
        .prepare_cached(SQL_HEAD_SELECT)?
        .query_row(params![draw.account], |row| Ok((row.get(0)?, row.get(1)?)))?;
    assert_ne!(document, "");
    let request: Option<String> = tx
        .prepare_cached(SQL_RECEIPT)?
        .query_row(params![draw.account, draw.op_id, draw.account], |row| {
            row.get("request")
        })?;
    assert!(request.is_none());
    let closed: Vec<String> = tx
        .prepare_cached(SQL_CLOSED)?
        .query_map(params![draw.account, "w-3", "w-1"], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    std::hint::black_box(closed);
    let owned: bool = tx
        .prepare_cached(SQL_OWNED)?
        .query_row(params![draw.terminal.as_slice(), draw.account], |row| {
            row.get(0)
        })?;
    std::hint::black_box(owned);
    let next = revision + 1;
    let json = document_json(next);
    tx.prepare_cached(SQL_HEAD_UPDATE)?
        .execute(params![next, json, draw.account])?;
    if next % CHECKPOINT == 0 {
        tx.prepare_cached(SQL_SNAPSHOT)?
            .execute(params![draw.account, next, json])?;
        tx.prepare_cached(SQL_OPS_DELETE)?
            .execute(params![draw.account])?;
    } else {
        tx.prepare_cached(SQL_OP_INSERT)?.execute(params![
            draw.account,
            next,
            event_json(next, &draw.op_id)
        ])?;
    }
    tx.prepare_cached(SQL_RECEIPT_INSERT)?.execute(params![
        draw.account,
        draw.op_id,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        next
    ])?;
    Ok(())
}

/// Warm every connection and statement cache, then measure `workload` with
/// `tasks` concurrent callers and print one JSON line.
async fn bench(kind: &str, workload: &'static str, tasks: usize, path: &Path) {
    let front = Arc::new(Front::open(kind, path).await);
    let mut warm = Vec::new();
    for task in 0..16_u64 {
        let front = front.clone();
        warm.push(tokio::spawn(async move {
            let mut rng = Rng::new(10_000 + task);
            for seq in 0..50 {
                for op in [Op::Session, Op::Hosts, Op::Events, Op::Apply] {
                    front
                        .run(op, draw(&mut rng, 9_000 + task as usize, seq))
                        .await;
                }
            }
        }));
    }
    for handle in warm {
        handle.await.unwrap();
    }
    let per_task = workload::ops_for(workload, tasks);
    workload::io_mark();
    let start = Instant::now();
    let mut running = Vec::new();
    for task in 0..tasks {
        let front = front.clone();
        running.push(tokio::spawn(async move {
            let mut rng = Rng::new(task as u64 + 1);
            let mut samples = Vec::with_capacity(per_task);
            for seq in 0..per_task {
                let op = workload::pick(workload, &mut rng);
                let input = draw(&mut rng, task, seq);
                let started = Instant::now();
                front.run(op, input).await;
                samples.push(started.elapsed().as_nanos() as u64);
            }
            samples
        }));
    }
    let mut samples = Vec::new();
    for handle in running {
        samples.extend(handle.await.unwrap());
    }
    workload::report(front.label(), workload, tasks, samples, start.elapsed());
}

/// Resident memory and thread count: before opening, after opening, and
/// after 16 tasks touched every connection with every statement.
async fn mem(kind: &str, path: &Path) {
    let (before, _) = workload::rss_kib();
    let threads_before = workload::threads();
    let front = Arc::new(Front::open(kind, path).await);
    let (opened, _) = workload::rss_kib();
    let mut tasks = Vec::new();
    for task in 0..16_u64 {
        let front = front.clone();
        tasks.push(tokio::spawn(async move {
            let mut rng = Rng::new(task + 7);
            for seq in 0..200 {
                for op in [Op::Session, Op::Hosts, Op::Events, Op::Apply] {
                    front.run(op, draw(&mut rng, task as usize, seq)).await;
                }
            }
        }));
    }
    for handle in tasks {
        handle.await.unwrap();
    }
    let (warm, peak) = workload::rss_kib();
    println!(
        "{{\"variant\":\"{}\",\"rss_before_kib\":{before},\"rss_opened_kib\":{opened},\"rss_warm_kib\":{warm},\"hwm_kib\":{peak},\"threads_before\":{threads_before},\"threads_after\":{}}}",
        front.label(),
        workload::threads()
    );
}

/// Time to open the pool and validate every recorded migration.
async fn startup(kind: &str, path: &Path) {
    let start = Instant::now();
    let front = Front::open(kind, path).await;
    let opened = workload::us(start);
    match &front {
        Front::Sqlx { pool, .. } => migrations::MIGRATIONS.run(pool).await.unwrap(),
        Front::Pool(db) => {
            let report = db.migrate(migrations::RUNNER_MIGRATIONS).await.unwrap();
            assert_eq!(
                (report.validated, report.applied.len()),
                (migrations::RUNNER_MIGRATIONS.len(), 0)
            );
        }
    }
    println!(
        "{{\"variant\":\"{}\",\"open_us\":{opened:.0},\"open_and_validate_all_us\":{:.0}}}",
        front.label(),
        workload::us(start)
    );
}

/// Bring an existing database (for example a backup-API copy of production's
/// file) up to date with one migration path and print what it did, so the
/// runner and today's sqlx path can be compared on real data (#473). Prints
/// the history rows before and after, the failed rows, and for `pool` the
/// runner's own report.
async fn migrate_existing(kind: &str, path: &Path) {
    let count = |sql: &'static str| {
        let conn = infraternal_db::rusqlite::Connection::open(path).unwrap();
        conn.query_row(sql, [], |row| row.get::<_, i64>(0)).unwrap()
    };
    let rows_before = count("SELECT count(*) FROM _sqlx_migrations");
    let start = Instant::now();
    let front = Front::open(kind, path).await;
    let (validated, applied) = match &front {
        Front::Sqlx { pool, .. } => {
            migrations::MIGRATIONS.run(pool).await.unwrap();
            (None, None)
        }
        Front::Pool(db) => {
            let report = db.migrate(migrations::RUNNER_MIGRATIONS).await.unwrap();
            (Some(report.validated), Some(report.applied))
        }
    };
    let elapsed = workload::us(start);
    drop(front);
    println!(
        "{{\"variant\":\"{}\",\"binary_migrations\":{},\"history_rows_before\":{rows_before},\"history_rows_after\":{},\"failed_rows\":{},\"validated\":{},\"applied\":{},\"us\":{elapsed:.0}}}",
        kind,
        migrations::RUNNER_MIGRATIONS.len(),
        count("SELECT count(*) FROM _sqlx_migrations"),
        count("SELECT count(*) FROM _sqlx_migrations WHERE success=0"),
        validated.map_or("null".to_owned(), |n| n.to_string()),
        applied.map_or("null".to_owned(), |v| format!("{v:?}")),
    );
}

/// Build the template database with today's sqlx path and the seed rows.
async fn prepare(path: &Path) {
    let pool = sqlx_pool(path, true).await;
    migrations::MIGRATIONS.run(&pool).await.unwrap();
    sqlx::raw_sql(workload::SEED).execute(&pool).await.unwrap();
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await
        .unwrap();
    let version: String = sqlx::query_scalar("SELECT sqlite_version()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success=1")
        .fetch_one(&pool)
        .await
        .unwrap();
    println!(
        "{{\"prepared\":\"{}\",\"sqlite\":\"{version}\",\"migrations\":{applied}}}",
        path.display()
    );
    pool.close().await;
}

/// Dispatch one command; see the module docs for usage.
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = Path::new(args.last().expect("database path"));
    match args.get(1).map(String::as_str) {
        Some("prepare") => prepare(path).await,
        Some("bench") => {
            let workload = workload::parse_workload(&args[3]).expect("workload");
            bench(&args[2], workload, args[4].parse().expect("tasks"), path).await;
        }
        Some("mem") => mem(&args[2], path).await,
        Some("startup") => startup(&args[2], path).await,
        Some("migrate") => migrate_existing(&args[2], path).await,
        _ => panic!("usage: db_pool_bench prepare|bench|mem|startup|migrate … <db>"),
    }
}
