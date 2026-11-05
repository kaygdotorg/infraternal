//! Checks release-writer admission against the shared SQLite authority pool [5,198; #157].
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_api::{Operation, SocketHost};
use infraternal_plugin_release::service::{ReleaseLookup, ReleaseService};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

struct Lookup;
impl ReleaseLookup for Lookup {
    fn latest<'a>(
        &'a self,
        _channel: &'a str,
    ) -> Operation<'a, Result<serde_json::Value, &'static str>> {
        Box::pin(async { unreachable!("channel writes do not perform a lookup") })
    }
}
struct Host;
impl SocketHost for Host {
    fn user_id(&self) -> &'static str {
        "owner"
    }
    fn token_hash(&self) -> &'static str {
        "fixture-session-hash"
    }
    fn authorized<'a>(
        &'a self,
        op: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        op
    }
    fn fresh(&self, _now: i64) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn live(&self) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn may_configure(&self) -> Operation<'_, bool> {
        Box::pin(async { true })
    }
}
/// Eight blocked release writes must still leave the eight-connection authority
/// pool able to serve an authority read while an outside writer holds the lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_channel_writers_preserve_authority_read_capacity() {
    let root = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join(format!("review-pool-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(root.join("state.sqlite"))
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        // Same durability as the server's database (runtime.rs). sqlx's
        // default FULL fsyncs every commit, and on a contended gate disk that
        // alone took 40-47 s of setup (#355).
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(15));
    // Setup is not under test, so its one-time writes stay out of the pool's
    // acquire deadline. `connect_with` plus `min_connections(8)` used to make
    // the file, switch it to WAL and open eight connections inside one 30 s
    // acquire timeout, and on an I/O-starved gate host that ran out
    // (PoolTimedOut at this point, #355). Now one plain connection makes the
    // file, the WAL switch and the schema. Then all eight pool connections
    // open at the same time and are released to the idle queue.
    let setup = Instant::now();
    {
        use sqlx::Connection;
        let mut schema = sqlx::sqlite::SqliteConnection::connect_with(&options)
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TABLE plugin_settings(role TEXT,plugin TEXT,enabled INTEGER,settings TEXT NOT NULL DEFAULT '{}',PRIMARY KEY(role,plugin)); CREATE TABLE users(id TEXT,owner INTEGER); CREATE TABLE sessions(token_hash TEXT,user_id TEXT,unlocked INTEGER,expires INTEGER,fresh INTEGER); INSERT INTO users VALUES('owner',1); INSERT INTO sessions VALUES('fixture-session-hash','owner',1,unixepoch()+600,unixepoch());")
            .execute(&mut schema).await.unwrap();
        schema.close().await.unwrap();
    }
    let schema_ms = setup.elapsed().as_millis();
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(8)
        .connect_lazy_with(options.clone());
    let mut opening = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let pool = pool.clone();
        opening.spawn(async move { pool.acquire().await.unwrap() });
    }
    // Hold every connection until all eight exist, so none is reused twice.
    let warm = opening.join_all().await;
    drop(warm);
    println!(
        "RELEASE_POOL_SETUP schema_ms={schema_ms} pool_ms={} connections={}",
        setup.elapsed().as_millis(),
        pool.size()
    );
    // The independent writer holds no connection from the eight-slot authority pool.
    let external = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let writer = external.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let control = tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query_scalar::<_, i64>("SELECT owner FROM users WHERE id='owner'").fetch_one(&pool),
    )
    .await;
    assert_eq!(
        control.unwrap().unwrap(),
        1,
        "WAL readers must work while a writer is held"
    );
    let service = ReleaseService::new(pool.clone(), Arc::new(Lookup));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let service = service.clone();
        tasks.spawn(async move {
            service
                .call(
                    "release.channel.set",
                    br#"{"channel":"stable"}"#,
                    Some(&Host),
                )
                .await
        });
    }
    // Wait for admission to settle without making exhaustion a requirement of a fixed implementation.
    let deadline = Instant::now() + Duration::from_secs(2);
    while pool.num_idle() != 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let idle = pool.num_idle();
    let started = Instant::now();
    let authority = tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::query_scalar::<_, i64>("SELECT owner FROM users WHERE id='owner'").fetch_one(&pool),
    )
    .await;
    println!(
        "RELEASE_POOL writers=8 slots={} idle={idle} external_writer_held=true control_read=true authority_read_completed={} elapsed_ms={}",
        pool.size(),
        authority.is_ok(),
        started.elapsed().as_millis()
    );
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    writer.rollback().await.unwrap();
    pool.close().await;
    external.close().await;
    std::fs::remove_dir_all(&root).unwrap();
    assert!(
        authority.is_ok(),
        "pending release writes must leave capacity for authority reads"
    );
}
