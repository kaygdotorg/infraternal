//! Migration-history compatibility between today's sqlx startup path and the
//! D379 rusqlite runner (`infraternal_db::migrate`), on real server databases.
//!
//! "Today's sqlx path" means exactly what the server runs at startup:
//! `open_database` (the production pool and pragmas), then `Auth::new`, which
//! runs the version-20 retag and `MIGRATIONS.run`. The runner side is
//! `infraternal_db::Database::open` plus `Database::migrate` with the list the
//! build script generates from the same migration files.
//!
//! What must hold (#473, slice 1):
//! - a copy-shaped database built by the sqlx path is accepted by the runner
//!   unchanged: every history row validated, nothing applied, and the history,
//!   schema and data byte-identical afterwards;
//! - a fresh database built by the runner is schema-identical to a fresh one
//!   built by sqlx (`sqlite_schema` diffed row by row), with the same history
//!   rows and the same migration-inserted data; and the sqlx path accepts it;
//! - both runners refuse the same tampered histories with the same error:
//!   changed checksum, unknown future version, dirty row.
use super::open_database;
use infraternal_db::{
    Database, MigrateError, Options,
    rusqlite::{Connection, types::Value},
};
use sqlx::migrate::{MigrateError as SqlxMigrateError, Migrator};
use std::path::{Path, PathBuf};

include!(concat!(env!("OUT_DIR"), "/compact_migrations.rs"));
include!(concat!(env!("OUT_DIR"), "/runner_migrations.rs"));

/// The D170-shaped rows (50 users, 8k sessions, 1k hosts, 200 terminals,
/// 100k layout receipts) shared with the `db_pool_bench` example.
const SEED: &str = include_str!("../examples/db_pool_bench/seed.sql");

/// A private data directory for one server database, removed on drop.
struct DataDir(PathBuf);

impl DataDir {
    /// A fresh, not yet created directory path under the system temp dir.
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("infraternal-dbcompat-{}", uuid::Uuid::new_v4())))
    }

    /// The database file `open_database` creates in this directory.
    fn file(&self) -> PathBuf {
        self.0.join("infraternal.sqlite")
    }
}

impl Drop for DataDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Build a database the way production databases were built: an older
/// release applied the first `stage_one` migrations, a later release
/// applied the rest at startup, then the server filled it with rows.
async fn sqlx_built(stage_one: usize, seed: bool) -> DataDir {
    let dir = DataDir::new();
    let pool = open_database(&dir.0).await.expect("production pool");
    let older = Migrator {
        migrations: std::borrow::Cow::Borrowed(&MIGRATIONS.migrations[..stage_one]),
        ..Migrator::DEFAULT
    };
    older.run(&pool).await.expect("older release migrations");
    crate::auth::Auth::new(pool.clone(), "localhost", "https://localhost")
        .await
        .expect("today's startup migrations");
    if seed {
        sqlx::raw_sql(SEED).execute(&pool).await.expect("seed rows");
    }
    pool.close().await;
    dir
}

/// Build a fresh database with the rusqlite runner only (no seeded rows).
async fn runner_built() -> DataDir {
    let dir = DataDir::new();
    std::fs::create_dir_all(&dir.0).unwrap();
    let db = Database::open(dir.file(), Options::default())
        .await
        .unwrap();
    let report = db.migrate(RUNNER_MIGRATIONS).await.unwrap();
    assert_eq!(report.applied.len(), RUNNER_MIGRATIONS.len());
    dir
}

/// Everything about a database file that a migration runner could change.
#[derive(Debug, PartialEq)]
struct Snapshot {
    /// `sqlite_schema` rows (`type`, `name`, `tbl_name`, `sql`) in creation order.
    schema: Vec<(String, String, String, Option<String>)>,
    /// `_sqlx_migrations` rows, every column, in version order.
    history: Vec<Vec<Value>>,
    /// Every other table's rows, sorted, keyed by table name.
    data: Vec<(String, Vec<String>)>,
    user_version: i64,
}

/// Read a [`Snapshot`]. With `mask_time`, integers within a day of now (rows
/// that migrations stamp with `unixepoch()`), `installed_on` and
/// `execution_time` are replaced by placeholders so two separately built
/// databases compare equal when they differ only in when they were built.
fn snapshot(path: &Path, mask_time: bool) -> Snapshot {
    let conn = Connection::open(path).unwrap();
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let mask = |value: Value| match value {
        Value::Integer(seconds) if mask_time && (seconds - now).abs() < 86_400 => {
            Value::Text("<now>".to_owned())
        }
        other => other,
    };
    let schema: Vec<(String, String, String, Option<String>)> = conn
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY rowid")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let rows = |sql: &str| -> Vec<Vec<Value>> {
        let mut statement = conn.prepare(sql).unwrap();
        let width = statement.column_count();
        statement
            .query_map([], |row| {
                (0..width)
                    .map(|index| row.get::<_, Value>(index))
                    .collect::<Result<Vec<Value>, _>>()
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    let history = rows("SELECT version, description, installed_on, success, checksum, execution_time FROM _sqlx_migrations ORDER BY version")
        .into_iter()
        .map(|mut row| {
            if mask_time {
                row[2] = Value::Text("<installed_on>".to_owned());
                row[5] = Value::Text("<execution_time>".to_owned());
            }
            row
        })
        .collect();
    let data = schema
        .iter()
        .filter(|(kind, name, _, _)| kind == "table" && name != "_sqlx_migrations")
        .map(|(_, name, _, _)| {
            let mut dumped: Vec<String> = rows(&format!("SELECT * FROM \"{name}\""))
                .into_iter()
                .map(|row| format!("{:?}", row.into_iter().map(&mask).collect::<Vec<_>>()))
                .collect();
            dumped.sort_unstable();
            (name.clone(), dumped)
        })
        .collect();
    let user_version = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    Snapshot {
        schema,
        history,
        data,
        user_version,
    }
}

/// The generated runner list is the server's migration list: same versions,
/// descriptions, executable SQL and original checksums, one per `.sql` file
/// in `migrations/` (counted from the directory, so a new migration never
/// needs this test edited), and none of them is a no-transaction migration.
#[test]
fn runner_list_matches_the_sqlx_list() {
    let files = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension == "sql")
        })
        .count();
    assert_eq!(RUNNER_MIGRATIONS.len(), files);
    assert_eq!(RUNNER_MIGRATIONS.len(), MIGRATIONS.migrations.len());
    for (runner, sqlx) in RUNNER_MIGRATIONS.iter().zip(MIGRATIONS.iter()) {
        assert_eq!(runner.version, sqlx.version);
        assert_eq!(runner.description, sqlx.description);
        assert_eq!(runner.sql, sqlx.sql);
        assert_eq!(runner.checksum, &*sqlx.checksum);
        // The runner always wraps a migration in a transaction; the build
        // script refuses `-- no-transaction` until it can do otherwise (#473).
        assert!(!sqlx.no_tx, "migration {} is no-transaction", sqlx.version);
    }
}

/// A copy-shaped database built by today's sqlx path opens under the runner
/// with every history row validated, nothing applied and nothing changed;
/// afterwards today's sqlx path still accepts it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlx_built_database_is_accepted_unchanged() {
    let dir = sqlx_built(27, true).await;
    let before = snapshot(&dir.file(), false);
    assert_eq!(before.history.len(), MIGRATIONS.migrations.len());
    assert!(
        before
            .data
            .iter()
            .any(|(table, rows)| table == "canvas_receipts" && rows.len() == 100_000)
    );

    let db = Database::open(dir.file(), Options::default())
        .await
        .unwrap();
    let report = db.migrate(RUNNER_MIGRATIONS).await.unwrap();
    assert_eq!(report.validated, MIGRATIONS.migrations.len());
    assert!(report.applied.is_empty(), "{:?}", report.applied);
    drop(db);
    assert_eq!(snapshot(&dir.file(), false), before);

    let pool = open_database(&dir.0).await.unwrap();
    crate::auth::Auth::new(pool.clone(), "localhost", "https://localhost")
        .await
        .unwrap();
    pool.close().await;
    assert_eq!(snapshot(&dir.file(), false), before);
}

/// A fresh database built by the runner is schema-identical to one built by
/// today's sqlx path, with the same history and the same rows (the ones the
/// migrations themselves insert; the seed uses `randomblob()`, so seeded
/// copies are compared only against themselves); and the sqlx path accepts
/// the runner's database without applying anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runner_built_database_is_identical_to_sqlx_built() {
    let by_sqlx = sqlx_built(MIGRATIONS.migrations.len(), false).await;
    let by_runner = runner_built().await;
    let expected = snapshot(&by_sqlx.file(), true);
    let actual = snapshot(&by_runner.file(), true);
    assert_eq!(actual.schema.len(), expected.schema.len());
    for (runner, sqlx) in actual.schema.iter().zip(&expected.schema) {
        assert_eq!(runner, sqlx, "sqlite_schema differs");
    }
    assert_eq!(actual, expected);

    let history_before = snapshot(&by_runner.file(), false).history;
    let pool = open_database(&by_runner.0).await.unwrap();
    crate::auth::Auth::new(pool.clone(), "localhost", "https://localhost")
        .await
        .unwrap();
    pool.close().await;
    assert_eq!(snapshot(&by_runner.file(), false).history, history_before);
}

/// The ways a recorded history can be refused, applied to a copy of a
/// sqlx-built database before both runners see it.
#[derive(Clone, Copy, Debug)]
enum Tamper {
    /// Change the recorded checksum of migration 0028.
    Checksum,
    /// Record a version from a newer build.
    FutureVersion,
    /// Mark migration 0030 as having broken half-way.
    Dirty,
}

/// Both runners refuse the same tampered histories with the same error and
/// version, and the runner refuses before applying anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_runners_refuse_the_same_histories() {
    for tamper in [Tamper::Checksum, Tamper::FutureVersion, Tamper::Dirty] {
        let dir = sqlx_built(39, false).await;
        {
            let conn = Connection::open(dir.file()).unwrap();
            // Forget 0040 so a migration is pending: the runner must refuse
            // without applying it (sqlx would apply pending ones before a
            // later mismatch; here the mismatch, 0028, comes first for both).
            conn.execute("DELETE FROM _sqlx_migrations WHERE version = 40", [])
                .unwrap();
            match tamper {
                Tamper::Checksum => conn.execute("UPDATE _sqlx_migrations SET checksum = zeroblob(48) WHERE version = 28", []),
                Tamper::FutureVersion => conn.execute(
                    "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) VALUES (99991231235959, 'from the future', 1, zeroblob(48), 0)",
                    [],
                ),
                Tamper::Dirty => conn.execute("UPDATE _sqlx_migrations SET success = 0 WHERE version = 30", []),
            }
            .unwrap();
        }
        let before = snapshot(&dir.file(), false);

        let db = Database::open(dir.file(), Options::default())
            .await
            .unwrap();
        let runner = db.migrate(RUNNER_MIGRATIONS).await;
        drop(db);
        assert_eq!(
            snapshot(&dir.file(), false),
            before,
            "{tamper:?}: the runner changed a refused database"
        );

        let pool = open_database(&dir.0).await.unwrap();
        let sqlx = MIGRATIONS.run(&pool).await;
        pool.close().await;

        let refused = match (&runner, &sqlx) {
            (
                Err(infraternal_db::Error::Migrate(MigrateError::VersionMismatch(a))),
                Err(SqlxMigrateError::VersionMismatch(b)),
            )
            | (
                Err(infraternal_db::Error::Migrate(MigrateError::VersionMissing(a))),
                Err(SqlxMigrateError::VersionMissing(b)),
            )
            | (
                Err(infraternal_db::Error::Migrate(MigrateError::Dirty(a))),
                Err(SqlxMigrateError::Dirty(b)),
            ) => a == b,
            _ => false,
        };
        assert!(refused, "{tamper:?}: runner {runner:?}, sqlx {sqlx:?}");
    }
}
