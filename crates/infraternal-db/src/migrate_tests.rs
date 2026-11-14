//! Rule tests for the `_sqlx_migrations` runner on small synthetic migration
//! lists (D379). The compatibility proof against the real 54 migrations and
//! databases written by the previous runner lives in the server crate
//! (`runtime_rusqlite_compat_tests.rs`), which has both runners.
use crate::migrate::{self, MigrateError, Migration};
use crate::pool_tests::TempDir;
use rusqlite::Connection;

/// Three valid migrations with distinct fake checksums.
const BASE: [Migration; 3] = [
    Migration {
        version: 1,
        description: "first",
        sql: "CREATE TABLE a (x INTEGER);",
        checksum: &[1; 48],
    },
    Migration {
        version: 2,
        description: "second",
        sql: "CREATE TABLE b (y INTEGER);",
        checksum: &[2; 48],
    },
    Migration {
        version: 20_261_105_020_355,
        description: "timestamped one",
        sql: "CREATE TABLE c (z INTEGER); INSERT INTO c VALUES (1);",
        checksum: &[3; 48],
    },
];

/// A fresh on-disk connection (the runner is used on files, never in memory).
fn connection(dir: &TempDir) -> Connection {
    Connection::open(dir.db()).unwrap()
}

/// History rows as (version, description, success, checksum, `execution_time` >= 0).
fn history(conn: &Connection) -> Vec<(i64, String, bool, Vec<u8>, bool)> {
    conn.prepare("SELECT version, description, success, checksum, execution_time FROM _sqlx_migrations ORDER BY version")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get::<_, i64>(4)? >= 0))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Names of user tables, to see which migrations ran.
fn tables(conn: &Connection) -> Vec<String> {
    conn.prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name != '_sqlx_migrations' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// A fresh database gets every migration once, with complete history rows;
/// a second run only validates.
#[test]
fn fresh_database_applies_all_then_only_validates() {
    let dir = TempDir::new("migrate-fresh");
    let mut conn = connection(&dir);
    let report = migrate::run(&mut conn, &BASE).unwrap();
    assert_eq!(report.validated, 0);
    assert_eq!(report.applied, vec![1, 2, 20_261_105_020_355]);
    assert_eq!(
        history(&conn),
        vec![
            (1, "first".to_owned(), true, vec![1; 48], true),
            (2, "second".to_owned(), true, vec![2; 48], true),
            (
                20_261_105_020_355,
                "timestamped one".to_owned(),
                true,
                vec![3; 48],
                true
            ),
        ]
    );
    let again = migrate::run(&mut conn, &BASE).unwrap();
    assert_eq!(again.validated, 3);
    assert_eq!(again.applied, Vec::<i64>::new());
}

/// A missing version below the highest applied one still runs (D347).
#[test]
fn missing_earlier_version_is_applied() {
    let dir = TempDir::new("migrate-gap");
    let mut conn = connection(&dir);
    migrate::run(&mut conn, &[BASE[0], BASE[2]]).unwrap();
    let report = migrate::run(&mut conn, &BASE).unwrap();
    assert_eq!(report.applied, vec![2]);
    assert_eq!(tables(&conn), vec!["a", "b", "c"]);
}

/// A dirty history row refuses to start and nothing new is applied.
#[test]
fn dirty_row_refuses() {
    let dir = TempDir::new("migrate-dirty");
    let mut conn = connection(&dir);
    migrate::run(&mut conn, &BASE[..1]).unwrap();
    conn.execute(
        "UPDATE _sqlx_migrations SET success = 0 WHERE version = 1",
        [],
    )
    .unwrap();
    assert!(matches!(
        migrate::run(&mut conn, &BASE),
        Err(MigrateError::Dirty(1))
    ));
    assert_eq!(tables(&conn), vec!["a"]);
}

/// A version this build does not know (a newer database) refuses to start.
#[test]
fn unknown_future_version_refuses() {
    let dir = TempDir::new("migrate-future");
    let mut conn = connection(&dir);
    migrate::run(&mut conn, &BASE).unwrap();
    assert!(matches!(
        migrate::run(&mut conn, &BASE[..2]),
        Err(MigrateError::VersionMissing(20_261_105_020_355))
    ));
}

/// A changed checksum refuses to start before anything is applied, even when
/// an earlier migration is still missing.
#[test]
fn checksum_mismatch_refuses_before_applying_anything() {
    let dir = TempDir::new("migrate-mismatch");
    let mut conn = connection(&dir);
    migrate::run(&mut conn, &[BASE[0], BASE[2]]).unwrap();
    let mut changed = BASE;
    changed[2].checksum = &[9; 48];
    assert!(matches!(
        migrate::run(&mut conn, &changed),
        Err(MigrateError::VersionMismatch(20_261_105_020_355))
    ));
    assert_eq!(
        tables(&conn),
        vec!["a", "c"],
        "version 2 must not run when a later checksum is wrong"
    );
}

/// A failing migration rolls back its own statements and stays unrecorded;
/// earlier ones stay applied.
#[test]
fn failing_migration_rolls_back_itself_only() {
    let dir = TempDir::new("migrate-fail");
    let mut conn = connection(&dir);
    let broken = [
        BASE[0],
        Migration {
            version: 2,
            description: "broken",
            sql: "CREATE TABLE b (y INTEGER); SELECT * FROM nowhere;",
            checksum: &[2; 48],
        },
    ];
    let outcome = migrate::run(&mut conn, &broken);
    assert!(
        matches!(outcome, Err(MigrateError::Execute { version: 2, .. })),
        "{outcome:?}"
    );
    assert_eq!(tables(&conn), vec!["a"]);
    assert_eq!(history(&conn).len(), 1);
}

/// Every statement runs to its last row, as with the previous runner: a
/// guard `SELECT` that fails only on its second row still fails the migration.
#[test]
fn statements_run_to_their_last_row() {
    let dir = TempDir::new("migrate-guard");
    let mut conn = connection(&dir);
    let guarded = [Migration {
        version: 1,
        description: "guarded",
        // abs() overflows only on the second row (x * -2^62 = i64::MIN). The
        // value depends on the row, so SQLite cannot hoist it to the first
        // step, and a plain scan (no ORDER BY, which would fill a sorter with
        // every row on the first step) reaches row 2 only on the second step.
        sql: "CREATE TABLE g (x INTEGER); INSERT INTO g VALUES (1), (2);
              SELECT abs(x * -4611686018427387904) FROM g;",
        checksum: &[1; 48],
    }];
    let outcome = migrate::run(&mut conn, &guarded);
    assert!(
        matches!(outcome, Err(MigrateError::Execute { version: 1, .. })),
        "{outcome:?}"
    );
    assert_eq!(
        tables(&conn),
        Vec::<String>::new(),
        "the failed migration must roll back"
    );
}

/// A list that is not strictly ascending is refused before touching the file.
#[test]
fn unordered_list_is_refused() {
    let dir = TempDir::new("migrate-order");
    let mut conn = connection(&dir);
    let outcome = migrate::run(&mut conn, &[BASE[1], BASE[0]]);
    assert!(
        matches!(outcome, Err(MigrateError::Unordered(1))),
        "{outcome:?}"
    );
    assert_eq!(tables(&conn), Vec::<String>::new());
}

/// The pool runs the same runner on its writer thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pool_migrate_runs_on_the_writer() {
    static LIST: [Migration; 3] = BASE;
    let dir = TempDir::new("migrate-pool");
    let db = crate::Database::open(dir.db(), crate::Options::default())
        .await
        .unwrap();
    let report = db.migrate(&LIST).await.unwrap();
    assert_eq!(report.applied.len(), 3);
    let rows: i64 = db
        .read(|tx| {
            Ok::<_, crate::Error>(tx.query_row("SELECT count(*) FROM c", [], |row| row.get(0))?)
        })
        .await
        .unwrap();
    assert_eq!(rows, 1);
}
