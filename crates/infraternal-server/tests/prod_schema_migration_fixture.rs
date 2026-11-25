//! Verifies pending SQLite migrations against the checked-in synthetic
//! prod-schema fixture (`tests/fixtures/prod-schema.sqlite`, #514).
//!
//! Owner rule (2026-11-25): jobs never copy production's database for
//! migration checks. Instead, every migration branch tests against a copy of
//! the deterministic synthetic fixture built by
//! `scripts/build-migration-fixture.py`, checking `PRAGMA integrity_check`,
//! `PRAGMA foreign_key_check`, per-table row counts, and byte-for-byte row
//! preservation across kept tables and columns.

#![expect(
    clippy::expect_used,
    reason = "integration test assertions fail fast on unexpected SQLite or fixture errors"
)]

use infraternal_db::rusqlite::{Connection, types::Value};
use sqlx::{
    SqlStr, SqlitePool,
    migrate::{Migration as SqlxMigration, MigrationType, Migrator},
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

/// Relative path from the `infraternal-server` crate manifest to the checked-in fixture.
const FIXTURE_RELATIVE_PATH: &str = "tests/fixtures/prod-schema.sqlite";

/// The shipping `sqlx` migration set embedded at compile time.
static SHIPPING_MIGRATIONS: Migrator = sqlx::migrate!("./migrations");

/// Tables whose row count or existing column bytes are intentionally changed by
/// a pending migration not yet reflected in the checked-in fixture.
///
/// Leave this empty by default so every existing table is checked byte-for-byte.
/// When a branch adds a migration that intentionally prunes or rewrites rows in
/// an existing table before the next release refreshes the fixture, list that
/// table name here and add a targeted assertion for its new state.
const TRANSFORMED_TABLES: &[&str] = &[];

/// A private temporary directory holding one copied fixture database, removed on drop.
struct FixtureCopy {
    /// Root temporary directory for this test run.
    dir: PathBuf,
    /// Path to the copied SQLite database file inside `dir`.
    db_path: PathBuf,
}

impl FixtureCopy {
    /// Copy the checked-in prod-schema fixture into a fresh private temp directory.
    fn new(tag: &str) -> Self {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_RELATIVE_PATH);
        assert!(
            source.is_file(),
            "checked-in migration fixture is missing at {}; run scripts/build-migration-fixture.py",
            source.display()
        );
        let dir = std::env::temp_dir().join(format!(
            "infraternal-migfix-{tag}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).expect("create fixture temp dir");
        let db_path = dir.join("prod-schema.sqlite");
        std::fs::copy(&source, &db_path).expect("copy prod-schema fixture");
        Self { dir, db_path }
    }

    /// Return the path to the copied SQLite database.
    fn path(&self) -> &Path {
        &self.db_path
    }
}

impl Drop for FixtureCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Ordered, byte-exact snapshot of one table's columns and rows.
#[derive(Debug, Clone, PartialEq)]
struct TableSnapshot {
    /// Column names in `PRAGMA table_info` order.
    columns: Vec<String>,
    /// All rows in the table, sorted deterministically by encoded cell bytes.
    rows: Vec<Vec<Value>>,
}

/// Complete snapshot of every application table in a SQLite database.
#[derive(Debug, Clone)]
struct DatabaseSnapshot {
    /// Per-table snapshots keyed by table name (excluding `sqlite_*` and `_sqlx_migrations`).
    tables: BTreeMap<String, TableSnapshot>,
}

/// Open a single-connection `sqlx` pool with foreign keys enabled, matching production.
async fn open_sqlx_pool(path: &Path) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(false)
                .foreign_keys(true),
        )
        .await
        .expect("open sqlx pool on fixture copy")
}

/// Encode a `rusqlite::types::Value` into a deterministic sortable byte key so
/// rows can be compared byte for byte regardless of physical scan order.
fn sort_key(row: &[Value]) -> Vec<u8> {
    let mut out = Vec::new();
    for cell in row {
        match cell {
            Value::Null => out.push(0),
            Value::Integer(n) => {
                out.push(1);
                out.extend_from_slice(&n.to_be_bytes());
            }
            Value::Real(f) => {
                out.push(2);
                out.extend_from_slice(&f.to_bits().to_be_bytes());
            }
            Value::Text(s) => {
                out.push(3);
                let len = u32::try_from(s.len()).expect("text cell length fits u32");
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(s.as_bytes());
            }
            Value::Blob(b) => {
                out.push(4);
                let len = u32::try_from(b.len()).expect("blob cell length fits u32");
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(b);
            }
        }
    }
    out
}

/// Read a byte-exact snapshot of every application table in `path`.
fn capture_snapshot(path: &Path) -> DatabaseSnapshot {
    let conn = Connection::open(path).expect("open sqlite connection for snapshot");
    let mut table_stmt = conn
        .prepare(
            "SELECT name FROM sqlite_master \
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != '_sqlx_migrations' \
             ORDER BY name",
        )
        .expect("prepare table list query");
    let table_names: Vec<String> = table_stmt
        .query_map([], |row| row.get(0))
        .expect("query table names")
        .collect::<Result<_, _>>()
        .expect("collect table names");

    let mut tables = BTreeMap::new();
    for table in table_names {
        let mut col_stmt = conn
            .prepare(&format!("PRAGMA table_info(\"{table}\")"))
            .expect("prepare table_info");
        let columns: Vec<String> = col_stmt
            .query_map([], |row| row.get(1))
            .expect("query table_info")
            .collect::<Result<_, _>>()
            .expect("collect column names");

        let quoted_cols = columns
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut row_stmt = conn
            .prepare(&format!("SELECT {quoted_cols} FROM \"{table}\""))
            .expect("prepare table dump");
        let width = columns.len();
        let mut rows: Vec<Vec<Value>> = row_stmt
            .query_map([], |row| {
                (0..width)
                    .map(|idx| row.get::<_, Value>(idx))
                    .collect::<Result<Vec<Value>, _>>()
            })
            .expect("query table rows")
            .collect::<Result<_, _>>()
            .expect("collect table rows");
        rows.sort_by_key(|row| sort_key(row));
        tables.insert(table, TableSnapshot { columns, rows });
    }
    DatabaseSnapshot { tables }
}

/// Assert `PRAGMA integrity_check` returns `ok` and `PRAGMA foreign_key_check` is empty.
fn assert_sqlite_healthy(path: &Path, stage: &str) {
    let conn = Connection::open(path).expect("open sqlite connection for health check");
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .expect("enable foreign_keys");

    let integrity: Vec<String> = conn
        .prepare("PRAGMA integrity_check")
        .expect("prepare integrity_check")
        .query_map([], |row| row.get(0))
        .expect("query integrity_check")
        .collect::<Result<_, _>>()
        .expect("collect integrity_check");
    assert_eq!(
        integrity,
        vec!["ok".to_owned()],
        "{stage}: PRAGMA integrity_check failed"
    );

    let fk_violations: Vec<(String, i64, String, i64)> = conn
        .prepare("PRAGMA foreign_key_check")
        .expect("prepare foreign_key_check")
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .expect("query foreign_key_check")
        .collect::<Result<_, _>>()
        .expect("collect foreign_key_check");
    assert!(
        fk_violations.is_empty(),
        "{stage}: PRAGMA foreign_key_check reported violations: {fk_violations:?}"
    );
}

/// Assert every table present before migration keeps its row count and exact
/// byte-for-byte values across all kept columns (excluding `TRANSFORMED_TABLES`).
fn assert_rows_preserved(before: &DatabaseSnapshot, after: &DatabaseSnapshot, stage: &str) {
    let transformed: BTreeSet<&str> = TRANSFORMED_TABLES.iter().copied().collect();
    for (table, prev) in &before.tables {
        if transformed.contains(table.as_str()) {
            continue;
        }
        let next = after
            .tables
            .get(table)
            .unwrap_or_else(|| panic!("{stage}: table `{table}` disappeared after migration"));
        assert_eq!(
            next.rows.len(),
            prev.rows.len(),
            "{stage}: row count changed for table `{table}` (before={}, after={})",
            prev.rows.len(),
            next.rows.len()
        );
        // Project onto columns present in both snapshots so an additive
        // `ALTER TABLE ... ADD COLUMN` migration still proves every existing
        // column survived byte for byte.
        let next_index: BTreeMap<&str, usize> = next
            .columns
            .iter()
            .enumerate()
            .map(|(idx, col)| (col.as_str(), idx))
            .collect();
        let common_positions: Vec<(usize, usize)> = prev
            .columns
            .iter()
            .enumerate()
            .filter_map(|(prev_idx, col)| {
                next_index
                    .get(col.as_str())
                    .map(|&after_idx| (prev_idx, after_idx))
            })
            .collect();
        assert_eq!(
            common_positions.len(),
            prev.columns.len(),
            "{stage}: table `{table}` dropped columns unexpectedly (before={:?}, after={:?})",
            prev.columns,
            next.columns
        );
        let mut prev_projected: Vec<Vec<Value>> = prev
            .rows
            .iter()
            .map(|row| {
                common_positions
                    .iter()
                    .map(|&(p, _)| row[p].clone())
                    .collect()
            })
            .collect();
        let mut next_projected: Vec<Vec<Value>> = next
            .rows
            .iter()
            .map(|row| {
                common_positions
                    .iter()
                    .map(|&(_, n)| row[n].clone())
                    .collect()
            })
            .collect();
        prev_projected.sort_by_key(|row| sort_key(row));
        next_projected.sort_by_key(|row| sort_key(row));
        assert_eq!(
            next_projected, prev_projected,
            "{stage}: rows in table `{table}` changed bytes during migration"
        );
    }
}

/// Assert the checked-in fixture exercises every required domain shape so the
/// migration suite never silently degrades to an empty or trivial database.
fn assert_fixture_coverage(path: &Path, snapshot: &DatabaseSnapshot) {
    let empty_tables: Vec<&String> = snapshot
        .tables
        .iter()
        .filter_map(|(name, data)| data.rows.is_empty().then_some(name))
        .collect();
    assert!(
        empty_tables.is_empty(),
        "prod-schema fixture has empty tables: {empty_tables:?}"
    );

    let conn = Connection::open(path).expect("open sqlite for coverage checks");
    let count = |sql: &str| -> i64 {
        conn.query_row(sql, [], |row| row.get(0))
            .unwrap_or_else(|err| panic!("coverage query `{sql}` failed: {err}"))
    };
    assert!(
        count("SELECT count(*) FROM users") >= 3,
        "fixture must contain multiple user accounts"
    );
    assert!(
        count("SELECT count(DISTINCT owner_id) FROM remote_hosts") >= 3,
        "fixture must have hosts across several owners"
    );
    assert_eq!(
        count(
            "SELECT count(DISTINCT mode) FROM remote_hosts WHERE mode IN ('rootless', 'rootful')"
        ),
        2,
        "fixture must cover both rootless and rootful host modes"
    );
    // A P-256 key belongs to a `device` host (#580), which no release before the device host mode
    // can store, so the fixture holds Ed25519 certificates only. The migration's own tests cover
    // P-256 on devices and the refusal of P-256 on any other host.
    assert_eq!(
        count("SELECT count(DISTINCT key_algorithm) FROM remote_certificates"),
        1,
        "fixture certificates are all Ed25519: P-256 is for devices only"
    );
    assert!(
        count("SELECT count(*) FROM remote_certificates WHERE role = 'successor'") >= 1,
        "fixture must include a successor certificate"
    );
    assert_eq!(
        count(
            "SELECT count(DISTINCT key_algorithm) FROM remote_join_tokens WHERE key_algorithm = 'ed25519'"
        ),
        1,
        "fixture must include Ed25519 join tokens (a P-256 invitation is for a device, #580)"
    );
    assert!(
        count(
            "SELECT count(*) FROM remote_identity_rotation WHERE length(predecessor_public_key) = 65"
        ) >= 1,
        "fixture must include P-256 identity rotation rows"
    );
    assert_eq!(
        count(
            "SELECT count(DISTINCT COALESCE(rotation_phase, 'idle')) FROM mesh_node_key_rotation"
        ),
        5,
        "fixture must exercise all five mesh key rotation phases"
    );
    assert!(
        count("SELECT count(*) FROM mesh_routes WHERE approved_at IS NOT NULL") >= 1
            && count("SELECT count(*) FROM mesh_routes WHERE approved_at IS NULL") >= 1,
        "fixture must include both approved and unapproved mesh routes"
    );
}

/// Applies every pending migration to a copy of the checked-in prod-schema
/// fixture, checks `PRAGMA integrity_check`, `PRAGMA foreign_key_check`,
/// per-table row counts, byte-for-byte row survival, idempotent re-runs, and
/// D379 rusqlite runner compatibility.
#[tokio::test]
async fn prod_schema_fixture_applies_pending_migrations_and_preserves_rows() {
    let copy = FixtureCopy::new("pending");
    assert_sqlite_healthy(copy.path(), "before migration");
    let before = capture_snapshot(copy.path());
    assert_fixture_coverage(copy.path(), &before);

    let pool = open_sqlx_pool(copy.path()).await;
    SHIPPING_MIGRATIONS
        .run(&pool)
        .await
        .expect("apply pending migrations to prod-schema fixture");
    SHIPPING_MIGRATIONS
        .run(&pool)
        .await
        .expect("re-running migrations on fixture must be idempotent");

    let recorded: Vec<(i64, Vec<u8>, bool)> =
        sqlx::query_as("SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .expect("read _sqlx_migrations");
    assert_eq!(
        recorded.len(),
        SHIPPING_MIGRATIONS.migrations.len(),
        "every migration must be recorded in _sqlx_migrations"
    );
    for ((version, checksum, success), expected) in recorded.iter().zip(SHIPPING_MIGRATIONS.iter())
    {
        assert_eq!(*version, expected.version);
        assert_eq!(checksum.as_slice(), expected.checksum.as_ref());
        assert!(*success, "migration {version} must have success = 1");
    }
    pool.close().await;

    assert_sqlite_healthy(copy.path(), "after sqlx migration");
    let after = capture_snapshot(copy.path());
    assert_rows_preserved(&before, &after, "after sqlx migration");

    // Verify the D379 rusqlite runner accepts the migrated fixture unchanged.
    let runner_list: Vec<infraternal_db::Migration> = SHIPPING_MIGRATIONS
        .iter()
        .map(|m| infraternal_db::Migration {
            version: m.version,
            description: m.description.as_ref(),
            sql: "",
            checksum: m.checksum.as_ref(),
        })
        .collect();
    let mut conn = Connection::open(copy.path()).expect("open rusqlite connection");
    let report = infraternal_db::migrate::run(&mut conn, &runner_list)
        .expect("rusqlite runner accepts fixture");
    assert_eq!(report.validated, SHIPPING_MIGRATIONS.migrations.len());
    assert_eq!(report.applied, Vec::<i64>::new());
}

/// Proves the upgrade harness exercises a real pending migration on top of the
/// populated fixture even when `dev` currently has zero pending migrations.
#[tokio::test]
async fn prod_schema_fixture_exercises_synthetic_pending_migration_and_byte_preservation() {
    let copy = FixtureCopy::new("synthetic-pending");
    let before = capture_snapshot(copy.path());

    let mut pending_migrator: Migrator = sqlx::migrate!("./migrations");
    let synthetic_version = 20_990_101_000_000_i64;
    pending_migrator
        .migrations
        .to_mut()
        .push(SqlxMigration::new(
            synthetic_version,
            Cow::Borrowed("synthetic fixture upgrade proof"),
            MigrationType::Simple,
            SqlStr::from_static(
                "ALTER TABLE remote_hosts ADD COLUMN fixture_note TEXT; \
             CREATE TABLE fixture_upgrade_probe ( \
                 host_id BLOB PRIMARY KEY REFERENCES remote_hosts(id) ON DELETE CASCADE, \
                 note TEXT NOT NULL \
             ) STRICT; \
             INSERT INTO fixture_upgrade_probe(host_id, note) \
             SELECT id, 'migrated' FROM remote_hosts;",
            ),
            false,
        ));

    let pool = open_sqlx_pool(copy.path()).await;
    pending_migrator
        .run(&pool)
        .await
        .expect("apply synthetic pending migration to fixture");
    pending_migrator
        .run(&pool)
        .await
        .expect("re-running synthetic pending migration must be idempotent");
    pool.close().await;

    assert_sqlite_healthy(copy.path(), "after synthetic pending migration");
    let after = capture_snapshot(copy.path());
    assert_rows_preserved(&before, &after, "after synthetic pending migration");
    let probe = after
        .tables
        .get("fixture_upgrade_probe")
        .expect("synthetic table must exist after migration");
    assert_eq!(
        probe.rows.len(),
        before.tables["remote_hosts"].rows.len(),
        "synthetic probe table should contain one row per existing host"
    );
}

/// Confirms key constraints and triggers remain live on a migrated copy of the fixture.
#[tokio::test]
async fn prod_schema_fixture_enforces_constraints_and_triggers_after_migration() {
    let copy = FixtureCopy::new("triggers");
    let pool = open_sqlx_pool(copy.path()).await;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrate fixture copy");

    // Unique index `one_owner` refuses a second owner account.
    assert!(
        sqlx::query(
            "INSERT INTO users(id, name, owner, recovery_hash, username, display_name) \
             VALUES ('u-second-owner', 'Second', 1, 'h', 'second-owner', 'Second')",
        )
        .execute(&pool)
        .await
        .is_err(),
        "one_owner index must reject a second owner = 1 row"
    );

    // Trigger `remote_certificates_key_write_once` refuses key/algorithm mutation.
    assert!(
        sqlx::query(
            "UPDATE remote_certificates SET key_algorithm = 'p256' WHERE key_algorithm = 'ed25519'"
        )
        .execute(&pool)
        .await
        .is_err(),
        "remote_certificates_key_write_once must refuse algorithm mutation"
    );

    // Trigger `remote_hosts_mode_write_once` refuses changing mode without an enrolled promotion.
    assert!(
        sqlx::query("UPDATE remote_hosts SET mode = 'rootful', execution_uid = 0 WHERE hostname = 'beta-dev'")
            .execute(&pool)
            .await
            .is_err(),
        "remote_hosts_mode_write_once must refuse unpromoted mode changes"
    );

    // Trigger `canvas_receipt_insert` increments `canvas_heads.receipt_count`.
    let before_receipts: i64 =
        sqlx::query_scalar("SELECT receipt_count FROM canvas_heads WHERE account = 'u-owner'")
            .fetch_one(&pool)
            .await
            .expect("read initial receipt_count");
    sqlx::query(
        "INSERT INTO canvas_receipts(account, op_id, request, revision) \
         VALUES ('u-owner', 'op-trigger-check', 'digest-trigger', 3)",
    )
    .execute(&pool)
    .await
    .expect("insert canvas receipt");
    let after_receipts: i64 =
        sqlx::query_scalar("SELECT receipt_count FROM canvas_heads WHERE account = 'u-owner'")
            .fetch_one(&pool)
            .await
            .expect("read incremented receipt_count");
    assert_eq!(after_receipts, before_receipts + 1);
    pool.close().await;
}
