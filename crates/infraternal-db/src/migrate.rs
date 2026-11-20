//! The schema migration runner, compatible with the existing `_sqlx_migrations` history (D379).
//!
//! Every infraternal database already records its applied migrations in a
//! table named `_sqlx_migrations`, written by the previous runner. This runner
//! reads and writes that same table with the same columns, values and rules,
//! so an existing database is accepted unchanged and a database this runner
//! creates is accepted by the old one (which matters when rolling back to an
//! older binary).
//!
//! # The history table
//!
//! | column | meaning |
//! |---|---|
//! | `version` | the migration's number: a legacy `NNNN` or a UTC `YYYYMMDDHHMMSS` (D347) |
//! | `description` | the file name after the first `_`, without `.sql`, with `_` turned into spaces |
//! | `installed_on` | when it was applied (SQLite's `CURRENT_TIMESTAMP`) |
//! | `success` | always `1` for a finished migration; `0` would mean it broke half-way |
//! | `checksum` | SHA-384 of the original `.sql` file, byte for byte |
//! | `execution_time` | nanoseconds the migration took; `-1` until it is filled in after commit |
//!
//! # Rules (each one refuses to start)
//!
//! 1. A row with `success = 0` (dirty): [`MigrateError::Dirty`].
//! 2. A recorded version this binary does not know (a database from a newer
//!    build, or a deleted migration): [`MigrateError::VersionMissing`].
//! 3. A recorded checksum that differs from this binary's copy of that
//!    migration (an edited migration): [`MigrateError::VersionMismatch`].
//!
//! Then each migration that is not recorded yet runs, in ascending version
//! order, each in its own transaction together with its history row. A
//! version below the highest recorded one still runs if it is missing
//! (out-of-order timestamps from parallel branches, D347).
//!
//! One deliberate difference from the previous runner: it checked checksums
//! while applying, so it could apply version N and only then refuse at a
//! later changed version. This runner checks every recorded row first and
//! applies nothing when any rule fails.
//!
//! The server's one-time production retag of version 20 to 22 (#169) is not
//! part of this runner; the server runs it before calling [`run`].
use rusqlite::{
    Batch, Connection, TransactionBehavior, fallible_iterator::FallibleIterator as _, params,
};
use std::{collections::HashMap, time::Instant};

/// One migration as compiled into the binary. The server's build script
/// generates the list from `crates/infraternal-server/migrations/`.
#[derive(Clone, Copy, Debug)]
pub struct Migration {
    /// The version number from the file name.
    pub version: i64,
    /// The description recorded in the history table (see the module docs).
    pub description: &'static str,
    /// The SQL to execute. May be a compacted form of the file (comments and
    /// redundant whitespace removed), as long as it does the same thing.
    pub sql: &'static str,
    /// SHA-384 of the original, unmodified file. This, not `sql`, is what the
    /// history records and compares.
    pub checksum: &'static [u8],
}

/// What one successful [`run`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// How many history rows were already recorded and passed every check.
    pub validated: usize,
    /// The versions this run applied, in the order it applied them.
    pub applied: Vec<i64>,
}

/// Why [`run`] refused to start or stopped.
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    /// A previous run broke half-way through this version (`success = 0`).
    /// Someone has to look at the database before the server may start.
    #[error("migration {0} is partially applied; fix and remove the migration row by hand")]
    Dirty(i64),
    /// The database records a version this binary does not have: it was
    /// migrated by a newer build, or a migration file was deleted.
    #[error("migration {0} was previously applied but is missing from this build")]
    VersionMissing(i64),
    /// The database records a different checksum for this version: the
    /// migration file changed after it was applied (never allowed, D347).
    #[error("migration {0} was previously applied but has been modified")]
    VersionMismatch(i64),
    /// The SQL of this version failed. Its transaction rolled back, so the
    /// version stays unrecorded and the database is as before this migration.
    #[error("while executing migration {version}: {source}")]
    Execute {
        /// The migration that failed.
        version: i64,
        /// SQLite's error.
        #[source]
        source: rusqlite::Error,
    },
    /// The list passed to [`run`] is not in strictly ascending version order:
    /// a bug in the build script, caught before touching the database.
    #[error("migration list is not in strictly ascending order at version {0}")]
    Unordered(i64),
    /// Reading or writing the history table failed.
    #[error("migration history: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// The history table, character for character as the previous runner created
/// it. SQLite stores this text in `sqlite_schema`, so keeping it identical
/// keeps new databases schema-identical to old ones.
const CREATE_HISTORY: &str = r"
CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    checksum BLOB NOT NULL,
    execution_time BIGINT NOT NULL
);
                ";

/// Bring `conn`'s schema up to date with `migrations`.
///
/// `migrations` must be sorted by ascending version with no duplicates.
/// See the module docs for the rules. Safe to call on every start: when
/// everything is applied it only reads the history.
///
/// # Errors
///
/// A [`MigrateError`] when a rule refuses the history or a migration fails.
/// Migrations applied before a failure stay applied (each one is its own
/// transaction), exactly as with the previous runner.
pub fn run(conn: &mut Connection, migrations: &[Migration]) -> Result<Report, MigrateError> {
    for pair in migrations.windows(2) {
        if pair[1].version <= pair[0].version {
            return Err(MigrateError::Unordered(pair[1].version));
        }
    }
    conn.execute_batch(CREATE_HISTORY)?;

    let dirty: Option<i64> = conn
        .query_row(
            "SELECT version FROM _sqlx_migrations WHERE success = false ORDER BY version LIMIT 1",
            [],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })?;
    if let Some(version) = dirty {
        return Err(MigrateError::Dirty(version));
    }

    let applied: Vec<(i64, Vec<u8>)> = conn
        .prepare("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let known: HashMap<i64, &Migration> = migrations.iter().map(|m| (m.version, m)).collect();
    for (version, _) in &applied {
        if !known.contains_key(version) {
            return Err(MigrateError::VersionMissing(*version));
        }
    }
    let recorded: HashMap<i64, &[u8]> = applied
        .iter()
        .map(|(version, checksum)| (*version, checksum.as_slice()))
        .collect();
    for migration in migrations {
        if let Some(checksum) = recorded.get(&migration.version)
            && *checksum != migration.checksum
        {
            return Err(MigrateError::VersionMismatch(migration.version));
        }
    }

    let mut report = Report {
        validated: applied.len(),
        applied: Vec::new(),
    };
    for migration in migrations {
        if recorded.contains_key(&migration.version) {
            continue;
        }
        apply(conn, migration)?;
        report.applied.push(migration.version);
    }
    Ok(report)
}

/// Apply one migration and record it, in one transaction.
///
/// `BEGIN IMMEDIATE` takes the write lock first, so two processes starting at
/// once cannot both apply the same version: the second waits (busy timeout),
/// then fails on the history row's primary key and rolls back. The
/// `execution_time` is filled in after commit, as before; if the process dies
/// in between, the row keeps `-1`, which is harmless.
fn apply(conn: &mut Connection, migration: &Migration) -> Result<(), MigrateError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let start = Instant::now();
    run_script(&tx, migration.sql).map_err(|source| MigrateError::Execute {
        version: migration.version,
        source,
    })?;
    tx.execute(
        "INSERT INTO _sqlx_migrations ( version, description, success, checksum, execution_time ) \
         VALUES ( ?1, ?2, TRUE, ?3, -1 )",
        params![migration.version, migration.description, migration.checksum],
    )?;
    tx.commit()?;
    let nanos = i64::try_from(start.elapsed().as_nanos()).unwrap_or(i64::MAX);
    conn.execute(
        "UPDATE _sqlx_migrations SET execution_time = ?1 WHERE version = ?2",
        params![nanos, migration.version],
    )?;
    Ok(())
}

/// Run every statement of a migration script, each one to completion.
///
/// `Connection::execute_batch` steps each statement only once. That is enough
/// for `CREATE`, `INSERT`, `UPDATE` and `DELETE`, which do all their work on
/// the first step, but a `SELECT` used as a guard (one that fails on a later
/// row) would stop after its first row. The previous runner read every row,
/// so this does too.
fn run_script(conn: &Connection, sql: &str) -> rusqlite::Result<()> {
    let mut batch = Batch::new(conn, sql);
    while let Some(mut statement) = batch.next()? {
        let mut rows = statement.raw_query();
        while rows.next()?.is_some() {}
    }
    Ok(())
}
