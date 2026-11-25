//! Preserves the durable wire writer-ID high-water mark across D295 database restores (#211).
//!
//! When an update is applied, the server saves a `VACUUM INTO` copy of its database before
//! switching to the new release (D295). If the owner later runs a manual Roll back (or any
//! undo restores that copy), the restored database's `wire_writer_clock` and
//! `sqlite_sequence('terminal_writers')` rewind to the pre-update values, while live shims
//! still remember every wire writer ID (`writer_id * 2`) and accepted input cursor that the
//! rolled-back release allocated.
//!
//! Without preserving the high-water mark, fresh attachments after a roll back reuse wire
//! writer IDs the shims have already seen at a non-zero cursor; the shims then treat the
//! first bytes typed on those attachments as already-delivered duplicates and silently drop
//! them.
//!
//! [`read_high_water`] reads the highest allocated writer ID from the database about to be
//! replaced (including any committed rows still in its WAL), and [`advance_to_at_least`]
//! raises both `wire_writer_clock` and `sqlite_sequence('terminal_writers')` in the restored
//! database before the server opens it.

use infraternal_db::rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{path::Path, time::Duration};

/// The highest valid `terminal_writers.writer_id` (31-bit signed limit so `writer_id * 2`
/// fits in `u32`, matching `wire_identity::reserve` and `terminal_writer_claim`).
const MAX_WRITER_ID: i64 = 2_147_483_647;

/// Busy timeout for the pre-startup SQLite open. At startup no server pool holds the file,
/// so this only guards against brief external readers.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Read the highest allocated writer ID from `database` before a D295 restore overwrites it.
///
/// Opens the existing database read-write (without `CREATE`, so a missing file is never
/// created) so SQLite recovers and reads any committed rows still sitting in `-wal`. Checks
/// `wire_writer_clock`, `sqlite_sequence('terminal_writers')` and `MAX(terminal_writers.writer_id)`,
/// returning the largest positive value clamped to [`MAX_WRITER_ID`], or `None` if the file
/// cannot be read or has no allocated writers. Closes the connection before returning so the
/// caller can unlink `-wal`/`-shm` and replace the file cleanly.
pub(crate) fn read_high_water(database: &Path) -> Option<i64> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(database, flags).ok()?;
    let _ = connection.busy_timeout(BUSY_TIMEOUT);
    let clock = query_optional_i64(
        &connection,
        "SELECT value FROM wire_writer_clock WHERE singleton = 1",
    );
    let sequence = query_optional_i64(
        &connection,
        "SELECT seq FROM sqlite_sequence WHERE name = 'terminal_writers'",
    );
    let max_row = query_optional_i64(&connection, "SELECT MAX(writer_id) FROM terminal_writers");
    let highest = [clock, sequence, max_row]
        .into_iter()
        .flatten()
        .max()
        .map(|value| value.clamp(0, MAX_WRITER_ID))?;
    (highest > 0).then_some(highest)
}

/// Advance `wire_writer_clock` and `sqlite_sequence('terminal_writers')` in the restored
/// `database` to at least `floor` so no wire writer ID allocated before a roll back is
/// ever handed out again to a fresh attachment.
///
/// Never moves either counter backwards, clamps `floor` to [`MAX_WRITER_ID`], and tolerates
/// a database that does not yet have one of the tables.
/// # Errors
/// Returns a short static reason if the database cannot be opened or the transaction fails.
pub(crate) fn advance_to_at_least(database: &Path, floor: i64) -> Result<(), &'static str> {
    if floor <= 0 {
        return Ok(());
    }
    let floor = floor.min(MAX_WRITER_ID);
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let mut connection = Connection::open_with_flags(database, flags)
        .map_err(|_| "the restored database could not be opened")?;
    let _ = connection.busy_timeout(BUSY_TIMEOUT);
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| "the writer-clock transaction could not start")?;
    if table_exists(&tx, "wire_writer_clock")? {
        tx.execute(
            "UPDATE wire_writer_clock SET value = MAX(value, ?1) WHERE singleton = 1",
            [floor],
        )
        .map_err(|_| "wire_writer_clock could not be advanced")?;
    }
    if table_exists(&tx, "sqlite_sequence")? {
        tx.execute(
            "UPDATE sqlite_sequence SET seq = MAX(seq, ?1) WHERE name = 'terminal_writers'",
            [floor],
        )
        .map_err(|_| "sqlite_sequence could not be updated")?;
        tx.execute(
            "INSERT INTO sqlite_sequence(name, seq) SELECT 'terminal_writers', ?1 WHERE NOT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name = 'terminal_writers')",
            [floor],
        )
        .map_err(|_| "sqlite_sequence could not be seeded")?;
    }
    tx.commit()
        .map_err(|_| "the writer-clock transaction could not commit")?;
    Ok(())
}

/// Run a single-column integer query, returning `None` if the table is absent, the query
/// returns no row, or the column is NULL.
fn query_optional_i64(connection: &Connection, sql: &str) -> Option<i64> {
    connection
        .query_row(sql, [], |row| row.get::<_, Option<i64>>(0))
        .optional()
        .ok()
        .flatten()
        .flatten()
}

/// Whether `name` exists as a table in the SQLite schema of `connection`.
fn table_exists(connection: &Connection, name: &str) -> Result<bool, &'static str> {
    let exists: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| "the database schema could not be inspected")?;
    Ok(exists.is_some())
}

#[cfg(test)]
mod tests {
    //! Regression tests for preserving the writer-ID high-water mark across D295 restores (#211).
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// Create the minimal schema that `terminal_writer_claim`, `wire_identity` and
    /// `bootstrap_remote` share for writer ID allocation.
    fn init_writer_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE terminal_writers (
                    writer_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tag TEXT
                 );
                 CREATE TABLE wire_writer_clock (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    value INTEGER NOT NULL CHECK(value >= 0 AND value <= 2147483647)
                 ) STRICT;
                 INSERT INTO wire_writer_clock(singleton, value) VALUES (1, 0);",
            )
            .unwrap();
    }

    /// A missing database file returns `None` and is never created as a side effect.
    #[test]
    fn read_high_water_missing_file_creates_nothing() {
        let dir = std::env::temp_dir().join(format!("j1148-missing-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let missing = dir.join("infraternal.sqlite");
        assert_eq!(read_high_water(&missing), None);
        assert!(!missing.exists(), "missing file must not be created");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `read_high_water` reads committed rows still sitting in `-wal` and takes the maximum
    /// across `wire_writer_clock`, `sqlite_sequence` and `terminal_writers`.
    #[test]
    fn read_high_water_reads_wal_and_takes_max_of_clock_and_sequence() {
        let dir = std::env::temp_dir().join(format!("j1148-wal-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let db = dir.join("infraternal.sqlite");
        let conn = Connection::open(&db).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        init_writer_schema(&conn);
        conn.execute(
            "INSERT INTO terminal_writers(writer_id, tag) VALUES (42, 'a')",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE wire_writer_clock SET value = 77 WHERE singleton = 1",
            [],
        )
        .unwrap();
        // Keep the WAL uncheckpointed on disk while closing the writer.
        drop(conn);
        assert_eq!(read_high_water(&db), Some(77));

        let conn = Connection::open(&db).unwrap();
        conn.execute(
            "INSERT INTO terminal_writers(writer_id, tag) VALUES (150, 'b')",
            [],
        )
        .unwrap();
        drop(conn);
        assert_eq!(read_high_water(&db), Some(150));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Simulates a full D295 update + manual Roll back cycle: the new release allocates
    /// writer IDs 11..=135 after the pre-update `VACUUM INTO` copy was taken, then the
    /// roll back restores the copy (clock = 10) and preserves the floor (135). The next
    /// attachment on the restored database allocates writer ID 136, never reusing 11..=135.
    #[test]
    fn advance_to_at_least_preserves_writer_floor_across_database_restore() {
        let dir = std::env::temp_dir().join(format!("j1148-restore-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let live = dir.join("infraternal.sqlite");
        let copy = dir.join("previous.sqlite");

        // Pre-update database: 10 writers allocated.
        let conn = Connection::open(&live).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        init_writer_schema(&conn);
        conn.execute(
            "INSERT INTO terminal_writers(writer_id, tag) VALUES (10, 'pre-update')",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE wire_writer_clock SET value = 10 WHERE singleton = 1",
            [],
        )
        .unwrap();
        conn.execute("VACUUM INTO ?1", [copy.to_str().unwrap()])
            .unwrap();

        // New release allocates 125 more writers (11..=135) while serving.
        conn.execute(
            "INSERT INTO terminal_writers(writer_id, tag) VALUES (135, 'on-new-release')",
            [],
        )
        .unwrap();
        drop(conn);

        // Roll back reads the high-water mark before overwriting the live database.
        let floor = read_high_water(&live).expect("high-water mark present");
        assert_eq!(floor, 135);

        // Restore the D295 copy (clock rewinds to 10) and drop old WAL/SHM.
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(dir.join(format!("infraternal.sqlite{suffix}")));
        }
        std::fs::copy(&copy, &live).unwrap();

        // Preserve the high-water mark on the restored database.
        advance_to_at_least(&live, floor).unwrap();

        let restored = Connection::open(&live).unwrap();
        let clock: i64 = restored
            .query_row(
                "SELECT value FROM wire_writer_clock WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let seq: i64 = restored
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'terminal_writers'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(clock, 135);
        assert_eq!(seq, 135);

        // Next allocation (same formula as terminal_writer_claim::SQL_INSERT) must be 136.
        restored
            .execute(
                "INSERT INTO terminal_writers(writer_id, tag)
                 SELECT MAX(COALESCE((SELECT seq FROM sqlite_sequence WHERE name='terminal_writers'), 0), w.value) + 1, 'after-rollback'
                 FROM wire_writer_clock w WHERE w.singleton = 1",
                [],
            )
            .unwrap();
        let allocated: i64 = restored
            .query_row(
                "SELECT writer_id FROM terminal_writers WHERE tag = 'after-rollback'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(allocated, 136);
        drop(restored);

        // Never moves backwards, and clamps above MAX_WRITER_ID.
        advance_to_at_least(&live, 50).unwrap();
        assert_eq!(read_high_water(&live), Some(136));
        advance_to_at_least(&live, MAX_WRITER_ID + 100).unwrap();
        assert_eq!(read_high_water(&live), Some(MAX_WRITER_ID));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
