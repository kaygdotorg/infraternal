//! infraternal's SQLite access layer (D379).
//!
//! The server keeps all of its state in one SQLite file. This crate is the way
//! the server talks to it:
//!
//! - [`Database`] owns the connections. Writes go to **one writer thread**
//!   that holds the only read-write connection, so two writers never fight
//!   over SQLite's write lock. Reads go to a small set of **reader threads**,
//!   each with its own connection in WAL mode, so reads never wait for writes.
//!   You hand the pool a closure; the whole closure runs as one transaction on
//!   that thread, in one hop, and you `.await` its result from async code.
//! - [`migrate`] applies the schema migrations and keeps the history in the
//!   `_sqlx_migrations` table that every existing database already has, with
//!   the same columns, checksums and refusal rules as before. An existing
//!   database therefore needs no conversion step.
//!
//! ```no_run
//! # async fn demo() -> Result<(), infraternal_db::Error> {
//! use infraternal_db::{Database, Options};
//! let db = Database::open("/var/lib/example/state.sqlite", Options::default()).await?;
//! db.write(|tx| {
//!     tx.execute("CREATE TABLE IF NOT EXISTS notes (body TEXT NOT NULL)", [])?;
//!     tx.execute("INSERT INTO notes (body) VALUES (?1)", ["hello"])?;
//!     Ok::<_, infraternal_db::Error>(())
//! })
//! .await?;
//! let count: i64 = db
//!     .read(|tx| Ok::<_, infraternal_db::Error>(tx.query_row("SELECT count(*) FROM notes", [], |row| row.get(0))?))
//!     .await?;
//! # let _ = count;
//! # Ok(())
//! # }
//! ```
//!
//! Slice 1 of the port: nothing in the server uses this crate on a request
//! path yet. The server still runs on sqlx; this crate is measured and tested
//! next to it first.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod migrate;
mod pool;

pub use migrate::{MigrateError, Migration, Report};
pub use pool::{Database, Error, Options};
/// The rusqlite types a closure works with, re-exported so callers depend on
/// exactly the rusqlite this crate was built against.
pub use rusqlite;

#[cfg(test)]
mod migrate_tests;
#[cfg(test)]
mod pool_tests;
