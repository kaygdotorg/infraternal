//! The connection pool: one writer thread and N reader threads (D379).
//!
//! # Shape
//!
//! ```text
//!  async callers ──write(closure)──▶ [bounded queue] ──▶ writer thread ── read-write connection
//!               └──read(closure)───▶ [bounded queue] ──▶ reader threads ─ query_only connections (WAL)
//! ```
//!
//! - **One writer.** Every write runs on one OS thread that owns the only
//!   read-write connection. SQLite allows one writer at a time anyway; with
//!   several writer connections they would queue inside SQLite with busy
//!   sleeps, which is where the old pool's long write tails came from (J438,
//!   #473). Here they queue in FIFO order instead, without sleeping.
//! - **N readers.** In WAL mode readers never block the writer and the writer
//!   never blocks readers. Each reader thread owns one connection with
//!   `query_only` on, so a read closure cannot write by mistake.
//! - **A whole transaction per call.** The closure you pass runs inside one
//!   transaction on the worker thread and returns once. There is no
//!   statement-by-statement round trip between your task and the connection.
//!
//! # Guarantees
//!
//! - **Atomic writes.** A write closure runs inside `BEGIN IMMEDIATE`. It
//!   commits only if the closure returns `Ok`. If the closure returns `Err` or
//!   panics, the transaction rolls back and nothing is applied.
//! - **Cancellation.** Dropping the future returned by [`Database::write`] or
//!   [`Database::read`] never leaves a half-applied transaction. The closure
//!   runs entirely on the worker thread, in one call, so it either never
//!   starts or runs to its end. If the caller is already gone when the job
//!   reaches the front of the queue, the job is skipped. If the caller leaves
//!   while the closure is running, the transaction still finishes (commit or
//!   rollback) and only the result is dropped. So a caller that cancels a
//!   write must not assume it did *not* happen.
//! - **Panics stay contained.** A panic inside a closure is caught on the
//!   worker thread. The transaction rolls back, the caller gets
//!   [`Error::Panicked`] and the worker keeps serving the next job.
//! - **Bounded memory.** Each queue holds at most [`Options::write_queue`] or
//!   [`Options::read_queue`] jobs. When a queue is full, callers wait in
//!   `.await` (backpressure) instead of growing a buffer. A caller waiting for
//!   queue space that gives up leaves nothing behind in the queue. Per
//!   connection, SQLite's page cache is capped by [`Options::cache_kib`] and
//!   the prepared-statement cache by [`Options::statement_cache`].
//! - **FIFO writes.** Writes run in the order their `write` calls entered the
//!   queue. Reads have no order between each other.
//!
//! # Rules for closures
//!
//! - Never issue `BEGIN`, `COMMIT`, `ROLLBACK` or `SAVEPOINT` yourself: the pool
//!   owns the transaction. (If a closure does anyway, the worker notices that a
//!   transaction is still open after the job and rolls it back.)
//! - Never block on anything but the database inside a closure (network, other
//!   locks, `.await` via a runtime handle). The writer is shared by every
//!   write in the process; a slow closure delays all of them.
//! - Do not call back into the same [`Database`] from inside a closure and
//!   wait for it: a write that waits for another write deadlocks the writer.
use crate::migrate::{self, Migration, Report};
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};
use std::{
    any::Any,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    thread,
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

/// Settings for [`Database::open`]. [`Options::default`] matches the old
/// sqlx pool: eight connections in total, a 5 s busy timeout and a
/// 100-statement cache per connection.
#[derive(Clone, Debug)]
pub struct Options {
    /// How many reader threads (and reader connections) to start. At least 1.
    pub readers: usize,
    /// How many write jobs may wait in the writer's queue. At least 1.
    pub write_queue: usize,
    /// How many read jobs may wait in the shared reader queue. At least 1.
    pub read_queue: usize,
    /// `PRAGMA busy_timeout`: how long a statement waits for a lock held by
    /// *another process* before it fails with `SQLITE_BUSY`. Inside this
    /// process writes never contend (one writer). Another process can still
    /// hold the lock briefly, for example a second server during an upgrade
    /// handover or the CLI reading the file.
    pub busy_timeout: Duration,
    /// Prepared statements kept per connection for `prepare_cached`.
    pub statement_cache: usize,
    /// `PRAGMA cache_size` in KiB per connection: the most page cache one
    /// connection keeps. 2000 is SQLite's own default and what the old pool
    /// used, written down here so it is a decision, not an accident.
    pub cache_kib: u32,
    /// Create the database file when it does not exist yet.
    pub create_if_missing: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            readers: 7,
            write_queue: 256,
            read_queue: 256,
            busy_timeout: Duration::from_secs(5),
            statement_cache: 100,
            cache_kib: 2000,
            create_if_missing: true,
        }
    }
}

/// What can go wrong when talking to the pool itself. Closures return their
/// own error type `E`; pool errors are converted into it with `E: From<Error>`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// SQLite returned an error (opening, a pragma, `BEGIN`, `COMMIT`, or a
    /// statement inside a closure that used this type as its error).
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The closure panicked. Its transaction was rolled back; the message is
    /// the panic payload when it was a string.
    #[error("database closure panicked: {0}")]
    Panicked(String),
    /// The worker thread is gone, so the job could not run. This only happens
    /// when a worker died outside a closure, which is a bug.
    #[error("database worker stopped")]
    Closed,
    /// The database refused WAL mode (for example an in-memory database or a
    /// filesystem without shared memory). The pool depends on WAL so that
    /// readers and the writer do not block each other.
    #[error("journal mode is {0:?}, expected \"wal\"")]
    NotWal(String),
    /// A pragma did not keep the value the pool set.
    #[error("pragma {0} did not take effect")]
    Pragma(&'static str),
    /// [`Options`] asked for zero readers or a zero-length queue.
    #[error("invalid pool options: {0}")]
    InvalidOptions(&'static str),
    /// The operating system refused to start a worker thread.
    #[error("could not start a database thread: {0}")]
    Spawn(#[source] std::io::Error),
    /// The migration runner refused or failed; see [`migrate::MigrateError`].
    #[error(transparent)]
    Migrate(#[from] migrate::MigrateError),
}

/// One unit of work for a worker thread. It gets the worker's connection and
/// reports its own result through a channel it captured.
type Job = Box<dyn FnOnce(&mut Connection) + Send>;

/// Which kind of connection a worker thread owns.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Writer,
    Reader,
}

/// A handle to the database. Cheap to clone; every clone talks to the same
/// threads. When the last clone is dropped, the worker threads finish the
/// jobs already queued (skipping ones whose caller is gone), close their
/// connections and exit.
#[derive(Clone, Debug)]
pub struct Database {
    writer: mpsc::Sender<Job>,
    readers: mpsc::Sender<Job>,
}

impl Database {
    /// Open (or create) the database at `path` and start the worker threads.
    ///
    /// The writer connection opens first and switches the file to WAL mode;
    /// then the readers open. Every connection gets the same pragmas, set
    /// explicitly and read back (see [`configure`]). Opening runs on the new
    /// threads, so this does not block the async runtime.
    ///
    /// # Errors
    ///
    /// Any [`Error`] from opening a connection, setting a pragma, or starting
    /// a thread. On error no thread is left running.
    pub async fn open(path: impl AsRef<Path>, options: Options) -> Result<Self, Error> {
        if options.readers == 0 {
            return Err(Error::InvalidOptions("readers must be at least 1"));
        }
        if options.write_queue == 0 || options.read_queue == 0 {
            return Err(Error::InvalidOptions("queues must hold at least 1 job"));
        }
        let path: PathBuf = path.as_ref().to_path_buf();
        let options = Arc::new(options);

        let (writer, writer_jobs) = mpsc::channel::<Job>(options.write_queue);
        let ready = spawn_worker(
            "db-writer".to_owned(),
            Role::Writer,
            path.clone(),
            options.clone(),
            Arc::new(Mutex::new(writer_jobs)),
        )?;
        ready.await.map_err(|_| Error::Closed)??;

        // Readers share one queue; whichever reader is free takes the next job.
        let (readers, reader_jobs) = mpsc::channel::<Job>(options.read_queue);
        let reader_jobs = Arc::new(Mutex::new(reader_jobs));
        let mut pending = Vec::with_capacity(options.readers);
        for index in 0..options.readers {
            pending.push(spawn_worker(
                format!("db-reader-{index}"),
                Role::Reader,
                path.clone(),
                options.clone(),
                reader_jobs.clone(),
            )?);
        }
        for ready in pending {
            ready.await.map_err(|_| Error::Closed)??;
        }
        Ok(Self { writer, readers })
    }

    /// Run `f` as one write transaction on the writer thread and return its result.
    ///
    /// The transaction is `BEGIN IMMEDIATE`: it takes SQLite's write lock up
    /// front, so it cannot fail half-way with a lock upgrade error. It commits
    /// when `f` returns `Ok` and rolls back when `f` returns `Err` or panics.
    /// Writes run one at a time, in the order they were queued.
    ///
    /// See the module docs for what cancelling the returned future means.
    ///
    /// # Errors
    ///
    /// `f`'s own error, or a pool [`Error`] (failed `BEGIN`/`COMMIT`, a panic,
    /// a stopped worker) converted with `E: From<Error>`.
    pub async fn write<T, E, F>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce(&Transaction<'_>) -> Result<T, E> + Send + 'static,
        T: Send + 'static,
        E: From<Error> + Send + 'static,
    {
        submit(&self.writer, move |conn| {
            in_transaction(conn, TransactionBehavior::Immediate, f)
        })
        .await
        .unwrap_or_else(|error| Err(E::from(error)))
    }

    /// Run `f` as one read transaction on a free reader thread.
    ///
    /// The transaction is a deferred `BEGIN`, so every statement inside `f`
    /// reads the same snapshot of the database, even when writes commit in
    /// between. The connection is `query_only`: any write fails with an error
    /// instead of changing data.
    ///
    /// # Errors
    ///
    /// `f`'s own error, or a pool [`Error`] converted with `E: From<Error>`.
    pub async fn read<T, E, F>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce(&Transaction<'_>) -> Result<T, E> + Send + 'static,
        T: Send + 'static,
        E: From<Error> + Send + 'static,
    {
        submit(&self.readers, move |conn| {
            in_transaction(conn, TransactionBehavior::Deferred, f)
        })
        .await
        .unwrap_or_else(|error| Err(E::from(error)))
    }

    /// How many write jobs wait in the queue right now (tests only).
    #[cfg(test)]
    pub(crate) fn queued_writes(&self) -> usize {
        self.writer.max_capacity() - self.writer.capacity()
    }

    /// Bring the schema up to date with `migrations` on the writer thread.
    ///
    /// Runs [`migrate::run`] with the writer's connection, so it is ordered
    /// with every other write. Call it once at startup, before serving.
    ///
    /// # Errors
    ///
    /// [`Error::Migrate`] when the history is refused (dirty row, unknown or
    /// changed migration) or a migration fails; other [`Error`]s as for writes.
    pub async fn migrate(&self, migrations: &'static [Migration]) -> Result<Report, Error> {
        submit(&self.writer, move |conn| migrate::run(conn, migrations))
            .await?
            .map_err(Error::Migrate)
    }
}

/// Run `f` inside a transaction of the given kind on `conn`; commit on `Ok`.
///
/// On `Err` the transaction is dropped, which rolls it back. On panic the
/// transaction is dropped while unwinding, which also rolls it back; the
/// caller ([`submit`]'s job) catches the panic.
fn in_transaction<T, E, F>(
    conn: &mut Connection,
    behavior: TransactionBehavior,
    f: F,
) -> Result<T, E>
where
    F: FnOnce(&Transaction<'_>) -> Result<T, E>,
    E: From<Error>,
{
    let tx = conn
        .transaction_with_behavior(behavior)
        .map_err(|error| E::from(Error::Sqlite(error)))?;
    let value = f(&tx)?;
    tx.commit().map_err(|error| E::from(Error::Sqlite(error)))?;
    Ok(value)
}

/// Queue `run` for a worker and wait for its result.
///
/// Waiting for queue space is cancellation-safe: if this future is dropped
/// while the queue is full, nothing was queued. Once queued, the job checks
/// whether this future still exists right before it starts and skips itself
/// if not. Panics inside `run` are caught and returned as [`Error::Panicked`].
async fn submit<T, R>(queue: &mpsc::Sender<Job>, run: R) -> Result<T, Error>
where
    R: FnOnce(&mut Connection) -> T + Send + 'static,
    T: Send + 'static,
{
    let (reply, result) = oneshot::channel::<thread::Result<T>>();
    let job: Job = Box::new(move |conn| {
        if reply.is_closed() {
            // The caller dropped its future before the job started: skip it,
            // so a cancelled call never starts a transaction.
            return;
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| run(conn)));
        // The caller may have left while the closure ran; the transaction is
        // already finished either way, so a closed channel is fine.
        let _ = reply.send(outcome);
    });
    queue.send(job).await.map_err(|_| Error::Closed)?;
    match result.await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(payload)) => Err(Error::Panicked(panic_message(payload.as_ref()))),
        // The job was dropped without replying: its worker is gone.
        Err(_) => Err(Error::Closed),
    }
}

/// The text of a panic payload when it is a string, for [`Error::Panicked`].
fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

/// Start one worker thread that opens its connection, reports readiness on
/// the returned channel, then runs jobs from `jobs` until every sender is gone.
///
/// Reader threads share one receiver behind a mutex: the reader holding the
/// lock waits for the next job, takes it, and releases the lock before it
/// runs the job, so the other readers can pick up the following ones.
fn spawn_worker(
    name: String,
    role: Role,
    path: PathBuf,
    options: Arc<Options>,
    jobs: Arc<Mutex<mpsc::Receiver<Job>>>,
) -> Result<oneshot::Receiver<Result<(), Error>>, Error> {
    let (ready, opened) = oneshot::channel();
    thread::Builder::new()
        .name(name)
        .spawn(move || {
            let mut conn = match open_connection(&path, &options, role) {
                Ok(conn) => conn,
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return;
                }
            };
            if ready.send(Ok(())).is_err() {
                return;
            }
            loop {
                // The guard lives only for this statement, never while a job runs.
                let job = jobs
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .blocking_recv();
                let Some(job) = job else { break };
                job(&mut conn);
                if !conn.is_autocommit() {
                    // A closure left a transaction open (it issued BEGIN or
                    // SAVEPOINT itself). Roll it back so the next job starts clean.
                    let _ = conn.execute_batch("ROLLBACK");
                }
            }
        })
        .map_err(Error::Spawn)?;
    Ok(opened)
}

/// Open one connection to `path` and configure it for `role`.
///
/// Flags: read-write (plus create when asked), `NO_MUTEX` because exactly one
/// thread ever uses each connection, a private page cache, and URI filenames,
/// the same flags the old sqlx pool used.
fn open_connection(path: &Path, options: &Options, role: Role) -> Result<Connection, Error> {
    let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
        | OpenFlags::SQLITE_OPEN_URI;
    if options.create_if_missing && role == Role::Writer {
        flags |= OpenFlags::SQLITE_OPEN_CREATE;
    }
    let conn = Connection::open_with_flags(path, flags)?;
    configure(&conn, options, role)?;
    Ok(conn)
}

/// Set every pragma the pool depends on, explicitly, and read each one back.
///
/// - `busy_timeout` ([`Options::busy_timeout`]): wait for another process's
///   lock instead of failing at once.
/// - `journal_mode = WAL`: readers and the writer do not block each other,
///   and a commit writes the WAL instead of rewriting pages in place. It is
///   persistent in the file; setting it again on readers is a no-op that
///   confirms it.
/// - `synchronous = NORMAL`: in WAL mode a commit does not wait for fsync;
///   the WAL is synced at checkpoints. A power loss can lose the last commits
///   but never corrupts the file. Same choice as the old pool.
/// - `foreign_keys = ON`: SQLite leaves them off by default; the schema relies
///   on them. Set per connection, outside any transaction.
/// - `cache_size` ([`Options::cache_kib`]): caps page cache per connection.
/// - `query_only = ON` on readers only: a read closure cannot write.
fn configure(conn: &Connection, options: &Options, role: Role) -> Result<(), Error> {
    conn.busy_timeout(options.busy_timeout)?;
    let mode: String =
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(Error::NotWal(mode));
    }
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    // SQLite reports synchronous as a number: NORMAL is 1.
    expect_pragma(conn, "synchronous", 1)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    expect_pragma(conn, "foreign_keys", 1)?;
    let cache = -i64::from(options.cache_kib);
    conn.pragma_update(None, "cache_size", cache)?;
    expect_pragma(conn, "cache_size", cache)?;
    if role == Role::Reader {
        conn.pragma_update(None, "query_only", true)?;
        expect_pragma(conn, "query_only", 1)?;
    }
    conn.set_prepared_statement_cache_capacity(options.statement_cache);
    Ok(())
}

/// Read an integer pragma back and fail with [`Error::Pragma`] if it differs.
fn expect_pragma(conn: &Connection, name: &'static str, expected: i64) -> Result<(), Error> {
    let actual: i64 = conn.pragma_query_value(None, name, |row| row.get(0))?;
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Pragma(name))
    }
}
