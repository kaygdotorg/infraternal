//! The connection pool: one writer thread and N reader threads (D379).
//!
//! # Shape
//!
//! ```text
//!  async callers ──write(closure)──▶ [bounded queue] ──▶ writer thread ── read-write connection
//!               └──read(closure)───▶ [bounded queue] ──▶ reader threads ─ read-only connections (WAL)
//!                                    writer's WAL hook ──kick──▶ checkpointer thread ── its own connection
//! ```
//!
//! - **One writer.** Every write runs on one OS thread that owns the only
//!   read-write connection. SQLite allows one writer at a time anyway; with
//!   several writer connections they would queue inside SQLite with busy
//!   sleeps, which is where the old pool's long write tails came from (J438,
//!   #473). Here they queue in FIFO order instead, without sleeping.
//! - **N readers.** In WAL mode readers never block the writer and the writer
//!   never blocks readers. Each reader thread owns one connection opened
//!   read-only, so a read closure cannot write, even on purpose.
//! - **A whole transaction per call.** The closure you pass runs inside one
//!   transaction on the worker thread and returns once. There is no
//!   statement-by-statement round trip between your task and the connection.
//! - **Checkpoints off the write path.** A WAL database has to copy the
//!   log back into the main file now and then (a *checkpoint*), or the log
//!   grows without end. SQLite's built-in auto-checkpoint does this inside the
//!   commit that pushes the log past 1,000 pages, on the committing thread,
//!   including an fsync. Here that thread is the one writer, so every write
//!   queued behind it waited: J449 measured a 1-task session-slide p999 of
//!   25.5 ms against 96 µs on sqlx, and J619 split the slow ops into 3.6–6.3 ms
//!   inside the job, recurring every ~1,000 slides (#473). So the writer
//!   replaces the auto-checkpoint with a WAL hook that only *kicks* a
//!   dedicated checkpointer thread, which checkpoints on its own connection
//!   while the writer keeps committing (WAL allows a checkpoint and a writer at
//!   the same time). See [`Options::checkpoint_pages`].
//!
//!   Why not autocommit for single statements, which measured just as fast:
//!   SQLite only runs the WAL hook when an autocommit statement is stepped to
//!   its end, and `UPDATE … RETURNING` read with `query_row` is reset after
//!   its first row. That path never checkpoints at all, so its speed came from
//!   skipping the work: the WAL reached 99 MB after 20k slides (and today's
//!   sqlx path does the same, 98.7 MB). Every write here is a transaction
//!   whose `COMMIT` always reaches the hook.
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
//! - **A WAL bounded while the pool owns the file.** While this pool is the
//!   only writer and no read transaction stays open for long, the WAL stays
//!   below about [`Options::checkpoint_limit_pages`] pages, even when writes
//!   never pause. Two things suspend the bound, because of how SQLite's WAL
//!   works, not because of this pool:
//!   - **A long read.** A read transaction, on a pool reader or in another
//!     process, pins every frame committed after its snapshot: no checkpoint
//!     may copy them, and the log cannot rewind while the read is open. The
//!     WAL grows for as long as the read lasts (J632 measured ~50× a 32-page
//!     limit).
//!   - **A second writer on the same file**, such as the sqlx pool while
//!     both drivers share the database during the port, or another process.
//!     Its commits don't pass through this pool's WAL hook (J632 measured
//!     ~9,700 pages against the 8,000-page limit).
//!
//!   Both are temporary. Once the read ends or the other writer stops, the
//!   next checkpoint copies the backlog and the next write rewinds the log.
//!   The writer's `journal_size_limit` (see [`configure`]) then truncates the
//!   file back to the limit, so the disk space comes back as well.
//! - **FIFO writes.** Writes run in the order their `write` calls entered the
//!   queue. Reads have no order between each other.
//!
//! # Rules for closures
//!
//! - Never issue `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT` or `RELEASE`
//!   yourself: the pool owns the transaction. SQLite refuses to prepare them
//!   while a closure runs (an authorizer on every worker connection, see
//!   [`install_transaction_guard`]), so the statement fails with an
//!   authorization error and the transaction stays the pool's. Without that
//!   guard, a closure that ran `COMMIT; BEGIN;` and then returned `Err` would
//!   make the rows it wrote before the `COMMIT` durable (J632, #473).
//! - Never block on anything but the database inside a closure (network, other
//!   locks, `.await` via a runtime handle). The writer is shared by every
//!   write in the process; a slow closure delays all of them.
//! - Do not call back into the same [`Database`] from inside a closure and
//!   wait for it: a write that waits for another write deadlocks the writer.
use crate::migrate::{self, Migration, Report};
use rusqlite::{
    Connection, OpenFlags, Transaction, TransactionBehavior,
    hooks::{AuthAction, AuthContext, Authorization, Wal},
    wal::CheckpointMode,
};
use std::{
    any::Any,
    ffi::c_int,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError,
        mpsc::{Receiver, SyncSender, sync_channel},
    },
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
    /// WAL size, in pages, at which a commit asks the checkpointer thread for
    /// a pass. 1,000 is SQLite's own auto-checkpoint threshold. The commit
    /// itself only sends a wake-up and never waits for the checkpoint.
    /// At least 1.
    pub checkpoint_pages: u32,
    /// WAL size, in pages, at which the writer checkpoints inline, on the
    /// commit path, the way SQLite's auto-checkpoint always would.
    ///
    /// This is a backstop. A checkpoint running next to a busy writer copies
    /// everything up to the moment it started, but SQLite only rewinds the
    /// WAL to its start when *every* frame has been copied. A writer that
    /// never pauses keeps adding frames during each pass, so the WAL could
    /// grow without end. At this limit the writer catches the log up itself,
    /// and its next write rewinds it. At the default 8,000 pages (about
    /// 32 MiB with 4 KiB pages) that happens only under sustained write load.
    ///
    /// The bound holds while this pool is the file's only writer and no
    /// read stays open for long (module docs, "Guarantees"). The same size is
    /// the writer's `journal_size_limit`, so a WAL that grew past it during a
    /// long read shrinks back once the log rewinds.
    pub checkpoint_limit_pages: u32,
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
            checkpoint_pages: 1000,
            checkpoint_limit_pages: 8000,
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
    /// The connection that runs background checkpoints for the writer.
    Checkpointer,
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
        if options.checkpoint_pages == 0 || options.checkpoint_limit_pages == 0 {
            return Err(Error::InvalidOptions(
                "checkpoint thresholds must be at least 1 page",
            ));
        }
        let path: PathBuf = path.as_ref().to_path_buf();
        let options = Arc::new(options);

        // One pending kick is enough: a checkpoint pass copies everything
        // committed before it starts, so kicks that arrive while one is
        // queued would only repeat it.
        let (kick, kicks) = sync_channel::<()>(1);
        let (writer, writer_jobs) = mpsc::channel::<Job>(options.write_queue);
        let ready = spawn_worker(
            "db-writer".to_owned(),
            Role::Writer,
            path.clone(),
            options.clone(),
            Arc::new(Mutex::new(writer_jobs)),
            Some(kick),
        )?;
        ready.await.map_err(|_| Error::Closed)??;
        // After the writer, so the file exists and is already in WAL mode.
        spawn_checkpointer(path.clone(), options.clone(), kicks)?
            .await
            .map_err(|_| Error::Closed)??;

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
                None,
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
    /// between. The connection is opened read-only: any write fails with an
    /// error instead of changing data.
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
    // Declared after `tx`, so it drops first on every exit path (`Err` and
    // unwinding included): the pool's own COMMIT or ROLLBACK runs with the
    // guard lowered.
    let guard = ClosureRunning::enter();
    let value = f(&tx)?;
    drop(guard);
    tx.commit().map_err(|error| E::from(Error::Sqlite(error)))?;
    Ok(value)
}

thread_local! {
    /// Whether a user closure is running on this worker thread right now.
    /// [`install_transaction_guard`]'s authorizer reads it. A thread-local
    /// is enough because each connection is used by exactly one thread.
    static IN_CLOSURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Marks this thread as running a user closure until dropped.
struct ClosureRunning;

impl ClosureRunning {
    /// Raise the flag; it is lowered again when the returned guard drops.
    fn enter() -> Self {
        IN_CLOSURE.with(|flag| flag.set(true));
        Self
    }
}

impl Drop for ClosureRunning {
    fn drop(&mut self) {
        IN_CLOSURE.with(|flag| flag.set(false));
    }
}

/// Make transaction control unpreparable while a closure runs (J632, #473).
///
/// The pool's guarantee is "a write commits only if its closure returns
/// `Ok`". A closure that could run `COMMIT` itself would break it: whatever it
/// wrote before the `COMMIT` is durable even if it then returns `Err`. So every
/// worker connection gets an authorizer that denies `BEGIN`, `COMMIT`,
/// `ROLLBACK`, `SAVEPOINT` and `RELEASE` while [`IN_CLOSURE`] is set; the
/// statement then fails to prepare with an authorization error.
///
/// The authorizer stays installed for the connection's life and checks the
/// flag, instead of being installed around each closure: setting an authorizer
/// expires every prepared statement on the connection, which would empty the
/// statement cache on every job. SQLite calls the authorizer only while it
/// prepares a statement, never while it runs one, so cached statements pay
/// nothing.
fn install_transaction_guard(conn: &mut Connection) -> Result<(), Error> {
    conn.authorizer(Some(|context: AuthContext<'_>| match context.action {
        AuthAction::Transaction { .. } | AuthAction::Savepoint { .. }
            if IN_CLOSURE.with(std::cell::Cell::get) =>
        {
            Authorization::Deny
        }
        _ => Authorization::Allow,
    }))?;
    Ok(())
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
///
/// The writer gets `kick`, the checkpointer's wake-up channel, for its WAL
/// hook (see [`install_checkpoint_hook`]); readers get `None`.
fn spawn_worker(
    name: String,
    role: Role,
    path: PathBuf,
    options: Arc<Options>,
    jobs: Arc<Mutex<mpsc::Receiver<Job>>>,
    kick: Option<SyncSender<()>>,
) -> Result<oneshot::Receiver<Result<(), Error>>, Error> {
    let (ready, opened) = oneshot::channel();
    thread::Builder::new()
        .name(name)
        .spawn(move || {
            let opened = open_connection(&path, &options, role).and_then(|mut conn| {
                install_transaction_guard(&mut conn)?;
                if let Some(kick) = kick {
                    install_checkpoint_hook(&mut conn, &options, kick)?;
                }
                Ok(conn)
            });
            let mut conn = match opened {
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
                    // Defence in depth: the transaction guard already stops a
                    // closure from opening its own transaction, but if one is
                    // still open here (a SQLite path the authorizer does not
                    // see), roll it back so the next job starts clean.
                    let _ = conn.execute_batch("ROLLBACK");
                }
            }
        })
        .map_err(Error::Spawn)?;
    Ok(opened)
}

/// Replace SQLite's auto-checkpoint on the writer with a hook that hands the
/// work to the checkpointer thread (see the module docs, "Checkpoints off the
/// write path").
///
/// SQLite calls the hook after every commit with the WAL's size in pages.
/// Below [`Options::checkpoint_pages`] it does nothing. From there it sends a
/// wake-up without blocking (a full channel means a pass is already pending).
/// At [`Options::checkpoint_limit_pages`] it checkpoints inline as the
/// backstop. Installing a hook switches SQLite's own auto-checkpoint off,
/// because both use the same slot; `PRAGMA wal_autocheckpoint` then reads 0.
///
/// The hook always reports success. Its result would become the result of
/// the `COMMIT` that triggered it, and that commit has already happened, so
/// a failed checkpoint must not turn it into an error. SQLite's own
/// auto-checkpoint ignores checkpoint errors the same way. A checkpoint that
/// fails is simply retried after the next commit.
fn install_checkpoint_hook(
    conn: &mut Connection,
    options: &Options,
    kick: SyncSender<()>,
) -> Result<(), Error> {
    let soft = c_int::try_from(options.checkpoint_pages).unwrap_or(c_int::MAX);
    let hard = c_int::try_from(options.checkpoint_limit_pages).unwrap_or(c_int::MAX);
    conn.wal_hook(Some(move |wal: &mut Wal, pages: c_int| {
        if pages >= hard {
            let _ = wal.checkpoint_v2(CheckpointMode::PASSIVE);
        } else if pages >= soft {
            let _ = kick.try_send(());
        }
        Ok(())
    }))?;
    Ok(())
}

/// Start the checkpointer thread: it opens its own connection, reports
/// readiness, then runs one PASSIVE checkpoint per kick from the writer's WAL
/// hook until the writer's connection (which owns the sending side) is gone.
///
/// A PASSIVE checkpoint never waits for locks: it copies every WAL frame that
/// no reader still needs and leaves the rest for the next pass. It runs at the
/// same time as the writer's commits, so its fsync is no longer on the write
/// path. Errors are ignored for the reason given in
/// [`install_checkpoint_hook`]; the inline backstop still bounds the WAL if
/// this thread keeps failing.
fn spawn_checkpointer(
    path: PathBuf,
    options: Arc<Options>,
    kicks: Receiver<()>,
) -> Result<oneshot::Receiver<Result<(), Error>>, Error> {
    let (ready, opened) = oneshot::channel();
    thread::Builder::new()
        .name("db-checkpoint".to_owned())
        .spawn(move || {
            let conn = match open_connection(&path, &options, Role::Checkpointer) {
                Ok(conn) => conn,
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return;
                }
            };
            if ready.send(Ok(())).is_err() {
                return;
            }
            while kicks.recv().is_ok() {
                let _ = conn.wal_checkpoint_v2(None::<&str>, CheckpointMode::PASSIVE);
            }
        })
        .map_err(Error::Spawn)?;
    Ok(opened)
}

/// Open one connection to `path` and configure it for `role`.
///
/// Flags: `NO_MUTEX` because exactly one thread ever uses each connection, a
/// private page cache, and URI filenames, the same flags the old sqlx pool
/// used. The writer and the checkpointer open read-write (the writer also
/// creates the file when asked). Readers open **read-only**: SQLite then
/// refuses every write on that connection, whatever a closure does to its
/// pragmas. `query_only` alone was not enough, because a closure can switch it
/// off (J632, #473). A read-only connection still reads a WAL database
/// normally: the writer, which always opens first, has already created the
/// `-wal` and `-shm` files.
fn open_connection(path: &Path, options: &Options, role: Role) -> Result<Connection, Error> {
    let access = if role == Role::Reader {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };
    let mut flags = access
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
/// - `journal_size_limit` on the writer only: the WAL file shrinks back to
///   [`Options::checkpoint_limit_pages`] after it rewinds (see
///   [`wal_size_limit`]).
/// - `query_only = ON` on readers only. Readers are opened read-only anyway
///   (see [`open_connection`]). This is a second layer, and makes a stray write
///   fail with a clear "query only" error first.
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
    if role == Role::Writer {
        let limit = wal_size_limit(conn, options)?;
        conn.pragma_update(None, "journal_size_limit", limit)?;
        expect_pragma(conn, "journal_size_limit", limit)?;
    }
    conn.set_prepared_statement_cache_capacity(options.statement_cache);
    Ok(())
}

/// The writer's `journal_size_limit` in bytes: a WAL of
/// [`Options::checkpoint_limit_pages`] frames (a 32-byte header, then each
/// frame is a 24-byte header plus one page).
///
/// SQLite never shrinks the WAL file on its own while the database is open.
/// It reuses the file from the start each time the log rewinds, so the file
/// keeps its high-water mark. With this limit, the first commit after a rewind
/// truncates a larger file back to this size. A WAL that grew during a long
/// read gives its disk space back once the read ends. The truncation costs one
/// `fstat` per rewind, plus an `ftruncate` only when the file is over the
/// limit.
fn wal_size_limit(conn: &Connection, options: &Options) -> Result<i64, Error> {
    let page: i64 = conn.pragma_query_value(None, "page_size", |row| row.get(0))?;
    Ok(i64::from(options.checkpoint_limit_pages)
        .saturating_mul(page.saturating_add(24))
        .saturating_add(32))
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
