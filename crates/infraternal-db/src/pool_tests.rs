//! Behaviour tests for the writer queue and the readers (D379, #473).
//!
//! The writer is held busy with a "gate" job where a test needs jobs to wait in
//! the queue. Futures are polled once by hand to put a job in the queue
//! without waiting for its result: one poll is enough for the send to finish
//! when the queue has room.
use crate::{Database, Error, Options};
use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{
        Barrier,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

/// A fresh directory under the system temp dir, removed on drop.
pub(crate) struct TempDir(pub(crate) PathBuf);

impl TempDir {
    /// Create a new empty directory whose name is unique in this process.
    pub(crate) fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "infraternal-db-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    /// The database file inside this directory.
    pub(crate) fn db(&self) -> PathBuf {
        self.0.join("test.sqlite")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The error type test closures use: a pool error, or a deliberate refusal.
#[derive(Debug)]
enum TestError {
    Db(Error),
    Refused,
}

impl From<Error> for TestError {
    fn from(error: Error) -> Self {
        Self::Db(error)
    }
}

impl From<rusqlite::Error> for TestError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Db(Error::Sqlite(error))
    }
}

/// Poll a future exactly once with a waker that does nothing.
fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let mut context = Context::from_waker(Waker::noop());
    future.poll(&mut context)
}

/// Upper bound for any single wait in these tests, so a bug fails instead of hanging.
const PATIENCE: Duration = Duration::from_secs(20);

/// Open a pool on a fresh file with table `t(id INTEGER PRIMARY KEY, v INTEGER)`.
async fn setup(label: &str, options: Options) -> (TempDir, Database) {
    let dir = TempDir::new(label);
    let db = Database::open(dir.db(), options).await.unwrap();
    db.write(|tx| {
        tx.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER NOT NULL)")?;
        Ok::<_, Error>(())
    })
    .await
    .unwrap();
    (dir, db)
}

/// Every value in `t`, in insertion (rowid) order, read on a reader.
async fn values(db: &Database) -> Vec<i64> {
    db.read(|tx| {
        let mut statement = tx.prepare("SELECT v FROM t ORDER BY id")?;
        let rows = statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        Ok::<_, Error>(rows)
    })
    .await
    .unwrap()
}

/// Occupy the writer until the returned sender is dropped or sent to.
/// Returns once the gate job is running (so it is no longer in the queue).
async fn gate_writer(db: &Database) -> (mpsc::Sender<()>, tokio::task::JoinHandle<()>) {
    let (release, wait) = mpsc::channel::<()>();
    let (started, is_started) = tokio::sync::oneshot::channel::<()>();
    let gate_db = db.clone();
    let handle = tokio::spawn(async move {
        gate_db
            .write(move |_| {
                let _ = started.send(());
                let _ = wait.recv_timeout(PATIENCE);
                Ok::<_, Error>(())
            })
            .await
            .unwrap();
    });
    tokio::time::timeout(PATIENCE, is_started)
        .await
        .unwrap()
        .unwrap();
    (release, handle)
}

/// What a generated write job does.
#[derive(Clone, Copy, Debug)]
enum Step {
    Commit,
    Fail,
    Panic,
}

/// Small deterministic generator for the property test (no extra crate).
struct XorShift(u64);

impl XorShift {
    /// The next pseudo-random value (xorshift64).
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Property: for any mix of committing, failing and panicking writes queued
/// behind a busy writer, the committed rows appear in exactly the order the
/// writes were queued, failed and panicked writes leave no rows, and each
/// caller gets its own outcome.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writes_apply_in_queue_order_and_failures_leave_nothing() {
    for seed in 1..=24_u64 {
        let (_dir, db) = setup("order", Options::default()).await;
        let mut rng = XorShift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let steps: Vec<Step> = (0..40)
            .map(|_| match rng.next() % 5 {
                0 => Step::Fail,
                1 => Step::Panic,
                _ => Step::Commit,
            })
            .collect();
        let (release, gate) = gate_writer(&db).await;
        let mut futures = Vec::new();
        for (value, step) in steps.iter().copied().enumerate() {
            let value = i64::try_from(value).unwrap();
            let mut future = Box::pin(db.write(move |tx| {
                tx.execute("INSERT INTO t (v) VALUES (?1)", [value])?;
                match step {
                    Step::Commit => Ok(value),
                    Step::Fail => Err(TestError::Refused),
                    Step::Panic => panic!("closure {value} panicked"),
                }
            }));
            assert!(
                poll_once(future.as_mut()).is_pending(),
                "seed {seed}: job {value} must wait behind the gate"
            );
            futures.push(future);
        }
        release.send(()).unwrap();
        gate.await.unwrap();
        let mut expected = Vec::new();
        for (value, (step, future)) in steps.iter().zip(futures).enumerate() {
            let value = i64::try_from(value).unwrap();
            let outcome = tokio::time::timeout(PATIENCE, future).await.unwrap();
            match (step, outcome) {
                (Step::Commit, Ok(got)) => {
                    assert_eq!(got, value);
                    expected.push(value);
                }
                (Step::Fail, Err(TestError::Refused)) => {}
                (Step::Panic, Err(TestError::Db(Error::Panicked(message)))) => {
                    assert_eq!(message, format!("closure {value} panicked"));
                }
                (step, other) => panic!("seed {seed}: job {value} ({step:?}) returned {other:?}"),
            }
        }
        assert_eq!(values(&db).await, expected, "seed {seed}");
    }
}

/// A write whose caller is gone before it reaches the writer never runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_cancelled_in_the_queue_never_runs() {
    let (_dir, db) = setup("cancel-queued", Options::default()).await;
    let (release, gate) = gate_writer(&db).await;
    let mut cancelled = Box::pin(db.write(|tx| {
        tx.execute("INSERT INTO t (v) VALUES (1)", [])?;
        Ok::<_, Error>(())
    }));
    assert!(poll_once(cancelled.as_mut()).is_pending());
    drop(cancelled);
    let mut kept = Box::pin(db.write(|tx| {
        tx.execute("INSERT INTO t (v) VALUES (2)", [])?;
        Ok::<_, Error>(())
    }));
    assert!(poll_once(kept.as_mut()).is_pending());
    release.send(()).unwrap();
    gate.await.unwrap();
    kept.await.unwrap();
    assert_eq!(values(&db).await, vec![2]);
}

/// A write whose caller leaves while it runs still finishes as one
/// transaction: all of its statements commit, none are lost half-way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_cancelled_while_running_commits_whole() {
    let (_dir, db) = setup("cancel-running", Options::default()).await;
    let (started, is_started) = tokio::sync::oneshot::channel::<()>();
    let (proceed, wait) = mpsc::channel::<()>();
    let writer_db = db.clone();
    let task = tokio::spawn(async move {
        writer_db
            .write(move |tx| {
                tx.execute("INSERT INTO t (v) VALUES (1)", [])?;
                let _ = started.send(());
                let _ = wait.recv_timeout(PATIENCE);
                tx.execute("INSERT INTO t (v) VALUES (2)", [])?;
                Ok::<_, Error>(())
            })
            .await
    });
    tokio::time::timeout(PATIENCE, is_started)
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    proceed.send(()).unwrap();
    // The next write queues behind the cancelled one, so once it returns the
    // cancelled transaction has finished.
    db.write(|_| Ok::<_, Error>(())).await.unwrap();
    assert_eq!(values(&db).await, vec![1, 2]);
}

/// A panic inside a write rolls back its statements, reaches the caller as
/// `Error::Panicked`, and the writer keeps serving later writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panic_in_write_rolls_back_and_writer_survives() {
    let (_dir, db) = setup("panic", Options::default()).await;
    let outcome = db
        .write(|tx| -> Result<(), Error> {
            tx.execute("INSERT INTO t (v) VALUES (1)", [])?;
            panic!("boom");
        })
        .await;
    assert!(
        matches!(outcome, Err(Error::Panicked(ref message)) if message == "boom"),
        "{outcome:?}"
    );
    db.write(|tx| {
        tx.execute("INSERT INTO t (v) VALUES (2)", [])?;
        Ok::<_, Error>(())
    })
    .await
    .unwrap();
    assert_eq!(values(&db).await, vec![2]);
}

/// A panic inside a read reaches the caller and the reader keeps serving.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panic_in_read_is_contained() {
    let (_dir, db) = setup(
        "panic-read",
        Options {
            readers: 1,
            ..Options::default()
        },
    )
    .await;
    let outcome = db
        .read(|_| -> Result<(), Error> { panic!("read boom") })
        .await;
    assert!(
        matches!(outcome, Err(Error::Panicked(ref message)) if message == "read boom"),
        "{outcome:?}"
    );
    assert_eq!(values(&db).await, Vec::<i64>::new());
}

/// A full queue makes callers wait instead of buffering without bound; a
/// caller that gives up while waiting for room leaves nothing behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_write_queue_waits_and_abandoned_waiters_leave_nothing() {
    let (_dir, db) = setup(
        "full",
        Options {
            write_queue: 2,
            ..Options::default()
        },
    )
    .await;
    let (release, gate) = gate_writer(&db).await;
    let insert = |value: i64| {
        db.write(move |tx| {
            tx.execute("INSERT INTO t (v) VALUES (?1)", [value])?;
            Ok::<_, Error>(())
        })
    };
    let mut first = Box::pin(insert(1));
    let mut second = Box::pin(insert(2));
    assert!(poll_once(first.as_mut()).is_pending());
    assert!(poll_once(second.as_mut()).is_pending());
    assert_eq!(db.queued_writes(), 2);
    // The queue holds two jobs, so the third caller waits for room...
    let mut third = Box::pin(insert(3));
    assert!(poll_once(third.as_mut()).is_pending());
    assert_eq!(db.queued_writes(), 2, "a full queue must not grow");
    // ...and when it gives up, its job was never queued.
    drop(third);
    assert_eq!(db.queued_writes(), 2);
    release.send(()).unwrap();
    gate.await.unwrap();
    first.await.unwrap();
    second.await.unwrap();
    // A later write proves the writer drained everything queued before it.
    insert(4).await.unwrap();
    assert_eq!(values(&db).await, vec![1, 2, 4]);
}

/// Every statement in one read sees the same snapshot, even when a write
/// commits between them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_sees_one_snapshot_while_a_write_commits() {
    let (_dir, db) = setup("snapshot", Options::default()).await;
    db.write(|tx| {
        tx.execute("INSERT INTO t (v) VALUES (1)", [])?;
        Ok::<_, Error>(())
    })
    .await
    .unwrap();
    let (first_done, is_first_done) = tokio::sync::oneshot::channel::<()>();
    let (write_done, wait_write) = mpsc::channel::<()>();
    let reader_db = db.clone();
    let read = tokio::spawn(async move {
        reader_db
            .read(move |tx| {
                let before: i64 = tx.query_row("SELECT count(*) FROM t", [], |row| row.get(0))?;
                let _ = first_done.send(());
                let _ = wait_write.recv_timeout(PATIENCE);
                let after: i64 = tx.query_row("SELECT count(*) FROM t", [], |row| row.get(0))?;
                Ok::<_, Error>((before, after))
            })
            .await
    });
    tokio::time::timeout(PATIENCE, is_first_done)
        .await
        .unwrap()
        .unwrap();
    db.write(|tx| {
        tx.execute("INSERT INTO t (v) VALUES (2)", [])?;
        Ok::<_, Error>(())
    })
    .await
    .unwrap();
    write_done.send(()).unwrap();
    assert_eq!(read.await.unwrap().unwrap(), (1, 1));
    assert_eq!(values(&db).await, vec![1, 2]);
}

/// Readers do not wait for a running write and never see its uncommitted rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_skip_uncommitted_writes_without_waiting() {
    let (_dir, db) = setup("uncommitted", Options::default()).await;
    let (started, is_started) = tokio::sync::oneshot::channel::<()>();
    let (proceed, wait) = mpsc::channel::<()>();
    let writer_db = db.clone();
    let write = tokio::spawn(async move {
        writer_db
            .write(move |tx| {
                tx.execute("INSERT INTO t (v) VALUES (1)", [])?;
                let _ = started.send(());
                let _ = wait.recv_timeout(PATIENCE);
                Ok::<_, Error>(())
            })
            .await
    });
    tokio::time::timeout(PATIENCE, is_started)
        .await
        .unwrap()
        .unwrap();
    // The write holds its transaction open; the read must still finish now.
    let seen = tokio::time::timeout(PATIENCE, values(&db)).await.unwrap();
    assert_eq!(seen, Vec::<i64>::new());
    proceed.send(()).unwrap();
    write.await.unwrap().unwrap();
    assert_eq!(values(&db).await, vec![1]);
}

/// A read closure cannot change data: its connection is `query_only`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readers_cannot_write() {
    let (_dir, db) = setup("query-only", Options::default()).await;
    let outcome = db
        .read(|tx| {
            tx.execute("INSERT INTO t (v) VALUES (1)", [])?;
            Ok::<_, Error>(())
        })
        .await;
    assert!(matches!(outcome, Err(Error::Sqlite(_))), "{outcome:?}");
    assert_eq!(values(&db).await, Vec::<i64>::new());
}

/// Reads run on several threads at once: two reads that wait for each other
/// both finish (with one reader thread they would wait forever).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_run_in_parallel() {
    let (_dir, db) = setup(
        "parallel",
        Options {
            readers: 2,
            ..Options::default()
        },
    )
    .await;
    let barrier = std::sync::Arc::new(Barrier::new(2));
    let read = |barrier: std::sync::Arc<Barrier>| {
        db.read(move |_| {
            barrier.wait();
            Ok::<_, Error>(())
        })
    };
    let both = async { tokio::join!(read(barrier.clone()), read(barrier.clone())) };
    let (first, second) = tokio::time::timeout(PATIENCE, both).await.unwrap();
    first.unwrap();
    second.unwrap();
}

/// Every pragma the pool documents is in effect on the writer and the readers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pragmas_are_set_on_every_connection() {
    /// (`journal_mode`, `synchronous`, `foreign_keys`, `busy_timeout`, `cache_size`, `query_only`)
    type Pragmas = (String, i64, i64, i64, i64, i64);
    fn read_pragmas(tx: &rusqlite::Transaction<'_>) -> Result<Pragmas, Error> {
        let get = |name: &str| tx.pragma_query_value(None, name, |row| row.get::<_, i64>(0));
        Ok((
            tx.pragma_query_value(None, "journal_mode", |row| row.get(0))?,
            get("synchronous")?,
            get("foreign_keys")?,
            get("busy_timeout")?,
            get("cache_size")?,
            get("query_only")?,
        ))
    }
    let (_dir, db) = setup(
        "pragmas",
        Options {
            readers: 3,
            ..Options::default()
        },
    )
    .await;
    let writer = db.write(read_pragmas).await.unwrap();
    assert_eq!(writer, ("wal".to_owned(), 1, 1, 5000, -2000, 0));
    for _ in 0..12 {
        let reader = db.read(read_pragmas).await.unwrap();
        assert_eq!(reader, ("wal".to_owned(), 1, 1, 5000, -2000, 1));
    }
}

/// Foreign keys are enforced on the writer: a dangling reference is refused.
/// (The bundled SQLite also defaults them on; the pool sets the pragma anyway
/// so enforcement never depends on how SQLite was compiled.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_keys_are_enforced() {
    let (_dir, db) = setup("fk", Options::default()).await;
    let outcome = db
        .write(|tx| {
            tx.execute_batch(
                "CREATE TABLE parent (id INTEGER PRIMARY KEY);
                 CREATE TABLE child (parent INTEGER NOT NULL REFERENCES parent(id));
                 INSERT INTO child (parent) VALUES (7);",
            )?;
            Ok::<_, Error>(())
        })
        .await;
    assert!(matches!(outcome, Err(Error::Sqlite(_))), "{outcome:?}");
}

/// The pool refuses a database that cannot use WAL instead of silently
/// running in a mode where reads and writes block each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_wal_database_is_refused() {
    let outcome = Database::open(":memory:", Options::default()).await;
    assert!(
        matches!(outcome, Err(Error::NotWal(ref mode)) if mode == "memory"),
        "{outcome:?}"
    );
}

/// Options that would make the pool useless are refused up front.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_options_are_refused() {
    let dir = TempDir::new("options");
    for options in [
        Options {
            readers: 0,
            ..Options::default()
        },
        Options {
            write_queue: 0,
            ..Options::default()
        },
        Options {
            read_queue: 0,
            ..Options::default()
        },
    ] {
        let outcome = Database::open(dir.db(), options).await;
        assert!(
            matches!(outcome, Err(Error::InvalidOptions(_))),
            "{outcome:?}"
        );
    }
}

/// A closure that leaves its own transaction open does not leak it into the
/// next job: the worker rolls it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_left_open_by_a_closure_is_rolled_back() {
    let (_dir, db) = setup("left-open", Options::default()).await;
    // COMMIT ends the pool's transaction early and BEGIN opens one the pool
    // does not know about; the closure then fails.
    let outcome = db
        .write(|tx| {
            tx.execute_batch("COMMIT; BEGIN; INSERT INTO t (v) VALUES (1); SAVEPOINT stray;")?;
            Err::<(), _>(TestError::Refused)
        })
        .await;
    assert!(matches!(outcome, Err(TestError::Refused)), "{outcome:?}");
    // The next write starts in a clean transaction and the stray insert is gone.
    db.write(|tx| {
        tx.execute("INSERT INTO t (v) VALUES (2)", [])?;
        Ok::<_, Error>(())
    })
    .await
    .unwrap();
    assert_eq!(values(&db).await, vec![2]);
}
