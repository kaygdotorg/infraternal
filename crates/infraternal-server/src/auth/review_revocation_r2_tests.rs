//! Independent completion-order checks with a real SQLite commit blocked by a reader (#240).

use super::*;
use futures_util::FutureExt;
use std::time::Duration;

#[derive(Clone, Copy)]
enum Departure {
    Panic,
    Timeout,
    Drop,
    Abort,
}

#[tokio::test]
async fn review_r2_panicking_commit_waiter_preserves_publication_order() {
    departed_commit(Departure::Panic, false).await;
}

#[tokio::test]
async fn review_r2_timed_out_commit_waiter_preserves_publication_order() {
    departed_commit(Departure::Timeout, false).await;
}

#[tokio::test]
async fn review_r2_aborted_commit_task_preserves_publication_order() {
    departed_commit(Departure::Abort, false).await;
}

#[tokio::test]
async fn review_r2_cancelled_refused_commit_never_publishes() {
    departed_commit(Departure::Drop, true).await;
}

/// Observe publication after the caller leaves a reader-blocked disk commit.
async fn departed_commit(departure: Departure, refuse: bool) {
    // Reader-blocked commits retain real disk semantics without build-disk load.
    let root = std::env::temp_dir().join("review-r2-commit");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join(format!("{}.sqlite", uuid::Uuid::new_v4()));
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Delete)
        .busy_timeout(Duration::from_secs(5));
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap();
    sqlx::query("CREATE TABLE state(id INTEGER PRIMARY KEY)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE dependent(id INTEGER REFERENCES state(id) DEFERRABLE INITIALLY DEFERRED)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let observer = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let mut reader = observer.begin().await.unwrap();
    let _: i64 = sqlx::query_scalar("SELECT count(*) FROM state")
        .fetch_one(&mut *reader)
        .await
        .unwrap();
    let changes = Arc::new(AccountEvents::default());
    let revocations = Arc::new(AccountEvents::default());
    let mut events = changes.subscribe("a");
    let mut revoked = revocations.subscribe("a");
    let other_change = changes.subscribe("b");
    let other_revocation = revocations.subscribe("b");
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO state VALUES(1)")
        .execute(&mut *tx)
        .await
        .unwrap();
    if refuse {
        sqlx::query("INSERT INTO dependent VALUES(2)")
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    // A deferred constraint can refuse COMMIT before the reader lock matters.
    // Fence its worker explicitly so caller departure precedes that refusal.
    let release_commit = if refuse {
        let (release, blocked) = std::sync::mpsc::channel();
        let mut blocked = Some(blocked);
        tx.lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, move || {
                if let Some(blocked) = blocked.take() {
                    let _ = blocked.recv();
                }
                true
            });
        Some(release)
    } else {
        None
    };
    let commit_changes = changes.clone();
    let mut waiting =
        Box::pin(async move { commit_changes.commit(tx, "a", Some(revocations)).await });
    assert!(waiting.as_mut().now_or_never().is_none());
    assert!(!events.has_changed().unwrap());
    assert!(!revoked.has_changed().unwrap());
    match departure {
        Departure::Panic => {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _waiting = waiting;
                panic!("review caller stops while commit is pending");
            }));
            assert!(result.is_err());
        }
        Departure::Timeout => {
            assert!(tokio::time::timeout(Duration::ZERO, waiting).await.is_err());
        }
        Departure::Drop => drop(waiting),
        Departure::Abort => {
            let task = tokio::spawn(waiting);
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
    }
    // The detached owner cannot publish while another connection still holds a read lock.
    assert!(!events.has_changed().unwrap());
    assert!(!revoked.has_changed().unwrap());
    if let Some(release) = release_commit {
        release.send(()).unwrap();
    }
    reader.rollback().await.unwrap();
    if !refuse {
        tokio::time::timeout(Duration::from_secs(5), async {
            events.changed().await.unwrap();
            revoked.changed().await.unwrap();
        })
        .await
        .unwrap();
    }
    // A new operation on the only connection is ordered after commit/refusal and rollback.
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM state")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, i64::from(!refuse));
    if refuse {
        assert!(!events.has_changed().unwrap());
        assert!(!revoked.has_changed().unwrap());
    }
    assert!(!other_change.has_changed().unwrap());
    assert!(!other_revocation.has_changed().unwrap());
    pool.close().await;
    observer.close().await;
    std::fs::remove_file(path).unwrap();
}
