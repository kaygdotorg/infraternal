//! Exercises host-bound invitations with real file-backed SQLite and concurrent transactions [64][133][134].
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(feature = "remote")]

use infraternal_server::enrollment::{
    CertificateRecord, EnrollmentError, EnrollmentStore, JoinToken, Mode,
};
use sha2::{Digest, Sha256};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{path::PathBuf, time::Duration};
use uuid::Uuid;

struct Database {
    pool: SqlitePool,
    path: PathBuf,
    host: Uuid,
}

impl Database {
    async fn new() -> Self {
        let directory =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/enrollment-tests");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("{}.sqlite", Uuid::new_v4()));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(&path)
                    .create_if_missing(true)
                    .foreign_keys(true)
                    .journal_mode(SqliteJournalMode::Wal)
                    .synchronous(SqliteSynchronous::Normal)
                    .busy_timeout(Duration::from_secs(5)),
            )
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query("INSERT INTO users (id, name, owner, recovery_hash, username, display_name) VALUES ('owner', 'owner', 1, 'test', 'owner', 'Owner')")
            .execute(&pool).await.unwrap();
        let host = Uuid::new_v4();
        sqlx::query("INSERT INTO remote_hosts (id, owner_id, mode, execution_uid, created_at) VALUES (?, 'owner', 'rootless', 1002, 100)")
            .bind(host.as_bytes().as_slice()).execute(&pool).await.unwrap();
        Self { pool, path, host }
    }

    fn store(&self) -> EnrollmentStore {
        EnrollmentStore::new(self.pool.clone())
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        // Connection workers may still be closing; unlink only this fixture's files.
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.path.display()));
        }
    }
}

fn certificate(seed: u8) -> CertificateRecord {
    CertificateRecord {
        fingerprint: [seed; 32],
        issuer_fingerprint: [2; 32],
        public_key: [3; 32],
        not_before: 100,
        not_after: 604_900,
    }
}

fn denied(result: &Result<(), EnrollmentError>) {
    assert!(matches!(result, Err(EnrollmentError::Denied)));
}

async fn issue_bound(store: &EnrollmentStore, host: Uuid, mode: Mode, now: i64) -> JoinToken {
    let digest: [u8; 32] = Sha256::digest([3u8; 32]).into();
    store
        .issue("owner", host, mode, now, &digest)
        .await
        .unwrap()
}

#[tokio::test]
// One sequential capability lifecycle keeps each failed admission tied to the same invitation.
#[allow(clippy::too_many_lines)]
async fn invitation_is_hashed_replaced_and_bound_to_owner_host_mode_and_exact_expiry() {
    let db = Database::new().await;
    let store = db.store();
    assert!(matches!(
        store
            .issue("stranger", db.host, Mode::Rootless, 100, &[0u8; 32])
            .await,
        Err(EnrollmentError::Denied)
    ));
    assert!(matches!(
        store
            .issue("owner", db.host, Mode::Rootful, 100, &[0u8; 32])
            .await,
        Err(EnrollmentError::Denied)
    ));
    for time in [-1, i64::MAX] {
        assert!(matches!(
            store
                .issue("owner", db.host, Mode::Rootless, time, &[0u8; 32])
                .await,
            Err(EnrollmentError::Denied)
        ));
    }
    let old = issue_bound(&store, db.host, Mode::Rootless, 100).await;
    let current = issue_bound(&store, db.host, Mode::Rootless, 100).await;
    let stored: Vec<u8> = sqlx::query_scalar("SELECT digest FROM remote_join_tokens")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        stored,
        Sha256::digest(current.secret().as_bytes()).as_slice()
    );
    assert_eq!(current.secret().len(), 43);
    denied(
        &store
            .redeem(old.secret(), db.host, Mode::Rootless, 100, &certificate(1))
            .await,
    );
    denied(
        &store
            .redeem(
                current.secret(),
                Uuid::new_v4(),
                Mode::Rootless,
                100,
                &certificate(1),
            )
            .await,
    );
    denied(
        &store
            .redeem(
                current.secret(),
                db.host,
                Mode::Rootful,
                100,
                &certificate(1),
            )
            .await,
    );
    denied(
        &store
            .redeem(
                current.secret(),
                db.host,
                Mode::Rootless,
                99,
                &certificate(1),
            )
            .await,
    );
    denied(
        &store
            .redeem(
                current.secret(),
                db.host,
                Mode::Rootless,
                1000,
                &certificate(1),
            )
            .await,
    );
    store
        .redeem(
            current.secret(),
            db.host,
            Mode::Rootless,
            999,
            &certificate(1),
        )
        .await
        .unwrap();
    denied(
        &store
            .redeem(
                current.secret(),
                db.host,
                Mode::Rootless,
                999,
                &certificate(1),
            )
            .await,
    );
}

#[tokio::test]
async fn concurrent_redemption_has_one_winner_and_one_certificate() {
    let db = Database::new().await;
    let store = db.store();
    let token = issue_bound(&store, db.host, Mode::Rootless, 100).await;
    let first = certificate(10);
    let second = certificate(11);
    let (a, b) = tokio::join!(
        store.redeem(token.secret(), db.host, Mode::Rootless, 101, &first),
        store.redeem(token.secret(), db.host, Mode::Rootless, 101, &second),
    );
    assert_ne!(a.is_ok(), b.is_ok());
    denied(&if a.is_ok() { b } else { a });
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM remote_certificates")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn invalid_certificate_and_failed_insert_preserve_the_invitation() {
    let db = Database::new().await;
    let store = db.store();
    let token = issue_bound(&store, db.host, Mode::Rootless, 100).await;
    let mut invalid = certificate(10);
    invalid.not_after -= 1;
    denied(
        &store
            .redeem(token.secret(), db.host, Mode::Rootless, 101, &invalid)
            .await,
    );
    store
        .redeem(
            token.secret(),
            db.host,
            Mode::Rootless,
            101,
            &certificate(10),
        )
        .await
        .unwrap();
    let replacement = issue_bound(&store, db.host, Mode::Rootless, 102).await;
    assert!(matches!(
        store
            .redeem(
                replacement.secret(),
                db.host,
                Mode::Rootless,
                102,
                &certificate(10)
            )
            .await,
        Err(EnrollmentError::Storage(_))
    ));
    store
        .redeem(
            replacement.secret(),
            db.host,
            Mode::Rootless,
            102,
            &certificate(11),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn revocation_tombstone_refuses_existing_and_new_invitations_after_restart() {
    let db = Database::new().await;
    let store = db.store();
    let token = issue_bound(&store, db.host, Mode::Rootless, 100).await;
    sqlx::query("UPDATE remote_hosts SET revoked_at=101 WHERE id=?")
        .bind(db.host.as_bytes().as_slice())
        .execute(&db.pool)
        .await
        .unwrap();
    db.pool.close().await;
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&db.path)
                .foreign_keys(true)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Normal),
        )
        .await
        .unwrap();
    let restarted = EnrollmentStore::new(pool.clone());
    denied(
        &restarted
            .redeem(
                token.secret(),
                db.host,
                Mode::Rootless,
                102,
                &certificate(10),
            )
            .await,
    );
    assert!(matches!(
        restarted
            .issue("owner", db.host, Mode::Rootless, 102, &[0u8; 32])
            .await,
        Err(EnrollmentError::Denied)
    ));
    pool.close().await;
}

#[tokio::test]
async fn malformed_capabilities_and_certificate_overflow_are_refused_before_mutation() {
    let db = Database::new().await;
    let store = db.store();
    let token = issue_bound(&store, db.host, Mode::Rootless, 100).await;
    for secret in ["", "not-a-token", &"A".repeat(44), &"!".repeat(43)] {
        denied(
            &store
                .redeem(secret, db.host, Mode::Rootless, 101, &certificate(10))
                .await,
        );
    }
    let mut invalid = certificate(10);
    invalid.not_before = i64::MAX;
    invalid.not_after = i64::MAX;
    denied(
        &store
            .redeem(token.secret(), db.host, Mode::Rootless, i64::MAX, &invalid)
            .await,
    );
    store
        .redeem(
            token.secret(),
            db.host,
            Mode::Rootless,
            101,
            &certificate(10),
        )
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "explicit 500-host storage measurement; not a remote transport budget"]
async fn enrollment_storage_at_500_hosts() {
    let db = Database::new().await;
    // Performance evidence must use the server's WAL/NORMAL policy, rather
    // than measure fsyncs imposed only by SQLite's DELETE/FULL defaults.
    let journal: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        journal, "wal",
        "measurement must match the server journal policy"
    );
    assert_eq!(
        synchronous, 1,
        "measurement must match the server synchronization policy"
    );
    let store = db.store();
    let before: i64 = sqlx::query_scalar("PRAGMA page_count")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let mut issue = Vec::with_capacity(500);
    let mut redeem = Vec::with_capacity(500);
    for _ in 0..500 {
        let host = Uuid::new_v4();
        sqlx::query("INSERT INTO remote_hosts (id, owner_id, mode, execution_uid, created_at) VALUES (?, 'owner', 'rootless', 1002, 100)")
            .bind(host.as_bytes().as_slice()).execute(&db.pool).await.unwrap();
        let start = std::time::Instant::now();
        let token = issue_bound(&store, host, Mode::Rootless, 100).await;
        issue.push(start.elapsed().as_micros());
        let certificate = CertificateRecord {
            fingerprint: Sha256::digest(host.as_bytes()).into(),
            ..certificate(1)
        };
        let start = std::time::Instant::now();
        store
            .redeem(token.secret(), host, Mode::Rootless, 101, &certificate)
            .await
            .unwrap();
        redeem.push(start.elapsed().as_micros());
    }
    issue.sort_unstable();
    redeem.sort_unstable();
    let after: i64 = sqlx::query_scalar("PRAGMA page_count")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM remote_certificates")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 500);
    let rss = std::fs::read_to_string("/proc/self/status").unwrap();
    let rss = rss.lines().find(|line| line.starts_with("VmRSS:")).unwrap();
    println!(
        "500-host SQLite WAL/NORMAL storage: issue_p50_us={} issue_p99_us={} redeem_p50_us={} redeem_p99_us={} page_delta_bytes={} bytes_per_host={} {} load={}",
        issue[250],
        issue[495],
        redeem[250],
        redeem[495],
        (after - before) * page_size,
        (after - before) * page_size / 500,
        rss,
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    db.pool.close().await;
}
