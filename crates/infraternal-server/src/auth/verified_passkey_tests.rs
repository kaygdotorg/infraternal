//! Exercises proof-only real `WebAuthn` verification without browser-session creation, including replay, deletion and cancellation [168], #78.
use super::*;

#[tokio::test]
async fn verified_passkey_has_live_registered_identity_and_creates_no_session() {
    let mut f = fixture().await;
    let start = f.auth.login_start(&f.user, NOW).await.unwrap();
    let proof = f.software.login(&start, ORIGIN, true);
    let verified = f
        .auth
        .verify_passkey(str_field(&start, "ceremony"), proof.clone(), NOW)
        .await
        .unwrap();
    assert_eq!(verified.user(), f.user);
    assert_eq!(verified.credential(), B64.encode(&f.software.id));
    assert_eq!(verified.verified_at(), NOW);
    assert_eq!(verified.expires(), NOW + 300);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert!(
        f.auth
            .verify_passkey(str_field(&start, "ceremony"), proof, NOW)
            .await
            .is_err()
    );
    assert!(f.auth.session(&f.session, NOW).await.is_ok());
}
#[tokio::test]
async fn proof_only_verification_refuses_missing_uv_or_deleted_credential() {
    for delete in [false, true] {
        let mut f = fixture().await;
        let start = f.auth.login_start(&f.user, NOW).await.unwrap();
        let proof = f.software.login(&start, ORIGIN, delete);
        if delete {
            sqlx::query("DELETE FROM passkeys WHERE user_id=?")
                .bind(&f.user)
                .execute(&f.auth.pool)
                .await
                .unwrap();
        }
        assert!(
            f.auth
                .verify_passkey(str_field(&start, "ceremony"), proof, NOW)
                .await
                .is_err()
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }
}
#[tokio::test]
async fn canceled_proof_before_writer_admission_leaves_no_new_session_or_pending_ceremony() {
    let mut f = fixture().await;
    let start = f.auth.login_start(&f.user, NOW).await.unwrap();
    let id = str_field(&start, "ceremony").to_owned();
    let proof = f.software.login(&start, ORIGIN, true);
    // This real one-connection SQLite pool pins the verifier at its writer boundary.
    let tx = f.auth.pool.begin().await.unwrap();
    let auth = f.auth.clone();
    let called = id.clone();
    let task = tokio::spawn(async move { auth.verify_passkey(&called, proof, NOW).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !f.auth.pending.lock().await.logins.contains_key(&id) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    match task.await {
        Err(error) => assert!(error.is_cancelled()),
        Ok(_) => panic!("canceled verifier unexpectedly completed"),
    }
    tx.rollback().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert!(!f.auth.pending.lock().await.logins.contains_key(&id));
}

#[tokio::test]
async fn proof_only_verification_preserves_monotone_registered_credential_counter() {
    let mut f = fixture().await;
    let first = f.auth.login_start(&f.user, NOW).await.unwrap();
    let proof = f.software.login(&first, ORIGIN, true);
    assert!(
        f.auth
            .verify_passkey(str_field(&first, "ceremony"), proof, NOW)
            .await
            .is_ok()
    );
    let second = f.auth.login_start(&f.user, NOW + 1).await.unwrap();
    f.software.counter -= 1;
    let stale = f.software.login(&second, ORIGIN, true);
    assert!(
        f.auth
            .verify_passkey(str_field(&second, "ceremony"), stale, NOW + 1)
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn proof_only_ceremony_expiring_during_writer_wait_cannot_commit_a_counter_or_session() {
    use std::sync::atomic::{AtomicI64, Ordering};
    let mut f = fixture().await;
    let start = f.auth.login_start(&f.user, NOW).await.unwrap();
    let id = str_field(&start, "ceremony").to_owned();
    let proof = f.software.login(&start, ORIGIN, true);
    let held = f.auth.pool.begin().await.unwrap();
    let clock = Arc::new(AtomicI64::new(NOW));
    let observed = clock.clone();
    let auth = f.auth.clone();
    let called = id.clone();
    let task = tokio::spawn(async move {
        auth.verify_passkey_clock(&called, proof, || Ok(observed.load(Ordering::SeqCst)))
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !f.auth.pending.lock().await.logins.contains_key(&id) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    clock.store(NOW + 300, Ordering::SeqCst);
    held.rollback().await.unwrap();
    assert!(task.await.unwrap().is_err());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    // A different live challenge can still authenticate the next legitimate count.
    let next = f.auth.login_start(&f.user, NOW + 301).await.unwrap();
    f.software.counter -= 1;
    let proof = f.software.login(&next, ORIGIN, true);
    assert!(
        f.auth
            .verify_passkey(str_field(&next, "ceremony"), proof, NOW + 301)
            .await
            .is_ok()
    );
}
