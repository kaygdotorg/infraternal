//! Real SQLite proofs of the promotion record (J415 R1, R3, R5, R7, B2, B9).
//!
//! Each test starts from the shared fixture: host 42, rootless as uid 1002,
//! with one active certificate `[1; 32]` for key `[3; 32]`, owned by the
//! server owner, whose session `s` is unlocked and inside its admin window.
use super::*;
use crate::enrollment::{Mode, authority::tests::enrolled};
use sqlx::SqlitePool;

/// The fixture's unlocked owner session, its admin window opened at 150.
async fn session(pool: &SqlitePool, hash: &str, fresh: i64) {
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,'owner','fixture',100000,?,1)")
        .bind(hash)
        .bind(fresh)
        .execute(pool)
        .await
        .unwrap();
}

/// The binding of the fixture's live rootless link.
fn bound() -> Bound {
    Bound {
        from_uid: 1002,
        from_fingerprint: [1; 32],
        link_generation: Uuid::from_u128(5),
    }
}

/// A signed successor certificate for key `key`.
fn successor(seed: u8, key: u8, now: i64) -> CertificateRecord {
    CertificateRecord {
        fingerprint: [seed; 32],
        issuer_fingerprint: [9; 32],
        public_key: crate::identity_key::IdentityKey::Ed25519([key; 32]),
        not_before: now,
        not_after: now + 604_800,
    }
}

/// A promotion of the fixture host driven to `enrolled`, its successor
/// certificate `[7; 32]` for key `[8; 32]`.
async fn enrolled_promotion(store: &EnrollmentStore, host: Uuid, attempt: Uuid, now: i64) {
    store
        .begin_promotion("s", host, attempt, Method::Sudo, bound(), now)
        .await
        .unwrap();
    store.reserve_try("s", attempt, true, now).await.unwrap();
    store
        .settle_try(attempt, Settled::Rooted, now)
        .await
        .unwrap();
    let token = store
        .issue_successor_token(attempt, &Sha256::digest([8u8; 32]).into(), now)
        .await
        .unwrap();
    assert_eq!(
        store
            .preflight_successor(token.secret(), host, now)
            .await
            .unwrap(),
        <[u8; 32]>::from(Sha256::digest([8u8; 32]))
    );
    store
        .redeem_successor(token.secret(), host, now, &successor(7, 8, now))
        .await
        .unwrap();
}

/// R1: a successor certificate is never admitted as the host's agent, and an
/// ordinary certificate never passes the successor check.
#[tokio::test]
async fn a_successor_is_admitted_only_by_its_own_check() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    let attempt = Uuid::from_u128(77);
    enrolled_promotion(&store, host, attempt, 200).await;
    assert!(matches!(
        store.admit(&[7; 32], 201).await,
        Err(EnrollmentError::Denied)
    ));
    let admitted = store.admit_successor(&[7; 32], 201).await.unwrap();
    assert_eq!(admitted.host, host);
    assert_eq!(admitted.attempt, attempt);
    assert_eq!(admitted.purpose, SuccessorPurpose::Proof);
    assert_eq!(admitted.not_after, 200 + LIFETIME);
    assert!(store.admit_successor(&[1; 32], 201).await.is_err());
    // The rootless agent is untouched until the handover.
    assert_eq!(
        store.admit(&[1; 32], 201).await.unwrap().execution_uid,
        1002
    );
    // Past the promotion's deadline, the successor's proof admission ends.
    assert!(
        store
            .admit_successor(&[7; 32], 200 + LIFETIME)
            .await
            .is_err()
    );
}

/// R1: a certificate whose uid isn't the host's is refused, and renewal
/// copies the predecessor's role and uid (so a renewal can't launder one).
#[tokio::test]
async fn admission_requires_the_certificates_own_uid_and_renewal_copies_it() {
    let (store, pool, host) = enrolled().await;
    let renewed = CertificateRecord {
        fingerprint: [2; 32],
        issuer_fingerprint: [9; 32],
        public_key: crate::identity_key::IdentityKey::Ed25519([3; 32]),
        not_before: 300,
        not_after: 300 + 604_800,
    };
    store.renew(&[1; 32], &renewed, 300).await.unwrap();
    let (role, uid): (String, i64) =
        sqlx::query_as("SELECT role, execution_uid FROM remote_certificates WHERE fingerprint=?")
            .bind([2u8; 32].as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((role.as_str(), uid), ("active", 1002));
    // A certificate written without a uid (a path that forgot it) is refused.
    sqlx::query("INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after) VALUES(?,?,?,?,100,604900)")
        .bind([4u8; 32].as_slice())
        .bind(host.as_bytes().as_slice())
        .bind([9u8; 32].as_slice())
        .bind([3u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.admit(&[4; 32], 301).await.is_err());
    // An active certificate can never become a successor, nor change uid.
    assert!(
        sqlx::query("UPDATE remote_certificates SET role='successor' WHERE fingerprint=?")
            .bind([1u8; 32].as_slice())
            .execute(&pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE remote_certificates SET execution_uid=0 WHERE fingerprint=?")
            .bind([1u8; 32].as_slice())
            .execute(&pool)
            .await
            .is_err()
    );
}

/// R3: no path but an enrolled promotion's handover changes a host's mode.
#[tokio::test]
async fn the_database_refuses_every_other_mode_change() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    let flip = || {
        sqlx::query("UPDATE remote_hosts SET mode='rootful', execution_uid=0 WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .execute(&pool)
    };
    assert!(flip().await.is_err());
    // An open (not yet enrolled) promotion doesn't open the door either.
    store
        .begin_promotion("s", host, Uuid::from_u128(1), Method::Sudo, bound(), 200)
        .await
        .unwrap();
    assert!(flip().await.is_err());
    // Nor may a host change uid within rootless.
    assert!(
        sqlx::query("UPDATE remote_hosts SET execution_uid=1003 WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .execute(&pool)
            .await
            .is_err()
    );
}

/// R3: the handover is one transaction. Afterwards the host is rootful, the
/// successor is its ordinary agent, every other key (a renewal that landed
/// during the promotion included) is revoked, and the retirement is queued.
#[tokio::test]
async fn the_handover_moves_authority_in_one_transaction() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    let attempt = Uuid::from_u128(77);
    enrolled_promotion(&store, host, attempt, 200).await;
    // A renewal of the rootless key commits during the promotion.
    let renewed = CertificateRecord {
        fingerprint: [2; 32],
        issuer_fingerprint: [9; 32],
        public_key: crate::identity_key::IdentityKey::Ed25519([3; 32]),
        not_before: 210,
        not_after: 210 + 604_800,
    };
    store.renew(&[1; 32], &renewed, 210).await.unwrap();
    // The wrong successor certificate can't hand over.
    assert!(store.handover(attempt, &[1; 32], 220).await.is_err());
    let handed = store.handover(attempt, &[7; 32], 220).await.unwrap();
    assert_eq!(
        handed,
        HandedOver {
            host,
            from_uid: 1002
        }
    );
    let root = store.admit(&[7; 32], 221).await.unwrap();
    assert_eq!((root.mode, root.execution_uid), (Mode::Rootful, 0));
    for old in [[1; 32], [2; 32]] {
        assert!(store.admit(&old, 221).await.is_err());
        assert!(store.admit_cleanup(&old, 221).await.is_err());
    }
    assert!(store.admit_successor(&[7; 32], 221).await.is_err());
    assert_eq!(
        store.pending_retirement(host).await.unwrap(),
        Some((attempt, 1002))
    );
    store.confirm_retirement(attempt).await.unwrap();
    assert_eq!(store.pending_retirement(host).await.unwrap(), None);
    // A second handover changes nothing.
    assert!(store.handover(attempt, &[7; 32], 222).await.is_err());
}

/// R3 + R7: a handover needs the exact rootless certificate the promotion
/// was bound to still live, and never commits after an abandonment (R5).
#[tokio::test]
async fn the_handover_refuses_a_lost_binding_or_an_abandoned_row() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    let attempt = Uuid::from_u128(77);
    enrolled_promotion(&store, host, attempt, 200).await;
    sqlx::query("UPDATE remote_certificates SET revoked_at=210 WHERE fingerprint=?")
        .bind([1u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.handover(attempt, &[7; 32], 220).await.is_err());
    sqlx::query("UPDATE remote_certificates SET revoked_at=NULL WHERE fingerprint=?")
        .bind([1u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.abandon_promotion(attempt, 221).await.unwrap());
    assert!(store.handover(attempt, &[7; 32], 222).await.is_err());
    let mode: String = sqlx::query_scalar("SELECT mode FROM remote_hosts WHERE id=?")
        .bind(host.as_bytes().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(mode, "rootless");
    // The abandoned successor may now only uninstall itself; its receipt
    // revokes it for good.
    let cleanup = store.admit_successor(&[7; 32], 223).await.unwrap();
    assert_eq!(cleanup.purpose, SuccessorPurpose::Uninstall);
    store
        .confirm_successor_uninstall(attempt, 224)
        .await
        .unwrap();
    assert!(store.admit_successor(&[7; 32], 225).await.is_err());
    // The rootless agent never noticed.
    assert!(store.admit(&[1; 32], 225).await.is_ok());
}

/// R7: only the host admin's unlocked session inside its admin window may
/// begin, bound to a live certificate of the host's own uid; one live
/// promotion per host.
#[tokio::test]
async fn begin_checks_authority_binding_and_one_live_row_in_its_write() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    // Admin window long closed.
    session(
        &pool,
        "stale",
        150 - infraternal_plugin_api::ADMIN_WINDOW_SECONDS - 1,
    )
    .await;
    let begin = |hash: &'static str, attempt: u128, bound: Bound| {
        let store = store.clone();
        async move {
            store
                .begin_promotion(
                    hash,
                    host,
                    Uuid::from_u128(attempt),
                    Method::Sudo,
                    bound,
                    200,
                )
                .await
        }
    };
    assert!(matches!(
        begin("stale", 1, bound()).await,
        Err(PromotionError::Denied)
    ));
    assert!(matches!(
        begin("nobody", 1, bound()).await,
        Err(PromotionError::Denied)
    ));
    let mut foreign = bound();
    foreign.from_fingerprint = [6; 32];
    assert!(matches!(
        begin("s", 1, foreign).await,
        Err(PromotionError::Denied)
    ));
    let mut wrong_uid = bound();
    wrong_uid.from_uid = 1003;
    assert!(matches!(
        begin("s", 1, wrong_uid).await,
        Err(PromotionError::Denied)
    ));
    begin("s", 1, bound()).await.unwrap();
    assert!(matches!(
        begin("s", 2, bound()).await,
        Err(PromotionError::Busy)
    ));
}

/// B2: the check and the try are one write. Two finishes of one attempt
/// can't both run, a timeout after typing counts, and the third try waits.
#[tokio::test]
async fn two_counted_tries_then_wait_reserved_in_one_write() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    let try_once = |attempt: u128, now: i64, settled: Settled| {
        let store = store.clone();
        async move {
            let attempt = Uuid::from_u128(attempt);
            store
                .begin_promotion("s", host, attempt, Method::Sudo, bound(), now)
                .await?;
            store.reserve_try("s", attempt, true, now).await?;
            // A second finish of the same attempt is refused.
            assert!(matches!(
                store.reserve_try("s", attempt, true, now).await,
                Err(PromotionError::Denied)
            ));
            store.settle_try(attempt, settled, now + 1).await
        }
    };
    try_once(1, 200, Settled::Wrong).await.unwrap();
    // A failure before the password reached PAM doesn't count.
    try_once(2, 210, Settled::Failed { typed: false })
        .await
        .unwrap();
    // A timeout after typing does.
    try_once(3, 220, Settled::Failed { typed: true })
        .await
        .unwrap();
    match try_once(4, 230, Settled::Wrong).await {
        Err(PromotionError::Locked { retry_after }) => assert_eq!(retry_after, 221 + WAIT - 230),
        other => panic!("expected the wait, got {other:?}"),
    }
    // B9: su checks root's password, a different account: not waiting.
    let su = Uuid::from_u128(5);
    store
        .begin_promotion("s", host, su, Method::Su, bound(), 230)
        .await
        .unwrap();
    store.abandon_promotion(su, 231).await.unwrap();
    // doas checks the same account as sudo: waiting too.
    assert!(matches!(
        store
            .begin_promotion("s", host, Uuid::from_u128(6), Method::Doas, bound(), 232)
            .await,
        Err(PromotionError::Locked { .. })
    ));
    // After the wait (a fresh admin window), a right password resets the count.
    sqlx::query("UPDATE sessions SET fresh=? WHERE token_hash='s'")
        .bind(221 + WAIT)
        .execute(&pool)
        .await
        .unwrap();
    try_once(7, 221 + WAIT, Settled::Rooted).await.unwrap();
    store
        .abandon_promotion(Uuid::from_u128(7), 221 + WAIT + 1)
        .await
        .unwrap();
    try_once(8, 221 + WAIT + 2, Settled::Wrong).await.unwrap();
    assert_eq!(
        store
            .retry_after(host, Method::Sudo, 221 + WAIT + 3)
            .await
            .unwrap(),
        None
    );
}

/// B2: a try left `elevating` (the server stopped mid-try) still counts
/// once the sweeper abandons it, because its password may have reached PAM.
#[tokio::test]
async fn an_abandoned_typed_try_still_counts() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    for (attempt, now) in [(1, 200), (2, 210)] {
        let attempt = Uuid::from_u128(attempt);
        store
            .begin_promotion("s", host, attempt, Method::Sudo, bound(), now)
            .await
            .unwrap();
        store.reserve_try("s", attempt, true, now).await.unwrap();
        assert_eq!(store.sweep_promotions(now + 1, true).await.unwrap(), 1);
    }
    assert!(
        store
            .retry_after(host, Method::Sudo, 212)
            .await
            .unwrap()
            .is_some()
    );
}

/// R5: the sweeper abandons expired rows; one with a successor queues its
/// uninstall, and a successor token can't be redeemed afterwards.
#[tokio::test]
async fn the_sweeper_abandons_and_bars_late_redemption() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    let attempt = Uuid::from_u128(9);
    store
        .begin_promotion("s", host, attempt, Method::SudoNoPassword, bound(), 200)
        .await
        .unwrap();
    store.reserve_try("s", attempt, false, 200).await.unwrap();
    store
        .settle_try(attempt, Settled::Rooted, 201)
        .await
        .unwrap();
    let token = store
        .issue_successor_token(attempt, &Sha256::digest([8u8; 32]).into(), 202)
        .await
        .unwrap();
    // A token is issued once.
    assert!(
        store
            .issue_successor_token(attempt, &Sha256::digest([8u8; 32]).into(), 203)
            .await
            .is_err()
    );
    assert_eq!(store.sweep_promotions(203, false).await.unwrap(), 0);
    assert_eq!(
        store.sweep_promotions(200 + LIFETIME, false).await.unwrap(),
        1
    );
    assert!(
        store
            .redeem_successor(token.secret(), host, 204, &successor(7, 8, 204))
            .await
            .is_err()
    );
    let cleanup: String =
        sqlx::query_scalar("SELECT cleanup FROM remote_host_promotions WHERE attempt=?")
            .bind(attempt.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    // No successor joined, so the relay's own rollback was the whole cleanup.
    assert_eq!(cleanup, "none");
}

/// A redemption must present the staged key, once.
#[tokio::test]
async fn a_successor_token_is_bound_to_its_staged_key_and_spent_once() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    let attempt = Uuid::from_u128(9);
    store
        .begin_promotion("s", host, attempt, Method::Sudo, bound(), 200)
        .await
        .unwrap();
    store.reserve_try("s", attempt, true, 200).await.unwrap();
    store
        .settle_try(attempt, Settled::Rooted, 201)
        .await
        .unwrap();
    let token = store
        .issue_successor_token(attempt, &Sha256::digest([8u8; 32]).into(), 202)
        .await
        .unwrap();
    assert!(
        store
            .redeem_successor(token.secret(), host, 203, &successor(7, 6, 203))
            .await
            .is_err()
    );
    store
        .redeem_successor(token.secret(), host, 203, &successor(7, 8, 203))
        .await
        .unwrap();
    assert!(
        store
            .redeem_successor(token.secret(), host, 204, &successor(5, 8, 204))
            .await
            .is_err()
    );
    // An ordinary join of the same host can't use a successor token.
    assert!(
        store
            .preflight(token.secret(), host, Mode::Rootful, 204)
            .await
            .is_err()
    );
}

/// Prepare the normal certificate and promotion session for wall-clock admission.
async fn promotion_on_real_clock() -> (EnrollmentStore, SqlitePool, Uuid, i64) {
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let (store, pool, host) = enrolled().await;
    // Move the fixture's identity and session to the real clock.
    sqlx::query("UPDATE remote_certificates SET not_before=?, not_after=?")
        .bind(now - 10)
        .bind(now - 10 + 604_800)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES ('s','owner','fixture',?,?,1)")
        .bind(now + 3600)
        .bind(now - 5)
        .execute(&pool)
        .await
        .unwrap();
    (store, pool, host, now)
}

/// Forget must end cleanup admission for the host's abandoned root successor too.
#[tokio::test]
async fn forget_refuses_abandoned_successor_cleanup_reconnect() {
    let (store, pool, host, now) = promotion_on_real_clock().await;
    let person = Uuid::new_v4().to_string();
    sqlx::query("UPDATE users SET owner=0 WHERE id='owner'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO users(id,name,owner,recovery_hash) VALUES(?,'review owner',1,'fixture')",
    )
    .bind(&person)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE sessions SET user_id=? WHERE token_hash='s'")
        .bind(&person)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE remote_hosts SET owner_id=? WHERE id=?")
        .bind(&person)
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let attempt = Uuid::from_u128(79);
    enrolled_promotion(&store, host, attempt, now).await;
    let token = "promotion-forget-session";
    sqlx::query("UPDATE sessions SET token_hash=? WHERE token_hash='s'")
        .bind(crate::auth::hash(token))
        .execute(&pool)
        .await
        .unwrap();
    let auth = crate::auth::Auth::new(pool.clone(), "forget.test", "https://forget.test/")
        .await
        .unwrap();
    let service = crate::remote_removal::Removal::new(
        auth,
        pool,
        store.clone(),
        crate::remote_runtime::RemoteHosts::default(),
        std::path::PathBuf::new(),
    );
    let review = service.start(token, host, true, now).await.unwrap();
    assert_eq!(
        service
            .finish_host(token, host, review["review"].as_str().unwrap(), now)
            .await
            .unwrap()["state"],
        "pending"
    );
    assert_eq!(
        store.admit_successor(&[7; 32], now).await.unwrap().purpose,
        SuccessorPurpose::Uninstall
    );
    assert_eq!(
        service.forget_browser(token, host, now).await.unwrap()["state"],
        "forgotten"
    );
    let history: (String, String, bool) = sqlx::query_as(
        "SELECT p.state,p.cleanup,c.revoked_at IS NOT NULL FROM remote_host_promotions p
         JOIN remote_certificates c ON c.fingerprint=p.successor_fingerprint WHERE p.attempt=?",
    )
    .bind(attempt.as_bytes().as_slice())
    .fetch_one(&store.0)
    .await
    .unwrap();
    assert_eq!(history, ("abandoned".to_owned(), "none".to_owned(), true));
    assert!(
        crate::remote_guard::AuthorityGuard::admit_transport(store, [7; 32])
            .await
            .is_err(),
        "a forgotten host still admits the abandoned successor for uninstall"
    );
}

/// R1 + R2 at the transport: a successor's certificate is admitted only as a
/// private successor guard (uid 0, never the host's ordinary guard), its
/// operations end the moment the promotion is abandoned, after which it is
/// admitted again only to uninstall itself; host removal cuts it too.
#[tokio::test]
async fn a_successor_guard_is_private_and_ends_with_its_promotion() {
    use crate::remote_guard::AuthorityGuard;
    let (store, _, host, now) = promotion_on_real_clock().await;
    let attempt = Uuid::from_u128(78);
    enrolled_promotion(&store, host, attempt, now).await;
    assert!(AuthorityGuard::admit(store.clone(), [7; 32]).await.is_err());
    let guard = AuthorityGuard::admit_transport(store.clone(), [7; 32])
        .await
        .unwrap();
    let successor = guard.successor_authority().cloned().unwrap();
    assert_eq!(successor.purpose, SuccessorPurpose::Proof);
    assert_eq!(guard.identity.execution_uid, 0);
    assert!(guard.cleanup_person().is_none());
    guard.admit_operation().await.unwrap();
    // The rootless agent keeps its own, separate authority meanwhile.
    let rootless = AuthorityGuard::admit(store.clone(), [1; 32]).await.unwrap();
    assert_eq!(rootless.identity.execution_uid, 1002);
    store.abandon_promotion(attempt, now).await.unwrap();
    assert!(guard.admit_operation().await.is_err());
    let cleanup = AuthorityGuard::admit_transport(store.clone(), [7; 32])
        .await
        .unwrap();
    assert_eq!(
        cleanup.successor_authority().unwrap().purpose,
        SuccessorPurpose::Uninstall
    );
    // Removing the host cuts every epoch, the successor's included.
    store.revoke("owner", host, now).await.unwrap();
    assert!(!cleanup.permits());
    assert!(!rootless.permits());
}

/// J465 P3-2: a digest mismatch reached root with the right password, so it
/// is no failed try: after it, one wrong password doesn't wait.
#[tokio::test]
async fn a_digest_mismatch_counts_as_reaching_root() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    let run = |attempt: u128, now: i64, settled: Settled| {
        let store = store.clone();
        async move {
            let attempt = Uuid::from_u128(attempt);
            store
                .begin_promotion("s", host, attempt, Method::Sudo, bound(), now)
                .await?;
            store.reserve_try("s", attempt, true, now).await?;
            store.settle_try(attempt, settled, now + 1).await
        }
    };
    run(1, 200, Settled::Wrong).await.unwrap();
    run(2, 210, Settled::Mismatch).await.unwrap();
    run(3, 220, Settled::Wrong).await.unwrap();
    assert_eq!(
        store.retry_after(host, Method::Sudo, 230).await.unwrap(),
        None
    );
}

/// J465 P3-3: the try is reserved only inside the admin window, as begin is.
#[tokio::test]
async fn a_try_needs_the_admin_window_still_open() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    let attempt = Uuid::from_u128(4);
    store
        .begin_promotion("s", host, attempt, Method::Sudo, bound(), 200)
        .await
        .unwrap();
    let late = 150 + infraternal_plugin_api::ADMIN_WINDOW_SECONDS;
    assert!(matches!(
        store.reserve_try("s", attempt, true, late).await,
        Err(PromotionError::Denied)
    ));
}

/// J465 P1: the install transaction is recorded once, for a live row, and
/// read back for the uninstall outbox.
#[tokio::test]
async fn the_install_transaction_is_recorded_once() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    let attempt = Uuid::from_u128(77);
    enrolled_promotion(&store, host, attempt, 200).await;
    assert_eq!(store.install_transaction(attempt).await.unwrap(), None);
    let transaction = Uuid::from_u128(0xabc);
    store
        .record_install_transaction(attempt, transaction)
        .await
        .unwrap();
    assert!(
        store
            .record_install_transaction(attempt, Uuid::from_u128(0xdef))
            .await
            .is_err()
    );
    assert_eq!(
        store.install_transaction(attempt).await.unwrap(),
        Some(transaction)
    );
}

/// J569 F3 (#399, J559's stale `uninstall`): a promotion whose relay rolled
/// the install back after the successor joined is over; nothing is left to
/// uninstall.
///
/// Every failure between the successor's join and the commit (`connect`,
/// `proof`, `terminals`, `link`, `commit`) runs the relay's rollback first,
/// which removes the successor. `install()` then calls `rolled_back`, which
/// refuses any row with a successor, and falls back to `abandon_promotion`,
/// which queues `cleanup='uninstall'` for good. The successor certificate
/// stays admissible (for Uninstall) for its whole 7 days, and the row reads
/// the same as a committed root install that may still be running.
#[tokio::test]
async fn a_relay_rollback_after_the_successor_joined_ends_the_cleanup() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    let attempt = Uuid::from_u128(0x5693);
    enrolled_promotion(&store, host, attempt, 200).await;
    store
        .record_install_transaction(attempt, Uuid::from_u128(0xf3))
        .await
        .unwrap();
    // The relay's rollback succeeded before any commit.
    let recorded = store.rolled_back(attempt, 210).await;
    let cleanup: String =
        sqlx::query_scalar("SELECT cleanup FROM remote_host_promotions WHERE attempt=?")
            .bind(attempt.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        recorded.is_ok(),
        "a confirmed relay rollback can't be recorded: {recorded:?}"
    );
    assert_ne!(cleanup, "uninstall");
    assert!(store.admit_successor(&[7; 32], 211).await.is_err());
}

/// J569 F2 (#399, PLAUSIBLE): a second promotion must not start while an
/// earlier one's root install may still be on the host.
///
/// `begin_promotion` ignores `cleanup`. Promotion B's handover revokes every
/// other certificate of the host, including A's successor, so A's queued
/// uninstall can then never be delivered, and A's committed root install
/// stays. A reconnecting A could also act on B's install while B runs. This
/// needs F3 first, or every rolled-back try would block the host for 7 days.
#[tokio::test]
async fn a_pending_uninstall_bars_the_next_promotion() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    let first = Uuid::from_u128(0x569a);
    enrolled_promotion(&store, host, first, 200).await;
    store
        .record_install_transaction(first, Uuid::from_u128(0xa))
        .await
        .unwrap();
    // A committed, then its handover was refused: its uninstall is queued.
    store.abandon_promotion(first, 205).await.unwrap();
    let second = store
        .begin_promotion(
            "s",
            host,
            Uuid::from_u128(0x569b),
            Method::Sudo,
            bound(),
            220,
        )
        .await;
    assert!(
        matches!(second, Err(PromotionError::Busy)),
        "a new promotion began while the last one's uninstall is pending: {second:?}"
    );
}

/// J569 F4 (#399): a caller who may not begin is told `denied`, never the
/// host's lock state.
///
/// `begin_promotion` maps every refused insert to `Locked` whenever the
/// host waits out 2 tries, so a locked session (or one outside its admin
/// window, or another owner's) learns the wait and its length. The HTTP
/// `begin` also calls the host first (facts, terminal census, probe) and
/// writes a `privilege.locked` activity row for that caller.
#[tokio::test]
async fn an_unauthorised_begin_is_denied_not_told_the_wait() {
    let (store, pool, host) = enrolled().await;
    session(&pool, "s", 150).await;
    for (attempt, now) in [(1, 200), (2, 205)] {
        let attempt = Uuid::from_u128(attempt);
        store
            .begin_promotion("s", host, attempt, Method::Sudo, bound(), now)
            .await
            .unwrap();
        store.reserve_try("s", attempt, true, now).await.unwrap();
        store
            .settle_try(attempt, Settled::Wrong, now + 1)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES ('x','owner','fixture',100000,150,0)")
        .execute(&pool)
        .await
        .unwrap();
    let refused = store
        .begin_promotion("x", host, Uuid::from_u128(3), Method::Sudo, bound(), 210)
        .await;
    assert!(
        matches!(refused, Err(PromotionError::Denied)),
        "a locked session was told {refused:?}"
    );
}
