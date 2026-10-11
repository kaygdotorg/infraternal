//! Proves explicit administrator authority against real registered passkeys, live SQLite sessions and role generations [168], #78.
use super::*;
use crate::ca_membership::{Membership, require_binding, require_current};

async fn current(f: &Fixture) -> std::result::Result<Membership, crate::ca::CaError> {
    let mut tx = f.auth.pool.begin().await.unwrap();
    let result = require_current(&mut tx, &hash(&f.session), NOW).await;
    tx.rollback().await.unwrap();
    result
}
#[tokio::test]
async fn administrator_bootstrap_is_explicit_and_owner_flag_cannot_replace_revoked_role() {
    let f = fixture().await;
    let first = current(&f).await.unwrap();
    assert_eq!(first.user, f.user);
    assert_eq!(first.generation, 1);
    sqlx::query("UPDATE users SET owner=0 WHERE id=?")
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert!(current(&f).await.is_ok());
    sqlx::query("UPDATE ca_administrators SET active=0,generation=generation+1 WHERE user_id=?")
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET owner=1 WHERE id=?")
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert!(
        current(&f).await.is_err(),
        "owner flag bypassed explicit role revocation"
    );
    sqlx::query("UPDATE ca_administrators SET active=1 WHERE user_id=?")
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let replacement = current(&f).await.unwrap();
    assert_eq!(replacement.generation, 2);
    assert!(
        require_binding(&replacement, &first).is_err(),
        "old ceremony survived role generation change"
    );
    assert!(require_binding(&replacement, &replacement).is_ok());
}
#[tokio::test]
async fn administrator_copy_refuses_pending_expired_stale_or_future_session() {
    let f = fixture().await;
    for (unlocked, expiry, fresh) in [
        (0, NOW + 60, NOW),
        (1, NOW, NOW),
        (1, NOW + 60, NOW - 300),
        (1, NOW + 60, NOW + 1),
    ] {
        sqlx::query("UPDATE sessions SET unlocked=?,expires=?,fresh=? WHERE token_hash=?")
            .bind(unlocked)
            .bind(expiry)
            .bind(fresh)
            .bind(hash(&f.session))
            .execute(&f.auth.pool)
            .await
            .unwrap();
        assert!(current(&f).await.is_err());
    }
    sqlx::query("UPDATE sessions SET unlocked=1,expires=?,fresh=? WHERE token_hash=?")
        .bind(NOW + 60)
        .bind(NOW)
        .bind(hash(&f.session))
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert!(current(&f).await.is_ok());
}
#[tokio::test]
async fn administrator_copy_refuses_deleted_passkey_or_session() {
    let f = fixture().await;
    assert!(current(&f).await.is_ok());
    sqlx::query("DELETE FROM passkeys WHERE user_id=?")
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert!(current(&f).await.is_err());
    f.auth.logout(&f.session).await.unwrap();
    assert!(current(&f).await.is_err());
}

/// Includes transaction begin, indexed live authority read and rollback. Idle
/// member rows are real SQLite metadata; credential/provisioning setup is excluded.
#[tokio::test]
#[ignore = "optimized administrator guard diagnostic at1000 memberships; no own build/browser overlap"]
async fn administrator_guard_cost_at_1000_memberships() {
    let f = fixture().await;
    let mut tx = f.auth.pool.begin().await.unwrap();
    for index in 1..1000 {
        let id = format!("membership-diagnostic-{index}");
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES(?,?,0,'public-fixture',?,?)")
            .bind(&id).bind(&id).bind(&id).bind(&id).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO ca_administrators(user_id,generation,active) VALUES(?,1,1)")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM ca_administrators")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(count, 1000);
    let mut samples = Vec::new();
    for _ in 0..1000 {
        let start = Instant::now();
        assert!(current(&f).await.is_ok());
        samples.push(start.elapsed().as_nanos());
    }
    samples.sort_unstable();
    println!(
        "administrator_guard memberships=1000 samples=1000 sqlite=memory transaction_begin_and_rollback_included=true real_registered_passkey_for_measured_principal=true idle_member_credential_setup_excluded=true p50_ns={} p99_ns={} cores={} machine={} load={}",
        samples[499],
        samples[989],
        std::thread::available_parallelism().unwrap(),
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}
