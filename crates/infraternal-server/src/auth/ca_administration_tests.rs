//! Exercises CA unlock using real passkey signatures, private wrapped copies and live SQLite role/session revocation [168], #78.
use super::*;
use crate::{
    ca::{CaKeySource, wrapping::WrappedCa},
    ca_administration::CaAdministration,
    ca_copies::CaCopies,
    ca_memory::MemoryCaSource,
};
use std::{os::unix::fs::DirBuilderExt, process::Command, sync::Arc};
use zeroize::Zeroizing;

struct UnlockFixture {
    auth: Fixture,
    administration: CaAdministration,
    source: Arc<MemoryCaSource>,
    root: PathBuf,
}
impl Drop for UnlockFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
async fn unlock_fixture() -> UnlockFixture {
    let auth = fixture().await;
    let material = crate::ca::tests::test_material();
    let source = Arc::new(MemoryCaSource::cold_start(material.issuer().clone()));
    let root = PathBuf::from(std::env::var_os("HOME").unwrap())
        .join(".cache/codex-scratch/remote-agents/ca-administration-tests")
        .join(Uuid::new_v4().to_string());
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&root)
        .unwrap();
    let copies = CaCopies::new(&root).unwrap();
    let wrapped = WrappedCa::seal(&material, &auth.user, 1, &[3; 32], &[7; 32]).unwrap();
    copies.publish(&auth.user, 1, &wrapped).unwrap();
    let administration = CaAdministration::new(
        auth.auth.clone(),
        auth.auth.pool.clone(),
        source.clone(),
        Arc::new(copies),
    );
    UnlockFixture {
        auth,
        administration,
        source,
        root,
    }
}
#[tokio::test]
async fn actual_passkey_unlocks_cold_ca_once_and_leaves_no_extra_browser_session() {
    let mut f = unlock_fixture().await;
    assert!(f.source.load().is_err());
    let start = f.administration.start(&f.auth.session, NOW).await.unwrap();
    let proof = f.auth.software.login(&start, ORIGIN, true);
    f.administration
        .finish(
            &f.auth.session,
            str_field(&start, "ceremony"),
            proof.clone(),
            Zeroizing::new([7; 32]),
            NOW,
        )
        .await
        .unwrap();
    assert!(f.source.load().is_ok());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
        .fetch_one(&f.auth.auth.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert!(
        f.administration
            .finish(
                &f.auth.session,
                str_field(&start, "ceremony"),
                proof,
                Zeroizing::new([7; 32]),
                NOW
            )
            .await
            .is_err()
    );
}
#[tokio::test]
async fn revoked_membership_or_original_session_cannot_finish_an_existing_ca_ceremony() {
    for revoke_role in [true, false] {
        let mut f = unlock_fixture().await;
        let start = f.administration.start(&f.auth.session, NOW).await.unwrap();
        let proof = f.auth.software.login(&start, ORIGIN, true);
        if revoke_role {
            sqlx::query(
                "UPDATE ca_administrators SET active=0,generation=generation+1 WHERE user_id=?",
            )
            .bind(&f.auth.user)
            .execute(&f.auth.auth.pool)
            .await
            .unwrap();
        } else {
            f.auth.auth.logout(&f.auth.session).await.unwrap();
        }
        assert!(
            f.administration
                .finish(
                    &f.auth.session,
                    str_field(&start, "ceremony"),
                    proof,
                    Zeroizing::new([7; 32]),
                    NOW
                )
                .await
                .is_err()
        );
        assert!(f.source.load().is_err());
    }
}
#[tokio::test]
async fn wrong_wrapping_key_or_missing_user_verification_leaves_ca_locked() {
    for uv in [true, false] {
        let mut f = unlock_fixture().await;
        let start = f.administration.start(&f.auth.session, NOW).await.unwrap();
        let proof = f.auth.software.login(&start, ORIGIN, uv);
        assert!(
            f.administration
                .finish(
                    &f.auth.session,
                    str_field(&start, "ceremony"),
                    proof,
                    Zeroizing::new([9; 32]),
                    NOW
                )
                .await
                .is_err()
        );
        assert!(f.source.load().is_err());
    }
}

#[tokio::test]
async fn administrator_with_stale_tap_must_make_a_new_verified_proof_to_unlock() {
    let mut f = unlock_fixture().await;
    let start = f
        .administration
        .start(&f.auth.session, NOW + 301)
        .await
        .unwrap();
    assert!(f.source.load().is_err());
    let proof = f.auth.software.login(&start, ORIGIN, true);
    f.administration
        .finish(
            &f.auth.session,
            str_field(&start, "ceremony"),
            proof,
            Zeroizing::new([7; 32]),
            NOW + 302,
        )
        .await
        .unwrap();
    assert!(f.source.load().is_ok());
}

#[tokio::test]
async fn foreign_browser_cannot_consume_the_original_ca_unlock_ceremony() {
    let mut f = unlock_fixture().await;
    let start = f.administration.start(&f.auth.session, NOW).await.unwrap();
    let proof = f.auth.software.login(&start, ORIGIN, true);
    assert!(
        f.administration
            .finish(
                "foreign-browser",
                str_field(&start, "ceremony"),
                proof.clone(),
                Zeroizing::new([7; 32]),
                NOW
            )
            .await
            .is_err()
    );
    assert!(f.source.load().is_err());
    f.administration
        .finish(
            &f.auth.session,
            str_field(&start, "ceremony"),
            proof,
            Zeroizing::new([7; 32]),
            NOW,
        )
        .await
        .unwrap();
    assert!(f.source.load().is_ok());
}

#[tokio::test]
async fn changed_generation_expired_session_or_removed_credential_cannot_unlock() {
    for change in 0..3 {
        let mut f = unlock_fixture().await;
        let start = f.administration.start(&f.auth.session, NOW).await.unwrap();
        let proof = f.auth.software.login(&start, ORIGIN, true);
        match change {
            0 => {
                sqlx::query("UPDATE ca_administrators SET generation=generation+1 WHERE user_id=?")
                    .bind(&f.auth.user)
                    .execute(&f.auth.auth.pool)
                    .await
                    .unwrap();
            }
            1 => {
                sqlx::query("UPDATE sessions SET expires=? WHERE token_hash=?")
                    .bind(NOW)
                    .bind(hash(&f.auth.session))
                    .execute(&f.auth.auth.pool)
                    .await
                    .unwrap();
            }
            _ => {
                sqlx::query("DELETE FROM passkeys WHERE user_id=?")
                    .bind(&f.auth.user)
                    .execute(&f.auth.auth.pool)
                    .await
                    .unwrap();
            }
        }
        assert!(
            f.administration
                .finish(
                    &f.auth.session,
                    str_field(&start, "ceremony"),
                    proof,
                    Zeroizing::new([7; 32]),
                    NOW
                )
                .await
                .is_err()
        );
        assert!(f.source.load().is_err());
    }
}

#[tokio::test]
async fn ordinary_login_ceremony_has_no_ca_unlock_purpose() {
    let mut f = unlock_fixture().await;
    let start = f.auth.auth.login_start(&f.auth.user, NOW).await.unwrap();
    let proof = f.auth.software.login(&start, ORIGIN, true);
    assert!(
        f.administration
            .finish(
                &f.auth.session,
                str_field(&start, "ceremony"),
                proof.clone(),
                Zeroizing::new([7; 32]),
                NOW
            )
            .await
            .is_err()
    );
    assert!(f.source.load().is_err());
    assert!(
        f.auth
            .auth
            .verify_passkey(str_field(&start, "ceremony"), proof, NOW)
            .await
            .is_ok()
    );
    assert!(f.source.load().is_err());
}

fn unlock_cpu_ns() -> u64 {
    // Match the existing CLI renewal diagnostic's independent process CPU clock.
    // Parent spawn/pipe coordination is included, so this is not isolated crypto CPU.
    let output = Command::new("python3").args(["-c", "import ctypes,sys,time; clock=ctypes.c_int(); status=ctypes.CDLL(None).clock_getcpuclockid(int(sys.argv[1]),ctypes.byref(clock)); assert status==0; print(time.clock_gettime_ns(clock.value))", &std::process::id().to_string()]).output().unwrap();
    assert!(output.status.success());
    std::str::from_utf8(&output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}
fn unlock_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .map(|value| value.split_whitespace().next().unwrap().parse().unwrap())
        })
        .unwrap()
}
#[tokio::test]
#[ignore = "release real authority diagnostic at1000 memberships/copies; no concurrent own build/browser"]
async fn actual_ca_unlock_cost_at_1000_administrator_records() {
    let mut f = unlock_fixture().await;
    let copies = CaCopies::new(&f.root).unwrap();
    let material = crate::ca::tests::test_material();
    let mut tx = f.auth.auth.pool.begin().await.unwrap();
    let mut encrypted_bytes = 0usize;
    for index in 1..1000 {
        let id = format!("unlock-scale-{index}");
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES(?,?,0,'public-fixture',?,?)").bind(&id).bind(&id).bind(&id).bind(&id).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO ca_administrators(user_id,generation,active) VALUES(?,1,1)")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .unwrap();
        // Idle records/copies are real, but only the measured principal has a
        // registered credential. Setup and durable publication are not timed.
        let wrapped = WrappedCa::seal(&material, &id, 1, &[3; 32], &[7; 32]).unwrap();
        encrypted_bytes += serde_json::to_vec(&wrapped).unwrap().len();
        copies.publish(&id, 1, &wrapped).unwrap();
    }
    tx.commit().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM ca_administrators")
        .fetch_one(&f.auth.auth.pool)
        .await
        .unwrap();
    assert_eq!(count, 1000);
    let rss_before = unlock_rss_kib();
    let mut starts = Vec::new();
    let mut finishes = Vec::new();
    let mut cpus = Vec::new();
    for _ in 0..100 {
        let begin = Instant::now();
        let start = f.administration.start(&f.auth.session, NOW).await.unwrap();
        starts.push(begin.elapsed().as_nanos());
        // Client-side signing is excluded from server authority cost.
        let proof = f.auth.software.login(&start, ORIGIN, true);
        let cpu = unlock_cpu_ns();
        let begin = Instant::now();
        f.administration
            .finish(
                &f.auth.session,
                str_field(&start, "ceremony"),
                proof,
                Zeroizing::new([7; 32]),
                NOW,
            )
            .await
            .unwrap();
        finishes.push(begin.elapsed().as_nanos());
        cpus.push(unlock_cpu_ns() - cpu);
    }
    starts.sort_unstable();
    finishes.sort_unstable();
    cpus.sort_unstable();
    println!(
        "ca_unlock memberships=1000 actual_private_copies=1000 measured_registered_principals=1 samples=100 http_excluded=true client_signing_excluded=true copy_setup_excluded=true start_wall_p50_ns={} start_wall_p99_ns={} finish_wall_p50_ns={} finish_wall_p99_ns={} finish_process_cpu_includes_measurement_coordination=true finish_process_cpu_p50_ns={} finish_process_cpu_p99_ns={} rss_before_kib={} rss_after_kib={} idle_copy_bytes={} cores={} load={}",
        starts[49],
        starts[98],
        finishes[49],
        finishes[98],
        cpus[49],
        cpus[98],
        rss_before,
        unlock_rss_kib(),
        encrypted_bytes,
        std::thread::available_parallelism().unwrap(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    assert!(f.source.load().is_ok());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM sessions")
            .fetch_one(&f.auth.auth.pool)
            .await
            .unwrap(),
        1
    );
}

#[path = "ca_http_tests.rs"]
mod http_tests;
