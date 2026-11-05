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
    // Explicit staging roots keep the VM fixture together; other shipping
    // proofs continue to follow their runner's private TMPDIR.
    let root = std::env::var_os("INFRATERNAL_CA_TEST_ROOT").map_or_else(
        || std::env::temp_dir().join(format!("ca-administration-{}", Uuid::new_v4())),
        |root| PathBuf::from(root).join(&Uuid::new_v4().simple().to_string()[..16]),
    );
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

#[path = "ca_shipping_cli_tests.rs"]
mod shipping_cli_tests;

async fn bootstrap_fixture() -> UnlockFixture {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = unlock_fixture().await;
    let directory = f.root.join("fresh-ca");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("pending"))
        .unwrap();
    let source = Arc::new(MemoryCaSource::unprovisioned(None));
    let mut administration = CaAdministration::new(
        f.auth.auth.clone(),
        f.auth.auth.pool.clone(),
        source.clone(),
        Arc::new(CaCopies::new(&directory).unwrap()),
    );
    administration.bootstrap = Some(Arc::new(crate::ca_bootstrap::BootstrapRuntime::new(
        crate::ca_bootstrap::BootstrapConfig {
            directory,
            name: "auth.example.test".into(),
            address: "127.0.0.1:0".parse().unwrap(),
            deferred: true,
        },
        crate::remote_runtime::RemoteHosts::default(),
        crate::enrollment::EnrollmentStore::new(f.auth.auth.pool.clone()),
    )));
    f.administration = administration;
    f.source = source;
    f
}
#[tokio::test]
async fn bootstrap_requires_a_fresh_real_proof_and_publishes_only_wrapped_ca_material() {
    struct Unlocked(crate::ca::CaMaterial);
    impl crate::ca_memory::AdministratorCaUnlock for Unlocked {
        fn unlock(&self) -> std::result::Result<crate::ca::CaMaterial, crate::ca::CaError> {
            Ok(self.0.clone())
        }
    }

    let mut f = bootstrap_fixture().await;
    let directory = f.root.join("fresh-ca");
    let start = f
        .administration
        .bootstrap_start(&f.auth.session, NOW)
        .await
        .unwrap();
    assert!(f.source.issuer().is_err());
    assert!(!directory.join("active").exists());
    let proof = f.auth.software.login(&start, ORIGIN, false);
    assert!(
        f.administration
            .bootstrap_finish(
                &f.auth.session,
                str_field(&start, "ceremony"),
                proof,
                Zeroizing::new([7; 32]),
                NOW
            )
            .await
            .is_err()
    );
    assert!(!directory.join("active").exists());
    let start = f
        .administration
        .bootstrap_start(&f.auth.session, NOW)
        .await
        .unwrap();
    let proof = f.auth.software.login(&start, ORIGIN, true);
    f.administration
        .bootstrap_finish(
            &f.auth.session,
            str_field(&start, "ceremony"),
            proof,
            Zeroizing::new([7; 32]),
            NOW,
        )
        .await
        .unwrap();
    let issuer = f.source.issuer().unwrap();
    assert!(f.source.load().is_ok());
    let copy = CaCopies::new(&directory.join("active"))
        .unwrap()
        .read(&f.auth.user, 1)
        .unwrap();
    let material = copy.open(&issuer, &f.auth.user, 1, &[7; 32]).unwrap();
    let cold = MemoryCaSource::cold_start(issuer.clone());
    assert!(cold.load().is_err());
    cold.unlock_from(&Unlocked(material)).unwrap();
    assert!(cold.load().is_ok());
    assert!(!directory.join("pending").exists());
    let mut names = std::fs::read_dir(directory.join("active"))
        .unwrap()
        .map(|v| v.unwrap().file_name().to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        ["administrators", "issuer.pem", "remote.key", "remote.pem"]
    );
}
#[tokio::test]
async fn concurrent_bootstrap_ceremonies_retain_one_issuer_and_replay_is_refused() {
    let mut f = bootstrap_fixture().await;
    let a = f
        .administration
        .bootstrap_start(&f.auth.session, NOW)
        .await
        .unwrap();
    let b = f
        .administration
        .bootstrap_start(&f.auth.session, NOW)
        .await
        .unwrap();
    let ap = f.auth.software.login(&a, ORIGIN, true);
    let bp = f.auth.software.login(&b, ORIGIN, true);
    let (ar, br) = tokio::join!(
        f.administration.bootstrap_finish(
            &f.auth.session,
            str_field(&a, "ceremony"),
            ap.clone(),
            Zeroizing::new([7; 32]),
            NOW
        ),
        f.administration.bootstrap_finish(
            &f.auth.session,
            str_field(&b, "ceremony"),
            bp,
            Zeroizing::new([7; 32]),
            NOW
        ),
    );
    assert!(ar.is_ok() || br.is_ok());
    let issuer = f.source.issuer().unwrap().to_der().unwrap();
    assert!(
        f.administration
            .bootstrap_finish(
                &f.auth.session,
                str_field(&a, "ceremony"),
                ap,
                Zeroizing::new([7; 32]),
                NOW
            )
            .await
            .is_err()
    );
    let c = f
        .administration
        .bootstrap_start(&f.auth.session, NOW)
        .await
        .unwrap();
    let cp = f.auth.software.login(&c, ORIGIN, true);
    f.administration
        .bootstrap_finish(
            &f.auth.session,
            str_field(&c, "ceremony"),
            cp,
            Zeroizing::new([7; 32]),
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(issuer, f.source.issuer().unwrap().to_der().unwrap());
}

/// Offline role recipients remain pending until their own device supplies a
/// scoped key; revocation removes only the previous generation's private copy.
#[tokio::test]
async fn published_issuer_without_memory_projection_is_recovered_as_locked_trust() {
    let mut f = bootstrap_fixture().await;
    let start = f
        .administration
        .bootstrap_start(&f.auth.session, NOW)
        .await
        .unwrap();
    let proof = f.auth.software.login(&start, ORIGIN, true);
    f.administration
        .bootstrap_finish(
            &f.auth.session,
            str_field(&start, "ceremony"),
            proof,
            Zeroizing::new([7; 32]),
            NOW,
        )
        .await
        .unwrap();
    let issuer = f.source.issuer().unwrap().to_der().unwrap();
    let source = Arc::new(MemoryCaSource::unprovisioned(None));
    let mut authority = CaAdministration::new(
        f.auth.auth.clone(),
        f.auth.auth.pool.clone(),
        source.clone(),
        Arc::new(CaCopies::new(&f.root.join("fresh-ca")).unwrap()),
    );
    authority.bootstrap = f.administration.bootstrap.clone();
    f.administration = authority;
    f.source = source;
    let start = f
        .administration
        .bootstrap_start(&f.auth.session, NOW)
        .await
        .unwrap();
    assert_eq!(
        start["ca"]["operation"], "unlock",
        "durable publication must never become another setup attempt"
    );
    assert!(
        f.source.load().is_err(),
        "recovering public trust unlocked private signing material"
    );
    let proof = f.auth.software.login(&start, ORIGIN, true);
    f.administration
        .bootstrap_finish(
            &f.auth.session,
            str_field(&start, "ceremony"),
            proof,
            Zeroizing::new([7; 32]),
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(f.source.issuer().unwrap().to_der().unwrap(), issuer);
}

#[tokio::test]
async fn role_grant_is_pending_and_revoke_removes_old_copy_without_restoring_old_authority() {
    let mut f = bootstrap_fixture().await;
    let start = f
        .administration
        .bootstrap_start(&f.auth.session, NOW)
        .await
        .unwrap();
    let proof = f.auth.software.login(&start, ORIGIN, true);
    f.administration
        .bootstrap_finish(
            &f.auth.session,
            str_field(&start, "ceremony"),
            proof,
            Zeroizing::new([7; 32]),
            NOW,
        )
        .await
        .unwrap();
    let pool = &f.auth.auth.pool;
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('role-recipient','Recipient',0,'public-fixture','recipient','Recipient')").execute(pool).await.unwrap();
    sqlx::query("INSERT INTO passkeys(id,user_id,credential) SELECT 'role-fixture-credential','role-recipient',credential FROM passkeys WHERE user_id=? LIMIT 1").bind(&f.auth.user).execute(pool).await.unwrap();
    for administrator in [true, false, true] {
        let change = crate::ca_administration::RoleChange {
            user_id: "role-recipient".into(),
            administrator,
        };
        let start = f
            .administration
            .membership_start(&f.auth.session, change, NOW)
            .await
            .unwrap();
        let proof = f.auth.software.login(&start, ORIGIN, true);
        f.administration
            .membership_finish(&f.auth.session, str_field(&start, "ceremony"), proof, NOW)
            .await
            .unwrap();
        let (generation, active): (i64, bool) = sqlx::query_as(
            "SELECT generation,active FROM ca_administrators WHERE user_id='role-recipient'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(active, administrator);
        if generation == 1 {
            let material = f.source.load().unwrap();
            let copies = CaCopies::new(&f.root.join("fresh-ca/active")).unwrap();
            assert!(
                copies.read("role-recipient", 1).is_err(),
                "offline grant created an unauthorized wrap"
            );
            copies
                .publish(
                    "role-recipient",
                    1,
                    &WrappedCa::seal(&material, "role-recipient", 1, &[3; 32], &[9; 32]).unwrap(),
                )
                .unwrap();
        } else {
            assert!(
                CaCopies::new(&f.root.join("fresh-ca/active"))
                    .unwrap()
                    .read("role-recipient", 1)
                    .is_err()
            );
        }
    }
    let generation: i64 = sqlx::query_scalar(
        "SELECT generation FROM ca_administrators WHERE user_id='role-recipient'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(generation, 3);
    assert!(f.source.load().is_ok());
}
#[tokio::test]
async fn role_changes_require_fresh_purpose_bound_proofs_and_recheck_owner_permission() {
    let mut f = unlock_fixture().await;
    let change = crate::ca_administration::RoleChange {
        user_id: f.auth.user.clone(),
        administrator: false,
    };
    let start = f
        .administration
        .membership_start(&f.auth.session, change, NOW)
        .await
        .unwrap();
    let proof = f.auth.software.login(&start, ORIGIN, true);
    assert!(
        f.administration
            .membership_finish(&f.auth.session, str_field(&start, "ceremony"), proof, NOW)
            .await
            .is_err(),
        "removed the last administrator"
    );
    let change = crate::ca_administration::RoleChange {
        user_id: f.auth.user.clone(),
        administrator: true,
    };
    let start = f
        .administration
        .membership_start(&f.auth.session, change, NOW)
        .await
        .unwrap();
    let proof = f.auth.software.login(&start, ORIGIN, true);
    sqlx::query("UPDATE users SET owner=0 WHERE id=?")
        .bind(&f.auth.user)
        .execute(&f.auth.auth.pool)
        .await
        .unwrap();
    assert!(
        f.administration
            .membership_finish(&f.auth.session, str_field(&start, "ceremony"), proof, NOW)
            .await
            .is_err()
    );
}

async fn registered_recipient(auth: &Auth) -> (String, String, Software) {
    let user = Uuid::new_v4();
    let software = Software::new();
    let (options, state) = auth
        .webauthn
        .start_passkey_registration(user, "recipient", "Recipient", None)
        .unwrap();
    let mut start = json!({"options":options});
    start["options"]["publicKey"]["authenticatorSelection"]["residentKey"] = json!("required");
    start["options"]["publicKey"]["authenticatorSelection"]["userVerification"] = json!("required");
    let proof = serde_json::from_value(software.registration(&start, ORIGIN, true)).unwrap();
    let passkey = auth
        .webauthn
        .finish_passkey_registration(&proof, &state)
        .unwrap();
    let user = user.to_string();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES(?,'Recipient',0,'public-fixture','recipient','Recipient')").bind(&user).execute(&auth.pool).await.unwrap();
    sqlx::query("INSERT INTO passkeys(id,user_id,credential) VALUES(?,?,?)")
        .bind(B64.encode(&software.id))
        .bind(&user)
        .bind(serde_json::to_string(&passkey).unwrap())
        .execute(&auth.pool)
        .await
        .unwrap();
    let token = random();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked,passkey_id) VALUES(?,?,'recipient-fixture',?,?,1,?)").bind(hash(&token)).bind(&user).bind(NOW+3600).bind(NOW).bind(B64.encode(&software.id)).execute(&auth.pool).await.unwrap();
    (user, token, software)
}
async fn change_role(f: &mut UnlockFixture, user: &str, administrator: bool) {
    let start = f
        .administration
        .membership_start(
            &f.auth.session,
            crate::ca_administration::RoleChange {
                user_id: user.into(),
                administrator,
            },
            NOW,
        )
        .await
        .unwrap();
    let proof = f.auth.software.login(&start, ORIGIN, true);
    f.administration
        .membership_finish(&f.auth.session, str_field(&start, "ceremony"), proof, NOW)
        .await
        .unwrap();
}
#[tokio::test]
async fn new_administrator_device_rewraps_pending_copy_and_role_generation_never_resurrects_it() {
    let mut f = bootstrap_fixture().await;
    let start = f
        .administration
        .bootstrap_start(&f.auth.session, NOW)
        .await
        .unwrap();
    let proof = f.auth.software.login(&start, ORIGIN, true);
    f.administration
        .bootstrap_finish(
            &f.auth.session,
            str_field(&start, "ceremony"),
            proof,
            Zeroizing::new([7; 32]),
            NOW,
        )
        .await
        .unwrap();
    let issuer = f.source.issuer().unwrap();
    let (user, token, mut software) = registered_recipient(&f.auth.auth).await;
    change_role(&mut f, &user, true).await;
    let copies = CaCopies::new(&f.root.join("fresh-ca/active")).unwrap();
    assert!(copies.read(&user, 1).is_err());
    let start = f.administration.bootstrap_start(&token, NOW).await.unwrap();
    let proof = software.login(&start, ORIGIN, true);
    f.administration
        .bootstrap_finish(
            &token,
            str_field(&start, "ceremony"),
            proof,
            Zeroizing::new([9; 32]),
            NOW,
        )
        .await
        .unwrap();
    assert!(
        copies
            .read(&user, 1)
            .unwrap()
            .open(&issuer, &user, 1, &[9; 32])
            .is_ok()
    );
    let stale = f.administration.bootstrap_start(&token, NOW).await.unwrap();
    let proof = software.login(&stale, ORIGIN, true);
    change_role(&mut f, &user, false).await;
    assert!(copies.read(&user, 1).is_err());
    change_role(&mut f, &user, true).await;
    assert!(
        f.administration
            .bootstrap_finish(
                &token,
                str_field(&stale, "ceremony"),
                proof,
                Zeroizing::new([9; 32]),
                NOW
            )
            .await
            .is_err()
    );
    let start = f.administration.bootstrap_start(&token, NOW).await.unwrap();
    assert_eq!(start["ca"]["generation"], 3);
    let proof = software.login(&start, ORIGIN, true);
    f.administration
        .bootstrap_finish(
            &token,
            str_field(&start, "ceremony"),
            proof,
            Zeroizing::new([9; 32]),
            NOW,
        )
        .await
        .unwrap();
    assert!(
        copies
            .read(&user, 3)
            .unwrap()
            .open(&issuer, &user, 3, &[9; 32])
            .is_ok()
    );
    assert_eq!(
        issuer.to_der().unwrap(),
        f.source.issuer().unwrap().to_der().unwrap()
    );
}

#[tokio::test]
async fn pending_administrator_cannot_replace_the_last_retained_wrapped_copy() {
    let mut f = bootstrap_fixture().await;
    let start = f
        .administration
        .bootstrap_start(&f.auth.session, NOW)
        .await
        .unwrap();
    let proof = f.auth.software.login(&start, ORIGIN, true);
    f.administration
        .bootstrap_finish(
            &f.auth.session,
            str_field(&start, "ceremony"),
            proof,
            Zeroizing::new([7; 32]),
            NOW,
        )
        .await
        .unwrap();
    let (recipient, _, _) = registered_recipient(&f.auth.auth).await;
    change_role(&mut f, &recipient, true).await;
    let start = f
        .administration
        .membership_start(
            &f.auth.session,
            crate::ca_administration::RoleChange {
                user_id: f.auth.user.clone(),
                administrator: false,
            },
            NOW,
        )
        .await
        .unwrap();
    let proof = f.auth.software.login(&start, ORIGIN, true);
    assert!(
        f.administration
            .membership_finish(&f.auth.session, str_field(&start, "ceremony"), proof, NOW)
            .await
            .is_err(),
        "pending grants cannot unlock after losing the last retained wrapped copy"
    );
    assert!(
        CaCopies::new(&f.root.join("fresh-ca/active"))
            .unwrap()
            .read(&f.auth.user, 1)
            .is_ok()
    );
}

#[path = "ca_unlock_audit_tests.rs"]
mod audit_tests;

/// D333 and D336: CA setup and CA role changes are per-action taps. Each ceremony is bound to
/// its one operation (setup, or one exact role change), is spent by its first finish, and
/// expires 300 s after it starts. `action_tap_tests` checks the other per-action categories.
#[tokio::test]
async fn ca_setup_ceremonies_are_bound_to_their_action_once_and_expire() {
    let mut f = bootstrap_fixture().await;
    let key = || Zeroizing::new([7; 32]);
    let session = f.auth.session.clone();

    // A setup tap cannot change a role, and the attempt spends it.
    let setup = f
        .administration
        .bootstrap_start(&session, NOW)
        .await
        .unwrap();
    let proof = f.auth.software.login(&setup, ORIGIN, true);
    let id = str_field(&setup, "ceremony");
    assert!(
        f.administration
            .membership_finish(&session, id, proof.clone(), NOW)
            .await
            .is_err(),
        "a CA setup tap changed a role"
    );
    assert!(
        f.administration
            .bootstrap_finish(&session, id, proof, key(), NOW)
            .await
            .is_err(),
        "a ceremony refused for another action stays spent"
    );

    // Expiry: a setup tap is refused once its 300 s are over.
    let late = f
        .administration
        .bootstrap_start(&session, NOW)
        .await
        .unwrap();
    let proof = f.auth.software.login(&late, ORIGIN, true);
    assert!(
        f.administration
            .bootstrap_finish(
                &session,
                str_field(&late, "ceremony"),
                proof,
                key(),
                NOW + 300
            )
            .await
            .is_err(),
        "an expired CA setup tap set up the CA"
    );

    // The setup tap sets up the CA once; its replay is refused.
    let setup = f
        .administration
        .bootstrap_start(&session, NOW)
        .await
        .unwrap();
    let proof = f.auth.software.login(&setup, ORIGIN, true);
    let id = str_field(&setup, "ceremony");
    f.administration
        .bootstrap_finish(&session, id, proof.clone(), key(), NOW)
        .await
        .unwrap();
    assert!(
        f.administration
            .bootstrap_finish(&session, id, proof, key(), NOW)
            .await
            .is_err(),
        "a CA setup tap was replayed"
    );
}

/// The role-change half of the check above: a role tap is bound to its one change.
#[tokio::test]
async fn ca_role_ceremonies_are_bound_to_their_change_once_and_expire() {
    let mut f = bootstrap_fixture().await;
    let key = || Zeroizing::new([7; 32]);
    let session = f.auth.session.clone();
    let setup = f
        .administration
        .bootstrap_start(&session, NOW)
        .await
        .unwrap();
    let proof = f.auth.software.login(&setup, ORIGIN, true);
    f.administration
        .bootstrap_finish(&session, str_field(&setup, "ceremony"), proof, key(), NOW)
        .await
        .unwrap();

    // A role tap cannot set up or rewrap the CA, and the attempt spends it.
    let (recipient, _, _) = registered_recipient(&f.auth.auth).await;
    let grant = crate::ca_administration::RoleChange {
        user_id: recipient.clone(),
        administrator: true,
    };
    let role = f
        .administration
        .membership_start(&session, grant.clone(), NOW)
        .await
        .unwrap();
    let proof = f.auth.software.login(&role, ORIGIN, true);
    let id = str_field(&role, "ceremony");
    assert!(
        f.administration
            .bootstrap_finish(&session, id, proof.clone(), key(), NOW)
            .await
            .is_err(),
        "a role tap ran CA setup"
    );
    assert!(
        f.administration
            .membership_finish(&session, id, proof, NOW)
            .await
            .is_err(),
        "a ceremony refused for another action stays spent"
    );

    // Expiry: a role tap is refused once its 300 s are over.
    let late = f
        .administration
        .membership_start(&session, grant.clone(), NOW)
        .await
        .unwrap();
    let proof = f.auth.software.login(&late, ORIGIN, true);
    assert!(
        f.administration
            .membership_finish(&session, str_field(&late, "ceremony"), proof, NOW + 300)
            .await
            .is_err(),
        "an expired role tap changed a role"
    );

    // The role tap applies its one change once; its replay is refused.
    let role = f
        .administration
        .membership_start(&session, grant, NOW)
        .await
        .unwrap();
    let proof = f.auth.software.login(&role, ORIGIN, true);
    let id = str_field(&role, "ceremony");
    f.administration
        .membership_finish(&session, id, proof.clone(), NOW)
        .await
        .unwrap();
    let active: bool = sqlx::query_scalar("SELECT active FROM ca_administrators WHERE user_id=?")
        .bind(&recipient)
        .fetch_one(&f.auth.auth.pool)
        .await
        .unwrap();
    assert!(active, "the role tap granted exactly the change it showed");
    assert!(
        f.administration
            .membership_finish(&session, id, proof, NOW)
            .await
            .is_err(),
        "a role tap was replayed"
    );
}
