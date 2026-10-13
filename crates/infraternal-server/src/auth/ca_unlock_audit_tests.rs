//! Verifies current-principal unlock evidence and temporal admission through real passkeys and HTTP, #154 [168].

use super::*;
use std::{io::Write, sync::Mutex};
use tracing_subscriber::fmt::MakeWriter;

const TEST_NAME: &str = "auth::tests::ca_administration_tests::audit_tests::unlock_audit_records_principal_time_outcome_without_material";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> MakeWriter<'a> for Capture {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn unlock_audit_records_principal_time_outcome_without_material() {
    if std::env::var_os("INFRATERNAL_UNLOCK_AUDIT_CHILD").is_none() {
        run_isolated_audit_test();
        return;
    }
    verify_audit_events();
}

/// Keep the event assertions out of the process that runs the other tests.
fn run_isolated_audit_test() {
    // Tracing callsite interest is process-wide, so other tests can change
    // whether this info event reaches a thread-local capture subscriber.
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST_NAME, "--nocapture"])
        .env("INFRATERNAL_UNLOCK_AUDIT_CHILD", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "isolated unlock audit test failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "isolated unlock audit test exceeded its 60-second hang bound:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Verify all completion outcomes and ensure no unlock material enters the event.
fn verify_audit_events() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(capture.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut f = unlock_fixture().await;
                let start = f.administration.start(&f.auth.session, NOW).await.unwrap();
                let proof = f.auth.software.login(&start, ORIGIN, true);
                let id = str_field(&start, "ceremony");
                f.administration
                    .finish(
                        &f.auth.session,
                        id,
                        proof.clone(),
                        Zeroizing::new([7; 32]),
                        NOW,
                    )
                    .await
                    .unwrap();
                assert!(
                    f.administration
                        .finish(&f.auth.session, id, proof, Zeroizing::new([7; 32]), NOW)
                        .await
                        .is_err()
                );
                let start = f.administration.start(&f.auth.session, NOW).await.unwrap();
                let proof = f.auth.software.login(&start, ORIGIN, true);
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
                let start = f.administration.start(&f.auth.session, NOW).await.unwrap();
                let proof = f.auth.software.login(&start, ORIGIN, true);
                let transaction = f.auth.auth.pool.begin().await.unwrap();
                let cancelled = tokio::time::timeout(
                    Duration::from_millis(50),
                    f.administration.finish(
                        &f.auth.session,
                        str_field(&start, "ceremony"),
                        proof,
                        Zeroizing::new([7; 32]),
                        NOW,
                    ),
                )
                .await;
                assert!(
                    cancelled.is_err(),
                    "writer must keep the proof pending until cancellation"
                );
                transaction.rollback().await.unwrap();
                let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
                let events: Vec<Value> = text
                    .lines()
                    .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                    .filter(|event| event["fields"]["event"] == "server_ca_unlock")
                    .collect();
                assert_eq!(
                    events.len(),
                    4,
                    "each completed unlock attempt must have one audit event"
                );
                assert_eq!(events[0]["fields"]["user"], f.auth.user);
                assert_eq!(events[0]["fields"]["outcome"], "unlocked");
                assert!(events[0]["fields"]["unix_seconds"].as_i64().unwrap() > 0);
                assert_eq!(events[1]["fields"]["outcome"], "refused");
                assert_eq!(events[2]["fields"]["outcome"], "refused");
                assert_eq!(events[2]["fields"]["user"], f.auth.user);
                assert_eq!(events[3]["fields"]["outcome"], "cancelled");
                assert_eq!(events[3]["fields"]["user"], f.auth.user);
                assert!(
                    !text.contains(&f.auth.session),
                    "session must not enter audit"
                );
                assert!(!text.contains(id), "proof ceremony must not enter audit");
                for field in [
                    "scoped_key",
                    "ciphertext",
                    "issuer_fingerprint",
                    "clientDataJSON",
                    "signature",
                    "private_key",
                ] {
                    assert!(!text.contains(field), "material field must not enter audit");
                }
            });
    });
}

#[tokio::test]
async fn private_copy_persistence_contains_only_ciphertext_and_public_metadata() {
    let f = unlock_fixture().await;
    let material = crate::ca::tests::test_material();
    let seed = Zeroizing::new(material.handoff_key().raw_private_key().unwrap());
    let copies = CaCopies::new(&f.root).unwrap();
    let wrapped =
        WrappedCa::seal(&material, "audit-storage-member", 1, &[3; 32], &[7; 32]).unwrap();
    copies.publish("audit-storage-member", 1, &wrapped).unwrap();
    let restored = copies
        .read("audit-storage-member", 1)
        .unwrap()
        .open(material.issuer(), "audit-storage-member", 1, &[7; 32])
        .unwrap();
    assert!(crate::ca::CertificateAuthority::from_material(restored).is_ok());
    for entry in std::fs::read_dir(f.root.join("administrators")).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes
                .windows(seed.len())
                .any(|part| part == seed.as_slice()),
            "raw fixture seed reached persistence"
        );
        assert!(
            !bytes.windows(17).any(|part| part == b"BEGIN PRIVATE KEY"),
            "private PEM reached persistence"
        );
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["ciphertext"].as_array().unwrap().len(), 48);
    }
}

#[test]
#[ignore = "real 100-unlock/1000-membership audit formatting diagnostic; no own builds or browsers"]
fn unlock_audit_cost_at_1000_memberships() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(capture.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        actual_ca_unlock_cost_at_1000_administrator_records();
    });
    let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    let events = text
        .lines()
        .filter(|line| line.contains("server_ca_unlock"))
        .count();
    println!(
        "METRIC unlock_audit_formatted_events={events} samples=100 captured_public_log_bytes={} kernel_journal_io_excluded=true profile=GNU-debug",
        text.len()
    );
}
