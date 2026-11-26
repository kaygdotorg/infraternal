//! Tests for issuing, storing and rotating the server's leg-B leaf (#559).
use super::*;
use crate::ca_memory::MemoryCaSource;
use openssl::{
    stack::Stack,
    x509::{X509StoreContext, store::X509StoreBuilder, verify::X509VerifyParam},
};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

/// A private (0700) scratch directory, removed on drop.
struct Directory(PathBuf);
impl Directory {
    /// Create a fresh private directory under the test state root.
    fn new() -> Self {
        let root = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map_or_else(
            || {
                PathBuf::from(std::env::var_os("HOME").unwrap())
                    .join(".cache/codex-scratch/server-leaf-tests")
            },
            PathBuf::from,
        );
        let path = root.join(format!("l{}", uuid::Uuid::new_v4().simple()));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&path)
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Unix seconds now.
fn now() -> i64 {
    crate::runtime::unix_seconds().unwrap()
}

/// Whether `leaf` chains to `issuer` for the server purpose and `name` at `at`.
fn verifies(issuer: &X509, leaf: &X509, name: &str, at: i64) -> bool {
    let mut trust = X509StoreBuilder::new().unwrap();
    trust.add_cert(issuer.clone()).unwrap();
    let mut parameters = X509VerifyParam::new().unwrap();
    parameters.set_time(at);
    parameters
        .set_purpose(openssl::x509::X509PurposeId::SSL_SERVER)
        .unwrap();
    parameters.set_host(name).unwrap();
    trust.set_param(&parameters).unwrap();
    X509StoreContext::new()
        .unwrap()
        .init(&trust.build(), leaf, &Stack::new().unwrap(), |context| {
            context.verify_cert()
        })
        .unwrap()
}

/// A leaf lasts 30 days, is backdated by an hour, verifies for its name and
/// nothing else, and each successor starts strictly later, even at the same instant.
#[test]
fn issued_leaf_is_short_lived_ordered_and_verifies_for_its_name() {
    let material = crate::ca::tests::test_material();
    let at = now();
    let first = issue(&material, "server.example.test", None, at).unwrap();
    let start = seconds(first.certificate.not_before()).unwrap();
    let end = seconds(first.certificate.not_after()).unwrap();
    assert_eq!(start, at - BACKDATE);
    assert_eq!(end - start, LIFETIME);
    assert!(verifies(
        material.issuer(),
        &first.certificate,
        "server.example.test",
        at
    ));
    assert!(!verifies(
        material.issuer(),
        &first.certificate,
        "other.example.test",
        at
    ));
    assert!(!verifies(
        material.issuer(),
        &first.certificate,
        "server.example.test",
        end + 1
    ));
    let second = issue(
        &material,
        "server.example.test",
        Some(&first.certificate),
        at,
    )
    .unwrap();
    assert!(seconds(second.certificate.not_before()).unwrap() > start);
    assert!(
        !second.key.public_eq(&first.key),
        "every rotation needs a new key"
    );
    assert_eq!(
        renew_at(&first.certificate).unwrap(),
        at + LIFETIME / 2 - BACKDATE / 2
    );
}

/// A clock that stepped back more than `BACKDATE` behind the previous leaf
/// cannot produce a successor that sorts below it (agents that accepted the
/// previous leaf would refuse it): issuance refuses and the old leaf stays.
#[test]
fn issuance_never_goes_below_the_previous_leaf() {
    let material = crate::ca::tests::test_material();
    let at = now();
    let previous = issue(&material, "server.example.test", None, at).unwrap();
    let stepped_back = at - BACKDATE - 7_200;
    assert!(
        issue(
            &material,
            "server.example.test",
            Some(&previous.certificate),
            stepped_back
        )
        .is_err()
    );
}

/// Publishing writes one private file atomically, replaces the pre-#559 pair
/// (so the old key no longer exists on disk), and `load` reads either layout.
#[test]
fn publish_replaces_the_legacy_pair_and_load_reads_both_layouts() {
    let directory = Directory::new();
    let material = crate::ca::tests::test_material();
    let legacy = issue(&material, "server.example.test", None, now() - 2 * BACKDATE).unwrap();
    std::fs::write(
        directory.0.join(LEGACY_CERTIFICATE),
        legacy.certificate.to_pem().unwrap(),
    )
    .unwrap();
    std::fs::write(
        directory.0.join(LEGACY_KEY),
        legacy.key.private_key_to_pem_pkcs8().unwrap(),
    )
    .unwrap();
    for name in [LEGACY_CERTIFICATE, LEGACY_KEY] {
        std::fs::set_permissions(
            directory.0.join(name),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let loaded = load(&directory.0).unwrap();
    assert_eq!(
        loaded.certificate.to_der().unwrap(),
        legacy.certificate.to_der().unwrap()
    );
    let next = issue(
        &material,
        "server.example.test",
        Some(&legacy.certificate),
        now(),
    )
    .unwrap();
    publish(&directory.0, &next).unwrap();
    let mut names = std::fs::read_dir(&directory.0)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, [FILE], "legacy key and pending files must be gone");
    let metadata = std::fs::metadata(directory.0.join(FILE)).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let reloaded = load(&directory.0).unwrap();
    assert_eq!(
        reloaded.certificate.to_der().unwrap(),
        next.certificate.to_der().unwrap()
    );
    assert!(reloaded.key.public_eq(&next.key));
}

/// A leaf file whose key belongs to another certificate is refused, not served.
#[test]
fn load_refuses_a_mismatched_key() {
    let directory = Directory::new();
    let material = crate::ca::tests::test_material();
    let one = issue(&material, "server.example.test", None, now()).unwrap();
    let two = issue(&material, "server.example.test", None, now()).unwrap();
    publish(
        &directory.0,
        &Identity {
            certificate: one.certificate,
            key: two.key,
        },
    )
    .unwrap();
    assert!(load(&directory.0).is_err());
}

/// Wait up to ten seconds for the next served leaf.
async fn next_served(served: &mut tokio::sync::mpsc::UnboundedReceiver<X509>) -> X509 {
    tokio::time::timeout(Duration::from_secs(10), served.recv())
        .await
        .expect("rotation must serve a leaf")
        .unwrap()
}

/// Start the rotation task for `directory`, reporting each served leaf and
/// checking that it was already durable when it was served.
fn start(
    source: Arc<MemoryCaSource>,
    directory: &Path,
    current: X509,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::UnboundedReceiver<X509>,
) {
    let (report, served) = tokio::sync::mpsc::unbounded_channel();
    let on_disk = directory.to_owned();
    let task = tokio::spawn(run(
        Rotation {
            source,
            directory: directory.to_owned(),
            name: "server.example.test".into(),
            relay: None,
        },
        Some(current),
        move |identity| {
            let durable = load(&on_disk).unwrap();
            assert_eq!(
                durable.certificate.to_der().unwrap(),
                identity.certificate.to_der().unwrap(),
                "a leaf must be durable before it is served"
            );
            report.send(identity.certificate.clone()).unwrap();
            Ok(())
        },
    ));
    (task, served)
}

/// While locked nothing is issued and the retained leaf keeps serving; the
/// administrator's unlock reissues it at once, newer than the one it replaces.
#[tokio::test]
async fn locked_server_keeps_its_leaf_and_an_unlock_reissues_it() {
    let directory = Directory::new();
    let material = crate::ca::tests::test_material();
    let retained = issue(&material, "server.example.test", None, now() - 2 * FRESH).unwrap();
    publish(&directory.0, &retained).unwrap();
    let source = Arc::new(MemoryCaSource::cold_start(material.issuer().clone()));
    let (task, mut served) = start(source.clone(), &directory.0, retained.certificate.clone());
    // sleep: a locked server must stay quiet; give the task time to act wrongly.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(served.try_recv().is_err(), "a locked CA cannot sign a leaf");
    assert_eq!(
        load(&directory.0).unwrap().certificate.to_der().unwrap(),
        retained.certificate.to_der().unwrap()
    );
    source.install(material).unwrap();
    let rotated = next_served(&mut served).await;
    assert!(
        seconds(rotated.not_before()).unwrap()
            > seconds(retained.certificate.not_before()).unwrap()
    );
    task.abort();
}

/// A process that starts unlocked (a warm handoff) with a leaf past half-life
/// reissues it; one that starts with a fresh leaf does not churn it.
#[tokio::test]
async fn handoff_start_renews_a_half_life_leaf_and_keeps_a_fresh_one() {
    let material = crate::ca::tests::test_material();
    let source = Arc::new(MemoryCaSource::cold_start(material.issuer().clone()));
    source.install(material.clone()).unwrap();

    let fresh_directory = Directory::new();
    let fresh = issue(&material, "server.example.test", None, now()).unwrap();
    publish(&fresh_directory.0, &fresh).unwrap();
    let (fresh_task, mut fresh_served) = start(
        source.clone(),
        &fresh_directory.0,
        fresh.certificate.clone(),
    );
    // sleep: a fresh leaf must not be reissued; give the task time to act wrongly.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(fresh_served.try_recv().is_err(), "a fresh leaf was churned");
    fresh_task.abort();

    let due_directory = Directory::new();
    let due = issue(
        &material,
        "server.example.test",
        None,
        now() - LIFETIME / 2 - 60,
    )
    .unwrap();
    publish(&due_directory.0, &due).unwrap();
    let (due_task, mut due_served) = start(source, &due_directory.0, due.certificate.clone());
    let rotated = next_served(&mut due_served).await;
    assert!(
        seconds(rotated.not_before()).unwrap() > seconds(due.certificate.not_before()).unwrap()
    );
    assert!(renew_at(&rotated).unwrap() > now());
    due_task.abort();
}

/// A leaf that could not be made durable is never served; the old one stays.
#[tokio::test]
async fn a_leaf_that_cannot_be_stored_is_never_served() {
    let directory = Directory::new();
    let material = crate::ca::tests::test_material();
    let retained = issue(&material, "server.example.test", None, now() - 2 * FRESH).unwrap();
    // A group-readable directory fails the private-directory check on publish.
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o750)).unwrap();
    let source = Arc::new(MemoryCaSource::cold_start(material.issuer().clone()));
    source.install(material).unwrap();
    let (report, mut served) = tokio::sync::mpsc::unbounded_channel::<()>();
    let task = tokio::spawn(run(
        Rotation {
            source,
            directory: directory.0.clone(),
            name: "server.example.test".into(),
            relay: None,
        },
        Some(retained.certificate),
        move |_| {
            report.send(()).unwrap();
            Ok(())
        },
    ));
    // sleep: the failed attempt happens at once; give a wrong serve time to show.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(served.try_recv().is_err());
    task.abort();
}

/// A relay leaf (D401 Q3) verifies for the server purpose and its name like the leg-B leaf,
/// carries exactly one relay URI with its id, lasts 7 days, and is stored in its own file:
/// publishing it leaves the leg-B leaf untouched and `load_relay` reads it back.
#[test]
fn relay_leaf_is_its_own_seven_day_key_with_one_relay_uri() {
    let directory = Directory::new();
    let material = crate::ca::tests::test_material();
    let at = now();
    let server = issue(&material, "server.example.test", None, at).unwrap();
    publish(&directory.0, &server).unwrap();
    assert!(load_relay(&directory.0).unwrap().is_none());
    let id = uuid::Uuid::new_v4();
    let relay = issue_relay(&material, "server.example.test", id, None, at).unwrap();
    let start = seconds(relay.certificate.not_before()).unwrap();
    let end = seconds(relay.certificate.not_after()).unwrap();
    assert_eq!(end - start, RELAY_LIFETIME);
    assert!(verifies(
        material.issuer(),
        &relay.certificate,
        "server.example.test",
        at
    ));
    assert_eq!(relay_id(&relay.certificate), Some(id));
    assert_eq!(relay_id(&server.certificate), None);
    assert!(
        !relay.key.public_eq(&server.key),
        "the relay has its own key"
    );
    publish_relay(&directory.0, &relay).unwrap();
    let (loaded, loaded_id) = load_relay(&directory.0).unwrap().unwrap();
    assert_eq!(loaded_id, id);
    assert_eq!(
        loaded.certificate.to_der().unwrap(),
        relay.certificate.to_der().unwrap()
    );
    assert_eq!(
        load(&directory.0).unwrap().certificate.to_der().unwrap(),
        server.certificate.to_der().unwrap(),
        "the relay leaf must not replace the leg-B leaf"
    );
}

/// A relay leaf never issued before is issued at the first unlock and only then: a locked
/// CA signs nothing, and the first served leaf is durable and carries the relay URI.
#[tokio::test]
async fn a_first_relay_leaf_waits_for_the_unlock() {
    let directory = Directory::new();
    let material = crate::ca::tests::test_material();
    let source = Arc::new(MemoryCaSource::cold_start(material.issuer().clone()));
    let id = uuid::Uuid::new_v4();
    let (report, mut served) = tokio::sync::mpsc::unbounded_channel::<X509>();
    let on_disk = directory.0.clone();
    let task = tokio::spawn(run(
        Rotation {
            source: source.clone(),
            directory: directory.0.clone(),
            name: "server.example.test".into(),
            relay: Some(id),
        },
        None,
        move |identity| {
            let (durable, _) = load_relay(&on_disk).unwrap().unwrap();
            assert_eq!(
                durable.certificate.to_der().unwrap(),
                identity.certificate.to_der().unwrap(),
                "a relay leaf is durable before it is served"
            );
            report.send(identity.certificate.clone()).unwrap();
            Ok(())
        },
    ));
    // sleep: a locked server must stay quiet; give the task time to act wrongly.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        served.try_recv().is_err(),
        "a locked CA cannot sign a relay leaf"
    );
    source.install(material).unwrap();
    let first = next_served(&mut served).await;
    assert_eq!(relay_id(&first), Some(id));
    task.abort();
}
