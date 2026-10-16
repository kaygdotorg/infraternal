//! Real lifetime-lock and admission checks for remote runtime/cleanup exclusion (#230).
#![allow(clippy::unwrap_used)]
use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/rl230/{}-{}",
            std::process::id(),
            uuid_free()
        ));
        fs::create_dir_all(root.join("base/sessions")).unwrap();
        for path in [&root, &root.join("base"), &root.join("base/sessions")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(root)
    }
    fn state(&self) -> PathBuf {
        self.0.join("base/sessions")
    }
}
fn uuid_free() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn lifetime_precedes_bind_and_survives_until_last_description_closes() {
    let fixture = Fixture::new();
    let first = acquire(&fixture.state()).unwrap();
    let duplicate = first.try_clone().unwrap();
    assert!(acquire(&fixture.state()).is_err());
    drop(first);
    assert!(acquire(&fixture.state()).is_err());
    drop(duplicate);
    assert!(acquire(&fixture.state()).is_ok());
}
#[test]
fn cleanup_admission_prevents_starting_even_if_runtime_lock_was_removed() {
    let fixture = Fixture::new();
    let parent = File::open(&fixture.0).unwrap();
    parent.try_lock().unwrap();
    let state = fixture.state();
    let (ready, started) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        ready.send(()).unwrap();
        acquire(&state)
    });
    started.recv().unwrap();
    assert!(!fixture.state().join(LOCK).exists());
    // Simulate final cleanup while the starter waits on directory admission.
    fs::remove_dir(fixture.state()).unwrap();
    fs::remove_dir(fixture.0.join("base")).unwrap();
    drop(parent);
    assert!(thread.join().unwrap().is_err());
}
#[test]
fn lock_links_and_replacements_are_refused() {
    let fixture = Fixture::new();
    let other = fixture.0.join("other");
    fs::write(&other, b"retained").unwrap();
    symlink(&other, fixture.state().join(LOCK)).unwrap();
    assert!(acquire(&fixture.state()).is_err());
    assert_eq!(fs::read(other).unwrap(), b"retained");
}

#[test]
fn managed_start_refuses_another_host_and_an_unfinished_receipt() {
    let fixture = Fixture::new();
    let marker = fixture.0.join("base/.bootstrap-owner");
    let host = "11111111111111111111111111111111";
    fs::write(&marker, format!("{host}\n")).unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(acquire_owned(&fixture.state(), "22222222222222222222222222222222").is_err());
    let receipt = fixture
        .0
        .join("base.bootstrap-rollback-22222222222222222222222222222222");
    fs::write(&receipt, b"retained").unwrap();
    assert!(acquire_owned(&fixture.state(), host).is_err());
    assert!(!fixture.state().join(LOCK).exists());
    fs::remove_file(receipt).unwrap();
    assert!(acquire_owned(&fixture.state(), host).is_ok());
}

#[test]
fn a_live_legacy_runtime_cannot_publish_an_unheld_lifetime_file() {
    let fixture = Fixture::new();
    let listener =
        std::os::unix::net::UnixListener::bind(fixture.state().join("plugins.sock")).unwrap();
    assert!(acquire(&fixture.state()).is_err());
    assert!(!fixture.state().join(LOCK).exists());
    drop(listener);
    assert!(acquire(&fixture.state()).is_ok());
}

#[test]
fn unavailable_lock_support_does_not_claim_a_live_holder() {
    assert_eq!(lock_status(&std::fs::TryLockError::WouldBlock), 73);
    assert_eq!(
        lock_status(&std::fs::TryLockError::Error(
            io::ErrorKind::PermissionDenied.into()
        )),
        77
    );
}
