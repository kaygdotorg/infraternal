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

/// Exact kernel replies validate lengths and identity before reading the owner.
#[test]
fn diagnostic_owner_rejects_unexpected_fixed_records() {
    let inode = 1234_u32;
    let mut record = [0_u8; 60];
    for (offset, value) in [
        (0, 60),
        (8, 1),
        (20, inode),
        (36, 4321),
        (40, 123),
        (56, 1001),
    ] {
        record[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
    }
    for (offset, value) in [
        (4, 20_u16),
        (32, 12),
        (34, 1),
        (44, 5),
        (46, 6),
        (52, 8),
        (54, 7),
    ] {
        record[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
    }
    record[16] = 1;
    assert_eq!(
        diagnostic_owner(&record, inode),
        Some(SocketOwner {
            uid: 1001,
            inode: 4321,
            device: 123
        })
    );
    for length in 0..record.len() {
        assert!(diagnostic_owner(&record[..length], inode).is_none());
    }
    let mut extended = record.to_vec();
    for _ in 0..64 {
        extended.push(0);
        assert!(diagnostic_owner(&extended, inode).is_none());
    }
    for offset in [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 16, 20, 21, 22, 23, 32, 33, 34, 35, 44, 45, 46, 47,
        52, 53, 54, 55,
    ] {
        let mut changed = record;
        changed[offset] ^= 0x80;
        assert!(diagnostic_owner(&changed, inode).is_none());
    }
    for byte in 0..=255 {
        assert!(diagnostic_owner(&[byte; 60], inode).is_none());
    }
}

/// Kernel ownership remains observable when a runtime makes descriptors private.
#[test]
fn diagnostic_owner_matches_a_real_bound_socket() {
    let fixture = Fixture::new();
    let path = fixture.state().join("plugins.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let rows = fs::read_to_string("/proc/net/unix").unwrap();
    let row = rows
        .lines()
        .find(|row| row.ends_with(path.to_str().unwrap()))
        .unwrap();
    let inode = row.split_whitespace().nth(6).unwrap().parse().unwrap();
    assert!(socket_matches(inode, &fs::metadata(&path).unwrap()).unwrap());
    let other = fixture.state().join("other.sock");
    drop(std::os::unix::net::UnixListener::bind(&other).unwrap());
    assert!(!socket_matches(inode, &fs::metadata(other).unwrap()).unwrap());
    drop(listener);
}

/// Whitespace separates kernel columns, never pieces of the socket name.
#[test]
fn legacy_rows_preserve_names_and_identifiers() {
    for name in [
        "sessions/plugins.sock",
        "/home/test user/.local/share/infraternal/sessions/plugins.sock",
        "/home/test /user/.local/share/infraternal/sessions/plugins.sock",
        "/home/tést user/.local/share/infraternal/sessions/plugins.sock",
    ] {
        let row = format!("00000000: 00000002 00000000 00010000 0001 01 1234 {name}");
        assert_eq!(legacy_row(&row), Some(("1234", name)));
    }
    assert_eq!(
        legacy_row("00000000: 2 0 0 1 1 unknown sessions/plugins.sock"),
        Some(("unknown", "sessions/plugins.sock"))
    );
    assert_eq!(legacy_row("00000000: 2 0 0 1 1 1234"), None);
    for length in 0..128 {
        let row = " ".repeat(length);
        assert_eq!(legacy_row(&row), None);
    }
}

/// A held lifetime description remains an explicit nonblocking refusal.
#[test]
fn lifetime_contention_preserves_would_block() {
    let fixture = Fixture::new();
    let _holder = acquire(&fixture.state()).unwrap();
    let error = acquire(&fixture.state()).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
}

#[test]
fn internal_dispatch_reads_only_the_normal_command_name() {
    let mut arguments = ["status", "--json"]
        .map(std::ffi::OsString::from)
        .into_iter();
    assert_eq!(command(&mut arguments), None);
    assert_eq!(arguments.next().unwrap(), "--json");
}

#[test]
fn internal_dispatch_checks_exact_argument_counts() {
    for arguments in [
        vec!["--bootstrap-runtime"],
        vec!["--bootstrap-runtime", "/unused", "1:2", "inspect", "extra"],
    ] {
        assert_eq!(
            command(&mut arguments.into_iter().map(Into::into)),
            Some(71)
        );
    }
    assert_eq!(
        command(&mut ["--bootstrap-runtime-version"].into_iter().map(Into::into)),
        Some(0)
    );
    assert_eq!(
        command(
            &mut ["--bootstrap-runtime-version", "extra"]
                .into_iter()
                .map(Into::into)
        ),
        None
    );
}
