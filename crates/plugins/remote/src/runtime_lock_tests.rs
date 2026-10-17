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
    assert_eq!(
        acquire(&fixture.state()).unwrap_err().kind(),
        io::ErrorKind::AddrInUse
    );
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

fn record(length: usize) -> Vec<u8> {
    let mut record = vec![0_u8; length];
    let length = u32::try_from(length).unwrap();
    record[0..4].copy_from_slice(&length.to_ne_bytes());
    record[4..6].copy_from_slice(&(if length == 20 { 3_u16 } else { 20 }).to_ne_bytes());
    record[6..8].copy_from_slice(&2_u16.to_ne_bytes());
    record[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    if length == 20 {
        return record;
    }
    record[16] = 1;
    record[20..24].copy_from_slice(&1234_u32.to_ne_bytes());
    let tail = if length == 60 {
        for (offset, value) in [(32, 12_u16), (34, 1)] {
            record[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
        }
        record[36..40].copy_from_slice(&4321_u32.to_ne_bytes());
        record[40..44].copy_from_slice(&123_u32.to_ne_bytes());
        44
    } else {
        32
    };
    for (offset, value) in [(0, 5_u16), (2, 6), (8, 8), (10, 7)] {
        record[tail + offset..tail + offset + 2].copy_from_slice(&value.to_ne_bytes());
    }
    record[tail + 12..tail + 16].copy_from_slice(&1001_u32.to_ne_bytes());
    record
}

/// Only the three known kernel record shapes are accepted; anything else is unsure.
#[test]
fn dump_records_accept_only_known_shapes() {
    let owner = SocketOwner {
        uid: 1001,
        inode: 4321,
        device: 123,
    };
    for (length, expected, checked) in [
        (
            60,
            DumpRecord::Bound(owner),
            &[0, 4, 6, 8, 16, 32, 34, 44, 46, 52, 54][..],
        ),
        (
            48,
            DumpRecord::Unbound,
            &[0, 4, 6, 8, 16, 32, 34, 40, 42][..],
        ),
        (20, DumpRecord::Done, &[0, 4, 6, 8, 16][..]),
    ] {
        let record = record(length);
        assert_eq!(dump_record(&record), Some(expected));
        for length in 0..record.len() {
            assert!(dump_record(&record[..length]).is_none());
        }
        let mut extended = record.clone();
        extended.extend([0; 4]);
        assert!(dump_record(&extended).is_none());
        for &offset in checked {
            let mut changed = record.clone();
            changed[offset] ^= 0x80;
            assert!(dump_record(&changed).is_none(), "{length}:{offset}");
        }
    }
    for byte in 0..=255 {
        assert!(dump_record(&[byte; 60]).is_none());
    }
}

/// A datagram is split by declared lengths; a malformed length fails the whole read.
#[test]
fn dump_datagrams_split_exactly() {
    let mut datagram = [record(60), record(48), record(20)].concat();
    let mut seen = 0;
    assert!(dump_datagram(&datagram, |_| seen += 1).is_some());
    assert_eq!(seen, 3);
    for length in 1..datagram.len() {
        let complete = [0, 60, 108].contains(&length);
        assert_eq!(
            dump_datagram(&datagram[..length], |_| {}).is_some(),
            complete
        );
    }
    datagram[60..64].copy_from_slice(&50_u32.to_ne_bytes());
    assert!(dump_datagram(&datagram, |_| {}).is_none());
    datagram[60..64].copy_from_slice(&4096_u32.to_ne_bytes());
    assert!(dump_datagram(&datagram, |_| {}).is_none());
}

/// Kernel ownership remains observable when a runtime makes descriptors private.
#[test]
fn legacy_inspection_finds_a_real_bound_socket() {
    let fixture = Fixture::new();
    let path = fixture.state().join("plugins.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let _pair = std::os::unix::net::UnixStream::pair().unwrap();
    let expected = fs::metadata(&path).unwrap();
    assert_eq!(legacy_bound(&expected), Some(true));
    let other = fixture.state().join("other.sock");
    drop(std::os::unix::net::UnixListener::bind(&other).unwrap());
    assert_eq!(legacy_bound(&fs::metadata(other).unwrap()), Some(false));
    drop(listener);
    assert_eq!(legacy_bound(&expected), Some(false));
}

/// Names are never read: newline homes and absolute aliases keep the same identity.
#[test]
fn legacy_inspection_is_independent_of_the_bound_name() {
    let fixture = Fixture::new();
    let odd = fixture.0.join("a\nb c");
    fs::create_dir(&odd).unwrap();
    let alias = fixture.0.join("alias");
    symlink(fixture.state(), &alias).unwrap();
    for (bound, probed) in [
        (odd.join("plugins.sock"), odd.join("plugins.sock")),
        (
            alias.join("plugins.sock"),
            fixture.state().join("plugins.sock"),
        ),
    ] {
        let listener = std::os::unix::net::UnixListener::bind(&bound).unwrap();
        assert_eq!(legacy_bound(&fs::metadata(&probed).unwrap()), Some(true));
        drop(listener);
        assert_eq!(legacy_bound(&fs::metadata(&probed).unwrap()), Some(false));
        fs::remove_file(probed).unwrap();
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
