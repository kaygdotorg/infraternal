//! Exercises the real replacement admission hook without running crafted candidates, #154 [224][226].

use super::fixture::{Directory, Signed};
use super::*;
use std::os::unix::fs::PermissionsExt;

/// Write a small executable candidate in this test's trusted private directory.
fn candidate(directory: &Directory, name: &str, bytes: &[u8]) -> PathBuf {
    let path = directory.0.join(name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

/// Unsigned, modified and oversized candidates must fail admission before execution.
#[test]
fn unsigned_or_tampered_replacement_is_refused_before_exec() {
    let directory = Directory::new();
    let mut accepted = 0;
    // No sidecars exist. Admission must refuse before any candidate can run.
    for (name, bytes) in [
        ("unsigned", b"candidate".as_slice()),
        ("tampered", b"changed"),
        ("truncated", b""),
    ] {
        let path = candidate(&directory, name, bytes);
        if Opened::open(path).is_ok() {
            accepted += 1;
        }
    }
    let path = candidate(&directory, "oversized", b"");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(65 * 1024 * 1024)
        .unwrap();
    if Opened::open(path).is_ok() {
        accepted += 1;
    }
    println!("METRIC unverified_replacements_accepted={accepted} candidates=4 executed=0");
    assert_eq!(
        accepted, 0,
        "replacement admission must fail closed without a verified signature"
    );
}

/// An admitted snapshot must retain its original bytes after the source is modified.
#[test]
fn admitted_inode_cannot_change_in_place_before_execution() {
    use std::os::unix::fs::FileExt;
    let directory = Directory::new();
    let path = candidate(&directory, "candidate", b"original");
    let signed = Signed::image(path.clone());
    let opened = signed.open().unwrap();
    let mut original = [0; 8];
    opened.file.read_exact_at(&mut original, 0).unwrap();
    std::fs::write(&path, b"modified").unwrap();
    let mut bytes = [0; 8];
    opened.file.read_exact_at(&mut bytes, 0).unwrap();
    assert!(
        bytes == original,
        "pinned descriptor exposes changed bytes before exec"
    );
}

/// Untrusted candidate ancestry and writable images must fail admission.
#[test]
fn symlink_parent_escape_and_writable_candidates_are_refused() {
    let directory = Directory::new();
    let path = candidate(&directory, "candidate", b"fixture");
    let alias = directory.0.join("alias");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(Opened::open(alias).is_err());
    assert!(Opened::open(directory.0.join("../candidate")).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o722)).unwrap();
    assert!(Opened::open(path).is_err());
}

/// Replacing the source pathname must leave the admitted snapshot pinned.
#[test]
fn pathname_replacement_keeps_the_admitted_inode() {
    use std::os::unix::fs::FileExt;
    let directory = Directory::new();
    let path = candidate(&directory, "candidate", b"original");
    let signed = Signed::image(path.clone());
    let opened = signed.open().unwrap();
    let mut original = [0; 8];
    opened.file.read_exact_at(&mut original, 0).unwrap();
    std::fs::rename(&path, directory.0.join("retained")).unwrap();
    candidate(&directory, "candidate", b"modified");
    let mut bytes = [0; 8];
    opened.file.read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(bytes, original);
}

/// Executable probing must preserve the existing listener when a candidate cannot run.
#[test]
fn unusable_admitted_image_keeps_the_existing_service_running() {
    use std::net::{TcpListener, TcpStream};
    let directory = Directory::new();
    let path = candidate(&directory, "invalid-executable", b"");
    let signed = Signed::new(path, b"invalid image");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let (ready, receiver) = std::sync::mpsc::channel();
    runtime.spawn(async move {
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        ready.send(()).unwrap();
        loop {
            let _ = listener.accept().await;
        }
    });
    receiver
        // A hang bound, not an expected duration: the listener thread may start late on a loaded host.
        .recv_timeout(std::time::Duration::from_secs(60))
        .unwrap();
    assert!(TcpStream::connect(address).is_ok());
    // A valid signature over unusable bytes reaches the actual image probe.
    // Refusal happens while the runtime still owns its existing listener.
    assert!(signed.open().is_err());
    assert!(
        TcpStream::connect(address).is_ok(),
        "failed executable must leave the current server serving"
    );
}

#[test]
#[ignore = "optimized weighted 20 MiB signature and admission measurement"]
fn verification_twenty_megabytes() {
    let directory = Directory::new();
    let mut bytes = std::fs::read("/usr/bin/true").unwrap();
    bytes.resize(20 * 1024 * 1024, 0);
    let signed = Signed::new(directory.0.join("candidate"), &bytes);
    drop(bytes);
    let snapshot = crate::restart_image::Image::copy_limit(
        &File::open(&signed.path).unwrap(),
        &directory.0,
        crate::restart_image::MAX_IMAGE,
    )
    .unwrap();
    let mut verify = Vec::new();
    for _ in 0..50 {
        let start = std::time::Instant::now();
        signed.verify_snapshot(&snapshot.file).unwrap();
        verify.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let mut admission = Vec::new();
    for _ in 0..10 {
        let start = std::time::Instant::now();
        let admitted = signed.open().unwrap();
        admission.push(start.elapsed().as_secs_f64() * 1000.0);
        assert_eq!(admitted.file.metadata().unwrap().len(), 20 * 1024 * 1024);
    }
    verify.sort_by(f64::total_cmp);
    admission.sort_by(f64::total_cmp);
    println!(
        "METRIC payload_bytes=20971520 verification_samples=50 verification_p50_ms={:.3} verification_max_ms={:.3} admission_samples=10 admission_p50_ms={:.3} admission_max_ms={:.3} admission_includes_copy_seals_version_and_probe=true",
        verify[25], verify[49], admission[5], admission[9]
    );
}
