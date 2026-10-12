//! Exercises the real replacement admission hook without running crafted candidates, #154 [224][226].

use super::fixture::Signed;
use super::*;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/audit-ca-update")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    fn candidate(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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
        let path = directory.candidate(name, bytes);
        if Opened::open(path).is_ok() {
            accepted += 1;
        }
    }
    let path = directory.candidate("oversized", b"");
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

#[test]
fn admitted_inode_cannot_change_in_place_before_execution() {
    use std::os::unix::fs::FileExt;
    let directory = Directory::new();
    let path = directory.candidate("candidate", b"original");
    let signed = Signed::new(path.clone(), b"original");
    let opened = signed.open().unwrap();
    std::fs::write(&path, b"modified").unwrap();
    let mut bytes = [0; 8];
    opened.file.read_exact_at(&mut bytes, 0).unwrap();
    assert!(
        bytes == *b"original",
        "pinned descriptor exposes changed bytes before exec"
    );
}

#[test]
fn symlink_parent_escape_and_writable_candidates_are_refused() {
    let directory = Directory::new();
    let path = directory.candidate("candidate", b"fixture");
    let alias = directory.0.join("alias");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(Opened::open(alias).is_err());
    assert!(Opened::open(directory.0.join("../candidate")).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o722)).unwrap();
    assert!(Opened::open(path).is_err());
}

#[test]
fn pathname_replacement_keeps_the_admitted_inode() {
    use std::os::unix::fs::FileExt;
    let directory = Directory::new();
    let path = directory.candidate("candidate", b"original");
    let signed = Signed::new(path.clone(), b"original");
    let opened = signed.open().unwrap();
    std::fs::rename(&path, directory.0.join("retained")).unwrap();
    directory.candidate("candidate", b"modified");
    let mut bytes = [0; 8];
    opened.file.read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(bytes, *b"original");
}

#[test]
#[ignore = "unresolved P1 UP-03: exec failure shuts down the running service; run explicitly"]
fn unusable_admitted_image_keeps_the_existing_service_running() {
    use std::net::{TcpListener, TcpStream};
    let directory = Directory::new();
    let path = directory.candidate("invalid-executable", b"");
    let replacement = crate::restart::Replacement::new(Opened::open(path).unwrap(), None);
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
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert!(TcpStream::connect(address).is_ok());
    let outcome = crate::restart::replace(runtime, replacement, true);
    assert_eq!(outcome, std::process::ExitCode::from(1));
    assert!(
        TcpStream::connect(address).is_ok(),
        "failed executable must leave the current server serving"
    );
}
