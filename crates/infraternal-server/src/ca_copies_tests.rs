//! Verifies private encrypted-copy persistence, atomic publication and generation-scoped removal with real CA material [168], #78.
use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/remote-agents/ca-copy-tests")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)
            .unwrap();
        Self(root)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn encrypted_copy_is_private_durable_and_bound_to_member_generation() {
    let root = Directory::new();
    let copies = CaCopies::new(&root.0).unwrap();
    let material = crate::ca::tests::test_material();
    let key = [7; 32];
    let copy = WrappedCa::seal(&material, "member", 1, &[3; 32], &key).unwrap();
    copies.publish("member", 1, &copy).unwrap();
    let loaded = copies.read("member", 1).unwrap();
    assert!(loaded.open(material.issuer(), "member", 1, &key).is_ok());
    let path = copies.path("member", 1).unwrap();
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&copies.directory)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(std::fs::read_dir(&copies.directory).unwrap().count(), 1);
    assert!(copies.read("member", 2).is_err());
    assert!(copies.publish("foreign", 1, &copy).is_err());
    assert!(copies.publish("member", 2, &copy).is_err());
}
#[test]
fn unsafe_copy_directory_or_file_is_refused_without_following_symlinks() {
    let root = Directory::new();
    let copies = CaCopies::new(&root.0).unwrap();
    let material = crate::ca::tests::test_material();
    let copy = WrappedCa::seal(&material, "member", 1, &[3; 32], &[7; 32]).unwrap();
    copies.publish("member", 1, &copy).unwrap();
    let path = copies.path("member", 1).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(copies.read("member", 1).is_err());
    std::fs::remove_file(&path).unwrap();
    let sentinel = root.0.join("sentinel");
    std::fs::write(&sentinel, b"unchanged").unwrap();
    std::fs::set_permissions(&sentinel, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&sentinel, &path).unwrap();
    assert!(copies.read("member", 1).is_err());
    copies.publish("member", 1, &copy).unwrap();
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
    assert!(copies.read("member", 1).is_ok());
    std::fs::set_permissions(&copies.directory, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(copies.read("member", 1).is_err());
    assert!(copies.publish("member", 1, &copy).is_err());
    assert!(copies.remove("member", 1).is_err());
}
#[test]
fn removal_is_member_generation_scoped_and_idempotent() {
    let root = Directory::new();
    let copies = CaCopies::new(&root.0).unwrap();
    let material = crate::ca::tests::test_material();
    for (member, generation) in [("member", 1), ("member", 2), ("other", 1)] {
        let copy = WrappedCa::seal(&material, member, generation, &[3; 32], &[7; 32]).unwrap();
        copies.publish(member, generation, &copy).unwrap();
    }
    copies.remove("member", 1).unwrap();
    copies.remove("member", 1).unwrap();
    assert!(copies.read("member", 1).is_err());
    assert!(copies.read("member", 2).is_ok());
    assert!(copies.read("other", 1).is_ok());
    assert_eq!(std::fs::read_dir(&copies.directory).unwrap().count(), 2);
}

/// Actual private disk publication/read cost at1,000 copies. Crypto setup is
/// outside timing; reads validate bounded shape/binding, not GCM authentication.
#[test]
#[ignore = "release-only private CA-copy disk diagnostic; no own build/browser overlap"]
fn copy_store_cost_at_1000_administrators() {
    use std::time::Instant;
    let root = Directory::new();
    let copies = CaCopies::new(&root.0).unwrap();
    let material = crate::ca::tests::test_material();
    let prepared: Vec<_> = (0..1000)
        .map(|index| {
            let member = format!("copy-store-diagnostic-{index}");
            let copy = WrappedCa::seal(&material, &member, 1, &[3; 32], &[7; 32]).unwrap();
            (member, copy)
        })
        .collect();
    let mut publish = Vec::with_capacity(1000);
    let mut read = Vec::with_capacity(1000);
    let mut bytes = 0;
    for (member, copy) in &prepared {
        let start = Instant::now();
        copies.publish(member, 1, copy).unwrap();
        publish.push(start.elapsed().as_micros());
        let start = Instant::now();
        assert!(copies.read(member, 1).is_ok());
        read.push(start.elapsed().as_micros());
        bytes += std::fs::metadata(copies.path(member, 1).unwrap())
            .unwrap()
            .len();
    }
    publish.sort_unstable();
    read.sort_unstable();
    assert_eq!(std::fs::read_dir(&copies.directory).unwrap().count(), 1000);
    println!(
        "ca_copy_store n=1000 publish_fsync_rename_dirsync_p50_us={} publish_p99_us={} bounded_private_read_decode_p50_us={} read_p99_us={} encrypted_public_metadata_file_bytes={bytes} crypto_setup_and_gcm_open_excluded=true root={} cores={} machine={} load={}",
        publish[499],
        publish[989],
        read[499],
        read[989],
        root.0.display(),
        std::thread::available_parallelism().unwrap(),
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}
