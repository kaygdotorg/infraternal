//! Checks custody and content-free failures using ephemeral synthetic CA material, #154 [168].

use crate::ca::{CaError, CaKeySource, CaMaterial, CertificateAuthority, wrapping::WrappedCa};
use crate::ca_memory::{AdministratorCaUnlock, MemoryCaSource};
use zeroize::Zeroizing;

struct Unlocked(CaMaterial);
impl AdministratorCaUnlock for Unlocked {
    fn unlock(&self) -> Result<CaMaterial, CaError> {
        Ok(self.0.clone())
    }
}

fn locked_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmLck:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn unlocked_signer_requires_persistent_locked_pages() {
    const NAME: &str = "ca_update_audit_tests::unlocked_signer_requires_persistent_locked_pages";
    if std::env::var_os("INFRATERNAL_CA_AUDIT_CHILD").is_some() {
        nix::sys::prctl::set_dumpable(false).unwrap();
        assert!(!nix::sys::prctl::get_dumpable().unwrap());
        assert_eq!(
            locked_kib(),
            0,
            "fixture must start without unrelated locks"
        );
        let rss_before = resident_kib();
        crate::ca_memory::initialize_private_key_memory().unwrap();
        let used_before = infraternal_shim::openssl_secure::used_bytes();
        let material = crate::ca::tests::test_material();
        let wrapped = WrappedCa::seal(&material, "locked-pages", 1, &[3; 32], &[5; 32]).unwrap();
        let issuer = material.issuer().clone();
        drop(material);
        let material = wrapped.open(&issuer, "locked-pages", 1, &[5; 32]).unwrap();
        let source = MemoryCaSource::cold_start(issuer);
        source.unlock_from(&Unlocked(material)).unwrap();
        assert!(CertificateAuthority::from_source(&source).is_ok());
        println!(
            "METRIC unlocked_ca_vm_lck_kib={} rss_before_kib={rss_before} rss_unlocked_kib={} secure_before_bytes={used_before} secure_unlocked_bytes={} servers=1 heap_bytes={}",
            locked_kib(),
            resident_kib(),
            infraternal_shim::openssl_secure::used_bytes(),
            infraternal_shim::openssl_secure::HEAP_BYTES
        );
        assert!(infraternal_shim::openssl_secure::used_bytes() >= used_before + 32);
        // Measure raw Ed25519 import after RAND initialization, independently
        // of its secure state. Clone handles share the original allocation.
        let before_import = infraternal_shim::openssl_secure::used_bytes();
        let seed = Zeroizing::new(
            source
                .load()
                .unwrap()
                .handoff_key()
                .raw_private_key()
                .unwrap(),
        );
        let imported = CaMaterial::key_from_seed(&seed).unwrap();
        drop(seed);
        assert_eq!(
            infraternal_shim::openssl_secure::used_bytes(),
            before_import + 32
        );
        drop(imported);
        assert_eq!(
            infraternal_shim::openssl_secure::used_bytes(),
            before_import
        );
        let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        assert!(maps.lines().any(|line| line.starts_with("VmFlags:")
            && line.split_whitespace().any(|flag| flag == "lo")
            && line.split_whitespace().any(|flag| flag == "dd")));
        assert!(
            locked_kib() >= 4,
            "persistent unlocked signer requires locked pages"
        );
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_CA_AUDIT_CHILD", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    // This child emits only assertion text and public counters, never keys.
    print!("{}", String::from_utf8_lossy(&output.stdout));
    assert!(
        output.status.success(),
        "unlocked persistent signer is unprotected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn every_ciphertext_byte_and_tag_mutation_refuses_without_material_in_errors() {
    let material = crate::ca::tests::test_material();
    let envelope = WrappedCa::seal(&material, "audit-member", 1, &[3; 32], &[5; 32]).unwrap();
    let encoded = serde_json::to_value(&envelope).unwrap();
    let seed = Zeroizing::new(material.handoff_key().raw_private_key().unwrap());
    for index in 0..48 {
        let mut altered = encoded.clone();
        let byte = altered["ciphertext"][index].as_u64().unwrap();
        altered["ciphertext"][index] = serde_json::json!(byte ^ 1);
        let altered = WrappedCa::decode(&serde_json::to_vec(&altered).unwrap()).unwrap();
        let result = altered.open(material.issuer(), "audit-member", 1, &[5; 32]);
        let Err(error) = result else {
            panic!("altered authenticated copy accepted")
        };
        assert_eq!(error.to_string(), "internal CA unavailable");
        assert_eq!(format!("{error:?}"), "CaError");
        assert!(
            !error
                .to_string()
                .as_bytes()
                .windows(seed.len())
                .any(|bytes| bytes == seed.as_slice())
        );
    }
    for bytes in [b"private-fixture-marker".as_slice(), &[0; 4096]] {
        let Err(error) = crate::ca_handoff::parse(bytes) else {
            panic!("malformed frame accepted")
        };
        assert_eq!(error.to_string(), "internal CA unavailable");
        assert_eq!(format!("{error:?}"), "CaError");
    }
}

#[test]
fn no_timer_locks_signing_and_wrong_issuer_cannot_replace_the_unlocked_source() {
    let material = crate::ca::tests::test_material();
    let source = MemoryCaSource::cold_start(material.issuer().clone());
    source.unlock_from(&Unlocked(material)).unwrap();
    for _ in 0..1000 {
        assert!(CertificateAuthority::from_source(&source).is_ok());
        assert!(!*source.subscribe_locked().borrow());
    }
    assert!(
        source
            .unlock_from(&Unlocked(crate::ca::tests::test_material()))
            .is_err()
    );
    assert!(CertificateAuthority::from_source(&source).is_ok());
    assert!(
        MemoryCaSource::cold_start(source.issuer().unwrap())
            .load()
            .is_err()
    );
}

#[test]
fn handoff_descriptor_is_close_on_exec_and_prepare_failure_preserves_source() {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    let material = crate::ca::tests::test_material();
    let source = MemoryCaSource::cold_start(material.issuer().clone());
    assert!(crate::ca_handoff::prepare(&source).is_err());
    source.unlock_from(&Unlocked(material)).unwrap();
    let socket = crate::ca_handoff::prepare(&source).unwrap();
    assert!(
        FdFlag::from_bits_retain(fcntl(&socket, FcntlArg::F_GETFD).unwrap())
            .contains(FdFlag::FD_CLOEXEC)
    );
    drop(socket);
    assert!(CertificateAuthority::from_source(&source).is_ok());
    assert!(!nix::sys::prctl::get_dumpable().unwrap());
}

#[test]
fn handoff_memory_protection_failure_keeps_the_existing_signer() {
    const NAME: &str =
        "ca_update_audit_tests::handoff_memory_protection_failure_keeps_the_existing_signer";
    if std::env::var_os("INFRATERNAL_AUDIT_MEMLOCK_ZERO").is_some() {
        assert!(infraternal_shim::locked_bytes::LockedBytes::new(32).is_err());
        let material = crate::ca::tests::test_material();
        let source = MemoryCaSource::cold_start(material.issuer().clone());
        source.unlock_from(&Unlocked(material)).unwrap();
        assert!(crate::ca_handoff::prepare(&source).is_err());
        assert!(CertificateAuthority::from_source(&source).is_ok());
        assert!(!*source.subscribe_locked().borrow());
        return;
    }
    let output = std::process::Command::new("python3")
        .args(["-c", "import os,resource,sys; resource.setrlimit(resource.RLIMIT_MEMLOCK,(0,0)); os.environ['INFRATERNAL_AUDIT_MEMLOCK_ZERO']='1'; os.execv(sys.argv[1],[sys.argv[1],'--exact',sys.argv[2],'--nocapture'])"])
        .arg(std::env::current_exe().unwrap()).arg(NAME)
        .stdin(std::process::Stdio::null()).output().unwrap();
    assert!(
        output.status.success(),
        "zero-lock-budget handoff must fail closed without relocking source"
    );
}

fn resident_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
#[ignore = "isolated secure heap sizing at 10000 live keys; run with no own builds/browser overlap"]
fn secure_heap_capacity_at_10000_live_keys() {
    const NAME: &str = "ca_update_audit_tests::secure_heap_capacity_at_10000_live_keys";
    if let Ok(mode) = std::env::var("INFRATERNAL_CA_HEAP_SCALE") {
        if mode == "after" {
            crate::ca_memory::initialize_private_key_memory().unwrap();
        }
        let rss_before = resident_kib();
        let keys: Vec<_> = (0..10000)
            .map(|_| openssl::pkey::PKey::generate_ed25519().unwrap())
            .collect();
        let used = infraternal_shim::openssl_secure::used_bytes();
        println!(
            "METRIC mode={mode} secure_heap_live_keys={} used_bytes={used} heap_bytes={} rss_before_kib={rss_before} rss_live_kib={} vm_lck_kib={} cores={} load={}",
            keys.len(),
            infraternal_shim::openssl_secure::HEAP_BYTES,
            resident_kib(),
            locked_kib(),
            std::thread::available_parallelism().unwrap(),
            std::fs::read_to_string("/proc/loadavg").unwrap().trim()
        );
        if mode == "after" {
            assert!(used >= 320_000);
            assert!(used < infraternal_shim::openssl_secure::HEAP_BYTES / 2);
            assert!(locked_kib() >= 1024);
        } else {
            assert_eq!(locked_kib(), 0);
        }
        drop(keys);
        println!(
            "METRIC secure_heap_after_drop_bytes={}",
            infraternal_shim::openssl_secure::used_bytes()
        );
        return;
    }
    for mode in ["before", "after"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--ignored", "--nocapture"])
            .env("INFRATERNAL_CA_HEAP_SCALE", mode)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        print!("{}", String::from_utf8_lossy(&output.stdout));
        assert!(output.status.success());
    }
}
