//! Exercises the verifier against real OpenSSH signatures and adversarial byte mutations.
use super::*;
use std::{
    io::{Seek, SeekFrom},
    path::PathBuf,
    process::Command,
};

#[test]
fn compiled_authorities_keep_production_and_isolate_staging() {
    let production = include_str!("../../../release/allowed_signers");
    assert!(TRUST.starts_with(production));
    assert_eq!(
        TRUST.contains("infraternal-staging-trust-v1"),
        cfg!(feature = "staging-trust")
    );
}

#[test]
fn per_run_signature_obeys_the_compiled_feature_boundary() {
    let Some(directory) = std::env::var_os("INFRATERNAL_STAGING_SIGNED_FIXTURE") else {
        return;
    };
    let directory = PathBuf::from(directory);
    let file = File::open(directory.join("payload")).unwrap();
    let sums = std::fs::read(directory.join("SHA256SUMS")).unwrap();
    let signature = std::fs::read(directory.join("SHA256SUMS.sig")).unwrap();
    let result = verify_release_file(&file, "payload", &sums, &signature);
    if cfg!(feature = "staging-trust") {
        assert_eq!(result, Ok(()));
    } else {
        assert_eq!(result, Err(ReleaseError::Untrusted));
    }
}

struct Fixture {
    root: PathBuf,
    sums: Vec<u8>,
    sig: Vec<u8>,
    trust: String,
    file: File,
}
impl Fixture {
    /// Writes the release fixture for `namespace` with the given payload `hash` under the private TMPDIR.
    fn new(namespace: &str, hash: &str) -> Self {
        // Release fixtures are written, fsynced and read back by the code under test, which bounds
        // each step; keep them on the private TMPDIR, not the slow build disk (#509).
        let root = std::env::temp_dir().join(format!("release-fixture-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let key = root.join("key");
        assert!(
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key)
                .status()
                .unwrap()
                .success()
        );
        let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
        let fields: Vec<_> = public.split_whitespace().collect();
        let trust = format!(
            "release@infraternal.com namespaces=\"infraternal-release\" {} {} fixture\n",
            fields[0], fields[1]
        );
        let payload = b"synthetic release payload\n";
        std::fs::write(root.join("payload"), payload).unwrap();
        let sums = format!("{:x}  payload\n", Sha256::digest(payload)).into_bytes();
        std::fs::write(root.join("SHA256SUMS"), &sums).unwrap();
        assert!(
            Command::new("ssh-keygen")
                .args(["-Y", "sign", "-f"])
                .arg(&key)
                .args(["-n", namespace, "-O", &format!("hashalg={hash}")])
                .arg(root.join("SHA256SUMS"))
                .output()
                .unwrap()
                .status
                .success()
        );
        // Throwaway signing material never survives the fixture lifetime or enters git.
        std::fs::remove_file(&key).unwrap();
        let sig = std::fs::read(root.join("SHA256SUMS.sig")).unwrap();
        let file = File::open(root.join("payload")).unwrap();
        Self {
            root,
            sums,
            sig,
            trust,
            file,
        }
    }
    fn verify(&self, sums: &[u8], sig: &[u8]) -> Result<(), ReleaseError> {
        verify_with_trust(&self.file, "payload", sums, sig, &self.trust)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn openssh_signatures_preserve_descriptor_and_reject_every_byte_mutation() {
    let mut fixture = Fixture::new("infraternal-release", "sha512");
    fixture.file.seek(SeekFrom::Start(7)).unwrap();
    fixture.verify(&fixture.sums, &fixture.sig).unwrap();
    assert_eq!(
        verify_with_trust(
            &File::open("/dev/null").unwrap(),
            "payload",
            &fixture.sums,
            &fixture.sig,
            &fixture.trust
        ),
        Err(ReleaseError::Read)
    );
    assert_eq!(fixture.file.stream_position().unwrap(), 7);
    for index in 0..fixture.sig.len() {
        let mut sig = fixture.sig.clone();
        sig[index] ^= 1;
        assert!(
            fixture.verify(&fixture.sums, &sig).is_err(),
            "signature byte {index}"
        );
    }
    for index in 0..fixture.sums.len() {
        let mut sums = fixture.sums.clone();
        sums[index] ^= 1;
        assert!(
            fixture.verify(&sums, &fixture.sig).is_err(),
            "manifest byte {index}"
        );
    }
    for size in 0..fixture.sig.len() {
        assert!(fixture.verify(&fixture.sums, &fixture.sig[..size]).is_err());
    }
    let original = std::fs::read(fixture.root.join("payload")).unwrap();
    for index in 0..original.len() {
        let mut changed = original.clone();
        changed[index] ^= 1;
        std::fs::write(fixture.root.join("payload"), changed).unwrap();
        assert_eq!(
            fixture.verify(&fixture.sums, &fixture.sig),
            Err(ReleaseError::Digest)
        );
    }
    std::fs::write(fixture.root.join("payload"), b"tampered").unwrap();
    assert_eq!(
        fixture.verify(&fixture.sums, &fixture.sig),
        Err(ReleaseError::Digest)
    );
}

#[test]
fn trust_namespace_hash_trailing_data_and_manifest_ambiguity_are_refused() {
    let good = Fixture::new("infraternal-release", "sha512");
    assert_eq!(
        verify_release_file(&good.file, "payload", &good.sums, &good.sig),
        Err(ReleaseError::Untrusted)
    );
    for (namespace, hash) in [
        ("wrong-namespace", "sha512"),
        ("infraternal-release", "sha256"),
    ] {
        let fixture = Fixture::new(namespace, hash);
        assert_eq!(
            fixture.verify(&fixture.sums, &fixture.sig),
            Err(ReleaseError::Signature)
        );
    }
    let mut trailing = good.sig.clone();
    trailing.push(b'\n');
    assert!(good.verify(&good.sums, &trailing).is_err());
    let mut duplicate = good.sums.clone();
    duplicate.extend_from_slice(&good.sums);
    assert_eq!(
        checksum("payload", &duplicate),
        Err(ReleaseError::Checksums)
    );
    for name in ["../payload", "", "payload\n", "missing"] {
        assert!(checksum(name, &good.sums).is_err());
    }
    // Mutations of the decoded envelope cover ignored/reserved fields and trailing bytes.
    let text = std::str::from_utf8(&good.sig).unwrap();
    let b64: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let binary = B64.decode(b64).unwrap();
    for index in 0..=binary.len() {
        let mut changed = binary.clone();
        if index == binary.len() {
            changed.push(0);
        } else {
            changed[index] ^= 1;
        }
        let encoded = B64.encode(changed);
        let mut armor = String::from("-----BEGIN SSH SIGNATURE-----\n");
        for line in encoded.as_bytes().chunks(70) {
            armor.push_str(std::str::from_utf8(line).unwrap());
            armor.push('\n');
        }
        armor.push_str("-----END SSH SIGNATURE-----\n");
        assert!(
            good.verify(&good.sums, armor.as_bytes()).is_err(),
            "decoded byte {index}"
        );
    }
}

#[test]
#[ignore = "run release-profile measurements in a weighted scope"]
fn verification_twenty_megabytes_fifty_runs() {
    let fixture = Fixture::new("infraternal-release", "sha512");
    let payload = vec![0x42; 20 * 1024 * 1024];
    std::fs::write(fixture.root.join("payload"), &payload).unwrap();
    let sums = format!("{:x}  payload\n", Sha256::digest(&payload)).into_bytes();
    // Measure the full verification hook. Generate a fresh signature for the enlarged manifest.
    let key = fixture.root.join("bench-key");
    assert!(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .unwrap()
            .success()
    );
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let parts: Vec<_> = public.split_whitespace().collect();
    let trust = format!(
        "release@infraternal.com namespaces=\"infraternal-release\" {} {} bench\n",
        parts[0], parts[1]
    );
    let manifest = fixture.root.join("bench-sums");
    std::fs::write(&manifest, &sums).unwrap();
    assert!(
        Command::new("ssh-keygen")
            .args(["-Y", "sign", "-f"])
            .arg(&key)
            .args(["-n", "infraternal-release"])
            .arg(&manifest)
            .output()
            .unwrap()
            .status
            .success()
    );
    std::fs::remove_file(key).unwrap();
    let sig = std::fs::read(manifest.with_extension("sig")).unwrap();
    let mut samples = Vec::new();
    for _ in 0..50 {
        let start = std::time::Instant::now();
        verify_with_trust(&fixture.file, "payload", &sums, &sig, &trust).unwrap();
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(f64::total_cmp);
    println!(
        "METRIC name=verify_release_file payload_bytes={} samples=50 p50_ms={:.3}",
        payload.len(),
        samples[25]
    );
}
