//! Exercises component trust against real OpenSSH signatures and hostile metadata [#281].

use super::verify_signature;
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

struct Fixture {
    root: PathBuf,
    sums: Vec<u8>,
    signature: Vec<u8>,
    trust: String,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("proxy-signature-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).expect("create fixture directory");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private fixture");
        let key = root.join("key");
        assert!(
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key)
                .status()
                .expect("generate fixture signing key")
                .success()
        );
        let public = fs::read_to_string(key.with_extension("pub")).expect("read public key");
        let fields: Vec<_> = public.split_whitespace().collect();
        let trust = format!(
            "release@infraternal.com namespaces=\"infraternal-release\" {} {} fixture\n",
            fields[0], fields[1]
        );
        let sums = format!(
            "{:x}  fixture.json\n",
            Sha256::digest(b"signed component manifest")
        )
        .into_bytes();
        let sums_path = root.join("SHA256SUMS");
        fs::write(&sums_path, &sums).expect("write checksums");
        assert!(
            Command::new("ssh-keygen")
                .args(["-Y", "sign", "-f"])
                .arg(&key)
                .args(["-n", "infraternal-release", "-O", "hashalg=sha512",])
                .arg(&sums_path)
                .output()
                .expect("sign fixture checksums")
                .status
                .success()
        );
        let signature = fs::read(root.join("SHA256SUMS.sig")).expect("read fixture signature");
        fs::remove_file(&key).expect("remove private fixture key");
        Self {
            root,
            sums,
            signature,
            trust,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn release_signature_accepts_only_signed_bytes_from_the_trusted_identity() {
    let fixture = Fixture::new();
    verify_signature(&fixture.sums, &fixture.signature, &fixture.trust)
        .expect("valid release signature");
    assert_eq!(
        verify_signature(b"changed checksums", &fixture.signature, &fixture.trust)
            .expect_err("changed checksums must be refused")
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        verify_signature(&fixture.sums, &fixture.signature, "")
            .expect_err("untrusted identity must be refused")
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
fn verifier_is_bound_to_the_compiled_release_authorities() {
    let production = include_str!("../../../../release/allowed_signers");
    assert!(production.contains("release@infraternal.com"));
    assert!(production.contains("namespaces=\"infraternal-release\""));
}
