//! Signed release metadata rejects a mismatched target or untrusted bytes.

use super::manifest::{
    ComponentManifest, ComponentManifestVerifier, TRAEFIK_VERSION, verify_component_manifest,
};
use sha2::{Digest, Sha256};

fn manifest() -> ComponentManifest {
    ComponentManifest {
        component: "traefik".to_owned(),
        version: TRAEFIK_VERSION.to_owned(),
        release_version: "0.1.0".to_owned(),
        os: "linux".to_owned(),
        arch: "amd64".to_owned(),
        archive_filename: "traefik_v3.7.17_linux_amd64.tar.gz".to_owned(),
        archive_url:
            "https://github.com/traefik/traefik/releases/download/v3.7.17/traefik_v3.7.17_linux_amd64.tar.gz"
                .to_owned(),
        mirror_path:
            "components/0.1.0/proxy/linux/amd64/traefik_v3.7.17_linux_amd64.tar.gz".to_owned(),
        archive_sha256: "a".repeat(64),
        archive_size: 1024,
        executable: "traefik".to_owned(),
        executable_sha256: "b".repeat(64),
        executable_size: 4096,
        license: "MIT".to_owned(),
    }
}

struct AcceptSignature;

impl ComponentManifestVerifier for AcceptSignature {
    fn verify(&self, _signed_checksums: &[u8], signature: &[u8]) -> std::io::Result<()> {
        if signature == b"valid signature" {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "signature refused",
            ))
        }
    }
}

#[test]
fn release_manifest_accepts_the_pinned_component_and_target() {
    let manifest = manifest();
    assert!(manifest.validate_for("linux", "amd64").is_ok());
}

#[test]
fn release_manifest_rejects_a_different_architecture() {
    assert!(manifest().validate_for("linux", "arm64").is_err());
}

#[test]
fn release_manifest_rejects_an_unbounded_archive_and_malformed_digest() {
    let mut manifest = manifest();
    manifest.archive_size = super::manifest::MAX_COMPONENT_ARCHIVE_BYTES + 1;
    assert!(manifest.validate_for("linux", "amd64").is_err());

    manifest.archive_size = 1024;
    manifest.executable_sha256 = "B".repeat(64);
    assert!(manifest.validate_for("linux", "amd64").is_err());
}

#[test]
fn component_manifest_must_match_a_signed_checksum_entry() {
    let manifest_bytes = serde_json::to_vec(&manifest()).expect("manifest JSON");
    let digest = format!("{:x}", Sha256::digest(&manifest_bytes));
    let sums = format!("{digest}  proxy-traefik-linux-amd64.json\n");

    let checked = verify_component_manifest(
        &manifest_bytes,
        "proxy-traefik-linux-amd64.json",
        sums.as_bytes(),
        b"valid signature",
        "linux",
        "amd64",
        &AcceptSignature,
    )
    .expect("signed component manifest");
    assert_eq!(checked.manifest().version, TRAEFIK_VERSION);
}

#[test]
fn component_manifest_refuses_a_bad_signature_or_unsigned_digest() {
    let manifest_bytes = serde_json::to_vec(&manifest()).expect("manifest JSON");
    let digest = format!("{:x}", Sha256::digest(&manifest_bytes));
    let sums = format!("{digest}  proxy-traefik-linux-amd64.json\n");

    assert!(
        verify_component_manifest(
            &manifest_bytes,
            "proxy-traefik-linux-amd64.json",
            sums.as_bytes(),
            b"invalid signature",
            "linux",
            "amd64",
            &AcceptSignature,
        )
        .is_err()
    );

    assert!(verify_component_manifest(
        &manifest_bytes,
        "proxy-traefik-linux-amd64.json",
        b"0000000000000000000000000000000000000000000000000000000000000000  proxy-traefik-linux-amd64.json\n",
        b"valid signature",
        "linux",
        "amd64",
        &AcceptSignature,
    )
    .is_err());
}
