//! Covers canonical signed identities, cross-channel mutations and exact payload hashes without writing signing keys [224,226], #157.
use super::*;
use sha2::Digest;
#[path = "../tests/support/release_signing.rs"]
mod signing;

#[test]
/// A release is accepted only with a signed identity and exactly the signed bytes.
fn signed_identity_and_exact_bytes_are_required() {
    // Fixture files live on the private TMPDIR, not the slow build disk (#509).
    let root = std::env::temp_dir();
    let path = root.join(format!("manifest-{}", uuid::Uuid::new_v4()));
    std::fs::write(&path, b"fixture").unwrap();
    let file = File::open(&path).unwrap();
    let manifest = format!(
        "infraternal-release-manifest-v1\nversion edge-20261012T000000Z\nchannel edge\n{:x}  payload\n",
        sha2::Sha256::digest(b"fixture")
    );
    let (signature, trust) = signing::sign(manifest.as_bytes());
    assert_eq!(
        verify_manifest_with_trust(
            &file,
            "payload",
            manifest.as_bytes(),
            signature.as_bytes(),
            &trust
        )
        .unwrap(),
        "edge-20261012T000000Z"
    );
    assert_eq!(
        verify_release_manifest(&file, "payload", manifest.as_bytes(), signature.as_bytes()),
        Err(ReleaseError::Untrusted)
    );
    for index in 0..manifest.len() {
        let mut changed = manifest.as_bytes().to_vec();
        changed[index] ^= 1;
        assert!(
            verify_manifest_with_trust(&file, "payload", &changed, signature.as_bytes(), &trust)
                .is_err()
        );
    }
    for size in 0..manifest.len() {
        assert!(
            verify_manifest_with_trust(
                &file,
                "payload",
                &manifest.as_bytes()[..size],
                signature.as_bytes(),
                &trust
            )
            .is_err()
        );
    }
    std::fs::write(&path, b"changed").unwrap();
    assert_eq!(
        verify_manifest_with_trust(
            &file,
            "payload",
            manifest.as_bytes(),
            signature.as_bytes(),
            &trust
        ),
        Err(ReleaseError::Digest)
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn noncanonical_or_cross_channel_identity_is_refused() {
    for text in [
        "",
        "infraternal-release-manifest-v2\nversion 1.2.3\nchannel stable\n",
        "infraternal-release-manifest-v1\nversion 1.2.3\nchannel edge\n",
        "infraternal-release-manifest-v1\nversion edge-20261012T000000Z\nchannel stable\n",
        "infraternal-release-manifest-v1\nversion ../edge\nchannel edge\n",
    ] {
        assert!(identity(text.as_bytes()).is_err());
    }
    assert!(identity(&vec![b'x'; 65537]).is_err());
    assert_eq!(
        identity(b"infraternal-release-manifest-v1\nversion 1.2.3\nchannel stable\n"),
        Ok(("1.2.3", b"".as_slice()))
    );
}
