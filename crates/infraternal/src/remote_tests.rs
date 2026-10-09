//! Verifies bounded operator input, private identity creation and certificate-only renewal publication [63][132][133], #78.

use super::*;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/remote-agents/identity-tests")
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
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn publication_is_private_and_never_replaces_existing_identity() {
    let directory = Directory::new();
    let data = directory.0.join("data");
    publish(&data, b"public test sentinel").unwrap();
    let path = data.join("identity.json");
    let metadata = std::fs::metadata(&path).unwrap();
    assert_eq!(metadata.uid(), nix::unistd::Uid::effective().as_raw());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        std::fs::metadata(&data).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(publish(&data, b"replacement").is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"public test sentinel");
    assert_eq!(std::fs::read_dir(data).unwrap().count(), 1);
}

#[test]
fn preparation_refuses_shared_and_symlinked_data_directories() {
    let directory = Directory::new();
    let data = directory.0.join("data");
    prepare(&data).unwrap();
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(prepare(&data).is_err());
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = directory.0.join("link");
    symlink(&data, &link).unwrap();
    assert!(prepare(&link).is_err());
    assert_eq!(std::fs::read_dir(data).unwrap().count(), 0);
}

#[tokio::test]
async fn oversized_or_invalid_invitation_fails_before_local_state_is_created() {
    let directory = Directory::new();
    let data = directory.0.join("data");
    for input in [vec![0; 8193], b"invalid public fixture".to_vec()] {
        let error = join("https://localhost/remote/join", &data, &input)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "remote infraternal agent operation refused"
        );
        assert!(!data.exists());
    }
}

#[tokio::test]
async fn local_identity_load_refuses_symlink_and_shared_file() {
    let directory = Directory::new();
    let data = directory.0.join("data");
    prepare(&data).unwrap();
    let target = directory.0.join("public-fixture");
    std::fs::write(&target, b"public fixture").unwrap();
    let path = data.join("identity.json");
    symlink(&target, &path).unwrap();
    assert!(run(&data, None).await.is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"public fixture").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        run(&data, None).await.unwrap_err().to_string(),
        "remote infraternal agent operation refused"
    );
}

#[tokio::test]
async fn uid_and_privilege_mismatch_fails_before_key_generation() {
    let directory = Directory::new();
    let data = directory.0.join("data");
    let uid = nix::unistd::Uid::effective().as_raw();
    let expected = if uid == 0 {
        Mode::Rootful
    } else {
        Mode::Rootless
    };
    let wrong = if uid == 0 {
        Mode::Rootless
    } else {
        Mode::Rootful
    };
    for (execution_uid, mode) in [(uid.checked_add(1).unwrap(), expected), (uid, wrong)] {
        let invitation = JoinInvitation {
            host_id: uuid::Uuid::new_v4(),
            mode,
            execution_uid,
            token: "invalid public fixture".into(),
            ca_der: String::new(),
            endpoint: "127.0.0.1:0".parse().unwrap(),
            server_name: "localhost".into(),
        };
        let input = serde_json::to_vec(&invitation).unwrap();
        assert!(
            join("https://localhost/remote/join", &data, &input)
                .await
                .is_err()
        );
        assert!(!data.exists());
    }
}

#[test]
fn renewal_publication_replaces_only_certificate_and_preserves_private_metadata() {
    use infraternal_agent::remote_renewal::CertificatePublisher;
    let directory = Directory::new();
    let data = directory.0.join("data");
    let stored = StoredIdentity {
        host_id: uuid::Uuid::new_v4(),
        certificate_der: "old public certificate".into(),
        key_der: "private fixture sentinel".into(),
        ca_der: "public issuer fixture".into(),
        endpoint: "127.0.0.1:7443".parse().unwrap(),
        server_name: "localhost".into(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
    };
    publish(&data, &serde_json::to_vec(&stored).unwrap()).unwrap();
    let key = PKey::generate_ed25519().unwrap();
    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    let name = openssl::x509::X509NameBuilder::new().unwrap().build();
    certificate.set_subject_name(&name).unwrap();
    certificate.set_issuer_name(&name).unwrap();
    certificate.set_pubkey(&key).unwrap();
    certificate
        .set_serial_number(
            &openssl::bn::BigNum::from_u32(1)
                .unwrap()
                .to_asn1_integer()
                .unwrap(),
        )
        .unwrap();
    certificate
        .set_not_before(&openssl::asn1::Asn1Time::from_unix(1_700_000_000).unwrap())
        .unwrap();
    certificate
        .set_not_after(&openssl::asn1::Asn1Time::from_unix(2_000_000_000).unwrap())
        .unwrap();
    certificate.sign(&key, MessageDigest::null()).unwrap();
    let certificate = certificate.build();
    let publisher = IdentityPublisher {
        data: data.clone(),
        stored,
    };
    publisher.publish(&certificate).unwrap();
    let path = data.join("identity.json");
    let current: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut expected = serde_json::to_value(&publisher.stored).unwrap();
    expected["certificate_der"] = B64.encode(certificate.to_der().unwrap()).into();
    assert!(
        current == expected,
        "publication changed private identity metadata"
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(std::fs::read_dir(&data).unwrap().count(), 1);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(publisher.publish(&certificate).is_err());
    std::fs::remove_file(&path).unwrap();
    let target = directory.0.join("sentinel");
    std::fs::write(&target, b"unchanged").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, &path).unwrap();
    assert!(publisher.publish(&certificate).is_err());
    assert_eq!(std::fs::read(target).unwrap(), b"unchanged");
}
