//! Verifies bounded operator input, private identity creation and certificate-only renewal publication [63][132][133], #78.

use super::*;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT")
            .map_or_else(
                || {
                    PathBuf::from(std::env::var_os("HOME").unwrap())
                        .join(".cache/codex-scratch/remote-agents/identity-tests")
                },
                PathBuf::from,
            )
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
            public_origin: String::new(),
            https_der: None,
            https_system_roots: false,
            endpoint: Some("127.0.0.1:0".parse().unwrap()),
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
        endpoint: Some("127.0.0.1:7443".parse().unwrap()),
        server_name: "localhost".into(),
        public_origin: None,
        https_der: None,
        https_system_roots: false,
        execution_uid: nix::unistd::Uid::effective().as_raw(),
        identity_rotation: None,
        completed_identity_rotation: None,
    };
    let mut expected = serde_json::to_value(&stored).unwrap();
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
    let publisher = IdentityPublisher { data: data.clone() };
    publisher.publish(&certificate).unwrap();
    let path = data.join("identity.json");
    let current: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
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

#[test]
fn legacy_7443_identity_migrates_atomically_to_its_https_origin() {
    let directory = Directory::new();
    let data = directory.0.join("data");
    let key = PKey::generate_ed25519().unwrap();
    let ca = self_signed(&key);
    let legacy = StoredIdentity {
        host_id: uuid::Uuid::new_v4(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
        endpoint: Some("10.69.69.89:7443".parse().unwrap()),
        server_name: "code.vpn.kayg.org".into(),
        public_origin: None,
        https_der: None,
        https_system_roots: false,
        ca_der: B64.encode(ca.to_der().unwrap()),
        certificate_der: B64.encode(ca.to_der().unwrap()),
        key_der: B64.encode(key.private_key_to_pkcs8().unwrap()),
        identity_rotation: None,
        completed_identity_rotation: None,
    };
    let mut old_document = serde_json::to_value(&legacy).unwrap();
    let old_object = old_document.as_object_mut().unwrap();
    old_object.remove("public_origin");
    old_object.remove("https_der");
    old_object.remove("https_system_roots");
    publish(&data, &serde_json::to_vec(&old_document).unwrap()).unwrap();

    let migrated = migrate_identity(&data).unwrap();
    assert_eq!(
        migrated.public_origin.as_deref(),
        Some("https://code.vpn.kayg.org")
    );
    assert_eq!(migrated.endpoint, None);
    assert!(migrated.https_system_roots);
    let stored: StoredIdentity =
        serde_json::from_slice(&std::fs::read(data.join("identity.json")).unwrap()).unwrap();
    assert_eq!(stored.public_origin, migrated.public_origin);
    assert_eq!(stored.endpoint, None);
    assert_eq!(stored.host_id, migrated.host_id);
}

#[test]
fn prepared_join_key_digest_is_stable_across_bootstrap_steps() {
    let directory = Directory::new();
    let data = directory.0.join("data");

    let first = prepared_key_digest(&data).unwrap();
    let second = prepared_key_digest(&data).unwrap();
    let pkcs8 = prepared_join_key_pkcs8(&data).unwrap();

    assert_eq!(first, second, "the CSR must use the SSH-proved key");
    assert_eq!(key_digest_from_pkcs8(&pkcs8).unwrap(), first);
    assert!(data.join("join-key.pk8").exists());
    retire_prepared_join_key(&data).unwrap();
    assert!(!data.join("join-key.pk8").exists());
}

#[tokio::test]
async fn public_origin_preflight_fails_before_preparing_a_host_key() {
    let directory = Directory::new();
    let data = directory.0.join("data");

    assert!(
        prepare_join_key("https://127.0.0.1:1", &data)
            .await
            .is_err()
    );
    assert!(
        !data.exists(),
        "unreachable origins must fail before key creation"
    );
}

#[test]
fn public_origin_reenrollment_keeps_the_legacy_d168_server_name() {
    let directory = Directory::new();
    let data = directory.0.join("data");
    let host_id = uuid::Uuid::new_v4();
    let uid = nix::unistd::Uid::effective().as_raw();
    let key = PKey::generate_ed25519().unwrap();
    let ca = self_signed(&PKey::generate_ed25519().unwrap());
    let stored = StoredIdentity {
        host_id,
        execution_uid: uid,
        endpoint: Some("10.69.69.89:7443".parse().unwrap()),
        server_name: "ssh.internal".into(),
        public_origin: None,
        https_der: None,
        https_system_roots: false,
        ca_der: B64.encode(ca.to_der().unwrap()),
        certificate_der: B64.encode(ca.to_der().unwrap()),
        key_der: B64.encode(key.private_key_to_pkcs8().unwrap()),
        identity_rotation: None,
        completed_identity_rotation: None,
    };
    publish(&data, &serde_json::to_vec(&stored).unwrap()).unwrap();
    let invitation = JoinInvitation {
        host_id,
        mode: Mode::Rootless,
        execution_uid: uid,
        public_origin: "https://ssh.kayg.org".into(),
        token: "public fixture token".into(),
        ca_der: stored.ca_der.clone(),
        https_der: None,
        https_system_roots: true,
        endpoint: None,
        server_name: "ssh.internal".into(),
    };

    let (_, new_server_name) = invitation_origin(&invitation).unwrap();
    assert_eq!(new_server_name, stored.server_name);
    let enrolled = enrolled_key(&data, &invitation, uid, &new_server_name)
        .unwrap()
        .expect("same D168 authority should permit re-enrollment at its HTTPS origin");
    assert!(enrolled.0.public_eq(&key));
}

#[test]
fn public_origin_invitation_preserves_d168_name_without_a_legacy_endpoint() {
    let invitation = JoinInvitation {
        host_id: uuid::Uuid::from_u128(1),
        mode: Mode::Rootless,
        execution_uid: 1000,
        public_origin: "https://ssh.kayg.org".into(),
        token: "fixture-token".into(),
        ca_der: "fixture-ca".into(),
        https_der: None,
        https_system_roots: true,
        endpoint: Some("10.69.69.89:7443".parse().unwrap()),
        server_name: "ssh.internal".into(),
    };

    let wire = serde_json::to_value(invitation).unwrap();
    assert_eq!(wire["public_origin"], "https://ssh.kayg.org");
    assert_eq!(wire["server_name"], "ssh.internal");
    assert!(wire.get("endpoint").is_none());
}

#[test]
fn preflight_errors_name_https_and_proxy_upgrade_fixes() {
    let unreachable = Failure::Connect.error(io::ErrorKind::NotConnected);
    assert_eq!(
        public_error(&unreachable),
        "The infraternal agent on this host cannot reach the server over HTTPS. Allow outbound TCP 443 to the server's public origin, then try again."
    );
    let upgrade = Failure::Upgrade.error(io::ErrorKind::InvalidData);
    assert_eq!(
        public_error(&upgrade),
        "The infraternal agent on this host reached the server over HTTPS, but the server or proxy did not accept the HTTP/1.1 WebSocket upgrade at /remote/agent. Check that the TLS proxy forwards WebSocket upgrades on this path, then try again."
    );
}

#[test]
fn ssh_installation_can_enroll_before_starting_the_service() {
    let parsed = crate::cli::command_tree::build(&crate::cli::actions::registry().unwrap())
        .try_get_matches_from([
            "infraternal",
            "agent",
            "--data",
            "/private/staged-identity",
            "join",
            "https://localhost/remote/join",
            "--enroll-only",
        ]);
    assert!(
        parsed.is_ok(),
        "SSH installation requires a finite enrollment command"
    );
    let parsed = parsed.unwrap();
    let command = crate::cli::command_tree::selected(&parsed);
    assert_eq!(command.path, ["agent", "join"]);
    assert!(command.matches.get_flag("enroll_only"));
    assert_eq!(
        command.matches.get_one::<String>("data").unwrap(),
        "/private/staged-identity"
    );
}

#[test]
fn ordinary_join_keeps_the_foreground_connection_default() {
    let parsed = crate::cli::command_tree::build(&crate::cli::actions::registry().unwrap())
        .try_get_matches_from([
            "infraternal",
            "agent",
            "join",
            "https://localhost/remote/join",
        ])
        .unwrap();
    let command = crate::cli::command_tree::selected(&parsed);
    assert_eq!(command.path, ["agent", "join"]);
    assert!(!command.matches.get_flag("enroll_only"));
}

#[tokio::test]
async fn join_dns_failure_reports_resolution_instead_of_generic_refusal() {
    let error = tokio::time::timeout(
        Duration::from_secs(10),
        connect_enrollment("infraternal-fixture-no-such-host.invalid", 443),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "The infraternal agent on this host cannot resolve the server's HTTPS origin. Check DNS for the public origin and allow outbound TCP 443."
    );
}

fn self_signed(key: &PKey<openssl::pkey::Private>) -> X509 {
    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    let name = openssl::x509::X509NameBuilder::new().unwrap().build();
    certificate.set_subject_name(&name).unwrap();
    certificate.set_issuer_name(&name).unwrap();
    certificate.set_pubkey(key).unwrap();
    certificate
        .set_not_before(&openssl::asn1::Asn1Time::from_unix(1_700_000_000).unwrap())
        .unwrap();
    certificate
        .set_not_after(&openssl::asn1::Asn1Time::from_unix(2_000_000_000).unwrap())
        .unwrap();
    certificate.sign(key, MessageDigest::null()).unwrap();
    certificate.build()
}

/// SSH setup copies the host's enrolled identity into its transaction before
/// joining, and a published-setup Retry joins again for the same host (#230).
/// Join must re-enroll that host's own key instead of refusing the identity;
/// an identity for any other host is still refused before any network use.
#[tokio::test]
async fn join_re_enrolls_the_same_hosts_identity_and_refuses_another_host() {
    let directory = Directory::new();
    let data = directory.0.join("data");
    let key = PKey::generate_ed25519().unwrap();
    let ca = self_signed(&key);
    let host_id = uuid::Uuid::new_v4();
    let uid = nix::unistd::Uid::effective().as_raw();
    let stored = StoredIdentity {
        host_id,
        execution_uid: uid,
        endpoint: Some("127.0.0.1:7443".parse().unwrap()),
        server_name: "localhost".into(),
        public_origin: None,
        https_der: None,
        https_system_roots: false,
        ca_der: B64.encode(ca.to_der().unwrap()),
        certificate_der: B64.encode(ca.to_der().unwrap()),
        key_der: B64.encode(key.private_key_to_pkcs8().unwrap()),
        identity_rotation: None,
        completed_identity_rotation: None,
    };
    let bytes = serde_json::to_vec(&stored).unwrap();
    publish(&data, &bytes).unwrap();
    let invitation = |host_id| {
        serde_json::to_vec(&JoinInvitation {
            host_id,
            mode: if uid == 0 {
                Mode::Rootful
            } else {
                Mode::Rootless
            },
            execution_uid: uid,
            token: "public fixture token".into(),
            ca_der: stored.ca_der.clone(),
            public_origin: String::new(),
            https_der: None,
            https_system_roots: false,
            endpoint: Some("127.0.0.1:7443".parse().unwrap()),
            server_name: "localhost".into(),
        })
        .unwrap()
    };
    // The same host reaches enrollment: only the unreachable fixture server refuses it.
    let error = join(
        "https://infraternal-fixture-no-such-host.invalid/remote/join",
        &data,
        &invitation(host_id),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "The infraternal agent on this host cannot reach the server over HTTPS. Allow outbound TCP 443 to the server's public origin, then try again."
    );
    let error = join(
        "https://infraternal-fixture-no-such-host.invalid/remote/join",
        &data,
        &invitation(uuid::Uuid::new_v4()),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "remote infraternal agent operation refused"
    );
    assert_eq!(std::fs::read(data.join("identity.json")).unwrap(), bytes);
    assert_eq!(std::fs::read_dir(&data).unwrap().count(), 1);
}

/// Break-it (#230): the host id alone does not name a host. Another server
/// (a staging copy of the database, or any server that issues the same id)
/// must not take over an identity enrolled with this one: its invitation has
/// a different CA, endpoint and server name. Join must refuse it before any
/// network use and leave the enrolled identity byte-identical, as it did
/// before re-enrollment existed.
#[tokio::test]
async fn join_refuses_the_same_host_id_from_another_server() {
    let directory = Directory::new();
    let data = directory.0.join("data");
    let key = PKey::generate_ed25519().unwrap();
    let ca = self_signed(&key);
    let host_id = uuid::Uuid::new_v4();
    let uid = nix::unistd::Uid::effective().as_raw();
    let stored = StoredIdentity {
        host_id,
        execution_uid: uid,
        endpoint: Some("127.0.0.1:7443".parse().unwrap()),
        server_name: "localhost".into(),
        public_origin: None,
        https_der: None,
        https_system_roots: false,
        ca_der: B64.encode(ca.to_der().unwrap()),
        certificate_der: B64.encode(ca.to_der().unwrap()),
        key_der: B64.encode(key.private_key_to_pkcs8().unwrap()),
        identity_rotation: None,
        completed_identity_rotation: None,
    };
    let bytes = serde_json::to_vec(&stored).unwrap();
    publish(&data, &bytes).unwrap();
    let other = self_signed(&PKey::generate_ed25519().unwrap());
    let invitation = serde_json::to_vec(&JoinInvitation {
        host_id,
        mode: if uid == 0 {
            Mode::Rootful
        } else {
            Mode::Rootless
        },
        execution_uid: uid,
        token: "public fixture token".into(),
        ca_der: B64.encode(other.to_der().unwrap()),
        public_origin: String::new(),
        https_der: None,
        https_system_roots: false,
        endpoint: Some("127.0.0.2:8443".parse().unwrap()),
        server_name: "other-server.invalid".into(),
    })
    .unwrap();
    let error = join(
        "https://infraternal-fixture-no-such-host.invalid/remote/join",
        &data,
        &invitation,
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "remote infraternal agent operation refused",
        "another server's invitation reached the network with this host's key"
    );
    assert_eq!(std::fs::read(data.join("identity.json")).unwrap(), bytes);
}

/// The same server may move (#230): a changed endpoint alone does not refuse
/// re-enrollment, while a different server name does.
#[tokio::test]
async fn join_re_enrolls_for_a_moved_server_but_not_a_renamed_one() {
    let directory = Directory::new();
    let data = directory.0.join("data");
    let key = PKey::generate_ed25519().unwrap();
    let ca = self_signed(&key);
    let host_id = uuid::Uuid::new_v4();
    let uid = nix::unistd::Uid::effective().as_raw();
    let stored = StoredIdentity {
        host_id,
        execution_uid: uid,
        endpoint: Some("127.0.0.1:7443".parse().unwrap()),
        server_name: "localhost".into(),
        public_origin: None,
        https_der: None,
        https_system_roots: false,
        ca_der: B64.encode(ca.to_der().unwrap()),
        certificate_der: B64.encode(ca.to_der().unwrap()),
        key_der: B64.encode(key.private_key_to_pkcs8().unwrap()),
        identity_rotation: None,
        completed_identity_rotation: None,
    };
    let bytes = serde_json::to_vec(&stored).unwrap();
    publish(&data, &bytes).unwrap();
    let invitation = |server_name: &str| {
        serde_json::to_vec(&JoinInvitation {
            host_id,
            mode: if uid == 0 {
                Mode::Rootful
            } else {
                Mode::Rootless
            },
            execution_uid: uid,
            token: "public fixture token".into(),
            ca_der: stored.ca_der.clone(),
            public_origin: String::new(),
            https_der: None,
            https_system_roots: false,
            endpoint: Some("127.0.0.2:8443".parse().unwrap()),
            server_name: server_name.into(),
        })
        .unwrap()
    };
    let url = "https://infraternal-fixture-no-such-host.invalid/remote/join";
    let error = join(url, &data, &invitation("localhost"))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "The infraternal agent on this host cannot reach the server over HTTPS. Allow outbound TCP 443 to the server's public origin, then try again."
    );
    let error = join(url, &data, &invitation("renamed.invalid"))
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "remote infraternal agent operation refused"
    );
    assert_eq!(std::fs::read(data.join("identity.json")).unwrap(), bytes);
}

/// A re-enrollment never overwrites an identity that changed after its key
/// was read (#230): another join or a renewal published in between wins.
#[test]
fn replace_aborts_when_the_identity_changed_since_it_was_read() {
    let directory = Directory::new();
    let data = directory.0.join("data");
    let key = PKey::generate_ed25519().unwrap();
    let ca = self_signed(&key);
    let mut stored = StoredIdentity {
        host_id: uuid::Uuid::new_v4(),
        execution_uid: nix::unistd::Uid::effective().as_raw(),
        endpoint: Some("127.0.0.1:7443".parse().unwrap()),
        server_name: "localhost".into(),
        public_origin: None,
        https_der: None,
        https_system_roots: false,
        ca_der: B64.encode(ca.to_der().unwrap()),
        certificate_der: B64.encode(ca.to_der().unwrap()),
        key_der: B64.encode(key.private_key_to_pkcs8().unwrap()),
        identity_rotation: None,
        completed_identity_rotation: None,
    };
    publish(&data, &serde_json::to_vec(&stored).unwrap()).unwrap();
    let (_, snapshot) = load_snapshot(&data).unwrap();
    stored.endpoint = Some("127.0.0.3:7443".parse().unwrap());
    let renewed = serde_json::to_vec(&stored).unwrap();
    replace(&data, &renewed, None).unwrap();
    assert_eq!(
        replace(&data, b"stale re-enrollment", Some(&snapshot))
            .unwrap_err()
            .to_string(),
        "remote infraternal agent operation refused"
    );
    assert_eq!(std::fs::read(data.join("identity.json")).unwrap(), renewed);
    assert_eq!(std::fs::read_dir(&data).unwrap().count(), 1);
    let (_, current) = load_snapshot(&data).unwrap();
    replace(&data, &renewed, Some(&current)).unwrap();
}
