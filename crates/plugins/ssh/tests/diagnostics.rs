//! Checks that authentication/host-key/mesh diagnostics never expose raw remote text.
#![allow(clippy::unwrap_used)]

use infraternal_plugin_ssh::{
    model::{FailureKind, MeshEvidence},
    openssh::classify,
};

#[test]
fn mesh_policy_requires_both_discovery_facts_and_a_transport_refusal() {
    let peer = MeshEvidence {
        is_peer: true,
        reachable_otherwise: true,
    };
    assert_eq!(
        classify(b"Connection refused", true, peer).kind,
        FailureKind::MeshPolicy
    );
    for mesh in [
        MeshEvidence::default(),
        MeshEvidence {
            is_peer: true,
            reachable_otherwise: false,
        },
        MeshEvidence {
            is_peer: false,
            reachable_otherwise: true,
        },
    ] {
        assert_eq!(
            classify(b"Connection timed out", true, mesh).kind,
            FailureKind::Unreachable
        );
    }
    assert_eq!(
        classify(b"Could not resolve hostname", true, peer).kind,
        FailureKind::Unreachable
    );
    assert_eq!(
        classify(b"Permission denied", true, peer).kind,
        FailureKind::Auth
    );
    assert_eq!(
        classify(b"Host key verification failed", true, peer).kind,
        FailureKind::HostKey
    );
}

#[test]
fn remote_command_text_is_not_ssh_authority_and_never_enters_logs() {
    let output = b"Permission denied; Host key verification failed; secret-sentinel SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let failure = classify(output, false, MeshEvidence::default());
    assert_eq!(failure.kind, FailureKind::Install);
    assert_eq!(failure.fingerprints.len(), 0);
    assert!(
        !serde_json::to_string(&failure)
            .unwrap()
            .contains("secret-sentinel")
    );
}

#[test]
fn effective_configuration_never_scans_a_proxy_or_invalid_endpoint() {
    use infraternal_plugin_ssh::{model::Destination, openssh::scan_destination};
    let original = Destination::parse("user@alias").unwrap();
    let parsed = scan_destination(
        &original,
        b"hostname 127.0.0.1\nport 2222\nproxycommand none\n",
    )
    .unwrap();
    assert_eq!(parsed.host(), "127.0.0.1");
    assert_eq!(parsed.port(), Some(2222));
    for input in [
        b"hostname 127.0.0.1\nport 2222\nproxyjump peer\n".as_slice(),
        b"hostname 127.0.0.1\nport 2222\nproxycommand ssh peer\n",
        b"hostname 127.0.0.1\nport 2222\nport 22\n",
        b"hostname --option\nport 22\n",
        b"hostname localhost\nport 0\n",
    ] {
        assert!(scan_destination(&original, input).is_none());
    }
}

#[test]
fn dynamic_public_trust_is_retained_without_becoming_file_only_admission() {
    use infraternal_plugin_ssh::{config::PublicSshConfiguration, model::Destination};
    let original = Destination::parse("user@alias").unwrap();
    let config = PublicSshConfiguration::parse(
        &original,
        b"hostname fixture.invalid\nport 22\nknownhostscommand /public/tool '%h' %n\n",
    )
    .unwrap();
    let mut command = tokio::process::Command::new("ssh");
    config.configure(&mut command);
    assert!(
        command
            .as_std()
            .get_args()
            .any(|argument| { argument == "knownhostscommand=/usr/bin/env -u SSH_AUTH_SOCK -u INFRATERNAL_SSH_ASKPASS_SOCKET -u SSH_ASKPASS -u SSH_ASKPASS_REQUIRE -- /public/tool '%h' alias" })
    );
    // Parsing retains syntax for the native engine; this test never executes it.
    assert!(config.trust_policy().unwrap().dynamic_trust);
    let disabled = PublicSshConfiguration::parse(
        &original,
        b"hostname fixture.invalid\nport 22\nknownhostscommand none\n",
    )
    .unwrap();
    assert!(!disabled.trust_policy().unwrap().dynamic_trust);
    assert!(PublicSshConfiguration::parse(
        &original,
        b"hostname fixture.invalid\nport 22\nknownhostscommand none\nknownhostscommand /public/tool\n",
    ).is_none());
}
