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

#[test]
fn failed_join_retains_only_the_allowlisted_host_dns_error() {
    let failure = classify(
        b"Join DNS lookup failed: Temporary failure in name resolution.\nprivate-sentinel\n",
        false,
        MeshEvidence::default(),
    );
    assert!(
        failure
            .log_tail
            .contains(&"Join DNS lookup failed: Temporary failure in name resolution.")
    );
    assert!(
        !serde_json::to_string(&failure)
            .unwrap()
            .contains("private-sentinel")
    );
}

#[test]
fn every_failed_step_names_the_step_and_a_next_action() {
    use infraternal_plugin_ssh::model::{Failure, InstallStep};
    for step in [
        InstallStep::Connect,
        InstallStep::Upload,
        InstallStep::Install,
        InstallStep::Join,
        InstallStep::Start,
    ] {
        let failure = Failure::install("The remote bootstrap command failed.").at(step);
        assert!(
            failure.message.contains("Check") || failure.message.contains("Try"),
            "{}",
            failure.message
        );
    }
}

#[test]
fn bootstrap_status_mapping_covers_each_step_and_approved_mode() {
    use infraternal_plugin_ssh::model::{Failure, InstallMode, InstallStep};
    println!(
        "METRIC failure_bytes={} retained_events=1024 failure_storage_bytes={}",
        std::mem::size_of::<Failure>(),
        std::mem::size_of::<Failure>() * 1024
    );
    for mode in [InstallMode::Rootless, InstallMode::Root] {
        for step in [
            InstallStep::Connect,
            InstallStep::Upload,
            InstallStep::Install,
            InstallStep::Join,
            InstallStep::Start,
        ] {
            for status in [71, 72, 1, 126, 255] {
                let mut failure = Failure::install("The remote bootstrap command failed.");
                failure.exit_status = Some(status);
                failure
                    .log_tail
                    .push("Remote command returned a failure status; raw output was withheld.");
                let failure = failure.at(step).in_mode(mode);
                let public = serde_json::to_value(&failure).unwrap();
                assert_eq!(public["exit_status"], status);
                assert!(public.get("failed_step").is_some());
                assert_eq!(failure.log_tail, Vec::<&str>::new());
                let path = if mode == InstallMode::Root {
                    "/var/lib/infraternal"
                } else {
                    "~/.local/share/infraternal"
                };
                match status {
                    71 | 72 if matches!(step, InstallStep::Join) => {
                        assert!(
                            failure
                                .message
                                .starts_with("Joining the host to this server failed.")
                        );
                        assert!(!failure.message.contains("Move it aside"));
                        assert!(!failure.message.contains("Finish its cleanup"));
                    }
                    71 => {
                        assert!(failure.message.contains(path));
                        assert!(failure.message.contains("Move it aside"));
                    }
                    72 => {
                        assert!(failure.message.contains(path));
                        assert!(failure.message.contains("Finish its cleanup"));
                    }
                    _ => assert!(failure.message.contains("Check")),
                }
            }
        }
    }
}

#[test]
fn status_mapping_preserves_authentication_and_missing_payload_classification() {
    use infraternal_plugin_ssh::model::{Failure, InstallMode, InstallStep};
    let mut failure = Failure::new(FailureKind::Auth, "Authentication was refused.");
    failure.exit_status = Some(71);
    assert_eq!(
        failure
            .at(InstallStep::Connect)
            .in_mode(InstallMode::Root)
            .message,
        "Authentication was refused."
    );
    assert_eq!(
        Failure::install("The matching static infraternal binary is unavailable.")
            .at(InstallStep::Upload)
            .message,
        "The matching static infraternal binary is unavailable."
    );
}
