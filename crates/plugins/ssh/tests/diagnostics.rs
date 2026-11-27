//! Checks that authentication/host-key/mesh diagnostics never expose raw remote text.
#![allow(clippy::unwrap_used)]

use infraternal_plugin_ssh::{
    model::{FailureKind, MeshEvidence},
    openssh::classify,
};

/// Both dial paths keep DNS, refused and timed-out connections distinct and private.
#[test]
fn dial_failures_name_the_cause_and_a_next_step() {
    for (line, expected) in [
        (
            "ssh: Could not resolve hostname private-sentinel: Name or service not known",
            "look up the host name",
        ),
        (
            "ssh: connect to host private-sentinel port 22: Connection refused",
            "refused the SSH connection",
        ),
        (
            "ssh: connect to host private-sentinel port 22: Connection timed out",
            "timed out",
        ),
        (
            "infraternal SSH connector: Could not resolve hostname",
            "look up the host name",
        ),
        (
            "infraternal SSH connector: Connection refused",
            "refused the SSH connection",
        ),
        (
            "infraternal SSH connector: Connection timed out",
            "timed out",
        ),
    ] {
        let failure = classify(line.as_bytes(), true, MeshEvidence::default());
        assert_eq!(failure.kind, FailureKind::Unreachable);
        assert!(failure.message.contains(expected), "{failure:?}");
        assert!(
            !serde_json::to_string(&failure)
                .unwrap()
                .contains("private-sentinel")
        );
    }
}

/// A changed key gets specific guidance while an unrecognized key still asks for review.
#[test]
fn host_key_mismatch_remains_a_trust_failure() {
    let changed = classify(
        b"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\nHost key verification failed.\r\n",
        true,
        MeshEvidence::default(),
    );
    let unknown = classify(
        b"Host key verification failed.\n",
        true,
        MeshEvidence::default(),
    );
    assert_eq!(changed.kind, FailureKind::HostKey);
    assert_eq!(unknown.kind, FailureKind::HostKey);
    assert!(changed.message.contains("differs from the trusted key"));
    assert!(unknown.message.contains("needs review"));
}

/// Only the protocol identification populates the recovery hint, and only fixed method names leave stderr.
#[test]
fn auth_failure_reports_offers_attempts_and_observed_ssh_software() {
    let output = b"debug1: kex.c:kex_exchange_identification():1534 (pid=42): Remote protocol version 2.0, remote software version NetBird-SSH-Server-0.83.2 private-sentinel\r\n\
debug1: sshconnect2.c:input_userauth_failure():601 (pid=42): Authentications that can continue: publickey,password,private-sentinel\r\n\
debug2: sshconnect2.c:userauth():526 (pid=42): we sent a publickey packet, wait for reply\r\n\
sshconnect2.c:userauth():517 (pid=42): user@private-sentinel: Permission denied (publickey,password).\r\n";
    let modern = String::from_utf8_lossy(output).replace("(pid=42)", "(bin=ssh, pid=42)");
    for output in [output.as_slice(), modern.as_bytes()] {
        let failure = classify(output, true, MeshEvidence::default());
        assert_eq!(failure.kind, FailureKind::Auth);
        let wire = serde_json::to_value(&failure).unwrap();
        assert_eq!(wire["ssh_server"], "netbird");
        assert!(
            failure
                .log_tail
                .contains(&"The SSH server offered sign-in with a password.")
        );
        assert!(
            failure
                .log_tail
                .contains(&"Tried signing in with an SSH key.")
        );
        assert!(
            !failure
                .log_tail
                .contains(&"Tried signing in with an SSH password.")
        );
        assert!(!wire.to_string().contains("private-sentinel"));
    }

    let wrong_source = b"debug1: kex.c:kex_exchange_identification():1509 (pid=42): banner line 0: NetBird-SSH-Server-0.83.2\r\nuser@host: Permission denied (publickey).\r\n";
    for (bytes, ssh_failure) in [(wrong_source.as_slice(), true), (output.as_slice(), false)] {
        let wire =
            serde_json::to_value(classify(bytes, ssh_failure, MeshEvidence::default())).unwrap();
        assert!(wire.get("ssh_server").is_none());
    }
}

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

/// Every installer exit status at every step and mode maps to its fixed public
/// text; a staging refusal (71) also names the setup location in Details (#394).
#[test]
fn bootstrap_status_mapping_covers_each_step_and_approved_mode() {
    use infraternal_plugin_ssh::model::{
        Failure, InstallMode, InstallStep, UNPROVEN_FILES, setup_location,
    };
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
            for status in [71, 72, 73, 1, 126, 255] {
                let mut failure = Failure::install("The remote bootstrap command failed.");
                failure.exit_status = Some(status);
                failure
                    .log_tail
                    .push("Remote command returned a failure status; raw output was withheld.");
                let failure = failure.at(step).in_mode(mode);
                let public = serde_json::to_value(&failure).unwrap();
                assert_eq!(public["exit_status"], status);
                assert!(public.get("failed_step").is_some());
                let path = if mode == InstallMode::Root {
                    "/var/lib/infraternal"
                } else {
                    "~/.local/share/infraternal"
                };
                // Only a staging refusal (71) names where it looked, in Details (#394).
                if status == 71 && !matches!(step, InstallStep::Join) {
                    assert_eq!(failure.log_tail, vec![setup_location(mode)]);
                    assert!(failure.log_tail[0].ends_with(path));
                } else {
                    assert_eq!(failure.log_tail, Vec::<&str>::new());
                }
                match status {
                    71..=73 if matches!(step, InstallStep::Join) => {
                        assert!(
                            failure
                                .message
                                .starts_with("Joining the host to this server failed.")
                        );
                        assert!(!failure.message.contains("Move it aside"));
                        assert!(!failure.message.contains("Finish its cleanup"));
                    }
                    71 => {
                        // One finding, no folder chore, no path in the sentence (#394, TASTE).
                        // A refusal the host did not name has the plain sentence,
                        // never "set up elsewhere" (J314 P2-1).
                        assert_eq!(failure.kind, FailureKind::UnprovenFiles);
                        assert_eq!(failure.message, UNPROVEN_FILES);
                        assert!(!failure.message.contains(path));
                        assert!(!failure.message.contains("Check"));
                    }
                    72 => {
                        assert!(failure.message.contains("Retry the host check"));
                        assert!(!failure.message.contains(path));
                        assert!(!failure.message.contains("Finish its cleanup"));
                    }
                    73 => {
                        assert_eq!(failure.kind, FailureKind::SetupRunning);
                        assert!(
                            failure
                                .message
                                .starts_with("Setup is already running on this host")
                        );
                        assert!(failure.message.contains("Wait"));
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

#[test]
fn failure_diagnostics_distinguish_auth_trust_transport_and_channel_without_raw_text() {
    use infraternal_plugin_ssh::model::{Failure, FailureKind, InstallStep};
    assert_eq!(
        Failure::new(FailureKind::Auth, "static").diagnostic_kind(),
        "auth"
    );
    assert_eq!(
        Failure::new(FailureKind::HostKey, "static").diagnostic_kind(),
        "host-key"
    );
    assert_eq!(
        Failure::new(FailureKind::Unreachable, "static").diagnostic_kind(),
        "transport"
    );
    let mut command = Failure::install("static").at_ssh_boundary(true);
    command.exit_status = Some(1);
    let command = command.at_ssh_boundary(true).at(InstallStep::Connect);
    assert_eq!(command.diagnostic_kind(), "setup");
    assert!(
        !command
            .log_tail
            .contains(&"The SSH command channel failed.")
    );
    assert!(
        !serde_json::to_string(&command)
            .unwrap()
            .contains("private-sentinel")
    );
}

#[test]
fn engine_failures_keep_their_ssh_boundary_without_remote_bytes() {
    for (connection_setup, expected) in [(true, "transport"), (false, "channel")] {
        let failure = classify(
            b"private-engine-sentinel",
            connection_setup,
            MeshEvidence::default(),
        );
        assert_eq!(failure.diagnostic_kind(), expected);
        assert!(
            !serde_json::to_string(&failure)
                .unwrap()
                .contains("private-engine-sentinel")
        );
    }
}

/// Every authenticated script status names the command, never a failed SSH channel.
#[test]
fn script_status_diagnostics_are_honest_for_all_nonzero_codes() {
    use infraternal_plugin_ssh::model::{Failure, InstallStep};
    for status in 1..=255 {
        let mut failure = Failure::install("static").at_ssh_boundary(true);
        failure.exit_status = Some(status);
        let failure = failure.at_ssh_boundary(true).at(InstallStep::Install);
        assert_eq!(failure.diagnostic_kind(), "setup");
        assert!(
            !failure
                .log_tail
                .contains(&"The SSH command channel failed.")
        );
        assert_eq!(failure.exit_status, Some(status));
    }
}

/// Recovery distinguishes missing probe support and uncertain liveness from SSH failures.
#[test]
fn control_probe_statuses_preserve_actionable_setup_messages() {
    use infraternal_plugin_ssh::model::{Failure, InstallMode, InstallStep};
    for (status, fragment) in [
        (76, "matching infraternal binary"),
        (77, "could not determine"),
    ] {
        for mode in [InstallMode::Rootless, InstallMode::Root] {
            let mut failure = Failure::install("static").at(InstallStep::Install);
            failure.exit_status = Some(status);
            let inspected = infraternal_plugin_ssh::previous_attempt::classify(failure.clone());
            let rollback = failure.clone().in_mode(mode);
            for classified in [inspected, rollback] {
                assert!(classified.message.contains(fragment));
                assert!(classified.message.contains("files were kept"));
                assert_eq!(classified.exit_status, Some(status));
                assert_eq!(classified.diagnostic_kind(), "setup");
            }
            let joined = failure.at(InstallStep::Join);
            let expected = joined.message;
            assert_eq!(
                joined.in_mode(mode).message,
                expected,
                "the uploaded command's status is not a probe receipt"
            );
        }
    }
}
