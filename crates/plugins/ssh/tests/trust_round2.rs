//! Proves one-key trust and reconnect against a real SSH target offering all three key families.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_ssh::{
    model::{Destination, FailureKind, MeshEvidence},
    openssh::OpenSsh,
    transport::{ConfirmationAuthority, Credentials, Input, Operation, Secret, SshTransport},
    trust::TrustedOpenSsh,
};
use std::{io::Read, path::PathBuf, time::Duration};
struct Confirm;
impl ConfirmationAuthority for Confirm {
    fn authorize(&self) -> Operation<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}
#[tokio::test]
#[ignore = "scripts/test-ssh-host-trust.py supplies a real multi-key sshd and memory-held credentials"]
async fn multi_key_target_trusts_once_and_reconnects_without_a_loop() {
    let fixture = PathBuf::from(std::env::var_os("INFRATERNAL_SSH_FIXTURE").unwrap());
    let port = std::env::var("INFRATERNAL_SSH_FIXTURE_PORT").unwrap();
    let destination = Destination::parse(&format!(
        "{}@127.0.0.1:{port}",
        std::env::var("USER").unwrap()
    ))
    .unwrap();
    let ssh = TrustedOpenSsh::new(
        OpenSsh {
            ssh: fixture.join("ssh"),
            ssh_agent: "/usr/bin/ssh-agent".into(),
            ssh_add: "/usr/bin/ssh-add".into(),
            ssh_keyscan: "/usr/bin/ssh-keyscan".into(),
            ssh_keygen: "/usr/bin/ssh-keygen".into(),
            askpass_binary: std::env::current_exe().unwrap(),
            scratch: fixture.clone(),
            command_timeout: Duration::from_secs(15),
        },
        fixture.join("pins"),
    );
    let failure = ssh
        .open(
            destination.clone(),
            Credentials::Network,
            MeshEvidence::default(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(failure.kind, FailureKind::HostKey);
    assert_eq!(
        failure.fingerprints.len(),
        1,
        "stock sshd must expose only the selected connection key"
    );
    let expected = std::env::var("INFRATERNAL_SSH_EXPECTED_ED25519").unwrap();
    assert_eq!(failure.fingerprints[0], expected);
    ssh.confirm_host_key(
        destination.clone(),
        &failure.host_key_challenge.unwrap().to_string(),
        &failure.fingerprints[0],
        &Confirm,
    )
    .await
    .unwrap();
    let mut private = Vec::new();
    std::io::stdin()
        .take(24_577)
        .read_to_end(&mut private)
        .unwrap();
    for _ in 0..2 {
        let session = ssh
            .open(
                destination.clone(),
                Credentials::PrivateKey {
                    key: Secret::new(private.clone()),
                    passphrase: None,
                },
                MeshEvidence::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            session
                .run("printf connected", Input::Empty)
                .await
                .unwrap()
                .stdout,
            b"connected"
        );
    }
    assert_explicit_replacement(&ssh, &destination, &fixture).await;
    println!("METRIC host_keys=3 displayed_keys=1 trust_clicks=1 authenticated_connections=2");
}

#[tokio::test]
#[ignore = "scripts/test-ssh-host-trust.py supplies the real multi-key target"]
async fn long_data_directory_does_not_bound_the_ssh_helper_socket() {
    let fixture = PathBuf::from(std::env::var_os("INFRATERNAL_SSH_FIXTURE").unwrap());
    let destination = Destination::parse(&format!(
        "{}@127.0.0.1:{}",
        std::env::var("USER").unwrap(),
        std::env::var("INFRATERNAL_SSH_FIXTURE_PORT").unwrap()
    ))
    .unwrap();
    let long = fixture.join("data-directory-".repeat(10));
    let ssh = TrustedOpenSsh::new(
        OpenSsh {
            ssh: fixture.join("ssh"),
            ssh_agent: "/usr/bin/ssh-agent".into(),
            ssh_add: "/usr/bin/ssh-add".into(),
            ssh_keyscan: "/usr/bin/ssh-keyscan".into(),
            ssh_keygen: "/usr/bin/ssh-keygen".into(),
            askpass_binary: std::env::current_exe().unwrap(),
            scratch: long.clone(),
            command_timeout: Duration::from_secs(15),
        },
        fixture.join("long-pins"),
    );
    let failure = ssh
        .open(destination, Credentials::Network, MeshEvidence::default())
        .await
        .err()
        .unwrap();
    assert_eq!(
        failure.kind,
        FailureKind::HostKey,
        "long data prefixes must reach SSH trust instead of failing socket creation"
    );
    assert!(
        !long.exists(),
        "socket helpers must live in the runtime directory"
    );
}

/// A changed public pin requires a new observation and rejects superseded confirmations.
async fn assert_explicit_replacement(
    ssh: &TrustedOpenSsh,
    destination: &Destination,
    fixture: &std::path::Path,
) {
    // Model a changed host key with the prior public pin. The actual target
    // still offers every family; only explicit confirmation may replace this pin.
    let pin = std::fs::read_dir(fixture.join("pins"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let original = std::fs::read(&pin).unwrap();
    std::fs::write(&pin, std::fs::read(fixture.join("old.pub")).unwrap()).unwrap();
    let changed = ssh
        .open(
            destination.clone(),
            Credentials::Network,
            MeshEvidence::default(),
        )
        .await
        .err()
        .unwrap();
    let concurrent = ssh
        .open(
            destination.clone(),
            Credentials::Network,
            MeshEvidence::default(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(changed.kind, FailureKind::HostKey);
    assert!(
        changed.host_key_challenge.is_some(),
        "changed application pins can be rechecked"
    );
    ssh.confirm_host_key(
        destination.clone(),
        &changed.host_key_challenge.unwrap().to_string(),
        &changed.fingerprints[0],
        &Confirm,
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(&pin).unwrap(), original);
    assert!(
        ssh.confirm_host_key(
            destination.clone(),
            &concurrent.host_key_challenge.unwrap().to_string(),
            &concurrent.fingerprints[0],
            &Confirm
        )
        .await
        .is_err(),
        "an older observation cannot replace a later confirmation"
    );
    let checked = ssh
        .open(
            destination.clone(),
            Credentials::Network,
            MeshEvidence::default(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(
        checked.kind,
        FailureKind::Auth,
        "the confirmed key must pass verification on recheck"
    );
}
