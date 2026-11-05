//! Proves first-contact confirmation, fresh authority and immutable pins against the disposable real sshd.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_ssh::{
    model::{Destination, Failure, FailureKind, MeshEvidence},
    openssh::OpenSsh,
    transport::{ConfirmationAuthority, Credentials, Input, Operation, Secret, SshTransport},
    trust::TrustedOpenSsh,
};
use std::{io::Read, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};

struct Authority(bool);
impl ConfirmationAuthority for Authority {
    fn authorize(&self) -> Operation<'_, ()> {
        Box::pin(async move {
            if self.0 {
                Ok(())
            } else {
                Err(Failure::new(
                    FailureKind::Auth,
                    "Confirmation authority was revoked.",
                ))
            }
        })
    }
}

async fn observe(ssh: &TrustedOpenSsh, destination: &Destination) -> Failure {
    let result = ssh
        .open(
            destination.clone(),
            Credentials::Network,
            MeshEvidence::default(),
        )
        .await;
    let failure = result
        .err()
        .expect("unknown trust must refuse before authentication");
    assert_eq!(failure.kind, FailureKind::HostKey);
    assert!(failure.host_key_challenge().is_some());
    assert_ne!(failure.fingerprints.len(), 0);
    failure
}

#[tokio::test]
#[ignore = "run through research/ssh-client/measure.py --negative-trust-oracle with its memory-held synthetic key"]
async fn first_contact_needs_fresh_authority_and_never_replaces_existing_trust() {
    let fixture = PathBuf::from(std::env::var_os("INFRATERNAL_SSH_FIXTURE").unwrap());
    let port = std::env::var("INFRATERNAL_SSH_FIXTURE_PORT").unwrap();
    let user = std::env::var("USER").unwrap();
    let destination = Destination::parse(&format!("{user}@127.0.0.1:{port}")).unwrap();
    let known = fixture.join("confirmation-known");
    std::fs::write(&known, "").unwrap();
    let configuration = fixture.join("confirmation-config");
    std::fs::write(&configuration, format!("# Isolated first-contact public trust oracle.\nHost *\n UserKnownHostsFile {}\n GlobalKnownHostsFile /dev/null\n IdentityFile none\n ConnectTimeout 10\n", known.display())).unwrap();
    let wrapper = fixture.join("confirmation-ssh");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec /usr/bin/ssh -F '{}' \"$@\"\n",
            configuration.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let pins = fixture.join("confirmed-pins");
    let ssh = TrustedOpenSsh::new(
        OpenSsh {
            ssh: wrapper,
            ssh_agent: "/usr/bin/ssh-agent".into(),
            ssh_add: "/usr/bin/ssh-add".into(),
            ssh_keyscan: "/usr/bin/ssh-keyscan".into(),
            ssh_keygen: "/usr/bin/ssh-keygen".into(),
            askpass_binary: std::env::current_exe().unwrap(),
            tcp_connector: None,
            scratch: fixture.clone(),
            command_timeout: Duration::from_secs(15),
        },
        pins.clone(),
    );
    let rejected = observe(&ssh, &destination).await;
    assert!(
        ssh.confirm_host_key(
            destination.clone(),
            &rejected.host_key_challenge().unwrap().to_string(),
            &rejected.fingerprints[0],
            &Authority(false)
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read_dir(&pins).unwrap().count(), 0);
    let foreign = observe(&ssh, &destination).await;
    let other = Destination::parse(&format!("{user}@127.0.0.2:{port}")).unwrap();
    assert!(
        ssh.confirm_host_key(
            other,
            &foreign.host_key_challenge().unwrap().to_string(),
            &foreign.fingerprints[0],
            &Authority(true)
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read_dir(&pins).unwrap().count(), 0);
    // Trust introduced after observation must supersede our pending confirmation,
    // including revoked and CA records; they must never be rewritten or omitted.
    let original = std::fs::read_to_string(fixture.join("known_hosts")).unwrap();
    let record = original.lines().next().unwrap();
    for marker in ["", "@revoked ", "@cert-authority "] {
        let pending = observe(&ssh, &destination).await;
        std::fs::write(&known, format!("{marker}{record}\n")).unwrap();
        assert!(
            ssh.confirm_host_key(
                destination.clone(),
                &pending.host_key_challenge().unwrap().to_string(),
                &pending.fingerprints[0],
                &Authority(true)
            )
            .await
            .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(&known).unwrap(),
            format!("{marker}{record}\n")
        );
        assert_eq!(std::fs::read_dir(&pins).unwrap().count(), 0);
        std::fs::write(&known, "").unwrap();
    }
    // OpenSSH uses HostKeyAlias verbatim even on a nondefault port.
    let base_configuration = std::fs::read_to_string(&configuration).unwrap();
    let public_fields = record.split_once(' ').unwrap().1;
    for alias in ["fixture-alias", "none"] {
        std::fs::write(
            &configuration,
            format!("{base_configuration} HostKeyAlias {alias}\n"),
        )
        .unwrap();
        std::fs::write(&known, format!("@revoked {alias} {public_fields}\n")).unwrap();
        let alias_refused = ssh
            .open(
                destination.clone(),
                Credentials::Network,
                MeshEvidence::default(),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(alias_refused.kind, FailureKind::HostKey);
        assert!(
            alias_refused.host_key_challenge().is_none(),
            "an existing revoked alias cannot get a first-contact challenge: {alias}"
        );
        assert_eq!(std::fs::read_dir(&pins).unwrap().count(), 0);
    }
    std::fs::write(&configuration, base_configuration).unwrap();
    std::fs::write(&known, "").unwrap();
    let confirmed = observe(&ssh, &destination).await;
    let challenge = confirmed.host_key_challenge().unwrap().to_string();
    ssh.confirm_host_key(
        destination.clone(),
        &challenge,
        &confirmed.fingerprints[0],
        &Authority(true),
    )
    .await
    .unwrap();
    assert!(
        ssh.confirm_host_key(
            destination.clone(),
            &challenge,
            &confirmed.fingerprints[0],
            &Authority(true)
        )
        .await
        .is_err()
    );
    let pin = std::fs::read_dir(&pins)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let before = std::fs::read(&pin).unwrap();
    assert_eq!(
        std::fs::metadata(&pin).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut private = Vec::new();
    std::io::stdin()
        .take(24_577)
        .read_to_end(&mut private)
        .unwrap();
    assert!(private.len() <= 24_576);
    let session = ssh
        .open(
            destination.clone(),
            Credentials::PrivateKey {
                key: Secret::new(private),
                passphrase: None,
            },
            MeshEvidence::default(),
        )
        .await
        .unwrap();
    let output = session.run("printf confirmed", Input::Empty).await.unwrap();
    assert_eq!(output.stdout, b"confirmed");
    drop(session);
    // New configured trust never silently loses to the stored public pin.
    std::fs::write(&known, format!("@revoked {record}\n")).unwrap();
    let refused = ssh
        .open(destination, Credentials::Network, MeshEvidence::default())
        .await
        .err()
        .unwrap();
    assert_eq!(refused.kind, FailureKind::HostKey);
    assert!(refused.host_key_challenge().is_none());
    assert_eq!(std::fs::read(pin).unwrap(), before);
    println!(
        "METRIC first_contact fresh_authority=true foreign_target_refused=true existing_ca_revoked_refused=true confirmed_command=true pin_immutable=true"
    );
}

#[tokio::test]
#[ignore = "run through research/ssh-client/measure.py with its synthetic public host key"]
async fn configured_known_hosts_command_revocation_cannot_offer_first_contact() {
    let fixture = PathBuf::from(std::env::var_os("INFRATERNAL_SSH_FIXTURE").unwrap());
    let port = std::env::var("INFRATERNAL_SSH_FIXTURE_PORT").unwrap();
    let user = std::env::var("USER").unwrap();
    let destination = Destination::parse(&format!("{user}@127.0.0.1:{port}")).unwrap();
    let public = std::fs::read_to_string(fixture.join("known_hosts")).unwrap();
    let revoked = fixture.join("command-public-revocation");
    std::fs::write(
        &revoked,
        format!("@revoked {}\n", public.lines().next().unwrap()),
    )
    .unwrap();
    let configuration = fixture.join("command-revocation-config");
    std::fs::write(&configuration, format!("# Synthetic public revocation supplied by the configured trust command.\nHost *\n StrictHostKeyChecking yes\n UserKnownHostsFile /dev/null\n GlobalKnownHostsFile /dev/null\n KnownHostsCommand /bin/cat {}\n IdentityFile none\n IdentityAgent none\n BatchMode yes\n", revoked.display())).unwrap();
    let mut normal = tokio::process::Command::new("/usr/bin/ssh");
    normal.args(["-F"]).arg(&configuration).args([
        "-T",
        "-p",
        &port,
        "-l",
        &user,
        "127.0.0.1",
        "true",
    ]);
    let output =
        infraternal_plugin_ssh::process::execute(&mut normal, Input::Empty, Duration::from_secs(5))
            .await
            .unwrap();
    assert!(!output.success);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("revoked"),
        "normal OpenSSH must enforce the synthetic command's revocation"
    );
    let wrapper = fixture.join("command-revocation-ssh");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec /usr/bin/ssh -F '{}' \"$@\"\n",
            configuration.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let ssh = TrustedOpenSsh::new(
        OpenSsh {
            ssh: wrapper,
            ssh_agent: "/usr/bin/ssh-agent".into(),
            ssh_add: "/usr/bin/ssh-add".into(),
            ssh_keyscan: "/usr/bin/ssh-keyscan".into(),
            ssh_keygen: "/usr/bin/ssh-keygen".into(),
            askpass_binary: std::env::current_exe().unwrap(),
            tcp_connector: None,
            scratch: fixture.clone(),
            command_timeout: Duration::from_secs(5),
        },
        fixture.join("command-revocation-pins"),
    );
    let failure = ssh
        .open(destination, Credentials::Network, MeshEvidence::default())
        .await
        .err()
        .unwrap();
    assert!(
        failure.host_key_challenge().is_none(),
        "configured revoked key received a first-contact challenge"
    );
}
