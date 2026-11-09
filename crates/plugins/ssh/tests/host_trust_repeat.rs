//! A repeated "trust this host key" for the same pending key must answer success, and a different key must not.
//!
//! The person's second or third click on "Trust and continue" (a double-click, or a slow screen) sends the same
//! confirmation again. The first one pins the key and consumes the challenge, so the repeat used to be refused
//! with the generic host-key error even though the key was already trusted. These tests use stand-in `ssh` and
//! `ssh-keyscan` programs, so they need no network and no sshd; only the system `ssh` (for `-G`) and
//! `ssh-keygen` are real.
#![allow(clippy::unwrap_used, clippy::expect_used)]

/// Shared scratch-directory helper for the SSH fixtures.
mod common;
use infraternal_plugin_ssh::{
    model::{Destination, Failure, FailureKind, MeshEvidence},
    openssh::OpenSsh,
    transport::{ConfirmationAuthority, Credentials, Operation, SshTransport},
    trust::TrustedOpenSsh,
};
use std::{os::unix::fs::PermissionsExt, path::Path, process::Command, time::Duration};

/// A confirmation authority that is either live or revoked.
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

/// Writes an executable script into `path`.
fn script(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// Builds a trust store whose `ssh` always fails host-key verification and whose key scan returns one fresh key.
fn rig(root: &Path) -> (TrustedOpenSsh, Destination) {
    let known = root.join("known");
    std::fs::write(&known, "").unwrap();
    let config = root.join("config");
    std::fs::write(
        &config,
        format!(
            "Host *\n UserKnownHostsFile {}\n GlobalKnownHostsFile /dev/null\n IdentityFile none\n",
            known.display()
        ),
    )
    .unwrap();
    // `-G` prints the effective configuration for real; every other call is a connection that the stand-in
    // refuses the way OpenSSH refuses an unknown key.
    let ssh = root.join("ssh");
    script(
        &ssh,
        &format!(
            "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = -G ] && exec /usr/bin/ssh -F '{}' \"$@\"; done\necho 'Host key verification failed.' >&2\nexit 255\n",
            config.display()
        ),
    );
    let key = root.join("host-key");
    assert!(
        Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .unwrap()
            .success()
    );
    let public = std::fs::read_to_string(root.join("host-key.pub")).unwrap();
    let mut fields = public.split_whitespace();
    let line = format!(
        "scanned {} {}\n",
        fields.next().unwrap(),
        fields.next().unwrap()
    );
    let scan_output = root.join("scan-output");
    std::fs::write(&scan_output, line).unwrap();
    let keyscan = root.join("ssh-keyscan");
    script(
        &keyscan,
        &format!("#!/bin/sh\ncat '{}'\n", scan_output.display()),
    );
    let trust = TrustedOpenSsh::new(
        OpenSsh {
            ssh,
            ssh_agent: "unused".into(),
            ssh_add: "unused".into(),
            ssh_keyscan: keyscan,
            ssh_keygen: "/usr/bin/ssh-keygen".into(),
            askpass_binary: "unused".into(),
            tcp_connector: None,
            scratch: root.to_path_buf(),
            command_timeout: Duration::from_secs(5),
        },
        root.join("pins"),
    );
    (trust, Destination::parse("user@repeat.invalid").unwrap())
}

/// Opens the destination and returns the host-key failure with its challenge and fingerprint.
async fn observe(trust: &TrustedOpenSsh, destination: &Destination) -> (String, String) {
    let failure = trust
        .open(
            destination.clone(),
            Credentials::Network,
            MeshEvidence::default(),
        )
        .await
        .err()
        .expect("an unknown key must refuse before sign-in");
    assert_eq!(failure.kind, FailureKind::HostKey);
    (
        failure.host_key_challenge().unwrap().to_string(),
        failure.fingerprints[0].clone(),
    )
}

#[tokio::test]
/// The same confirmation sent again, one after another, answers success and writes exactly one pin.
async fn the_same_confirmation_repeated_answers_success_and_pins_once() {
    let scratch = common::scratch();
    let root = scratch.join(format!("repeat-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&root).unwrap();
    let (trust, destination) = rig(&root);
    let (challenge, fingerprint) = observe(&trust, &destination).await;
    let live = Authority(true);
    trust
        .confirm_host_key(destination.clone(), &challenge, &fingerprint, &live)
        .await
        .expect("the first confirmation pins the key");
    let pins = || std::fs::read_dir(root.join("pins")).unwrap().count();
    assert_eq!(pins(), 1);
    for repeat in 2..=3 {
        trust
            .confirm_host_key(destination.clone(), &challenge, &fingerprint, &live)
            .await
            .unwrap_or_else(|_| {
                panic!("confirmation {repeat} of the same key must answer success")
            });
    }
    assert_eq!(pins(), 1, "a repeat must not write another pin");
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
/// Three identical confirmations that arrive together all answer success: they take turns, none loses the consumed challenge.
async fn simultaneous_identical_confirmations_all_succeed() {
    let scratch = common::scratch();
    let root = scratch.join(format!("race-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&root).unwrap();
    let (trust, destination) = rig(&root);
    let (challenge, fingerprint) = observe(&trust, &destination).await;
    let live = Authority(true);
    let (a, b, c) = tokio::join!(
        trust.confirm_host_key(destination.clone(), &challenge, &fingerprint, &live),
        trust.confirm_host_key(destination.clone(), &challenge, &fingerprint, &live),
        trust.confirm_host_key(destination.clone(), &challenge, &fingerprint, &live),
    );
    assert!(a.is_ok() && b.is_ok() && c.is_ok(), "{a:?} {b:?} {c:?}");
    std::fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
/// A repeat is only for the exact key that was pinned: another key, another destination, a revoked sign-in or an unknown challenge stay refused.
async fn a_repeat_with_another_key_or_revoked_authority_is_still_refused() {
    let scratch = common::scratch();
    let root = scratch.join(format!("other-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&root).unwrap();
    let (trust, destination) = rig(&root);
    let (challenge, fingerprint) = observe(&trust, &destination).await;
    trust
        .confirm_host_key(
            destination.clone(),
            &challenge,
            &fingerprint,
            &Authority(true),
        )
        .await
        .unwrap();
    // A different (well-formed) key for the same challenge is never "already trusted".
    let other = format!("SHA256:{}", "a".repeat(43));
    assert!(
        trust
            .confirm_host_key(destination.clone(), &challenge, &other, &Authority(true))
            .await
            .is_err(),
        "a different key must stay refused"
    );
    // The same key for another destination is refused too.
    assert!(
        trust
            .confirm_host_key(
                Destination::parse("user@elsewhere.invalid").unwrap(),
                &challenge,
                &fingerprint,
                &Authority(true)
            )
            .await
            .is_err(),
        "another destination must stay refused"
    );
    // A repeat is not a way around a revoked sign-in.
    assert!(
        trust
            .confirm_host_key(
                destination.clone(),
                &challenge,
                &fingerprint,
                &Authority(false)
            )
            .await
            .is_err(),
        "a repeat still needs live authority"
    );
    // A challenge nobody issued is refused.
    assert!(
        trust
            .confirm_host_key(
                destination.clone(),
                &uuid::Uuid::new_v4().to_string(),
                &fingerprint,
                &Authority(true)
            )
            .await
            .is_err(),
        "an unknown challenge must stay refused"
    );
    std::fs::remove_dir_all(&root).unwrap();
}
