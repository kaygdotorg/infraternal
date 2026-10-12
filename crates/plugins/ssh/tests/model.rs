//! Exercises untrusted address/admission/remote-output boundaries without contacting a host.
#![allow(clippy::unwrap_used)]

use infraternal_plugin_ssh::{
    model::{Destination, InstallMode, Target, TargetAddress},
    probe::Check,
};

#[test]
fn addresses_never_become_options_or_shell_syntax() {
    for text in [
        "user@host",
        "user@host:2222",
        "user@[::1]:22",
        "user@[2001:db8::1]",
        "user@10.0.0.1",
    ] {
        assert!(Destination::parse(text).is_ok(), "{text}");
    }
    for text in [
        "host",
        "-o@host",
        "user@-oProxyCommand=x",
        "user@host;touch x",
        "user@$(id)",
        "user@host:0",
        "user@host:65536",
        "user@host:+22",
        "user@host:22:23",
        "user@::1",
        "user@[::1]oops",
        "user@h\n-o",
        "user@host@host",
        "user name@host",
        "user@[x]",
    ] {
        assert!(Destination::parse(text).is_err(), "{text}");
    }
}

#[test]
fn root_consent_is_required_before_ssh_and_uid_zero_cannot_be_rootless() {
    let mut target = Target {
        id: "one".into(),
        address: TargetAddress::Manual("root@host".into()),
        credential: None,
        mode: InstallMode::Root,
        root_consent: false,
    };
    assert!(target.validate().is_err());
    target.root_consent = true;
    assert!(target.validate().is_ok());
    let check =
        Check::parse(b"INFRATERNAL_CHECK_V1\nLinux\naarch64\nsystemd\n0\nyes\nyes\nno\nno\n")
            .unwrap();
    assert!(check.authorize_mode(InstallMode::Rootless).is_err());
    assert!(check.authorize_mode(InstallMode::Root).is_ok());
}

#[test]
fn check_is_exact_bounded_and_rejects_every_truncation() {
    let record = b"INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\n";
    let check = Check::parse(record).unwrap();
    assert_eq!(check.uid, 1002);
    for count in 0..record.len() {
        assert!(Check::parse(&record[..count]).is_err());
    }
    let mut suffix = record.to_vec();
    suffix.extend_from_slice(b"secret");
    assert!(Check::parse(&suffix).is_err());
    for text in ["01002", "+1002", "4294967296", "1002\n", "secret", "1002\r"] {
        assert!(
            Check::parse(
                String::from_utf8_lossy(record)
                    .replace("1002", text)
                    .as_bytes()
            )
            .is_err()
        );
    }
    assert!(Check::parse(&[b'a'; 257]).is_err());
    assert!(Check::parse(&[0xff]).is_err());
}

#[test]
fn consent_and_credential_references_are_the_only_request_authority() {
    assert!(serde_json::from_str::<Target>(r#"{"id":"one","address":{"kind":"manual","value":"user@host"},"password":"do-not-accept"}"#).is_err());
    assert!(
        serde_json::from_str::<Target>(
            r#"{"id":"one","address":{"kind":"discovered","value":"peer","mesh_reachable":true}}"#
        )
        .is_err()
    );
}

#[test]
fn passwordless_sudo_keeps_default_rootless_without_explicit_consent() {
    let mut target: Target =
        serde_json::from_str(r#"{"id":"one","address":{"kind":"manual","value":"user@host"}}"#)
            .unwrap();
    let check =
        Check::parse(b"INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nyes\nyes\nyes\nno\n")
            .unwrap();
    assert_eq!(target.mode, InstallMode::Rootless);
    assert!(!target.root_consent);
    assert!(target.validate().is_ok());
    assert!(check.authorize_mode(target.mode).is_ok());
    target.mode = InstallMode::Root;
    assert!(target.validate().is_err());
    target.root_consent = true;
    assert!(target.validate().is_ok());
    assert!(check.authorize_mode(target.mode).is_ok());
}

#[test]
fn start_fresh_is_declared_as_an_owned_host_provisioning_action() {
    let action = infraternal_plugin_ssh::manifest::DESCRIPTOR
        .actions
        .iter()
        .find(|action| action.id == "ssh.start-fresh")
        .unwrap();
    assert_eq!(action.summary, "Start fresh");
    assert!(matches!(
        action.permission,
        infraternal_plugin_api::Permission::One("ssh.manage")
    ));
}
