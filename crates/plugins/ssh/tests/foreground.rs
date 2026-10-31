//! Uses the real OpenSSH option parser to verify foreground option precedence for bootstrap children.
#![allow(clippy::unwrap_used)]

mod common;
use infraternal_plugin_ssh::{
    model::{Destination, MeshEvidence},
    openssh::OpenSsh,
    transport::{Credentials, Input, SshTransport},
};
use std::{os::unix::fs::PermissionsExt, time::Duration};

#[tokio::test]
async fn configured_backgrounding_is_overridden_for_owned_bootstrap_commands() {
    let scratch = common::scratch();
    let root = scratch.join(format!(
        "fg-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = root.join("config");
    std::fs::write(&config, "# Public option fixture; no SSH connection is attempted.\nHost *\n  HostName 127.0.0.1\n  ForkAfterAuthentication yes\n").unwrap();
    let wrapper = root.join("ssh");
    let master = common::master_fixture(&root);
    std::fs::write(&wrapper, format!(r#"#!/bin/sh
case "$1" in
-G) /usr/bin/ssh -G -F '{}' "$@" | /usr/bin/awk '/^(hostname|port|proxyjump|proxycommand|forkafterauthentication) /'; exit $?;;
esac
case " $* " in
  *" -M "*) /usr/bin/ssh -G -F '{}' "$@" | /usr/bin/awk '/^forkafterauthentication /' > '{}'; exec /usr/bin/python3 '{}' "$@";;
esac
/usr/bin/ssh -G -F '{}' "$@" | /usr/bin/awk '/^forkafterauthentication /'
"#, config.display(), config.display(), root.join("master-options").display(), master.display(), config.display())).unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let adapter = OpenSsh {
        ssh: wrapper,
        ssh_agent: "unused".into(),
        ssh_add: "unused".into(),
        ssh_keyscan: "unused".into(),
        ssh_keygen: "unused".into(),
        askpass_binary: "unused".into(),
        tcp_connector: None,
        scratch: root.clone(),
        command_timeout: Duration::from_secs(3),
    };
    let session = adapter
        .open(
            Destination::parse("user@fixture").unwrap(),
            Credentials::Network,
            MeshEvidence::default(),
        )
        .await
        .unwrap();
    let effective = session.run("exit 0", Input::Empty).await.unwrap();
    let master_policy = std::fs::read_to_string(root.join("master-options")).unwrap();
    drop(session);
    std::fs::remove_dir_all(root).unwrap();
    assert_eq!(master_policy, "forkafterauthentication no\n");
    assert!(
        std::str::from_utf8(&effective.stdout)
            .unwrap()
            .lines()
            .any(|line| line == "forkafterauthentication no"),
        "configured backgrounding was not overridden"
    );
}
