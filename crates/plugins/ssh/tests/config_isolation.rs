//! Proves the command child preserves public trust settings while excluding additive configured identity paths.
#![allow(clippy::unwrap_used)]

mod common;
use infraternal_plugin_ssh::{
    model::{Destination, MeshEvidence},
    openssh::OpenSsh,
    transport::{Credentials, Input, SshTransport},
};
use std::{os::unix::fs::PermissionsExt, time::Duration};

#[tokio::test]
async fn configured_identity_paths_are_not_inherited_by_the_command_child() {
    let root = common::scratch().join(format!("cfg-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&root).unwrap();
    let wrapper = root.join("ssh");
    std::fs::write(&wrapper, r#"#!/bin/sh
# Only synthetic public configuration is returned; no credential path is accessed.
case "$1" in
-G) printf '%s\n' 'hostname fixture.invalid' 'port 2222' 'proxyjump none' 'proxycommand none' 'userknownhostsfile /nonexistent/infraternal-public-trust' 'identityfile /nonexistent/infraternal-identity' 'certificatefile /nonexistent/infraternal-certificate'; exit 0;;
esac
empty_config=no
public_trust=no
while [ "$#" -gt 0 ]; do
  case "$1" in
    -F) shift; [ "$1" = /dev/null ] && empty_config=yes;;
    userknownhostsfile=*) public_trust=yes;;
    *infraternal-identity*|*infraternal-certificate*) exit 77;;
  esac
  shift
done
[ "$empty_config" = yes ] && [ "$public_trust" = yes ] || exit 77
printf '%s\n' 'isolated-public-policy'
"#).unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let adapter = OpenSsh {
        ssh: wrapper,
        ssh_agent: "unused".into(),
        ssh_add: "unused".into(),
        ssh_keyscan: "unused".into(),
        ssh_keygen: "unused".into(),
        askpass_binary: "unused".into(),
        scratch: root.clone(),
        command_timeout: Duration::from_secs(3),
    };
    let session = adapter
        .open(
            Destination::parse("user@alias.invalid").unwrap(),
            Credentials::ServerIdentity,
            MeshEvidence::default(),
        )
        .await
        .unwrap();
    let result = session.run("exit 0", Input::Empty).await;
    drop(session);
    std::fs::remove_dir_all(root).unwrap();
    let output = result.unwrap();
    assert_eq!(output.stdout, b"isolated-public-policy\n");
}
