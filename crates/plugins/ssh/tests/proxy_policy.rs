//! Uses the real SSH config parser to refuse proxy hops whose host-key policy the direct adapter cannot enforce.
#![allow(clippy::unwrap_used)]

mod common;
use infraternal_plugin_ssh::{
    model::{Destination, FailureKind, MeshEvidence},
    openssh::OpenSsh,
    transport::{Credentials, SshTransport},
};
use std::{os::unix::fs::PermissionsExt, time::Duration};

#[tokio::test]
async fn unchecked_proxy_hops_are_refused_before_credential_helpers_or_network() {
    let root = common::scratch().join(format!("proxy-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&root).unwrap();
    let config = root.join("config");
    std::fs::write(&config, "# Public config-parser fixture; never connects to a proxy.\nHost *\n  HostName 127.0.0.1\n  ProxyJump bootstrap-unknown.invalid\n").unwrap();
    let wrapper = root.join("ssh");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec /usr/bin/ssh -F '{}' \"$@\"\n",
            config.display()
        ),
    )
    .unwrap();
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
    let opened = adapter
        .open(
            Destination::parse("user@fixture").unwrap(),
            Credentials::Network,
            MeshEvidence::default(),
        )
        .await;
    std::fs::remove_dir_all(root).unwrap();
    assert!(
        matches!(opened, Err(error) if error.kind == FailureKind::Unsupported),
        "adapter admitted a proxy without enforcing its host-key policy"
    );
}
