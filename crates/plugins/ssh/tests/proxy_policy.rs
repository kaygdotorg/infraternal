//! Uses the real SSH config parser to refuse proxy hops whose host-key policy the direct adapter cannot enforce.
#![allow(clippy::unwrap_used)]

mod common;
use infraternal_plugin_ssh::{
    model::{Destination, FailureKind, MeshEvidence},
    openssh::OpenSsh,
    transport::{Credentials, SshTransport},
};
use std::{os::unix::fs::PermissionsExt, time::Duration};

/// Refuse unverified proxy hops after parsing the real SSH configuration.
#[tokio::test]
async fn unchecked_proxy_hops_are_refused_before_credential_helpers_or_network() {
    let scratch = common::scratch();
    let root = scratch.join(format!("proxy-{}", uuid::Uuid::new_v4().simple()));
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
    // This checks proxy policy after real config parsing, independently of
    // host scheduling and disk-page latency in the external helper (#509).
    // Keep the runtime runnable so paused time cannot expire its preflight.
    tokio::time::pause();
    let opening = adapter.open(
        Destination::parse("user@fixture").unwrap(),
        Credentials::Network,
        MeshEvidence::default(),
    );
    tokio::pin!(opening);
    let hang_guard = std::time::Instant::now() + Duration::from_secs(600);
    let opened = loop {
        tokio::select! {
            biased;
            result = &mut opening => break result,
            () = tokio::task::yield_now() => {
                assert!(
                    std::time::Instant::now() < hang_guard,
                    "the proxy policy fixture's external helper stopped making progress"
                );
            },
        }
    };
    tokio::time::resume();
    std::fs::remove_dir_all(root).unwrap();
    let refusal = opened
        .as_ref()
        .err()
        .map(|error| (&error.kind, &error.message));
    assert!(
        matches!(&opened, Err(error) if error.kind == FailureKind::Unsupported),
        "proxy policy must refuse an unchecked hop: {refusal:?}"
    );
}
