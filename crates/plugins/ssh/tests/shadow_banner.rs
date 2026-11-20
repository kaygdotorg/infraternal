//! Shadow review (#189): the master's diagnostic budget must not depend on the size of a host's login banner.
//!
//! OpenSSH writes a server's pre-authentication banner to stderr only when the
//! effective `LogLevel` is INFO or more verbose. The master used to run at ERROR,
//! so banners never reached the bounded 8 KiB pre-authentication diagnostics.
//! At VERBOSE they do. The fixture asks the real OpenSSH option parser for the
//! effective level and emits a banner exactly when OpenSSH would.
#![allow(clippy::unwrap_used)]

mod common;
use infraternal_plugin_ssh::{
    model::{Destination, MeshEvidence},
    openssh::OpenSsh,
    transport::{Credentials, SshTransport},
};
use std::{os::unix::fs::PermissionsExt, time::Duration};

/// Banner policy remains correct while external SSH helpers await the host.
#[tokio::test]
async fn a_long_pre_authentication_banner_does_not_refuse_the_host() {
    let scratch = common::scratch();
    let root = scratch.join(format!(
        "bn-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = root.join("config");
    std::fs::write(
        &config,
        "# Public option fixture; no SSH connection is attempted.\nHost *\n  HostName 127.0.0.1\n",
    )
    .unwrap();
    // About 9 KiB of policy text, the size of a long legal notice.
    let banner = root.join("banner");
    std::fs::write(
        &banner,
        "Authorized use only. Activity on this system is monitored and recorded.\n".repeat(128),
    )
    .unwrap();
    let wrapper = root.join("ssh");
    let master = common::master_fixture(&root);
    std::fs::write(
        &wrapper,
        format!(
            r#"#!/bin/sh
case "$1" in
-G) /usr/bin/ssh -G -F '{config}' "$@" | /usr/bin/awk '/^(hostname|port|proxyjump|proxycommand|forkafterauthentication) /'; exit $?;;
esac
case " $* " in
  *" -M "*)
    level=$(/usr/bin/ssh -G -F '{config}' "$@" | /usr/bin/awk '/^loglevel / {{ print $2 }}')
    case "$level" in INFO|VERBOSE|DEBUG*) cat '{banner}' >&2;; esac
    exec /usr/bin/python3 '{master}' "$@";;
esac
exit 0
"#,
            config = config.display(),
            banner = banner.display(),
            master = master.display(),
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
        command_timeout: Duration::from_secs(5),
    };
    // This assertion covers banner policy, independently of how long real
    // ssh/awk/Python helpers wait for host scheduling or disk pages (#509).
    // Keep the runtime runnable so paused time cannot automatically advance
    // past the preflight or master deadline while an external child works.
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
                    "the banner fixture's external helper stopped making progress"
                );
                // Only wake the master's readiness poll after the child has
                // actually bound its socket. Host latency consumes no deadline.
                if root.join("master.ready").exists() {
                    tokio::time::advance(Duration::from_millis(10)).await;
                }
            },
        }
    };
    tokio::time::resume();
    let refusal = opened.as_ref().err().map(|error| error.message);
    drop(opened);
    std::fs::remove_dir_all(root).unwrap();
    assert!(
        refusal.is_none(),
        "a host's banner refused the connection: {refusal:?}"
    );
}
