//! Proves two commands share one real SSH connection and lost masters never re-use one-time credentials.
#![allow(clippy::unwrap_used)]

use infraternal_plugin_ssh::{
    model::{Destination, FailureKind, MeshEvidence},
    openssh::OpenSsh,
    transport::{Credentials, Input, Secret, SshTransport},
};
use std::{io::Read, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};

#[tokio::test]
#[ignore = "run through the rootless real-sshd fixture, selecting this test only"]
async fn one_physical_connection_erases_helpers_and_refuses_reconnect() {
    let fixture = PathBuf::from(std::env::var_os("INFRATERNAL_SSH_FIXTURE").unwrap());
    let port = std::env::var("INFRATERNAL_SSH_FIXTURE_PORT").unwrap();
    let user = std::env::var("USER").unwrap();
    let mut private = Vec::new();
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut private)
        .unwrap();
    assert!(private.len() <= 65536);
    let lookup = fixture.join("public-lookup");
    let called = fixture.join("public-lookup-called");
    std::fs::write(&lookup, format!("#!/bin/sh\n# Check helper isolation without recording environment values.\n[ -z \"${{SSH_AUTH_SOCK+x}}\" ] && [ -z \"${{INFRATERNAL_SSH_ASKPASS_SOCKET+x}}\" ] && [ -z \"${{SSH_ASKPASS+x}}\" ] || exit 1\nprintf 'lookup\\n' >> '{}'\ncat '{}'\n", called.display(), fixture.join("known_hosts").display())).unwrap();
    std::fs::set_permissions(&lookup, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(fixture.join("lookup-config"), format!("# Isolated dynamic public host trust.\nHost *\n UserKnownHostsFile /dev/null\n GlobalKnownHostsFile /dev/null\n KnownHostsCommand {}\n", lookup.display())).unwrap();
    let wrapper = fixture.join("lookup-ssh");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec /usr/bin/ssh -F '{}' \"$@\"\n",
            fixture.join("lookup-config").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let adapter = OpenSsh {
        ssh: wrapper,
        ssh_agent: "/usr/bin/ssh-agent".into(),
        ssh_add: "/usr/bin/ssh-add".into(),
        ssh_keyscan: "/usr/bin/ssh-keyscan".into(),
        ssh_keygen: "/usr/bin/ssh-keygen".into(),
        askpass_binary: std::env::current_exe().unwrap(),
        tcp_connector: None,
        scratch: fixture.clone(),
        command_timeout: Duration::from_secs(15),
    };
    let session = adapter
        .open(
            Destination::parse(&format!("{user}@127.0.0.1:{port}")).unwrap(),
            Credentials::PrivateKey {
                key: Secret::new(private),
                passphrase: None,
            },
            MeshEvidence::default(),
        )
        .await
        .unwrap();
    assert!(std::fs::read_to_string(called).unwrap().lines().count() >= 1);
    let connection = "printf '%s\\n' \"$SSH_CONNECTION\"";
    let first = session.run(connection, Input::Empty).await.unwrap();
    let second = session.run(connection, Input::Empty).await.unwrap();
    assert_ne!(first.stdout, [] as [u8; 0]);
    assert!(
        first.stdout == second.stdout,
        "commands opened different physical SSH connections"
    );
    let directory = std::fs::read_dir(&fixture)
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().starts_with("ssh-"))
        .unwrap()
        .path();
    assert!(
        !directory.join("agent.sock").exists(),
        "key helper survived authentication"
    );
    assert!(
        !directory.join("askpass.sock").exists(),
        "prompt helper survived authentication"
    );
    let socket = directory.join("c");
    assert!(socket.exists());
    let stopped = tokio::process::Command::new("/usr/bin/ssh")
        .args(["-F", "/dev/null", "-O", "exit", "-S"])
        .arg(&socket)
        .args(["--", "127.0.0.1"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .unwrap();
    assert!(stopped.success());
    tokio::time::timeout(Duration::from_secs(2), async {
        while socket.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let refused = session.run("exit 0", Input::Empty).await;
    assert!(
        matches!(refused, Err(error) if matches!(error.kind, FailureKind::Unreachable | FailureKind::Install)),
        "lost connection admitted a new login"
    );
    drop(session);
    assert!(!directory.exists(), "connection scope leaked artifacts");
}
