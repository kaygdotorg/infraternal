//! Proves two commands share one real SSH connection and lost masters never re-use one-time credentials.
#![allow(clippy::unwrap_used)]

use infraternal_plugin_ssh::{
    model::{Destination, FailureKind, MeshEvidence},
    openssh::OpenSsh,
    transport::{Credentials, Input, Secret, SshTransport},
};
use std::{io::Read, path::PathBuf, time::Duration};

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
    let adapter = OpenSsh {
        ssh: fixture.join("ssh"),
        ssh_agent: "/usr/bin/ssh-agent".into(),
        ssh_add: "/usr/bin/ssh-add".into(),
        ssh_keyscan: "/usr/bin/ssh-keyscan".into(),
        ssh_keygen: "/usr/bin/ssh-keygen".into(),
        askpass_binary: std::env::current_exe().unwrap(),
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
