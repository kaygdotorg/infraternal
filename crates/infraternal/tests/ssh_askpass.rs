//! Proves the real hidden CLI responds only through a private socket, with no credential file or argv.
#![cfg(feature = "ssh")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "../../plugins/ssh/tests/common/mod.rs"]
mod common;

use infraternal_plugin_ssh::{
    credentials::{CredentialConfig, CredentialSession},
    transport::{Credentials, Secret},
};
use std::process::Stdio;
use tokio::process::Command;

#[tokio::test]
async fn real_cli_askpass_handoff_and_helper_cleanup() {
    let parent = common::scratch();
    let root = parent.join(format!("a-{}", std::process::id()));
    let session = CredentialSession::prepare(
        &CredentialConfig {
            scratch: root.clone(),
            ssh_agent: "unused".into(),
            ssh_add: "unused".into(),
            askpass_binary: env!("CARGO_BIN_EXE_infraternal").into(),
        },
        Credentials::Password(Secret::new(b"synthetic-prompt-reply".to_vec())),
    )
    .await
    .expect("prepare private prompt");
    let directory = std::fs::read_dir(&root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let output = Command::new(directory.join("askpass"))
        .arg("fixture-user@fixture-host's password: ")
        .env(
            "INFRATERNAL_SSH_ASKPASS_SOCKET",
            directory.join("askpass.sock"),
        )
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        .expect("run real askpass CLI");
    assert!(output.status.success());
    let reply = Secret::new(output.stdout);
    // Never format a private response on assertion failure.
    assert!(reply.expose().eq(b"synthetic-prompt-reply"));
    drop(reply);
    drop(session);
    assert!(!directory.exists());
    std::fs::remove_dir(root).unwrap();
}

#[tokio::test]
async fn real_cli_unlocks_an_encrypted_synthetic_key_on_private_pipes() {
    use tokio::io::AsyncWriteExt;
    let root = common::scratch().join(format!("e-{}", std::process::id()));
    let passphrase = Secret::new(b"synthetic-key-unlock\n".to_vec());
    let mut generating = Command::new("openssl")
        .args([
            "genrsa",
            "-traditional",
            "-aes256",
            "-passout",
            "stdin",
            "2048",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = generating.stdin.take().unwrap();
    input.write_all(passphrase.expose()).await.unwrap();
    drop(input);
    let generated = generating.wait_with_output().await.unwrap();
    assert!(generated.status.success());
    let session = CredentialSession::prepare(
        &CredentialConfig {
            scratch: root.clone(),
            ssh_agent: "/usr/bin/ssh-agent".into(),
            ssh_add: "/usr/bin/ssh-add".into(),
            askpass_binary: env!("CARGO_BIN_EXE_infraternal").into(),
        },
        Credentials::PrivateKey {
            key: Secret::new(generated.stdout),
            passphrase: Some(Secret::new(b"synthetic-key-unlock".to_vec())),
        },
    )
    .await
    .unwrap();
    let directory = std::fs::read_dir(&root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let public = Command::new("ssh-add")
        .arg("-L")
        .env("SSH_AUTH_SOCK", directory.join("agent.sock"))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(public.status.success());
    assert!(public.stdout.starts_with(b"ssh-rsa "));
    drop(session);
    assert!(!directory.exists());
    std::fs::remove_dir(root).unwrap();
}

#[tokio::test]
#[ignore = "run under the disposable controlling-terminal harness"]
async fn encrypted_key_without_passphrase_never_prompts_on_a_controlling_terminal() {
    use tokio::io::AsyncWriteExt;
    let root = common::scratch().join(format!("n-{}", std::process::id()));
    let passphrase = Secret::new(b"synthetic-key-unlock\n".to_vec());
    let mut generating = Command::new("openssl")
        .args([
            "genrsa",
            "-traditional",
            "-aes256",
            "-passout",
            "stdin",
            "2048",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = generating.stdin.take().unwrap();
    input.write_all(passphrase.expose()).await.unwrap();
    drop(input);
    let generated = generating.wait_with_output().await.unwrap();
    assert!(generated.status.success());
    let result = CredentialSession::prepare(
        &CredentialConfig {
            scratch: root.clone(),
            ssh_agent: "/usr/bin/ssh-agent".into(),
            ssh_add: "/usr/bin/ssh-add".into(),
            askpass_binary: env!("CARGO_BIN_EXE_infraternal").into(),
        },
        Credentials::PrivateKey {
            key: Secret::new(generated.stdout),
            passphrase: None,
        },
    )
    .await;
    let Err(error) = result else {
        panic!("encrypted key without passphrase must be refused")
    };
    assert_eq!(error.kind, infraternal_plugin_ssh::model::FailureKind::Auth);
    assert!(std::fs::read_dir(&root).unwrap().next().is_none());
    std::fs::remove_dir(root).unwrap();
}
