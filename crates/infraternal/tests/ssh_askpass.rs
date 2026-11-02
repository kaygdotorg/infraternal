//! Proves the real hidden CLI responds only through a private socket, with no credential file or argv.
#![cfg(feature = "ssh")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "../../plugins/ssh/tests/common/mod.rs"]
mod common;

use infraternal_plugin_ssh::{
    credentials::{CredentialConfig, CredentialSession},
    transport::{Credentials, Secret},
};
use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex, OnceLock, Weak},
};
use tokio::process::Command;

async fn helper_output(command: &mut Command) -> std::io::Result<std::process::Output> {
    // Another test's fork can briefly inherit a helper's writer before exec
    // closes it, even with CLOEXEC. Only ETXTBSY proves no child started: retry
    // that spawn, never a failed authentication or a running helper's outcome.
    command.kill_on_drop(true);
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            match command.output().await {
                Err(error) if error.raw_os_error() == Some(nix::libc::ETXTBSY) => {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                output => return output,
            }
        }
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "helper writer did not close"))?
}

#[tokio::test]
async fn helper_exec_preserves_unrelated_spawn_errors() {
    let scratch = common::scratch();
    let error = helper_output(&mut Command::new(
        scratch.join(format!("missing-{}", uuid::Uuid::new_v4())),
    ))
    .await
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[tokio::test]
async fn helper_exec_waits_for_an_inherited_writer_to_close() {
    let scratch = common::scratch();
    let directory = scratch.join(format!("exec-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("helper");
    let fixture = AskpassImage {
        _scratch: scratch,
        directory,
        path,
    };
    std::fs::write(&fixture.path, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A sibling fork can retain a writer even after the parent closes its fd.
    // Hold that kernel condition until the first exec attempt has been polled.
    let writer = std::fs::OpenOptions::new()
        .write(true)
        .open(&fixture.path)
        .unwrap();
    let mut command = Command::new(&fixture.path);
    let mut output = Box::pin(helper_output(&mut command));
    std::future::poll_fn(|context| {
        assert!(
            std::future::Future::poll(output.as_mut(), context).is_pending(),
            "exec must wait for the transient writer instead of returning ETXTBSY"
        );
        std::task::Poll::Ready(())
    })
    .await;
    drop(writer);
    assert!(output.await.unwrap().status.success());
}

/// Shares a private stripped copy of the real CLI across this test binary.
///
/// The peer-image digest runs before a prompt reply. The unstripped debug CLI
/// contains large debug sections, so this fixture strips a private copy while
/// retaining the real CLI code. SHA-256 also stays optimized in dev/test builds
/// so test-only artifacts do not consume the fixed prompt deadline.
struct AskpassImage {
    _scratch: common::ScratchRoot,
    directory: PathBuf,
    path: PathBuf,
}
impl Drop for AskpassImage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn askpass_image() -> Arc<AskpassImage> {
    static IMAGE: OnceLock<Mutex<Weak<AskpassImage>>> = OnceLock::new();
    let cache = IMAGE.get_or_init(|| Mutex::new(Weak::new()));
    let mut cached = cache.lock().unwrap();
    if let Some(image) = cached.upgrade() {
        return image;
    }

    let scratch = common::scratch();
    let directory = scratch.join(format!(
        "askpass-image-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let path = directory.join("infraternal");
    std::fs::copy(env!("CARGO_BIN_EXE_infraternal"), &path).unwrap();
    let stripped = std::process::Command::new("strip")
        .arg("--strip-unneeded")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        stripped.status.success(),
        "strip the askpass test CLI: {}",
        String::from_utf8_lossy(&stripped.stderr)
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
    let image = Arc::new(AskpassImage {
        directory,
        path,
        _scratch: scratch,
    });
    *cached = Arc::downgrade(&image);
    image
}

#[tokio::test]
async fn real_cli_askpass_refuses_unregistered_parent_and_cleans_helper() {
    let parent = common::scratch();
    let root = parent.join(format!("a-{}", std::process::id()));
    let askpass_image = askpass_image();
    let session = CredentialSession::prepare(
        &CredentialConfig {
            scratch: root.clone(),
            ssh_agent: "unused".into(),
            ssh_add: "unused".into(),
            askpass_binary: askpass_image.path.clone(),
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
    let output = helper_output(
        Command::new(directory.join("askpass"))
            .arg("fixture-user@fixture-host's password: ")
            .env(
                "INFRATERNAL_SSH_ASKPASS_SOCKET",
                directory.join("askpass.sock"),
            )
            .stdin(Stdio::null())
            .stderr(Stdio::null()),
    )
    .await
    .expect("run real askpass CLI");
    // Knowing the private path is insufficient: this invocation has no owned
    // SSH/ssh-add parent. The encrypted-key test exercises an authorized helper.
    assert!(!output.status.success());
    assert_eq!(output.stdout.len(), 0);
    drop(session);
    assert!(!directory.exists());
    std::fs::remove_dir(root).unwrap();
}

#[tokio::test]
async fn real_cli_unlocks_an_encrypted_synthetic_key_on_private_pipes() {
    use tokio::io::AsyncWriteExt;
    let scratch = common::scratch();
    let root = scratch.join(format!("e-{}", std::process::id()));
    let askpass_image = askpass_image();
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
            askpass_binary: askpass_image.path.clone(),
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
    let scratch = common::scratch();
    let root = scratch.join(format!("n-{}", std::process::id()));
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
