//! Verifies ephemeral helper permissions, fresh scratch preparation and secret lifetime without real credentials.
#![allow(clippy::unwrap_used)]

mod common;

use infraternal_plugin_ssh::{
    credentials::{CredentialConfig, CredentialSession},
    transport::{Credentials, Secret},
};
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn password_helpers_prepare_a_fresh_private_root_and_remove_only_their_directory() {
    let root = common::scratch().join(format!(
        "c-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let config = CredentialConfig {
        scratch: root.clone(),
        ssh_agent: "unused".into(),
        ssh_add: "unused".into(),
        askpass_binary: std::env::current_exe().unwrap(),
    };
    let session = CredentialSession::prepare(
        &config,
        Credentials::Password(Secret::new(b"synthetic-password-marker".to_vec())),
    )
    .await;
    assert!(
        session.is_ok(),
        "first supplied credential requires a freshly prepared private helper root"
    );
    let session = session.unwrap();
    assert_eq!(
        std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let directory = std::fs::read_dir(&root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert_eq!(
        std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let helper = std::fs::read_to_string(directory.join("askpass")).unwrap();
    assert!(!helper.contains("synthetic-password-marker"));
    assert_eq!(
        std::fs::metadata(directory.join("askpass.sock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(session);
    assert!(!directory.exists());
    assert!(root.is_dir());
    std::fs::remove_dir(root).unwrap();
}

#[tokio::test]
async fn credential_helper_refuses_host_trust_and_permission_prompts() {
    let root = common::scratch().join(format!(
        "c-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let config = CredentialConfig {
        scratch: root.clone(),
        ssh_agent: "unused".into(),
        ssh_add: "unused".into(),
        askpass_binary: "/usr/bin/true".into(),
    };
    let session =
        CredentialSession::prepare(&config, Credentials::Password(Secret::new(b"yes".to_vec())))
            .await
            .unwrap();
    let directory = std::fs::read_dir(&root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    // The stub succeeds for any invocation, isolating whether the generated
    // helper rejects the public prompt before invoking its credential responder.
    let output = tokio::process::Command::new(directory.join("askpass"))
        .arg("Are you sure you want to continue connecting (yes/no/[fingerprint])? ")
        .output()
        .await
        .unwrap();
    let refused = !output.status.success() && output.stdout.is_empty();
    drop(session);
    std::fs::remove_dir(root).unwrap();
    assert!(refused, "credential responder accepted a host trust prompt");
}

#[tokio::test]
async fn password_socket_refuses_an_unrelated_same_user_process() {
    use tokio::io::AsyncReadExt;
    let root = common::scratch().join(format!(
        "c-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let config = CredentialConfig {
        scratch: root.clone(),
        ssh_agent: "unused".into(),
        ssh_add: "unused".into(),
        askpass_binary: std::env::current_exe().unwrap(),
    };
    let session = CredentialSession::prepare(
        &config,
        Credentials::Password(Secret::new(b"synthetic-login-material".to_vec())),
    )
    .await
    .unwrap();
    let directory = std::fs::read_dir(&root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut stream = tokio::net::UnixStream::connect(directory.join("askpass.sock"))
        .await
        .unwrap();
    let mut reply = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read_to_end(&mut reply),
    )
    .await
    .unwrap();
    drop(session);
    std::fs::remove_dir(root).unwrap();
    assert!(reply.is_empty(), "unrelated peer received login material");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn kernel_running_helper_is_materialized_in_its_private_scope() {
    let root = common::scratch().join(format!(
        "c-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let config = CredentialConfig {
        scratch: root.clone(),
        ssh_agent: "unused".into(),
        ssh_add: "unused".into(),
        askpass_binary: "/proc/self/exe".into(),
    };
    let session = CredentialSession::prepare(
        &config,
        Credentials::Password(Secret::new(b"synthetic-reply".to_vec())),
    )
    .await
    .unwrap();
    let directory = std::fs::read_dir(&root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let image = directory.join("askpass-image");
    assert!(
        image.is_file(),
        "external SSH must execute a scoped copy of the kernel running image"
    );
    assert_eq!(
        std::fs::metadata(&image).unwrap().permissions().mode() & 0o777,
        0o500
    );
    let wrapper = std::fs::read_to_string(directory.join("askpass")).unwrap();
    assert!(wrapper.contains(image.to_str().unwrap()));
    assert!(!wrapper.contains("/proc/self/exe"));
    drop(session);
    assert!(!image.exists());
    std::fs::remove_dir(root).unwrap();
}
