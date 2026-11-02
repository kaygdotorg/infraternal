//! Exercise certificate, exec, PTY and file channels with the host SSH clients.
//!
//! Synthetic private keys stay in anonymous memory descriptors. All client
//! configuration and host trust are explicit; no user key/config files are read.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "common/mesh_runtime.rs"]
mod runtime;
use infraternal_plugin_ssh::mesh_server::{config, serve};
use nix::sys::{
    memfd::{MFdFlags, memfd_create},
    stat::{Mode, fchmod},
};
use std::{
    fs::File,
    io::{Read, Seek, Write},
    os::fd::AsRawFd,
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::TcpListener, process::Command, task::JoinSet, time::timeout};

fn memory(bytes: &[u8]) -> File {
    let mut file = File::from(memfd_create("mesh-ssh-fixture", MFdFlags::MFD_CLOEXEC).unwrap());
    fchmod(&file, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
    file.write_all(bytes).unwrap();
    file.rewind().unwrap();
    file
}
fn descriptor(file: &File) -> String {
    format!("/proc/{}/fd/{}", std::process::id(), file.as_raw_fd())
}
fn options(command: &mut Command, key: &File, certificate: &File, known_hosts: &File) {
    command.args(["-F", "/dev/null"]);
    for option in [
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=/dev/null",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "ControlMaster=no",
        "ControlPath=none",
        "LogLevel=ERROR",
    ] {
        command.args(["-o", option]);
    }
    for (name, file) in [
        ("IdentityFile", key),
        ("CertificateFile", certificate),
        ("UserKnownHostsFile", known_hosts),
    ] {
        command.args(["-o", &format!("{name}={}", descriptor(file))]);
    }
    command
        .env_remove("SSH_AUTH_SOCK")
        .env("TERM", "xterm")
        .kill_on_drop(true);
}
async fn run(mut command: Command, input: &[u8]) -> std::process::Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).await.unwrap();
    stdin.shutdown().await.unwrap();
    drop(stdin);
    child.wait_with_output().await.unwrap()
}

#[tokio::test]
async fn stock_clients_negotiate_certificate_exec_pty_and_sftp() {
    timeout(Duration::from_secs(30), async {
        let ca = runtime::key();
        let user = runtime::key();
        let host = runtime::key();
        let cert = runtime::certificate(
            &ca,
            &user,
            runtime::now() - 1,
            runtime::now() + 3600,
            "person-1",
        );
        let authority = runtime::Authority::new(&ca, &cert);
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let known_hosts = memory(
            format!(
                "[127.0.0.1]:{} {}\n",
                address.port(),
                host.public_key().to_openssh().unwrap()
            )
            .as_bytes(),
        );
        let observed = Arc::clone(&authority);
        let config = Arc::new(config(host));
        let server = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            for _ in 0..3 {
                let (stream, peer) = listener.accept().await.unwrap();
                stream.set_nodelay(true).unwrap();
                let authority = Arc::clone(&authority);
                let config = Arc::clone(&config);
                connections.spawn(async move {
                    let _ = serve(authority, peer.ip(), 9, config, stream).await;
                });
            }
            while connections.join_next().await.is_some() {}
        });
        let encoded = user
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap();
        let key = memory(encoded.as_bytes());
        drop(encoded);
        let certificate = memory(cert.to_openssh().unwrap().as_bytes());
        for terminal in ["-T", "-tt"] {
            let mut command = Command::new("ssh");
            options(&mut command, &key, &certificate, &known_hosts);
            command.args([
                terminal,
                "-p",
                &address.port().to_string(),
                "operator@127.0.0.1",
                "echo",
            ]);
            let result = run(command, b"roundtrip\n").await;
            assert!(
                result.status.success(),
                "{terminal}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(result.stdout, b"roundtrip\n");
        }
        let source = memory(b"file bytes\n");
        let mut destination = memory(&[]);
        let mut command = Command::new("sftp");
        options(&mut command, &key, &certificate, &known_hosts);
        command.args([
            "-q",
            "-b",
            "-",
            "-P",
            &address.port().to_string(),
            "operator@127.0.0.1",
        ]);
        let batch = format!(
            "put {} /sample\nget /sample {}\n",
            descriptor(&source),
            descriptor(&destination)
        );
        let result = run(command, batch.as_bytes()).await;
        assert!(
            result.status.success(),
            "sftp: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        destination.rewind().unwrap();
        let mut received = Vec::new();
        destination.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"file bytes\n");
        server.await.unwrap();
        let opened = observed.opened.lock().unwrap();
        assert_eq!(opened.len(),2);
        assert!(opened.iter().all(|open| open.person == "person-1" && open.account == "operator" && matches!(&open.kind, infraternal_plugin_ssh::mesh_login::SessionKind::Exec(command) if command == b"echo")));
        assert!(opened[0].terminal.is_none());
        assert_eq!(opened[1].terminal.as_ref().unwrap().size, infraternal_plugin_ssh::mesh_login::TerminalSize::default());
    })
    .await
    .unwrap();
}
