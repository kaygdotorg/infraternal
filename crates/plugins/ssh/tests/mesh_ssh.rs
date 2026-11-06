//! Exercises connect/check with the real SSH server engine and none authentication used by `NetBird`.
#![allow(clippy::unwrap_used)]

mod common;
use infraternal_plugin_ssh::{
    auth_order::{AuthMethod, AuthProvider, AutoAuth, NetworkProvider},
    model::{Destination, FailureKind, InstallMode, MeshEvidence},
    openssh::OpenSsh,
    probe::CHECK_SCRIPT,
    transport::{Credentials, Input, Operation, SshTransport},
};
use std::{
    io::{BufRead, BufReader},
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

struct NetworkOnly(Option<NetworkProvider>);
impl AuthProvider for NetworkOnly {
    fn network(&self) -> Option<NetworkProvider> {
        self.0
    }
    fn server_key(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async { panic!("network auth must not request keys") })
    }
    fn user_key(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async { panic!("network auth must not request keys") })
    }
    fn password(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async { panic!("network auth must not request passwords") })
    }
}
struct Fixture(std::process::Child, std::path::PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

#[tokio::test]
#[ignore = "requires the Go interoperability fixture; run research/ssh-client/mesh-fixture/run"]
async fn network_identity_connect_check_and_changed_key_refusal() {
    let scratch = common::scratch();
    let root = scratch.join(format!(
        "m-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut child = Command::new(std::env::var_os("INFRATERNAL_MESH_FIXTURE").unwrap())
        .arg(&root)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut port = String::new();
    output.read_line(&mut port).unwrap();
    let _fixture = Fixture(child, root.clone());
    let config = root.join("config");
    std::fs::write(&config, format!("# Isolated public trust for the synthetic in-memory host key.\nHost *\n UserKnownHostsFile {}\n GlobalKnownHostsFile /dev/null\n", root.join("known_hosts").display())).unwrap();
    let wrapper = root.join("ssh");
    std::fs::write(&wrapper, format!("#!/bin/sh\n# Apply the fixture's public trust configuration.\nexec /usr/bin/ssh -F '{}' \"$@\"\n", config.display())).unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let adapter = OpenSsh {
        ssh: wrapper,
        ssh_agent: "/usr/bin/ssh-agent".into(),
        ssh_add: "/usr/bin/ssh-add".into(),
        ssh_keyscan: "/usr/bin/ssh-keyscan".into(),
        ssh_keygen: "/usr/bin/ssh-keygen".into(),
        askpass_binary: std::env::current_exe().unwrap(),
        tcp_connector: None,
        scratch: root.clone(),
        command_timeout: Duration::from_secs(10),
    };
    let destination = Destination::parse(&format!("kayg@127.0.0.1:{}", port.trim())).unwrap();
    let adapter = Arc::new(adapter);
    let automatic = AutoAuth::new(adapter.clone());
    // Release 4's system sniff and both release 5 initial commands must each
    // choose network auth once and retain that same physical connection.
    let scripts = [
        CHECK_SCRIPT.to_owned(),
        infraternal_plugin_ssh::previous_attempt::check_script(InstallMode::Rootless),
        format!("{CHECK_SCRIPT}\nprintf 'INFRATERNAL_SETUP_CLEAR\\n'"),
    ];
    // Provider metadata is advisory: typed hosts have none, while discovered
    // hosts preserve either mesh provider without changing SSH negotiation.
    let mut connections = 0;
    for provider in [
        Some(NetworkProvider::Netbird),
        Some(NetworkProvider::Tailscale),
        None,
    ] {
        for (index, script) in scripts.iter().enumerate() {
            let session = automatic
                .open(
                    destination.clone(),
                    Credentials::Automatic(Arc::new(NetworkOnly(provider))),
                    MeshEvidence::default(),
                )
                .await
                .unwrap();
            let check = session.run(script, Input::Empty).await.unwrap();
            let authentication = session.authentication().unwrap();
            assert_eq!(authentication.method, AuthMethod::Network);
            assert_eq!(authentication.network, provider);
            assert!(check.stdout.starts_with(b"INFRATERNAL_CHECK_V1\nLinux\n"));
            if index != 0 {
                // Both mean "no earlier setup"; ABSENT also proves no install (D355).
                assert!(
                    check.stdout.ends_with(b"INFRATERNAL_SETUP_CLEAR\n")
                        || check.stdout.ends_with(b"INFRATERNAL_SETUP_ABSENT\n")
                );
            }
            let again = session
                .run("printf 'same-connection\n'", Input::Empty)
                .await
                .unwrap();
            assert_eq!(again.stdout, b"same-connection\n");
            connections += 1;
            assert_eq!(
                std::fs::read_to_string(root.join("connections")).unwrap(),
                connections.to_string()
            );
            drop(session);
        }
    }
    // A corrupted public pin must still refuse admission, never be replaced by the transport.
    let pin = root.join("known_hosts");
    let original = std::fs::read_to_string(&pin).unwrap();
    let mut bytes = original.into_bytes();
    let index = bytes
        .iter()
        .rposition(|byte| *byte != b'\n' && *byte != b'=')
        .unwrap();
    bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
    std::fs::write(&pin, &bytes).unwrap();
    let refused = adapter
        .open(destination, Credentials::Network, MeshEvidence::default())
        .await
        .err()
        .unwrap();
    assert_eq!(refused.kind, FailureKind::HostKey);
    assert_eq!(std::fs::read(&pin).unwrap(), bytes);
    println!(
        "FUNCTIONAL check_variants=3 provider_cases=3 physical_connections=9 later_credentials_requested=0 changed_key_refused=1"
    );
}
