//! Verifies socket acceleration preserves native public source-address admission (#190, D181).
#![cfg(feature = "ssh")]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_ssh::{
    model::{Destination, MeshEvidence},
    openssh::OpenSsh,
    transport::{Credentials, SshTransport},
};
use std::{net::TcpListener, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};

#[tokio::test]
async fn connector_preserves_configured_bind_address_refusal() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.scratch")
        .join(format!("source-address-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    // Keep helper sockets below sun_path without using the shared runtime root.
    let helper_root = PathBuf::from(std::env::var_os("HOME").unwrap())
        .join(".cache/codex-scratch/addhost-instant/s");
    std::fs::create_dir_all(&helper_root).unwrap();
    std::fs::set_permissions(&helper_root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let wrapper = root.join("ssh");
    // This reserved address is not a local interface. Native SSH must refuse
    // before contacting the target; no trust acceptance or login is involved.
    std::fs::write(
        &wrapper,
        "#!/bin/sh\n# Supplies public source-address policy to the production adapter.\nif [ \"$1\" = -G ]; then while [ \"$1\" != -p ]; do shift; done; shift; printf 'port %s\\n' \"$1\"; printf '%s\\n' 'hostname 127.0.0.1' 'proxyjump none' 'proxycommand none' 'bindaddress 203.0.113.190'; exit 0; fi\nexec /usr/bin/ssh \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut contacts = Vec::new();
    for connector in [None, Some(PathBuf::from(env!("CARGO_BIN_EXE_infraternal")))] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Drop an admitted connection immediately so the check never authenticates.
        listener.set_nonblocking(true).unwrap();
        let observer = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(4);
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok(_) => return true,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("listener refused: {error}"),
                }
            }
            false
        });
        let adapter = OpenSsh {
            ssh: wrapper.clone(),
            ssh_agent: "unused".into(),
            ssh_add: "unused".into(),
            ssh_keyscan: "unused".into(),
            ssh_keygen: "unused".into(),
            askpass_binary: "unused".into(),
            tcp_connector: connector,
            scratch: helper_root.clone(),
            command_timeout: Duration::from_secs(3),
        };
        let result = adapter
            .open(
                Destination::parse(&format!("fixture@127.0.0.1:{port}")).unwrap(),
                Credentials::Network,
                MeshEvidence::default(),
            )
            .await;
        assert!(result.is_err());
        contacts.push(observer.join().unwrap());
    }
    std::fs::remove_dir_all(root).unwrap();
    assert!(!contacts[0], "native SSH must enforce source admission");
    assert!(
        !contacts[1],
        "the connector must retain source admission: native_contact={}, connector_contact={}",
        contacts[0], contacts[1]
    );
}
