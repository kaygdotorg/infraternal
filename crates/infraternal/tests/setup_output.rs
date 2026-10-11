//! Checks legacy and versioned setup-output readers with an unregistered local fixture response [16][202][217], #163.
#![cfg(all(unix, feature = "plugin-server"))]
#![allow(clippy::expect_used)]

use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    process::Command,
    thread,
};

#[test]
fn setup_output_keeps_legacy_and_versioned_readers() {
    let data = std::env::temp_dir().join(format!("it-setup-output-{}", std::process::id()));
    fs::create_dir(&data).expect("private fixture directory");
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).expect("private permissions");
    let listener = UnixListener::bind(data.join("setup-token.sock")).expect("fixture socket");
    // This public synthetic string is never registered as an authentication capability.
    let sample = "a".repeat(43);
    let reply = sample.clone();
    let worker = thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("local request");
        let mut request = [0; 4];
        socket.read_exact(&mut request).expect("request bytes");
        assert_eq!(&request, b"GET\n");
        socket.write_all(reply.as_bytes()).expect("fixture reply");
        socket.write_all(b"\n").expect("reply delimiter");
    });
    let output = Command::new(env!("CARGO_BIN_EXE_infraternal"))
        .args(["--json", "server", "--data"])
        .arg(&data)
        .arg("setup-token")
        .output()
        .expect("real setup-output CLI");
    worker.join().expect("fixture worker");
    fs::remove_dir_all(&data).expect("fixture cleanup");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON response");
    // Never include response values in assertion diagnostics, even for a synthetic fixture.
    assert!(
        value["data"]["token"].as_str() == Some(sample.as_str()),
        "versioned reader"
    );
    assert!(
        value["token"].as_str() == Some(sample.as_str()),
        "legacy reader"
    );
}
