//! Checks legacy and versioned setup-output readers with an unregistered local fixture response [16][202][217], #163.
#![cfg(all(unix, feature = "plugin-server"))]
#![allow(clippy::expect_used)]

use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
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

#[test]
fn setup_token_finds_the_data_dir_from_a_system_service_without_flags() {
    let root = std::env::temp_dir().join(format!("it-setup-unit-{}", std::process::id()));
    let data = root.join("server-state");
    let units = root.join("systemd");
    fs::create_dir_all(&data).expect("private fixture directory");
    fs::create_dir_all(&units).expect("system unit fixture directory");
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).expect("private permissions");
    let socket_path = data.join("setup-token.sock");
    let listener = UnixListener::bind(&socket_path).expect("fixture socket");
    let binary = env!("CARGO_BIN_EXE_infraternal");
    fs::write(
        units.join("custom-server.service"),
        format!(
            "[Service]\nExecStart=\"{binary}\" \"server\" \"--data\" \"{}\"\n",
            data.display()
        ),
    )
    .expect("write system service fixture");
    let reply = "B".repeat(43);
    let worker_reply = reply.clone();
    let worker = thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("local request");
        let mut request = [0; 4];
        if socket.read_exact(&mut request).is_ok() {
            assert_eq!(&request, b"GET\n");
            socket
                .write_all(worker_reply.as_bytes())
                .expect("fixture reply");
            socket.write_all(b"\n").expect("reply delimiter");
        }
    });
    let output = Command::new(binary)
        .args(["server", "setup-token"])
        .current_dir(&root)
        .env_clear()
        .env("INFRATERNAL_TEST_SYSTEMD_SYSTEM_UNIT_DIR", &units)
        .output()
        .expect("real setup-token CLI");
    if !output.status.success() {
        // Wake the local fixture so a red test still leaves no blocked worker.
        let _ = UnixStream::connect(&socket_path);
    }
    worker.join().expect("fixture worker");
    fs::remove_dir_all(&root).expect("fixture cleanup");
    assert!(
        output.status.success(),
        "setup-token must use the installed system service data directory"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(&reply));
}

#[test]
fn unreadable_system_service_data_prints_one_sudo_command_line() {
    let root = std::env::temp_dir().join(format!("it-setup-denied-{}", std::process::id()));
    let data = root.join("server-state");
    let units = root.join("systemd");
    fs::create_dir_all(&data).expect("private fixture directory");
    fs::create_dir_all(&units).expect("system unit fixture directory");
    fs::write(
        units.join("custom-server.service"),
        format!(
            "[Service]\nExecStart=\"{}\" \"server\" \"--data\" \"{}\"\n",
            env!("CARGO_BIN_EXE_infraternal"),
            data.display()
        ),
    )
    .expect("write system service fixture");
    fs::set_permissions(&data, fs::Permissions::from_mode(0o000))
        .expect("make service data unreadable");

    let output = Command::new(env!("CARGO_BIN_EXE_infraternal"))
        .args(["server", "setup-token"])
        .current_dir(&root)
        .env_clear()
        .env("INFRATERNAL_TEST_SYSTEMD_SYSTEM_UNIT_DIR", &units)
        .output();
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700))
        .expect("restore fixture permissions");
    fs::remove_dir_all(&root).expect("remove setup fixture");
    let output = output.expect("real setup-token CLI");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert_eq!(output.stdout.as_slice(), b"");
    assert_eq!(stderr.lines().count(), 1, "stderr must contain one line");
    assert_eq!(
        stderr.trim(),
        "The server data directory is not readable. Run: sudo infraternal server setup-token"
    );
}
