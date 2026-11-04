//! `infraternal up` with no terminal to show its approval code to (#263, J122 P3).
//!
//! The code and link are a live approval capability. Redirected output (a
//! pipe, file or CI log) must not receive them, and the command must return a
//! pending result at once instead of waiting out the ten-minute lifetime.
#![cfg(all(target_os = "linux", feature = "remote"))]
#![allow(clippy::expect_used)]

use std::{
    io::ErrorKind,
    net::TcpListener,
    path::PathBuf,
    process::{Command, Stdio},
};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_redirected(json: bool) {
    // A listener that records whether `up` tried to reach the server at all.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let server = format!(
        "https://127.0.0.1:{}/",
        listener.local_addr().expect("address").port()
    );
    let home = Scratch(std::env::temp_dir().join(format!(
        "infraternal-up-no-terminal-{}-{json}",
        std::process::id()
    )));
    std::fs::create_dir_all(&home.0).expect("scratch home");
    let data = home.0.join("data");

    let mut command = Command::new(env!("CARGO_BIN_EXE_infraternal"));
    command.arg("up").arg(&server);
    if json {
        command.arg("--json");
    }
    let output = command
        .env("HOME", &home.0)
        .env("XDG_DATA_HOME", &data)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run the real CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let all = format!("{stdout}\n{stderr}");
    assert_eq!(output.status.code(), Some(3), "json={json}: {all}");
    assert!(
        !all.contains("#join=") && !all.contains("Code:") && !all.contains("user_code"),
        "json={json}: approval code or link reached redirected output: {all}"
    );
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
        "json={json}: up contacted the server without a terminal"
    );
    assert!(
        !data.exists(),
        "json={json}: up prepared a machine key without a terminal"
    );
    if json {
        let value: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("one JSON result");
        assert_eq!(value["command"], "up");
        assert_eq!(value["state"], "pending");
    } else {
        assert!(all.contains("terminal"), "{all}");
    }
}

#[test]
fn redirected_up_shows_no_code_and_returns_pending_at_once() {
    run_redirected(true);
    run_redirected(false);
}
