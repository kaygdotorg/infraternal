//! Exercises D314 command discovery, structured errors and same-host authority (#251).
#![cfg(all(feature = "plugin-agent", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_infraternal"))
        .args(args)
        .output()
        .expect("run CLI")
}

#[test]
fn sessions_commands_are_registered_and_have_generated_skills() {
    for args in [
        vec!["sessions", "--help"],
        vec!["sessions", "new", "--help"],
        vec!["sessions", "send", "--help"],
        vec!["sessions", "read", "--help"],
        vec!["sessions", "close", "--help"],
        vec!["skill", "sessions", "send"],
    ] {
        let out = run(&args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_ne!(out.stdout, [] as [u8; 0]);
    }
}

#[test]
fn sessions_invalid_targets_have_usage_envelope_and_fix() {
    for args in [
        vec!["sessions", "send", "missing-separator", "hello", "--json"],
        vec!["sessions", "read", "local:build", "--last", "0", "--json"],
        vec!["sessions", "new", "local", "--name", "../bad", "--json"],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2));
        let envelope: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("JSON envelope");
        assert_eq!(envelope["schema_version"], 1);
        assert_eq!(envelope["ok"], false);
        assert!(
            !envelope["next"].as_array().unwrap().is_empty(),
            "{envelope}"
        );
    }
}

#[test]
fn sessions_never_accept_attach() {
    let out = run(&["sessions", "attach", "local:build", "--json"]);
    assert_eq!(out.status.code(), Some(2));
    let envelope: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["ok"], false);
}

#[test]
fn literal_program_pipe_rejects_invalid_input_before_startup() {
    use std::io::Write;
    use std::process::Stdio;
    for bytes in [
        Vec::new(),
        b"unterminated".to_vec(),
        b"\0arg\0".to_vec(),
        vec![b'x'; 8193],
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_infraternal"))
            .args([
                "__shim",
                "--session",
                "0123456789abcdef0123456789abcdef",
                "--uid",
                "0",
                "--command-stdin",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(&bytes);
        assert!(!child.wait().unwrap().success());
    }
}

#[test]
fn saved_shell_can_automate_real_ptys_but_same_uid_alone_cannot() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .args([
            "scripts/test-cli-sessions.py",
            env!("CARGO_BIN_EXE_infraternal"),
        ])
        .env("INFRATERNAL_TEST_RTT", "0")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
