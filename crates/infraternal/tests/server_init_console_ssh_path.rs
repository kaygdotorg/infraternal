//! A console `server init` must not save a default-drop host table without an SSH path (J589 P3, #483).
//!
//! Since `e3a8b46de` any TCP admin rule satisfied the policy check, so a
//! console install (no `SSH_CONNECTION`) with only `--host-firewall-allow
//! '*,*,tcp,443'` saved a default-drop `inet infraternal_host` table that
//! nothing on sshd's port could pass. The live-session check only protects
//! remote installs. A console install must name a TCP rule for a port sshd is
//! listening on, or for 22 when no sshd listener can be seen (an
//! unprivileged dry-run cannot see root's sockets, so it always needs 22).
#![cfg(all(target_os = "linux", feature = "plugin-server"))]
#![allow(clippy::expect_used)]

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

/// Run `server init --system --dry-run` without an SSH session and with the given allow rules.
fn console_dry_run(tag: &str, allow: &[&str]) -> std::process::Output {
    let root = PathBuf::from(std::env::var_os("HOME").expect("fixture home"))
        .join(".cache/codex-scratch/j591")
        .join(format!("{tag}-{}", std::process::id()));
    let data = root.join("d");
    let units = root.join("u");
    fs::create_dir_all(&data).expect("create data fixture");
    fs::create_dir_all(&units).expect("create unit fixture");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private fixture");
    let mut command = Command::new(env!("CARGO_BIN_EXE_infraternal"));
    command
        .args([
            "--json",
            "server",
            "init",
            "--system",
            "--dry-run",
            "--data",
        ])
        .arg(&data);
    for rule in allow {
        command.args(["--host-firewall-allow", rule]);
    }
    let output = command
        .current_dir(&root)
        .env_clear()
        .env("INFRATERNAL_TEST_SYSTEMD_SYSTEM_UNIT_DIR", &units)
        .output()
        .expect("run server init dry-run");
    let _ = fs::remove_dir_all(&root);
    output
}

/// Only a 443 rule, from a console: refused, because the saved table would drop every SSH login.
#[test]
fn console_server_init_with_no_sshd_rule_is_refused() {
    let output = console_dry_run("https-only", &["*,*,tcp,443"]);
    assert!(
        !output.status.success(),
        "a default-drop table with no SSH path was planned: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("sshd"), "the refusal must say why: {text}");
}

/// The same install with a TCP/22 rule added is accepted.
#[test]
fn console_server_init_with_an_ssh_rule_is_accepted() {
    let output = console_dry_run("with-ssh", &["*,*,tcp,443", "*,*,tcp,22"]);
    assert!(
        output.status.success(),
        "server init dry-run failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
