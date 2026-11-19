//! A console `server init` must not save a default-drop host table without an SSH path (J589 P3, #483).
//!
//! Since `e3a8b46de` any TCP admin rule satisfied the policy check, so a
//! console install (no `SSH_CONNECTION`) with only `--host-firewall-allow
//! '*,*,tcp,443'` saved a default-drop `inet infraternal_host` table that
//! nothing on sshd's port could pass. The live-session check only protects
//! remote installs. A console install must name a TCP rule for a port sshd
//! really accepts on, learned from its socket unit, `sshd -G`/`-T` or its
//! listeners; when none can be learned it is refused, never assumed to be 22
//! (J608, #483).
//!
//! These runs are unprivileged, so whether sshd's port can be learned
//! depends on the host (sshd's configuration is root-only). Only refusals
//! are asserted here; the accepted path needs root and is proven by
//! `review_j608_socket_sshd_console.sh` under a private mount namespace.
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

/// A rule that misses the learned port, or a port that cannot be learned, is refused with a reason.
///
/// Port 1 is never sshd's here, so the run is refused either way. The
/// refusal names the learned port and its source, or says no port could be
/// determined; it never falls back to 22 (J608).
#[test]
fn console_server_init_names_why_the_ssh_rule_is_refused() {
    let output = console_dry_run("port-one", &["*,*,tcp,1"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "tcp/1 was accepted as sshd's path: {text}"
    );
    assert!(
        text.contains("(from ") || text.contains("could not be determined"),
        "the refusal must name the port's source or say it is unknown: {text}"
    );
    assert!(
        !text.contains("no sshd listener was seen"),
        "the refusal still falls back to 22: {text}"
    );
}
