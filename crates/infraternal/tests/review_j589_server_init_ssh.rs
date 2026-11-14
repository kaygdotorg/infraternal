//! J589 review (#483): `server init` over SSH must not pin the server's SSH
//! admin path to the installer's own address or to the interface that owns
//! the address they dialled.
//!
//! The server role installs a default-drop `inet infraternal_host` table
//! (`InputMode::Enforce`). When no TCP `--host-firewall-allow` rule is given,
//! `server init` derives the only admin rule from `SSH_CONNECTION` through
//! `admin_rule_for_ssh_connection`, which records the remote address as a /32
//! (or /128) source and the interface owning the local address. J573 rejected
//! exactly this pinning for `infraternal up` ("drops a second administrator or
//! the same one after their address changes") but left it in `server init`.
//! The interface pin adds a second lock-out: when sshd is reached on an
//! address held by `lo` or a dummy interface (an anycast or load-balancer VIP),
//! packets arrive on the physical NIC, so `iifname "lo"` never matches a new
//! connection. The live session survives through conntrack, so the install
//! succeeds and the lock-out only shows on the next login.
#![cfg(all(target_os = "linux", feature = "plugin-server"))]
#![allow(clippy::expect_used)]

use std::{fs, os::unix::fs::PermissionsExt, process::Command};

/// The saved server policy admits SSH from any source on any interface when it
/// was derived from the installer's session.
#[test]
fn review_j589_server_init_over_ssh_does_not_pin_ssh_to_one_source_or_interface() {
    let root = std::path::PathBuf::from(std::env::var_os("HOME").expect("fixture home"))
        .join(".cache/codex-scratch/review-j589")
        .join(format!("s-{}", std::process::id()));
    let data = root.join("d");
    let units = root.join("u");
    fs::create_dir_all(&data).expect("create data fixture");
    fs::create_dir_all(&units).expect("create unit fixture");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private fixture");
    // 127.0.0.1 is held by `lo` on every host, standing in for a VIP on `lo`.
    let plan = Command::new(env!("CARGO_BIN_EXE_infraternal"))
        .args([
            "--json",
            "server",
            "init",
            "--system",
            "--dry-run",
            "--data",
        ])
        .arg(&data)
        .current_dir(&root)
        .env_clear()
        .env("INFRATERNAL_TEST_SYSTEMD_SYSTEM_UNIT_DIR", &units)
        .env("SSH_CONNECTION", "192.0.2.5 43122 127.0.0.1 22")
        .output()
        .expect("generate service plan");
    let _ = fs::remove_dir_all(&root);
    assert!(
        plan.status.success(),
        "server init dry-run failed: {}",
        String::from_utf8_lossy(&plan.stderr)
    );
    let plan: serde_json::Value = serde_json::from_slice(&plan.stdout).expect("service plan JSON");
    let text = plan["data"]["plan"].as_str().expect("service plan");
    let start = text
        .find("host-firewall-server.json:\n")
        .expect("server policy in the plan")
        + "host-firewall-server.json:\n".len();
    let end = start
        + text[start..]
            .find("\nWould write")
            .expect("policy boundary");
    let policy: serde_json::Value =
        serde_json::from_str(&text[start..end]).expect("server policy JSON");
    let ssh_rules = policy["admin_rules"]
        .as_array()
        .expect("admin rules")
        .iter()
        .filter(|rule| rule["protocol"] == "tcp" && rule["port"] == 22)
        .collect::<Vec<_>>();
    assert!(!ssh_rules.is_empty(), "no SSH admin rule saved: {policy:#}");
    for rule in ssh_rules {
        assert!(
            rule["source"].is_null() && rule["interface"].is_null(),
            "server init pins SSH to the installer's address/interface; a second administrator, \
             the same one after an address change, or any login to a VIP on lo is dropped: {rule}"
        );
    }
}
