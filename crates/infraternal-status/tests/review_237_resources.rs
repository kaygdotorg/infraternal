//! Resource-refusal regression for the concurrent local status probe (#237).
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(target_os = "linux")]

use infraternal_status::{Activity, Roots, probe_local};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

#[test]
fn thread_resource_refusal_preserves_a_status_answer() {
    if let Some(root) = std::env::var_os("STATUS_RESOURCE_REVIEW_ROOT") {
        let root = PathBuf::from(root);
        let status = probe_local(
            &Roots {
                system_units: vec![root.join("units")],
                user_units: None,
                run_dir: None,
                data_dirs: vec![],
                net_class: root.join("net"),
            },
            &["agent".to_owned()],
        );
        assert_eq!(
            status.units.len(),
            96,
            "resource refusal must retain every installed service"
        );
        assert!(
            status
                .units
                .iter()
                .all(|(_, activity)| *activity == Activity::Unknown)
        );
        return;
    }
    let base = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || {
            PathBuf::from(std::env::var_os("HOME").expect("home directory"))
                .join(".cache/codex-scratch/review-status-crash-loop-237-r2")
        },
        PathBuf::from,
    );
    let root = base.join(format!("resource-review-{}", std::process::id()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("units")).unwrap();
    for index in 0..96 {
        fs::write(
            root.join(format!("units/infraternal-{index}.service")),
            "[Service]\nExecStart=/usr/bin/infraternal agent run\n",
        )
        .unwrap();
    }
    let manager = root.join("bin/systemctl");
    fs::write(&manager, "#!/bin/sh\nexec /bin/sleep 1\n").unwrap();
    fs::set_permissions(&manager, fs::Permissions::from_mode(0o755)).unwrap();
    // Restrict only the fixture process. A stalled manager performs no CPU work;
    // spawning more workers than this address-space budget allows must be fallible.
    let output = Command::new("/bin/bash")
        .args([
            "-c",
            "ulimit -v 196608; exec \"$@\"",
            "status-resource-review",
        ])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "thread_resource_refusal_preserves_a_status_answer",
            "--nocapture",
        ])
        .env("STATUS_RESOURCE_REVIEW_ROOT", &root)
        .env("MALLOC_ARENA_MAX", "1")
        .env("PATH", root.join("bin"))
        .output()
        .unwrap();
    fs::remove_dir_all(root).unwrap();
    assert!(
        output.status.success(),
        "resource-limited probe lost its answer: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
