//! Refused workers and manager executables retain the installed role and a plain reason (#237).
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(target_os = "linux")]
use infraternal_status::{Activity, Roots, probe_local};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

#[test]
fn refused_manager_process_preserves_unknown_and_reason() {
    if let Some(root) = std::env::var_os("STATUS_QUERY_REFUSAL_ROOT") {
        let root = PathBuf::from(root);
        let refuse_worker = std::env::var_os("STATUS_REFUSE_WORKER").is_some();
        if refuse_worker {
            // Lower only this already-running fixture child's process limit,
            // after the Rust harness created its test thread. Host limits and
            // other jobs are untouched. The caller is an unprivileged account.
            assert!(
                Command::new("/usr/bin/prlimit")
                    .args(["--pid", &std::process::id().to_string(), "--nproc=1:1"])
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let node = probe_local(
            &Roots {
                system_units: vec![root.join("units")],
                user_units: None,
                run_dir: None,
                data_dirs: vec![],
                net_class: root.join("net"),
            },
            &["agent".to_owned()],
        );
        assert_eq!(node.units.len(), 1);
        assert_eq!(node.units[0].1, Activity::Unknown);
        assert!(
            node.components[0].detail.contains(if refuse_worker {
                "service query worker unavailable"
            } else {
                "could not start the service manager query"
            }),
            "{}",
            node.components[0].detail
        );
        return;
    }
    let base = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || {
            PathBuf::from(std::env::var_os("HOME").expect("home"))
                .join(".cache/codex-scratch/status-crash-loop-fix2")
        },
        PathBuf::from,
    );
    let root = base.join(format!("query-refusal-{}", std::process::id()));
    fs::create_dir_all(root.join("units")).unwrap();
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::write(
        root.join("units/infraternal-agent.service"),
        "[Service]\nExecStart=/usr/bin/infraternal agent run\n",
    )
    .unwrap();
    // Both a missing executable and a permission refusal exercise Command::spawn.
    for mode in ["missing", "permission", "worker"] {
        // Privileged callers are exempt from RLIMIT_NPROC; still exercise both
        // process-refusal paths when this suite is run as root.
        if mode == "worker" && nix::unistd::Uid::effective().is_root() {
            continue;
        }
        if mode == "permission" {
            let manager = root.join("bin/systemctl");
            fs::write(&manager, "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(manager, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut command = Command::new(std::env::current_exe().unwrap());
        if mode == "worker" {
            command.env("STATUS_REFUSE_WORKER", "1");
        }
        let output = command
            .args([
                "--exact",
                "refused_manager_process_preserves_unknown_and_reason",
                "--nocapture",
            ])
            .env("STATUS_QUERY_REFUSAL_ROOT", &root)
            .env("PATH", root.join("bin"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fs::remove_dir_all(root).unwrap();
}
