//! Round-3 review of #237: a mask is activation configuration, not runtime state (D303).
//!
//! `systemctl mask` without `--now` leaves the running process alone, and a
//! real manager then reports `LoadState=masked` with `ActiveState=active`.
//! A mask on a unit the machine never needed is the plainest way an
//! administrator says it must not run, so on its own it is not a role that
//! "should run" (D303). Both cases are driven through `probe_local` with a stub
//! `systemctl` that prints what the manager prints for them.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_status::{Activity, Role, Roots, probe_local};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

const RUNNING: &str = "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nNRestarts=0\nExecMainStartTimestampMonotonic=1\n";
const MASKED_RUNNING: &str = "LoadState=masked\nUnitFileState=masked\nActiveState=active\nSubState=running\nMainPID=4343\nNRestarts=0\nExecMainStartTimestampMonotonic=1\n";
const MASKED_DEAD: &str = "LoadState=masked\nUnitFileState=masked\nActiveState=inactive\nSubState=dead\nMainPID=0\nNRestarts=0\nExecMainStartTimestampMonotonic=0\n";

/// Re-run one test in a child process whose `PATH` holds only the stub manager.
fn isolated(name: &str, check: impl FnOnce(&Path)) {
    if let Some(root) = std::env::var_os("STATUS_R3_MASKS_ROOT") {
        check(Path::new(&root));
        return;
    }
    let base = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || {
            PathBuf::from(std::env::var_os("HOME").expect("home directory"))
                .join(".cache/codex-scratch/review-status-crash-loop-237-r3/fixtures")
        },
        PathBuf::from,
    );
    let root = base.join(format!("r3-masks-{name}-{}", std::process::id()));
    fs::create_dir_all(root.join("bin")).unwrap();
    let manager = root.join("bin/systemctl");
    fs::write(
        &manager,
        r#"#!/bin/sh
for unit; do :; done
case "$unit" in *server*) role=server;; *) role=agent;; esac
while IFS= read -r line; do printf '%s\n' "$line"; done < "$STATUS_R3_MASKS_ROOT/$role.properties"
"#,
    )
    .unwrap();
    fs::set_permissions(&manager, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("STATUS_R3_MASKS_ROOT", &root)
        .env("PATH", root.join("bin"))
        .output()
        .unwrap();
    fs::remove_dir_all(root).unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Fresh unit directories; `user` selects the user manager for `role`'s unit.
fn reset(root: &Path) -> Roots {
    for dir in ["system", "user", "data"] {
        let path = root.join(dir);
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }
        fs::create_dir_all(path).unwrap();
    }
    Roots {
        system_units: vec![root.join("system")],
        user_units: Some(root.join("user")),
        run_dir: None,
        data_dirs: vec![root.join("data")],
        net_class: root.join("net"),
    }
}

fn unit_dir(root: &Path, user: bool) -> PathBuf {
    root.join(if user { "user" } else { "system" })
}

#[test]
fn a_masked_service_its_manager_reports_running_is_not_stopped() {
    isolated(
        "a_masked_service_its_manager_reports_running_is_not_stopped",
        |root| {
            let mut wrong = Vec::new();
            for role in ["server", "agent"] {
                for user in [false, true] {
                    let roots = reset(root);
                    if role == "server" {
                        fs::write(root.join("data/infraternal.sqlite"), []).unwrap();
                    }
                    symlink(
                        "/dev/null",
                        unit_dir(root, user).join(format!("infraternal-{role}.service")),
                    )
                    .unwrap();
                    fs::write(root.join(format!("{role}.properties")), MASKED_RUNNING).unwrap();
                    let node = probe_local(&roots, &[role.to_owned()]);
                    assert!(
                        node.headline().2.is_empty(),
                        "a running masked service needs no repair"
                    );
                    if node.overall() != Activity::Active
                        || node.confirmed_down_count() != 0
                        || node.components[0].state != "Running"
                    {
                        wrong.push(format!(
                            "{role} user={user}: {} / {:?} / down={}",
                            node.components[0].state,
                            node.overall(),
                            node.confirmed_down_count()
                        ));
                    }
                }
            }
            assert!(
                wrong.is_empty(),
                "the manager reports these masked services running: {wrong:?}"
            );
        },
    );
}

#[test]
fn a_mask_alone_does_not_make_a_down_infraternal_agent() {
    isolated(
        "a_mask_alone_does_not_make_a_down_infraternal_agent",
        |root| {
            let mut wrong = Vec::new();
            for user in [false, true] {
                // A healthy server; the separate agent unit was masked by an
                // administrator (the server already embeds its own agent).
                let roots = reset(root);
                fs::write(
                    unit_dir(root, !user).join("infraternal-server.service"),
                    "[Service]\nExecStart=/usr/bin/infraternal server\n",
                )
                .unwrap();
                symlink(
                    "/dev/null",
                    unit_dir(root, user).join("infraternal-agent.service"),
                )
                .unwrap();
                fs::write(root.join("server.properties"), RUNNING).unwrap();
                fs::write(root.join("agent.properties"), MASKED_DEAD).unwrap();
                let node = probe_local(&roots, &["server".to_owned(), "agent".to_owned()]);
                let headline = node.headline().1;
                if headline != "The server is running on this machine."
                    || node.confirmed_down_count() != 0
                {
                    wrong.push(format!(
                        "server beside masked agent user={user}: {headline} / down={}",
                        node.confirmed_down_count()
                    ));
                }
                // Nothing but the mask: this machine runs no infraternal role.
                let roots = reset(root);
                symlink(
                    "/dev/null",
                    unit_dir(root, user).join("infraternal-agent.service"),
                )
                .unwrap();
                fs::write(root.join("agent.properties"), MASKED_DEAD).unwrap();
                let node = probe_local(&roots, &["agent".to_owned()]);
                if node.role != Role::None || node.confirmed_down_count() != 0 {
                    wrong.push(format!(
                        "mask only user={user}: {:?} {} / down={}",
                        node.role,
                        node.headline().1,
                        node.confirmed_down_count()
                    ));
                }
            }
            assert!(
                wrong.is_empty(),
                "a masked agent unit is not something that should run: {wrong:?}"
            );
        },
    );
}
