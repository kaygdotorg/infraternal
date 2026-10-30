//! Checks that units in one manager retain independent evidence and deadlines (#237).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use infraternal_status::{Activity, Roots, probe_local};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

#[test]
fn stalled_units_preserve_other_units_in_each_manager() {
    if let Some(root) = std::env::var_os("STATUS_UNIT_ISOLATION_ROOT") {
        let root = PathBuf::from(root);
        for scope in ["system", "user"] {
            let units = root.join(scope);
            fs::create_dir_all(&units).unwrap();
            for name in ["stalled", "restarting"] {
                fs::write(
                    units.join(format!("infraternal-{name}.service")),
                    "[Service]\nExecStart=/usr/bin/infraternal agent run\n",
                )
                .unwrap();
            }
            let roots = Roots {
                system_units: if scope == "system" {
                    vec![units.clone()]
                } else {
                    vec![]
                },
                user_units: (scope == "user").then_some(units),
                run_dir: None,
                data_dirs: vec![],
                net_class: root.join("net"),
            };
            let status = probe_local(&roots, &["agent".to_owned()]);
            assert_eq!(status.units.len(), 2);
            for (unit, activity) in status.units {
                assert_eq!(
                    activity,
                    if unit.name == "infraternal-stalled.service" {
                        Activity::Unknown
                    } else {
                        Activity::Restarting { code: 1, status: 7 }
                    },
                    "{scope}/{} lost its own evidence",
                    unit.name
                );
            }
        }
        return;
    }
    let root = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").expect("job target directory"))
        .join(format!("independent-units-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("bin")).unwrap();
    let executable = root.join("bin/systemctl");
    fs::write(
        &executable,
        r#"#!/bin/sh
marker="$STATUS_UNIT_ISOLATION_ROOT/system.started"
[ "$1" != --user ] || marker="$STATUS_UNIT_ISOLATION_ROOT/user.started"
for last; do :; done
case "$last" in *stalled*) : > "$marker"; exec /bin/sleep 1;; esac
# Wait for the other query to start, so filesystem enumeration order cannot
# accidentally make a serial shared-deadline implementation pass.
while [ ! -e "$marker" ]; do /bin/sleep 0.001; done
printf '%s\n' ActiveState=activating SubState=auto-restart NRestarts=3 ExecMainCode=1 ExecMainStatus=7
"#,
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "stalled_units_preserve_other_units_in_each_manager",
            "--nocapture",
        ])
        .env("STATUS_UNIT_ISOLATION_ROOT", &root)
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
