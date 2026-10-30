//! Independent manager-observation regressions for #237 (D299/D303).
use infraternal_status::{Activity, Roots, Scope, probe_local};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

fn isolated(name: &str, manager: &str, check: impl FnOnce(PathBuf)) {
    if let Some(root) = std::env::var_os("STATUS_REVIEW_237_ROOT") {
        check(PathBuf::from(root));
        return;
    }
    let root = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").expect("target directory"))
        .join(format!("review-237-{name}-{}", std::process::id()));
    fs::create_dir_all(root.join("bin")).unwrap();
    let executable = root.join("bin/systemctl");
    let future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 60;
    let manager = manager.replace("FUTURE_TIMESTAMP", &future.to_string());
    fs::write(&executable, format!("#!/bin/sh\n{manager}\n")).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("STATUS_REVIEW_237_ROOT", &root)
        .env("PATH", root.join("bin"))
        .output()
        .unwrap();
    fs::remove_dir_all(root).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn unavailable_system_manager_preserves_user_restart_observation() {
    isolated(
        "unavailable_system_manager_preserves_user_restart_observation",
        r#"
if [ "$1" != --user ]; then exec /bin/sleep 1; fi
printf '%s\n' ActiveState=activating SubState=auto-restart NRestarts=45 MainPID=0 ExecMainCode=1 ExecMainStatus=1
"#,
        |root| {
            let system = root.join("system");
            let user = root.join("user");
            for directory in [&system, &user] {
                fs::create_dir_all(directory).unwrap();
            }
            fs::write(
                system.join("infraternal-server.service"),
                "[Service]\nExecStart=/usr/bin/infraternal server\n",
            )
            .unwrap();
            fs::write(
                user.join("infraternal-agent.service"),
                "[Service]\nExecStart=/usr/bin/infraternal agent run\n",
            )
            .unwrap();
            let roots = Roots {
                system_units: vec![system],
                user_units: Some(user),
                run_dir: None,
                data_dirs: vec![],
                net_class: root.join("net"),
            };
            let status = probe_local(&roots, &["server".to_owned(), "agent".to_owned()]);
            assert_eq!(
                status
                    .units
                    .iter()
                    .find(|(unit, _)| unit.scope == Scope::System)
                    .unwrap()
                    .1,
                Activity::Unknown
            );
            assert_eq!(
                status
                    .units
                    .iter()
                    .find(|(unit, _)| unit.scope == Scope::User)
                    .unwrap()
                    .1,
                Activity::Restarting { code: 1, status: 1 },
                "one unavailable manager must not hide another manager's restart loop"
            );
            assert_eq!(
                status.confirmed_down().len(),
                1,
                "D303 must retain the down service"
            );
        },
    );
}
