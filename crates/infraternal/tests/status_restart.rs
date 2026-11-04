//! Local manager-property regressions for both service roles and scopes (#237, D299, D303).
#![allow(clippy::unwrap_used)]
use nix::sys::time::TimeValLike;
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
#[allow(clippy::too_many_lines)] // Keep the complete role/scope/output matrix together.
fn service_states_are_truthful_in_text_and_json() {
    let root = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(
            || {
                std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
                    .join(".cache/codex-scratch/status-crash-loop-237/target")
            },
            std::path::PathBuf::from,
        )
        .join(format!("status-restart-fixture-{}", std::process::id()));
    let now = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .unwrap()
        .num_microseconds();
    // Fixture managers run with a PATH holding only themselves; they stamp fresh
    // starts with the interpreter the other real-binary fixtures already use.
    let python = String::from_utf8(
        Command::new("sh")
            .args(["-c", "command -v python3"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    assert!(!python.is_empty(), "the status fixtures need python3");
    let cases = [
        (
            "activating",
            "auto-restart",
            45,
            now,
            1,
            1,
            "Restarting repeatedly",
            "restarting",
            5,
        ),
        (
            "active",
            "auto-restart",
            45,
            now,
            1,
            1,
            "Restarting repeatedly",
            "restarting",
            5,
        ),
        (
            "active",
            "running",
            46,
            now,
            2,
            11,
            "Restarting repeatedly",
            "restarting",
            5,
        ),
        (
            "delayed",
            "auto-restart",
            45,
            now,
            1,
            1,
            "Restarting repeatedly",
            "restarting",
            5,
        ),
        (
            "busy",
            "auto-restart",
            45,
            now,
            1,
            1,
            "Restarting repeatedly",
            "restarting",
            5,
        ),
        (
            "busy-active",
            "running",
            0,
            now,
            0,
            0,
            "Running",
            "running",
            0,
        ),
        ("active", "running", 0, 1, 0, 0, "Running", "running", 0),
        ("active", "running", 46, 1, 0, 0, "Running", "running", 0),
        ("inactive", "dead", 0, 1, 0, 0, "Stopped", "stopped", 5),
        ("failed", "failed", 45, now, 1, 1, "Failed", "failed", 5),
        ("unknown", "", 0, 0, 0, 0, "Unknown", "unknown", 0),
    ];
    for scope in ["system", "user"] {
        for role in ["server", "agent"] {
            let home = root.join(format!("{scope}-{role}"));
            let system = home.join("system");
            let config = home.join("config");
            let units = if scope == "system" {
                system.clone()
            } else {
                config.join("systemd/user")
            };
            fs::create_dir_all(&units).unwrap();
            fs::create_dir_all(home.join("bin")).unwrap();
            fs::write(
                units.join(format!("infraternal-{role}.service")),
                format!("[Service]\nExecStart=/usr/bin/infraternal {role}\n"),
            )
            .unwrap();
            let manager = home.join("bin/systemctl");
            for (active, sub, restarts, started, code, status, label, state, exit) in cases {
                // A recent start is stamped when the manager is asked, one
                // second before that moment: a single cold status run on a
                // loaded host can take longer than the 10 s restart window, so
                // a value frozen when this fixture is written can age out (#334).
                let started = if started == now {
                    format!(
                        "$({python} -c 'import time; print(int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1e6) - 1000000)')"
                    )
                } else {
                    started.to_string()
                };
                let scope_check = if scope == "user" {
                    "test \"$1\" = --user || exit 1\nshift\n"
                } else {
                    "test \"$1\" = show || exit 1\n"
                };
                // Delayed responses still exercise the child-exit wakeup and
                // the two observations of a fresh active service. The matrix
                // runs under a hang-sized budget: it checks how states read,
                // and a cold debug binary can spend seconds of a 500 ms window
                // on its own page faults (#334). The budget's structure (one
                // deadline for both observations) is a unit test in
                // infraternal-status.
                let delay = match active {
                    "delayed" => "/bin/sleep 0.025\n",
                    "busy" => "/bin/sleep 0.3\n",
                    "busy-active" => "/bin/sleep 0.075\n",
                    _ => "",
                };
                let active = match active {
                    "delayed" | "busy" => "activating",
                    "busy-active" => "active",
                    _ => active,
                };
                let response = if active == "unknown" {
                    "exit 1".to_owned()
                } else {
                    format!(
                        "printf '%s\\n' ActiveState={active} SubState={sub} MainPID=42 Result=exit-code NRestarts={restarts} ExecMainStartTimestampMonotonic={started} ExecMainCode={code} ExecMainStatus={status}"
                    )
                };
                fs::write(
                    &manager,
                    format!("#!/bin/sh\n{scope_check}{delay}{response}\n"),
                )
                .unwrap();
                fs::set_permissions(&manager, fs::Permissions::from_mode(0o755)).unwrap();
                for json in [false, true] {
                    let mut cmd = Command::new(env!("CARGO_BIN_EXE_infraternal"));
                    cmd.arg("status");
                    if json {
                        cmd.arg("--json");
                    }
                    let output = cmd
                        .env_clear()
                        .env("HOME", &home)
                        .env("XDG_CONFIG_HOME", &config)
                        .env("INFRATERNAL_TEST_SYSTEMD_SYSTEM_UNIT_DIR", &system)
                        .env("PATH", home.join("bin"))
                        .env("INFRATERNAL_TEST_MANAGER_QUERY_BUDGET_MS", "30000")
                        .output()
                        .unwrap();
                    let text = String::from_utf8(output.stdout).unwrap();
                    assert!(text.contains(label), "{scope}/{role}/{active}: {text}");
                    assert_eq!(output.status.code(), Some(exit), "{text}");
                    if state == "restarting" {
                        assert!(
                            text.contains(if code == 1 {
                                "last exit status 1"
                            } else {
                                "last signal 11"
                            }),
                            "{text}"
                        );
                        assert!(text.contains("journalctl"), "{text}");
                        assert_eq!(
                            text.contains("journalctl --user"),
                            scope == "user",
                            "{text}"
                        );
                    }
                    if json {
                        let envelope: serde_json::Value = serde_json::from_str(&text).unwrap();
                        assert_eq!(envelope["schema_version"], 1);
                        assert_eq!(envelope["state"], state);
                        assert_eq!(envelope["ok"], exit == 0);
                        assert_eq!(
                            envelope["data"]["role"],
                            if role == "server" { "server" } else { "host" }
                        );
                        assert_eq!(envelope["error"].is_object(), exit != 0);
                    }
                }
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}
