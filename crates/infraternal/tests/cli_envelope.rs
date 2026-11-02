//! Walks the whole command tree of the real binary: every command answers `--json` with the one envelope, errors included (#239, D299).
//!
//! Commands that change state are probed only with a mistyped option, which fails at the
//! parser before any handler runs. Read-only commands, and component commands pointed at
//! a directory that does not exist, are run for real. Nothing here touches the machine's
//! own infraternal agent, service units or data.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Command, Output};

use serde_json::Value;

const STATES: [&str; 9] = [
    "ready",
    "running",
    "restarting",
    "stopped",
    "pending",
    "unavailable",
    "refused",
    "failed",
    "unknown",
];

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_infraternal"))
        .args(args)
        .env_remove("NO_COLOR")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run the real CLI")
}

/// Every non-empty line of standard output must be exactly one envelope.
fn envelopes(label: &str, output: &Output) -> Vec<Value> {
    let text = String::from_utf8(output.stdout.clone()).expect("UTF-8 output");
    assert!(!text.trim().is_empty(), "{label}: empty standard output");
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let value: Value =
                serde_json::from_str(line).unwrap_or_else(|_| panic!("{label}: not JSON: {line}"));
            check_envelope(label, &value);
            value
        })
        .collect()
}

fn check_envelope(label: &str, value: &Value) {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("{label}: not an object"));
    assert_eq!(object["schema_version"], 1, "{label}");
    assert!(
        object["command"].as_str().is_some_and(|c| !c.is_empty()),
        "{label}: command"
    );
    let ok = object["ok"]
        .as_bool()
        .unwrap_or_else(|| panic!("{label}: ok must be a boolean"));
    assert!(
        STATES.contains(&object["state"].as_str().unwrap_or("")),
        "{label}: state"
    );
    assert!(
        object["message"].as_str().is_some_and(|m| !m.is_empty()),
        "{label}: message"
    );
    let next = object["next"]
        .as_array()
        .unwrap_or_else(|| panic!("{label}: next must be a list"));
    assert!(
        next.len() <= 3 && next.iter().all(Value::is_string),
        "{label}: next"
    );
    assert!(object.contains_key("data"), "{label}: data");
    if ok {
        assert!(
            !object.contains_key("error"),
            "{label}: ok results carry no error"
        );
    } else {
        assert!(
            object["error"]["code"].as_str().is_some(),
            "{label}: error.code"
        );
    }
    for key in object.keys() {
        assert!(
            [
                "schema_version",
                "command",
                "ok",
                "state",
                "message",
                "next",
                "next_step",
                "details",
                "error",
                "data",
            ]
            .contains(&key.as_str()),
            "{label}: unknown field {key}"
        );
    }
}

/// Every visible command path, from the binary's own list.
fn commands() -> Vec<Vec<String>> {
    let output = run(&["skill", "--json"]);
    let envelope = &envelopes("skill --json", &output)[0];
    envelope["data"]["commands"]
        .as_array()
        .expect("command list")
        .iter()
        .map(|entry| {
            entry["command"]
                .as_str()
                .expect("command path")
                .split(' ')
                .map(str::to_owned)
                .collect()
        })
        .collect()
}

#[test]
fn every_command_reports_a_usage_error_in_the_envelope_naming_the_argument() {
    let commands = commands();
    assert!(
        commands.len() >= 5,
        "the tree lists its commands: {commands:?}"
    );
    for path in commands {
        let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
        args.extend(["--json", "--no-such-option"]);
        let label = args.join(" ");
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{label}: usage exits 2");
        assert!(
            output.stderr.is_empty(),
            "{label}: JSON mode writes nothing to stderr"
        );
        let found = envelopes(&label, &output);
        assert_eq!(found.len(), 1, "{label}");
        assert_eq!(found[0]["ok"], false, "{label}");
        assert_eq!(found[0]["error"]["code"], "usage", "{label}");
        assert_eq!(found[0]["error"]["argument"], "--no-such-option", "{label}");
    }
}

#[test]
fn read_only_commands_answer_in_the_envelope() {
    for args in [
        vec!["status", "--json"],
        vec!["--json", "skill"],
        vec!["skill", "status", "--json"],
        vec!["skill", "mesh", "--json"],
        vec!["--json"],
        vec!["server", "--json"],
    ] {
        let label = args.join(" ");
        let output = run(&args);
        let found = envelopes(&label, &output);
        assert_eq!(found.len(), 1, "{label}");
    }
}

#[test]
fn an_unknown_command_is_a_usage_envelope_that_does_not_echo_odd_input() {
    let output = run(&["--json", "https://user:secret@example.test/path"]);
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8(output.stdout.clone()).unwrap();
    assert!(!text.contains("secret"), "{text}");
    envelopes("unknown command", &output);
}

#[cfg(all(feature = "plugin-mesh", feature = "plugin-agent", target_os = "linux"))]
#[test]
fn component_commands_fail_in_the_envelope_when_the_agent_is_not_there() {
    // A directory that does not exist: the call fails before any socket is touched.
    let missing = std::env::temp_dir().join(format!("cli-envelope-missing-{}", std::process::id()));
    assert!(!missing.exists());
    let state = missing.to_str().unwrap();
    for command in [
        ["mesh", "status"],
        ["mesh", "peers"],
        ["mesh", "up"],
        ["mesh", "down"],
    ] {
        let args = [command[0], command[1], "--json", "--state", state];
        let label = args.join(" ");
        let output = run(&args);
        // D303: the infraternal agent is off or unreachable, exit 5.
        assert_eq!(output.status.code(), Some(5), "{label}");
        let found = envelopes(&label, &output);
        assert_eq!(found[0]["error"]["code"], "unreachable", "{label}");
        assert_eq!(found[0]["ok"], false, "{label}");
        assert_eq!(
            found[0]["command"],
            format!("{} {}", command[0], command[1]),
            "{label}"
        );
        assert!(output.stderr.is_empty(), "{label}");
    }
}

#[test]
fn bare_infraternal_is_the_overview_and_points_to_help() {
    let output = run(&["--json"]);
    // The overview reports the real machine: a configured but stopped service
    // is exit 5, while an unconfigured or healthy machine is exit 0 (#296).
    assert!(matches!(output.status.code(), Some(0 | 5)));
    let found = envelopes("bare", &output);
    assert_eq!(found[0]["ok"], output.status.success());
    if !output.status.success() {
        assert_eq!(found[0]["error"]["code"], "component_down");
    }
    assert!(found[0]["data"]["role"].is_string());
    let next = found[0]["next"].as_array().unwrap();
    assert!(
        next.iter().any(|entry| entry == "infraternal --help"),
        "{next:?}"
    );
    // Text mode is the same answer, on standard output.
    let text = run(&[]);
    assert!(matches!(text.status.code(), Some(0 | 5)));
    assert!(
        String::from_utf8(text.stdout)
            .unwrap()
            .contains("infraternal --help")
    );
}

/// A private machine whose manager always confirms the fixture unit is inactive.
fn status_in(home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_infraternal"))
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_RUNTIME_DIR", home.join("run"))
        .env(
            "INFRATERNAL_TEST_SYSTEMD_SYSTEM_UNIT_DIR",
            home.join("system"),
        )
        .env(
            "PATH",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/inactive-manager"),
        )
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run the real CLI")
}

#[test]
fn status_exits_5_when_something_that_should_run_is_down() {
    let home = std::env::temp_dir().join(format!("cli-status-exit-{}", std::process::id()));
    let units = home.join("config/systemd/user");
    std::fs::create_dir_all(&units).unwrap();
    // An unavailable host manager means Unknown, not confirmed-down. The private
    // manager supplies the inactive observation this exit-code test requires.
    std::fs::write(
        units.join(format!("infraternal-test-{}.service", std::process::id())),
        "[Service]\nExecStart=/usr/bin/infraternal agent run\n",
    )
    .unwrap();
    for args in [vec!["status", "--json"], vec!["--json"]] {
        let output = status_in(&home, &args);
        assert_eq!(output.status.code(), Some(5), "{args:?}");
        let found = envelopes("status down", &output);
        assert_eq!(found[0]["ok"], false);
        assert_eq!(found[0]["error"]["code"], "component_down");
        assert_eq!(output.stderr.len(), 0);
    }
    // Text mode: the report is information, so it is on standard output even though the exit is 5.
    let text = status_in(&home, &["status"]);
    assert_eq!(text.status.code(), Some(5));
    assert!(!text.stdout.is_empty() && text.stderr.is_empty());
    std::fs::remove_dir_all(&home).unwrap();
}

#[test]
fn status_exits_0_on_a_machine_with_nothing_installed() {
    let home = std::env::temp_dir().join(format!("cli-status-none-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let system_units = std::fs::read_dir("/etc/systemd/system").is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("infraternal")
        })
    });
    // The probe also reads the system's own unit directory and data directory.
    if !system_units && !std::path::Path::new("/var/lib/infraternal/infraternal.sqlite").exists() {
        let output = status_in(&home, &["status", "--json"]);
        assert_eq!(output.status.code(), Some(0));
        let found = envelopes("status none", &output);
        assert_eq!(found[0]["ok"], true);
        assert_eq!(found[0]["data"]["role"], "none");
    }
    std::fs::remove_dir_all(&home).unwrap();
}

#[cfg(feature = "release")]
#[test]
fn a_missing_server_is_not_found_exit_4() {
    let missing = std::env::temp_dir().join(format!("cli-no-server-{}", std::process::id()));
    assert!(!missing.exists());
    let output = run(&[
        "server",
        "release",
        "latest",
        "--json",
        "--data",
        missing.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(4));
    let found = envelopes("server release latest", &output);
    assert_eq!(found[0]["error"]["code"], "not_found");
}
