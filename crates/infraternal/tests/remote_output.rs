//! Checks declared remote CLI output against the deployed binary's real operator response [16][202], #163.
#![cfg(feature = "remote")]
#![allow(clippy::expect_used)]

use std::process::{Command, Stdio};

#[test]
fn remote_refusal_matches_its_declared_cli_output() {
    // An explicitly absent directory prevents this test from reading any enrolled identity.
    let data = std::env::current_dir()
        .expect("test directory")
        .join(format!("missing-remote-metadata-{}", std::process::id()));
    assert!(!data.exists());
    let output = Command::new(env!("CARGO_BIN_EXE_infraternal"))
        .args(["--json", "agent", "--data"])
        .arg(&data)
        .arg("run")
        .stdin(Stdio::null())
        .output()
        .expect("run the real CLI");
    assert!(!output.status.success());
    // JSON-mode logging is a separate line; select the operator record by its action.
    let value = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<serde_json::Value>()
        .map(|record| record.expect("JSON response line"))
        .filter(|record| record["action"] == "remote.host.run")
        .last()
        .expect("operator response");
    assert_eq!(value["action"], "remote.host.run");
    assert_eq!(value["state"], "refused");

    let action = infraternal_plugin_remote::cli::agent_actions()
        .into_iter()
        .find(|action| action.command.join(" ") == "agent run")
        .expect("registered remote action");
    let object = value.as_object().expect("operator object");
    for field in &action.output_schema.required {
        assert!(
            object.contains_key(field),
            "actual remote response lacks declared required field {field}"
        );
    }
    if action.output_schema.additional_properties == Some(false) {
        for field in object.keys() {
            assert!(
                action.output_schema.properties.contains_key(field),
                "actual remote response contains undeclared field {field}"
            );
        }
    }
}

#[cfg(not(feature = "plugin-server"))]
#[test]
fn node_build_refuses_server_creation() {
    let output = Command::new(env!("CARGO_BIN_EXE_infraternal"))
        .args(["server", "--json"])
        .output()
        .expect("run the node server command");
    assert!(!output.status.success());
    let creation = Command::new(env!("CARGO_BIN_EXE_infraternal"))
        .args(["server", "init", "--json"])
        .output()
        .expect("run the node server-init command");
    assert!(!creation.status.success());
}
