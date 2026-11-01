//! Positional and named action inputs must reach local node components [D303, D314].

use crate::{
    cli::command_tree::{build, selected},
    cli::output::Exit,
    component_cli::{add_cli_values, component_error_exit, component_error_result},
};
use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionRegistry, ActionTarget,
    CliDryRun as DryRun, JsonSchema, PluginDefinition,
};
use serde_json::{Value, json};

fn proxy_registry() -> ActionRegistry {
    let publish = ActionDefinition::new(
        ["publish"],
        "Publish or list services.",
        "Publish a local service or list current publications.",
        ["With no port, list publications."],
        JsonSchema::object(
            [
                ("port".to_owned(), JsonSchema::integer("Local TCP port.")),
                (
                    "public".to_owned(),
                    JsonSchema::boolean("Publish publicly."),
                ),
                (
                    "flat_name".to_owned(),
                    JsonSchema::boolean("Use flat service names."),
                ),
                (
                    "confirm_public".to_owned(),
                    JsonSchema::boolean("Confirm first public use."),
                ),
            ],
            std::iter::empty::<String>(),
        ),
        JsonSchema::command_result(),
        ActionContract::new(
            ActionTarget::Host,
            ActionEffect::Write,
            "proxy.publish",
            DryRun::Unsupported,
        ),
    )
    .with_cli_positionals(["port"]);
    let unpublish = ActionDefinition::new(
        ["unpublish"],
        "Remove a published service.",
        "Stop publishing a local TCP port or named service.",
        ["Give the port or exact published name to remove."],
        JsonSchema::object(
            [(
                "target".to_owned(),
                JsonSchema::string("Port or published name."),
            )],
            ["target".to_owned()],
        ),
        JsonSchema::command_result(),
        ActionContract::new(
            ActionTarget::Host,
            ActionEffect::Write,
            "proxy.unpublish",
            DryRun::Unsupported,
        ),
    )
    .with_cli_positionals(["target"]);
    ActionRegistry::new(vec![PluginDefinition::new(
        "proxy",
        "Publish and unpublish local services.",
        [publish, unpublish],
    )])
    .expect("valid proxy registry")
}

fn action_input(command_name: &str, arguments: &[&str]) -> Value {
    let registry = proxy_registry();
    let command = build(&registry);
    let matches = command
        .try_get_matches_from(arguments.iter().copied())
        .expect("proxy command arguments");
    let selected = selected(&matches);
    let action = registry
        .find(&[command_name])
        .expect("proxy command action");
    let mut input = json!({});
    add_cli_values(action.action, selected.matches, &mut input).expect("action inputs");
    input
}

#[test]
fn publish_positional_port_and_scope_flags_reach_the_agent_action() {
    assert_eq!(
        action_input(
            "publish",
            &[
                "infraternal",
                "publish",
                "3000",
                "--public",
                "--flat-name",
                "--confirm-public",
            ]
        ),
        json!({
            "port": 3000,
            "public": true,
            "flat_name": true,
            "confirm_public": true
        })
    );
}

#[test]
fn bare_publish_sends_an_empty_list_request() {
    assert_eq!(
        action_input("publish", &["infraternal", "publish"]),
        json!({})
    );
}

#[test]
fn unpublish_accepts_a_port_or_exact_published_name() {
    assert_eq!(
        action_input("unpublish", &["infraternal", "unpublish", "3000"]),
        json!({"target": "3000"})
    );
    assert_eq!(
        action_input(
            "unpublish",
            &["infraternal", "unpublish", "port-3000.host-2.internal"]
        ),
        json!({"target": "port-3000.host-2.internal"})
    );
}

#[test]
fn missing_component_action_results_use_the_d303_not_found_exit() {
    assert_eq!(component_error_exit("missing").map(Exit::code), Some(4));
    assert_eq!(component_error_exit("invalid"), None);
}

#[test]
fn missing_component_action_results_keep_the_code_and_one_line_message() {
    let (result, exit) = component_error_result(
        "unpublish",
        &json!({
            "error": {"code": "missing"},
            "message": "No publication matches 3000."
        }),
    )
    .expect("typed component error");

    assert_eq!(exit.code(), 4);
    assert!(!result.ok);
    assert_eq!(result.message, "No publication matches 3000.");
    assert_eq!(result.error.expect("D303 error").code, "missing");
}
