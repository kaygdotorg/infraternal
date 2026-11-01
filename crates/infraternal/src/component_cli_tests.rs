//! Positional and named action inputs must reach local node components [D303, D314].

use crate::{
    cli::command_tree::{build, selected},
    component_cli::add_cli_values,
};
use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionRegistry, ActionTarget,
    CliDryRun as DryRun, JsonSchema, PluginDefinition,
};
use serde_json::{Value, json};

fn publish_registry() -> ActionRegistry {
    let action = ActionDefinition::new(
        ["publish"],
        "Publish or list services.",
        "Publish a local service or list current publications.",
        ["With no port, list publications."],
        JsonSchema::object(
            [
                ("port".to_owned(), JsonSchema::integer("Local TCP port.")),
                ("public".to_owned(), JsonSchema::boolean("Publish publicly.")),
                ("flat_name".to_owned(), JsonSchema::boolean("Use flat service names.")),
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
    ActionRegistry::new(vec![PluginDefinition::new(
        "proxy",
        "Publish local services.",
        [action],
    )])
    .expect("valid publish registry")
}

fn action_input(arguments: &[&str]) -> Value {
    let registry = publish_registry();
    let command = build(&registry);
    let matches = command
        .try_get_matches_from(arguments.iter().copied())
        .expect("publish command arguments");
    let selected = selected(&matches);
    let action = registry.find(&["publish"]).expect("publish action");
    let mut input = json!({});
    add_cli_values(action.action, selected.matches, &mut input).expect("action inputs");
    input
}

#[test]
fn publish_positional_port_and_scope_flags_reach_the_agent_action() {
    assert_eq!(
        action_input(&[
            "infraternal",
            "publish",
            "3000",
            "--public",
            "--flat-name",
            "--confirm-public",
        ]),
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
    assert_eq!(action_input(&["infraternal", "publish"]), json!({}));
}
