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
    assert_eq!(component_error_exit("not_found").map(Exit::code), Some(4));
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

/// Root Add host discovery refuses a state directory from a user-owned unit.
#[test]
fn root_add_host_refuses_a_user_owned_unit_source() {
    let fixture = std::env::temp_dir().join(format!("j470b-cli-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&fixture).unwrap();
    let installed = fixture.join("sessions");
    std::fs::write(fixture.join("infraternal-agent.service"), format!(
        "[Service]\nExecStart=\"/var/lib/infraternal/bin/current\" agent --data \"/var/lib/infraternal/state\" --state \"{}\" run\n", installed.display()
    )).unwrap();
    let roots = infraternal_status::Roots {
        system_units: vec![fixture.clone()],
        user_units: None,
        run_dir: Some(fixture.join("wrong-runtime")),
        system_run_dir: None,
        data_dirs: vec![],
        net_class: fixture.join("net"),
    };
    let result = super::action_state(None, &roots, true);
    let explicit = super::action_state(Some(fixture.join("explicit")), &roots, true).unwrap();
    std::fs::remove_dir_all(&fixture).unwrap();
    assert_eq!(
        result.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(explicit, fixture.join("explicit"));
}

/// Root Add host discovery refuses a group-writable installed unit.
#[test]
fn root_add_host_refuses_a_group_writable_unit_file() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = std::env::temp_dir().join(format!("j470b-cli-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&fixture).unwrap();
    let unit = fixture.join("infraternal-agent.service");
    std::fs::write(
        &unit,
        "[Service]\nExecStart=/var/lib/infraternal/bin/current agent --state=/var/lib/infraternal/sessions run\n",
    )
    .unwrap();
    std::fs::set_permissions(&unit, std::fs::Permissions::from_mode(0o664)).unwrap();
    let roots = infraternal_status::Roots {
        system_units: vec![fixture.clone()],
        user_units: None,
        run_dir: Some(fixture.join("wrong-runtime")),
        system_run_dir: None,
        data_dirs: vec![],
        net_class: fixture.join("net"),
    };

    let result = super::action_state(None, &roots, true);
    std::fs::remove_dir_all(&fixture).unwrap();
    assert_eq!(
        result.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

/// Root Add host discovery refuses a world-writable unit drop-in.
#[test]
fn root_add_host_refuses_a_world_writable_dropin() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = std::env::temp_dir().join(format!("j470b-cli-{}", uuid::Uuid::new_v4()));
    let dropins = fixture.join("infraternal-agent.service.d");
    std::fs::create_dir_all(&dropins).unwrap();
    std::fs::write(
        fixture.join("infraternal-agent.service"),
        "[Service]\nExecStart=/var/lib/infraternal/bin/current agent --state=/var/lib/infraternal/sessions run\n",
    )
    .unwrap();
    let dropin = dropins.join("10-state.conf");
    std::fs::write(
        &dropin,
        "[Service]\nExecStart=\nExecStart=/var/lib/infraternal/bin/current agent --state=/tmp/alternate-sessions run\n",
    )
    .unwrap();
    std::fs::set_permissions(&dropin, std::fs::Permissions::from_mode(0o666)).unwrap();
    let roots = infraternal_status::Roots {
        system_units: vec![fixture.clone()],
        user_units: None,
        run_dir: Some(fixture.join("wrong-runtime")),
        system_run_dir: None,
        data_dirs: vec![],
        net_class: fixture.join("net"),
    };

    let result = super::action_state(None, &roots, true);
    std::fs::remove_dir_all(&fixture).unwrap();
    assert_eq!(
        result.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

/// Root Add host discovery refuses a unit reached through a writable path component.
#[test]
fn root_add_host_refuses_a_writable_unit_path_chain() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = std::env::temp_dir().join(format!("j470b-cli-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&fixture).unwrap();
    std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::write(
        fixture.join("infraternal-agent.service"),
        "[Service]\nExecStart=/var/lib/infraternal/bin/current agent --state=/var/lib/infraternal/sessions run\n",
    )
    .unwrap();
    let roots = infraternal_status::Roots {
        system_units: vec![fixture.clone()],
        user_units: None,
        run_dir: Some(fixture.join("wrong-runtime")),
        system_run_dir: None,
        data_dirs: vec![],
        net_class: fixture.join("net"),
    };

    let result = super::action_state(None, &roots, true);
    std::fs::remove_dir_all(&fixture).unwrap();
    assert_eq!(
        result.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}
