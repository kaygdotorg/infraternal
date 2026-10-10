//! Declares server role commands and their stable CLI contracts.

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliHandler, DryRun, JsonSchema,
    PluginDefinition, SafetyNotes,
};

#[cfg(feature = "cli-plugin")]
#[must_use]
pub fn plugin() -> PluginDefinition {
    PluginDefinition::new(
        "server",
        "Create and run the infraternal control plane.",
        [
            server_run_action(),
            server_init_action(),
            server_features_action(),
            server_install_compat_action(),
            server_setup_token_action(),
        ],
    )
}

#[cfg(feature = "cli-plugin")]
fn server_run_action() -> ActionDefinition {
    let server_data = JsonSchema::object(
        [
            (
                "listen".to_owned(),
                JsonSchema::string("Server listener address."),
            ),
            (
                "public_origin".to_owned(),
                JsonSchema::string("Public server origin."),
            ),
        ],
        ["listen".to_owned(), "public_origin".to_owned()],
    );
    ActionDefinition::new(
        ["server"],
        "Run the configured infraternal server.",
        "Use this command to run the control plane in the foreground with the supplied listener and data settings.",
        [
            "Choose a listener address and private data directory.",
            "Provide HTTPS settings or select a trusted reverse proxy mode.",
            "Start the server and review its final state.",
        ],
        JsonSchema::object(server_input_fields(), std::iter::empty()),
        JsonSchema::command_result_with(server_data),
        ActionContract::new(
            ActionTarget::Global,
            ActionEffect::Write,
            "server.run",
            DryRun::Unsupported,
        ),
    )
    .with_cli_handler(CliHandler::ServerRun)
    .with_example("server --listen 127.0.0.1:7443", "Run a local server.")
}

#[cfg(feature = "cli-plugin")]
fn server_init_action() -> ActionDefinition {
    let mut inputs = server_input_fields();
    inputs.extend([
        (
            "yes".to_owned(),
            JsonSchema::boolean("Confirm server setup."),
        ),
        (
            "dry_run".to_owned(),
            JsonSchema::boolean("Print the installation plan without applying it."),
        ),
        (
            "force".to_owned(),
            JsonSchema::boolean("Replace a different existing service unit."),
        ),
        (
            "name".to_owned(),
            JsonSchema::string("Service unit name without the .service suffix."),
        ),
    ]);
    ActionDefinition::new(
        ["server", "init"],
        "Create and start a user service for this server.",
        "Use this command to explicitly set up a persistent server on this node.",
        [
            "Choose the listener, data directory, and public origin.",
            "Run with --dry-run to review the unit and systemd operations.",
            "Confirm interactively or pass --yes, then review the service state.",
        ],
        JsonSchema::object(inputs, std::iter::empty()),
        JsonSchema::command_result_with(server_init_result_schema()),
        ActionContract::new(
            ActionTarget::Global,
            ActionEffect::Write,
            "server.init",
            DryRun::Supported,
        ),
    )
    .with_cli_handler(CliHandler::ServerInit)
    .with_safety(SafetyNotes {
        destructive: false,
        dry_run_first: true,
        notes: vec![
            "Without --dry-run, setup enables and starts a user service after confirmation."
                .to_owned(),
        ],
    })
    .with_example("server init --dry-run", "Preview server setup.")
}

#[cfg(feature = "cli-plugin")]
fn server_features_action() -> ActionDefinition {
    let feature = JsonSchema::object(
        [
            (
                "name".to_owned(),
                JsonSchema::string("Server feature name."),
            ),
            ("state".to_owned(), JsonSchema::string("Feature state.")),
        ],
        ["name".to_owned(), "state".to_owned()],
    );
    let data = JsonSchema::object(
        [(
            "features".to_owned(),
            JsonSchema::array(feature, "Switchable server features."),
        )],
        ["features".to_owned()],
    );
    ActionDefinition::new(
        ["server", "features"],
        "Show runtime-switchable server features.",
        "Use this command to inspect which server capabilities can be enabled on this node.",
        ["Server feature switching is not available yet."],
        JsonSchema::empty_object(),
        JsonSchema::command_result_with(data),
        ActionContract::new(
            ActionTarget::Global,
            ActionEffect::Read,
            "server.features",
            DryRun::Unsupported,
        ),
    )
    .not_available_yet()
}

#[cfg(feature = "cli-plugin")]
fn server_install_compat_action() -> ActionDefinition {
    let mut inputs = server_input_fields();
    inputs.extend([
        (
            "system".to_owned(),
            JsonSchema::boolean("Install a system service."),
        ),
        (
            "user".to_owned(),
            JsonSchema::boolean("Install a user service."),
        ),
        (
            "dry_run".to_owned(),
            JsonSchema::boolean("Print the installation plan without applying it."),
        ),
        (
            "force".to_owned(),
            JsonSchema::boolean("Replace a different existing service unit."),
        ),
        (
            "name".to_owned(),
            JsonSchema::string("Service unit name without the .service suffix."),
        ),
    ]);
    ActionDefinition::new(
        ["server", "install"],
        "Redirect legacy setup commands to the confirmed server init path.",
        "Use this hidden compatibility command to learn how to update older setup scripts.",
        [
            "Review the server init instructions and configuration options.",
            "Run server init with --dry-run to inspect the service plan.",
            "Confirm service creation with server init --yes.",
        ],
        JsonSchema::object(inputs, std::iter::empty()),
        JsonSchema::command_result_with(server_init_result_schema()),
        ActionContract::new(
            ActionTarget::Global,
            ActionEffect::Read,
            "server.install.compatibility",
            DryRun::Unsupported,
        ),
    )
    .with_cli_handler(CliHandler::ServerInstallCompatibility)
    .hidden()
    .with_safety(SafetyNotes {
        destructive: false,
        dry_run_first: true,
        notes: vec!["This legacy path does not create or change a service.".to_owned()],
    })
}

#[cfg(feature = "cli-plugin")]
fn server_setup_token_action() -> ActionDefinition {
    let token = JsonSchema::object(
        [(
            "token".to_owned(),
            JsonSchema::string("One-time owner setup capability."),
        )],
        ["token".to_owned()],
    );
    ActionDefinition::new(
        ["server", "setup-token"],
        "Read the active one-time owner setup capability.",
        "Use this command only during first-owner setup while the server setup socket is active.",
        [
            "Start the server and begin first-owner setup.",
            "Read the one-time capability from the private local socket.",
            "Enter the capability only into the matching setup flow.",
        ],
        JsonSchema::object(
            [(
                "data".to_owned(),
                JsonSchema::string("Server data directory."),
            )],
            std::iter::empty(),
        ),
        JsonSchema::command_result_with(token),
        ActionContract::new(
            ActionTarget::Global,
            ActionEffect::Read,
            "server.setup-token",
            DryRun::Unsupported,
        ),
    )
    .with_cli_handler(CliHandler::ServerSetupToken)
    .with_safety(SafetyNotes {
        destructive: false,
        dry_run_first: false,
        notes: vec!["Treat the returned setup capability as a secret.".to_owned()],
    })
}

#[cfg(feature = "cli-plugin")]
fn server_init_result_schema() -> JsonSchema {
    JsonSchema::object(
        [
            (
                "service".to_owned(),
                JsonSchema::string("Installed service unit name."),
            ),
            (
                "enabled".to_owned(),
                JsonSchema::boolean("Whether the service is enabled and started."),
            ),
            (
                "dry_run".to_owned(),
                JsonSchema::boolean("Whether the operation only printed a plan."),
            ),
            (
                "plan".to_owned(),
                JsonSchema::string("Preview of the service unit and systemd operations."),
            ),
        ],
        [
            "service".to_owned(),
            "enabled".to_owned(),
            "dry_run".to_owned(),
        ],
    )
}

#[cfg(feature = "cli-plugin")]
fn server_input_fields() -> Vec<(String, JsonSchema)> {
    vec![
        (
            "listen".to_owned(),
            JsonSchema::string("HTTP(S) listener address."),
        ),
        (
            "data".to_owned(),
            JsonSchema::string("Private data directory."),
        ),
        (
            "public_origin".to_owned(),
            JsonSchema::string("Public HTTPS origin."),
        ),
        (
            "web_root".to_owned(),
            JsonSchema::string("Directory containing the built web application."),
        ),
        (
            "tls_cert".to_owned(),
            JsonSchema::string("PEM certificate chain path."),
        ),
        (
            "tls_key".to_owned(),
            JsonSchema::string("PEM private key path."),
        ),
        (
            "behind_proxy".to_owned(),
            JsonSchema::boolean("Trust a configured TLS-terminating reverse proxy."),
        ),
        (
            "trusted_proxy".to_owned(),
            JsonSchema::array(
                JsonSchema::string("Proxy peer address or CIDR."),
                "Trusted reverse proxy peers.",
            ),
        ),
    ]
}
