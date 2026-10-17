//! Declares server role commands and their stable CLI contracts.

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliDryRun as DryRun, CliHandler,
    JsonSchema, PluginDefinition, SafetyNotes, placeholders,
};

/// Stable plugin owner used to materialize only the requested CLI definitions.
pub const ID: &str = "server";

#[cfg(feature = "cli-plugin")]
#[must_use]
pub fn plugin() -> PluginDefinition {
    let mut plugin = PluginDefinition::new(
        ID,
        "Run the infraternal server.",
        [
            server_run_action(),
            server_init_action(),
            server_install_compat_action(),
            server_setup_token_action(),
        ],
    );
    #[cfg(feature = "release")]
    {
        plugin
            .actions
            .extend(infraternal_plugin_release::descriptor::server_cli_actions());
        plugin = plugin.with_group("server release", "Look at the server's releases.");
    }
    plugin
        .actions
        .extend(placeholders(|| [server_features_action()]));
    for action in &mut plugin.actions {
        if action.input_schema.properties.contains_key("remote_ca_dir") {
            action
                .cli_requires
                .insert("remote_ca_dir".to_owned(), "remote_listen".to_owned());
        }
    }
    #[cfg(feature = "remote")]
    plugin
        .actions
        .push(infraternal_plugin_remote::cli::restart_action());
    plugin
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
        "Run the infraternal server in this terminal.",
        "Use this to run the server in the foreground, for a trial or under your own service manager.",
        [
            "Choose where it listens and a private folder for its data.",
            "Give it HTTPS files, or say that a trusted reverse proxy handles HTTPS.",
            "Start it. It runs until you stop it.",
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
            "system".to_owned(),
            JsonSchema::boolean(
                "Install for the whole machine (needs root) instead of your account.",
            ),
        ),
        (
            "user".to_owned(),
            JsonSchema::boolean("Install for your account only."),
        ),
        (
            "yes".to_owned(),
            JsonSchema::boolean("Do not ask for confirmation."),
        ),
        (
            "dry_run".to_owned(),
            JsonSchema::boolean("Show what would be installed and change nothing."),
        ),
        (
            "force".to_owned(),
            JsonSchema::boolean("Replace a different service that has the same name."),
        ),
        (
            "name".to_owned(),
            JsonSchema::string("Service name, without .service."),
        ),
    ]);
    ActionDefinition::new(
        ["server", "init"],
        "Install the server as a service and start it.",
        "Use this the first time you set up a server on this machine.",
        [
            "Choose where it listens, its data folder and its public address.",
            "Run with --dry-run to see exactly what would be installed.",
            "Run it again and confirm, or pass --yes when no one is at the terminal.",
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
            "Without --dry-run, setup enables and starts the selected service after confirmation."
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
            JsonSchema::boolean("Show what would be installed and change nothing."),
        ),
        (
            "force".to_owned(),
            JsonSchema::boolean("Replace a different service that has the same name."),
        ),
        (
            "name".to_owned(),
            JsonSchema::string("Service name, without .service."),
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
    let mut output = JsonSchema::command_result_with(token);
    // The additive alias preserves the deployed local reader without changing data.token.
    output.properties.insert(
        "token".to_owned(),
        JsonSchema::string("Compatibility alias of the one-time capability in data.token."),
    );
    ActionDefinition::new(
        ["server", "setup-token"],
        "Print the one-time code for creating the first owner.",
        "Use this only while setting up the first owner, before anyone has signed in.",
        [
            "Start the server and open its address in the app.",
            "Run this to read the one-time code from the server's private local socket.",
            "Enter the code only on the setup screen. Treat it as a secret.",
        ],
        JsonSchema::object(
            [(
                "data".to_owned(),
                JsonSchema::string("Folder of the server's data."),
            )],
            std::iter::empty(),
        ),
        output,
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
            "remote_listen".to_owned(),
            JsonSchema::string("Address and port where enrolled hosts connect."),
        ),
        (
            "remote_ca_dir".to_owned(),
            JsonSchema::string(
                "Folder of trusted certificate authority files for hosts. Needs --remote-listen.",
            ),
        ),
        (
            "listen".to_owned(),
            JsonSchema::string("Address and port to listen on, such as 127.0.0.1:7443."),
        ),
        (
            "data".to_owned(),
            JsonSchema::string("Folder for the server's data. Only this account may read it."),
        ),
        (
            "public_origin".to_owned(),
            JsonSchema::string(
                "The server's public HTTPS address, such as https://infra.example.org.",
            ),
        ),
        (
            "web_root".to_owned(),
            JsonSchema::string("Folder with the built web app."),
        ),
        (
            "tls_cert".to_owned(),
            JsonSchema::string("File with the TLS certificate chain (PEM)."),
        ),
        (
            "tls_key".to_owned(),
            JsonSchema::string("File with the TLS private key (PEM)."),
        ),
        (
            "behind_proxy".to_owned(),
            JsonSchema::boolean("A reverse proxy in front of the server handles HTTPS."),
        ),
        (
            "trusted_proxy".to_owned(),
            JsonSchema::array(
                JsonSchema::string("Proxy peer address or CIDR."),
                "Addresses or networks of the reverse proxies to trust.",
            ),
        ),
    ]
}
