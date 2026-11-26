//! Declares server role commands and their stable CLI contracts.

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliDryRun as DryRun, CliHandler,
    JsonSchema, PluginDefinition, SafetyNotes, placeholders,
};

/// Stable plugin owner used to materialize only the requested CLI definitions.
pub const ID: &str = "server";

#[cfg(feature = "cli-plugin")]
const SETUP_TOKEN_COMMAND: [&str; 2] = ["server", "setup-token"];

/// Build the server's CLI actions, including the read-only Mesh identity check.
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
        plugin = plugin
            .with_group("server release", "Look at the server's releases.")
            .with_group(
                "server update",
                "Update the running server to a signed release, or go back, from the server machine.",
            );
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
    {
        plugin = plugin.with_group("server mesh", "Check the running server's Mesh identity.");
        plugin
            .actions
            .push(infraternal_plugin_remote::cli::restart_action());
        plugin.actions.push(server_mesh_status_action());
    }
    #[cfg(all(feature = "release", feature = "mesh"))]
    {
        plugin.actions.extend(server_mesh_routes_actions());
        plugin = plugin.with_group(
            "server mesh routes",
            "Approve and revoke the networks machines advertise, from the server machine.",
        );
    }
    plugin
}

/// What every `infraternal server mesh routes` command says about who may run it (D400).
#[cfg(all(feature = "cli-plugin", feature = "release", feature = "mesh"))]
const ROUTES_WHO: &str = "Run it on the server machine as root or as the account that runs the server; it needs no passkey there. From any other device, the owner approves with a fresh passkey.";

/// The `infraternal server mesh routes …` commands (D197 M3, #580): list, approve and revoke the
/// networks machines advertise, through the running server's private control socket (D400).
#[cfg(all(feature = "cli-plugin", feature = "release", feature = "mesh"))]
fn server_mesh_routes_actions() -> [ActionDefinition; 3] {
    let contract = |id: &str, effect| {
        ActionContract::new(ActionTarget::Global, effect, id, DryRun::Unsupported)
    };
    [
        ActionDefinition::new(
            ["server", "mesh", "routes"],
            "List the networks machines advertise and whether each is approved.",
            "Use this command on the server machine before approving or revoking a subnet route.",
            [
                ROUTES_WHO,
                "A waiting network shows why its approval would be refused, such as an overlap.",
            ],
            JsonSchema::empty_object(),
            JsonSchema::command_result(),
            contract("mesh.route.list", ActionEffect::Read),
        )
        .with_cli_handler(CliHandler::ServerMeshRoutes)
        .with_example(
            "server mesh routes",
            "List advertised and approved networks.",
        ),
        ActionDefinition::new(
            ["server", "mesh", "routes", "approve"],
            "Approve a network a machine advertises, so the mesh routes it.",
            "Use this command after `server mesh routes` shows the network waiting for approval.",
            [
                ROUTES_WHO,
                "Name the machine by its mesh name or node number, then the network.",
                "Forwarded traffic is masqueraded unless --keep-source is given.",
                "Who may reach the network follows Access: the mesh default, or arrows to it.",
            ],
            JsonSchema::object(
                [
                    (
                        "node".to_owned(),
                        JsonSchema::string(
                            "The machine that advertises the network: its name or node number.",
                        ),
                    ),
                    (
                        "network".to_owned(),
                        JsonSchema::string("The advertised network, such as 192.168.1.0/24."),
                    ),
                    (
                        "keep_source".to_owned(),
                        JsonSchema::boolean(
                            "Keep the peers' mesh addresses instead of masquerading.",
                        ),
                    ),
                ],
                ["node".to_owned(), "network".to_owned()],
            ),
            JsonSchema::command_result(),
            contract("mesh.route.approve", ActionEffect::Write),
        )
        .with_cli_handler(CliHandler::ServerMeshRoutes)
        .with_cli_positionals(["node", "network"])
        .with_example(
            "server mesh routes approve nas 192.168.1.0/24",
            "Route the LAN behind the machine named nas.",
        ),
        ActionDefinition::new(
            ["server", "mesh", "routes", "revoke"],
            "Stop routing an approved network.",
            "Use this command to take a network out of the mesh; the arrows to it are removed.",
            [
                ROUTES_WHO,
                "Name the route by the number `server mesh routes` shows.",
            ],
            JsonSchema::object(
                [(
                    "route".to_owned(),
                    JsonSchema::integer("The route number from `server mesh routes`."),
                )],
                ["route".to_owned()],
            ),
            JsonSchema::command_result(),
            contract("mesh.route.revoke", ActionEffect::Write),
        )
        .with_cli_handler(CliHandler::ServerMeshRoutes)
        .with_cli_positionals(["route"])
        .with_example("server mesh routes revoke 3", "Stop routing route 3."),
    ]
}

/// Define the command that reads the running server's public Mesh fingerprint.
#[cfg(all(feature = "cli-plugin", feature = "remote"))]
fn server_mesh_status_action() -> ActionDefinition {
    let data = JsonSchema::object(
        [
            (
                "running".to_owned(),
                JsonSchema::boolean("The running server answered its private control socket."),
            ),
            (
                "public_key_fingerprint".to_owned(),
                JsonSchema::string("SHA-256 fingerprint of the server's public Mesh key."),
            ),
        ],
        ["running".to_owned(), "public_key_fingerprint".to_owned()],
    );
    ActionDefinition::new(
        ["server", "mesh", "status"],
        "Show the running server's Mesh public-key fingerprint.",
        "Use this command on the server host, as the account that runs the server, to verify Mesh identity continuity.",
        [
            "Pass the server's private data directory with --data.",
            "The command checks the live server control socket and prints only the public-key fingerprint.",
        ],
        JsonSchema::empty_object(),
        JsonSchema::command_result_with(data),
        ActionContract::new(
            ActionTarget::Global,
            ActionEffect::Read,
            "server.status",
            DryRun::Unsupported,
        ),
    )
    .with_cli_handler(CliHandler::ServerMeshStatus)
    .with_example(
        "server mesh status --data /var/lib/infraternal --json",
        "Read the running server's public Mesh fingerprint.",
    )
}

/// Register the command that runs the server in the current terminal.
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
            "For a system service, the product owns its host input rules and installs a boot-time firewall unit, replacing any hand-installed infraternal-firewall.service. Add trusted admin paths with --host-firewall-allow.",
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

/// Register first-time system and user server installation.
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
            "host_firewall_off".to_owned(),
            JsonSchema::boolean(
                "For a system install, clear the server host policy and remove the shared table and loader when no agent policy remains.",
            ),
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
            "A system install also takes over infraternal-firewall.service and writes the configured default-drop host policy.",
            "Use --host-firewall-allow and --host-firewall-accept-interface to keep administrator paths, then inspect the complete plan with --dry-run.",
            "On an existing system install, --host-firewall-off clears only the server policy; an agent role keeps the shared table active.",
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
            "--host-firewall-off removes the server's default-drop table when no agent policy remains, which opens input."
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
        SETUP_TOKEN_COMMAND,
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

/// Format the setup-token command using the registered action path.
#[cfg(feature = "cli-plugin")]
#[must_use]
pub fn setup_token_command(system_service: bool) -> String {
    let command = format!("infraternal {}", SETUP_TOKEN_COMMAND.join(" "));
    if system_service {
        format!("sudo {command}")
    } else {
        command
    }
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

/// Describe the server and host-firewall settings accepted by run and init.
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
            JsonSchema::string(
                "File with the TLS certificate chain (PEM). With --remote-listen, only this account may read it (mode 0600, no symbolic link).",
            ),
        ),
        (
            "tls_key".to_owned(),
            JsonSchema::string(
                "File with the TLS private key (PEM). With --remote-listen, only this account may read it (mode 0600, no symbolic link).",
            ),
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
        (
            "host_firewall_listen_interface".to_owned(),
            JsonSchema::string("Interface that receives the main server listener."),
        ),
        (
            "host_firewall_remote_interface".to_owned(),
            JsonSchema::string("Interface that receives the remote agent listener."),
        ),
        (
            "host_firewall_remote_source".to_owned(),
            JsonSchema::array(
                JsonSchema::string("Remote listener peer address or CIDR."),
                "Peer addresses or networks allowed to reach the remote listener.",
            ),
        ),
        (
            "host_firewall_accept_interface".to_owned(),
            JsonSchema::array(
                JsonSchema::string("Host interface name."),
                "Interfaces whose existing broad input allowance should be kept.",
            ),
        ),
        (
            "host_firewall_allow".to_owned(),
            JsonSchema::array(
                JsonSchema::string("INTERFACE,SOURCE,tcp|udp,PORT; use * for any."),
                "Additional typed host input rules, including administrator SSH paths.",
            ),
        ),
    ]
}
