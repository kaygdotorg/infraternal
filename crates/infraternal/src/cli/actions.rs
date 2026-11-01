//! Builds the validated action registry from built-in and enabled component plugins.

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionRegistry, ActionTarget,
    CliDryRun as DryRun, CliHandler, JsonSchema, PluginDefinition, RegistryError,
};

/// Create the action registry for the plugins enabled in this binary.
pub fn registry() -> Result<ActionRegistry, RegistryError> {
    build_registry(None)
}

/// Materialize one plugin for its command; core discovery keeps the full registry.
/// A plugin's own identifier selects its factory, never a handwritten action route.
pub fn registry_for(root: Option<&str>) -> Result<ActionRegistry, RegistryError> {
    if root == Some("__shim") {
        // This synchronous process boundary is entered once for each worker
        // and terminal. Keep the same declared schema/parser, but do not build
        // status, skill or operator metadata that this launch cannot execute.
        return ActionRegistry::new(vec![PluginDefinition::new(
            "cli",
            "Inspect this node and manage its configured components.",
            [session_shim_action()],
        )]);
    }
    if let Some(factory) =
        root.and_then(|root| factories().iter().find(|factory| factory.id == root))
    {
        return ActionRegistry::new(vec![(factory.build)()]);
    }
    if let Some(root) = root {
        let core = cli_plugin();
        if core.actions.iter().any(|action| {
            action
                .command
                .first()
                .is_some_and(|command| command == root)
                && !matches!(action.cli_handler, CliHandler::Status | CliHandler::Skill)
        }) {
            return ActionRegistry::new(vec![core]);
        }
    }
    registry()
}

struct PluginFactory {
    id: &'static str,
    build: fn() -> PluginDefinition,
}

fn factories() -> &'static [PluginFactory] {
    static FACTORIES: &[PluginFactory] = &[
        #[cfg(feature = "release")]
        PluginFactory {
            id: infraternal_plugin_release::descriptor::DESCRIPTOR.id,
            build: release_plugin,
        },
        #[cfg(feature = "plugin-server")]
        PluginFactory {
            id: infraternal_server::cli::ID,
            build: infraternal_server::cli::plugin,
        },
        #[cfg(feature = "plugin-agent")]
        PluginFactory {
            id: infraternal_agent::cli::ID,
            build: infraternal_agent::cli::plugin,
        },
        #[cfg(feature = "plugin-mesh")]
        PluginFactory {
            id: infraternal_plugin_mesh::descriptor::DESCRIPTOR.id,
            build: infraternal_plugin_mesh::descriptor::cli_plugin,
        },
        #[cfg(feature = "plugin-proxy")]
        PluginFactory {
            id: infraternal_plugin_proxy::cli::ID,
            build: infraternal_plugin_proxy::cli::plugin,
        },
        #[cfg(feature = "plugin-host-facts")]
        PluginFactory {
            id: infraternal_plugin_host_facts::DESCRIPTOR.id,
            build: host_plugin,
        },
        #[cfg(feature = "plugin-relay")]
        PluginFactory {
            id: infraternal_plugin_relay::cli::ID,
            build: infraternal_plugin_relay::cli::plugin,
        },
        #[cfg(feature = "plugin-backup")]
        PluginFactory {
            id: infraternal_plugin_backup::cli::ID,
            build: infraternal_plugin_backup::cli::plugin,
        },
        #[cfg(feature = "plugin-ssh")]
        PluginFactory {
            id: infraternal_plugin_ssh::cli::ID,
            build: infraternal_plugin_ssh::cli::plugin,
        },
    ];
    FACTORIES
}

fn build_registry(root: Option<&str>) -> Result<ActionRegistry, RegistryError> {
    let plugins = std::iter::once(cli_plugin())
        .chain(
            factories()
                .iter()
                .filter(|factory| root.is_none_or(|root| factory.id == root))
                .map(|factory| (factory.build)()),
        )
        .collect();
    ActionRegistry::new(plugins)
}

#[cfg(feature = "plugin-host-facts")]
fn host_plugin() -> PluginDefinition {
    let descriptor = &infraternal_plugin_host_facts::DESCRIPTOR;
    if infraternal_plugin_api::PLACEHOLDERS {
        descriptor.cli_plugin(ActionTarget::Host)
    } else {
        PluginDefinition::new(descriptor.id, "Read facts about a host.", [])
    }
}

#[cfg(feature = "release")]
fn release_plugin() -> PluginDefinition {
    let descriptor = &infraternal_plugin_release::descriptor::DESCRIPTOR;
    if infraternal_plugin_api::PLACEHOLDERS {
        descriptor.cli_plugin(ActionTarget::Global)
    } else {
        PluginDefinition::new(descriptor.id, "Look at the server's releases.", [])
    }
}

fn cli_plugin() -> PluginDefinition {
    let plugin = PluginDefinition::new(
        "cli",
        "Run and manage infraternal on this machine.",
        [
            status_action(),
            skill_action(),
            sign_in_action(),
            session_shim_action(),
        ],
    );
    let mut plugin = plugin;
    plugin
        .actions
        .extend(infraternal_plugin_api::placeholders(|| [up_action()]));
    #[cfg(feature = "remote")]
    plugin
        .actions
        .push(infraternal_plugin_remote::cli::remove_action());
    #[cfg(feature = "remote")]
    plugin.actions.push(key_memory_check_action());
    #[cfg(feature = "ssh")]
    plugin.actions.push(ssh_askpass_action());
    #[cfg(all(feature = "ssh", feature = "remote"))]
    plugin.actions.push(ssh_session_action());
    #[cfg(all(feature = "plugin-agent", target_os = "linux"))]
    plugin
        .actions
        .extend(infraternal_agent::automation::actions());
    plugin
}

fn sign_in_action() -> ActionDefinition {
    let data = JsonSchema::object(
        [
            ("server".to_owned(), JsonSchema::string("Server origin.")),
            (
                "device".to_owned(),
                JsonSchema::string("This device's name."),
            ),
            (
                "scopes".to_owned(),
                JsonSchema::array(JsonSchema::string("Granted scope."), "Granted scopes."),
            ),
            (
                "stored".to_owned(),
                JsonSchema::boolean("Credential stored securely."),
            ),
            (
                "user_code".to_owned(),
                JsonSchema::string("Short-lived code for browser approval."),
            ),
            (
                "verification_url".to_owned(),
                JsonSchema::string("HTTPS link to review the device request."),
            ),
            (
                "expires_in_seconds".to_owned(),
                JsonSchema::integer("Time remaining for the approval request."),
            ),
        ],
        [],
    );
    ActionDefinition::new(
        ["sign-in"],
        "Sign this device into a server with a passkey approval.",
        "Use this command to authorize this CLI device for automation on one server.",
        [
            "Start a short-lived device approval on the server.",
            "Open the printed link and confirm this device and its scopes with your passkey.",
            "Wait for approval; the resulting credential is saved in your private config folder.",
        ],
        JsonSchema::object(
            [(
                "server".to_owned(),
                JsonSchema::string("HTTPS origin of the server."),
            )],
            ["server".to_owned()],
        ),
        JsonSchema::command_result_with(data),
        ActionContract::new(
            ActionTarget::Global,
            ActionEffect::Write,
            "cli.sign-in",
            DryRun::Unsupported,
        ),
    )
    .with_cli_handler(CliHandler::SignIn)
    .with_cli_positionals(["server"])
    .with_example(
        "sign-in https://infra.example.org",
        "Authorize this CLI device.",
    )
}

fn status_action() -> ActionDefinition {
    let component = JsonSchema::object(
        [
            ("name".to_owned(), JsonSchema::string("Component name.")),
            (
                "state".to_owned(),
                JsonSchema::string("Current component state."),
            ),
            (
                "state_detail".to_owned(),
                JsonSchema::string("Extra fact for this component, such as the mesh peer count."),
            ),
        ],
        ["name".to_owned(), "state".to_owned()],
    );
    let status_data = JsonSchema::object(
        [
            ("role".to_owned(), JsonSchema::string("Current node role.")),
            (
                "components".to_owned(),
                JsonSchema::array(component, "Components and their observed states."),
            ),
        ],
        ["role".to_owned(), "components".to_owned()],
    );
    ActionDefinition::new(
        ["status"],
        "Show what infraternal runs on this machine.",
        "Use this to see which infraternal services run here and whether any is down. It exits 5 when an installed service is not running.",
        [
            "Read the service files and data folders on this machine.",
            "Read the components table: each line says whether that part is running.",
        ],
        JsonSchema::empty_object(),
        JsonSchema::command_result_with(status_data),
        ActionContract::new(
            ActionTarget::Global,
            ActionEffect::Read,
            "cli.status",
            DryRun::Unsupported,
        ),
    )
    .with_cli_handler(CliHandler::Status)
    .with_example("status", "Show what runs on this machine.")
}

fn up_action() -> ActionDefinition {
    let up_data = JsonSchema::object(
        [(
            "started".to_owned(),
            JsonSchema::array(JsonSchema::string("Component name."), "Started components."),
        )],
        ["started".to_owned()],
    );
    ActionDefinition::new(
        ["up"],
        "Start the configured node components.",
        "Use this command when this node should bring its configured components online.",
        [
            "Review the configured components with status.",
            "Start the node components when lifecycle management is available.",
        ],
        JsonSchema::empty_object(),
        JsonSchema::command_result_with(up_data),
        ActionContract::new(
            ActionTarget::Global,
            ActionEffect::Write,
            "cli.up",
            DryRun::Unsupported,
        ),
    )
    .not_available_yet()
    .with_example(
        "up",
        "Request startup of this node's configured components.",
    )
}

fn skill_action() -> ActionDefinition {
    ActionDefinition::new(
        ["skill"],
        "List the commands, or print one as instructions for an AI agent.",
        "Use this to give an AI agent the exact contract of a command: what it does, its options and its JSON output.",
        [
            "Run `infraternal skill` to list the commands you can use.",
            "Add a command, such as `infraternal skill mesh peers`, to print its instructions.",
            "Add --write DIR to save one Markdown file per command.",
        ],
        skill_input_schema(),
        JsonSchema::command_result_with(skill_output_data_schema()),
        ActionContract::new(
            ActionTarget::Global,
            ActionEffect::Read,
            "cli.skill",
            DryRun::Unsupported,
        ),
    )
    .with_cli_handler(CliHandler::Skill)
    .with_example("skill status", "Print the generated skill for status.")
}

/// D244 diagnostics use the same hidden-action parsing and compile-out path as the shim.
#[cfg(feature = "remote")]
fn key_memory_check_action() -> ActionDefinition {
    ActionDefinition::new(
        ["__key-memory-check"],
        "Check the compiled provider’s key memory without creating or importing keys.",
        "Use this hidden diagnostic to verify the shipping provider’s page protection.",
        [
            "Run under an 8 MiB memlock limit.",
            "Require initialization=1 for locked pages and dump exclusion.",
        ],
        JsonSchema::object([], []),
        JsonSchema::command_result(),
        ActionContract::new(
            ActionTarget::Global,
            ActionEffect::Read,
            "cli.internal.key-memory-check",
            DryRun::Unsupported,
        ),
    )
    .hidden()
    .with_cli_handler(CliHandler::KeyMemoryCheck)
}

fn session_shim_action() -> ActionDefinition {
    ActionDefinition::new(
        ["__shim"],
        "Run the internal session shim.",
        "Use this hidden command only when a host process starts a private session shim.",
        [
            "Connect the shim to the requested session identifier and user.",
            "Use the optional terminal dimensions, state directory and replay capacity when supplied.",
        ],
        JsonSchema::object(
            [
                #[cfg(feature = "process-per-user")]
                ("host_sessions".to_owned(), JsonSchema::integer("Research-only count of sessions in one existing person login; 1–1000.")),
                #[cfg(feature = "process-per-user")]
                ("host_accounting".to_owned(), JsonSchema::string("Research-only new private file for numeric session ownership receipts on SIGUSR2; no timer or terminal content.")),
                (
                    "session".to_owned(),
                    JsonSchema::string("Validated session identifier."),
                ),
                (
                    "uid".to_owned(),
                    JsonSchema::integer("Effective user identifier."),
                ),
                (
                    "cols".to_owned(),
                    JsonSchema::integer("PTY column count; defaults to 80."),
                ),
                (
                    "rows".to_owned(),
                    JsonSchema::integer("PTY row count; defaults to 24."),
                ),
                (
                    "state".to_owned(),
                    JsonSchema::string("Private session state directory."),
                ),
                #[cfg(feature = "plugin-agent")]
                ("controller_uid".to_owned(), JsonSchema::integer("Authenticated local login controller uid; defaults to root.")),
                #[cfg(feature = "plugin-agent")]
                ("login_worker_proc".to_owned(), JsonSchema::string("Pinned authenticated login process directory.")),
                #[cfg(feature = "plugin-agent")]
                ("login_worker_pid".to_owned(), JsonSchema::integer("Authenticated host login worker PID.")),
                #[cfg(feature = "plugin-agent")]
                ("login_worker_parent".to_owned(), JsonSchema::integer("Authenticated original host login parent PID.")),
                #[cfg(feature = "plugin-agent")]
                ("login_cgroup".to_owned(), JsonSchema::string("Verified host login cgroup membership file.")),
                #[cfg(feature = "plugin-agent")]
                ("login_ready_fd".to_owned(), JsonSchema::integer("Internal shell-start confirmation descriptor.")),
                #[cfg(feature = "plugin-agent")]
                ("login_master_fd".to_owned(), JsonSchema::integer("Internal prestarted terminal master descriptor.")),
                #[cfg(feature = "plugin-agent")]
                ("login_lease_fd".to_owned(), JsonSchema::integer("Internal authenticated terminal lease descriptor.")),
                #[cfg(feature = "plugin-agent")]
                ("login_socket".to_owned(), JsonSchema::string("Private host login path socket.")),
                #[cfg(feature = "plugin-agent")]
                ("login_worker".to_owned(), JsonSchema::boolean("Serve an account login session.")),
                #[cfg(feature = "plugin-agent")]
                ("login_proxy".to_owned(), JsonSchema::boolean("Pass one terminal to its login session.")),
                (
                    "detach".to_owned(),
                    JsonSchema::boolean("Detach from the parent process."),
                ),
                ("retain_output".to_owned(), JsonSchema::boolean("Keep automation output until the bounded exit deadline.")),
                ("command_stdin".to_owned(), JsonSchema::boolean("Read literal program arguments from a private pipe.")),
                ("readiness".to_owned(), JsonSchema::boolean("Private fixed-command readiness probe; never reads login startup.")),
                ("exit_retention_ms".to_owned(), JsonSchema::integer("Exited session retention in milliseconds, clamped to the production ceiling.")),
                (
                    "ring_capacity".to_owned(),
                    JsonSchema::integer("Replay ring capacity; defaults to 8388608 bytes."),
                ),
            ],
            ["session".to_owned(), "uid".to_owned()],
        ),
        JsonSchema::command_result(),
        ActionContract::new(
            ActionTarget::Session,
            ActionEffect::Write,
            "cli.internal.session-shim",
            DryRun::Unsupported,
        ),
    )
    .hidden()
    .with_cli_handler(CliHandler::SessionShim)
}

#[cfg(test)]
mod internal_selection_tests {
    //! Private process launches must not allocate unrelated operator metadata.
    #[test]
    fn hidden_shim_materializes_only_its_declared_action() {
        let registry = super::registry_for(Some("__shim")).expect("shim registry");
        let plugins: Vec<_> = registry.plugins().collect();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].actions.len(), 1);
        assert_eq!(plugins[0].actions[0].command, ["__shim"]);
    }
}

fn skill_input_schema() -> JsonSchema {
    JsonSchema::object(
        [
            (
                "command".to_owned(),
                JsonSchema::array(
                    JsonSchema::string("Command path part."),
                    "The command to print, such as `status` or `mesh peers`.",
                ),
            ),
            (
                "write".to_owned(),
                JsonSchema::string("Folder to save one skill file per command in."),
            ),
        ],
        std::iter::empty(),
    )
}

fn skill_output_data_schema() -> JsonSchema {
    let skill_command_row = JsonSchema::object(
        [
            (
                "command".to_owned(),
                JsonSchema::string("Registered command path."),
            ),
            (
                "description".to_owned(),
                JsonSchema::string("Short command description."),
            ),
        ],
        ["command".to_owned(), "description".to_owned()],
    );
    JsonSchema::object(
        [
            (
                "commands".to_owned(),
                JsonSchema::array(skill_command_row, "Visible registered commands."),
            ),
            (
                "skill".to_owned(),
                JsonSchema::string("Generated Markdown skill, empty when not requested."),
            ),
            (
                "files".to_owned(),
                JsonSchema::array(
                    JsonSchema::string("Written skill filename."),
                    "Written skill files.",
                ),
            ),
        ],
        [
            "commands".to_owned(),
            "skill".to_owned(),
            "files".to_owned(),
        ],
    )
}

#[cfg(test)]
mod tests {
    //! Verifies every enabled public action has complete, collision-free metadata.

    use super::registry;
    use infraternal_plugin_api::CliHandler;

    #[test]
    fn every_registered_action_has_description_and_step_by_step_guidance() {
        let registry = registry().expect("built-in plugin metadata is valid");
        let actions = registry.actions().collect::<Vec<_>>();
        assert!(!actions.is_empty());
        for registered in actions {
            assert_ne!(registered.action.description.trim(), "");
            assert_ne!(registered.action.when_to_use.trim(), "");
            assert_ne!(registered.action.instructions, [] as [String; 0]);
            assert!(
                registered
                    .action
                    .instructions
                    .iter()
                    .all(|instruction| !instruction.trim().is_empty())
            );
        }
    }

    #[test]
    fn sign_in_output_schema_covers_pending_and_completed_data() {
        let schema = &super::sign_in_action().output_schema;
        let data = schema
            .properties
            .get("data")
            .expect("command result data schema");

        for field in [
            "server",
            "device",
            "scopes",
            "stored",
            "user_code",
            "verification_url",
            "expires_in_seconds",
        ] {
            assert!(data.properties.contains_key(field), "missing {field}");
            assert!(
                !data.required.iter().any(|required| required == field),
                "{field} is state-dependent and must remain optional"
            );
        }
    }

    #[test]
    fn hidden_session_shim_is_registered_to_its_runtime_handler() {
        let registry = registry().expect("built-in plugin metadata is valid");
        let action = registry
            .find(&["__shim"])
            .expect("internal shim action is registered");
        assert!(!action.action.visible);
        assert_eq!(action.action.cli_handler, CliHandler::SessionShim);
    }

    #[cfg(all(feature = "ssh", feature = "remote"))]
    #[test]
    fn hidden_ssh_session_bridge_is_registered_to_its_runtime_handler() {
        let registry = registry().expect("built-in plugin metadata is valid");
        let action = registry
            .find(&["__ssh-session"])
            .expect("internal SSH session action is registered");
        assert!(!action.action.visible);
        assert_eq!(action.action.cli_handler, CliHandler::SshSession);
        assert_eq!(action.action.input_schema.required, ["state".to_owned()]);
        assert!(
            action
                .action
                .input_schema
                .properties
                .contains_key("session")
        );
    }

    #[cfg(feature = "plugin-mesh")]
    #[test]
    fn registered_actions_include_plugin_permission_contract_fields() {
        let registry = registry().expect("built-in plugin metadata is valid");
        let action = registry
            .find(&["mesh", "up"])
            .expect("mesh action is registered");
        let value = serde_json::to_value(action.action).expect("serialize action definition");

        for field in ["target", "effect", "permission", "dry_run"] {
            assert!(
                value.get(field).is_some(),
                "registered action is missing the `{field}` field required by the plugin contract: {value}"
            );
        }
    }

    #[cfg(not(feature = "plugin-mesh"))]
    #[test]
    fn compiled_out_mesh_has_no_registered_commands() {
        let registry = registry().expect("built-in plugin metadata is valid");
        assert!(registry.find(&["mesh", "up"]).is_none());
    }

    #[cfg(feature = "plugin-mesh")]
    #[test]
    fn enabled_mesh_plugin_registers_its_component_commands() {
        let registry = registry().expect("built-in plugin metadata is valid");
        assert!(registry.find(&["mesh", "up"]).is_some());
    }

    #[cfg(all(
        not(feature = "plugin-agent"),
        not(feature = "plugin-backup"),
        not(feature = "plugin-mesh"),
        not(feature = "plugin-proxy"),
        not(feature = "plugin-relay"),
        not(feature = "plugin-server"),
        not(feature = "plugin-ssh")
    ))]
    #[test]
    fn no_default_plugins_register_no_component_commands() {
        let registry = registry().expect("core CLI metadata is valid");
        for command in [
            ["agent", "up"],
            ["backup", "up"],
            ["mesh", "up"],
            ["relay", "up"],
            ["server", "init"],
            ["ssh", "up"],
        ] {
            assert!(
                registry.find(&command).is_none(),
                "{command:?} is compiled out"
            );
        }
    }

    #[cfg(not(feature = "plugin-server"))]
    #[test]
    fn server_only_dependencies_are_removed_with_server_plugin() {
        let manifest = include_str!("../../Cargo.toml");
        let dependencies = manifest
            .split("[dependencies]")
            .nth(1)
            .expect("normal dependency section")
            .split("[features]")
            .next()
            .expect("feature section boundary");
        let server_feature = manifest
            .lines()
            .find(|line| line.starts_with("plugin-server ="))
            .expect("server feature declaration");

        for dependency in ["sqlx", "tokio"] {
            let declaration = dependencies
                .lines()
                .map(str::trim)
                .find(|line| line.starts_with(&format!("{dependency}.")));
            let Some(declaration) = declaration else {
                continue;
            };
            assert!(
                declaration.contains("optional = true")
                    && server_feature.contains(&format!("dep:{dependency}")),
                "{dependency} remains available without the server plugin: {declaration}"
            );
        }
    }

    #[cfg(feature = "plugin-agent")]
    #[test]
    fn enabled_agent_registers_host_login_shim_flags() {
        let registry = registry().expect("enabled agent metadata");
        let action = registry.find(&["__shim"]).expect("shim metadata");
        for flag in [
            "controller_uid",
            "login_worker_proc",
            "login_worker_pid",
            "login_worker_parent",
            "login_cgroup",
            "login_ready_fd",
            "login_master_fd",
            "login_lease_fd",
            "login_socket",
            "login_worker",
            "login_proxy",
        ] {
            assert!(
                action.action.input_schema.properties.contains_key(flag),
                "enabled host login flag missing: {flag}"
            );
        }
    }

    #[cfg(not(feature = "plugin-agent"))]
    #[test]
    fn compiled_out_agent_removes_host_login_shim_flags() {
        let registry = registry().expect("core metadata");
        let action = registry
            .find(&["__shim"])
            .expect("legacy shim remains available");
        for flag in [
            "controller_uid",
            "login_worker_proc",
            "login_worker_pid",
            "login_worker_parent",
            "login_cgroup",
            "login_ready_fd",
            "login_master_fd",
            "login_lease_fd",
            "login_socket",
            "login_worker",
            "login_proxy",
        ] {
            assert!(
                !action.action.input_schema.properties.contains_key(flag),
                "compiled-out host login flag remains registered: {flag}"
            );
        }
        assert!(
            action
                .action
                .input_schema
                .properties
                .contains_key("session")
        );
        assert!(action.action.input_schema.properties.contains_key("uid"));
    }

    #[cfg(not(feature = "plugin-agent"))]
    #[test]
    fn agent_session_integration_target_is_gated_by_agent_plugin() {
        let integration_test = include_str!("../../tests/agent_sessions.rs");
        assert!(
            integration_test
                .lines()
                .any(|line| line.trim() == "#![cfg(feature = \"plugin-agent\")]")
        );
    }
}

#[cfg(all(
    test,
    feature = "placeholders",
    feature = "plugin-mesh",
    feature = "plugin-host-facts"
))]
mod hosted_tests {
    //! Ensures every production descriptor is discoverable with its original authority.
    use super::registry;
    use infraternal_plugin_api::{ActionEffect, ActionTarget, CliDryRun as DryRun, Permission};

    #[test]
    fn production_descriptors_share_cli_registry_and_skills() {
        let registry = registry().expect("valid combined registry");
        for descriptor in [
            &infraternal_plugin_mesh::descriptor::DESCRIPTOR,
            &infraternal_plugin_host_facts::DESCRIPTOR,
        ] {
            for source in descriptor.actions {
                let path = source.id.split('.').collect::<Vec<_>>();
                let action = registry
                    .find(&path)
                    .expect("hosted action is registered")
                    .action;
                assert_eq!(action.hosted, Some(*source));
                let contract = serde_json::to_value(&action.contract).expect("authority contract");
                match source.permission {
                    Permission::One(permission) => assert_eq!(contract["permission"], permission),
                    Permission::Any(permissions) => assert_eq!(
                        contract["permission"]["any"],
                        serde_json::to_value(permissions).expect("permission alternatives")
                    ),
                }
                assert_eq!(action.description, source.summary);
                let skill = crate::cli::skills::render_action(action).expect("generated skill");
                assert!(skill.contains(source.id));
                assert!(
                    skill.contains(&serde_json::to_string(&source.input).expect("input reference"))
                );
                assert!(
                    skill.contains(
                        &serde_json::to_string(&source.output).expect("output reference")
                    )
                );
                if action.contract.effect == ActionEffect::Destructive {
                    assert_eq!(action.contract.dry_run, DryRun::Required);
                    assert!(action.safety.destructive);
                }
            }
        }
        assert_eq!(
            registry
                .find(&["host", "facts", "read"])
                .expect("facts")
                .action
                .contract
                .target,
            ActionTarget::Host
        );
    }
}

#[cfg(all(test, feature = "plugin-agent", feature = "plugin-mesh"))]
mod factory_tests {
    //! Keeps daemon startup bounded without changing discovery or action handlers.
    use super::registry_for;
    use infraternal_plugin_api::CliHandler;

    #[test]
    fn plugin_command_materializes_only_its_owner_and_discovery_remains_complete() {
        let registry = registry_for(Some(infraternal_agent::cli::ID)).expect("agent registry");
        assert_eq!(
            registry
                .find(&["agent"])
                .expect("agent action")
                .action
                .cli_handler,
            CliHandler::EmbeddedAgent
        );
        assert!(registry.find(&["mesh", "list"]).is_none());
        let internal = registry_for(Some("__shim")).expect("internal registry");
        assert!(internal.find(&["__shim"]).is_some());
        assert!(internal.find(&["mesh", "list"]).is_none());
        for root in [None, Some("status"), Some("skill")] {
            let registry = registry_for(root).expect("discovery registry");
            assert_eq!(
                registry.find(&["mesh", "list"]).is_some(),
                cfg!(feature = "placeholders")
            );
        }
    }
}

/// The private prompt responder stays hidden and executes before any credential output is formatted.
#[cfg(feature = "ssh")]
fn ssh_askpass_action() -> ActionDefinition {
    ActionDefinition::new(
        ["__ssh-askpass"],
        "Answer a private SSH prompt.",
        "Used only by the owned OpenSSH bootstrap subprocess.",
        ["Write the requested credential to the inherited private pipe."],
        JsonSchema::empty_object(),
        JsonSchema::command_result(),
        ActionContract::new(
            ActionTarget::Host,
            ActionEffect::Read,
            "ssh.internal.askpass",
            DryRun::Unsupported,
        ),
    )
    .hidden()
    .with_cli_handler(CliHandler::SshAskpass)
}

/// Runs the private session bridge only after the generated CLI validates its state path.
#[cfg(all(feature = "ssh", feature = "remote"))]
fn ssh_session_action() -> ActionDefinition {
    ActionDefinition::new(
        ["__ssh-session"],
        "Bridge an authenticated SSH session.",
        "Used only after SSH authentication to start the shell through its owned session shim.",
        [
            "Provide the private session state directory.",
            "Use only from the authenticated SSH bootstrap process.",
            "Supply the published session identifier only when reconnecting its existing shim.",
        ],
        JsonSchema::object(
            [
                (
                    "session".to_owned(),
                    JsonSchema::string("Existing published session identifier to reconnect."),
                ),
                (
                    "state".to_owned(),
                    JsonSchema::string("Private session state directory."),
                ),
            ],
            ["state".to_owned()],
        ),
        JsonSchema::command_result(),
        ActionContract::new(
            ActionTarget::Session,
            ActionEffect::Write,
            "cli.internal.ssh-session",
            DryRun::Unsupported,
        ),
    )
    .hidden()
    .with_cli_handler(CliHandler::SshSession)
}

#[cfg(all(test, feature = "release"))]
mod release_tests {
    //! Preserves release operator paths and hosted discovery through lazy server metadata.
    #[cfg(feature = "placeholders")]
    use super::registry;
    use super::registry_for;
    use infraternal_plugin_api::CliHandler;

    #[test]
    fn server_commands_bind_release_without_losing_hosted_skills() {
        let server = registry_for(Some("server")).expect("server registry");
        for path in [
            vec!["server", "channel"],
            vec!["server", "release", "latest"],
        ] {
            let action = server.find(&path).expect("release operator command").action;
            assert_eq!(action.cli_handler, CliHandler::ServerPlugin);
            assert!(action.hosted.is_some());
            let skill = crate::cli::skills::render_action(action).expect("operator skill");
            assert!(skill.contains("signature") || skill.contains("unreviewed"));
        }
        #[cfg(feature = "placeholders")]
        let full = registry().expect("full registry");
        #[cfg(feature = "placeholders")]
        for source in infraternal_plugin_release::descriptor::DESCRIPTOR.actions {
            let path = source.id.split('.').collect::<Vec<_>>();
            assert_eq!(
                full.find(&path)
                    .expect("hosted release action")
                    .action
                    .hosted,
                Some(*source)
            );
        }
        let tree = crate::cli::command_tree::build(&server);
        let matches = tree
            .try_get_matches_from([
                "infraternal",
                "server",
                "--data",
                "private-state",
                "channel",
                "edge",
                "--yes",
            ])
            .expect("existing syntax");
        let selected = crate::cli::command_tree::selected(&matches);
        assert_eq!(
            selected
                .matches
                .get_one::<String>("channel")
                .map(String::as_str),
            Some("edge")
        );
        assert_eq!(
            selected
                .matches
                .get_one::<String>("data")
                .map(String::as_str),
            Some("private-state")
        );
        assert!(selected.matches.get_flag("yes"));
    }
}

#[cfg(test)]
mod key_memory_registry_tests {
    //! Keeps the shipping diagnostic hidden and removable with the remote capability.
    use super::*;

    #[test]
    fn key_memory_diagnostic_follows_remote_feature() {
        let registry = registry_for(Some("__key-memory-check")).unwrap();
        let registered = registry.find(&["__key-memory-check"]);
        #[cfg(feature = "remote")]
        {
            let action = registered.unwrap().action;
            assert!(!action.visible);
            assert_eq!(action.cli_handler, CliHandler::KeyMemoryCheck);
        }
        #[cfg(not(feature = "remote"))]
        assert!(registered.is_none());
    }
}

#[cfg(all(test, not(feature = "placeholders")))]
mod default_build_tests {
    //! A default build carries no declaration of a component that is not built yet (D243).
    use super::registry;

    #[test]
    fn default_build_registers_no_unbuilt_command() {
        let registry = registry().expect("registry");
        assert!(registry.actions().all(|a| a.action.availability
            != infraternal_plugin_api::ActionAvailability::NotAvailableYet),);
        let commands: [&[&str]; 5] = [
            &["up"],
            &["relay", "up"],
            &["mesh", "list"],
            &["publish"],
            &["host", "facts", "read"],
        ];
        for command in commands {
            assert!(registry.find(command).is_none(), "{command:?}");
        }
    }
}
