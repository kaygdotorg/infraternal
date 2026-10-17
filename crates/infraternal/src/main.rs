//! Defines the process entry point and dispatches metadata-registered actions.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

mod cli;
#[cfg(all(feature = "plugin-agent", target_os = "linux"))]
mod component_cli;
#[cfg(feature = "plugin-agent")]
mod embedded_cli;
#[cfg(feature = "remote")]
mod host_remove;
#[cfg(feature = "release")]
mod release_cli;

#[cfg(any(feature = "remote", all(feature = "plugin-agent", target_os = "linux")))]
mod output;
#[cfg(feature = "remote")]
mod remote;
#[cfg(feature = "plugin-server")]
mod remote_server;
#[cfg(feature = "remote")]
mod remote_service;
#[cfg(feature = "remote")]
mod restart;
#[cfg(feature = "remote")]
mod restart_binary;
#[cfg(feature = "remote")]
mod restart_image;
#[cfg(feature = "ssh")]
mod ssh_askpass;

#[cfg(feature = "plugin-server")]
mod install;

use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

#[cfg(feature = "plugin-server")]
use std::net::SocketAddr;

use clap::ArgMatches;
use cli::output::{CommandResult, CommandState, RenderOptions, render_json, render_pretty};
use infraternal_plugin_api::{
    ActionAvailability, ActionDefinition, ActionRegistry, CliHandler, JsonSchema, JsonSchemaType,
};
use serde::Serialize;
use serde_json::json;

/// Server listener and application settings read from a registered action's input schema.
#[cfg(feature = "plugin-server")]
#[derive(Debug)]
struct ServerArgs {
    remote: remote_server::Options,
    listen: SocketAddr,
    data: PathBuf,
    public_origin: Option<String>,
    web_root: Option<PathBuf>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    behind_proxy: bool,
    trusted_proxies: Vec<infraternal_server::ProxyNetwork>,
}

/// Options controlling a user or system service installation.
#[cfg(feature = "plugin-server")]
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
struct InstallArgs {
    system: bool,
    user: bool,
    dry_run: bool,
    force: bool,
    name: String,
}

fn main() -> ExitCode {
    run_invocation()
}

/// Re-enter the same action dispatch if both replacement exec attempts are refused.
fn run_invocation() -> ExitCode {
    if harden_startup().is_err() {
        return ExitCode::FAILURE;
    }
    #[cfg(target_os = "linux")]
    if nix::sys::prctl::set_name(c"infraternal").is_err() {
        return ExitCode::FAILURE;
    }
    #[cfg(feature = "remote")]
    if let Some(result) =
        infraternal_plugin_remote::runtime_lock::command(&mut std::env::args_os().skip(1))
    {
        return ExitCode::from(result);
    }
    #[cfg(feature = "remote")]
    if let Some(result) = remote::uninstall_if_requested() {
        return result;
    }
    #[cfg(feature = "plugin-agent")]
    if let Some(result) = embedded_cli::run_if_requested() {
        return result;
    }
    // Global JSON is a flag; plugin ownership selects lazy metadata, while
    // root help and core discovery need all compiled definitions. Parsing and
    // execution still come solely from the resulting action registry.
    let requested_root = std::env::args().skip(1).find(|arg| arg != "--json");
    let requested_root = requested_root
        .as_deref()
        .filter(|arg| !arg.starts_with('-'));
    let registry = match cli::actions::registry_for(requested_root) {
        Ok(registry) => registry,
        Err(error) => {
            print_result(
                &CommandResult::new(
                    "cli",
                    CommandState::Failed,
                    "The command registry could not be loaded.",
                    json!({}),
                )
                .with_details(error.to_string()),
                false,
                true,
            );
            return ExitCode::FAILURE;
        }
    };
    let requested_json = std::env::args_os().any(|argument| argument == "--json");
    let matches = match cli::command_tree::build(&registry).try_get_matches() {
        Ok(matches) => matches,
        Err(error)
            if requested_json
                && !matches!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                ) =>
        {
            // Invalid private transport coordinates must not leak through Clap diagnostics.
            #[cfg(feature = "remote")]
            return output::refuse(
                true,
                "cli",
                "Invalid command arguments",
                "Read the command help and retry.",
                2,
            );
            #[cfg(not(feature = "remote"))]
            {
                print_result(
                    &CommandResult::new(
                        "cli",
                        CommandState::Failed,
                        "Invalid command arguments.",
                        json!({}),
                    )
                    .with_next_step("Read the command help and retry."),
                    true,
                    false,
                );
                return ExitCode::from(2);
            }
        }
        Err(error) => error.exit(),
    };
    let json_output = matches.get_flag("json");
    let selected = cli::command_tree::selected(&matches);
    dispatch_selected_action(&registry, &selected, json_output)
}

fn dispatch_selected_action(
    registry: &ActionRegistry,
    selected: &cli::command_tree::SelectedCommand<'_>,
    json_output: bool,
) -> ExitCode {
    let path = selected.path.iter().map(String::as_str).collect::<Vec<_>>();
    let Some(registered) = registry.find(&path) else {
        return missing_action(json_output);
    };
    dispatch_action(registry, registered.action, selected.matches, json_output)
}

fn dispatch_action(
    registry: &ActionRegistry,
    action: &ActionDefinition,
    matches: &ArgMatches,
    json_output: bool,
) -> ExitCode {
    match action.cli_handler {
        CliHandler::NodeComponent => {
            #[cfg(all(feature = "plugin-agent", target_os = "linux"))]
            {
                component_cli::run_action(action, matches, json_output)
            }
            #[cfg(not(all(feature = "plugin-agent", target_os = "linux")))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::Unavailable => run_unavailable(action, json_output),
        CliHandler::Status => run_status(registry, json_output),
        CliHandler::Skill => run_skill(registry, matches, json_output),
        CliHandler::ServerPlugin => {
            #[cfg(feature = "release")]
            {
                release_cli::run(action, matches, json_output)
            }
            #[cfg(not(feature = "release"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::ServerRun => {
            #[cfg(feature = "plugin-server")]
            {
                run_server(matches, json_output)
            }
            #[cfg(not(feature = "plugin-server"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::ServerInit => {
            #[cfg(feature = "plugin-server")]
            {
                run_server_init(matches, json_output)
            }
            #[cfg(not(feature = "plugin-server"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::ServerInstallCompatibility => {
            #[cfg(feature = "plugin-server")]
            {
                run_server_install_compat(matches, json_output)
            }
            #[cfg(not(feature = "plugin-server"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::ServerSetupToken => {
            #[cfg(feature = "plugin-server")]
            {
                run_setup_token(matches, json_output)
            }
            #[cfg(not(feature = "plugin-server"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::EmbeddedAgent => {
            #[cfg(feature = "plugin-agent")]
            {
                run_embedded_agent(matches, json_output)
            }
            #[cfg(not(feature = "plugin-agent"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::SessionShim => run_shim_command(matches),
        CliHandler::KeyMemoryCheck => {
            #[cfg(feature = "remote")]
            {
                run_key_memory_check(json_output)
            }
            #[cfg(not(feature = "remote"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::RemoteAgent
        | CliHandler::ServerRestart
        | CliHandler::RemoveHost
        | CliHandler::SshAskpass => run_operator_action(action, matches, json_output),
    }
}

fn missing_action(json_output: bool) -> ExitCode {
    print_result(
        &CommandResult::new(
            "cli",
            CommandState::Failed,
            "The requested command is not registered in this build.",
            json!({}),
        )
        .with_next_step("Run `infraternal --help` to see the enabled commands."),
        json_output,
        true,
    );
    ExitCode::from(2)
}

/// The shipping diagnostic refuses partial protection independently of server development policy.
#[cfg(feature = "remote")]
fn run_key_memory_check(json_output: bool) -> ExitCode {
    // D244 requires fully protected pages even for a non-root gate runner.
    if infraternal_shim::openssl_secure::initialize() == 1 {
        output::report(
            json_output,
            "internal.key-memory-check",
            "ready",
            "Key memory initialization=1; locked pages and dump exclusion enabled",
            "Run this check under an 8 MiB memlock limit.",
        );
        ExitCode::SUCCESS
    } else {
        output::refuse(
            json_output,
            "internal.key-memory-check",
            "Key memory refused",
            "Check the compiled provider and memlock limit.",
            1,
        )
    }
}

fn run_status(registry: &ActionRegistry, json_output: bool) -> ExitCode {
    let server_active = systemd_server_state();
    let role = match server_active {
        Some(true) => "server",
        Some(false) => "node",
        None => "unknown",
    };
    let mut components = Vec::new();
    for plugin in registry.plugins().filter(|plugin| plugin.id != "cli") {
        let state = match (plugin.id.as_str(), server_active) {
            ("server", Some(true)) => "Running",
            ("server", Some(false)) => "Stopped",
            ("server", None) => "Unknown",
            _ => "Not available yet",
        };
        components.push(json!({"name": plugin.id, "state": state}));
    }

    let (state, message, next_step) = match server_active {
        Some(true) => (
            CommandState::Running,
            "An infraternal server service is running on this node.",
            "No action is needed while the server service is running.",
        ),
        Some(false) => (
            CommandState::Stopped,
            "No infraternal server service is running on this node.",
            "Run `infraternal server init` to create a server on this node.",
        ),
        None => (
            CommandState::Unknown,
            "The infraternal server service state could not be read.",
            "Check the user and system service managers for the infraternal server unit.",
        ),
    };
    let result = CommandResult::new(
        "status",
        state,
        message,
        json!({"role": role, "components": components}),
    )
    .with_next_step(next_step);
    print_result(&result, json_output, false);
    ExitCode::SUCCESS
}

fn run_skill(registry: &ActionRegistry, matches: &ArgMatches, json_output: bool) -> ExitCode {
    // Preserve hosted dotted action IDs alongside generated command paths.
    let command = matches
        .get_many::<String>("command")
        .into_iter()
        .flatten()
        .flat_map(|part| part.split('.'))
        .collect::<Vec<_>>();
    let write_directory = matches.get_one::<String>("write");
    if write_directory.is_some() && !command.is_empty() {
        return report_failure(
            "skill",
            "Choose a command path or a destination directory.",
            "--write cannot be combined with a command path".to_owned(),
            json_output,
        );
    }

    if let Some(directory) = write_directory {
        return match cli::skills::write_all(registry, Path::new(directory)) {
            Ok(files) => {
                let result = CommandResult::new(
                    "skill",
                    CommandState::Ready,
                    format!("Wrote {} command skill files.", files.len()),
                    json!({"commands": [], "skill": "", "files": files}),
                )
                .with_next_step("Open a generated Markdown file to review its command contract.");
                print_result(&result, json_output, false);
                ExitCode::SUCCESS
            }
            Err(error) => report_failure(
                "skill",
                "The command skill files could not be written.",
                error.to_string(),
                json_output,
            ),
        };
    }

    if command.is_empty() {
        let commands = cli::skills::commands(registry);
        let result = CommandResult::new(
            "skill",
            CommandState::Ready,
            format!("{} commands are enabled in this build.", commands.len()),
            json!({"commands": commands, "skill": "", "files": []}),
        )
        .with_next_step("Run `infraternal skill <command>` to print one command skill.");
        print_result(&result, json_output, false);
        return ExitCode::SUCCESS;
    }

    if let Some(result) = run_skill_group(registry, &command, json_output) {
        return result;
    }
    let path = command.join(" ");
    let Some(registered) = registry.find(&command) else {
        return report_failure(
            "skill",
            "The requested command has no generated skill in this build.",
            format!("No visible action is registered for {path:?}."),
            json_output,
        );
    };
    if !registered.action.visible {
        return report_failure(
            "skill",
            "The requested command has no generated skill in this build.",
            "internal commands are not listed as skills".to_owned(),
            json_output,
        );
    }
    let markdown = match cli::skills::render_action(registered.action) {
        Ok(markdown) => markdown,
        Err(error) => {
            return report_failure(
                "skill",
                "The command skill could not be rendered.",
                error.to_string(),
                json_output,
            );
        }
    };
    if json_output {
        let result = CommandResult::new(
            format!("skill {}", command.join(" ")),
            CommandState::Ready,
            format!("Generated the skill for `infraternal {path}`."),
            json!({"commands": [], "skill": markdown, "files": []}),
        );
        print_result(&result, true, false);
    } else if let Err(error) = io::stdout().write_all(markdown.as_bytes()) {
        return report_failure(
            "skill",
            "The generated command skill could not be printed.",
            error.to_string(),
            false,
        );
    }
    ExitCode::SUCCESS
}

// Component groups list enabled actions from the same registry as help.
fn run_skill_group(
    registry: &ActionRegistry,
    command: &[&str],
    json_output: bool,
) -> Option<ExitCode> {
    if registry.find(command).is_some() {
        return None;
    }
    let commands = cli::skills::commands(registry)
        .into_iter()
        .filter(|entry| {
            entry
                .command
                .split_whitespace()
                .collect::<Vec<_>>()
                .starts_with(command)
        })
        .collect::<Vec<_>>();
    if commands.is_empty() {
        return None;
    }
    let result = CommandResult::new(
        format!("skill {}", command.join(" ")),
        CommandState::Ready,
        "Enabled commands in this component.",
        json!({"commands": commands, "skill": "", "files": []}),
    );
    print_result(&result, json_output, false);
    Some(ExitCode::SUCCESS)
}

fn systemd_server_state() -> Option<bool> {
    let scopes: [&[&str]; 2] = [&["--user"], &[]];
    let mut every_manager_responded = true;
    for scope in scopes {
        let output = Command::new("systemctl")
            .args(scope)
            .args([
                "list-units",
                "--type=service",
                "--all",
                "--no-legend",
                "--no-pager",
                "--plain",
                "--full",
            ])
            .env("LC_ALL", "C")
            .env("COLUMNS", "4096")
            .env("SYSTEMD_COLORS", "0")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            every_manager_responded = false;
            continue;
        }
        if server_state_from_units(&String::from_utf8_lossy(&output.stdout)) == Some(true) {
            return Some(true);
        }
    }
    every_manager_responded.then_some(false)
}

fn server_state_from_units(units: &str) -> Option<bool> {
    let mut found = false;
    for line in units.lines() {
        let mut fields = line.split_whitespace();
        let (Some(unit), Some(_load), Some(active), Some(_sub)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !unit.ends_with(".service") {
            continue;
        }
        let description = fields.collect::<Vec<_>>().join(" ");
        if description.starts_with("infraternal server (") && description.ends_with(')') {
            found = true;
            if active == "active" {
                return Some(true);
            }
        }
    }
    found.then_some(false)
}

#[cfg(test)]
mod status_tests {
    //! Verifies status recognizes server services independently of their chosen unit name.

    use super::server_state_from_units;

    #[test]
    fn custom_named_server_service_is_reported_as_running() {
        let units = "infraternal-edge.service loaded active running infraternal server (infraternal-edge)\n";
        assert_eq!(server_state_from_units(units), Some(true));
    }

    #[test]
    fn custom_named_stopped_server_service_is_reported_as_stopped() {
        let units =
            "infraternal-edge.service loaded inactive dead infraternal server (infraternal-edge)\n";
        assert_eq!(server_state_from_units(units), Some(false));
    }

    #[test]
    fn unrelated_services_do_not_appear_as_infraternal_servers() {
        let units = "infraternal-edge.service loaded active running infraternal mesh component\n";
        assert_eq!(server_state_from_units(units), None);
    }
}

fn run_unavailable(action: &ActionDefinition, json_output: bool) -> ExitCode {
    let command = action.command.join(" ");
    let data = empty_action_data(action);
    let (state, message) = if action.availability == ActionAvailability::NotAvailableYet {
        (
            CommandState::Unavailable,
            format!("The {command} command is not available yet."),
        )
    } else {
        (
            CommandState::Failed,
            format!("The {command} command has no handler in this build."),
        )
    };
    let next_step = if action.hosted.is_some() {
        "Use the server UI with an authenticated session to run this plugin action."
    } else {
        "Run `infraternal status` to review this node's current components."
    };
    print_result(
        &CommandResult::new(command, state, message, data).with_next_step(next_step),
        json_output,
        state == CommandState::Failed,
    );
    if state == CommandState::Unavailable {
        ExitCode::from(2)
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(feature = "plugin-server")]
fn run_server(matches: &ArgMatches, json_output: bool) -> ExitCode {
    if !server_configuration_was_supplied(matches) {
        print_result(
            &CommandResult::new(
                "server",
                CommandState::Unavailable,
                "The server is not configured yet.",
                json!({"listen": "127.0.0.1:7443", "public_origin": "https://localhost:7443"}),
            )
            .with_next_step("Run `infraternal server init` to configure a server."),
            json_output,
            false,
        );
        return ExitCode::from(2);
    }
    let args = match server_args(matches) {
        Ok(args) => args,
        Err(error) => {
            return report_failure(
                "server",
                "The server configuration is invalid.",
                error,
                json_output,
            );
        }
    };
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        return report_failure(
            "server",
            "The server could not start its async runtime.",
            "async runtime initialization failed".to_owned(),
            json_output,
        );
    };
    run_server_foreground(args, runtime, json_output)
}

#[cfg(feature = "plugin-server")]
fn server_configuration_was_supplied(matches: &ArgMatches) -> bool {
    [
        "listen",
        "data",
        "public_origin",
        "web_root",
        "tls_cert",
        "tls_key",
        "remote_listen",
        "remote_ca_dir",
    ]
    .iter()
    .any(|name| matches.get_one::<String>(name).is_some())
        || matches.get_flag("behind_proxy")
        || matches.get_many::<String>("trusted_proxy").is_some()
}

#[cfg(feature = "plugin-server")]
fn server_args(matches: &ArgMatches) -> Result<ServerArgs, String> {
    let listen = matches.get_one::<String>("listen").map_or_else(
        || Ok(SocketAddr::from(([127, 0, 0, 1], 7443))),
        |value| {
            value
                .parse::<SocketAddr>()
                .map_err(|_| "listener address is invalid".to_owned())
        },
    )?;
    let trusted_proxies = matches
        .get_many::<String>("trusted_proxy")
        .into_iter()
        .flatten()
        .map(|value| {
            value
                .parse::<infraternal_server::ProxyNetwork>()
                .map_err(|_| "trusted proxy address or CIDR is invalid".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let remote_listen = matches
        .try_get_one::<String>("remote_listen")
        .ok()
        .flatten()
        .map(|value| {
            value
                .parse::<SocketAddr>()
                .map_err(|_| "remote listener is invalid".to_owned())
        })
        .transpose()?;
    let remote_ca_dir = matches
        .try_get_one::<String>("remote_ca_dir")
        .ok()
        .flatten()
        .map(PathBuf::from);
    if remote_ca_dir.is_some() && remote_listen.is_none() {
        return Err("--remote-ca-dir requires --remote-listen".to_owned());
    }
    Ok(ServerArgs {
        remote: remote_server::Options {
            remote_listen,
            remote_ca_dir,
        },
        listen,
        data: matches
            .get_one::<String>("data")
            .map_or_else(|| PathBuf::from("./data"), PathBuf::from),
        public_origin: matches.get_one::<String>("public_origin").cloned(),
        web_root: matches.get_one::<String>("web_root").map(PathBuf::from),
        tls_cert: matches.get_one::<String>("tls_cert").map(PathBuf::from),
        tls_key: matches.get_one::<String>("tls_key").map(PathBuf::from),
        behind_proxy: matches.get_flag("behind_proxy"),
        trusted_proxies,
    })
}

#[cfg(feature = "plugin-server")]
fn run_server_init(matches: &ArgMatches, json_output: bool) -> ExitCode {
    let args = match server_args(matches) {
        Ok(args) => args,
        Err(error) => {
            return report_failure(
                "server init",
                "The server configuration is invalid.",
                error,
                json_output,
            );
        }
    };
    let dry_run = matches.get_flag("dry_run");
    let yes = matches.get_flag("yes");
    if let Err(error) = confirm_server_setup(
        yes,
        dry_run,
        args.listen,
        &args.data,
        if matches.get_flag("system") {
            "system"
        } else {
            "user"
        },
    ) {
        return report_failure(
            "server init",
            "Server setup needs confirmation.",
            error,
            json_output,
        );
    }
    let name = matches
        .get_one::<String>("name")
        .cloned()
        .unwrap_or_else(|| "infraternal-server".to_owned());
    if matches.get_flag("system") && matches.get_flag("user") {
        return report_failure(
            "server init",
            "Choose one service scope.",
            "--system conflicts with --user".to_owned(),
            json_output,
        );
    }
    let install_args = InstallArgs {
        system: matches.get_flag("system"),
        user: !matches.get_flag("system"),
        dry_run,
        force: matches.get_flag("force"),
        name: name.clone(),
    };
    install_server("server init", &args, &install_args, json_output)
}

#[cfg(feature = "plugin-server")]
fn confirm_server_setup(
    yes: bool,
    dry_run: bool,
    listen: SocketAddr,
    data_dir: &Path,
    scope: &str,
) -> Result<(), String> {
    if yes || dry_run {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err("pass --yes in non-interactive mode, or use --dry-run first".to_owned());
    }
    print!(
        "Create and start the {scope} server service on {listen} with data in {}? [y/N] ",
        data_dir.display()
    );
    io::stdout()
        .flush()
        .map_err(|_| "the confirmation prompt could not be displayed".to_owned())?;
    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .map_err(|_| "the confirmation could not be read".to_owned())?;
    if response.trim().eq_ignore_ascii_case("y") || response.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err("setup was cancelled; no server service was created".to_owned())
    }
}

#[cfg(feature = "plugin-server")]
fn run_server_install_compat(_matches: &ArgMatches, json_output: bool) -> ExitCode {
    let result = CommandResult::new(
        "server install",
        CommandState::Unavailable,
        "The legacy server install path is disabled and did not create a service.",
        json!({"service": "", "enabled": false, "dry_run": false}),
    )
    .with_next_step(
        "Run `infraternal server init --dry-run` to review setup, then use `infraternal server init --yes` to create the service.",
    );
    print_result(&result, json_output, false);
    ExitCode::from(2)
}

#[cfg(feature = "plugin-server")]
fn install_server(
    command: &str,
    args: &ServerArgs,
    install_args: &InstallArgs,
    json_output: bool,
) -> ExitCode {
    match install::install(args, install_args) {
        Ok(plan) => {
            let mut data = json!({
                "service": format!("{}.service", install_args.name),
                "enabled": !install_args.dry_run,
                "dry_run": install_args.dry_run,
            });
            if install_args.dry_run {
                data["plan"] = json!(plan);
            }
            let result = CommandResult::new(
                command,
                CommandState::Ready,
                if install_args.dry_run {
                    "The server installation plan is ready."
                } else {
                    "The server service was installed and enabled."
                },
                data,
            )
            .with_next_step(if install_args.dry_run {
                "Review the plan, then run `infraternal server init --yes` to apply it."
            } else {
                "Run `infraternal status` to review the server service."
            });
            print_result(&result, json_output, false);
            ExitCode::SUCCESS
        }
        Err(error) => report_failure(
            command,
            "The server service could not be installed.",
            error.to_string(),
            json_output,
        ),
    }
}

#[cfg(feature = "plugin-server")]
#[derive(Serialize)]
/// Keeps the deployed private setup reader alongside the versioned CLI envelope.
struct SetupTokenOutput<'a> {
    #[serde(flatten)]
    result: &'a CommandResult<serde_json::Value>,
    token: &'a str,
}

#[cfg(feature = "plugin-server")]
fn run_setup_token(matches: &ArgMatches, json_output: bool) -> ExitCode {
    let data_dir = matches
        .get_one::<String>("data")
        .map_or_else(|| PathBuf::from("./data"), PathBuf::from);
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        return report_failure(
            "server setup-token",
            "The setup capability could not be read.",
            "async runtime initialization failed".to_owned(),
            json_output,
        );
    };
    match runtime.block_on(read_setup_token(&data_dir)) {
        Ok(token) => {
            let result = CommandResult::new(
                "server setup-token",
                CommandState::Ready,
                "A one-time setup capability is available.",
                json!({"token": &token}),
            );
            if json_output {
                // Both private-pipe readers remain valid; the capability never enters logs or argv.
                write_command_output(
                    render_json(&SetupTokenOutput {
                        result: &result,
                        token: &token,
                    }),
                    false,
                );
            } else {
                print_result(&result, false, false);
            }
            ExitCode::SUCCESS
        }
        Err(error) => report_failure(
            "server setup-token",
            "The setup capability is not available.",
            error.to_owned(),
            json_output,
        ),
    }
}

#[cfg(feature = "plugin-server")]
fn run_server_foreground(
    mut args: ServerArgs,
    runtime: tokio::runtime::Runtime,
    json_output: bool,
) -> ExitCode {
    let options = std::mem::take(&mut args.remote);
    let action_id = options.action_id();
    let remote_requested = options.remote_listen.is_some();
    let config = match server_config(args) {
        Ok(config) => config,
        Err(error) => {
            return report_failure(
                "server",
                "The server configuration is invalid.",
                error,
                json_output,
            );
        }
    };
    let output = json!({
        "listen": config.listen.to_string(),
        "public_origin": config.public_origin,
    });
    infraternal_server::configure_logging(json_output);
    match runtime.block_on(remote_server::serve(config, options)) {
        #[cfg(feature = "remote")]
        Ok(remote_server::Outcome::Restart(replacement)) => {
            // Same-PID exec consumes the runtime after cancelling server tasks.
            restart::replace(runtime, replacement, json_output)
        }
        Ok(remote_server::Outcome::Stopped) => {
            print_result(
                &CommandResult::new(
                    "server",
                    CommandState::Stopped,
                    "The server stopped normally.",
                    output,
                ),
                json_output,
                false,
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            #[cfg(feature = "remote")]
            if remote_requested {
                return output::refuse(
                    json_output,
                    action_id,
                    &error.to_string(),
                    "Check configuration and retained public server trust.",
                    1,
                );
            }
            #[cfg(not(feature = "remote"))]
            let _ = (action_id, remote_requested);
            report_failure(
                "server",
                "The server stopped after an error.",
                error.to_string(),
                json_output,
            )
        }
    }
}

#[cfg(feature = "plugin-agent")]
fn run_embedded_agent(matches: &ArgMatches, json_output: bool) -> ExitCode {
    let Some(fd) = matches
        .get_one::<i64>("fd")
        .and_then(|fd| i32::try_from(*fd).ok())
    else {
        print_result(
            &CommandResult::new(
                "agent",
                CommandState::Unavailable,
                "The infraternal agent needs a server connection to start.",
                json!({}),
            )
            .with_next_step("Use `infraternal agent up` when component setup is available."),
            json_output,
            false,
        );
        return ExitCode::from(2);
    };
    let state = matches.get_one::<String>("state").map(PathBuf::from);
    match infraternal_agent::run_embedded(fd, state) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => report_failure(
            "agent",
            "The infraternal agent could not start.",
            error.to_string(),
            json_output,
        ),
    }
}

fn run_shim_command(matches: &ArgMatches) -> ExitCode {
    let session = matches
        .get_one::<String>("session")
        .map_or("", String::as_str);
    let parsed: Result<(u32, u16, u16, usize), String> = (|| {
        Ok((
            shim_integer(matches, "uid", None)?,
            shim_integer(matches, "cols", Some(80))?,
            shim_integer(matches, "rows", Some(24))?,
            shim_integer(matches, "ring_capacity", Some(8 * 1024 * 1024))?,
        ))
    })();
    let (uid, cols, rows, ring_capacity) = match parsed {
        Ok(values) => values,
        Err(error) => {
            eprintln!("shim startup/session failed: {error}");
            return ExitCode::from(2);
        }
    };
    let state = matches.get_one::<String>("state").map(PathBuf::from);
    let detach = matches.get_flag("detach");
    match run_shim(
        session,
        uid,
        cols,
        rows,
        state,
        detach,
        ring_capacity,
        matches
            .get_one::<i64>("exit_retention_ms")
            .copied()
            .unwrap_or(600_000)
            .try_into()
            .unwrap_or(600_000),
        matches.get_flag("readiness"),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("shim startup/session failed: {error}");
            ExitCode::from(1)
        }
    }
}

/// Parse schema-generated integer inputs into the shim's platform-specific types.
fn shim_integer<T>(matches: &ArgMatches, name: &str, default: Option<T>) -> Result<T, String>
where
    T: TryFrom<i64>,
{
    let Some(value) = matches.get_one::<i64>(name).copied() else {
        return default.ok_or_else(|| format!("--{name} is required"));
    };
    T::try_from(value).map_err(|_| format!("--{name} is outside the supported range"))
}

fn report_failure(command: &str, message: &str, details: String, json_output: bool) -> ExitCode {
    print_result(
        &CommandResult::new(
            command,
            CommandState::Failed,
            message,
            failure_data(command),
        )
        .with_details(details),
        json_output,
        true,
    );
    ExitCode::FAILURE
}

/// Keep failed JSON results typed by the action's declared `data` schema.
fn failure_data(command: &str) -> serde_json::Value {
    let command = command.split_whitespace().collect::<Vec<_>>();
    cli::actions::registry()
        .ok()
        .and_then(|registry| {
            registry
                .find(&command)
                .map(|registered| empty_action_data(registered.action))
        })
        .unwrap_or_else(|| json!({}))
}

/// Build an empty data value matching the registered action's output contract.
fn empty_action_data(action: &ActionDefinition) -> serde_json::Value {
    action
        .output_schema
        .properties
        .get("data")
        .map_or_else(|| json!({}), empty_schema_value)
}

/// Build neutral values recursively, omitting optional fields from objects.
fn empty_schema_value(schema: &JsonSchema) -> serde_json::Value {
    match schema.schema_type {
        JsonSchemaType::String => json!(""),
        JsonSchemaType::Integer | JsonSchemaType::Number => json!(0),
        JsonSchemaType::Boolean => json!(false),
        JsonSchemaType::Array => json!([]),
        JsonSchemaType::Object => {
            let mut object = serde_json::Map::new();
            for field in &schema.required {
                if let Some(field_schema) = schema.properties.get(field) {
                    object.insert(field.clone(), empty_schema_value(field_schema));
                }
            }
            serde_json::Value::Object(object)
        }
    }
}

#[cfg(test)]
mod failure_data_tests {
    //! Keeps JSON error payloads typed to their registered action schemas.

    use super::failure_data;
    use serde_json::json;

    #[test]
    fn skill_errors_keep_the_registered_result_data_shape() {
        assert_eq!(
            failure_data("skill"),
            json!({"commands": [], "skill": "", "files": []})
        );
    }

    #[test]
    fn unavailable_results_keep_registered_data_shapes() {
        assert_eq!(failure_data("up"), json!({"started": []}));
        #[cfg(feature = "plugin-server")]
        assert_eq!(failure_data("server features"), json!({"features": []}));
    }

    #[cfg(feature = "plugin-server")]
    #[test]
    fn server_errors_keep_the_registered_result_data_shapes() {
        assert_eq!(
            failure_data("server"),
            json!({"listen": "", "public_origin": ""})
        );
        assert_eq!(
            failure_data("server init"),
            json!({"service": "", "enabled": false, "dry_run": false})
        );
        assert_eq!(failure_data("server setup-token"), json!({"token": ""}));
    }
}

fn print_result<T: Serialize>(result: &CommandResult<T>, json_output: bool, to_stderr: bool) {
    let to_stderr = to_stderr && !json_output;
    let terminal = if to_stderr {
        io::stderr().is_terminal()
    } else {
        io::stdout().is_terminal()
    };
    let output = if json_output {
        render_json(result)
    } else {
        render_pretty(result, RenderOptions::detect(terminal))
    };
    write_command_output(output, to_stderr);
}

/// Shares formatting-error and destination handling for standard and compatibility output.
fn write_command_output(output: Result<String, serde_json::Error>, to_stderr: bool) {
    let rendered = match output {
        Ok(output) => output,
        Err(error) => {
            eprintln!("Could not format command output.\nTechnical detail: {error}");
            return;
        }
    };
    let write_result = if to_stderr {
        io::stderr().write_all(rendered.as_bytes())
    } else {
        io::stdout().write_all(rendered.as_bytes())
    };
    if let Err(error) = write_result {
        eprintln!("Could not write command output.\nTechnical detail: {error}");
    }
}

#[cfg(all(unix, feature = "plugin-server"))]
async fn read_setup_token(data_dir: &Path) -> Result<String, &'static str> {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };

    let mut socket = UnixStream::connect(data_dir.join("setup-token.sock"))
        .await
        .map_err(|_| "no active first-run token socket")?;
    socket
        .write_all(b"GET\n")
        .await
        .map_err(|_| "local token request failed")?;
    let mut response = Vec::with_capacity(44);
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        socket.take(45).read_to_end(&mut response),
    )
    .await
    .map_err(|_| "local token request timed out")?
    .map_err(|_| "local token response failed")?;
    if response.len() != 44
        || response[43] != b'\n'
        || !response[..43]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("no active first-run token");
    }
    String::from_utf8(response[..43].to_vec()).map_err(|_| "invalid local token response")
}

#[cfg(all(not(unix), feature = "plugin-server"))]
async fn read_setup_token(_data_dir: &Path) -> Result<String, &'static str> {
    Err("local token retrieval requires a Unix socket")
}

#[cfg(feature = "plugin-server")]
fn server_config(args: ServerArgs) -> Result<infraternal_server::ServerConfig, String> {
    let tls = match (args.tls_cert, args.tls_key) {
        (Some(certificate), Some(private_key)) => Some(infraternal_server::TlsFiles {
            certificate,
            private_key,
        }),
        (None, None) => None,
        _ => return Err("both --tls-cert and --tls-key are required".to_owned()),
    };
    let public_origin = args
        .public_origin
        .unwrap_or_else(|| origin_for_listener(args.listen));
    Ok(infraternal_server::ServerConfig {
        listen: args.listen,
        data_dir: args.data,
        public_origin,
        web_root: args.web_root,
        tls,
        behind_proxy: args.behind_proxy,
        trusted_proxies: args.trusted_proxies,
    })
}

#[cfg(feature = "plugin-server")]
fn origin_for_listener(listen: SocketAddr) -> String {
    let host = if listen.ip().is_loopback() {
        "localhost".to_owned()
    } else {
        listen.ip().to_string()
    };
    format!("https://{host}:{}", listen.port())
}

#[cfg(all(test, unix, feature = "plugin-server"))]
mod setup_token_tests {
    //! Verifies the explicit CLI handoff uses the private local request protocol.

    use super::read_setup_token;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };

    #[tokio::test]
    async fn setup_token_command_reads_only_the_expected_socket_response() {
        let data_dir =
            std::env::temp_dir().join(format!("infraternal-token-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data_dir);
        std::fs::create_dir_all(&data_dir).expect("create token test directory");
        let listener =
            UnixListener::bind(data_dir.join("setup-token.sock")).expect("bind token test socket");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept token request");
            let mut request = [0; 4];
            socket
                .read_exact(&mut request)
                .await
                .expect("read token request");
            assert_eq!(&request, b"GET\n");
            socket
                .write_all(format!("{}\n", "A".repeat(43)).as_bytes())
                .await
                .expect("write token response");
        });
        assert_eq!(
            read_setup_token(&data_dir).await.expect("read setup token"),
            "A".repeat(43)
        );
        server.await.expect("token test socket server");
        std::fs::remove_dir_all(data_dir).expect("remove token test directory");
    }
}

/// Validate the session identifier before any fork or filesystem operation.
/// Validate identifiers before forking; clamp exited-screen retention inside the shim.
#[allow(clippy::too_many_arguments)]
fn run_shim(
    session: &str,
    uid: u32,
    cols: u16,
    rows: u16,
    state: Option<std::path::PathBuf>,
    detach: bool,
    ring_capacity: usize,
    exit_retention_ms: u64,
    readiness: bool,
) -> std::io::Result<()> {
    if session.len() != 32 || !session.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "session must be 32 hexadecimal characters",
        ));
    }
    let mut id = [0; 16];
    for (i, value) in id.iter_mut().enumerate() {
        *value =
            u8::from_str_radix(&session[i * 2..i * 2 + 2], 16).map_err(std::io::Error::other)?;
    }
    if detach && !infraternal_shim::detach()? {
        return Ok(());
    }
    infraternal_shim::run_with_retention(
        infraternal_shim::Config {
            session: id,
            uid,
            cols,
            rows,
            state,
            ring_capacity,
            readiness,
        },
        std::time::Duration::from_millis(exit_retention_ms),
    )
}

#[cfg(test)]
mod dispatch_tests {
    //! Ensures internal CLI actions resolve and execute through their registered handler.

    use super::{ExitCode, dispatch_selected_action};
    use crate::cli::{actions, command_tree};

    #[test]
    fn hidden_session_shim_dispatches_from_the_registered_action() {
        let registry = actions::registry().expect("action registry");
        let matches = command_tree::build(&registry)
            .try_get_matches_from([
                "infraternal",
                "__shim",
                "--session",
                "invalid",
                "--uid",
                "1000",
            ])
            .expect("registered session shim input schema");
        let selected = command_tree::selected(&matches);

        assert_eq!(
            dispatch_selected_action(&registry, &selected, false),
            ExitCode::from(1)
        );
    }
}

#[cfg(test)]
#[path = "startup_tests.rs"]
mod startup_tests;

/// First userspace entry protection applies equally to server and child modes.
fn harden_startup() -> Result<(), nix::errno::Errno> {
    nix::sys::prctl::set_dumpable(false)?;
    #[cfg(feature = "remote")]
    if std::env::args_os()
        .skip(1)
        .find(|argument| argument != "--json")
        .is_some_and(|argument| argument == "server")
    {
        crate::restart::queue_reload().map_err(|_| nix::errno::Errno::EIO)?;
    }
    Ok(())
}

/// Startup reads an invitation once; reconnects use only the private local identity.
#[cfg(feature = "remote")]
fn run_remote_agent(
    action: AgentAction,
    fd: Option<i32>,
    state: Option<PathBuf>,
    data: Option<PathBuf>,
    json: bool,
) -> ExitCode {
    let enroll_only = matches!(
        &action,
        AgentAction::Join {
            enroll_only: true,
            ..
        }
    );
    let operation = match &action {
        AgentAction::Join { .. } => infraternal_plugin_remote::JOIN.id,
        AgentAction::Run => infraternal_plugin_remote::RUN.id,
    };
    if fd.is_some() {
        return output::refuse(
            json,
            operation,
            "Incompatible infraternal agent modes",
            "Choose one infraternal agent mode.",
            2,
        );
    }
    let Ok(data) = data.map_or_else(remote::default_data, Ok) else {
        return output::refuse(
            json,
            operation,
            "Infraternal agent data directory unavailable",
            "Set a private identity directory with --data.",
            1,
        );
    };
    output::report(
        json,
        operation,
        "starting",
        "Preparing the enrolled host connection",
        "Keep invitation material on private stdin; retain private identity locally.",
    );
    let result = (|| -> std::io::Result<()> {
        use std::io::Read;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        if let AgentAction::Join { url, .. } = action {
            let mut invitation = Vec::with_capacity(8192);
            std::io::stdin().take(8193).read_to_end(&mut invitation)?;
            runtime.block_on(remote::join(&url, &data, &invitation))?;
            // SSH publishes staged state only after enrollment returns. Running
            // here would hold its transaction until the service was cancelled.
            if enroll_only {
                return Ok(());
            }
            output::report(
                json,
                operation,
                "enrolled",
                "Private host identity retained",
                "Keep this process running to maintain the connection.",
            );
        }
        remote_service::run(runtime, remote::run(&data, state))
    })();
    if result.is_ok() {
        if enroll_only {
            output::report(
                json,
                operation,
                "enrolled",
                "Private host identity retained",
                "Start the service with infraternal agent run using this identity directory.",
            );
        } else {
            output::report(
                json,
                operation,
                "stopped",
                "Remote infraternal agent stopped",
                "Reconnect with the retained enrolled identity when needed.",
            );
        }
        ExitCode::SUCCESS
    } else {
        output::refuse(
            json,
            operation,
            result.as_ref().err().map_or(
                "Remote infraternal agent operation failed",
                remote::public_error,
            ),
            "Check the enrolled identity and existing server trust.",
            1,
        )
    }
}

/// Remote node modes never create a server or accept an invitation through argv.
#[cfg(feature = "remote")]
enum AgentAction {
    Join { url: String, enroll_only: bool },
    Run,
}

/// Adapt schema-parsed operator inputs to the production transport handlers.
fn run_operator_action(action: &ActionDefinition, matches: &ArgMatches, json: bool) -> ExitCode {
    #[cfg(feature = "ssh")]
    if action.cli_handler == CliHandler::SshAskpass {
        return ssh_askpass::run();
    }
    #[cfg(feature = "remote")]
    {
        if action.cli_handler == CliHandler::RemoteAgent {
            let fd = matches
                .try_get_one::<i64>("fd")
                .ok()
                .flatten()
                .and_then(|fd| i32::try_from(*fd).ok());
            let state = matches
                .try_get_one::<String>("state")
                .ok()
                .flatten()
                .map(PathBuf::from);
            let data = matches
                .try_get_one::<String>("data")
                .ok()
                .flatten()
                .map(PathBuf::from);
            let mode = if action.command.last().is_some_and(|part| part == "join") {
                AgentAction::Join {
                    url: matches
                        .get_one::<String>("url")
                        .cloned()
                        .unwrap_or_default(),
                    enroll_only: matches.get_flag("enroll_only"),
                }
            } else {
                AgentAction::Run
            };
            return run_remote_agent(mode, fd, state, data, json);
        }
        if action.cli_handler == CliHandler::ServerRestart {
            let data = matches
                .get_one::<String>("data")
                .map_or_else(|| PathBuf::from("./data"), PathBuf::from);
            let options = restart::Options {
                binary: matches.get_one::<String>("binary").map(PathBuf::from),
            };
            return match tokio::runtime::Runtime::new() {
                Ok(runtime) => restart::run(&runtime, &data, &options, json),
                Err(_) => report_failure(
                    "server restart",
                    "Could not start the async runtime.",
                    "runtime initialization failed".to_owned(),
                    json,
                ),
            };
        }
        if action.cli_handler == CliHandler::RemoveHost {
            let host = matches
                .get_one::<String>("host")
                .and_then(|host| host.parse().ok());
            let Some(host) = host else {
                return report_failure(
                    "remove-host",
                    "Invalid host identifier.",
                    "expected a host UUID".to_owned(),
                    json,
                );
            };
            return host_remove::run(
                matches
                    .get_one::<String>("server")
                    .map_or("", String::as_str),
                host,
                matches.get_flag("finish"),
                matches.get_flag("retain"),
                json,
            );
        }
    }
    let _ = matches;
    run_unavailable(action, json)
}
