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
#[cfg(feature = "process-per-user")]
mod user_host_cli;

#[cfg(any(
    feature = "remote",
    feature = "session-payload",
    all(feature = "plugin-agent", target_os = "linux")
))]
mod output;
#[cfg(feature = "remote")]
mod remote;
#[cfg(feature = "plugin-server")]
mod remote_server;
#[cfg(feature = "remote")]
mod remote_service;
#[cfg(all(feature = "remote", feature = "plugin-server"))]
mod restart;
#[cfg(all(feature = "remote", feature = "plugin-server"))]
mod restart_binary;
#[cfg(all(feature = "remote", feature = "plugin-server"))]
mod restart_image;
mod shim_cli;
#[cfg(feature = "remote")]
mod sign_in;
#[cfg(feature = "ssh")]
mod ssh_askpass;
#[cfg(feature = "ssh")]
mod ssh_internal;

#[cfg(feature = "plugin-server")]
mod install;

use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

#[cfg(feature = "plugin-server")]
use std::net::SocketAddr;

use clap::ArgMatches;
use cli::output::{CommandResult, CommandState, Exit, emit};
#[cfg(feature = "plugin-server")]
use cli::output::{render_json, write_output};
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
    if let Some(result) = infraternal_agent::startup_guard::run_if_requested() {
        return result;
    }
    #[cfg(feature = "plugin-agent")]
    if !shim_cli::PAYLOAD_ONLY
        && let Some(result) = embedded_cli::run_if_requested()
    {
        return result;
    }
    #[cfg(feature = "ssh")]
    if let Some(result) = ssh_internal::run_if_requested() {
        return result;
    }
    #[cfg(feature = "session-payload")]
    if shim_cli::PAYLOAD_ONLY {
        return shim_cli::payload_entry();
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
            return emit(
                CommandResult::new(
                    "infraternal",
                    CommandState::Failed,
                    "The command list could not be loaded.",
                    json!({}),
                )
                .with_details(error.to_string()),
                requested_json_early(),
                Exit::Failed,
            );
        }
    };
    let requested_json = requested_json_early();
    let matches = match cli::command_tree::build(&registry).try_get_matches() {
        Ok(matches) => matches,
        Err(error) => return parse_failure(&registry, &error, requested_json),
    };
    let json_output = matches.get_flag("json");
    let selected = cli::command_tree::selected(&matches);
    if json_output {
        // One envelope per command, also when Ctrl-C stops it (D303/D305).
        let command = if selected.path.is_empty() {
            "infraternal".to_owned()
        } else {
            selected.path.join(" ")
        };
        infraternal_shim::exit_on_interrupt(cli::output::interrupted_notice(&command));
    }
    dispatch_selected_action(&registry, &selected, json_output)
}

fn dispatch_selected_action(
    registry: &ActionRegistry,
    selected: &cli::command_tree::SelectedCommand<'_>,
    json_output: bool,
) -> ExitCode {
    let path = selected.path.iter().map(String::as_str).collect::<Vec<_>>();
    if path.is_empty() {
        return run_overview(registry, json_output);
    }
    let Some(registered) = registry.find(&path) else {
        return run_group(registry, &path, json_output)
            .unwrap_or_else(|| missing_action(json_output));
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
        CliHandler::NodeComponent | CliHandler::Sessions => {
            run_local_action(action, matches, json_output)
        }
        CliHandler::Unavailable => run_unavailable(action, json_output),
        CliHandler::Status => run_status(registry, json_output),
        CliHandler::Skill => run_skill(registry, matches, json_output),
        CliHandler::SignIn => run_sign_in(action, matches, json_output),
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
                run_embedded_agent(registry, matches, json_output)
            }
            #[cfg(not(feature = "plugin-agent"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::SessionShim => run_shim_command(matches),
        CliHandler::SshSession => {
            #[cfg(all(feature = "ssh", feature = "remote"))]
            {
                run_ssh_session(matches)
            }
            #[cfg(not(all(feature = "ssh", feature = "remote")))]
            {
                run_unavailable(action, json_output)
            }
        }
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

fn run_sign_in(_action: &ActionDefinition, matches: &ArgMatches, json_output: bool) -> ExitCode {
    #[cfg(feature = "remote")]
    {
        let Some(server) = matches.get_one::<String>("server") else {
            return report_failure_as(
                "sign-in",
                "A server address is required.",
                "provide an HTTPS server origin, for example https://infra.example.org".to_owned(),
                json_output,
                Exit::Usage,
            );
        };
        sign_in::run(server, json_output)
    }
    #[cfg(not(feature = "remote"))]
    {
        run_unavailable(_action, json_output)
    }
}

#[cfg(all(feature = "ssh", feature = "remote"))]
fn run_ssh_session(matches: &ArgMatches) -> ExitCode {
    let (Some(state), session) = (
        matches.get_one::<String>("state"),
        matches
            .get_one::<String>("session")
            .map(|value| uuid::Uuid::parse_str(value))
            .transpose(),
    ) else {
        return ExitCode::FAILURE;
    };
    let Ok(session) = session else {
        return ExitCode::FAILURE;
    };
    if infraternal_plugin_ssh::session_bridge::run(PathBuf::from(state), session).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn missing_action(json_output: bool) -> ExitCode {
    emit(
        CommandResult::new(
            "infraternal",
            CommandState::Refused,
            "That is not a command this build has.",
            json!({}),
        )
        .with_next_step("infraternal --help"),
        json_output,
        Exit::Usage,
    )
}

/// Whether `--json` was typed anywhere, known before any parsing so failures can honour it.
fn requested_json_early() -> bool {
    std::env::args_os().any(|argument| argument == "--json")
}

/// What to do with a command line that did not parse (see `cli::usage`).
///
/// Help and version are not failures: people get the parser's text, `--json` callers one envelope
/// that carries the same text. Every real failure is worded by us, in text and in JSON, so the
/// value that was typed (it may be a URL with a token, or a path) is never echoed back.
fn parse_failure(registry: &ActionRegistry, error: &clap::Error, json: bool) -> ExitCode {
    use clap::error::ErrorKind;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let tree = cli::command_tree::build(registry);
    match error.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion if json => {
            emit(cli::usage::help_result(&tree, &args, error), true, Exit::Ok)
        }
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayVersion
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            if !json =>
        {
            error.exit()
        }
        _ => emit(cli::usage::result(&tree, &args, error), json, Exit::Usage),
    }
}

/// The shipping diagnostic refuses partial protection independently of server development policy.
#[cfg(feature = "remote")]
fn run_key_memory_check(json_output: bool) -> ExitCode {
    // D244 requires fully protected pages even for a non-root gate runner.
    if infraternal_shim::openssl_secure::initialize() == 1 {
        output::done(
            json_output,
            "internal.key-memory-check",
            "ready",
            "Key memory initialization=1; locked pages and dump exclusion enabled",
            "",
        )
    } else {
        output::refuse(
            json_output,
            "internal.key-memory-check",
            "Key memory refused",
            "Raise the memlock limit to at least 8 MiB and run the check again.",
            Exit::Failed,
        )
    }
}

/// What this machine runs, as the shared result; the second value is how many installed services are confirmed not running (unknown ones are not counted).
fn status_result(
    registry: &ActionRegistry,
    command: &str,
) -> (CommandResult<serde_json::Value>, usize) {
    use infraternal_status::Activity;
    let ids: Vec<String> = registry
        .plugins()
        .filter(|plugin| plugin.id != "cli")
        .map(|plugin| plugin.id.clone())
        .collect();
    let node = infraternal_status::probe_local(&infraternal_status::Roots::detect(), &ids);
    let (activity, message, next) = node.headline();
    let state = match activity {
        Activity::Active => CommandState::Running,
        Activity::Restarting { .. } => CommandState::Restarting,
        Activity::Inactive => CommandState::Stopped,
        Activity::Failed => CommandState::Failed,
        Activity::Unknown => CommandState::Unknown,
    };
    // A component without a runtime yet is not something this machine has.
    let components: Vec<_> = node
        .components
        .iter()
        .filter(|c| c.state != "Not available yet")
        .map(|c| json!({"name": c.name, "state": c.state, "state_detail": c.detail}))
        .collect();
    // People get the components table; the role id is a scripting detail.
    let options = cli::output::RenderOptions::detect(io::stdout().is_terminal());
    let rows: Vec<Vec<String>> = node
        .components
        .iter()
        .filter(|c| c.state != "Not available yet")
        .map(|c| vec![c.name.clone(), c.state.clone(), c.detail.clone()])
        .collect();
    let tint = |column: usize, text: &str| {
        (options.color && column == 1)
            .then(|| cli::output::state_tint(text))
            .flatten()
    };
    let mut result = CommandResult::new(
        command,
        state,
        message,
        json!({"role": node.role.id(), "components": components}),
    )
    .with_body(infraternal_plugin_api::present::table(
        &["Component", "State", "Detail"],
        &rows,
        0,
        options.usable_width(),
        Some(&tint),
    ));
    for step in next {
        result = result.with_next_step(step);
    }
    let down = node.confirmed_down_count();
    (result, down)
}

fn run_status(registry: &ActionRegistry, json_output: bool) -> ExitCode {
    let (result, down) = status_result(registry, "status");
    finish_status(result, down, json_output)
}

/// `status` exits 5 when something that should run is down, so `infraternal status || alert`
/// works in a script (D303). The report itself is information, so it stays on standard output.
fn finish_status(
    result: CommandResult<serde_json::Value>,
    down: usize,
    json_output: bool,
) -> ExitCode {
    if down == 0 {
        return emit(result, json_output, Exit::Ok);
    }
    cli::output::emit_to(
        result.with_error_code("component_down"),
        json_output,
        Exit::Unreachable,
        false,
    )
}

/// Bare `infraternal`: the status overview, or how to join when this machine is not set up (D299).
fn run_overview(registry: &ActionRegistry, json_output: bool) -> ExitCode {
    let (result, down) = status_result(registry, "infraternal");
    finish_status(
        result.with_next_step("infraternal --help"),
        down,
        json_output,
    )
}

/// "1 command", "4 commands".
fn count_commands(count: usize) -> String {
    format!("{count} command{}", if count == 1 { "" } else { "s" })
}

/// A group typed alone (`infraternal mesh`) lists what it can do.
fn run_group(registry: &ActionRegistry, path: &[&str], json_output: bool) -> Option<ExitCode> {
    let commands: Vec<_> = cli::skills::commands(registry)
        .into_iter()
        .filter(|entry| {
            entry
                .command
                .split_whitespace()
                .collect::<Vec<_>>()
                .starts_with(path)
        })
        .collect();
    if commands.is_empty() {
        return None;
    }
    let rows: Vec<Vec<String>> = commands
        .iter()
        .map(|entry| vec![entry.command.clone(), entry.description.clone()])
        .collect();
    let body = infraternal_plugin_api::present::table(
        &["Command", "What it does"],
        &rows,
        0,
        cli::output::RenderOptions::detect(false).usable_width(),
        None,
    );
    let name = path.join(" ");
    Some(emit(
        CommandResult::new(
            name.clone(),
            CommandState::Ready,
            format!("infraternal {name} has {}.", count_commands(commands.len())),
            json!({"commands": commands}),
        )
        .with_body(body)
        .with_next_step(format!("infraternal {name} <command> --help")),
        json_output,
        Exit::Ok,
    ))
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
        return report_failure_as(
            "skill",
            "Choose a command path or a destination directory.",
            "--write cannot be combined with a command path".to_owned(),
            json_output,
            Exit::Usage,
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
                );
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
            format!(
                "{} {} enabled in this build.",
                count_commands(commands.len()),
                if commands.len() == 1 { "is" } else { "are" }
            ),
            json!({"commands": commands, "skill": "", "files": []}),
        )
        .with_next_step("infraternal skill <command>");
        print_result(&result, json_output, false);
        return ExitCode::SUCCESS;
    }

    if let Some(result) = run_skill_group(registry, &command, json_output) {
        return result;
    }
    let path = command.join(" ");
    let Some(registered) = registry.find(&command).filter(|r| r.action.is_public()) else {
        return report_failure_as(
            "skill",
            "The requested command has no generated skill in this build.",
            "The command path supplied to skill is not a public action.".to_owned(),
            json_output,
            Exit::NotFound,
        );
    };
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
            format!("Generated the skill for infraternal {path}."),
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
        "infraternal status"
    };
    emit(
        CommandResult::new(command, state, message, data).with_next_step(next_step),
        json_output,
        Exit::Failed,
    )
}

#[cfg(feature = "plugin-server")]
fn run_server(matches: &ArgMatches, json_output: bool) -> ExitCode {
    if !server_configuration_was_supplied(matches) {
        return emit(
            CommandResult::new(
                "server",
                CommandState::Unavailable,
                "The server is not configured yet.",
                json!({"listen": "127.0.0.1:7443", "public_origin": "https://localhost:7443"}),
            )
            .with_next_step("infraternal server init"),
            json_output,
            Exit::Usage,
        );
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
        data: server_data_directory(
            matches.get_one::<String>("data").map(String::as_str),
            infraternal_status::Roots::detect,
        ),
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
    .with_next_step("infraternal server init --dry-run");
    emit(result, json_output, Exit::Usage)
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
            let mut result = CommandResult::new(
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
                "infraternal server init --yes"
            } else {
                "infraternal status"
            });
            if install_args.dry_run {
                // The unit file is data for a person to read and copy: the generic renderer
                // would reflow its lines into prose and break it.
                result = result.with_body(plan);
            }
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
    let data_dir = server_data_directory(
        matches.get_one::<String>("data").map(String::as_str),
        infraternal_status::Roots::detect,
    );
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        return report_failure(
            "server setup-token",
            "The setup capability could not be read.",
            "async runtime initialization failed".to_owned(),
            json_output,
        );
    };
    match block_on(&runtime, read_setup_token(&data_dir)) {
        Ok(token) => {
            let result = CommandResult::new(
                "server setup-token",
                CommandState::Ready,
                "A one-time setup capability is available.",
                json!({"token": &token}),
            );
            if json_output {
                // Both private-pipe readers remain valid; the capability never enters logs or argv.
                write_output(
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
        Err(SetupTokenReadError::PermissionDenied) => {
            setup_token_permission_failure(matches, json_output)
        }
        Err(SetupTokenReadError::Unavailable(error)) => report_failure(
            "server setup-token",
            "The setup capability is not available.",
            error.to_owned(),
            json_output,
        ),
    }
}

/// Resolve the server's explicit, installed-service, and fallback data locations in that order.
#[cfg(feature = "plugin-server")]
fn server_data_directory(
    explicit: Option<&str>,
    roots: impl FnOnce() -> infraternal_status::Roots,
) -> PathBuf {
    if let Some(explicit) = explicit {
        return PathBuf::from(explicit);
    }

    infraternal_status::server_data_directory(&roots()).unwrap_or_else(|| PathBuf::from("./data"))
}

/// Keep the non-JSON permission diagnostic to one actionable line.
#[cfg(feature = "plugin-server")]
fn setup_token_permission_failure(matches: &ArgMatches, json_output: bool) -> ExitCode {
    let explicit = matches.get_one::<String>("data");
    let command = setup_token_sudo_command(explicit.map(String::as_str));
    if json_output {
        return report_failure(
            "server setup-token",
            "The server data directory is not readable.",
            format!("run: {command}"),
            true,
        );
    }
    eprintln!("The server data directory is not readable. Run: {command}");
    ExitCode::from(Exit::Failed.code())
}

/// Format the actual action command, preserving an explicit path as a shell-safe argument.
#[cfg(feature = "plugin-server")]
fn setup_token_sudo_command(explicit_data: Option<&str>) -> String {
    let mut command = infraternal_server::cli::setup_token_command(true);
    if let Some(data) = explicit_data {
        command.push_str(" --data ");
        command.push_str(&shell_quote(data));
    }
    command
}

/// Quote a path as one POSIX shell argument when the permission diagnostic is copied.
#[cfg(feature = "plugin-server")]
fn shell_quote(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./-".contains(&byte))
    {
        return argument.to_owned();
    }
    format!("'{}'", argument.replace('\'', "'\\''"))
}

/// Share cold command startup through the existing reactor regardless of result type [243].
/// The result slot outlives its adapter future, which stores the result before
/// completing. Panics propagate to the caller's existing recovery boundary.
#[cfg(any(feature = "plugin-server", feature = "remote"))]
fn block_on<T>(
    runtime: &tokio::runtime::Runtime,
    operation: impl std::future::Future<Output = T>,
) -> T {
    #[cfg(feature = "plugin-agent")]
    {
        let mut outcome = None;
        // One allocation per command keeps its typed result out of another
        // reactor instantiation; terminal frames never cross this adapter.
        let _completion = infraternal_agent::block_on_io(
            runtime,
            Box::pin(async {
                outcome = Some(operation.await);
                Ok(())
            }),
        );
        match outcome {
            Some(value) => value,
            None => unreachable!("a completed startup operation stores its result"),
        }
    }
    #[cfg(not(feature = "plugin-agent"))]
    runtime.block_on(operation)
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
    match block_on(&runtime, remote_server::serve(config, options)) {
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
                    Exit::Failed,
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
fn run_embedded_agent(
    registry: &ActionRegistry,
    matches: &ArgMatches,
    json_output: bool,
) -> ExitCode {
    let Some(fd) = matches
        .get_one::<i64>("fd")
        .and_then(|fd| i32::try_from(*fd).ok())
    else {
        // Typed by a person (the server passes a descriptor), `agent` is a group like the others.
        if let Some(listed) = run_group(registry, &["agent"], json_output) {
            return listed;
        }
        return emit(
            CommandResult::new(
                "agent",
                CommandState::Unavailable,
                "The infraternal agent needs a server connection to start.",
                json!({}),
            )
            .with_next_step("infraternal agent join --help"),
            json_output,
            Exit::Usage,
        );
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

// Parse the paired private handoff capability without reserving fixed slots.
#[cfg(feature = "plugin-agent")]
fn prestarted_descriptors(matches: &ArgMatches) -> Result<Option<(i32, i32)>, ExitCode> {
    match (
        matches.get_one::<i64>("login_master_fd"),
        matches.get_one::<i64>("login_lease_fd"),
    ) {
        (None, None) => Ok(None),
        (Some(master), Some(lease)) => match (i32::try_from(*master), i32::try_from(*lease)) {
            (Ok(master), Ok(lease)) if master >= 8 && lease >= 8 && master != lease => {
                Ok(Some((master, lease)))
            }
            _ => Err(ExitCode::from(2)),
        },
        _ => Err(ExitCode::from(2)),
    }
}

// This startup entry is absent from a running daemon; keep its code away
// from hot dispatch pages without changing the terminal/worker pump itself.
#[cold]
fn run_shim_command(matches: &ArgMatches) -> ExitCode {
    let options = match (|| {
        Ok::<_, String>(shim_cli::Options {
            session: matches
                .get_one::<String>("session")
                .cloned()
                .unwrap_or_default(),
            uid: shim_integer(matches, "uid", None)?,
            cols: shim_integer(matches, "cols", Some(80))?,
            rows: shim_integer(matches, "rows", Some(24))?,
            state: matches.get_one::<String>("state").map(PathBuf::from),
            detach: matches.get_flag("detach"),
            ring_capacity: shim_integer(matches, "ring_capacity", Some(8 * 1024 * 1024))?,
            exit_retention_ms: matches
                .get_one::<i64>("exit_retention_ms")
                .copied()
                .unwrap_or(600_000)
                .try_into()
                .unwrap_or(600_000),
            readiness: matches.get_flag("readiness"),
            command_stdin: matches.get_flag("command_stdin"),
            retain_output: matches.get_flag("retain_output"),
        })
    })() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("shim startup/session failed: {error}");
            return ExitCode::from(2);
        }
    };
    #[cfg(feature = "process-per-user")]
    if matches.get_one::<i64>("host_sessions").is_some() {
        return user_host_cli::run(matches);
    }
    #[cfg(feature = "process-per-user")]
    if matches.get_one::<String>("host_accounting").is_some() {
        eprintln!("--host-accounting requires --host-sessions");
        return ExitCode::from(2);
    }

    #[cfg(feature = "plugin-agent")]
    if let Some(result) = run_login_shim_if_requested(matches, &options) {
        return result;
    }
    match options.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("shim startup/session failed: {error}");
            ExitCode::from(1)
        }
    }
}

/// Dispatch the private login workers only when their authenticated fields are present.
#[cfg(feature = "plugin-agent")]
#[cold]
fn run_login_shim_if_requested(
    matches: &ArgMatches,
    options: &shim_cli::Options,
) -> Option<ExitCode> {
    let login_socket = matches.get_one::<String>("login_socket").map(PathBuf::from);
    if matches
        .get_one::<String>("login_worker_proc")
        .is_some_and(|path| infraternal_shim::protect_login_process_at(Path::new(path)).is_err())
    {
        return Some(ExitCode::FAILURE);
    }
    let prestarted = match prestarted_descriptors(matches) {
        Ok(descriptors) => descriptors,
        Err(code) => return Some(code),
    };
    if matches.get_flag("login_worker") || matches.get_flag("login_proxy") {
        if prestarted.is_some() {
            return Some(ExitCode::from(2));
        }
        let Some(endpoint) = login_socket.as_deref() else {
            return Some(ExitCode::from(2));
        };
        return Some(run_login_command(
            matches,
            &options.session,
            options.uid,
            endpoint,
        ));
    }
    let login_cgroup = matches.get_one::<String>("login_cgroup").map(PathBuf::from);
    let login_worker_pid = matches
        .get_one::<i64>("login_worker_pid")
        .and_then(|pid| i32::try_from(*pid).ok());
    let login_worker_parent = matches
        .get_one::<i64>("login_worker_parent")
        .and_then(|pid| i32::try_from(*pid).ok());
    let login_worker_proc = matches
        .get_one::<String>("login_worker_proc")
        .map(PathBuf::from);
    let has_login_config = login_socket.is_some()
        || login_cgroup.is_some()
        || login_worker_pid.is_some()
        || login_worker_parent.is_some()
        || login_worker_proc.is_some()
        || prestarted.is_some();
    if !has_login_config {
        return None;
    }
    if options.command_stdin {
        eprintln!("command startup with a host login is unavailable");
        return Some(ExitCode::from(2));
    }
    Some(
        match run_shim(
            &options.session,
            options.uid,
            options.cols,
            options.rows,
            options.state.clone(),
            options.detach,
            options.ring_capacity,
            login_socket,
            login_cgroup.as_deref(),
            login_worker_pid,
            login_worker_parent,
            login_worker_proc,
            options.exit_retention_ms,
            options.readiness,
            options.retain_output,
            prestarted,
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("shim startup/session failed: {error}");
                ExitCode::from(1)
            }
        },
    )
}

#[cfg(feature = "plugin-agent")]
// This startup entry is absent from a running daemon; keep its code away
// from hot dispatch pages without changing the terminal/worker pump itself.
#[cold]
fn run_login_command(
    matches: &ArgMatches,
    session: &str,
    uid: u32,
    endpoint: &std::path::Path,
) -> ExitCode {
    let result = if matches.get_flag("login_worker") {
        let startup = match matches.get_one::<i64>("login_ready_fd") {
            None => infraternal_shim::login::worker_as_controller,
            Some(1) => infraternal_shim::login::worker_announced,
            Some(_) => return ExitCode::from(2),
        };
        startup(
            endpoint,
            infraternal_shim::login::GRACE,
            shim_integer(matches, "controller_uid", Some(0)).unwrap_or(u32::MAX),
        )
        .map(|()| 0)
    } else {
        let Ok(id) = uuid::Uuid::parse_str(session) else {
            return ExitCode::from(2);
        };
        infraternal_shim::login::proxy_at_parent(
            endpoint,
            uid,
            id.as_bytes(),
            matches
                .get_one::<i64>("login_ready_fd")
                .is_some_and(|fd| *fd == 4),
            matches
                .get_one::<i64>("login_worker_pid")
                .and_then(|pid| i32::try_from(*pid).ok()),
            matches
                .get_one::<String>("login_worker_proc")
                .map(std::path::Path::new),
            matches
                .get_one::<i64>("login_worker_parent")
                .and_then(|pid| i32::try_from(*pid).ok()),
        )
    };
    match result {
        Ok(status) if status < 0 => {
            if let Some(number) = status.checked_neg()
                && let Ok(signal) = nix::sys::signal::Signal::try_from(number)
            {
                let _ = nix::sys::signal::kill(nix::unistd::getpid(), signal);
            }
            ExitCode::FAILURE
        }
        Ok(status) => ExitCode::from(u8::try_from(status).unwrap_or(1)),
        Err(_) => ExitCode::FAILURE,
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
    report_failure_as(command, message, details, json_output, Exit::Failed)
}

/// Like [`report_failure`], for a failure that D303 gives its own exit code (not found, usage).
fn report_failure_as(
    command: &str,
    message: &str,
    details: String,
    json_output: bool,
    exit: Exit,
) -> ExitCode {
    emit(
        CommandResult::new(
            command,
            CommandState::Failed,
            message,
            failure_data(command),
        )
        .with_details(details),
        json_output,
        exit,
    )
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
        #[cfg(feature = "placeholders")]
        assert_eq!(failure_data("up"), json!({"started": []}));
        #[cfg(all(feature = "plugin-server", feature = "placeholders"))]
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

#[cfg(all(test, feature = "plugin-server"))]
mod server_data_resolution_tests {
    //! Checks the CLI's explicit, installed-service and ordinary fallback precedence.

    use super::server_data_directory;
    use infraternal_status::Roots;
    use std::{fs, path::PathBuf};

    fn roots(system_units: Vec<PathBuf>) -> Roots {
        Roots {
            system_units,
            user_units: None,
            run_dir: None,
            data_dirs: Vec::new(),
            net_class: PathBuf::new(),
        }
    }

    #[test]
    fn explicit_data_directory_wins_over_the_installed_service() {
        assert_eq!(
            server_data_directory(Some("/srv/explicit"), || {
                panic!("explicit data path must not scan installed services")
            }),
            PathBuf::from("/srv/explicit")
        );
    }

    #[test]
    fn installed_service_data_directory_is_selected_when_no_override_is_given() {
        let root = std::env::temp_dir().join(format!("setup-data-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("system unit fixture");
        fs::write(
            root.join("infraternal-server.service"),
            "[Service]\nExecStart=/usr/bin/infraternal server --data /srv/installed\n",
        )
        .expect("write system unit fixture");

        assert_eq!(
            server_data_directory(None, || roots(vec![root.clone()])),
            PathBuf::from("/srv/installed")
        );
        fs::remove_dir_all(root).expect("remove system unit fixture");
    }

    #[test]
    fn missing_install_uses_the_existing_default_directory() {
        assert_eq!(
            server_data_directory(None, || roots(Vec::new())),
            PathBuf::from("./data")
        );
    }
}

fn print_result<T: Serialize>(result: &CommandResult<T>, json_output: bool, to_stderr: bool) {
    cli::output::print(result, json_output, to_stderr && !json_output);
}

/// Preserve access refusal separately from sanitized, non-secret protocol failures.
#[cfg(feature = "plugin-server")]
#[derive(Debug)]
enum SetupTokenReadError {
    PermissionDenied,
    Unavailable(&'static str),
}

#[cfg(feature = "plugin-server")]
impl From<&'static str> for SetupTokenReadError {
    fn from(message: &'static str) -> Self {
        Self::Unavailable(message)
    }
}

#[cfg(all(unix, feature = "plugin-server"))]
async fn read_setup_token(data_dir: &Path) -> Result<String, SetupTokenReadError> {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };

    let mut socket = UnixStream::connect(data_dir.join("setup-token.sock"))
        .await
        .map_err(|error| {
            if error.kind() == io::ErrorKind::PermissionDenied {
                SetupTokenReadError::PermissionDenied
            } else {
                SetupTokenReadError::Unavailable("no active first-run token socket")
            }
        })?;
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
        return Err("no active first-run token".into());
    }
    String::from_utf8(response[..43].to_vec()).map_err(|_| "invalid local token response".into())
}

#[cfg(all(not(unix), feature = "plugin-server"))]
async fn read_setup_token(_data_dir: &Path) -> Result<String, SetupTokenReadError> {
    Err("local token retrieval requires a Unix socket".into())
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
    use std::{
        os::unix::{ffi::OsStrExt, fs::PermissionsExt},
        path::{Path, PathBuf},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };

    struct PrivateDirectory(PathBuf);

    impl PrivateDirectory {
        /// Keep Unix socket fixture paths short even when `TMPDIR` is nested deeply.
        fn new() -> Self {
            let path = Path::new("/tmp").join(format!("itok-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).expect("create token test directory");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("set token test directory permissions");
            Self(path)
        }
    }

    impl Drop for PrivateDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn setup_token_command_reads_only_the_expected_socket_response() {
        let data_dir = PrivateDirectory::new();
        let socket = data_dir.0.join("setup-token.sock");
        assert!(
            socket.as_os_str().as_bytes().len() < 108,
            "token test socket path exceeds the Unix socket path limit"
        );
        let listener = UnixListener::bind(socket).expect("bind token test socket");
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
            read_setup_token(&data_dir.0)
                .await
                .expect("read setup token"),
            "A".repeat(43)
        );
        server.await.expect("token test socket server");
    }
}

/// Validate identifiers before forking; clamp exited-screen retention inside the shim.
#[allow(clippy::too_many_arguments)]
// This startup entry is absent from a running daemon; keep its code away
// from hot dispatch pages without changing the terminal/worker pump itself.
#[cold]
#[cfg(feature = "plugin-agent")]
fn run_shim(
    session: &str,
    uid: u32,
    cols: u16,
    rows: u16,
    state: Option<std::path::PathBuf>,
    detach: bool,
    ring_capacity: usize,
    login_socket: Option<PathBuf>,
    login_cgroup: Option<&std::path::Path>,
    login_worker_pid: Option<i32>,
    login_worker_parent: Option<i32>,
    login_worker_proc: Option<PathBuf>,
    exit_retention_ms: u64,
    readiness: bool,
    retain_output: bool,
    prestarted: Option<(i32, i32)>,
) -> std::io::Result<()> {
    if prestarted.is_some() && (readiness || detach) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
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
    #[cfg(not(feature = "plugin-agent"))]
    if login_cgroup.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "host login support was compiled out",
        ));
    }
    let config = infraternal_shim::Config {
        session: id,
        uid,
        cols,
        rows,
        state,
        ring_capacity,
        login_socket,
        login_worker_pid,
        login_worker_parent,
        login_worker_proc,
        readiness,
        command: Vec::new(),
        retain_output,
    };
    let retention = std::time::Duration::from_millis(exit_retention_ms);
    #[cfg(feature = "plugin-agent")]
    if let Some((master, lease)) = prestarted {
        return infraternal_shim::run_with_prestarted_login(
            config,
            retention,
            login_cgroup,
            master,
            lease,
        );
    }
    #[cfg(not(feature = "plugin-agent"))]
    if prestarted.is_some() {
        return Err(io::ErrorKind::Unsupported.into());
    }
    #[cfg(feature = "plugin-agent")]
    if let Some(group) = login_cgroup {
        return infraternal_shim::run_with_login_group(config, retention, group);
    }
    infraternal_shim::run_with_retention(config, retention)
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
    #[cfg(all(feature = "remote", feature = "plugin-server"))]
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
// Keep enrollment and its ordered status reporting in one CLI lifecycle.
#[allow(clippy::too_many_lines)]
fn run_remote_agent(
    action: AgentAction,
    has_fd: bool,
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
        AgentAction::PrepareJoinKey { .. } => "agent.prepare-join-key",
        AgentAction::Run => infraternal_plugin_remote::RUN.id,
    };
    // Remote actions use the enrolled identity; only the hidden parent action consumes this fd.
    if has_fd {
        return output::refuse(
            json,
            operation,
            "These infraternal agent options cannot be used together.",
            "infraternal agent --help",
            Exit::Usage,
        );
    }
    let Ok(data) = data.map_or_else(remote::default_data, Ok) else {
        return output::refuse(
            json,
            operation,
            "The infraternal agent has no private directory for its identity.",
            "Pass --data with a directory only this account can read.",
            Exit::Failed,
        );
    };
    if let AgentAction::PrepareJoinKey { origin } = &action {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| io::Error::other("runtime unavailable"))
            .and_then(|runtime| runtime.block_on(remote::prepare_join_key(origin, &data)));
        match result {
            Ok(digest) => {
                let encoded: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
                println!("KEY-DIGEST {encoded}");
            }
            Err(error) => {
                let class = match remote::Failure::of(&error) {
                    Some(remote::Failure::Dns(_)) => "DNS",
                    Some(remote::Failure::Connect) => "CONNECT",
                    Some(remote::Failure::Tls) => "TLS",
                    Some(remote::Failure::Upgrade) => "UPGRADE",
                    Some(remote::Failure::Challenge) => "CHALLENGE",
                    Some(remote::Failure::Refused) | None => "REFUSED",
                };
                println!("PREPARE-REFUSED {class}");
            }
        }
        return ExitCode::SUCCESS;
    }
    output::report(
        json,
        operation,
        "starting",
        "Preparing the connection to the server.",
        "",
    );
    let result = (|| -> std::io::Result<()> {
        use std::io::Read;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        if let AgentAction::Join { url, .. } = action {
            let mut invitation = Vec::with_capacity(8192);
            std::io::stdin().take(8193).read_to_end(&mut invitation)?;
            infraternal_agent::block_on_io(
                &runtime,
                Box::pin(remote::join(&url, &data, &invitation)),
            )?;
            // SSH publishes staged state only after enrollment returns. Running
            // here would hold its transaction until the service was cancelled.
            if enroll_only {
                return Ok(());
            }
            output::report(
                json,
                operation,
                "enrolled",
                "This machine is enrolled. Connecting now; keep this running.",
                "",
            );
        }
        remote_service::run(runtime, remote::run(&data, state))
    })();
    if result.is_ok() {
        if enroll_only {
            output::done(
                json,
                operation,
                "enrolled",
                "This machine is enrolled. Its identity is saved here.",
                "infraternal agent run",
            )
        } else {
            output::done(
                json,
                operation,
                "stopped",
                "The infraternal agent stopped.",
                "infraternal agent run",
            )
        }
    } else {
        output::refuse(
            json,
            operation,
            result.as_ref().err().map_or(
                "The infraternal agent could not finish.",
                remote::public_error,
            ),
            "Check the server address and that this machine is still enrolled, then run the command again.",
            result
                .as_ref()
                .err()
                .map_or(Exit::Failed, |error| match remote::Failure::of(error) {
                    Some(remote::Failure::Tls) => Exit::NotAllowed,
                    Some(remote::Failure::Dns(_) | remote::Failure::Connect) => Exit::Unreachable,
                    Some(
                        remote::Failure::Refused
                        | remote::Failure::Upgrade
                        | remote::Failure::Challenge,
                    )
                    | None => Exit::Failed,
                }),
        )
    }
}

/// Remote node modes never create a server or accept an invitation through argv.
#[cfg(feature = "remote")]
enum AgentAction {
    Join { url: String, enroll_only: bool },
    PrepareJoinKey { origin: String },
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
            let has_fd = matches.try_contains_id("fd").is_ok_and(|present| present);
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
            let mode = match action.command.last().map(String::as_str) {
                Some("join") => AgentAction::Join {
                    url: matches
                        .get_one::<String>("url")
                        .cloned()
                        .unwrap_or_default(),
                    enroll_only: matches.get_flag("enroll_only"),
                },
                Some("prepare-join-key") => AgentAction::PrepareJoinKey {
                    origin: matches
                        .get_one::<String>("origin")
                        .cloned()
                        .unwrap_or_default(),
                },
                _ => AgentAction::Run,
            };
            return run_remote_agent(mode, has_fd, state, data, json);
        }
        #[cfg(feature = "plugin-server")]
        if action.cli_handler == CliHandler::ServerRestart {
            let data = server_data_directory(
                matches.get_one::<String>("data").map(String::as_str),
                infraternal_status::Roots::detect,
            );
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
                return report_failure_as(
                    "remove-host",
                    "Invalid host identifier.",
                    "expected a host UUID".to_owned(),
                    json,
                    Exit::Usage,
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

/// Session automation is removable with the host runtime, including in minimal CLI builds.
fn run_local_action(
    action: &ActionDefinition,
    matches: &ArgMatches,
    json_output: bool,
) -> ExitCode {
    #[cfg(all(feature = "plugin-agent", target_os = "linux"))]
    {
        if action.cli_handler == CliHandler::Sessions {
            cli::sessions::run(action, matches, json_output)
        } else {
            component_cli::run_action(action, matches, json_output)
        }
    }
    #[cfg(not(all(feature = "plugin-agent", target_os = "linux")))]
    {
        let _ = matches;
        run_unavailable(action, json_output)
    }
}
