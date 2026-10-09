//! Defines the process entry point and dispatches metadata-registered actions.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

mod cli;
mod install;

use std::{
    io::{self, IsTerminal, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use clap::ArgMatches;
use cli::output::{CommandResult, CommandState, RenderOptions, render_json, render_pretty};
use infraternal_plugin_api::{ActionAvailability, ActionDefinition, ActionRegistry};
use serde::Serialize;
use serde_json::json;

/// Server listener and application settings read from a registered action's input schema.
#[derive(Debug)]
struct ServerArgs {
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
    let registry = match cli::actions::registry() {
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
    let matches = cli::command_tree::build(&registry).get_matches();
    let json_output = matches.get_flag("json");
    let selected = cli::command_tree::selected(&matches);
    let path = selected.path.iter().map(String::as_str).collect::<Vec<_>>();
    match path.as_slice() {
        ["__shim"] => run_shim_command(selected.matches),
        ["status"] => run_status(&registry, json_output),
        ["server"] => run_server(selected.matches, json_output),
        ["server", "init"] => run_server_init(selected.matches, json_output),
        ["server", "install"] => run_server_install_compat(selected.matches, json_output),
        ["server", "setup-token"] => run_setup_token(selected.matches, json_output),
        ["agent"] => run_embedded_agent(selected.matches, json_output),
        _ => {
            let Some(action) = find_action(&registry, &selected.path) else {
                return missing_action(json_output);
            };
            run_unavailable(action, json_output)
        }
    }
}

fn find_action<'a>(registry: &'a ActionRegistry, path: &[String]) -> Option<&'a ActionDefinition> {
    let path = path.iter().map(String::as_str).collect::<Vec<_>>();
    registry.find(&path).map(|registered| registered.action)
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
            "Check the user service with `systemctl --user status infraternal-server.service`.",
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

fn systemd_server_state() -> Option<bool> {
    let scopes: [&[&str]; 2] = [&["--user"], &[]];
    let mut service_was_found = false;
    for scope in scopes {
        let output = Command::new("systemctl")
            .args(scope)
            .args(["is-active", "infraternal-server.service"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        let state = String::from_utf8_lossy(&output.stdout);
        match state.trim() {
            "active" => return Some(true),
            "inactive" | "failed" | "deactivating" | "dead" => service_was_found = true,
            _ => {}
        }
    }
    service_was_found.then_some(false)
}

fn run_unavailable(action: &ActionDefinition, json_output: bool) -> ExitCode {
    let command = action.command.join(" ");
    let (state, message, data) = if action.availability == ActionAvailability::NotAvailableYet {
        let data = match action.command.as_slice() {
            [command] if command == "up" => json!({"started": []}),
            [server, feature] if server == "server" && feature == "features" => {
                json!({"features": []})
            }
            _ => json!({}),
        };
        (
            CommandState::Unavailable,
            format!("The {command} command is not available yet."),
            data,
        )
    } else {
        (
            CommandState::Failed,
            format!("The {command} command has no handler in this build."),
            json!({}),
        )
    };
    print_result(
        &CommandResult::new(command, state, message, data)
            .with_next_step("Run `infraternal status` to review this node's current components."),
        json_output,
        state == CommandState::Failed,
    );
    if state == CommandState::Unavailable {
        ExitCode::from(2)
    } else {
        ExitCode::FAILURE
    }
}

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
    run_server_foreground(args, &runtime, json_output)
}

fn server_configuration_was_supplied(matches: &ArgMatches) -> bool {
    [
        "listen",
        "data",
        "public_origin",
        "web_root",
        "tls_cert",
        "tls_key",
    ]
    .iter()
    .any(|name| matches.get_one::<String>(name).is_some())
        || matches.get_flag("behind_proxy")
        || matches.get_many::<String>("trusted_proxy").is_some()
}

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
    Ok(ServerArgs {
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
    if let Err(error) = confirm_server_setup(yes, dry_run, args.listen, &args.data) {
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
    let install_args = InstallArgs {
        system: false,
        user: true,
        dry_run,
        force: matches.get_flag("force"),
        name: name.clone(),
    };
    install_server("server init", &args, &install_args, json_output)
}

fn confirm_server_setup(
    yes: bool,
    dry_run: bool,
    listen: SocketAddr,
    data_dir: &Path,
) -> Result<(), String> {
    if yes || dry_run {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err("pass --yes in non-interactive mode, or use --dry-run first".to_owned());
    }
    print!(
        "Create and start the user server service on {listen} with data in {}? [y/N] ",
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
            print_result(
                &CommandResult::new(
                    "server setup-token",
                    CommandState::Ready,
                    "A one-time setup capability is available.",
                    json!({"token": token}),
                ),
                json_output,
                false,
            );
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

fn run_server_foreground(
    args: ServerArgs,
    runtime: &tokio::runtime::Runtime,
    json_output: bool,
) -> ExitCode {
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
    match runtime.block_on(infraternal_server::serve(config)) {
        Ok(()) => {
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
        Err(error) => report_failure(
            "server",
            "The server stopped after an error.",
            error.to_string(),
            json_output,
        ),
    }
}

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
    let uid = matches.get_one::<u32>("uid").copied().unwrap_or_default();
    let cols = matches.get_one::<u16>("cols").copied().unwrap_or(80);
    let rows = matches.get_one::<u16>("rows").copied().unwrap_or(24);
    let state = matches.get_one::<String>("state").map(PathBuf::from);
    let detach = matches.get_flag("detach");
    let ring_capacity = matches
        .get_one::<usize>("ring_capacity")
        .copied()
        .unwrap_or(8 * 1024 * 1024);
    match run_shim(session, uid, cols, rows, state, detach, ring_capacity) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("shim startup/session failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn report_failure(command: &str, message: &str, details: String, json_output: bool) -> ExitCode {
    print_result(
        &CommandResult::new(command, CommandState::Failed, message, json!({}))
            .with_details(details),
        json_output,
        true,
    );
    ExitCode::FAILURE
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

#[cfg(unix)]
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

#[cfg(not(unix))]
async fn read_setup_token(_data_dir: &Path) -> Result<String, &'static str> {
    Err("local token retrieval requires a Unix socket")
}

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

fn origin_for_listener(listen: SocketAddr) -> String {
    let host = if listen.ip().is_loopback() {
        "localhost".to_owned()
    } else {
        listen.ip().to_string()
    };
    format!("https://{host}:{}", listen.port())
}

#[cfg(all(test, unix))]
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
#[allow(clippy::too_many_arguments)]
fn run_shim(
    session: &str,
    uid: u32,
    cols: u16,
    rows: u16,
    state: Option<PathBuf>,
    detach: bool,
    ring_capacity: usize,
) -> std::io::Result<()> {
    if session.len() != 32 || !session.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "session must be 32 hexadecimal characters",
        ));
    }
    let mut id = [0; 16];
    for (index, value) in id.iter_mut().enumerate() {
        *value = u8::from_str_radix(&session[index * 2..index * 2 + 2], 16)
            .map_err(std::io::Error::other)?;
    }
    if detach && !infraternal_shim::detach()? {
        return Ok(());
    }
    infraternal_shim::run(infraternal_shim::Config {
        session: id,
        uid,
        cols,
        rows,
        state,
        ring_capacity,
    })
}
