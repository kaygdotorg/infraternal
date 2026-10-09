//! Defines the process entry point and dispatches public commands through shared output.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

mod cli;
mod install;

use std::{
    io::{self, IsTerminal, Write},
    net::SocketAddr,
    path::PathBuf,
    process::ExitCode,
};

use clap::{Args, Parser, Subcommand};
use cli::output::{CommandResult, CommandState, RenderOptions, render_json, render_pretty};
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Parser)]
#[command(name = "infraternal")]
struct Cli {
    /// Print the stable, versioned JSON result envelope.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the trusted control plane.
    Server(ServerArgs),
    /// Run the per-host infraternal agent.
    Agent {
        /// Trusted socketpair inherited from the spawning server.
        #[arg(long)]
        fd: Option<i32>,
        /// Override the private runtime state directory.
        #[arg(long)]
        state: Option<std::path::PathBuf>,
    },
    /// Internal session owner; not a public CLI interface.
    #[command(name = "__shim", hide = true)]
    Shim {
        #[arg(long)]
        session: String,
        #[arg(long)]
        uid: u32,
        #[arg(long, default_value_t = 80)]
        cols: u16,
        #[arg(long, default_value_t = 24)]
        rows: u16,
        #[arg(long)]
        state: Option<std::path::PathBuf>,
        #[arg(long)]
        detach: bool,
        #[arg(long, default_value_t = 8 * 1024 * 1024)]
        ring_capacity: usize,
    },
}

#[derive(Debug, Args)]
struct ServerArgs {
    /// HTTP(S) listener address.
    #[arg(long, default_value = "127.0.0.1:7443", global = true)]
    listen: SocketAddr,
    /// Private data directory; SQLite is stored in infraternal.sqlite inside it.
    #[arg(long, default_value = "./data", global = true)]
    data: PathBuf,
    /// Public HTTPS origin seen by the browser and passkey authenticator.
    #[arg(long, global = true)]
    public_origin: Option<String>,
    /// Directory containing the built web application.
    #[arg(long, global = true)]
    web_root: Option<PathBuf>,
    /// PEM certificate chain for a standalone HTTPS listener.
    #[arg(long, global = true, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// PEM private key for a standalone HTTPS listener.
    #[arg(long, global = true, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Serve HTTP behind a TLS-terminating reverse proxy.
    #[arg(long, global = true)]
    behind_proxy: bool,
    /// Explicit trusted reverse proxy peer address or CIDR; repeat for a proxy chain.
    #[arg(long = "trusted-proxy", global = true)]
    trusted_proxies: Vec<infraternal_server::ProxyNetwork>,
    /// Optional server service installer.
    #[command(subcommand)]
    action: Option<ServerAction>,
}

#[derive(Debug, Subcommand)]
enum ServerAction {
    /// Write and enable a systemd unit for this server configuration.
    Install(InstallArgs),
    /// Print the initial owner setup capability through the private local control socket.
    SetupToken,
}

#[derive(Debug, Args)]
// Clap exposes these independent switches directly because they map to distinct systemd operations.
#[allow(clippy::struct_excessive_bools)]
struct InstallArgs {
    /// Install a system service (default is a user service).
    #[arg(long, conflicts_with = "user")]
    system: bool,
    /// Install a user service.
    #[arg(long)]
    user: bool,
    /// Print the unit and systemctl commands without writing or enabling it.
    #[arg(long)]
    dry_run: bool,
    /// Replace a different unit already at the target path.
    #[arg(long)]
    force: bool,
    /// Installed unit basename, without the `.service` suffix.
    #[arg(long, default_value = "infraternal-server")]
    name: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Server(args) => run_server(args, cli.json),
        Command::Shim {
            session,
            uid,
            cols,
            rows,
            state,
            detach,
            ring_capacity,
        } => match run_shim(&session, uid, cols, rows, state, detach, ring_capacity) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("shim startup/session failed: {error}");
                ExitCode::from(1)
            }
        },
        Command::Agent { fd, state } => {
            let Some(fd) = fd else {
                print_result(
                    &CommandResult::new(
                        "agent",
                        CommandState::Unavailable,
                        "The infraternal agent needs a server connection to start.",
                        json!({}),
                    )
                    .with_next_step(
                        "Use `infraternal agent up` when component setup is available.",
                    ),
                    cli.json,
                    false,
                );
                return ExitCode::from(2);
            };
            match infraternal_agent::run_embedded(fd, state) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    print_result(
                        &CommandResult::new(
                            "agent",
                            CommandState::Failed,
                            "The infraternal agent could not start.",
                            json!({}),
                        )
                        .with_details(error.to_string()),
                        cli.json,
                        true,
                    );
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn run_server(args: ServerArgs, json_output: bool) -> ExitCode {
    // Keep the unconfigured server stub useful while allowing the global output switch either
    // before or after the command name.
    if args.action.is_none()
        && std::env::args_os()
            .filter(|argument| argument.to_str() != Some("--json"))
            .count()
            == 2
    {
        print_result(
            &CommandResult::new(
                "server",
                CommandState::Unavailable,
                "The server is not configured yet.",
                json!({}),
            )
            .with_next_step("Run `infraternal server init` to configure a server."),
            json_output,
            false,
        );
        return ExitCode::from(2);
    }
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        print_result(
            &CommandResult::new(
                "server",
                CommandState::Failed,
                "The server could not start its async runtime.",
                json!({}),
            ),
            json_output,
            true,
        );
        return ExitCode::FAILURE;
    };
    match args.action.as_ref() {
        Some(ServerAction::Install(install_args)) => {
            run_server_install(&args, install_args, json_output)
        }
        Some(ServerAction::SetupToken) => run_setup_token(&runtime, &args.data, json_output),
        None => run_server_foreground(args, &runtime, json_output),
    }
}

fn run_server_install(
    args: &ServerArgs,
    install_args: &InstallArgs,
    json_output: bool,
) -> ExitCode {
    match install::install(args, install_args) {
        Ok(message) => {
            print_result(
                &CommandResult::new(
                    "server install",
                    CommandState::Ready,
                    if install_args.dry_run {
                        "The server installation plan is ready."
                    } else {
                        "The server service was installed and enabled."
                    },
                    json!({"plan": message}),
                ),
                json_output,
                false,
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_result(
                &CommandResult::new(
                    "server install",
                    CommandState::Failed,
                    "The server service could not be installed.",
                    json!({}),
                )
                .with_details(error.to_string()),
                json_output,
                true,
            );
            ExitCode::FAILURE
        }
    }
}

fn run_setup_token(
    runtime: &tokio::runtime::Runtime,
    data_dir: &std::path::Path,
    json_output: bool,
) -> ExitCode {
    match runtime.block_on(read_setup_token(data_dir)) {
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
        Err(error) => {
            print_result(
                &CommandResult::new(
                    "server setup-token",
                    CommandState::Failed,
                    "The setup capability is not available.",
                    json!({}),
                )
                .with_details(error),
                json_output,
                true,
            );
            ExitCode::FAILURE
        }
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
            print_result(
                &CommandResult::new(
                    "server",
                    CommandState::Failed,
                    "The server configuration is invalid.",
                    json!({}),
                )
                .with_details(error),
                json_output,
                true,
            );
            return ExitCode::from(2);
        }
    };
    match runtime.block_on(infraternal_server::serve(config)) {
        Ok(()) => {
            print_result(
                &CommandResult::new(
                    "server",
                    CommandState::Stopped,
                    "The server stopped normally.",
                    json!({}),
                ),
                json_output,
                false,
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            print_result(
                &CommandResult::new(
                    "server",
                    CommandState::Failed,
                    "The server stopped after an error.",
                    json!({}),
                )
                .with_details(error.to_string()),
                json_output,
                true,
            );
            ExitCode::FAILURE
        }
    }
}

fn print_result<T: Serialize>(result: &CommandResult<T>, json_output: bool, to_stderr: bool) {
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
async fn read_setup_token(data_dir: &std::path::Path) -> Result<String, &'static str> {
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
async fn read_setup_token(_data_dir: &std::path::Path) -> Result<String, &'static str> {
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
    state: Option<std::path::PathBuf>,
    detach: bool,
    ring_capacity: usize,
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
    infraternal_shim::run(infraternal_shim::Config {
        session: id,
        uid,
        cols,
        rows,
        state,
        ring_capacity,
    })
}
