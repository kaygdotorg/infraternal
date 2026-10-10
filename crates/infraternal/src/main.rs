//! Defines the single `infraternal server` and `infraternal agent` entry point [7][20].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

mod embedded_cli;
#[cfg(feature = "remote")]
mod host_remove;
mod install;
mod output;
#[cfg(feature = "remote")]
mod remote;
mod remote_server;
#[cfg(feature = "remote")]
mod restart;
#[cfg(feature = "ssh")]
mod ssh_askpass;

use std::{net::SocketAddr, path::PathBuf, process::ExitCode};

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "infraternal")]
struct Cli {
    /// Print machine-readable result records.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print one compiled plugin action as step-by-step instructions.
    Skill { action: String },
    #[cfg(feature = "remote")]
    #[command(about=infraternal_plugin_remote::REMOVE.summary, long_about=infraternal_plugin_remote::REMOVE.help())]
    RemoveHost {
        host: uuid::Uuid,
        #[arg(long)]
        server: String,
        /// Complete a previously issued fresh passkey challenge using private stdin.
        #[arg(long)]
        finish: bool,
        /// Revoke server access while keeping the installation on the host.
        #[arg(long)]
        retain: bool,
    },
    /// Run the trusted control plane.
    Server(ServerArgs),
    /// Run the per-host infraternal agent.
    Agent {
        #[command(flatten)]
        boot: embedded_cli::Options,
        /// Persistent enrolled identity directory (XDG by default).
        #[arg(long)]
        data: Option<PathBuf>,
        /// Operator/bootstrap actions; users enroll through the server UI later [132].
        #[command(subcommand)]
        action: Option<AgentAction>,
    },
    #[cfg(feature = "ssh")]
    /// Internal OpenSSH prompt responder; stdout is the private credential pipe.
    #[command(name = "__ssh-askpass", hide = true)]
    SshAskpass,
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

#[derive(Debug, Subcommand)]
enum AgentAction {
    /// Redeem a private-stdin invitation over pinned HTTPS, then connect.
    #[cfg_attr(feature = "remote", command(about = infraternal_plugin_remote::JOIN.summary, long_about = infraternal_plugin_remote::JOIN.help()))]
    Join {
        url: String,
        /// Save the joined identity and return so a service can start it.
        #[arg(long)]
        enroll_only: bool,
    },
    /// Reconnect using the local enrolled identity.
    #[cfg_attr(feature = "remote", command(about = infraternal_plugin_remote::RUN.summary, long_about = infraternal_plugin_remote::RUN.help()))]
    Run,
}

#[derive(Debug, Args)]
struct ServerArgs {
    #[command(flatten)]
    remote: remote_server::Options,
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
    #[cfg(feature = "remote")]
    #[command(about = infraternal_plugin_remote::RESTART.summary, long_about = infraternal_plugin_remote::RESTART.help())]
    Restart(restart::Options),
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

fn run_skill(action: &str, json: bool) -> ExitCode {
    let definition = infraternal_server::compiled_plugins()
        .iter()
        .flat_map(|plugin| plugin.actions)
        .find(|definition| definition.id == action);
    if let Some(definition) = definition {
        output::report(
            json,
            definition.id,
            "instructions",
            &definition.help(),
            "Follow the declared action steps.",
        );
        ExitCode::SUCCESS
    } else {
        output::refuse(
            json,
            "skill",
            "This action is not available in this build",
            "Inspect the compiled plugin actions.",
            1,
        )
    }
}

fn main() -> ExitCode {
    // Installation slots and symlinks must not rename the daemon or its shims
    // in ps/journald. Apply before the embedded dispatcher bypasses clap.
    #[cfg(target_os = "linux")]
    if nix::sys::prctl::set_name(c"infraternal").is_err() {
        return ExitCode::FAILURE;
    }
    #[cfg(feature = "remote")]
    if let Some(result) = remote::uninstall_if_requested() {
        return result;
    }
    if let Some(result) = embedded_cli::run_if_requested() {
        return result;
    }
    let requested_json = std::env::args_os().any(|argument| argument == "--json");
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if requested_json
                && !matches!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                ) =>
        {
            return output::refuse(
                true,
                "cli",
                "Invalid command arguments",
                "Read the command help and retry.",
                2,
            );
        }
        Err(error) => error.exit(),
    };
    let json = cli.json;
    match cli.command {
        Command::Skill { action } => run_skill(&action, json),
        #[cfg(feature = "remote")]
        Command::RemoveHost {
            host,
            server,
            finish,
            retain,
        } => host_remove::run(&server, host, finish, retain, json),
        Command::Server(args) => {
            infraternal_server::configure_logging(json);
            run_server(args, json)
        }
        #[cfg(feature = "ssh")]
        Command::SshAskpass => ssh_askpass::run(),
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
            Err(_) => output::refuse(
                json,
                "internal.shim",
                "Session startup failed",
                "Check the session configuration.",
                1,
            ),
        },
        Command::Agent { boot, data, action } => {
            let embedded_cli::Options { fd, state } = boot;
            if let Some(action) = action {
                return run_remote_agent(action, fd, state, data, json);
            }
            let Some(fd) = fd else {
                if json {
                    return output::refuse(
                        true,
                        "agent.embedded",
                        "No infraternal agent mode selected",
                        "Select an infraternal agent component or enrollment action.",
                        2,
                    );
                }
                eprintln!("not implemented");
                return ExitCode::from(2);
            };
            match infraternal_agent::run_embedded(fd, state) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => output::refuse(
                    json,
                    "agent.embedded",
                    "Infraternal agent failed",
                    "Check the inherited channel and private session storage.",
                    1,
                ),
            }
        }
    }
}

/// Dispatch the configured server with one presentation mode for results and logs.
fn run_server(mut args: ServerArgs, json: bool) -> ExitCode {
    if args.action.is_none() && std::env::args_os().len() == 2 {
        eprintln!("not implemented");
        return ExitCode::from(2);
    }
    let action = args.remote.action_id();
    // Only the server arm constructs a multi-threaded runtime: shim dispatch must remain synchronous before fork.
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        return output::refuse(
            json,
            action,
            "Could not start the async runtime",
            "Check local runtime resources.",
            1,
        );
    };
    match args.action.as_ref() {
        Some(ServerAction::Install(options)) => match install::install(&args, options) {
            Ok(message) => {
                if json {
                    output::report(
                        true,
                        "server.install",
                        "completed",
                        &message,
                        "Review the installed service configuration.",
                    );
                } else {
                    print!("{message}");
                }
                ExitCode::SUCCESS
            }
            Err(_) => output::refuse(
                json,
                "server.install",
                "Server installation failed",
                "Check the service name and installation target.",
                1,
            ),
        },
        Some(ServerAction::SetupToken) => match runtime.block_on(read_setup_token(&args.data)) {
            Ok(token) => {
                // This explicit local capability retrieval retains the private-socket output contract.
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"action": "server.setup-token", "state": "ready", "setup_token": token})
                    );
                } else {
                    println!("{token}");
                }
                ExitCode::SUCCESS
            }
            Err(_) => output::refuse(
                json,
                "server.setup-token",
                "Setup capability unavailable",
                "Check that the existing server is awaiting first-owner setup.",
                1,
            ),
        },
        #[cfg(feature = "remote")]
        Some(ServerAction::Restart(options)) => restart::run(&runtime, &args.data, options, json),
        None => {
            let options = std::mem::take(&mut args.remote);
            let config = match server_config(args) {
                Ok(config) => config,
                Err(message) => {
                    return output::refuse(json, action, &message, "Check listener and TLS.", 2);
                }
            };
            output::report(
                json,
                action,
                "starting",
                "Preparing the configured server",
                "Check the configured listener and retained public trust.",
            );
            match runtime.block_on(remote_server::serve(config, options)) {
                Ok(remote_server::Outcome::Stopped) => {
                    output::report(
                        json,
                        action,
                        "stopped",
                        "Server stopped",
                        "Start the configured server when needed.",
                    );
                    ExitCode::SUCCESS
                }
                #[cfg(feature = "remote")]
                Ok(remote_server::Outcome::Restart(replacement)) => {
                    restart::replace(runtime, replacement, json)
                }
                Err(error) => output::refuse(
                    json,
                    action,
                    &error.to_string(),
                    "Check configuration and retained public server trust.",
                    1,
                ),
            }
        }
    }
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
        runtime.block_on(remote::run(&data, state))
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

/// A core-only node refuses remote activation before reading stdin or private identity.
#[cfg(not(feature = "remote"))]
fn run_remote_agent(
    action: AgentAction,
    _fd: Option<i32>,
    _state: Option<PathBuf>,
    _data: Option<PathBuf>,
    json: bool,
) -> ExitCode {
    let operation = match action {
        AgentAction::Join { .. } => "remote.host.join",
        AgentAction::Run => "remote.host.run",
    };
    drop(action);
    output::refuse(
        json,
        operation,
        "Remote support is unavailable in this build",
        "Use a build with the remote plugin enabled.",
        2,
    )
}
