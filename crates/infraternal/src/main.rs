//! Defines the single `infraternal server` and `infraternal agent` entry point [7][20].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "infraternal")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the trusted control plane.
    Server,
    /// Run the per-host infraternal agent.
    Agent,
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

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Server => {
            // A tokio runtime only for the server arm. main() stays synchronous on purpose:
            // the hidden __shim mode forks (double fork + setsid), and forking a process
            // that already runs a multi-threaded runtime is unsound.
            let Ok(runtime) = tokio::runtime::Runtime::new() else {
                eprintln!("could not start the async runtime");
                return ExitCode::FAILURE;
            };
            // Exercise the real auth constructor and router even while server startup is
            // unfinished. Static builds must link the verifier, SQLite and crypto [7,53].
            let result = runtime.block_on(async {
                let pool = sqlx::sqlite::SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect("sqlite::memory:")
                    .await?;
                let auth =
                    infraternal_server::auth::Auth::new(pool, "localhost", "https://localhost")
                        .await?;
                let _router = infraternal_server::auth::router(auth);
                Ok::<(), infraternal_server::auth::Error>(())
            });
            if result.is_err() {
                eprintln!("auth initialization failed");
                return ExitCode::FAILURE;
            }
            eprintln!("not implemented");
            ExitCode::from(2)
        }
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
        Command::Agent => {
            eprintln!("not implemented");
            ExitCode::from(2)
        }
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
