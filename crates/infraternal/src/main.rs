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
}

#[tokio::main]
async fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Server => {
            // Exercise the real auth constructor and router even while server startup is
            // unfinished. Static builds must link the verifier, SQLite and crypto [7,53].
            let result = async {
                let pool = sqlx::sqlite::SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect("sqlite::memory:")
                    .await?;
                let auth =
                    infraternal_server::auth::Auth::new(pool, "localhost", "https://localhost")
                        .await?;
                let _router = infraternal_server::auth::router(auth);
                Ok::<(), infraternal_server::auth::Error>(())
            }
            .await;
            if result.is_err() {
                eprintln!("auth initialization failed");
                return ExitCode::FAILURE;
            }
            eprintln!("not implemented");
            ExitCode::from(2)
        }
        Command::Agent => {
            eprintln!("not implemented");
            ExitCode::from(2)
        }
    }
}
