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

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Server | Command::Agent => {
            eprintln!("not implemented");
            ExitCode::from(2)
        }
    }
}
