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
        Command::Server | Command::Agent => {
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
