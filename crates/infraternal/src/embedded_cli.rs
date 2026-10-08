//! Keeps trusted inherited-fd startup off the server/enrollment parser working set, sharing existing Clap flag validation [9][41], #78.

use clap::{Args, Parser};
use std::{ffi::OsString, path::PathBuf, process::ExitCode};

/// The same boot flags are flattened into both the public and inherited-fd parsers.
#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Trusted socketpair inherited from the spawning server.
    #[arg(long)]
    pub(crate) fd: Option<i32>,
    /// Override the private runtime state directory.
    #[arg(long)]
    pub(crate) state: Option<PathBuf>,
}

#[derive(Parser)]
#[command(name = "infraternal agent")]
struct Inherited {
    #[command(flatten)]
    options: Options,
}

fn requested(args: &[OsString]) -> bool {
    args.get(1).is_some_and(|arg| arg == "agent")
        && args.iter().skip(2).any(|arg| {
            arg == "--fd" || arg.as_encoded_bytes().starts_with(b"--fd=")
        })
        // Preserve the complete public help and operator modes. Only the
        // internal fd/state invocation takes the small parser path.
        && !args.iter().skip(2).any(|arg| {
            matches!(arg.to_str(), Some("--help" | "-h" | "--version" | "--data"))
                || arg.as_encoded_bytes().starts_with(b"--data=")
        })
}

/// Parse trusted embedded startup without constructing unrelated command trees.
/// Unknown options/actions still fail through the existing Clap engine; no
/// alternative parser or new descriptor ownership rule is introduced.
pub(crate) fn run_if_requested() -> Option<ExitCode> {
    let args: Vec<_> = std::env::args_os().collect();
    if !requested(&args) {
        return None;
    }
    let program = args.first()?.clone();
    let parsed =
        Inherited::try_parse_from(std::iter::once(program).chain(args.into_iter().skip(2)));
    let Ok(Inherited { options }) = parsed else {
        eprintln!("invalid infraternal agent startup arguments");
        return Some(ExitCode::from(2));
    };
    let Some(fd) = options.fd else {
        return Some(ExitCode::from(2));
    };
    Some(match infraternal_agent::run_embedded(fd, options.state) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("infraternal agent failed: {error}");
            ExitCode::FAILURE
        }
    })
}
