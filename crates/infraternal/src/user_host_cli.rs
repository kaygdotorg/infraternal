//! Explicit research-only batch launch through the existing hidden shim action [D7/D268].
use crate::{ArgMatches, ExitCode, PathBuf, shim_integer};
use infraternal_shim::{Config, run_host_accounted};
use std::os::unix::fs::OpenOptionsExt;

/// Runs the batch session-host launch for the measuring mode of the hidden shim command.
///
/// Returns success when the hosts finish without error. On a startup problem it prints
/// `session host startup failed: <reason>` to standard error and returns failure.
pub(super) fn run(matches: &ArgMatches) -> ExitCode {
    match start(matches) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("session host startup failed: {error}");
            ExitCode::FAILURE
        }
    }
}
/// Validates the options, then runs `host_sessions` session hosts in this process.
///
/// Every session gets an id: the 128-bit hex `session` value plus its index, so one command
/// line names a whole contiguous batch. Real account shells are started, never the fixed
/// readiness canary, so `readiness` and `detach` are refused. The target `uid` must be the
/// current user: this mode cannot change login authority. When `host_accounting` is given, a
/// new file is created for it with owner-only access and an existing file is never overwritten.
///
/// Fails with `InvalidInput` for a count outside 1..=1000, a session id that is not 32 hex
/// digits, any unparsable number, or the refusals above, all before a terminal is created.
fn start(matches: &ArgMatches) -> std::io::Result<()> {
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidInput);
    let count: usize = shim_integer(matches, "host_sessions", None).map_err(|_| invalid())?;
    let session = matches.get_one::<String>("session").ok_or_else(invalid)?;
    if count == 0
        || count > 1000
        || session.len() != 32
        || !session.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    let origin = u128::from_str_radix(session, 16).map_err(|_| invalid())?;
    let mut config = Config::new(
        origin.to_be_bytes(),
        shim_integer(matches, "uid", None).map_err(|_| invalid())?,
    );
    config.cols = shim_integer(matches, "cols", Some(80)).map_err(|_| invalid())?;
    config.rows = shim_integer(matches, "rows", Some(24)).map_err(|_| invalid())?;
    config.ring_capacity =
        shim_integer(matches, "ring_capacity", Some(8 * 1024 * 1024)).map_err(|_| invalid())?;
    config.state = matches.get_one::<String>("state").map(PathBuf::from);
    // This mode measures real account shells, never the fixed readiness canary.
    if matches.get_flag("readiness") || matches.get_flag("detach") {
        return Err(invalid());
    }
    // Profiling cannot change login authority or overwrite an existing file.
    // No terminal content is recorded; failure here precedes PTY creation.
    if config.uid != nix::unistd::Uid::effective().as_raw() {
        return Err(invalid());
    }
    let accounting = matches
        .get_one::<String>("host_accounting")
        .map(|path| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
        })
        .transpose()?;
    let configs = (0..count)
        .map(|i| {
            let mut config = config.clone();
            config.session = origin.wrapping_add(i as u128).to_be_bytes();
            config
        })
        .collect();
    run_host_accounted(configs, accounting)
}
