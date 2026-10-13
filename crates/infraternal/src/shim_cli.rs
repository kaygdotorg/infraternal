//! Shares the internal shim startup schema and identity checks across executable build profiles (D13, D255).

pub(crate) const PAYLOAD_ONLY: bool = cfg!(all(
    feature = "session-payload",
    not(any(
        feature = "server",
        feature = "remote",
        feature = "mesh",
        feature = "plugin-host-facts"
    ))
));
const RING_CAPACITY: usize = 8 * 1024 * 1024;
const EXIT_RETENTION_MS: u64 = 600_000;

/// One option record supplies the full CLI and the private session payload.
#[derive(Debug, clap::Args)]
pub(crate) struct Options {
    #[arg(long)]
    pub(crate) session: String,
    #[arg(long)]
    pub(crate) uid: u32,
    #[arg(long, default_value_t = 80)]
    pub(crate) cols: u16,
    #[arg(long, default_value_t = 24)]
    pub(crate) rows: u16,
    #[arg(long)]
    pub(crate) state: Option<std::path::PathBuf>,
    #[arg(long)]
    pub(crate) detach: bool,
    #[arg(long, default_value_t = RING_CAPACITY)]
    pub(crate) ring_capacity: usize,
    /// Internal test/startup override, clamped to the production ceiling.
    #[arg(long, default_value_t = EXIT_RETENTION_MS)]
    pub(crate) exit_retention_ms: u64,
    /// Private fixed-command readiness probe; never reads login startup.
    #[arg(long)]
    pub(crate) readiness: bool,
}

impl Options {
    /// Validate the session identifier before any fork or filesystem operation.
    pub(crate) fn run(self) -> std::io::Result<()> {
        let Self {
            session,
            uid,
            cols,
            rows,
            state,
            detach,
            ring_capacity,
            exit_retention_ms,
            readiness,
        } = self;

        let id = session_id(&session)?;
        if detach && !infraternal_shim::detach()? {
            return Ok(());
        }
        infraternal_shim::run_with_retention(
            infraternal_shim::Config {
                session: id,
                uid,
                cols,
                rows,
                state,
                ring_capacity,
                readiness,
            },
            std::time::Duration::from_millis(exit_retention_ms),
        )
    }
}

/// Decode only the exact invocation emitted by `sessions::launch_with_readiness`.
/// Operator argument permutations and test overrides stay with the full CLI;
/// the private release image must not link that unrelated command graph.
impl Options {
    pub(crate) fn spawned(arguments: &[std::ffi::OsString]) -> Option<Self> {
        let [
            session_flag,
            session,
            uid_flag,
            uid,
            cols_flag,
            cols,
            rows_flag,
            rows,
            state_flag,
            state,
            trailing @ ..,
        ] = arguments
        else {
            return None;
        };
        if session_flag != "--session"
            || uid_flag != "--uid"
            || cols_flag != "--cols"
            || rows_flag != "--rows"
            || state_flag != "--state"
        {
            return None;
        }
        let (readiness, detach) = match trailing {
            [] => (false, false),
            [flag] if flag == "--readiness" => (true, false),
            [flag] if flag == "--detach" => (false, true),
            [first, second] if first == "--readiness" && second == "--detach" => (true, true),
            _ => return None,
        };
        let session = session.to_str()?;
        session_id(session).ok()?;
        Some(Self {
            session: session.to_owned(),
            uid: number(uid)?,
            cols: number(cols)?,
            rows: number(rows)?,
            state: Some(state.into()),
            detach,
            readiness,
            ring_capacity: RING_CAPACITY,
            exit_retention_ms: EXIT_RETENTION_MS,
        })
    }
}

/// The launcher writes canonical unsigned decimal values; accepting another
/// spelling here would add an invocation shape the launcher never emits.
fn number<T: std::str::FromStr>(argument: &std::ffi::OsStr) -> Option<T> {
    let text = argument.to_str()?;
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse().ok()
}

fn session_id(session: &str) -> std::io::Result<[u8; 16]> {
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
    Ok(id)
}

/// SSH entrypoints are dispatched first through their existing implementations.
/// This final private route can only start the shim using its shared runner.
pub(crate) fn payload_entry() -> std::process::ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().is_none_or(|command| command != "__shim") {
        return crate::output::refuse(
            false,
            "internal.session",
            "Invalid session startup command",
            "Use the full host build for operator commands.",
            2,
        );
    }
    let arguments: Vec<_> = arguments.collect();
    let Some(options) = Options::spawned(&arguments) else {
        return crate::output::refuse(
            false,
            "internal.shim",
            "Invalid session startup arguments",
            "Check the session configuration.",
            2,
        );
    };
    if options.run().is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        crate::output::refuse(
            false,
            "internal.shim",
            "Session startup failed",
            "Check the session configuration.",
            1,
        )
    }
}

#[cfg(test)]
#[path = "shim_cli_tests.rs"]
mod tests;
