//! Shares shim configuration, exact private argv decoding and startup across signed executable images (D13, D255).

const RING_CAPACITY: usize = 8 * 1024 * 1024;
const EXIT_RETENTION_MS: u64 = 600_000;

/// One option record supplies the full CLI and the private session payload.
#[derive(Debug)]
#[cfg_attr(feature = "cli", derive(clap::Args))]
pub struct Options {
    #[cfg_attr(feature = "cli", arg(long))]
    pub session: String,
    #[cfg_attr(feature = "cli", arg(long))]
    pub uid: u32,
    #[cfg_attr(feature = "cli", arg(long, default_value_t = 80))]
    pub cols: u16,
    #[cfg_attr(feature = "cli", arg(long, default_value_t = 24))]
    pub rows: u16,
    #[cfg_attr(feature = "cli", arg(long))]
    pub state: Option<std::path::PathBuf>,
    #[cfg_attr(feature = "cli", arg(long))]
    pub detach: bool,
    #[cfg_attr(feature = "cli", arg(long, default_value_t = RING_CAPACITY))]
    pub ring_capacity: usize,
    /// Internal test/startup override, clamped to the production ceiling.
    #[cfg_attr(feature = "cli", arg(long, default_value_t = EXIT_RETENTION_MS))]
    pub exit_retention_ms: u64,
    /// Private fixed-command readiness probe; never reads login startup.
    #[cfg_attr(feature = "cli", arg(long))]
    pub readiness: bool,
}

impl Options {
    /// Validate the session identifier before any fork or filesystem operation.
    /// # Errors
    /// Returns identity, fork, PTY or private-state admission failures.
    pub fn run(self) -> std::io::Result<()> {
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
        if detach && !crate::detach()? {
            return Ok(());
        }
        crate::run_with_retention(
            crate::Config {
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
    #[must_use]
    pub fn spawned(arguments: &[std::ffi::OsString]) -> Option<Self> {
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
