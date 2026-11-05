//! Shares shim configuration, exact private argv decoding and startup across signed executable images (D13, D255).

const RING_CAPACITY: usize = 8 * 1024 * 1024;
const EXIT_RETENTION_MS: u64 = 600_000;

/// One option record supplies the full CLI and the private session payload.
#[derive(Debug)]
// This record mirrors independent private CLI switches, rather than runtime state.
#[allow(clippy::struct_excessive_bools)]
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
    /// Read literal program arguments from the private bounded startup pipe.
    #[cfg_attr(feature = "cli", arg(long))]
    pub command_stdin: bool,
    /// Keep automation output until the existing bounded exit deadline.
    #[cfg_attr(feature = "cli", arg(long))]
    pub retain_output: bool,
    /// The launch lifeline: an inherited pipe's write end that every process of the launch holds and
    /// that this shim holds for its whole life, never passing it to its shell (contracts/shim.md §2).
    #[cfg_attr(feature = "cli", arg(long))]
    pub lifeline_fd: Option<i32>,
}

impl Options {
    /// Validate the session identifier before any fork or filesystem operation.
    /// # Errors
    /// Returns identity, fork, PTY or private-state admission failures.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
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
            command_stdin,
            retain_output,
            lifeline_fd,
        } = self;

        let id = session_id(&session)?;
        let command = if command_stdin {
            read_command()?
        } else {
            Vec::new()
        };
        if readiness && command_stdin {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        // Hold the lifeline before forking: the original launcher and the intermediate inherit it and let
        // go when they exit, and the session process keeps it until it exits. An absent descriptor fails
        // closed, because a shim running without it would make the launch's proof of death meaningless.
        if let Some(descriptor) = lifeline_fd {
            crate::hold_lifeline(descriptor)?;
        }
        if detach && !crate::detach()? {
            return Ok(());
        }
        let mut config = crate::Config::new(id, uid);
        config.cols = cols;
        config.rows = rows;
        config.state = state;
        config.ring_capacity = ring_capacity;
        config.readiness = readiness;
        config.command = command;
        config.retain_output = retain_output;
        crate::run_with_retention(config, std::time::Duration::from_millis(exit_retention_ms))
    }
}

/// Decode only the exact invocation emitted by `sessions::launch_with_readiness`.
/// Operator argument permutations and test overrides stay with the full CLI;
/// the private release image must not link that unrelated command graph.
impl Options {
    /// Decode the exact private invocation the launcher emits, or `None` for any other shape.
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
        // The launcher appends the lifeline pair last, so peel it off before the fixed shapes below.
        let (trailing, lifeline_fd) = match trailing {
            [rest @ .., flag, value] if flag == "--lifeline-fd" => (rest, Some(number(value)?)),
            _ => (trailing, None),
        };
        let retain_output = trailing
            .first()
            .is_some_and(|flag| flag == "--retain-output");
        let trailing = if retain_output {
            &trailing[1..]
        } else {
            trailing
        };
        let command_stdin = trailing
            .first()
            .is_some_and(|flag| flag == "--command-stdin");
        let trailing = if command_stdin {
            &trailing[1..]
        } else {
            trailing
        };
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
            command_stdin,
            retain_output,
            lifeline_fd,
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

/// NUL separators preserve empty arguments and literal metacharacters without a shell.
/// Bound before allocation; consume before detach closes the inherited pipe.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_command() -> std::io::Result<Vec<std::ffi::OsString>> {
    use std::{io::Read, os::unix::ffi::OsStringExt};
    let mut bytes = Vec::new();
    std::io::stdin().take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 || bytes.last() != Some(&0) || bytes.first() == Some(&0) {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    bytes.pop();
    Ok(bytes
        .split(|b| *b == 0)
        .map(|part| std::ffi::OsString::from_vec(part.to_vec()))
        .collect())
}
