//! The open-file limit of the long-lived processes, and the people's shells
//! that must not inherit a raised one (#562).
//!
//! A host serving many terminals holds a few descriptors per session. The
//! common default soft `RLIMIT_NOFILE` of 1024 therefore ran out at about 500
//! sessions on a host, and opens failed with `resource_unavailable`. The server
//! and the infraternal agent raise their own soft limit to the hard one at
//! startup ([`raise_open_file_limit`]).
//!
//! The raise must stay ours. `select()`-based programs in a person's shell
//! break above descriptor 1023, so every program these processes start gets the
//! soft limit the process was *started* with: [`restore_in_child`] is a
//! `pre_exec` step of [`crate::prepare_child`], and [`with_launcher_limit`]
//! wraps an in-place restart. Session shims are started that way, so they and
//! the shells they exec run with the original limit. This is the same pattern
//! as the transparent-huge-page policy of #522.
//!
//! The embedded infraternal agent is started with `posix_spawn`, which cannot
//! change limits. The server hands it the original through
//! [`HANDOFF_ENV`]; the agent takes the variable out of its environment at
//! startup, so no shell ever sees it.

#![allow(unsafe_code)]

use std::io;
use std::sync::OnceLock;

use nix::libc::{RLIM_INFINITY, RLIMIT_NOFILE, getrlimit, rlim_t, rlimit, setrlimit};

/// The environment variable that carries the original soft limit from the
/// server to its embedded infraternal agent. Read once by
/// [`raise_open_file_limit`], and removed from the environment there.
pub const HANDOFF_ENV: &str = "INFRATERNAL_LAUNCHER_NOFILE";

/// The soft limit this process was started with, set by the first
/// [`raise_open_file_limit`]. Unset in processes that never raise it: their
/// children simply inherit the limit they run with.
static LAUNCHER_SOFT: OnceLock<rlim_t> = OnceLock::new();

/// Read this process's `RLIMIT_NOFILE`.
fn current() -> io::Result<rlimit> {
    let mut limit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit to the live pointer given.
    if unsafe { getrlimit(RLIMIT_NOFILE, &raw mut limit) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(limit)
}

/// Set only the soft `RLIMIT_NOFILE`, keeping the hard limit.
fn set_soft(soft: rlim_t, hard: rlim_t) -> io::Result<()> {
    let limit = rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: setrlimit copies the live, initialized record.
    if unsafe { setrlimit(RLIMIT_NOFILE, &raw const limit) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The soft limit this process was started with, once
/// [`raise_open_file_limit`] has recorded it. The server passes it to its
/// embedded infraternal agent through [`HANDOFF_ENV`].
#[must_use]
pub fn launcher_soft_limit() -> Option<u64> {
    LAUNCHER_SOFT.get().copied()
}

/// Raise this process's soft open-file limit as far as the kernel allows, up
/// to the hard limit, after recording the soft limit it was started with.
/// Returns the new soft limit.
///
/// Call it first thing in the server and infraternal agent roles, while the
/// process is still single-threaded (it also removes [`HANDOFF_ENV`] from the
/// environment). Shims and other short-lived roles do not call it. Only the
/// first call records, so a role that re-enters its startup keeps the
/// launcher's value.
///
/// An unlimited hard limit, or one above what the kernel will grant (`fs.nr_open`
/// on Linux, `kern.maxfilesperproc` on macOS), is not an error: the highest
/// value of a short list that the kernel accepts is used instead.
/// # Errors
/// Returns the kernel's refusal when the limit can't be read or no step up is
/// accepted; the process then keeps its current limit.
pub fn raise_open_file_limit() -> io::Result<u64> {
    let limit = current()?;
    let handed_down = std::env::var(HANDOFF_ENV)
        .ok()
        .and_then(|value| value.parse::<rlim_t>().ok());
    // SAFETY: startup is single-threaded (documented above), so nothing reads
    // the environment while it changes.
    unsafe { std::env::remove_var(HANDOFF_ENV) };
    // A handed-down value is trusted only if it is a limit this process could
    // have been started with: never above its hard limit.
    let original = handed_down
        .filter(|soft| *soft <= limit.rlim_max)
        .unwrap_or(limit.rlim_cur);
    let _ = LAUNCHER_SOFT.set(original);
    // 2^20 is the kernel's default `fs.nr_open`; 10240 is macOS's usual
    // `kern.maxfilesperproc` ceiling.
    let candidates = [limit.rlim_max, 1 << 20, 1 << 16, 10_240, 4_096];
    for soft in candidates {
        if soft <= limit.rlim_cur || soft > limit.rlim_max {
            continue;
        }
        if soft != RLIM_INFINITY && set_soft(soft, limit.rlim_max).is_ok() {
            return Ok(soft);
        }
    }
    Ok(limit.rlim_cur)
}

/// A `pre_exec` step: give the program about to be started the soft limit
/// this process was started with. A no-op when nothing was recorded, and when
/// the original is above the hard limit it never lowers below what is allowed.
///
/// Uses only `getrlimit` and `setrlimit`, which are async-signal-safe, so it
/// may run between `fork` and `exec`.
pub(crate) fn restore_in_child() -> io::Result<()> {
    let Some(original) = LAUNCHER_SOFT.get().copied() else {
        return Ok(());
    };
    let limit = current()?;
    if limit.rlim_cur == original {
        return Ok(());
    }
    set_soft(original.min(limit.rlim_max), limit.rlim_max)
}

/// Run `exec`, which replaces this process's image, with the launcher's soft
/// limit in place so the new image records the original and not our raise. If
/// `exec` returns (the kernel refused the image), this process's own raised
/// limit is put back before the result is returned. Without a record, `exec`
/// just runs.
///
/// Errors while switching are ignored: the new image then starts with the
/// current limit, which is the behaviour without a record.
#[cfg(target_os = "linux")]
pub(crate) fn with_launcher_limit<T>(exec: impl FnOnce() -> T) -> T {
    let Some(original) = LAUNCHER_SOFT.get().copied() else {
        return exec();
    };
    let Ok(own) = current() else {
        return exec();
    };
    let _ = set_soft(original.min(own.rlim_max), own.rlim_max);
    let result = exec();
    let _ = set_soft(own.rlim_cur, own.rlim_max);
    result
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    //! The raise is the server's and agent's own; started programs keep the
    //! limit their launcher had.
    use super::*;
    use std::os::unix::process::CommandExt as _;
    use std::process::Command;

    /// Set in the environment of [`raised_limit_fixture`]'s fresh process: the
    /// soft limit it is started with.
    const FIXTURE: &str = "INFRATERNAL_NOFILE_FIXTURE";

    /// What a started `/bin/sh` reports for `ulimit -Sn`.
    fn shell_limit(mut command: Command) -> u64 {
        let output = command.args(["-c", "ulimit -Sn"]).output().unwrap();
        String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    /// Body of [`servers_raise_and_their_shells_keep_the_original`], run in a
    /// fresh copy of the test binary: the limit is process-wide, and the
    /// record is a once-only static. Without the fixture variable it does
    /// nothing.
    #[test]
    fn raised_limit_fixture() {
        let Ok(started_with) = std::env::var(FIXTURE) else {
            return;
        };
        let started_with: rlim_t = started_with.parse().unwrap();
        let before = current().unwrap();
        assert_eq!(before.rlim_cur, started_with);
        let raised = raise_open_file_limit().unwrap();
        assert!(
            raised > started_with,
            "raised {raised} from {started_with}: hard limit {}",
            before.rlim_max
        );
        assert_eq!(current().unwrap().rlim_cur, raised);
        assert_eq!(launcher_soft_limit(), Some(started_with));
        // A second call keeps the launcher's value.
        raise_open_file_limit().unwrap();
        assert_eq!(launcher_soft_limit(), Some(started_with));
        // A plain child inherits the raise; a prepared child (how shims, and
        // through them every shell, start) sees the original.
        assert_eq!(shell_limit(Command::new("/bin/sh")), raised);
        let mut prepared = Command::new("/bin/sh");
        crate::prepare_child(&mut prepared);
        assert_eq!(shell_limit(prepared), started_with);
        let during_exec = with_launcher_limit(|| current().unwrap().rlim_cur);
        assert_eq!(during_exec, started_with, "the new image starts original");
        assert_eq!(
            current().unwrap().rlim_cur,
            raised,
            "a refused exec keeps the raise"
        );
    }

    /// The server and the infraternal agent get past 1,024 descriptors, but a
    /// person's shell started under them still reads the original `ulimit -n`
    /// (#562).
    #[test]
    fn servers_raise_and_their_shells_keep_the_original() {
        let hard = current().unwrap().rlim_max;
        if hard <= 2048 {
            // The raise has nowhere to go: nothing to prove on this runner.
            return;
        }
        let mut fixture = Command::new(std::env::current_exe().unwrap());
        fixture
            .args([
                "--exact",
                "open_files::tests::raised_limit_fixture",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(FIXTURE, "1024");
        // SAFETY: one setrlimit syscall on a live record; no allocation or
        // lock after fork.
        unsafe {
            fixture.pre_exec(move || set_soft(1024, hard));
        }
        let output = fixture.output().unwrap();
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// The embedded infraternal agent, started by `posix_spawn`, learns the
    /// original from [`HANDOFF_ENV`], and the variable does not stay in its
    /// environment.
    #[test]
    fn the_embedded_agent_takes_the_original_from_its_server() {
        let hard = current().unwrap().rlim_max;
        if hard <= 4096 {
            return;
        }
        if std::env::var_os(FIXTURE).is_some() {
            let raised = raise_open_file_limit().unwrap();
            assert!(raised > 1024);
            assert_eq!(launcher_soft_limit(), Some(1024), "the server's original");
            assert!(std::env::var_os(HANDOFF_ENV).is_none(), "taken out");
            return;
        }
        let mut fixture = Command::new(std::env::current_exe().unwrap());
        fixture
            .args([
                "--exact",
                "open_files::tests::the_embedded_agent_takes_the_original_from_its_server",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(FIXTURE, "raise")
            // The server already raised to 2048; the agent starts there.
            .env(HANDOFF_ENV, "1024");
        // SAFETY: as above.
        unsafe {
            fixture.pre_exec(move || set_soft(2048, hard));
        }
        let output = fixture.output().unwrap();
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
