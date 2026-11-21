//! Private macOS entry that starts the desktop helper as the console user (D203 C2, #146).
//!
//! On a Mac enrolled with `infraternal up`, the infraternal agent is a root
//! `LaunchDaemon`. Screen capture and input belong to the person at the
//! screen: macOS grants them to an app in that person's login session. So the
//! root agent never captures. It starts a small per-user helper
//! (`infraternal-desktop-helper`) in the console user's session and talks to
//! it over one private socket. This module is the root half of that start;
//! the rest of the boundary is in the desktop plugin (`source_ipc`).
//!
//! **How the helper is started.** The agent runs
//! `/bin/launchctl asuser <uid> <this binary> __desktop-user --uid <uid> -- <helper> <args…>`
//! ([`command`]). `asuser` execs in place (same pid, same descriptors) and
//! moves the process into the person's launchd bootstrap and audit session.
//! This entry then runs as a fresh, single-threaded root process, and:
//!
//! 1. closes every descriptor above standard error, so nothing the root
//!    chain held reaches the helper. Standard input stays: it is the pipe
//!    that carries the helper's one-time token, which is never on disk or in
//!    argv;
//! 2. refuses unless `<uid>` is not root and still owns `/dev/console`, so a
//!    helper is never started for someone who is not at the screen;
//! 3. checks that the helper program is a root-owned file that no group or
//!    other user can write, in root-owned folders that no group or other user
//!    can write;
//! 4. joins the account's groups and drops to its gid and uid, and verifies
//!    that root cannot be regained (shared with the shell entry, D335). It
//!    does not call `setlogin`: it is not a session leader, and the session it
//!    shares with the daemon must keep its login name;
//! 5. checks its own audit record: the audit user must be the person and the
//!    session must have graphic access, which means it really is in the
//!    person's GUI login. With no GUI login (only the login window, or a
//!    plain SSH session) it refuses: capture needs one;
//! 6. builds the environment from a fixed list (home, names, a fixed PATH,
//!    the per-user temporary folder) plus two values the agent sets itself:
//!    the capture app's path and the capture-callback timeout. Nothing else
//!    from root's environment passes, including any `DYLD_*` variable;
//! 7. execs the helper.
//!
//! **What the helper can and cannot do.** It runs with only the console
//! user's rights. It holds no enrollment key, server connection or root file.
//! It reads commands from the root agent and answers with window lists,
//! geometry and encoded video of that person's own screen. The agent accepts
//! its socket only after the kernel peer checks in `source_ipc`. Another local
//! user cannot be started here (step 2). A different process of the same user
//! cannot pass for it: it never sees the token, and its code signature does
//! not match.

use crate::session_shell::{GRAPHIC_ACCESS, LAUNCHCTL, PATH};
use nix::unistd::{Uid, User};
use std::{
    ffi::{CString, OsStr, OsString},
    io,
    os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _, process::CommandExt as _},
    path::Path,
    process::Command,
};

/// The private argv verb; the parser accepts only the shape [`command`] emits.
pub const VERB: &str = "__desktop-user";
/// The device whose owner is the person at the screen: root while only the
/// login window shows.
const CONSOLE: &str = "/dev/console";
/// The variables the agent sets for the helper; every other one is dropped.
const PASSED: [&str; 2] = [
    "INFRATERNAL_DESKTOP_COMPANION",
    "SCREENCAPTUREKIT_COMPLETION_TIMEOUT_SECS",
];
/// The helper's argv is short and fixed: program, folder and two flags.
const MAX_PROGRAM_ARGUMENTS: usize = 8;

/// The start of the command that places a program in `uid`'s GUI login as
/// that user. The caller appends the helper program and its arguments, sets
/// the [`PASSED`] variables and standard input, and spawns it.
///
/// # Errors
/// Refuses when this process is not root (a rootless agent is already the
/// person) or `uid` is root, and when the running binary cannot be named.
pub fn command(uid: u32) -> io::Result<Command> {
    if !Uid::effective().is_root() || uid == 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    // The entry runs as root before it drops privileges, so it is the binary
    // that is running this root agent, never a path from elsewhere.
    let executable = std::env::current_exe()?.canonicalize()?;
    let uid = uid.to_string();
    let mut command = Command::new(LAUNCHCTL);
    command
        .arg("asuser")
        .arg(&uid)
        .arg(executable)
        .args([VERB, "--uid", &uid, "--"]);
    command.env_clear();
    Ok(command)
}

/// Parsed private entry arguments.
#[derive(Debug, PartialEq, Eq)]
struct Request {
    uid: Uid,
    program: Vec<OsString>,
}

/// Decode the entry's private argv; `None` for any shape [`command`] never emits.
fn parse(arguments: &[OsString]) -> Option<Request> {
    let [uid_flag, uid, separator, program @ ..] = arguments else {
        return None;
    };
    if uid_flag != "--uid" || separator != "--" {
        return None;
    }
    let uid = uid.to_str()?;
    if uid.is_empty() || !uid.bytes().all(|b| b.is_ascii_digit()) || uid.starts_with('0') {
        return None;
    }
    let uid = Uid::from_raw(uid.parse().ok()?);
    if program.is_empty()
        || program.len() > MAX_PROGRAM_ARGUMENTS
        || program.iter().any(|argument| argument.is_empty())
    {
        return None;
    }
    Some(Request {
        uid,
        program: program.to_vec(),
    })
}

/// Run the private entry when argv selects it; never returns on success.
/// Call first in `main`, before any thread, runtime or allocation-heavy setup.
#[must_use]
pub fn run_if_requested() -> Option<std::process::ExitCode> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().is_none_or(|verb| verb != VERB) {
        return None;
    }
    let arguments: Vec<OsString> = arguments.collect();
    let error = match parse(&arguments) {
        Some(request) => match prepare(&request) {
            Ok(mut command) => command.exec(),
            Err(error) => error,
        },
        None => io::Error::from(io::ErrorKind::InvalidInput),
    };
    eprintln!("infraternal: the desktop helper could not start: {error}");
    Some(std::process::ExitCode::FAILURE)
}

/// Everything between entry and exec; see the module docs for each step.
fn prepare(request: &Request) -> io::Result<Command> {
    crate::pty::close_above_stderr()?;
    if !Uid::effective().is_root() || request.uid.is_root() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    if console_owner()? != request.uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the account is not at the screen",
        ));
    }
    let program = Path::new(&request.program[0]);
    trusted_program(program)?;
    let user = User::from_uid(request.uid)
        .map_err(io::Error::from)?
        .ok_or_else(|| io::Error::other("the account does not exist"))?;
    let name = CString::new(user.name.as_bytes()).map_err(|_| io::Error::other("invalid name"))?;
    crate::session_shell::drop_to_account(&name, user.uid, user.gid)?;
    let (audit_user, audit_flags) = crate::session_shell::audit_record()?;
    if !in_gui_login(request.uid, audit_user, audit_flags) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the account has no graphical login",
        ));
    }
    let mut command = Command::new(program);
    command.args(&request.program[1..]);
    let passed: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(key, _)| forwarded(key))
        .collect();
    command.env_clear();
    command.envs(passed);
    command
        .env("HOME", &user.dir)
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env("PATH", PATH);
    if let Some(directory) = crate::session_shell::darwin_user_temp_dir() {
        command.env("TMPDIR", directory);
    }
    // Never keep the daemon's working folder.
    std::env::set_current_dir("/")?;
    Ok(command)
}

/// The uid that owns the console device, which is the person at the screen.
fn console_owner() -> io::Result<Uid> {
    Ok(Uid::from_raw(std::fs::metadata(CONSOLE)?.uid()))
}

/// Whether the agent set this variable for the helper.
fn forwarded(key: &OsStr) -> bool {
    PASSED.iter().any(|name| key == *name)
}

/// After `launchctl asuser`, the entry must be in the person's own GUI login:
/// their audit user, with graphic access. A plain session (nobody logged in at
/// the screen) or someone else's session is refused.
fn in_gui_login(uid: Uid, audit_user: u32, flags: u64) -> bool {
    audit_user == uid.as_raw() && flags & GRAPHIC_ACCESS != 0
}

/// The helper must be an absolute regular file owned by root, with no group
/// or other write bit, in folders owned by root with no group or other write
/// bit. Then only root could have put it there, and the person cannot swap it.
fn trusted_program(path: &Path) -> io::Result<()> {
    let refuse = || io::Error::new(io::ErrorKind::PermissionDenied, "untrusted desktop helper");
    if !path.is_absolute() || path.as_os_str().as_bytes().contains(&b'\0') {
        return Err(refuse());
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(refuse());
    }
    for folder in path.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(folder)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(refuse());
        }
    }
    Ok(())
}

#[cfg(test)]
/// The entry's argv parser, environment allowlist, GUI-placement and program checks.
mod tests {
    use super::*;

    /// Arguments as `OsString`s, for the parser tests.
    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    /// The parser accepts exactly the shape `command` emits and refuses the rest.
    #[test]
    fn parser_accepts_only_the_emitted_shape() {
        assert_eq!(
            parse(&args(&["--uid", "501", "--", "/h", "/r", "--once"])),
            Some(Request {
                uid: Uid::from_raw(501),
                program: args(&["/h", "/r", "--once"]),
            })
        );
        for refused in [
            &["--uid", "501", "--"][..],
            &["--uid", "0501", "--", "/h"],
            &["--uid", "", "--", "/h"],
            &["--uid", "-1", "--", "/h"],
            &["--uid", "501", "/h"],
            &["--user", "501", "--", "/h"],
            &["--uid", "501", "--", ""],
            &[
                "--uid", "501", "--", "/h", "1", "2", "3", "4", "5", "6", "7", "8",
            ],
        ] {
            assert!(parse(&args(refused)).is_none(), "{refused:?}");
        }
    }

    /// Only the two values the agent sets pass; loader, shell and path
    /// variables from root's environment never reach the helper.
    #[test]
    fn only_the_agents_two_variables_are_forwarded() {
        for kept in PASSED {
            assert!(forwarded(OsStr::new(kept)), "{kept}");
        }
        for dropped in [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "PATH",
            "HOME",
            "TMPDIR",
            "INFRATERNAL_DESKTOP_MEASURE",
        ] {
            assert!(!forwarded(OsStr::new(dropped)), "{dropped}");
        }
    }

    /// Graphic access in the person's own audit session only.
    #[test]
    fn helpers_run_only_in_the_persons_gui_login() {
        let person = Uid::from_raw(1500);
        assert!(in_gui_login(person, 1500, 0x2030));
        assert!(!in_gui_login(person, 1500, 0x2020), "no graphic access");
        assert!(!in_gui_login(person, 501, 0x2030), "someone else's login");
        assert!(!in_gui_login(person, u32::MAX, 0x1), "the daemon's session");
    }

    /// A program the person could write or replace is refused.
    #[test]
    fn helper_program_must_be_root_owned_all_the_way_up() {
        assert!(trusted_program(Path::new("relative/helper")).is_err());
        // The test runs unprivileged, so its own temporary file is not root's.
        let directory = std::env::temp_dir().join(format!("du-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("helper");
        std::fs::write(&file, b"").unwrap();
        let refused = trusted_program(&file);
        std::fs::remove_dir_all(&directory).unwrap();
        assert!(refused.is_err());
        // A root-owned system program in root-owned folders passes.
        trusted_program(Path::new("/bin/ls")).unwrap();
    }

    /// The launch shape: `launchctl asuser`, this binary, the verb and uid.
    #[test]
    fn command_is_refused_without_root() {
        if !Uid::effective().is_root() {
            assert!(command(501).is_err());
        }
        assert!(command(0).is_err());
    }
}
