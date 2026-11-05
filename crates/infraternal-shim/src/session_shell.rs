//! Darwin shell placement and privilege drop for one PTY child [D13, D335, #328].
//!
//! On macOS a person's shell runs inside their own login session while they
//! are logged in (keychain, ssh-agent, privacy permissions), and is otherwise a
//! plain shell started by the root infraternal agent as their user (D335).
//!
//! The root shim cannot drop privileges inside its post-fork `pre_exec`:
//! `initgroups` resolves membership through Open Directory, which is not safe
//! after fork. So the shim's child only makes itself the PTY's session leader
//! and then execs a fixed private entry of the same binary
//! (`__session-shell`). That entry is a fresh single-threaded process, where
//! the documented calls are safe, and it:
//!
//! 1. closes every descriptor above standard error while still root, so
//!    nothing the root chain held reaches the shell, and checks that it is
//!    the session leader of its controlling PTY;
//! 2. records the login name (`setlogin`), joins the account's groups
//!    (`initgroups`), drops to the account's gid and uid, and verifies that
//!    root cannot be regained;
//! 3. builds the environment from a fixed allowlist, never from the root
//!    caller's environment as a whole, so no `DYLD_*` or other inherited
//!    variable reaches the shell;
//! 4. execs the login shell, the readiness probe or the literal program.
//!
//! **Placement.** A root shim always execs `/bin/launchctl asuser <uid>` in
//! front of the entry. `asuser` execs in place (same pid, same descriptors)
//! and moves the process into the person's launchd bootstrap and audit
//! session: their GUI login when they have one (keychain, ssh-agent, privacy
//! permissions), otherwise a fresh session whose audit user is the person, so
//! the shell is attributed to them and shares no session with the root daemon
//! (D335, #328 P2). Placement is then *verified* from the entry's own audit
//! record (`classify`): the audit user must be the person, and graphic access
//! tells the GUI login from a plain shell. `SSH_AUTH_SOCK` is taken from the
//! placed bootstrap only in the GUI case, and only when it names a socket the
//! account owns.
#![allow(unsafe_code)]

use nix::unistd::{self, Gid, Uid, User};
use std::{
    ffi::{CString, OsStr, OsString},
    io,
    os::unix::{
        ffi::{OsStrExt as _, OsStringExt as _},
        fs::{FileTypeExt as _, MetadataExt as _},
        process::CommandExt as _,
    },
    path::PathBuf,
    process::{Command, Stdio},
};

/// The private argv verb; the parser accepts only the shape `command` emits.
pub const VERB: &str = "__session-shell";
/// The system launchd control tool, by absolute path.
const LAUNCHCTL: &str = "/bin/launchctl";
/// The fixed readiness probe: wait for one line of input, then confirm.
const READINESS: &str = "read -r line; printf 'infraternal-ready\\n'";
// macOS shells rebuild PATH from /etc/paths through path_helper at login.
const PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
// The only variables the entry takes from its caller, the root shim, which
// sets each of them itself: TERM and COLORTERM are fixed terminal values,
// INFRATERNAL_SESSION is this terminal's marker. Locale variables (LANG, LC_*)
// come from the host's installed locales (locale.rs). Everything else is
// dropped, including ZDOTDIR: zsh would run startup code from a directory a
// root environment named (#328 P3-1). HOME, USER, LOGNAME, SHELL, PATH and
// TMPDIR are set from the account, and SSH_AUTH_SOCK only from a verified
// GUI login.
const PASSED: [&str; 3] = ["TERM", "COLORTERM", "INFRATERNAL_SESSION"];
// <bsm/audit.h>: AU_SESSION_FLAG_HAS_GRAPHIC_ACCESS.
const GRAPHIC_ACCESS: u64 = 0x10;
// <unistd.h>: _CS_DARWIN_USER_TEMP_DIR.
const USER_TEMP_DIR: nix::libc::c_int = 65537;
/// The literal program arrives on the entry's argv after `--`; the shim already
/// bounds it to 8 KiB (`startup::read_command`).
const MAX_PROGRAM: usize = 8192;

/// `auditinfo_addr_t` from <bsm/audit.h> (48 bytes; offsets checked on
/// macOS 26.5 arm64: auid 0, mask 4, termid 12, asid 36, flags 40).
#[repr(C)]
struct AuditInfo {
    auid: u32,
    mask: [u32; 2],
    port: i32,
    kind: u32,
    address: [u32; 4],
    asid: i32,
    flags: u64,
}
/// The record must match the 48 bytes `getaudit_addr` writes.
const _: () = assert!(std::mem::size_of::<AuditInfo>() == 48);

unsafe extern "C" {
    /// `<bsm/audit.h>`: read this process's audit record.
    fn getaudit_addr(info: *mut AuditInfo, length: nix::libc::c_int) -> nix::libc::c_int;
    /// `<unistd.h>`: set the login name of this process's session (root, session leader).
    fn setlogin(name: *const nix::libc::c_char) -> nix::libc::c_int;
}

/// How the shim asks the entry to start the PTY's program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    Login,
    Readiness,
    Program,
}

/// Build the shim child's command: the private entry, behind `launchctl
/// asuser` when the account has a GUI login. The caller installs the PTY as
/// standard handles and makes the child its session leader before exec.
/// # Errors
/// Returns an unusable executable path or account name.
pub(crate) fn command(user: &User, start: Start, program: &[OsString]) -> io::Result<Command> {
    if !Uid::effective().is_root() && Uid::effective() != user.uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "rootless shim cannot change user",
        ));
    }
    // The entry runs as root before it drops privileges. It is the binary that
    // is running this shim, which the root infraternal agent already trusts.
    let executable = std::env::current_exe()?.canonicalize()?;
    // A root shim always enters the person's own launchd bootstrap and audit
    // session through `launchctl asuser`: their GUI login when they have one,
    // otherwise a fresh session whose audit user is the person, never the
    // daemon's system session (#328 P2). A rootless shim is already the person.
    let mut command = if Uid::effective().is_root() {
        let mut command = Command::new(LAUNCHCTL);
        command
            .arg("asuser")
            .arg(user.uid.to_string())
            .arg(&executable);
        command
    } else {
        Command::new(&executable)
    };
    command
        .args([VERB, "--uid", &user.uid.to_string()])
        .arg(match start {
            Start::Login => "--login",
            Start::Readiness => "--readiness",
            Start::Program => "--program",
        });
    if start == Start::Program {
        if program.is_empty() || program.iter().map(|a| a.len() + 1).sum::<usize>() > MAX_PROGRAM {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        command.arg("--").args(program);
    }
    command.env_clear();
    Ok(command)
}

/// Parsed private entry arguments.
#[derive(Debug, PartialEq, Eq)]
struct Request {
    uid: Uid,
    start: Start,
    program: Vec<OsString>,
}

/// Decode the entry's private argv; `None` for any shape `command` never emits.
fn parse(arguments: &[OsString]) -> Option<Request> {
    let [uid_flag, uid, start, rest @ ..] = arguments else {
        return None;
    };
    if uid_flag != "--uid" {
        return None;
    }
    let uid = uid.to_str()?;
    if uid.is_empty()
        || !uid.bytes().all(|b| b.is_ascii_digit())
        || (uid.len() > 1 && uid.starts_with('0'))
    {
        return None;
    }
    let uid = Uid::from_raw(uid.parse().ok()?);
    let start = match start.to_str()? {
        "--login" => Start::Login,
        "--readiness" => Start::Readiness,
        "--program" => Start::Program,
        _ => return None,
    };
    let program = match (start, rest) {
        (Start::Program, [separator, program @ ..]) if separator == "--" && !program.is_empty() => {
            program.to_vec()
        }
        (Start::Login | Start::Readiness, []) => Vec::new(),
        _ => return None,
    };
    if program.first().is_some_and(|program| program.is_empty())
        || program.iter().map(|a| a.len() + 1).sum::<usize>() > MAX_PROGRAM
    {
        return None;
    }
    Some(Request {
        uid,
        start,
        program,
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
        Some(request) => exec(&request),
        None => io::Error::from(io::ErrorKind::InvalidInput),
    };
    // Standard error is the person's terminal; say what failed, nothing else.
    eprintln!("infraternal: the shell could not start: {error}");
    Some(std::process::ExitCode::FAILURE)
}

/// Prepare and exec the shell; returns only the error that stopped it.
fn exec(request: &Request) -> io::Error {
    match prepare(request) {
        Ok(mut command) => command.exec(),
        Err(error) => error,
    }
}

/// Everything between entry and exec: descriptor sweep, session checks, privilege drop, placement and environment.
fn prepare(request: &Request) -> io::Result<Command> {
    // Still root and single-threaded: close everything but the PTY's standard
    // handles before anything else, so no descriptor the root chain held (a
    // root-authenticated socket, a root-only file) can reach the shell (#328 P1).
    crate::pty::close_above_stderr()?;
    let pid = unistd::getpid();
    // Only the shim's PTY child reaches this entry legitimately: it is the
    // leader of a fresh session whose controlling terminal is standard input.
    if unistd::getsid(None).map_err(io::Error::from)? != pid
        || unistd::tcgetpgrp(std::io::stdin()).map_err(io::Error::from)? != unistd::getpgrp()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "not a terminal session leader",
        ));
    }
    let user = User::from_uid(request.uid)
        .map_err(io::Error::from)?
        .ok_or_else(|| io::Error::other("the account does not exist"))?;
    let root = Uid::effective().is_root();
    if !root && Uid::effective() != user.uid {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let name = CString::new(user.name.as_bytes()).map_err(|_| io::Error::other("invalid name"))?;
    if root {
        drop_privileges(&name, user.uid, user.gid)?;
    }
    // `root` means the shim started this entry through `launchctl asuser`.
    let (audit_user, audit_flags) = audit_record()?;
    let placed = classify(root, user.uid, audit_user, audit_flags)?;
    let shell = if request.start == Start::Readiness || user.shell.as_os_str().is_empty() {
        PathBuf::from("/bin/sh")
    } else {
        user.shell.clone()
    };
    let mut command = match request.start {
        Start::Program => {
            let mut command = Command::new(&request.program[0]);
            command.args(&request.program[1..]);
            command
        }
        Start::Readiness => {
            let mut command = Command::new(&shell);
            command.args(["-c", READINESS]);
            command
        }
        Start::Login => {
            let mut command = Command::new(&shell);
            let base = shell.file_name().unwrap_or_default();
            let mut login = OsString::from("-");
            login.push(base);
            command.arg0(login);
            command
        }
    };
    let inherited: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    command.env_clear();
    for (key, value) in &inherited {
        if forwarded(key) {
            command.env(key, value);
        }
    }
    command
        .env("HOME", &user.dir)
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env("SHELL", &shell)
        .env("PATH", PATH);
    if let Some(directory) = temporary_directory() {
        command.env("TMPDIR", directory);
    }
    if placed && let Some(socket) = agent_socket(user.uid) {
        command.env("SSH_AUTH_SOCK", socket);
    }
    if request.start == Start::Login {
        crate::shell_startup::configure(&mut command, &shell, true, false);
    }
    // Home traversal is checked as the account, after the drop.
    std::env::set_current_dir(&user.dir)?;
    Ok(command)
}

/// Whether the entry passes this variable from its caller on to the shell.
fn forwarded(key: &OsStr) -> bool {
    PASSED.iter().any(|name| key == *name) || locale(key)
}

/// Locale variables: `LANG` and the `LC_*` family.
fn locale(key: &OsStr) -> bool {
    key == "LANG" || key.as_bytes().starts_with(b"LC_")
}

/// Record the login name for the session, join the account's groups, then
/// drop gid before uid. Verifies the result and that root cannot come back.
fn drop_privileges(name: &CString, uid: Uid, gid: Gid) -> io::Result<()> {
    // SAFETY: `name` is a valid NUL-terminated string that outlives each call;
    // neither function retains the pointer. This process is single-threaded.
    if unsafe { setlogin(name.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // initgroups registers the account for dynamic membership, so groups past
    // the kernel's 16-entry list still resolve; setgroups alone would drop them.
    #[allow(clippy::cast_possible_wrap)]
    let group = gid.as_raw() as nix::libc::c_int;
    // SAFETY: as above; the call copies the name and gid.
    if unsafe { nix::libc::initgroups(name.as_ptr(), group) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // Every infraternal process starts with a hard core limit of 0 (main's
    // harden_startup). The shell gets the macOS default back (soft 0, hard
    // unlimited), so `ulimit -c` works for the person as in any other shell.
    let core = nix::libc::rlimit {
        rlim_cur: 0,
        rlim_max: nix::libc::RLIM_INFINITY,
    };
    // SAFETY: setrlimit copies the live, initialized record.
    if unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_CORE, &raw const core) } != 0 {
        return Err(io::Error::last_os_error());
    }
    unistd::setgid(gid).map_err(io::Error::from)?;
    unistd::setuid(uid).map_err(io::Error::from)?;
    if unistd::getuid() != uid
        || unistd::geteuid() != uid
        || unistd::getgid() != gid
        || unistd::getegid() != gid
        || (!uid.is_root() && unistd::setuid(Uid::from_raw(0)).is_ok())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "privilege drop did not take effect",
        ));
    }
    Ok(())
}

/// This process's audit user and session flags (`getaudit_addr`).
fn audit_record() -> io::Result<(u32, u64)> {
    let mut info = AuditInfo {
        auid: 0,
        mask: [0; 2],
        port: 0,
        kind: 0,
        address: [0; 4],
        asid: 0,
        flags: 0,
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let length = std::mem::size_of::<AuditInfo>() as nix::libc::c_int;
    // SAFETY: the kernel fills exactly `length` bytes of this live repr(C)
    // record, whose layout matches <bsm/audit.h> (size asserted above).
    if unsafe { getaudit_addr(&raw mut info, length) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((info.auid, info.flags))
}

/// Decide the shell's placement from its own audit record: `Ok(true)` inside
/// the person's GUI login (keychain, ssh-agent, privacy permissions), `Ok(false)`
/// a plain shell in a session of its own.
///
/// After `launchctl asuser` (`through_asuser`) the audit user must be the person
/// in both cases. Anything else means the shell would share another session,
/// such as the root daemon's system session or someone else's login, so the
/// entry refuses rather than start it there. Graphic access only tells GUI from
/// plain. A rootless shim was never moved, so it keeps the caller's session.
fn classify(through_asuser: bool, uid: Uid, audit_user: u32, flags: u64) -> io::Result<bool> {
    let own = audit_user == uid.as_raw();
    if through_asuser && !own {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the shell did not get its own login session",
        ));
    }
    Ok(own && flags & GRAPHIC_ACCESS != 0)
}

/// The account's per-user temporary directory, as login shells receive it.
fn temporary_directory() -> Option<OsString> {
    let mut buffer = [0_u8; 1024];
    // SAFETY: confstr writes at most `buffer.len()` bytes, NUL included.
    let length =
        unsafe { nix::libc::confstr(USER_TEMP_DIR, buffer.as_mut_ptr().cast(), buffer.len()) };
    (length > 1 && length <= buffer.len())
        .then(|| OsString::from_vec(buffer[..length - 1].to_vec()))
}

/// The placed bootstrap's ssh-agent socket, when it is a socket the account owns.
fn agent_socket(uid: Uid) -> Option<PathBuf> {
    let output = Command::new(LAUNCHCTL)
        .args(["getenv", "SSH_AUTH_SOCK"])
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let text = output.stdout.strip_suffix(b"\n")?;
    if !output.status.success() || text.is_empty() || text.len() > 1024 || text.contains(&0) {
        return None;
    }
    let path = PathBuf::from(OsStr::from_bytes(text));
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    (path.is_absolute() && metadata.file_type().is_socket() && metadata.uid() == uid.as_raw())
        .then_some(path)
}

#[cfg(test)]
mod tests {
    //! The private argv parser accepts only the shapes `command` emits.
    use super::*;

    /// Arguments as `OsString`s, for the parser tests.
    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    /// The private argv parser accepts exactly the shapes `command` emits and refuses the rest.
    fn parser_accepts_only_emitted_shapes() {
        assert_eq!(
            parse(&args(&["--uid", "501", "--login"])).map(|r| (r.uid.as_raw(), r.start)),
            Some((501, Start::Login))
        );
        assert_eq!(
            parse(&args(&["--uid", "0", "--readiness"])).map(|r| r.start),
            Some(Start::Readiness)
        );
        assert_eq!(
            parse(&args(&[
                "--uid",
                "501",
                "--program",
                "--",
                "/bin/echo",
                "a b"
            ]))
            .map(|r| r.program),
            Some(args(&["/bin/echo", "a b"]))
        );
        for refused in [
            &["--uid", "0501", "--login"][..],
            &["--uid", "", "--login"],
            &["--uid", "-1", "--login"],
            &["--uid", "501", "--login", "extra"],
            &["--uid", "501", "--program"],
            &["--uid", "501", "--program", "--"],
            &["--uid", "501", "--program", "--", ""],
            &["--uid", "501", "--readiness", "--", "/bin/sh"],
            &["--user", "501", "--login"],
            &["--uid", "501", "--shell"],
        ] {
            assert!(parse(&args(refused)).is_none(), "{refused:?}");
        }
        let long = "x".repeat(MAX_PROGRAM);
        assert!(parse(&args(&["--uid", "1", "--program", "--", &long])).is_none());
    }

    /// The environment allowlist: terminal values, the marker and locale only;
    /// no loader, shell-startup or path variable from the root caller.
    #[test]
    fn only_terminal_and_locale_variables_are_forwarded() {
        for kept in [
            "TERM",
            "COLORTERM",
            "INFRATERNAL_SESSION",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
        ] {
            assert!(forwarded(OsStr::new(kept)), "{kept}");
        }
        for dropped in [
            "ZDOTDIR",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "BASH_ENV",
            "ENV",
            "PATH",
            "HOME",
            "SSH_AUTH_SOCK",
            "TMPDIR",
        ] {
            assert!(!forwarded(OsStr::new(dropped)), "{dropped}");
        }
    }

    /// Every process has an audit record; the call must succeed with our
    /// layout. (The values are checked end to end by the Mac proof.)
    #[test]
    fn audit_record_layout_is_readable() {
        audit_record().unwrap();
    }

    /// `AU_DEFAUDITID`: no audit user.
    const UNSET: u32 = u32::MAX;
    /// Graphic, tty and console access.
    const GUI: u64 = 0x2030;
    /// The root daemon's system session.
    const SYSTEM: u64 = 0x1;

    /// D335 placement after `launchctl asuser`: the person's GUI login or a
    /// plain session of their own; never the daemon's or someone else's.
    #[test]
    fn asuser_shells_run_only_in_the_persons_own_session() {
        let person = Uid::from_raw(1500);
        assert!(classify(true, person, 1500, GUI).unwrap());
        assert!(!classify(true, person, 1500, 0).unwrap());
        // The daemon's system session (what a LaunchDaemon's plain shell
        // inherited before #328 P2): no audit user, so refused.
        assert!(classify(true, person, UNSET, SYSTEM).is_err());
        // A daemon sitting in someone else's GUI login (a developer's sudo
        // from Terminal) must not lend that login to this person.
        assert!(classify(true, person, 501, GUI).is_err());
    }

    /// A rootless shim is already the person and keeps the caller's session.
    #[test]
    fn rootless_shells_keep_the_callers_session() {
        let person = Uid::from_raw(1500);
        assert!(classify(false, person, 1500, GUI).unwrap());
        assert!(!classify(false, person, 1500, 0).unwrap());
        assert!(!classify(false, person, 501, GUI).unwrap());
    }
}
