//! A pseudo-terminal that no other process of this account can open (#399, D274, J569 P1-2).
//!
//! The root upgrade types a password (on the su path, root's) to sudo, doas
//! or su through a terminal. An ordinary pseudo-terminal's `/dev/pts/N`
//! belongs to the account with mode 0620, so any other process of the
//! account can open it by path and read the line first. This module makes
//! one that only the infraternal agent and a root helper can use:
//!
//! 1. While the new terminal is still locked (nobody can open a locked
//!    terminal), its node is set to mode 000 and its change time is noted.
//! 2. The code waits until the kernel's coarse clock has moved past that
//!    time, so any later change to the node gets a later change time.
//! 3. It unlocks the terminal and opens it through the master
//!    (`TIOCGPTPEER`), which needs no path lookup and so ignores mode 000.
//! 4. It sets `TIOCEXCL`: from then on the kernel refuses every new open by
//!    a process without `CAP_SYS_ADMIN` (`EBUSY`). sudo, doas and su run as
//!    root and can still open `/dev/tty`.
//! 5. It checks that the node still has mode 000 and its noted change time.
//!
//! Between steps 3 and 4 another process of the account could only open the
//! node after giving it a mode that allows opening. That `chmod` updates the
//! change time, which no one but root can set back, so step 5 catches it and
//! the terminal is refused before anything is typed. The process holding the
//! master must itself be non-dumpable (the infraternal binary is, from
//! startup), so its descriptors can't be reached through `/proc`.
//!
//! The same holds for every process that ever holds the slave: only the
//! infraternal agent (and its own fork before exec) and the setuid elevation
//! command may. [`lead_session`] gives the child its session and controlling
//! terminal without running any helper program in between (J701 F1).
#![allow(unsafe_code)]

use std::{
    io,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::Path,
    time::Duration,
};

/// A terminal pair whose slave no other process of this account can open.
pub struct PrivateTerminal {
    /// The master side, kept by the infraternal agent.
    pub master: OwnedFd,
    /// The slave side, for the elevation command's stdin, stdout and stderr.
    pub slave: OwnedFd,
}

/// How long step 2 waits at most for the coarse clock to move (a few ticks).
const CLOCK_WAIT: Duration = Duration::from_millis(200);

/// Open a [`PrivateTerminal`].
///
/// # Errors
/// `PermissionDenied` when the node was changed while it was briefly open to
/// the account (someone tried to get in): nothing has used the terminal yet,
/// and the caller must not type to it. Other errors when the system can't
/// make a terminal.
pub fn open() -> io::Result<PrivateTerminal> {
    open_with(|_| {})
}

/// [`open`], running `window` with the node's path between unlocking and
/// making the terminal exclusive (step 3), so tests can act as an intruder.
fn open_with(window: impl FnOnce(&Path)) -> io::Result<PrivateTerminal> {
    use nix::{fcntl::OFlag, pty};
    let master = pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC)?;
    pty::grantpt(&master)?;
    let name = pty::ptsname_r(&master)?;
    let path = Path::new(&name);
    // Step 1: still locked, so no one can open it while its mode changes.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000))?;
    let before = std::fs::metadata(path)?;
    if before.mode() & 0o7777 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    // Step 2.
    wait_for_clock_after(before.ctime(), before.ctime_nsec())?;
    pty::unlockpt(&master)?;
    window(path);
    // SAFETY: the descriptor is the master just opened and still owned here;
    // into_raw_fd hands its ownership to the OwnedFd exactly once.
    let master = unsafe { OwnedFd::from_raw_fd(master.into_raw_fd()) };
    // Step 3.
    let slave = peer(&master)?;
    // Step 4.
    // SAFETY: TIOCEXCL takes no argument and changes only the terminal's
    // exclusive flag; the slave descriptor is open for the whole call.
    if unsafe { nix::libc::ioctl(slave.as_raw_fd(), nix::libc::TIOCEXCL) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // Step 5, on the descriptor, so it is the node that was noted.
    let after = std::fs::File::from(slave.try_clone()?).metadata()?;
    if after.rdev() != before.rdev()
        || after.mode() & 0o7777 != 0
        || after.ctime() != before.ctime()
        || after.ctime_nsec() != before.ctime_nsec()
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(PrivateTerminal { master, slave })
}

/// Make `command`'s child the leader of a new session whose controlling
/// terminal is its standard input, before it executes its program.
///
/// Use it for the elevation command that reads from a [`PrivateTerminal`]:
/// set the slave as the command's stdin (and stdout and stderr), call this,
/// then spawn. The program then starts already holding the terminal as its
/// controlling terminal, so sudo, doas and su can be executed directly.
///
/// Why not a helper program such as `setsid --ctty` (J701 F1, #399): any
/// ordinary program the account executes is dumpable again, and while it
/// holds the slave another process of the account could take a copy of the
/// descriptor through it (ptrace or `pidfd_getfd`), which the mode 000 node
/// and `TIOCEXCL` don't stop, since they only refuse new opens. Done here, the
/// work runs in the forked copy of the infraternal agent, which is still
/// non-dumpable, and the next program to hold the terminal is the setuid one.
///
/// Rust's `Command` installs the stdio descriptors before it runs this hook,
/// so descriptor 0 is the slave when `TIOCSCTTY` runs. The child of a fork
/// is never a process-group leader, so `setsid` can't fail with `EPERM`.
/// The new session's id is the child's pid, so killing that process group
/// still ends the whole elevation.
pub fn lead_session(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt as _;
    // SAFETY: setsid and ioctl are async-signal-safe system calls; the hook
    // touches no allocation, lock or other Rust state of the parent.
    unsafe {
        command.pre_exec(|| {
            if nix::libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if nix::libc::ioctl(0, nix::libc::TIOCSCTTY, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Open the slave of `master` without a path lookup (Linux 4.13+).
fn peer(master: &OwnedFd) -> io::Result<OwnedFd> {
    let flags = nix::libc::O_RDWR | nix::libc::O_NOCTTY | nix::libc::O_CLOEXEC;
    // SAFETY: TIOCGPTPEER takes the open flags by value and returns a new
    // descriptor, which is owned exactly once below.
    let fd = unsafe { nix::libc::ioctl(master.as_raw_fd(), nix::libc::TIOCGPTPEER, flags) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned this new descriptor to us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Wait until the coarse real-time clock, which the kernel uses for change
/// times, reads later than `seconds.nanoseconds`.
fn wait_for_clock_after(seconds: i64, nanoseconds: i64) -> io::Result<()> {
    let deadline = std::time::Instant::now() + CLOCK_WAIT;
    loop {
        let mut now = nix::libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime writes one timespec to the pointer given.
        if unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_REALTIME_COARSE, &raw mut now) } == -1
        {
            return Err(io::Error::last_os_error());
        }
        if (now.tv_sec, now.tv_nsec) > (seconds, nanoseconds) {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        // sleep: waiting for the coarse clock's next tick; there is no event for it.
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    //! The private terminal refuses the account and catches an intruder.
    use super::*;

    /// Whether this test runs as root, which bypasses file modes.
    fn root() -> bool {
        nix::unistd::geteuid().is_root()
    }

    /// The slave's path, from the descriptor.
    fn name(terminal: &PrivateTerminal) -> std::path::PathBuf {
        std::fs::read_link(format!("/proc/self/fd/{}", terminal.slave.as_raw_fd())).unwrap()
    }

    /// The account can't open the terminal by path, even after giving the
    /// node an open mode: the terminal is exclusive.
    #[test]
    fn the_account_cannot_open_a_private_terminal() {
        use std::os::unix::fs::OpenOptionsExt as _;
        if root() {
            return;
        }
        let terminal = open().unwrap();
        let path = name(&terminal);
        let read = || {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOCTTY | nix::libc::O_NONBLOCK)
                .open(&path)
        };
        assert_eq!(read().unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read().unwrap_err().raw_os_error(),
            Some(nix::libc::EBUSY),
            "an exclusive terminal admits no second opener"
        );
        // The pair itself works: what the master writes, the slave reads.
        nix::unistd::write(&terminal.master, b"x\n").unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(nix::unistd::read(&terminal.slave, &mut byte).unwrap(), 1);
    }

    /// Someone who opens the terminal in the moment before it is exclusive
    /// had to change its mode, and the terminal is refused.
    #[test]
    fn an_opener_before_the_terminal_is_exclusive_is_caught() {
        if root() {
            return;
        }
        let mut stolen = None;
        let refused = open_with(|path| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            stolen = std::fs::OpenOptions::new().read(true).open(path).ok();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
        });
        assert!(
            stolen.is_some(),
            "the intruder got in, so it must be caught"
        );
        assert_eq!(
            refused.err().map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
    }

    /// J716 B (#399, D274): the elevation command gets only its terminal.
    ///
    /// sudo, doas or su, and then root's snippet and relay, must not inherit
    /// a descriptor the infraternal agent happened to receive from whatever
    /// launched it: a leaked lock would stay held, a leaked socket stay open,
    /// for as long as the relay runs. This test leaks one on purpose (a
    /// descriptor without close-on-exec, the way a launcher leaks them),
    /// starts an ordinary program the way `elevate` starts the elevation
    /// command, and reads that program's descriptor table once it runs: it
    /// must hold exactly 0, 1 and 2, the terminal.
    #[test]
    fn the_session_leader_holds_only_its_terminal() {
        let terminal = open().unwrap();
        let null = std::fs::File::open("/dev/null").unwrap();
        // SAFETY: dup returns a new descriptor (without close-on-exec), owned
        // exactly once by the OwnedFd below.
        let leaked = unsafe { nix::libc::dup(null.as_raw_fd()) };
        assert!(leaked >= 3);
        // SAFETY: just returned by dup and not owned anywhere else.
        let leaked = unsafe { OwnedFd::from_raw_fd(leaked) };
        let sleep = std::fs::canonicalize("/bin/sleep").unwrap();
        let mut command = std::process::Command::new(&sleep);
        command
            .arg("30")
            .stdin(terminal.slave.try_clone().unwrap())
            .stdout(terminal.slave.try_clone().unwrap())
            .stderr(terminal.slave.try_clone().unwrap());
        lead_session(&mut command);
        let mut child = command.spawn().unwrap();
        let pid = child.id();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::fs::read_link(format!("/proc/{pid}/exe")).ok().as_ref() != Some(&sleep) {
            assert!(
                std::time::Instant::now() < deadline,
                "the child never ran sleep"
            );
            // sleep: waiting for the child to execute its program; there is no event for it.
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut held: Vec<u32> = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .unwrap()
            .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
            .collect();
        held.sort_unstable();
        let _ = child.kill();
        let _ = child.wait();
        drop(leaked);
        assert_eq!(
            held,
            [0, 1, 2],
            "the elevation command inherited more than its terminal"
        );
    }

    /// Without the mode change no one gets in at all in that moment.
    #[test]
    fn a_locked_down_node_admits_no_opener_before_it_is_exclusive() {
        if root() {
            return;
        }
        let mut opened = None;
        let terminal = open_with(|path| {
            opened = Some(
                std::fs::OpenOptions::new()
                    .read(true)
                    .open(path)
                    .map(|_| ()),
            );
        })
        .unwrap();
        assert_eq!(
            opened.unwrap().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(terminal);
    }
}
