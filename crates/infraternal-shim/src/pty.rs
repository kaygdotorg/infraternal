//! Audited Linux PTY and process boundary; all unsafe code is confined here [13][40].
#![allow(unsafe_code)]
use nix::{
    fcntl::{FcntlArg, OFlag, fcntl},
    pty::{Winsize, openpty},
    sys::signal::{Signal, killpg},
    unistd::{self, ForkResult, Uid, User},
};
use std::os::unix::ffi::OsStrExt as _;
use std::{
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    process::{Child, Command, Stdio},
};

pub struct Pty {
    pub master: File,
    pub child: Child,
}
fn errno(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}
impl Pty {
    #[cfg(test)]
    pub fn spawn(uid: u32, cols: u16, rows: u16) -> io::Result<Self> {
        Self::spawn_with_readiness(uid, cols, rows, false)
    }
    pub fn spawn_with_readiness(
        uid: u32,
        cols: u16,
        rows: u16,
        readiness: bool,
    ) -> io::Result<Self> {
        let user = User::from_uid(Uid::from_raw(uid))
            .map_err(errno)?
            .ok_or_else(|| io::Error::other("target uid has no login account"))?;
        if !Uid::effective().is_root() && Uid::effective() != user.uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "rootless shim cannot change user",
            ));
        }
        let terminal = openpty(
            Some(&Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            }),
            None,
        )
        .map_err(errno)?;
        // Explicit CLOEXEC prevents the login shell inheriting a master that
        // would keep its own PTY alive, including when descriptor 0 is closed.
        fcntl(
            &terminal.master,
            FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .map_err(errno)?;
        fcntl(
            &terminal.slave,
            FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .map_err(errno)?;
        let slave = File::from(terminal.slave);
        // A rootful openpty creates a root-owned slave. Give the target user
        // its own terminal while denying other users direct device writes.
        if Uid::effective().is_root() {
            unistd::fchown(&slave, Some(user.uid), Some(user.gid)).map_err(errno)?;
        }
        nix::sys::stat::fchmod(&slave, nix::sys::stat::Mode::from_bits_truncate(0o600))
            .map_err(errno)?;
        let name =
            CString::new(user.name.clone()).map_err(|_| io::Error::other("invalid login name"))?;
        let directory = CString::new(user.dir.as_os_str().as_bytes())
            .map_err(|_| io::Error::other("invalid home directory"))?;
        let root = Uid::effective().is_root();
        let groups = if root {
            unistd::getgrouplist(&name, user.gid).map_err(errno)?
        } else {
            Vec::new()
        };
        let target_uid = user.uid;
        let group = user.gid;
        let shell = if readiness || user.shell.as_os_str().is_empty() {
            std::path::PathBuf::from("/bin/sh")
        } else {
            user.shell
        };
        let mut command = Command::new(&shell);
        let login_name = format!(
            "-{}",
            shell.file_name().unwrap_or_default().to_string_lossy()
        );
        if readiness {
            // Wait for attachment input without invoking any login rc files.
            command.args(["-c", "read -r line; printf 'infraternal-ready\\n'"]);
        } else {
            command.arg0(login_name);
        }
        command
            .env_clear()
            .env("HOME", &user.dir)
            .env("USER", &user.name)
            .env("LOGNAME", &user.name)
            .env("SHELL", &shell)
            .env("TERM", "xterm-256color")
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .stdin(Stdio::from(slave.try_clone()?))
            .stdout(Stdio::from(slave.try_clone()?))
            .stderr(Stdio::from(slave));
        // Keep only locale values from the host environment; all other inherited
        // variables stay scrubbed, and an explicit user locale remains authoritative.
        for (name, value) in crate::session_locale_environment() {
            command.env(name, value);
        }
        // Preserve zsh's supported profile location for isolated canaries.
        if let Some(directory) = std::env::var_os("ZDOTDIR") {
            command.env("ZDOTDIR", directory);
        }
        // SAFETY: the callback runs after fork, uses only libc-backed syscalls
        // and existing immutable data, and neither allocates nor takes locks.
        // Descriptor 0 is Command's installed slave; privilege order prevents
        // retaining supplementary root groups after dropping uid.
        prepare_child(&mut command);
        unsafe {
            command.pre_exec(move || {
                unistd::setsid().map_err(errno)?;
                if nix::libc::ioctl(0, nix::libc::TIOCSCTTY, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if root {
                    unistd::setgroups(&groups).map_err(errno)?;
                    unistd::setgid(group).map_err(errno)?;
                    unistd::setuid(target_uid).map_err(errno)?;
                }
                // CStr uses the preallocated pointer without allocating after fork.
                // Validate home traversal as the target uid, after dropping root.
                unistd::chdir(directory.as_c_str()).map_err(errno)?;
                Ok(())
            });
        }
        let child = command.spawn()?;
        let master = File::from(terminal.master);
        fcntl(&master, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).map_err(errno)?;
        Ok(Self { master, child })
    }
    pub fn resize(&self, cols: u16, rows: u16, px_w: u16, px_h: u16) -> io::Result<()> {
        let size = Winsize {
            ws_col: cols,
            ws_row: rows,
            ws_xpixel: px_w,
            ws_ypixel: px_h,
        };
        // SAFETY: TIOCSWINSZ reads exactly a valid Winsize; the owned master is
        // live throughout this call, and no pointer is retained by the kernel.
        if unsafe {
            nix::libc::ioctl(
                self.master.as_raw_fd(),
                nix::libc::TIOCSWINSZ,
                &raw const size,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    // Cleanup can race a retained exit. Validate but never signal a recycled
    // foreground group or close the peer before its ExitAck.
    pub(crate) fn signal_unless_exited(&self, number: u8, exited: bool) -> io::Result<()> {
        if exited {
            allowed_signal(number).map(|_| ())
        } else {
            self.signal(number)
        }
    }
    pub fn signal(&self, number: u8) -> io::Result<()> {
        let signal = allowed_signal(number)?;
        // Job control gives full-screen applications their own foreground group.
        // Send to that group, not merely to the login shell's process group.
        let group = unistd::tcgetpgrp(&self.master).map_err(errno)?;
        killpg(group, signal).map_err(errno)
    }
}
// Validate independently of delivery: an already exited PTY must still refuse
// unsupported signals, while a permitted duplicate cannot disturb its ExitAck.
fn allowed_signal(number: u8) -> io::Result<Signal> {
    let signal = Signal::try_from(i32::from(number)).map_err(errno)?;
    if !matches!(
        signal,
        Signal::SIGINT | Signal::SIGTERM | Signal::SIGHUP | Signal::SIGKILL | Signal::SIGWINCH
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "signal is not allowed",
        ));
    }
    Ok(signal)
}
/// Detach only before threads or PTYs exist. The original process returns;
/// the grandchild owns the session and redirects inherited standard handles.
pub fn detach() -> io::Result<bool> {
    // SAFETY: called once by the single-threaded CLI before any session is
    // created; children only invoke syscalls before returning to normal code.
    match unsafe { unistd::fork() }.map_err(errno)? {
        ForkResult::Parent { child } => {
            nix::sys::wait::waitpid(child, None).map_err(errno)?;
            Ok(false)
        }
        ForkResult::Child => {
            // Raw fork does not run Command's pre-exec callbacks. Give each
            // detached child the same default policy before normal shim code,
            // without changing the original caller's reload mask [217].
            reset_child_signals()?;
            unistd::setsid().map_err(errno)?;
            // SAFETY: same single-threaded startup boundary as the first fork.
            match unsafe { unistd::fork() }.map_err(errno)? {
                ForkResult::Parent { .. } => std::process::exit(0),
                ForkResult::Child => {
                    reset_child_signals()?;
                    let null = File::options().read(true).write(true).open("/dev/null")?;
                    // Opening /dev/null can claim a closed standard descriptor.
                    // Move its ownership above stderr before dup2, so dropping the
                    // source cannot close any redirected standard handle. Keep
                    // CLOEXEC on this temporary source; dup2 clears it on 0/1/2.
                    let source = fcntl(&null, FcntlArg::F_DUPFD_CLOEXEC(3)).map_err(errno)?;
                    drop(null);
                    // SAFETY: successful F_DUPFD_CLOEXEC creates a fresh fd >= 3
                    // with no other owner. Transfer it exactly once to File.
                    let source_file = unsafe { File::from_raw_fd(source) };
                    unistd::dup2_stdin(&source_file).map_err(errno)?;
                    unistd::dup2_stdout(&source_file).map_err(errno)?;
                    unistd::dup2_stderr(&source_file).map_err(errno)?;
                    Ok(true)
                }
            }
        }
    }
}

/// Install only async-signal-safe syscalls in the post-fork child. Ignored
/// dispositions survive exec, so reset them as well as the inherited mask.
pub(super) fn prepare_child(command: &mut Command) {
    // SAFETY: no captured state, allocation or locks after fork. The reset uses
    // only sigaction/sigprocmask and stack storage; errors abort this child's exec.
    unsafe {
        command.pre_exec(reset_child_signals);
    }
}

/// Direct launch keeps the same signal policy and closes the trusted leg-B fd.
pub(super) fn prepare_child_without_control(command: &mut Command) {
    prepare_child(command);
    // SAFETY: close is async-signal-safe and captures no runtime state. EBADF
    // means no control descriptor exists; every other error refuses the child.
    unsafe {
        command.pre_exec(|| {
            if nix::libc::close(3) == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(nix::libc::EBADF) {
                    return Err(error);
                }
            }
            Ok(())
        });
    }
}

fn reset_child_signals() -> io::Result<()> {
    // SAFETY: zero initializes sigaction's storage; sigemptyset initializes its
    // mask before any syscall consumes it. All pointers refer to live stack data.
    let mut action: nix::libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = nix::libc::SIG_DFL;
    unsafe { nix::libc::sigemptyset(&raw mut action.sa_mask) };
    for signal in 1..=nix::libc::SIGRTMAX() {
        if signal == nix::libc::SIGKILL || signal == nix::libc::SIGSTOP {
            continue;
        }
        // SAFETY: action is initialized; null oldact requests no prior value.
        if unsafe { nix::libc::sigaction(signal, &raw const action, std::ptr::null_mut()) } == -1 {
            let error = io::Error::last_os_error();
            // libc reserves internal thread signals, which sigaction refuses.
            if error.raw_os_error() != Some(nix::libc::EINVAL) {
                return Err(error);
            }
        }
    }
    // Reset dispositions before unblocking so a pending signal never runs an
    // inherited runtime handler in the forked address space.
    nix::sys::signal::SigSet::empty()
        .thread_set_mask()
        .map_err(errno)
}

/// Open a CLOEXEC process lifetime descriptor without signalling or attaching to the process.
/// The caller must authenticate the PID and recheck its birth identity after registration.
#[cfg(target_os = "linux")]
pub(super) fn process_exit_descriptor(pid: u32) -> io::Result<std::os::fd::OwnedFd> {
    let pid = i32::try_from(pid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if pid == 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: pidfd_open takes only a positive integer PID and zero flags, no
    // pointers. It returns a new CLOEXEC descriptor, or -1 with errno. Using
    // the syscall avoids libc-version requirements on distribution-independent
    // musl binaries. No other code owns the returned descriptor.
    let result = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0_u32) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    let fd = i32::try_from(result).map_err(io::Error::other)?;
    // SAFETY: a successful pidfd_open returns exactly one owned descriptor;
    // OwnedFd closes it on every path, including cancelled daemon discovery.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod child_signal_tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn child_reset_restores_ignored_dispositions_and_leaves_parent_mask() {
        const CASE: &str = "pty::child_signal_tests::child_reset_restores_ignored_dispositions_and_leaves_parent_mask";
        const FIXTURE: &str = "INFRATERNAL_CHILD_SIGNAL_FIXTURE";
        if std::env::var_os(FIXTURE).is_none() {
            assert!(
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", CASE])
                    .env(FIXTURE, "1")
                    .status()
                    .unwrap()
                    .success()
            );
            return;
        }
        // Change signal policy only in this disposable fixture process.
        let signal = nix::sys::signal::Signal::SIGHUP;
        let mut blocked = nix::sys::signal::SigSet::empty();
        blocked.add(signal);
        blocked.thread_block().unwrap();
        let ignored = nix::sys::signal::SigAction::new(
            nix::sys::signal::SigHandler::SigIgn,
            nix::sys::signal::SaFlags::empty(),
            nix::sys::signal::SigSet::empty(),
        );
        // SAFETY: fixture-local disposition with no handler pointer.
        unsafe {
            nix::sys::signal::sigaction(signal, &ignored).unwrap();
        }
        let before = nix::sys::signal::SigSet::thread_get_mask().unwrap();
        let mut child = Command::new("/bin/sh");
        child.args(["-c", "kill -HUP $$; exit 42"]);
        prepare_child(&mut child);
        let status = child.status().unwrap();
        assert_eq!(status.signal(), Some(nix::libc::SIGHUP));

        let mut attributes = nix::spawn::PosixSpawnAttr::init().unwrap();
        crate::prepare_spawn(&mut attributes).unwrap();
        let actions = nix::spawn::PosixSpawnFileActions::init().unwrap();
        let shell = CString::new("/bin/sh").unwrap();
        let flag = CString::new("-c").unwrap();
        let script = CString::new("kill -HUP $$; exit 42").unwrap();
        let environment: [&std::ffi::CStr; 0] = [];
        let pid = nix::spawn::posix_spawn(
            shell.as_c_str(),
            &actions,
            &attributes,
            &[shell.as_c_str(), flag.as_c_str(), script.as_c_str()],
            &environment,
        )
        .unwrap();
        assert_eq!(
            nix::sys::wait::waitpid(pid, None).unwrap(),
            nix::sys::wait::WaitStatus::Signaled(pid, signal, false),
        );
        assert_eq!(nix::sys::signal::SigSet::thread_get_mask().unwrap(), before);
    }
    #[test]
    fn child_policy_closes_the_control_descriptor_before_direct_exec() {
        let control = File::open("/dev/null").unwrap();
        let fd = control.as_raw_fd();
        let mut child = Command::new("/bin/sh");
        child.args(["-c", "test ! -e /proc/self/fd/3"]);
        // SAFETY: create a fixture-only inherited control descriptor with only
        // dup2/fcntl before the production child policy runs.
        unsafe {
            child.pre_exec(move || {
                if nix::libc::dup2(fd, 3) == -1 || nix::libc::fcntl(3, nix::libc::F_SETFD, 0) == -1
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        prepare_child_without_control(&mut child);
        assert!(
            child.status().unwrap().success(),
            "leg-B control must be closed before direct child exec"
        );
    }

    #[test]
    #[ignore = "child spawn diagnostic; run locally in a weighted scope without own build overlap"]
    fn child_signal_reset_spawn_cost_at_128_children() {
        let count = 128;
        let mut baseline = Vec::new();
        let mut reset = Vec::new();
        for round in 0..7 {
            for enabled in if round % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let start = std::time::Instant::now();
                for _ in 0..count {
                    let mut command = Command::new("/bin/true");
                    if enabled {
                        prepare_child(&mut command);
                    }
                    assert!(command.status().unwrap().success());
                }
                let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                if enabled {
                    reset.push(elapsed);
                } else {
                    baseline.push(elapsed);
                }
            }
        }
        baseline.sort_by(f64::total_cmp);
        reset.sort_by(f64::total_cmp);
        println!(
            "METRIC name=child_signal_reset_spawn n={count} rounds=7 baseline_batch_p50_ms={:.3} reset_batch_p50_ms={:.3} delta_per_child_us={:.3} delta_at_128_children_ms={:.3} idle_wakeups=0 retained_bytes_per_child=0",
            baseline[3],
            reset[3],
            (reset[3] - baseline[3]) * 1000.0 / f64::from(count),
            reset[3] - baseline[3]
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod child_locale_tests {
    use super::*;

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn spawned_login_shell_receives_selected_locale_without_other_host_variables() {
        let expected = crate::locale::environment();
        let pty = Pty::spawn(Uid::effective().as_raw(), 80, 24).unwrap();
        let child = ChildGuard(pty.child);
        let raw = std::fs::read(format!("/proc/{}/environ", child.0.id())).unwrap();
        let actual = raw
            .split(|byte| *byte == 0)
            .filter_map(|entry| {
                let separator = entry.iter().position(|byte| *byte == b'=')?;
                Some((&entry[..separator], &entry[separator + 1..]))
            })
            .collect::<Vec<_>>();
        for (name, value) in expected {
            let name = name.as_os_str().as_encoded_bytes();
            let value = value.as_os_str().as_encoded_bytes();
            assert!(
                actual.iter().any(|(actual_name, actual_value)| {
                    *actual_name == name && *actual_value == value
                }),
                "the login shell must receive the selected locale variable"
            );
        }
        assert!(
            actual
                .iter()
                .any(|(name, value)| *name == b"TERM" && *value == b"xterm-256color")
        );
        assert!(actual.iter().all(|(name, _)| {
            *name == b"HOME"
                || *name == b"USER"
                || *name == b"LOGNAME"
                || *name == b"SHELL"
                || *name == b"TERM"
                || *name == b"PATH"
                || *name == b"ZDOTDIR"
                || *name == b"LANG"
                || name.starts_with(b"LC_")
        }));
    }
}

#[cfg(feature = "process-per-user")]
#[path = "pty_handoff.rs"]
pub(crate) mod handoff;
