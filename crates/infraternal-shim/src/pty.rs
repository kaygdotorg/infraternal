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
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    path::Path,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU8, Ordering},
};

pub struct Pty {
    pub master: File,
    pub child: Child,
}
fn errno(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

/// Establish waitable child ownership for the shared host before its first PTY.
/// The caller has validated single-threaded startup and blocked SIGCHLD. A
/// blocked ignored disposition (or `SA_NOCLDWAIT`) still lets the kernel discard
/// exit status; replacing the entire action removes both auto-reaping forms.
#[cfg(feature = "process-per-user")]
pub(crate) fn reset_host_child_notifications() -> io::Result<()> {
    let action = nix::sys::signal::SigAction::new(
        nix::sys::signal::SigHandler::SigDfl,
        nix::sys::signal::SaFlags::empty(),
        nix::sys::signal::SigSet::empty(),
    );
    // SAFETY: no user handler is installed; the caller has one thread, blocks
    // SIGCHLD, and has not created children. sigaction copies the valid action.
    unsafe { nix::sys::signal::sigaction(Signal::SIGCHLD, &action) }
        .map(|_| ())
        .map_err(errno)
}

/// Read the same kernel monotonic clock used by numeric scheduler receipts.
#[cfg(feature = "host-diagnostics")]
pub(crate) fn monotonic_ns() -> io::Result<u64> {
    let mut stamp = nix::libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the kernel synchronously fills this valid timespec. CLOCK_MONOTONIC
    // needs no process authority and retains no pointer after the call.
    if unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_MONOTONIC, &raw mut stamp) } == -1 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(stamp.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|ns| ns.checked_add(u64::try_from(stamp.tv_nsec).ok()?))
        .ok_or_else(|| io::Error::other("monotonic clock overflow"))
}

/// Classify already-ready PTY output without consuming or reordering bytes.
/// The shared reactor uses this hint to read short interactive replies before
/// bulk output. Read readiness remains authoritative if the hint changes.
#[cfg(feature = "process-per-user")]
pub(crate) fn available_output(master: &File) -> io::Result<usize> {
    let mut count: nix::libc::c_int = 0;
    // SAFETY: FIONREAD synchronously writes one c_int through this valid
    // pointer. The borrowed PTY master stays open throughout the ioctl.
    let result =
        unsafe { nix::libc::ioctl(master.as_raw_fd(), nix::libc::FIONREAD, &raw mut count) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    usize::try_from(count).map_err(|_| io::Error::other("negative PTY readable byte count"))
}

#[cfg(all(test, feature = "process-per-user"))]
mod output_readiness_tests {
    //! Readable-byte classification borrows a real PTY without consuming data.
    use super::*;
    use nix::poll::{PollFd, PollFlags, poll};
    use std::{io::Read, os::fd::AsFd};

    #[test]
    fn readable_byte_hint_preserves_the_complete_output_stream() {
        let terminal = openpty(None, None).unwrap();
        let mut master = File::from(terminal.master);
        assert_eq!(available_output(&master).unwrap(), 0);
        unistd::write(&terminal.slave, b"short-reply").unwrap();
        assert_eq!(
            poll(
                &mut [PollFd::new(master.as_fd(), PollFlags::POLLIN)],
                5000_u16
            )
            .unwrap(),
            1
        );
        assert_eq!(available_output(&master).unwrap(), 11);
        assert_eq!(available_output(&master).unwrap(), 11);
        let mut bytes = [0; 11];
        master.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"short-reply");
        assert_eq!(available_output(&master).unwrap(), 0);
    }
}

impl Pty {
    #[cfg(test)]
    pub fn spawn(uid: u32, cols: u16, rows: u16) -> io::Result<Self> {
        Self::spawn_with_readiness(uid, cols, rows, false)
    }
    #[cfg(any(test, feature = "process-per-user"))]
    pub fn spawn_with_readiness(
        uid: u32,
        cols: u16,
        rows: u16,
        readiness: bool,
    ) -> io::Result<Self> {
        Self::spawn_with_command(uid, cols, rows, readiness, &[])
    }
    pub fn spawn_with_command(
        uid: u32,
        cols: u16,
        rows: u16,
        readiness: bool,
        program: &[std::ffi::OsString],
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
            Path::new("/bin/sh")
        } else {
            user.shell.as_path()
        };
        let mut command = session_command(shell, readiness, program);
        command
            .env_clear()
            .env("HOME", &user.dir)
            .env("USER", &user.name)
            .env("LOGNAME", &user.name)
            .env("SHELL", shell)
            .env("TERM", "xterm-256color")
            // Keep TERM broadly compatible while separately advertising 24-bit colour.
            .env("COLORTERM", "truecolor")
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
    /// Target the owned shell group even while a job owns the foreground PTY.
    /// Child caches a reaped status. Check it even before output has drained:
    /// a live or unreaped child reserves its PID until this loop can reap it.
    pub(crate) fn close_session(&mut self, exited: bool) -> io::Result<()> {
        if exited || self.child.try_wait()?.is_some() {
            return Ok(());
        }
        let group =
            nix::unistd::Pid::from_raw(i32::try_from(self.child.id()).map_err(io::Error::other)?);
        killpg(group, Signal::SIGHUP).map_err(errno)
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
/// Columns of the terminal behind standard output; `None` for a pipe, a file or a zero-width reply.
pub fn stdout_columns() -> Option<u16> {
    let mut size = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ writes exactly one Winsize through the pointer, which
    // outlives the call; descriptor 1 is only inspected and never closed.
    let status = unsafe { nix::libc::ioctl(1, nix::libc::TIOCGWINSZ, &raw mut size) };
    (status == 0 && size.ws_col > 0).then_some(size.ws_col)
}
/// What the interrupt handler writes to standard output before it exits; set once, read in the handler.
static INTERRUPT_NOTICE: std::sync::OnceLock<Box<[u8]>> = std::sync::OnceLock::new();
const OUTPUT_NOT_STARTED: u8 = 0;
const OUTPUT_WRITING: u8 = 1;
const INTERRUPT_DURING_OUTPUT: u8 = 2;
const OUTPUT_FINISHED: u8 = 3;
const INTERRUPTED_BEFORE_OUTPUT: u8 = 4;
/// A signal during the final write is deferred until that complete line has been written.
static FINAL_OUTPUT: AtomicU8 = AtomicU8::new(OUTPUT_NOT_STARTED);

/// Whether a runtime has installed a chaining handler above this one.
fn handler_is_current() -> bool {
    let mut current = MaybeUninit::<nix::libc::sigaction>::uninit();
    // SAFETY: `sigaction` reads the current action into this stack slot and is async-signal-safe.
    if unsafe { nix::libc::sigaction(nix::libc::SIGINT, std::ptr::null(), current.as_mut_ptr()) }
        != 0
    {
        return false;
    }
    // SAFETY: a successful `sigaction` query initialized the action.
    unsafe { current.assume_init().sa_sigaction == on_interrupt as *const () as usize }
}

/// Only lock-free atomics, an async-signal-safe `sigaction` query, `write(2)` and SIGINT reset.
extern "C" fn on_interrupt(_signal: nix::libc::c_int) {
    if !handler_is_current() {
        // A later runtime handler chains this handler before dispatching its own notification.
        return;
    }
    loop {
        let phase = FINAL_OUTPUT.load(Ordering::Relaxed);
        let next = match phase {
            OUTPUT_NOT_STARTED => INTERRUPTED_BEFORE_OUTPUT,
            OUTPUT_WRITING => INTERRUPT_DURING_OUTPUT,
            INTERRUPT_DURING_OUTPUT => return,
            // Unknown state cannot be allowed to write beside a result.
            _ => return_by_sigint(),
        };
        if FINAL_OUTPUT
            .compare_exchange(phase, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            if phase == OUTPUT_NOT_STARTED {
                if let Some(notice) = INTERRUPT_NOTICE.get() {
                    // SAFETY: the boxed slice is live and never freed; the process exits next.
                    unsafe { nix::libc::write(1, notice.as_ptr().cast(), notice.len()) };
                }
                return_by_sigint();
            }
            return;
        }
    }
}

/// Restore the default action and terminate by SIGINT so calling shells stop their scripts.
fn return_by_sigint() -> ! {
    // SAFETY: the signal action and mask are initialized before use. These syscalls are
    // async-signal-safe, so this also works when called by `on_interrupt`.
    unsafe {
        let mut action = MaybeUninit::<nix::libc::sigaction>::zeroed().assume_init();
        if nix::libc::sigemptyset(&raw mut action.sa_mask) != 0 {
            nix::libc::_exit(130);
        }
        action.sa_sigaction = nix::libc::SIG_DFL;
        action.sa_flags = 0;
        if nix::libc::sigaction(nix::libc::SIGINT, &raw const action, std::ptr::null_mut()) != 0 {
            nix::libc::_exit(130);
        }

        let mut unblocked = MaybeUninit::<nix::libc::sigset_t>::uninit();
        if nix::libc::sigemptyset(unblocked.as_mut_ptr()) != 0
            || nix::libc::sigaddset(unblocked.as_mut_ptr(), nix::libc::SIGINT) != 0
        {
            nix::libc::_exit(130);
        }
        let unblocked = unblocked.assume_init();
        if nix::libc::sigprocmask(
            nix::libc::SIG_UNBLOCK,
            &raw const unblocked,
            std::ptr::null_mut(),
        ) != 0
            || nix::libc::raise(nix::libc::SIGINT) != 0
        {
            nix::libc::_exit(130);
        }
        // The default SIGINT action should have ended the process before `raise` returned.
        nix::libc::_exit(130);
    }
}

/// Enter the final output write, preventing a second line from entering it.
pub fn begin_final_output() {
    if INTERRUPT_NOTICE.get().is_none() {
        return;
    }
    if FINAL_OUTPUT
        .compare_exchange(
            OUTPUT_NOT_STARTED,
            OUTPUT_WRITING,
            Ordering::Relaxed,
            Ordering::Relaxed,
        )
        .is_err()
    {
        // An earlier interrupt already owns the final result.
        return_by_sigint();
    }
}

/// Finish the final write and honor any interrupt deferred while the line was in progress.
pub fn finish_final_output() {
    if INTERRUPT_NOTICE.get().is_none() {
        return;
    }
    match FINAL_OUTPUT.compare_exchange(
        OUTPUT_WRITING,
        OUTPUT_FINISHED,
        Ordering::Relaxed,
        Ordering::Relaxed,
    ) {
        Ok(_) => {}
        Err(INTERRUPT_DURING_OUTPUT) => {
            // The complete result has been written; stop without appending another line.
            return_by_sigint();
        }
        Err(_) => {
            // SAFETY: an impossible phase cannot be allowed to emit another result.
            return_by_sigint();
        }
    }
}

/// On SIGINT before final output starts, write the notice and re-raise SIGINT. During the final
/// write, let that complete line finish and then re-raise without appending another one. A later
/// runtime handler may chain this handler first; in that case it returns to the runtime's handler.
/// Only the first call has an effect.
pub fn exit_on_interrupt(notice: Vec<u8>) {
    use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, sigaction};
    let mut inherited = MaybeUninit::<nix::libc::sigaction>::uninit();
    // SAFETY: a null action reads the current disposition without changing it. If the query
    // fails, keep the existing policy because installing a handler could change SIG_IGN.
    if unsafe { nix::libc::sigaction(nix::libc::SIGINT, std::ptr::null(), inherited.as_mut_ptr()) }
        != 0
    {
        return;
    }
    // SAFETY: sigaction initialized the previous disposition after returning success.
    if unsafe { inherited.assume_init() }.sa_sigaction == nix::libc::SIG_IGN {
        return;
    }
    if INTERRUPT_NOTICE.set(notice.into_boxed_slice()).is_err() {
        return;
    }
    let action = SigAction::new(
        SigHandler::Handler(on_interrupt),
        SaFlags::empty(),
        SigSet::empty(),
    );
    // SAFETY: the handler uses lock-free atomics and async-signal-safe syscalls, without locks.
    let _ = unsafe { sigaction(Signal::SIGINT, &action) };
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
/// Checks that spawned login shells receive only the selected locale and terminal variables.
mod child_environment_tests {
    use super::*;

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Read one process environment snapshot into owned pairs for bounded startup polling.
    fn read_environment(pid: u32) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let raw = std::fs::read(format!("/proc/{pid}/environ"))?;
        Ok(raw
            .split(|byte| *byte == 0)
            .filter_map(|entry| {
                let separator = entry.iter().position(|byte| *byte == b'=')?;
                Some((entry[..separator].to_vec(), entry[separator + 1..].to_vec()))
            })
            .collect())
    }

    #[test]
    fn spawned_login_shell_receives_selected_environment_without_other_host_variables() {
        let expected = crate::locale::environment();
        let pty = Pty::spawn(Uid::effective().as_raw(), 80, 24).unwrap();
        let child = ChildGuard(pty.child);
        // The spawned shell can start after this test resumes; avoid treating one
        // early procfs snapshot as the shell's final environment.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let actual = loop {
            let actual = read_environment(child.0.id()).unwrap();
            let has_locale = expected.iter().all(|(name, value)| {
                let name = name.as_os_str().as_encoded_bytes();
                let value = value.as_os_str().as_encoded_bytes();
                actual
                    .iter()
                    .any(|(actual_name, actual_value)| actual_name == name && actual_value == value)
            });
            let has_terminal = actual
                .iter()
                .any(|(name, value)| name == b"TERM" && value == b"xterm-256color")
                && actual
                    .iter()
                    .any(|(name, value)| name == b"COLORTERM" && value == b"truecolor");
            if (has_locale && has_terminal) || std::time::Instant::now() >= deadline {
                break actual;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        for (name, value) in expected {
            let name = name.as_os_str().as_encoded_bytes();
            let value = value.as_os_str().as_encoded_bytes();
            assert!(
                actual.iter().any(|(actual_name, actual_value)| {
                    actual_name == name && actual_value == value
                }),
                "the login shell must receive the selected locale variable"
            );
        }
        assert!(
            actual
                .iter()
                .any(|(name, value)| name == b"TERM" && value == b"xterm-256color")
        );
        assert!(
            actual
                .iter()
                .any(|(name, value)| name == b"COLORTERM" && value == b"truecolor")
        );
        assert!(actual.iter().all(|(name, _)| {
            name == b"HOME"
                || name == b"USER"
                || name == b"LOGNAME"
                || name == b"SHELL"
                || name == b"TERM"
                || name == b"COLORTERM"
                || name == b"PATH"
                || name == b"ZDOTDIR"
                || name == b"LANG"
                || name.starts_with(b"LC_")
        }));
    }
}

#[cfg(feature = "process-per-user")]
#[path = "pty_handoff.rs"]
pub(crate) mod handoff;

/// Literal programs bypass login-shell argument conventions; the shell path is still exported.
fn session_command(shell: &Path, readiness: bool, program: &[std::ffi::OsString]) -> Command {
    let mut command = Command::new(
        program
            .first()
            .map_or(shell.as_os_str(), std::ffi::OsString::as_os_str),
    );
    let login_name = format!(
        "-{}",
        shell.file_name().unwrap_or_default().to_string_lossy()
    );
    if readiness {
        // Wait for attachment input without invoking any login rc files.
        command.args(["-c", "read -r line; printf 'infraternal-ready\\n'"]);
    } else if program.is_empty() {
        command.arg0(login_name);
    } else {
        command.args(&program[1..]);
    }
    command
}
