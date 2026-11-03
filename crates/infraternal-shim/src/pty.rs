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

// Broad TERM compatibility, true colour and the cooperative startup marker [D315].
const TERMINAL_ENVIRONMENT: [(&str, &str); 3] = [
    ("TERM", "xterm-256color"),
    ("COLORTERM", "truecolor"),
    ("INFRATERNAL_SESSION", "1"),
];

#[cfg(feature = "host-login")]
pub(super) fn inherit_login_process(
    command: &mut Command,
    process: &File,
) -> io::Result<std::path::PathBuf> {
    if !process.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "login process pin is not a directory",
        ));
    }
    let descriptor = inherit_descriptor(command, process)?;
    Ok(std::path::PathBuf::from(format!(
        "/proc/self/fd/{descriptor}"
    )))
}

#[cfg(feature = "host-login")]
pub(crate) fn inherit_descriptor(
    command: &mut Command,
    file: &dyn std::os::fd::AsFd,
) -> io::Result<i32> {
    // A borrowed descriptor keeps one audited implementation for both files
    // and Unix streams, without a separate generic copy of the spawn callback.
    let descriptor = fcntl(file.as_fd(), FcntlArg::F_DUPFD_CLOEXEC(8)).map_err(errno)?;
    // SAFETY: this fresh descriptor has one owner, captured until spawn ends.
    let source = unsafe { File::from_raw_fd(descriptor) };
    // SAFETY: only an async-signal-safe descriptor syscall runs before exec.
    // Keep the occupied slot: a fixed destination could overwrite Command's
    // private exec-error pipe. The parent copy always retains CLOEXEC.
    unsafe {
        command.pre_exec(move || {
            if nix::libc::fcntl(source.as_raw_fd(), nix::libc::F_SETFD, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(descriptor)
}

#[cfg(feature = "host-login")]
pub(crate) fn duplicate_inherited_descriptor(descriptor: i32) -> io::Result<File> {
    if descriptor < 8 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    // SAFETY: fcntl validates the integer without borrowing an invalid raw fd.
    // Only the fresh returned descriptor is owned. The input remains borrowed
    // for this process's lifetime and is excluded from every descendant exec.
    let duplicated = unsafe { nix::libc::fcntl(descriptor, nix::libc::F_DUPFD_CLOEXEC, 8) };
    if duplicated == -1 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(duplicated) };
    let flags = unsafe { nix::libc::fcntl(descriptor, nix::libc::F_GETFD) };
    if flags == -1
        || unsafe {
            nix::libc::fcntl(
                descriptor,
                nix::libc::F_SETFD,
                flags | nix::libc::FD_CLOEXEC,
            )
        } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

#[cfg(feature = "host-login")]
pub(crate) fn validate_master(master: &File) -> io::Result<()> {
    let mut number = 0_u32;
    // SAFETY: TIOCGPTN writes exactly one u32. It accepts PTY masters only,
    // preventing a socket, file or slave from being adopted as the output path.
    if unsafe { nix::libc::ioctl(master.as_raw_fd(), nix::libc::TIOCGPTN, &raw mut number) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(feature = "host-login")]
pub(super) fn protect_login_process() -> io::Result<()> {
    protect_login_process_at(std::path::Path::new("/proc/self/fd/5"))
}

#[cfg(feature = "host-login")]
pub(super) fn protect_login_process_at(path: &std::path::Path) -> io::Result<()> {
    let Some(descriptor) = crate::login_ready::inherited_pin_descriptor(path)? else {
        // External pins are held by their controller, not inherited here.
        return Ok(());
    };
    // SAFETY: fcntl changes descriptor policy only and takes no pointers. The
    // synchronous hidden CLI owns this inherited pin. A proxy duplicates
    // its own pin before exec; unrelated future children never inherit it.
    let flags = unsafe { nix::libc::fcntl(descriptor, nix::libc::F_GETFD) };
    if flags == -1
        || unsafe {
            nix::libc::fcntl(
                descriptor,
                nix::libc::F_SETFD,
                flags | nix::libc::FD_CLOEXEC,
            )
        } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub struct Pty {
    pub master: File,
    pub child: crate::child::OwnedChild,
}

/// Replacing a startup file must not silently discard ACLs or other security metadata.
pub(crate) fn file_has_attributes(file: &File) -> io::Result<bool> {
    // SAFETY: a null buffer and zero size query only the required list length;
    // the borrowed descriptor remains open and the kernel retains no pointer.
    let length = unsafe { nix::libc::flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
    if length >= 0 {
        return Ok(length != 0);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(nix::libc::ENOTSUP) {
        Ok(false)
    } else {
        Err(error)
    }
}
fn errno(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

/// Keep sparse shim mappings out of khugepaged while retaining the caller's
/// policy for the user's shell. This runs during single-threaded shim startup.
pub(crate) fn disable_shim_thp() -> io::Result<Option<nix::libc::c_int>> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: these prctl operations use scalar arguments only and retain
        // no pointers. Read first: a launcher may already have disabled THP.
        let inherited = unsafe { nix::libc::prctl(nix::libc::PR_GET_THP_DISABLE, 0, 0, 0, 0) };
        if inherited == -1 {
            return Err(io::Error::last_os_error());
        }
        set_thp_disabled(1)?;
        Ok(Some(inherited))
    }
    #[cfg(not(target_os = "linux"))]
    Ok(None)
}

#[cfg(target_os = "linux")]
fn set_thp_disabled(disabled: nix::libc::c_int) -> io::Result<()> {
    // SAFETY: scalar-only process policy syscall, also safe in the post-fork
    // child; no allocation, locks or pointers are involved.
    // GET also reports bit 1 for the kernel's except-advised mode. SET takes
    // that bit in arg3, so preserve it when restoring an inherited policy.
    if unsafe {
        nix::libc::prctl(
            nix::libc::PR_SET_THP_DISABLE,
            disabled & 1,
            disabled & 2,
            0,
            0,
        )
    } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `PR_SET_THP_DISABLE` survives fork/exec. Undo only the shim's opt-out so
/// shells and their programs retain the launcher's policy after exec.
fn restore_child_thp(inherited: Option<nix::libc::c_int>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    if let Some(disabled) = inherited {
        set_thp_disabled(disabled)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = inherited;
    Ok(())
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

#[cfg(feature = "host-login")]
pub(crate) fn announce_login() -> io::Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
    let record = crate::login_ready::encode(unistd::getpid().as_raw(), Uid::effective().as_raw())?;
    let process = File::open("/proc/self")?;
    let descriptors = [process.as_raw_fd()];
    if sendmsg::<()>(
        io::stdout().as_raw_fd(),
        &[std::io::IoSlice::new(&record)],
        &[ControlMessage::ScmRights(&descriptors)],
        MsgFlags::MSG_NOSIGNAL,
        None,
    )
    .map_err(errno)?
        != record.len()
    {
        return Err(io::ErrorKind::WriteZero.into());
    }
    // Only this startup record uses stdout. Release the inherited socket while
    // keeping a valid standard slot, so later sockets cannot alias stdout.
    let null = File::options().write(true).open("/dev/null")?;
    unistd::dup2_stdout(&null).map_err(errno)
}
/// Receive the original process inode, never reopening a numeric PID after announcement.
#[cfg(feature = "host-login")]
pub(crate) fn receive_login_ready(
    peer: &impl AsRawFd,
) -> io::Result<(crate::login_ready::Ready, File)> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    let mut bytes = [0; crate::login_ready::LENGTH];
    let mut ancillary = nix::cmsg_space!([i32; 253]);
    let mut files = Vec::new();
    let (length, truncated) = {
        let mut buffers = [std::io::IoSliceMut::new(&mut bytes)];
        let received = recvmsg::<()>(
            peer.as_raw_fd(),
            &mut buffers,
            Some(&mut ancillary),
            MsgFlags::MSG_CMSG_CLOEXEC | MsgFlags::MSG_DONTWAIT,
        )
        .map_err(errno)?;
        for message in received.cmsgs().map_err(errno)? {
            if let ControlMessageOwned::ScmRights(descriptors) = message {
                for fd in descriptors {
                    // SAFETY: the kernel creates fresh SCM_RIGHTS descriptors; each is
                    // owned once and closed even when validation below rejects the frame.
                    files.push(unsafe { File::from_raw_fd(fd) });
                }
            }
        }
        (
            received.bytes,
            received
                .flags
                .intersects(MsgFlags::MSG_CTRUNC | MsgFlags::MSG_TRUNC),
        )
    };
    if length == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if truncated || files.len() != 1 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let record = crate::login_ready::decode(&bytes[..length])?;
    let process = files.pop().ok_or(io::ErrorKind::InvalidData)?;
    if !process.metadata()?.is_dir() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok((record, process))
}
// Account ownership, restrictive mode and descriptor policy are shared by
// local startup and pre-exec login transfer; no second PTY implementation.
pub(crate) fn open_terminal(user: &User, cols: u16, rows: u16) -> io::Result<(File, File)> {
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
    let master = File::from(terminal.master);
    fcntl(&master, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).map_err(errno)?;
    Ok((master, slave))
}

impl Pty {
    #[cfg(test)]
    pub fn spawn(uid: u32, cols: u16, rows: u16) -> io::Result<Self> {
        Self::spawn_with_login(uid, cols, rows, &[0; 16], None, None, None, None)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_with_login(
        uid: u32,
        cols: u16,
        rows: u16,
        session: &[u8; 16],
        login: Option<&std::path::Path>,
        login_worker_pid: Option<i32>,
        login_worker_parent: Option<i32>,
        login_worker_proc: Option<&std::path::Path>,
    ) -> io::Result<Self> {
        Self::spawn_login_configured(
            uid,
            cols,
            rows,
            session,
            login,
            login_worker_pid,
            login_worker_parent,
            login_worker_proc,
            false,
        )
    }
    pub fn spawn_with_readiness(
        uid: u32,
        cols: u16,
        rows: u16,
        readiness: bool,
        child_thp: Option<nix::libc::c_int>,
    ) -> io::Result<Self> {
        Self::spawn_with_command(uid, cols, rows, readiness, &[], child_thp)
    }
    pub fn spawn_with_command(
        uid: u32,
        cols: u16,
        rows: u16,
        readiness: bool,
        program: &[std::ffi::OsString],
        child_thp: Option<nix::libc::c_int>,
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
        let mut command = linux_command(&user, slave, readiness, program, child_thp)?;
        let child = command.spawn()?;
        let master = File::from(terminal.master);
        fcntl(&master, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).map_err(errno)?;
        Ok(Self {
            master,
            child: crate::child::OwnedChild::Local(child),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_login_configured(
        uid: u32,
        cols: u16,
        rows: u16,
        session: &[u8; 16],
        login: Option<&std::path::Path>,
        login_worker_pid: Option<i32>,
        login_worker_parent: Option<i32>,
        login_worker_proc: Option<&std::path::Path>,
        readiness: bool,
    ) -> io::Result<Self> {
        #[cfg(not(feature = "host-login"))]
        if login.is_some()
            || login_worker_pid.is_some()
            || login_worker_parent.is_some()
            || login_worker_proc.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "host login support was compiled out",
            ));
        }
        let user = User::from_uid(Uid::from_raw(uid))
            .map_err(errno)?
            .ok_or_else(|| io::Error::other("target uid has no login account"))?;
        let (master, slave) = open_terminal(&user, cols, rows)?;
        #[cfg(feature = "host-login")]
        let child = if let Some(endpoint) = login {
            crate::child::OwnedChild::login(crate::login::start(
                endpoint,
                uid,
                session,
                &slave,
                login_worker_pid,
                login_worker_proc,
                login_worker_parent,
            )?)
        } else {
            crate::child::OwnedChild::Local(spawn_shell(&user, slave, session, false, readiness)?)
        };
        #[cfg(not(feature = "host-login"))]
        let child =
            crate::child::OwnedChild::Local(spawn_shell(&user, slave, session, false, readiness)?);
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
        let Some(pid) = self.child.local_pid() else {
            // A login worker owns the shell PID; closing its authenticated
            // terminal lease asks that owner to stop and reap the shell.
            return self.child.kill();
        };
        let group = nix::unistd::Pid::from_raw(i32::try_from(pid).map_err(io::Error::other)?);
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
#[cfg(all(test, feature = "host-login"))]
fn inherit_login_ready(command: &mut Command, source: &impl std::os::fd::AsFd) -> io::Result<()> {
    let descriptor = fcntl(source, FcntlArg::F_DUPFD_CLOEXEC(6)).map_err(errno)?;
    // SAFETY: fcntl returns a fresh owned descriptor. Its capture stays live
    // through spawn and closes on exec. Source >=6 cannot alias reserved
    // leg-B fd3 or the destination readiness descriptor 4.
    let ready = unsafe { File::from_raw_fd(descriptor) };
    // SAFETY: dup2 is async-signal-safe and only changes the fresh child's
    // descriptor table. It clears CLOEXEC on reserved readiness descriptor 4.
    unsafe {
        command.pre_exec(move || {
            if nix::libc::dup2(ready.as_raw_fd(), 4) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
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

#[cfg(target_os = "linux")]
pub(crate) fn prepare_parent_bound_child(command: &mut Command) {
    let owner = unistd::getpid();
    // SAFETY: the child hook runs between fork and exec and only calls prctl/getppid wrappers.
    // Installing the signal before checking the parent closes the fork-to-hook race.
    unsafe {
        command.pre_exec(move || {
            nix::sys::prctl::set_pdeathsig(Signal::SIGTERM).map_err(io::Error::from)?;
            if unistd::getppid() != owner {
                return Err(io::Error::other("proxy owner exited before child startup"));
            }
            Ok(())
        });
    }
}

/// Keep the proxy's rootful credential drop inside the audited child boundary [#281].
#[cfg(unix)]
pub(crate) fn prepare_proxy_child(
    command: &mut Command,
    working_directory: &File,
    descriptors: &[(i32, i32)],
    identity: Option<(u32, u32)>,
) -> io::Result<()> {
    let working_directory = working_directory.as_raw_fd();
    let descriptors = descriptors.to_vec();
    if descriptors
        .iter()
        .any(|(source, target)| *source < 3 || *target < 64 || source == target)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "proxy child descriptor mapping is outside policy",
        ));
    }
    #[cfg(target_os = "linux")]
    let owner = unistd::getpid();
    // SAFETY: the established shim hooks set signal defaults, close the trusted
    // control descriptor, and bind the process to its owner before this hook.
    // This hook only remaps pre-opened descriptors, enters the pinned working
    // directory, drops credentials and re-arms the parent-death signal before exec.
    unsafe {
        command.pre_exec(move || {
            for (source, target) in &descriptors {
                if nix::libc::dup2(*source, *target) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            if nix::libc::fchdir(working_directory) == -1 {
                return Err(io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            if let Some((uid, gid)) = identity {
                drop_proxy_root(uid, gid)?;
            }
            #[cfg(not(target_os = "linux"))]
            if let Some((uid, gid)) = identity {
                unistd::setgroups(&[]).map_err(errno)?;
                unistd::setgid(unistd::Gid::from_raw(gid)).map_err(errno)?;
                unistd::setuid(unistd::Uid::from_raw(uid)).map_err(errno)?;
            }
            #[cfg(target_os = "linux")]
            set_no_new_privileges()?;
            // Changing the effective UID clears the parent-death signal, so the earlier owner
            // binding no longer holds after the drop. Re-arm it last, then recheck the parent:
            // an owner that died before this point must not leave a listener behind. SIGKILL,
            // because a graceful stop would keep the listeners open while it drains [#281].
            #[cfg(target_os = "linux")]
            {
                nix::sys::prctl::set_pdeathsig(Signal::SIGKILL).map_err(io::Error::from)?;
                if unistd::getppid() != owner {
                    return Err(io::Error::other("proxy owner exited before child startup"));
                }
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[cfg(target_os = "linux")]
fn drop_proxy_root(uid: u32, gid: u32) -> io::Result<()> {
    const CAP_NET_BIND_SERVICE: u32 = 10;
    const CAPABILITY_BIT: u32 = 1 << CAP_NET_BIND_SERVICE;
    const PR_SET_KEEPCAPS: i32 = 8;
    const PR_CAPBSET_DROP: i32 = 24;
    const PR_CAP_AMBIENT: i32 = 47;
    const PR_CAP_AMBIENT_RAISE: u32 = 2;
    const PR_CAP_AMBIENT_CLEAR_ALL: u32 = 4;

    linux_prctl(PR_SET_KEEPCAPS, 1, 0)?;
    for capability in 0..64_u32 {
        if capability == CAP_NET_BIND_SERVICE {
            continue;
        }
        let result = unsafe {
            nix::libc::prctl(
                PR_CAPBSET_DROP,
                nix::libc::c_ulong::from(capability),
                0,
                0,
                0,
            )
        };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(nix::libc::EINVAL) {
                return Err(error);
            }
        }
    }
    unistd::setgroups(&[]).map_err(errno)?;
    unistd::setgid(unistd::Gid::from_raw(gid)).map_err(errno)?;
    unistd::setuid(unistd::Uid::from_raw(uid)).map_err(errno)?;

    let header = CapabilityHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [
        CapabilityData {
            effective: CAPABILITY_BIT,
            permitted: CAPABILITY_BIT,
            inheritable: CAPABILITY_BIT,
        },
        CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: the kernel reads fixed-layout, initialized capability structures for this process.
    let result =
        unsafe { nix::libc::syscall(nix::libc::SYS_capset, &raw const header, data.as_ptr()) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    linux_prctl(
        PR_CAP_AMBIENT,
        nix::libc::c_ulong::from(PR_CAP_AMBIENT_CLEAR_ALL),
        0,
    )?;
    linux_prctl(
        PR_CAP_AMBIENT,
        nix::libc::c_ulong::from(PR_CAP_AMBIENT_RAISE),
        nix::libc::c_ulong::from(CAP_NET_BIND_SERVICE),
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_no_new_privileges() -> io::Result<()> {
    const PR_SET_NO_NEW_PRIVS: i32 = 38;
    linux_prctl(PR_SET_NO_NEW_PRIVS, 1, 0)
}

#[cfg(target_os = "linux")]
fn linux_prctl(
    option: i32,
    argument: nix::libc::c_ulong,
    extra: nix::libc::c_ulong,
) -> io::Result<()> {
    // SAFETY: prctl consumes only the scalar arguments supplied by this module.
    if unsafe { nix::libc::prctl(option, argument, extra, 0, 0) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Keep the public direct-exec policy on the same audited descriptor boundary.
pub(super) fn prepare_child_without_control(command: &mut Command) {
    prepare_isolated_child(command);
}

pub(super) fn prepare_isolated_child(command: &mut Command) {
    prepare_child(command);
    // SAFETY: fcntl is async-signal-safe and uses no captured allocation or lock.
    // Do not close this slot: Command may use it to report an exec failure when
    // the parent had no fd3. CLOEXEC preserves that pipe until exec succeeds.
    unsafe {
        command.pre_exec(|| {
            if nix::libc::fcntl(3, nix::libc::F_SETFD, nix::libc::FD_CLOEXEC) < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(nix::libc::EBADF) {
                    return Err(error);
                }
            }
            Ok(())
        });
    }
}

pub(super) fn prepare_independent_session(command: &mut Command) {
    // SAFETY: setsid is async-signal-safe, with no inherited Rust state touched.
    unsafe {
        command.pre_exec(|| unistd::setsid().map(|_| ()).map_err(errno));
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

/// Real exec regressions for leg-B isolation and controller-owned sessions.
#[cfg(test)]
mod isolated_spawn_tests {
    use super::*;
    use std::io::{BufRead as _, Write as _};

    #[test]
    fn isolated_exec_excludes_fd3_and_keeps_exec_errors() {
        let source = File::open("/dev/null").unwrap();
        let duplicate = fcntl(&source, FcntlArg::F_DUPFD_CLOEXEC(4)).unwrap();
        // SAFETY: fcntl returned a fresh descriptor owned exactly once here.
        let source = unsafe { File::from_raw_fd(duplicate) };
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "test ! -e /proc/self/fd/3"]);
        // SAFETY: the fixture captures one live fd and only duplicates it in
        // the child. It never replaces a descriptor in the parent test runner.
        unsafe {
            command.pre_exec(move || {
                if nix::libc::dup2(source.as_raw_fd(), 3) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        prepare_isolated_child(&mut command);
        assert!(command.status().unwrap().success());

        let mut missing = Command::new("/nonexistent/infraternal-spawn-fixture");
        prepare_isolated_child(&mut missing);
        assert_eq!(missing.spawn().unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn owned_child_has_an_independent_session_without_changing_parent() {
        let original = unistd::getsid(None).unwrap();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf 'ready\\n'; read line"]);
        command.stdin(Stdio::piped()).stdout(Stdio::piped());
        prepare_isolated_child(&mut command);
        prepare_independent_session(&mut command);
        let mut child = command.spawn().unwrap();
        let mut ready = String::new();
        std::io::BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        let pid = unistd::Pid::from_raw(child.id().try_into().unwrap());
        let session = unistd::getsid(Some(pid));
        child.stdin.take().unwrap().write_all(b"done\n").unwrap();
        let status = child.wait().unwrap();
        assert_eq!(ready, "ready\n");
        assert_eq!(session.unwrap(), pid);
        assert!(status.success());
        assert_eq!(unistd::getsid(None).unwrap(), original);
    }
}

/// Exercise pin inheritance with closed reserved slots in a private process.
#[cfg(all(test, feature = "host-login"))]
mod pin_exec_error_tests {
    use super::*;

    #[test]
    fn captured_pin_becomes_private_before_descendant_exec() {
        const FIXTURE: &str = "INFRATERNAL_PIN_PRIVATE_FIXTURE";
        if let Some(path) = std::env::var_os(FIXTURE) {
            let path = std::path::Path::new(&path);
            assert!(path.is_dir());
            protect_login_process_at(path).unwrap();
            assert!(
                Command::new("/bin/sh")
                    .args(["-c", "test ! -e \"$1\"", "pin-private"])
                    .arg(path)
                    .status()
                    .unwrap()
                    .success()
            );
            return;
        }
        let process = File::open("/proc/self").unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--exact",
            "pty::pin_exec_error_tests::captured_pin_becomes_private_before_descendant_exec",
            "--nocapture",
        ]);
        let path = inherit_login_process(&mut command, &process).unwrap();
        let descriptor = crate::login_ready::inherited_pin_descriptor(&path)
            .unwrap()
            .unwrap();
        command.env(FIXTURE, path);
        assert!(command.status().unwrap().success());
        // SAFETY: Command still owns the captured descriptor. Inspect only its
        // flags; preparing the child's copy must not change the parent's flags.
        let flags = unsafe { nix::libc::fcntl(descriptor, nix::libc::F_GETFD) };
        assert_ne!(flags & nix::libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn inherited_pin_preserves_exec_failure_with_fd5_closed() {
        const FIXTURE: &str = "INFRATERNAL_PIN_EXEC_ERROR_FIXTURE";
        if std::env::var_os(FIXTURE).is_none() {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "pty::pin_exec_error_tests::inherited_pin_preserves_exec_failure_with_fd5_closed",
                    "--nocapture",
                ])
                .env(FIXTURE, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        // Only this fresh synchronous fixture changes its own fd table. Leave
        // slots 4/5 free for Command's private exec-error pipe; never close
        // descriptors in the parent or the parallel test runner.
        for descriptor in [3, 4, 5] {
            let _ = unistd::close(descriptor);
        }
        let process = File::open("/proc/self").unwrap();
        let mut command = Command::new("/nonexistent/infraternal-pin-exec-fixture");
        inherit_login_process(&mut command, &process).unwrap();
        let error = match command.spawn() {
            Ok(mut child) => {
                let _ = child.wait();
                panic!("pin inheritance hid the missing executable");
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}

/// The Linux PTY child: the account's shell with an explicit environment,
/// dropping to the account in `pre_exec` after it becomes the session leader.
fn linux_command(
    user: &User,
    slave: File,
    readiness: bool,
    program: &[std::ffi::OsString],
    child_thp: Option<nix::libc::c_int>,
) -> io::Result<Command> {
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
        .envs(TERMINAL_ENVIRONMENT)
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
            restore_child_thp(child_thp)?;
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
    Ok(command)
}

// The broker inherits the host login environment/limits; legacy PTYs start
// from the existing explicit environment. Both paths use the same shell setup.
fn shell_command(user: &User, inherited: bool, readiness: bool) -> io::Result<Command> {
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
        user.shell.clone()
    };
    let mut command = Command::new(&shell);
    let login_name = format!(
        "-{}",
        shell.file_name().unwrap_or_default().to_string_lossy()
    );
    // PAM establishes this environment once per login. Snapshot it before
    // readiness so each terminal avoids rebuilding the inherited environment;
    // explicit account variables and the per-terminal marker still win below.
    command.env_clear();
    if inherited {
        command.envs(std::env::vars_os());
    }
    if readiness {
        command.args(["-c", "read -r line; printf 'infraternal-ready\\n'"]);
    } else {
        command.arg0(login_name);
    }
    command
        .env("HOME", &user.dir)
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env("SHELL", &shell)
        .env("TERM", "xterm-256color")
        .env("COLORTERM", "truecolor")
        .env("PATH", "/usr/local/bin:/usr/bin:/bin");
    // Legacy terminals preserve only host locale variables; real login shells
    // retain the locale selected by the host PAM session.
    if !inherited {
        for (name, value) in crate::session_locale_environment() {
            command.env(name, value);
        }
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
    if !readiness {
        crate::shell_startup::configure(&mut command, &shell, true, inherited);
    }
    Ok(command)
}

fn spawn_shell(
    user: &User,
    slave: File,
    session: &[u8; 16],
    inherited: bool,
    readiness: bool,
) -> io::Result<Child> {
    spawn_command(
        &mut shell_command(user, inherited, readiness)?,
        slave,
        session,
    )
}

// All descriptor clones exist before mutating the reusable command. Clear its
// stdio on both spawn success and failure: retaining even one slave would hide
// terminal EOF and keep a cancelled shell's device alive for the whole login.
fn spawn_command(command: &mut Command, slave: File, session: &[u8; 16]) -> io::Result<Child> {
    let input = slave.try_clone()?;
    let output = slave.try_clone()?;
    command.env("INFRATERNAL_SESSION", session_marker(session));
    command
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output))
        .stderr(Stdio::from(slave));
    let result = command.spawn();
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    result
}

/// One PAM login's immutable shell setup; each spawn owns a fresh terminal and
/// session marker. No terminal descriptors or child buffers are retained here.
#[cfg(feature = "host-login")]
pub(crate) struct LoginShell {
    command: Command,
    uid: Uid,
}

#[cfg(feature = "host-login")]
impl LoginShell {
    pub(crate) fn new(user: &User) -> io::Result<Self> {
        if user.uid != Uid::effective() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(Self {
            command: shell_command(user, true, false)?,
            uid: user.uid,
        })
    }

    pub(crate) fn spawn(&mut self, slave: File, session: &[u8; 16]) -> io::Result<Child> {
        if self.uid != Uid::effective() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        spawn_command(&mut self.command, slave, session)
    }
}

/// Send exactly one terminal descriptor alongside the fixed session identity.
#[cfg(feature = "host-login")]
pub(crate) fn send_terminal(
    peer: &std::os::unix::net::UnixStream,
    session: &[u8; 16],
) -> io::Result<()> {
    send_terminal_from(peer, &io::stdin(), session)
}

#[cfg(feature = "host-login")]
pub(crate) fn send_terminal_from(
    peer: &std::os::unix::net::UnixStream,
    terminal: &impl std::os::fd::AsFd,
    session: &[u8; 16],
) -> io::Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
    if !unistd::isatty(terminal).map_err(errno)? {
        return Err(io::Error::other("login request requires a terminal slave"));
    }
    let fds = [terminal.as_fd().as_raw_fd()];
    let bytes = [std::io::IoSlice::new(session)];
    let size = sendmsg::<()>(
        peer.as_raw_fd(),
        &bytes,
        &[ControlMessage::ScmRights(&fds)],
        MsgFlags::MSG_NOSIGNAL,
        None,
    )
    .map_err(errno)?;
    if size != session.len() {
        return Err(io::ErrorKind::WriteZero.into());
    }
    Ok(())
}

#[cfg(feature = "host-login")]
pub(crate) enum LoginRequest {
    Ready,
    Stop,
    Terminal(File, [u8; 16]),
}

/// A descriptor is transferred once into File, including malformed-message cleanup.
#[cfg(feature = "host-login")]
pub(crate) fn receive_terminal(peer: &std::os::unix::net::UnixStream) -> io::Result<LoginRequest> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    let mut bytes = [0; 16];
    let mut ancillary = nix::cmsg_space!([i32; 253]);
    let mut files = Vec::new();
    let (length, truncated) = {
        let mut buffers = [std::io::IoSliceMut::new(&mut bytes)];
        let received = recvmsg::<()>(
            peer.as_raw_fd(),
            &mut buffers,
            Some(&mut ancillary),
            MsgFlags::MSG_CMSG_CLOEXEC | MsgFlags::MSG_WAITALL,
        )
        .map_err(errno)?;
        for message in received.cmsgs().map_err(errno)? {
            if let ControlMessageOwned::ScmRights(fds) = message {
                for fd in fds {
                    // SAFETY: SCM_RIGHTS installs fresh descriptors in this process;
                    // MSG_CMSG_CLOEXEC protects exec and File owns each exactly once.
                    files.push(unsafe { File::from_raw_fd(fd) });
                }
            }
        }
        (
            received.bytes,
            received
                .flags
                .intersects(MsgFlags::MSG_CTRUNC | MsgFlags::MSG_TRUNC),
        )
    };
    if truncated {
        return Err(io::Error::other("truncated login descriptor request"));
    }
    match crate::login::decode_header(&bytes[..length], files.len())? {
        crate::login::RequestHeader::Ready => Ok(LoginRequest::Ready),
        crate::login::RequestHeader::Stop => Ok(LoginRequest::Stop),
        crate::login::RequestHeader::Terminal(session) => {
            let file = files
                .pop()
                .ok_or_else(|| io::Error::other("missing login terminal"))?;
            if !unistd::isatty(&file).map_err(errno)? {
                return Err(io::Error::other("login descriptor is not a terminal"));
            }
            Ok(LoginRequest::Terminal(file, session))
        }
    }
}

/// Transfer the live broker connection, so shell exit does not release terminal ownership.
#[cfg(feature = "host-login")]
pub(crate) fn notify_started(peer: &std::os::unix::net::UnixStream) -> io::Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
    let descriptors = [peer.as_raw_fd()];
    let buffers = [std::io::IoSlice::new(b"A")];
    if sendmsg::<()>(
        4,
        &buffers,
        &[ControlMessage::ScmRights(&descriptors)],
        MsgFlags::MSG_NOSIGNAL,
        None,
    )
    .map_err(errno)?
        != 1
    {
        return Err(io::ErrorKind::WriteZero.into());
    }
    Ok(())
}

fn session_marker(session: &[u8; 16]) -> String {
    use std::fmt::Write as _;
    session
        .iter()
        .fold(String::with_capacity(32), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
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

/// Send `signal` to the process a pidfd names. Unlike `kill(pid)`, this can't reach a later
/// process that reused the PID: once the named process is gone the call fails with `ESRCH`.
#[cfg(target_os = "linux")]
pub(super) fn signal_process_descriptor(
    process: std::os::fd::BorrowedFd<'_>,
    signal: nix::sys::signal::Signal,
) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;
    // SAFETY: pidfd_send_signal takes a borrowed descriptor that outlives the call, a signal
    // number, a null siginfo pointer (the kernel then fills in a kill-like siginfo) and zero
    // flags. It reads no memory from us and returns 0 or -1 with errno.
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_pidfd_send_signal,
            process.as_raw_fd(),
            signal as nix::libc::c_int,
            std::ptr::null::<nix::libc::siginfo_t>(),
            0_u32,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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

#[cfg(all(test, not(feature = "host-login")))]
mod compiled_out_login_tests {
    //! Programmatic login configuration cannot activate a removed descriptor bridge.
    use super::*;
    #[test]
    fn disabled_login_refuses_worker_endpoint_before_spawning() {
        let result = Pty::spawn_with_login(
            Uid::effective().as_raw(),
            80,
            24,
            &[0; 16],
            Some(std::path::Path::new("/unavailable-login-fixture")),
            None,
            None,
            None,
        );
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::Unsupported);
    }
}

#[cfg(all(test, feature = "host-login"))]
mod inherited_login_process_tests {
    //! Process pins cross exec without asking the child to inspect a protected parent's descriptors.
    use super::*;
    use std::io::Read as _;
    #[test]
    fn reserved_ready_source_survives_process_pin_transfer() {
        const FIXTURE: &str = "INFRATERNAL_READY_PIN_FIXTURE";
        if std::env::var_os(FIXTURE).is_none() {
            assert!(Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "pty::inherited_login_process_tests::reserved_ready_source_survives_process_pin_transfer"])
                .env(FIXTURE, "1").status().unwrap().success());
            return;
        }
        let (parent, ready) = std::os::unix::net::UnixStream::pair().unwrap();
        let parent_copy = parent.try_clone().unwrap();
        let ready_copy = ready.try_clone().unwrap();
        drop(parent);
        drop(ready);
        // SAFETY: this isolated fixture owns no descriptor 5 after its original
        // socket pair closes. Duplicate the ready socket onto the reserved pin
        // slot to reproduce callback ordering with a small descriptor table.
        assert_ne!(unsafe { nix::libc::dup2(ready_copy.as_raw_fd(), 5) }, -1);
        let ready = unsafe { File::from_raw_fd(5) };
        // Open the process pin after reserving fd 5 so the fixture cannot
        // overwrite an owned File when it installs the readiness descriptor.
        let process = File::open("/proc/self").unwrap();
        let mut child = Command::new("/bin/sh");
        let pin = inherit_login_process(&mut child, &process).unwrap();
        child.args(["-c", "test -d \"$1\" && printf r >&4", "pin-ready"]);
        child.arg(pin);
        inherit_login_ready(&mut child, &ready).unwrap();
        assert!(
            child.status().unwrap().success(),
            "readiness source was replaced by the process pin"
        );
        let mut response = [0];
        (&parent_copy).read_exact(&mut response).unwrap();
        assert_eq!(&response, b"r");
    }

    #[test]
    fn child_reads_pin_with_nondumpable_parent() {
        const FIXTURE: &str = "INFRATERNAL_NON_DUMPABLE_PIN_FIXTURE";
        if std::env::var_os(FIXTURE).is_none() {
            assert!(Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "pty::inherited_login_process_tests::child_reads_pin_with_nondumpable_parent"])
                .env(FIXTURE, "1").status().unwrap().success());
            return;
        }
        nix::sys::prctl::set_dumpable(false).unwrap();
        let process = File::open("/proc/self").unwrap();
        let external = format!(
            "/proc/{}/fd/{}/stat",
            std::process::id(),
            process.as_raw_fd()
        );
        if !Uid::effective().is_root() {
            assert!(
                !Command::new("/bin/sh")
                    .args(["-c", "test -r \"$1\"", "pin-external", &external])
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let mut child = Command::new("/bin/sh");
        let pin = inherit_login_process(&mut child, &process).unwrap();
        child.args(["-c", "test -r \"$1/stat\"", "pin-child"]);
        child.arg(pin);
        assert!(
            child.status().unwrap().success(),
            "child could not read its inherited process pin"
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
/// Checks that spawned login shells receive only the selected locale and terminal variables.
mod child_environment_tests {
    use super::*;

    struct ChildGuard(crate::child::OwnedChild);
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
        assert!(
            actual
                .iter()
                .any(|(name, value)| name == b"INFRATERNAL_SESSION" && !value.is_empty())
        );
        assert!(actual.iter().all(|(name, _)| {
            name.as_slice() == b"HOME"
                || name.as_slice() == b"USER"
                || name.as_slice() == b"LOGNAME"
                || name.as_slice() == b"SHELL"
                || name.as_slice() == b"TERM"
                || name.as_slice() == b"COLORTERM"
                || name.as_slice() == b"INFRATERNAL_SESSION"
                || name.as_slice() == b"PATH"
                || name.as_slice() == b"ZDOTDIR"
                || name.as_slice() == b"LANG"
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
