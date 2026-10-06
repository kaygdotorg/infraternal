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
    pub fn spawn(uid: u32, cols: u16, rows: u16) -> io::Result<Self> {
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
        let shell = if user.shell.as_os_str().is_empty() {
            std::path::PathBuf::from("/bin/sh")
        } else {
            user.shell
        };
        let mut command = Command::new(&shell);
        let login_name = format!(
            "-{}",
            shell.file_name().unwrap_or_default().to_string_lossy()
        );
        command
            .arg0(login_name)
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
        // Preserve zsh's supported profile location for isolated canaries.
        if let Some(directory) = std::env::var_os("ZDOTDIR") {
            command.env("ZDOTDIR", directory);
        }
        // SAFETY: the callback runs after fork, uses only libc-backed syscalls
        // and existing immutable data, and neither allocates nor takes locks.
        // Descriptor 0 is Command's installed slave; privilege order prevents
        // retaining supplementary root groups after dropping uid.
        unsafe {
            command.pre_exec(move || {
                unistd::setsid().map_err(errno)?;
                nix::sys::signal::SigSet::empty()
                    .thread_set_mask()
                    .map_err(errno)?;
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
    pub fn signal(&self, number: u8) -> io::Result<()> {
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
        // Job control gives full-screen applications their own foreground group.
        // Send to that group, not merely to the login shell's process group.
        let group = unistd::tcgetpgrp(&self.master).map_err(errno)?;
        killpg(group, signal).map_err(errno)
    }
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
            unistd::setsid().map_err(errno)?;
            // SAFETY: same single-threaded startup boundary as the first fork.
            match unsafe { unistd::fork() }.map_err(errno)? {
                ForkResult::Parent { .. } => std::process::exit(0),
                ForkResult::Child => {
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
