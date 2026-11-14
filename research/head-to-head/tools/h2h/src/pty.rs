//! The kit's stand-in for a terminal window: it owns a PTY master, runs a
//! client (`tmux attach`, `zellij attach`, `ssh -tt … tmux attach`) on the
//! slave, writes keystrokes and timestamps the bytes the client draws.
//!
//! It never renders, so every system is measured to the same point: bytes
//! delivered to the terminal. Rendering cost is the terminal's (or browser's)
//! and is outside these numbers for all systems alike.
use crate::args::die;
use crate::term::TermIo;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// A terminal viewer backed by a child process attached to a new PTY.
pub struct Pty {
    master: File,
    child: Child,
}

impl Pty {
    /// Run `/bin/sh -c command` on a new PTY of the given size, in its own session.
    pub fn spawn(command: &str, cols: u16, rows: u16, env: &[(String, String)]) -> Self {
        let mut master = -1;
        let mut slave = -1;
        let size = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
        // SAFETY: openpty writes two descriptors; the name and termios are null.
        let rc = unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), &size) };
        if rc != 0 {
            die("openpty failed");
        }
        // SAFETY: both descriptors were just returned by openpty and are owned here.
        let (master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(command);
        cmd.env("TERM", "xterm-256color");
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        // SAFETY: only async-signal-safe calls run between fork and exec.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap_or_else(|e| die(&format!("spawn: {e}")));
        Self { master, child }
    }
}

impl TermIo for Pty {
    fn send(&mut self, bytes: &[u8]) {
        self.master.write_all(bytes).unwrap_or_else(|e| die(&format!("pty write: {e}")));
    }

    fn recv(&mut self, timeout: Duration) -> Option<Vec<u8>> {
        let mut pfd = libc::pollfd { fd: self.master.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd.
        let n = unsafe { libc::poll(&mut pfd, 1, timeout.as_millis().min(i32::MAX as u128) as i32) };
        if n <= 0 {
            return None;
        }
        let mut buf = vec![0u8; 256 * 1024];
        match self.master.read(&mut buf) {
            Ok(0) | Err(_) => die("terminal client exited"),
            Ok(n) => {
                buf.truncate(n);
                Some(buf)
            }
        }
    }

    fn close(mut self: Box<Self>) {
        // Closing the window: the client gets SIGHUP and detaches.
        // SAFETY: signalling our own child's process group.
        unsafe { libc::kill(-(self.child.id() as i32), libc::SIGHUP) };
        drop(self.master);
        for _ in 0..200 {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
