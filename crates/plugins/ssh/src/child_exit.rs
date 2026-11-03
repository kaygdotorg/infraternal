//! Asks whether an owned child has exited while leaving it unreaped.
//!
//! The SSH helpers keep their process-group leader unreaped until the group
//! is retired (see `process::Group`): while the leader is a zombie its id
//! cannot be reused, so a later group signal cannot reach a stranger. The
//! exit check must therefore never reap.
//!
//! Linux answers with `waitid(WEXITED | WNOWAIT | WNOHANG)`. macOS has no
//! `WNOWAIT` (and nix exposes no `waitid` there), so it registers the
//! kernel's exit note for the pid on a fresh kqueue and polls it with a zero
//! timeout; kqueue never reaps either. An exited child either delivers
//! `NOTE_EXIT` at once or is refused with `ESRCH`, depending on how far its
//! exit has progressed; both mean "exited". The caller owns the unreaped
//! child, so `ESRCH` cannot mean a different process.

use nix::{errno::Errno, unistd::Pid};

/// Whether `pid`, an unreaped child of this process, has exited.
/// # Errors
/// Returns the kernel error when the state cannot be read.
#[cfg(target_os = "linux")]
pub(crate) fn exited(pid: Pid) -> nix::Result<bool> {
    use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG;
    loop {
        match waitid(Id::Pid(pid), flags) {
            Err(Errno::EINTR) => {}
            result => return result.map(|status| status != WaitStatus::StillAlive),
        }
    }
}

/// Whether `pid`, an unreaped child of this process, has exited.
/// # Errors
/// Returns the kernel error when the state cannot be read.
#[cfg(target_os = "macos")]
pub(crate) fn exited(pid: Pid) -> nix::Result<bool> {
    use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};
    let ident = usize::try_from(pid.as_raw()).map_err(|_| Errno::EINVAL)?;
    let queue = Kqueue::new()?;
    let note = KEvent::new(
        ident,
        EventFilter::EVFILT_PROC,
        EvFlags::EV_ADD | EvFlags::EV_ONESHOT,
        FilterFlag::NOTE_EXIT,
        0,
        0,
    );
    let mut events = [note];
    let now = nix::libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let count = loop {
        match queue.kevent(&[note], &mut events, Some(now)) {
            Err(Errno::EINTR) => {}
            result => break result?,
        }
    };
    if count == 0 {
        return Ok(false);
    }
    let event = events[0];
    if event.flags().contains(EvFlags::EV_ERROR) && event.data() != 0 {
        let error = Errno::from_raw(i32::try_from(event.data()).unwrap_or(0));
        return if error == Errno::ESRCH {
            Ok(true)
        } else {
            Err(error)
        };
    }
    Ok(event.fflags().contains(FilterFlag::NOTE_EXIT))
}

#[cfg(test)]
mod tests {
    //! Both platforms: a running child is alive, an exited one is seen as
    //! exited, and checking does not reap it (the zombie still answers).
    use super::exited;
    use nix::unistd::Pid;
    use std::{process::Command, time::Duration};

    fn pid(child: &std::process::Child) -> Pid {
        Pid::from_raw(i32::try_from(child.id()).unwrap())
    }

    #[test]
    fn running_child_has_not_exited() {
        let mut child = Command::new("sleep").arg("5").spawn().unwrap();
        assert!(!exited(pid(&child)).unwrap());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn exited_child_is_seen_and_stays_unreaped() {
        let mut child = Command::new("true").spawn().unwrap();
        let id = pid(&child);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !exited(id).unwrap() {
            assert!(std::time::Instant::now() < deadline, "exit never observed");
            std::thread::sleep(Duration::from_millis(10));
        }
        // Not reaped: asking again still sees the same exited child, and
        // the real wait still collects its status.
        assert!(exited(id).unwrap());
        assert!(child.wait().unwrap().success());
    }
}
