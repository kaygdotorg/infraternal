//! Own reactor sources until deregistration, with no safe way to replace a live descriptor [40].
#![allow(unsafe_code)]

use std::{
    io,
    os::fd::{AsFd, AsRawFd, OwnedFd, RawFd},
};
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard, TryIoError};

mod sealed {
    //! Only audited descriptor owners may enter the registration boundary.
    use super::{AsFd, AsRawFd, OwnedFd, RawFd};
    pub trait Source {
        fn descriptor(&self) -> RawFd;
        /// Reactor interest; read and write unless the descriptor kind
        /// cannot report write readiness.
        fn interest() -> tokio::io::Interest {
            tokio::io::Interest::READABLE.add(tokio::io::Interest::WRITABLE)
        }
    }
    impl Source for OwnedFd {
        fn descriptor(&self) -> RawFd {
            self.as_raw_fd()
        }
    }
    #[cfg(unix)]
    impl Source for std::os::unix::net::UnixStream {
        fn descriptor(&self) -> RawFd {
            self.as_fd().as_raw_fd()
        }
    }
    #[cfg(target_os = "linux")]
    impl Source for nix::sys::inotify::Inotify {
        fn descriptor(&self) -> RawFd {
            self.as_fd().as_raw_fd()
        }
    }
    #[cfg(target_os = "linux")]
    impl Source for nix::sys::epoll::Epoll {
        fn descriptor(&self) -> RawFd {
            self.0.as_raw_fd()
        }
    }
    #[cfg(target_os = "macos")]
    impl Source for nix::sys::event::Kqueue {
        fn descriptor(&self) -> RawFd {
            self.as_fd().as_raw_fd()
        }
        /// A kqueue descriptor supports only read filters: registering
        /// `EVFILT_WRITE` on it fails with `EINVAL`.
        fn interest() -> tokio::io::Interest {
            tokio::io::Interest::READABLE
        }
    }
}

/// Sealed set of owners whose descriptor stays open and stable until drop.
pub trait Source: sealed::Source {}
impl<T: sealed::Source> Source for T {}

struct Descriptor<T: Source>(T);
impl<T: Source> AsRawFd for Descriptor<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.0.descriptor()
    }
}

/// An owning registration. Mutable access and raw reactor guards stay private:
/// replacing an owner through `AsyncFd::get_mut` would invalidate registration.
///
/// Borrowed descriptors cannot enter the owning boundary:
/// ```compile_fail
/// use infraternal_shim::readiness::Registration;
/// use std::os::fd::AsFd;
/// let file = std::fs::File::open("/dev/null").unwrap();
/// let _registration = Registration::new(file.as_fd());
/// ```
/// A live owner cannot be replaced through safe mutable access:
/// ```compile_fail
/// use infraternal_shim::readiness::Registration;
/// use std::os::fd::OwnedFd;
/// let (reader, _writer) = nix::unistd::pipe().unwrap();
/// let mut registration = Registration::new(reader).unwrap();
/// let replacement: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
/// *registration.get_mut() = replacement;
/// ```
pub struct Registration<T: Source>(AsyncFd<Descriptor<T>>);
impl<T: Source> Registration<T> {
    /// Register one owned source with the current runtime.
    /// # Errors
    /// Returns reactor registration errors, dropping the unregistered owner.
    pub fn new(source: T) -> io::Result<Self> {
        // SAFETY: the sealed Source implementations own their descriptor and
        // always return the same open descriptor. AsyncFd owns Descriptor<T>
        // until deregistration before drop. This wrapper exposes no mutable
        // owner access, so safe callers cannot close or replace it while live.
        unsafe { AsyncFd::register_with_interest(Descriptor(source), T::interest()) }
            .map(Self)
            .map_err(|error| error.into_parts().1)
    }

    /// Borrow the owner without permitting replacement of its descriptor.
    pub fn get_ref(&self) -> &T {
        &self.0.get_ref().0
    }

    /// Wait for readable readiness without exposing mutable owner access.
    /// # Errors
    /// Returns reactor readiness errors.
    pub async fn readable(&self) -> io::Result<Ready<'_, T>> {
        self.0.readable().await.map(Ready)
    }

    /// Wait for writable readiness without exposing mutable owner access.
    /// # Errors
    /// Returns reactor readiness errors.
    pub async fn writable(&self) -> io::Result<Ready<'_, T>> {
        self.0.writable().await.map(Ready)
    }
}

/// Readiness operations borrow the owner; they never expose the raw registration.
pub struct Ready<'a, T: Source>(AsyncFdReadyGuard<'a, Descriptor<T>>);
impl<T: Source> Ready<'_, T> {
    /// Clear stale readiness only when the operation reports `WouldBlock`.
    /// # Errors
    /// Returns `TryIoError` for `WouldBlock`, or the operation's error otherwise.
    pub fn try_io<R>(
        &mut self,
        operation: impl FnOnce(&T) -> io::Result<R>,
    ) -> Result<io::Result<R>, TryIoError> {
        self.0.try_io(|fd| operation(&fd.get_ref().0))
    }
}

/// Duplicate an inherited descriptor without ever borrowing an unproven `RawFd`.
/// The kernel validates the number and returns an independently owned CLOEXEC fd.
/// # Errors
/// Returns the kernel error for an invalid descriptor or descriptor exhaustion.
pub fn duplicate_inherited(fd: RawFd) -> io::Result<OwnedFd> {
    use std::os::fd::FromRawFd;
    // SAFETY: fcntl validates any integer fd and takes no pointer for this
    // operation. It does not close or change the caller's descriptor.
    let duplicate = unsafe { nix::libc::fcntl(fd, nix::libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful F_DUPFD_CLOEXEC returns a fresh open descriptor owned
    // solely by this call. OwnedFd closes it only after its registration drops.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

/// How many times [`retry_interrupted`] repeats a call a signal interrupted.
pub const INTERRUPT_RETRIES: usize = 8;

/// Run `call`, repeating it while a signal interrupts it (`EINTR`), at most
/// [`INTERRUPT_RETRIES`] times. After that the `EINTR` is returned, so a
/// caller in an event loop goes back to its loop (and its cancellation
/// points) instead of spinning here under a storm of signals (#328).
/// # Errors
/// Returns the call's error, or `EINTR` once the retries are used up.
pub fn retry_interrupted<T>(mut call: impl FnMut() -> nix::Result<T>) -> nix::Result<T> {
    for _ in 0..INTERRUPT_RETRIES {
        match call() {
            Err(nix::errno::Errno::EINTR) => {}
            result => return result,
        }
    }
    Err(nix::errno::Errno::EINTR)
}

/// Run one non-blocking `kevent` call (zero timeout), repeating it a bounded
/// number of times when a signal interrupts it.
///
/// macOS never restarts `kevent` after a signal handler runs, whatever the
/// handler's `SA_RESTART` flag, and the infraternal agent's runtime handles
/// SIGCHLD while it waits for a launching shim (#324). An `EINTR` from a
/// kqueue drain must not end the agent (#328). Callers that wait in an event
/// loop treat a final `EINTR` (`io::ErrorKind::Interrupted`) as "try again":
/// they yield to the runtime and retry without clearing readiness. Repeating
/// a registration is idempotent; callers already accept `ENOENT` when
/// deleting a filter twice.
/// # Errors
/// Returns every other `kevent` error unchanged, and `EINTR` when the
/// interruptions outlast the retries.
#[cfg(target_os = "macos")]
pub fn kevent_now(
    queue: &nix::sys::event::Kqueue,
    changes: &[nix::sys::event::KEvent],
    events: &mut [nix::sys::event::KEvent],
) -> nix::Result<usize> {
    let now = nix::libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    retry_interrupted(|| queue.kevent(changes, &mut *events, Some(now)))
}

#[cfg(test)]
mod interrupt_tests {
    //! Interrupted calls are retried a bounded number of times (#328, J215 P2).
    use super::*;

    /// A call interrupted forever must give up with `EINTR` after the bound,
    /// not spin: run it on a thread and require an answer in time.
    #[test]
    fn a_permanently_interrupted_call_gives_up() {
        let (done, result) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut calls = 0;
            let outcome = retry_interrupted(|| -> nix::Result<()> {
                calls += 1;
                Err(nix::errno::Errno::EINTR)
            });
            let _ = done.send((outcome, calls));
        });
        let (outcome, calls) = result
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the retry loop never returned");
        assert_eq!(outcome, Err(nix::errno::Errno::EINTR));
        assert_eq!(calls, INTERRUPT_RETRIES);
    }

    /// A transient interruption is absorbed; other errors pass straight out.
    #[test]
    fn transient_interruptions_are_retried_and_other_errors_returned() {
        let mut calls = 0;
        let outcome = retry_interrupted(|| {
            calls += 1;
            if calls < 3 {
                Err(nix::errno::Errno::EINTR)
            } else {
                Ok(calls)
            }
        });
        assert_eq!(outcome, Ok(3));
        assert_eq!(
            retry_interrupted(|| -> nix::Result<()> { Err(nix::errno::Errno::EBADF) }),
            Err(nix::errno::Errno::EBADF)
        );
    }
}
