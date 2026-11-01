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
        unsafe { AsyncFd::register(Descriptor(source)) }
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
