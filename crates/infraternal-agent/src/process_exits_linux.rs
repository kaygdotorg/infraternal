//! Aggregate pidfds into one epoll descriptor registered with the daemon's Tokio reactor [D81].
use infraternal_shim::readiness::Registration;
use nix::{
    errno::Errno,
    sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout},
};
use std::{
    collections::HashMap,
    io,
    os::fd::{AsRawFd, OwnedFd},
};

/// Watches every session shim process for exit through one epoll queue that the
/// daemon's reactor polls, so no per-shim task or timer is needed.
///
/// Each shim is represented by an owned pidfd, kept in `shims` by session id.
/// `queue` is created lazily on the first successful registration. `unavailable`
/// latches once the kernel reports it has no pidfd support; after that nothing is
/// registered and callers fall back to reconciling on lifecycle events only.
#[derive(Default)]
pub(crate) struct ProcessExits {
    queue: Option<Registration<Epoll>>,
    shims: HashMap<[u8; 16], OwnedFd>,
    unavailable: bool,
}

impl ProcessExits {
    /// False means the PID exited before registration. Old kernels reconcile only on lifecycle events.
    pub(crate) fn watch(&mut self, id: [u8; 16], pid: u32) -> io::Result<bool> {
        self.watch_with(id, pid, infraternal_shim::process_exit_descriptor)
    }

    /// Implements `watch` with an injectable pidfd opener so tests can simulate
    /// kernels and failures.
    ///
    /// Returns `Ok(false)` if the process is already gone (`ESRCH`), `Ok(true)` when
    /// it is now watched, or when pidfds are unsupported (`ENOSYS`/`EINVAL`, which
    /// latches `unavailable`). Other errors, such as running out of descriptors, are
    /// returned as errors and do not disable tracking.
    fn watch_with(
        &mut self,
        id: [u8; 16],
        pid: u32,
        open: impl FnOnce(u32) -> io::Result<OwnedFd>,
    ) -> io::Result<bool> {
        if self.unavailable {
            return Ok(true);
        }
        let descriptor = match open(pid) {
            Ok(fd) => fd,
            Err(error) if error.raw_os_error() == Some(Errno::ESRCH as i32) => return Ok(false),
            Err(error) if matches!(error.raw_os_error(), Some(code) if code == Errno::ENOSYS as i32 || code == Errno::EINVAL as i32) =>
            {
                // Never invent a polling fallback. Resource/permission failures
                // are errors, not evidence that this kernel lacks pidfds.
                self.unavailable = true;
                return Ok(true);
            }
            Err(error) => return Err(error),
        };
        if self.queue.is_none() {
            self.queue = Some(Registration::new(Epoll::new(
                EpollCreateFlags::EPOLL_CLOEXEC,
            )?)?);
        }
        let queue = self
            .queue
            .as_ref()
            .ok_or_else(|| io::Error::other("missing exit queue"))?;
        // EPOLLONESHOT consumes the death notification even if registry refresh
        // follows later. Closing the owned pidfd automatically removes interest.
        queue.get_ref().add(
            &descriptor,
            EpollEvent::new(
                EpollFlags::EPOLLIN | EpollFlags::EPOLLONESHOT,
                u64::try_from(descriptor.as_raw_fd()).map_err(io::Error::other)?,
            ),
        )?;
        self.shims.insert(id, descriptor);
        Ok(true)
    }

    /// Stops watching every session for which `live` returns false. Dropping the
    /// pidfd also removes it from the epoll queue.
    pub(crate) fn retain(&mut self, live: impl Fn(&[u8; 16]) -> bool) {
        self.shims.retain(|id, _| live(id));
    }

    /// Waits until at least one watched shim has exited and returns the session ids
    /// of the ones that did.
    ///
    /// Each exit is reported once (the registration is one-shot). If no shim was ever
    /// registered the future never completes. Cancel-safe: dropping it loses no event.
    pub(crate) async fn changed(&self) -> io::Result<Vec<[u8; 16]>> {
        let Some(queue) = &self.queue else {
            return std::future::pending().await;
        };
        loop {
            let mut ready = queue.readable().await?;
            if let Ok(result) = ready.try_io(|fd| {
                let mut events = [EpollEvent::empty(); 32];
                let count = fd.wait(&mut events, EpollTimeout::ZERO)?;
                if count == 0 {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Ok(self
                    .shims
                    .iter()
                    .filter_map(|(id, shim)| {
                        let descriptor = u64::try_from(shim.as_raw_fd()).ok()?;
                        events[..count]
                            .iter()
                            .any(|event| event.data() == descriptor)
                            .then_some(*id)
                    })
                    .collect())
            }) {
                return result;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unavailable kernels keep no readiness source or periodic fallback [D81].
    use super::*;
    #[tokio::test]
    async fn unavailable_kernel_has_no_timer_or_descriptor() {
        let mut exits = ProcessExits::default();
        assert!(
            exits
                .watch_with([1; 16], std::process::id(), |_| Err(Errno::ENOSYS.into()))
                .unwrap()
        );
        assert!(exits.unavailable);
        assert!(
            exits
                .watch_with([2; 16], std::process::id(), |_| panic!(
                    "fallback must not open more descriptors"
                ))
                .unwrap()
        );
        assert!(exits.queue.is_none());
        assert!(exits.shims.is_empty());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), exits.changed())
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn resource_failures_do_not_silently_disable_exit_tracking() {
        let mut exits = ProcessExits::default();
        let error = exits
            .watch_with([1; 16], std::process::id(), |_| Err(Errno::EMFILE.into()))
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(Errno::EMFILE as i32));
        assert!(!exits.unavailable);
    }
}
