//! Register shim `NOTE_EXIT` filters in one kqueue watched by the daemon's Tokio reactor [D81].
use nix::{
    errno::Errno,
    fcntl::{FcntlArg, FdFlag, fcntl},
    sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue},
};
use std::{
    collections::HashMap,
    io,
    os::fd::{AsFd, AsRawFd, RawFd},
};
use tokio::io::unix::AsyncFd;

struct Queue(Kqueue);
impl AsRawFd for Queue {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_fd().as_raw_fd()
    }
}

#[derive(Default)]
pub(crate) struct ProcessExits {
    queue: Option<AsyncFd<Queue>>,
    shims: HashMap<[u8; 16], u32>,
}

fn event(pid: u32, flags: EvFlags) -> KEvent {
    KEvent::new(
        pid as usize,
        EventFilter::EVFILT_PROC,
        flags,
        FilterFlag::NOTE_EXIT,
        0,
        0,
    )
}
fn zero_timeout() -> nix::libc::timespec {
    nix::libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }
}

impl ProcessExits {
    pub(crate) fn watch(&mut self, id: [u8; 16], pid: u32) -> io::Result<bool> {
        if self.queue.is_none() {
            let queue = Kqueue::new()?;
            fcntl(&queue, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
            self.queue = Some(AsyncFd::new(Queue(queue))?);
        }
        let queue = self
            .queue
            .as_ref()
            .ok_or_else(|| io::Error::other("missing exit queue"))?;
        match queue.get_ref().0.kevent(
            &[event(pid, EvFlags::EV_ADD | EvFlags::EV_ONESHOT)],
            &mut [],
            Some(zero_timeout()),
        ) {
            Ok(_) => {
                self.shims.insert(id, pid);
                Ok(true)
            }
            Err(Errno::ESRCH) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn retain(&mut self, live: impl Fn(&[u8; 16]) -> bool) {
        self.shims.retain(|id, pid| {
            if live(id) {
                return true;
            }
            if let Some(queue) = &self.queue {
                // A delivered ONESHOT or an already-dead process has no filter
                // left to delete; either way it must not wake the daemon again.
                let _ = queue.get_ref().0.kevent(
                    &[event(*pid, EvFlags::EV_DELETE)],
                    &mut [],
                    Some(zero_timeout()),
                );
            }
            false
        });
    }

    pub(crate) async fn changed(&self) -> io::Result<Vec<[u8; 16]>> {
        let Some(queue) = &self.queue else {
            return std::future::pending().await;
        };
        loop {
            let mut ready = queue.readable().await?;
            if let Ok(result) = ready.try_io(|fd| {
                let mut events = [event(0, EvFlags::empty()); 32];
                let count = fd
                    .get_ref()
                    .0
                    .kevent(&[], &mut events, Some(zero_timeout()))?;
                if count == 0 {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Ok(self
                    .shims
                    .iter()
                    .filter_map(|(id, pid)| {
                        events[..count]
                            .iter()
                            .any(|event| event.ident() == *pid as usize)
                            .then_some(*id)
                    })
                    .collect())
            }) {
                return result;
            }
        }
    }
}
