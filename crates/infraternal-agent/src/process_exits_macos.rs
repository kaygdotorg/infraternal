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
struct Lifetime {
    pid: u32,
    token: isize,
}
#[derive(Default)]
pub(crate) struct ProcessExits {
    queue: Option<AsyncFd<Queue>>,
    shims: HashMap<[u8; 16], Lifetime>,
    token: isize,
    retired: Vec<[u8; 16]>,
}
fn event(pid: u32, flags: EvFlags, token: isize) -> KEvent {
    KEvent::new(
        pid as usize,
        EventFilter::EVFILT_PROC,
        flags,
        FilterFlag::NOTE_EXIT,
        0,
        token,
    )
}
fn zero_timeout() -> nix::libc::timespec {
    nix::libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }
}
fn delete(queue: &Kqueue, pid: u32) -> io::Result<()> {
    match queue.kevent(
        &[event(pid, EvFlags::EV_DELETE, 0)],
        &mut [],
        Some(zero_timeout()),
    ) {
        Ok(_) | Err(Errno::ENOENT | Errno::ESRCH) => Ok(()),
        Err(error) => Err(error.into()),
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
        // Kernel filter keys are PIDs, which can be reused before dispatch reads
        // an older NOTE_EXIT. Delete that filter before adding the replacement,
        // and deliver the old session IDs separately from the new lifetime.
        if self.shims.values().any(|life| life.pid == pid) {
            delete(&queue.get_ref().0, pid)?;
        }
        self.shims.retain(|old_id, life| {
            if life.pid != pid {
                return true;
            }
            if *old_id != id {
                self.retired.push(*old_id);
            }
            false
        });
        if let Some(old) = self.shims.remove(&id) {
            delete(&queue.get_ref().0, old.pid)?;
        }
        self.token = self
            .token
            .checked_add(1)
            .ok_or_else(|| io::Error::other("exit registration tokens exhausted"))?;
        match queue.get_ref().0.kevent(
            &[event(
                pid,
                EvFlags::EV_ADD | EvFlags::EV_ONESHOT,
                self.token,
            )],
            &mut [],
            Some(zero_timeout()),
        ) {
            Ok(_) => {
                self.shims.insert(
                    id,
                    Lifetime {
                        pid,
                        token: self.token,
                    },
                );
                Ok(true)
            }
            Err(Errno::ESRCH) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    pub(crate) fn retain(&mut self, live: impl Fn(&[u8; 16]) -> bool) {
        self.retired.retain(|id| live(id));
        self.shims.retain(|id, life| {
            if live(id) {
                return true;
            }
            if let Some(queue) = &self.queue {
                let _ = delete(&queue.get_ref().0, life.pid);
            }
            false
        });
    }
    fn matching_ids(&self, events: &[KEvent]) -> Vec<[u8; 16]> {
        self.shims
            .iter()
            .filter_map(|(id, life)| {
                // Match registration identity rather than PID; a late event cannot
                // remove a live replacement that acquired the same PID.
                events
                    .iter()
                    .any(|event| event.udata() == life.token)
                    .then_some(*id)
            })
            .collect()
    }
    pub(crate) async fn changed(&self) -> io::Result<Vec<[u8; 16]>> {
        if !self.retired.is_empty() {
            return Ok(self.retired.clone());
        }
        let Some(queue) = &self.queue else {
            return std::future::pending().await;
        };
        loop {
            let mut ready = queue.readable().await?;
            if let Ok(result) = ready.try_io(|fd| {
                let mut events = [event(0, EvFlags::empty(), 0); 32];
                let count = fd
                    .get_ref()
                    .0
                    .kevent(&[], &mut events, Some(zero_timeout()))?;
                if count == 0 {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Ok(self.matching_ids(&events[..count]))
            }) {
                return result;
            }
        }
    }
}
#[cfg(test)]
mod tests {
    //! Queue decoding must preserve registration lifetime even when a PID repeats.
    use super::*;
    #[test]
    fn an_old_exit_token_does_not_remove_a_reused_pid() {
        let mut exits = ProcessExits::default();
        exits.shims.insert([1; 16], Lifetime { pid: 42, token: 2 });
        assert_eq!(
            exits.matching_ids(&[event(42, EvFlags::empty(), 1)]),
            Vec::<[u8; 16]>::new()
        );
        assert_eq!(
            exits.matching_ids(&[event(42, EvFlags::empty(), 2)]),
            vec![[1; 16]]
        );
    }
}
