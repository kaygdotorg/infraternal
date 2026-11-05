//! Register shim `NOTE_EXIT` filters in one kqueue watched by the daemon's Tokio reactor [D81].
use infraternal_shim::readiness::Registration;
use nix::{
    errno::Errno,
    fcntl::{FcntlArg, FdFlag, fcntl},
    sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue},
};
use std::{collections::HashMap, io};

/// One registered watch: the shim's PID and a unique `token` naming this
/// registration, so a late event for an older process that had the same PID is
/// not mistaken for the current one.
struct Lifetime {
    pid: u32,
    token: isize,
}
/// Watches every session shim process for exit through one kqueue that the
/// daemon's reactor polls, so no per-shim task or timer is needed.
///
/// `token` counts registrations and is never reused. `retired` holds ids of
/// sessions whose PID was taken over by a newer registration; they are reported
/// as exited by `changed` until `retain` drops them.
#[derive(Default)]
pub(crate) struct ProcessExits {
    queue: Option<Registration<Kqueue>>,
    shims: HashMap<[u8; 16], Lifetime>,
    token: isize,
    retired: Vec<[u8; 16]>,
}
/// Builds a one-shot-capable `NOTE_EXIT` process event for `pid`, carrying
/// `token` as user data so it can be matched back to a registration.
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
/// A zero timeout: kqueue calls return immediately and never block the reactor.
/// Removes the exit filter for `pid`. A filter that is already gone (`ENOENT`
/// or `ESRCH`) counts as success.
fn delete(queue: &Kqueue, pid: u32) -> io::Result<()> {
    match infraternal_shim::readiness::kevent_now(
        queue,
        &[event(pid, EvFlags::EV_DELETE, 0)],
        &mut [],
    ) {
        Ok(_) | Err(Errno::ENOENT | Errno::ESRCH) => Ok(()),
        Err(error) => Err(error.into()),
    }
}
impl ProcessExits {
    /// Starts watching `pid` as the shim of session `id`.
    ///
    /// Returns `Ok(false)` if the process had already exited, `Ok(true)` once
    /// watched. PIDs can be reused before an older exit event is read, so an existing
    /// filter for the same PID is deleted first, and a previous session id registered
    /// for that PID is moved to `retired`. Fails if the kqueue cannot be created or
    /// tokens are exhausted.
    pub(crate) fn watch(&mut self, id: [u8; 16], pid: u32) -> io::Result<bool> {
        if self.queue.is_none() {
            let queue = Kqueue::new()?;
            fcntl(&queue, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
            self.queue = Some(Registration::new(queue)?);
        }
        let queue = self
            .queue
            .as_ref()
            .ok_or_else(|| io::Error::other("missing exit queue"))?;
        // Kernel filter keys are PIDs, which can be reused before dispatch reads
        // an older NOTE_EXIT. Delete that filter before adding the replacement,
        // and deliver the old session IDs separately from the new lifetime.
        if self.shims.values().any(|life| life.pid == pid) {
            delete(queue.get_ref(), pid)?;
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
            delete(queue.get_ref(), old.pid)?;
        }
        self.token = self
            .token
            .checked_add(1)
            .ok_or_else(|| io::Error::other("exit registration tokens exhausted"))?;
        match infraternal_shim::readiness::kevent_now(
            queue.get_ref(),
            &[event(
                pid,
                EvFlags::EV_ADD | EvFlags::EV_ONESHOT,
                self.token,
            )],
            &mut [],
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
    /// Stops watching every session for which `live` returns false and removes the
    /// kernel filters. Also drops matching ids from `retired`.
    pub(crate) fn retain(&mut self, live: impl Fn(&[u8; 16]) -> bool) {
        self.retired.retain(|id| live(id));
        self.shims.retain(|id, life| {
            if live(id) {
                return true;
            }
            if let Some(queue) = &self.queue {
                let _ = delete(queue.get_ref(), life.pid);
            }
            false
        });
    }
    /// Returns the session ids whose current registration token appears in
    /// `events`. Matching is by token, not PID, so a late event cannot end a live
    /// replacement process that reused the PID.
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
    /// Waits until at least one watched shim has exited and returns the session ids
    /// of the ones that did. Returns immediately with `retired` ids when any exist.
    /// If nothing was ever registered the future never completes.
    pub(crate) async fn changed(&self) -> io::Result<Vec<[u8; 16]>> {
        if !self.retired.is_empty() {
            return Ok(self.retired.clone());
        }
        let Some(queue) = &self.queue else {
            return std::future::pending().await;
        };
        loop {
            let mut ready = queue.readable().await?;
            match ready.try_io(|fd| {
                let mut events = [event(0, EvFlags::empty(), 0); 32];
                let count = infraternal_shim::readiness::kevent_now(fd, &[], &mut events)?;
                if count == 0 {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Ok(self.matching_ids(&events[..count]))
            }) {
                // Signals outlasted the bounded retries: yield to the runtime
                // and retry with readiness kept, never spin or fail (#328).
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
                    tokio::task::yield_now().await;
                }
                Ok(result) => return result,
                Err(_would_block) => {}
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
