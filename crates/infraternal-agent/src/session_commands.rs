//! Accumulates Credit and reserves reply capacity while preserving one Input/Resize/reply FIFO [130, 307].
use super::Command;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};

/// How many ordinary commands (input, resize, and so on) may wait in the queue
/// at once. Replies have their own budget, `REPLY_SLOTS`.
const COMMAND_SLOTS: usize = 8;
/// How many replies (answers to terminal queries) may wait in the queue at once,
/// kept apart from `COMMAND_SLOTS` so replies can never use up typing's room.
const REPLY_SLOTS: usize = 64;

/// A queued command stamped with the total credit published before it.
/// `credit_before` is the fence: the receiver releases no more credit than this
/// before delivering the command, which keeps credit and commands in the order
/// the producer sent them. `_slot` holds the command's queue reservation until
/// the command is delivered.
pub(super) struct Ordered {
    command: Command,
    credit_before: u64,
    // Keep admission reserved while a pending command waits for its credit fence.
    _slot: OwnedSemaphorePermit,
}

// One shared dispatcher owns this sender; exposing no Clone keeps the credit
// publication and ordered-command fences under that single producer's order.
// Mutable admission also prevents concurrent callers from interleaving a fence
// snapshot with publication of a later credit total.
/// The single producer side of a session's command queue.
///
/// Input, resize and replies go through one FIFO. Credit (permission to send more
/// output bytes) is not queued: it is added to a running total that the receiver
/// turns into grants, so credit can never fill the queue. There is deliberately
/// no `Clone`, and sending needs `&mut self`: one owner publishes credit and takes
/// each command's fence snapshot, so the two cannot interleave out of order.
pub(super) struct Sender {
    raw: mpsc::Sender<Ordered>,
    credits: watch::Sender<u64>,
    slots: Arc<Semaphore>,
    reply_slots: Arc<Semaphore>,
}
/// The consuming side of a session's command queue.
pub(super) enum Receiver {
    /// Plain FIFO used by native connections, which carry their own credit.
    #[cfg(feature = "remote")]
    Native(mpsc::Receiver<Command>),
    /// Queue plus credit total shared with a `Sender`. `seen` is how much credit
    /// has already been handed out; `pending` is a command taken from the queue
    /// that is waiting for its credit fence to be satisfied.
    Shared {
        raw: mpsc::Receiver<Ordered>,
        credits: watch::Receiver<u64>,
        seen: u64,
        pending: Option<Ordered>,
    },
}
/// Creates a connected `Sender` and `Receiver` with room for `COMMAND_SLOTS`
/// ordinary commands plus `REPLY_SLOTS` replies.
pub(super) fn channel() -> (Sender, Receiver) {
    let (tx, rx) = mpsc::channel(COMMAND_SLOTS + REPLY_SLOTS);
    let (credits, reader) = watch::channel(0);
    (
        Sender {
            raw: tx,
            credits,
            slots: Arc::new(Semaphore::new(COMMAND_SLOTS)),
            reply_slots: Arc::new(Semaphore::new(REPLY_SLOTS)),
        },
        Receiver::Shared {
            raw: rx,
            credits: reader,
            seen: 0,
            pending: None,
        },
    )
}
impl Sender {
    /// True once the receiver has been dropped, so sending is pointless.
    pub(super) fn is_closed(&self) -> bool {
        self.raw.is_closed()
    }
    /// Queues a command without waiting.
    ///
    /// * `Credit(n)` adds `n` to the credit total. It never blocks and never takes a
    ///   queue slot; zero is ignored. It fails with `Full` only if the total would
    ///   overflow `u64`.
    /// * Everything else needs a free slot, replies from their own pool. When none is
    ///   free, `Ping` and `Reply` are dropped silently and `Ok` is returned, because
    ///   they are best-effort and must not displace accepted typing. Any other
    ///   command fails with `Full`.
    /// * Fails with `Closed` (returning the command) after the receiver is gone.
    pub(super) fn try_send(
        &mut self,
        command: Command,
    ) -> Result<(), mpsc::error::TrySendError<Command>> {
        if let Command::Credit(bytes) = command {
            if self.raw.is_closed() {
                return Err(mpsc::error::TrySendError::Closed(Command::Credit(bytes)));
            }
            let mut overflow = false;
            self.credits.send_if_modified(|total| {
                if bytes == 0 {
                    return false;
                }
                if let Some(sum) = total.checked_add(u64::from(bytes)) {
                    *total = sum;
                    true
                } else {
                    overflow = true;
                    false
                }
            });
            if overflow {
                Err(mpsc::error::TrySendError::Full(Command::Credit(bytes)))
            } else {
                Ok(())
            }
        } else {
            if self.raw.is_closed() {
                return Err(mpsc::error::TrySendError::Closed(command));
            }
            // Replies cannot spend the eight ordinary command reservations.
            // One FIFO still orders them with Input/Resize and accumulated Credit.
            let slots = if matches!(command, Command::Reply(_)) {
                &self.reply_slots
            } else {
                &self.slots
            };
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                return if matches!(command, Command::Ping(..) | Command::Reply(_)) {
                    Ok(())
                } else {
                    Err(mpsc::error::TrySendError::Full(command))
                };
            };
            let credit_before = *self.credits.borrow();
            match self.raw.try_send(Ordered {
                command,
                credit_before,
                _slot: slot,
            }) {
                // Best-effort probes and renderer replies cannot displace accepted
                // typing or retire its writer under local queue pressure.
                Ok(())
                | Err(mpsc::error::TrySendError::Full(Ordered {
                    command: Command::Ping(..) | Command::Reply(..),
                    ..
                })) => Ok(()),
                Err(mpsc::error::TrySendError::Full(ordered)) => {
                    Err(mpsc::error::TrySendError::Full(ordered.command))
                }
                Err(mpsc::error::TrySendError::Closed(ordered)) => {
                    Err(mpsc::error::TrySendError::Closed(ordered.command))
                }
            }
        }
    }
}
impl Receiver {
    /// Waits for the next command to run, in send order. Returns `None` when the
    /// sender is gone and nothing remains. May be cancelled and called again without
    /// losing a command or credit.
    pub(super) async fn next(&mut self) -> Option<Command> {
        match self {
            #[cfg(feature = "remote")]
            Self::Native(raw) => raw.recv().await,
            Self::Shared {
                raw,
                credits,
                seen,
                pending,
            } => next_shared(raw, credits, seen, pending).await,
        }
    }
}
/// Implements `next` for the shared queue.
///
/// Turns the credit total into `Credit` grants (at most `u32::MAX` each) up to the
/// next queued command's fence, then yields that command. The total is read
/// before looking ahead in the queue so credit sent after a command can never be
/// granted ahead of it. State is committed only when a value is returned, so
/// cancelling this future (as the terminal's outer `select!` does) loses nothing.
async fn next_shared(
    raw: &mut mpsc::Receiver<Ordered>,
    credits: &mut watch::Receiver<u64>,
    seen: &mut u64,
    pending: &mut Option<Ordered>,
) -> Option<Command> {
    loop {
        // Observe the total BEFORE looking ahead in the FIFO. If this total
        // includes credit sent after an Input, that Input is already published
        // by the single producer and its fence must cap this grant.
        let total = *credits.borrow_and_update();
        let mut closed = false;
        if pending.is_none() {
            match raw.try_recv() {
                Ok(ordered) => *pending = Some(ordered),
                Err(mpsc::error::TryRecvError::Disconnected) => closed = true,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }
        let target = pending
            .as_ref()
            .map_or(total, |ordered| ordered.credit_before);
        let allowance = target.checked_sub(*seen)?;
        if allowance != 0 {
            // Commit only when returning Ready. The pending ordered command
            // stays in this receiver across cancellation by the terminal's
            // outer select; neither its fence nor a credit delta can disappear.
            let grant = u32::try_from(allowance.min(u64::from(u32::MAX))).ok()?;
            *seen += u64::from(grant);
            return Some(Command::Credit(grant));
        }
        if let Some(ordered) = pending.take() {
            return Some(ordered.command);
        }
        if closed {
            return None;
        }
        tokio::select! {
            ordered = raw.recv() => {
                let Some(ordered) = ordered else { continue; };
                *pending = Some(ordered);
            },
            _ = credits.changed() => {},
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "session_commands_tests.rs"]
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "session_commands_bench.rs"]
mod measurements;

#[cfg(test)]
#[path = "session_command_reply_tests.rs"]
mod reply_capacity_tests;
