//! The relay's per-stream output queue, bounded in bytes rather than in frames [D381, #477].
//!
//! Each browser attachment has one queue between the host-link actor and the task that forwards
//! to the browser's socket. The actor must never wait on it (one slow viewer would stall every
//! terminal on the host), so when the queue is full the actor retires only that stream (1013) and
//! the browser reattaches and replays from its last offset.
//!
//! # Why bytes, not frames
//!
//! The browser's credit window is in bytes: an Output or Snapshot spends credit before it is
//! queued, and the browser returns credit only after it has consumed the bytes. So a viewer that
//! respects credit can never have more payload queued than it granted. A frame count cannot be
//! derived from that window: under a flood the host forwards whatever each PTY read returned,
//! about 1 KiB on average, and the full opening grant arrived as more frames than the old 320-slot
//! queue held, so a healthy viewer was retired mid-flood.
//!
//! # Invariants
//!
//! - Every queued item is charged its payload plus [`OUTPUT_ITEM_CHARGE`] bytes, and the charges
//!   of the items still queued never exceed [`OUTPUT_QUEUE_BYTES`]. That caps one stream's queue
//!   at 9 MiB whatever the peers do, including a browser that re-grants credit without reading,
//!   and a host that floods items which spend no credit (Acks, notices).
//! - A viewer that respects credit is never retired by the cap unless its frames average under
//!   about 9 bytes at the 1 MiB window (more than 147,000 queued frames), or under 512 bytes at
//!   the 8 MiB credit ceiling. Real floods use far larger frames.
//! - The channel's slot count is the cap divided by the per-item charge, so it can never fill
//!   before the byte cap does; it is a backstop, not the bound. Tokio allocates channel blocks
//!   lazily, so an idle stream costs no slots.
//!
//! # How the bytes are counted
//!
//! The receiver stays a plain `mpsc::Receiver`; only the sending side keeps a ledger. The channel
//! is FIFO and the receiver takes items oldest first, so the number of items still queued
//! (`max_capacity - capacity`) says exactly how many of the oldest charges have been consumed.
//! A concurrent receive can only make that count lower than the truth, which over-counts the
//! queue and never under-counts it.

use super::{MAX_OUTPUT_CREDIT, TerminalOutput};
use std::{collections::VecDeque, sync::Mutex};
use tokio::sync::mpsc;

/// Bytes charged for every queued item on top of its payload: the channel slot, the payload's
/// shared-buffer header and this ledger's entry, rounded up. It is also what stops items that
/// carry no payload from queueing without bound.
pub(super) const OUTPUT_ITEM_CHARGE: u64 = 64;
/// The most one stream's queue may hold, in charged bytes: the 8 MiB credit ceiling plus 1 MiB of
/// headroom for per-item charges and uncredited Acks and notices.
pub(super) const OUTPUT_QUEUE_BYTES: u64 = MAX_OUTPUT_CREDIT + 1024 * 1024;
/// Channel slots for a production attachment. Every item charges at least
/// [`OUTPUT_ITEM_CHARGE`], so the byte cap is always reached first.
#[expect(
    clippy::cast_possible_truncation,
    reason = "147,456 slots fits every supported usize"
)]
pub(super) const OUTPUT_QUEUE_SLOTS: usize = (OUTPUT_QUEUE_BYTES / OUTPUT_ITEM_CHARGE) as usize;
/// A drained ledger keeps at most this many entries' worth of allocation after a flood.
const LEDGER_KEEP: usize = 1024;

/// The actor's sending end of one stream's output queue. All sends go through [`Self::try_send`],
/// so the ledger sees every item that enters the channel.
pub(super) struct OutputQueue {
    sender: mpsc::Sender<TerminalOutput>,
    /// Interior mutability lets the notice paths, which only borrow the attachment table, send
    /// too. The actor is the only sender, so the lock is never contended.
    ledger: Mutex<Ledger>,
}

/// Charges of the items still queued, oldest first, and their sum.
#[derive(Default)]
struct Ledger {
    charges: VecDeque<u32>,
    queued: u64,
}

impl Ledger {
    /// Forgets the charges of items the receiver has taken; `queued_items` is how many remain.
    fn settle(&mut self, queued_items: usize) {
        while self.charges.len() > queued_items {
            let charge = self.charges.pop_front().unwrap_or_default();
            self.queued -= u64::from(charge);
        }
        if self.charges.is_empty() && self.charges.capacity() > LEDGER_KEEP {
            self.charges = VecDeque::new();
        }
    }
}

/// Wraps a fresh channel's sender. The channel must be empty and this must become its only
/// sender, or the ledger would miss items.
impl From<mpsc::Sender<TerminalOutput>> for OutputQueue {
    fn from(sender: mpsc::Sender<TerminalOutput>) -> Self {
        Self {
            sender,
            ledger: Mutex::new(Ledger::default()),
        }
    }
}

impl OutputQueue {
    /// Queues `item` if the stream's charged bytes stay within [`OUTPUT_QUEUE_BYTES`] and the
    /// receiver is still open. On refusal the item comes back and nothing is recorded; the caller
    /// decides whether that retires the stream.
    pub(super) fn try_send(&self, item: TerminalOutput) -> Result<(), TerminalOutput> {
        let charge = charge(&item);
        let mut ledger = self.lock();
        ledger.settle(self.queued_items());
        if ledger.queued.saturating_add(charge) > OUTPUT_QUEUE_BYTES {
            return Err(item);
        }
        self.sender.try_send(item).map_err(|error| error.into_inner())?;
        // Within the cap, so the charge is at most 9 MiB and fits the compact ledger entry.
        ledger.charges.push_back(u32::try_from(charge).unwrap_or(u32::MAX));
        ledger.queued += charge;
        Ok(())
    }

    /// Whether an item carrying `payload` bytes would be queued right now. The priming shadow uses
    /// it to keep deliveries that would retire a working stream out of the ordinary path.
    pub(super) fn admits(&self, payload: usize) -> bool {
        let mut ledger = self.lock();
        ledger.settle(self.queued_items());
        self.sender.capacity() > 0
            && !self.sender.is_closed()
            && ledger.queued.saturating_add(charge_for(payload)) <= OUTPUT_QUEUE_BYTES
    }

    /// Items in the channel that the receiver has not taken yet.
    fn queued_items(&self) -> usize {
        self.sender.max_capacity() - self.sender.capacity()
    }

    /// The ledger, recovered from a poisoned lock: it holds plain numbers that stay consistent.
    fn lock(&self) -> std::sync::MutexGuard<'_, Ledger> {
        self.ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The charged size of one queued item.
fn charge(item: &TerminalOutput) -> u64 {
    charge_for(match item {
        TerminalOutput::Output { bytes, .. } | TerminalOutput::Snapshot { bytes, .. } => bytes.len(),
        TerminalOutput::Event { event_json } => event_json.len(),
        _ => 0,
    })
}

/// Payload plus the per-item charge, saturating so an impossible size is simply refused by the cap.
fn charge_for(payload: usize) -> u64 {
    u64::try_from(payload)
        .unwrap_or(u64::MAX)
        .saturating_add(OUTPUT_ITEM_CHARGE)
}
