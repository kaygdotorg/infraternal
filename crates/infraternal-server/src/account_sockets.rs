//! Each account's live browser sockets, and taking one over when the account is full (#523, owner decision B).
//!
//! An account may hold [`MAX_USER_CONNECTIONS`](crate::websocket) live sockets: one per open tab or app. A phone
//! keeps old tabs alive in the background, so an account can fill up with tabs nobody is looking at, and a fresh
//! page then had nowhere to go. The owner's rule (2026-11-15): **the new page takes over the socket of the account's
//! oldest hidden tab.** That tab is told why and pauses; it connects again when the person comes back to it. Only
//! when no tab of the account is hidden does the new page hear that the account has too many open connections.
//!
//! A second rule uses the same list. A **host** can be full too: its link carries a bounded number of terminals, and a
//! socket whose browser vanished without closing it keeps its share until the server notices. A page that last said it
//! was hidden gets no liveness probes (#317), so nothing would notice. When an attach is refused for a full host, every
//! socket of the account is asked to answer once ([`AccountSockets::challenge_all`]); the transport ends the ones that
//! stay silent, which releases their terminals (#562). Nothing is asked while no host is full, so idle pages stay
//! asleep, and a socket that answered is left alone for a while however often the refused page retries.
//!
//! How it fits together:
//!  - [`AccountSockets`] is one account's semaphore of socket slots plus the list of its admitted viewers. The
//!    WebSocket state keeps a weak entry per account, so an account with no sockets costs nothing.
//!  - [`AccountSlot`] is what an admitted socket holds for its whole life: the slot permit and its [`Viewer`].
//!    Dropping it (after the socket's teardown has marked its connection row inactive) frees the slot.
//!  - [`Viewer`] is the part the socket's reader and loop share: whether the page says it is hidden, since when,
//!    the signal that asks the socket to end because another tab took it over, and the one that asks it to prove it
//!    is still there.
//!  - [`AccountSockets::take_over_hidden`] picks the viewer hidden the longest, signals it, and waits a bounded time
//!    for its slot.
//!
//! Invariants:
//!  - Only sockets of the same account are ever candidates: the registry is keyed by the session's user id and a
//!    viewer lives only in its own account's list. Nothing here can end another account's socket.
//!  - "Hidden" is what the page itself reported through the visibility notice (Hello bit 2). A page that never
//!    reports it (an older page, a native client) is never taken over.
//!  - A viewer is claimed at most once ([`Viewer::claim`]), so two new pages arriving together pick two different
//!    hidden tabs instead of both waiting on one.
//!  - The slot a taken-over socket frees goes to a waiting taker before any later `try_acquire`: tokio's semaphore
//!    hands released permits to queued waiters first.

use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// How long a new page waits for a taken-over socket to finish its teardown and free its slot. The teardown is one
/// authority read, two close frames bounded at 25 ms each and one row update, so this is generous; past it the new
/// page is told the account is full and keeps retrying by itself.
pub(crate) const TAKEOVER_WAIT: Duration = Duration::from_secs(2);

/// One account's socket slots and the viewers that hold them.
pub(crate) struct AccountSockets {
    /// One permit per live socket of the account.
    slots: Arc<Semaphore>,
    /// Every admitted socket's viewer. Weak, so a socket that ended without its drop running cannot keep one alive;
    /// dead entries are swept whenever the list is touched.
    viewers: Mutex<Vec<Weak<Viewer>>>,
}

/// What one admitted socket shares between its reader (which hears the page's visibility) and its loop (which ends
/// the socket when another tab takes it over).
#[derive(Default)]
pub(crate) struct Viewer {
    /// When the page last said it went hidden; `None` while it is visible or has never said.
    hidden_since: Mutex<Option<Instant>>,
    /// Set once by the taker that chose this viewer, so no second taker picks it.
    claimed: AtomicBool,
    /// Signalled once to ask the socket to end with the takeover reason. `Notify` keeps the signal if the loop is not
    /// waiting at that moment, so it is never lost.
    taken_over: Notify,
    /// Signalled to ask the socket to prove its browser still answers. Signals that arrive while one proof is running
    /// merge into a single further proof.
    challenged: Notify,
}

/// The slot an admitted socket holds until it ends. Keep it alive until after the socket's teardown, so the slot is
/// free only once the connection row is inactive and a new connection can take its place in the row count too.
pub(crate) struct AccountSlot {
    /// The account's slot itself; released when the slot drops.
    _permit: OwnedSemaphorePermit,
    /// The account, to take the viewer off its list on drop (and to keep its weak registry entry alive).
    account: Arc<AccountSockets>,
    /// This socket's viewer, shared with its reader and loop.
    viewer: Arc<Viewer>,
}

impl AccountSockets {
    /// An account with `limit` socket slots and no viewers yet.
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(limit)),
            viewers: Mutex::new(Vec::new()),
        }
    }

    /// A free slot right now, or `None` when the account is full.
    pub(crate) fn try_slot(self: &Arc<Self>) -> Option<AccountSlot> {
        let permit = self.slots.clone().try_acquire_owned().ok()?;
        self.admit(permit)
    }

    /// Takes over the account's longest-hidden socket for a new page: signals it to end, then waits up to `wait`
    /// for its slot. `None` when no socket of the account is hidden (or all hidden ones are already being taken
    /// over), or when the slot did not free in time: the caller then refuses the new page with the limit's reason.
    pub(crate) async fn take_over_hidden(self: &Arc<Self>, wait: Duration) -> Option<AccountSlot> {
        let victim = self.claim_longest_hidden()?;
        victim.taken_over.notify_one();
        let permit = tokio::time::timeout(wait, self.slots.clone().acquire_owned())
            .await
            .ok()?
            .ok()?;
        self.admit(permit)
    }

    /// Claims the viewer that has been hidden the longest and is not claimed yet. Picking and claiming happen under
    /// the list's lock, so concurrent takers never choose the same viewer.
    fn claim_longest_hidden(&self) -> Option<Arc<Viewer>> {
        let mut viewers = self.viewers.lock().ok()?;
        viewers.retain(|viewer| viewer.strong_count() != 0);
        let victim = viewers
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|viewer| !viewer.claimed.load(Ordering::Acquire))
            .filter_map(|viewer| viewer.hidden_since().map(|since| (since, viewer)))
            .min_by_key(|(since, _)| *since)
            .map(|(_, viewer)| viewer)?;
        victim.claim().then_some(victim)
    }

    /// Asks every live socket of the account to prove its browser still answers. Returns at once: the sockets' own
    /// transports send the probe and end a socket that stays silent.
    pub(crate) fn challenge_all(&self) {
        let Ok(mut viewers) = self.viewers.lock() else {
            return;
        };
        viewers.retain(|viewer| viewer.strong_count() != 0);
        for viewer in viewers.iter().filter_map(Weak::upgrade) {
            viewer.challenged.notify_one();
        }
    }

    /// Registers a fresh viewer for a socket that got `permit`.
    fn admit(self: &Arc<Self>, permit: OwnedSemaphorePermit) -> Option<AccountSlot> {
        let viewer = Arc::new(Viewer::default());
        let mut viewers = self.viewers.lock().ok()?;
        viewers.retain(|viewer| viewer.strong_count() != 0);
        viewers.push(Arc::downgrade(&viewer));
        drop(viewers);
        Some(AccountSlot {
            _permit: permit,
            account: Arc::clone(self),
            viewer,
        })
    }
}

impl Viewer {
    /// Records what the page said about its visibility. Going hidden starts the clock once (a repeated "hidden" keeps
    /// the first time, so a page cannot jump the queue by repeating itself); becoming visible clears it.
    pub(crate) fn set_hidden(&self, hidden: bool) {
        if let Ok(mut since) = self.hidden_since.lock() {
            match (hidden, *since) {
                (true, None) => *since = Some(Instant::now()),
                (false, _) => *since = None,
                (true, Some(_)) => {}
            }
        }
    }

    /// When the page went hidden, if it is hidden now.
    fn hidden_since(&self) -> Option<Instant> {
        self.hidden_since.lock().ok().and_then(|since| *since)
    }

    /// Marks this viewer as chosen; true only for the first caller.
    fn claim(&self) -> bool {
        !self.claimed.swap(true, Ordering::AcqRel)
    }

    /// Resolves once another tab of the account has taken this socket over; the socket loop then ends the socket.
    pub(crate) async fn taken_over(&self) {
        self.taken_over.notified().await;
    }

    /// Resolves when the socket is asked to prove its browser still answers; the socket's transport then probes it.
    pub(crate) async fn challenged(&self) {
        self.challenged.notified().await;
    }
}

impl AccountSlot {
    /// The viewer this socket's reader and loop share.
    pub(crate) fn viewer(&self) -> Arc<Viewer> {
        Arc::clone(&self.viewer)
    }
}

impl Drop for AccountSlot {
    /// Takes the viewer off its account's list right away, so the list never grows with ended sockets.
    fn drop(&mut self) {
        if let Ok(mut viewers) = self.account.viewers.lock() {
            let ended = Arc::as_ptr(&self.viewer);
            viewers.retain(|viewer| viewer.strong_count() != 0 && viewer.as_ptr() != ended);
        }
    }
}

/// Which socket is taken over, and what never is.
#[cfg(test)]
#[path = "account_sockets_tests.rs"]
mod tests;
