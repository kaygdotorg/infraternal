//! Coalesced wakeups and underlay endpoint announcements for the Linux and macOS userspace mesh (#483).
//!
//! When the host's underlay changes in a way that can move our own endpoint (a new or removed
//! address, a route or link change), every peer with a live session should hear one
//! authenticated packet from us, so it follows our new address at once instead of after the
//! keepalive or rekey timeout. Each platform's underlay listener calls
//! [`UnderlayAnnounce::changed`]; the engine's worker waits on an [`AnnouncementWaiter`] and asks
//! `GotaTun` for one keepalive per live session (`request_keepalives`).
//!
//! The schedule debounces changes for 25 ms, sends at most one announcement per 250 ms, keeps
//! the trailing edge, and arms no timer while the underlay is quiet (D81).
//!
//! The workers' endpoint scans share the schedule, and wake on [`confirmed_changed`] instead of
//! a timer (#260, J1253).

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};

/// A wakeup that coalesces requests: any number of requests made while one is pending are
/// covered by that one wakeup.
///
/// A request costs one relaxed load while a wakeup is already pending, and one swap plus a
/// `Notify` otherwise; it never allocates, so the packet path can call it. The waiter calls
/// [`CoalescedWake::begin`] right before it reads the state the requests are about, so a request
/// that arrives during that read queues exactly one more wakeup and is never lost.
#[derive(Debug, Default)]
pub struct CoalescedWake {
    /// Set from the first request until the waiter starts the work that will observe it.
    /// Tests of the signals built on it read it directly.
    pub pending: AtomicBool,
    notify: Notify,
}

impl CoalescedWake {
    /// Whether a wakeup is already queued and not yet begun. Only the Linux packet path asks; tests on every host check it.
    #[cfg(any(target_os = "linux", test))]
    pub fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Relaxed)
    }

    /// Queue one wakeup unless one is already queued.
    pub fn request(&self) {
        if !self.pending.swap(true, Ordering::AcqRel) {
            self.notify.notify_one();
        }
    }

    /// Wait for the next coalesced wakeup. Cancel-safe: a dropped wait consumes nothing.
    pub async fn notified(&self) {
        self.notify.notified().await;
    }

    /// Re-arm right before the waiter reads the state the requests are about.
    ///
    /// A request after this point is not covered by the read that follows, so it must queue
    /// another wakeup; clearing the flag first guarantees that it does.
    pub fn begin(&self) {
        self.pending.store(false, Ordering::Release);
    }
}

/// When the next coalesced piece of work runs: a short debounce after the first request, and
/// never sooner than a floor after the previous run.
///
/// The debounce gathers a burst (one kernel change is often several notifications, and traffic
/// arrives in batches) into one run; the floor bounds the rate however long the burst lasts.
/// Requests that arrive while a run is scheduled are covered by it, and a request after the run
/// starts schedules the next one, so the last request in any sequence is always followed by a
/// run (the trailing edge is kept).
#[derive(Default)]
pub struct CoalescedSchedule {
    /// When the scheduled run is due; `None` while nothing is scheduled.
    due: Option<Instant>,
    /// When the previous run last recorded its dispatch or completion.
    last: Option<Instant>,
}

impl CoalescedSchedule {
    /// Whether a run is scheduled. Callers stop listening for requests while it is.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.due.is_some()
    }

    /// Schedule a run for a request seen at `now`: after the debounce, and no sooner than the
    /// floor after the previous run.
    pub fn arm(&mut self, now: Instant) {
        let debounce = now + COALESCE_DEBOUNCE;
        let minimum = self.last.map_or(now, |last| last + COALESCE_MIN_INTERVAL);
        self.due = Some(debounce.max(minimum));
    }

    /// Sleep until the scheduled run is due, or forever while none is scheduled.
    pub async fn wait(&self) {
        if let Some(at) = self.due {
            tokio::time::sleep_until(at).await;
        } else {
            std::future::pending::<()>().await;
        }
    }

    /// The run starts: nothing is scheduled any more.
    pub fn start(&mut self) {
        self.due = None;
    }

    /// Record the caller's rate-limit reference time.
    pub fn finish(&mut self, now: Instant) {
        self.last = Some(now);
    }
}

/// Tells the `GotaTun` worker that the host's underlay changed in a way that can move our own
/// endpoint, so every peer with a live session should hear from us now (#260 J561, #483).
///
/// A peer learns our endpoint only from an authenticated packet. A node that is only receiving
/// sends nothing until `WireGuard`'s keepalive-plus-rekey timeout, so after an address change the
/// peer kept sending to the old address for 15.2 s (J561's break-it matrix, against the reconnect budget of D375 and D267).
/// The Linux route-netlink listener and the macOS routing-socket listener call
/// [`Self::changed`]. The worker asks `GotaTun` for one keepalive per live session via
/// `request_keepalives`, so the send count follows the number of live sessions.
///
/// The Linux node owns the wake across listener restarts and engine rebuilds. With the
/// kernel engine nobody waits on it, so a change costs one atomic swap. Each macOS worker
/// owns its wake alongside its listener.
#[derive(Debug, Default)]
pub struct UnderlayAnnounce {
    wake: CoalescedWake,
}

impl UnderlayAnnounce {
    /// Record that the underlay changed. Cheap and non-blocking; safe from any thread.
    pub fn changed(&self) {
        self.wake.request();
    }

    /// Whether an announcement was requested since the last call; clears the request.
    #[cfg(any(test, feature = "test-support"))]
    pub fn take_for_test(&self) -> bool {
        let pending = self.wake.pending.load(Ordering::Acquire);
        self.wake.begin();
        pending
    }
}

/// The worker's side of [`UnderlayAnnounce`]: yields once per announcement that is due.
///
/// Announcements use the endpoint refresh's coalescing ([`CoalescedSchedule`]): 25 ms after the
/// first change, and at most one per 250 ms (#483 J633 P1). One kernel change is several
/// notifications (an address, its connected and local routes), and a container host or routing
/// daemon can change routes many times a second; each announcement costs one keepalive per live
/// session, so the rate must not follow the churn. The last change is always announced: a
/// change after an announcement starts schedules the next one, which is how the announcement
/// after IPv6 duplicate address detection, or after a late connected route, still goes out.
pub struct AnnouncementWaiter {
    announce: Arc<UnderlayAnnounce>,
    schedule: CoalescedSchedule,
}

impl AnnouncementWaiter {
    /// Wait on `announce` for the worker that owns this waiter.
    pub fn new(announce: Arc<UnderlayAnnounce>) -> Self {
        Self {
            announce,
            schedule: CoalescedSchedule::default(),
        }
    }

    /// Wait until an announcement is due, then re-arm the signal so a later change queues the
    /// next one.
    ///
    /// Cancel-safe, so it can sit in a `select!`: the schedule keeps its deadline across a
    /// dropped call, and a dropped wait for a change consumes nothing. The floor counts from
    /// when the announcement starts; the keepalive request itself takes microseconds per peer.
    pub async fn next(&mut self) {
        if !self.schedule.is_armed() {
            self.announce.wake.notified().await;
            self.schedule.arm(Instant::now());
        }
        self.schedule.wait().await;
        self.schedule.start();
        self.announce.wake.begin();
        self.schedule.finish(Instant::now());
    }
}

impl Drop for AnnouncementWaiter {
    /// Return a consumed wakeup if the worker stops before dispatching the armed announcement.
    fn drop(&mut self) {
        if self.schedule.is_armed() {
            self.announce.wake.notify.notify_one();
        }
    }
}

/// Wait until the engine reports a changed confirmed endpoint
/// (`Device::confirmed_endpoint_changes`, passed in as `changes`); forever while no engine
/// runs. Cancel-safe: a change reported while nobody waits is seen by the next wait.
pub async fn confirmed_changed(changes: Option<Arc<Notify>>) {
    match changes {
        Some(changes) => changes.notified().await,
        None => std::future::pending().await,
    }
}

/// Coalesce closely spaced requests (packet deliveries, kernel notifications) into one run.
pub const COALESCE_DEBOUNCE: Duration = Duration::from_millis(25);
/// Bound each coalesced kind of work (route refreshes and endpoint scans) to four runs a second.
pub const COALESCE_MIN_INTERVAL: Duration = Duration::from_millis(250);

/// What an underlay listener last saw of the host's network facts (addresses, routes, links),
/// so a notification that only repeats a known fact is not counted as a change (#483 J633 P1).
///
/// Kernels send notifications for refreshes as well as for changes: Linux sends `RTM_NEWADDR`
/// for every lifetime refresh (DHCP renewals, IPv6 router advertisements), and a route can be
/// re-installed with only its lifetime changed. Each listener reduces a notification to a key
/// (what the fact is) and a value (the parts of it that can move our endpoint, never its
/// lifetime), and asks the book whether it changed.
///
/// A fact the book has not seen counts, so a book that starts empty (or is rebuilt after lost
/// notifications) costs at most one extra announcement per fact, never a missed one.
#[derive(Debug)]
pub struct ChangeBook<K, V> {
    known: std::collections::HashMap<K, V>,
}

impl<K, V> Default for ChangeBook<K, V> {
    fn default() -> Self {
        Self {
            known: std::collections::HashMap::new(),
        }
    }
}

/// Two books are equal when they hold the same facts; a listener compares a fresh read of the
/// host with what it has seen to find changes it may have missed.
impl<K: Eq + std::hash::Hash, V: PartialEq> PartialEq for ChangeBook<K, V> {
    fn eq(&self, other: &Self) -> bool {
        self.known == other.known
    }
}

impl<K: Eq + std::hash::Hash, V: Eq> Eq for ChangeBook<K, V> {}

impl<K: Eq + std::hash::Hash, V: PartialEq> ChangeBook<K, V> {
    /// Record that `key` exists with `value`. Returns whether that is a change: a new key or a
    /// different value. The same key with the same value (a refresh) is not.
    pub fn present(&mut self, key: K, value: V) -> bool {
        if self.known.get(&key) == Some(&value) {
            return false;
        }
        self.known.insert(key, value);
        true
    }

    /// Record that `key` is gone. A removal always counts, known or not: the book may have
    /// missed the fact's arrival (it started empty, or notifications were lost).
    pub fn absent(&mut self, key: &K) -> bool {
        self.known.remove(key);
        true
    }

    /// How many facts the book holds; the host's own address, route or link count.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.known.len()
    }
}

/// Paused-clock tests of the coalescing and unit tests of the change book.
#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use std::{sync::Arc, time::Duration};

    /// Count the announcements `waiter` yields until `until`.
    async fn announcements_until(
        waiter: &mut super::AnnouncementWaiter,
        until: tokio::time::Instant,
    ) -> Vec<tokio::time::Instant> {
        let mut runs = Vec::new();
        while tokio::time::timeout_at(until, waiter.next()).await.is_ok() {
            runs.push(tokio::time::Instant::now());
        }
        runs
    }

    /// J633 P1 (D81, D393): route churn on an unrelated link (a container host starting pods,
    /// a routing daemon) is coalesced like the endpoint refresh: a 25 ms debounce and at most
    /// one announcement per 250 ms, however long the churn lasts. Each announcement costs one
    /// keepalive per live session, so without the bound 40 routes cost 40 rounds.
    #[tokio::test(start_paused = true)]
    async fn route_churn_announcements_are_rate_limited() {
        let announce = Arc::new(super::UnderlayAnnounce::default());
        let mut waiter = super::AnnouncementWaiter::new(Arc::clone(&announce));
        let started = tokio::time::Instant::now();
        let churn = {
            let announce = Arc::clone(&announce);
            tokio::spawn(async move {
                for _ in 0..40 {
                    announce.changed();
                    // sleep: paused clock; spaces the changes as a container host spaces routes.
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
        };
        let runs = announcements_until(&mut waiter, started + Duration::from_secs(2)).await;
        churn.await.expect("the churn task finishes");
        assert!(
            runs.len() <= 6,
            "40 changes over 1 s caused {} announcements; the budget is one per 250 ms",
            runs.len()
        );
        let last_change = started + Duration::from_millis(39 * 25);
        assert!(
            runs.last().is_some_and(|run| *run >= last_change),
            "the last change must still be announced (trailing edge)"
        );
    }

    /// The announce after IPv6 duplicate address detection still goes out: a change that
    /// arrives after a burst was announced gets its own announcement, because the address only
    /// becomes usable as a source then.
    #[tokio::test(start_paused = true)]
    async fn a_change_after_the_burst_is_announced_too() {
        let announce = Arc::new(super::UnderlayAnnounce::default());
        let mut waiter = super::AnnouncementWaiter::new(Arc::clone(&announce));
        let started = tokio::time::Instant::now();
        // The tentative address and its routes arrive together.
        for _ in 0..3 {
            announce.changed();
        }
        let burst = announcements_until(&mut waiter, started + Duration::from_millis(500)).await;
        assert_eq!(burst.len(), 1, "one burst is one announcement");
        // Duplicate address detection completes a second later.
        announce.changed();
        let late = announcements_until(&mut waiter, started + Duration::from_millis(1_000)).await;
        assert_eq!(
            late.len(),
            1,
            "the change after the burst needs its own announcement"
        );
    }

    /// D81: while the underlay is quiet, the announce path never yields and arms no timer, so an
    /// idle node gains no wakeups from it (an hour on the paused clock).
    #[tokio::test(start_paused = true)]
    async fn an_idle_underlay_never_announces() {
        let announce = Arc::new(super::UnderlayAnnounce::default());
        let mut waiter = super::AnnouncementWaiter::new(Arc::clone(&announce));
        let until = tokio::time::Instant::now() + Duration::from_secs(3_600);
        assert_eq!(announcements_until(&mut waiter, until).await, Vec::new());
        assert!(
            !waiter.schedule.is_armed(),
            "no timer may be armed while nothing changed"
        );
    }

    /// A worker replaced during the debounce returns its wakeup for the next worker to dispatch.
    #[tokio::test(start_paused = true)]
    async fn a_replaced_waiter_preserves_the_armed_announcement() {
        let announce = Arc::new(super::UnderlayAnnounce::default());
        let mut waiter = super::AnnouncementWaiter::new(Arc::clone(&announce));
        announce.changed();
        let before_due = tokio::time::Instant::now() + Duration::from_millis(1);
        assert_eq!(
            announcements_until(&mut waiter, before_due).await,
            Vec::new()
        );
        assert!(waiter.schedule.is_armed());
        drop(waiter);

        let mut replacement = super::AnnouncementWaiter::new(announce);
        let until = tokio::time::Instant::now() + Duration::from_millis(500);
        assert_eq!(announcements_until(&mut replacement, until).await.len(), 1);
    }

    /// A refresh repeats a known fact and is not a change; a new value, a new key or any
    /// removal is.
    #[test]
    fn the_book_counts_changes_not_refreshes() {
        let mut book = super::ChangeBook::<u8, u32>::default();
        assert!(book.present(1, 7), "a new fact is a change");
        assert!(!book.present(1, 7), "the same fact again is a refresh");
        assert!(
            book.present(1, 8),
            "a new value for a known fact is a change"
        );
        assert!(book.absent(&1), "a removal is a change");
        assert!(book.absent(&2), "a removal the book never saw still counts");
        assert_eq!(book.len(), 0);
    }
}
