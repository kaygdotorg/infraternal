//! Captures bounded public transport milestones in opt-in namespace tests, without retaining terminal contents or changing shipping code [243,262,263].
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
    time::{Instant, SystemTime},
};

/// Most distinct first events the recorder keeps. Going over it makes the proof fail when read, instead of growing without bound.
const MAX_EVENTS: usize = 8192;
/// The one recorder currently capturing, held weakly so a finished proof is not kept alive.
static ACTIVE: Mutex<Option<Weak<Mutex<Events>>>> = Mutex::new(None);
// Observer integration tests share this owner without blocking an async runtime.
/// Tests that use the recorder hold this lock so only one capture runs at a time.
pub(crate) static TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A transport milestone worth recording.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Kind {
    /// The TLS handshake finished.
    TlsHandshake,
    /// The connection was admitted by the host ledger.
    LedgerAdmission,
    /// The control stream became usable.
    ControlReady,
    /// The control stream became usable over QUIC.
    QuicControlReady,
    /// The control stream became usable over TCP.
    TcpControlReady,
    /// A terminal detach found the writer already retired.
    TerminalDetachAlreadyRetired,
    /// A terminal detach failed with a write error.
    TerminalDetachWriteError,
    /// A terminal byte was seen.
    TerminalByte,
}

/// One recorded milestone. Holds identifiers and times only, never terminal content.
#[derive(Clone, Debug)]
pub(crate) struct Event {
    /// Which milestone.
    pub(crate) kind: Kind,
    /// Peer address (the physical one when a route table is set).
    pub(crate) peer: SocketAddr,
    /// Stream or writer number.
    pub(crate) stream: u32,
    /// Monotonic time, for measuring durations.
    pub(crate) monotonic: Instant,
    /// Wall-clock time, for comparing with the kernel's handshake timestamp.
    pub(crate) wall: SystemTime,
}

/// Recorded milestones: the first event per (kind, peer, stream), plus counts.
struct Events {
    include_peer: fn(SocketAddr) -> bool,
    routes: Option<Arc<infraternal_plugin_remote::remote_bindings::Bindings>>,
    first: BTreeMap<(Kind, SocketAddr, u32), Event>,
    overflow: bool,
    counts: BTreeMap<Kind, usize>,
    peer_counts: BTreeMap<(Kind, SocketAddr), usize>,
}
impl Events {
    /// Keeps the event if its peer passes the filter and it is the first of its key. Sets the overflow flag if [`MAX_EVENTS`] would be exceeded. Counts every kept callback.
    fn record(&mut self, mut event: Event) {
        if let Some(routes) = &self.routes {
            event.peer = routes.physical_peer(event.peer);
        }
        if !(self.include_peer)(event.peer) {
            return;
        }
        let key = (event.kind, event.peer, event.stream);
        // Per-peer callback counts cannot allocate beyond the first-event bound.
        if !self.first.contains_key(&key) && self.first.len() == MAX_EVENTS {
            self.overflow = true;
            return;
        }
        *self.counts.entry(event.kind).or_default() += 1;
        *self
            .peer_counts
            .entry((event.kind, event.peer))
            .or_default() += 1;
        if self.first.contains_key(&key) {
            return;
        }
        self.first.insert(key, event);
    }
}

/// One proof owns recording. Weak global ownership cannot keep a finished proof
/// or its event buffers alive, and a later proof starts with an empty recorder.
pub(crate) struct Capture(Arc<Mutex<Events>>);
impl Capture {
    /// Begins a capture and makes it the active one. Only peers for which `include_peer` is true are recorded.
    pub(crate) fn start(include_peer: fn(SocketAddr) -> bool) -> Self {
        // Ordinary tests may open connections concurrently. Only this proof's
        // peer addresses can contribute milestones or consume its record bound.
        let events = Arc::new(Mutex::new(Events {
            include_peer,
            routes: None,
            first: BTreeMap::new(),
            overflow: false,
            counts: BTreeMap::new(),
            peer_counts: BTreeMap::new(),
        }));
        let mut active = ACTIVE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(active.as_ref().and_then(Weak::upgrade).is_none());
        *active = Some(Arc::downgrade(&events));
        Self(events)
    }

    /// Resolve a logical tuple to its current physical route for diagnostics.
    /// Buffered or reordered plaintext has no packet provenance here; exact
    /// mesh-byte claims need the separate path-exclusive fresh-marker proof.
    pub(crate) fn with_routes(
        self,
        routes: Arc<infraternal_plugin_remote::remote_bindings::Bindings>,
    ) -> Self {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .routes = Some(routes);
        self
    }
    /// Counts callbacks even when the first-milestone map already has that tuple.
    pub(crate) fn count(&self, kind: Kind) -> usize {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .counts
            .get(&kind)
            .copied()
            .unwrap_or(0)
    }
    /// Integration assertions isolate their real TLS tuple from concurrent tests.
    pub(crate) fn count_peer(&self, kind: Kind, peer: SocketAddr) -> usize {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .peer_counts
            .get(&(kind, peer))
            .copied()
            .unwrap_or(0)
    }
    /// Returns the recorded first events. Panics if the recorder overflowed.
    pub(crate) fn events(&self) -> Vec<Event> {
        let events = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(!events.overflow, "transport milestone recorder overflowed");
        events.first.values().cloned().collect()
    }
    /// Select a fresh terminal witness for the expected non-control writer.
    pub(crate) fn first_terminal_after(&self, stream: u32, boundary: Instant) -> Option<Event> {
        assert!(stream != 0 && stream & 1 == 0);
        self.events()
            .into_iter()
            .filter(|event| {
                event.kind == Kind::TerminalByte
                    && event.stream == stream
                    && event.monotonic >= boundary
            })
            .min_by_key(|event| event.monotonic)
    }
    /// Begin a fresh terminal witness after draining earlier expected bytes.
    /// Retain cumulative admission/control and global output callback counts.
    /// Retire terminal peer counters too, preserving the recorder's key bound.
    pub(crate) fn clear_terminal_milestones(&self) {
        let mut events = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        events
            .first
            .retain(|(kind, _, _), _| *kind != Kind::TerminalByte);
        events
            .peer_counts
            .retain(|(kind, _), _| *kind != Kind::TerminalByte);
    }
}
impl Drop for Capture {
    /// Ends the capture if it is still the active one.
    fn drop(&mut self) {
        let mut active = ACTIVE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|events| Arc::ptr_eq(&events, &self.0))
        {
            *active = None;
        }
    }
}

/// Records a milestone for the active capture; does nothing when none is running. Takes both clocks before the lock so lock waits do not skew the times.
pub(crate) fn record(kind: Kind, peer: SocketAddr, stream: u32) {
    // Take both clocks before acquiring the recorder lock. Wall time compares
    // with the kernel's handshake timestamp; durations between callbacks use
    // the monotonic clock and cannot be affected by a wall-clock adjustment.
    let event = Event {
        kind,
        peer,
        stream,
        monotonic: Instant::now(),
        wall: SystemTime::now(),
    };
    let events = ACTIVE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(Weak::upgrade);
    if let Some(events) = events {
        events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(event);
    }
}

#[cfg(test)]
mod tests {
    //! Recording retains first milestones, distinguishes streams and ends with its proof owner.
    use super::*;
    #[test]
    fn fresh_terminal_witness_excludes_another_writer() {
        let _owner = TEST_SERIAL.blocking_lock();
        let peer = SocketAddr::from(([127, 0, 0, 1], 7444));
        let capture = Capture::start(|peer| peer == SocketAddr::from(([127, 0, 0, 1], 7444)));
        let boundary = Instant::now();
        {
            let mut events = capture.0.lock().unwrap();
            // Insert out of time order: another terminal's earlier callback
            // cannot satisfy this writer's post-fence byte witness.
            for (kind, stream, offset) in [
                (Kind::TerminalByte, 2, 2),
                (Kind::TerminalByte, 4, 1),
                (Kind::ControlReady, 2, 0),
            ] {
                events.record(Event {
                    kind,
                    peer,
                    stream,
                    monotonic: boundary + std::time::Duration::from_millis(offset),
                    wall: SystemTime::UNIX_EPOCH,
                });
            }
        }
        let observed = capture.first_terminal_after(2, boundary).unwrap();
        assert_eq!(
            observed.stream, 2,
            "another writer supplied the byte witness"
        );
        assert_eq!(
            observed.monotonic,
            boundary + std::time::Duration::from_millis(2)
        );
    }

    #[test]
    fn capture_retains_first_milestones_and_releases_ownership() {
        let _owner = TEST_SERIAL.blocking_lock();
        let peer = SocketAddr::from(([127, 0, 0, 1], 7443));
        let capture = Capture::start(|peer| peer == SocketAddr::from(([127, 0, 0, 1], 7443)));
        record(Kind::TlsHandshake, peer, 0);
        record(Kind::TerminalByte, peer, 2);
        let first = capture.events();
        record(
            Kind::TerminalByte,
            SocketAddr::from(([127, 0, 0, 2], 7443)),
            2,
        );
        record(Kind::TerminalByte, peer, 2);
        assert_eq!(capture.events().len(), 2);
        assert_eq!(capture.count(Kind::TerminalByte), 2);
        assert_eq!(capture.count(Kind::TlsHandshake), 1);
        assert_eq!(capture.events()[1].monotonic, first[1].monotonic);
        assert_eq!(capture.events()[1].wall, first[1].wall);
        record(Kind::TerminalByte, peer, 4);
        assert_eq!(capture.events().len(), 3);
        capture.clear_terminal_milestones();
        assert_eq!(capture.events().len(), 1);
        assert_eq!(capture.count(Kind::TerminalByte), 3);
        assert_eq!(capture.count_peer(Kind::TerminalByte, peer), 0);
        record(Kind::TerminalByte, peer, 2);
        assert_eq!(capture.events().len(), 2);
        assert_eq!(capture.count(Kind::TerminalByte), 4);
        assert_eq!(capture.count_peer(Kind::TerminalByte, peer), 1);
        drop(capture);
        record(Kind::TerminalByte, peer, 6);
        assert!(
            Capture::start(|peer| peer == SocketAddr::from(([127, 0, 0, 1], 7443)))
                .events()
                .is_empty()
        );
    }
}
