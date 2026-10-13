//! Captures bounded public transport milestones in opt-in namespace tests, without retaining terminal contents or changing shipping code [243,262,263].
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
    time::{Instant, SystemTime},
};

const MAX_EVENTS: usize = 8192;
static ACTIVE: Mutex<Option<Weak<Mutex<Events>>>> = Mutex::new(None);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Kind {
    TlsHandshake,
    LedgerAdmission,
    ControlReady,
    TerminalByte,
}

#[derive(Clone, Debug)]
pub(crate) struct Event {
    pub(crate) kind: Kind,
    pub(crate) peer: SocketAddr,
    pub(crate) stream: u32,
    pub(crate) monotonic: Instant,
    pub(crate) wall: SystemTime,
}

struct Events {
    include_peer: fn(SocketAddr) -> bool,
    first: BTreeMap<(Kind, SocketAddr, u32), Event>,
    overflow: bool,
}
impl Events {
    fn record(&mut self, event: Event) {
        if !(self.include_peer)(event.peer) {
            return;
        }
        let key = (event.kind, event.peer, event.stream);
        if self.first.contains_key(&key) {
            return;
        }
        if self.first.len() == MAX_EVENTS {
            self.overflow = true;
            return;
        }
        self.first.insert(key, event);
    }
}

/// One proof owns recording. Weak global ownership cannot keep a finished proof
/// or its event buffers alive, and a later proof starts with an empty recorder.
pub(crate) struct Capture(Arc<Mutex<Events>>);
impl Capture {
    pub(crate) fn start(include_peer: fn(SocketAddr) -> bool) -> Self {
        // Ordinary tests may open connections concurrently. Only this proof's
        // peer addresses can contribute milestones or consume its record bound.
        let events = Arc::new(Mutex::new(Events {
            include_peer,
            first: BTreeMap::new(),
            overflow: false,
        }));
        let mut active = ACTIVE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(active.as_ref().and_then(Weak::upgrade).is_none());
        *active = Some(Arc::downgrade(&events));
        Self(events)
    }

    pub(crate) fn events(&self) -> Vec<Event> {
        let events = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(!events.overflow, "transport milestone recorder overflowed");
        events.first.values().cloned().collect()
    }
}
impl Drop for Capture {
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
    fn capture_retains_first_milestones_and_releases_ownership() {
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
        assert_eq!(capture.events()[1].monotonic, first[1].monotonic);
        assert_eq!(capture.events()[1].wall, first[1].wall);
        record(Kind::TerminalByte, peer, 4);
        assert_eq!(capture.events().len(), 3);
        drop(capture);
        record(Kind::TerminalByte, peer, 6);
        assert!(
            Capture::start(|peer| peer == SocketAddr::from(([127, 0, 0, 1], 7443)))
                .events()
                .is_empty()
        );
    }
}
