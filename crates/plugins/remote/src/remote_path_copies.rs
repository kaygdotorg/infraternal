//! Schedules one bounded ciphertext backup through the owning endpoint's receive poll, with no detached worker [215,263], #201.
use std::{
    pin::Pin,
    task::{Context, Poll, Waker},
    time::Duration,
};

/// Overlap loss detection and the enrolled-path round trip without waiting for
/// QUIC's loss timer. A terminal echo can need a copy at both ends, so their
/// combined delay consumes 20ms of the RTT + 50ms fallback budget.
pub(crate) const COPY_DELAY: Duration = Duration::from_millis(10);
/// Bound send work between receive polls, shared by every peer on an endpoint.
pub(crate) const COPY_BATCH: usize = 32;

/// One clock per endpoint socket, not one task or clock per leased peer.
#[derive(Default)]
pub(crate) struct CopyClock {
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    receiver: Option<Waker>,
}
impl CopyClock {
    /// Schedules the next copy for `deadline`. An earlier existing deadline wins, and the endpoint's receive task is woken so the new timer is registered.
    pub fn arm(&mut self, deadline: tokio::time::Instant) {
        if let Some(timer) = &mut self.timer {
            if deadline >= timer.deadline() {
                return;
            }
            timer.as_mut().reset(deadline);
        } else {
            self.timer = Some(Box::pin(tokio::time::sleep_until(deadline)));
        }
        // A send can follow the receive poll's Pending result. Wake the same
        // endpoint driver so the newly armed clock cannot miss registration.
        if let Some(receiver) = &self.receiver {
            receiver.wake_by_ref();
        }
    }
    /// Registers the waker and reports whether the timer has fired (clearing it). Call it from the endpoint's receive poll.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> bool {
        use std::future::Future as _;
        if !self
            .receiver
            .as_ref()
            .is_some_and(|old| old.will_wake(cx.waker()))
        {
            self.receiver = Some(cx.waker().clone());
        }
        if self
            .timer
            .as_mut()
            .is_some_and(|timer| matches!(timer.as_mut().poll(cx), Poll::Ready(())))
        {
            self.timer = None;
            return true;
        }
        false
    }
    #[cfg(test)]
    pub fn armed(&self) -> bool {
        self.timer.is_some()
    }
    #[cfg(test)]
    pub fn empty(&self) -> bool {
        self.timer.is_none() && self.receiver.is_none()
    }
    /// Retiring the last queued item cancels its timer while a live endpoint
    /// keeps its receive registration for the next successful transmit.
    pub fn cancel_timer(&mut self) {
        self.timer = None;
    }
    pub fn clear(&mut self) {
        self.timer = None;
        self.receiver = None;
    }
}

#[cfg(test)]
mod tests {
    //! A send after a pending receive cannot strand its clock registration.
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    struct Wake(AtomicBool);
    impl std::task::Wake for Wake {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::Relaxed);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    #[tokio::test]
    async fn cancelling_retired_work_keeps_the_next_send_receive_wakeup() {
        let signal = Arc::new(Wake(AtomicBool::new(false)));
        let waker = std::task::Waker::from(signal.clone());
        let mut cx = Context::from_waker(&waker);
        let mut clock = CopyClock::default();
        assert!(!clock.poll(&mut cx));
        clock.arm(tokio::time::Instant::now() + COPY_DELAY);
        clock.cancel_timer();
        assert!(!clock.armed());
        signal.0.store(false, Ordering::Relaxed);
        clock.arm(tokio::time::Instant::now() + COPY_DELAY);
        assert!(clock.armed());
        assert!(signal.0.load(Ordering::Relaxed));
        clock.clear();
        assert!(clock.empty());
    }

    #[tokio::test]
    async fn arming_after_pending_wakes_the_owned_endpoint_and_clear_drops_it() {
        let signal = Arc::new(Wake(AtomicBool::new(false)));
        let waker = std::task::Waker::from(signal.clone());
        let mut cx = Context::from_waker(&waker);
        let mut clock = CopyClock::default();
        assert!(!clock.poll(&mut cx));
        clock.arm(tokio::time::Instant::now() + COPY_DELAY);
        assert!(signal.0.load(Ordering::Relaxed));
        assert!(!clock.empty());
        clock.clear();
        assert!(clock.empty());
    }
}
