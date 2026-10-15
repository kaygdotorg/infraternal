//! Bounded correlated Ping/Pong deadlines for pipelined and answer-paced routes [D265, #199].

use std::{collections::VecDeque, time::Duration};
use tokio::time::Instant;

/// A short scheduling allowance keeps failure detection near one measured RTT.
/// Pipelining avoids waiting another RTT before discovering a newly broken direction.
pub(crate) const TICK: Duration = Duration::from_millis(25);
// One millisecond lets a ready client tick precede fallback. Take it from the
// response margin, preserving the exact measured-RTT + 50ms total allowance.
const SERIAL_GAP: Duration = Duration::from_millis(26);
const SERIAL_RESPONSE: Duration = Duration::from_millis(24);
const _: () = assert!(SERIAL_GAP.as_millis() + SERIAL_RESPONSE.as_millis() == TICK.as_millis() * 2);

pub(crate) struct Liveness {
    origin: Instant,
    answered: Instant,
    sent: u64,
    acked: u64,
    budget: Duration,
    answer_paced: bool,
    issued: VecDeque<u64>,
}

impl Liveness {
    pub(crate) fn new() -> Self {
        let now = Instant::now();
        Self {
            origin: now,
            answered: now,
            sent: 0,
            acked: 0,
            issued: VecDeque::new(),
            answer_paced: false,
            // Before the first sample, allow greeting/replay and an unknown link RTT.
            budget: Duration::from_secs(2),
        }
    }

    /// Serial probes divide the fixed silence allowance between idle and reply
    /// time; pipelined routes retain their existing two-tick response floor.
    pub(crate) fn answer_paced() -> Self {
        Self {
            answer_paced: true,
            ..Self::new()
        }
    }

    /// Restart monitoring on the same transport without reusing a prior probe ID.
    /// Clearing issued requests disarms the lease; the clock and counter survive.
    pub(crate) fn restart(&mut self) {
        self.answered = Instant::now();
        self.acked = 0;
        self.budget = Duration::from_secs(2);
        self.issued.clear();
    }

    /// Startup pipelines samples; a sampled route waits for its actual answer.
    pub(crate) fn next_probe_due(&self, fast: bool) -> Option<Instant> {
        if self.acked == 0 {
            Some(
                self.origin
                    + Duration::from_micros(self.sent)
                    + if self.sent == 0 { Duration::ZERO } else { TICK },
            )
        } else if self.issued.is_empty() {
            Some(
                self.answered
                    + if self.answer_paced && !fast {
                        SERIAL_GAP
                    } else {
                        TICK
                    },
            )
        } else {
            None
        }
    }

    /// An already-ready reply may pull the next probe forward, never amplify it.
    pub(crate) fn can_piggyback(&self) -> bool {
        self.acked != 0
            && self.issued.is_empty()
            && self.origin.elapsed() >= Duration::from_micros(self.sent) + TICK
    }

    /// Wake independently of the next probe; preserve the strict expiry boundary.
    pub(crate) fn response_deadline(&self) -> Option<Instant> {
        (!self.issued.is_empty()).then(|| self.answered + self.budget + Duration::from_nanos(1))
    }

    pub(crate) fn ping(&mut self) -> (u64, u64) {
        // Never move an outstanding deadline: pipelining cannot mask silence.
        if self.issued.is_empty() {
            let now = Instant::now();
            if self.acked == 0 || self.answer_paced {
                // Serial routes budget their idle gap separately; startup has
                // no measured silence window until the first actual request.
                self.answered = now;
            } else {
                // Keep the pipelined last-answer window, including its intended
                // idle tick. Only a late local callback earns timing credit.
                let due =
                    (self.origin + Duration::from_micros(self.sent) + TICK).max(self.answered);
                if now > due {
                    self.answered += now - due;
                }
            }
        }
        self.sent = u64::try_from(self.origin.elapsed().as_micros())
            .unwrap_or(u64::MAX)
            .max(self.sent.saturating_add(1));
        // The startup grace admits at most 80 ticks; bound retained correlation
        // even if a caller pipelines faster. Eviction cannot renew readiness.
        if self.issued.len() == 128 {
            self.issued.pop_front();
        }
        self.issued.push_back(self.sent);
        (self.sent, self.sent)
    }

    pub(crate) fn pong(&mut self, nonce: u64, sent_us: u64) -> bool {
        // Only a new reply to this route's issued probes renews its lease.
        // Delayed/duplicate replies, ordinary traffic and another stream cannot do so.
        if nonce != sent_us
            || nonce <= self.acked
            || !self.issued.contains(&nonce)
            || self.expired()
        {
            return false;
        }
        let now = Instant::now();
        let rtt = now
            .duration_since(self.origin)
            .saturating_sub(Duration::from_micros(sent_us));
        self.acked = nonce;
        while self.issued.front().is_some_and(|issued| *issued <= nonce) {
            self.issued.pop_front();
        }
        self.answered = now;
        self.budget = if self.answer_paced {
            rtt + SERIAL_RESPONSE
        } else {
            (rtt + TICK).max(TICK * 2)
        };
        true
    }

    pub(crate) fn expired(&self) -> bool {
        !self.issued.is_empty() && self.answered.elapsed() > self.budget
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn pipelined_idle_gap_does_not_renew_the_sampled_lease() {
        let mut route = Liveness::new();
        tokio::time::advance(TICK).await;
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(route.pong(nonce, stamp));
        tokio::time::advance(TICK - Duration::from_millis(1)).await;
        route.ping();
        tokio::time::advance(Duration::from_millis(26)).await;
        assert!(
            !route.expired(),
            "the existing silence boundary is inclusive"
        );
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert!(
            route.expired(),
            "the intended idle gap cannot renew readiness"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn late_native_probe_keeps_its_unissued_reply_allowance() {
        let mut route = Liveness::new();
        tokio::time::advance(TICK).await;
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(route.pong(nonce, stamp));
        // The next intended tick is 50ms; its local callback arrives 11ms late.
        tokio::time::advance(Duration::from_millis(35)).await;
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(20)).await;
        assert!(route.pong(nonce, stamp), "local delay is not peer silence");
    }

    #[tokio::test(start_paused = true)]
    async fn delayed_server_probe_does_not_expire_an_answered_route() {
        let mut route = Liveness::new();
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(1)).await;
        route.pong(nonce, stamp);
        // Server-side authorization or writer work can postpone the next probe.
        // The peer cannot answer a probe that has not been issued yet.
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(!route.expired(), "all issued probes were answered");
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(1)).await;
        route.pong(nonce, stamp);
        assert_eq!(route.acked, nonce, "the timely answer must renew the route");
        assert!(!route.expired());
    }

    #[tokio::test(start_paused = true)]
    async fn missing_replies_expire_even_with_probes_in_flight() {
        let mut route = Liveness::new();
        tokio::time::advance(TICK).await;
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(150)).await;
        route.pong(nonce, stamp);
        assert!(!route.expired());
        route.ping();
        tokio::time::advance(Duration::from_millis(175)).await;
        route.ping();
        // A stale or unsolicited Pong cannot hide a one-direction failure.
        route.pong(nonce, stamp);
        route.pong(u64::MAX, u64::MAX);
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(route.expired());
        // A queued reply may win the select before an overdue timer. It cannot
        // turn suspension into a longer lease after the old lease has ended.
        let (nonce, stamp) = route.ping();
        route.pong(nonce, stamp);
        assert!(route.expired());
    }

    #[tokio::test(start_paused = true)]
    async fn serial_probe_deadline_includes_idle_gap_within_rtt_plus_fifty() {
        for rtt in [1, 30, 150, 1200] {
            for phase in [0, 7, 20, 24, 25] {
                let mut route = Liveness::answer_paced();
                let (nonce, stamp) = route.ping();
                tokio::time::advance(Duration::from_millis(rtt)).await;
                assert!(route.pong(nonce, stamp));
                let answered = Instant::now();
                assert_eq!(route.next_probe_due(false), Some(answered + SERIAL_GAP));
                tokio::time::advance(Duration::from_millis(phase)).await;
                let broken = Instant::now();
                let Some(until_probe) = SERIAL_GAP.checked_sub(Duration::from_millis(phase)) else {
                    panic!("phase must remain inside the idle tick");
                };
                tokio::time::advance(until_probe).await;
                route.ping();
                assert!(
                    route.next_probe_due(false).is_none(),
                    "one sampled probe in flight"
                );
                let Some(deadline) = route.response_deadline() else {
                    panic!("issued probe needs a deadline");
                };
                assert!(
                    deadline - broken
                        <= Duration::from_millis(rtt) + TICK * 2 + Duration::from_nanos(1)
                );
                tokio::time::advance(deadline - Instant::now()).await;
                assert!(route.expired());
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ready_reply_only_pulls_forward_an_answered_probe_after_one_tick() {
        let mut route = Liveness::answer_paced();
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(5)).await;
        assert!(route.pong(nonce, stamp));
        tokio::time::advance(Duration::from_millis(19)).await;
        assert!(!route.can_piggyback());
        tokio::time::advance(Duration::from_millis(2)).await;
        assert!(route.can_piggyback());
        assert!(
            route
                .next_probe_due(false)
                .is_some_and(|due| due > Instant::now())
        );
        route.ping();
        let deadline = route.response_deadline();
        tokio::time::advance(TICK).await;
        assert!(!route.can_piggyback(), "pending proof cannot be replaced");
        assert_eq!(route.response_deadline(), deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn serial_probe_accepts_a_timely_rtt_step_without_renewing_unsolicited_replies() {
        let mut route = Liveness::answer_paced();
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(route.pong(nonce, stamp));
        assert!(!route.pong(nonce, stamp));
        tokio::time::advance(TICK).await;
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(20)).await;
        assert!(!route.pong(nonce + 1, stamp + 1));
        assert!(route.pong(nonce, stamp));
        assert!(!route.expired());
    }

    #[tokio::test(start_paused = true)]
    async fn restarting_monitoring_never_reuses_an_old_issued_probe() {
        let mut route = Liveness::answer_paced();
        let old = route.ping();
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(route.pong(old.0, old.1));
        route.restart();
        assert!(route.response_deadline().is_none());
        let fresh = route.ping();
        assert!(fresh.0 > old.0);
        let deadline = route.response_deadline();
        assert!(
            !route.pong(old.0, old.1),
            "old activation cannot answer the new probe"
        );
        assert_eq!(route.response_deadline(), deadline);
        assert!(route.pong(fresh.0, fresh.1));
    }

    #[tokio::test(start_paused = true)]
    async fn recent_application_progress_preserves_the_first_tick_cadence() {
        let mut route = Liveness::answer_paced();
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(route.pong(nonce, stamp));
        assert_eq!(route.next_probe_due(true), Some(Instant::now() + TICK));
        assert_eq!(
            route.next_probe_due(false),
            Some(Instant::now() + SERIAL_GAP)
        );
    }
}
