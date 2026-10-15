//! Bounded correlated Ping/Pong deadlines for pipelined and answer-paced routes [D265, #199].

use std::{collections::VecDeque, time::Duration};
use tokio::time::Instant;

/// Probe cadence is independent of response allowance: idle work stays unchanged.
pub(crate) const TICK: Duration = Duration::from_millis(25);
// One millisecond lets a ready client tick precede fallback.
const SERIAL_GAP: Duration = Duration::from_millis(26);
// The floor covers a 150ms local stall plus reply dispatch, without waiting for
// transport timeouts. Slow routes instead follow their measured RTT and jitter.
const RESPONSE_FLOOR: Duration = Duration::from_millis(250);
const RESPONSE_MARGIN: Duration = Duration::from_millis(50);

pub(crate) struct Liveness {
    origin: Instant,
    answered: Instant,
    sent: u64,
    acked: u64,
    budget: Duration,
    srtt: Option<Duration>,
    rttvar: Duration,
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
            srtt: None,
            rttvar: Duration::ZERO,
            // Before the first sample, allow greeting/replay and an unknown link RTT.
            budget: Duration::from_secs(2),
        }
    }

    /// Browser routes pace idle requests from their correlated answers.
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
        self.srtt = None;
        self.rttvar = Duration::ZERO;
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
            // A peer cannot answer an unissued request. Account for local
            // timer delay only here; sending again never renews silence.
            self.answered = now;
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
        // Update variation against the previous SRTT (alpha=1/8, beta=1/4).
        // Only the correlated, unexpired reply above can train either estimate.
        let srtt = if let Some(previous) = self.srtt {
            self.rttvar = (self.rttvar * 3 + previous.abs_diff(rtt)) / 4;
            (previous * 7 + rtt) / 8
        } else {
            self.rttvar = rtt / 2;
            rtt
        };
        self.srtt = Some(srtt);
        self.budget = (srtt + self.rttvar * 4 + RESPONSE_MARGIN).max(RESPONSE_FLOOR);
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
    async fn healthy_reply_survives_a_150ms_server_stall() {
        for mut route in [Liveness::new(), Liveness::answer_paced()] {
            let (nonce, stamp) = route.ping();
            tokio::time::advance(Duration::from_millis(1)).await;
            assert!(route.pong(nonce, stamp));
            tokio::time::advance(TICK).await;
            let (nonce, stamp) = route.ping();
            let deadline = route.response_deadline();
            tokio::time::advance(Duration::from_millis(150)).await;
            assert!(!route.expired(), "scheduler stalls are not peer loss");
            assert_eq!(route.response_deadline(), deadline);
            assert!(route.pong(nonce, stamp));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn quiet_dead_peer_expires_within_floor_plus_one_interval() {
        let mut route = Liveness::answer_paced();
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(route.pong(nonce, stamp));
        let broken = Instant::now();
        tokio::time::advance(SERIAL_GAP).await;
        route.ping();
        let deadline = route.response_deadline().expect("issued probe deadline");
        assert_eq!(
            deadline - Instant::now(),
            Duration::from_millis(250) + Duration::from_nanos(1)
        );
        assert!(deadline - broken <= Duration::from_millis(277));
        tokio::time::advance(deadline - Instant::now()).await;
        assert!(route.expired());
    }

    #[tokio::test(start_paused = true)]
    async fn variation_uses_the_previous_smoothed_sample() {
        let mut route = Liveness::answer_paced();
        // Advance first so the nonce's nonzero sentinel adds no timestamp skew.
        tokio::time::advance(TICK).await;
        for rtt in [100, 200] {
            let (nonce, stamp) = route.ping();
            tokio::time::advance(Duration::from_millis(rtt)).await;
            assert!(route.pong(nonce, stamp));
        }
        assert_eq!(route.srtt, Some(Duration::from_micros(112_500)));
        assert_eq!(route.rttvar, Duration::from_micros(62_500));
        assert_eq!(route.budget, Duration::from_micros(412_500));
    }

    #[tokio::test(start_paused = true)]
    async fn jitter_allowance_decays_after_the_link_settles() {
        let mut route = Liveness::answer_paced();
        for rtt in [100, 200, 100, 200] {
            let (nonce, stamp) = route.ping();
            tokio::time::advance(Duration::from_millis(rtt)).await;
            assert!(route.pong(nonce, stamp));
        }
        // A single-sample estimator misses variance; smoothing preserves it.
        assert!(route.budget > Duration::from_millis(300));
        let jitter_budget = route.budget;
        for _ in 0..100 {
            let (nonce, stamp) = route.ping();
            tokio::time::advance(Duration::from_millis(1)).await;
            assert!(route.pong(nonce, stamp));
        }
        assert!(route.budget < jitter_budget);
        assert_eq!(route.budget, Duration::from_millis(250));
    }

    #[tokio::test(start_paused = true)]
    async fn pipelined_requests_do_not_renew_an_outstanding_deadline() {
        let mut route = Liveness::new();
        tokio::time::advance(TICK).await;
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(route.pong(nonce, stamp));
        tokio::time::advance(TICK.checked_sub(Duration::from_millis(1)).unwrap()).await;
        route.ping();
        let deadline = route.response_deadline().unwrap();
        tokio::time::advance(Duration::from_millis(150)).await;
        route.ping();
        assert_eq!(route.response_deadline(), Some(deadline));
        tokio::time::advance(
            (deadline - Instant::now())
                .checked_sub(Duration::from_nanos(1))
                .unwrap(),
        )
        .await;
        assert!(!route.expired(), "the silence boundary is inclusive");
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert!(route.expired(), "another request cannot renew readiness");
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
        tokio::time::advance(Duration::from_millis(1000)).await;
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
        tokio::time::advance(route.budget).await;
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
    async fn serial_probe_deadline_includes_only_one_gap_and_the_estimated_allowance() {
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
                assert!(deadline - broken <= route.budget + SERIAL_GAP + Duration::from_nanos(1));
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
