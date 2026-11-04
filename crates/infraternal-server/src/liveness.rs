//! Bounded correlated Ping/Pong deadlines for pipelined and answer-paced routes [D265, #199].
//!
//! Host routes follow the measured path [D300]: a reply held behind one lost
//! packet on the ordered stream is retransmitted after about one more round
//! trip, so their allowance spans two smoothed round trips. The primary host
//! link only reports doubt on its first miss and retires on the second
//! consecutive one. Browser routes likewise doubt one missed allowance; terminal
//! routes still rebind on the first miss. Hidden viewers park their probe lease.
//! Browser routes carry these probes as native WebSocket Ping control frames,
//! which the browser answers without running page JavaScript [#317].

use std::{collections::VecDeque, time::Duration};
use tokio::time::Instant;

/// Probe cadence is independent of response allowance: idle work stays unchanged.
pub(crate) const TICK: Duration = Duration::from_millis(25);
// One millisecond lets a ready client tick precede fallback.
const SERIAL_GAP: Duration = Duration::from_millis(26);
// The floor covers a 150ms local stall plus reply dispatch, without waiting for
// transport timeouts. Slow routes instead follow their measured RTT and jitter.
const RESPONSE_FLOOR: Duration = Duration::from_millis(250);
// Covers the peer's acknowledgement delay on top of one retransmission [D300].
const HOST_MARGIN: Duration = Duration::from_millis(75);
// Bounds dead-host detection on slow or jittery paths; also the startup grace.
const RESPONSE_CEILING: Duration = Duration::from_secs(2);

/// Which reply allowance and miss policy a route follows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Allowance {
    /// Browser routes: two round trips and first-miss doubt [D300, #244].
    Browser,
    /// Host terminal routes: two round trips; the first miss ends the lease.
    Terminal,
    /// The primary host link: two round trips; the first miss only raises doubt.
    /// `pinned` is set when a doubt recovered while the allowance sat at its
    /// ceiling: the path needs more than the ceiling allows, so further early
    /// misses on it are its normal delay, not doubt. Only retirement reports it,
    /// until a reply brings the allowance back below the ceiling [#234].
    HostLink { doubt: bool, pinned: bool },
}

pub(crate) struct Liveness {
    origin: Instant,
    answered: Instant,
    sent: u64,
    acked: u64,
    budget: Duration,
    srtt: Option<Duration>,
    rttvar: Duration,
    answer_paced: bool,
    allowance: Allowance,
    issued: VecDeque<u64>,
    suspended: bool,
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
            suspended: false,
            answer_paced: false,
            allowance: Allowance::Terminal,
            srtt: None,
            rttvar: Duration::ZERO,
            // Before the first sample, allow greeting/replay and an unknown link RTT.
            budget: RESPONSE_CEILING,
        }
    }

    /// Browser routes pace idle requests from their correlated answers.
    pub(crate) fn answer_paced() -> Self {
        Self {
            answer_paced: true,
            allowance: Allowance::Browser,
            ..Self::new()
        }
    }

    /// The primary host link doubts before it retires [D300].
    pub(crate) fn host_link() -> Self {
        Self {
            allowance: Allowance::HostLink {
                doubt: false,
                pinned: false,
            },
            ..Self::new()
        }
    }

    /// A hidden viewer may stop executing altogether. Keep its socket and writer
    /// ownership, but discard old correlations so visibility starts a fresh lease.
    pub(crate) fn set_suspended(&mut self, suspended: bool) {
        if self.suspended != suspended {
            self.restart();
            self.suspended = suspended;
        }
    }

    /// Restart monitoring on the same transport without reusing a prior probe ID.
    /// Clearing issued requests disarms the lease; the clock and counter survive.
    pub(crate) fn restart(&mut self) {
        self.answered = Instant::now();
        self.acked = 0;
        self.budget = RESPONSE_CEILING;
        self.srtt = None;
        self.rttvar = Duration::ZERO;
        self.issued.clear();
    }

    /// Startup pipelines samples; a sampled route waits for its actual answer.
    pub(crate) fn next_probe_due(&self, fast: bool) -> Option<Instant> {
        if self.suspended {
            return None;
        }
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
        !self.suspended
            && self.acked != 0
            && self.issued.is_empty()
            && self.origin.elapsed() >= Duration::from_micros(self.sent) + TICK
    }

    /// Wake independently of the next probe; preserve the strict expiry boundary.
    pub(crate) fn response_deadline(&self) -> Option<Instant> {
        let allowance = if self.allowance == Allowance::Browser && self.acked != 0 {
            self.budget * 2
        } else {
            self.budget
        };
        (!self.suspended && !self.issued.is_empty())
            .then(|| self.answered + allowance + Duration::from_nanos(1))
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
        // Two ceiling allowances admit at most 160 ticks; bound retained
        // correlation regardless. Eviction cannot renew readiness.
        if self.issued.len() == 128 {
            self.issued.pop_front();
        }
        self.issued.push_back(self.sent);
        (self.sent, self.sent)
    }

    pub(crate) fn pong(&mut self, nonce: u64, sent_us: u64) -> bool {
        // Only a new reply to this route's issued probes renews its lease.
        // Delayed/duplicate replies, ordinary traffic and another stream cannot do so.
        if self.suspended
            || nonce != sent_us
            || nonce <= self.acked
            || !self.issued.contains(&nonce)
            || self.retired()
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
        self.budget =
            (srtt * 2 + self.rttvar * 4 + HOST_MARGIN).clamp(RESPONSE_FLOOR, RESPONSE_CEILING);
        if let Allowance::HostLink { doubt, pinned } = &mut self.allowance {
            // Below the ceiling the estimator widens on its own and a late reply
            // cannot recur at the same delay; at the ceiling it would, forever.
            *pinned = self.budget == RESPONSE_CEILING && (*doubt || *pinned);
            *doubt = false;
        }
        true
    }

    pub(crate) fn expired(&self) -> bool {
        !self.suspended && !self.issued.is_empty() && self.answered.elapsed() > self.budget
    }

    /// True once per episode when a proven host link misses its first reply.
    /// An unproven link has no health to doubt; it retires at the startup grace.
    pub(crate) fn doubt_started(&mut self) -> bool {
        let expired = self.acked != 0 && self.expired();
        match &mut self.allowance {
            Allowance::HostLink { doubt, pinned } if expired && !*doubt && !*pinned => {
                *doubt = true;
                true
            }
            _ => false,
        }
    }

    pub(crate) fn doubtful(&self) -> bool {
        matches!(self.allowance, Allowance::HostLink { doubt: true, .. })
    }

    /// The lease is over: a host link after its second consecutive allowance,
    /// browser routes also after two, terminal routes after one. No reply can renew it afterwards.
    pub(crate) fn retired(&self) -> bool {
        if matches!(
            self.allowance,
            Allowance::HostLink { .. } | Allowance::Browser
        ) && self.acked != 0
        {
            !self.suspended && !self.issued.is_empty() && self.answered.elapsed() > self.budget * 2
        } else {
            self.expired()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn browser_doubts_one_mobile_delay_and_retires_only_after_two_allowances() {
        let mut route = Liveness::answer_paced();
        for _ in 0..100 {
            let probe = route.ping();
            tokio::time::advance(Duration::from_millis(150)).await;
            assert!(route.pong(probe.0, probe.1));
        }
        let probe = route.ping();
        tokio::time::advance(Duration::from_millis(600)).await;
        assert!(route.expired(), "first allowance is doubt");
        assert!(!route.retired());
        assert!(route.pong(probe.0, probe.1));
        route.ping();
        let retirement = route.response_deadline().unwrap();
        tokio::time::advance(retirement - Instant::now()).await;
        assert!(route.retired(), "silence is still bounded while visible");
    }

    #[tokio::test(start_paused = true)]
    async fn suspended_browser_keeps_its_lease_and_relearns_the_mobile_path() {
        let mut route = Liveness::answer_paced();
        let old = route.ping();
        tokio::time::advance(Duration::from_millis(150)).await;
        assert!(route.pong(old.0, old.1));
        let queued = route.ping();
        route.set_suspended(true);
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(!route.retired());
        assert!(route.response_deadline().is_none());
        assert!(route.next_probe_due(false).is_none());
        route.set_suspended(false);
        assert!(!route.pong(queued.0, queued.1));
        let fresh = route.ping();
        tokio::time::advance(Duration::from_millis(600)).await;
        assert!(route.pong(fresh.0, fresh.1));
        assert!(!route.retired());
    }

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
    async fn quiet_dead_browser_retires_within_two_floors_plus_one_interval() {
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
            Duration::from_millis(500) + Duration::from_nanos(1)
        );
        assert!(deadline - broken <= Duration::from_millis(527));
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
        assert_eq!(route.budget, Duration::from_millis(550));
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
                assert!(
                    deadline - broken <= route.budget * 2 + SERIAL_GAP + Duration::from_nanos(1)
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

    /// Settles a route on one constant round trip.
    async fn settle(route: &mut Liveness, rtt: Duration, samples: usize) {
        for _ in 0..samples {
            let (nonce, stamp) = route.ping();
            tokio::time::advance(rtt).await;
            assert!(route.pong(nonce, stamp));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn host_and_browser_allowance_cover_one_loss_recovery() {
        let mut host = Liveness::new();
        let mut browser = Liveness::answer_paced();
        tokio::time::advance(TICK).await;
        for rtt in [100, 200] {
            let (host_nonce, host_stamp) = host.ping();
            let (browser_nonce, browser_stamp) = browser.ping();
            tokio::time::advance(Duration::from_millis(rtt)).await;
            assert!(host.pong(host_nonce, host_stamp));
            assert!(browser.pong(browser_nonce, browser_stamp));
        }
        // srtt 112.5 ms, rttvar 62.5 ms: 2 x 112.5 + 4 x 62.5 + 75 = 550 ms [D300].
        assert_eq!(host.budget, Duration::from_millis(550));
        assert_eq!(browser.budget, Duration::from_millis(550));
    }

    #[tokio::test(start_paused = true)]
    async fn host_allowance_has_a_floor_a_settled_long_haul_value_and_a_ceiling() {
        let mut lan = Liveness::new();
        settle(&mut lan, Duration::from_millis(1), 50).await;
        assert_eq!(
            lan.budget,
            Duration::from_millis(250),
            "LAN keeps the floor"
        );
        let mut long_haul = Liveness::new();
        settle(&mut long_haul, Duration::from_millis(150), 200).await;
        // One retransmission of a lost ordered reply costs about one more round trip.
        assert!(long_haul.budget >= Duration::from_millis(375));
        assert!(long_haul.budget < Duration::from_millis(380));
        let mut far = Liveness::new();
        settle(&mut far, Duration::from_millis(1500), 20).await;
        assert_eq!(
            far.budget,
            Duration::from_secs(2),
            "dead-host detection stays bounded"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn host_link_doubts_on_the_first_miss_and_retires_on_the_second() {
        let mut route = Liveness::host_link();
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(route.pong(nonce, stamp));
        tokio::time::advance(TICK).await;
        route.ping();
        let budget = route.budget;
        tokio::time::advance(budget).await;
        assert!(
            !route.doubt_started(),
            "the allowance boundary is inclusive"
        );
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert!(route.doubt_started(), "the first miss marks doubt");
        assert!(!route.doubt_started(), "doubt is reported once per episode");
        assert!(route.doubtful());
        assert!(!route.retired(), "one miss never retires the link");
        // Probes pipelined during doubt cannot renew the outstanding deadline.
        route.ping();
        tokio::time::advance(budget.checked_sub(Duration::from_nanos(1)).unwrap()).await;
        assert!(!route.retired());
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert!(route.retired(), "the second consecutive miss retires");
        let (nonce, stamp) = route.ping();
        assert!(
            !route.pong(nonce, stamp),
            "a retired lease cannot be revived"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_reply_during_doubt_clears_it_and_renews_the_route() {
        let mut route = Liveness::host_link();
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(route.pong(nonce, stamp));
        tokio::time::advance(TICK).await;
        let (nonce, stamp) = route.ping();
        tokio::time::advance(route.budget + Duration::from_millis(100)).await;
        assert!(route.doubt_started());
        // The reply held behind one lost packet arrives inside the second allowance.
        assert!(route.pong(nonce, stamp));
        assert!(!route.doubtful());
        assert!(!route.expired());
        assert!(!route.retired());
        assert!(route.response_deadline().is_none());
    }

    /// One late reply below the ceiling keeps doubt armed: a 150 ms path
    /// that recovered from one loss still reports the next miss early [#234].
    #[tokio::test(start_paused = true)]
    async fn a_recovered_doubt_below_the_ceiling_keeps_early_notice() {
        let mut route = Liveness::host_link();
        settle(&mut route, Duration::from_millis(150), 100).await;
        let budget = route.budget;
        let (nonce, stamp) = route.ping();
        tokio::time::advance(budget + Duration::from_millis(1)).await;
        assert!(route.doubt_started());
        assert!(route.pong(nonce, stamp));
        settle(&mut route, Duration::from_millis(150), 100).await;
        route.ping();
        tokio::time::advance(route.budget + Duration::from_millis(1)).await;
        assert!(
            route.doubt_started(),
            "the next miss is reported early again"
        );
    }

    /// At the ceiling a recovered doubt pins the link; draining the path
    /// below the ceiling restores early doubt [#234].
    #[tokio::test(start_paused = true)]
    async fn a_doubt_recovered_at_the_ceiling_pins_until_the_path_drains() {
        let mut route = Liveness::host_link();
        settle(&mut route, Duration::from_millis(1500), 20).await;
        assert_eq!(route.budget, RESPONSE_CEILING);
        let (nonce, stamp) = route.ping();
        tokio::time::advance(RESPONSE_CEILING + Duration::from_millis(1)).await;
        assert!(route.doubt_started());
        tokio::time::advance(Duration::from_millis(500)).await;
        assert!(route.pong(nonce, stamp));
        let (nonce, stamp) = route.ping();
        tokio::time::advance(RESPONSE_CEILING + Duration::from_millis(1)).await;
        assert!(
            !route.doubt_started(),
            "a pinned link reports only retirement"
        );
        assert!(route.pong(nonce, stamp));
        settle(&mut route, Duration::from_millis(100), 40).await;
        assert!(route.budget < RESPONSE_CEILING);
        route.ping();
        tokio::time::advance(route.budget + Duration::from_millis(1)).await;
        assert!(route.doubt_started(), "a drained path doubts early again");
        // A pinned dead host still retires after two ceilings.
        let mut pinned = Liveness::host_link();
        settle(&mut pinned, Duration::from_millis(1500), 20).await;
        let (nonce, stamp) = pinned.ping();
        tokio::time::advance(RESPONSE_CEILING + Duration::from_millis(1)).await;
        assert!(pinned.doubt_started());
        tokio::time::advance(Duration::from_millis(500)).await;
        assert!(pinned.pong(nonce, stamp));
        pinned.ping();
        tokio::time::advance(RESPONSE_CEILING * 2 + Duration::from_millis(1)).await;
        assert!(!pinned.doubt_started());
        assert!(pinned.retired());
    }

    #[tokio::test(start_paused = true)]
    async fn an_unanswered_host_link_retires_at_the_startup_grace_without_doubt() {
        let mut route = Liveness::host_link();
        route.ping();
        tokio::time::advance(Duration::from_secs(2) + Duration::from_nanos(1)).await;
        assert!(
            !route.doubt_started(),
            "an unproven link has no health to doubt"
        );
        assert!(route.retired());
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_routes_still_end_their_lease_on_the_first_miss() {
        let mut route = Liveness::new();
        let (nonce, stamp) = route.ping();
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(route.pong(nonce, stamp));
        tokio::time::advance(TICK).await;
        let (nonce, stamp) = route.ping();
        tokio::time::advance(route.budget + Duration::from_nanos(1)).await;
        assert!(!route.doubt_started());
        assert!(route.retired());
        assert!(!route.pong(nonce, stamp));
    }
}
