//! Constant-space, pipelined Ping/Pong deadlines shared by browser and infraternal agent routes [D265, #199].

use std::{collections::VecDeque, time::Duration};
use tokio::time::Instant;

/// A short scheduling allowance keeps failure detection near one measured RTT.
/// Pipelining avoids waiting another RTT before discovering a newly broken direction.
pub(crate) const TICK: Duration = Duration::from_millis(25);

pub(crate) struct Liveness {
    origin: Instant,
    answered: Instant,
    sent: u64,
    acked: u64,
    budget: Duration,
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
            // Before the first sample, allow greeting/replay and an unknown link RTT.
            budget: Duration::from_secs(2),
        }
    }

    pub(crate) fn ping(&mut self) -> (u64, u64) {
        // Begin a response deadline only when the peer has something to answer.
        // SQL/writer scheduling before this probe is not evidence of peer loss.
        // Never move an outstanding deadline: pipelining cannot mask silence.
        if self.sent == self.acked {
            self.answered = Instant::now();
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

    pub(crate) fn pong(&mut self, nonce: u64, sent_us: u64) {
        // Only a new reply to this route's issued probes renews its lease.
        // Delayed/duplicate replies, ordinary traffic and another stream cannot do so.
        if nonce != sent_us
            || nonce <= self.acked
            || !self.issued.contains(&nonce)
            || self.expired()
        {
            return;
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
        self.budget = (rtt + TICK).max(TICK * 2);
    }

    pub(crate) fn expired(&self) -> bool {
        self.sent > self.acked && self.answered.elapsed() > self.budget
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
