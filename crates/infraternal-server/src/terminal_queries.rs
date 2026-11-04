//! Arbitrates renderer replies by observed output positions without parsing terminal grammar [307].
//! Output ranges retain original deadlines across fan-out and replay; bounded claims prevent duplicates.
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

/// How long a terminal query stays answerable.
const WINDOW: Duration = Duration::from_secs(1);
/// Most query positions tracked per session.
pub(crate) const POSITIONS: usize = 64;
/// Most sessions tracked at once.
const SESSIONS: usize = 4096;

#[cfg(test)]
#[path = "terminal_queries_review_tests.rs"]
mod review_tests;

#[derive(Default)]
pub(crate) struct Registry {
    sessions: HashMap<[u8; 16], Session>,
}
#[derive(Default)]
struct Session {
    host: Option<uuid::Uuid>,
    next: u64,
    output: VecDeque<Output>,
    claimed: VecDeque<Claim>,
}
struct Output {
    start: u64,
    end: u64,
    started: Instant,
}
struct Claim {
    seq: u64,
    expires: Instant,
}
impl Registry {
    /// Session UUIDs are never reused. Ordered final events release their retained state.
    pub(crate) fn retire(&mut self, session: [u8; 16]) {
        self.sessions.remove(&session);
    }
    /// Each authoritative host census releases ended sessions even when no
    /// viewer was attached to receive their ordered terminal.exited notice.
    pub(crate) fn reconcile(&mut self, host: Option<uuid::Uuid>, live: &[[u8; 16]]) {
        self.sessions
            .retain(|id, state| state.host != host || live.contains(id));
    }
    #[cfg(any(test, feature = "parser-checks"))]
    fn output(&mut self, session: [u8; 16], seq: u64, bytes: &[u8], now: Instant) {
        self.observe(session, None, seq, bytes, now);
    }
    pub(crate) fn observe(
        &mut self,
        session: [u8; 16],
        host: Option<uuid::Uuid>,
        seq: u64,
        bytes: &[u8],
        now: Instant,
    ) {
        let Some(end) = seq.checked_add(bytes.len() as u64) else {
            return;
        };
        if !self.sessions.contains_key(&session) && self.sessions.len() == SESSIONS {
            return;
        }
        let state = self.sessions.entry(session).or_insert_with(|| Session {
            host,
            ..Session::default()
        });
        let start = seq.max(state.next);
        if start >= end {
            return;
        }
        // Replay/fan-out cannot renew timestamps. Each newly observed byte
        // belongs to exactly one range, irrespective of its terminal meaning.
        state
            .output
            .retain(|span| now.duration_since(span.started) < WINDOW);
        if let Some(last) = state
            .output
            .back_mut()
            .filter(|span| span.end == start && span.started == now)
        {
            last.end = end;
        } else {
            if state.output.len() == POSITIONS {
                state.output.pop_front();
            }
            state.output.push_back(Output {
                start,
                end,
                started: now,
            });
        }
        state.next = end;
    }
    pub(crate) fn claim(
        &mut self,
        session: [u8; 16],
        seq: u64,
        bytes: &[u8],
        now: Instant,
    ) -> Option<Instant> {
        let accepted = self.sessions.get_mut(&session).and_then(|state| {
            if bytes.is_empty() || bytes.len() > 1024 {
                return None;
            }
            let span = state
                .output
                .iter()
                .find(|span| span.start <= seq && seq < span.end)?;
            if now.duration_since(span.started) >= WINDOW {
                return None;
            }
            let expires = span.started + WINDOW;
            state.claimed.retain(|claim| now < claim.expires);
            // Never evict a live claim: it would let another viewer repeat an
            // accepted reply. A full table refuses new replies until expiry.
            if state.claimed.len() == POSITIONS
                || state.claimed.iter().any(|claim| claim.seq == seq)
            {
                return None;
            }
            state.claimed.push_back(Claim { seq, expires });
            Some(expires)
        });
        if accepted.is_none() {
            record_drop();
        }
        accepted
    }
    #[cfg(test)]
    fn accept(&mut self, session: [u8; 16], seq: u64, bytes: &[u8], now: Instant) -> bool {
        self.claim(session, seq, bytes, now).is_some()
    }
}
/// Sample cumulative, content-free diagnostics across admission and forwarding drops.
pub(crate) fn record_drop() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static DROPPED: AtomicU64 = AtomicU64::new(0);
    let dropped = DROPPED.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    if dropped.is_power_of_two() {
        tracing::debug!(dropped, "terminal query replies dropped");
    }
}

#[cfg(test)]
mod tests {
    //! Exercises fan-out, reconnect, late fragments, reply bounds and bounded retained state.
    use super::*;
    #[test]
    fn review_renderer_supported_query_forms_are_admitted() {
        for (request, response) in [
            (b"\x1bZ".as_slice(), b"\x1b[?62;22c".as_slice()),
            (b"\x1b[06n", b"\x1b[1;1R"),
            (b"\x1b[\x006n", b"\x1b[1;1R"),
        ] {
            let mut state = Registry::default();
            let now = Instant::now();
            state.output([1; 16], 0, request, now);
            // The shipping VT engine answers these equivalent control forms;
            // admission must agree with its grammar before deduplicating replies.
            assert!(state.accept([1; 16], 0, response, now));
        }
    }
    #[test]
    fn only_one_reply_across_viewers_and_replay() {
        let mut state = Registry::default();
        let now = Instant::now();
        state.output([1; 16], 0, b"\x1b[6", now);
        state.output([1; 16], 0, b"\x1b[6", now);
        state.output([1; 16], 3, b"n", now);
        assert!(state.accept([1; 16], 0, b"\x1b[1;1R", now));
        assert!(!state.accept([1; 16], 0, b"\x1b[1;1R", now));
        state.output([1; 16], 0, b"\x1b[6n", now);
        assert!(!state.accept([1; 16], 0, b"\x1b[1;1R", now));
    }
    #[test]
    fn deadline_includes_incomplete_query() {
        let mut state = Registry::default();
        let now = Instant::now();
        state.output([1; 16], 0, b"\x1b[6", now);
        state.output([1; 16], 3, b"n", now + WINDOW);
        assert!(!state.accept([1; 16], 0, b"\x1b[1;1R", now + WINDOW));
    }
    #[test]
    fn marked_flood_never_allocates_queries() {
        let mut state = Registry::default();
        let now = Instant::now();
        for seq in 0..100_000 {
            assert!(!state.accept([1; 16], seq, b"\x1b[1;1R", now));
        }
        assert!(state.sessions.is_empty());
        for seq in 0..1000 {
            state.output(
                [1; 16],
                seq * 4,
                b"\x1b[6n",
                now + Duration::from_nanos(seq),
            );
        }
        assert_eq!(state.sessions[&[1; 16]].output.len(), POSITIONS);
    }
    #[test]
    fn gaps_and_replay_never_authorize_unobserved_or_expired_positions() {
        let now = Instant::now();
        let mut state = Registry::default();
        state.output([1; 16], 0, b"ab", now);
        state.output([1; 16], 4, b"cd", now);
        assert!(!state.accept([1; 16], 2, b"renderer reply", now));
        assert!(!state.accept([1; 16], 3, b"renderer reply", now));
        state.output([1; 16], 0, b"ab", now + WINDOW);
        assert!(!state.accept([1; 16], 0, b"renderer reply", now + WINDOW));
        state.output([1; 16], 6, b"ef", now + WINDOW);
        assert!(state.accept([1; 16], 6, b"renderer reply", now + WINDOW));
        state.output([2; 16], u64::MAX, b"overflow", now);
        assert!(!state.accept([2; 16], u64::MAX, b"renderer reply", now));
    }
    #[test]
    fn every_observed_output_position_can_identify_a_renderer_answer() {
        let now = Instant::now();
        for request in [
            b"\x1bZ".as_slice(),
            b"\x1b[31m",
            b"\x1b(B",
            b"\x1b]0;title\x07",
            b"\x1bPanything\x1b\\",
            b"\x1b_ignored\x1b\\",
        ] {
            let mut state = Registry::default();
            state.output([1; 16], 0, request, now);
            assert!(state.accept([1; 16], 0, b"renderer answer", now));
        }
        let request = [b"\x1b[".as_slice(), &vec![0; 100_000], b"6n"].concat();
        let mut state = Registry::default();
        state.output([1; 16], 0, &request, now);
        assert!(state.accept([1; 16], 0, b"renderer answer", now));
        // No terminal text is retained, including text that contains no controls.
        state.output([2; 16], 0, b"ordinary output", now);
        assert!(state.accept([2; 16], 4, b"renderer answer", now));
    }
    #[test]
    fn style_controls_cannot_evict_queries_and_live_claims_never_reopen() {
        let now = Instant::now();
        let mut state = Registry::default();
        let output = [b"\x1b[6n".as_slice(), &b"\x1b[31m".repeat(100)].concat();
        state.output([1; 16], 0, &output, now);
        assert!(state.accept([1; 16], 0, b"renderer reply", now));
        for seq in 1..POSITIONS as u64 {
            assert!(state.accept([1; 16], seq, b"renderer reply", now));
        }
        assert!(!state.accept([1; 16], POSITIONS as u64, b"renderer reply", now));
        assert!(!state.accept([1; 16], 0, b"renderer reply", now));
        assert_eq!(state.sessions[&[1; 16]].claimed.len(), POSITIONS);
        state.output([1; 16], output.len() as u64, b"next output", now + WINDOW);
        assert!(state.accept(
            [1; 16],
            output.len() as u64,
            b"renderer reply",
            now + WINDOW
        ));
    }
    #[test]
    fn renderer_owns_reply_contents_but_size_and_identity_are_bounded() {
        let now = Instant::now();
        let mut state = Registry::default();
        state.output([1; 16], 0, b"\x1b[6n", now);
        assert!(!state.accept([1; 16], 4, b"future renderer answer", now));
        assert!(!state.accept([1; 16], 0, b"", now));
        assert!(!state.accept([1; 16], 0, &[0; 1025], now));
        assert!(state.accept([1; 16], 0, b"future renderer answer", now));
        assert!(!state.accept([1; 16], 0, b"future renderer answer", now));
    }
}

#[cfg(test)]
mod lifecycle_tests {
    //! Finished shells must not exhaust the bounded table over the server lifetime.
    use super::*;
    #[test]
    fn ended_sessions_release_query_slots() {
        let mut state = Registry::default();
        let now = Instant::now();
        state.output([255; 16], 0, b"\x1b[6n", now);
        for id in 0..5000_u64 {
            let mut session = [0; 16];
            session[..8].copy_from_slice(&id.to_le_bytes());
            state.output(session, 0, b"\x1b[6n", now);
            state.retire(session);
        }
        assert_eq!(state.sessions.len(), 1);
        assert!(state.accept([255; 16], 0, b"\x1b[1;1R", now));
        state.output([1; 16], 0, b"\x1b[6n", now);
        assert!(state.accept([1; 16], 0, b"\x1b[1;1R", now));
    }
}

#[cfg(test)]
mod overflow_tests {
    //! Oversized OSC titles retain their BEL terminator while their content is discarded.
    use super::*;
    #[test]
    fn oversized_osc_does_not_hide_the_next_query() {
        let mut state = Registry::default();
        let now = Instant::now();
        let mut output = b"\x1b]0;".to_vec();
        output.extend_from_slice(&[b'a'; 260]);
        output.push(7);
        let seq = output.len() as u64;
        output.extend_from_slice(b"\x1b[6n");
        state.output([1; 16], 0, &output, now);
        assert!(state.accept([1; 16], seq, b"\x1b[1;1R", now));
    }
}

/// Development-only sample-corpus entrypoint: same-time chunk boundaries must
/// preserve output coverage without retaining terminal bytes.
#[cfg(any(test, feature = "parser-checks"))]
#[doc(hidden)]
pub fn verify_terminal_query_sample(data: &[u8]) {
    let now = Instant::now();
    let session = [1; 16];
    let mut whole = Registry::default();
    whole.output(session, 0, data, now);
    let mut split = Registry::default();
    for (index, byte) in data.iter().enumerate() {
        split.output(session, index as u64, &[*byte], now);
    }
    let spans = |registry: &Registry| {
        registry
            .sessions
            .get(&session)
            .map(|state| {
                state
                    .output
                    .iter()
                    .map(|span| (span.start, span.end))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    assert_eq!(spans(&whole), spans(&split));
    for registry in [&whole, &split] {
        if let Some(state) = registry.sessions.get(&session) {
            assert!(state.output.len() <= POSITIONS);
            assert!(state.claimed.len() <= POSITIONS);
        }
    }
}
#[cfg(test)]
mod corpus_tests {
    //! Deterministic unexpected input checks supplement the continuously extensible sample harness.
    use super::*;
    #[test]
    fn output_chunking_preserves_bounded_query_state() {
        for query in [
            b"\x1b[6n".as_slice(),
            b"\x1b]4;1;?;2;rgb:f/0/0\x07",
            b"\x1bP$qm\x1b\\",
        ] {
            verify_terminal_query_sample(query);
        }
        let mut random = 17_u64;
        for length in 0..512 {
            let bytes: Vec<_> = (0..length)
                .map(|_| {
                    random = random
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1);
                    random.to_le_bytes()[7]
                })
                .collect();
            verify_terminal_query_sample(&bytes);
        }
    }
}

#[cfg(test)]
mod census_tests {
    //! Detached ended sessions release records; another host's live watermarks remain.
    use super::*;
    #[test]
    fn census_cleanup_is_host_scoped_and_preserves_detached_live_queries() {
        let mut state = Registry::default();
        let now = Instant::now();
        let host = Some(uuid::Uuid::from_bytes([2; 16]));
        state.observe([1; 16], None, 0, b"\x1b[6n", now);
        state.observe([2; 16], host, 0, b"\x1b[6n", now);
        state.reconcile(None, &[]);
        assert!(!state.accept([1; 16], 0, b"\x1b[1;1R", now));
        assert!(state.accept([2; 16], 0, b"\x1b[1;1R", now));
        state.observe([2; 16], host, 0, b"\x1b[6n", now);
        assert!(!state.accept([2; 16], 0, b"\x1b[1;1R", now));
        state.reconcile(host, &[]);
        assert!(state.sessions.is_empty());
    }
}
