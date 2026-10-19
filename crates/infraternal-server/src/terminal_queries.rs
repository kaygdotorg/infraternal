//! Recognises bounded terminal queries and arbitrates one reply per output identity [307].
//! Output offsets deduplicate fan-out and replay; marked input never creates query state.
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(1);
const QUERIES: usize = 64;
const SESSIONS: usize = 4096;
const CONTROL: usize = 256;

#[derive(Default)]
pub(crate) struct Registry {
    sessions: HashMap<[u8; 16], Session>,
}
#[derive(Default)]
struct Session {
    host: Option<uuid::Uuid>,
    next: u64,
    scanner: Scanner,
    pending: VecDeque<Query>,
}
struct Query {
    seq: u64,
    started: Instant,
    request: Vec<u8>,
}
#[derive(Default)]
struct Scanner {
    state: u8,
    seq: u64,
    started: Option<Instant>,
    bytes: Vec<u8>,
    escaped: bool,
    overflow: bool,
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
        let Some(skip) = state
            .next
            .checked_sub(seq)
            .and_then(|v| usize::try_from(v).ok())
        else {
            // A missing output span cannot be interpreted as a continuation.
            state.scanner = Scanner::default();
            state.next = seq;
            return self.observe(session, host, seq, bytes, now);
        };
        if skip >= bytes.len() {
            return;
        }
        state
            .pending
            .retain(|query| now.duration_since(query.started) < WINDOW);
        let mut index = skip;
        while index < bytes.len() {
            // Plain output needs only an escape-byte search; the state machine
            // runs for control sequences rather than every byte in a flood.
            if state.scanner.state == 0 {
                let Some(escape) = bytes[index..].iter().position(|byte| *byte == 0x1b) else {
                    break;
                };
                index += escape;
            }
            if let Some(query) = state.scanner.feed(bytes[index], seq + index as u64, now) {
                if state.pending.len() == QUERIES {
                    state.pending.pop_front();
                }
                state.pending.push_back(query);
            }
            index += 1;
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
            let index = state.pending.iter().position(|query| query.seq == seq)?;
            let query = &state.pending[index];
            if now.duration_since(query.started) >= WINDOW || !matches_reply(&query.request, bytes)
            {
                return None;
            }
            let expires = query.started + WINDOW;
            state.pending.remove(index);
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

impl Scanner {
    fn feed(&mut self, byte: u8, seq: u64, now: Instant) -> Option<Query> {
        if self.state == 0 {
            if byte == 0x1b {
                self.state = 1;
                self.seq = seq;
                self.started = Some(now);
                self.overflow = false;
                self.bytes.clear();
                self.bytes.push(byte);
            }
            return None;
        }
        if byte == 0x18 || byte == 0x1a {
            self.state = 0;
            return None;
        }
        if self.state == 2 && byte == 0x1b {
            self.state = 1;
            self.seq = seq;
            self.started = Some(now);
            self.bytes.clear();
            self.bytes.push(byte);
            self.overflow = false;
            return None;
        }
        if self.state == 1 {
            self.state = match byte {
                b'[' => 2,
                b']' => 3,
                b'P' => 4,
                b'X' | b'^' | b'_' => 5,
                0x1b => {
                    self.seq = seq;
                    self.started = Some(now);
                    return None;
                }
                _ => 0,
            };
            self.bytes.push(byte);
            self.escaped = false;
            return None;
        }
        let end = if self.state == 2 {
            (0x40..=0x7e).contains(&byte)
        } else {
            (self.state == 3 && byte == 7) || (self.escaped && byte == b'\\')
        };
        if self.bytes.len() < CONTROL {
            self.bytes.push(byte);
        } else {
            self.overflow = true;
            if self.state == 2 {
                self.state = 0;
            }
        }
        self.escaped = byte == 0x1b;
        if !end {
            return None;
        }
        self.state = 0;
        if self.overflow || !is_query(&self.bytes) {
            return None;
        }
        Some(Query {
            seq: self.seq,
            started: self.started?,
            request: self.bytes.clone(),
        })
    }
}
fn is_query(q: &[u8]) -> bool {
    matches!(
        q,
        b"\x1b[c"
            | b"\x1b[0c"
            | b"\x1b[>c"
            | b"\x1b[>0c"
            | b"\x1b[=c"
            | b"\x1b[=0c"
            | b"\x1b[5n"
            | b"\x1b[6n"
            | b"\x1b[?6n"
            | b"\x1b[>q"
            | b"\x1b[>0q"
            | b"\x1b[?u"
    ) || (q.starts_with(b"\x1b[")
        && q.ends_with(b"$p")
        && digits(
            q[2..q.len() - 2]
                .strip_prefix(b"?")
                .unwrap_or(&q[2..q.len() - 2]),
        ))
        || ((q.starts_with(b"\x1b]10;")
            || q.starts_with(b"\x1b]11;")
            || q.starts_with(b"\x1b]12;")
            || q.starts_with(b"\x1b]4;"))
            && q.contains(&b'?'))
        || q.starts_with(b"\x1bP$q")
        || q.starts_with(b"\x1bP+q")
        || matches!(q, b"\x1b[14t" | b"\x1b[16t" | b"\x1b[18t" | b"\x1b[19t")
}
fn digits(s: &[u8]) -> bool {
    !s.is_empty() && s.len() <= 6 && s.iter().all(u8::is_ascii_digit)
}
fn parameters(s: &[u8]) -> bool {
    !s.is_empty() && s.split(|b| *b == b';').all(digits)
}
fn string_body(bytes: &[u8]) -> Option<&[u8]> {
    bytes
        .strip_suffix(b"\x1b\\")
        .or_else(|| bytes.strip_suffix(b"\x07"))
}
fn matches_reply(q: &[u8], r: &[u8]) -> bool {
    if r.is_empty() || r.len() > 1024 {
        return false;
    }
    if matches!(q, b"\x1b[6n" | b"\x1b[?6n") {
        let prefix: &[u8] = if q == b"\x1b[?6n" {
            b"\x1b[?"
        } else {
            b"\x1b["
        };
        return r
            .strip_prefix(prefix)
            .and_then(|b| b.strip_suffix(b"R"))
            .is_some_and(|b| b.split(|v| *v == b';').count() == 2 && parameters(b));
    }
    if q == b"\x1b[5n" {
        return r == b"\x1b[0n";
    }
    if matches!(q, b"\x1b[=c" | b"\x1b[=0c") {
        return r
            .strip_prefix(b"\x1bP!|")
            .and_then(|b| b.strip_suffix(b"\x1b\\"))
            .is_some_and(|b| b.len() == 8 && b.iter().all(u8::is_ascii_hexdigit));
    }
    if q.ends_with(b"c") {
        let prefix: &[u8] = if q.get(2) == Some(&b'>') {
            b"\x1b[>"
        } else {
            b"\x1b[?"
        };
        return r
            .strip_prefix(prefix)
            .and_then(|b| b.strip_suffix(b"c"))
            .is_some_and(parameters);
    }
    if q.ends_with(b"$p") {
        let mode = &q[2..q.len() - 2];
        return r
            .strip_prefix(b"\x1b[")
            .and_then(|b| b.strip_prefix(mode))
            .and_then(|b| b.strip_prefix(b";"))
            .is_some_and(|b| matches!(b, b"0$y" | b"1$y" | b"2$y" | b"3$y" | b"4$y"));
    }
    if q.ends_with(b"q") && q.starts_with(b"\x1b[") {
        return r
            .strip_prefix(b"\x1bP>|")
            .and_then(|b| b.strip_suffix(b"\x1b\\"))
            .is_some_and(|b| !b.is_empty() && b.iter().all(|v| (0x20..=0x7e).contains(v)));
    }
    if q == b"\x1b[?u" {
        return r
            .strip_prefix(b"\x1b[?")
            .and_then(|b| b.strip_suffix(b"u"))
            .is_some_and(digits);
    }
    if q.starts_with(b"\x1b]") {
        return matches_colors(q, r);
    }
    if q.ends_with(b"t") {
        let expected: &[u8] = match q {
            b"\x1b[14t" => b"4;",
            b"\x1b[16t" => b"6;",
            b"\x1b[18t" => b"8;",
            b"\x1b[19t" => b"9;",
            _ => return false,
        };
        return r
            .strip_prefix(b"\x1b[")
            .and_then(|b| b.strip_suffix(b"t"))
            .and_then(|b| b.strip_prefix(expected))
            .is_some_and(|b| b.split(|v| *v == b';').count() == 2 && parameters(b));
    }
    matches_dcs(q, r)
}

fn matches_dcs(q: &[u8], r: &[u8]) -> bool {
    if q.starts_with(b"\x1bP$q") {
        let Some(wanted) = q
            .strip_prefix(b"\x1bP$q")
            .and_then(|b| b.strip_suffix(b"\x1b\\"))
        else {
            return false;
        };
        return r
            .strip_prefix(b"\x1bP")
            .and_then(|b| b.strip_suffix(b"\x1b\\"))
            .is_some_and(|b| {
                b == b"0$r"
                    || (b.starts_with(b"1$r")
                        && b.len() > 3
                        && b.ends_with(wanted)
                        && b.iter().all(|v| (0x20..=0x7e).contains(v)))
            });
    }
    if q.starts_with(b"\x1bP+q") {
        let Some(wanted) = q
            .strip_prefix(b"\x1bP+q")
            .and_then(|b| b.strip_suffix(b"\x1b\\"))
        else {
            return false;
        };
        let mut remaining = r;
        for key in wanted.split(|b| *b == b';') {
            if key.is_empty() || !key.iter().all(u8::is_ascii_hexdigit) {
                return false;
            }
            let Some(body) = remaining.strip_prefix(b"\x1bP") else {
                return false;
            };
            let Some(end) = body.windows(2).position(|b| b == b"\x1b\\") else {
                return false;
            };
            let response = &body[..end];
            let valid = if let Some(value) = response.strip_prefix(b"0+r") {
                value == key
            } else {
                response
                    .strip_prefix(b"1+r")
                    .and_then(|b| b.strip_prefix(key))
                    .and_then(|b| b.strip_prefix(b"="))
                    .is_some_and(|b| b.len() % 2 == 0 && b.iter().all(u8::is_ascii_hexdigit))
            };
            if !valid {
                return false;
            }
            remaining = &body[end + 2..];
        }
        return remaining.is_empty();
    }
    false
}

/// OSC 4 may request several palette entries in one query. Validate each
/// response against its requested index before consuming the single identity.
fn number(bytes: &[u8]) -> Option<u16> {
    if !digits(bytes) {
        return None;
    }
    bytes.iter().try_fold(0_u16, |n, b| {
        n.checked_mul(10)?.checked_add(u16::from(b - b'0'))
    })
}
fn matches_colors(q: &[u8], mut replies: &[u8]) -> bool {
    let Some(request) = string_body(q).and_then(|b| b.strip_prefix(b"\x1b]")) else {
        return false;
    };
    let mut fields = request.split(|b| *b == b';');
    let Some(code) = fields.next().and_then(number) else {
        return false;
    };
    let mut dynamic = code;
    let mut count = 0;
    while let Some(field) = fields.next() {
        let (index, value, expected) = if code == 4 {
            let Some(index) = number(field) else {
                return false;
            };
            let Some(value) = fields.next() else {
                return false;
            };
            (Some(index), value, code)
        } else {
            let expected = dynamic;
            let Some(next) = dynamic.checked_add(1) else {
                return false;
            };
            dynamic = next;
            (None, field, expected)
        };
        // Set operations produce no response but may precede or follow queries.
        if value != b"?" {
            continue;
        }
        count += 1;
        let Some(body) = replies.strip_prefix(b"\x1b]") else {
            return false;
        };
        let Some(end) = body.iter().position(|b| *b == 7 || *b == 27) else {
            return false;
        };
        let terminator = if body[end] == 7 {
            1
        } else if body.get(end..end + 2) == Some(&b"\x1b\\"[..]) {
            2
        } else {
            return false;
        };
        let mut response = body[..end].split(|b| *b == b';');
        if response.next().and_then(number) != Some(expected)
            || (index.is_some() && response.next().and_then(number) != index)
        {
            return false;
        }
        let Some(rgb) = response.next().and_then(|b| b.strip_prefix(b"rgb:")) else {
            return false;
        };
        if response.next().is_some()
            || rgb.split(|b| *b == b'/').count() != 3
            || !rgb
                .split(|b| *b == b'/')
                .all(|b| !b.is_empty() && b.len() <= 4 && b.iter().all(u8::is_ascii_hexdigit))
        {
            return false;
        }
        replies = &body[end + terminator..];
    }
    count > 0 && replies.is_empty()
}

#[cfg(test)]
mod tests {
    //! Exercises fan-out, reconnect, late fragments, byte validation and bounded retained state.
    use super::*;
    #[test]
    fn only_one_reply_across_viewers_and_replay() {
        let mut state = Registry::default();
        let now = Instant::now();
        state.output([1; 16], 0, b"\x1b[6", now);
        state.output([1; 16], 0, b"\x1b[6", now);
        state.output([1; 16], 3, b"n", now);
        assert!(!state.accept([1; 16], 0, b"typing", now));
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
            state.output([1; 16], seq * 4, b"\x1b[6n", now);
        }
        assert_eq!(state.sessions[&[1; 16]].pending.len(), QUERIES);
    }
    #[test]
    fn response_grammars_refuse_trailing_typing_and_wrong_kind() {
        for (q, r) in [
            (&b"\x1b[c"[..], &b"\x1b[?1;2c"[..]),
            (b"\x1b[>c", b"\x1b[>1;2;3c"),
            (b"\x1b]11;?\x07", b"\x1b]11;rgb:ffff/ffff/ffff\x07"),
            (b"\x1b[?2004$p", b"\x1b[?2004;1$y"),
            (b"\x1b[?u", b"\x1b[?0u"),
        ] {
            assert!(matches_reply(q, r));
            assert!(!matches_reply(q, &[r, b"typed"].concat()));
            assert!(!matches_reply(q, b"\x1b[1;1R"));
        }
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
mod grammar_tests {
    //! A wrong response kind cannot consume an outstanding query.
    use super::*;
    #[test]
    fn binds_reply_kind_and_all_color_query_fields() {
        assert!(!matches_reply(b"\x1bP$qm\x1b\\", b"\x1bP1+r\x1b\\"));
        assert!(matches_reply(b"\x1bP$qm\x1b\\", b"\x1bP0$r\x1b\\"));
        assert!(matches_reply(
            b"\x1bP+q436f;5463\x1b\\",
            b"\x1bP1+r436f=323536\x1b\\\x1bP0+r5463\x1b\\"
        ));
        assert!(!matches_reply(b"\x1b[14t", b"\x1b[8;24;80t"));
        assert!(matches_reply(b"\x1b[14t", b"\x1b[4;600;800t"));
        assert!(matches_reply(
            b"\x1b]10;?;?\x07",
            b"\x1b]10;rgb:f/f/f\x07\x1b]11;rgb:0/0/0\x07"
        ));
        assert!(matches_reply(
            b"\x1b]4;1;rgb:ff/00/00;2;?\x07",
            b"\x1b]4;2;rgb:0/f/0\x07"
        ));
        assert!(matches_reply(
            b"\x1b]4;2;?;1;rgb:ff/00/00\x07",
            b"\x1b]4;2;rgb:0/f/0\x07"
        ));
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

/// Development-only sample-corpus entrypoint: chunk boundaries must not alter
/// identities, recognised queries or bounded scanner storage.
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
    let queries = |registry: &Registry| {
        registry
            .sessions
            .get(&session)
            .map(|state| {
                state
                    .pending
                    .iter()
                    .map(|query| (query.seq, query.request.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    assert_eq!(queries(&whole), queries(&split));
    for registry in [&whole, &split] {
        if let Some(state) = registry.sessions.get(&session) {
            assert!(state.pending.len() <= QUERIES);
            assert!(state.scanner.bytes.len() <= CONTROL);
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
