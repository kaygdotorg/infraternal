//! Classifies and rate-limits terminal stream close records without touching stream payloads.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::Notify,
    time::{Instant, sleep_until},
};

const CLOSE_WINDOW: Duration = Duration::from_secs(60);
const CLOSE_WINDOW_SECONDS: u64 = 60;
// A closed-session storm can outlive its sockets; retain only one minute of bounded per-session state.
const MAX_TRACKED_SESSIONS: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CloseReason {
    pub(crate) category: &'static str,
    pub(crate) kind: &'static str,
    pub(crate) client_text: &'static str,
}

impl CloseReason {
    const fn new(category: &'static str, kind: &'static str, client_text: &'static str) -> Self {
        Self {
            category,
            kind,
            client_text,
        }
    }
}

pub(crate) const CLIENT_WENT_AWAY: CloseReason = CloseReason::new(
    "client_went_away",
    "websocket_closed",
    "browser closed the connection",
);
pub(crate) const AGENT_STREAM_ENDED: CloseReason = CloseReason::new(
    "agent_stream_ended",
    "terminal_stream_closed",
    "the infraternal agent ended the terminal stream",
);
pub(crate) const AGENT_CONNECTION_DROPPED: CloseReason = CloseReason::new(
    "agent_connection_dropped",
    "server_link_lost",
    "the infraternal agent lost its connection to the server",
);
pub(crate) const AGENT_CONNECTION_REFUSED: CloseReason = CloseReason::new(
    "agent_connection_refused",
    "terminal_attach_unavailable",
    "the host could not accept the terminal attachment",
);
pub(crate) const INPUT_QUEUE_FULL: CloseReason = CloseReason::new(
    "flow_control_refusal",
    "input_queue_full",
    "terminal input exceeded the flow-control limit",
);
pub(crate) const READER_FELL_BEHIND: CloseReason = CloseReason::new(
    "flow_control_refusal",
    "reader_fell_behind",
    "the terminal reader fell behind and is reconnecting",
);
pub(crate) const TERMINAL_ROUTE_IDLE: CloseReason = CloseReason::new(
    "idle",
    "terminal_route_unresponsive",
    "the terminal on the host stopped responding",
);
pub(crate) const CREDIT_REFUSED: CloseReason = CloseReason::new(
    "flow_control_refusal",
    "credit_exceeded",
    "terminal output credit exceeded its limit",
);
pub(crate) const REPLY_QUEUE_FULL: CloseReason = CloseReason::new(
    "flow_control_refusal",
    "control_reply_queue_full",
    "the server could not keep up with connection replies",
);
pub(crate) const FRAME_TOO_LARGE: CloseReason = CloseReason::new(
    "size_limit",
    "frame_too_large",
    "a terminal frame exceeded the size limit",
);
pub(crate) const PROTOCOL_ERROR: CloseReason = CloseReason::new(
    "protocol_error",
    "invalid_frame",
    "the terminal stream sent an invalid protocol frame",
);
pub(crate) const ATTACH_REFUSED: CloseReason = CloseReason::new(
    "auth_resume_refusal",
    "terminal_attach_refused",
    "the server refused the terminal attachment",
);
pub(crate) const RESUME_REFUSED: CloseReason = CloseReason::new(
    "auth_resume_refusal",
    "connection_resume_refused",
    "the server refused to resume the connection",
);
pub(crate) const IDLE_TIMEOUT: CloseReason = CloseReason::new(
    "idle",
    "liveness_timeout",
    "the server stopped receiving connection replies",
);
pub(crate) const SERVER_WRITE_FAILED: CloseReason = CloseReason::new(
    "server_transport_error",
    "websocket_write_failed",
    "the server could not write to the connection",
);
pub(crate) const SERVER_PROCESSING_FAILED: CloseReason = CloseReason::new(
    "server_processing_error",
    "terminal_stream_processing_failed",
    "the server could not continue the terminal stream",
);
const MIXED_REASON: CloseReason = CloseReason::new(
    "multiple",
    "multiple_close_reasons",
    "the stream closed repeatedly for different reasons",
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CloseWho {
    Browser,
    Server,
    InfraternalAgent,
    Multiple,
}

impl CloseWho {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Server => "server",
            Self::InfraternalAgent => "infraternal_agent",
            Self::Multiple => "multiple",
        }
    }
}

/// The log contains only identifiers, close metadata, and existing stream cursors/credit.
#[derive(Clone, Debug)]
pub(crate) struct CloseRecord {
    pub(crate) who: CloseWho,
    pub(crate) reason: CloseReason,
    pub(crate) host_id: Option<uuid::Uuid>,
    pub(crate) session_id: [u8; 16],
    pub(crate) browser_stream_id: u32,
    pub(crate) agent_stream_id: u32,
    pub(crate) out_seq: u64,
    pub(crate) input_acked: u64,
    pub(crate) input_sent: u64,
    pub(crate) output_credit_bytes: u64,
    pub(crate) agent_close_code: Option<u16>,
    pub(crate) agent_close_reason: Option<&'static str>,
    pub(crate) browser_stream_close_code: Option<u16>,
    pub(crate) browser_stream_close_reason: Option<&'static str>,
    pub(crate) websocket_code: Option<u16>,
    pub(crate) websocket_reason: Option<&'static str>,
}

impl CloseRecord {
    pub(crate) fn new(
        who: CloseWho,
        reason: CloseReason,
        host_id: Option<uuid::Uuid>,
        session_id: [u8; 16],
        browser_stream_id: u32,
    ) -> Self {
        Self {
            who,
            reason,
            host_id,
            session_id,
            browser_stream_id,
            agent_stream_id: 0,
            out_seq: 0,
            input_acked: 0,
            input_sent: 0,
            output_credit_bytes: 0,
            agent_close_code: None,
            agent_close_reason: None,
            browser_stream_close_code: None,
            browser_stream_close_reason: None,
            websocket_code: None,
            websocket_reason: None,
        }
    }
}

struct Window {
    started: Instant,
    closes: u64,
    last: CloseRecord,
}

#[derive(Default)]
struct State {
    sessions: HashMap<[u8; 16], Window>,
    last_sweep: Option<Instant>,
}

struct Inner {
    state: Mutex<State>,
    changed: Arc<Notify>,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let worker = self
            .worker
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(worker) = worker {
            worker.abort();
        }
    }
}

/// Shared close logger; its timer parks unless a session has a close window to summarize.
#[derive(Clone)]
pub(crate) struct StreamCloseLog(Arc<Inner>);

impl StreamCloseLog {
    pub(crate) fn new() -> Self {
        let changed = Arc::new(Notify::new());
        let inner = Arc::new(Inner {
            state: Mutex::new(State::default()),
            changed: changed.clone(),
            worker: Mutex::new(None),
        });
        let worker = tokio::spawn(run(Arc::downgrade(&inner), changed));
        *inner
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(worker);
        Self(inner)
    }

    /// Record the first close immediately and collapse later closes for the same session.
    pub(crate) fn record(&self, record: &CloseRecord) {
        self.record_at(record, Instant::now());
    }

    fn record_at(&self, record: &CloseRecord, now: Instant) {
        let key = record.session_id;
        let mut summary = None;
        let mut summaries = Vec::new();
        {
            let mut state = self
                .0
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(window) = state.sessions.get_mut(&key) {
                if now < window.started + CLOSE_WINDOW {
                    window.closes = window.closes.saturating_add(1);
                    if window.last.reason != record.reason {
                        window.last.reason = MIXED_REASON;
                    }
                    if window.last.who != record.who {
                        window.last.who = CloseWho::Multiple;
                    }
                    window.last.host_id = record.host_id;
                    window.last.browser_stream_id = record.browser_stream_id;
                    window.last.agent_stream_id = record.agent_stream_id;
                    window.last.out_seq = record.out_seq;
                    window.last.input_acked = record.input_acked;
                    window.last.input_sent = record.input_sent;
                    window.last.output_credit_bytes = record.output_credit_bytes;
                    window.last.agent_close_code = record.agent_close_code;
                    window.last.agent_close_reason = record.agent_close_reason;
                    window.last.browser_stream_close_code = record.browser_stream_close_code;
                    window.last.browser_stream_close_reason = record.browser_stream_close_reason;
                    window.last.websocket_code = record.websocket_code;
                    window.last.websocket_reason = record.websocket_reason;
                    return;
                }
                summary = state.sessions.remove(&key);
            } else if state.sessions.len() >= MAX_TRACKED_SESSIONS {
                // Full map: drop windows that already ended, at most once a second so a
                // flood of distinct sessions pays an amortised, not a per-close, scan.
                // If every window is still live, this close is logged but not tracked, so
                // memory stays bounded and each distinct session still gets its first line.
                if state
                    .last_sweep
                    .is_none_or(|at| now.duration_since(at) >= Duration::from_secs(1))
                {
                    state.last_sweep = Some(now);
                    let expired = state
                        .sessions
                        .iter()
                        .filter(|(_, window)| now >= window.started + CLOSE_WINDOW)
                        .map(|(session, _)| *session)
                        .collect::<Vec<_>>();
                    for session in expired {
                        if let Some(window) = state.sessions.remove(&session) {
                            summaries.push(window);
                        }
                    }
                }
                if state.sessions.len() >= MAX_TRACKED_SESSIONS {
                    drop(state);
                    for window in &summaries {
                        log_summary(window);
                    }
                    log_close(record);
                    return;
                }
            }
            state.sessions.insert(
                key,
                Window {
                    started: now,
                    closes: 1,
                    last: record.clone(),
                },
            );
        }
        if let Some(window) = summary {
            log_summary(&window);
        }
        for window in &summaries {
            log_summary(window);
        }
        log_close(record);
        self.0.changed.notify_one();
    }

    fn flush_expired(&self, now: Instant) {
        let expired = {
            let mut state = self
                .0
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let keys = state
                .sessions
                .iter()
                .filter(|(_, window)| now >= window.started + CLOSE_WINDOW)
                .map(|(session, _)| *session)
                .collect::<Vec<_>>();
            keys.into_iter()
                .filter_map(|session| state.sessions.remove(&session))
                .collect::<Vec<_>>()
        };
        for window in expired {
            log_summary(&window);
        }
    }
}

async fn run(inner: std::sync::Weak<Inner>, changed: Arc<Notify>) {
    loop {
        let Some(shared) = inner.upgrade() else {
            return;
        };
        let next = shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sessions
            .values()
            .map(|window| window.started + CLOSE_WINDOW)
            .min();
        drop(shared);
        if let Some(deadline) = next {
            tokio::select! {
                () = sleep_until(deadline) => {
                    let Some(shared) = inner.upgrade() else {
                        return;
                    };
                    let logger = StreamCloseLog(shared);
                    logger.flush_expired(Instant::now());
                }
                () = changed.notified() => {}
            }
        } else {
            changed.notified().await;
        }
    }
}

/// One call site for both lines keeps the binary small: `closes` is 1 for the
/// first close and the repeat count for a window summary. The stream close pair is
/// the peer's close of a browser stream or of the control stream, whichever ended.
fn emit(record: &CloseRecord, closes: u64) {
    let session_id = uuid::Uuid::from_bytes(record.session_id);
    let host_id = record
        .host_id
        .map_or_else(|| "local".to_owned(), |id| id.to_string());
    let summary = closes > 1;
    let message = if summary {
        format!(
            "closed {closes} times in {CLOSE_WINDOW_SECONDS} s, reason {}",
            record.reason.kind
        )
    } else {
        "terminal stream closed".to_owned()
    };
    tracing::info!(
        target: "infraternal::terminal_stream",
        event = if summary { "terminal_stream_close_summary" } else { "terminal_stream_closed" },
        message = %message,
        who = record.who.as_str(),
        reason_category = record.reason.category,
        reason = record.reason.kind,
        closed_count = closes,
        host_id = %host_id,
        session_id = %session_id,
        browser_stream_id = record.browser_stream_id,
        agent_stream_id = record.agent_stream_id,
        out_seq = record.out_seq,
        input_acked = record.input_acked,
        input_sent = record.input_sent,
        output_credit_bytes = record.output_credit_bytes,
        agent_close_code = record.agent_close_code.unwrap_or_default(),
        agent_close_reason = record.agent_close_reason.unwrap_or_default(),
        stream_close_code = record.browser_stream_close_code.unwrap_or_default(),
        stream_close_reason = record.browser_stream_close_reason.unwrap_or_default(),
        websocket_code = record.websocket_code.unwrap_or_default(),
        websocket_reason = record.websocket_reason.unwrap_or_default(),
    );
}

fn log_close(record: &CloseRecord) {
    emit(record, 1);
}

fn log_summary(window: &Window) {
    if window.closes >= 2 {
        emit(&window.last, window.closes);
    }
}

/// Browser close reasons are untrusted text; only known local strings can enter server logs.
pub(crate) fn safe_websocket_reason(reason: &str) -> &'static str {
    match reason {
        "" => "",
        "connection unresponsive" => "connection unresponsive",
        "tracer connection rotation" => "tracer connection rotation",
        "tracer resume probe" => "tracer resume probe",
        "window closed" => "window closed",
        "connection closed" => "connection closed",
        "connection ended" => "connection ended",
        _ => "other",
    }
}

/// Agent close text is untrusted protocol input; only known static reasons enter logs or UI.
pub(crate) fn safe_agent_close_reason(reason: &str) -> &'static str {
    match reason {
        "" => "",
        "window closed" => "window closed",
        "connection closed" => "connection closed",
        "connection ended" => "connection ended",
        "tracer connection rotation" => "tracer connection rotation",
        "tracer resume probe" => "tracer resume probe",
        "session ended" => "session ended",
        "detached" => "detached",
        "attachment ended" => "attachment ended",
        "reader fell behind; reattach" => "reader fell behind; reattach",
        "connection unresponsive" => "connection unresponsive",
        "terminal route unresponsive" => "terminal route unresponsive",
        "standby writer unavailable" => "standby writer unavailable",
        "input queue full" => "input queue full",
        "remote stream unavailable" => "remote stream unavailable",
        "terminal shim disconnected" => "terminal shim disconnected",
        "terminal command queue full; reattach and replay unacknowledged input" => {
            "terminal command queue full; reattach and replay unacknowledged input"
        }
        "shim lacks restart-safe input capability" => "shim lacks restart-safe input capability",
        "shim refused terminal request" => "shim refused terminal request",
        _ => "other",
    }
}

/// A missing agent stream is a link drop; other terminal closes end just that stream.
pub(crate) fn classify_terminal_close(reason: &'static str) -> CloseReason {
    match reason {
        "remote stream unavailable" => AGENT_CONNECTION_DROPPED,
        "terminal command queue full; reattach and replay unacknowledged input"
        | "input queue full" => INPUT_QUEUE_FULL,
        "reader fell behind; reattach" => READER_FELL_BEHIND,
        "terminal route unresponsive" | "connection unresponsive" => TERMINAL_ROUTE_IDLE,
        "standby writer unavailable" => AGENT_CONNECTION_REFUSED,
        _ => AGENT_STREAM_ENDED,
    }
}

#[cfg(test)]
mod tests {
    //! Captures actual structured close lines and verifies session-level log bounds.
    use super::*;
    use std::{io::Write, sync::Mutex};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Self;

        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    impl Capture {
        fn start() -> (Self, tracing::subscriber::DefaultGuard) {
            let capture = Self::default();
            let subscriber = tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_writer(capture.clone())
                .finish();
            let guard = tracing::subscriber::set_default(subscriber);
            (capture, guard)
        }

        fn events(&self, name: &str) -> Vec<serde_json::Value> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .filter(|event: &serde_json::Value| event["fields"]["event"] == name)
                .collect()
        }

        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn record(session_id: [u8; 16]) -> CloseRecord {
        CloseRecord {
            who: CloseWho::InfraternalAgent,
            reason: AGENT_STREAM_ENDED,
            host_id: Some(uuid::Uuid::from_u128(0x1234)),
            session_id,
            browser_stream_id: 3,
            agent_stream_id: 2,
            out_seq: 2048,
            input_acked: 128,
            input_sent: 192,
            output_credit_bytes: 4096,
            agent_close_code: None,
            agent_close_reason: None,
            browser_stream_close_code: None,
            browser_stream_close_reason: None,
            websocket_code: None,
            websocket_reason: None,
        }
    }

    /// Cost of the close path, run by hand in release mode (`--ignored --nocapture`).
    /// A suppressed repeat (the storm case) must stay far below a frame's cost, and
    /// frames themselves never call the logger, so the hot path adds nothing.
    #[tokio::test]
    #[ignore = "manual microbenchmark"]
    async fn close_path_cost() {
        let logger = StreamCloseLog::new();
        let close = record([5; 16]);
        logger.record(&close);
        let n = 2_000_000u32;
        let t = std::time::Instant::now();
        for _ in 0..n {
            logger.record(std::hint::black_box(&close));
        }
        let per = t.elapsed().as_nanos() / u128::from(n);
        println!("suppressed repeat: {per} ns/close");
        let (capture, _guard) = Capture::start();
        let n = 20_000u32;
        let t = std::time::Instant::now();
        for i in 0..n {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&i.to_le_bytes());
            logger.record(&record(id));
        }
        let per = t.elapsed().as_nanos() / u128::from(n);
        println!("first close of a new session (formats and writes one line): {per} ns/close");
        assert_eq!(capture.events("terminal_stream_closed").len(), n as usize);
    }

    #[tokio::test(start_paused = true)]
    async fn a_flood_of_distinct_sessions_keeps_memory_bounded_and_logs_each_first_close() {
        let (capture, _guard) = Capture::start();
        let logger = StreamCloseLog::new();
        let total = MAX_TRACKED_SESSIONS + 500;
        for i in 0..total {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            logger.record(&record(id));
        }
        assert_eq!(capture.events("terminal_stream_closed").len(), total);
        assert!(logger.0.state.lock().unwrap().sessions.len() <= MAX_TRACKED_SESSIONS);
        // After the windows end the sweep frees the map and tracking resumes.
        tokio::time::advance(CLOSE_WINDOW + Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        logger.record(&record([0xee; 16]));
        assert!(logger.0.state.lock().unwrap().sessions.len() < MAX_TRACKED_SESSIONS);
    }

    #[tokio::test(start_paused = true)]
    async fn one_close_line_and_one_summary_bound_a_session_storm() {
        let (capture, _guard) = Capture::start();
        let logger = StreamCloseLog::new();
        let session = [7; 16];
        for _ in 0..512 {
            logger.record_at(&record(session), Instant::now());
        }
        assert_eq!(capture.events("terminal_stream_closed").len(), 1);
        assert_eq!(capture.events("terminal_stream_close_summary").len(), 0);

        tokio::time::advance(CLOSE_WINDOW).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        let summaries = capture.events("terminal_stream_close_summary");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0]["fields"]["closed_count"], 512);
        assert_eq!(
            summaries[0]["fields"]["message"],
            "closed 512 times in 60 s, reason terminal_stream_closed"
        );
        assert_eq!(capture.text().lines().count(), 2);
        assert!(capture.text().contains("agent_stream_ended"));
        assert!(
            capture
                .text()
                .contains(&uuid::Uuid::from_u128(0x1234).to_string())
        );
    }

    #[tokio::test]
    async fn close_line_has_session_counters_and_never_copies_untrusted_close_text() {
        let (capture, _guard) = Capture::start();
        let logger = StreamCloseLog::new();
        let mut close = record([9; 16]);
        close.who = CloseWho::Browser;
        close.reason = CLIENT_WENT_AWAY;
        close.websocket_code = Some(4000);
        close.websocket_reason = Some(safe_websocket_reason("connection unresponsive"));
        close.agent_close_reason = Some(safe_agent_close_reason("private terminal contents"));
        logger.record(&close);

        let events = capture.events("terminal_stream_closed");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["fields"]["who"], "browser");
        assert_eq!(events[0]["fields"]["reason_category"], "client_went_away");
        assert_eq!(events[0]["fields"]["websocket_code"], 4000);
        assert_eq!(
            events[0]["fields"]["websocket_reason"],
            "connection unresponsive"
        );
        assert_eq!(events[0]["fields"]["out_seq"], 2048);
        assert_eq!(events[0]["fields"]["input_acked"], 128);
        assert_eq!(
            safe_websocket_reason("private-token https://private.invalid"),
            "other"
        );
        assert_eq!(
            safe_agent_close_reason("terminal content and private-token"),
            "other"
        );
        assert!(!capture.text().contains("private-token"));
        assert!(!capture.text().contains("private.invalid"));
        assert!(!capture.text().contains("private terminal contents"));
    }

    #[test]
    fn an_unavailable_agent_stream_is_reported_as_a_link_drop() {
        let reason = safe_agent_close_reason("remote stream unavailable");
        let close = classify_terminal_close(reason);
        assert_eq!(close.category, "agent_connection_dropped");
        assert_eq!(close.kind, "server_link_lost");
        let ended = classify_terminal_close(safe_agent_close_reason("attachment ended"));
        assert_eq!(ended.category, "agent_stream_ended");
        assert_eq!(ended.kind, "terminal_stream_closed");
        let input = classify_terminal_close(safe_agent_close_reason(
            "terminal command queue full; reattach and replay unacknowledged input",
        ));
        assert_eq!(input.category, "flow_control_refusal");
        assert_eq!(input.kind, "input_queue_full");
        let route = classify_terminal_close("terminal route unresponsive");
        assert_eq!(route.category, "idle");
        assert_eq!(route.kind, "terminal_route_unresponsive");
    }
}

#[cfg(test)]
mod review_tests {
    //! Break-it review of #227: the limiter must stay a limiter when its map is full.
    use super::*;

    fn close(session_id: [u8; 16]) -> CloseRecord {
        CloseRecord::new(
            CloseWho::InfraternalAgent,
            AGENT_STREAM_ENDED,
            None,
            session_id,
            1,
        )
    }

    #[derive(Clone, Default)]
    struct Count(Arc<std::sync::atomic::AtomicUsize>);

    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let lines = bytes.iter().filter(|b| **b == b'\n').count();
            self.0
                .fetch_add(lines, std::sync::atomic::Ordering::Relaxed);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Count {
        type Writer = Self;

        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    /// 8,192 distinct session ids (one authenticated client can mint them with
    /// AttachTerm for sessions it does not own) fill the map; from then on a real
    /// session's close storm is logged once per close, not once per minute.
    #[tokio::test(start_paused = true)]
    async fn a_full_map_does_not_turn_off_rate_limiting_for_a_storming_session() {
        let logger = StreamCloseLog::new();
        for i in 0..MAX_TRACKED_SESSIONS {
            let mut id = [0xa5_u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            logger.record(&close(id));
        }
        let count = Count::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .without_time()
            .with_writer(count.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let storm = [0x5a; 16];
        for _ in 0..1000 {
            logger.record(&close(storm));
        }
        let lines = count.0.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            lines <= 2,
            "{lines} log lines for 1000 closes of one session within a minute while the map is full"
        );
    }

    /// Hand-run (`--ignored --nocapture`, release): the summary worker wakes on every new
    /// window and scans the whole map under the logger mutex. The shipped benchmark runs on
    /// a current-thread runtime, where that worker never runs during the loop.
    #[test]
    #[ignore = "manual microbenchmark"]
    fn first_close_cost_with_the_worker_running() {
        for threads in [1_usize, 4] {
            let runtime = if threads == 1 {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
            } else {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(threads)
                    .enable_all()
                    .build()
                    .unwrap()
            };
            runtime.block_on(async {
                let logger = StreamCloseLog::new();
                for i in 0..(MAX_TRACKED_SESSIONS - 4096) {
                    let mut id = [1_u8; 16];
                    id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    logger.record(&close(id));
                }
                tokio::task::yield_now().await;
                let n = 4000_u64;
                let t = std::time::Instant::now();
                for i in 0..n {
                    let mut id = [2_u8; 16];
                    id[..8].copy_from_slice(&i.to_le_bytes());
                    logger.record(&close(id));
                }
                let per = t.elapsed().as_nanos() / u128::from(n);
                println!("runtime threads {threads}: first close with ~4k-8k live windows: {per} ns/close");
            });
        }
    }
}
