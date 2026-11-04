//! Classifies terminal stream closes and writes a bounded, rate-limited log of them.
//!
//! Socket code never formats or writes a close line. `StreamCloseLog::record` copies
//! the close into a bounded queue read by one logger thread and returns at once. When
//! the queue is full the close is dropped and counted; the thread reports the count in
//! one warning line per window. A slow log sink therefore never stalls a socket worker.
//!
//! The logger thread rate-limits per (account, reason category). The first close of a
//! window is written at once; later ones are only counted and summarised in one line
//! when the 60 s window ends. The key is chosen by the server, never by the client: a
//! client can name any session id in an attach, but it cannot change the account that
//! owns its socket. When the per-account table is full, closes fall into one
//! server-wide window per reason category, so the line rate stays bounded during a
//! storm across many accounts too.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError},
    },
    time::{Duration, Instant},
};

/// Length of one rate-limit window. Within a window an account gets one log line per reason category; the rest are counted.
const CLOSE_WINDOW: Duration = Duration::from_secs(60);
/// [`CLOSE_WINDOW`] in whole seconds, for the summary line.
const CLOSE_WINDOW_SECONDS: u64 = 60;
// Each live window costs about 250 bytes; this bounds the table near 2 MiB.
/// Most (account, category) windows tracked at once.
const MAX_TRACKED_WINDOWS: usize = 8192;
// Closes arrive at socket-event rate, not frame rate. 1,024 records (about 200 KiB,
// allocated on the first close) absorb a mass disconnect while the thread writes;
// beyond that a close is dropped and counted rather than waited for.
/// Most close records waiting for the logger thread. When full, new closes are dropped and counted.
const QUEUE_CAPACITY: usize = 1024;
/// The session field of a close that names no session the account owns. Session ids
/// are random 128-bit values, so the all-zero id is never a real one.
pub(crate) const NO_SESSION: [u8; 16] = [0; 16];

/// Why a terminal stream closed. Every reason is a fixed, static set of strings, so nothing a client sends can reach the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CloseReason {
    /// Coarse group used for rate limiting and for reading the log (for example `flow_control_refusal`).
    pub(crate) category: &'static str,
    /// Specific cause within the category.
    pub(crate) kind: &'static str,
    /// Plain-language explanation that may be shown to the person using the browser.
    pub(crate) client_text: &'static str,
}

impl CloseReason {
    /// Builds a reason from its three fixed strings.
    const fn new(category: &'static str, kind: &'static str, client_text: &'static str) -> Self {
        Self {
            category,
            kind,
            client_text,
        }
    }
}

/// The browser closed its WebSocket.
pub(crate) const CLIENT_WENT_AWAY: CloseReason = CloseReason::new(
    "client_went_away",
    "websocket_closed",
    "browser closed the connection",
);
/// The infraternal agent on the host ended the terminal stream.
pub(crate) const AGENT_STREAM_ENDED: CloseReason = CloseReason::new(
    "agent_stream_ended",
    "terminal_stream_closed",
    "the infraternal agent ended the terminal stream",
);
/// The infraternal agent's connection to the server was lost.
pub(crate) const AGENT_CONNECTION_DROPPED: CloseReason = CloseReason::new(
    "agent_connection_dropped",
    "server_link_lost",
    "the infraternal agent lost its connection to the server",
);
/// The host could not accept the terminal attachment.
pub(crate) const AGENT_CONNECTION_REFUSED: CloseReason = CloseReason::new(
    "agent_connection_refused",
    "terminal_attach_unavailable",
    "the host could not accept the terminal attachment",
);
/// The terminal's input queue overflowed its flow-control limit.
pub(crate) const INPUT_QUEUE_FULL: CloseReason = CloseReason::new(
    "flow_control_refusal",
    "input_queue_full",
    "terminal input exceeded the flow-control limit",
);
/// The browser reader fell too far behind and must reconnect.
pub(crate) const READER_FELL_BEHIND: CloseReason = CloseReason::new(
    "flow_control_refusal",
    "reader_fell_behind",
    "the terminal reader fell behind and is reconnecting",
);
/// The terminal on the host stopped responding.
pub(crate) const TERMINAL_ROUTE_IDLE: CloseReason = CloseReason::new(
    "idle",
    "terminal_route_unresponsive",
    "the terminal on the host stopped responding",
);
/// The terminal output credit exceeded its limit.
pub(crate) const CREDIT_REFUSED: CloseReason = CloseReason::new(
    "flow_control_refusal",
    "credit_exceeded",
    "terminal output credit exceeded its limit",
);
/// The server could not keep up with connection replies.
pub(crate) const REPLY_QUEUE_FULL: CloseReason = CloseReason::new(
    "flow_control_refusal",
    "control_reply_queue_full",
    "the server could not keep up with connection replies",
);
/// A terminal frame exceeded the size limit.
pub(crate) const FRAME_TOO_LARGE: CloseReason = CloseReason::new(
    "size_limit",
    "frame_too_large",
    "a terminal frame exceeded the size limit",
);
/// The terminal stream sent a frame that is not valid protocol.
pub(crate) const PROTOCOL_ERROR: CloseReason = CloseReason::new(
    "protocol_error",
    "invalid_frame",
    "the terminal stream sent an invalid protocol frame",
);
/// The server refused a terminal attachment.
pub(crate) const ATTACH_REFUSED: CloseReason = CloseReason::new(
    "auth_resume_refusal",
    "terminal_attach_refused",
    "the server refused the terminal attachment",
);
/// An attach naming a session this account has no record of. The line never carries
/// the named id: it may be another account's session, and logging it would let a
/// client write arbitrary ids into the log.
pub(crate) const ATTACH_UNOWNED: CloseReason = CloseReason::new(
    "auth_resume_refusal",
    "unowned_session_attach",
    "the account has no such terminal session",
);
/// The server refused to resume a connection.
pub(crate) const RESUME_REFUSED: CloseReason = CloseReason::new(
    "auth_resume_refusal",
    "connection_resume_refused",
    "the server refused to resume the connection",
);
/// The server stopped receiving replies on the connection.
pub(crate) const IDLE_TIMEOUT: CloseReason = CloseReason::new(
    "idle",
    "liveness_timeout",
    "the server stopped receiving connection replies",
);
/// The server could not write to the connection.
pub(crate) const SERVER_WRITE_FAILED: CloseReason = CloseReason::new(
    "server_transport_error",
    "websocket_write_failed",
    "the server could not write to the connection",
);
/// The session read that authorizes a frame missed its time bound, typically under
/// database load. The session itself was not refused: the browser reconnects and
/// the next read decides. Kept apart from `PROTOCOL_ERROR` so a busy server never
/// reads as a misbehaving browser in the log or on the page.
pub(crate) const AUTHORITY_UNAVAILABLE: CloseReason = CloseReason::new(
    "server_busy",
    "authority_unavailable",
    "the server was too busy to confirm the session",
);
/// The server hit an internal error and could not continue the stream.
pub(crate) const SERVER_PROCESSING_FAILED: CloseReason = CloseReason::new(
    "server_processing_error",
    "terminal_stream_processing_failed",
    "the server could not continue the terminal stream",
);
/// Used in a summary line when a window saw closes with different reasons.
const MIXED_REASON: CloseReason = CloseReason::new(
    "multiple",
    "multiple_close_reasons",
    "the stream closed repeatedly for different reasons",
);

/// Which side ended the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CloseWho {
    /// The browser.
    Browser,
    /// The server.
    Server,
    /// The infraternal agent on the host.
    InfraternalAgent,
    /// More than one side, in a summary line.
    Multiple,
}

impl CloseWho {
    /// Name written to the log.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Server => "server",
            Self::InfraternalAgent => "infraternal_agent",
            Self::Multiple => "multiple",
        }
    }
}

/// Rate-limit key for the account that owns a socket. The server derives it from the
/// authenticated user id, so a client cannot choose it. A hash keeps the key small and
/// allocation-free; a collision only merges two accounts' windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct CloseOwner(u64);

impl CloseOwner {
    /// Derives the rate-limit key from an authenticated user id.
    pub(crate) fn of(user_id: &str) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        user_id.hash(&mut hasher);
        Self(hasher.finish())
    }
}

/// The log contains only identifiers, close metadata, and existing stream cursors/credit.
/// `owner` keys the rate limit and is never written.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CloseRecord {
    /// Rate-limit key for the owning account. Never logged.
    pub(crate) owner: CloseOwner,
    /// Which side ended the stream.
    pub(crate) who: CloseWho,
    /// Why it ended.
    pub(crate) reason: CloseReason,
    /// Host the terminal runs on, if remote.
    pub(crate) host_id: Option<uuid::Uuid>,
    /// Terminal session id, or [`NO_SESSION`].
    pub(crate) session_id: [u8; 16],
    /// Stream number on the browser's WebSocket.
    pub(crate) browser_stream_id: u32,
    /// Stream number on the infraternal agent's connection; 0 if none.
    pub(crate) agent_stream_id: u32,
    /// Output position the server had sent.
    pub(crate) out_seq: u64,
    /// Input bytes the host had acknowledged.
    pub(crate) input_acked: u64,
    /// Input bytes the server had sent.
    pub(crate) input_sent: u64,
    /// Output credit outstanding, in bytes.
    pub(crate) output_credit_bytes: u64,
    /// Close code the infraternal agent gave, if any.
    pub(crate) agent_close_code: Option<u16>,
    /// Short fixed text for the infraternal agent's close, if any.
    pub(crate) agent_close_reason: Option<&'static str>,
    /// Close code on the browser stream, if any.
    pub(crate) browser_stream_close_code: Option<u16>,
    /// Short fixed text for the browser stream's close, if any.
    pub(crate) browser_stream_close_reason: Option<&'static str>,
    /// WebSocket close code, if any.
    pub(crate) websocket_code: Option<u16>,
    /// WebSocket close reason text, if any.
    pub(crate) websocket_reason: Option<&'static str>,
}

impl CloseRecord {
    /// Starts a record for a close. Cursor, credit and close-code fields start at zero or `None`; set them before recording.
    pub(crate) fn new(
        owner: CloseOwner,
        who: CloseWho,
        reason: CloseReason,
        host_id: Option<uuid::Uuid>,
        session_id: [u8; 16],
        browser_stream_id: u32,
    ) -> Self {
        Self {
            owner,
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

/// Shared close logger. The thread starts on the first close and ends when the last
/// handle is dropped, after it has written every pending summary.
#[derive(Clone)]
pub(crate) struct StreamCloseLog(Arc<Inner>);

/// Shared state: the lazily created queue, the dropped-close counter and the fallback for a dead logger.
struct Inner {
    /// Sender to the logger thread; `None` inside means it failed to start.
    queue: OnceLock<Option<SyncSender<CloseRecord>>>,
    /// Closes dropped since the last summary.
    dropped: Arc<AtomicU64>,
    /// Fallback used when the logger thread is gone.
    degraded: Degraded,
}

/// Fallback for a logger thread that failed to start or died. Nothing reads the queue then, so the
/// callers themselves count the closes, say once on stderr that the logger is gone, and write the
/// drop summary about once per window. This is the only path that formats on a caller's thread, and
/// it runs only when the logger is already broken.
#[derive(Default)]
struct Degraded {
    /// True once the one-time stderr notice has been printed.
    announced: std::sync::atomic::AtomicBool,
    /// When the last fallback summary was written.
    last_summary: Mutex<Option<Instant>>,
}

impl Degraded {
    /// Counts a close that nothing can log, prints the stderr notice once, and writes a drop summary at most once per window.
    fn note(&self, dropped: &AtomicU64, now: Instant) {
        if !self.announced.swap(true, Ordering::Relaxed) {
            // stderr, not tracing: the subscriber is what the dead thread was writing through.
            eprintln!(
                "infraternal: terminal stream close logger is not running; counting closes and summarising them once a minute"
            );
        }
        let mut last = self
            .last_summary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.is_some_and(|last| now < last + CLOSE_WINDOW) {
            return;
        }
        *last = Some(now);
        report_dropped(dropped.swap(0, Ordering::Relaxed));
    }
}

#[cfg(test)]
static IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl StreamCloseLog {
    /// Creates the shared logger. The thread starts on the first close, not now.
    pub(crate) fn new() -> Self {
        Self(Arc::new(Inner {
            queue: OnceLock::new(),
            dropped: Arc::default(),
            degraded: Degraded::default(),
        }))
    }

    /// Queue one close for the logger thread. Never blocks and never formats.
    pub(crate) fn record(&self, record: &CloseRecord) {
        let queue = self
            .0
            .queue
            .get_or_init(|| spawn_logger(self.0.dropped.clone()));
        let Some(queue) = queue else {
            self.0.dropped.fetch_add(1, Ordering::Relaxed);
            self.0.degraded.note(&self.0.dropped, Instant::now());
            return;
        };
        #[cfg(test)]
        IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
        if let Err(error) = queue.try_send(*record) {
            #[cfg(test)]
            IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
            self.0.dropped.fetch_add(1, Ordering::Relaxed);
            if matches!(error, TrySendError::Disconnected(_)) {
                self.0.degraded.note(&self.0.dropped, Instant::now());
            }
        }
    }
}

/// Block until every queued close has been written (tests only; bounded at 5 s). It
/// may block a runtime thread: the logger thread needs none of the runtime's.
#[cfg(test)]
pub(crate) fn settled() {
    let give_up = Instant::now() + Duration::from_secs(5);
    while IN_FLIGHT.load(Ordering::SeqCst) > 0 && Instant::now() < give_up {
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// The thread writes through the subscriber that was current where the first close
/// happened: the global one in the server, a captured one in tests.
fn spawn_logger(dropped: Arc<AtomicU64>) -> Option<SyncSender<CloseRecord>> {
    let (queue, closes) = std::sync::mpsc::sync_channel(QUEUE_CAPACITY);
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    std::thread::Builder::new()
        .name("close-log".to_owned())
        .stack_size(256 * 1024)
        .spawn(move || tracing::dispatcher::with_default(&dispatch, || run(&closes, &dropped)))
        .ok()?;
    Some(queue)
}

fn run(closes: &Receiver<CloseRecord>, dropped: &AtomicU64) {
    let mut limiter = Limiter::default();
    let mut drops = DropReport::default();
    loop {
        let deadline = match (limiter.next_deadline(), drops.next_deadline(dropped)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let received = match deadline {
            Some(deadline) => {
                closes.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            }
            None => closes.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        let now = Instant::now();
        match received {
            Ok(record) => {
                limiter.record(record, now, &mut emit);
                #[cfg(test)]
                IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
            }
            Err(RecvTimeoutError::Timeout) => limiter.expire(now, &mut emit),
            Err(RecvTimeoutError::Disconnected) => {
                limiter.finish(&mut emit);
                drops.report(dropped, None);
                return;
            }
        }
        drops.report(dropped, Some(now));
    }
}

/// Closes dropped on a full queue, reported as one warning at most once per window.
#[derive(Default)]
struct DropReport {
    last: Option<Instant>,
}

impl DropReport {
    fn next_deadline(&self, dropped: &AtomicU64) -> Option<Instant> {
        (dropped.load(Ordering::Relaxed) > 0).then(|| {
            self.last
                .map_or_else(Instant::now, |last| last + CLOSE_WINDOW)
        })
    }

    /// `now` is `None` at shutdown, which reports regardless of the window.
    fn report(&mut self, dropped: &AtomicU64, now: Option<Instant>) {
        if dropped.load(Ordering::Relaxed) == 0 {
            return;
        }
        if let (Some(now), Some(last)) = (now, self.last)
            && now < last + CLOSE_WINDOW
        {
            return;
        }
        self.last = now;
        report_dropped(dropped.swap(0, Ordering::Relaxed));
    }
}

/// One warning for closes that never reached the log: the queue was full or the logger is gone.
fn report_dropped(count: u64) {
    if count > 0 {
        tracing::warn!(
            target: "infraternal::terminal_stream",
            event = "terminal_stream_close_records_dropped",
            dropped = count,
            "terminal stream close records dropped because the log queue was full or the logger is not running"
        );
    }
}

/// Whether a line's window is one account's or the server-wide overflow window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    Account,
    Server,
}

struct Window {
    started: Instant,
    closes: u64,
    last: CloseRecord,
}

impl Window {
    fn new(record: CloseRecord, now: Instant) -> Self {
        Self {
            started: now,
            closes: 1,
            last: record,
        }
    }

    /// Keep the latest cursors; a window that saw different reasons or closers says so.
    fn absorb(&mut self, record: CloseRecord) {
        let reason = if self.last.reason == record.reason {
            record.reason
        } else {
            MIXED_REASON
        };
        let who = if self.last.who == record.who {
            record.who
        } else {
            CloseWho::Multiple
        };
        self.last = CloseRecord {
            who,
            reason,
            ..record
        };
        self.closes = self.closes.saturating_add(1);
    }
}

type WindowKey = (CloseOwner, &'static str);

/// Owned by the logger thread alone, so it needs no lock.
#[derive(Default)]
struct Limiter {
    accounts: HashMap<WindowKey, Window>,
    /// Account windows in start order, one entry per live window. One thread stamps
    /// `now` for every record, so starts never decrease and the front holds the
    /// earliest deadline: finding and ending due windows costs O(1) per window.
    order: VecDeque<(Instant, WindowKey)>,
    /// Server-wide windows by reason category, used only while `accounts` is full.
    /// The category table is fixed, so this stays a handful of entries.
    overflow: Vec<(&'static str, Window)>,
}

impl Limiter {
    fn record(
        &mut self,
        record: CloseRecord,
        now: Instant,
        out: &mut impl FnMut(&CloseRecord, u64, Scope),
    ) {
        // Ending due windows first means a key found below always has a live window.
        self.expire(now, out);
        let key = (record.owner, record.reason.category);
        if let Some(window) = self.accounts.get_mut(&key) {
            window.absorb(record);
            return;
        }
        if self.accounts.len() < MAX_TRACKED_WINDOWS {
            out(&record, 1, Scope::Account);
            self.order.push_back((now, key));
            self.accounts.insert(key, Window::new(record, now));
            return;
        }
        if let Some((_, window)) = self
            .overflow
            .iter_mut()
            .find(|(category, _)| *category == key.1)
        {
            window.absorb(record);
            return;
        }
        out(&record, 1, Scope::Server);
        self.overflow.push((key.1, Window::new(record, now)));
    }

    fn expire(&mut self, now: Instant, out: &mut impl FnMut(&CloseRecord, u64, Scope)) {
        while let Some(&(started, key)) = self.order.front() {
            if now < started + CLOSE_WINDOW {
                break;
            }
            self.order.pop_front();
            if let Some(window) = self.accounts.remove(&key) {
                summarize(&window, Scope::Account, out);
            }
        }
        self.overflow.retain(|(_, window)| {
            if now < window.started + CLOSE_WINDOW {
                return true;
            }
            summarize(window, Scope::Server, out);
            false
        });
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.order
            .front()
            .map(|(started, _)| *started)
            .into_iter()
            .chain(self.overflow.iter().map(|(_, window)| window.started))
            .min()
            .map(|started| started + CLOSE_WINDOW)
    }

    /// Shutdown: summarise every window that is still open.
    fn finish(&mut self, out: &mut impl FnMut(&CloseRecord, u64, Scope)) {
        self.order.clear();
        for (_, window) in self.accounts.drain() {
            summarize(&window, Scope::Account, out);
        }
        for (_, window) in self.overflow.drain(..) {
            summarize(&window, Scope::Server, out);
        }
    }
}

fn summarize(window: &Window, scope: Scope, out: &mut impl FnMut(&CloseRecord, u64, Scope)) {
    if window.closes >= 2 {
        out(&window.last, window.closes, scope);
    }
}

/// One call site for both lines keeps the binary small: `closes` is 1 for the first
/// close of a window and the window's close count for its summary. The stream close
/// pair is the peer's close of a browser stream or of the control stream, whichever
/// ended. A close that names no owned session prints "none" for session and host.
fn emit(record: &CloseRecord, closes: u64, scope: Scope) {
    let named = record.session_id != NO_SESSION;
    let session_id = if named {
        uuid::Uuid::from_bytes(record.session_id).to_string()
    } else {
        "none".to_owned()
    };
    let host_id = match record.host_id {
        _ if !named => "none".to_owned(),
        Some(id) => id.to_string(),
        None => "local".to_owned(),
    };
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
        limit_scope = if scope == Scope::Account { "account" } else { "server" },
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
    //! The limiter's bounds on synthetic time, and real close lines through the thread.
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

    fn owner(n: u64) -> CloseOwner {
        CloseOwner(n)
    }

    fn record(owner: CloseOwner, session_id: [u8; 16]) -> CloseRecord {
        CloseRecord {
            agent_stream_id: 2,
            out_seq: 2048,
            input_acked: 128,
            input_sent: 192,
            output_credit_bytes: 4096,
            ..CloseRecord::new(
                owner,
                CloseWho::InfraternalAgent,
                AGENT_STREAM_ENDED,
                Some(uuid::Uuid::from_u128(0x1234)),
                session_id,
                3,
            )
        }
    }

    fn session(n: u64) -> [u8; 16] {
        let mut id = [0xa5_u8; 16];
        id[..8].copy_from_slice(&n.to_le_bytes());
        id
    }

    /// Runs records through a limiter at the given offsets and returns (closes, scope) per line.
    #[derive(Default)]
    struct Lines(Vec<(u64, Scope)>);

    impl Lines {
        fn sink(&mut self) -> impl FnMut(&CloseRecord, u64, Scope) + '_ {
            |_, closes, scope| self.0.push((closes, scope))
        }
    }

    #[test]
    fn one_close_line_and_one_summary_bound_an_account_storm() {
        let mut limiter = Limiter::default();
        let mut lines = Lines::default();
        let start = Instant::now();
        for i in 0..512 {
            limiter.record(
                record(owner(1), session(i % 3)),
                start + Duration::from_millis(i),
                &mut lines.sink(),
            );
        }
        assert_eq!(lines.0, [(1, Scope::Account)]);
        assert_eq!(limiter.next_deadline(), Some(start + CLOSE_WINDOW));
        limiter.expire(start + CLOSE_WINDOW, &mut lines.sink());
        assert_eq!(lines.0, [(1, Scope::Account), (512, Scope::Account)]);
        assert_eq!(limiter.next_deadline(), None);
    }

    #[test]
    fn different_accounts_and_reason_categories_each_get_their_first_line() {
        let mut limiter = Limiter::default();
        let mut lines = Lines::default();
        let now = Instant::now();
        limiter.record(record(owner(1), session(1)), now, &mut lines.sink());
        limiter.record(record(owner(2), session(1)), now, &mut lines.sink());
        let mut refused = record(owner(1), session(1));
        refused.reason = ATTACH_REFUSED;
        limiter.record(refused, now, &mut lines.sink());
        assert_eq!(lines.0.len(), 3);
    }

    /// A client names any session id it likes; the key is its account, so naming
    /// thousands of ids yields one line, not one per id (#227 review P1-1).
    #[test]
    fn client_chosen_session_ids_share_their_accounts_window() {
        let mut limiter = Limiter::default();
        let mut lines = Lines::default();
        let now = Instant::now();
        for i in 0..10_000 {
            let mut unowned = record(owner(7), NO_SESSION);
            unowned.reason = ATTACH_UNOWNED;
            unowned.browser_stream_id = u32::try_from(i % 64).unwrap() * 2 + 1;
            limiter.record(unowned, now, &mut lines.sink());
        }
        assert_eq!(lines.0, [(1, Scope::Account)]);
        assert_eq!(limiter.accounts.len(), 1);
    }

    /// With the table full of live windows, every further account still gets rate
    /// limited through the server-wide window of its category (#227 review P1-2).
    #[test]
    fn a_full_table_keeps_rate_limiting_a_storm() {
        let mut limiter = Limiter::default();
        let mut lines = Lines::default();
        let start = Instant::now();
        for i in 0..MAX_TRACKED_WINDOWS as u64 {
            limiter.record(record(owner(i), session(i)), start, &mut lines.sink());
        }
        lines.0.clear();
        let storm = start + Duration::from_secs(1);
        for i in 0..1000 {
            limiter.record(record(owner(1 << 40), session(i)), storm, &mut lines.sink());
        }
        for i in 0..1000_u64 {
            limiter.record(
                record(owner((1 << 41) + i), session(i)),
                storm,
                &mut lines.sink(),
            );
        }
        assert_eq!(lines.0, [(1, Scope::Server)], "one line for 2000 closes");
        assert_eq!(limiter.accounts.len(), MAX_TRACKED_WINDOWS);
        assert_eq!(limiter.overflow.len(), 1);
        // The account windows end first; the overflow window ends a second later.
        limiter.expire(start + CLOSE_WINDOW, &mut lines.sink());
        assert!(limiter.accounts.is_empty());
        assert_eq!(limiter.overflow.len(), 1);
        limiter.expire(storm + CLOSE_WINDOW, &mut lines.sink());
        assert_eq!(lines.0.last(), Some(&(2000, Scope::Server)));
        // Tracking per account resumes once the table has room.
        limiter.record(
            record(owner(3), session(3)),
            storm + CLOSE_WINDOW,
            &mut lines.sink(),
        );
        assert_eq!(limiter.accounts.len(), 1);
    }

    #[test]
    fn mixed_reasons_and_closers_in_one_window_are_named_as_mixed() {
        let mut limiter = Limiter::default();
        let mut last = None;
        let now = Instant::now();
        let mut out = |record: &CloseRecord, closes: u64, _: Scope| {
            if closes > 1 {
                last = Some(*record);
            }
        };
        limiter.record(record(owner(1), session(1)), now, &mut out);
        let mut other = record(owner(1), session(2));
        other.who = CloseWho::Server;
        other.reason = INPUT_QUEUE_FULL;
        other.reason.category = AGENT_STREAM_ENDED.category;
        limiter.record(other, now, &mut out);
        limiter.finish(&mut out);
        let last = last.unwrap();
        assert_eq!(last.reason, MIXED_REASON);
        assert_eq!(last.who, CloseWho::Multiple);
        assert_eq!(last.session_id, session(2));
    }

    /// Real lines through the thread: the first at once, the summary at shutdown.
    #[tokio::test]
    async fn the_thread_writes_the_first_close_and_summarises_the_rest_on_shutdown() {
        let (capture, _guard) = Capture::start();
        let logger = StreamCloseLog::new();
        for i in 0..512 {
            logger.record(&record(owner(1), session(7)));
            if i % 128 == 127 {
                settled();
            }
        }
        settled();
        assert_eq!(capture.events("terminal_stream_closed").len(), 1);
        assert_eq!(capture.events("terminal_stream_close_summary").len(), 0);
        drop(logger);
        let give_up = Instant::now() + Duration::from_secs(5);
        while capture.events("terminal_stream_close_summary").is_empty() && Instant::now() < give_up
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let summaries = capture.events("terminal_stream_close_summary");
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0]["fields"]["closed_count"], 512);
        assert_eq!(summaries[0]["fields"]["limit_scope"], "account");
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
        let mut close = record(owner(9), [9; 16]);
        close.who = CloseWho::Browser;
        close.reason = CLIENT_WENT_AWAY;
        close.websocket_code = Some(4000);
        close.websocket_reason = Some(safe_websocket_reason("connection unresponsive"));
        close.agent_close_reason = Some(safe_agent_close_reason("private terminal contents"));
        logger.record(&close);
        settled();

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

    #[tokio::test]
    async fn a_close_naming_no_owned_session_prints_none_for_session_and_host() {
        let (capture, _guard) = Capture::start();
        let logger = StreamCloseLog::new();
        let mut unowned = record(owner(4), NO_SESSION);
        unowned.reason = ATTACH_UNOWNED;
        logger.record(&unowned);
        settled();
        let events = capture.events("terminal_stream_closed");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["fields"]["session_id"], "none");
        assert_eq!(events[0]["fields"]["host_id"], "none");
        assert_eq!(events[0]["fields"]["reason"], "unowned_session_attach");
    }

    /// A full queue never blocks the caller: the close is dropped and counted.
    #[test]
    fn a_full_queue_drops_and_counts_instead_of_blocking() {
        let (queue, _closes) = std::sync::mpsc::sync_channel(1);
        let logger = StreamCloseLog(Arc::new(Inner {
            queue: OnceLock::from(Some(queue)),
            dropped: Arc::default(),
            degraded: Degraded::default(),
        }));
        for _ in 0..3 {
            logger.record(&record(owner(1), session(1)));
        }
        assert_eq!(logger.0.dropped.load(Ordering::Relaxed), 2);
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        let (capture, _guard) = Capture::start();
        let mut report = DropReport::default();
        let now = Instant::now();
        report.report(&logger.0.dropped, Some(now));
        logger.0.dropped.fetch_add(5, Ordering::Relaxed);
        report.report(&logger.0.dropped, Some(now + Duration::from_secs(1)));
        assert_eq!(
            report.next_deadline(&logger.0.dropped),
            Some(now + CLOSE_WINDOW)
        );
        report.report(&logger.0.dropped, Some(now + CLOSE_WINDOW));
        let reports = capture.events("terminal_stream_close_records_dropped");
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0]["fields"]["dropped"], 2);
        assert_eq!(reports[1]["fields"]["dropped"], 5);
    }

    /// A logger that never started or died must not drop closes silently: the callers count them and
    /// write one summary per window.
    #[test]
    fn a_dead_logger_is_counted_and_summarised_by_the_callers() {
        for started in [false, true] {
            let queue = started.then(|| std::sync::mpsc::sync_channel(1).0);
            let logger = StreamCloseLog(Arc::new(Inner {
                queue: OnceLock::from(queue),
                dropped: Arc::default(),
                degraded: Degraded::default(),
            }));
            let (capture, _guard) = Capture::start();
            let now = Instant::now();
            for _ in 0..3 {
                logger.record(&record(owner(1), session(1)));
            }
            // The first close summarised at once; the other two wait for the next window.
            assert_eq!(logger.0.dropped.load(Ordering::Relaxed), 2);
            logger
                .0
                .degraded
                .note(&logger.0.dropped, now + CLOSE_WINDOW * 2);
            assert_eq!(logger.0.dropped.load(Ordering::Relaxed), 0);
            let reports = capture.events("terminal_stream_close_records_dropped");
            assert_eq!(reports.len(), 2, "started={started}");
            assert_eq!(reports[0]["fields"]["dropped"], 1);
            assert_eq!(reports[1]["fields"]["dropped"], 2);
            assert!(logger.0.degraded.announced.load(Ordering::Relaxed));
        }
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

    /// Hand-run in release (`--ignored --nocapture`) on a multi-threaded runtime, with
    /// lines formatted as JSON into a discarding writer. Reports (a) what a socket worker
    /// pays per close below the queue bound, (b) what the logger thread pays per written
    /// line and per counted close, and (c) a flood far past the bound from four workers:
    /// the caller still never waits, the excess is dropped and counted.
    #[test]
    #[ignore = "manual microbenchmark"]
    fn close_path_cost() {
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::sink)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let logger = StreamCloseLog::new();
            // The first close starts the thread under this subscriber; then warm the
            // table to 4,096 live windows, the review's worst case.
            for i in 0..4096 {
                logger.record(&record(owner(i), session(i)));
                if i % 512 == 511 {
                    settled();
                }
            }
            settled();
            // Spin, not settled()'s 1 ms sleep, so the drain time is the thread's own.
            let drain = || {
                while IN_FLIGHT.load(Ordering::SeqCst) > 0 {
                    std::hint::spin_loop();
                }
            };
            let batch = 512_u64;
            for (label, distinct) in [("first close of a new account", true), ("storm of one account", false)] {
                // 8 rounds of new accounts fill the table to its 8,192 bound, never past it.
                let rounds = if distinct { 8_u64 } else { 40 };
                let mut caller = Duration::ZERO;
                let mut drained = Duration::ZERO;
                for round in 0..rounds {
                    let start = Instant::now();
                    for i in 0..batch {
                        let id = if distinct { 1_000_000 + round * batch + i } else { 1 << 50 };
                        logger.record(std::hint::black_box(&record(owner(id), session(i))));
                    }
                    caller += start.elapsed();
                    drain();
                    drained += start.elapsed();
                }
                let n = u32::try_from(batch * rounds).unwrap();
                println!(
                    "{label}: caller {} ns/close, logger thread {} ns/close (incl. JSON line when written)",
                    (caller / n).as_nanos(),
                    (drained / n).as_nanos()
                );
            }
            let dropped_before = logger.0.dropped.load(Ordering::Relaxed);
            let tasks = 4_u64;
            let per_task = 50_000_u64;
            let mut handles = Vec::new();
            for t in 0..tasks {
                let logger = logger.clone();
                handles.push(tokio::spawn(async move {
                    let start = Instant::now();
                    for i in 0..per_task {
                        logger.record(std::hint::black_box(&record(owner((t << 32) + i + (1 << 40)), session(i))));
                    }
                    start.elapsed() / u32::try_from(per_task).unwrap()
                }));
            }
            let mut per = Duration::ZERO;
            for handle in handles {
                per += handle.await.unwrap();
            }
            settled();
            println!(
                "flood from {tasks} workers: caller {} ns/close, {} of {} closes dropped and counted",
                (per / u32::try_from(tasks).unwrap()).as_nanos(),
                logger.0.dropped.load(Ordering::Relaxed) - dropped_before,
                tasks * per_task
            );
        });
    }
}
