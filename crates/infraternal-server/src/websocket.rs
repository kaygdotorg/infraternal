//! Authenticates browser sockets, resumes connections, and relays user-owned terminal streams [19][41][50].

use crate::embedded::{
    AgentError, AttachmentHandle, EmbeddedAgent, SessionInventoryState, TerminalOutput,
    TerminalSize,
};
/// Public fixture clocks distinguish browser stalls from serialized backend work.
#[cfg(test)]
fn addhost_timeline(step: &'static str) {
    if std::env::var_os("ADDHOST_BROWSER_TIMELINE").is_some()
        && let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
    {
        eprintln!(
            "{{\"source\":\"socket\",\"step\":\"{step}\",\"epoch_ms\":{}}}",
            now.as_secs_f64() * 1000.0
        );
    }
}
use crate::{
    auth::Auth,
    plugins::{Dispatch, PluginRuntime, SocketPlugins},
    stream_close::{
        AGENT_CONNECTION_DROPPED, AGENT_CONNECTION_REFUSED, AGENT_STREAM_ENDED, ATTACH_REFUSED,
        ATTACH_UNOWNED, AUTHORITY_UNAVAILABLE, CLIENT_WENT_AWAY, CREDIT_REFUSED, CloseOwner,
        CloseReason, CloseRecord, CloseWho, INPUT_QUEUE_FULL, NO_SESSION, PROTOCOL_ERROR,
        RESUME_REFUSED, StreamCloseLog, TERMINAL_ROUTE_IDLE, classify_terminal_close,
        safe_agent_close_reason, safe_websocket_reason,
    },
};
use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use bytes::{Bytes, BytesMut};
use futures_util::{FutureExt, SinkExt, Stream, StreamExt};
use infraternal_plugin_api::{ActionDef, Operation, Permission, PluginDescriptor, SocketHost};
use infraternal_protocol::{
    CLOSE_SESSION_GONE, DecodeError, Frame, MAX_FRAME_LEN, SESSION_GONE_REASON, decode_muxed_frame,
    encode_muxed_frame_into,
};
use rand::random;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Semaphore, mpsc, watch};

const CONTROL_STREAM: u32 = 0;
const RESUME_NEXT: u64 = 1;
/// Browser Hello bit 1: the viewer understands `terminal.link_doubt` and
/// `terminal.link_recovered`. Older viewers reject unknown notices, so they
/// are never sent one and simply see no indicator for a kept link [D300].
const LINK_DOUBT_NOTICES: u64 = 1 << 1;
/// Browser Hello bit 2 enables bounded control-stream visibility notices (#244).
const VIEWER_VISIBILITY: u64 = 1 << 2;
/// Reply-marked Input is independent of shipped viewer visibility.
const TERMINAL_QUERY_REPLIES: u64 = 1 << 3;
const RESUME_WINDOW_SECONDS: u32 = 120;
// Reject upgrades immediately when the process is at this fixed socket limit.
const MAX_CONNECTIONS: usize = 256;
const MAX_USER_CONNECTIONS: usize = 16;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const PARTIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const BACKEND_TIMEOUT: Duration = Duration::from_secs(5);
// SSH/terminal connection work can legitimately take tens of seconds. No prior
// connect budget exists; #29 sets 60s. Authority interruption remains independent.
const TERMINAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
// Stored expiry changes do not publish revocations; poll only during pending work, never idle.
const BUSY_AUTHORITY_INTERVAL: Duration = Duration::from_millis(25);
// Deadline of one authority read attempt. Teardown makes exactly one attempt,
// without renewal, so closing never holds a socket on a busy store for longer.
const AUTHORITY_READ_TIMEOUT: Duration = Duration::from_millis(25);
// A read that misses its deadline is a busy store, not a refusal (#240): it is
// retried while the socket's work stays held, and fails closed after this wait.
const AUTHORITY_WAIT: Duration = Duration::from_secs(1);
// Pause between attempts: 5 ms, doubling to 100 ms. A socket stalled for the
// whole wait makes about 11 attempts, each a read-only SELECT.
const AUTHORITY_RETRY_PAUSE: Duration = Duration::from_millis(5);
const AUTHORITY_RETRY_PAUSE_MAX: Duration = Duration::from_millis(100);
const CLOSE_TIMEOUT: Duration = Duration::from_millis(25);
/// Bounds the lookup that names a refused resume's sessions in the close log.
const REFUSAL_LOG_TIMEOUT: Duration = Duration::from_millis(250);
// Expired rows are pruned during new handshakes; this caps retained bearer metadata globally.
const MAX_RESUME_ROWS: i64 = 4096;
// Reject further AttachTerm requests on a socket at this bound.
pub(super) const MAX_ATTACHMENTS: usize = 32;
// Enough to cover every stream on a server socket while keeping the exit-status sidecar small.
const MAX_ENDED_SESSION_STATUSES: i64 = 128;
// Bound unfinished host-facts and terminal-open calls on each socket.
const MAX_PENDING_PLUGIN_CALLS: usize = 4;
// A blocked websocket writer applies backpressure to each bounded attachment pump.
const OUTPUT_CHANNEL_CAPACITY: usize = 4;
// Cap a fragmented input frame before the decoder retains more bytes.
pub(super) const MAX_SOCKET_BUFFER: usize = MAX_FRAME_LEN + 10;
// Framing initializes this window before every I/O poll, including small idle
// proofs. A 32KiB chunk bounds that work and fits a 16KiB input plus its envelope;
// larger messages still assemble incrementally within the existing frame limit.
const SOCKET_READ_CHUNK: usize = 32 * 1024;
const MAX_CREDIT: u64 = 8 * 1024 * 1024;

type PendingPluginCall = (u32, Result<Vec<u8>, AgentError>);

// Pool connections that authority work may hold at once: half of the
// production pool's eight (runtime.rs), so retries and renewals under a stalled
// store can never take the connections the rest of the server needs (#240).
const AUTHORITY_READS: usize = 4;

/// Server-wide bounds on authority work (#240), shared by every socket.
struct AuthorityLimits {
    // Authority reads and renewals running now; at most `AUTHORITY_READS`.
    // A read waits its turn here within its attempt deadline, in order,
    // instead of backing off: under a burst of fast reads that costs
    // microseconds, not a retry pause.
    reads: Semaphore,
    // Whether the one session renewal allowed at a time is running.
    renewing: std::sync::atomic::AtomicBool,
}

/// A running renewal's read place and renewal flag, given back when its task
/// ends or is dropped.
struct RenewalHold(Arc<AuthorityLimits>);

impl Drop for RenewalHold {
    fn drop(&mut self) {
        self.0.reads.add_permits(1);
        self.0
            .renewing
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Keep a server-wide read place until its SELECT future completes.
struct AuthorityReadHold(Arc<AuthorityLimits>);

impl AuthorityReadHold {
    /// Move a borrowed permit into an owned query lifetime.
    fn take(limits: Arc<AuthorityLimits>, place: tokio::sync::SemaphorePermit<'_>) -> Self {
        place.forget();
        Self(limits)
    }
}

impl Drop for AuthorityReadHold {
    fn drop(&mut self) {
        self.0.reads.add_permits(1);
    }
}

/// State shared by the authenticated browser socket route.
#[derive(Clone)]
pub(crate) struct WebSocketState {
    auth: Auth,
    pool: SqlitePool,
    pub(crate) plugins: PluginRuntime,
    agent: EmbeddedAgent,
    plugin_descriptors: &'static [&'static PluginDescriptor],
    #[cfg(feature = "remote")]
    remote_hosts: crate::remote_runtime::RemoteHosts,
    #[cfg(test)]
    handshake_timeout: Duration,
    #[cfg(test)]
    authority_read_timeout: Duration,
    #[cfg(test)]
    terminal_connect_timeout: Duration,
    connections: Arc<Semaphore>,
    authority: Arc<AuthorityLimits>,
    users: Arc<std::sync::Mutex<HashMap<String, std::sync::Weak<Semaphore>>>>,
    session_changes: watch::Sender<u64>,
    close_logs: StreamCloseLog,
    queries: Arc<std::sync::Mutex<crate::terminal_queries::Registry>>,
}

impl WebSocketState {
    /// Create bounded socket admission around the configured auth and agent services.
    #[cfg(any(not(feature = "remote"), test))]
    pub(crate) async fn new(
        auth: Auth,
        pool: SqlitePool,
        agent: EmbeddedAgent,
    ) -> Result<Self, crate::plugins::PluginError> {
        Self::new_inner(
            auth,
            pool,
            agent,
            #[cfg(feature = "remote")]
            crate::remote_runtime::RemoteHosts::default(),
        )
        .await
    }
    #[cfg(feature = "remote")]
    pub(crate) async fn new_with_hosts(
        auth: Auth,
        pool: SqlitePool,
        agent: EmbeddedAgent,
        hosts: crate::remote_runtime::RemoteHosts,
    ) -> Result<Self, crate::plugins::PluginError> {
        Self::new_inner(auth, pool, agent, hosts).await
    }
    async fn new_inner(
        auth: Auth,
        pool: SqlitePool,
        agent: EmbeddedAgent,
        #[cfg(feature = "remote")] hosts: crate::remote_runtime::RemoteHosts,
    ) -> Result<Self, crate::plugins::PluginError> {
        let plugins = crate::plugins::compiled_with_hosts(
            &pool,
            #[cfg(feature = "remote")]
            hosts.clone(),
        )
        .await?;
        let (session_changes, _) = watch::channel(0_u64);
        let close_logs = StreamCloseLog::new();
        #[cfg(feature = "remote")]
        let queries = hosts.6.clone();
        #[cfg(not(feature = "remote"))]
        let queries: Arc<std::sync::Mutex<crate::terminal_queries::Registry>> = Arc::default();
        let inventory_queries = queries.clone();
        let mut inventory = agent.session_inventory();
        let inventory_pool = pool.clone();
        let inventory_changes = session_changes.clone();
        tokio::spawn(async move {
            loop {
                let snapshot = inventory.borrow_and_update().clone();
                match snapshot {
                    SessionInventoryState::Pending => {}
                    SessionInventoryState::Unavailable => {
                        inventory_changes.send_modify(|version| *version = version.wrapping_add(1));
                    }
                    SessionInventoryState::Available(_) => {
                        if reconcile_embedded_inventory(&inventory_pool, &inventory)
                            .await
                            .is_ok()
                        {
                            {
                                let mut queries = inventory_queries
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                if let SessionInventoryState::Available(ids) = &*inventory.borrow()
                                {
                                    queries.reconcile(None, ids);
                                }
                            }
                            inventory_changes
                                .send_modify(|version| *version = version.wrapping_add(1));
                        } else {
                            tracing::warn!("could not reconcile embedded terminal sessions");
                        }
                    }
                }
                if inventory.changed().await.is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            auth,
            pool,
            plugins,
            agent,
            plugin_descriptors: &[],
            #[cfg(feature = "remote")]
            remote_hosts: hosts,
            #[cfg(test)]
            handshake_timeout: HANDSHAKE_TIMEOUT,
            #[cfg(test)]
            authority_read_timeout: AUTHORITY_READ_TIMEOUT,
            #[cfg(test)]
            terminal_connect_timeout: TERMINAL_CONNECT_TIMEOUT,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            authority: Arc::new(AuthorityLimits {
                reads: Semaphore::new(AUTHORITY_READS),
                renewing: std::sync::atomic::AtomicBool::new(false),
            }),
            users: Arc::default(),
            session_changes,
            close_logs,
            queries,
        })
    }

    /// Bind this socket to the generic host authority bridge without starting features.
    pub(crate) fn plugin_socket(self: &Arc<Self>, user: &str, token: &str) -> SocketPlugins {
        let host: Arc<dyn SocketHost> = Arc::new(PluginHost {
            state: Arc::clone(self),
            user: user.to_owned(),
            hash: crate::auth::hash(token),
            incarnation: crate::auth::session_incarnation(token),
            token: token.to_owned(),
        });
        SocketPlugins::new(self.plugins.clone(), host)
    }

    /// Use only descriptors compiled into the matching infraternal agent binary.
    pub(crate) fn with_plugin_descriptors(
        mut self,
        plugin_descriptors: &'static [&'static PluginDescriptor],
    ) -> Self {
        self.plugin_descriptors = plugin_descriptors;
        self
    }

    #[cfg(feature = "ssh")]
    pub(crate) fn session_notifications(&self) -> watch::Sender<u64> {
        self.session_changes.clone()
    }

    /// Start a due session renewal without waiting for it (#240). The read that
    /// asked for it already proved the session live, and renewal is at most
    /// once a minute against a 30-day session, so running it later is safe. A
    /// renewal UPDATE can wait up to SQLite's busy timeout behind another
    /// writer; held in the frame, or retried on a fresh connection each
    /// attempt, that drained the pool. Here at most one runs server-wide, it
    /// counts against the authority cap, and when either is busy it is skipped:
    /// the session is still due, so a later frame starts it again.
    fn renew_soon(&self, user: &str, token: &str) {
        use std::sync::atomic::Ordering;
        let limits = &self.authority;
        if limits.renewing.swap(true, Ordering::Acquire) {
            return;
        }
        let Ok(place) = limits.reads.try_acquire() else {
            limits.renewing.store(false, Ordering::Release);
            return;
        };
        // RenewalHold gives both back when the task ends, completed or dropped.
        place.forget();
        tokio::spawn(
            self.auth
                .renewal(token, user, RenewalHold(Arc::clone(&self.authority))),
        );
    }

    /// Wake authenticated session-list subscribers after the local host changes its live set.
    fn sessions_changed(&self) {
        self.session_changes
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    fn action(&self, action_id: &str) -> Option<ActionDef> {
        self.plugin_descriptors
            .iter()
            .flat_map(|descriptor| descriptor.actions)
            .find(|action| action.id == action_id)
            .copied()
    }

    #[cfg(feature = "remote")]
    pub(crate) fn with_remote_hosts(mut self, hosts: crate::remote_runtime::RemoteHosts) -> Self {
        self.remote_hosts = hosts;
        self
    }

    /// Keep production's terminal deadline fixed while allowing deadline tests to run quickly.
    #[cfg(test)]
    pub(crate) fn with_terminal_connect_timeout(mut self, timeout: Duration) -> Self {
        self.terminal_connect_timeout = timeout;
        self
    }

    /// Keep production's handshake deadline fixed while tolerating a loaded test host.
    #[cfg(test)]
    pub(crate) fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Keep production's authority-read deadline fixed while tests run on loaded hosts.
    #[cfg(test)]
    pub(crate) fn with_authority_read_timeout(mut self, timeout: Duration) -> Self {
        self.authority_read_timeout = timeout;
        self
    }

    /// Observe retained reads while socket tests control time around real storage.
    #[cfg(all(test, feature = "remote"))]
    pub(crate) fn authority_read_monitor(&self) -> impl Fn() -> usize + 'static {
        let authority = Arc::clone(&self.authority);
        move || AUTHORITY_READS - authority.reads.available_permits()
    }

    /// Reserve per-user capacity before Hello. Weak entries disappear when the last socket drops.
    fn user_permit(&self, user: &str) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let mut users = self.users.lock().ok()?;
        users.retain(|_, semaphore| semaphore.strong_count() != 0);
        let semaphore = users
            .get(user)
            .and_then(std::sync::Weak::upgrade)
            .unwrap_or_else(|| Arc::new(Semaphore::new(MAX_USER_CONNECTIONS)));
        let permit = semaphore.clone().try_acquire_owned().ok()?;
        users.insert(user.to_owned(), Arc::downgrade(&semaphore));
        Some(permit)
    }
}

/// Close stale embedded session rows after an agent restart or a shim retirement.
async fn reconcile_embedded_inventory(
    pool: &SqlitePool,
    inventory: &watch::Receiver<SessionInventoryState>,
) -> Result<(), sqlx::Error> {
    let mut transaction = infraternal_plugin_api::storage::begin_immediate(pool).await?;
    // The ordered leg-B census precedes its open Result. Read the current watch
    // only after the writer lock: a newly persisted row then has a known live ID,
    // even if an earlier census caused this task to wait for the connection.
    let SessionInventoryState::Available(session_ids) = inventory.borrow().clone() else {
        return Ok(());
    };
    let live: HashSet<[u8; 16]> = session_ids.iter().copied().collect();
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT id FROM terminal_sessions WHERE remote_host_id IS NULL AND closed_at IS NULL",
    )
    .fetch_all(&mut *transaction)
    .await?;
    for id in rows {
        let Ok(id_array) = <[u8; 16]>::try_from(id.as_slice()) else {
            continue;
        };
        if live.contains(&id_array) {
            continue;
        }
        sqlx::query("UPDATE terminal_sessions SET closed_at=COALESCE(closed_at,unixepoch()) WHERE id=? AND remote_host_id IS NULL AND closed_at IS NULL")
            .bind(id)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await
}

/// Mount the authenticated leg-A WebSocket endpoint.
pub(crate) fn router(state: WebSocketState) -> Router {
    Router::new()
        .route("/v1/ws", get(upgrade))
        .with_state(Arc::new(state))
}

async fn upgrade(
    State(state): State<Arc<WebSocketState>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        != Some(state.auth.origin())
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(token) = session_cookie(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(now) = unix_seconds() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(session) = state.auth.session(token, now).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let owner = session.owner;
    let session_token = token.to_owned();
    let Ok(permit) = state.connections.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(user_permit) = state.user_permit(&session.user_id) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.read_buffer_size(SOCKET_READ_CHUNK)
        .max_message_size(MAX_SOCKET_BUFFER)
        .max_frame_size(MAX_SOCKET_BUFFER)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            let _user_permit = user_permit;
            run_socket(socket, state, session.user_id, session_token, owner).await;
        })
}

/// Socket upgrades use exactly the same cookie shape and request-wide uniqueness as HTTP auth.
pub(crate) fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    crate::auth::cookies::capability(headers, "__Host-infraternal=")
}

// Plugin work has independent bounded admission; this loop dispatches shared control and terminal frames.
#[allow(clippy::too_many_lines)]
async fn run_socket(
    socket: WebSocket,
    state: Arc<WebSocketState>,
    user_id: String,
    session_token: String,
    owner: bool,
) {
    // One absolute budget covers server Hello, authority reads, client Hello and Resume.
    // Starting a fresh five seconds after a slow initial write would retain admission too long.
    #[cfg(test)]
    let handshake_timeout = state.handshake_timeout;
    #[cfg(not(test))]
    let handshake_timeout = HANDSHAKE_TIMEOUT;
    let handshake_deadline = tokio::time::Instant::now() + handshake_timeout;
    let mut recovery_events = state.auth.recovery_events(&user_id);
    let mut recovery_subscribed = false;
    let mut recovery_snapshot = RecoverySnapshot::Unread;
    let mut session_changes = state.session_changes.subscribe();
    let mut terminal_sessions_subscribed = None;
    let mut revocations = state.auth.revocation_events(&user_id);
    let (mut sink, mut source) = socket.split();
    let mut receive = BytesMut::with_capacity(4096);
    let mut encode = Vec::with_capacity(4096);
    if !matches!(
        tokio::time::timeout_at(
            handshake_deadline,
            while_authorized(
                &state,
                &user_id,
                &session_token,
                false,
                send_frame(
                    &mut sink,
                    CONTROL_STREAM,
                    &Frame::Hello {
                        version: 1,
                        caps: VIEWER_VISIBILITY | TERMINAL_QUERY_REPLIES,
                        client_info: "infraternal-server/0.1",
                    },
                    &mut encode,
                ),
            )
        )
        .await,
        Ok(Ok(()))
    ) {
        return;
    }

    let mut pending_welcome = None;
    let mut resume_attempt = None;
    let handshake = tokio::time::timeout_at(
        handshake_deadline,
        while_authorized_value(
            &state,
            &user_id,
            &session_token,
            false,
            handshake(
                &mut source,
                &mut sink,
                &mut receive,
                &mut encode,
                &state,
                &user_id,
                &session_token,
                &mut pending_welcome,
                &mut resume_attempt,
            ),
        ),
    )
    .await;
    let Ok(Ok((connection_id, proof_authority, link_doubt_notices, viewer_visibility))) = handshake
    else {
        let reason = if resume_attempt.is_some() {
            RESUME_REFUSED
        } else {
            ATTACH_REFUSED
        };
        let _ = tokio::time::timeout(
            CLOSE_TIMEOUT,
            send_frame(
                &mut sink,
                CONTROL_STREAM,
                &Frame::Close {
                    code: 1008,
                    reason: reason.client_text,
                },
                &mut encode,
            ),
        )
        .await;
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, send_message(&mut sink, Message::Close(None)))
            .await;
        drop(sink);
        drop(source);
        if let Some(connection_id) = resume_attempt {
            // After the socket is closed, so a busy database never delays the refusal;
            // bounded, so it never holds the task either. A timeout only loses lines.
            let rows = tokio::time::timeout(
                REFUSAL_LOG_TIMEOUT,
                sqlx::query("SELECT w.client_stream,t.id,t.remote_host_id FROM terminal_writers w JOIN terminal_sessions t ON t.id=w.session_id WHERE w.connection_id=? AND t.user_id=?")
                    .bind(connection_id.as_slice())
                    .bind(&user_id)
                    .fetch_all(&state.pool),
            )
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
            for row in rows {
                let Ok(session_id) = <[u8; 16]>::try_from(row.get::<Vec<u8>, _>("id").as_slice())
                else {
                    continue;
                };
                let host_bytes: Option<Vec<u8>> = row.get("remote_host_id");
                let host_id = host_bytes
                    .as_deref()
                    .and_then(|bytes| uuid::Uuid::from_slice(bytes).ok());
                let stream_id =
                    u32::try_from(row.get::<i64, _>("client_stream")).unwrap_or_default();
                state.close_logs.record(&CloseRecord::new(
                    CloseOwner::of(&user_id),
                    CloseWho::Server,
                    RESUME_REFUSED,
                    host_id,
                    session_id,
                    stream_id,
                ));
            }
        }
        if let Some(welcome) = pending_welcome.take() {
            rollback_connection(&state.pool, &user_id, &welcome).await;
        }
        return;
    };
    // Welcome was sent while authorized; subsequent drops use the normal resume cleanup.
    pending_welcome.take();

    let (output_tx, mut output_rx) =
        mpsc::channel::<(u32, TerminalOutput)>(OUTPUT_CHANNEL_CAPACITY);
    // Poll plugin calls beside inbound frames; dropping this socket drops any unfinished waits.
    // Calls keep polling while this loop authorizes another frame. An in-loop
    // future can hold the only SQLite connection while the loop awaits that same
    // pool; independent tasks avoid that cycle without raising the four-call bound.
    // Shutdown below aborts and joins every call before releasing socket state.
    let mut pending_plugin_calls = tokio::task::JoinSet::<PendingPluginCall>::new();
    let mut plugins = state.plugin_socket(&user_id, &session_token);
    let mut output_open = true;
    // Welcome certifies that the non-renewing proof lease and initial expiry
    // are ready. No initial authority query may race the peer's first idle period.
    let mut expiry = proof_authority.deadline();
    let (mut sink, mut transport) = crate::websocket_transport::Transport::start(
        sink,
        source,
        receive,
        state.clone(),
        user_id.clone(),
        session_token.clone(),
        proof_authority,
        viewer_visibility,
    );
    let mut attachments = HashMap::<u32, ClientAttachment>::new();
    let mut ended = EndedStreams::default();
    let mut loop_result = Ok(());
    let mut teardown_reason = crate::stream_close::SERVER_PROCESSING_FAILED;
    let mut close_already_logged = false;
    // AUTHORITY_UNAVAILABLE is provisional after frame errors; only a typed
    // unavailable result, closed revocation source, or transport end is final.
    let mut authority_unavailable_known = false;
    // Set when teardown already read the session's authority, so the final Close
    // decision reuses that answer instead of reading a second time (#227).
    let mut session_live_at_teardown = None;
    loop {
        transport.active(!attachments.is_empty());
        tokio::select! {
            Some(reply) = plugins.recv() => {
                let Some(wire) = plugins.accept(reply, &mut encode) else {continue;};
                if while_authorized(&state, &user_id, &session_token, true,
                    send_message(&mut sink, Message::Binary(wire))
                ).await.is_err() {break;}
            }
            changed = recovery_events.changed(), if recovery_subscribed => {
                if changed.is_err() { break; }
                if while_authorized(&state, &user_id, &session_token, false,
                    send_recovery_snapshot(&state, &user_id, &mut sink, &mut encode, &mut recovery_snapshot)
                ).await.is_err() { break; }
            }
            changed = session_changes.changed(), if terminal_sessions_subscribed.is_some() => {
                if changed.is_err() { break; }
                if let Some(sub_id) = terminal_sessions_subscribed
                    && while_authorized(&state, &user_id, &session_token, false,
                        send_terminal_sessions_snapshot(&state, &user_id, sub_id, &mut sink, &mut encode)
                    ).await.is_err() { break; }
            }
            changed = revocations.changed() => {
                if changed.is_err() { break; }
                match authority_deadline(&state, &user_id, &session_token, false).await {
                    Ok(deadline) => expiry = deadline,
                    Err(miss) => {
                        // Unproven authority after the bounded retry is server
                        // unavailability; only a known deletion/expiry is refusal.
                        teardown_reason = match miss {
                            AuthorityMiss::Refused => RESUME_REFUSED,
                            AuthorityMiss::Unavailable => {
                                authority_unavailable_known = true;
                                AUTHORITY_UNAVAILABLE
                            }
                        };
                        loop_result = Err(());
                        break;
                    }
                }
            }
            () = tokio::time::sleep_until(expiry) => {
                match authority_deadline(&state, &user_id, &session_token, false).await {
                    Ok(deadline) => expiry = deadline,
                    Err(miss) => {
                        // Unproven authority after the bounded retry is server
                        // unavailability; only a known deletion/expiry is refusal.
                        teardown_reason = match miss {
                            AuthorityMiss::Refused => RESUME_REFUSED,
                            AuthorityMiss::Unavailable => {
                                authority_unavailable_known = true;
                                AUTHORITY_UNAVAILABLE
                            }
                        };
                        loop_result = Err(());
                        break;
                    }
                }
            }
            input = transport.recv() => {
                let Ok(Some(input)) = input else {
                        let end = transport.end_reason();
                        let socket_close = transport.socket_close();
                        let who = if end == crate::websocket_transport::EndReason::ClientWentAway {
                            CloseWho::Browser
                        } else {
                            CloseWho::Server
                        };
                        record_socket_close(
                            &state,
                            &attachments,
                            who,
                            end.close_reason(),
                            socket_close.code,
                            socket_close.reason,
                        );
                        close_already_logged = true;
                        if end != crate::websocket_transport::EndReason::ClientWentAway
                            && end != crate::websocket_transport::EndReason::ServerWriteFailed
                        {
                            let code = match end {
                                crate::websocket_transport::EndReason::SizeLimit => 1009,
                                crate::websocket_transport::EndReason::IdleTimeout => 1001,
                                crate::websocket_transport::EndReason::AuthorizationRefused => 1008,
                                crate::websocket_transport::EndReason::FlowControlRefused
                                | crate::websocket_transport::EndReason::AuthorityUnavailable => 1013,
                                _ => 1002,
                            };
                            let _ = tokio::time::timeout(
                                CLOSE_TIMEOUT,
                                send_frame(
                                    &mut sink,
                                    CONTROL_STREAM,
                                    &Frame::Close {
                                        code,
                                        reason: end.close_reason().client_text,
                                    },
                                    &mut encode,
                                ),
                            )
                            .await;
                        }
                        break;
                };
                match input {
                    Inbound::TransportPing(payload) => {
                        if while_authorized(&state, &user_id, &session_token, true, send_message(&mut sink, Message::Pong(payload))).await.is_err() { break; }
                    }
                    // The transport's read task consumes socket ends and receive
                    // failures itself (it retires the context, logged above); only
                    // frames reach this queue.
                    Inbound::SocketClose { .. } | Inbound::Failure(_) => {}
                    Inbound::Frame(wire) => {
                    if let Ok(decoded) = decode_muxed_frame(&wire)
                        && decoded.stream_id == CONTROL_STREAM
                        && let Frame::Subscribe { sub_id: 45, filter_json } = decoded.frame
                        && serde_json::from_slice::<serde_json::Value>(filter_json).ok()
                            == Some(json!({"topic":"auth.recovery"})) {
                        // Subscribe before reading the snapshot. A concurrent commit
                        // remains visible in the watch generation and cannot be lost.
                        recovery_subscribed = true;
                        recovery_snapshot = RecoverySnapshot::Unread;
                        if while_authorized(&state, &user_id, &session_token, true,
                            send_recovery_snapshot(&state, &user_id, &mut sink, &mut encode, &mut recovery_snapshot)
                        ).await.is_err() { break; }
                        continue;
                    }
                    if let Ok(decoded) = decode_muxed_frame(&wire)
                        && decoded.stream_id == CONTROL_STREAM
                        && let Frame::Subscribe { sub_id, filter_json } = decoded.frame
                        && serde_json::from_slice::<serde_json::Value>(filter_json).ok()
                            == Some(json!({"topic":"terminal.sessions"})) {
                        // Install the watch before reading the snapshot so an intervening update is sent too.
                        terminal_sessions_subscribed = Some(sub_id);
                        if while_authorized(&state, &user_id, &session_token, true,
                            send_terminal_sessions_snapshot(&state, &user_id, sub_id, &mut sink, &mut encode)
                        ).await.is_err() { break; }
                        continue;
                    }
                    if let Ok(decoded) = decode_muxed_frame(&wire)
                        && decoded.stream_id == CONTROL_STREAM
                        && let Frame::Close { code, reason } = decoded.frame {
                        record_control_close(
                            &state,
                            &attachments,
                            code,
                            reason,
                        );
                        close_already_logged = true;
                        let _ = while_authorized(&state, &user_id, &session_token, true, async {
                            send_frame(&mut sink, CONTROL_STREAM,
                                &Frame::Close { code, reason: "connection closed" }, &mut encode).await?;
                            send_message(&mut sink, Message::Close(None)).await
                        }).await;
                        break;
                    }
                    match plugins.dispatch(&wire, &mut encode) {
                        Dispatch::Queued => continue,
                        Dispatch::Refused(wire) => {
                            if while_authorized(&state, &user_id, &session_token, true,
                                send_message(&mut sink,Message::Binary(wire))).await.is_err() {break;}
                            continue;
                        }
                        Dispatch::Unhandled => {}
                    }
                    // Set only when the frame handler itself fails, so a failure of the
                    // wrapper's own authority reads is never blamed on the frame.
                    let mut frame_failed = false;
                    let handled = while_authorized(&state, &user_id, &session_token, true, async {
                        let handled = handle_client_frame(
                            wire,
                            &state,
                            &user_id,
                            &session_token,
                            owner,
                            &mut pending_plugin_calls,
                            &connection_id,
                            &mut attachments,
                            &mut ended,
                            &output_tx,
                            &mut sink,
                            &mut encode,
                        ).await;
                        frame_failed = handled.is_err();
                        handled
                    }).await;
                    if handled.is_err() {
                        // Provisional: a failed frame or a missed wrapper read. Teardown
                        // confirms it with one read, so a refusal or a busy store is
                        // never logged as a bad frame.
                        teardown_reason = if frame_failed { PROTOCOL_ERROR } else { AUTHORITY_UNAVAILABLE };
                            loop_result = Err(());
                            break;
                        }
                    }
                }
            }
            output = output_rx.recv(), if output_open => {
                let Some((stream_id, output)) = output else {
                    output_open = false;
                    continue;
                };
                // Proof replies stay in the host actor. A failed route returns here
                // for two authority gates: the browser notice, then backend rebind.
                let reconnect = matches!(output, TerminalOutput::RouteExpired)
                    .then(|| attachments.get(&stream_id).map(|a| a.handle.clone())).flatten();
                if while_authorized(&state, &user_id, &session_token, true, handle_terminal_output(
                    &state, &user_id, &session_token, &connection_id, stream_id, output,
                    link_doubt_notices, &mut attachments, &mut ended, &mut sink, &mut encode,
                )).await.is_err() { break; }
                if let Some(handle) = reconnect
                    && while_authorized(&state, &user_id, &session_token, true,
                        async { handle.reconnect().await.map_err(|_| ()) }).await.is_err() { break; }

            }
            plugin_call = pending_plugin_calls.join_next(), if !pending_plugin_calls.is_empty() => {
                let Some(Ok((call_id, result))) = plugin_call else { loop_result = Err(()); break; };
                let (ok, json) = match result {
                    Ok(json) => (true, json),
                    Err(AgentError::OpenRefused(reason)) => {
                        let Ok(json) = reason.json() else { break; };
                        (false, json)
                    }
                    Err(_) => (false, br#"{"error":"action unavailable"}"#.to_vec()),
                };
                if while_authorized(&state, &user_id, &session_token, true,
                    send_frame(&mut sink, CONTROL_STREAM,
                        &Frame::Result { call_id, ok, json: &json }, &mut encode)
                ).await.is_err() { break; }
            }
        }
    }
    // A closed account cursor stays closed even if its registry entry is replaced.
    // Share the known-unavailable teardown for recovery, revocation and guarded
    // work exits: source loss must report 1013 without another authority read,
    // preserving the same unavailable outcome as bootstrap/setup sockets (#240 R2-1).
    if revocations.has_changed().is_err()
        || (recovery_subscribed && recovery_events.has_changed().is_err())
    {
        teardown_reason = AUTHORITY_UNAVAILABLE;
        authority_unavailable_known = true;
        loop_result = Err(());
    }
    pending_plugin_calls.shutdown().await;
    drop(plugins);
    if !close_already_logged && !attachments.is_empty() {
        let end = transport.end_reason();
        if end == crate::websocket_transport::EndReason::AuthorityUnavailable {
            authority_unavailable_known = true;
        }
        let reason = if end != crate::websocket_transport::EndReason::Open {
            end.close_reason()
        } else if authority_unavailable_known {
            // The authority outcome is already known unavailable. Preserve its
            // classification and release attached streams without another read.
            AUTHORITY_UNAVAILABLE
        } else if teardown_reason == PROTOCOL_ERROR
            || teardown_reason == AUTHORITY_UNAVAILABLE
            || teardown_reason == crate::stream_close::SERVER_PROCESSING_FAILED
        {
            // These exits are guarded work that failed with the transport still
            // open: its authority read, or the work itself. One bounded read tells
            // a refusal and a busy server from a real failure.
            let (reason, live) =
                failure_reason(&state, &user_id, &session_token, teardown_reason).await;
            session_live_at_teardown = Some(live);
            authority_unavailable_known = reason == AUTHORITY_UNAVAILABLE;
            reason
        } else {
            teardown_reason
        };
        teardown_reason = reason;
        record_socket_close(&state, &attachments, CloseWho::Server, reason, None, None);
    }
    drop(attachments);
    // A known server_busy outcome reports only server status, so it does not
    // need another liveness read. Other close details require confirmed
    // liveness, reusing the close-log read or making one non-renewing attempt.
    if loop_result.is_err() {
        let close_allowed = if authority_unavailable_known {
            true
        } else {
            match session_live_at_teardown {
                Some(live) => live,
                None => match teardown_read(&state, &user_id, &session_token).await {
                    Ok(_) => true,
                    Err(AuthorityMiss::Refused) => false,
                    Err(AuthorityMiss::Unavailable) => {
                        authority_unavailable_known = true;
                        teardown_reason = AUTHORITY_UNAVAILABLE;
                        true
                    }
                },
            }
        };
        if close_allowed {
            let _ = tokio::time::timeout(
                CLOSE_TIMEOUT,
                send_frame(
                    &mut sink,
                    CONTROL_STREAM,
                    &Frame::Close {
                        code: if authority_unavailable_known {
                            1013
                        } else {
                            1011
                        },
                        reason: teardown_reason.client_text,
                    },
                    &mut encode,
                ),
            )
            .await;
        }
    }
    let _ =
        tokio::time::timeout(CLOSE_TIMEOUT, send_message(&mut sink, Message::Close(None))).await;
    // Drop transport before metadata cleanup so a busy SQLite writer cannot retain a revoked socket.
    drop(sink);
    drop(transport);
    let now = unix_seconds().unwrap_or_default();
    let _ = sqlx::query("UPDATE websocket_connections SET active=0, expires_at=? WHERE connection_id=? AND user_id=? AND active=1")
        .bind(now.saturating_add(i64::from(RESUME_WINDOW_SECONDS)))
        .bind(connection_id.as_slice())
        .bind(user_id)
        .execute(&state.pool)
        .await;
}

/// Interrupt pending work on authority loss. Subscribing before the read closes the missed-wakeup window.
/// Checks on the ready branch prevent a late backend reply winning against committed revocation.
pub(super) async fn while_authorized(
    state: &WebSocketState,
    user: &str,
    token: &str,
    renew: bool,
    operation: impl std::future::Future<Output = Result<(), ()>> + Send,
) -> Result<(), ()> {
    // Sharing the watchdog across operation future types bounds transport code
    // size as compiled plugins grow. One short-lived allocation replaces each
    // separate watchdog state machine; operation cancellation stays unchanged.
    while_authorized_operation(state, user, token, renew, operation.boxed()).await
}

/// Keep owned results behind the shared guard until its final authority check.
/// Only value-returning operations need this slot; ordinary frames retain the
/// existing boxed operation's allocation payload and common unit watchdog.
async fn while_authorized_value<T: Send>(
    state: &WebSocketState,
    user: &str,
    token: &str,
    renew: bool,
    operation: impl std::future::Future<Output = Result<T, ()>> + Send,
) -> Result<T, ()> {
    let mut value = None;
    while_authorized(state, user, token, renew, async {
        value = Some(operation.await?);
        Ok(())
    })
    .await?;
    value.ok_or(())
}

async fn while_authorized_operation(
    state: &WebSocketState,
    user: &str,
    token: &str,
    renew: bool,
    operation: infraternal_plugin_api::Operation<'_, Result<(), ()>>,
) -> Result<(), ()> {
    let mut revocations = state.auth.revocation_events(user);
    let mut expiry = authority_deadline(state, user, token, renew)
        .await
        .map_err(|_| ())?;
    let mut check = tokio::time::interval_at(
        tokio::time::Instant::now() + BUSY_AUTHORITY_INTERVAL,
        BUSY_AUTHORITY_INTERVAL,
    );
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::pin!(operation);
    let result = loop {
        tokio::select! {
            biased;
            changed = revocations.changed() => {
                changed.map_err(|_| ())?;
                expiry = socket_deadline(state, user, token).await?;
            }
            () = tokio::time::sleep_until(expiry) => { expiry = socket_deadline(state, user, token).await?; }
            _ = check.tick() => {
                // The operation may own the connection this read needs. Keep
                // polling its owner instead of suspending a transaction while
                // waiting for that same pool. Neither completion nor progress
                // renews the already-started authority read's deadline.
                let recheck = {
                    let authority = socket_deadline(state, user, token);
                    tokio::pin!(authority);
                    tokio::select! {
                        biased;
                        changed = revocations.changed() => {
                            changed.map_err(|_| ())?;
                            true
                        }
                        () = tokio::time::sleep_until(expiry) => true,
                        checked = &mut authority => {
                            expiry = checked?;
                            false
                        }
                        result = &mut operation => {
                            expiry = authority.await?;
                            break result;
                        }
                    }
                };
                // Authority was lost or reached its deadline while a read was
                // in flight. A guarded poll may itself send bytes, so the
                // operation is no longer polled; a late result check cannot
                // undo a write. The in-flight read began before the change and
                // its answer is stale, so it is dropped here (with its permit
                // and pool place) instead of awaited: one fresh read decides,
                // and the socket closes within one bounded wait of the change
                // (#240, review P3-4), not after two back to back.
                if recheck {
                    expiry = socket_deadline(state, user, token).await?;
                }
            }
            result = &mut operation => break result,
        }
    };
    // The entry read authenticates this operation. All production revocations
    // publish after commit, and renewal can only extend expiry. Recheck that
    // generation/deadline without two redundant SQLite reads per fast frame.
    // Backend/persistence boundaries still read actual authority and predicate SQL.
    if revocations.has_changed().map_err(|_| ())? || tokio::time::Instant::now() >= expiry {
        socket_deadline(state, user, token).await?;
    }
    result
}

// Initial subscription must distinguish an unread state from a known absence.
#[derive(PartialEq)]
enum RecoverySnapshot {
    Unread,
    Read(Option<i64>),
}

// Reuse the existing event frame; account scope comes only from socket authority.
async fn send_recovery_snapshot<K>(
    state: &WebSocketState,
    user: &str,
    sink: &mut K,
    encode: &mut Vec<u8>,
    last: &mut RecoverySnapshot,
) -> Result<(), ()>
where
    K: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    let pending = state.auth.pending_recovery(user).await.map_err(|_| ())?;
    // A global wake must never reveal another account's recovery timing.
    if *last == RecoverySnapshot::Read(pending) {
        return Ok(());
    }
    let event = serde_json::to_vec(&json!({"topic":"auth.recovery",
        "pending":pending.map(|ready_at| json!({"ready_at":ready_at}))}))
    .map_err(|_| ())?;
    send_frame(
        sink,
        CONTROL_STREAM,
        &Frame::Event {
            sub_id: 45,
            event_json: &event,
        },
        encode,
    )
    .await?;
    *last = RecoverySnapshot::Read(pending);
    Ok(())
}

/// Send only this account's open rows that the embedded infraternal agent reports live.
async fn send_terminal_sessions_snapshot<K>(
    state: &WebSocketState,
    user: &str,
    sub_id: u32,
    sink: &mut K,
    encode: &mut Vec<u8>,
) -> Result<(), ()>
where
    K: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    let source = state.agent.session_inventory();
    let mut inventory = source.borrow().clone();
    // Unavailability needs no storage. For a census, acquire first and refresh
    // the watch so storage contention cannot leave us publishing an older set.
    let database = if matches!(inventory, SessionInventoryState::Available(_)) {
        let connection = state.pool.acquire().await.map_err(|_| ())?;
        inventory = source.borrow().clone();
        Some(connection)
    } else {
        None
    };
    let event = match (inventory, database) {
        (SessionInventoryState::Pending | SessionInventoryState::Unavailable, _)
        | (SessionInventoryState::Available(_), None) => json!({
            "topic":"terminal.sessions",
            "type":"terminal.sessions.unavailable",
        }),
        (SessionInventoryState::Available(live), Some(mut database)) => {
            let rows: Vec<Vec<u8>> = sqlx::query_scalar(
                "SELECT id FROM terminal_sessions WHERE user_id=? AND remote_host_id IS NULL AND closed_at IS NULL",
            )
            .bind(user)
            .fetch_all(&mut *database)
            .await
            .map_err(|_| ())?;
            let live: HashSet<[u8; 16]> = live.iter().copied().collect();
            let mut session_ids: Vec<String> = rows
                .iter()
                .filter_map(|id| <[u8; 16]>::try_from(id.as_slice()).ok())
                .filter(|id| live.contains(id))
                .map(|id| uuid::Uuid::from_bytes(id).to_string())
                .collect();
            session_ids.sort_unstable();
            let ended_rows: Vec<(Vec<u8>, i64)> = sqlx::query_as(
                "SELECT id,exit_status FROM terminal_sessions WHERE user_id=? AND remote_host_id IS NULL AND closed_at IS NOT NULL AND exit_status IS NOT NULL ORDER BY closed_at DESC,id DESC LIMIT ?",
            )
            .bind(user)
            .bind(MAX_ENDED_SESSION_STATUSES)
            .fetch_all(&mut *database)
            .await
            .map_err(|_| ())?;
            let ended_sessions: Vec<serde_json::Value> = ended_rows
                .into_iter()
                .filter_map(|(id, status)| {
                    let id = <[u8; 16]>::try_from(id.as_slice()).ok()?;
                    let status = i32::try_from(status).ok()?;
                    Some(json!({
                        "session_id": uuid::Uuid::from_bytes(id),
                        "status": status,
                    }))
                })
                .collect();
            json!({
                "topic":"terminal.sessions",
                "type":"terminal.sessions.snapshot",
                "session_ids":session_ids,
                "ended_sessions":ended_sessions,
            })
        }
    };
    let event = serde_json::to_vec(&event).map_err(|_| ())?;
    send_frame(
        sink,
        CONTROL_STREAM,
        &Frame::Event {
            sub_id,
            event_json: &event,
        },
        encode,
    )
    .await
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn handle_terminal_output<K>(
    state: &WebSocketState,
    user_id: &str,
    session_token: &str,
    connection_id: &[u8; 16],
    stream_id: u32,
    output: TerminalOutput,
    link_doubt_notices: bool,
    attachments: &mut HashMap<u32, ClientAttachment>,
    ended: &mut EndedStreams,
    sink: &mut K,
    encode: &mut Vec<u8>,
) -> Result<(), ()>
where
    K: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    let Some(attachment) = attachments.get_mut(&stream_id) else {
        return Ok(());
    };
    let sent = match output {
        TerminalOutput::Output { out_seq, bytes } => {
            let Some(end) = out_seq.checked_add(bytes.len() as u64) else {
                return Err(());
            };
            let Ok(length) = u64::try_from(bytes.len()) else {
                return Err(());
            };
            if out_seq < attachment.last_out_seq {
                return Ok(());
            }
            if out_seq != attachment.last_out_seq {
                attachment.needs_snapshot = true;
                return Ok(());
            }
            if attachment.needs_snapshot || length > attachment.credit {
                attachment.needs_snapshot = true;
                return Ok(());
            }
            state
                .queries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .observe(
                    attachment.session_id,
                    attachment.host_id,
                    out_seq,
                    &bytes,
                    std::time::Instant::now(),
                );
            attachment.credit -= length;
            attachment.last_out_seq = end;
            send_frame(
                sink,
                stream_id,
                &Frame::Output {
                    out_seq,
                    bytes: &bytes,
                },
                encode,
            )
            .await
            .is_ok()
        }
        TerminalOutput::Snapshot { out_seq, bytes } => {
            let Ok(length) = u64::try_from(bytes.len()) else {
                return Err(());
            };
            if out_seq < attachment.last_out_seq || length > attachment.credit {
                attachment.needs_snapshot = true;
                return Ok(());
            }
            attachment.credit -= length;
            attachment.last_out_seq = out_seq;
            attachment.needs_snapshot = false;
            send_frame(
                sink,
                stream_id,
                &Frame::Snapshot {
                    out_seq,
                    bytes: &bytes,
                },
                encode,
            )
            .await
            .is_ok()
        }
        TerminalOutput::Event { event_json } => {
            let ended = crate::terminal_exit::record(
                &state.pool,
                user_id,
                session_token,
                &attachment.session_id,
                attachment.last_out_seq,
                &event_json,
            )
            .await?;
            if ended {
                state
                    .queries
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .retire(attachment.session_id);
                state.sessions_changed();
            }
            send_frame(
                sink,
                stream_id,
                &Frame::Event {
                    sub_id: 0,
                    event_json: &event_json,
                },
                encode,
            )
            .await
            .is_ok()
        }
        TerminalOutput::Reconnecting
        | TerminalOutput::RouteExpired
        | TerminalOutput::LinkDoubt
        | TerminalOutput::Recovered => {
            let Some((kind, awaits_ack)) = link_notice(&output, link_doubt_notices) else {
                return Ok(());
            };
            // Only a lost route is a close worth logging; a doubted link is kept (D300).
            let reason = match output {
                TerminalOutput::RouteExpired => Some(TERMINAL_ROUTE_IDLE),
                TerminalOutput::Reconnecting => Some(AGENT_CONNECTION_DROPPED),
                _ => None,
            };
            if let Some(reason) = reason {
                state.close_logs.record(&attachment.close_record(
                    stream_id,
                    CloseWho::InfraternalAgent,
                    reason,
                ));
            }
            attachment.awaiting_ack |= awaits_ack;
            let session_id = uuid::Uuid::from_bytes(attachment.session_id).to_string();
            let notice = match reason {
                Some(reason) => {
                    json!({"type": kind, "session_id": session_id, "reason": reason.client_text})
                }
                None => json!({"type": kind, "session_id": session_id}),
            };
            let notice = serde_json::to_vec(&notice).map_err(|_| ())?;
            send_frame(
                sink,
                stream_id,
                &Frame::Event {
                    sub_id: 0,
                    event_json: &notice,
                },
                encode,
            )
            .await
            .is_ok()
        }
        TerminalOutput::Ack { in_seq_acked } => {
            if in_seq_acked < attachment.last_in_acked
                || (!attachment.awaiting_ack && in_seq_acked > attachment.input_sent_end)
            {
                return Err(());
            }
            attachment.awaiting_ack = false;
            attachment.input_sent_end = attachment.input_sent_end.max(in_seq_acked);
            attachment.last_in_acked = in_seq_acked;
            // Each device acknowledges only its durable writer range. The old
            // session column is retained for diagnostics, never new input authority.
            let changed = sqlx::query("UPDATE terminal_writers SET input_acked=? WHERE connection_id=? AND client_stream=? AND session_id=? AND input_acked<=? AND EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>unixepoch())")
                .bind(in_seq_acked.to_be_bytes().as_slice()).bind(connection_id.as_slice()).bind(stream_id)
                .bind(attachment.session_id.as_slice()).bind(in_seq_acked.to_be_bytes().as_slice())
                .bind(crate::auth::hash(session_token)).bind(user_id).execute(&state.pool).await;
            if !matches!(changed, Ok(result) if result.rows_affected() == 1) {
                return Err(());
            }
            let legacy_acked = i64::try_from(in_seq_acked).unwrap_or(-1);
            let acked_u64 = in_seq_acked.to_be_bytes();
            let Ok(now) = unix_seconds() else {
                return Err(());
            };
            let result = sqlx::query("UPDATE terminal_sessions SET input_acked_u64=CASE WHEN input_acked_u64<? THEN ? ELSE input_acked_u64 END, input_acked=CASE WHEN ?>=0 THEN MAX(input_acked,?) ELSE input_acked END, last_seen=? WHERE id=? AND user_id=? AND EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>unixepoch())")
                .bind(acked_u64.as_slice())
                .bind(acked_u64.as_slice())
                .bind(legacy_acked)
                .bind(legacy_acked)
                .bind(now)
                .bind(attachment.session_id.as_slice())
                .bind(user_id)
                .bind(crate::auth::hash(session_token)).bind(user_id)
                .execute(&state.pool)
                .await;
            if !matches!(result, Ok(result) if result.rows_affected() == 1) {
                return Err(());
            }
            if !session_is_live(state, user_id, session_token).await {
                return Err(());
            }
            send_frame(sink, stream_id, &Frame::Ack { in_seq_acked }, encode)
                .await
                .is_ok()
        }
        TerminalOutput::Closed { who, code, reason } => {
            // The host's infraternal agent found no shim for the session: a final
            // answer, distinct from every transient close (wire §4, #158).
            let gone = code == CLOSE_SESSION_GONE;
            if gone {
                state
                    .queries
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .retire(attachment.session_id);
            }
            let reason = if gone { SESSION_GONE_REASON } else { reason };
            let close_reason = classify_terminal_close(reason);
            let mut close = attachment.close_record(stream_id, who, close_reason);
            close.agent_close_code = Some(code);
            close.agent_close_reason = Some(reason);
            state.close_logs.record(&close);
            let sent = send_frame(sink, stream_id, &Frame::Close { code, reason }, encode)
                .await
                .is_ok();
            attachments.remove(&stream_id);
            // Every host close races frames already queued by the browser,
            // including the initial Credit/Resize. Absorb them until Close or
            // reattach, just as for a final close, without losing sibling streams.
            ended.insert(stream_id)?;
            sent
        }
    };
    if !sent {
        return Err(());
    }
    Ok(())
}

/// The browser notice for a host-link state change, and whether the stream
/// now awaits a fresh Ack. A replaced link replays, so its stream waits for the
/// replacement's Ack. A doubted link is kept: the viewer only shows an
/// indicator and keeps live replies and input flowing, so neither doubt nor
/// recovery relaxes the Ack check, and recovery is never a replay fence.
/// Viewers that did not announce `LINK_DOUBT_NOTICES` get no doubt notice
/// [D300, #234].
fn link_notice(output: &TerminalOutput, link_doubt_notices: bool) -> Option<(&'static str, bool)> {
    match output {
        TerminalOutput::Reconnecting | TerminalOutput::RouteExpired => {
            Some(("terminal.reconnecting", true))
        }
        TerminalOutput::LinkDoubt => link_doubt_notices.then_some(("terminal.link_doubt", false)),
        TerminalOutput::Recovered => {
            link_doubt_notices.then_some(("terminal.link_recovered", false))
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn handshake<S, K>(
    source: &mut S,
    sink: &mut K,
    receive: &mut BytesMut,
    encode: &mut Vec<u8>,
    state: &WebSocketState,
    user_id: &str,
    session_token: &str,
    pending_welcome: &mut Option<Welcome>,
    resume_attempt: &mut Option<[u8; 16]>,
) -> Result<([u8; 16], probe_authority::Lease, bool, bool), ()>
where
    S: Stream<Item = Result<Message, axum::Error>> + Unpin,
    K: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    let hello = next_wire(source, sink, receive).await?.ok_or(())?;
    socket_deadline(state, user_id, session_token).await?;
    let decoded = decode_muxed_frame(&hello).map_err(|_| ())?;
    let (resume, link_doubt_notices, viewer_visibility, layout_session) =
        match (decoded.stream_id, decoded.frame) {
            (
                CONTROL_STREAM,
                Frame::Hello {
                    version: 1, caps, ..
                },
            ) => (
                caps & RESUME_NEXT != 0,
                caps & LINK_DOUBT_NOTICES != 0,
                caps & VIEWER_VISIBILITY != 0,
                caps & 16 != 0,
            ),
            _ => return Err(()),
        };
    let welcome = if resume {
        let request = next_wire(source, sink, receive).await?.ok_or(())?;
        socket_deadline(state, user_id, session_token).await?;
        let decoded = decode_muxed_frame(&request).map_err(|_| ())?;
        let (id, token) = match (decoded.stream_id, decoded.frame) {
            (
                CONTROL_STREAM,
                Frame::Resume {
                    connection_id,
                    resume_token,
                },
            ) => (*connection_id, *resume_token),
            _ => return Err(()),
        };
        *resume_attempt = Some(id);
        resume_connection(
            &state.pool,
            user_id,
            id,
            token,
            unix_seconds()?,
            Some(&crate::auth::hash(session_token)),
            Some(pending_welcome),
        )
        .await
        .map_err(|_| ())?
    } else {
        new_connection(
            &state.pool,
            user_id,
            unix_seconds()?,
            Some(&crate::auth::hash(session_token)),
            Some(pending_welcome),
        )
        .await
        .map_err(|_| ())?
    };
    // Retain rollback metadata outside the cancelled future, including the previous Resume token.
    *pending_welcome = Some(welcome);
    let welcome = pending_welcome.as_ref().ok_or(())?;
    // Subscribe and finish the initial authority read before sending Welcome.
    // The shared loop reuses this exact absolute expiry without another SQL read.
    let proof_authority = probe_authority::Lease::new(state, user_id, session_token).await?;
    let incarnation = crate::auth::session_incarnation(session_token);
    if send_frame(
        sink,
        CONTROL_STREAM,
        &Frame::Welcome {
            connection_id: &welcome.connection_id,
            resume_token: &welcome.resume_token,
            resume_window_seconds: RESUME_WINDOW_SECONDS,
            session_incarnation: layout_session.then_some(incarnation.as_str()),
        },
        encode,
    )
    .await
    .is_err()
    {
        return Err(());
    }
    Ok((
        welcome.connection_id,
        proof_authority,
        link_doubt_notices,
        viewer_visibility,
    ))
}

#[derive(Clone)]
struct Welcome {
    connection_id: [u8; 16],
    resume_token: [u8; 32],
    previous_token_hash: Option<[u8; 32]>,
    previous_expiry: Option<i64>,
}

async fn new_connection(
    pool: &SqlitePool,
    user_id: &str,
    now: i64,
    authority: Option<&str>,
    pending_welcome: Option<&mut Option<Welcome>>,
) -> Result<Welcome, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("DELETE FROM websocket_connections WHERE active=0 AND expires_at<?")
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    require_socket_authority_tx(&mut transaction, user_id, authority).await?;
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM websocket_connections WHERE user_id=? AND active=1",
    )
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await?;
    if active >= 16 {
        return Err(sqlx::Error::Protocol("connection limit reached".into()));
    }
    let retained: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM websocket_connections WHERE active=1 OR expires_at>=?",
    )
    .bind(now)
    .fetch_one(&mut *transaction)
    .await?;
    if retained >= MAX_RESUME_ROWS {
        return Err(sqlx::Error::Protocol("resume capacity reached".into()));
    }
    let welcome = Welcome {
        connection_id: random(),
        resume_token: random(),
        previous_token_hash: None,
        previous_expiry: None,
    };
    // Stage before the SQL write/commit await: cancellation can outlive SQLx's worker command.
    if let Some(pending) = pending_welcome {
        *pending = Some(welcome.clone());
    }
    let token_hash = token_hash(&welcome.resume_token);
    sqlx::query("INSERT INTO websocket_connections(connection_id,token_hash,user_id,created_at,expires_at,active) VALUES (?,?,?,?,NULL,1)")
        .bind(welcome.connection_id.as_slice())
        .bind(token_hash.as_slice())
        .bind(user_id)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    require_socket_authority_tx(&mut transaction, user_id, authority).await?;
    transaction.commit().await?;
    Ok(welcome)
}

async fn resume_connection(
    pool: &SqlitePool,
    user_id: &str,
    connection_id: [u8; 16],
    token: [u8; 32],
    now: i64,
    authority: Option<&str>,
    pending_welcome: Option<&mut Option<Welcome>>,
) -> Result<Welcome, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    // Lock before reading auth/resume state: logout cannot commit between validation and rotation.
    sqlx::query("UPDATE websocket_connections SET created_at=created_at WHERE connection_id=?")
        .bind(connection_id.as_slice())
        .execute(&mut *transaction)
        .await?;
    require_socket_authority_tx(&mut transaction, user_id, authority)
        .await
        .inspect_err(|_| log_resume_refusal("session_authority"))?;
    let row = sqlx::query("SELECT token_hash,expires_at FROM websocket_connections WHERE connection_id=? AND user_id=? AND active=0 AND expires_at>=?")
        .bind(connection_id.as_slice())
        .bind(user_id)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(row) = row else {
        // Diagnose only fixed state categories, inside the existing writer lock.
        // Never read or print capability bytes for diagnostics; ownership remains
        // enforced by the original admission query above.
        let check: Option<String> = sqlx::query_scalar("SELECT CASE WHEN user_id != ? THEN 'connection_owner' WHEN active != 0 THEN 'connection_active' WHEN expires_at < ? THEN 'resume_expired' ELSE 'connection_state' END FROM websocket_connections WHERE connection_id=?")
            .bind(user_id).bind(now).bind(connection_id.as_slice())
            .fetch_optional(&mut *transaction).await?;
        let check = match check.as_deref() {
            Some("connection_owner") => "connection_owner",
            Some("connection_active") => "connection_active",
            Some("resume_expired") => "resume_expired",
            Some(_) => "connection_state",
            None => "connection_missing",
        };
        return Err(resume_refused(check));
    };
    let stored: Vec<u8> = row.get("token_hash");
    let previous_expiry: i64 = row.get("expires_at");
    let requested_hash = token_hash(&token);
    if stored.len() != 32 || !openssl::memcmp::eq(&stored, &requested_hash) {
        return Err(resume_refused("token_mismatch"));
    }
    let previous_token_hash: [u8; 32] = stored
        .try_into()
        .map_err(|_| resume_refused("token_shape"))?;
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM websocket_connections WHERE user_id=? AND active=1",
    )
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await?;
    if active >= 16 {
        return Err(resume_refused("connection_capacity"));
    }
    let welcome = Welcome {
        connection_id,
        resume_token: random(),
        previous_token_hash: Some(previous_token_hash),
        previous_expiry: Some(previous_expiry),
    };
    // Previous token metadata must survive cancellation while rotation/commit is pending.
    if let Some(pending) = pending_welcome {
        *pending = Some(welcome.clone());
    }
    let rotated_hash = token_hash(&welcome.resume_token);
    let changed = sqlx::query("UPDATE websocket_connections SET token_hash=?, active=1, expires_at=NULL WHERE connection_id=? AND user_id=? AND active=0 AND expires_at>=?")
        .bind(rotated_hash.as_slice())
        .bind(connection_id.as_slice())
        .bind(user_id)
        .bind(now)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
    if changed != 1 {
        return Err(resume_refused("rotation_conflict"));
    }
    require_socket_authority_tx(&mut transaction, user_id, authority)
        .await
        .inspect_err(|_| log_resume_refusal("session_authority"))?;
    transaction.commit().await?;
    Ok(welcome)
}

/// Fixed diagnostic categories only: clients retain the generic refusal and
/// administrators can distinguish expiry, overlap and a lost rotation (#244).
fn resume_refused(check: &'static str) -> sqlx::Error {
    log_resume_refusal(check);
    sqlx::Error::Protocol(check.into())
}

fn log_resume_refusal(check: &'static str) {
    tracing::info!(
        event = "connection_resume_refused",
        check,
        "connection resume check refused"
    );
}

async fn rollback_connection(pool: &SqlitePool, user_id: &str, welcome: &Welcome) {
    if let Some(previous_hash) = welcome.previous_token_hash {
        let _ = sqlx::query("UPDATE websocket_connections SET token_hash=?, active=0, expires_at=? WHERE connection_id=? AND user_id=? AND active=1 AND token_hash=?")
            .bind(previous_hash.as_slice())
            .bind(welcome.previous_expiry.unwrap_or_default())
            .bind(welcome.connection_id.as_slice())
            .bind(user_id)
            .bind(token_hash(&welcome.resume_token).as_slice())
            .execute(pool)
            .await;
    } else {
        let _ = sqlx::query(
            "DELETE FROM websocket_connections WHERE connection_id=? AND user_id=? AND active=1 AND token_hash=?",
        )
        .bind(welcome.connection_id.as_slice())
        .bind(user_id)
        .bind(token_hash(&welcome.resume_token).as_slice())
        .execute(pool)
        .await;
    }
}

fn token_hash(token: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(token).into()
}

// Each browser frame is validated here and routed without allocating a second terminal payload.
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
async fn handle_client_frame<K>(
    wire: Bytes,
    state: &WebSocketState,
    user_id: &str,
    session_token: &str,
    owner: bool,
    pending_plugin_calls: &mut tokio::task::JoinSet<PendingPluginCall>,
    connection_id: &[u8; 16],
    attachments: &mut HashMap<u32, ClientAttachment>,
    ended: &mut EndedStreams,
    output_tx: &mpsc::Sender<(u32, TerminalOutput)>,
    sink: &mut K,
    encode: &mut Vec<u8>,
) -> Result<(), ()>
where
    K: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    let decoded = decode_muxed_frame(&wire).map_err(|_| ())?;
    let stream_id = decoded.stream_id;
    let passthrough = wire.clone();
    if ended.absorbs(stream_id, &decoded.frame)? {
        return Ok(());
    }
    // The surrounding watchdog authenticates every frame, including attach, input and credit.
    match decoded.frame {
        Frame::Ping { nonce, sent_us } if stream_id == CONTROL_STREAM => {
            #[cfg(test)]
            addhost_timeline("control_ping");
            send_frame(
                sink,
                CONTROL_STREAM,
                &Frame::Pong { nonce, sent_us },
                encode,
            )
            .await
        }
        Frame::Call {
            call_id,
            action_id: action_id @ ("terminal.open" | "ssh.session.open"),
            input_json,
        } if stream_id == CONTROL_STREAM => {
            let request = if action_id == "ssh.session.open" {
                serde_json::from_slice::<BrowserTerminalOpen>(input_json)
                    .ok()
                    .map(|input| {
                        (
                            TerminalOpen {
                                cols: 80,
                                rows: 24,
                                px_w: 0,
                                px_h: 0,
                            },
                            input.host_id,
                        )
                    })
            } else {
                serde_json::from_slice::<TerminalOpen>(input_json)
                    .ok()
                    .map(|size| (size, None))
            };
            let valid = request.as_ref().is_some_and(|(size, _)| size.valid());
            if let Some((size, host)) = request.filter(|(size, _)| size.valid())
                && pending_plugin_calls.len() < MAX_PENDING_PLUGIN_CALLS
            {
                let state = state.clone();
                let user = user_id.to_owned();
                let token = session_token.to_owned();
                let browser_action = action_id == "ssh.session.open";
                // Opening a PTY may wait for a remote login. Poll it alongside route
                // proofs, input and revocation; never suspend the multiplexed receive loop.
                // The existing bounded call queue owns cancellation on socket teardown.
                pending_plugin_calls.spawn(async move {
                    let result = while_authorized_value(&state, &user, &token, false, async {
                        Ok(open_terminal(&state, &user, &token, size, host).await)
                    })
                    .await
                    .unwrap_or(Err(AgentError::Unavailable));
                    let result = result
                        .map_err(|error| match error {
                            AgentError::OpenRefused(_) => error,
                            _ => AgentError::OpenRefused(
                                infraternal_plugin_api::admission::OpenRefusal::Unavailable,
                            ),
                        })
                        .and_then(|session| {
                            let session_id = if browser_action {
                                uuid::Uuid::from_bytes(session).to_string()
                            } else {
                                encode_session_id(&session)
                            };
                            serde_json::to_vec(&json!({"session_id": session_id}))
                                .map_err(|_| AgentError::Unavailable)
                        });
                    (call_id, result)
                });
                return Ok(());
            }
            let refusal = if valid {
                infraternal_plugin_api::admission::OpenRefusal::Unavailable
            } else {
                infraternal_plugin_api::admission::OpenRefusal::Invalid
            };
            let json = refusal.json().map_err(|_| ())?;
            send_frame(
                sink,
                CONTROL_STREAM,
                &Frame::Result {
                    call_id,
                    ok: false,
                    json: &json,
                },
                encode,
            )
            .await
        }
        Frame::Call {
            call_id,
            action_id: "terminal.startup",
            input_json,
        } if stream_id == CONTROL_STREAM
            && input_json.len() <= 8192
            && pending_plugin_calls.len() < MAX_PENDING_PLUGIN_CALLS =>
        {
            let state = state.clone();
            let user = user_id.to_owned();
            let token = session_token.to_owned();
            let input = input_json.to_vec();
            pending_plugin_calls.spawn(async move {
                let result = while_authorized_value(&state, &user, &token, false, async {
                    Ok(startup_call(&state, &user, &input).await)
                })
                .await
                .unwrap_or(Err(AgentError::Unavailable));
                (call_id, result)
            });
            Ok(())
        }
        Frame::Call {
            call_id,
            action_id,
            input_json,
        } if stream_id == CONTROL_STREAM => {
            let action = state.action(action_id);
            // Node-side actions retain their owner-only grant source. Mesh tag roles
            // authorize Mesh operations, never host-wide reads or configuration.
            // A valid unlocked session alone must not forward work to leg B.
            let authorized = action_id.len() <= 128
                && input_json.len() <= infraternal_plugin_api::MAX_ACTION_BYTES
                && action.is_some_and(|action| {
                    owner
                        && match action.permission {
                            Permission::One(permission) => !permission.is_empty(),
                            Permission::Any(permissions) => !permissions.is_empty(),
                        }
                });
            if authorized && pending_plugin_calls.len() < MAX_PENDING_PLUGIN_CALLS {
                let agent = state.agent.clone();
                let action_id = action_id.to_owned();
                let input_json = input_json.to_vec();
                pending_plugin_calls.spawn(async move {
                    let result =
                        tokio::time::timeout(BACKEND_TIMEOUT, agent.call(action_id, input_json))
                            .await
                            .unwrap_or(Err(AgentError::Unavailable));
                    (call_id, result)
                });
                return Ok(());
            }
            let result = Err(AgentError::Rejected);
            if !session_is_live(state, user_id, session_token).await {
                return Err(());
            }
            let (ok, json) = match result {
                Ok(json) => (true, json),
                Err(_) => (false, br#"{"error":"action unavailable"}"#.to_vec()),
            };
            send_frame(
                sink,
                CONTROL_STREAM,
                &Frame::Result {
                    call_id,
                    ok,
                    json: &json,
                },
                encode,
            )
            .await
        }
        Frame::AttachTerm {
            session_id,
            last_out_seq,
            last_in_seq,
        } if stream_id != 0 && stream_id % 2 == 1 => {
            #[cfg(test)]
            addhost_timeline("attach_received");
            if attachments.contains_key(&stream_id) || attachments.len() >= MAX_ATTACHMENTS {
                return Err(());
            }
            let mut session = [0_u8; 16];
            session.copy_from_slice(session_id);
            // `None`: this account has no record of the session. The id is the client's
            // choice and may be another account's, so no line ever names it (#227).
            let Ok(owned_host) = session_host_id(&state.pool, user_id, &session).await else {
                // The store could not answer; the browser's frame was well formed.
                state.close_logs.record(&CloseRecord::new(
                    CloseOwner::of(user_id),
                    CloseWho::Server,
                    AUTHORITY_UNAVAILABLE,
                    None,
                    NO_SESSION,
                    stream_id,
                ));
                return Err(());
            };
            let logged_session = if owned_host.is_some() {
                session
            } else {
                NO_SESSION
            };
            let host_id = owned_host.flatten();
            let Ok((input_acked, writer_stream)) = owned_writer(
                &state.pool,
                user_id,
                connection_id,
                stream_id,
                &session,
                Some(&crate::auth::hash(session_token)),
            )
            .await
            else {
                // A session that ended, or one this account never had, gets the final
                // stream Close instead of losing the whole socket: the browser would
                // reconnect and attach again at once, forever (#158). Every other
                // refusal (authority, the writer limit, the database) still closes it.
                let authority = authority_read(state, user_id, session_token).await;
                if authority == AuthorityRead::Live
                    && session_gone(&state.pool, user_id, &session).await?
                {
                    let close = if owned_host.is_some() {
                        let mut close = CloseRecord::new(
                            CloseOwner::of(user_id),
                            CloseWho::Server,
                            AGENT_STREAM_ENDED,
                            host_id,
                            session,
                            stream_id,
                        );
                        close.out_seq = last_out_seq;
                        close.input_sent = last_in_seq;
                        close
                    } else {
                        CloseRecord::new(
                            CloseOwner::of(user_id),
                            CloseWho::Browser,
                            ATTACH_UNOWNED,
                            None,
                            NO_SESSION,
                            stream_id,
                        )
                    };
                    state.close_logs.record(&close);
                    ended.insert(stream_id)?;
                    let gone = Frame::Close {
                        code: CLOSE_SESSION_GONE,
                        reason: SESSION_GONE_REASON,
                    };
                    return send_frame(sink, stream_id, &gone, encode).await;
                }
                // A read that missed its bound is a busy server, not a refused attach.
                let refusal = attach_refusal(authority);
                let mut close = CloseRecord::new(
                    CloseOwner::of(user_id),
                    CloseWho::Server,
                    refusal,
                    host_id,
                    logged_session,
                    stream_id,
                );
                close.out_seq = last_out_seq;
                close.input_sent = last_in_seq;
                return close_terminal_stream(
                    state,
                    TerminalClose {
                        record: close,
                        code: 1008,
                    },
                    attachments,
                    ended,
                    sink,
                    encode,
                )
                .await;
            };
            if last_in_seq > input_acked {
                let mut close = CloseRecord::new(
                    CloseOwner::of(user_id),
                    CloseWho::Server,
                    PROTOCOL_ERROR,
                    host_id,
                    session,
                    stream_id,
                );
                close.out_seq = last_out_seq;
                close.input_acked = input_acked;
                close.input_sent = last_in_seq;
                state.close_logs.record(&close);
                return Err(());
            }
            let authority = authority_read(state, user_id, session_token).await;
            if authority != AuthorityRead::Live {
                let refusal = attach_refusal(authority);
                let mut close = CloseRecord::new(
                    CloseOwner::of(user_id),
                    CloseWho::Server,
                    refusal,
                    host_id,
                    session,
                    stream_id,
                );
                close.out_seq = last_out_seq;
                close.input_acked = input_acked;
                close.input_sent = last_in_seq;
                state.close_logs.record(&close);
                return Err(());
            }
            let Ok(agent) = terminal_agent(state, user_id, host_id).await else {
                let mut close = CloseRecord::new(
                    CloseOwner::of(user_id),
                    CloseWho::Server,
                    AGENT_CONNECTION_REFUSED,
                    host_id,
                    session,
                    stream_id,
                );
                close.out_seq = last_out_seq;
                close.input_acked = input_acked;
                close.input_sent = last_in_seq;
                return close_terminal_stream(
                    state,
                    TerminalClose {
                        record: close,
                        code: 1013,
                    },
                    attachments,
                    ended,
                    sink,
                    encode,
                )
                .await;
            };
            #[cfg(test)]
            addhost_timeline("attach_agent_resolved");
            let Ok(Ok(attachment)) = tokio::time::timeout(
                BACKEND_TIMEOUT,
                agent.attach_monitored(session, last_out_seq, input_acked, writer_stream),
            )
            .await
            else {
                let mut close = CloseRecord::new(
                    CloseOwner::of(user_id),
                    CloseWho::InfraternalAgent,
                    AGENT_CONNECTION_REFUSED,
                    host_id,
                    session,
                    stream_id,
                );
                close.out_seq = last_out_seq;
                close.input_acked = input_acked;
                close.input_sent = last_in_seq;
                return close_terminal_stream(
                    state,
                    TerminalClose {
                        record: close,
                        code: 1013,
                    },
                    attachments,
                    ended,
                    sink,
                    encode,
                )
                .await;
            };
            #[cfg(test)]
            addhost_timeline("attach_sent");
            let authority = authority_read(state, user_id, session_token).await;
            if authority != AuthorityRead::Live {
                let refusal = attach_refusal(authority);
                let mut close = CloseRecord::new(
                    CloseOwner::of(user_id),
                    CloseWho::Server,
                    refusal,
                    host_id,
                    session,
                    stream_id,
                );
                close.out_seq = last_out_seq;
                close.input_acked = input_acked;
                close.input_sent = last_in_seq;
                state.close_logs.record(&close);
                return Err(());
            }
            let (handle, mut output) = attachment.split();
            attachments.insert(
                stream_id,
                ClientAttachment {
                    input: crate::websocket_input::InputQueue::new(
                        handle.clone(),
                        stream_id,
                        output_tx.clone(),
                    ),
                    handle,
                    session_id: session,
                    host_id,
                    owner: CloseOwner::of(user_id),
                    last_out_seq,
                    last_in_acked: input_acked,
                    input_sent_end: input_acked,
                    credit: 0,
                    awaiting_ack: true,
                    needs_snapshot: false,
                },
            );
            let sender = output_tx.clone();
            tokio::spawn(async move {
                while let Some(event) = output.recv().await {
                    if sender.send((stream_id, event)).await.is_err() {
                        return;
                    }
                }
                // An isolated slow attachment closes its browser stream explicitly so the
                // client reconnects from delivered offsets instead of waiting silently.
                let _ = sender
                    .send((
                        stream_id,
                        TerminalOutput::Closed {
                            who: CloseWho::InfraternalAgent,
                            code: 1013,
                            reason: "attachment ended",
                        },
                    ))
                    .await;
            });
            send_frame(
                sink,
                stream_id,
                &Frame::Ack {
                    in_seq_acked: input_acked,
                },
                encode,
            )
            .await
        }
        Frame::Close { code, reason } if stream_id != 0 && stream_id % 2 == 1 => {
            let attachment = attachments.remove(&stream_id).ok_or(())?;
            let mut close = attachment.close_record(stream_id, CloseWho::Browser, CLIENT_WENT_AWAY);
            close.browser_stream_close_code = Some(code);
            close.browser_stream_close_reason = Some(safe_agent_close_reason(reason));
            state.close_logs.record(&close);
            Ok(())
        }
        Frame::InputReply { query_seq, bytes } if stream_id != 0 && stream_id % 2 == 1 => {
            let attachment = attachments.get(&stream_id).ok_or(())?;
            let expires = state
                .queries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .claim(
                    attachment.session_id,
                    query_seq,
                    bytes,
                    std::time::Instant::now(),
                );
            if let Some(expires) = expires
                && !attachment
                    .input
                    .reply(query_seq, Bytes::copy_from_slice(bytes), expires)
            {
                crate::terminal_queries::record_drop();
            }
            Ok(())
        }
        Frame::Input { in_seq, bytes } if stream_id != 0 && stream_id % 2 == 1 => {
            let attachment = attachments.get_mut(&stream_id).ok_or(())?;
            let end = in_seq
                .checked_add(u64::try_from(bytes.len()).map_err(|_| ())?)
                .ok_or(())?;
            if in_seq > attachment.input_sent_end {
                return Err(());
            }
            if end <= attachment.last_in_acked {
                return Ok(());
            }
            attachment.input_sent_end = attachment.input_sent_end.max(end);
            if attachment.input.enqueue(passthrough).is_ok() {
                return Ok(());
            }
            retire_input_stream(state, stream_id, attachments, ended, sink, encode).await
        }
        Frame::Resize {
            cols,
            rows,
            px_w,
            px_h,
        } if stream_id != 0 && stream_id % 2 == 1 => {
            let attachment = attachments.get(&stream_id).ok_or(())?;
            if cols == 0 || cols > 500 || rows == 0 || rows > 300 || px_w > 16_384 || px_h > 16_384
            {
                return Err(());
            }
            if attachment.input.enqueue(passthrough).is_ok() {
                return Ok(());
            }
            retire_input_stream(state, stream_id, attachments, ended, sink, encode).await
        }
        Frame::Credit { bytes } if stream_id != 0 && stream_id % 2 == 1 => {
            let refused = {
                let attachment = attachments.get_mut(&stream_id).ok_or(())?;
                if let Some(credit) = attachment.credit.checked_add(u64::from(bytes))
                    && credit <= MAX_CREDIT
                {
                    attachment.credit = credit;
                    return attachment
                        .handle
                        .send_frame(passthrough)
                        .await
                        .map_err(|_| ());
                }
                true
            };
            debug_assert!(refused);
            let close = attachments.get(&stream_id).ok_or(())?.close_record(
                stream_id,
                CloseWho::Server,
                CREDIT_REFUSED,
            );
            close_terminal_stream(
                state,
                TerminalClose {
                    record: close,
                    code: 1013,
                },
                attachments,
                ended,
                sink,
                encode,
            )
            .await
        }
        _ => Err(()),
    }
}

struct TerminalClose {
    record: CloseRecord,
    code: u16,
}

/// Log a terminal close once, retire its local attachment, and notify the browser.
async fn close_terminal_stream<K>(
    state: &WebSocketState,
    close: TerminalClose,
    attachments: &mut HashMap<u32, ClientAttachment>,
    ended: &mut EndedStreams,
    sink: &mut K,
    encode: &mut Vec<u8>,
) -> Result<(), ()>
where
    K: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    if close.code == CLOSE_SESSION_GONE {
        state
            .queries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retire(close.record.session_id);
    }
    let stream_id = close.record.browser_stream_id;
    let reason = close.record.reason.client_text;
    attachments.remove(&stream_id);
    state.close_logs.record(&close.record);
    ended.insert(stream_id)?;
    send_frame(
        sink,
        stream_id,
        &Frame::Close {
            code: close.code,
            reason,
        },
        encode,
    )
    .await
}

/// FIFO overload retires only its stream; trailing Input/Resize/Credit are
/// absorbed until explicit reattach, preserving control and sibling dispatch.
async fn retire_input_stream<K>(
    state: &WebSocketState,
    stream: u32,
    attachments: &mut HashMap<u32, ClientAttachment>,
    ended: &mut EndedStreams,
    sink: &mut K,
    encode: &mut Vec<u8>,
) -> Result<(), ()>
where
    K: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    let close = attachments.get(&stream).ok_or(())?.close_record(
        stream,
        CloseWho::Server,
        INPUT_QUEUE_FULL,
    );
    close_terminal_stream(
        state,
        TerminalClose {
            record: close,
            code: 1013,
        },
        attachments,
        ended,
        sink,
        encode,
    )
    .await
}

/// Deadline and revocation checks are event-driven; idle sockets do no repeated database work.
#[path = "websocket_probe_authority.rs"]
pub(super) mod probe_authority;

/// Server-generated proofs reuse a non-renewing absolute deadline; SQL delay cannot extend it.
pub(super) async fn probe_deadline(
    state: &WebSocketState,
    user: &str,
    token: &str,
) -> Result<tokio::time::Instant, AuthorityMiss> {
    authority_deadline(state, user, token, false).await
}

async fn socket_deadline(
    state: &WebSocketState,
    user_id: &str,
    token: &str,
) -> Result<tokio::time::Instant, ()> {
    authority_deadline(state, user_id, token, false)
        .await
        .map_err(|_| ())
}

async fn authority_deadline(
    state: &WebSocketState,
    user_id: &str,
    token: &str,
    renew: bool,
) -> Result<tokio::time::Instant, AuthorityMiss> {
    let expiry = read_expiry(state, user_id, token, renew, AUTHORITY_WAIT).await?;
    // Pair the clocks after the read and retain fractional wall seconds. Neither
    // SQL delay nor truncation may extend authority beyond the stored expiry.
    let started = tokio::time::Instant::now();
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthorityMiss::Unavailable)?;
    let wall_deadline =
        Duration::from_secs(u64::try_from(expiry).map_err(|_| AuthorityMiss::Refused)?);
    started
        .checked_add(
            wall_deadline
                .checked_sub(wall)
                .ok_or(AuthorityMiss::Refused)?,
        )
        .ok_or(AuthorityMiss::Unavailable)
}

/// Read the session's expiry, and start its renewal when `renew` is set and it
/// is due. Each attempt has the fixed per-read deadline. An attempt that misses
/// it is a busy store, not a refusal (#240): it is dropped and tried again after
/// a pause (5 ms doubling to 100 ms) until `wait` has passed (`AUTHORITY_WAIT`
/// everywhere but teardown, which passes zero for a single attempt), then the
/// read fails closed. A store that answers (no live session, or a storage
/// error) fails at once and is never retried. The caller does no work
/// meanwhile: every call site awaits this before it polls the operation it
/// guards, so input stays queued in order behind the read instead of being
/// dropped with the socket. One non-generic function serves every call site so
/// the retry loop is compiled once (D243).
///
/// Only the read is retried. It is a SELECT, which a WAL database serves while
/// another connection holds the write lock. The renewal is a write that may
/// wait seconds for that lock; it never runs here (`renew_soon`). Each attempt
/// obtains one of the `AUTHORITY_READS` places within its deadline. Fast SELECTs
/// run inline. If one misses its deadline, `DetachOnDrop` moves its pinned
/// future into a task with its place until the SELECT future completes. Pool
/// return and health checks may finish afterward, so the place bounds active
/// queries rather than an instantaneous pool-idle count. A retry cannot start
/// another SELECT while its previous query future remains in flight.
///
/// Expiry is monotonic: once a session's end has passed it is never found live
/// again. Every attempt reads the wall clock when it starts, so a retry after a
/// wait that crossed the session's end does not judge the session by a time
/// that has already gone. The result is checked once more against the clock
/// after the read, because the attempt that answered may itself have waited
/// for a connection past the end. Renewal is decided from that same check.
async fn read_expiry(
    state: &WebSocketState,
    user_id: &str,
    token: &str,
    renew: bool,
    wait: Duration,
) -> Result<i64, AuthorityMiss> {
    #[cfg(test)]
    let read_timeout = state.authority_read_timeout;
    #[cfg(not(test))]
    let read_timeout = AUTHORITY_READ_TIMEOUT;
    let give_up = tokio::time::Instant::now() + wait;
    let mut pause = AUTHORITY_RETRY_PAUSE;
    let expiry = loop {
        let attempt_deadline = tokio::time::Instant::now() + read_timeout;
        let read = async {
            let reads = &state.authority.reads;
            let place = match reads.try_acquire() {
                Ok(place) => place,
                Err(_) => reads.acquire().await.ok()?,
            };
            let Ok(now) = unix_seconds() else {
                drop(place);
                return Some(Err(AuthorityMiss::Unavailable));
            };
            let hold = AuthorityReadHold::take(Arc::clone(&state.authority), place);
            let query = crate::completion::DetachOnDrop::new(Box::pin(
                state.auth.live_expiry(token, user_id, now, hold),
            ));
            Some(query.await.map_err(|error| match error {
                crate::auth::Error::Denied => AuthorityMiss::Refused,
                _ => AuthorityMiss::Unavailable,
            }))
        };
        match tokio::time::timeout_at(attempt_deadline, read).await {
            // A future that does not yield can finish after the timer. Keep the
            // explicit post-result check so such a completion still retries.
            Ok(Some(result)) if tokio::time::Instant::now() <= attempt_deadline => break result?,
            _ if tokio::time::Instant::now() + pause < give_up => {
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(AUTHORITY_RETRY_PAUSE_MAX);
            }
            _ => return Err(AuthorityMiss::Unavailable),
        }
    };
    let now = unix_seconds().map_err(|()| AuthorityMiss::Unavailable)?;
    if expiry <= now {
        return Err(AuthorityMiss::Refused);
    }
    if renew && Auth::renewal_due(expiry, now) {
        state.renew_soon(user_id, token);
    }
    Ok(expiry)
}

/// Why one authority read did not find the session live. A session the store
/// reports as gone or expired is `Refused`; a read that missed its bound, or
/// could not reach storage, is `Unavailable`: the server was busy, which is
/// neither a refusal nor a bad frame (#227, #240).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AuthorityMiss {
    Refused,
    Unavailable,
}

/// What one bounded authority read found.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthorityRead {
    Live,
    Refused,
    Unavailable,
}

/// The close reason for an attach that did not get a live read.
fn attach_refusal(read: AuthorityRead) -> CloseReason {
    if read == AuthorityRead::Unavailable {
        AUTHORITY_UNAVAILABLE
    } else {
        ATTACH_REFUSED
    }
}

/// The renewing authority read with the full wait, classified for the close log.
async fn authority_read(state: &WebSocketState, user_id: &str, token: &str) -> AuthorityRead {
    match read_expiry(state, user_id, token, true, AUTHORITY_WAIT).await {
        Ok(_) => AuthorityRead::Live,
        Err(AuthorityMiss::Refused) => AuthorityRead::Refused,
        Err(AuthorityMiss::Unavailable) => AuthorityRead::Unavailable,
    }
}

/// One attempt, no wait and no renewal, for teardown: a busy store must not
/// hold a closing socket, and a closing socket is not activity (#240).
async fn teardown_read(
    state: &WebSocketState,
    user_id: &str,
    token: &str,
) -> Result<i64, AuthorityMiss> {
    read_expiry(state, user_id, token, false, Duration::ZERO).await
}

async fn session_is_live(state: &WebSocketState, user_id: &str, token: &str) -> bool {
    authority_read(state, user_id, token).await == AuthorityRead::Live
}

struct ClientAttachment {
    handle: AttachmentHandle,
    input: crate::websocket_input::InputQueue,
    session_id: [u8; 16],
    host_id: Option<uuid::Uuid>,
    /// Rate-limit key of the account that owns this socket, for close lines.
    owner: CloseOwner,
    last_out_seq: u64,
    last_in_acked: u64,
    input_sent_end: u64,
    credit: u64,
    awaiting_ack: bool,
    needs_snapshot: bool,
}

impl ClientAttachment {
    fn close_record(
        &self,
        browser_stream_id: u32,
        who: CloseWho,
        reason: CloseReason,
    ) -> CloseRecord {
        let mut record = CloseRecord::new(
            self.owner,
            who,
            reason,
            self.host_id,
            self.session_id,
            browser_stream_id,
        );
        record.agent_stream_id = self.handle.stream_id();
        record.out_seq = self.last_out_seq;
        record.input_acked = self.last_in_acked;
        record.input_sent = self.input_sent_end;
        record.output_credit_bytes = self.credit;
        record
    }
}

fn record_socket_close(
    state: &WebSocketState,
    attachments: &HashMap<u32, ClientAttachment>,
    who: CloseWho,
    reason: CloseReason,
    code: Option<u16>,
    websocket_reason: Option<&'static str>,
) {
    for (stream_id, attachment) in attachments {
        let mut record = attachment.close_record(*stream_id, who, reason);
        record.websocket_code = code;
        record.websocket_reason = websocket_reason;
        state.close_logs.record(&record);
    }
}

/// Record a browser control-stream close separately from the native WebSocket close frame.
fn record_control_close(
    state: &WebSocketState,
    attachments: &HashMap<u32, ClientAttachment>,
    code: u16,
    reason: &str,
) {
    let close_reason = safe_websocket_reason(reason);
    for (stream_id, attachment) in attachments {
        let mut record = attachment.close_record(*stream_id, CloseWho::Browser, CLIENT_WENT_AWAY);
        record.browser_stream_close_code = Some(code);
        record.browser_stream_close_reason = Some(close_reason);
        state.close_logs.record(&record);
    }
}

/// Why a socket ends after guarded work failed with the transport open, and whether the session still
/// reads live. One non-renewing read decides both: a refused session is a refusal; a read that misses
/// its bound or cannot reach storage means the server was busy, never that the browser misbehaved; only
/// while the session reads live is the caller's `live` reason true (#227). Teardown reuses the liveness
/// for the 1011 Close, so a failed exit costs one authority read, not two.
async fn failure_reason(
    state: &WebSocketState,
    user_id: &str,
    token: &str,
    live: CloseReason,
) -> (CloseReason, bool) {
    match teardown_read(state, user_id, token).await {
        Ok(_) => (live, true),
        Err(AuthorityMiss::Refused) => (RESUME_REFUSED, false),
        Err(AuthorityMiss::Unavailable) => (AUTHORITY_UNAVAILABLE, false),
    }
}

/// Browser plugin action adapter; dimensions arrive in the attachment's Resize.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserTerminalOpen {
    host_id: Option<uuid::Uuid>,
}

/// Startup-file authority follows the same account-owned session and host as terminal attachment.
async fn startup_call(
    state: &WebSocketState,
    user: &str,
    input: &[u8],
) -> Result<Vec<u8>, AgentError> {
    use crate::terminal_startup::{self, Request};
    let invalid = || AgentError::Rejected;
    if input.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err(invalid());
    }
    let request = Request::parse(input).map_err(|_| invalid())?;
    let key =
        |host: Option<uuid::Uuid>| host.map_or_else(|| "local".to_owned(), |id| id.to_string());
    let (session, op, proposal, confirmed) = match request {
        Request::Get { host_id } | Request::Set { host_id, .. } => {
            if let Some(host) = host_id {
                let owned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_hosts WHERE id=? AND owner_id=? AND revoked_at IS NULL)")
                    .bind(host.as_bytes().as_slice()).bind(user).fetch_one(&state.pool).await.map_err(|_| invalid())?;
                if !owned {
                    return Err(invalid());
                }
            }
            if let Request::Set {
                global, enabled, ..
            } = request
            {
                if global && (host_id.is_some() || enabled.is_none()) {
                    return Err(invalid());
                }
                let host_key = key(host_id);
                terminal_startup::save(
                    &state.pool,
                    user,
                    if global { "*" } else { &host_key },
                    enabled,
                )
                .await
                .map_err(|()| invalid())?;
            }
            let (global, host) = terminal_startup::preferences(&state.pool, user, &key(host_id))
                .await
                .map_err(|()| invalid())?;
            return serde_json::to_vec(&json!({"global_enabled":global,"host_override":host,"enabled":host.unwrap_or(global)})).map_err(|_| invalid());
        }
        Request::Inspect { session } => (session, "inspect", None, false),
        Request::Apply {
            session,
            proposal,
            confirmed,
        } => (session, "apply", Some(proposal), confirmed),
        Request::Undo {
            session,
            proposal,
            confirmed,
        } => (session, "undo", Some(proposal), confirmed),
    };
    let host = session_host_id(&state.pool, user, session.as_bytes())
        .await
        .map_err(|()| invalid())?
        .ok_or_else(invalid)?;
    let host_key = key(host);
    if op == "inspect" {
        if !terminal_startup::pending(&state.pool, user, &host_key)
            .await
            .map_err(|()| invalid())?
            || !startup_session_untyped(&state.pool, user, session.as_bytes()).await?
        {
            return Ok(b"{}".to_vec());
        }
    } else if !confirmed {
        return Err(invalid());
    }
    let agent = terminal_agent(state, user, host)
        .await
        .map_err(|()| invalid())?;
    let input = serde_json::to_vec(
        &json!({"op":op,"session":session,"proposal":proposal,"confirmed":confirmed}),
    )
    .map_err(|_| invalid())?;
    let output = agent.call("terminal.startup".to_owned(), input).await?;
    if op == "inspect" {
        let value: serde_json::Value = serde_json::from_slice(&output).map_err(|_| invalid())?;
        if value.get("multiplexer").is_none()
            || !startup_session_untyped(&state.pool, user, session.as_bytes()).await?
            || !terminal_startup::claim(&state.pool, user, &host_key)
                .await
                .map_err(|()| invalid())?
        {
            return Ok(b"{}".to_vec());
        }
    }
    Ok(output)
}

/// A command typed by a person must not be mistaken for an automatic startup.
async fn startup_session_untyped(
    pool: &SqlitePool,
    user: &str,
    session: &[u8; 16],
) -> Result<bool, AgentError> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM terminal_sessions WHERE id=? AND user_id=? AND closed_at IS NULL AND created_at>=unixepoch()-10 AND input_acked_u64=X'0000000000000000')")
        .bind(session.as_slice()).bind(user).fetch_one(pool).await.map_err(|_| AgentError::Unavailable)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalOpen {
    cols: u16,
    rows: u16,
    px_w: u16,
    px_h: u16,
}

impl TerminalOpen {
    fn valid(&self) -> bool {
        (1..=500).contains(&self.cols)
            && (1..=300).contains(&self.rows)
            && self.px_w <= 16_384
            && self.px_h <= 16_384
    }
}

async fn open_terminal(
    state: &WebSocketState,
    user_id: &str,
    session_token: &str,
    size: TerminalOpen,
    host: Option<uuid::Uuid>,
) -> Result<[u8; 16], crate::embedded::AgentError> {
    #[cfg(test)]
    let connect_timeout = state.terminal_connect_timeout;
    #[cfg(not(test))]
    let connect_timeout = TERMINAL_CONNECT_TIMEOUT;
    let agent = terminal_agent(state, user_id, host)
        .await
        .map_err(|()| crate::embedded::AgentError::Unavailable)?;
    let session_id = tokio::time::timeout(
        connect_timeout,
        agent.open(TerminalSize {
            cols: size.cols,
            rows: size.rows,
            px_w: size.px_w,
            px_h: size.px_h,
        }),
    )
    .await
    .map_err(|_| crate::embedded::AgentError::Unavailable)??;
    if !session_is_live(state, user_id, session_token).await {
        return Err(crate::embedded::AgentError::Unavailable);
    }
    let now = unix_seconds().map_err(|()| crate::embedded::AgentError::Unavailable)?;
    let changed = sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,remote_host_id) SELECT ?,?,?,?,? FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>unixepoch() AND (? IS NULL OR EXISTS (SELECT 1 FROM remote_hosts WHERE id=? AND owner_id=? AND revoked_at IS NULL))")
        .bind(session_id.as_slice())
        .bind(user_id)
        .bind(now)
        .bind(now)
        .bind(host.map(|id| id.as_bytes().to_vec()))
        .bind(crate::auth::hash(session_token)).bind(user_id)
        .bind(host.map(|id| id.as_bytes().to_vec())).bind(host.map(|id| id.as_bytes().to_vec())).bind(user_id)
        .execute(&state.pool)
        .await
        .map_err(|_| crate::embedded::AgentError::Unavailable)?;
    if changed.rows_affected() != 1 {
        return Err(crate::embedded::AgentError::Unavailable);
    }
    state.sessions_changed();
    Ok(session_id)
}

/// Core-only builds select the local host and refuse every remote selection.
#[cfg(not(feature = "remote"))]
fn terminal_agent(
    state: &WebSocketState,
    _user: &str,
    host: Option<uuid::Uuid>,
) -> std::future::Ready<Result<EmbeddedAgent, ()>> {
    std::future::ready(if host.is_some() {
        Err(())
    } else {
        Ok(state.agent.clone())
    })
}

/// Host selection is a durable authority check; a missing remote host never falls back locally.
#[cfg(feature = "remote")]
async fn terminal_agent(
    state: &WebSocketState,
    user: &str,
    host: Option<uuid::Uuid>,
) -> Result<EmbeddedAgent, ()> {
    let Some(host) = host else {
        return Ok(state.agent.clone());
    };
    let allowed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_hosts WHERE id=? AND owner_id=? AND revoked_at IS NULL)")
        .bind(host.as_bytes().as_slice()).bind(user).fetch_one(&state.pool).await.map_err(|_|())?;
    if !allowed {
        return Err(());
    }
    state.remote_hosts.actor(host).await.ok_or(())
}

/// The session's host for this account: `None` when the account has no such session,
/// `Some(None)` for a session on the server's own host.
async fn session_host_id(
    pool: &SqlitePool,
    user: &str,
    session: &[u8; 16],
) -> Result<Option<Option<uuid::Uuid>>, ()> {
    let Some(row) =
        sqlx::query("SELECT remote_host_id FROM terminal_sessions WHERE id=? AND user_id=?")
            .bind(session.as_slice())
            .bind(user)
            .fetch_optional(pool)
            .await
            .map_err(|_| ())?
    else {
        return Ok(None);
    };
    let bytes: Option<Vec<u8>> = row.get("remote_host_id");
    bytes
        .as_deref()
        .map(uuid::Uuid::from_slice)
        .transpose()
        .map(Some)
        .map_err(|_| ())
}

/// Writer identity survives reconnect and supervision; output remains session-wide.
/// True when the account has no live record of this session: it never had it,
/// or its shell's exit was recorded. Either way an attach can never succeed.
async fn session_gone(pool: &SqlitePool, user: &str, session: &[u8; 16]) -> Result<bool, ()> {
    let closed: Option<bool> = sqlx::query_scalar(
        "SELECT closed_at IS NOT NULL FROM terminal_sessions WHERE id=? AND user_id=?",
    )
    .bind(session.as_slice())
    .bind(user)
    .fetch_optional(pool)
    .await
    .map_err(|_| ())?;
    Ok(closed.unwrap_or(true))
}

/// Browser streams retired by final session-gone or bounded input overload Close (wire §4/§6).
///
/// The browser sends Credit and Resize right behind its `AttachTerm`, and may type
/// before the Close reaches it. Those frames are dropped rather than treated as a
/// protocol error, which would cut every sibling terminal on the socket. The entry
/// lives until the browser's own Close for the stream, or until the stream id
/// attaches again. Bounded like attachments: a browser that never closes them
/// loses the socket.
#[derive(Default)]
struct EndedStreams(HashSet<u32>);

impl EndedStreams {
    fn insert(&mut self, stream_id: u32) -> Result<(), ()> {
        if self.0.len() >= MAX_ATTACHMENTS && !self.0.contains(&stream_id) {
            return Err(());
        }
        self.0.insert(stream_id);
        Ok(())
    }

    /// Whether `frame` belongs to an ended stream and is consumed here.
    fn absorbs(&mut self, stream_id: u32, frame: &Frame<'_>) -> Result<bool, ()> {
        if stream_id == CONTROL_STREAM || !self.0.contains(&stream_id) {
            return Ok(false);
        }
        match frame {
            Frame::Close { .. } => {
                self.0.remove(&stream_id);
                Ok(true)
            }
            Frame::Input { .. }
            | Frame::InputReply { .. }
            | Frame::Credit { .. }
            | Frame::Resize { .. } => Ok(true),
            Frame::AttachTerm { .. } => {
                self.0.remove(&stream_id);
                Ok(false)
            }
            _ => Err(()),
        }
    }
}

async fn owned_writer(
    pool: &SqlitePool,
    user: &str,
    connection: &[u8; 16],
    stream: u32,
    session: &[u8; 16],
    authority: Option<&str>,
) -> Result<(u64, u32), ()> {
    let mut tx = pool.begin().await.map_err(|_| ())?;
    // Acquire the writer lock before admission/ownership reads; concurrent devices
    // cannot allocate one identity twice or bypass the retained-writer limit.
    sqlx::query("UPDATE websocket_connections SET created_at=created_at WHERE connection_id=?")
        .bind(connection.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|_| ())?;
    require_socket_authority_tx(&mut tx, user, authority)
        .await
        .map_err(|_| ())?;
    let existing: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM terminal_writers WHERE connection_id=? AND client_stream=?)",
    )
    .bind(connection.as_slice())
    .bind(stream)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| ())?;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM terminal_writers WHERE connection_id=?")
            .bind(connection.as_slice())
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ())?;
    if !existing && count >= i64::try_from(MAX_ATTACHMENTS).map_err(|_| ())? {
        return Err(());
    }
    sqlx::query("INSERT INTO terminal_writers(connection_id,client_stream,session_id) SELECT ?,?,t.id FROM terminal_sessions t JOIN websocket_connections c ON c.connection_id=? AND c.user_id=t.user_id AND c.active=1 WHERE t.id=? AND t.user_id=? AND t.closed_at IS NULL ON CONFLICT(connection_id,client_stream) DO NOTHING")
        .bind(connection.as_slice()).bind(stream).bind(connection.as_slice()).bind(session.as_slice()).bind(user)
        .execute(&mut *tx).await.map_err(|_| ())?;
    let row = sqlx::query("SELECT w.writer_id,w.input_acked FROM terminal_writers w JOIN terminal_sessions t ON t.id=w.session_id JOIN websocket_connections c ON c.connection_id=w.connection_id WHERE w.connection_id=? AND w.client_stream=? AND w.session_id=? AND t.user_id=? AND c.user_id=? AND c.active=1 AND t.closed_at IS NULL")
        .bind(connection.as_slice()).bind(stream).bind(session.as_slice()).bind(user).bind(user)
        .fetch_optional(&mut *tx).await.map_err(|_| ())?.ok_or(())?;
    let writer: i64 = row.get("writer_id");
    let writer = u32::try_from(writer)
        .map_err(|_| ())?
        .checked_mul(2)
        .filter(|id| *id != 0)
        .ok_or(())?;
    let ack: Vec<u8> = row.get("input_acked");
    let ack = u64::from_be_bytes(ack.try_into().map_err(|_| ())?);
    require_socket_authority_tx(&mut tx, user, authority)
        .await
        .map_err(|_| ())?;
    tx.commit().await.map_err(|_| ())?;
    Ok((ack, writer))
}

fn encode_session_id(session_id: &[u8; 16]) -> String {
    let mut output = String::with_capacity(32);
    for byte in session_id {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(super) enum Inbound {
    Frame(Bytes),
    TransportPing(Bytes),
    SocketClose {
        code: Option<u16>,
        reason: Option<&'static str>,
    },
    Failure(ReceiveFailure),
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ReceiveFailure {
    ConnectionClosed,
    Protocol,
    SizeLimit,
    IdleTimeout,
}

async fn next_wire<S, K>(
    source: &mut S,
    sink: &mut K,
    receive: &mut BytesMut,
) -> Result<Option<Bytes>, ()>
where
    S: Stream<Item = Result<Message, axum::Error>> + Unpin,
    K: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    let mut deadline = None;
    loop {
        match receive_wire(source, receive, &mut deadline).await? {
            Some(Inbound::Frame(frame)) => return Ok(Some(frame)),
            Some(Inbound::TransportPing(payload)) => {
                send_message(sink, Message::Pong(payload)).await?;
            }
            Some(Inbound::SocketClose { .. } | Inbound::Failure(_)) => return Err(()),
            None => return Ok(None),
        }
    }
}

#[cfg(test)]
#[path = "websocket_receive_tests.rs"]
mod receive_tests;

pub(super) async fn receive_wire<S>(
    source: &mut S,
    receive: &mut BytesMut,
    deadline: &mut Option<tokio::time::Instant>,
) -> Result<Option<Inbound>, ()>
where
    S: Stream<Item = Result<Message, axum::Error>> + Unpin,
{
    loop {
        // Buffered frames and transport controls can remain ready without I/O.
        // Bound their turn so an independent proof future can run in this task.
        tokio::task::consume_budget().await;
        match decode_muxed_frame(receive) {
            Ok(decoded) => {
                let wire_len = decoded.wire_len;
                let frame = receive.split_to(wire_len).freeze();
                if receive.is_empty() {
                    *deadline = None;
                }
                return Ok(Some(Inbound::Frame(frame)));
            }
            Err(DecodeError::Incomplete) => {}
            Err(DecodeError::FrameTooLarge { .. } | DecodeError::BufferLimitExceeded) => {
                return Ok(Some(Inbound::Failure(ReceiveFailure::SizeLimit)));
            }
            Err(_) => return Ok(Some(Inbound::Failure(ReceiveFailure::Protocol))),
        }
        if receive.len() >= MAX_SOCKET_BUFFER {
            return Ok(Some(Inbound::Failure(ReceiveFailure::SizeLimit)));
        }
        // A silent authenticated socket has no completion work and no timer [41].
        // Preserve a begun mux frame's deadline across select cancellation and
        // transport pings. Axum reassembles RFC fragments internally; those are
        // bounded by message/frame size, admission and live authority, rather
        // than an idle-read timer that disconnects healthy terminals every 30s.
        let message = if let Some(end) = *deadline {
            match tokio::time::timeout_at(end, source.next()).await {
                Ok(message) => message,
                Err(_) => return Ok(Some(Inbound::Failure(ReceiveFailure::IdleTimeout))),
            }
        } else {
            source.next().await
        };
        let Some(message) = message else {
            return Ok(None);
        };
        match message {
            Err(_) => return Ok(Some(Inbound::Failure(ReceiveFailure::ConnectionClosed))),
            Ok(message) => match message {
                Message::Binary(bytes) => {
                    let Some(new_len) = receive.len().checked_add(bytes.len()) else {
                        return Ok(Some(Inbound::Failure(ReceiveFailure::SizeLimit)));
                    };
                    if new_len > MAX_SOCKET_BUFFER {
                        return Ok(Some(Inbound::Failure(ReceiveFailure::SizeLimit)));
                    }
                    receive.extend_from_slice(&bytes);
                    let partial = tokio::time::Instant::now() + PARTIAL_FRAME_TIMEOUT;
                    *deadline = Some(deadline.map_or(partial, |existing| existing.min(partial)));
                }
                Message::Ping(payload) => return Ok(Some(Inbound::TransportPing(payload))),
                Message::Pong(_) => {}
                Message::Close(frame) => {
                    let (code, reason) = frame.map_or((None, None), |frame| {
                        (
                            Some(frame.code),
                            Some(safe_websocket_reason(frame.reason.as_ref())),
                        )
                    });
                    return Ok(Some(Inbound::SocketClose { code, reason }));
                }
                Message::Text(_) => return Ok(Some(Inbound::Failure(ReceiveFailure::Protocol))),
            },
        }
    }
}

pub(super) async fn send_frame<K>(
    sink: &mut K,
    stream_id: u32,
    frame: &Frame<'_>,
    encode: &mut Vec<u8>,
) -> Result<(), ()>
where
    K: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    encode_muxed_frame_into(stream_id, frame, encode).map_err(|_| ())?;
    send_message(sink, Message::Binary(Bytes::copy_from_slice(encode))).await
}

/// Bound each writer independently; a stalled browser cannot retain its permits forever.
pub(super) async fn send_message<K>(sink: &mut K, message: Message) -> Result<(), ()>
where
    K: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    send_messages(sink, [message]).await
}

/// Flush one bounded group while retaining a separate WebSocket message per item.
/// The deadline covers the whole group, including backpressure and final flush.
pub(super) async fn send_messages<K>(
    sink: &mut K,
    messages: impl IntoIterator<Item = Message>,
) -> Result<(), ()>
where
    K: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    tokio::time::timeout(WRITE_TIMEOUT, async {
        for message in messages {
            sink.feed(message).await.map_err(|_| ())?;
        }
        sink.flush().await.map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
}

#[cfg(test)]
#[path = "websocket_write_tests.rs"]
mod write_tests;

/// Recover active rows after a process restart, granting the documented resume grace period.
pub(crate) async fn recover_connections(pool: &SqlitePool, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE websocket_connections SET active=0, expires_at=? WHERE active=1")
        .bind(now.saturating_add(i64::from(RESUME_WINDOW_SECONDS)))
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM websocket_connections WHERE active=0 AND expires_at<?")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

pub(crate) fn now_seconds() -> Result<i64, ()> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs(),
    )
    .map_err(|_| ())
}

fn unix_seconds() -> Result<i64, ()> {
    now_seconds()
}

#[cfg(test)]
#[path = "writer_tests.rs"]
mod writer_tests;

#[cfg(test)]
#[path = "session_inventory_tests.rs"]
mod session_inventory_tests;

/// Caller already holds SQLite's writer lock. Production supplies an exact session hash;
/// storage-only unit tests omit it. Reads do not slide expiry or require a fresh destructive tap.
async fn require_socket_authority_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user: &str,
    authority: Option<&str>,
) -> Result<(), sqlx::Error> {
    if let Some(hash) = authority {
        let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>unixepoch())")
            .bind(hash).bind(user).fetch_one(&mut **tx).await?;
        if !live {
            return Err(sqlx::Error::Protocol("session authority ended".into()));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "recovery_notification_bench.rs"]
mod recovery_notification_bench;

/// The host retains session secrets and authority interruption independently of feature work.
struct PluginHost {
    state: Arc<WebSocketState>,
    user: String,
    token: String,
    hash: String,
    incarnation: String,
}
impl SocketHost for PluginHost {
    fn session_incarnation(&self) -> Option<&str> {
        Some(&self.incarnation)
    }
    fn node_action_declared(&self, id: &str) -> bool {
        self.state.action(id).is_some()
    }
    fn user_id(&self) -> &str {
        &self.user
    }
    fn token_hash(&self) -> &str {
        &self.hash
    }
    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        Box::pin(while_authorized_operation(
            &self.state,
            &self.user,
            &self.token,
            true,
            operation,
        ))
    }
    fn fresh(&self, now: i64) -> Operation<'_, bool> {
        Box::pin(async move {
            self.state
                .auth
                .fresh_session(&self.token, now)
                .await
                .is_ok()
        })
    }
    fn live(&self) -> Operation<'_, bool> {
        Box::pin(session_is_live(&self.state, &self.user, &self.token))
    }
    fn may_configure(&self) -> Operation<'_, bool> {
        Box::pin(async move {
            let Ok(mut tx) = self.state.pool.begin().await else {
                return false;
            };
            let owner = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND owner=1)",
            )
            .bind(&self.user)
            .fetch_one(&mut *tx)
            .await
            .unwrap_or(false);
            owner
                && infraternal_plugin_api::fresh_session_tx(
                    &mut tx,
                    &self.hash,
                    &self.user,
                    unix_seconds().unwrap_or(i64::MAX),
                    infraternal_plugin_api::FRESH_SECONDS,
                )
                .await
                .unwrap_or(false)
        })
    }
}

#[cfg(test)]
#[path = "websocket_cookie_tests.rs"]
mod cookie_tests;

#[cfg(test)]
mod link_notice_tests {
    //! A kept, doubted host link is never presented as a replay [D300, #234].
    use super::*;

    #[test]
    fn doubt_notices_reach_only_viewers_that_announced_them_and_never_await_an_ack() {
        assert_eq!(
            link_notice(&TerminalOutput::LinkDoubt, true),
            Some(("terminal.link_doubt", false))
        );
        assert_eq!(
            link_notice(&TerminalOutput::Recovered, true),
            Some(("terminal.link_recovered", false))
        );
        // Older viewers reject unknown notices; they keep working without one.
        assert_eq!(link_notice(&TerminalOutput::LinkDoubt, false), None);
        assert_eq!(link_notice(&TerminalOutput::Recovered, false), None);
        // A replaced link still makes every viewer wait for the replay's Ack.
        for viewer in [false, true] {
            assert_eq!(
                link_notice(&TerminalOutput::Reconnecting, viewer),
                Some(("terminal.reconnecting", true))
            );
            assert_eq!(
                link_notice(&TerminalOutput::RouteExpired, viewer),
                Some(("terminal.reconnecting", true))
            );
        }
    }
}
