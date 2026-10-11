//! Authenticates browser sockets, resumes connections, and relays user-owned terminal streams [19][41][50].

use crate::embedded::{
    AgentError, AttachmentHandle, EmbeddedAgent, SessionInventoryState, TerminalOutput,
    TerminalSize,
};
use crate::{
    auth::Auth,
    plugins::{Dispatch, PluginRuntime, SocketPlugins},
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
use futures_util::{
    FutureExt, SinkExt, Stream, StreamExt, future::BoxFuture, stream::FuturesUnordered,
};
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
// Authority/storage stalls fail closed; shutdown cannot inherit the normal one-second writer wait.
const AUTHORITY_READ_TIMEOUT: Duration = Duration::from_millis(25);
const CLOSE_TIMEOUT: Duration = Duration::from_millis(25);
// Expired rows are pruned during new handshakes; this caps retained bearer metadata globally.
const MAX_RESUME_ROWS: i64 = 4096;
// Reject further AttachTerm requests on a socket at this bound.
const MAX_ATTACHMENTS: usize = 32;
// Enough to cover every stream on a server socket while keeping the exit-status sidecar small.
const MAX_ENDED_SESSION_STATUSES: i64 = 128;
// One slow host-facts poll per second can queue only a small bounded number per socket.
const MAX_PENDING_PLUGIN_CALLS: usize = 4;
// A blocked websocket writer applies backpressure to each bounded attachment pump.
const OUTPUT_CHANNEL_CAPACITY: usize = 4;
// Cap a fragmented input frame before the decoder retains more bytes.
const MAX_SOCKET_BUFFER: usize = MAX_FRAME_LEN + 10;
const MAX_CREDIT: u64 = 8 * 1024 * 1024;

type PendingPluginCall = BoxFuture<'static, (u32, Result<Vec<u8>, AgentError>)>;

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
    users: Arc<std::sync::Mutex<HashMap<String, std::sync::Weak<Semaphore>>>>,
    session_changes: watch::Sender<u64>,
}

impl WebSocketState {
    /// Create bounded socket admission around the configured auth and agent services.
    pub(crate) async fn new(
        auth: Auth,
        pool: SqlitePool,
        agent: EmbeddedAgent,
    ) -> Result<Self, crate::plugins::PluginError> {
        let plugins = crate::plugins::compiled(&pool).await?;
        let (session_changes, _) = watch::channel(0_u64);
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
                    SessionInventoryState::Available(ids) => {
                        if reconcile_embedded_sessions(&inventory_pool, &ids)
                            .await
                            .is_ok()
                        {
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
            remote_hosts: crate::remote_runtime::RemoteHosts::default(),
            #[cfg(test)]
            handshake_timeout: HANDSHAKE_TIMEOUT,
            #[cfg(test)]
            authority_read_timeout: AUTHORITY_READ_TIMEOUT,
            #[cfg(test)]
            terminal_connect_timeout: TERMINAL_CONNECT_TIMEOUT,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            users: Arc::default(),
            session_changes,
        })
    }

    /// Bind this socket to the generic host authority bridge without starting features.
    pub(crate) fn plugin_socket(self: &Arc<Self>, user: &str, token: &str) -> SocketPlugins {
        let host: Arc<dyn SocketHost> = Arc::new(PluginHost {
            state: Arc::clone(self),
            user: user.to_owned(),
            hash: crate::auth::hash(token),
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
async fn reconcile_embedded_sessions(
    pool: &SqlitePool,
    session_ids: &[[u8; 16]],
) -> Result<(), sqlx::Error> {
    let live: HashSet<[u8; 16]> = session_ids.iter().copied().collect();
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
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
    ws.max_message_size(MAX_SOCKET_BUFFER)
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
    let mut recovery_events = state.auth.recovery_events();
    let mut recovery_subscribed = false;
    let mut recovery_snapshot = RecoverySnapshot::Unread;
    let mut session_changes = state.session_changes.subscribe();
    let mut terminal_sessions_subscribed = None;
    let mut revocations = state.auth.revocation_events();
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
                        caps: 0,
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
    let handshake = tokio::time::timeout_at(
        handshake_deadline,
        while_authorized(
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
            ),
        ),
    )
    .await;
    let Ok(Ok(connection_id)) = handshake else {
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, send_message(&mut sink, Message::Close(None)))
            .await;
        drop(sink);
        drop(source);
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
    let mut pending_plugin_calls = FuturesUnordered::<PendingPluginCall>::new();
    let mut plugins = state.plugin_socket(&user_id, &session_token);
    let mut output_open = true;
    let mut receive_deadline = None;
    let mut attachments = HashMap::<u32, ClientAttachment>::new();
    let mut ended = EndedStreams::default();
    let mut loop_result = Ok(());
    let mut expiry = socket_deadline(&state, &user_id, &session_token)
        .await
        .unwrap_or_else(|()| tokio::time::Instant::now());
    loop {
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
                let Ok(deadline) = socket_deadline(&state, &user_id, &session_token).await else { break; };
                expiry = deadline;
            }
            () = tokio::time::sleep_until(expiry) => {
                let Ok(deadline) = socket_deadline(&state, &user_id, &session_token).await else { break; };
                expiry = deadline;
            }
            input = receive_wire(&mut source, &mut receive, &mut receive_deadline) => {
                let input = match input {
                    Ok(Some(input)) => input,
                    Ok(None) => break,
                    Err(()) => {
                        loop_result = Err(());
                        break;
                    }
                };
                match input {
                    Inbound::TransportPing(payload) => {
                        if while_authorized(&state, &user_id, &session_token, true, send_message(&mut sink, Message::Pong(payload))).await.is_err() { break; }
                    }
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
                        && let Frame::Close { code, .. } = decoded.frame {
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
                    if while_authorized(&state, &user_id, &session_token, true, handle_client_frame(
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
                        )).await.is_err() {
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
                if while_authorized(&state, &user_id, &session_token, true, handle_terminal_output(
                    &state, &user_id, &session_token, &connection_id, stream_id, output,
                    &mut attachments, &mut ended, &mut sink, &mut encode,
                )).await.is_err() { break; }
            }
            plugin_call = pending_plugin_calls.next(), if !pending_plugin_calls.is_empty() => {
                let Some((call_id, result)) = plugin_call else { continue; };
                let (ok, json) = match result {
                    Ok(json) => (true, json),
                    Err(_) => (false, br#"{"error":"action unavailable"}"#.to_vec()),
                };
                if while_authorized(&state, &user_id, &session_token, true,
                    send_frame(&mut sink, CONTROL_STREAM,
                        &Frame::Result { call_id, ok, json: &json }, &mut encode)
                ).await.is_err() { break; }
            }
        }
    }
    drop(plugins);
    drop(attachments);
    if loop_result.is_err() && session_is_live(&state, &user_id, &session_token).await {
        let _ = tokio::time::timeout(
            CLOSE_TIMEOUT,
            send_frame(
                &mut sink,
                CONTROL_STREAM,
                &Frame::Close {
                    code: 1011,
                    reason: "connection ended",
                },
                &mut encode,
            ),
        )
        .await;
    }
    let _ =
        tokio::time::timeout(CLOSE_TIMEOUT, send_message(&mut sink, Message::Close(None))).await;
    // Drop transport before metadata cleanup so a busy SQLite writer cannot retain a revoked socket.
    drop(sink);
    drop(source);
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
async fn while_authorized<T: Send>(
    state: &WebSocketState,
    user: &str,
    token: &str,
    renew: bool,
    operation: impl std::future::Future<Output = Result<T, ()>> + Send,
) -> Result<T, ()> {
    // Sharing the watchdog across operation future types bounds transport code
    // size as compiled plugins grow. One short-lived allocation replaces each
    // separate watchdog state machine; operation cancellation stays unchanged.
    while_authorized_operation(state, user, token, renew, operation.boxed()).await
}

async fn while_authorized_operation<T: Send>(
    state: &WebSocketState,
    user: &str,
    token: &str,
    renew: bool,
    operation: infraternal_plugin_api::Operation<'_, Result<T, ()>>,
) -> Result<T, ()> {
    let mut revocations = state.auth.revocation_events();
    let mut expiry = authority_deadline(state, user, token, renew).await?;
    let mut check = tokio::time::interval_at(
        tokio::time::Instant::now() + BUSY_AUTHORITY_INTERVAL,
        BUSY_AUTHORITY_INTERVAL,
    );
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::pin!(operation);
    loop {
        tokio::select! {
            biased;
            changed = revocations.changed() => {
                changed.map_err(|_| ())?;
                expiry = socket_deadline(state, user, token).await?;
            }
            () = tokio::time::sleep_until(expiry) => { expiry = socket_deadline(state, user, token).await?; }
            _ = check.tick() => { expiry = socket_deadline(state, user, token).await?; }
            result = &mut operation => {
                // The entry read authenticates this operation. All production revocations
                // publish after commit, and renewal can only extend expiry. Recheck that
                // generation/deadline without two redundant SQLite reads per fast frame.
                // Backend/persistence boundaries still read actual authority and predicate SQL.
                if revocations.has_changed().map_err(|_| ())? || tokio::time::Instant::now() >= expiry {
                    socket_deadline(state, user, token).await?;
                }
                return result;
            }
        }
    }
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
    let inventory = state.agent.session_inventory().borrow().clone();
    let event = match inventory {
        SessionInventoryState::Pending | SessionInventoryState::Unavailable => json!({
            "topic":"terminal.sessions",
            "type":"terminal.sessions.unavailable",
        }),
        SessionInventoryState::Available(live) => {
            let rows: Vec<Vec<u8>> = sqlx::query_scalar(
                "SELECT id FROM terminal_sessions WHERE user_id=? AND remote_host_id IS NULL AND closed_at IS NULL",
            )
            .bind(user)
            .fetch_all(&state.pool)
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
            .fetch_all(&state.pool)
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
        TerminalOutput::Closed { code } => {
            // The host's infraternal agent found no shim for the session: a final
            // answer, distinct from every transient close (wire §4, #158).
            let gone = code == CLOSE_SESSION_GONE;
            let reason = if gone {
                SESSION_GONE_REASON
            } else {
                "attachment ended"
            };
            let sent = send_frame(sink, stream_id, &Frame::Close { code, reason }, encode)
                .await
                .is_ok();
            attachments.remove(&stream_id);
            if gone {
                ended.insert(stream_id)?;
            }
            sent
        }
    };
    if !sent {
        return Err(());
    }
    Ok(())
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
) -> Result<[u8; 16], ()>
where
    S: Stream<Item = Result<Message, axum::Error>> + Unpin,
    K: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    let hello = next_wire(source, sink, receive).await?.ok_or(())?;
    socket_deadline(state, user_id, session_token).await?;
    let decoded = decode_muxed_frame(&hello).map_err(|_| ())?;
    let resume = match (decoded.stream_id, decoded.frame) {
        (
            CONTROL_STREAM,
            Frame::Hello {
                version: 1, caps, ..
            },
        ) => caps & RESUME_NEXT != 0,
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
    socket_deadline(state, user_id, session_token).await?;
    if send_frame(
        sink,
        CONTROL_STREAM,
        &Frame::Welcome {
            connection_id: &welcome.connection_id,
            resume_token: &welcome.resume_token,
            resume_window_seconds: RESUME_WINDOW_SECONDS,
        },
        encode,
    )
    .await
    .is_err()
    {
        return Err(());
    }
    Ok(welcome.connection_id)
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
    require_socket_authority_tx(&mut transaction, user_id, authority).await?;
    let row = sqlx::query("SELECT token_hash,expires_at FROM websocket_connections WHERE connection_id=? AND user_id=? AND active=0 AND expires_at>=?")
        .bind(connection_id.as_slice())
        .bind(user_id)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| sqlx::Error::Protocol("resume rejected".into()))?;
    let stored: Vec<u8> = row.get("token_hash");
    let previous_expiry: i64 = row.get("expires_at");
    let requested_hash = token_hash(&token);
    if stored.len() != 32 || !openssl::memcmp::eq(&stored, &requested_hash) {
        return Err(sqlx::Error::Protocol("resume rejected".into()));
    }
    let previous_token_hash: [u8; 32] = stored
        .try_into()
        .map_err(|_| sqlx::Error::Protocol("resume rejected".into()))?;
    let active: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM websocket_connections WHERE user_id=? AND active=1",
    )
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await?;
    if active >= 16 {
        return Err(sqlx::Error::Protocol("connection limit reached".into()));
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
        return Err(sqlx::Error::Protocol("resume rejected".into()));
    }
    require_socket_authority_tx(&mut transaction, user_id, authority).await?;
    transaction.commit().await?;
    Ok(welcome)
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
    pending_plugin_calls: &mut FuturesUnordered<PendingPluginCall>,
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
            let result = match request {
                Some((size, host)) if size.valid() => {
                    open_terminal(state, user_id, session_token, size, host).await
                }
                _ => Err(crate::embedded::AgentError::OpenRefused(
                    infraternal_plugin_api::admission::OpenRefusal::Invalid,
                )),
            };
            if !session_is_live(state, user_id, session_token).await {
                return Err(());
            }
            match result {
                Ok(session_id) => {
                    let session_id = if action_id == "ssh.session.open" {
                        uuid::Uuid::from_bytes(session_id).to_string()
                    } else {
                        encode_session_id(&session_id)
                    };
                    let json =
                        serde_json::to_vec(&json!({"session_id": session_id})).map_err(|_| ())?;
                    send_frame(
                        sink,
                        CONTROL_STREAM,
                        &Frame::Result {
                            call_id,
                            ok: true,
                            json: &json,
                        },
                        encode,
                    )
                    .await
                }
                Err(error) => {
                    let refusal = match error {
                        crate::embedded::AgentError::OpenRefused(reason) => reason,
                        _ => infraternal_plugin_api::admission::OpenRefusal::Unavailable,
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
            }
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
                pending_plugin_calls.push(Box::pin(async move {
                    let result =
                        tokio::time::timeout(BACKEND_TIMEOUT, agent.call(action_id, input_json))
                            .await
                            .unwrap_or(Err(AgentError::Unavailable));
                    (call_id, result)
                }));
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
            if attachments.contains_key(&stream_id) || attachments.len() >= MAX_ATTACHMENTS {
                return Err(());
            }
            let mut session = [0_u8; 16];
            session.copy_from_slice(session_id);
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
                if session_is_live(state, user_id, session_token).await
                    && session_gone(&state.pool, user_id, &session).await?
                {
                    ended.insert(stream_id)?;
                    let gone = Frame::Close {
                        code: CLOSE_SESSION_GONE,
                        reason: SESSION_GONE_REASON,
                    };
                    return send_frame(sink, stream_id, &gone, encode).await;
                }
                return Err(());
            };
            if last_in_seq > input_acked {
                return Err(());
            }
            if !session_is_live(state, user_id, session_token).await {
                return Err(());
            }
            let host: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT remote_host_id FROM terminal_sessions WHERE id=? AND user_id=?",
            )
            .bind(session.as_slice())
            .bind(user_id)
            .fetch_one(&state.pool)
            .await
            .map_err(|_| ())?;
            let agent = terminal_agent(
                state,
                user_id,
                host.as_deref()
                    .map(uuid::Uuid::from_slice)
                    .transpose()
                    .map_err(|_| ())?,
            )
            .await?;
            let attachment = tokio::time::timeout(
                BACKEND_TIMEOUT,
                agent.attach(session, last_out_seq, input_acked, writer_stream),
            )
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
            if !session_is_live(state, user_id, session_token).await {
                return Err(());
            }
            let (handle, mut output) = attachment.split();
            let agent_stream = handle.stream_id();
            attachments.insert(
                stream_id,
                ClientAttachment {
                    handle,
                    session_id: session,
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
                    .send((stream_id, TerminalOutput::Closed { code: 1013 }))
                    .await;
            });
            tracing::debug!(
                agent_stream,
                "attached browser terminal stream to embedded infraternal agent"
            );
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
        Frame::Close { .. } if stream_id != 0 && stream_id % 2 == 1 => {
            attachments.remove(&stream_id).ok_or(())?;
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
            attachment
                .handle
                .send_frame(passthrough)
                .await
                .map_err(|_| ())
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
            attachment
                .handle
                .send_frame(passthrough)
                .await
                .map_err(|_| ())
        }
        Frame::Credit { bytes } if stream_id != 0 && stream_id % 2 == 1 => {
            let attachment = attachments.get_mut(&stream_id).ok_or(())?;
            let credit = attachment.credit.checked_add(u64::from(bytes)).ok_or(())?;
            if credit > MAX_CREDIT {
                return Err(());
            }
            attachment.credit = credit;
            attachment
                .handle
                .send_frame(passthrough)
                .await
                .map_err(|_| ())
        }
        _ => Err(()),
    }
}

/// Deadline and revocation checks are event-driven; idle sockets do no repeated database work.
async fn socket_deadline(
    state: &WebSocketState,
    user_id: &str,
    token: &str,
) -> Result<tokio::time::Instant, ()> {
    authority_deadline(state, user_id, token, false).await
}

async fn authority_deadline(
    state: &WebSocketState,
    user_id: &str,
    token: &str,
    renew: bool,
) -> Result<tokio::time::Instant, ()> {
    let now = unix_seconds()?;
    #[cfg(test)]
    let read_timeout = state.authority_read_timeout;
    #[cfg(not(test))]
    let read_timeout = AUTHORITY_READ_TIMEOUT;
    let expiry = tokio::time::timeout(read_timeout, async {
        if renew {
            state.auth.socket_activity(token, user_id, now).await
        } else {
            state.auth.live_expiry(token, user_id, now).await
        }
    })
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    let remaining = u64::try_from(expiry - now).map_err(|_| ())?;
    Ok(tokio::time::Instant::now() + Duration::from_secs(remaining))
}

async fn session_is_live(state: &WebSocketState, user_id: &str, token: &str) -> bool {
    let Ok(now) = unix_seconds() else {
        return false;
    };
    #[cfg(test)]
    let read_timeout = state.authority_read_timeout;
    #[cfg(not(test))]
    let read_timeout = AUTHORITY_READ_TIMEOUT;
    matches!(
        tokio::time::timeout(
            read_timeout,
            state.auth.socket_activity(token, user_id, now)
        )
        .await,
        Ok(Ok(_))
    )
}

struct ClientAttachment {
    handle: AttachmentHandle,
    session_id: [u8; 16],
    last_out_seq: u64,
    last_in_acked: u64,
    input_sent_end: u64,
    credit: u64,
    awaiting_ack: bool,
    needs_snapshot: bool,
}

/// Browser plugin action adapter; dimensions arrive in the attachment's Resize.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserTerminalOpen {
    host_id: Option<uuid::Uuid>,
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

/// Browser streams this socket ended with the final session-gone Close (wire §4).
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
            Frame::Input { .. } | Frame::Credit { .. } | Frame::Resize { .. } => Ok(true),
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

enum Inbound {
    Frame(Bytes),
    TransportPing(Bytes),
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
            None => return Ok(None),
        }
    }
}

async fn receive_wire<S>(
    source: &mut S,
    receive: &mut BytesMut,
    deadline: &mut Option<tokio::time::Instant>,
) -> Result<Option<Inbound>, ()>
where
    S: Stream<Item = Result<Message, axum::Error>> + Unpin,
{
    loop {
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
            Err(_) => return Err(()),
        }
        if receive.len() >= MAX_SOCKET_BUFFER {
            return Err(());
        }
        // A silent authenticated socket has no completion work and no timer [41].
        // Preserve a begun mux frame's deadline across select cancellation and
        // transport pings. Axum reassembles RFC fragments internally; those are
        // bounded by message/frame size, admission and live authority, rather
        // than an idle-read timer that disconnects healthy terminals every 30s.
        let message = if let Some(end) = *deadline {
            tokio::time::timeout_at(end, source.next())
                .await
                .map_err(|_| ())?
        } else {
            source.next().await
        };
        let Some(message) = message else {
            return Ok(None);
        };
        match message.map_err(|_| ())? {
            Message::Binary(bytes) => {
                let new_len = receive.len().checked_add(bytes.len()).ok_or(())?;
                if new_len > MAX_SOCKET_BUFFER {
                    return Err(());
                }
                receive.extend_from_slice(&bytes);
                let partial = tokio::time::Instant::now() + PARTIAL_FRAME_TIMEOUT;
                *deadline = Some(deadline.map_or(partial, |existing| existing.min(partial)));
            }
            Message::Ping(payload) => return Ok(Some(Inbound::TransportPing(payload))),
            Message::Pong(_) => {}
            Message::Close(_) => return Ok(None),
            Message::Text(_) => return Err(()),
        }
    }
}

async fn send_frame<K>(
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
async fn send_message<K>(sink: &mut K, message: Message) -> Result<(), ()>
where
    K: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    tokio::time::timeout(WRITE_TIMEOUT, sink.send(message))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

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
}
impl SocketHost for PluginHost {
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
