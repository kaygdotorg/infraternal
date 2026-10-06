//! Authenticates browser sockets, resumes connections, and relays user-owned terminal streams [19][41][50].

use crate::auth::Auth;
use crate::embedded::{AttachmentHandle, EmbeddedAgent, TerminalOutput, TerminalSize};
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
use futures_util::{SinkExt, Stream, StreamExt};
use infraternal_protocol::{
    DecodeError, Frame, MAX_FRAME_LEN, decode_muxed_frame, encode_muxed_frame_into,
};
use rand::random;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Semaphore, mpsc};

const CONTROL_STREAM: u32 = 0;
const RESUME_NEXT: u64 = 1;
const RESUME_WINDOW_SECONDS: u32 = 120;
// Reject upgrades immediately when the process is at this fixed socket limit.
const MAX_CONNECTIONS: usize = 256;
const MAX_USER_CONNECTIONS: usize = 16;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(30);
const PARTIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
// Expired rows are pruned during new handshakes; this caps retained bearer metadata globally.
const MAX_RESUME_ROWS: i64 = 4096;
// Reject further AttachTerm requests on a socket at this bound.
const MAX_ATTACHMENTS: usize = 32;
// A blocked websocket writer applies backpressure to each bounded attachment pump.
const OUTPUT_CHANNEL_CAPACITY: usize = 4;
// Cap a fragmented input frame before the decoder retains more bytes.
const MAX_SOCKET_BUFFER: usize = MAX_FRAME_LEN + 10;
const MAX_CREDIT: u64 = 8 * 1024 * 1024;

/// State shared by the authenticated browser socket route.
#[derive(Clone)]
pub(crate) struct WebSocketState {
    auth: Auth,
    pool: SqlitePool,
    agent: EmbeddedAgent,
    connections: Arc<Semaphore>,
    users: Arc<std::sync::Mutex<HashMap<String, std::sync::Weak<Semaphore>>>>,
}

impl WebSocketState {
    /// Create bounded socket admission around the configured auth and agent services.
    pub(crate) fn new(auth: Auth, pool: SqlitePool, agent: EmbeddedAgent) -> Self {
        Self {
            auth,
            pool,
            agent,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            users: Arc::default(),
        }
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
            run_socket(socket, state, session.user_id, session_token).await;
        })
}

/// The auth route's cookie parser is intentionally private; this socket uses the same strict cookie shape.
fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    let mut values = cookies
        .split(';')
        .filter_map(|cookie| cookie.trim().strip_prefix("__Host-infraternal="));
    let value = values.next()?;
    if values.next().is_some()
        || value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return None;
    }
    Some(value)
}

// This select loop keeps websocket writes, bounded agent output and inbound frames under one backpressure policy.
#[allow(clippy::too_many_lines)]
async fn run_socket(
    socket: WebSocket,
    state: Arc<WebSocketState>,
    user_id: String,
    session_token: String,
) {
    let mut revocations = state.auth.revocation_events();
    let (mut sink, mut source) = socket.split();
    let mut receive = BytesMut::with_capacity(4096);
    let mut encode = Vec::with_capacity(4096);
    if send_frame(
        &mut sink,
        CONTROL_STREAM,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "infraternal-server/0.1",
        },
        &mut encode,
    )
    .await
    .is_err()
    {
        return;
    }

    let handshake = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake(
            &mut source,
            &mut sink,
            &mut receive,
            &mut encode,
            &state,
            &user_id,
        ),
    )
    .await;
    let Ok(Ok(connection_id)) = handshake else {
        let _ = send_message(&mut sink, Message::Close(None)).await;
        return;
    };

    let (output_tx, mut output_rx) =
        mpsc::channel::<(u32, TerminalOutput)>(OUTPUT_CHANNEL_CAPACITY);
    let mut output_open = true;
    let mut receive_deadline = None;
    let mut attachments = HashMap::<u32, ClientAttachment>::new();
    let mut loop_result = Ok(());
    let mut expiry = socket_deadline(&state, &user_id, &session_token)
        .await
        .unwrap_or_else(|()| tokio::time::Instant::now());
    loop {
        tokio::select! {
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
                        if send_message(&mut sink, Message::Pong(payload)).await.is_err() { break; }
                    }
                    Inbound::Frame(wire) => {
                    if handle_client_frame(
                            wire,
                            &state,
                            &user_id,
                            &session_token,
                            &mut attachments,
                            &output_tx,
                            &mut sink,
                            &mut encode,
                        ).await.is_err() {
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
                if !session_is_live(&state, &user_id, &session_token).await { break; }
                let Some(attachment) = attachments.get_mut(&stream_id) else { continue; };
                let sent = match output {
                    TerminalOutput::Output { out_seq, bytes } => {
                        let Some(end) = out_seq.checked_add(bytes.len() as u64) else {
                            loop_result = Err(());
                            break;
                        };
                        let Ok(length) = u64::try_from(bytes.len()) else {
                            loop_result = Err(());
                            break;
                        };
                        if out_seq < attachment.last_out_seq {
                            continue;
                        }
                        if out_seq != attachment.last_out_seq {
                            attachment.needs_snapshot = true;
                            continue;
                        }
                        if attachment.needs_snapshot || length > attachment.credit {
                            attachment.needs_snapshot = true;
                            continue;
                        }
                        attachment.credit -= length;
                        attachment.last_out_seq = end;
                        send_frame(&mut sink, stream_id, &Frame::Output { out_seq, bytes: &bytes }, &mut encode).await.is_ok()
                    }
                    TerminalOutput::Snapshot { out_seq, bytes } => {
                        let Ok(length) = u64::try_from(bytes.len()) else {
                            loop_result = Err(());
                            break;
                        };
                        if out_seq < attachment.last_out_seq
                            || length > attachment.credit
                        {
                            attachment.needs_snapshot = true;
                            continue;
                        }
                        attachment.credit -= length;
                        attachment.last_out_seq = out_seq;
                        attachment.needs_snapshot = false;
                        send_frame(&mut sink, stream_id, &Frame::Snapshot { out_seq, bytes: &bytes }, &mut encode).await.is_ok()
                    }
                    TerminalOutput::Ack { in_seq_acked } => {
                        if in_seq_acked < attachment.last_in_acked
                            || in_seq_acked > attachment.input_sent_end
                        {
                            loop_result = Err(());
                            break;
                        }
                        attachment.last_in_acked = in_seq_acked;
                        let legacy_acked = i64::try_from(in_seq_acked).unwrap_or(-1);
                        let acked_u64 = in_seq_acked.to_be_bytes();
                        let Ok(now) = unix_seconds() else {
                            loop_result = Err(());
                            break;
                        };
                        let result = sqlx::query("UPDATE terminal_sessions SET input_acked_u64=CASE WHEN input_acked_u64<? THEN ? ELSE input_acked_u64 END, input_acked=CASE WHEN ?>=0 THEN MAX(input_acked,?) ELSE input_acked END, last_seen=? WHERE id=? AND user_id=?")
                            .bind(acked_u64.as_slice())
                            .bind(acked_u64.as_slice())
                            .bind(legacy_acked)
                            .bind(legacy_acked)
                            .bind(now)
                            .bind(attachment.session_id.as_slice())
                            .bind(&user_id)
                            .execute(&state.pool)
                            .await;
                        if result.is_err() {
                            loop_result = Err(());
                            break;
                        }
                        send_frame(&mut sink, stream_id, &Frame::Ack { in_seq_acked }, &mut encode).await.is_ok()
                    }
                    TerminalOutput::Closed { code } => {
                        let sent = send_frame(
                            &mut sink,
                            stream_id,
                            &Frame::Close {
                                code,
                                reason: "terminal closed",
                            },
                            &mut encode,
                        )
                        .await
                        .is_ok();
                        attachments.remove(&stream_id);
                        sent
                    }
                };
                if !sent {
                    break;
                }
            }
        }
    }
    drop(attachments);
    if loop_result.is_err() {
        let _ = send_frame(
            &mut sink,
            CONTROL_STREAM,
            &Frame::Close {
                code: 1011,
                reason: "connection ended",
            },
            &mut encode,
        )
        .await;
    }
    let now = unix_seconds().unwrap_or_default();
    let _ = sqlx::query("UPDATE websocket_connections SET active=0, expires_at=? WHERE connection_id=? AND user_id=? AND active=1")
        .bind(now.saturating_add(i64::from(RESUME_WINDOW_SECONDS)))
        .bind(connection_id.as_slice())
        .bind(user_id)
        .execute(&state.pool)
        .await;
}

async fn handshake<S, K>(
    source: &mut S,
    sink: &mut K,
    receive: &mut BytesMut,
    encode: &mut Vec<u8>,
    state: &WebSocketState,
    user_id: &str,
) -> Result<[u8; 16], ()>
where
    S: Stream<Item = Result<Message, axum::Error>> + Unpin,
    K: futures_util::Sink<Message, Error = axum::Error> + Unpin,
{
    let hello = next_wire(source, sink, receive).await?.ok_or(())?;
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
        resume_connection(&state.pool, user_id, id, token, unix_seconds()?)
            .await
            .map_err(|_| ())?
    } else {
        new_connection(&state.pool, user_id, unix_seconds()?)
            .await
            .map_err(|_| ())?
    };
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
        rollback_connection(&state.pool, user_id, &welcome).await;
        return Err(());
    }
    Ok(welcome.connection_id)
}

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
) -> Result<Welcome, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("DELETE FROM websocket_connections WHERE active=0 AND expires_at<?")
        .bind(now)
        .execute(&mut *transaction)
        .await?;
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
    let token_hash = token_hash(&welcome.resume_token);
    sqlx::query("INSERT INTO websocket_connections(connection_id,token_hash,user_id,created_at,expires_at,active) VALUES (?,?,?,?,NULL,1)")
        .bind(welcome.connection_id.as_slice())
        .bind(token_hash.as_slice())
        .bind(user_id)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(welcome)
}

async fn resume_connection(
    pool: &SqlitePool,
    user_id: &str,
    connection_id: [u8; 16],
    token: [u8; 32],
    now: i64,
) -> Result<Welcome, sqlx::Error> {
    let mut transaction = pool.begin().await?;
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
    transaction.commit().await?;
    Ok(welcome)
}

async fn rollback_connection(pool: &SqlitePool, user_id: &str, welcome: &Welcome) {
    if let Some(token_hash) = welcome.previous_token_hash {
        let _ = sqlx::query("UPDATE websocket_connections SET token_hash=?, active=0, expires_at=? WHERE connection_id=? AND user_id=? AND active=1")
            .bind(token_hash.as_slice())
            .bind(welcome.previous_expiry.unwrap_or_default())
            .bind(welcome.connection_id.as_slice())
            .bind(user_id)
            .execute(pool)
            .await;
    } else {
        let _ = sqlx::query(
            "DELETE FROM websocket_connections WHERE connection_id=? AND user_id=? AND active=1",
        )
        .bind(welcome.connection_id.as_slice())
        .bind(user_id)
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
    attachments: &mut HashMap<u32, ClientAttachment>,
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
    // Every terminal/control frame uses current authority, including attach, input and credit.
    if !session_is_live(state, user_id, session_token).await {
        return Err(());
    }
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
            action_id: "terminal.open",
            input_json,
        } if stream_id == CONTROL_STREAM => {
            let result = match serde_json::from_slice::<TerminalOpen>(input_json) {
                Ok(size) if size.valid() => open_terminal(state, user_id, size).await,
                _ => Err(()),
            };
            match result {
                Ok(session_id) => {
                    let json =
                        serde_json::to_vec(&json!({"session_id":encode_session_id(&session_id)}))
                            .map_err(|_| ())?;
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
                Err(()) => {
                    send_frame(
                        sink,
                        CONTROL_STREAM,
                        &Frame::Result {
                            call_id,
                            ok: false,
                            json: br#"{"error":"terminal unavailable"}"#,
                        },
                        encode,
                    )
                    .await
                }
            }
        }
        Frame::Call { call_id, .. } if stream_id == CONTROL_STREAM => {
            send_frame(
                sink,
                CONTROL_STREAM,
                &Frame::Result {
                    call_id,
                    ok: false,
                    json: br#"{"error":"unknown action"}"#,
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
            let input_acked = owned_session_ack(&state.pool, user_id, &session).await?;
            if last_in_seq > input_acked {
                return Err(());
            }
            let attachment = state
                .agent
                .attach(session, last_out_seq, input_acked)
                .await
                .map_err(|_| ())?;
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
    let now = unix_seconds()?;
    let expiry = state
        .auth
        .live_expiry(token, user_id, now)
        .await
        .map_err(|_| ())?;
    let remaining = u64::try_from(expiry - now).map_err(|_| ())?;
    Ok(tokio::time::Instant::now() + Duration::from_secs(remaining))
}

async fn session_is_live(state: &WebSocketState, user_id: &str, token: &str) -> bool {
    let Ok(now) = unix_seconds() else {
        return false;
    };
    state
        .auth
        .socket_activity(token, user_id, now)
        .await
        .is_ok()
}

struct ClientAttachment {
    handle: AttachmentHandle,
    session_id: [u8; 16],
    last_out_seq: u64,
    last_in_acked: u64,
    input_sent_end: u64,
    credit: u64,
    needs_snapshot: bool,
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
    size: TerminalOpen,
) -> Result<[u8; 16], ()> {
    let session_id = state
        .agent
        .open(TerminalSize {
            cols: size.cols,
            rows: size.rows,
            px_w: size.px_w,
            px_h: size.px_h,
        })
        .await
        .map_err(|_| ())?;
    let now = unix_seconds()?;
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES (?,?,?,?)")
        .bind(session_id.as_slice())
        .bind(user_id)
        .bind(now)
        .bind(now)
        .execute(&state.pool)
        .await
        .map_err(|_| ())?;
    Ok(session_id)
}

async fn owned_session_ack(
    pool: &SqlitePool,
    user_id: &str,
    session_id: &[u8; 16],
) -> Result<u64, ()> {
    let row = sqlx::query("UPDATE terminal_sessions SET last_seen=? WHERE id=? AND user_id=? AND closed_at IS NULL RETURNING input_acked_u64")
        .bind(unix_seconds()?)
        .bind(session_id.as_slice())
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| ())?
        .ok_or(())?;
    let bytes: Vec<u8> = row.get("input_acked_u64");
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| ())?;
    Ok(u64::from_be_bytes(bytes))
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
        // Preserve the deadline across select cancellation and transport pings, including
        // RFC WebSocket fragmentation hidden inside Axum's message stream.
        let end = *deadline.get_or_insert_with(|| tokio::time::Instant::now() + MESSAGE_TIMEOUT);
        let Some(message) = tokio::time::timeout_at(end, source.next())
            .await
            .map_err(|_| ())?
        else {
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
                *deadline = Some(end.min(partial));
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
