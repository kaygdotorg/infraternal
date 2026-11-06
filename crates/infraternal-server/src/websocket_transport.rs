//! Keeps authenticated browser proofs responsive while application work awaits SQL or a host [D265, #199].

use super::websocket::{
    AuthorityMiss, Inbound, MAX_ATTACHMENTS, MAX_SOCKET_BUFFER, ReceiveFailure, WebSocketState,
    receive_wire, send_messages,
};
use crate::liveness::Liveness;
use crate::stream_close::{
    CLIENT_WENT_AWAY, CloseReason, IDLE_TIMEOUT, PROTOCOL_ERROR, REPLY_QUEUE_FULL, RESUME_REFUSED,
    SERVER_WRITE_FAILED,
};
use axum::extract::ws::{Message, WebSocket};
use bytes::{Bytes, BytesMut};
use futures_util::{
    FutureExt, Sink, SinkExt,
    stream::{SplitSink, SplitStream},
};
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use std::sync::{
    Arc, Mutex as LeaseMutex,
    atomic::{AtomicU8, Ordering},
};
use std::{
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch};

// One attach plus its credit per admitted window. Payload admission also has a
// byte bound: a client cannot turn these small-frame slots into 64 full-size frames.
const INPUT_SLOTS: usize = MAX_ATTACHMENTS * 2;
const CONTROL_SLOTS: usize = 128;
// Ready replies plus one probe remain below the framing buffer and yield after a bounded turn.
const PROOF_BATCH: usize = 64;
// Application progress keeps the first-tick cadence briefly. Content-free
// proofs bypass this window, and its expiry creates no separate timer.
const FAST_PROBE_WINDOW: std::time::Duration = std::time::Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum EndReason {
    Open = 0,
    ClientWentAway = 1,
    ProtocolError = 2,
    SizeLimit = 3,
    IdleTimeout = 4,
    AuthorizationRefused = 5,
    ServerWriteFailed = 6,
    FlowControlRefused = 7,
    AuthorityUnavailable = 8,
}

impl EndReason {
    fn from_code(code: u8) -> Self {
        match code {
            1 => Self::ClientWentAway,
            2 => Self::ProtocolError,
            3 => Self::SizeLimit,
            4 => Self::IdleTimeout,
            5 => Self::AuthorizationRefused,
            6 => Self::ServerWriteFailed,
            7 => Self::FlowControlRefused,
            8 => Self::AuthorityUnavailable,
            _ => Self::Open,
        }
    }

    pub(super) const fn close_reason(self) -> CloseReason {
        match self {
            Self::ClientWentAway => CLIENT_WENT_AWAY,
            Self::ProtocolError => PROTOCOL_ERROR,
            Self::SizeLimit => crate::stream_close::FRAME_TOO_LARGE,
            Self::IdleTimeout => IDLE_TIMEOUT,
            Self::AuthorizationRefused => RESUME_REFUSED,
            Self::ServerWriteFailed | Self::Open => SERVER_WRITE_FAILED,
            Self::FlowControlRefused => REPLY_QUEUE_FULL,
            Self::AuthorityUnavailable => crate::stream_close::AUTHORITY_UNAVAILABLE,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SocketClose {
    pub(super) code: Option<u16>,
    pub(super) reason: Option<&'static str>,
}
type Writer = Arc<Mutex<SplitSink<WebSocket, Message>>>;

struct Queued {
    input: Inbound,
    _bytes: OwnedSemaphorePermit,
}

enum Reply {
    Wire { nonce: u64, sent_us: u64 },
    Transport(bytes::Bytes),
}

/// Native WebSocket pongs are opaque to browser JavaScript, so carry the existing
/// route correlation in the control-frame payload (well below RFC 6455's limit).
fn encode_transport_probe(nonce: u64, sent_us: u64) -> Bytes {
    let mut payload = [0; 16];
    payload[..8].copy_from_slice(&nonce.to_le_bytes());
    payload[8..].copy_from_slice(&sent_us.to_le_bytes());
    Bytes::copy_from_slice(&payload)
}

fn decode_transport_probe(payload: &[u8]) -> Option<(u64, u64)> {
    if payload.len() != 16 {
        return None;
    }
    let (nonce, sent_us) = payload.split_at(8);
    Some((
        u64::from_le_bytes(nonce.try_into().ok()?),
        u64::from_le_bytes(sent_us.try_into().ok()?),
    ))
}

/// Admit a best-effort proof reply without parking the shared socket reader.
fn queue_reply(sender: &mpsc::Sender<Reply>, reply: Reply) -> bool {
    // A full local queue is temporary pressure. Keep reading correlated Pongs
    // and let their existing deadline decide liveness; a closed writer is fatal.
    match sender.try_send(reply) {
        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

struct Context {
    state: Arc<WebSocketState>,
    user: String,
    token: String,
    writer: Writer,
    lease: LeaseMutex<Liveness>,
    viewer_visibility: bool,
    fast_until: LeaseMutex<tokio::time::Instant>,
    // The first classified end wins so teardown cannot turn malformed input into an ordinary disconnect.
    ended: AtomicU8,
    socket_close: LeaseMutex<SocketClose>,
    closed: Notify,
    proof_changed: Notify,
}

impl Context {
    fn retire(&self, reason: EndReason) {
        if reason != EndReason::Open
            && self
                .ended
                .compare_exchange(0, reason as u8, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.closed.notify_waiters();
        }
    }

    fn end_reason(&self) -> EndReason {
        EndReason::from_code(self.ended.load(Ordering::Acquire))
    }

    fn socket_close(&self) -> SocketClose {
        *self
            .socket_close
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn set_socket_close(&self, close: SocketClose) {
        if let Ok(mut current) = self.socket_close.lock()
            && current.code.is_none()
        {
            *current = close;
        }
    }

    fn reset(&self) -> Result<(), ()> {
        self.lease.lock().map_err(|_| ())?.restart();
        self.note_activity()
    }

    fn note_activity(&self) -> Result<(), ()> {
        *self.fast_until.lock().map_err(|_| ())? = tokio::time::Instant::now() + FAST_PROBE_WINDOW;
        self.proof_changed.notify_one();
        Ok(())
    }

    fn fast_active(&self) -> Result<bool, ()> {
        self.fast_until
            .lock()
            .map(|until| tokio::time::Instant::now() < *until)
            .map_err(|_| ())
    }

    async fn transmit(
        &self,
        mut first: Option<Reply>,
        replies: &mut mpsc::Receiver<Reply>,
        active: bool,
        messages: &mut Vec<Message>,
        encoded: &mut Vec<u8>,
    ) -> Result<(), ()> {
        if self.ended.load(Ordering::Acquire) != 0 {
            return Err(());
        }
        let mut writer = self.writer.lock().await;
        if self.ended.load(Ordering::Acquire) != 0 {
            return Err(());
        }
        messages.clear();
        // Drain only replies that are ready now, preserving queue and message
        // boundaries. The cap also leaves revocation and activity changes a turn.
        for _ in 0..PROOF_BATCH {
            let Some(reply) = first.take().or_else(|| replies.try_recv().ok()) else {
                break;
            };
            let message = match reply {
                Reply::Wire { nonce, sent_us } => {
                    encode_muxed_frame_into(0, &Frame::Pong { nonce, sent_us }, encoded)
                        .map_err(|_| ())?;
                    Message::Binary(Bytes::copy_from_slice(encoded))
                }
                Reply::Transport(bytes) => Message::Pong(bytes),
            };
            messages.push(message);
        }
        let Ok(fast) = self.fast_active() else {
            self.retire(EndReason::ServerWriteFailed);
            return Err(());
        };
        let probe = {
            let Ok(mut lease) = self.lease.lock() else {
                self.retire(EndReason::ServerWriteFailed);
                return Err(());
            };
            if active && lease.retired() {
                self.retire(EndReason::IdleTimeout);
                return Err(());
            }
            let due = lease
                .next_probe_due(fast)
                .is_some_and(|at| at <= tokio::time::Instant::now());
            (active && (due || (!messages.is_empty() && lease.can_piggyback())))
                .then(|| lease.ping())
        };
        if let Some((nonce, sent_us)) = probe {
            messages.push(Message::Ping(encode_transport_probe(nonce, sent_us)));
        }
        if messages.is_empty() {
            return Ok(());
        }
        let result = send_messages(&mut *writer, messages.drain(..)).await;
        if result.is_err() {
            self.retire(EndReason::ServerWriteFailed);
        }
        result
    }
}

/// Own both transport workers; dropping a socket cancels their I/O and releases
/// the reader, writer, session capability and queued payloads before SQL cleanup.
pub(super) struct Transport {
    input: mpsc::Receiver<Queued>,
    active: watch::Sender<bool>,
    context: Arc<Context>,
    tasks: tokio::task::JoinSet<()>,
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.context.retire(EndReason::ServerWriteFailed);
        self.tasks.abort_all();
    }
}

impl Transport {
    pub(super) fn start(
        writer: SplitSink<WebSocket, Message>,
        reader: SplitStream<WebSocket>,
        receive: BytesMut,
        state: Arc<WebSocketState>,
        user: String,
        token: String,
        authority: super::websocket::probe_authority::Lease,
        viewer_visibility: bool,
    ) -> (impl Sink<Message, Error = axum::Error> + Unpin, Self) {
        let writer = Arc::new(Mutex::new(writer));
        let context = Arc::new(Context {
            state,
            user,
            token,
            writer,
            lease: LeaseMutex::new(Liveness::answer_paced()),
            viewer_visibility,
            fast_until: LeaseMutex::new(tokio::time::Instant::now() + FAST_PROBE_WINDOW),
            ended: AtomicU8::new(0),
            socket_close: LeaseMutex::new(SocketClose::default()),
            closed: Notify::new(),
            proof_changed: Notify::new(),
        });
        let (send, input) = mpsc::channel(INPUT_SLOTS);
        let (reply, replies) = mpsc::channel(CONTROL_SLOTS);
        let (active, activity) = watch::channel(false);
        let mut tasks = tokio::task::JoinSet::new();
        // Erase both future types once per connection to share task bookkeeping code.
        tasks.spawn(read(context.clone(), reader, receive, send, reply).boxed());
        tasks.spawn(proofs(context.clone(), activity, replies, authority).boxed());
        // Keep one serialized WebSocket writer. The existing send timeout still
        // covers lock acquisition and flushing; no extra payload copy or queued
        // output is introduced by this adapter.
        let failure = Arc::new(LeaseMutex::new(None));
        let write_failure = failure.clone();
        let inner = Box::pin(futures_util::sink::unfold(
            context.clone(),
            move |context, message| {
                let failure = write_failure.clone();
                async move {
                    let result = async {
                        let mut writer = context.writer.lock().await;
                        if context.ended.load(Ordering::Acquire) != 0 && !shutdown_message(&message)
                        {
                            return Err(axum::Error::new(std::io::Error::from(
                                std::io::ErrorKind::ConnectionAborted,
                            )));
                        }
                        writer.send(message).await?;
                        if context.ended.load(Ordering::Acquire) == 0 {
                            context.note_activity().map_err(|()| {
                                axum::Error::new(std::io::Error::other(
                                    "proof activity state unavailable",
                                ))
                            })?;
                        }
                        Ok(())
                    }
                    .await;
                    if let Err(error) = result {
                        *failure
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
                        context.retire(EndReason::ServerWriteFailed);
                    }
                    // Restore the state before reporting the error through the
                    // adapter. Cleanup may send another frame after a failure.
                    Ok::<_, axum::Error>(context)
                }
            },
        ));
        let sink = SharedSink { inner, failure };
        (
            sink,
            Self {
                input,
                active,
                context,
                tasks,
            },
        )
    }

    pub(super) fn active(&self, active: bool) {
        self.active.send_if_modified(|current| {
            if *current == active {
                return false;
            }
            *current = active;
            true
        });
    }

    pub(super) fn end_reason(&self) -> EndReason {
        self.context.end_reason()
    }

    pub(super) fn socket_close(&self) -> SocketClose {
        self.context.socket_close()
    }

    pub(super) async fn recv(&mut self) -> Result<Option<Inbound>, ()> {
        loop {
            match self.context.ended.load(Ordering::Acquire) {
                1 => return Ok(None),
                2..=8 => return Err(()),
                _ => {}
            }
            tokio::select! {
                () = self.context.closed.notified() => {}
                input = self.input.recv() => {
                    // The worker records the failure before closing its queue.
                    // EOF and the notification can be ready together; recheck
                    // that state so malformed input still gets its wire Close.
                    if let Some(queued) = input { return Ok(Some(queued.input)); }
                },
            }
        }
    }
}

// A failed write must leave the adapter usable for best-effort stream cleanup.
// The socket loop sends terminal Close frames after a failed application write;
// a state-consuming sink loses its writer on error and panics on that cleanup.
struct SharedSink<S> {
    inner: S,
    failure: Arc<LeaseMutex<Option<axum::Error>>>,
}

impl<S: Sink<Message, Error = axum::Error> + Unpin> SharedSink<S> {
    fn report(&self, result: Poll<Result<(), axum::Error>>) -> Poll<Result<(), axum::Error>> {
        match result {
            Poll::Ready(Ok(())) => Poll::Ready(
                self.failure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                    .map_or(Ok(()), Err),
            ),
            other => other,
        }
    }
}

impl<S: Sink<Message, Error = axum::Error> + Unpin> Sink<Message> for SharedSink<S> {
    type Error = axum::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let result = Pin::new(&mut self.inner).poll_ready(cx);
        self.report(result)
    }

    fn start_send(mut self: Pin<&mut Self>, message: Message) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner).start_send(message)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        self.report(result)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let result = Pin::new(&mut self.inner).poll_close(cx);
        self.report(result)
    }
}

fn shutdown_message(message: &Message) -> bool {
    match message {
        Message::Close(_) => true,
        Message::Binary(bytes) => decode_muxed_frame(bytes)
            .is_ok_and(|decoded| matches!(decoded.frame, Frame::Close { .. })),
        _ => false,
    }
}

/// Only this small transport notice is accepted from a viewer, never arbitrary events.
fn visibility_notice(json: &[u8]) -> Option<bool> {
    if json.len() > 128 {
        return None;
    }
    let notice: serde_json::Value = serde_json::from_slice(json).ok()?;
    (notice.get("topic")?.as_str()? == "connection.visibility")
        .then(|| notice.get("hidden")?.as_bool())?
}

// Keep transport controls in one reader turn, ahead of bounded application admission.
async fn read(
    context: Arc<Context>,
    mut reader: SplitStream<WebSocket>,
    mut receive: BytesMut,
    input: mpsc::Sender<Queued>,
    replies: mpsc::Sender<Reply>,
) {
    let bytes = Arc::new(Semaphore::new(MAX_SOCKET_BUFFER));
    let mut deadline = None;
    loop {
        let incoming = tokio::select! {
            () = context.closed.notified() => break,
            incoming = receive_wire(&mut reader, &mut receive, &mut deadline) => incoming,
        };
        let incoming = match incoming {
            Ok(Some(incoming)) => incoming,
            Ok(None) => {
                context.retire(EndReason::ClientWentAway);
                break;
            }
            Err(()) => {
                context.retire(EndReason::ProtocolError);
                break;
            }
        };
        let (incoming, size) = match incoming {
            Inbound::SocketClose { code, reason } => {
                context.set_socket_close(SocketClose { code, reason });
                context.retire(EndReason::ClientWentAway);
                break;
            }
            Inbound::Failure(failure) => {
                context.retire(match failure {
                    ReceiveFailure::ConnectionClosed => EndReason::ClientWentAway,
                    ReceiveFailure::Protocol => EndReason::ProtocolError,
                    ReceiveFailure::SizeLimit => EndReason::SizeLimit,
                    ReceiveFailure::IdleTimeout => EndReason::IdleTimeout,
                });
                break;
            }
            Inbound::TransportPing(payload) => {
                if !queue_reply(&replies, Reply::Transport(payload)) {
                    context.retire(EndReason::ServerWriteFailed);
                    break;
                }
                continue;
            }
            Inbound::TransportPong(payload) => {
                if let Some((nonce, sent_us)) = decode_transport_probe(&payload) {
                    let updated = context
                        .lease
                        .lock()
                        .map(|mut lease| lease.pong(nonce, sent_us));
                    match updated {
                        Ok(true) => context.proof_changed.notify_one(),
                        Ok(false) => {}
                        Err(_) => {
                            context.retire(EndReason::ServerWriteFailed);
                            break;
                        }
                    }
                }
                continue;
            }
            Inbound::Frame(wire) => {
                if let Ok(decoded) = decode_muxed_frame(&wire)
                    && decoded.stream_id == 0
                {
                    match decoded.frame {
                        Frame::Event {
                            sub_id: 0,
                            event_json,
                        } if context.viewer_visibility => {
                            // The bounded lifecycle notice changes probe scheduling only;
                            // socket authority, attachment caps and writer ownership stay strict.
                            // A hidden page gets no probes at all, native ones included: even
                            // a control frame the browser answers without page JavaScript
                            // wakes its network stack and a phone's radio about 30 times a
                            // second at the answer-paced cadence [#317].
                            let hidden = visibility_notice(event_json);
                            let updated = hidden.and_then(|hidden| {
                                context
                                    .lease
                                    .lock()
                                    .ok()
                                    .map(|mut lease| lease.set_suspended(hidden))
                            });
                            if updated.is_none() {
                                context.retire(EndReason::ProtocolError);
                                break;
                            }
                            context.proof_changed.notify_one();
                            continue;
                        }
                        Frame::Pong { nonce, sent_us } => {
                            let updated = context
                                .lease
                                .lock()
                                .map(|mut lease| lease.pong(nonce, sent_us));
                            match updated {
                                Ok(true) => context.proof_changed.notify_one(),
                                Ok(false) => {}
                                Err(_) => {
                                    context.retire(EndReason::ServerWriteFailed);
                                    break;
                                }
                            }
                            continue;
                        }
                        Frame::Ping { nonce, sent_us } => {
                            if !queue_reply(&replies, Reply::Wire { nonce, sent_us }) {
                                context.retire(EndReason::ServerWriteFailed);
                                break;
                            }
                            continue;
                        }
                        _ => {}
                    }
                }
                let size = u32::try_from(wire.len());
                (Inbound::Frame(wire), size)
            }
        };
        let Ok(size) = size else {
            context.retire(EndReason::SizeLimit);
            break;
        };
        let admitted = async {
            let permit = bytes
                .clone()
                .acquire_many_owned(size)
                .await
                .map_err(|_| ())?;
            input
                .send(Queued {
                    input: incoming,
                    _bytes: permit,
                })
                .await
                .map_err(|_| ())
        };
        tokio::select! {
            () = context.closed.notified() => break,
            result = admitted => if result.is_err() { context.retire(EndReason::ServerWriteFailed); break; },
        }
    }
}

async fn proofs(
    context: Arc<Context>,
    mut activity: watch::Receiver<bool>,
    mut replies: mpsc::Receiver<Reply>,
    mut authority: super::websocket::probe_authority::Lease,
) {
    let mut active = false;
    let mut messages = Vec::new();
    let mut encoded = Vec::new();
    loop {
        // Another ready branch may win beside the retirement notification.
        if context.ended.load(Ordering::Acquire) != 0 {
            break;
        }
        let Ok(fast) = context.fast_active() else {
            context.retire(EndReason::ServerWriteFailed);
            break;
        };
        let Ok((next_probe, response_deadline)) = context
            .lease
            .lock()
            .map(|lease| (lease.next_probe_due(fast), lease.response_deadline()))
        else {
            context.retire(EndReason::ServerWriteFailed);
            break;
        };
        let first = tokio::select! {
            () = context.closed.notified() => break,
            changed = activity.changed() => {
                if changed.is_err() { break; }
                active = *activity.borrow_and_update();
                if context.reset().is_err() {
                    context.retire(EndReason::ServerWriteFailed);
                    break;
                }
                continue;
            }
            () = context.proof_changed.notified() => None,
            () = wait_deadline(next_probe), if active => None,
            () = wait_deadline(response_deadline), if active => None,
            reply = replies.recv() => {
                let Some(reply) = reply else { break; };
                Some(reply)
            }
        };
        // Probe only under an activation this loop has already applied. Another wake
        // can win the select beside an unseen activation; that activation's reset
        // then clears every issued probe, so a probe sent first is refused when its
        // answer arrives and the route stays unsampled until the next startup tick.
        // A deactivation is honoured at once, before it is consumed.
        let active = activation_applied(active, &activity);
        if first.is_none() && replies.is_empty() {
            let Ok(fast) = context.fast_active() else {
                context.retire(EndReason::ServerWriteFailed);
                break;
            };
            let Ok(idle) = context.lease.lock().map(|lease| {
                !active
                    || (!lease.retired()
                        && lease
                            .next_probe_due(fast)
                            .is_none_or(|at| at > tokio::time::Instant::now()))
            }) else {
                context.retire(EndReason::ServerWriteFailed);
                break;
            };
            // An answer only changes scheduling; it does not need a writer or
            // an authority operation. Rearm deadlines on the next loop turn.
            if idle {
                continue;
            }
        }
        // A queued reply already has its reader event. Timer-driven sends give
        // runnable socket data one turn to join the same bounded write.
        if first.is_none() {
            tokio::task::yield_now().await;
        }
        let active = activation_applied(active, &activity);
        let result = authority.run(&context.state, &context.user, &context.token, async {
            let result = tokio::select! {
                biased;
                () = context.closed.notified() => Err(()),
                result = context.transmit(first, &mut replies, active, &mut messages, &mut encoded) => result,
            };
            // An authorized write failure is transport failure. The outer error
            // classification below is reserved for the authority check itself.
            if result.is_err() && context.end_reason() == EndReason::Open {
                context.retire(EndReason::ServerWriteFailed);
            }
            result
        }).await;
        if let Err(miss) = result {
            if context.end_reason() == EndReason::Open {
                context.retire(match miss {
                    AuthorityMiss::Refused => EndReason::AuthorizationRefused,
                    AuthorityMiss::Unavailable => EndReason::AuthorityUnavailable,
                });
            }
            break;
        }
    }
    if context.end_reason() == EndReason::Open {
        context.retire(EndReason::ServerWriteFailed);
    }
}

/// Whether this loop may probe: it is active, and no later activity change is waiting unseen. Reading
/// the shared value alone is not enough: active, idle and active again between two turns leaves it
/// true while the reset for the first activation is still owed, and a probe sent before that reset is
/// cleared and refused when its answer arrives. An unseen change (or a closed channel) means not yet;
/// the next turn consumes it and resets first.
fn activation_applied(active: bool, activity: &watch::Receiver<bool>) -> bool {
    active && !activity.has_changed().unwrap_or(true)
}

/// An absent deadline parks without creating a timer [D81].
async fn wait_deadline(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod queue_tests {
    //! Keeps proof reply overflow separate from an actually closed writer, #234.
    use super::*;

    #[tokio::test]
    async fn full_browser_wire_proof_queue_keeps_connection_usable() {
        verify_full_proof_queue(Reply::Wire {
            nonce: 2,
            sent_us: 3,
        })
        .await;
    }

    #[tokio::test]
    async fn full_browser_transport_proof_queue_keeps_connection_usable() {
        verify_full_proof_queue(Reply::Transport(Bytes::from_static(b"probe"))).await;
    }

    async fn verify_full_proof_queue(reply: Reply) {
        let (sender, mut receiver) = mpsc::channel(1);
        assert!(queue_reply(
            &sender,
            Reply::Wire {
                nonce: 1,
                sent_us: 1
            }
        ));
        assert!(
            queue_reply(&sender, reply),
            "local proof queue fullness must not retire the socket"
        );
        assert!(matches!(
            receiver.recv().await,
            Some(Reply::Wire {
                nonce: 1,
                sent_us: 1
            })
        ));
        assert!(queue_reply(
            &sender,
            Reply::Wire {
                nonce: 4,
                sent_us: 5
            }
        ));
        assert!(matches!(
            receiver.recv().await,
            Some(Reply::Wire {
                nonce: 4,
                sent_us: 5
            })
        ));
        drop(receiver);
        assert!(
            !queue_reply(
                &sender,
                Reply::Wire {
                    nonce: 6,
                    sent_us: 7
                }
            ),
            "a closed reply writer still fails"
        );
    }
}

#[cfg(test)]
mod tests {
    //! End conditions stay specific through socket teardown and structured logging.
    use super::*;

    #[test]
    fn native_transport_probe_payload_preserves_correlations_and_rejects_bad_lengths() {
        let probe = (u64::MAX - 1, u64::MAX - 2);
        let payload = encode_transport_probe(probe.0, probe.1);
        assert_eq!(payload.len(), 16);
        assert_eq!(decode_transport_probe(&payload), Some(probe));
        for length in [0, 8, 15, 17, 125] {
            assert_eq!(decode_transport_probe(&vec![0; length]), None);
        }
    }

    #[test]
    fn visibility_notices_are_small_typed_transport_messages() {
        assert_eq!(
            visibility_notice(br#"{"topic":"connection.visibility","hidden":true}"#),
            Some(true)
        );
        assert_eq!(
            visibility_notice(br#"{"topic":"connection.visibility","hidden":false}"#),
            Some(false)
        );
        for bytes in [
            br#"{"topic":"other","hidden":true}"#.as_slice(),
            br#"{"topic":"connection.visibility","hidden":1}"#,
            b"null",
            &[b' '; 129],
        ] {
            assert_eq!(visibility_notice(bytes), None);
        }
    }

    #[test]
    fn no_probe_in_an_active_idle_active_window() {
        let (send, mut seen) = watch::channel(false);
        send.send_replace(true);
        assert!(
            !activation_applied(true, &seen),
            "an unseen change blocks the probe"
        );
        assert!(*seen.borrow_and_update());
        assert!(activation_applied(true, &seen), "applied once consumed");
        // Deactivate and reactivate before the loop looks again: the value reads true but is unseen.
        send.send_replace(false);
        send.send_replace(true);
        assert!(*seen.borrow(), "the shared value alone cannot tell");
        assert!(!activation_applied(true, &seen));
        assert!(!activation_applied(false, &seen));
        drop(send);
        assert!(
            !activation_applied(true, &seen),
            "a closed channel never probes"
        );
    }

    #[test]
    fn each_receive_end_has_a_structured_terminal_close_reason() {
        let cases = [
            (
                EndReason::ClientWentAway,
                "client_went_away",
                "websocket_closed",
            ),
            (
                EndReason::AuthorityUnavailable,
                "server_busy",
                "authority_unavailable",
            ),
            (EndReason::ProtocolError, "protocol_error", "invalid_frame"),
            (EndReason::SizeLimit, "size_limit", "frame_too_large"),
            (EndReason::IdleTimeout, "idle", "liveness_timeout"),
            (
                EndReason::AuthorizationRefused,
                "auth_resume_refusal",
                "connection_resume_refused",
            ),
            (
                EndReason::ServerWriteFailed,
                "server_transport_error",
                "websocket_write_failed",
            ),
            (
                EndReason::FlowControlRefused,
                "flow_control_refusal",
                "control_reply_queue_full",
            ),
        ];
        for (end, category, kind) in cases {
            let reason = end.close_reason();
            assert_eq!(reason.category, category);
            assert_eq!(reason.kind, kind);
        }
    }
}
