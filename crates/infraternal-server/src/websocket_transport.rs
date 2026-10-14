//! Keeps authenticated browser proofs responsive while application work awaits SQL or a host [D265, #199].

use super::websocket::{
    Inbound, MAX_ATTACHMENTS, MAX_SOCKET_BUFFER, WebSocketState, receive_wire, send_messages,
};
use crate::liveness::Liveness;
use axum::extract::ws::{Message, WebSocket};
use bytes::{Bytes, BytesMut};
use futures_util::{
    Sink, SinkExt,
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
type Writer = Arc<Mutex<SplitSink<WebSocket, Message>>>;

struct Queued {
    input: Inbound,
    _bytes: OwnedSemaphorePermit,
}

enum Reply {
    Wire { nonce: u64, sent_us: u64 },
    Transport(bytes::Bytes),
}

struct Context {
    state: Arc<WebSocketState>,
    user: String,
    token: String,
    writer: Writer,
    lease: LeaseMutex<Liveness>,
    fast_until: LeaseMutex<tokio::time::Instant>,
    // 0 is usable, 1 is an ordinary end, 2 is a protocol failure. The first end
    // wins so teardown cannot turn malformed input into an ordinary disconnect.
    ended: AtomicU8,
    closed: Notify,
    proof_changed: Notify,
}

impl Context {
    fn retire(&self, failed: bool) {
        let _ = self.ended.compare_exchange(
            0,
            if failed { 2 } else { 1 },
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.closed.notify_waiters();
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
        let fast = self.fast_active()?;
        let probe = {
            let mut lease = self.lease.lock().map_err(|_| ())?;
            if active && lease.expired() {
                return Err(());
            }
            let due = lease
                .next_probe_due(fast)
                .is_some_and(|at| at <= tokio::time::Instant::now());
            (active && (due || (!messages.is_empty() && lease.can_piggyback())))
                .then(|| lease.ping())
        };
        if let Some((nonce, sent_us)) = probe {
            encode_muxed_frame_into(0, &Frame::Ping { nonce, sent_us }, encoded).map_err(|_| ())?;
            messages.push(Message::Binary(Bytes::copy_from_slice(encoded)));
        }
        if messages.is_empty() {
            return Ok(());
        }
        send_messages(&mut *writer, messages.drain(..)).await
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
        self.context.retire(false);
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
    ) -> (impl Sink<Message, Error = axum::Error> + Unpin, Self) {
        let writer = Arc::new(Mutex::new(writer));
        let context = Arc::new(Context {
            state,
            user,
            token,
            writer,
            lease: LeaseMutex::new(Liveness::answer_paced()),
            fast_until: LeaseMutex::new(tokio::time::Instant::now() + FAST_PROBE_WINDOW),
            ended: AtomicU8::new(0),
            closed: Notify::new(),
            proof_changed: Notify::new(),
        });
        let (send, input) = mpsc::channel(INPUT_SLOTS);
        let (reply, replies) = mpsc::channel(CONTROL_SLOTS);
        let (active, activity) = watch::channel(false);
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(read(context.clone(), reader, receive, send, reply));
        tasks.spawn(proofs(context.clone(), activity, replies, authority));
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

    pub(super) async fn recv(&mut self) -> Result<Option<Inbound>, ()> {
        loop {
            match self.context.ended.load(Ordering::Acquire) {
                1 => return Ok(None),
                2 => return Err(()),
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
                context.retire(false);
                break;
            }
            Err(()) => {
                context.retire(true);
                break;
            }
        };
        let (incoming, size) = match incoming {
            Inbound::TransportPing(payload) => {
                if replies.try_send(Reply::Transport(payload)).is_err() {
                    context.retire(true);
                    break;
                }
                continue;
            }
            Inbound::Frame(wire) => {
                if let Ok(decoded) = decode_muxed_frame(&wire)
                    && decoded.stream_id == 0
                {
                    match decoded.frame {
                        Frame::Pong { nonce, sent_us } => {
                            let updated = context
                                .lease
                                .lock()
                                .map(|mut lease| lease.pong(nonce, sent_us));
                            match updated {
                                Ok(true) => context.proof_changed.notify_one(),
                                Ok(false) => {}
                                Err(_) => {
                                    context.retire(true);
                                    break;
                                }
                            }
                            continue;
                        }
                        Frame::Ping { nonce, sent_us } => {
                            if replies.try_send(Reply::Wire { nonce, sent_us }).is_err() {
                                context.retire(true);
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
            context.retire(true);
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
            result = admitted => if result.is_err() { context.retire(false); break; },
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
            break;
        };
        let Ok((next_probe, response_deadline)) = context
            .lease
            .lock()
            .map(|lease| (lease.next_probe_due(fast), lease.response_deadline()))
        else {
            break;
        };
        let first = tokio::select! {
            () = context.closed.notified() => break,
            changed = activity.changed() => {
                if changed.is_err() { break; }
                active = *activity.borrow_and_update();
                if context.reset().is_err() { break; }
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
        let active = *activity.borrow();
        if first.is_none() && replies.is_empty() {
            let Ok(fast) = context.fast_active() else {
                break;
            };
            let Ok(idle) = context.lease.lock().map(|lease| {
                !active
                    || (!lease.expired()
                        && lease
                            .next_probe_due(fast)
                            .is_none_or(|at| at > tokio::time::Instant::now()))
            }) else {
                break;
            };
            // An answer only changes scheduling; it does not need a writer or
            // an authority operation. Rearm deadlines on the next loop turn.
            if idle {
                continue;
            }
        }
        // Collect already-runnable replies without a timed coalescing wait.
        // Fallback and response margins still sum to measured RTT + 50ms.
        tokio::task::yield_now().await;
        let active = *activity.borrow();
        let result = authority.run(&context.state, &context.user, &context.token, async {
            tokio::select! {
                biased;
                () = context.closed.notified() => Err(()),
                result = context.transmit(first, &mut replies, active, &mut messages, &mut encoded) => result,
            }
        }).await;
        if result.is_err() {
            break;
        }
    }
    context.retire(false);
}

/// An absent deadline parks without creating a timer [D81].
async fn wait_deadline(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
