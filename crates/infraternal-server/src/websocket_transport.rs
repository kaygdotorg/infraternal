//! Keeps authenticated browser proofs responsive while application work awaits SQL or a host [D265, #199].

use super::websocket::{
    Inbound, MAX_ATTACHMENTS, MAX_SOCKET_BUFFER, WebSocketState, receive_wire, send_frame,
    send_message, while_authorized,
};
use crate::liveness::{Liveness, TICK};
use axum::extract::ws::{Message, WebSocket};
use bytes::BytesMut;
use futures_util::{
    Sink, SinkExt,
    stream::{SplitSink, SplitStream},
};
use infraternal_protocol::{Frame, decode_muxed_frame};
use std::sync::{
    Arc, Mutex as LeaseMutex,
    atomic::{AtomicU8, Ordering},
};
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch};

// One attach plus its credit per admitted window. Payload admission also has a
// byte bound: a client cannot turn these small-frame slots into 64 full-size frames.
const INPUT_SLOTS: usize = MAX_ATTACHMENTS * 2;
const CONTROL_SLOTS: usize = 128;
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
    // 0 is usable, 1 is an ordinary end, 2 is a protocol failure. The first end
    // wins so teardown cannot turn malformed input into an ordinary disconnect.
    ended: AtomicU8,
    closed: Notify,
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
        *self.lease.lock().map_err(|_| ())? = Liveness::new();
        Ok(())
    }

    async fn reply(&self, reply: Reply) -> Result<(), ()> {
        while_authorized(&self.state, &self.user, &self.token, true, async {
            let mut writer = self.writer.lock().await;
            match reply {
                Reply::Wire { nonce, sent_us } => {
                    send_frame(
                        &mut *writer,
                        0,
                        &Frame::Pong { nonce, sent_us },
                        &mut Vec::new(),
                    )
                    .await
                }
                Reply::Transport(bytes) => send_message(&mut *writer, Message::Pong(bytes)).await,
            }
        })
        .await
    }

    async fn probe(&self) -> Result<(), ()> {
        while_authorized(&self.state, &self.user, &self.token, true, async {
            let mut writer = self.writer.lock().await;
            let (nonce, sent_us) = self.lease.lock().map_err(|_| ())?.ping();
            send_frame(
                &mut *writer,
                0,
                &Frame::Ping { nonce, sent_us },
                &mut Vec::new(),
            )
            .await
        })
        .await
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
    ) -> (impl Sink<Message, Error = axum::Error> + Unpin, Self) {
        let writer = Arc::new(Mutex::new(writer));
        let context = Arc::new(Context {
            state,
            user,
            token,
            writer,
            lease: LeaseMutex::new(Liveness::new()),
            ended: AtomicU8::new(0),
            closed: Notify::new(),
        });
        let (send, input) = mpsc::channel(INPUT_SLOTS);
        let (reply, replies) = mpsc::channel(CONTROL_SLOTS);
        let (active, activity) = watch::channel(false);
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(read(context.clone(), reader, receive, send, reply));
        tasks.spawn(proofs(context.clone(), activity, replies));
        // Keep one serialized WebSocket writer. The existing send timeout still
        // covers lock acquisition and flushing; no extra payload copy or queued
        // output is introduced by this adapter.
        let sink = Box::pin(futures_util::sink::unfold(
            context.clone(),
            |context, message| async move {
                let mut writer = context.writer.lock().await;
                if context.ended.load(Ordering::Acquire) != 0 && !shutdown_message(&message) {
                    return Err(axum::Error::new(std::io::Error::from(
                        std::io::ErrorKind::ConnectionAborted,
                    )));
                }
                writer.send(message).await?;
                drop(writer);
                Ok(context)
            },
        ));
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
                            if updated.is_err() {
                                context.retire(true);
                                break;
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
) {
    let mut ticks = tokio::time::interval(TICK);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut active = false;
    loop {
        let result = tokio::select! {
            () = context.closed.notified() => break,
            changed = activity.changed() => {
                if changed.is_err() { break; }
                active = *activity.borrow_and_update();
                if context.reset().is_err() { break; }
                continue;
            }
            reply = replies.recv() => {
                let Some(reply) = reply else { break; };
                context.reply(reply).await
            }
            _ = ticks.tick(), if active => {
                let expired = context.lease.lock().map_or(true, |lease| lease.expired());
                if expired { break; }
                context.probe().await
            }
        };
        if result.is_err() {
            break;
        }
    }
    context.retire(false);
}
