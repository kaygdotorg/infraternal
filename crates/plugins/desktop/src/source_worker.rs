//! Multiplexes one source helper's control replies and bounded media while keeping native input independent of video writes [D200,D203,D232].
//!
//! [`run`] is the task behind one served data lane. It starts a private helper,
//! sends it the session's `Start` request, and then runs two cooperating loops:
//!
//! - The pump reads from the lane and the helper. Commands from the server
//!   (input, size, control, repair) are translated and forwarded to the helper
//!   in order; the helper's replies are matched to them in order; and video from
//!   the helper is handed to the sender. Every reply is owed within 3 seconds,
//!   but while nothing is owed and no video flows there is no timer at all.
//! - The sender (`send_video`) writes video to the lane in its own task, so a
//!   slow or blocked video write can never delay input. Between them sits an
//!   age-bounded queue ([`crate::backlog`]): a sender that falls behind for a
//!   moment catches up with the waiting delta frames. Only a sender more than
//!   about 100 ms behind loses them, and then a keyframe is requested, because
//!   a delta frame after a gap cannot be decoded.
//!
//! When the task ends for any reason, the helper is stopped and its cleanup
//! result is reported separately from the session's own result.
use crate::{
    backlog::{Admission, Backlog},
    media::{ASSEMBLY_TIMEOUT, Video},
    protocol::{self, Input, Kind, Size},
    source::{Control, Metadata, Outcome},
    source_ipc::{Config, Helper},
};
use infraternal_plugin_api::{PluginError, streams::WireLane};
use infraternal_protocol::{
    Frame, decode_frame,
    desktop::{Delivery, EndReason, Input as WireInput, Message},
    encode_frame_into,
};
use serde_json::Value;
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Notify, mpsc, watch};
use uuid::Uuid;

/// Everything a worker needs to serve one lane.
pub(super) struct Leg {
    /// The session id, used to tag datagram fragments.
    pub id: Uuid,
    /// The session's shared size and sequence counter.
    pub metadata: Arc<Metadata>,
    pub lane: Arc<dyn WireLane>,
    /// Reliable frames or datagram fragments.
    pub delivery: Delivery,
    /// Becomes true when the worker should stop.
    pub cancelled: watch::Receiver<bool>,
    /// Requests from elsewhere in the plugin (such as a clock query).
    pub requests: mpsc::Receiver<Control>,
    /// Lets the video sender queue keyframe and congestion requests.
    pub repair: mpsc::Sender<Control>,
}
/// Retires the lane when dropped, however the worker ends.
struct Lease(Arc<dyn WireLane>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.retire();
    }
}
// A solicited reply owns one fixed send+reply deadline; video never renews it.
const CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
/// A command sent to the helper whose reply has not arrived yet.
struct Pending {
    /// When the reply is overdue.
    deadline: tokio::time::Instant,
    /// The reply kind that answers it. Replies must come back in order.
    expected: Kind,
    /// Where to pass the reply body on, for requests that want it.
    reply: Option<tokio::sync::oneshot::Sender<Result<Value, PluginError>>>,
}
/// The frames waiting between the pump and the video sender.
///
/// One in-flight write plus an age-bounded [`Backlog`] bound storage: a
/// stalled lane can hold at most about 100 ms of video, never an unbounded
/// queue ahead of new damage.
#[derive(Default)]
struct Waiting {
    /// Frames the sender has not taken yet, oldest first.
    backlog: Mutex<Backlog<Video>>,
    /// Wakes the sender when a frame is queued or the pump goes away. It keeps
    /// one permit, so a wake-up just before the sender waits is not lost.
    ready: Notify,
    /// The pump has finished; the sender ends once the backlog is empty.
    closed: AtomicBool,
}
/// The producing end of [`Waiting`]. Dropping it lets the sender finish.
struct PendingVideo {
    waiting: Arc<Waiting>,
}
/// Creates the frame queue: the publisher and the sender's end.
fn pending_video() -> (PendingVideo, Arc<Waiting>) {
    let waiting = Arc::new(Waiting::default());
    (
        PendingVideo {
            waiting: Arc::clone(&waiting),
        },
        waiting,
    )
}
impl PendingVideo {
    /// Queues `video` for the sender. Never waits for a transport write: a
    /// blocked lane only makes the backlog overflow, and control stays
    /// independent. On anything but [`Admission::Queued`] the caller asks for
    /// a keyframe; the frames that waited were dropped.
    fn publish(&self, video: Video) -> Admission {
        let admission = self
            .waiting
            .backlog
            .lock()
            .map_or(Admission::Overflowed, |mut backlog| {
                backlog.push(video, tokio::time::Instant::now().into_std())
            });
        if admission == Admission::Queued {
            self.waiting.ready.notify_one();
        }
        admission
    }
}
impl Drop for PendingVideo {
    fn drop(&mut self) {
        self.waiting.closed.store(true, Ordering::Release);
        self.waiting.ready.notify_one();
    }
}
/// Runs one lane to completion: starts a helper, opens the capture, pumps until
/// the lane ends or `leg.cancelled` is set, and stops the helper.
///
/// The returned [`Outcome`] has two parts. `output` is `Ok` for a normal or
/// cancelled end and an error if something failed. `cleanup` says whether the
/// helper was confirmed stopped.
pub(super) async fn run(config: Config, mut leg: Leg) -> Outcome {
    let _lease = Lease(leg.lane.clone());
    if *leg.cancelled.borrow() {
        return Outcome {
            output: Ok(Value::Null),
            cleanup: Ok(()),
        };
    }
    // A root agent's helper runs as the person at the screen. With nobody
    // logged in, wait (idle, nothing started) instead of failing at once,
    // which would only make the server attach again in a tight loop.
    if config.cross_user.is_some() {
        tokio::select! { biased;
            _ = leg.cancelled.changed() => {
                return Outcome {
                    output: Ok(Value::Null),
                    cleanup: Ok(()),
                };
            }
            () = crate::cross_user::someone_at_screen() => {}
        }
    }
    let mut helper = match Helper::start(&config, &mut leg.cancelled).await {
        Ok(helper) => helper,
        Err(error) => return Outcome::failed(error.cleanup()),
    };
    // A session first shown for one person never shows another's screen: a
    // leg whose helper runs for someone else ends the session before `Start`.
    if !leg.metadata.bind_console(helper.console_uid()) {
        return Outcome::failed(helper.stop().await.map_err(|_| PluginError::Rejected));
    }
    let result = async {
        let start = leg
            .metadata
            .start
            .lock()
            .map_err(|_| PluginError::Rejected)?
            .clone();
        let opening = serde_json::to_vec(&start).map_err(|_| PluginError::Rejected)?;
        let started: std::io::Result<()> = tokio::select! { biased;
            _ = leg.cancelled.changed() => Ok(()),
            result = async {
                let (kind, body) = tokio::time::timeout(CONTROL_TIMEOUT, async {
                    helper.send(Kind::Start, &opening).await?;
                    helper.receive().await
                }).await.map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
                if kind != Kind::Geometry {
                    if kind == Kind::Error { remember_closed_window(&leg.metadata, &body); }
                    return Err(std::io::ErrorKind::PermissionDenied.into());
                }
                Ok(())
            } => result,
        };
        started.map_err(|_| PluginError::Rejected)?;
        if *leg.cancelled.borrow() {
            Ok(())
        } else {
            pump(&mut helper, &mut leg).await
        }
    }
    .await;
    let cancelled = *leg.cancelled.borrow();
    let cleanup = helper.stop().await.map_err(|_| PluginError::Rejected);
    Outcome {
        output: if cancelled {
            Ok(Value::Null)
        } else {
            result.map(|()| Value::Null)
        },
        cleanup,
    }
}

/// The main loop once the helper is capturing; see the module docs.
///
/// At most 64 commands may await replies at a time. It fails if a reply is
/// overdue, arrives out of order, or is an error, if the helper sends something
/// unexpected, or if the video sender fails. It returns `Ok` when cancelled or
/// when the request channel closes. On the way out the lane is retired and the
/// video sender is stopped.
async fn pump(helper: &mut Helper, leg: &mut Leg) -> Result<(), PluginError> {
    let (send, receive) = pending_video();
    let lane = leg.lane.clone();
    let repair = leg.repair.clone();
    let id = leg.id;
    let mode = leg.delivery;
    let mut sender = tokio::spawn(async move { send_video(lane, mode, id, receive, repair).await });
    let mut pending = VecDeque::<Pending>::new();
    // A keyframe request for an overflowed backlog could not be queued yet.
    let mut repair_owed = false;
    // A root agent's helper runs as the person at the screen. When that person
    // changes, the session ends for good (`gone`), whole-screen ones included.
    let mut console = helper.console_watch();
    let result = async {
        loop {
            if *leg.cancelled.borrow() { return Ok(()); }
            tokio::select! { biased;
                _ = leg.cancelled.changed() => return Ok(()),
                () = console.changed() => {
                    leg.metadata.console_changed();
                    return Err(PluginError::Rejected);
                }
                // No deadline exists while video is idle and no control reply is owed.
                () = async { match pending.front() { Some(response) => tokio::time::sleep_until(response.deadline).await, None => std::future::pending().await } } => return Err(PluginError::Rejected),
                result = &mut sender => return result.map_err(|_| PluginError::Rejected).and_then(|result| result),
                packet = leg.lane.receive(), if pending.len() < 64 => {
                    let packet = packet.map_err(|()| PluginError::Rejected)?;
                    let (kind, body) = command(&packet, &leg.metadata)?;
                    crate::measurement::control("source_control_receive", kind);
                    let deadline = tokio::time::Instant::now() + CONTROL_TIMEOUT;
                    let send_deadline = pending.front().map_or(deadline, |response| response.deadline.min(deadline));
                    tokio::time::timeout_at(send_deadline, helper.send(kind, &body)).await.map_err(|_| PluginError::Rejected)?.map_err(|_| PluginError::Rejected)?;
                    crate::measurement::control("source_control_sent", kind);
                    pending.push_back(Pending { deadline, expected: reply_kind(kind), reply: None });
                },
                request = leg.requests.recv(), if pending.len() < 64 => {
                    let Some(request) = request else { return Ok(()); };
                    let deadline = tokio::time::Instant::now() + CONTROL_TIMEOUT;
                    let send_deadline = pending.front().map_or(deadline, |response| response.deadline.min(deadline));
                    tokio::time::timeout_at(send_deadline, helper.send(request.kind, b"{}")).await.map_err(|_| PluginError::Rejected)?.map_err(|_| PluginError::Rejected)?;
                    pending.push_back(Pending { deadline, expected: reply_kind(request.kind), reply: request.reply });
                },
                message = helper.receive() => {
                    let (kind, body) = message.map_err(|_| PluginError::Rejected)?;
                    if kind == Kind::Video {
                        let video = video(&body, &leg.metadata)?;
                        crate::measurement::frame("source_helper_read", &video);
                        // The sender fell beyond the backlog's bound: only an IDR can
                        // follow. Ask once per overflow; retry on later sealed deltas
                        // only while the bounded repair queue had no room.
                        let admission = send.publish(video);
                        if admission == Admission::Overflowed || (admission == Admission::Sealed && repair_owed) {
                            repair_owed = leg.repair.try_send(Control { kind: Kind::Keyframe, reply: None }).is_err();
                        }
                    } else if kind == Kind::Error {
                        remember_closed_window(&leg.metadata, &body);
                        return Err(PluginError::Rejected);
                    }
                    else if pending.front().is_some_and(|response| response.expected == kind) {
                        crate::measurement::control("source_control_ack", kind);
                        let response = pending.pop_front().ok_or(PluginError::Rejected)?;
                        if let Some(reply) = response.reply { let value = serde_json::from_slice(&body).map_err(|_| PluginError::Rejected); let _ = reply.send(value); }
                    } else if kind != Kind::Geometry { return Err(PluginError::Rejected); }
                },
            }
        }
    }.await;
    // A cancelled provider operation never detaches its video writer. Closing
    // this native lease cancels pending writes before joining the owned task.
    leg.lane.retire();
    if !sender.is_finished() {
        sender.abort();
        let _ = sender.await;
    }
    result
}

/// Keeps the companion's permanent closure result across replacement capture lanes.
/// Generic helper errors and transport failures leave the target eligible to reconnect.
fn remember_closed_window(metadata: &Metadata, body: &[u8]) {
    if let Ok(reply) = serde_json::from_slice::<Value>(body)
        && reply["state"] == "gone"
    {
        metadata.latch_gone(EndReason::from_helper_word(reply["reason"].as_str()));
    }
}
/// Turns the helper's video payload (8-byte capture time, 1-byte keyframe flag,
/// then the encoded frame) into a [`Video`] with the next sequence number from
/// the session's counter. Rejects a malformed payload or an exhausted counter.
fn video(body: &bytes::Bytes, metadata: &Metadata) -> Result<Video, PluginError> {
    if body.len() < 10 || body[8] > 1 {
        return Err(PluginError::Rejected);
    }
    let sequence = metadata
        .sequence
        .try_update(Ordering::AcqRel, Ordering::Acquire, |sequence| {
            sequence.checked_add(1)
        })
        .map_err(|_| PluginError::Rejected)?
        .checked_add(1)
        .ok_or(PluginError::Rejected)?;
    let capture_ns = u64::from_be_bytes(body[..8].try_into().map_err(|_| PluginError::Rejected)?);
    let video = Video {
        sequence,
        capture_ns,
        keyframe: body[8] == 1,
        bytes: body.slice(9..),
    };
    video.validate().map_err(|_| PluginError::Rejected)?;
    Ok(video)
}
/// Writes each waiting frame to the lane, oldest first, until the pump has
/// gone and nothing waits.
///
/// Reliable mode sends a whole frame per packet; datagram mode sends
/// fixed-size fragments. A frame gets 250 ms to be written, otherwise the worker
/// fails. After a gap in sequence numbers, delta frames are skipped and a
/// keyframe is requested through `repair` until one arrives. A write slower than
/// 100 ms also queues a congestion hint for the encoder, as long as one slot of
/// the repair queue stays free for keyframe requests.
async fn send_video(
    lane: Arc<dyn WireLane>,
    mode: Delivery,
    id: Uuid,
    frames: Arc<Waiting>,
    repair: mpsc::Sender<Control>,
) -> Result<(), PluginError> {
    let datagrams = match mode {
        Delivery::Reliable => None,
        Delivery::Datagram => Some(lane.datagrams().ok_or(PluginError::Rejected)?),
    };
    let mut wire = Vec::new();
    let mut previous = 0;
    let mut waiting_keyframe = true;
    loop {
        let next = frames
            .backlog
            .lock()
            .map_err(|_| PluginError::Rejected)?
            .pop(tokio::time::Instant::now().into_std());
        let Some(video) = next else {
            if frames.closed.load(Ordering::Acquire) {
                break;
            }
            // A notify sent since the last check left its permit, so this
            // returns at once and the backlog is checked again.
            frames.ready.notified().await;
            continue;
        };
        if previous != 0 && previous + 1 != video.sequence {
            waiting_keyframe = true;
        }
        if waiting_keyframe && !video.keyframe {
            let _ = repair.try_send(Control {
                kind: Kind::Keyframe,
                reply: None,
            });
            continue;
        }
        crate::measurement::frame("source_send_begin", &video);
        let began = std::time::Instant::now();
        let send = async {
            if let Some(datagrams) = &datagrams {
                let total = u32::try_from(video.bytes.len()).map_err(|_| ())?;
                for (index, chunk) in video
                    .bytes
                    .chunks(crate::datagram::FRAGMENT_BYTES)
                    .enumerate()
                {
                    let offset =
                        u32::try_from(index * crate::datagram::FRAGMENT_BYTES).map_err(|_| ())?;
                    encode_frame_into(
                        &Frame::Desktop(Message::Fragment {
                            session_id: id.as_bytes(),
                            sequence: video.sequence,
                            capture_ns: video.capture_ns,
                            keyframe: video.keyframe,
                            total,
                            offset,
                            bytes: chunk,
                        }),
                        &mut wire,
                    )
                    .map_err(|_| ())?;
                    datagrams.send(&wire).await?;
                }
                Ok(())
            } else {
                encode_frame_into(
                    &Frame::Desktop(Message::Video {
                        sequence: video.sequence,
                        capture_ns: video.capture_ns,
                        keyframe: video.keyframe,
                        bytes: &video.bytes,
                    }),
                    &mut wire,
                )
                .map_err(|_| ())?;
                lane.send(&wire).await
            }
        };
        tokio::time::timeout(ASSEMBLY_TIMEOUT, send)
            .await
            .map_err(|_| PluginError::Rejected)?
            .map_err(|()| PluginError::Rejected)?;
        crate::measurement::frame("source_send_end", &video);
        // Propagate leg-B backpressure to capture quality. This shares the
        // bounded repair queue, so slow links cannot create an unbounded task
        // or control backlog. Reserve a slot for mandatory delta repair; quality
        // feedback must never prevent the next decodable picture. Browser-leg
        // pressure still requires its own signal.
        if began.elapsed() >= std::time::Duration::from_millis(100) && repair.capacity() > 1 {
            let _ = repair.try_send(Control {
                kind: Kind::Congested,
                reply: None,
            });
        }
        previous = video.sequence;
        waiting_keyframe = false;
    }
    Ok(())
}
/// The kind of reply that answers a request of `kind`.
fn reply_kind(kind: Kind) -> Kind {
    match kind {
        Kind::Start | Kind::Resize => Kind::Geometry,
        Kind::Input => Kind::InputResult,
        _ => Kind::State,
    }
}
/// Translates one viewer packet into a helper command. The helper applies its
/// commands in order, so the size a Size message sets is the output every later
/// pointer position refers to: it is recorded when the command is sent, not when
/// its reply arrives (a click right after a size used to be scaled to the old
/// output, #146). A failed send or reply ends the whole worker, so the recorded
/// size never outlives a helper that did not apply it.
///
/// `packet` must be exactly one frame. Pointer positions arrive as millionths of
/// the output width and height and are converted to output pixels. Returns the
/// helper command kind and its validated JSON body, or a rejection for anything
/// that is not a repair, control, release, size or input message.
fn command(packet: &[u8], metadata: &Metadata) -> Result<(Kind, Vec<u8>), PluginError> {
    let decoded = decode_frame(packet).map_err(|_| PluginError::Rejected)?;
    if decoded.wire_len != packet.len() {
        return Err(PluginError::Rejected);
    }
    let Frame::Desktop(message) = decoded.frame else {
        return Err(PluginError::Rejected);
    };
    let (kind, body) = match message {
        Message::Repair { .. } => (Kind::Keyframe, b"{}".to_vec()),
        // A viewer's connection is backed up: the encoder lowers its bit rate.
        Message::Pressure { .. } => (Kind::Congested, b"{}".to_vec()),
        Message::Input(WireInput::Control { active }) => (
            Kind::Control,
            serde_json::to_vec(&serde_json::json!({"active":active}))
                .map_err(|_| PluginError::Rejected)?,
        ),
        Message::Input(WireInput::Release) => (Kind::ReleaseInput, b"{}".to_vec()),
        Message::Size {
            width,
            height,
            density_milli,
        } => {
            let backing_scale = f64::from(density_milli) / 1000.0;
            let size = Size {
                width: u32::from(width),
                height: u32::from(height),
                canvas_width: f64::from(width) / backing_scale,
                canvas_height: f64::from(height) / backing_scale,
                backing_scale,
            };
            size.validate().map_err(|_| PluginError::Rejected)?;
            let body = serde_json::to_vec(&size).map_err(|_| PluginError::Rejected)?;
            metadata
                .start
                .lock()
                .map_err(|_| PluginError::Rejected)?
                .size = size;
            (Kind::Resize, body)
        }
        Message::Input(input) => {
            let size = metadata
                .start
                .lock()
                .map_err(|_| PluginError::Rejected)?
                .size;
            let x = |x| f64::from(x) * f64::from(size.width) / 1_000_000.0;
            let y = |y| f64::from(y) * f64::from(size.height) / 1_000_000.0;
            let input = match input {
                WireInput::Text { scalar } => Input::Text { scalar },
                WireInput::Mouse {
                    x: px,
                    y: py,
                    button,
                    state,
                    modifiers,
                } => Input::Mouse {
                    x: x(px),
                    y: y(py),
                    button,
                    state,
                    modifiers,
                },
                WireInput::Scroll {
                    x: px,
                    y: py,
                    dx,
                    dy,
                    modifiers,
                } => Input::Scroll {
                    x: x(px),
                    y: y(py),
                    dx,
                    dy,
                    modifiers,
                },
                WireInput::Key {
                    keycode,
                    down,
                    modifiers,
                } => Input::Key {
                    keycode,
                    down,
                    modifiers,
                },
                WireInput::Release | WireInput::Control { .. } => {
                    return Err(PluginError::Rejected);
                }
            };
            (
                Kind::Input,
                serde_json::to_vec(&input).map_err(|_| PluginError::Rejected)?,
            )
        }
        _ => return Err(PluginError::Rejected),
    };
    protocol::validate_command(kind, &body).map_err(|_| PluginError::Rejected)?;
    Ok((kind, body))
}

#[cfg(test)]
mod pacing_tests {
    //! Proves newest-frame resumption and delta repair across a held native write.
    use super::*;
    use infraternal_plugin_api::Operation;

    // The admitted writer is paused after its first packet, so later frames
    // compete for exactly the production pending slot without scheduler sleeps.
    struct PausedLane {
        entered: mpsc::UnboundedSender<u64>,
        release: tokio::sync::Notify,
    }
    impl WireLane for PausedLane {
        fn stream_id(&self) -> u32 {
            2
        }
        fn receive(&self) -> Operation<'_, Result<bytes::Bytes, ()>> {
            Box::pin(std::future::pending())
        }
        fn send<'a>(&'a self, packet: &'a [u8]) -> Operation<'a, Result<(), ()>> {
            Box::pin(async move {
                let Frame::Desktop(Message::Video { sequence, .. }) =
                    decode_frame(packet).unwrap().frame
                else {
                    panic!("expected source video")
                };
                self.entered.send(sequence).unwrap();
                if sequence == 1 {
                    self.release.notified().await;
                }
                Ok(())
            })
        }
        fn retire(&self) {}
    }
    fn frame(sequence: u64) -> Video {
        Video {
            sequence,
            capture_ns: sequence,
            keyframe: true,
            bytes: bytes::Bytes::from_static(b"\x00\x00\x00\x01\x65"),
        }
    }
    /// An immediately writable transport must get a chance to consume each
    /// coded reference when the pipe reader receives several units together.
    #[tokio::test]
    async fn ready_source_write_preserves_a_continuous_read_burst() {
        let (entered, mut packets) = mpsc::unbounded_channel();
        let lane = Arc::new(PausedLane {
            entered,
            release: tokio::sync::Notify::new(),
        });
        lane.release.notify_one();
        let (repair, _repairs) = mpsc::channel(1);
        let (publisher, receive) = pending_video();
        let writing = tokio::spawn(send_video(
            lane,
            Delivery::Reliable,
            Uuid::new_v4(),
            receive,
            repair,
        ));
        publisher.publish(frame(1));
        for sequence in 2..=6 {
            let mut next = frame(sequence);
            next.keyframe = false;
            publisher.publish(next);
        }
        drop(publisher);
        assert!(writing.await.unwrap().is_ok());
        let mut sent = Vec::new();
        while let Some(sequence) = packets.recv().await {
            sent.push(sequence);
        }
        assert_eq!(
            sent,
            vec![1, 2, 3, 4, 5, 6],
            "ready writer lost codec references to a producer read burst"
        );
    }

    /// While a write is blocked, a newer keyframe replaces a waiting keyframe:
    /// the blocked lane resumes with the newest picture.
    #[tokio::test]
    async fn blocked_source_write_resumes_with_newest_pending_frame() {
        let (entered, mut packets) = mpsc::unbounded_channel();
        let lane = Arc::new(PausedLane {
            entered,
            release: tokio::sync::Notify::new(),
        });
        let (repair, _repairs) = mpsc::channel(1);
        let (publisher, receive) = pending_video();
        let writing = tokio::spawn(send_video(
            lane.clone(),
            Delivery::Reliable,
            Uuid::new_v4(),
            receive,
            repair,
        ));
        publisher.publish(frame(1));
        assert_eq!(packets.recv().await, Some(1));
        publisher.publish(frame(2));
        publisher.publish(frame(3));
        drop(publisher);
        lane.release.notify_one();
        let resumed = packets.recv().await;
        assert!(writing.await.unwrap().is_ok());
        assert_eq!(resumed, Some(3), "a newer keyframe replaces a waiting one");
    }

    /// A lane blocked for less than the backlog bound loses no delta: the
    /// waiting frames follow in order once it writes again (#146).
    #[tokio::test(start_paused = true)]
    async fn briefly_blocked_source_write_sends_every_waiting_delta() {
        let (entered, mut packets) = mpsc::unbounded_channel();
        let lane = Arc::new(PausedLane {
            entered,
            release: tokio::sync::Notify::new(),
        });
        let (repair, mut repairs) = mpsc::channel(1);
        let (publisher, receive) = pending_video();
        let writing = tokio::spawn(send_video(
            lane.clone(),
            Delivery::Reliable,
            Uuid::new_v4(),
            receive,
            repair,
        ));
        publisher.publish(frame(1));
        assert_eq!(packets.recv().await, Some(1));
        for sequence in 2..=6 {
            tokio::time::advance(std::time::Duration::from_millis(8)).await;
            let mut delta = frame(sequence);
            delta.keyframe = false;
            assert_eq!(publisher.publish(delta), Admission::Queued);
        }
        drop(publisher);
        for sequence in 2..=6 {
            lane.release.notify_one();
            assert_eq!(packets.recv().await, Some(sequence));
        }
        lane.release.notify_one();
        assert!(writing.await.unwrap().is_ok());
        assert!(repairs.try_recv().is_err(), "no keyframe was needed");
    }

    /// A lane blocked past the backlog bound drops what waited and takes no
    /// delta until a fresh keyframe (D254 drop-to-newest beyond the bound).
    /// The blocked write here is a keyframe, whose write time is forgiven, so
    /// the unit bound is the one reached.
    #[tokio::test(start_paused = true)]
    async fn delta_past_the_bound_waits_for_fresh_keyframe() {
        let (entered, mut packets) = mpsc::unbounded_channel();
        let lane = Arc::new(PausedLane {
            entered,
            release: tokio::sync::Notify::new(),
        });
        let (repair, _repairs) = mpsc::channel(1);
        let (publisher, receive) = pending_video();
        let writing = tokio::spawn(send_video(
            lane.clone(),
            Delivery::Reliable,
            Uuid::new_v4(),
            receive,
            repair,
        ));
        publisher.publish(frame(1));
        assert_eq!(packets.recv().await, Some(1));
        let delta = |sequence| {
            let mut delta = frame(sequence);
            delta.keyframe = false;
            delta
        };
        let mut sequence = 2;
        while publisher.publish(delta(sequence)) == Admission::Queued {
            sequence += 1;
        }
        assert_eq!(
            sequence,
            2 + crate::backlog::MAX_UNITS as u64,
            "the unit bound overflowed"
        );
        assert_eq!(publisher.publish(delta(sequence + 1)), Admission::Sealed);
        assert_eq!(publisher.publish(frame(sequence + 2)), Admission::Queued);
        drop(publisher);
        lane.release.notify_one();
        assert_eq!(packets.recv().await, Some(sequence + 2));
        lane.release.notify_one();
        assert!(writing.await.unwrap().is_ok());
        drop(lane);
        assert!(packets.recv().await.is_none());
    }
}

#[cfg(test)]
mod mapping_tests {
    //! Pointer input maps to the output size the helper applies before it, in order (#146).
    use super::*;

    fn packet(message: Message<'_>) -> Vec<u8> {
        let mut wire = Vec::new();
        encode_frame_into(&Frame::Desktop(message), &mut wire).unwrap();
        wire
    }

    /// The browser sends its latest size when it takes control and the click
    /// right after it. The helper resizes first, so the click must be scaled
    /// to the new output even though the Size reply has not arrived yet.
    #[test]
    fn a_click_right_after_a_size_maps_to_that_size() {
        let metadata = Metadata::new(
            protocol::Start {
                passive_geometry: false,
                target: protocol::Target::Window {
                    window_id: 7,
                    owner_pid: 70,
                },
                size: Size {
                    width: 1000,
                    height: 500,
                    canvas_width: 1000.0,
                    canvas_height: 500.0,
                    backing_scale: 1.0,
                },
            },
            0,
        );
        let (kind, _) = command(
            &packet(Message::Size {
                width: 2000,
                height: 1200,
                density_milli: 2000,
            }),
            &metadata,
        )
        .unwrap();
        assert_eq!(kind, Kind::Resize);
        let (kind, body) = command(
            &packet(Message::Input(WireInput::Mouse {
                x: 250_000,
                y: 500_000,
                button: 0,
                state: 1,
                modifiers: 0,
            })),
            &metadata,
        )
        .unwrap();
        assert_eq!(kind, Kind::Input);
        let input: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            input["x"], 500.0,
            "click scaled to the previous output width"
        );
        assert_eq!(
            input["y"], 600.0,
            "click scaled to the previous output height"
        );
    }
}
