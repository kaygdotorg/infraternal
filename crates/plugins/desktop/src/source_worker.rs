//! Multiplexes one source helper's control replies and bounded media while keeping native input independent of video writes [D200,D203,D232].
use crate::{
    media::{ASSEMBLY_TIMEOUT, Video},
    protocol::{self, Input, Kind, Size},
    source::{Control, Metadata, Outcome},
    source_ipc::{Config, Helper},
};
use infraternal_plugin_api::{PluginError, streams::WireLane};
use infraternal_protocol::{
    Frame, decode_frame,
    desktop::{Delivery, Input as WireInput, Message},
    encode_frame_into,
};
use serde_json::Value;
use std::{
    collections::VecDeque,
    sync::{Arc, atomic::Ordering},
};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

pub(super) struct Leg {
    pub id: Uuid,
    pub metadata: Arc<Metadata>,
    pub lane: Arc<dyn WireLane>,
    pub delivery: Delivery,
    pub cancelled: watch::Receiver<bool>,
    pub requests: mpsc::Receiver<Control>,
    pub repair: mpsc::Sender<Control>,
}
struct Lease(Arc<dyn WireLane>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.retire();
    }
}
// A solicited reply owns one fixed send+reply deadline; video never renews it.
const CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
struct Pending {
    deadline: tokio::time::Instant,
    expected: Kind,
    resize: Option<Size>,
    reply: Option<tokio::sync::oneshot::Sender<Result<Value, PluginError>>>,
}
struct PendingVideo {
    frames: watch::Sender<Option<Video>>,
}
fn pending_video() -> (PendingVideo, watch::Receiver<Option<Video>>) {
    let (frames, receive) = watch::channel(None);
    (PendingVideo { frames }, receive)
}
impl PendingVideo {
    fn publish(&self, video: Video) {
        // One in-flight write and one newest pending frame bound storage. A
        // stalled native lane cannot pin an older queue entry ahead of damage.
        // Sequence gaps are repaired by the consumer before sending any delta.
        self.frames.send_replace(Some(video));
    }
}
pub(super) async fn run(config: Config, mut leg: Leg) -> Outcome {
    let _lease = Lease(leg.lane.clone());
    if *leg.cancelled.borrow() {
        return Outcome {
            output: Ok(Value::Null),
            cleanup: Ok(()),
        };
    }
    let mut helper = match Helper::start(&config, &mut leg.cancelled).await {
        Ok(helper) => helper,
        Err(error) => return Outcome::failed(error.cleanup()),
    };
    let result = async {
        let start = leg.metadata.start.lock().map_err(|_| PluginError::Rejected)?.clone();
        let opening = serde_json::to_vec(&start).map_err(|_| PluginError::Rejected)?;
        let started: std::io::Result<()> = tokio::select! { biased;
            _ = leg.cancelled.changed() => Ok(()),
            result = async {
                let (kind, _) = tokio::time::timeout(CONTROL_TIMEOUT, async {
                    helper.send(Kind::Start, &opening).await?;
                    helper.receive().await
                }).await.map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
                if kind != Kind::Geometry { return Err(std::io::ErrorKind::PermissionDenied.into()); }
                Ok(())
            } => result,
        };
        started.map_err(|_| PluginError::Rejected)?;
        if *leg.cancelled.borrow() { Ok(()) } else { pump(&mut helper, &mut leg).await }
    }.await;
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

async fn pump(helper: &mut Helper, leg: &mut Leg) -> Result<(), PluginError> {
    let (send, receive) = pending_video();
    let lane = leg.lane.clone();
    let repair = leg.repair.clone();
    let id = leg.id;
    let mode = leg.delivery;
    let mut sender = tokio::spawn(async move { send_video(lane, mode, id, receive, repair).await });
    let mut pending = VecDeque::<Pending>::new();
    let result = async {
        loop {
            if *leg.cancelled.borrow() { return Ok(()); }
            tokio::select! { biased;
                _ = leg.cancelled.changed() => return Ok(()),
                // No deadline exists while video is idle and no control reply is owed.
                () = async { match pending.front() { Some(response) => tokio::time::sleep_until(response.deadline).await, None => std::future::pending().await } } => return Err(PluginError::Rejected),
                result = &mut sender => return result.map_err(|_| PluginError::Rejected).and_then(|result| result),
                packet = leg.lane.receive(), if pending.len() < 64 => {
                    let packet = packet.map_err(|()| PluginError::Rejected)?;
                    let (kind, body, resize) = command(&packet, &leg.metadata)?;
                    let deadline = tokio::time::Instant::now() + CONTROL_TIMEOUT;
                    let send_deadline = pending.front().map_or(deadline, |response| response.deadline.min(deadline));
                    tokio::time::timeout_at(send_deadline, helper.send(kind, &body)).await.map_err(|_| PluginError::Rejected)?.map_err(|_| PluginError::Rejected)?;
                    pending.push_back(Pending { deadline, expected: reply_kind(kind), resize, reply: None });
                },
                request = leg.requests.recv(), if pending.len() < 64 => {
                    let Some(request) = request else { return Ok(()); };
                    let deadline = tokio::time::Instant::now() + CONTROL_TIMEOUT;
                    let send_deadline = pending.front().map_or(deadline, |response| response.deadline.min(deadline));
                    tokio::time::timeout_at(send_deadline, helper.send(request.kind, b"{}")).await.map_err(|_| PluginError::Rejected)?.map_err(|_| PluginError::Rejected)?;
                    pending.push_back(Pending { deadline, expected: reply_kind(request.kind), resize: None, reply: request.reply });
                },
                message = helper.receive() => {
                    let (kind, body) = message.map_err(|_| PluginError::Rejected)?;
                    if kind == Kind::Video {
                        let video = video(&body, &leg.metadata)?;
                        send.publish(video);
                    } else if kind == Kind::Error { return Err(PluginError::Rejected); }
                    else if pending.front().is_some_and(|response| response.expected == kind) {
                        let response = pending.pop_front().ok_or(PluginError::Rejected)?;
                        if let Some(size) = response.resize { leg.metadata.start.lock().map_err(|_| PluginError::Rejected)?.size = size; }
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
async fn send_video(
    lane: Arc<dyn WireLane>,
    mode: Delivery,
    id: Uuid,
    mut frames: watch::Receiver<Option<Video>>,
    repair: mpsc::Sender<Control>,
) -> Result<(), PluginError> {
    let datagrams = match mode {
        Delivery::Reliable => None,
        Delivery::Datagram => Some(lane.datagrams().ok_or(PluginError::Rejected)?),
    };
    let mut wire = Vec::new();
    let mut previous = 0;
    let mut waiting_keyframe = true;
    while frames.changed().await.is_ok() {
        let Some(video) = frames.borrow_and_update().clone() else {
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
fn reply_kind(kind: Kind) -> Kind {
    match kind {
        Kind::Start | Kind::Resize => Kind::Geometry,
        Kind::Input => Kind::InputResult,
        _ => Kind::State,
    }
}
fn command(
    packet: &[u8],
    metadata: &Metadata,
) -> Result<(Kind, Vec<u8>, Option<Size>), PluginError> {
    let decoded = decode_frame(packet).map_err(|_| PluginError::Rejected)?;
    if decoded.wire_len != packet.len() {
        return Err(PluginError::Rejected);
    }
    let Frame::Desktop(message) = decoded.frame else {
        return Err(PluginError::Rejected);
    };
    let (kind, body, resize) = match message {
        Message::Repair { .. } => (Kind::Keyframe, b"{}".to_vec(), None),
        Message::Input(WireInput::Control { active }) => (
            Kind::Control,
            serde_json::to_vec(&serde_json::json!({"active":active}))
                .map_err(|_| PluginError::Rejected)?,
            None,
        ),
        Message::Input(WireInput::Release) => (Kind::ReleaseInput, b"{}".to_vec(), None),
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
            (
                Kind::Resize,
                serde_json::to_vec(&size).map_err(|_| PluginError::Rejected)?,
                Some(size),
            )
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
                None,
            )
        }
        _ => return Err(PluginError::Rejected),
    };
    protocol::validate_command(kind, &body).map_err(|_| PluginError::Rejected)?;
    Ok((kind, body, resize))
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
        assert_eq!(
            resumed,
            Some(3),
            "a blocked source must drop the stale pending frame"
        );
    }

    #[tokio::test]
    async fn overwritten_delta_waits_for_fresh_keyframe() {
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
        publisher.publish(frame(2));
        let mut delta = frame(3);
        delta.keyframe = false;
        publisher.publish(delta);
        lane.release.notify_one();
        assert_eq!(repairs.recv().await.unwrap().kind, Kind::Keyframe);
        publisher.publish(frame(4));
        drop(publisher);
        assert_eq!(packets.recv().await, Some(4));
        assert!(writing.await.unwrap().is_ok());
        drop(lane);
        assert!(packets.recv().await.is_none());
    }
}
