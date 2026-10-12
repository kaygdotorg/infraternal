//! Owns bounded native input flights so QUIC backpressure cannot stop the sibling writers or control dispatch [128,215], #129.
use super::{AgentConnection, AttachmentState, Bytes, HashMap, Peer};
use infraternal_protocol::{Frame, encode_frame_into};
use std::time::Duration;
use tokio::{sync::mpsc, task::JoinSet};

const FLIGHT: usize = 16 * 1024;
// One queued and one active control frame, including the maximum authority JSON,
// bounded action identifier and protocol headers; command producers retain their
// existing bounded queue and await capacity rather than discarding controls.
pub(super) const CONTROL_FLIGHT: usize = infraternal_plugin_api::channel::MAX_CONTROL_JSON + 256;

#[derive(Default)]
pub(super) struct State {
    enabled: bool,
    control: Option<mpsc::Receiver<Bytes>>,
    control_busy: bool,
    sent: HashMap<u32, ([u8; 16], u64)>,
    busy: HashMap<u32, [u8; 16]>,
    blocked: HashMap<u32, [u8; 16]>,
    credit: HashMap<u32, ([u8; 16], u32)>,
    resize: HashMap<u32, ([u8; 16], [u16; 4])>,
    tasks: JoinSet<(u32, [u8; 16], Option<u64>, bool)>,
}
impl State {
    pub(super) fn enable(&mut self, attachments: &HashMap<u64, AttachmentState>) {
        if !self.enabled {
            self.enabled = true;
            self.sent.extend(attachments.values().map(|a| {
                // Replacement retention records server admission, not
                // transport delivery. Its first durable Ack owns replay.
                let sent = if a.replaying {
                    a.last_in_seq
                } else {
                    a.last_input_end
                };
                (a.stream_id, (a.session_id, sent))
            }));
        }
    }
    pub(super) fn install(&mut self, connection: &mut AgentConnection) {
        if self.enabled
            && self.control.is_none()
            && matches!(&connection.peer, Peer::Remote(link) if link.native())
        {
            let (sender, receiver) = mpsc::channel(1);
            connection.owned_control = Some(sender);
            self.control = Some(receiver);
        }
    }
    pub(super) fn can_admit(&self) -> bool {
        self.control
            .as_ref()
            .is_none_or(|queue| queue.capacity() != 0)
    }
    pub(super) fn enabled(&self) -> bool {
        self.enabled
    }
    pub(super) fn owns(&self, stream: u32) -> bool {
        self.busy.contains_key(&stream) || self.blocked.contains_key(&stream)
    }
    pub(super) fn block(&mut self, stream: u32) {
        if let Some((session, _)) = self.sent.get(&stream) {
            self.blocked.insert(stream, *session);
        }
    }
    pub(super) fn credit(&mut self, stream: u32, session: [u8; 16], bytes: u32) -> bool {
        if self.blocked.get(&stream) == Some(&session) {
            return true;
        }
        let entry = self.credit.entry(stream).or_insert((session, 0));
        if entry.0 != session {
            *entry = (session, 0);
        }
        let Some(total) = entry.1.checked_add(bytes) else {
            return false;
        };
        entry.1 = total;
        true
    }
    pub(super) fn resize(&mut self, stream: u32, session: [u8; 16], dimensions: [u16; 4]) {
        self.resize.insert(stream, (session, dimensions));
    }
    pub(super) async fn stop(&mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        self.control = None;
        self.control_busy = false;
        self.busy.clear();
        self.blocked.clear();
        self.sent.clear();
        self.credit.clear();
        self.resize.clear();
    }
    pub(super) fn schedule(
        &mut self,
        connection: &AgentConnection,
        attachments: &HashMap<u64, AttachmentState>,
    ) {
        if !self.enabled {
            return;
        }
        let Peer::Remote(link) = &connection.peer else {
            return;
        };
        if !link.native() {
            return;
        }
        if !self.control_busy
            && let Some(encoded) = self
                .control
                .as_mut()
                .and_then(|queue| queue.try_recv().ok())
        {
            let link = link.clone();
            self.control_busy = true;
            self.tasks.spawn(async move {
                let success = tokio::time::timeout(
                    Duration::from_secs(1),
                    link.write_encoded_terminal(0, &encoded),
                )
                .await
                .is_ok_and(|result| result.is_ok());
                (0, [0; 16], None, success)
            });
        }
        self.sent.retain(|stream, (session, _)| {
            attachments
                .values()
                .any(|a| a.stream_id == *stream && a.session_id == *session)
        });
        self.busy.retain(|stream, session| {
            attachments
                .values()
                .any(|a| a.stream_id == *stream && a.session_id == *session)
        });
        self.blocked.retain(|stream, session| {
            attachments
                .values()
                .any(|a| a.stream_id == *stream && a.session_id == *session)
        });
        self.credit.retain(|stream, (session, _)| {
            attachments
                .values()
                .any(|a| a.stream_id == *stream && a.session_id == *session)
        });
        self.resize.retain(|stream, (session, _)| {
            attachments
                .values()
                .any(|a| a.stream_id == *stream && a.session_id == *session)
        });
        for a in attachments.values() {
            // The single control owner has its own slot. Count every unjoined
            // terminal task, including detached writers whose route is gone.
            if self.owns(a.stream_id)
                || self.tasks.len()
                    >= infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS
                        + usize::from(self.control_busy)
            {
                continue;
            }
            let Some((encoded, end)) = self.encode(a) else {
                continue;
            };
            let stream = a.stream_id;
            let link = link.clone();
            let session = a.session_id;
            self.busy.insert(stream, session);
            self.tasks.spawn(async move {
                let success = tokio::time::timeout(
                    Duration::from_secs(1),
                    link.write_encoded_terminal(stream, &encoded),
                )
                .await
                .is_ok_and(|result| result.is_ok());
                (stream, session, end, success)
            });
        }
    }
    fn encode(&mut self, a: &AttachmentState) -> Option<(Bytes, Option<u64>)> {
        if a.replaying {
            return None;
        }
        let (_, sent) = self
            .sent
            .entry(a.stream_id)
            .or_insert((a.session_id, a.last_in_seq));
        let start = (*sent).max(a.last_in_seq);
        let (frame, end) = if let Some((_, bytes)) = self.credit.remove(&a.stream_id) {
            (Frame::Credit { bytes }, None)
        } else if let Some((_, [cols, rows, px_w, px_h])) = self.resize.remove(&a.stream_id) {
            (
                Frame::Resize {
                    cols,
                    rows,
                    px_w,
                    px_h,
                },
                None,
            )
        } else {
            let skip = usize::try_from(start.saturating_sub(a.last_in_seq)).ok()?;
            // Socket completion only releases the owned task. It does not
            // acknowledge PTY acceptance: keep at most one flight beyond the
            // durable writer cursor, even when QUIC keeps accepting bytes.
            let available = FLIGHT.checked_sub(skip)?;
            let pending = a.unacknowledged.get(skip..)?;
            let bytes = &pending[..pending.len().min(available)];
            if bytes.is_empty() {
                return None;
            }
            (
                Frame::Input {
                    in_seq: start,
                    bytes,
                },
                Some(start + bytes.len() as u64),
            )
        };
        let capacity = match frame {
            Frame::Input { bytes, .. } => bytes.len() + 16,
            _ => 32,
        };
        let mut encoded = Vec::with_capacity(capacity);
        encode_frame_into(&frame, &mut encoded).ok()?;
        Some((Bytes::from(encoded), end))
    }
    pub(super) async fn next(&mut self) -> (u32, bool) {
        loop {
            match self.tasks.join_next().await {
                Some(Ok((stream, session, end, success))) => {
                    if stream == 0 {
                        self.control_busy = false;
                        return (stream, success);
                    }
                    if self.busy.get(&stream) != Some(&session) {
                        continue;
                    }
                    self.busy.remove(&stream);
                    if success {
                        if let Some(end) = end {
                            self.sent.insert(stream, (session, end));
                        }
                    } else {
                        self.blocked.insert(stream, session);
                    }
                    return (stream, success);
                }
                Some(Err(_)) => {}
                None => return std::future::pending().await,
            }
        }
    }
}
