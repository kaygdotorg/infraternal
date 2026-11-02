//! Owns bounded native input flights so QUIC backpressure cannot stop the secondary hedge or sibling writers [128,215], #129.
use super::{AgentConnection, AttachmentState, Bytes, HashMap, Peer};
use infraternal_protocol::{Frame, encode_frame_into};
use std::{collections::VecDeque, time::Duration};
use tokio::{sync::mpsc, task::JoinSet};

const FLIGHT: usize = 16 * 1024;
// One queued and one active control frame, including the maximum authority JSON,
// bounded action identifier and protocol headers; command producers retain their
// existing bounded queue and await capacity rather than discarding controls.
pub(super) const CONTROL_FLIGHT: usize = infraternal_plugin_api::channel::MAX_CONTROL_JSON + 256;

#[derive(Default)]
pub(super) struct State {
    #[cfg(test)]
    test_peer: Option<std::net::SocketAddr>,
    enabled: bool,
    control: Option<mpsc::Receiver<Bytes>>,
    cleanup: Option<mpsc::UnboundedReceiver<Bytes>>,
    control_busy: bool,
    sent: HashMap<u32, ([u8; 16], u64)>,
    busy: HashMap<u32, [u8; 16]>,
    blocked: HashMap<u32, [u8; 16]>,
    credit: HashMap<u32, ([u8; 16], u32)>,
    resize: HashMap<u32, ([u8; 16], [u16; 4])>,
    // At most two fixed-size cursor/Attach/Credit headers per live writer.
    prefix: HashMap<u32, ([u8; 16], VecDeque<Bytes>)>,
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
            let (sender, receiver) = mpsc::unbounded_channel();
            connection.owned_cleanup = Some(sender);
            self.cleanup = Some(receiver);
            #[cfg(test)]
            if let Peer::Remote(link) = &connection.peer {
                self.test_peer = link.test_native_peer_address();
            }
        }
    }
    // Retirement is already admitted by its trusted finalizer and cannot spend
    // ordinary control capacity. One ordered write owner preserves stream order.
    fn next_control(&mut self) -> Option<Bytes> {
        self.cleanup
            .as_mut()
            .and_then(|queue| queue.try_recv().ok())
            .or_else(|| {
                self.control
                    .as_mut()
                    .and_then(|queue| queue.try_recv().ok())
            })
    }
    pub(super) fn can_admit(&self) -> bool {
        #[cfg(test)]
        if let Some(peer) = self.test_peer {
            TEST_CONTROL_STATES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(
                    peer,
                    (
                        self.control_busy,
                        self.control.as_ref().map_or(1, mpsc::Receiver::capacity),
                    ),
                );
        }
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
        self.cleanup = None;
        self.control_busy = false;
        self.busy.clear();
        self.blocked.clear();
        self.sent.clear();
        self.credit.clear();
        self.resize.clear();
        self.prefix.clear();
    }
    /// Orders promotion fences ahead of input without awaiting native flow control.
    pub(super) fn promote_writer(
        &mut self,
        a: &AttachmentState,
        cached: Option<&(u64, u64, bool)>,
    ) -> bool {
        let mut frames = VecDeque::with_capacity(2);
        let mut encode = |frame: Frame<'_>| {
            let mut bytes = Vec::with_capacity(128);
            if encode_frame_into(&frame, &mut bytes).is_err() || bytes.len() > 128 {
                return false;
            }
            frames.push_back(Bytes::from(bytes));
            true
        };
        let credit = if let Some((_, credit, hedged)) = cached {
            if !hedged {
                let Ok(json) = serde_json::to_vec(&serde_json::json!({"out_seq": a.last_out_seq}))
                else {
                    return false;
                };
                if !encode(Frame::Call {
                    call_id: 0,
                    action_id: "transport.cursor",
                    input_json: &json,
                }) {
                    return false;
                }
            }
            a.credit.saturating_sub(*credit)
        } else {
            if !encode(Frame::AttachTerm {
                session_id: &a.session_id,
                last_out_seq: a.last_out_seq,
                last_in_seq: a.last_in_seq,
            }) {
                return false;
            }
            a.credit
        };
        if credit > 0 {
            let Ok(bytes) = u32::try_from(credit) else {
                return false;
            };
            if !encode(Frame::Credit { bytes }) {
                return false;
            }
        }
        if !frames.is_empty() {
            if self.prefix.len() >= infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS
                && !self.prefix.contains_key(&a.stream_id)
            {
                return false;
            }
            self.prefix.insert(a.stream_id, (a.session_id, frames));
        }
        true
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
            && let Some(encoded) = self.next_control()
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
        self.prefix.retain(|stream, (session, _)| {
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
        if let Some((session, frames)) = self.prefix.get_mut(&a.stream_id)
            && *session == a.session_id
            && let Some(bytes) = frames.pop_front()
        {
            return Some((bytes, None));
        }
        self.prefix.remove(&a.stream_id);
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

// This observation is sampled at the actual actor admission check; it neither
// reserves queue space nor holds a connection or frame alive.
#[cfg(test)]
static TEST_CONTROL_STATES: std::sync::LazyLock<
    std::sync::Mutex<HashMap<std::net::SocketAddr, (bool, usize)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));
#[cfg(test)]
pub(super) fn test_control_queue_state(peer: std::net::SocketAddr) -> Option<(bool, usize)> {
    TEST_CONTROL_STATES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&peer)
        .copied()
}

#[cfg(test)]
mod tests {
    //! Checks the encoded queue bound and joins owned flights before shutdown returns.
    use super::*;
    fn retained_writer() -> AttachmentState {
        let (output, _) = mpsc::channel(16);
        AttachmentState {
            session_id: [7; 16],
            stream_id: 2,
            last_out_seq: 0,
            last_in_seq: 0,
            last_input_end: 4 * 1024 * 1024,
            unacknowledged: super::super::BytesMut::from(vec![b'x'; 4 * 1024 * 1024].as_slice()),
            input_credit: tokio::sync::watch::channel(0).0,
            credit: 0,
            awaiting_ack: false,
            replaying: false,
            route: None,
            proof_rebind_pending: false,
            output,
        }
    }

    #[test]
    fn promotion_headers_preserve_attach_credit_ack_input_order() {
        let mut state = State::default();
        let mut writer = retained_writer();
        writer.replaying = true;
        writer.credit = 42;
        assert!(state.promote_writer(&writer, None));
        let (attach, _) = state.encode(&writer).unwrap();
        assert!(attach.len() <= 128);
        assert!(matches!(
            infraternal_protocol::decode_frame(&attach).unwrap().frame,
            Frame::AttachTerm { last_in_seq: 0, .. }
        ));
        let (credit, _) = state.encode(&writer).unwrap();
        assert!(matches!(
            infraternal_protocol::decode_frame(&credit).unwrap().frame,
            Frame::Credit { bytes: 42 }
        ));
        assert!(
            state.encode(&writer).is_none(),
            "unprimed input must wait for first Ack"
        );
        writer.replaying = false;
        let (input, end) = state.encode(&writer).unwrap();
        assert!(matches!(
            infraternal_protocol::decode_frame(&input).unwrap().frame,
            Frame::Input { in_seq: 0, .. }
        ));
        assert_eq!(end, Some(FLIGHT as u64));
    }

    #[test]
    fn enabling_owned_writes_preserves_unsent_replacement_input() {
        let mut state = State::default();
        let mut writer = retained_writer();
        writer.replaying = true;
        let mut attachments = HashMap::from([(1, writer)]);
        state.enable(&attachments);
        let writer = attachments.get_mut(&1).unwrap();
        writer.replaying = false;
        let (_, end) = state
            .encode(writer)
            .expect("replacement input was retained, not sent");
        assert_eq!(end, Some(FLIGHT as u64));
    }

    #[test]
    fn socket_completion_cannot_spend_unacknowledged_writer_credit() {
        let mut state = State::default();
        let mut writer = retained_writer();
        let (_, end) = state.encode(&writer).expect("first bounded flight");
        assert_eq!(end, Some(FLIGHT as u64));
        state
            .sent
            .insert(writer.stream_id, (writer.session_id, end.unwrap()));
        assert!(
            state.encode(&writer).is_none(),
            "socket completion is not a durable PTY Ack"
        );
        writer.last_in_seq = FLIGHT as u64;
        let _ = writer.unacknowledged.split_to(FLIGHT);
        assert!(
            state.encode(&writer).is_some(),
            "a real Ack must resume the writer"
        );
    }

    #[tokio::test]
    async fn cached_promotion_ack_never_replays_inside_the_actor() {
        use super::super::{AgentConnection, BytesMut, Peer, apply_cached_ack};
        let (socket, _unread) = tokio::net::UnixStream::pair().unwrap();
        let (reader, writer) = socket.into_split();
        let mut connection = AgentConnection {
            peer: Peer::Local { reader, writer },
            execution_uid: 0,
            pid: None,
            receive: BytesMut::new(),
            scratch: vec![0; 4096],
            encode: Vec::new(),
            next_call_id: 1,
            owned_control: None,
            #[cfg(feature = "remote")]
            owned_cleanup: None,
        };
        let mut retained = retained_writer();
        let (output, mut observed) = mpsc::channel(16);
        retained.output = output;
        retained.awaiting_ack = true;
        retained.replaying = true;
        let mut attachments = HashMap::from([(1, retained)]);
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            apply_cached_ack(
                2,
                0,
                &mut connection,
                &mut attachments,
                &mut HashMap::from([(2, 1)]),
                &mut HashMap::new(),
            ),
        )
        .await;
        assert!(
            result.is_ok_and(|valid| valid),
            "cached Ack waited for blocked replay socket"
        );
        assert!(matches!(
            observed.recv().await,
            Some(super::super::TerminalOutput::Ack { in_seq_acked: 0 })
        ));
        assert_eq!(attachments[&1].unacknowledged.len(), 4 * 1024 * 1024);
        assert!(!attachments[&1].replaying);
    }

    #[tokio::test]
    async fn person_cleanup_is_admitted_when_native_control_lane_is_full() {
        use super::super::{BytesMut, write_frame};
        let (link, _control, _listener, _endpoint, _peer) =
            crate::remote_runtime::tests::native_link_pair().await;
        let mut connection = AgentConnection {
            peer: Peer::Remote(link),
            execution_uid: 0,
            pid: None,
            receive: BytesMut::new(),
            scratch: vec![0; 4096],
            encode: Vec::new(),
            next_call_id: 1,
            owned_control: None,
            #[cfg(feature = "remote")]
            owned_cleanup: None,
        };
        let mut state = State::default();
        state.enable(&HashMap::new());
        state.install(&mut connection);
        connection
            .owned_control
            .as_ref()
            .unwrap()
            .try_send(Bytes::from_static(b"held"))
            .unwrap();
        assert!(!state.can_admit());
        // One active flight and a full queued slot cannot reserve retirement.
        state.control_busy = true;
        for call_id in 1..=96 {
            let cleanup = Frame::Call {
                call_id: 0x4000_0000 | call_id,
                action_id: "terminal.login.revoke",
                input_json: br#"{"person":"00000000-0000-0000-0000-000000000001"}"#,
            };
            assert!(
                write_frame(&mut connection, 0, &cleanup).await,
                "ordinary native control capacity must not refuse person cleanup"
            );
        }
        // When the active flight ends, cleanup precedes the ordinary queued frame.
        state.control_busy = false;
        for expected in 1..=96 {
            let encoded = state.next_control().unwrap();
            assert!(
                matches!(infraternal_protocol::decode_frame(&encoded).unwrap().frame,
                Frame::Call { call_id, action_id: "terminal.login.revoke", .. }
                    if call_id == 0x4000_0000 | expected)
            );
        }
        assert_eq!(state.next_control().unwrap(), b"held"[..]);
        assert!(state.next_control().is_none());
    }

    #[tokio::test]
    async fn saturated_control_queue_preserves_fifo_and_shutdown_owns_flights() {
        let (sender, receiver) = mpsc::channel(1);
        let mut state = State {
            enabled: true,
            control: Some(receiver),
            ..State::default()
        };
        sender.try_send(Bytes::from_static(b"first")).unwrap();
        assert!(!state.can_admit());
        assert!(matches!(
            sender.try_send(Bytes::from_static(b"second")),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        assert_eq!(
            state.control.as_mut().unwrap().try_recv().unwrap(),
            b"first"[..]
        );
        assert!(state.can_admit());
        sender.try_send(Bytes::from_static(b"second")).unwrap();
        let (finished, mut observed) = mpsc::channel::<()>(1);
        state.tasks.spawn(async move {
            let _guard = finished;
            std::future::pending().await
        });
        state.stop().await;
        assert!(sender.is_closed());
        assert!(observed.recv().await.is_none());
        assert!(state.tasks.is_empty());
    }
    #[test]
    fn bounded_lane_metadata_and_flight_sizes() {
        eprintln!(
            "fixture-layout owned write State={} B (test observers included, not shipping layout); input flight <={} B plus frame header; control queued+active <={} B/host, <={} B/1000hosts; 200 input flights <={} B plus headers/maps/transport",
            std::mem::size_of::<State>(),
            FLIGHT,
            2 * CONTROL_FLIGHT,
            2000 * CONTROL_FLIGHT,
            200 * FLIGHT
        );
        eprintln!(
            "fixture-layout priming State={} B; parked1000 fixture empty-state type bytes={} (test fields included; heap/transport excluded)",
            std::mem::size_of::<super::super::priming::State>(),
            1000 * std::mem::size_of::<super::super::priming::State>()
        );
        assert_eq!(CONTROL_FLIGHT, 33024);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn full_control_lane_keeps_all_terminal_owner_slots_available() {
        use super::super::BytesMut;
        let (link, _control, _listener, _endpoint, _peer) =
            crate::remote_runtime::tests::native_link_pair().await;
        let mut connection = AgentConnection {
            peer: Peer::Remote(link),
            execution_uid: 0,
            pid: None,
            receive: BytesMut::new(),
            scratch: vec![0; 4096],
            encode: Vec::new(),
            next_call_id: 1,
            owned_control: None,
            #[cfg(feature = "remote")]
            owned_cleanup: None,
        };
        let mut state = State::default();
        state.enable(&HashMap::new());
        state.install(&mut connection);
        let mut encoded = Vec::new();
        encode_frame_into(
            &Frame::Ping {
                nonce: 1,
                sent_us: 0,
            },
            &mut encoded,
        )
        .unwrap();
        let control = connection.owned_control.as_ref().unwrap();
        control.try_send(Bytes::copy_from_slice(&encoded)).unwrap();
        state.schedule(&connection, &HashMap::new());
        control.try_send(Bytes::from(encoded)).unwrap();
        assert!(state.control_busy);
        assert!(!state.can_admit());
        assert_eq!(state.tasks.len(), 1);
        let limit = infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS;
        let mut attachments: HashMap<_, _> = (0..limit)
            .map(|index| {
                let (output, _) = mpsc::channel(1);
                (
                    u64::try_from(index).unwrap(),
                    AttachmentState {
                        session_id: [u8::try_from(index).unwrap(); 16],
                        stream_id: 2 + 2 * u32::try_from(index).unwrap(),
                        last_out_seq: 0,
                        last_in_seq: 0,
                        last_input_end: 1,
                        unacknowledged: BytesMut::from(&b"x"[..]),
                        input_credit: tokio::sync::watch::channel(0).0,
                        credit: 0,
                        awaiting_ack: false,
                        replaying: false,
                        route: None,
                        proof_rebind_pending: false,
                        output,
                    },
                )
            })
            .collect();
        // No spawn can poll inline on this current-thread runtime. The control
        // owner occupies its own lane while this single scheduling pass admits
        // every terminal; no completed write can conceal a missing owner slot.
        state.schedule(&connection, &attachments);
        let admitted = state.busy.len();
        let total_tasks = state.tasks.len();
        // Detached routing entries do not release a still-owned task slot.
        // Replace every identity before any owner can run or be joined.
        for writer in attachments.values_mut() {
            writer.stream_id += 2 * u32::try_from(limit).unwrap();
        }
        state.schedule(&connection, &attachments);
        let replacement_owners = state.busy.len();
        let retained_tasks = state.tasks.len();
        state.stop().await;
        assert_eq!(
            admitted, limit,
            "an active/full control lane must not consume a terminal owner slot"
        );
        assert_eq!(total_tasks, limit + 1);
        assert_eq!(replacement_owners, 0);
        assert_eq!(retained_tasks, total_tasks);
    }
}
