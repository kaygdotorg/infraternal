//! Owns one native secondary and bounded readiness/credit metadata; the actor retains input once [128,215], #129.
use super::{
    AgentConnection, AgentError, AttachmentState, Bytes, Duration, Frame, HashMap, Incoming, Peer,
    RemoteLink, TerminalNotice, connect_remote, decode_session_id, encode_muxed_frame_into,
    oneshot, read_incoming, send_attach, write_frame,
};
use infraternal_protocol::{MAX_FRAME_LEN, encode_frame_into};
#[path = "embedded_shadow_flights.rs"]
mod flights;
use std::collections::HashSet;
use tokio::{task::JoinHandle, time::Instant};

const MAX_WRITERS: usize = infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS;
const HEDGE_AFTER: Duration = Duration::from_millis(200);
const SHADOW_CREDIT: u64 = 16 * 1024;

struct Preparing {
    task: JoinHandle<Result<Shadow, AgentError>>,
    reply: Option<oneshot::Sender<Result<(), AgentError>>>,
}
impl Preparing {
    async fn finish(&mut self) -> Result<Shadow, AgentError> {
        tokio::select! {
            result = &mut self.task => result.map_err(|_| AgentError::Unavailable).and_then(std::convert::identity),
            () = async { match self.reply.as_mut() { Some(reply) => reply.closed().await, None => std::future::pending().await } } => Err(AgentError::Unavailable),
        }
    }
}
impl Drop for Preparing {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct Slot {
    session: [u8; 16],
    ack: u64,
    hedged: bool,
    credit: u64,
    ready: bool,
    sent: u64,
    born: Instant,
}
struct Shadow {
    connection: AgentConnection,
    slots: HashMap<u32, Slot>,
}
struct Waiting {
    ack: u64,
    since: Instant,
}

#[derive(Default)]
pub(super) struct State {
    flights: flights::State,
    cancel_requested: bool,
    preparing: Option<Preparing>,
    shadow: Option<Shadow>,
    waiting: HashMap<u64, Waiting>,
    deduplicate: bool,
    setup: Option<JoinHandle<Vec<u32>>>,
    retired: Vec<u32>,
    refused: HashMap<u32, [u8; 16]>,
    snapshots: HashMap<u32, ([u8; 16], u64)>,
    notices: HashMap<u32, ([u8; 16], u8, u64)>,
}
pub(super) enum Event {
    Prepared,
    Incoming(Option<Incoming>),
    Hedge,
}

impl State {
    pub(super) fn active(&self) -> bool {
        self.preparing.is_some() || self.shadow.is_some()
    }
    pub(super) fn connection(&mut self) -> Option<&mut AgentConnection> {
        self.shadow.as_mut().map(|shadow| &mut shadow.connection)
    }
    pub(super) async fn cancel(&mut self) {
        // Flights keep native channels alive. Join them before releasing the
        // shadow connection so cancellation cannot publish after its owner exits.
        let _ = self.flights.stop().await;
        if let Some(task) = self.setup.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(mut preparing) = self.preparing.take() {
            preparing.task.abort();
            let _ = (&mut preparing.task).await;
        }
        self.retired.clear();
        self.shadow = None;
        self.waiting.clear();
        self.refused.clear();
        self.snapshots.clear();
        self.notices.clear();
        self.deduplicate = false;
        self.cancel_requested = false;
    }
    pub(super) fn start(
        &mut self,
        link: RemoteLink,
        uid: u32,
        attachments: &HashMap<u64, AttachmentState>,
        reply: oneshot::Sender<Result<(), AgentError>>,
    ) {
        if self.preparing.is_some()
            || self.shadow.is_some()
            || attachments.len() > MAX_WRITERS
            || !link.primed()
        {
            let _ = reply.send(Err(AgentError::Unavailable));
            return;
        }
        // Public identifiers/cursors only: retained input stays in AttachmentState.
        let plans: Vec<_> = attachments
            .values()
            .map(|a| (a.stream_id, a.session_id, a.last_out_seq, a.last_in_seq))
            .collect();
        self.preparing = Some(Preparing {
            task: tokio::spawn(prepare(link, uid, plans)),
            reply: Some(reply),
        });
    }
    pub(super) fn observe(&mut self, attachments: &HashMap<u64, AttachmentState>) {
        if self
            .preparing
            .as_ref()
            .and_then(|p| p.reply.as_ref())
            .is_some_and(oneshot::Sender::is_closed)
        {
            self.cancel_requested = true;
        }
        let Some(shadow) = self.shadow.as_mut() else {
            self.waiting.clear();
            return;
        };
        self.refused.retain(|stream, session| {
            attachments
                .values()
                .any(|a| a.stream_id == *stream && a.session_id == *session)
        });
        for (stream, slot) in &shadow.slots {
            if !slot.ready && slot.born.elapsed() >= Duration::from_secs(5) {
                self.refused.insert(*stream, slot.session);
            }
        }
        shadow.slots.retain(|stream, slot| {
            let live = !self.refused.contains_key(stream)
                && attachments
                    .values()
                    .any(|a| a.stream_id == *stream && a.session_id == slot.session);
            if !live && !self.retired.contains(stream) {
                self.flights.abort_writer(*stream);
                self.retired.push(*stream);
            }
            live
        });
        // One owned setup task serializes bounded new writers without blocking
        // the actor's existing shadow receive or its input hedge.
        if self.setup.is_none() {
            let mut plans = Vec::new();
            for a in attachments.values() {
                if shadow.slots.len() >= MAX_WRITERS {
                    break;
                }
                // Join a cancelled owner before reusing its binding identity.
                if !shadow.slots.contains_key(&a.stream_id)
                    && !self.refused.contains_key(&a.stream_id)
                    && !self.flights.owns(a.stream_id)
                {
                    shadow.slots.insert(
                        a.stream_id,
                        Slot {
                            session: a.session_id,
                            ack: 0,
                            hedged: false,
                            credit: 0,
                            ready: false,
                            sent: 0,
                            born: Instant::now(),
                        },
                    );
                    plans.push((a.stream_id, a.session_id, a.last_out_seq, a.last_in_seq));
                }
            }
            if (!plans.is_empty() || !self.retired.is_empty())
                && let Peer::Remote(link) = &shadow.connection.peer
            {
                let link = link.clone();
                let retired = std::mem::take(&mut self.retired);
                self.setup = Some(tokio::spawn(async move {
                    for stream in retired {
                        link.retire_writer(stream).await;
                    }
                    let mut failed = Vec::new();
                    let deadline = Instant::now() + Duration::from_secs(5);
                    for (stream, session, last_out_seq, last_in_seq) in plans {
                        let frame = Frame::AttachTerm {
                            session_id: &session,
                            last_out_seq,
                            last_in_seq,
                        };
                        let mut muxed = Vec::new();
                        let result = encode_muxed_frame_into(stream, &frame, &mut muxed);
                        if result.is_err()
                            || tokio::time::timeout_at(deadline, link.write(stream, &frame, &muxed))
                                .await
                                .map_or(true, |result| result.is_err())
                        {
                            failed.push(stream);
                        }
                    }
                    failed
                }));
            }
        }
        self.track_waiting(attachments);
    }
    fn track_waiting(&mut self, attachments: &HashMap<u64, AttachmentState>) {
        let Some(shadow) = self.shadow.as_ref() else {
            return;
        };
        self.waiting.retain(|id, _| {
            attachments
                .get(id)
                .is_some_and(|a| !a.unacknowledged.is_empty())
        });
        for (id, a) in attachments {
            if a.unacknowledged.is_empty() || !shadow.slots.contains_key(&a.stream_id) {
                continue;
            }
            let entry = self.waiting.entry(*id).or_insert(Waiting {
                ack: a.last_in_seq,
                since: Instant::now(),
            });
            if entry.ack != a.last_in_seq {
                entry.ack = a.last_in_seq;
                entry.since = Instant::now();
            }
        }
    }
    fn deadline(&self, attachments: &HashMap<u64, AttachmentState>) -> Option<Instant> {
        let shadow = self.shadow.as_ref()?;
        let mut deadline = None;
        for (id, a) in attachments {
            let Some(slot) = shadow.slots.get(&a.stream_id) else {
                continue;
            };
            if self.flights.owns(a.stream_id) {
                continue;
            }
            if !slot.ready {
                let when = slot.born + Duration::from_secs(5);
                deadline = Some(deadline.map_or(when, |old: Instant| old.min(when)));
                continue;
            }
            let confirmed = a.last_in_seq.max(slot.ack);
            let has_input = a.last_input_end > slot.sent.max(confirmed)
                && slot.sent.saturating_sub(confirmed) < SHADOW_CREDIT;
            let when =
                if slot.hedged && (has_input || slot.credit < a.credit.min(MAX_FRAME_LEN as u64)) {
                    Some(Instant::now())
                } else if !slot.hedged {
                    self.waiting
                        .get(id)
                        .map(|waiting| waiting.since + HEDGE_AFTER)
                } else {
                    None
                };
            if let Some(when) = when {
                deadline = Some(deadline.map_or(when, |old: Instant| old.min(when)));
            }
        }
        deadline
    }
    pub(super) async fn next(&mut self, attachments: &HashMap<u64, AttachmentState>) -> Event {
        if self.cancel_requested {
            self.cancel().await;
            return Event::Prepared;
        }
        let deadline = self.deadline(attachments);
        tokio::select! {
            completion = self.flights.next(), if self.flights.active() => {
                if !completion.success
                    && let Some(shadow) = self.shadow.as_mut()
                    && shadow.slots.get(&completion.stream).is_some_and(|slot| slot.session == completion.session)
                {
                    shadow.slots.remove(&completion.stream);
                    self.refused.insert(completion.stream, completion.session);
                    self.retired.push(completion.stream);
                }
                Event::Prepared
            }

            result = async { match self.setup.as_mut() { Some(task) => task.await, None => std::future::pending().await } }, if self.setup.is_some() => {
                self.setup = None;
                match result {
                    Ok(failed) => { if let Some(shadow) = self.shadow.as_mut() { for stream in failed { if let Some(slot) = shadow.slots.remove(&stream) { self.refused.insert(stream, slot.session); } self.retired.push(stream); } } }
                    Err(_) => self.cancel().await,
                }
                Event::Prepared
            }
            result = async { match self.preparing.as_mut() { Some(p) => p.finish().await, None => std::future::pending().await } }, if self.preparing.is_some() => {
                if let Some(mut preparing) = self.preparing.take() {
                    let result = result.and_then(|shadow| {
                        // A first Ack may advance while the primary continues typing.
                        // Validate at completion, but do not release browser input here.
                        for (stream, slot) in &shadow.slots {
                            let Some(a) = attachments.values().find(|a| a.stream_id == *stream && a.session_id == slot.session) else { return Err(AgentError::Unavailable); };
                            if !a.awaiting_ack && slot.ack > a.last_input_end { return Err(AgentError::Protocol); }
                        }
                        self.shadow = Some(shadow); self.deduplicate = true; Ok(())
                    });
                    if let Some(reply) = preparing.reply.take() && reply.send(result).is_err() { self.cancel().await; }
                }
                Event::Prepared
            }
            incoming = async { match self.shadow.as_mut() { Some(s) => read_incoming(&mut s.connection).await, None => std::future::pending().await } }, if self.shadow.is_some() => Event::Incoming(incoming),
            () = async { match deadline { Some(deadline) => tokio::time::sleep_until(deadline).await, None => std::future::pending().await } } => Event::Hedge,
        }
    }
    pub(super) fn hedge(
        &mut self,
        attachments: &HashMap<u64, AttachmentState>,
    ) -> std::future::Ready<bool> {
        let Some(shadow) = self.shadow.as_mut() else {
            return std::future::ready(true);
        };
        let native = matches!(&shadow.connection.peer, Peer::Remote(link) if link.native());
        for (id, a) in attachments {
            let Some(slot) = shadow.slots.get_mut(&a.stream_id) else {
                continue;
            };
            if !slot.ready || self.flights.owns(a.stream_id) {
                continue;
            }
            let due = self
                .waiting
                .get(id)
                .is_some_and(|waiting| waiting.since.elapsed() >= HEDGE_AFTER);
            if !slot.hedged && (!due || a.unacknowledged.is_empty()) {
                continue;
            }
            let Ok(plan) = flight_plan(a, slot, native) else {
                self.refused.insert(a.stream_id, slot.session);
                self.retired.push(a.stream_id);
                continue;
            };
            if plan.frames.is_empty() {
                continue;
            }
            if self.flights.schedule(
                &mut shadow.connection,
                a.stream_id,
                a.session_id,
                plan.frames,
            ) {
                // Reserve before the actor can consume flight output. Socket completion
                // never opens another input window: only durable Ack does that.
                slot.credit = plan.credit;
                slot.sent = plan.sent;
                slot.hedged = true;
            }
        }
        shadow
            .slots
            .retain(|stream, _| !self.refused.contains_key(stream));
        std::future::ready(true)
    }
    /// Trim interleaved output before shared actor credit accounting.
    pub(super) fn trim(
        &mut self,
        incoming: &mut Incoming,
        attachments: &HashMap<u64, AttachmentState>,
    ) {
        if !self.deduplicate {
            return;
        }
        let _ = normalize_notice(incoming, attachments, &mut self.notices);
        normalize_snapshot(incoming, attachments, &mut self.snapshots);
        trim_output(incoming, attachments);
    }
    pub(super) fn accept(
        &mut self,
        incoming: &mut Incoming,
        attachments: &HashMap<u64, AttachmentState>,
    ) -> bool {
        let Some(shadow) = self.shadow.as_mut() else {
            return false;
        };
        match incoming {
            Incoming::Activate => true,
            Incoming::Ack {
                stream_id,
                in_seq_acked,
            } => {
                let Some(slot) = shadow.slots.get_mut(stream_id) else {
                    return false;
                };
                let Some(a) = attachments
                    .values()
                    .find(|a| a.stream_id == *stream_id && a.session_id == slot.session)
                else {
                    return false;
                };
                if (!a.awaiting_ack && *in_seq_acked > a.last_input_end)
                    || (slot.ready && *in_seq_acked < slot.ack)
                {
                    return false;
                }
                slot.ack = *in_seq_acked;
                slot.ready = true;
                true
            }
            Incoming::Output {
                stream_id, bytes, ..
            }
            | Incoming::Snapshot {
                stream_id, bytes, ..
            } => {
                let Some(slot) = shadow.slots.get_mut(stream_id) else {
                    return false;
                };
                if !slot.hedged || bytes.len() as u64 > slot.credit {
                    return false;
                }
                slot.credit -= bytes.len() as u64;
                normalize_snapshot(incoming, attachments, &mut self.snapshots);
                trim_output(incoming, attachments);
                safe_delivery(incoming, attachments)
            }
            Incoming::Event { stream_id, .. } => {
                let Some(slot) = shadow.slots.get(stream_id) else {
                    return false;
                };
                slot.hedged && normalize_notice(incoming, attachments, &mut self.notices)
            }
            // A queued notice, reset or unexpected control frame does
            // not mutate the working primary or its browser attachment.
            _ => false,
        }
    }
    pub(super) fn ready(&self, stream: u32) -> bool {
        self.shadow
            .as_ref()
            .and_then(|shadow| shadow.slots.get(&stream))
            .is_some_and(|slot| slot.ready)
    }
    pub(super) fn hedged(&self, stream: u32) -> bool {
        self.shadow
            .as_ref()
            .and_then(|shadow| shadow.slots.get(&stream))
            .is_some_and(|slot| slot.hedged)
    }
    pub(super) async fn retire_slot(&mut self, stream: u32) {
        self.flights.retire(stream).await;
        if let Some(shadow) = self.shadow.as_mut() {
            if let Some(slot) = shadow.slots.remove(&stream) {
                self.refused.insert(stream, slot.session);
            }
            if let Peer::Remote(link) = &shadow.connection.peer {
                link.retire_writer(stream).await;
                return;
            }
            let _ = write_frame(
                &mut shadow.connection,
                stream,
                &Frame::Close {
                    code: 1000,
                    reason: "standby writer unavailable",
                },
            )
            .await;
        }
    }
    pub(super) async fn promote(
        &mut self,
    ) -> Result<(AgentConnection, HashMap<u32, (u64, u64, bool)>), AgentError> {
        let completions = self.flights.stop().await;
        // No setup future may select a writer after priming is cleared.
        if let Some(task) = self.setup.take() {
            task.abort();
            let _ = task.await;
        }
        let mut shadow = self.shadow.take().ok_or(AgentError::Unavailable)?;
        // Credit/sent are reservations until the owned write completes. A
        // cancelled native write retires its channel; remove only its matching
        // slot so promotion can bind it afresh without duplicating grants on
        // the writers that completed successfully.
        for completion in completions {
            if !completion.success
                && shadow
                    .slots
                    .get(&completion.stream)
                    .is_some_and(|slot| slot.session == completion.session)
            {
                shadow.slots.remove(&completion.stream);
            }
        }
        let pending: Vec<_> = shadow
            .slots
            .iter()
            .filter_map(|(stream, slot)| (!slot.ready).then_some(*stream))
            .collect();
        let Peer::Remote(link) = &shadow.connection.peer else {
            return Err(AgentError::Protocol);
        };
        for stream in pending {
            link.retire_writer(stream).await;
            shadow.slots.remove(&stream);
        }
        let ready: Vec<_> = shadow.slots.keys().copied().collect();
        link.retain_writers(&ready).await;
        self.retired.clear();
        link.promote().await.map_err(|_| AgentError::Unavailable)?;
        let ack = shadow
            .slots
            .into_iter()
            .filter(|(_, slot)| slot.ready)
            .map(|(stream, slot)| (stream, (slot.ack, slot.credit, slot.hedged)))
            .collect();
        self.waiting.clear();
        Ok((shadow.connection, ack))
    }
}

struct FlightPlan {
    frames: Vec<Bytes>,
    credit: u64,
    sent: u64,
}
fn flight_plan(a: &AttachmentState, slot: &Slot, native: bool) -> Result<FlightPlan, ()> {
    let confirmed = a.last_in_seq.max(slot.ack);
    let start = confirmed.max(slot.sent);
    let skip = usize::try_from(start.saturating_sub(a.last_in_seq)).map_err(|_| ())?;
    let pending = a.unacknowledged.get(skip..).ok_or(())?;
    let available = usize::try_from(SHADOW_CREDIT.saturating_sub(start.saturating_sub(confirmed)))
        .map_err(|_| ())?;
    let bytes = &pending[..pending.len().min(available)];
    let mut frames = Vec::with_capacity(3);
    let mut append = |frame: &Frame<'_>| {
        // The shared encoders clear their destination. Keep each bounded frame
        // separate; the owned task serializes this list without a concat copy.
        let mut encoded = Vec::new();
        if native {
            encode_frame_into(frame, &mut encoded)
        } else {
            encode_muxed_frame_into(a.stream_id, frame, &mut encoded)
        }
        .map_err(|_| ())?;
        frames.push(Bytes::from(encoded));
        Ok::<(), ()>(())
    };
    if !slot.hedged {
        let json =
            serde_json::to_vec(&serde_json::json!({"out_seq": a.last_out_seq})).map_err(|_| ())?;
        append(&Frame::Call {
            call_id: 0,
            action_id: "transport.cursor",
            input_json: &json,
        })?;
    }
    let target = a.credit.min(if slot.hedged {
        MAX_FRAME_LEN as u64
    } else {
        SHADOW_CREDIT
    });
    let credit = slot.credit.max(target);
    if target > slot.credit {
        append(&Frame::Credit {
            bytes: u32::try_from(target - slot.credit).map_err(|_| ())?,
        })?;
    }
    if !bytes.is_empty() {
        append(&Frame::Input {
            in_seq: start,
            bytes,
        })?;
    }
    // Cursor and credit headers are fixed and small; a single input flight is
    // at most16KiB, even after socket completion without a durable writer Ack.
    if frames.iter().map(Bytes::len).sum::<usize>()
        > usize::try_from(SHADOW_CREDIT).map_err(|_| ())? + 256
    {
        return Err(());
    }
    Ok(FlightPlan {
        frames,
        credit,
        sent: start + bytes.len() as u64,
    })
}

async fn prepare(
    link: RemoteLink,
    uid: u32,
    plans: Vec<(u32, [u8; 16], u64, u64)>,
) -> Result<Shadow, AgentError> {
    let mut connection = connect_remote(link, uid).await?;
    let mut slots = HashMap::new();
    for (stream, session, out_seq, in_seq) in plans {
        if !send_attach(&mut connection, stream, session, out_seq, in_seq).await {
            return Err(AgentError::Unavailable);
        }
        slots.insert(
            stream,
            Slot {
                session,
                ack: 0,
                hedged: false,
                credit: 0,
                ready: true,
                sent: 0,
                born: Instant::now(),
            },
        );
    }
    let mut waiting: HashSet<_> = slots.keys().copied().collect();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !waiting.is_empty() {
            let Some(Incoming::Ack {
                stream_id,
                in_seq_acked,
            }) = read_incoming(&mut connection).await
            else {
                return Err(AgentError::Protocol);
            };
            let slot = slots.get_mut(&stream_id).ok_or(AgentError::Protocol)?;
            slot.ack = in_seq_acked;
            waiting.remove(&stream_id);
        }
        Ok::<_, AgentError>(())
    })
    .await
    .map_err(|_| AgentError::Unavailable)??;
    Ok(Shadow { connection, slots })
}

fn normalize_notice(
    incoming: &mut Incoming,
    attachments: &HashMap<u64, AttachmentState>,
    seen: &mut HashMap<u32, ([u8; 16], u8, u64)>,
) -> bool {
    let (stream, json) = match incoming {
        Incoming::Event {
            stream_id,
            event_json,
        } => (*stream_id, event_json),
        _ => return true,
    };
    let Some(a) = attachments.values().find(|a| a.stream_id == stream) else {
        return false;
    };
    if json.len() > infraternal_plugin_api::MAX_ACTION_BYTES {
        return false;
    }
    let Ok(notice) = serde_json::from_slice::<TerminalNotice>(json) else {
        return false;
    };
    if decode_session_id(notice.session_id()) != Some(a.session_id) {
        return false;
    }
    let (kind, seq) = match notice {
        TerminalNotice::Snapshot { seq, .. } => (0, seq),
        TerminalNotice::Unavailable { seq, .. } => (1, seq),
        TerminalNotice::Exited { final_seq, .. } => (2, final_seq),
        TerminalNotice::ReplayComplete { out_seq, .. } => (3, out_seq),
        TerminalNotice::QueryRepliesUnavailable { .. } => (4, 0),
    };
    if seen
        .get(&stream)
        .is_some_and(|(session, previous_kind, previous_seq)| {
            *session == a.session_id && *previous_kind == kind && *previous_seq >= seq
        })
    {
        *incoming = Incoming::Output {
            stream_id: stream,
            out_seq: a.last_out_seq,
            bytes: Bytes::new(),
        };
        return true;
    }
    if a.output.capacity() == 0 || a.output.is_closed() {
        return false;
    }
    seen.retain(|stream, _| attachments.values().any(|a| a.stream_id == *stream));
    seen.insert(stream, (a.session_id, kind, seq));
    true
}

fn normalize_snapshot(
    incoming: &mut Incoming,
    attachments: &HashMap<u64, AttachmentState>,
    seen: &mut HashMap<u32, ([u8; 16], u64)>,
) {
    let (stream, seq) = match incoming {
        Incoming::Snapshot {
            stream_id, out_seq, ..
        } => (*stream_id, *out_seq),
        _ => return,
    };
    let Some(a) = attachments.values().find(|a| a.stream_id == stream) else {
        return;
    };
    if seq < a.last_out_seq
        || seen
            .get(&stream)
            .is_some_and(|(session, previous)| *session == a.session_id && *previous >= seq)
    {
        *incoming = Incoming::Output {
            stream_id: stream,
            out_seq: a.last_out_seq,
            bytes: Bytes::new(),
        };
    } else if safe_delivery(incoming, attachments) {
        // At most one marker per live writer, retained through promotion.
        seen.retain(|stream, _| attachments.values().any(|a| a.stream_id == *stream));
        seen.insert(stream, (a.session_id, seq));
    }
}

// Shadow protocol errors/backpressure must not enter the ordinary handler's
// retirement branch and destroy an otherwise working primary attachment.
fn safe_delivery(incoming: &Incoming, attachments: &HashMap<u64, AttachmentState>) -> bool {
    let (stream, seq, bytes, snapshot) = match incoming {
        Incoming::Output {
            stream_id,
            out_seq,
            bytes,
        } => (*stream_id, *out_seq, bytes, false),
        Incoming::Snapshot {
            stream_id,
            out_seq,
            bytes,
        } => (*stream_id, *out_seq, bytes, true),
        _ => return true,
    };
    let Some(a) = attachments.values().find(|a| a.stream_id == stream) else {
        return false;
    };
    if !snapshot && bytes.is_empty() && seq == a.last_out_seq {
        return true;
    }
    seq.checked_add(bytes.len() as u64).is_some()
        && bytes.len() as u64 <= a.credit
        && a.output.capacity() > 0
        && !a.output.is_closed()
        && if snapshot {
            seq >= a.last_out_seq
        } else {
            seq == a.last_out_seq
        }
}

fn trim_output(incoming: &mut Incoming, attachments: &HashMap<u64, AttachmentState>) {
    // A snapshot behind already delivered raw output cannot replace browser
    // state or retire the primary; normalize it to a zero-credit no-op.
    if let Incoming::Snapshot {
        stream_id, out_seq, ..
    } = incoming
        && let Some(a) = attachments.values().find(|a| a.stream_id == *stream_id)
        && *out_seq < a.last_out_seq
    {
        *incoming = Incoming::Output {
            stream_id: *stream_id,
            out_seq: a.last_out_seq,
            bytes: Bytes::new(),
        };
        return;
    }
    let Incoming::Output {
        stream_id,
        out_seq,
        bytes,
    } = incoming
    else {
        return;
    };
    let Some(a) = attachments.values().find(|a| a.stream_id == *stream_id) else {
        return;
    };
    if *out_seq < a.last_out_seq
        && let Ok(skip) = usize::try_from(a.last_out_seq - *out_seq)
    {
        let skip = skip.min(bytes.len());
        *bytes = bytes.slice(skip..);
        *out_seq += skip as u64;
    }
}

impl Drop for State {
    fn drop(&mut self) {
        if let Some(task) = self.setup.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    //! Proves bounded shadow credit, replay, and cancellation without changing primary writer state.
    use super::super::{
        BytesMut, TerminalOutput, UnixStream, decode_muxed_frame, mpsc, process_incoming, watch,
    };
    use super::*;
    use tokio::io::AsyncReadExt;

    pub(super) fn attachment() -> (AttachmentState, mpsc::Receiver<TerminalOutput>) {
        let (output, receiver) = mpsc::channel(4);
        let (input_credit, _) = watch::channel(0);
        (
            AttachmentState {
                stream_id: 1,
                session_id: [7; 16],
                last_out_seq: 10,
                last_in_seq: 0,
                last_input_end: 3,
                unacknowledged: BytesMut::from(&b"abc"[..]),
                input_credit,
                credit: 1024,
                awaiting_ack: false,
                replaying: false,
                route: None,
                proof_rebind_pending: false,
                output,
            },
            receiver,
        )
    }
    pub(super) fn shadow(socket: UnixStream) -> Shadow {
        let (reader, writer) = socket.into_split();
        Shadow {
            connection: AgentConnection {
                peer: Peer::Local { reader, writer },
                execution_uid: 0,
                pid: None,
                receive: BytesMut::new(),
                scratch: vec![0; 4096],
                encode: Vec::new(),
                next_call_id: 1,
                owned_control: None,
                owned_cleanup: None,
            },
            slots: HashMap::from([(
                1,
                Slot {
                    session: [7; 16],
                    ack: 0,
                    hedged: false,
                    credit: 0,
                    ready: true,
                    sent: 0,
                    born: Instant::now(),
                },
            )]),
        }
    }
    async fn wire(peer: &mut UnixStream, buffered: &mut BytesMut) -> Bytes {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(frame) = decode_muxed_frame(buffered) {
                    return buffered.split_to(frame.wire_len).freeze();
                }
                assert_ne!(peer.read_buf(buffered).await.unwrap(), 0);
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn flow_control_blocked_shadow_does_not_stop_actor_control_progress() {
        use infraternal_agent::{
            remote_native::NativeChannel,
            transport::{Receive, Transmit},
        };
        use infraternal_plugin_remote::remote_quic;
        let (link, control, _listener, _endpoint, peer) =
            crate::remote_runtime::tests::native_link_pair().await;
        let hello = Frame::Hello {
            version: 1,
            caps: remote_quic::REMOTE_WRITER_BINDING,
            client_info: "fixture",
        };
        let binding = remote_quic::negotiate_binding(&peer, &hello).unwrap();
        let attach = Frame::AttachTerm {
            session_id: &[7; 16],
            last_out_seq: 0,
            last_in_seq: 0,
        };
        let mut wire = Vec::new();
        infraternal_protocol::encode_muxed_frame_into(42, &attach, &mut wire).unwrap();
        link.write(42, &attach, &wire).await.unwrap();
        let parked =
            NativeChannel::terminal(remote_quic::accept_bound(&binding).await.unwrap()).unwrap();
        assert!(matches!(
            Receive::default().next(&parked).await.unwrap().frame,
            Frame::AttachTerm { .. }
        ));
        // The peer stops reading this4KiB window. A256B server send window
        // makes a16KiB Input flight block after QUIC has exhausted receive credit.
        link.limit_send_window(256);
        let (socket, _unused) = UnixStream::pair().unwrap();
        let mut ready_shadow = shadow(socket);
        ready_shadow.connection.peer = Peer::Remote(link.clone());
        let slot = ready_shadow.slots.remove(&1).unwrap();
        ready_shadow.slots.insert(42, slot);
        let mut state = State::default();
        state.shadow = Some(ready_shadow);
        state.waiting.insert(
            1,
            Waiting {
                ack: 0,
                since: Instant::now() - HEDGE_AFTER,
            },
        );
        let (mut attachment, _output) = attachment();
        attachment.stream_id = 42;
        attachment.unacknowledged.resize(16384, b'x');
        attachment.last_input_end = 16384;
        let attachments = HashMap::from([(1, attachment)]);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), state.hedge(&attachments))
                .await
                .expect("shadow I/O must be owned, not awaited by the actor")
        );
        Transmit::default()
            .send(
                &control,
                0,
                &Frame::Result {
                    call_id: 92,
                    ok: true,
                    json: b"{}",
                },
            )
            .await
            .unwrap();
        let mut received = BytesMut::new();
        tokio::time::timeout(
            Duration::from_millis(100),
            link.read(&mut received, &mut [0; 4096]),
        )
        .await
        .expect("healthy control progresses while shadow is blocked")
        .unwrap();
        assert!(matches!(
            decode_muxed_frame(&received).unwrap().frame,
            Frame::Result { call_id: 92, .. }
        ));
        state.cancel().await;
    }

    #[tokio::test]
    async fn stream_reuse_waits_for_the_retired_flight_to_join() {
        let (socket, _peer) = UnixStream::pair().unwrap();
        let mut state = State::default();
        state.shadow = Some(shadow(socket));
        state.waiting.insert(
            1,
            Waiting {
                ack: 0,
                since: Instant::now() - HEDGE_AFTER,
            },
        );
        let (a, _output) = attachment();
        let attachments = HashMap::from([(1, a)]);
        assert!(state.hedge(&attachments).await);
        assert!(state.flights.owns(1));
        // No yield occurs between detach and reattach. The cancelled task has
        // not joined yet, even if its stream/session identifiers are reused.
        state.observe(&HashMap::new());
        state.observe(&attachments);
        let rebound = state.shadow.as_ref().unwrap().slots.contains_key(&1);
        state.cancel().await;
        assert!(
            !rebound,
            "a retired flight still owns the reused shadow stream"
        );
    }

    #[tokio::test]
    async fn abandoned_preparation_cancels_even_before_the_owned_task_first_polls() {
        struct Lifetime(Option<oneshot::Sender<()>>);
        impl Drop for Lifetime {
            fn drop(&mut self) {
                if let Some(done) = self.0.take() {
                    let _ = done.send(());
                }
            }
        }
        let (done, cancelled) = oneshot::channel();
        let lifetime = Lifetime(Some(done));
        let task = tokio::spawn(async move {
            let _lifetime = lifetime;
            std::future::pending::<Result<Shadow, AgentError>>().await
        });
        let (reply, receiver) = oneshot::channel();
        let mut preparing = Preparing {
            task,
            reply: Some(reply),
        };
        drop(receiver);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), preparing.finish())
                .await
                .unwrap()
                .is_err()
        );
        drop(preparing);
        tokio::time::timeout(Duration::from_secs(1), cancelled)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn later_input_is_hedged_without_resending_the_first_suffix() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let mut state = State::default();
        state.shadow = Some(shadow(socket));
        state.waiting.insert(
            1,
            Waiting {
                ack: 0,
                since: Instant::now() - HEDGE_AFTER,
            },
        );
        let (a, _output) = attachment();
        let mut attachments = HashMap::from([(1, a)]);
        assert!(state.hedge(&attachments).await);
        let mut buffered = BytesMut::new();
        let cursor = wire(&mut peer, &mut buffered).await;
        assert!(matches!(
            decode_muxed_frame(&cursor).unwrap().frame,
            Frame::Call {
                action_id: "transport.cursor",
                ..
            }
        ));
        let credit = wire(&mut peer, &mut buffered).await;
        assert!(matches!(
            decode_muxed_frame(&credit).unwrap().frame,
            Frame::Credit { bytes: 1024 }
        ));
        let first = wire(&mut peer, &mut buffered).await;
        assert_eq!(
            decode_muxed_frame(&first).unwrap().frame,
            Frame::Input {
                in_seq: 0,
                bytes: b"abc"
            }
        );
        let _ = state.flights.next().await;
        let a = attachments.get_mut(&1).unwrap();
        a.unacknowledged.extend_from_slice(b"def");
        a.last_input_end = 6;
        assert!(state.hedge(&attachments).await);
        let second = wire(&mut peer, &mut buffered).await;
        assert_eq!(
            decode_muxed_frame(&second).unwrap().frame,
            Frame::Input {
                in_seq: 3,
                bytes: b"def"
            }
        );
        let _ = state.flights.next().await;
        assert!(state.hedge(&attachments).await);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), wire(&mut peer, &mut buffered))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn shadow_input_and_snapshot_credit_have_independent_bounded_windows() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let mut state = State::default();
        state.shadow = Some(shadow(socket));
        state.waiting.insert(
            1,
            Waiting {
                ack: 0,
                since: Instant::now() - HEDGE_AFTER,
            },
        );
        let (mut a, _output) = attachment();
        a.unacknowledged
            .resize(usize::try_from(SHADOW_CREDIT * 2).unwrap(), b'x');
        a.last_input_end = SHADOW_CREDIT * 2;
        a.credit = MAX_FRAME_LEN as u64 + 1024;
        let attachments = HashMap::from([(1, a)]);
        let mut buffered = BytesMut::new();
        assert!(state.hedge(&attachments).await);
        let _ = wire(&mut peer, &mut buffered).await;
        let initial_grant = wire(&mut peer, &mut buffered).await;
        assert!(matches!(
            decode_muxed_frame(&initial_grant).unwrap().frame,
            Frame::Credit { bytes: 16384 }
        ));
        let initial_payload = wire(&mut peer, &mut buffered).await;
        assert!(
            matches!(decode_muxed_frame(&initial_payload).unwrap().frame, Frame::Input { in_seq: 0, bytes } if bytes.len() == usize::try_from(SHADOW_CREDIT).unwrap())
        );
        let _ = state.flights.next().await;
        assert!(state.hedge(&attachments).await);
        let followup = wire(&mut peer, &mut buffered).await;
        assert!(
            matches!(decode_muxed_frame(&followup).unwrap().frame, Frame::Credit { bytes } if u64::from(bytes) == MAX_FRAME_LEN as u64 - SHADOW_CREDIT)
        );
        let _ = state.flights.next().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), wire(&mut peer, &mut buffered))
                .await
                .is_err()
        );
        assert!(state.accept(
            &mut Incoming::Ack {
                stream_id: 1,
                in_seq_acked: SHADOW_CREDIT
            },
            &attachments
        ));
        assert!(state.hedge(&attachments).await);
        let next_input = wire(&mut peer, &mut buffered).await;
        assert!(
            matches!(decode_muxed_frame(&next_input).unwrap().frame, Frame::Input { in_seq: 16384, bytes } if bytes.len() == usize::try_from(SHADOW_CREDIT).unwrap())
        );
        assert_eq!(attachments[&1].credit, MAX_FRAME_LEN as u64 + 1024);
    }

    #[tokio::test]
    async fn snapshot_notice_precedes_repaint_and_duplicates_spend_no_browser_credit() {
        let (socket, _) = UnixStream::pair().unwrap();
        let mut state = State::default();
        state.shadow = Some(shadow(socket));
        let slot = state.shadow.as_mut().unwrap().slots.get_mut(&1).unwrap();
        slot.hedged = true;
        slot.credit = 1024;
        let (a, mut output) = attachment();
        let mut attachments = HashMap::from([(1, a)]);
        let json = serde_json::to_vec(&serde_json::json!({"type":"terminal.snapshot", "session_id": uuid::Uuid::from_bytes([7;16]).simple().to_string(), "seq":20, "approximate":false})).unwrap();
        let mut notice = Incoming::Event {
            stream_id: 1,
            event_json: Bytes::from(json.clone()),
        };
        assert!(
            state.accept(&mut notice, &attachments),
            "valid shadow snapshot notice must precede its repaint"
        );
        let mut primary = shadow(UnixStream::pair().unwrap().0).connection;
        let mut routes = HashMap::from([(1, 1)]);
        let mut pending = HashMap::new();
        assert!(
            process_incoming(
                notice,
                &mut primary,
                &mut attachments,
                &mut routes,
                &mut pending
            )
            .await
        );
        let mut snapshot = Incoming::Snapshot {
            stream_id: 1,
            out_seq: 20,
            bytes: Bytes::from_static(b"repaint"),
        };
        assert!(state.accept(&mut snapshot, &attachments));
        assert!(
            process_incoming(
                snapshot,
                &mut primary,
                &mut attachments,
                &mut routes,
                &mut pending
            )
            .await
        );
        assert!(matches!(
            output.try_recv().unwrap(),
            TerminalOutput::Event { .. }
        ));
        assert!(matches!(
            output.try_recv().unwrap(),
            TerminalOutput::Snapshot { out_seq: 20, .. }
        ));
        let credit = attachments[&1].credit;
        let mut duplicate = Incoming::Event {
            stream_id: 1,
            event_json: Bytes::from(json),
        };
        assert!(state.accept(&mut duplicate, &attachments));
        assert!(
            process_incoming(
                duplicate,
                &mut primary,
                &mut attachments,
                &mut routes,
                &mut pending
            )
            .await
        );
        let mut duplicate = Incoming::Snapshot {
            stream_id: 1,
            out_seq: 20,
            bytes: Bytes::from_static(b"repaint"),
        };
        assert!(state.accept(&mut duplicate, &attachments));
        assert!(
            process_incoming(
                duplicate,
                &mut primary,
                &mut attachments,
                &mut routes,
                &mut pending
            )
            .await
        );
        assert!(output.try_recv().is_err());
        assert_eq!(attachments[&1].credit, credit);
    }

    #[tokio::test]
    async fn overlap_and_stale_snapshot_do_not_spend_browser_credit() {
        let (socket, _) = UnixStream::pair().unwrap();
        let mut state = State::default();
        state.shadow = Some(shadow(socket));
        let slot = state.shadow.as_mut().unwrap().slots.get_mut(&1).unwrap();
        slot.hedged = true;
        slot.credit = 1024;
        let (a, _output) = attachment();
        let attachments = HashMap::from([(1, a)]);
        let mut output = Incoming::Output {
            stream_id: 1,
            out_seq: 8,
            bytes: Bytes::from_static(b"abcd"),
        };
        assert!(state.accept(&mut output, &attachments));
        assert!(
            matches!(output, Incoming::Output { out_seq: 10, ref bytes, .. } if bytes.as_ref() == b"cd")
        );
        let mut old_snapshot = Incoming::Snapshot {
            stream_id: 1,
            out_seq: 9,
            bytes: Bytes::from_static(b"old"),
        };
        assert!(state.accept(&mut old_snapshot, &attachments));
        assert!(
            matches!(old_snapshot, Incoming::Output { out_seq: 10, ref bytes, .. } if bytes.is_empty())
        );
        let mut newer = Incoming::Snapshot {
            stream_id: 1,
            out_seq: 20,
            bytes: Bytes::from_static(b"new"),
        };
        assert!(state.accept(&mut newer, &attachments));
        assert!(matches!(newer, Incoming::Snapshot { out_seq: 20, .. }));
        let mut duplicate = Incoming::Snapshot {
            stream_id: 1,
            out_seq: 20,
            bytes: Bytes::from_static(b"new"),
        };
        assert!(state.accept(&mut duplicate, &attachments));
        assert!(matches!(duplicate, Incoming::Output { ref bytes, .. } if bytes.is_empty()));
        let mut gap = Incoming::Output {
            stream_id: 1,
            out_seq: 30,
            bytes: Bytes::from_static(b"gap"),
        };
        assert!(!state.accept(&mut gap, &attachments));
        assert_eq!(attachments[&1].credit, 1024);
    }
}

#[cfg(test)]
#[path = "embedded_priming_header_tests.rs"]
mod header_tests;
