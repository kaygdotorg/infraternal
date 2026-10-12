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
