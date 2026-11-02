//! Owns admitted app-window sessions independently of browser logins and joins captures on feature disable [D104,D198,D208,D232].
use crate::{
    protocol::Start,
    registry::Registry,
    server_manifest::DESCRIPTOR,
    session::{AccessRules, Error, Session, SessionId},
};
use bytes::Bytes;
use infraternal_plugin_api::{
    Operation, Plugin, PluginDescriptor, ReplySender, SocketHost, SubscriptionRegistry,
    streams::NodeHost,
};
use infraternal_protocol::{
    Frame, decode_muxed_frame,
    desktop::{Delivery, Message},
    encode_frame_into, encode_muxed_frame_into,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};

pub use crate::wire::WIRE;

// The current enrolled-host authority is owner-only, matching terminal host
// selection. Each viewer separately retains its own login projection in Session.
// Host revocation withdraws this shared admission without per-frame SQLite reads.
struct HostAccessRules(Arc<dyn NodeHost>);
impl AccessRules for HostAccessRules {
    fn may_view(&self, user: &str, host: &str, owner: &str) -> bool {
        user == owner && owner == self.0.owner_id() && host == self.0.id() && self.0.permits()
    }
    fn may_control(&self, user: &str, host: &str, owner: &str) -> bool {
        self.may_view(user, host, owner)
    }
    fn authorized_view<'a>(
        &'a self,
        user: &'a str,
        host: &'a str,
        owner: &'a str,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        if self.may_view(user, host, owner) {
            self.0.authorized(operation)
        } else {
            Box::pin(async { Err(()) })
        }
    }
}
struct Record {
    session: Arc<Session>,
    host: Arc<dyn NodeHost>,
    worker: Arc<Worker>,
}
// Keep the join handle in shared state while awaiting it. Cancelling a stop
// or feature switch then leaves the same worker available to the next join.
struct Worker {
    handle: tokio::sync::Mutex<Option<JoinHandle<Result<(), Error>>>>,
    retired: Arc<AtomicBool>,
}
impl Worker {
    fn finished(&self) -> bool {
        self.retired.load(Ordering::Acquire)
            && self
                .handle
                .try_lock()
                .is_ok_and(|handle| handle.as_ref().is_none_or(JoinHandle::is_finished))
    }
    async fn join(&self, host: &dyn NodeHost, id: SessionId) -> Result<(), Error> {
        let mut handle = self.handle.lock().await;
        let result = match handle.as_mut() {
            Some(worker) => worker
                .await
                .map_err(|_| Error::Unavailable)
                .and_then(|result| result),
            // A completed worker can still owe native retirement. Serialize
            // owner retry and disable through this same cancellation-safe lock.
            None if self.retired.load(Ordering::Acquire) => return Ok(()),
            None => stop_source(host, id).await,
        };
        handle.take();
        self.retired.store(result.is_ok(), Ordering::Release);
        result
    }
}
struct State {
    enabled: bool,
    limit: usize,
    records: HashMap<SessionId, Record>,
}
/// Construction has no worker, helper connection, listener or timer.
#[derive(Clone)]
pub struct DesktopServer {
    registry: Arc<Registry>,
    state: Arc<Mutex<State>>,
}
impl DesktopServer {
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            registry: Arc::new(Registry::new(limit)),
            state: Arc::new(Mutex::new(State {
                enabled: false,
                limit,
                records: HashMap::new(),
            })),
        }
    }
    /// Server-generated identities are prepared by an authorized start action; Attach
    /// is solely a lookup and can never cause capture on an unknown identity.
    /// # Errors
    /// Refuses disabled state, host admission, invalid geometry or helper failure.
    pub async fn start(
        &self,
        host: Arc<dyn NodeHost>,
        start: Start,
        mode: Delivery,
    ) -> Result<SessionId, Error> {
        let start_json = serde_json::to_vec(&start).map_err(|_| Error::Invalid)?;
        crate::protocol::validate_command(crate::protocol::Kind::Start, &start_json)
            .map_err(|_| Error::Invalid)?;
        if !host.permits() {
            return Err(Error::Forbidden);
        }
        if !self.state.lock().map_err(|_| Error::Unavailable)?.enabled {
            return Err(Error::Unavailable);
        }
        let id = *uuid::Uuid::new_v4().as_bytes();
        let input =
            serde_json::to_vec(&json!({"session_id":uuid::Uuid::from_bytes(id),"start":start}))
                .map_err(|_| Error::Invalid)?;
        let (session, commands) = Session::new(
            id,
            host.id().to_owned(),
            host.owner_id().to_owned(),
            Arc::new(HostAccessRules(host.clone())),
        );
        let (prepared, result) = tokio::sync::oneshot::channel();
        {
            let mut state = self.state.lock().map_err(|_| Error::Unavailable)?;
            if !state.enabled || !host.permits() {
                return Err(Error::Unavailable);
            }
            state.records.retain(|_, record| !record.worker.finished());
            // Attachment withdrawal is immediate, but native cleanup may still
            // be running. Keep its resource reservation until the worker ends.
            if state.records.len() >= state.limit {
                return Err(Error::Limit);
            }
            self.registry.insert(session.clone())?;
            let worker_session = session.clone();
            let worker_host = host.clone();
            let registry = self.registry.clone();
            let retired = Arc::new(AtomicBool::new(false));
            let retirement = retired.clone();
            let worker = tokio::spawn(async move {
                let mut stopped = worker_session.stopped();
                let preparation = tokio::select! { biased;
                    () = async {
                        // A close can precede this worker's first poll. Watching
                        // only changes would miss that already-published state.
                        if !*stopped.borrow_and_update() {
                            let _ = stopped.changed().await;
                        }
                    } => Err(Error::Unavailable),
                    response = tokio::time::timeout(Duration::from_secs(5), worker_host.call("desktop.source.start", &input)) => {
                        response.map_err(|_| Error::Unavailable).and_then(|value| value.map_err(|()| Error::Unavailable))
                            .and_then(|bytes| validate_prepared(&bytes, id))
                    },
                };
                let ready = preparation.is_ok();
                let _ = prepared.send(preparation);
                let outcome = if ready {
                    capture(worker_session.clone(), worker_host, mode, commands, input).await
                } else {
                    worker_session.close();
                    stop_source(worker_host.as_ref(), id).await
                };
                let _ = registry.remove(&id);
                retirement.store(outcome.is_ok(), Ordering::Release);
                outcome
            });
            state.records.insert(
                id,
                Record {
                    session,
                    host,
                    worker: Arc::new(Worker {
                        handle: tokio::sync::Mutex::new(Some(worker)),
                        retired,
                    }),
                },
            );
        }
        // Cancelled start withdraws its session synchronously. The tracked
        // producer performs native retirement; disable joins the same worker,
        // including a preparation whose acknowledgement never arrives.
        let mut rollback = Preparation {
            registry: self.registry.clone(),
            id,
            armed: true,
        };
        result.await.map_err(|_| Error::Unavailable)??;
        let state = self.state.lock().map_err(|_| Error::Unavailable)?;
        if !state.enabled
            || !state
                .records
                .get(&id)
                .is_some_and(|record| record.host.permits())
        {
            return Err(Error::Unavailable);
        }
        rollback.armed = false;
        Ok(id)
    }
    /// Stop requires the session's immutable owning host and current admission.
    /// # Errors
    /// Refuses unknown sessions, another owner or a failed native retirement.
    pub async fn stop(&self, id: SessionId, user: &str) -> Result<(), Error> {
        let (worker, host) = {
            let state = self.state.lock().map_err(|_| Error::Unavailable)?;
            let record = state.records.get(&id).ok_or(Error::Unavailable)?;
            if record.host.owner_id() != user || !record.host.permits() {
                return Err(Error::Forbidden);
            }
            // Closing is idempotent; concurrent or retried stops join the same
            // tracked worker rather than detaching an in-progress retirement.
            record.session.close();
            let _ = self.registry.remove(&id);
            (record.worker.clone(), record.host.clone())
        };
        worker.join(host.as_ref(), id).await?;
        self.state
            .lock()
            .map_err(|_| Error::Unavailable)?
            .records
            .remove(&id);
        Ok(())
    }
    /// Attach is fail-closed and retains the originating viewer's login lease.
    /// # Errors
    /// Refuses unknown sessions and current view access rule or login failures.
    pub fn attach(
        &self,
        id: &SessionId,
        host: &dyn SocketHost,
    ) -> Result<crate::session::Viewer, Error> {
        self.registry
            .attach_authorized(id, host.user_id().to_owned(), host.authority())
    }
    async fn execute(
        &self,
        host: &dyn SocketHost,
        action: &str,
        input: &[u8],
    ) -> Result<Value, Error> {
        match action {
            "desktop.windows" => {
                let input: HostInput = parse(input)?;
                let node = host.node(&input.host_id).await.ok_or(Error::Forbidden)?;
                let mut inventory: Option<Value> = None;
                let mut cursor: Option<String> = None;
                let mut seen = std::collections::HashSet::new();
                loop {
                    let input = cursor.as_ref().map_or_else(
                        || b"{}".to_vec(),
                        |cursor| serde_json::to_vec(&json!({"cursor":cursor})).unwrap_or_default(),
                    );
                    let bytes = node
                        .call("desktop.source.windows", &input)
                        .await
                        .map_err(|()| Error::Unavailable)?;
                    let mut page: InventoryPage =
                        serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
                    let windows = page
                        .inventory
                        .get_mut("windows")
                        .and_then(Value::as_array_mut)
                        .ok_or(Error::Invalid)?;
                    if let Some(inventory) = inventory.as_mut() {
                        inventory
                            .get_mut("windows")
                            .and_then(Value::as_array_mut)
                            .ok_or(Error::Invalid)?
                            .append(windows);
                    } else {
                        inventory = Some(page.inventory);
                    }
                    if serde_json::to_vec(&inventory)
                        .map_err(|_| Error::Invalid)?
                        .len()
                        > crate::protocol::MAX_CONTROL - 1024
                    {
                        return Err(Error::Limit);
                    }
                    cursor = page.cursor;
                    if let Some(cursor) = &cursor {
                        if !seen.insert(cursor.clone()) || seen.len() > 256 {
                            return Err(Error::Invalid);
                        }
                    } else {
                        return inventory.ok_or(Error::Invalid);
                    }
                }
            }
            "desktop.session.start" => {
                let input: StartInput = parse(input)?;
                let node = host.node(&input.host_id).await.ok_or(Error::Forbidden)?;
                let mode = match input.delivery.as_str() {
                    "reliable" => Delivery::Reliable,
                    "datagram" => Delivery::Datagram,
                    _ => return Err(Error::Invalid),
                };
                let id = self.start(node, input.start, mode).await?;
                Ok(json!({"session_id":uuid::Uuid::from_bytes(id)}))
            }
            "desktop.session.stop" => {
                let input: SessionInput = parse(input)?;
                self.stop(*input.session_id.as_bytes(), host.user_id())
                    .await?;
                Ok(json!({"stopped":true}))
            }
            "desktop.session.status" | "desktop.session.clock" => {
                let input: SessionInput = parse(input)?;
                let node = {
                    let state = self.state.lock().map_err(|_| Error::Unavailable)?;
                    let record = state
                        .records
                        .get(input.session_id.as_bytes())
                        .ok_or(Error::Unavailable)?;
                    if record.host.owner_id() != host.user_id() || !record.host.permits() {
                        return Err(Error::Forbidden);
                    }
                    record.host.clone()
                };
                let input = serde_json::to_vec(&json!({"session_id":input.session_id}))
                    .map_err(|_| Error::Invalid)?;
                let action = if action.ends_with("clock") {
                    "desktop.source.clock"
                } else {
                    "desktop.source.status"
                };
                let bytes = node
                    .call(action, &input)
                    .await
                    .map_err(|()| Error::Unavailable)?;
                serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)
            }
            // Control is bound to this socket's attached viewer, never to an
            // arbitrary UUID. The viewer adapter owns that lease and operation.
            _ => Err(Error::Invalid),
        }
    }
}
impl Plugin for DesktopServer {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    fn configure(&self, enabled: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.enabled = enabled;
            let _ = self.registry.set_enabled(enabled);
        }
    }
    fn stopped(&self) -> Operation<'_, ()> {
        Box::pin(async {
            let workers: Vec<_> = self
                .state
                .lock()
                .map(|state| {
                    state
                        .records
                        .values()
                        .map(|record| {
                            (
                                record.worker.clone(),
                                record.host.clone(),
                                record.session.id(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            for (worker, host, id) in workers {
                let _ = worker.join(host.as_ref(), id).await;
            }
            if let Ok(mut state) = self.state.lock() {
                state.records.retain(|_, record| !record.worker.finished());
            }
        })
    }
    fn run(
        &self,
        host: Arc<dyn SocketHost>,
        mut requests: mpsc::Receiver<Bytes>,
        replies: ReplySender,
        _: SubscriptionRegistry,
    ) -> Operation<'static, ()> {
        let server = self.clone();
        Box::pin(async move {
            let mut viewers: HashMap<u32, ViewerHandle> = HashMap::new();
            let mut workers = JoinSet::new();
            let mut calls = JoinSet::new();
            let mut pending = None;
            // One live login lease owns all active socket tasks. An idle socket
            // holds no watchdog: the next request must enter a fresh scope before
            // dispatch. Packet/input projections retain their authority checks.
            let outcome = loop {
                if viewers.is_empty() && workers.is_empty() && calls.is_empty() {
                    pending = requests.recv().await;
                    if pending.is_none() {
                        break Ok(());
                    }
                }
                let mut idle = false;
                let outcome = host.authorized(Box::pin(async {
                loop {
                    if pending.is_none() && viewers.is_empty() && workers.is_empty() && calls.is_empty() {
                        idle = true;
                        break;
                    }
                    tokio::select! {
                        result = calls.join_next(), if !calls.is_empty() => {
                            if !matches!(result, Some(Ok(Ok(())))) { break; }
                        }
                        ended = workers.join_next_with_id(), if !workers.is_empty() => {
                            // A stream ID can be reused before its prior task finishes.
                            // Only the task that owns the current handle may remove it.
                            if let Some(Ok((task, stream))) = ended
                                && viewers.get(&stream).is_some_and(|viewer| viewer.task == task) { viewers.remove(&stream); }
                        }
                        request = async { match pending.take() { Some(wire) => Some(wire), None => requests.recv().await } } => {
                            let Some(wire) = request else { break; };
                            let Ok(decoded) = decode_muxed_frame(&wire) else { break; };
                            let stream = decoded.stream_id;
                            if stream != 0 {
                                if let Frame::Desktop(Message::Attach { session_id, delivery: Delivery::Reliable }) = decoded.frame {
                                    if viewers.contains_key(&stream) || viewers.len() >= WIRE.max_streams { break; }
                                    match server.attach(session_id, host.as_ref()) {
                                        Ok(viewer) => {
                                            // At most 32 small commands (64 bytes each) buffer one socket
                                            // ingress burst plus independent control, never media/RPC bodies.
                                            let (tx, rx) = mpsc::channel(32);
                                            let (stop, stopped) = watch::channel(false);
                                            let replies = replies.clone();
                                            let task = workers.spawn(async move {
                                                // A late Close belongs to this attachment, just as its video does.
                                                // Keep the reply guarded through the actual socket write.
                                                let completed = replies.with_authority(Arc::new(ViewerCompletion(stopped.clone())));
                                                let _ = viewer_loop(viewer, stream, rx, replies.clone(), stopped).await;
                                                let mut closed = Vec::new();
                                                if encode_muxed_frame_into(stream, &Frame::Close { code: 4404, reason: "viewer ended" }, &mut closed).is_ok() { let _ = tokio::time::timeout(Duration::from_secs(1), completed.send_and_wait(Bytes::from(closed))).await; }
                                                stream
                                            });
                                            viewers.insert(stream, ViewerHandle { task: task.id(), requests: tx, stop });
                                        }
                                        Err(_) => { send_viewer_close(&replies, stream).await; }
                                    }
                                } else if matches!(decoded.frame, Frame::Close { .. }) {
                                    viewers.remove(&stream);
                                } else if let Some(sender) = viewers.get(&stream) {
                                    if matches!(decoded.frame, Frame::Desktop(Message::Input(_))) {
                                        crate::measurement::control("server_input_receive", crate::protocol::Kind::Input);
                                    }
                                    if wire.len() > 64 || !matches!(decoded.frame, Frame::Desktop(Message::Input(_) | Message::Size { .. } | Message::Repair { .. }))
                                        || sender.requests.try_send(ViewerCommand::Wire(wire.clone())).is_err() { viewers.remove(&stream); }
                                } else { send_viewer_close(&replies, stream).await; }
                                continue;
                            }
                            let Frame::Call { action_id, input_json, .. } = decoded.frame else { break; };
                            // Source RPCs may wait on a helper; keep native Input,
                            // Close and independent control handovers outside them.
                            let mut failed = false;
                            while let Some(result) = calls.try_join_next() { failed |= !matches!(result, Ok(Ok(()))); }
                            if failed || calls.len() >= 32 { break; }
                            let controller = if action_id == "desktop.session.control" || action_id == "desktop.session.parameters" {
                                parse::<ViewerInput>(input_json).ok().and_then(|input| viewers.get(&input.stream_id).map(|viewer| viewer.requests.clone()))
                            } else { None };
                            calls.spawn(socket_call(server.clone(), host.clone(), replies.clone(), wire, controller));
                        }
                    }
                }
                Ok(())
                })).await;
                if outcome.is_err() || !idle {
                    break outcome;
                }
            };
            // Fixed states only: diagnostics never contain login, target or input data.
            if std::env::var_os("INFRATERNAL_NATIVE_DIAGNOSTICS").is_some() {
                eprintln!(
                    "desktop_socket_exit authorized={} socket_live={}",
                    outcome.is_ok(),
                    host.authority().permits()
                );
            }
            // Dropping channels releases every viewer and its held input before
            // this socket worker joins; feature retirement aborts the same set.
            viewers.clear();
            calls.abort_all();
            while calls.join_next().await.is_some() {}
            workers.abort_all();
            while workers.join_next().await.is_some() {}
        })
    }
}
// Last owner retires global sessions even if the runtime is dropped without an
// explicit switch. No worker owns State, so this does not form a retention cycle.
impl Drop for State {
    fn drop(&mut self) {
        for (_, record) in self.records.drain() {
            record.session.close();
        }
    }
}
struct Preparation {
    registry: Arc<Registry>,
    id: SessionId,
    armed: bool,
}
impl Drop for Preparation {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.registry.remove(&self.id);
        }
    }
}
async fn stop_source(host: &dyn NodeHost, id: SessionId) -> Result<(), Error> {
    let bytes = serde_json::to_vec(&json!({"session_id":uuid::Uuid::from_bytes(id)}))
        .map_err(|_| Error::Invalid)?;
    tokio::time::timeout(
        Duration::from_secs(5),
        host.call("desktop.source.stop", &bytes),
    )
    .await
    .map_err(|_| Error::Unavailable)?
    .map_err(|()| Error::Unavailable)?;
    Ok(())
}
async fn capture(
    session: Arc<Session>,
    host: Arc<dyn NodeHost>,
    mode: Delivery,
    mut commands: mpsc::Receiver<crate::session::HostCommand>,
    preparation: Vec<u8>,
) -> Result<(), Error> {
    let mut stopped = session.stopped();
    let mut opening = Vec::new();
    encode_frame_into(
        &Frame::Desktop(Message::Attach {
            session_id: &session.id(),
            delivery: mode,
        }),
        &mut opening,
    )
    .map_err(|_| Error::Invalid)?;
    let mut preparation: Value =
        serde_json::from_slice(&preparation).map_err(|_| Error::Invalid)?;
    let mut reconnect = false;
    while !*stopped.borrow() && host.permits() {
        if reconnect {
            let floor = session.sequence_floor()?;
            if floor == u64::MAX {
                break;
            }
            preparation["sequence_floor"] = json!(floor);
            if let Some(size) = session.last_forwarded_size() {
                preparation["start"]["size"] =
                    serde_json::to_value(size).map_err(|_| Error::Invalid)?;
            }
            let preparation = serde_json::to_vec(&preparation).map_err(|_| Error::Invalid)?;
            let ready = tokio::select! { biased;
                _ = stopped.changed() => break,
                response = tokio::time::timeout(Duration::from_secs(5), host.call("desktop.source.start", &preparation)) => response.ok().and_then(Result::ok).is_some_and(|bytes| validate_prepared(&bytes, session.id()).is_ok()),
            };
            if !ready {
                tokio::select! { biased; _ = stopped.changed() => break, () = tokio::time::sleep(Duration::from_millis(200)) => {} }
                continue;
            }
        }
        reconnect = true;
        let lane = tokio::select! { biased;
            _ = stopped.changed() => break,
            lane = host.open(&WIRE, &opening) => lane,
        };
        if let Ok(lane) = lane {
            let _ =
                crate::relay::run(session.clone(), host.clone(), lane, mode, &mut commands).await;
        }
        if *stopped.borrow() || !host.permits() {
            break;
        }
        // Reconnect backoff only exists after an actual failed lane. Idle live
        // sessions have no reconnect timer. Commands are drained by each lease.
        tokio::select! { biased;
            _ = stopped.changed() => break,
            () = tokio::time::sleep(Duration::from_millis(200)) => {},
        }
    }
    session.close();
    stop_source(host.as_ref(), session.id()).await
}
fn parse<T: serde::de::DeserializeOwned>(input: &[u8]) -> Result<T, Error> {
    if input.len() > crate::protocol::MAX_CONTROL
        || input.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{')
    {
        return Err(Error::Invalid);
    }
    serde_json::from_slice(input).map_err(|_| Error::Invalid)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostInput {
    host_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartInput {
    host_id: String,
    start: Start,
    delivery: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionInput {
    session_id: uuid::Uuid,
}

// The socket owns every admitted action task. Cancelling its worker cancels
// preparations and waits through the server-held lifecycle guards.
async fn socket_call(
    server: DesktopServer,
    host: Arc<dyn SocketHost>,
    replies: ReplySender,
    wire: Bytes,
    controller: Option<mpsc::Sender<ViewerCommand>>,
) -> Result<(), ()> {
    let decoded = decode_muxed_frame(&wire).map_err(|_| ())?;
    let Frame::Call {
        call_id,
        action_id,
        input_json,
    } = decoded.frame
    else {
        return Err(());
    };
    let value = if action_id == "desktop.session.parameters" {
        match (parse::<ViewerInput>(input_json), controller) {
            (Ok(input), Some(sender)) if input.parameters.is_some() => {
                let (ack, result) = oneshot::channel();
                if sender
                    .try_send(ViewerCommand::Parameters(
                        input.parameters.unwrap_or_default(),
                        ack,
                    ))
                    .is_ok()
                {
                    match tokio::time::timeout(Duration::from_secs(1), result).await {
                        Ok(Ok(Ok(()))) => {
                            Ok(json!({"stream_id":input.stream_id,"pending_keyframe":true}))
                        }
                        _ => Err(Error::Forbidden),
                    }
                } else {
                    Err(Error::Busy)
                }
            }
            _ => Err(Error::Forbidden),
        }
    } else if action_id == "desktop.session.control" {
        match (parse::<ViewerInput>(input_json), controller) {
            (Ok(input), Some(sender)) => {
                let (ack, result) = oneshot::channel();
                if sender.try_send(ViewerCommand::Control(ack)).is_ok() {
                    match tokio::time::timeout(Duration::from_secs(1), result).await {
                        Ok(Ok(Ok(()))) => {
                            Ok(json!({"controller":true,"stream_id":input.stream_id}))
                        }
                        _ => Err(Error::Forbidden),
                    }
                } else {
                    Err(Error::Busy)
                }
            }
            _ => Err(Error::Forbidden),
        }
    } else {
        server.execute(host.as_ref(), action_id, input_json).await
    };
    let (ok, json) = match value {
        Ok(value) => (true, serde_json::to_vec(&value).map_err(|_| ())?),
        Err(_) => (false, DESCRIPTOR.unavailable.to_vec()),
    };
    let mut encoded = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Result {
            call_id,
            ok,
            json: &json,
        },
        &mut encoded,
    )
    .map_err(|_| ())?;
    tokio::time::timeout(Duration::from_secs(1), replies.send(Bytes::from(encoded)))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}
// Only this socket's attached viewer can acquire control; UUIDs cannot forge a lease.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewerInput {
    stream_id: u32,
    #[serde(default)]
    parameters: Option<crate::parameter_sets::Parameters>,
}
// A control task may retain a sender after Close. Its sender cannot retain
// the viewer lease: every map removal publishes retirement independently.
struct ViewerHandle {
    task: tokio::task::Id,
    requests: mpsc::Sender<ViewerCommand>,
    stop: watch::Sender<bool>,
}
impl Drop for ViewerHandle {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}
// Final Close packets retain attachment retirement independently of the stream ID.
struct ViewerCompletion(watch::Receiver<bool>);
impl infraternal_plugin_api::streams::Authority for ViewerCompletion {
    fn permits(&self) -> bool {
        !*self.0.borrow()
    }
    fn cancelled(&self) -> Operation<'_, ()> {
        let mut stopped = self.0.clone();
        Box::pin(async move {
            if !*stopped.borrow_and_update() {
                let _ = stopped.changed().await;
            }
        })
    }
}
enum ViewerCommand {
    Wire(Bytes),
    Control(oneshot::Sender<Result<(), Error>>),
    Parameters(
        crate::parameter_sets::Parameters,
        oneshot::Sender<Result<(), Error>>,
    ),
}
async fn send_viewer_close(replies: &ReplySender, stream: u32) {
    let mut wire = Vec::new();
    if encode_muxed_frame_into(
        stream,
        &Frame::Close {
            code: 4403,
            reason: "viewer unavailable",
        },
        &mut wire,
    )
    .is_ok()
    {
        let _ = replies.send(Bytes::from(wire)).await;
    }
}
async fn viewer_loop(
    mut viewer: crate::session::Viewer,
    stream: u32,
    mut commands: mpsc::Receiver<ViewerCommand>,
    replies: ReplySender,
    mut stopped: watch::Receiver<bool>,
) -> Result<(), ()> {
    let authority = viewer.delivery_authority();
    let measuring = crate::measurement::enabled();
    let replies = replies.with_authority(authority.clone());
    let mut parameters = crate::parameter_sets::Parameters::default();
    let mut pending_parameters = None;
    let mut delivery: Option<Operation<'static, Result<(), ()>>> = None;
    loop {
        tokio::select! { biased;
            () = async { if !*stopped.borrow_and_update() { let _ = stopped.changed().await; } } => return Ok(()),
            command = commands.recv() => {
                match command {
                    None => return Ok(()),
                    Some(ViewerCommand::Parameters(choice, ack)) => {
                        let result = viewer.request_keyframe();
                        if result.is_ok() { pending_parameters = Some(choice); }
                        let _ = ack.send(result);
                    }
                    Some(ViewerCommand::Control(ack)) => { let _ = ack.send(viewer.take_control()); }
                    Some(ViewerCommand::Wire(wire)) => {
                        let decoded = decode_muxed_frame(&wire).map_err(|_| ())?;
                        match decoded.frame {
                            Frame::Desktop(Message::Input(input)) => tokio::select! { biased;
                                _ = stopped.changed() => return Ok(()),
                                result = viewer.input_wait(input) => result.map_err(|_| ())?,
                            },
                            Frame::Desktop(Message::Size { width, height, density_milli }) => tokio::select! { biased;
                                _ = stopped.changed() => return Ok(()),
                                result = viewer.resize_wait(width, height, density_milli) => result.map_err(|_| ())?,
                            },
                            Frame::Desktop(Message::Repair { .. }) => viewer.request_keyframe().map_err(|_| ())?,
                            _ => return Err(()),
                        }
                    }
                }
            }
            completed = async { if let Some(delivery) = delivery.as_mut() { delivery.await } else { std::future::pending().await } }, if delivery.is_some() => {
                completed?;
                delivery = None;
            }
            frame = viewer.next(), if delivery.is_none() => {
                let frame = frame.map_err(|_| ())?;
                crate::measurement::frame("viewer_dequeue", &frame);
                if frame.keyframe && let Some(choice) = pending_parameters.take() { parameters = choice; }
                let bytes = if frame.keyframe { crate::parameter_sets::select(&frame.bytes, parameters)? } else { frame.bytes.clone() };
                let mut encoded = Vec::new();
                encode_muxed_frame_into(stream, &Frame::Desktop(Message::Video { sequence: frame.sequence, capture_ns: frame.capture_ns, keyframe: frame.keyframe, bytes: &bytes }), &mut encoded).map_err(|_| ())?;
                // A latest-frame watch and one retained packet prevent a slow
                // browser from accumulating a second per-viewer bulk queue.
                let replies = if measuring { replies.with_authority(crate::measurement::delivery(authority.clone(), &frame)) } else { replies.clone() };
                delivery = Some(Box::pin(async move {
                    tokio::time::timeout(Duration::from_secs(1), replies.send_and_wait(Bytes::from(encoded))).await.map_err(|_| ())?
                }));
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryPage {
    inventory: Value,
    cursor: Option<String>,
}
fn validate_prepared(bytes: &[u8], id: SessionId) -> Result<(), Error> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    if value
        .get("session_id")
        .and_then(Value::as_str)
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .is_some_and(|value| *value.as_bytes() == id)
    {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}

#[cfg(test)]
mod viewer_tests {
    use super::*;
    struct Owner;
    impl AccessRules for Owner {
        fn may_view(&self, user: &str, _: &str, owner: &str) -> bool {
            user == owner
        }
        fn may_control(&self, user: &str, _: &str, owner: &str) -> bool {
            user == owner
        }
    }
    #[tokio::test]
    async fn waiting_input_cannot_cross_a_controller_handover() {
        waiting_command_cannot_cross_a_controller_handover(false).await;
    }
    #[tokio::test]
    async fn waiting_resize_cannot_cross_a_controller_handover() {
        waiting_command_cannot_cross_a_controller_handover(true).await;
    }
    async fn waiting_command_cannot_cross_a_controller_handover(resize: bool) {
        use infraternal_protocol::desktop::Input;
        use std::{future::Future, task::Poll};
        let (session, mut commands) =
            Session::new([1; 16], "node".into(), "owner".into(), Arc::new(Owner));
        let first = session.attach("owner".into()).unwrap();
        let second = session.attach("owner".into()).unwrap();
        commands.recv().await.unwrap();
        first.take_control().unwrap();
        commands.recv().await.unwrap();
        for _ in 0..8 {
            if resize {
                first.resize(640, 480, 1000).unwrap();
            } else {
                first
                    .input(Input::Text {
                        scalar: u32::from('a'),
                    })
                    .unwrap();
            }
        }
        let pending = async {
            if resize {
                first.resize_wait(800, 600, 1000).await
            } else {
                first
                    .input_wait(Input::Text {
                        scalar: u32::from('b'),
                    })
                    .await
            }
        };
        tokio::pin!(pending);
        // Poll once against a full real host queue, then change control before
        // the waiting sender can publish its reserved slot. No scheduler sleep.
        std::future::poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        commands.recv().await.unwrap();
        commands.recv().await.unwrap();
        second.take_control().unwrap();
        assert_eq!(pending.await, Err(Error::Forbidden));
        while let Ok(command) = commands.try_recv() {
            assert!(if resize {
                !matches!(
                    command,
                    crate::session::HostCommand::Size { width: 800, .. }
                )
            } else {
                !matches!(command, crate::session::HostCommand::Input { input: Input::Text { scalar }, .. } if scalar == u32::from('b'))
            });
        }
    }
    #[tokio::test]
    async fn pending_bulk_delivery_does_not_hold_viewer_control() {
        let (session, mut host_commands) =
            Session::new([1; 16], "node".into(), "owner".into(), Arc::new(Owner));
        let viewer = session.attach("owner".into()).unwrap();
        host_commands.recv().await.unwrap();
        let (commands, rx) = mpsc::channel(8);
        let (tx, mut replies) = mpsc::channel(4);
        let (_stop, stopped) = watch::channel(false);
        let worker = tokio::spawn(viewer_loop(
            viewer,
            1,
            rx,
            ReplySender::new(tx, "desktop", 1),
            stopped,
        ));
        session
            .publish(crate::session::Video {
                sequence: 1,
                capture_ns: 1,
                keyframe: true,
                bytes: Bytes::from_static(&[7; 100]),
            })
            .unwrap();
        let retained = replies.recv().await.unwrap();
        let (ack, done) = oneshot::channel();
        commands.send(ViewerCommand::Control(ack)).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), done)
                .await
                .is_ok(),
            "bulk retention blocked current viewer control"
        );
        drop(retained);
        drop(commands);
        worker.await.unwrap().unwrap();
    }
}

#[cfg(test)]
mod slow_action_tests {
    use super::*;
    use infraternal_plugin_api::streams::{Authority, WireLane, WireStreamDef};
    struct Owner;
    impl AccessRules for Owner {
        fn may_view(&self, user: &str, _: &str, owner: &str) -> bool {
            user == owner
        }
        fn may_control(&self, user: &str, _: &str, owner: &str) -> bool {
            user == owner
        }
    }
    struct Live;
    impl Authority for Live {
        fn permits(&self) -> bool {
            true
        }
        fn cancelled(&self) -> Operation<'_, ()> {
            Box::pin(std::future::pending())
        }
    }
    struct SlowNode {
        started: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }
    impl NodeHost for SlowNode {
        fn id(&self) -> &'static str {
            "node"
        }
        fn owner_id(&self) -> &'static str {
            "owner"
        }
        fn permits(&self) -> bool {
            true
        }
        fn authorized<'a>(
            &'a self,
            operation: Operation<'a, Result<(), ()>>,
        ) -> Operation<'a, Result<(), ()>> {
            operation
        }
        fn call<'a>(&'a self, _: &'a str, _: &'a [u8]) -> Operation<'a, Result<Vec<u8>, ()>> {
            Box::pin(async move {
                self.started.notify_one();
                self.release.notified().await;
                Ok(br#"{"inventory":{"windows":[]},"cursor":null}"#.to_vec())
            })
        }
        fn open<'a>(
            &'a self,
            _: &'static WireStreamDef,
            _: &'a [u8],
        ) -> Operation<'a, Result<Arc<dyn WireLane>, ()>> {
            Box::pin(async { Err(()) })
        }
    }
    struct Host(Arc<SlowNode>);
    impl SocketHost for Host {
        fn user_id(&self) -> &'static str {
            "owner"
        }
        fn token_hash(&self) -> &'static str {
            "fixture"
        }
        fn authority(&self) -> Arc<dyn Authority> {
            Arc::new(Live)
        }
        fn authorized<'a>(
            &'a self,
            operation: Operation<'a, Result<(), ()>>,
        ) -> Operation<'a, Result<(), ()>> {
            operation
        }
        fn fresh(&self, _: i64) -> Operation<'_, bool> {
            Box::pin(async { true })
        }
        fn live(&self) -> Operation<'_, bool> {
            Box::pin(async { true })
        }
        fn may_configure(&self) -> Operation<'_, bool> {
            Box::pin(async { true })
        }
        fn node<'a>(&'a self, _: &'a str) -> Operation<'a, Option<Arc<dyn NodeHost>>> {
            Box::pin(async move { Some(self.0.clone() as Arc<dyn NodeHost>) })
        }
    }
    struct CountedHost {
        host: Host,
        active: Arc<std::sync::atomic::AtomicUsize>,
        started: Arc<std::sync::atomic::AtomicUsize>,
        cancelled: watch::Receiver<bool>,
        released: Arc<tokio::sync::Notify>,
    }
    impl SocketHost for CountedHost {
        fn user_id(&self) -> &'static str {
            "owner"
        }
        fn token_hash(&self) -> &'static str {
            "fixture"
        }
        fn authority(&self) -> Arc<dyn Authority> {
            Arc::new(Live)
        }
        fn authorized<'a>(
            &'a self,
            operation: Operation<'a, Result<(), ()>>,
        ) -> Operation<'a, Result<(), ()>> {
            Box::pin(async move {
                use std::sync::atomic::Ordering::SeqCst;
                struct Lease<'a>(&'a std::sync::atomic::AtomicUsize, &'a tokio::sync::Notify);
                impl Drop for Lease<'_> {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, SeqCst);
                        self.1.notify_one();
                    }
                }
                self.started.fetch_add(1, SeqCst);
                self.active.fetch_add(1, SeqCst);
                let _lease = Lease(&self.active, &self.released);
                let mut cancelled = self.cancelled.clone();
                tokio::select! {
                    result = operation => result,
                    () = async { if !*cancelled.borrow_and_update() { let _ = cancelled.changed().await; } } => Err(()),
                }
            })
        }
        fn fresh(&self, _: i64) -> Operation<'_, bool> {
            Box::pin(async { true })
        }
        fn live(&self) -> Operation<'_, bool> {
            Box::pin(async { true })
        }
        fn may_configure(&self) -> Operation<'_, bool> {
            Box::pin(async { true })
        }
        fn node<'a>(&'a self, id: &'a str) -> Operation<'a, Option<Arc<dyn NodeHost>>> {
            self.host.node(id)
        }
    }
    fn counted_socket(
        server: &DesktopServer,
        active: &Arc<std::sync::atomic::AtomicUsize>,
        started: &Arc<std::sync::atomic::AtomicUsize>,
        cancelled: &watch::Receiver<bool>,
    ) -> (
        Arc<SlowNode>,
        mpsc::Sender<Bytes>,
        mpsc::Receiver<infraternal_plugin_api::PluginReply>,
        JoinHandle<()>,
    ) {
        let node = Arc::new(SlowNode {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let host = Arc::new(CountedHost {
            host: Host(node.clone()),
            active: active.clone(),
            started: started.clone(),
            cancelled: cancelled.clone(),
            released: Arc::new(tokio::sync::Notify::new()),
        });
        let (sender, requests) = mpsc::channel(16);
        let (replies, receiver) = mpsc::channel(16);
        let worker = tokio::spawn(server.run(
            host,
            requests,
            ReplySender::new(replies, "desktop", 1),
            Arc::new(std::array::from_fn(|_| {
                std::sync::atomic::AtomicU64::new(0)
            })),
        ));
        (node, sender, receiver, worker)
    }
    async fn hold_inventory(sender: &mpsc::Sender<Bytes>) {
        send(
            sender,
            0,
            &Frame::Call {
                call_id: 1,
                action_id: "desktop.windows",
                input_json: br#"{"host_id":"node"}"#,
            },
        )
        .await;
    }
    #[tokio::test]
    async fn completed_inventory_releases_login_watchdog_until_next_request() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let server = DesktopServer::new(1);
        server.configure(true);
        let active = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(tokio::sync::Notify::new());
        let (_cancel, cancelled) = watch::channel(false);
        let node = Arc::new(SlowNode {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let host = Arc::new(CountedHost {
            host: Host(node.clone()),
            active: active.clone(),
            started: started.clone(),
            cancelled,
            released: released.clone(),
        });
        let (sender, requests) = mpsc::channel(16);
        let (replies, mut receiver) = mpsc::channel(16);
        let worker = tokio::spawn(server.run(
            host,
            requests,
            ReplySender::new(replies, "desktop", 1),
            Arc::new(std::array::from_fn(|_| {
                std::sync::atomic::AtomicU64::new(0)
            })),
        ));
        for expected in 1..=2 {
            hold_inventory(&sender).await;
            node.started.notified().await;
            assert_eq!(
                active.load(SeqCst),
                1,
                "pending inventory needs live authority"
            );
            assert_eq!(
                started.load(SeqCst),
                expected,
                "each new idle request needs fresh authority"
            );
            node.release.notify_one();
            let reply = receiver.recv().await.unwrap();
            assert!(matches!(
                decode_muxed_frame(&reply.wire).unwrap().frame,
                Frame::Result { .. }
            ));
            // The lease-drop receipt is a causal barrier, not a scheduler sleep.
            let idle = tokio::time::timeout(Duration::from_secs(1), released.notified()).await;
            assert!(
                idle.is_ok(),
                "completed inventory retained a database watchdog on an idle socket"
            );
            assert_eq!(active.load(SeqCst), 0);
        }
        drop(sender);
        worker.await.unwrap();
    }
    /// Retiring an attachment must not consume the replacement stream identity.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn retiring_viewer_does_not_remove_replacement_on_same_stream() {
        let server = DesktopServer::new(1);
        server.configure(true);
        let (session, mut host_commands) =
            Session::new([146; 16], "node".into(), "owner".into(), Arc::new(Owner));
        server.registry.insert(session).unwrap();
        let node = Arc::new(SlowNode {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let (requests, rx) = mpsc::channel(8);
        let (tx, mut replies) = mpsc::channel(16);
        let reply_sender = ReplySender::new(tx, "desktop", 1);
        let worker = tokio::spawn(server.run(
            Arc::new(Host(node)),
            rx,
            reply_sender.clone(),
            Arc::new(std::array::from_fn(|_| {
                std::sync::atomic::AtomicU64::new(0)
            })),
        ));
        send(
            &requests,
            1,
            &Frame::Desktop(Message::Attach {
                session_id: &[146; 16],
                delivery: Delivery::Reliable,
            }),
        )
        .await;
        assert!(matches!(
            host_commands.recv().await,
            Some(crate::session::HostCommand::Keyframe)
        ));
        // Hold the old task's final reply until a new attachment has control.
        // This forces task completion after replacement without scheduler sleeps.
        for _ in 0..16 {
            reply_sender
                .send(Bytes::from_static(b"held"))
                .await
                .unwrap();
        }
        send(
            &requests,
            1,
            &Frame::Close {
                code: 1000,
                reason: "viewer closed",
            },
        )
        .await;
        send(
            &requests,
            1,
            &Frame::Desktop(Message::Attach {
                session_id: &[146; 16],
                delivery: Delivery::Reliable,
            }),
        )
        .await;
        send(
            &requests,
            0,
            &Frame::Call {
                call_id: 1,
                action_id: "desktop.session.control",
                input_json: br#"{"stream_id":1}"#,
            },
        )
        .await;
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(3), host_commands.recv())
                .await
                .unwrap(),
            Some(crate::session::HostCommand::Control { .. })
        ));
        for _ in 0..16 {
            assert_eq!(replies.recv().await.unwrap().wire.as_ref(), b"held");
        }
        let mut first_control = false;
        let mut old_close = false;
        let mut old_close_allowed = true;
        while !first_control || !old_close {
            let reply = tokio::time::timeout(Duration::from_secs(3), replies.recv())
                .await
                .unwrap()
                .unwrap();
            match decode_muxed_frame(&reply.wire).unwrap().frame {
                Frame::Result { call_id: 1, ok, .. } => {
                    assert!(ok);
                    first_control = true;
                }
                Frame::Close { .. } => {
                    old_close_allowed = reply
                        .authority
                        .as_ref()
                        .is_none_or(|authority| authority.permits());
                    old_close = true;
                }
                _ => panic!("unexpected reply"),
            }
        }
        // The replacement must remain addressable after the prior task exits.
        send(
            &requests,
            0,
            &Frame::Call {
                call_id: 2,
                action_id: "desktop.session.control",
                input_json: br#"{"stream_id":1}"#,
            },
        )
        .await;
        let permitted = loop {
            let reply = tokio::time::timeout(Duration::from_secs(3), replies.recv())
                .await
                .unwrap()
                .unwrap();
            if let Frame::Result { call_id: 2, ok, .. } =
                decode_muxed_frame(&reply.wire).unwrap().frame
            {
                break ok;
            }
        };
        drop(requests);
        worker.await.unwrap();
        server.configure(false);
        server.stopped().await;
        assert!(
            permitted,
            "prior viewer completion removed the replacement attachment"
        );
        assert!(
            !old_close_allowed,
            "prior Close retained authority over the reused stream"
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn parameter_choice_is_socket_local_and_waits_for_repairing_keyframe() {
        use std::sync::atomic::AtomicUsize;
        let server = DesktopServer::new(1);
        server.configure(true);
        let (session, mut host_commands) =
            Session::new([1; 16], "node".into(), "owner".into(), Arc::new(Owner));
        server.registry.insert(session.clone()).unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let (cancel, cancelled) = watch::channel(false);
        let (_, first, mut first_replies, first_worker) =
            counted_socket(&server, &active, &started, &cancelled);
        let (_, second, mut second_replies, second_worker) =
            counted_socket(&server, &active, &started, &cancelled);
        for (sender, stream) in [(&first, 1), (&second, 3)] {
            send(
                sender,
                stream,
                &Frame::Desktop(Message::Attach {
                    session_id: &session.id(),
                    delivery: Delivery::Reliable,
                }),
            )
            .await;
        }
        session
            .publish(crate::session::Video {
                sequence: 1,
                capture_ns: 1,
                keyframe: true,
                bytes: Bytes::from_static(&[7]),
            })
            .unwrap();
        for receiver in [&mut first_replies, &mut second_replies] {
            let reply = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(
                decode_muxed_frame(&reply.wire).unwrap().frame,
                Frame::Desktop(Message::Video { .. })
            ));
            drop(reply);
        }
        // Keep the existing repair request: selecting parameters may coalesce
        // with it while the cached first IDR is being delivered.
        // The same owner's other socket cannot address the first socket's viewer.
        for (sender, receiver, expected) in [
            (&second, &mut second_replies, false),
            (&first, &mut first_replies, true),
        ] {
            send(
                sender,
                0,
                &Frame::Call {
                    call_id: 42,
                    action_id: "desktop.session.parameters",
                    input_json: br#"{"stream_id":1,"parameters":"encoder"}"#,
                },
            )
            .await;
            let reply = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(decode_muxed_frame(&reply.wire).unwrap().frame,Frame::Result {call_id:42,ok,..} if ok==expected)
            );
            drop(reply);
        }
        assert!(matches!(
            host_commands.recv().await,
            Some(crate::session::HostCommand::Keyframe)
        ));
        let original = [0x27, 0x64, 0, 0x2a, 0xff];
        let restricted = [0x27, 0x64, 0, 0x2a, 0xee];
        let mut packet = vec![0, 0, 0, 1];
        packet.extend(restricted);
        packet.extend([0, 0, 0, 1, 6, 5, 21]);
        packet.extend(b"infraternal-sps1");
        packet.extend(original);
        packet.push(0x80);
        let pictures = [0, 0, 0, 1, 0x65, 0xff];
        packet.extend(pictures);
        session
            .publish(crate::session::Video {
                sequence: 2,
                capture_ns: 2,
                keyframe: true,
                bytes: Bytes::from(packet),
            })
            .unwrap();
        for (receiver, sps) in [
            (&mut first_replies, original),
            (&mut second_replies, restricted),
        ] {
            let reply = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
                .await
                .unwrap()
                .unwrap();
            let decoded = decode_muxed_frame(&reply.wire).unwrap();
            let Frame::Desktop(Message::Video { bytes, .. }) = decoded.frame else {
                panic!("expected video")
            };
            let mut expected = vec![0, 0, 0, 1];
            expected.extend(sps);
            expected.extend(pictures);
            assert_eq!(bytes, expected);
            drop(reply);
        }
        cancel.send_replace(true);
        first_worker.await.unwrap();
        second_worker.await.unwrap();
    }
    #[tokio::test]
    async fn fifty_viewers_share_five_socket_login_leases_and_join_on_revoke() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let server = DesktopServer::new(10);
        server.configure(true);
        let mut sessions = Vec::new();
        let mut command_receivers = Vec::new();
        for index in 1..=10 {
            let (session, commands) =
                Session::new([index; 16], "node".into(), "owner".into(), Arc::new(Owner));
            server.registry.insert(session.clone()).unwrap();
            sessions.push(session);
            command_receivers.push(commands);
        }
        let active = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let (cancel, cancelled) = watch::channel(false);
        let mut workers = Vec::new();
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        let mut nodes = Vec::new();
        for _ in 0..5 {
            let (node, sender, receiver, worker) =
                counted_socket(&server, &active, &started, &cancelled);
            workers.push(worker);
            for (index, session) in sessions.iter().enumerate() {
                send(
                    &sender,
                    u32::try_from(index * 2 + 1).unwrap(),
                    &Frame::Desktop(Message::Attach {
                        session_id: &session.id(),
                        delivery: Delivery::Reliable,
                    }),
                )
                .await;
            }
            senders.push(sender);
            receivers.push(receiver);
            nodes.push(node);
        }
        for session in &sessions {
            session
                .publish(crate::session::Video {
                    sequence: 1,
                    capture_ns: 1,
                    keyframe: true,
                    bytes: Bytes::from_static(&[7]),
                })
                .unwrap();
        }
        // A video on all fifty streams proves their long-running workers exist;
        // the count measures authority scopes rather than scheduler timing.
        for receiver in &mut receivers {
            for _ in 0..10 {
                let reply = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert!(matches!(
                    decode_muxed_frame(&reply.wire).unwrap().frame,
                    Frame::Desktop(Message::Video { .. })
                ));
            }
        }
        assert_eq!(
            active.load(SeqCst),
            5,
            "one long login lease per socket, independent of viewer count"
        );
        assert_eq!(started.load(SeqCst), 5);
        // Hold a node RPC inside each owned action set while the socket is revoked.
        for sender in &senders {
            hold_inventory(sender).await;
        }
        for node in nodes {
            tokio::time::timeout(Duration::from_secs(1), node.started.notified())
                .await
                .unwrap();
        }
        assert_eq!(
            active.load(SeqCst),
            5,
            "pending actions share the socket lease"
        );
        assert_eq!(started.load(SeqCst), 5);
        cancel.send_replace(true);
        for worker in workers {
            tokio::time::timeout(Duration::from_secs(1), worker)
                .await
                .unwrap()
                .unwrap();
        }
        assert_eq!(active.load(SeqCst), 0);
        // Every old viewer was joined and dropped: all five slots are available.
        for session in sessions {
            let viewers: Vec<_> = (0..5)
                .map(|_| session.attach("owner".into()).unwrap())
                .collect();
            drop(viewers);
        }
        drop(command_receivers);
    }
    async fn send(sender: &mpsc::Sender<Bytes>, stream: u32, frame: &Frame<'_>) {
        let mut wire = Vec::new();
        encode_muxed_frame_into(stream, frame, &mut wire).unwrap();
        sender.send(Bytes::from(wire)).await.unwrap();
    }
    #[tokio::test]
    async fn delayed_inventory_cannot_hold_viewer_close_and_input_release() {
        let server = DesktopServer::new(10);
        server.configure(true);
        let (session, mut host_commands) =
            Session::new([3; 16], "node".into(), "owner".into(), Arc::new(Owner));
        server.registry.insert(session).unwrap();
        let node = Arc::new(SlowNode {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let (requests, rx) = mpsc::channel(4);
        let (tx, mut replies) = mpsc::channel(4);
        let worker = tokio::spawn(server.run(
            Arc::new(Host(node.clone())),
            rx,
            ReplySender::new(tx, "desktop", 1),
            Arc::new(std::array::from_fn(|_| {
                std::sync::atomic::AtomicU64::new(0)
            })),
        ));
        send(
            &requests,
            1,
            &Frame::Desktop(Message::Attach {
                session_id: &[3; 16],
                delivery: Delivery::Reliable,
            }),
        )
        .await;
        host_commands.recv().await.unwrap();
        send(
            &requests,
            0,
            &Frame::Call {
                call_id: 1,
                action_id: "desktop.session.control",
                input_json: br#"{"stream_id":1}"#,
            },
        )
        .await;
        let control = replies.recv().await.unwrap();
        assert!(matches!(
            decode_muxed_frame(&control.wire).unwrap().frame,
            Frame::Result { ok: true, .. }
        ));
        host_commands.recv().await.unwrap();
        send(
            &requests,
            0,
            &Frame::Call {
                call_id: 2,
                action_id: "desktop.windows",
                input_json: br#"{"host_id":"node"}"#,
            },
        )
        .await;
        node.started.notified().await;
        send(
            &requests,
            1,
            &Frame::Close {
                code: 1000,
                reason: "viewer closed",
            },
        )
        .await;
        let released = tokio::time::timeout(Duration::from_millis(100), host_commands.recv()).await;
        node.release.notify_one();
        drop(requests);
        worker.await.unwrap();
        assert!(
            matches!(
                released,
                Ok(Some(crate::session::HostCommand::ReleaseInput))
            ),
            "remote inventory blocked viewer retirement and held-input release"
        );
    }

    /// A finite browser text burst can arrive in one socket read. It must keep
    /// the existing attachment usable after bounded command forwarding [D208].
    #[tokio::test]
    async fn finite_text_burst_preserves_viewer_control() {
        finite_burst_preserves_viewer_control(false).await;
    }

    #[tokio::test]
    async fn finite_resize_burst_preserves_viewer_control() {
        finite_burst_preserves_viewer_control(true).await;
    }

    fn burst_message(resize: bool, index: usize, scalar: char) -> Message<'static> {
        if resize {
            Message::Size {
                width: 640 + 2 * u16::try_from(index).unwrap(),
                height: 480,
                density_milli: 1000,
            }
        } else {
            Message::Input(infraternal_protocol::desktop::Input::Text {
                scalar: u32::from(scalar),
            })
        }
    }

    async fn finite_burst_preserves_viewer_control(resize: bool) {
        let server = DesktopServer::new(1);
        server.configure(true);
        let (session, mut host_commands) =
            Session::new([146; 16], "node".into(), "owner".into(), Arc::new(Owner));
        server.registry.insert(session).unwrap();
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (_cancel, cancelled) = watch::channel(false);
        let (_, requests, mut replies, worker) =
            counted_socket(&server, &active, &started, &cancelled);
        send(
            &requests,
            1,
            &Frame::Desktop(Message::Attach {
                session_id: &[146; 16],
                delivery: Delivery::Reliable,
            }),
        )
        .await;
        host_commands.recv().await.unwrap();
        send(
            &requests,
            0,
            &Frame::Call {
                call_id: 1,
                action_id: "desktop.session.control",
                input_json: br#"{"stream_id":1}"#,
            },
        )
        .await;
        let acquired = replies.recv().await.unwrap();
        assert!(matches!(
            decode_muxed_frame(&acquired.wire).unwrap().frame,
            Frame::Result { ok: true, .. }
        ));
        drop(acquired);
        host_commands.recv().await.unwrap();
        // Drain the real host queue independently. The burst fits the socket's
        // finite ingress queue, without sleeps or any artificial CPU load.
        let drain = tokio::spawn(async move {
            let mut forwarded = 0;
            while let Some(command) = host_commands.recv().await {
                forwarded += usize::from(if resize {
                    matches!(command, crate::session::HostCommand::Size { .. })
                } else {
                    matches!(
                        command,
                        crate::session::HostCommand::Input {
                            input: infraternal_protocol::desktop::Input::Text { .. },
                            ..
                        }
                    )
                });
            }
            forwarded
        });
        // Sixteen scalars fit the existing ingress queue exactly. Populate it
        // before yielding, matching a coalesced browser/socket delivery.
        for (index, scalar) in "ordinary text 🐈!".chars().enumerate() {
            let mut wire = Vec::new();
            encode_muxed_frame_into(
                1,
                &Frame::Desktop(burst_message(resize, index, scalar)),
                &mut wire,
            )
            .unwrap();
            requests.try_send(Bytes::from(wire)).unwrap();
        }
        send(
            &requests,
            0,
            &Frame::Call {
                call_id: 2,
                action_id: "desktop.session.control",
                input_json: br#"{"stream_id":1}"#,
            },
        )
        .await;
        let retained = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let reply = replies.recv().await.unwrap();
                if let Frame::Result { call_id: 2, ok, .. } =
                    decode_muxed_frame(&reply.wire).unwrap().frame
                {
                    break ok;
                }
            }
        })
        .await;
        drop(requests);
        worker.await.unwrap();
        server.configure(false);
        drop(server);
        let forwarded = drain.await.unwrap();
        assert!(
            matches!(retained, Ok(true)),
            "finite burst retired its viewer (resize={resize}, forwarded={forwarded})"
        );
        assert_eq!(forwarded, "ordinary text 🐈!".chars().count());
    }
}
