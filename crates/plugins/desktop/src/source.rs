//! Prepared UUIDs own desktop metadata while each admitted native leg owns one private helper and joined worker [D198,D203,D232].
//!
//! [`SourceBridge`] is the plugin the infraternal agent runs on a host that has
//! windows to share. The server first "prepares" a session: the bridge records
//! the target, size and a video sequence counter under the session's UUID, and
//! starts nothing. Only when the server then opens a data lane for that UUID
//! does the bridge start one private helper process and one worker task, which
//! pump video out and input in until the lane ends, the session is stopped, or
//! the plugin is switched off.
//!
//! It also answers one-off questions (window inventory, status, clock) by
//! starting a short-lived helper, and pages large inventories with
//! [`crate::source_inventory`]. Switching off, or stopping a session, waits for
//! the helper to be fully retired before reporting success; a failed cleanup
//! blocks re-enabling until it is joined again.
//!
//! Executable and runtime paths come from trusted node setup, never from action
//! bodies.
use crate::{
    protocol::{Kind, Start},
    source_inventory::Snapshot,
    source_ipc::{Config, Helper},
    source_manifest::DESCRIPTOR,
    source_request::{self, SourceRequest},
    wire::WIRE,
};
use bytes::Bytes;
use infraternal_plugin_api::{
    ActionReply, AgentPlugin, ComponentPlugin, MAX_ACTION_BYTES, Operation, PluginDescriptor,
    PluginError, PluginOperation, PluginState, PluginStatus,
    streams::{WireLane, WireProvider, WireStreamDef},
};
use infraternal_protocol::{
    Frame, decode_frame,
    desktop::{Delivery, Message},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
};
use uuid::Uuid;

/// What a prepared session remembers; it outlives any one helper or lane.
pub(super) struct Metadata {
    /// What is captured and the current output size (changes as the viewer resizes).
    pub start: Mutex<Start>,
    /// Last video sequence number used. Shared with the worker so a later lane
    /// carries on counting instead of repeating numbers.
    pub sequence: AtomicU64,
}
/// A session that has been prepared by the server.
struct Prepared {
    metadata: Arc<Metadata>,
    /// The worker of the current or latest lane, if a lane was ever served.
    worker: Option<Arc<Worker>>,
    /// Set once a stop or switch-off began; the record accepts no new lane and
    /// is removed when cleanup is confirmed.
    stopping: bool,
}
/// Everything behind the bridge's state lock (never held across an `await`).
struct State {
    enabled: bool,
    /// Transport capabilities negotiated with the server; `None` until known.
    native_caps: Option<u64>,
    /// Maximum prepared sessions.
    limit: usize,
    prepared: HashMap<Uuid, Prepared>,
    /// Worker of the latest short-lived inventory/status helper.
    inventory: Option<Arc<Worker>>,
    /// The window inventory currently being paged through.
    snapshot: Option<Snapshot>,
}
/// Shared innards of [`SourceBridge`].
struct Inner {
    config: Config,
    state: Mutex<State>,
    /// Serializes enable/disable so two switches cannot interleave their cleanup.
    lifecycle: tokio::sync::Mutex<()>,
}
/// Construction and enable allocate metadata only. Executable/runtime paths
/// come from trusted node setup and are never taken from remote action bodies.
#[derive(Clone)]
pub struct SourceBridge(Arc<Inner>);
/// A request sent to a running worker's helper from outside, such as a status or
/// clock query.
pub(super) struct Control {
    pub kind: Kind,
    /// Where to send the helper's answer, if the caller wants one.
    pub reply: Option<oneshot::Sender<Result<Value, PluginError>>>,
}
/// A spawned task that owns one helper process, with handles to cancel and join it.
pub(super) struct Worker {
    /// Set to true to ask the task to wind down.
    stop: watch::Sender<bool>,
    /// The data lane, held so cancelling can retire it at once.
    lane: Mutex<Option<Arc<dyn WireLane>>>,
    /// Channel for [`Control`] requests; `None` for inventory helpers.
    pub control: Option<mpsc::Sender<Control>>,
    join: tokio::sync::Mutex<Job>,
}
/// How a worker ended: the answer, and separately whether its helper was retired.
// A rejected operation is distinct from a failed native retirement. Off/stop
// still succeed after a denied request whose helper was never started.
#[derive(Clone)]
pub(super) struct Outcome {
    /// What the operation produced.
    pub output: Result<Value, PluginError>,
    /// Whether the helper was confirmed retired. Failure here is a fence: it
    /// must be joined successfully before the source is used again.
    pub cleanup: Result<(), PluginError>,
}
impl Outcome {
    /// A rejected operation whose helper cleanup result is `cleanup`.
    pub fn failed(cleanup: Result<(), PluginError>) -> Self {
        Self {
            output: Err(PluginError::Rejected),
            cleanup,
        }
    }
}
/// The task handle and, once joined, its remembered result, so any number of
/// callers can ask for the outcome.
struct Job {
    handle: Option<JoinHandle<Outcome>>,
    result: Option<Outcome>,
}
impl Worker {
    /// Wraps a spawned task with its cancel handle, lane and control channel.
    fn new(
        stop: watch::Sender<bool>,
        lane: Option<Arc<dyn WireLane>>,
        control: Option<mpsc::Sender<Control>>,
        handle: JoinHandle<Outcome>,
    ) -> Arc<Self> {
        Arc::new(Self {
            stop,
            lane: Mutex::new(lane),
            control,
            join: tokio::sync::Mutex::new(Job {
                handle: Some(handle),
                result: None,
            }),
        })
    }
    /// Asks the task to stop and retires its lane. Does not wait; use
    /// [`Worker::retire`] for that. Safe to call repeatedly.
    fn cancel(&self) {
        self.stop.send_replace(true);
        if let Ok(mut lane) = self.lane.lock()
            && let Some(lane) = lane.take()
        {
            lane.retire();
        }
    }
    /// True if the task has ended (or is being joined by someone else right now,
    /// in which case this returns false). Never blocks.
    fn finished(&self) -> bool {
        self.join
            .try_lock()
            .is_ok_and(|job| job.handle.as_ref().is_none_or(JoinHandle::is_finished))
    }
    /// Waits for the task to end and returns its outcome. The first caller does
    /// the join; later callers get the same remembered result.
    async fn outcome(&self) -> Outcome {
        let mut job = self.join.lock().await;
        if let Some(handle) = job.handle.as_mut() {
            job.result = Some(
                handle
                    .await
                    .unwrap_or_else(|_| Outcome::failed(Err(PluginError::Rejected))),
            );
            job.handle.take();
            // Retained metadata must not retain a retired native channel/parser.
            self.cancel();
        }
        job.result.clone().unwrap_or(Outcome {
            output: Ok(Value::Null),
            cleanup: Ok(()),
        })
    }
    /// Waits for the task and returns its output, but only if cleanup succeeded.
    async fn join(&self) -> Result<Value, PluginError> {
        let outcome = self.outcome().await;
        outcome.cleanup?;
        outcome.output
    }
    /// Waits for the task and returns only whether its helper was retired.
    async fn retire(&self) -> Result<(), PluginError> {
        self.outcome().await.cleanup
    }
}
/// Retires the lane when dropped, so a lane is never left open if the serving
/// future is dropped or returns early.
struct WireLease(Arc<dyn WireLane>);
impl Drop for WireLease {
    fn drop(&mut self) {
        self.0.retire();
    }
}
/// Cancels the worker when dropped. Held while awaiting it so that a cancelled
/// caller does not leave the helper running.
struct Wait(Arc<Worker>);
impl Drop for Wait {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
impl SourceBridge {
    /// Creates a disabled bridge. `runtime` is the base directory for helper
    /// sockets, `executable` is the helper binary, and `limit` caps prepared
    /// sessions (never more than the lane definition's maximum streams).
    #[must_use]
    pub fn new(runtime: PathBuf, executable: PathBuf, limit: usize) -> Self {
        Self(Arc::new(Inner {
            config: Config {
                runtime,
                executable,
            },
            lifecycle: tokio::sync::Mutex::new(()),
            state: Mutex::new(State {
                enabled: false,
                native_caps: None,
                limit: limit.min(WIRE.max_streams),
                prepared: HashMap::new(),
                inventory: None,
                snapshot: None,
            }),
        }))
    }
    /// Registers session `id` for `start` and returns its current size and
    /// sequence as JSON. Starts no helper.
    ///
    /// # Errors
    /// Refuses disabled/bounded admission or a reused UUID with a foreign target.
    /// Re-preparation retains the current resized geometry and sequence.
    pub fn prepare(&self, id: Uuid, start: Start) -> Result<Value, PluginError> {
        self.prepare_with_floor(id, start, 0)
    }
    /// Like [`SourceBridge::prepare`], but also makes sure the sequence counter is at
    /// least `sequence_floor`.
    ///
    /// Resume after a node process restart above the server's retained sequence.
    /// Known metadata keeps its current geometry and any higher local counter.
    /// # Errors
    /// Refuses ordinary preparation failures or a floor with no next sequence.
    pub fn prepare_with_floor(
        &self,
        id: Uuid,
        start: Start,
        sequence_floor: u64,
    ) -> Result<Value, PluginError> {
        start.validate().map_err(|_| PluginError::Rejected)?;
        if id.is_nil() || sequence_floor == u64::MAX {
            return Err(PluginError::Rejected);
        }
        let mut state = self.0.state.lock().map_err(|_| PluginError::Rejected)?;
        if !state.enabled {
            return Err(PluginError::Rejected);
        }
        if let Some(prepared) = state.prepared.get(&id) {
            if prepared.stopping
                || prepared
                    .metadata
                    .start
                    .lock()
                    .map_err(|_| PluginError::Rejected)?
                    .target
                    != start.target
            {
                return Err(PluginError::Rejected);
            }
        } else {
            if state
                .native_caps
                .is_some_and(|caps| caps & WIRE.capability == 0)
            {
                return Err(PluginError::Rejected);
            }
            if state.prepared.len() >= state.limit {
                return Err(PluginError::Rejected);
            }
            state.prepared.insert(
                id,
                Prepared {
                    metadata: Arc::new(Metadata {
                        start: Mutex::new(start),
                        sequence: AtomicU64::new(sequence_floor),
                    }),
                    worker: None,
                    stopping: false,
                },
            );
        }
        let prepared = state.prepared.get(&id).ok_or(PluginError::Rejected)?;
        // An active helper may advance concurrently; raising the floor must
        // never overwrite that newer counter or replay an older sequence.
        prepared
            .metadata
            .sequence
            .fetch_max(sequence_floor, Ordering::AcqRel);
        Ok(
            json!({"session_id":id,"size":prepared.metadata.start.lock().map_err(|_| PluginError::Rejected)?.size,"sequence":prepared.metadata.sequence.load(Ordering::Acquire)}),
        )
    }
    /// Ends session `id`: cancels its worker, waits until the helper is retired,
    /// then forgets the session.
    ///
    /// # Errors
    /// Reports joined helper retirement failure; unknown stops are idempotent.
    pub async fn stop(&self, id: Uuid) -> Result<(), PluginError> {
        let (metadata, worker) = {
            let mut state = self.0.state.lock().map_err(|_| PluginError::Rejected)?;
            state.snapshot = None;
            let Some(prepared) = state.prepared.get_mut(&id) else {
                return Ok(());
            };
            prepared.stopping = true;
            if let Some(worker) = &prepared.worker {
                worker.cancel();
            }
            (prepared.metadata.clone(), prepared.worker.clone())
        };
        if let Some(worker) = worker {
            worker.retire().await?;
        }
        let mut state = self.0.state.lock().map_err(|_| PluginError::Rejected)?;
        // Duplicate stop callers may finish after another caller has removed
        // the old record and trusted preparation has reused the UUID.
        if state
            .prepared
            .get(&id)
            .is_some_and(|record| Arc::ptr_eq(&record.metadata, &metadata))
        {
            state.prepared.remove(&id);
        }
        Ok(())
    }
    /// Status JSON: enabled flag and counts, plus the size and sequence of
    /// session `id` when given (an error if that session is unknown).
    fn status_value(&self, id: Option<Uuid>) -> Result<Value, PluginError> {
        let state = self.0.state.lock().map_err(|_| PluginError::Rejected)?;
        let active = state
            .prepared
            .values()
            .filter(|record| {
                record
                    .worker
                    .as_ref()
                    .is_some_and(|worker| !worker.finished())
            })
            .count();
        let mut value = json!({"enabled":state.enabled,"prepared_count":state.prepared.len(),"active_work":active});
        if let Some(id) = id {
            let record = state.prepared.get(&id).ok_or(PluginError::Rejected)?;
            value["session_id"] = json!(id);
            value["size"] = json!(
                record
                    .metadata
                    .start
                    .lock()
                    .map_err(|_| PluginError::Rejected)?
                    .size
            );
            value["sequence"] = json!(record.metadata.sequence.load(Ordering::Acquire));
        }
        Ok(value)
    }
    /// Starts a short-lived helper, sends it one command of `kind` (list or
    /// status), returns its JSON answer, and retires the helper.
    ///
    /// One send-and-reply budget of 3 seconds covers everything. Only one such
    /// helper may run at a time; a second request is refused.
    async fn idle_request(&self, kind: Kind) -> Result<Value, PluginError> {
        let worker = {
            let mut state = self.0.state.lock().map_err(|_| PluginError::Rejected)?;
            if !state.enabled
                || state
                    .inventory
                    .as_ref()
                    .is_some_and(|worker| !worker.finished())
            {
                return Err(PluginError::Rejected);
            }
            let (stop, mut cancelled) = watch::channel(false);
            let config = self.0.config.clone();
            let task = tokio::spawn(async move {
                if *cancelled.borrow() {
                    return Outcome::failed(Ok(()));
                }
                let mut helper = match Helper::start(&config, &mut cancelled).await {
                    Ok(helper) => helper,
                    Err(error) => return Outcome::failed(error.cleanup()),
                };
                let result = tokio::select! { biased;
                    _ = cancelled.changed() => Err(PluginError::Rejected),
                    // A solicited response has one send+reply budget, including
                    // silence before the first byte. Idle capture receives keep
                    // their existing partial-frame-only deadline.
                    result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                        helper.send(kind, b"{}").await?;
                        let (reply, body) = helper.receive().await?;
                        if reply == Kind::Error { return Err(std::io::ErrorKind::PermissionDenied.into()); }
                        serde_json::from_slice(&body).map_err(std::io::Error::other)
                    }) => result.map_err(|_| PluginError::Rejected).and_then(|result| result.map_err(|_| PluginError::Rejected)),
                };
                let cleanup = helper.stop().await.map_err(|_| PluginError::Rejected);
                Outcome {
                    output: result,
                    cleanup,
                }
            });
            let worker = Worker::new(stop, None, None, task);
            state.inventory = Some(worker.clone());
            worker
        };
        let wait = Wait(worker);
        wait.0.join().await
    }
    /// Returns one page of the window inventory. Without a cursor it takes a
    /// fresh inventory from a helper and returns its first page; with a cursor it
    /// returns the next page of the current snapshot, if the cursor is valid.
    async fn windows(&self, cursor: Option<String>) -> Result<Value, PluginError> {
        if let Some(cursor) = cursor {
            let mut state = self.0.state.lock().map_err(|_| PluginError::Rejected)?;
            if !state.enabled {
                return Err(PluginError::Rejected);
            }
            let snapshot = state.snapshot.as_mut().ok_or(PluginError::Rejected)?;
            if !snapshot.accepts(&cursor) {
                return Err(PluginError::Rejected);
            }
            return snapshot.page();
        }
        let inventory = self.idle_request(Kind::List).await?;
        let mut state = self.0.state.lock().map_err(|_| PluginError::Rejected)?;
        if !state.enabled {
            return Err(PluginError::Rejected);
        }
        let mut snapshot = Snapshot::new(inventory)?;
        let page = snapshot.page()?;
        state.snapshot = Some(snapshot);
        Ok(page)
    }
    /// Reads the capture clock. Asks the running worker of session `id` (or any
    /// running one when no id is given); if none is running, asks a short-lived
    /// helper instead.
    async fn clock(&self, id: Option<Uuid>) -> Result<Value, PluginError> {
        let sender = {
            let state = self.0.state.lock().map_err(|_| PluginError::Rejected)?;
            if !state.enabled {
                return Err(PluginError::Rejected);
            }
            let sender_for = |record: &Prepared| {
                record
                    .worker
                    .as_ref()
                    .filter(|worker| !record.stopping && !worker.finished())
                    .and_then(|worker| {
                        worker
                            .control
                            .clone()
                            .map(|sender| (worker.clone(), sender))
                    })
            };
            match id {
                Some(id) => Some(
                    state
                        .prepared
                        .get(&id)
                        .and_then(sender_for)
                        .ok_or(PluginError::Rejected)?,
                ),
                None => state.prepared.values().find_map(sender_for),
            }
        };
        let Some((worker, sender)) = sender else {
            return self.idle_request(Kind::Status).await;
        };
        let (reply, result) = oneshot::channel();
        sender
            .send(Control {
                kind: Kind::Status,
                reply: Some(reply),
            })
            .await
            .map_err(|_| PluginError::Rejected)?;
        if let Ok(reply) = result.await {
            reply
        } else {
            // A closed reply means the pump is retiring. Report failure only
            // after native cleanup joins, so callers cannot outlive the helper.
            worker.retire().await?;
            Err(PluginError::Rejected)
        }
    }
    /// Decodes and runs one `desktop.*` source action, returning its JSON result.
    async fn execute(&self, action: &str, input: &[u8]) -> Result<Value, PluginError> {
        match source_request::decode(action, input)? {
            SourceRequest::Enabled(enabled) => {
                self.set_enabled(enabled)
                    .await
                    .map_err(|_| PluginError::Rejected)?;
                self.status_value(None)
            }
            SourceRequest::Status(id) => self.status_value(id),
            SourceRequest::Start {
                session_id,
                start,
                sequence_floor,
            } => self.prepare_with_floor(session_id, start, sequence_floor),
            SourceRequest::Stop(id) => {
                self.stop(id).await?;
                Ok(json!({"session_id":id,"stopped":true}))
            }
            SourceRequest::Windows(cursor) => self.windows(cursor).await,
            SourceRequest::Clock(id) => self.clock(id).await,
        }
    }
    /// Before a new lane for session `id`: fails if the previous worker is still
    /// running, and otherwise joins it so its helper is known to be retired.
    async fn retire_previous(&self, id: Uuid) -> Result<(), ()> {
        let previous = self
            .0
            .state
            .lock()
            .map_err(|_| ())?
            .prepared
            .get(&id)
            .ok_or(())?
            .worker
            .clone();
        if previous.as_ref().is_some_and(|worker| !worker.finished()) {
            return Err(());
        }
        // Completion alone does not prove the owned process group retired.
        // Preserve a failed cleanup as an admission fence until joined stop/off.
        if let Some(previous) = previous {
            previous.retire().await.map_err(|_| ())?;
        }
        Ok(())
    }
    /// Serves one data lane: checks the lane and its opening `Attach` packet,
    /// then starts a worker for the prepared session and waits for it to end.
    ///
    /// The lane is retired and an error returned for a wrong stream definition,
    /// a malformed or trailing-bytes opening, a datagram request on a lane
    /// without datagrams, an unknown or stopping session, a disabled bridge, or a
    /// session whose previous worker is still running.
    async fn serve_leg(
        &self,
        definition: &'static WireStreamDef,
        opening: Bytes,
        lane: Arc<dyn WireLane>,
    ) -> Result<(), ()> {
        definition.validate().map_err(|_| ())?;
        if definition.capability != WIRE.capability {
            lane.retire();
            return Err(());
        }
        let decoded = decode_frame(&opening).map_err(|_| ())?;
        if decoded.wire_len != opening.len() {
            lane.retire();
            return Err(());
        }
        let Frame::Desktop(Message::Attach {
            session_id,
            delivery,
        }) = decoded.frame
        else {
            lane.retire();
            return Err(());
        };
        if delivery == Delivery::Datagram && lane.datagrams().is_none() {
            lane.retire();
            return Err(());
        }
        let id = Uuid::from_bytes(*session_id);
        self.retire_previous(id).await?;
        let worker = {
            let mut state = self.0.state.lock().map_err(|_| ())?;
            if !state.enabled
                || state
                    .native_caps
                    .is_some_and(|caps| caps & WIRE.capability == 0)
            {
                lane.retire();
                return Err(());
            }
            let record = state.prepared.get_mut(&id).ok_or(())?;
            if record.stopping
                || record
                    .worker
                    .as_ref()
                    .is_some_and(|worker| !worker.finished())
            {
                lane.retire();
                return Err(());
            }
            let (stop, cancelled) = watch::channel(false);
            let (commands, requests) = mpsc::channel(4);
            let config = self.0.config.clone();
            let metadata = record.metadata.clone();
            let owned_lane = lane.clone();
            let repair = commands.clone();
            let task = tokio::spawn(async move {
                crate::source_worker::run(
                    config,
                    crate::source_worker::Leg {
                        id,
                        metadata,
                        lane: owned_lane,
                        delivery,
                        cancelled,
                        requests,
                        repair,
                    },
                )
                .await
            });
            let worker = Worker::new(stop, Some(lane), Some(commands), task);
            record.worker = Some(worker.clone());
            worker
        };
        let wait = Wait(worker);
        wait.0.join().await.map(|_| ()).map_err(|_| ())
    }
}
impl AgentPlugin for SourceBridge {
    /// Records what the connection to the server supports. If desktop lanes are
    /// not supported, running workers are cancelled but prepared sessions are kept.
    fn transport_capabilities(&mut self, capabilities: u64) {
        if let Ok(mut state) = self.0.state.lock() {
            state.native_caps = Some(capabilities);
            if capabilities & WIRE.capability == 0 {
                // Losing the leg withdraws its workers, not their prepared UUIDs.
                for record in state.prepared.values() {
                    if let Some(worker) = &record.worker {
                        worker.cancel();
                    }
                }
            }
        }
    }
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    /// Always refused: every action here may wait on a helper, so they are all
    /// served by `call_async`.
    fn call(&mut self, _: &str, _: &[u8]) -> Result<Vec<u8>, PluginError> {
        Err(PluginError::Rejected)
    }
    /// Runs a source action. Returns `None` for actions this plugin does not
    /// declare. A reply over the action size limit is an error.
    fn call_async(
        &mut self,
        action: &str,
        input: &[u8],
    ) -> Option<Operation<'static, Result<ActionReply, PluginError>>> {
        if !DESCRIPTOR
            .actions
            .iter()
            .any(|definition| definition.id == action)
        {
            return None;
        }
        let bridge = self.clone();
        let action = action.to_owned();
        let input = input.to_vec();
        Some(Box::pin(async move {
            let value = bridge.execute(&action, &input).await?;
            let json = serde_json::to_vec(&value).map_err(|_| PluginError::Rejected)?;
            if json.len() > MAX_ACTION_BYTES {
                return Err(PluginError::MessageTooLarge);
            }
            Ok(ActionReply {
                json,
                after_write: None,
            })
        }))
    }
    fn wire_provider(&self) -> Option<Arc<dyn WireProvider>> {
        Some(Arc::new(self.clone()))
    }
}
impl WireProvider for SourceBridge {
    /// Serves a lane the server opened; see `serve_leg`. The lane is retired
    /// when this future ends or is dropped.
    fn serve(
        &self,
        definition: &'static WireStreamDef,
        opening: Bytes,
        lane: Arc<dyn WireLane>,
    ) -> Operation<'static, Result<(), ()>> {
        let bridge = self.clone();
        let lease = WireLease(lane);
        Box::pin(async move { bridge.serve_leg(definition, opening, lease.0.clone()).await })
    }
}
impl ComponentPlugin for SourceBridge {
    /// The static description of the source plugin.
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    /// `On` when enabled; when disabled, `Stopping` while workers are still
    /// ending and `Off` once none remain. `active_work` counts running workers.
    fn status(&self) -> PluginStatus {
        let Ok(state) = self.0.state.lock() else {
            return PluginStatus {
                state: PluginState::Stopping,
                active_work: 0,
            };
        };
        let active_work = state
            .prepared
            .values()
            .filter(|record| {
                record
                    .worker
                    .as_ref()
                    .is_some_and(|worker| !worker.finished())
            })
            .count()
            + usize::from(
                state
                    .inventory
                    .as_ref()
                    .is_some_and(|worker| !worker.finished()),
            );
        PluginStatus {
            state: if state.enabled {
                PluginState::On
            } else if active_work == 0 {
                PluginState::Off
            } else {
                PluginState::Stopping
            },
            active_work,
        }
    }
    /// Switches the source on or off.
    ///
    /// Enabling is refused (and leaves it off) while an earlier cleanup is still
    /// unjoined. Disabling cancels every worker, waits for each helper to be
    /// retired, and then forgets all prepared sessions; if any cleanup fails the
    /// error is returned and the sessions stay marked as stopping.
    fn set_enabled(&self, enabled: bool) -> PluginOperation<'_, ()> {
        Box::pin(async move {
            let _lifecycle = self.0.lifecycle.lock().await;
            let workers = {
                let mut state = self
                    .0
                    .state
                    .lock()
                    .map_err(|_| "Desktop source state is unavailable.")?;
                state.enabled = enabled;
                if enabled {
                    if state.prepared.values().any(|record| record.stopping) {
                        state.enabled = false;
                        return Err("Join desktop source cleanup before enabling it again.");
                    }
                    return Ok(());
                }
                state.snapshot = None;
                let mut workers = Vec::new();
                for record in state.prepared.values_mut() {
                    record.stopping = true;
                    if let Some(worker) = &record.worker {
                        worker.cancel();
                        workers.push(worker.clone());
                    }
                }
                if let Some(worker) = &state.inventory {
                    worker.cancel();
                    workers.push(worker.clone());
                }
                workers
            };
            for worker in workers {
                worker
                    .retire()
                    .await
                    .map_err(|_| "Desktop source cleanup failed.")?;
            }
            let mut state = self
                .0
                .state
                .lock()
                .map_err(|_| "Desktop source state is unavailable.")?;
            state.prepared.clear();
            state.inventory = None;
            Ok(())
        })
    }
}
impl Drop for State {
    fn drop(&mut self) {
        for record in self.prepared.values() {
            if let Some(worker) = &record.worker {
                worker.cancel();
            }
        }
        if let Some(worker) = &self.inventory {
            worker.cancel();
        }
    }
}
#[cfg(test)]
#[path = "source_tests.rs"]
mod tests;
