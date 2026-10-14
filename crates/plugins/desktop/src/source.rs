//! Prepared UUIDs own desktop metadata while each admitted native leg owns one private helper and joined worker [D198,D203,D232].
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

pub(super) struct Metadata {
    pub start: Mutex<Start>,
    pub sequence: AtomicU64,
}
struct Prepared {
    metadata: Arc<Metadata>,
    worker: Option<Arc<Worker>>,
    stopping: bool,
}
struct State {
    enabled: bool,
    native_caps: Option<u64>,
    limit: usize,
    prepared: HashMap<Uuid, Prepared>,
    inventory: Option<Arc<Worker>>,
    snapshot: Option<Snapshot>,
}
struct Inner {
    config: Config,
    state: Mutex<State>,
    lifecycle: tokio::sync::Mutex<()>,
}
/// Construction and enable allocate metadata only. Executable/runtime paths
/// come from trusted node setup and are never taken from remote action bodies.
#[derive(Clone)]
pub struct SourceBridge(Arc<Inner>);
pub(super) struct Control {
    pub kind: Kind,
    pub reply: Option<oneshot::Sender<Result<Value, PluginError>>>,
}
pub(super) struct Worker {
    stop: watch::Sender<bool>,
    lane: Mutex<Option<Arc<dyn WireLane>>>,
    pub control: Option<mpsc::Sender<Control>>,
    join: tokio::sync::Mutex<Job>,
}
// A rejected operation is distinct from a failed native retirement. Off/stop
// still succeed after a denied request whose helper was never started.
#[derive(Clone)]
pub(super) struct Outcome {
    pub output: Result<Value, PluginError>,
    pub cleanup: Result<(), PluginError>,
}
impl Outcome {
    pub fn failed(cleanup: Result<(), PluginError>) -> Self {
        Self {
            output: Err(PluginError::Rejected),
            cleanup,
        }
    }
}
struct Job {
    handle: Option<JoinHandle<Outcome>>,
    result: Option<Outcome>,
}
impl Worker {
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
    fn cancel(&self) {
        self.stop.send_replace(true);
        if let Ok(mut lane) = self.lane.lock()
            && let Some(lane) = lane.take()
        {
            lane.retire();
        }
    }
    fn finished(&self) -> bool {
        self.join
            .try_lock()
            .is_ok_and(|job| job.handle.as_ref().is_none_or(JoinHandle::is_finished))
    }
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
    async fn join(&self) -> Result<Value, PluginError> {
        let outcome = self.outcome().await;
        outcome.cleanup?;
        outcome.output
    }
    async fn retire(&self) -> Result<(), PluginError> {
        self.outcome().await.cleanup
    }
}
struct WireLease(Arc<dyn WireLane>);
impl Drop for WireLease {
    fn drop(&mut self) {
        self.0.retire();
    }
}
struct Wait(Arc<Worker>);
impl Drop for Wait {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
impl SourceBridge {
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
    /// # Errors
    /// Refuses disabled/bounded admission or a reused UUID with a foreign target.
    /// Re-preparation retains the current resized geometry and sequence.
    pub fn prepare(&self, id: Uuid, start: Start) -> Result<Value, PluginError> {
        self.prepare_with_floor(id, start, 0)
    }
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
    fn call(&mut self, _: &str, _: &[u8]) -> Result<Vec<u8>, PluginError> {
        Err(PluginError::Rejected)
    }
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
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
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
