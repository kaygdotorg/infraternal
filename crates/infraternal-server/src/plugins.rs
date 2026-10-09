//! Discovers compiled plugins and owns cancellable socket work and runtime feature switches [16,198,201].
use bytes::Bytes;
use infraternal_plugin_api::routing::subscription_topic;
use infraternal_plugin_api::{
    ActionDef, Effect, Permission, Plugin, PluginReply, ReplySender, SocketHost,
    SubscriptionRegistry, subscription_current, subscription_withdraw,
};
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use serde::Deserialize;
use serde_json::{Value, json};
// Serde structs also accept positional arrays. Control actions declare objects,
// so reject that alternate representation before deserializing bounded input.
fn parse_control<T: serde::de::DeserializeOwned>(input: &[u8]) -> Result<T, ()> {
    if input.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return Err(());
    }
    serde_json::from_slice(input).map_err(|_| ())
}
/// Core lifecycle actions share their labels and skill instructions with discovery [16,202].
const CONTROL_ACTIONS: &[ActionDef] = &[
    ActionDef {
        id: "plugins.list",
        summary: "List compiled features",
        instructions: &[
            "Sign in to the server.",
            "Read feature actions, settings, defaults and current states.",
        ],
        input: "Empty",
        output: "PluginInventory",
        permission: Permission::One("authenticated"),
        effect: Effect::Read,
    },
    ActionDef {
        id: "plugins.set_enabled",
        summary: "Switch a server feature",
        instructions: &[
            "Sign in as the owner.",
            "Confirm with your passkey.",
            "Choose a compiled feature and its enabled state.",
        ],
        input: "PluginSetting",
        output: "PluginState",
        permission: Permission::One("server.configure"),
        effect: Effect::Destructive,
    },
];
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

/// Runtime settings are scoped to this already-initialized host role; they never create another role.
#[derive(Clone)]
pub struct PluginRuntime {
    inner: Arc<Runtime>,
}
struct Runtime {
    entries: Vec<Arc<Entry>>,
    role: &'static str,
    switches: tokio::sync::Mutex<()>,
    changed: watch::Sender<()>,
}
struct Entry {
    plugin: Arc<dyn Plugin>,
    enabled: AtomicBool,
    epoch: AtomicU64,
    tasks: Mutex<Vec<Arc<Task>>>,
}
// Wake socket lifecycle delivery even when a worker returns, panics or is cancelled.
struct WorkerWake(watch::Sender<()>);
impl Drop for WorkerWake {
    fn drop(&mut self) {
        self.0.send_replace(());
    }
}
struct Task {
    handle: Mutex<Option<JoinHandle<()>>>,
}
impl Drop for Task {
    fn drop(&mut self) {
        if let Ok(handle) = self.handle.get_mut()
            && let Some(handle) = handle.take()
        {
            handle.abort();
        }
    }
}
/// Plain lifecycle failures contain no inputs or storage details.
#[derive(Debug, PartialEq, Eq)]
pub enum PluginError {
    NotFound,
    RoleUnavailable,
    Forbidden,
}
impl PluginRuntime {
    /// Assemble pure declarations; no worker, timer or listener starts here.
    #[must_use]
    pub fn new(plugins: Vec<Arc<dyn Plugin>>, role: &'static str) -> Self {
        let entries = plugins
            .into_iter()
            .map(|plugin| {
                let enabled = plugin
                    .descriptor()
                    .roles
                    .iter()
                    .find(|part| part.id == role)
                    .is_some_and(|part| {
                        part.default_enabled
                            && part.requires.iter().all(|required| *required == role)
                    });
                Arc::new(Entry {
                    plugin,
                    enabled: AtomicBool::new(enabled),
                    epoch: AtomicU64::new(1),
                    tasks: Mutex::new(Vec::new()),
                })
            })
            .collect();
        Self {
            inner: Arc::new(Runtime {
                entries,
                role,
                switches: tokio::sync::Mutex::new(()),
                changed: watch::channel(()).0,
            }),
        }
    }
    /// Discovery uses the plugin's action definitions, including while it is off.
    #[must_use]
    pub fn list(&self) -> Value {
        json!({"actions":CONTROL_ACTIONS,"plugins": self.inner.entries.iter().map(|entry| json!({"descriptor":({let mut descriptor=serde_json::to_value(entry.plugin.descriptor()).unwrap_or(Value::Null); descriptor["settings"]=serde_json::from_str(entry.plugin.descriptor().settings).unwrap_or(Value::Null); descriptor}),"enabled":entry.enabled.load(Ordering::Acquire)})).collect::<Vec<_>>()})
    }
    /// Stop and join every worker before returning disabled. Enabling remains lazy.
    ///
    /// # Errors
    /// Refuses unknown plugins and role dependencies absent from this host.
    pub async fn set_enabled(&self, id: &str, enabled: bool) -> Result<(), PluginError> {
        self.switch(id, enabled, None).await
    }
    async fn switch(
        &self,
        id: &str,
        enabled: bool,
        host: Option<&dyn SocketHost>,
    ) -> Result<(), PluginError> {
        let _switch = self.inner.switches.lock().await;
        if let Some(host) = host
            && !host.may_configure().await
        {
            return Err(PluginError::Forbidden);
        }
        let entry = self
            .inner
            .entries
            .iter()
            .find(|entry| entry.plugin.descriptor().id == id)
            .ok_or(PluginError::NotFound)?;
        if enabled
            && !entry.plugin.descriptor().roles.iter().any(|part| {
                part.id == self.inner.role
                    && part
                        .requires
                        .iter()
                        .all(|required| *required == self.inner.role)
            })
        {
            return Err(PluginError::RoleUnavailable);
        }
        let tasks = {
            let mut tasks = entry
                .tasks
                .lock()
                .map_err(|_| PluginError::RoleUnavailable)?;
            if entry.enabled.load(Ordering::Acquire) == enabled {
                return Ok(());
            }
            let epoch = entry
                .epoch
                .load(Ordering::Acquire)
                .checked_add(1)
                .ok_or(PluginError::RoleUnavailable)?;
            entry.epoch.store(epoch, Ordering::Release);
            entry.enabled.store(enabled, Ordering::Release);
            if enabled {
                Vec::new()
            } else {
                std::mem::take(&mut *tasks)
            }
        };
        // Epoch invalidation precedes abort/join, so buffered replies cannot escape
        // a disable followed by re-enable on the same browser connection.

        self.inner.changed.send_replace(());
        let handles: Vec<_> = tasks
            .into_iter()
            .filter_map(|task| task.handle.lock().ok().and_then(|mut handle| handle.take()))
            .collect();
        // Abort all tasks before the first await. Cancellation of the switch
        // operation itself must not leave another socket's worker running.
        for handle in &handles {
            handle.abort();
        }
        for handle in handles {
            let _ = handle.await;
        }
        Ok(())
    }
    /// Count live tasks for lifecycle evidence; disabled tasks are removed only after join.
    #[must_use]
    pub fn active_workers(&self, id: &str) -> usize {
        self.inner
            .entries
            .iter()
            .find(|entry| entry.plugin.descriptor().id == id)
            .map_or(0, |entry| {
                entry.tasks.lock().map_or(0, |tasks| {
                    tasks
                        .iter()
                        .filter(|task| {
                            task.handle.lock().is_ok_and(|handle| {
                                handle.as_ref().is_some_and(|handle| !handle.is_finished())
                            })
                        })
                        .count()
                })
            })
    }
}
/// Dispatch separates unknown frames, queued plugin work and immediate bounded refusals.
pub enum Dispatch {
    Unhandled,
    Queued,
    Refused(Bytes),
}
struct SocketEntry {
    entry: Arc<Entry>,
    epoch: u64,
    requests: mpsc::Sender<Bytes>,
    registry: SubscriptionRegistry,
    withdraw_before: u32,
    task: Arc<Task>,
}
impl Drop for SocketEntry {
    fn drop(&mut self) {
        // Runtime retains the join handle until shutdown/pruning, even when
        // the socket disappears concurrently with a disable operation.
        if let Ok(handle) = self.task.handle.lock()
            && let Some(handle) = handle.as_ref()
        {
            handle.abort();
        }
    }
}
/// Host lifecycle withdrawals validate the original, never-reused view generation at delivery.
pub enum SocketReply {
    Plugin(PluginReply),
    Withdrawal(PluginReply),
}
/// One bounded reply queue is shared by this socket's plugin workers.
pub struct SocketPlugins {
    changed: watch::Receiver<()>,
    controller: Option<(mpsc::Sender<Bytes>, Task)>,
    runtime: PluginRuntime,
    host: Arc<dyn SocketHost>,
    entries: Vec<SocketEntry>,
    replies: mpsc::Sender<PluginReply>,
    receiver: mpsc::Receiver<PluginReply>,
    generation: u32,
}
impl SocketPlugins {
    /// Bind one browser socket without starting plugin workers.
    #[must_use]
    pub fn new(runtime: PluginRuntime, host: Arc<dyn SocketHost>) -> Self {
        let (replies, receiver) = mpsc::channel(4);
        let changed = runtime.inner.changed.subscribe();
        Self {
            changed,
            controller: None,
            runtime,
            host,
            entries: Vec::new(),
            replies,
            receiver,
            generation: 0,
        }
    }
    /// Wait on queued work and lifecycle changes; disabled views end without polling.
    pub async fn recv(&mut self) -> Option<SocketReply> {
        loop {
            for socket in &self.entries {
                let expired = socket.entry.epoch.load(Ordering::Acquire) != socket.epoch
                    || socket.requests.is_closed();
                if !expired && socket.withdraw_before == 0 {
                    continue;
                }
                for slot in socket.registry.iter() {
                    let stamp = slot.load(Ordering::Acquire);
                    let Ok(generation) = u32::try_from(stamp >> 32) else {
                        continue;
                    };
                    if generation == 0 || (!expired && generation > socket.withdraw_before) {
                        continue;
                    }
                    let sub_id = u32::try_from(stamp & u64::from(u32::MAX)).unwrap_or_default();
                    let mut wire = Vec::new();
                    if encode_muxed_frame_into(
                        (generation << 1) | 1,
                        &Frame::Event {
                            sub_id,
                            event_json: br#"{"type":"error","error":"forbidden"}"#,
                        },
                        &mut wire,
                    )
                    .is_ok()
                    {
                        return Some(SocketReply::Withdrawal(PluginReply {
                            plugin_id: socket.entry.plugin.descriptor().id,
                            epoch: socket.epoch,
                            wire: Bytes::from(wire),
                        }));
                    }
                }
            }
            tokio::select! {
                reply=self.receiver.recv()=>return reply.map(SocketReply::Plugin),
                changed=self.changed.changed()=>{if changed.is_err(){return None;}}
            }
        }
    }
    /// Generation and lifecycle checks run before the public header is restored.
    #[must_use]
    pub fn accept(&self, reply: SocketReply, encode: &mut Vec<u8>) -> Option<Bytes> {
        let (reply, withdrawal) = match reply {
            SocketReply::Plugin(reply) => (reply, false),
            SocketReply::Withdrawal(reply) => (reply, true),
        };
        if reply.plugin_id.is_empty() && reply.epoch == 0 && !withdrawal {
            return Some(reply.wire);
        }
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.entry.plugin.descriptor().id == reply.plugin_id)?;
        if (!withdrawal && entry.epoch != reply.epoch)
            || reply.wire.len() > entry.entry.plugin.descriptor().max_frame_len
        {
            return None;
        }
        if !withdrawal
            && (!entry.entry.enabled.load(Ordering::Acquire)
                || entry.entry.epoch.load(Ordering::Acquire) != reply.epoch)
        {
            return None;
        }
        let decoded = decode_muxed_frame(&reply.wire).ok()?;
        if decoded.stream_id == 0 {
            return Some(reply.wire);
        }
        let Frame::Event { sub_id, .. } = decoded.frame else {
            return None;
        };
        if !subscription_current(&entry.registry, sub_id, decoded.stream_id >> 1) {
            return None;
        }
        if decoded.stream_id & 1 != 0 {
            subscription_withdraw(&entry.registry, sub_id);
        }
        encode_muxed_frame_into(0, &decoded.frame, encode).ok()?;
        Some(Bytes::copy_from_slice(encode))
    }
    fn start(&mut self, entry: Arc<Entry>) -> Option<usize> {
        let epoch = entry.epoch.load(Ordering::Acquire);
        let id = entry.plugin.descriptor().id;
        let (registry, withdraw_before) = if let Some(index) = self
            .entries
            .iter()
            .position(|socket| socket.entry.plugin.descriptor().id == id)
        {
            if self.entries[index].epoch == epoch && !self.entries[index].requests.is_closed() {
                return Some(index);
            }
            // Retain old view generations across an unrelated call's lazy
            // restart. Only a new Subscribe may supersede their final event.
            let previous = self.entries.swap_remove(index);
            (Arc::clone(&previous.registry), self.generation)
        } else {
            (Arc::new(std::array::from_fn(|_| AtomicU64::new(0))), 0)
        };
        let (requests, receiver) = mpsc::channel(4);
        // Registration and the final enabled check share the shutdown task lock.
        // A concurrent switch either sees this task or prevents it from starting.
        let mut tasks = entry.tasks.lock().ok()?;
        if !entry.enabled.load(Ordering::Acquire) || entry.epoch.load(Ordering::Acquire) != epoch {
            return None;
        }
        tasks.retain(|task| {
            task.handle
                .lock()
                .is_ok_and(|handle| handle.as_ref().is_some_and(|handle| !handle.is_finished()))
        });
        let worker = entry.plugin.run(
            Arc::clone(&self.host),
            receiver,
            ReplySender::new(self.replies.clone(), id, epoch),
            Arc::clone(&registry),
        );
        let changed = self.runtime.inner.changed.clone();
        let handle = tokio::spawn(async move {
            let _wake = WorkerWake(changed);
            worker.await;
        });
        let task = Arc::new(Task {
            handle: Mutex::new(Some(handle)),
        });
        tasks.push(Arc::clone(&task));
        drop(tasks);
        self.entries.push(SocketEntry {
            entry,
            epoch,
            requests,
            registry,
            withdraw_before,
            task,
        });
        Some(self.entries.len() - 1)
    }
    #[allow(clippy::too_many_lines)]
    fn control(&mut self) -> Option<&mpsc::Sender<Bytes>> {
        if self.controller.is_none() {
            let (tx, mut rx) = mpsc::channel::<Bytes>(4);
            let host = Arc::clone(&self.host);
            let runtime = self.runtime.clone();
            let replies = ReplySender::new(self.replies.clone(), "", 0);
            let handle = tokio::spawn(async move {
                while let Some(wire) = rx.recv().await {
                    let result = host.authorized(Box::pin(async {
                        let decoded = decode_muxed_frame(&wire).map_err(|_| ())?;
                        let Frame::Call {call_id, action_id, input_json} = decoded.frame else {return Err(());};
                        let (ok, result) = if action_id == "plugins.list" {
                            #[derive(Deserialize)]
                            #[serde(deny_unknown_fields)]
                            struct Empty {}
                            if parse_control::<Empty>(input_json).is_ok() {(true, runtime.list())} else {(false,json!({"error":"invalid input"}))}
                        } else {
                            #[derive(Deserialize)]
                            #[serde(deny_unknown_fields)]
                            struct Setting { plugin: String, enabled: bool }
                            match parse_control::<Setting>(input_json) {
                                Ok(setting) => match runtime.switch(&setting.plugin,setting.enabled,Some(host.as_ref())).await {
                                    Ok(()) => (true,json!({"plugin":setting.plugin,"enabled":setting.enabled})),
                                    Err(_) => (false,json!({"error":"not permitted"})),
                                },
                                Err(()) => (false,json!({"error":"invalid input"})),
                            }
                        };
                        let json = serde_json::to_vec(&result).map_err(|_| ())?;
                        if json.len() > 60 * 1024 { return Err(()); }
                        let mut encoded = Vec::new();
                        encode_muxed_frame_into(0,&Frame::Result {call_id,ok,json:&json},&mut encoded).map_err(|_| ())?;
                        replies.send(Bytes::from(encoded)).await.map_err(|_| ())
                    })).await;
                    if result.is_err() {
                        break;
                    }
                }
            });
            self.controller = Some((
                tx,
                Task {
                    handle: Mutex::new(Some(handle)),
                },
            ));
        }
        self.controller.as_ref().map(|controller| &controller.0)
    }
    /// Route only declared actions/topics, retaining bounded independent queues.
    #[allow(clippy::too_many_lines)]
    pub fn dispatch(&mut self, wire: &Bytes, encode: &mut Vec<u8>) -> Dispatch {
        let Ok(decoded) = decode_muxed_frame(wire) else {
            return Dispatch::Unhandled;
        };
        if decoded.stream_id != 0 {
            return Dispatch::Unhandled;
        }
        if let Frame::Subscribe { sub_id, .. } = decoded.frame {
            for socket in &self.entries {
                subscription_withdraw(&socket.registry, sub_id);
            }
        }
        if let Frame::Call {
            action_id, call_id, ..
        } = decoded.frame
            && CONTROL_ACTIONS.iter().any(|action| action.id == action_id)
        {
            if wire.len() <= 1024
                && self
                    .control()
                    .is_some_and(|sender| sender.try_send(wire.clone()).is_ok())
            {
                return Dispatch::Queued;
            }
            if encode_muxed_frame_into(
                0,
                &Frame::Result {
                    call_id,
                    ok: false,
                    json: br#"{"error":"plugin unavailable"}"#,
                },
                encode,
            )
            .is_ok()
            {
                return Dispatch::Refused(Bytes::copy_from_slice(encode));
            }
            return Dispatch::Unhandled;
        }
        let entry = match decoded.frame {
            Frame::Call { action_id, .. } => self
                .runtime
                .inner
                .entries
                .iter()
                .find(|entry| {
                    entry
                        .plugin
                        .descriptor()
                        .actions
                        .iter()
                        .any(|action| action.id == action_id)
                })
                .cloned(),
            Frame::Subscribe {
                sub_id,
                filter_json,
            } => {
                // With one subscription provider, let its existing strict
                // filter parser own validation. No JSON parsing is needed in
                // terminal dispatch, including refusal of oversized input.
                let mut providers = self
                    .runtime
                    .inner
                    .entries
                    .iter()
                    .filter(|entry| !entry.plugin.descriptor().topics.is_empty());
                let mut single = providers.clone();
                let first = single.next();
                if single.next().is_none() {
                    first.cloned()
                } else {
                    let limit = providers
                        .clone()
                        .map(|entry| entry.plugin.descriptor().max_frame_len)
                        .max()
                        .unwrap_or(0);
                    if wire.len() > limit {
                        if encode_muxed_frame_into(
                            0,
                            &Frame::Event {
                                sub_id,
                                event_json: br#"{"type":"error","error":"plugin unavailable"}"#,
                            },
                            encode,
                        )
                        .is_ok()
                        {
                            return Dispatch::Refused(Bytes::copy_from_slice(encode));
                        }
                        return Dispatch::Unhandled;
                    }
                    let topic = subscription_topic(filter_json, limit);
                    providers
                        .find(|entry| {
                            topic.as_deref().is_some_and(|topic| {
                                entry.plugin.descriptor().topics.contains(&topic)
                            })
                        })
                        .cloned()
                }
            }
            _ => None,
        };
        let Some(entry) = entry else {
            if let Frame::Call {
                call_id, action_id, ..
            } = decoded.frame
                && let Some(entry) = self.runtime.inner.entries.iter().find(|entry| {
                    action_id
                        .split_once('.')
                        .is_some_and(|(namespace, _)| namespace == entry.plugin.descriptor().id)
                })
            {
                let descriptor = entry.plugin.descriptor();
                let json = if wire.len() > descriptor.max_frame_len
                    || !entry.enabled.load(Ordering::Acquire)
                {
                    descriptor.unavailable
                } else {
                    br#"{"error":"invalid input"}"#
                };
                if encode_muxed_frame_into(
                    0,
                    &Frame::Result {
                        call_id,
                        ok: false,
                        json,
                    },
                    encode,
                )
                .is_ok()
                {
                    return Dispatch::Refused(Bytes::copy_from_slice(encode));
                }
            }
            if let Frame::Subscribe { sub_id, .. } = decoded.frame {
                let refusal = Frame::Event {
                    sub_id,
                    event_json: br#"{"type":"error","error":"invalid input"}"#,
                };
                if encode_muxed_frame_into(0, &refusal, encode).is_ok() {
                    return Dispatch::Refused(Bytes::copy_from_slice(encode));
                }
            }
            return Dispatch::Unhandled;
        };
        let descriptor = entry.plugin.descriptor();
        if let Frame::Subscribe { sub_id, .. } = decoded.frame {
            for socket in &self.entries {
                subscription_withdraw(&socket.registry, sub_id);
            }
        }
        let refusal = match decoded.frame {
            Frame::Call { call_id, .. } => Frame::Result {
                call_id,
                ok: false,
                json: descriptor.unavailable,
            },
            Frame::Subscribe { sub_id, .. } => Frame::Event {
                sub_id,
                event_json: descriptor.unavailable_event,
            },
            _ => return Dispatch::Unhandled,
        };
        let mut admitted = false;
        if wire.len() <= descriptor.max_frame_len
            && entry.enabled.load(Ordering::Acquire)
            && let Some(index) = self.start(entry)
        {
            let socket = &self.entries[index];
            if let Frame::Subscribe { sub_id, .. } = decoded.frame {
                if let Some(generation) = self
                    .generation
                    .checked_add(1)
                    .filter(|value| *value <= u32::MAX >> 1)
                {
                    self.generation = generation;
                    if encode_muxed_frame_into(generation << 1, &decoded.frame, encode).is_ok()
                        && let Some(slot) = socket
                            .registry
                            .iter()
                            .find(|slot| slot.load(Ordering::Acquire) == 0)
                    {
                        slot.store(
                            (u64::from(generation) << 32) | u64::from(sub_id),
                            Ordering::Release,
                        );
                        admitted = socket
                            .requests
                            .try_send(Bytes::copy_from_slice(encode))
                            .is_ok();
                        if !admitted {
                            subscription_withdraw(&socket.registry, sub_id);
                        }
                    }
                }
            } else {
                admitted = socket.requests.try_send(wire.clone()).is_ok();
            }
        }
        if admitted {
            Dispatch::Queued
        } else if encode_muxed_frame_into(0, &refusal, encode).is_ok() {
            Dispatch::Refused(Bytes::copy_from_slice(encode))
        } else {
            Dispatch::Unhandled
        }
    }
}

/// Register server features for an existing server; no constructor creates one [201].
#[must_use]
pub fn compiled(pool: &sqlx::SqlitePool) -> PluginRuntime {
    #[cfg(feature = "mesh")]
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(infraternal_plugin_mesh::MeshPlugin::new(
        pool.clone(),
    ))];
    #[cfg(not(feature = "mesh"))]
    let plugins = {
        let _ = pool;
        Vec::new()
    };
    PluginRuntime::new(plugins, "server")
}
