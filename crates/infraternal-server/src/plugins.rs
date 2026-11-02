//! Discovers compiled plugins and owns cancellable socket work and runtime feature switches [16,198,201].
#[path = "node_lifecycle.rs"]
mod node_lifecycle;
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
        target: infraternal_plugin_api::Target::Global,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        id: "plugins.list",
        summary: "List compiled features",
        instructions: &[
            "Sign in to the server.",
            "Read feature actions, settings, defaults and current states.",
        ],
        input: infraternal_plugin_api::SchemaRef("Empty"),
        output: infraternal_plugin_api::SchemaRef("PluginInventory"),
        permission: Permission::One("authenticated"),
        effect: Effect::Read,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Global,
        dry_run: infraternal_plugin_api::DryRun::Required,
        opens: None,
        id: "plugins.set_enabled",
        summary: "Switch a server feature",
        instructions: &[
            "Sign in as the owner.",
            "Confirm with your passkey.",
            "Choose a compiled feature and its enabled state.",
        ],
        input: infraternal_plugin_api::SchemaRef("PluginSetting"),
        output: infraternal_plugin_api::SchemaRef("PluginState"),
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
/// Remote host registries never keep a server plugin runtime alive.
#[derive(Clone, Default)]
#[cfg(feature = "remote")]
pub(crate) struct WeakRuntime(std::sync::Weak<Runtime>);
#[cfg(feature = "remote")]
impl WeakRuntime {
    pub(crate) fn upgrade(&self) -> Option<PluginRuntime> {
        self.0.upgrade().map(|inner| PluginRuntime { inner })
    }
}
struct Runtime {
    entries: Vec<Arc<Entry>>,
    role: &'static str,
    store: Option<sqlx::SqlitePool>,
    switches: tokio::sync::Mutex<()>,
    nodes: tokio::sync::Mutex<node_lifecycle::Nodes>,
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
    Storage,
}
impl PluginRuntime {
    /// Wake enabled plugins after a durable authority edit, without retaining disabled work.
    pub async fn authority_changed(&self) {
        for entry in &self.inner.entries {
            if entry.enabled.load(Ordering::Acquire)
                && let Some(operation) = entry.plugin.authority_changed()
            {
                operation.await;
            }
        }
    }
    #[cfg(feature = "remote")]
    pub(crate) fn downgrade(&self) -> WeakRuntime {
        WeakRuntime(Arc::downgrade(&self.inner))
    }

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
                store: None,
                switches: tokio::sync::Mutex::new(()),
                nodes: tokio::sync::Mutex::new(node_lifecycle::Nodes::default()),
                changed: watch::channel(()).0,
            }),
        }
    }
    /// Restore durable switches before sharing a newly constructed runtime.
    ///
    /// # Errors
    /// Refuses storage failures, a shared runtime or enabled roles unavailable here.
    pub async fn with_store(mut self, pool: sqlx::SqlitePool) -> Result<Self, PluginError> {
        use sqlx::Row;
        let inner = Arc::get_mut(&mut self.inner).ok_or(PluginError::RoleUnavailable)?;
        let rows = sqlx::query("SELECT plugin,enabled FROM plugin_settings WHERE role=?")
            .bind(inner.role)
            .fetch_all(&pool)
            .await
            .map_err(|_| PluginError::Storage)?;
        for row in rows {
            let id: String = row.get("plugin");
            let enabled: bool = row.get("enabled");
            if let Some(entry) = inner
                .entries
                .iter()
                .find(|entry| entry.plugin.descriptor().id == id)
            {
                if enabled
                    && !entry.plugin.descriptor().roles.iter().any(|part| {
                        part.id == inner.role
                            && part.requires.iter().all(|required| *required == inner.role)
                    })
                {
                    return Err(PluginError::RoleUnavailable);
                }
                entry.enabled.store(enabled, Ordering::Release);
            }
        }
        inner.store = Some(pool);
        Ok(self)
    }
    // Disable joins work before waiting for the SQLite writer. Otherwise an
    // in-flight inventory writer could prevent the switch which cancels it.
    async fn persist_setting(
        &self,
        id: &str,
        enabled: bool,
        host: Option<&dyn SocketHost>,
    ) -> Result<(), PluginError> {
        let Some(pool) = &self.inner.store else {
            return Ok(());
        };
        let mut tx = infraternal_plugin_api::storage::begin_immediate(pool)
            .await
            .map_err(|_| PluginError::Storage)?;
        sqlx::query("INSERT INTO plugin_settings(role,plugin,enabled) VALUES (?,?,?) ON CONFLICT(role,plugin) DO UPDATE SET enabled=excluded.enabled")
            .bind(self.inner.role).bind(id).bind(enabled).execute(&mut *tx).await.map_err(|_| PluginError::Storage)?;
        if let Some(host) = host {
            // Repeat owner/fresh authority inside the writer transaction after
            // lock waits, exactly where rollback still protects the setting [28].
            let now: i64 = sqlx::query_scalar("SELECT unixepoch()")
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| PluginError::Storage)?;
            let owner: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND owner=1)")
                    .bind(host.user_id())
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| PluginError::Storage)?;
            if !owner
                || !infraternal_plugin_api::fresh_session_tx(
                    &mut tx,
                    host.token_hash(),
                    host.user_id(),
                    now,
                    infraternal_plugin_api::FRESH_SECONDS,
                )
                .await
                .map_err(|_| PluginError::Storage)?
            {
                return Err(PluginError::Forbidden);
            }
        }
        tx.commit().await.map_err(|_| PluginError::Storage)
    }
    /// Discovery uses the plugin's action definitions, including while it is off.
    #[must_use]
    pub fn list(&self) -> Value {
        json!({"actions":CONTROL_ACTIONS,"plugins": self.inner.entries.iter().map(|entry| json!({"descriptor":({let mut descriptor=serde_json::to_value(entry.plugin.descriptor()).unwrap_or(Value::Null); descriptor["settings"]=entry.plugin.descriptor().settings.and_then(|schema| serde_json::from_str(schema.0).ok()).unwrap_or(Value::Null); descriptor}),"enabled":entry.enabled.load(Ordering::Acquire)})).collect::<Vec<_>>()})
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
        if entry.enabled.load(Ordering::Acquire) == enabled {
            return self.persist_setting(id, enabled, host).await;
        }
        let next_epoch = entry
            .epoch
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or(PluginError::RoleUnavailable)?;
        let restore_epoch = next_epoch
            .checked_add(1)
            .ok_or(PluginError::RoleUnavailable)?;
        // Enabling cannot admit a worker until its setting is durable.
        if enabled {
            self.persist_setting(id, enabled, host).await?;
        }
        let tasks = {
            let mut tasks = entry
                .tasks
                .lock()
                .map_err(|_| PluginError::RoleUnavailable)?;
            if entry.enabled.load(Ordering::Acquire) == enabled {
                return Ok(());
            }
            entry.epoch.store(next_epoch, Ordering::Release);
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
        if !enabled && let Err(error) = self.persist_setting(id, enabled, host).await {
            // A failed save must retain the previous durable state. Old workers
            // stay stopped; restoring enabled state remains lazy.
            entry.epoch.store(restore_epoch, Ordering::Release);
            entry.enabled.store(true, Ordering::Release);
            self.inner.changed.send_replace(());
            self.start_nodes(entry).await?;
            return Err(error);
        }
        if enabled {
            self.start_nodes(entry).await?;
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
// Four queued requests, one active call and four buffered replies bound admission.
const MAX_PENDING_CALLS: usize = 9;
struct SocketEntry {
    entry: Arc<Entry>,
    epoch: u64,
    reply_epoch: u64,
    requests: mpsc::Sender<Bytes>,
    registry: SubscriptionRegistry,
    withdraw_before: u32,
    // The cancellation flag survives lazy restarts until its Result is delivered.
    pending_calls: Vec<(u32, bool)>,
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
            if self.entries.iter().any(|socket| {
                socket.requests.is_closed()
                    && socket.entry.epoch.load(Ordering::Acquire) == socket.epoch
                    && socket.pending_calls.iter().any(|pending| !pending.1)
            }) && let Ok(reply) = self.receiver.try_recv()
            {
                return Some(SocketReply::Plugin(reply));
            }
            for socket in &mut self.entries {
                let expired = socket.entry.epoch.load(Ordering::Acquire) != socket.epoch
                    || socket.requests.is_closed();
                if expired {
                    for pending in &mut socket.pending_calls {
                        pending.1 = true;
                    }
                }
                if let Some(&(call_id, true)) =
                    socket.pending_calls.iter().find(|pending| pending.1)
                {
                    let mut wire = Vec::new();
                    if encode_muxed_frame_into(
                        0,
                        &Frame::Result {
                            call_id,
                            ok: false,
                            json: socket.entry.plugin.descriptor().unavailable,
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
    pub fn accept(&mut self, reply: SocketReply, encode: &mut Vec<u8>) -> Option<Bytes> {
        let (reply, withdrawal) = match reply {
            SocketReply::Plugin(reply) => (reply, false),
            SocketReply::Withdrawal(reply) => (reply, true),
        };
        if reply.plugin_id.is_empty() && reply.epoch == 0 && !withdrawal {
            return Some(reply.wire);
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.entry.plugin.descriptor().id == reply.plugin_id)?;
        if (!withdrawal && entry.reply_epoch != reply.epoch)
            || reply.wire.len() > entry.entry.plugin.descriptor().max_frame_len
        {
            return None;
        }
        if !withdrawal
            && (!entry.entry.enabled.load(Ordering::Acquire)
                || entry.entry.epoch.load(Ordering::Acquire) != entry.epoch)
        {
            return None;
        }
        let decoded = decode_muxed_frame(&reply.wire).ok()?;
        if decoded.stream_id == 0 {
            if let Frame::Result { call_id, .. } = decoded.frame {
                let index = entry
                    .pending_calls
                    .iter()
                    .position(|pending| pending.0 == call_id && pending.1 == withdrawal)?;
                entry.pending_calls.swap_remove(index);
            }
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
        let previous_index = self
            .entries
            .iter()
            .position(|socket| socket.entry.plugin.descriptor().id == id);
        if let Some(index) = previous_index
            && self.entries[index].epoch == epoch
            && !self.entries[index].requests.is_closed()
        {
            return Some(index);
        }
        // Check shutdown under the task lock before taking old calls/views out
        // of the socket. A refused restart must preserve their final replies.
        let mut tasks = entry.tasks.lock().ok()?;
        if !entry.enabled.load(Ordering::Acquire) || entry.epoch.load(Ordering::Acquire) != epoch {
            return None;
        }
        let generation = self
            .generation
            .checked_add(1)
            .filter(|value| *value <= u32::MAX >> 1)?;
        let (registry, withdraw_before, pending_calls) = if let Some(index) = previous_index {
            let mut previous = self.entries.swap_remove(index);
            let mut pending = std::mem::take(&mut previous.pending_calls);
            for call in &mut pending {
                call.1 = true;
            }
            (Arc::clone(&previous.registry), self.generation, pending)
        } else {
            (
                Arc::new(std::array::from_fn(|_| AtomicU64::new(0))),
                0,
                Vec::with_capacity(MAX_PENDING_CALLS),
            )
        };
        // Workers and views share a never-reused socket generation. A buffered
        // Result from an exited worker cannot answer a retry with the same id.
        self.generation = generation;
        let reply_epoch = u64::from(generation);
        let (requests, receiver) = mpsc::channel(4);
        tasks.retain(|task| {
            task.handle
                .lock()
                .is_ok_and(|handle| handle.as_ref().is_some_and(|handle| !handle.is_finished()))
        });
        let worker = entry.plugin.run(
            Arc::clone(&self.host),
            receiver,
            ReplySender::new(self.replies.clone(), id, reply_epoch),
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
            reply_epoch,
            requests,
            registry,
            withdraw_before,
            pending_calls,
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
                let providers = self
                    .runtime
                    .inner
                    .entries
                    .iter()
                    .filter(|entry| !entry.plugin.descriptor().topics.is_empty());
                let limit = providers
                    .clone()
                    .map(|entry| entry.plugin.descriptor().max_frame_len)
                    .max()
                    .unwrap_or(0);
                if limit == 0 {
                    return Dispatch::Unhandled;
                }
                if wire.len() > limit {
                    let mut candidates = providers.clone();
                    let first = candidates.next();
                    let event_json = if candidates.next().is_none() {
                        first.map_or(
                            br#"{"type":"error","error":"plugin unavailable"}"#.as_slice(),
                            |entry| entry.plugin.descriptor().unavailable_event,
                        )
                    } else {
                        br#"{"type":"error","error":"plugin unavailable"}"#
                    };
                    if encode_muxed_frame_into(0, &Frame::Event { sub_id, event_json }, encode)
                        .is_ok()
                    {
                        return Dispatch::Refused(Bytes::copy_from_slice(encode));
                    }
                    return Dispatch::Unhandled;
                }
                let topic = subscription_topic(filter_json, limit);
                if let Some(topic) = topic.as_deref() {
                    // The auth namespace is core-owned even if a plugin declares it.
                    // Valid undeclared topics must reach the core with one or many providers.
                    if topic.starts_with("auth.") {
                        return Dispatch::Unhandled;
                    }
                    let entry = providers
                        .into_iter()
                        .find(|entry| entry.plugin.descriptor().topics.contains(&topic))
                        .cloned();
                    if entry.is_none() {
                        return Dispatch::Unhandled;
                    }
                    entry
                } else {
                    None
                }
            }
            _ => None,
        };
        let Some(entry) = entry else {
            if let Frame::Call { action_id, .. } = decoded.frame
                && self.host.node_action_declared(action_id)
            {
                return Dispatch::Unhandled;
            }
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
            let socket = &mut self.entries[index];
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
            } else if let Frame::Call { call_id, .. } = decoded.frame
                && socket.pending_calls.len() < MAX_PENDING_CALLS
                && !socket
                    .pending_calls
                    .iter()
                    .any(|pending| pending.0 == call_id)
            {
                admitted = socket.requests.try_send(wire.clone()).is_ok();
                if admitted {
                    socket.pending_calls.push((call_id, false));
                }
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
///
/// # Errors
/// Refuses unavailable or inconsistent persisted feature settings.
pub async fn compiled(pool: &sqlx::SqlitePool) -> Result<PluginRuntime, PluginError> {
    compiled_with_hosts(
        pool,
        None,
        #[cfg(feature = "remote")]
        crate::remote_runtime::RemoteHosts::default(),
    )
    .await
}
pub(crate) async fn compiled_with_hosts(
    pool: &sqlx::SqlitePool,
    public_origin: Option<&str>,
    #[cfg(feature = "remote")] hosts: crate::remote_runtime::RemoteHosts,
) -> Result<PluginRuntime, PluginError> {
    #[cfg(feature = "mesh")]
    let mesh_plugin = Arc::new(public_origin.map_or_else(
        || infraternal_plugin_mesh::MeshPlugin::new(pool.clone()),
        |origin| infraternal_plugin_mesh::MeshPlugin::with_public_origin(pool.clone(), origin),
    ));
    #[cfg(all(feature = "mesh", feature = "remote"))]
    let mesh_service = mesh_plugin.service();
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        #[cfg(feature = "ssh")]
        Arc::new(crate::preferred_accounts::AccountsPlugin::new(pool.clone())),
        #[cfg(feature = "mesh")]
        mesh_plugin,
        #[cfg(feature = "release")]
        Arc::new(crate::release_latest::plugin(pool.clone()).await?),
        #[cfg(feature = "remote")]
        Arc::new(infraternal_plugin_remote::inventory::InventoryPlugin(
            Arc::new(crate::remote_inventory::Source {
                pool: pool.clone(),
                hosts,
                #[cfg(feature = "mesh")]
                mesh: Some(mesh_service),
            }),
        )),
        // Append features so existing discovery positions remain stable.
        #[cfg(feature = "canvas")]
        Arc::new(infraternal_plugin_canvas::socket::CanvasPlugin(Arc::new(
            crate::canvas_store::Store::new(pool.clone()),
        ))),
    ];
    PluginRuntime::new(plugins, "server")
        .with_store(pool.clone())
        .await
}
