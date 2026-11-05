//! The Mesh plugin's connection to browsers and tools: calls, live watches and
//! their expiry [11,28,198].
//!
//! Each connected user gets one worker task that runs apart from the terminal
//! dispatch loop, so slow database work can never stall a terminal. On the
//! multiplexed socket it handles two kinds of traffic:
//!
//! - **Calls** on the control stream (stream 0) whose action id starts with
//!   `mesh.`. Destructive actions need a fresh passkey confirmation, not just
//!   an unlocked socket.
//! - **Watches** (subscriptions) on their own streams. A watch starts with a
//!   `snapshot` event, then gets `changed` notices, `resync` snapshots after
//!   missed changes, presence changes or a liveness deadline, or an `error`.
//!   A watch only ever sees what its user may view.
//!
//! On a watch's stream the id is `generation << 1`. The low bit is set on the
//! last event of a watch, which tells the host the watch has ended.
//!
//! The plugin also starts the per-node coordination for each connected
//! infraternal agent (see [`MeshPlugin::node_connected`]).
use crate::{
    api::{MAX_MESH_FRAME_LEN, MeshApiError, MeshChange, MeshFilter, MeshService},
    descriptor::DESCRIPTOR,
};
use bytes::Bytes;
use futures_util::{FutureExt, SinkExt};
use infraternal_plugin_api::{
    Effect, MAX_SUBSCRIPTIONS, Operation, Plugin, PluginDescriptor, ReplySender, SocketHost,
    SubscriptionRegistry, subscription_current,
};
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Semaphore, mpsc};
/// The stream that carries calls and their results.
const CONTROL_STREAM: u32 = 0;
/// How many watches one socket may hold. Sized so the list is a small array that
/// is scanned, not hashed.
const MAX_MESH_SUBSCRIPTIONS: usize = MAX_SUBSCRIPTIONS;
/// The Mesh plugin: serves Mesh calls and watches for users and runs the mesh
/// coordination for connected nodes [201].
///
/// Creating it is pure. It never starts a server; it only holds the database
/// pool (inside [`MeshService`]) and a limit on concurrent mesh work. Cloning
/// is cheap and shares both.
#[derive(Clone)]
pub struct MeshPlugin {
    mesh: MeshService,
    mesh_work: Arc<Semaphore>,
}
impl MeshPlugin {
    /// Creates the plugin on the server's database pool.
    ///
    /// Mesh work may use at most two of the pool's connections (fewer on a
    /// tiny pool, never fewer than one), leaving the rest, six in production,
    /// for authority checks and other features.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        let capacity = Self::mesh_work_capacity(&pool);
        Self::with_mesh_service(capacity, MeshService::new(pool))
    }

    /// Like [`new`](MeshPlugin::new), but also gives the mesh the server's
    /// public origin (`public_origin`), from which the default DNS suffix is
    /// derived.
    #[must_use]
    pub fn with_public_origin(pool: SqlitePool, public_origin: &str) -> Self {
        let capacity = Self::mesh_work_capacity(&pool);
        Self::with_mesh_service(
            capacity,
            MeshService::with_public_origin(pool, public_origin),
        )
    }

    /// How many mesh jobs may use the database at once: the pool size minus two
    /// connections kept free, limited to 1 or 2.
    fn mesh_work_capacity(pool: &SqlitePool) -> usize {
        pool.options()
            .get_max_connections()
            .saturating_sub(2)
            .clamp(1, 2) as usize
    }

    /// Assembles the plugin from a service and a work limit.
    fn with_mesh_service(capacity: usize, mesh: MeshService) -> Self {
        Self {
            mesh,
            mesh_work: Arc::new(Semaphore::new(capacity)),
        }
    }

    /// The mesh service this plugin uses. Other server features can take it to
    /// share the same change broadcaster, so they hear about mesh revisions too.
    #[must_use]
    pub fn service(&self) -> MeshService {
        self.mesh.clone()
    }
}
impl Plugin for MeshPlugin {
    /// Drops the cached data-plane view when permissions change, so the next
    /// read uses the new authority.
    fn authority_changed(&self) -> Option<Operation<'_, ()>> {
        Some(Box::pin(self.mesh.invalidate_dataplane()))
    }
    /// The static description of the plugin's actions and topics.
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    /// Runs for as long as an infraternal agent's channel is connected: serves
    /// that node's mesh configuration. On the server's own channel it also
    /// tracks who is online, and the two tasks end together.
    fn node_connected(
        &self,
        channel: Arc<dyn infraternal_plugin_api::node_channel::NodeChannel>,
    ) -> Option<Operation<'static, ()>> {
        let service = self.mesh.clone();
        let store = service.dataplane();
        let work = self.mesh_work.clone();
        if !channel.is_server() {
            return Some(Box::pin(crate::node_coordination::run(
                store, service, channel, work,
            )));
        }
        // The server's own channel also reads who is online; the two end together (presence.rs, #236).
        let presence = crate::presence::run(service.clone(), channel.clone());
        let coordination = crate::node_coordination::run(store, service, channel, work);
        Some(Box::pin(async move {
            tokio::select! {
                () = coordination => {}
                () = presence => {}
            }
        }))
    }
    /// Runs one user's worker until the socket closes.
    ///
    /// The loop waits for the first of: a watch's liveness deadline, a request
    /// frame, a presence change, or a mesh change notice. Every step runs under
    /// the host's authorization check, and any failure ends the worker.
    fn run(
        &self,
        host: Arc<dyn SocketHost>,
        mut requests: mpsc::Receiver<Bytes>,
        replies: ReplySender,
        worker_registry: SubscriptionRegistry,
    ) -> Operation<'static, ()> {
        let worker_state = self.clone();
        let worker_user = host.user_id().to_owned();
        Box::pin(async move {
            let mut mesh_updates = worker_state.mesh.subscribe();
            let mut presence_updates = worker_state.mesh.subscribe_presence();
            // The view this worker last compared against; a transition is judged per watch against it.
            let mut seen_presence = presence_updates.borrow_and_update().clone();
            let mut mesh_subscriptions =
                Vec::<MeshSubscription>::with_capacity(MAX_MESH_SUBSCRIPTIONS);
            let mut encode = Vec::with_capacity(4096);
            let sink = futures_util::sink::unfold(replies, move |tx, wire| async move {
                tx.send(wire).await.map_err(|_| ())?;
                Ok::<_, ()>(tx)
            });
            tokio::pin!(sink);
            loop {
                mesh_subscriptions.retain(|sub| {
                    subscription_current(&worker_registry, sub.sub_id, sub.generation)
                });
                let next_expiry = mesh_subscriptions
                    .iter()
                    .filter_map(|sub| sub.liveness_deadline)
                    .min();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();
                let expiry_wait = next_expiry
                    .and_then(|expiry| u64::try_from(expiry).ok())
                    .map(|expiry| Duration::from_secs(expiry).saturating_sub(now));
                let result = tokio::select! {
                    () = tokio::time::sleep(expiry_wait.unwrap_or_default()), if expiry_wait.is_some() => {
                        host.authorized(
                            send_mesh_resync(&worker_state, &worker_user,
                                &mut mesh_subscriptions, &mut sink, &mut encode, Resync::Expired).boxed()
                        ).await
                    }
                    wire = requests.recv() => {
                        let Some(wire) = wire else { break; };
                        if let Ok(decoded) = decode_muxed_frame(&wire)
                            && let Frame::Subscribe { sub_id, .. } = decoded.frame
                            && !subscription_current(&worker_registry, sub_id, decoded.stream_id >> 1) {
                            continue;
                        }
                        host.authorized(async {
                                let _permit = worker_state.mesh_work.acquire().await.map_err(|_| ())?;
                                handle_mesh_frame(wire, &worker_state, &worker_user, host.as_ref(),
                                    &mut mesh_subscriptions, &mut sink, &mut encode).await
                            }.boxed()
                        ).await
                    }
                    // Presence moves without a revision: a watch that sees a changed node gets a fresh snapshot.
                    changed = presence_updates.changed(), if !mesh_subscriptions.is_empty() => {
                        if changed.is_err() {
                            Err(())
                        } else {
                            let next = presence_updates.borrow_and_update().clone();
                            let previous = std::mem::replace(&mut seen_presence, next.clone());
                            host.authorized(
                                send_mesh_resync(&worker_state, &worker_user, &mut mesh_subscriptions,
                                    &mut sink, &mut encode, Resync::Presence(&previous, &next)).boxed()
                            ).await
                        }
                    }
                    change = mesh_updates.recv(), if !mesh_subscriptions.is_empty() => {
                        match change {
                            Ok(change) => host.authorized(async {
                                    let _permit = worker_state.mesh_work.acquire().await.map_err(|_| ())?;
                                    send_mesh_change(&worker_state, &worker_user, &change,
                                        &mut mesh_subscriptions, &mut sink, &mut encode).await
                                }.boxed()
                            ).await,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) =>
                                host.authorized(
                                    send_mesh_resync(&worker_state, &worker_user,
                                        &mut mesh_subscriptions, &mut sink, &mut encode, Resync::All).boxed()
                                ).await,
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => Err(()),
                        }
                    }
                };
                if result.is_err() {
                    break;
                }
            }
        })
    }
}

/// One live watch on this socket.
///
/// The filter and the generation belong together: replacing the watch replaces
/// both.
#[derive(Clone)]
struct MeshSubscription {
    /// The watch id chosen by the client.
    sub_id: u32,
    /// What the watch wants to see.
    filter: MeshFilter,
    /// Counts how many times this stream was subscribed; stale replies are
    /// dropped by comparing it.
    generation: u32,
    /// Unix time in seconds at which a node shown by this watch is due to be
    /// reported offline, so a resync is owed. `None` if no such time exists.
    liveness_deadline: Option<i64>,
}

/// Removes the watch `sub_id` if present. The small fixed limit on watches makes
/// this a short scan that needs no hashing or allocation.
fn mesh_remove(subscriptions: &mut Vec<MeshSubscription>, sub_id: u32) {
    if let Some(index) = subscriptions.iter().position(|sub| sub.sub_id == sub_id) {
        subscriptions.swap_remove(index);
    }
}

/// The JSON a client sends to start a watch: `{"topic": "mesh", "tag": ...}`.
/// Unknown fields are refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeshSubscribeFilter {
    /// Must be `mesh`.
    topic: String,
    /// Only show nodes with this tag, if given.
    #[serde(default)]
    tag: Option<String>,
}

/// The `error` event for a failed watch, with a short message that is safe to
/// show the user.
fn mesh_error_event(error: MeshApiError) -> Value {
    let message = match error {
        MeshApiError::InvalidInput => "invalid input",
        MeshApiError::Denied => "forbidden",
        MeshApiError::FreshRequired => "confirm with your passkey again",
        MeshApiError::NotFound => "not found",
        MeshApiError::Conflict => "conflict",
        MeshApiError::Reserved => "reserved for the server",
        MeshApiError::Storage => "mesh unavailable",
    };
    json!({"type":"error","error":message})
}

/// Sends one event on a watch's stream. `stream_id` carries the generation and
/// the end-of-watch bit (see the module docs).
async fn send_mesh_event<K>(
    sink: &mut K,
    sub_id: u32,
    event: &Value,
    encode: &mut Vec<u8>,
    stream_id: u32,
) -> Result<(), ()>
where
    K: futures_util::Sink<Bytes, Error = ()> + Unpin,
{
    let event_json = serde_json::to_vec(event).map_err(|_| ())?;
    send_frame(
        sink,
        stream_id,
        &Frame::Event {
            sub_id,
            event_json: &event_json,
        },
        encode,
    )
    .await
}

/// Tells every watch that may see `change` that something changed, and updates
/// its liveness deadline.
///
/// A watch that is not allowed to see the change hears nothing. A watch whose
/// permission check fails is sent an `error` and removed.
async fn send_mesh_change<K>(
    state: &MeshPlugin,
    user_id: &str,
    change: &MeshChange,
    subscriptions: &mut Vec<MeshSubscription>,
    sink: &mut K,
    encode: &mut Vec<u8>,
) -> Result<(), ()>
where
    K: futures_util::Sink<Bytes, Error = ()> + Unpin,
{
    let current = subscriptions.clone();
    for subscription in current {
        let sub_id = subscription.sub_id;
        let (event, ended) = match state
            .mesh
            .can_view_change(user_id, &subscription.filter, change)
            .await
        {
            Ok(true) => {
                let deadline = if let Some(deadline) = change.liveness_deadline {
                    subscription
                        .liveness_deadline
                        .map_or(Some(deadline), |old| Some(old.min(deadline)))
                } else {
                    // Membership and role edits can reveal live hosts even when
                    // this watch previously had no timer. Recompute its full view.
                    state
                        .mesh
                        .watch_deadline(user_id, &subscription.filter, unix_seconds()?)
                        .await
                        .map_err(|_| ())?
                };
                if let Some(watch) = subscriptions.iter_mut().find(|sub| sub.sub_id == sub_id) {
                    watch.liveness_deadline = deadline;
                }
                (json!({"type":"changed","revision":change.revision}), false)
            }
            Ok(false) => continue,
            Err(error) => {
                mesh_remove(subscriptions, sub_id);
                (mesh_error_event(error), true)
            }
        };
        send_mesh_event(
            sink,
            sub_id,
            &event,
            encode,
            (subscription.generation << 1) | u32::from(ended),
        )
        .await?;
    }
    Ok(())
}

/// Which watches a resync goes to.
#[derive(Clone, Copy)]
enum Resync<'a> {
    /// Watches whose stored-liveness deadline has passed.
    Expired,
    /// Every watch, after missed change notices.
    All,
    /// Watches that see a node whose presence changed between the two views (#236). A watch that sees none of
    /// the changed nodes is sent nothing, so a tag-scoped viewer learns nothing about nodes outside its view, not
    /// even when they change.
    Presence(&'a crate::presence::Live, &'a crate::presence::Live),
}

/// Sends fresh snapshots to the watches `which` selects.
///
/// The snapshots are read under one shared `mesh_work` permit and sent after
/// it is released: a viewer slow to drain its socket must not hold the permit
/// that host configuration delivery also needs (#236). A watch whose snapshot
/// fails gets an `error` and is removed.
async fn send_mesh_resync<K>(
    state: &MeshPlugin,
    user_id: &str,
    subscriptions: &mut Vec<MeshSubscription>,
    sink: &mut K,
    encode: &mut Vec<u8>,
    which: Resync<'_>,
) -> Result<(), ()>
where
    K: futures_util::Sink<Bytes, Error = ()> + Unpin,
{
    let now = unix_seconds()?;
    let mut events = Vec::with_capacity(subscriptions.len());
    {
        let _permit = state.mesh_work.acquire().await.map_err(|_| ())?;
        for subscription in subscriptions.iter() {
            if matches!(which, Resync::Expired)
                && subscription
                    .liveness_deadline
                    .is_none_or(|deadline| deadline > now)
            {
                continue;
            }
            let event = match state
                .mesh
                .list_with_deadline(user_id, subscription.filter.clone(), now)
                .await
            {
                Ok((snapshot, deadline)) => {
                    if let Resync::Presence(previous, next) = which
                        && !snapshot
                            .nodes
                            .iter()
                            .any(|node| previous.get(&node.node.id) != next.get(&node.node.id))
                    {
                        continue;
                    }
                    (json!({"type":"resync","snapshot":snapshot}), Some(deadline))
                }
                Err(error) => (mesh_error_event(error), None),
            };
            events.push((subscription.sub_id, subscription.generation, event));
        }
    }
    for (sub_id, generation, (event, retained)) in events {
        // The worker carries withdrawal as typed metadata, without inspecting JSON.
        send_mesh_event(
            sink,
            sub_id,
            &event,
            encode,
            (generation << 1) | u32::from(retained.is_none()),
        )
        .await?;
        match retained {
            Some(deadline) => {
                if let Some(watch) = subscriptions.iter_mut().find(|sub| sub.sub_id == sub_id) {
                    watch.liveness_deadline = deadline;
                }
            }
            None => mesh_remove(subscriptions, sub_id),
        }
    }
    Ok(())
}

/// Builds and sends the first snapshot (or a replacement) of one watch.
///
/// Returns whether the watch stays open and its next liveness deadline. If
/// the user may no longer view the data, an `error` is sent and the watch ends.
/// `kind` is the event type, such as `snapshot`.
async fn send_mesh_snapshot<K>(
    state: &MeshPlugin,
    user_id: &str,
    sub_id: u32,
    subscription: MeshSubscription,
    sink: &mut K,
    encode: &mut Vec<u8>,
    kind: &str,
) -> Result<(bool, Option<i64>), ()>
where
    K: futures_util::Sink<Bytes, Error = ()> + Unpin,
{
    let (event, retained, deadline) = match state
        .mesh
        .list_with_deadline(user_id, subscription.filter, unix_seconds()?)
        .await
    {
        Ok((snapshot, deadline)) => (json!({"type":kind,"snapshot":snapshot}), true, deadline),
        Err(error) => (mesh_error_event(error), false, None),
    };
    // The worker carries withdrawal as typed metadata, without inspecting JSON.
    send_mesh_event(
        sink,
        sub_id,
        &event,
        encode,
        (subscription.generation << 1) | u32::from(!retained),
    )
    .await?;
    Ok((retained, deadline))
}

/// Parses the JSON filter of a Mesh watch, separately from generic topic
/// discovery.
///
/// # Errors
/// Refuses oversized JSON, unknown fields, duplicate fields and other topics.
pub fn parse_subscription(input: &[u8]) -> Result<MeshFilter, MeshApiError> {
    if input.len() > MAX_MESH_FRAME_LEN {
        return Err(MeshApiError::InvalidInput);
    }
    let filter: MeshSubscribeFilter =
        serde_json::from_slice(input).map_err(|_| MeshApiError::InvalidInput)?;
    if filter.topic != "mesh" {
        return Err(MeshApiError::InvalidInput);
    }
    Ok(MeshFilter {
        tag: filter.tag,
        cursor: None,
    })
}
/// Handles one request frame: starts a watch (`Subscribe`) or runs a `mesh.*`
/// action (`Call`). Any other frame, or a wrong stream, is an error that ends
/// the worker.
///
/// Mesh work runs in its own ordered, bounded socket worker [D11]. Slow
/// database writes and subscriber reads must never park the terminal and
/// control dispatch loop.
///
/// A watch is registered before its first snapshot is built, and a bad filter
/// answers with an `error` event that ends the watch. For a call, the result
/// frame is only sent if the socket is still live afterwards, and destructive
/// actions first require a fresh passkey confirmation.
async fn handle_mesh_frame<K>(
    wire: Bytes,
    state: &MeshPlugin,
    user_id: &str,
    host: &dyn SocketHost,
    mesh_subscriptions: &mut Vec<MeshSubscription>,
    sink: &mut K,
    encode: &mut Vec<u8>,
) -> Result<(), ()>
where
    K: futures_util::Sink<Bytes, Error = ()> + Unpin,
{
    let decoded = decode_muxed_frame(&wire).map_err(|_| ())?;
    let stream_id = decoded.stream_id;
    match decoded.frame {
        Frame::Subscribe {
            sub_id,
            filter_json,
        } if stream_id != CONTROL_STREAM && stream_id & 1 == 0 => {
            let generation = stream_id >> 1;
            mesh_remove(mesh_subscriptions, sub_id);
            if let Ok(filter) = parse_subscription(filter_json) {
                let subscription = MeshSubscription {
                    sub_id,
                    filter,
                    generation,
                    liveness_deadline: None,
                };
                // The worker cannot process updates while assembling this snapshot.
                // Dispatch drops superseded output; its registry bounds all admission.
                mesh_subscriptions.push(subscription.clone());
                let (retained, deadline) = send_mesh_snapshot(
                    state,
                    user_id,
                    sub_id,
                    subscription,
                    sink,
                    encode,
                    "snapshot",
                )
                .await?;
                if retained {
                    if let Some(watch) = mesh_subscriptions
                        .iter_mut()
                        .find(|sub| sub.sub_id == sub_id)
                    {
                        watch.liveness_deadline = deadline;
                    }
                } else {
                    mesh_remove(mesh_subscriptions, sub_id);
                }
                Ok(())
            } else {
                mesh_remove(mesh_subscriptions, sub_id);
                send_mesh_event(
                    sink,
                    sub_id,
                    &mesh_error_event(MeshApiError::InvalidInput),
                    encode,
                    (generation << 1) | 1,
                )
                .await
            }
        }
        Frame::Call {
            call_id,
            action_id,
            input_json,
        } if stream_id == CONTROL_STREAM && action_id.starts_with("mesh.") => {
            let now = unix_seconds()?;
            // Destructive policy and inventory edits need the same fresh passkey
            // authority as account changes [28]; an unlocked socket alone is insufficient.
            let requires_fresh = DESCRIPTOR
                .actions
                .iter()
                .find(|action| action.id == action_id)
                .is_some_and(|action| action.effect == Effect::Destructive);
            let service = if requires_fresh {
                state
                    .mesh
                    .with_fresh_authority(host.token_hash().to_owned())
            } else {
                state.mesh.clone()
            };
            let value = if requires_fresh && !host.fresh(now).await {
                Err(MeshApiError::FreshRequired)
            } else {
                service.execute(user_id, action_id, input_json, now).await
            };
            if !host.live().await {
                return Err(());
            }
            match value {
                Ok(value) => {
                    let json = serde_json::to_vec(&value).map_err(|_| ())?;
                    send_frame(
                        sink,
                        CONTROL_STREAM,
                        &Frame::Result {
                            call_id,
                            ok: true,
                            json: &json,
                        },
                        encode,
                    )
                    .await
                }
                Err(error) => {
                    send_frame(
                        sink,
                        CONTROL_STREAM,
                        &Frame::Result {
                            call_id,
                            ok: false,
                            json: error.wire_error(),
                        },
                        encode,
                    )
                    .await
                }
            }
        }
        _ => Err(()),
    }
}

/// Encodes `frame` and queues it for the socket. The queueing itself may wait at
/// most one second; the host owns the deadline for the actual socket write.
async fn send_frame<K>(
    sink: &mut K,
    stream_id: u32,
    frame: &Frame<'_>,
    encode: &mut Vec<u8>,
) -> Result<(), ()>
where
    K: futures_util::Sink<Bytes, Error = ()> + Unpin,
{
    encode_muxed_frame_into(stream_id, frame, encode).map_err(|_| ())?;
    tokio::time::timeout(
        Duration::from_secs(1),
        sink.send(Bytes::copy_from_slice(encode)),
    )
    .await
    .map_err(|_| ())?
}
/// The current Unix time in seconds, or `Err` if the clock is before 1970 or out
/// of range.
fn unix_seconds() -> Result<i64, ()> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs(),
    )
    .map_err(|_| ())
}
