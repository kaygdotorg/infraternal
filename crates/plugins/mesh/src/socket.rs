//! Owns Mesh socket calls, scoped live watches and deadline expiry outside terminal dispatch [11,28,198].
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
const CONTROL_STREAM: u32 = 0;
const MAX_MESH_SUBSCRIPTIONS: usize = MAX_SUBSCRIPTIONS;
/// Coordinator implementation; construction is pure and never creates a server [201].
#[derive(Clone)]
pub struct MeshPlugin {
    mesh: MeshService,
    mesh_work: Arc<Semaphore>,
}
impl MeshPlugin {
    /// Bind to an existing server pool, leaving six authority slots in production.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        let capacity = Self::mesh_work_capacity(&pool);
        Self::with_mesh_service(capacity, MeshService::new(pool))
    }

    /// Bind the coordinator's derived DNS default to the server's configured public origin.
    #[must_use]
    pub fn with_public_origin(pool: SqlitePool, public_origin: &str) -> Self {
        let capacity = Self::mesh_work_capacity(&pool);
        Self::with_mesh_service(
            capacity,
            MeshService::with_public_origin(pool, public_origin),
        )
    }

    fn mesh_work_capacity(pool: &SqlitePool) -> usize {
        pool.options()
            .get_max_connections()
            .saturating_sub(2)
            .clamp(1, 2) as usize
    }

    fn with_mesh_service(capacity: usize, mesh: MeshService) -> Self {
        Self {
            mesh,
            mesh_work: Arc::new(Semaphore::new(capacity)),
        }
    }

    /// Share the same revision broadcaster with other server inventory features.
    #[must_use]
    pub fn service(&self) -> MeshService {
        self.mesh.clone()
    }
}
impl Plugin for MeshPlugin {
    fn authority_changed(&self) -> Option<Operation<'_, ()>> {
        Some(Box::pin(self.mesh.invalidate_dataplane()))
    }
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
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

/// The retained filter and its queue-only generation share one installed watch.
#[derive(Clone)]
struct MeshSubscription {
    sub_id: u32,
    filter: MeshFilter,
    generation: u32,
    liveness_deadline: Option<i64>,
}

/// The 32-watch bound makes replacement a bounded scan without hashing/allocation.
fn mesh_remove(subscriptions: &mut Vec<MeshSubscription>, sub_id: u32) {
    if let Some(index) = subscriptions.iter().position(|sub| sub.sub_id == sub_id) {
        subscriptions.swap_remove(index);
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MeshSubscribeFilter {
    topic: String,
    #[serde(default)]
    tag: Option<String>,
}

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

#[allow(clippy::too_many_arguments)]
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
/// The snapshots are read under one shared `mesh_work` permit and sent after it is released: a viewer slow to
/// drain its socket must not hold the permit that host configuration delivery also needs (#236).
#[allow(clippy::too_many_arguments)]
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

/// Initial and resync snapshots share permission/error delivery for one generation.
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

/// Parse the complete Mesh view filter separately from generic topic discovery.
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
#[allow(clippy::too_many_lines)]
// Mesh work runs in its own ordered, bounded socket worker [D11]. Slow database
// writes and subscriber reads must never park the terminal/control dispatch loop.
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

/// Queue only bounded encoded bytes; the host owns the actual socket write deadline.
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
fn unix_seconds() -> Result<i64, ()> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs(),
    )
    .map_err(|_| ())
}
