//! Drives crash-safe `WireGuard` key rotation from authenticated node channels [163,166], #285.

use crate::{
    api::MeshService,
    dataplane::Identity,
    policy::model::PublicKey,
    store::{RotationPhase, RotationRecord, Store},
};
use infraternal_plugin_api::node_channel::NodeChannel;
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const OVERLAP_NANOS: i64 = 120_000_000_000;
const RETRY: Duration = Duration::from_secs(5);

/// Kernel clocks and the Linux boot ID keep schedule cadence and overlap independent of wall steps.
#[derive(Clone, Debug)]
struct Clock {
    wall_secs: i64,
    boot_id: String,
    monotonic_secs: i64,
    monotonic_nanos: i64,
}

impl Clock {
    fn read() -> io::Result<Self> {
        let wall_secs = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_secs(),
        )
        .map_err(io::Error::other)?;
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned();
        if boot_id.len() != 36 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let monotonic = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
            .map_err(io::Error::other)?;
        let monotonic_secs = monotonic.tv_sec();
        let monotonic_nanos = monotonic_secs
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(monotonic.tv_nsec()))
            .ok_or(io::ErrorKind::InvalidData)?;
        Ok(Self {
            wall_secs,
            boot_id,
            monotonic_secs,
            monotonic_nanos,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyReply {
    public_key: PublicKey,
}

/// Advance one node's durable rotation state. `None` sleeps until an external event or schedule deadline.
pub(crate) async fn drive(
    store: &Store,
    service: &MeshService,
    channel: &dyn NodeChannel,
    node: infraternal_mesh::model::NodeId,
    identity: &Identity,
    live: &BTreeSet<infraternal_mesh::model::NodeId>,
) -> Option<Duration> {
    let Ok(clock) = Clock::read() else {
        return Some(RETRY);
    };
    let Ok(schedule) = store
        .rotation_schedule(
            node,
            clock.wall_secs,
            &clock.boot_id,
            clock.monotonic_secs,
            clock.monotonic_nanos,
        )
        .await
    else {
        return Some(RETRY);
    };
    if !identity.key_rotation || !schedule.supported {
        return None;
    }

    let Some(record) = schedule.record else {
        return start_due_rotation(
            store,
            service,
            channel,
            node,
            schedule.all_nodes_supported,
            schedule.due_in_secs,
            &clock,
        )
        .await;
    };

    match record.phase {
        RotationPhase::Preparing => {
            Some(run_preparation(store, service, channel, node, &record, &clock).await)
        }
        RotationPhase::Overlap => {
            advance_overlap(store, service, channel, node, &record, &clock, live).await
        }
        RotationPhase::Retiring => advance_retiring(store, service, node, &record, live).await,
        RotationPhase::Cleanup => {
            advance_cleanup(store, service, channel, node, &record, &clock, live).await
        }
    }
}

async fn start_due_rotation(
    store: &Store,
    service: &MeshService,
    channel: &dyn NodeChannel,
    node: infraternal_mesh::model::NodeId,
    all_nodes_supported: bool,
    due_in_secs: u64,
    clock: &Clock,
) -> Option<Duration> {
    if !all_nodes_supported {
        return None;
    }
    if due_in_secs > 0 {
        return Some(Duration::from_secs(due_in_secs));
    }
    match store
        .begin_rotation(node, &clock.boot_id, clock.monotonic_secs)
        .await
    {
        Ok(Some(record)) => {
            Some(run_preparation(store, service, channel, node, &record, clock).await)
        }
        Ok(None) | Err(_) => Some(RETRY),
    }
}

async fn advance_overlap(
    store: &Store,
    service: &MeshService,
    channel: &dyn NodeChannel,
    node: infraternal_mesh::model::NodeId,
    record: &RotationRecord,
    clock: &Clock,
    live: &BTreeSet<infraternal_mesh::model::NodeId>,
) -> Option<Duration> {
    let Some(started) = record.monotonic else {
        return Some(RETRY);
    };
    let remaining =
        OVERLAP_NANOS.saturating_sub(clock.monotonic_nanos.saturating_sub(started).max(0));
    if remaining > 0 {
        return Some(Duration::from_nanos(
            u64::try_from(remaining).unwrap_or(u64::MAX),
        ));
    }
    let Some(revision) = record.revision else {
        return Some(RETRY);
    };
    let Ok(reachable) = store.rotation_reachable_peers(node, live).await else {
        return Some(RETRY);
    };
    if !matches!(
        store.rotation_acks_ready(revision, &reachable).await,
        Ok(true)
    ) {
        return None;
    }
    let input = operation_input(record);
    let reply = match channel.call("mesh.rotation.commit", input).await {
        Ok(reply) => serde_json::from_slice::<KeyReply>(&reply).ok(),
        Err(_) => None,
    };
    let Some(reply) = reply else {
        return Some(RETRY);
    };
    if !store
        .rotation_candidate_key(node)
        .await
        .is_ok_and(|candidate| candidate == reply.public_key)
    {
        return Some(RETRY);
    }
    match store.commit_rotation(node, &record.operation_id).await {
        Ok(_) => {
            service.invalidate_dataplane().await;
            Some(Duration::ZERO)
        }
        Err(_) => Some(RETRY),
    }
}

async fn advance_retiring(
    store: &Store,
    service: &MeshService,
    node: infraternal_mesh::model::NodeId,
    record: &RotationRecord,
    live: &BTreeSet<infraternal_mesh::model::NodeId>,
) -> Option<Duration> {
    let Some(revision) = record.revision else {
        return Some(RETRY);
    };
    let Ok(reachable) = store.rotation_reachable_peers(node, live).await else {
        return Some(RETRY);
    };
    if !matches!(
        store.rotation_acks_ready(revision, &reachable).await,
        Ok(true)
    ) {
        return None;
    }
    match store
        .begin_rotation_cleanup(node, &record.operation_id)
        .await
    {
        Ok(_) => {
            service.invalidate_dataplane().await;
            Some(Duration::ZERO)
        }
        Err(_) => Some(RETRY),
    }
}

async fn advance_cleanup(
    store: &Store,
    service: &MeshService,
    channel: &dyn NodeChannel,
    node: infraternal_mesh::model::NodeId,
    record: &RotationRecord,
    clock: &Clock,
    live: &BTreeSet<infraternal_mesh::model::NodeId>,
) -> Option<Duration> {
    let Some(revision) = record.revision else {
        return Some(RETRY);
    };
    let Ok(reachable) = store.rotation_reachable_peers(node, live).await else {
        return Some(RETRY);
    };
    if !matches!(
        store.rotation_acks_ready(revision, &reachable).await,
        Ok(true)
    ) {
        return None;
    }
    if channel
        .call("mesh.rotation.finish", operation_input(record))
        .await
        .is_err()
    {
        return Some(RETRY);
    }
    match store
        .finish_rotation(
            node,
            &record.operation_id,
            clock.wall_secs,
            &clock.boot_id,
            clock.monotonic_secs,
        )
        .await
    {
        Ok(()) => {
            service.invalidate_dataplane().await;
            Some(Duration::ZERO)
        }
        Err(_) => Some(RETRY),
    }
}

async fn run_preparation(
    store: &Store,
    service: &MeshService,
    channel: &dyn NodeChannel,
    node: infraternal_mesh::model::NodeId,
    record: &RotationRecord,
    clock: &Clock,
) -> Duration {
    let reply = match channel
        .call("mesh.rotation.prepare", operation_input(record))
        .await
    {
        Ok(reply) => serde_json::from_slice::<KeyReply>(&reply).ok(),
        Err(_) => None,
    };
    let Some(reply) = reply else {
        return RETRY;
    };
    if reply.public_key == PublicKey([0; 32]) {
        return RETRY;
    }
    match store
        .start_rotation_overlap(
            node,
            &record.operation_id,
            reply.public_key,
            clock.wall_secs,
            &clock.boot_id,
            clock.monotonic_nanos,
        )
        .await
    {
        Ok(_) => {
            service.invalidate_dataplane().await;
            Duration::ZERO
        }
        Err(_) => RETRY,
    }
}

fn operation_input(record: &RotationRecord) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "operation_id": record.operation_id,
        "sequence": record.sequence,
    }))
    .unwrap_or_default()
}
