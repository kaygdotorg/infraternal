//! Public-only persistence boundary: validate canonical inputs and rebuild all derived coordinator indices.
use super::Coordinator;
use crate::{
    address::{AddressAllocator, Route},
    model::{MeshError, MeshSettings, Node, NodeId},
    names::NameTable,
    rules::Arrow,
    view::PeerKeys,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
/// Public-only checkpoint; derived indices/views are rebuilt and acknowledgements are re-established.
/// Persistence belongs to slice 2. Save atomically before publishing diffs to avoid identity changes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoordinatorCheckpoint {
    pub settings: MeshSettings,
    pub server: NodeId,
    pub allocation: AddressAllocator,
    pub members: Vec<MemberCheckpoint>,
    pub rules: Vec<Arrow>,
    pub desired_versions: BTreeMap<NodeId, u64>,
    pub generation: u64,
}

/// Retained public rotation state. The node independently persists both corresponding private keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberCheckpoint {
    pub node: Node,
    pub keys: PeerKeys,
    pub retire_after: Option<u64>,
}

impl Coordinator {
    #[must_use]
    pub fn checkpoint(&self) -> CoordinatorCheckpoint {
        CoordinatorCheckpoint {
            settings: self.settings.clone(),
            server: self.server,
            allocation: self.allocator.clone(),
            members: self
                .members
                .values()
                .map(|member| MemberCheckpoint {
                    node: member.node.clone(),
                    keys: member.keys.clone(),
                    retire_after: member.retire_after,
                })
                .collect(),
            rules: self.rules.values().cloned().collect(),
            desired_versions: self
                .views
                .iter()
                .map(|(id, view)| (*id, view.rule_version))
                .collect(),
            generation: self.generation,
        }
    }
    /// Restore canonical inputs, stable addresses and public overlaps without trusting derived indices.
    /// Acknowledgements intentionally reset: every node confirms its applied view after reconnect.
    /// # Errors
    /// Rejects invalid settings/routes, mismatched allocation, duplicate identities/keys/names/rules,
    /// inconsistent rotation state, absent server membership, or impossible desired versions.
    pub fn restore(checkpoint: CoordinatorCheckpoint, routes: &[Route]) -> Result<Self, MeshError> {
        // Allocation depends only on address settings. DNS and rotation policy may change
        // independently without invalidating stable addresses from the original allocation.
        if checkpoint.settings.ipv4 != checkpoint.allocation.settings().ipv4
            || checkpoint.settings.ula_global_id != checkpoint.allocation.settings().ula_global_id
            || checkpoint.members.len() != checkpoint.allocation.assigned_count()
            || checkpoint.members.len() != checkpoint.desired_versions.len()
            || !checkpoint
                .members
                .iter()
                .any(|member| member.node.id == checkpoint.server)
            || checkpoint
                .desired_versions
                .values()
                .any(|version| *version > checkpoint.generation)
        {
            return Err(MeshError::InvalidCheckpoint);
        }
        if !crate::address::conflicts(&checkpoint.settings, routes)?.is_empty() {
            return Err(MeshError::RouteOverlap);
        }
        let names = NameTable::new(checkpoint.settings.dns_suffix.clone())?;
        let mut state = Self {
            settings: checkpoint.settings,
            server: checkpoint.server,
            members: BTreeMap::new(),
            allocator: checkpoint.allocation,
            names,
            rules: BTreeMap::new(),
            tags: BTreeMap::new(),
            endpoint_rules: BTreeMap::new(),
            grants: BTreeMap::new(),
            views: BTreeMap::new(),
            keys: BTreeMap::new(),
            acknowledged: BTreeMap::new(),
            generation: 0,
        };
        let mut rotations = Vec::new();
        // Server first ensures automatic server reachability when replaying other memberships.
        let mut members = checkpoint.members;
        members.sort_by_key(|member| (member.node.id != state.server, member.node.id));
        for member in members {
            if state.allocator.get(member.node.id).is_none()
                || member.node.public_key != member.keys.current
                || member.keys.previous.is_some() != member.retire_after.is_some()
            {
                return Err(MeshError::InvalidCheckpoint);
            }
            rotations.push((member.node.id, member.keys, member.retire_after));
            state.join(member.node)?;
        }
        for (id, keys, deadline) in rotations {
            if let Some(previous) = keys.previous
                && state.keys.insert(previous, id).is_some()
            {
                return Err(MeshError::DuplicateKey);
            }
            if let Some(member) = state.members.get_mut(&id) {
                member.keys = keys;
                member.retire_after = deadline;
            }
        }
        for arrow in checkpoint.rules {
            arrow.validate()?;
            if state.rules.contains_key(&arrow.id) {
                return Err(MeshError::DuplicateRule);
            }
            // Removed-node endpoints remain dormant until that stable inventory identity rejoins.
            let pairs = state.pairs(&arrow);
            state.put_grants(&arrow, &pairs);
            for endpoint in [&arrow.from, &arrow.to] {
                state
                    .endpoint_rules
                    .entry(endpoint.clone())
                    .or_default()
                    .insert(arrow.id);
            }
            state.rules.insert(arrow.id, arrow);
        }
        state.generation = checkpoint.generation;
        for (id, view) in &mut state.views {
            view.rule_version = *checkpoint
                .desired_versions
                .get(id)
                .ok_or(MeshError::InvalidCheckpoint)?;
        }
        state.views = state.full_compile();
        Ok(state)
    }
}
