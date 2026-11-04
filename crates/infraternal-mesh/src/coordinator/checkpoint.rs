//! Saving and restoring a [`Coordinator`].
//!
//! A checkpoint holds only the canonical inputs: settings, membership with
//! public keys, rules and version counters. Everything derived from them
//! (name table, grants, compiled peer views) is rebuilt on restore, never
//! trusted from the file. No private key is ever part of a checkpoint.
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

/// The saved state of a [`Coordinator`], containing public data only.
///
/// Derived indices and views are rebuilt on restore, and delivery
/// acknowledgements start over. Writing it to disk belongs to slice 2. Save it
/// atomically *before* publishing the diffs that depend on it, so a crash can
/// never leave nodes holding addresses the saved state does not know about.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoordinatorCheckpoint {
    /// The deployment settings.
    pub settings: MeshSettings,
    /// The node that is the server. It must also appear in `members`.
    pub server: NodeId,
    /// The address allocator, including its never-reuse counter.
    pub allocation: AddressAllocator,
    /// Every member, the server included.
    pub members: Vec<MemberCheckpoint>,
    /// All policy rules. Rules that mention a removed node are kept and stay
    /// dormant until that node rejoins.
    pub rules: Vec<Arrow>,
    /// The policy version each member should be at. One entry per member,
    /// none above `generation`.
    pub desired_versions: BTreeMap<NodeId, u64>,
    /// The coordinator-wide policy version counter. It only grows.
    pub generation: u64,
}

/// One member in a [`CoordinatorCheckpoint`], with its key rotation state.
///
/// Only public keys are kept here. The node itself stores the matching private
/// keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberCheckpoint {
    /// The member's inventory facts. Its `public_key` must equal `keys.current`.
    pub node: Node,
    /// The keys accepted for the member now.
    pub keys: PeerKeys,
    /// When the previous key stops being accepted, on the deployment clock.
    /// Set exactly when `keys.previous` is set.
    pub retire_after: Option<u64>,
}

impl Coordinator {
    /// Captures the coordinator's current state so it can be saved.
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
    /// Rebuilds a coordinator from a saved checkpoint.
    ///
    /// Addresses and key overlaps are kept exactly as saved. Derived data is
    /// recomputed instead of trusted. Delivery acknowledgements are reset on
    /// purpose: every node confirms the view it has applied after it
    /// reconnects. `routes` are the host's current routes, checked against the
    /// deployment ranges as in [`crate::address::conflicts`].
    ///
    /// # Errors
    /// Rejects invalid settings or routes, an allocation that does not match
    /// the settings or members, duplicate identities, keys, names or rules,
    /// inconsistent rotation state, a missing server, and desired versions
    /// that cannot exist.
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
