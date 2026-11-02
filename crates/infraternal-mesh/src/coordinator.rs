//! Indexed coordination: mutations visit grant expansions or incident peers, never every rule/node.
//! Slice 2 persists inventory/settings/allocation and transports these plain messages atomically.
use crate::{
    address::{AddressAllocator, Route},
    model::{Addresses, MeshError, MeshSettings, Node, NodeId, PublicKey},
    names::{NameDiff, NameTable},
    rules::{Arrow, Endpoint, RuleId, TrafficPolicy},
    view::{Peer, PeerDiff, PeerKeys, PeerView},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[path = "coordinator/checkpoint.rs"]
mod checkpoint;
pub use checkpoint::{CoordinatorCheckpoint, MemberCheckpoint};

/// Minimum overlap; retirement additionally waits for every current peer's delivery acknowledgement.
pub const KEY_OVERLAP_SECS: u64 = 120;

/// Peer messages are individually targeted. DNS deltas go to every subscribed mesh resolver.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub peers: BTreeMap<NodeId, PeerDiff>,
    pub names: NameDiff,
    /// Local public-key state instructions; corresponding private keys stay on the addressed node.
    pub local_keys: BTreeMap<NodeId, PeerKeys>,
}

#[derive(Clone, Debug)]
struct Member {
    node: Node,
    addresses: Addresses,
    keys: PeerKeys,
    retire_after: Option<u64>,
}

type Pair = (NodeId, NodeId);

/// In-memory source of truth. Neither transport availability nor elapsed time expires a local view.
#[derive(Debug)]
pub struct Coordinator {
    settings: MeshSettings,
    server: NodeId,
    members: BTreeMap<NodeId, Member>,
    allocator: AddressAllocator,
    names: NameTable,
    rules: BTreeMap<RuleId, Arrow>,
    tags: BTreeMap<String, BTreeSet<NodeId>>,
    endpoint_rules: BTreeMap<Endpoint, BTreeSet<RuleId>>,
    // Directed pairs retain rule IDs, not cloned policies. Most pairs have one grant; a vector
    // avoids a minimum-sized tree allocation per pair (measured at 200k arrows, D167).
    // Keeping each ID preserves overlapping grants when one rule is removed.
    grants: BTreeMap<Pair, Vec<RuleId>>,
    views: BTreeMap<NodeId, PeerView>,
    keys: BTreeMap<PublicKey, NodeId>,
    acknowledged: BTreeMap<NodeId, u64>,
    generation: u64,
}
impl Coordinator {
    /// # Errors
    /// Rejects invalid settings/routes or an invalid server identity/name.
    pub fn new(settings: MeshSettings, routes: &[Route], server: Node) -> Result<Self, MeshError> {
        let allocator = AddressAllocator::new(settings.clone(), routes)?;
        let names = NameTable::new(settings.dns_suffix.clone())?;
        let server_id = server.id;
        let mut coordinator = Self {
            settings,
            server: server_id,
            members: BTreeMap::new(),
            allocator,
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
        coordinator.join(server)?;
        Ok(coordinator)
    }
    #[must_use]
    pub fn settings(&self) -> &MeshSettings {
        &self.settings
    }
    #[must_use]
    pub fn names(&self) -> &NameTable {
        &self.names
    }
    #[must_use]
    pub fn view(&self, node: NodeId) -> Option<&PeerView> {
        self.views.get(&node)
    }
    #[must_use]
    pub fn views(&self) -> &BTreeMap<NodeId, PeerView> {
        &self.views
    }
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.members.len()
    }

    fn endpoint(&self, endpoint: &Endpoint) -> BTreeSet<NodeId> {
        match endpoint {
            Endpoint::Node(id) => self
                .members
                .contains_key(id)
                .then_some(*id)
                .into_iter()
                .collect(),
            Endpoint::Tag(tag) => self.tags.get(tag).cloned().unwrap_or_default(),
            Endpoint::User(_) => BTreeSet::new(),
        }
    }
    fn pairs(&self, arrow: &Arrow) -> BTreeSet<Pair> {
        let mut pairs = BTreeSet::new();
        for from in self.endpoint(&arrow.from) {
            for to in self.endpoint(&arrow.to) {
                if from != to {
                    pairs.insert((from, to));
                    if arrow.both_ways {
                        pairs.insert((to, from));
                    }
                }
            }
        }
        pairs
    }
    fn endpoint_contains(&self, endpoint: &Endpoint, id: NodeId) -> bool {
        match endpoint {
            Endpoint::Node(node) => *node == id && self.members.contains_key(&id),
            Endpoint::Tag(tag) => self.tags.get(tag).is_some_and(|nodes| nodes.contains(&id)),
            Endpoint::User(_) => false,
        }
    }
    fn incident_pairs(&self, arrow: &Arrow, id: NodeId) -> BTreeSet<Pair> {
        let mut pairs = BTreeSet::new();
        // Treat source and destination separately: equal tag endpoints still grant both ordered pairs.
        for (source, target, forward) in [
            (&arrow.from, &arrow.to, true),
            (&arrow.to, &arrow.from, false),
        ] {
            if !self.endpoint_contains(source, id) {
                continue;
            }
            for other in self.endpoint(target) {
                if other == id {
                    continue;
                }
                pairs.insert(if forward { (id, other) } else { (other, id) });
                if arrow.both_ways {
                    pairs.insert(if forward { (other, id) } else { (id, other) });
                }
            }
        }
        pairs
    }
    fn policy(&self, from: NodeId, to: NodeId) -> TrafficPolicy {
        // Every node can initiate to the server even without an arrow (D164).
        if to == self.server {
            return TrafficPolicy::All;
        }
        let mut policy = TrafficPolicy::None;
        if let Some(grants) = self.grants.get(&(from, to)) {
            for id in grants {
                if let Some(arrow) = self.rules.get(id) {
                    policy.union(&arrow.ports);
                }
            }
        }
        policy
    }
    fn peer(&self, owner: NodeId, other: NodeId) -> Option<Peer> {
        let member = self.members.get(&other)?;
        let outbound = self.policy(owner, other);
        let inbound = self.policy(other, owner);
        if inbound == TrafficPolicy::None && outbound == TrafficPolicy::None {
            return None;
        }
        Some(Peer {
            node: other,
            keys: member.keys.clone(),
            allowed_ips: member.addresses,
            inbound,
            outbound,
        })
    }
    fn ensure_generation(&self) -> Result<(), MeshError> {
        self.generation
            .checked_add(1)
            .ok_or(MeshError::VersionExhausted)
            .map(|_| ())
    }
    fn refresh(&mut self, pairs: BTreeSet<Pair>) -> Change {
        // Every mutating caller reserves counter capacity before changing source state.
        self.generation += 1;
        let mut change = Change::default();
        for (a, b) in pairs {
            for (owner, other) in [(a, b), (b, a)] {
                if !self.members.contains_key(&owner) {
                    continue;
                }
                let next = self.peer(owner, other);
                let Some(view) = self.views.get_mut(&owner) else {
                    continue;
                };
                if view.peers.get(&other) == next.as_ref() {
                    continue;
                }
                let diff = change.peers.entry(owner).or_insert_with(|| PeerDiff {
                    node: owner,
                    from_version: view.rule_version,
                    to_version: self.generation,
                    removed: Vec::new(),
                    upserted: BTreeMap::new(),
                });
                if let Some(peer) = next {
                    view.peers.insert(other, peer.clone());
                    diff.upserted.insert(other, peer);
                } else {
                    view.peers.remove(&other);
                    diff.removed.push(other);
                }
                view.rule_version = self.generation;
            }
        }
        change
    }
    fn canonical(pair: Pair) -> Pair {
        if pair.0 < pair.1 {
            pair
        } else {
            (pair.1, pair.0)
        }
    }
    fn put_grants(&mut self, arrow: &Arrow, pairs: &BTreeSet<Pair>) {
        for pair in pairs {
            let grants = self.grants.entry(*pair).or_default();
            if !grants.contains(&arrow.id) {
                grants.push(arrow.id);
            }
        }
    }
    fn drop_grants(&mut self, id: RuleId, pairs: &BTreeSet<Pair>) {
        for pair in pairs {
            if let Some(grants) = self.grants.get_mut(pair) {
                grants.retain(|rule| *rule != id);
                if grants.is_empty() {
                    self.grants.remove(pair);
                }
            }
        }
    }
    fn index_member(&mut self, node: &Node) {
        for tag in &node.tags {
            self.tags.entry(tag.clone()).or_default().insert(node.id);
        }
    }
    fn unindex_member(&mut self, node: &Node) {
        for tag in &node.tags {
            if let Some(members) = self.tags.get_mut(tag) {
                members.remove(&node.id);
                if members.is_empty() {
                    self.tags.remove(tag);
                }
            }
        }
    }
    fn member_rules(&self, node: &Node) -> BTreeSet<RuleId> {
        let mut result = self
            .endpoint_rules
            .get(&Endpoint::Node(node.id))
            .cloned()
            .unwrap_or_default();
        for tag in &node.tags {
            if let Some(rules) = self.endpoint_rules.get(&Endpoint::Tag(tag.clone())) {
                result.extend(rules);
            }
        }
        result
    }

    /// Joining is automatic; new nodes get only server reachability and existing matching grants.
    /// # Errors
    /// Rejects duplicate identities/keys/names, invalid names, and exhausted ranges.
    pub fn join(&mut self, node: Node) -> Result<Change, MeshError> {
        self.ensure_generation()?;
        if self.members.contains_key(&node.id) {
            return Err(MeshError::DuplicateNode);
        }
        if self.keys.contains_key(&node.public_key) {
            return Err(MeshError::DuplicateKey);
        }
        self.names.check_host(node.id, &node.host)?;
        let addresses = self.allocator.allocate(node.id)?;
        let names = self.names.upsert(node.id, node.host.clone(), addresses)?;
        let id = node.id;
        let matching_rules = self.member_rules(&node);
        self.index_member(&node);
        self.keys.insert(node.public_key, id);
        self.members.insert(
            id,
            Member {
                keys: PeerKeys {
                    current: node.public_key,
                    previous: None,
                },
                node,
                addresses,
                retire_after: None,
            },
        );
        self.views.insert(id, PeerView::empty(id));
        let mut dirty = BTreeSet::new();
        if id != self.server {
            dirty.insert(Self::canonical((id, self.server)));
        }
        for rule in matching_rules {
            if let Some(arrow) = self.rules.get(&rule).cloned() {
                // Only new pairs can change at join, even for a large tag-to-tag grant.
                let pairs = self.incident_pairs(&arrow, id);
                self.put_grants(&arrow, &pairs);
                dirty.extend(pairs.into_iter().map(Self::canonical));
            }
        }
        let mut change = self.refresh(dirty);
        change.names = names;
        Ok(change)
    }

    fn validate_arrow_endpoints(&self, arrow: &Arrow) -> Result<(), MeshError> {
        arrow.validate()?;
        for endpoint in [&arrow.from, &arrow.to] {
            if let Endpoint::Node(id) = endpoint
                && !self.members.contains_key(id)
            {
                return Err(MeshError::UnknownNode);
            }
        }
        Ok(())
    }
    /// # Errors
    /// Rejects invalid grants, duplicate rule IDs, or unknown node endpoints.
    pub fn add_arrow(&mut self, arrow: Arrow) -> Result<Change, MeshError> {
        self.ensure_generation()?;
        self.validate_arrow_endpoints(&arrow)?;
        if self.rules.contains_key(&arrow.id) {
            return Err(MeshError::DuplicateRule);
        }
        let pairs = self.pairs(&arrow);
        self.put_grants(&arrow, &pairs);
        for endpoint in [&arrow.from, &arrow.to] {
            self.endpoint_rules
                .entry(endpoint.clone())
                .or_default()
                .insert(arrow.id);
        }
        self.rules.insert(arrow.id, arrow);
        Ok(self.refresh(pairs.into_iter().map(Self::canonical).collect()))
    }
    /// Replace a grant atomically, emitting the union of genuinely changed incident peer entries.
    /// # Errors
    /// Rejects unknown rules, invalid grants/endpoints, or an exhausted version counter before mutation.
    pub fn replace_arrow(&mut self, arrow: Arrow) -> Result<Change, MeshError> {
        self.ensure_generation()?;
        self.validate_arrow_endpoints(&arrow)?;
        let old = self
            .rules
            .get(&arrow.id)
            .ok_or(MeshError::UnknownRule)?
            .clone();
        let old_pairs = self.pairs(&old);
        let new_pairs = self.pairs(&arrow);
        self.drop_grants(old.id, &old_pairs);
        self.put_grants(&arrow, &new_pairs);
        for endpoint in [&old.from, &old.to] {
            if let Some(rules) = self.endpoint_rules.get_mut(endpoint) {
                rules.remove(&old.id);
                if rules.is_empty() {
                    self.endpoint_rules.remove(endpoint);
                }
            }
        }
        for endpoint in [&arrow.from, &arrow.to] {
            self.endpoint_rules
                .entry(endpoint.clone())
                .or_default()
                .insert(arrow.id);
        }
        self.rules.insert(arrow.id, arrow);
        Ok(self.refresh(
            old_pairs
                .into_iter()
                .chain(new_pairs)
                .map(Self::canonical)
                .collect(),
        ))
    }
    /// # Errors
    /// Returns `UnknownRule` for a missing rule.
    pub fn remove_arrow(&mut self, id: RuleId) -> Result<Change, MeshError> {
        self.ensure_generation()?;
        let arrow = self.rules.remove(&id).ok_or(MeshError::UnknownRule)?;
        let pairs = self.pairs(&arrow);
        self.drop_grants(id, &pairs);
        for endpoint in [&arrow.from, &arrow.to] {
            if let Some(rules) = self.endpoint_rules.get_mut(endpoint) {
                rules.remove(&id);
                if rules.is_empty() {
                    self.endpoint_rules.remove(endpoint);
                }
            }
        }
        Ok(self.refresh(pairs.into_iter().map(Self::canonical).collect()))
    }
    /// # Errors
    /// Rejects server removal and unknown membership.
    pub fn remove_node(&mut self, id: NodeId) -> Result<Change, MeshError> {
        self.ensure_generation()?;
        if id == self.server {
            return Err(MeshError::RemoveServer);
        }
        let member = self.members.remove(&id).ok_or(MeshError::UnknownNode)?;
        self.unindex_member(&member.node);
        self.keys.remove(&member.keys.current);
        if let Some(previous) = member.keys.previous {
            self.keys.remove(&previous);
        }
        self.allocator.remove(id);
        self.acknowledged.remove(&id);
        let old_view = self.views.remove(&id).ok_or(MeshError::UnknownNode)?;
        let dirty: BTreeSet<_> = old_view
            .peers
            .keys()
            .map(|other| Self::canonical((id, *other)))
            .collect();
        for other in old_view.peers.keys() {
            self.grants.remove(&(id, *other));
            self.grants.remove(&(*other, id));
        }
        let mut change = self.refresh(dirty);
        change.names = self.names.remove(id);
        Ok(change)
    }
    /// # Errors
    /// Returns `UnknownNode` for a missing member.
    pub fn set_tags(&mut self, id: NodeId, tags: BTreeSet<String>) -> Result<Change, MeshError> {
        self.ensure_generation()?;
        let old_node = self
            .members
            .get(&id)
            .ok_or(MeshError::UnknownNode)?
            .node
            .clone();
        let mut next_node = old_node.clone();
        next_node.tags = tags;
        let mut rules = self.member_rules(&old_node);
        rules.extend(self.member_rules(&next_node));
        let mut dirty = BTreeSet::new();
        // Tag edits visit only rules that refer to an old or new tag of this node.
        let arrows: Vec<_> = rules
            .iter()
            .filter_map(|id| self.rules.get(id).cloned())
            .collect();
        for arrow in &arrows {
            let pairs: BTreeSet<_> = self.incident_pairs(arrow, id);
            self.drop_grants(arrow.id, &pairs);
            dirty.extend(pairs.into_iter().map(Self::canonical));
        }
        self.unindex_member(&old_node);
        self.index_member(&next_node);
        if let Some(member) = self.members.get_mut(&id) {
            member.node = next_node;
        }
        for arrow in &arrows {
            let pairs: BTreeSet<_> = self.incident_pairs(arrow, id);
            self.put_grants(arrow, &pairs);
            dirty.extend(pairs.into_iter().map(Self::canonical));
        }
        Ok(self.refresh(dirty))
    }
    /// # Errors
    /// Rejects unknown nodes and invalid or duplicate names.
    pub fn rename(&mut self, id: NodeId, host: String) -> Result<Change, MeshError> {
        let member = self.members.get_mut(&id).ok_or(MeshError::UnknownNode)?;
        let names = self.names.upsert(id, host.clone(), member.addresses)?;
        member.node.host = host;
        Ok(Change {
            names,
            ..Change::default()
        })
    }
    /// # Errors
    /// Rejects invalid suffixes or oversized resulting names.
    pub fn set_suffix(&mut self, suffix: String) -> Result<Change, MeshError> {
        let names = self.names.set_suffix(suffix.clone())?;
        self.settings.dns_suffix = suffix;
        self.settings.dns_suffix_is_explicit = true;
        Ok(Change {
            names,
            ..Change::default()
        })
    }
    /// Caller has installed its new private key locally BEFORE presenting the new public key.
    /// `now_secs` is a monotonic deployment clock. Retirement requires elapsed overlap and delivery.
    /// # Errors
    /// Rejects unknown nodes, duplicate keys, overlapping rotations, and unrepresentable deadlines.
    pub fn rotate_key(
        &mut self,
        id: NodeId,
        key: PublicKey,
        now_secs: u64,
    ) -> Result<Change, MeshError> {
        self.ensure_generation()?;
        let member = self.members.get(&id).ok_or(MeshError::UnknownNode)?;
        if member.retire_after.is_some() {
            return Err(MeshError::RotationInProgress);
        }
        if self.keys.contains_key(&key) {
            return Err(MeshError::DuplicateKey);
        }
        // Reject overflow before any mutation: saturation would shorten the mandatory overlap.
        let retire_after = now_secs
            .checked_add(KEY_OVERLAP_SECS)
            .ok_or(MeshError::ClockExhausted)?;
        if let Some(member) = self.members.get_mut(&id) {
            member.keys.previous = Some(member.keys.current);
            member.keys.current = key;
            member.node.public_key = key;
            member.retire_after = Some(retire_after);
        }
        self.keys.insert(key, id);
        let dirty = self
            .views
            .get(&id)
            .map(|view| {
                view.peers
                    .keys()
                    .map(|other| Self::canonical((id, *other)))
                    .collect()
            })
            .unwrap_or_default();
        let mut change = self.refresh(dirty);
        if let Some(member) = self.members.get(&id) {
            change.local_keys.insert(id, member.keys.clone());
        }
        Ok(change)
    }
    /// Acknowledgements refer to successfully applied peer views, never just transport receipt.
    /// # Errors
    /// Rejects unknown nodes and acknowledgements beyond the desired version.
    pub fn acknowledge(&mut self, id: NodeId, version: u64) -> Result<(), MeshError> {
        let desired = self
            .views
            .get(&id)
            .ok_or(MeshError::UnknownNode)?
            .rule_version;
        if version > desired {
            return Err(MeshError::StaleDiff);
        }
        let acknowledged = self.acknowledged.entry(id).or_default();
        *acknowledged = (*acknowledged).max(version);
        Ok(())
    }
    #[must_use]
    pub fn is_behind(&self, id: NodeId) -> Option<bool> {
        self.views
            .get(&id)
            .map(|view| self.acknowledged.get(&id).copied().unwrap_or(0) < view.rule_version)
    }
    /// Explicit coordinator action only: offline local views never expire keys or policies.
    /// # Errors
    /// Returns `UnknownNode` for a missing member.
    pub fn finish_rotation(&mut self, id: NodeId, now_secs: u64) -> Result<Change, MeshError> {
        let member = self.members.get(&id).ok_or(MeshError::UnknownNode)?;
        let Some(deadline) = member.retire_after else {
            return Ok(Change::default());
        };
        let neighbours = self
            .views
            .get(&id)
            .map(|view| view.peers.keys().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        if now_secs < deadline
            || neighbours
                .iter()
                .any(|peer| self.is_behind(*peer) != Some(false))
        {
            return Ok(Change::default());
        }
        self.ensure_generation()?;
        if let Some(member) = self.members.get_mut(&id) {
            if let Some(old) = member.keys.previous.take() {
                self.keys.remove(&old);
            }
            member.retire_after = None;
        }
        let mut change = self.refresh(
            neighbours
                .into_iter()
                .map(|other| Self::canonical((id, other)))
                .collect(),
        );
        if let Some(member) = self.members.get(&id) {
            change.local_keys.insert(id, member.keys.clone());
        }
        Ok(change)
    }

    /// Retire the previous key after the minimum overlap and acknowledgements from every reachable peer.
    /// Offline peers retain their last compiled view and receive the current key when they reconnect.
    /// # Errors
    /// Returns `UnknownNode` for a missing member or a generation exhaustion error before mutation.
    pub fn finish_rotation_reachable(
        &mut self,
        id: NodeId,
        now_secs: u64,
        reachable: &BTreeSet<NodeId>,
    ) -> Result<Change, MeshError> {
        let member = self.members.get(&id).ok_or(MeshError::UnknownNode)?;
        let Some(deadline) = member.retire_after else {
            return Ok(Change::default());
        };
        let neighbours = self
            .views
            .get(&id)
            .map(|view| view.peers.keys().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        if now_secs < deadline
            || neighbours
                .iter()
                .filter(|peer| reachable.contains(peer))
                .any(|peer| self.is_behind(*peer) != Some(false))
        {
            return Ok(Change::default());
        }
        self.ensure_generation()?;
        if let Some(member) = self.members.get_mut(&id) {
            if let Some(old) = member.keys.previous.take() {
                self.keys.remove(&old);
            }
            member.retire_after = None;
        }
        let mut change = self.refresh(
            neighbours
                .into_iter()
                .map(|other| Self::canonical((id, other)))
                .collect(),
        );
        if let Some(member) = self.members.get(&id) {
            change.local_keys.insert(id, member.keys.clone());
        }
        Ok(change)
    }

    /// Immediately replace a compromised key and discard every overlap reference to it.
    /// # Errors
    /// Rejects an unknown node, a duplicate replacement key, or generation exhaustion before mutation.
    pub fn compromise_key(
        &mut self,
        id: NodeId,
        replacement: PublicKey,
    ) -> Result<Change, MeshError> {
        let member = self.members.get(&id).ok_or(MeshError::UnknownNode)?;
        if replacement == member.keys.current {
            return Ok(Change::default());
        }
        if self.keys.contains_key(&replacement) {
            return Err(MeshError::DuplicateKey);
        }
        self.ensure_generation()?;
        let neighbours = self
            .views
            .get(&id)
            .map(|view| view.peers.keys().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        let member = self.members.get_mut(&id).ok_or(MeshError::UnknownNode)?;
        self.keys.remove(&member.keys.current);
        if let Some(previous) = member.keys.previous.take() {
            self.keys.remove(&previous);
        }
        member.keys.current = replacement;
        member.node.public_key = replacement;
        member.retire_after = None;
        self.keys.insert(replacement, id);
        let mut change = self.refresh(
            neighbours
                .into_iter()
                .map(|other| Self::canonical((id, other)))
                .collect(),
        );
        if let Some(member) = self.members.get(&id) {
            change.local_keys.insert(id, member.keys.clone());
        }
        Ok(change)
    }

    /// Independent reference compiler and reconnect snapshot. It does not consult the grant index.
    #[must_use]
    pub fn full_compile(&self) -> BTreeMap<NodeId, PeerView> {
        let mut policies: BTreeMap<Pair, TrafficPolicy> = BTreeMap::new();
        for arrow in self.rules.values() {
            for pair in self.pairs(arrow) {
                policies.entry(pair).or_default().union(&arrow.ports);
            }
        }
        for id in self.members.keys() {
            if *id != self.server {
                policies.insert((*id, self.server), TrafficPolicy::All);
            }
        }
        let mut views: BTreeMap<_, _> = self
            .members
            .keys()
            .map(|id| {
                (
                    *id,
                    PeerView {
                        node: *id,
                        rule_version: self.views.get(id).map_or(0, |view| view.rule_version),
                        peers: BTreeMap::new(),
                    },
                )
            })
            .collect();
        let pairs: BTreeSet<_> = policies.keys().copied().map(Self::canonical).collect();
        for (a, b) in pairs {
            for (owner, other) in [(a, b), (b, a)] {
                if let (Some(member), Some(view)) =
                    (self.members.get(&other), views.get_mut(&owner))
                {
                    view.peers.insert(
                        other,
                        Peer {
                            node: other,
                            keys: member.keys.clone(),
                            allowed_ips: member.addresses,
                            inbound: policies.get(&(other, owner)).cloned().unwrap_or_default(),
                            outbound: policies.get(&(owner, other)).cloned().unwrap_or_default(),
                        },
                    );
                }
            }
        }
        views
    }
}
