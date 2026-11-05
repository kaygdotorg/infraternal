//! Packs access-only changes into one negotiated action without repeating peer identity [242,252,256].
#[cfg(feature = "agent")]
use crate::policy::model::NodeId;
use crate::{
    configuration,
    dataplane::{AccessUpdate, Chunk, Config},
};

/// Keep snapshots and peer identity changes on the original bounded chunk path.
/// # Errors
/// Returns the original encoder's resource or transition refusal.
pub fn chunks(old: Option<&Config>, new: &Config) -> Result<Vec<Chunk>, &'static str> {
    #[cfg(feature = "cutoff-measure")]
    let _encode = crate::cutoff_measure::Stage::new(new.node, new.version, "compact_encode");
    let Some(old) = old.filter(|old| {
        old.node == new.node
            && old.local_key == new.local_key
            && old.server == new.server
            && old.addresses == new.addresses
            && {
                #[cfg(feature = "mesh-dns-spike")]
                {
                    old.name == new.name && old.peer_names == new.peer_names
                }
                #[cfg(not(feature = "mesh-dns-spike"))]
                {
                    true
                }
            }
            && old.exposure == new.exposure
            && old.peers.len() == new.peers.len()
            && old
                .peers
                .iter()
                // Updates carry only inbound and outbound; a changed mesh SSH
                // flag (server node, #221) takes the full path.
                .all(|(id, peer)| {
                    new.peers.get(id).is_some_and(|next| {
                        peer.peer == next.peer && peer.access_ssh == next.access_ssh
                    })
                })
    }) else {
        return configuration::chunks(old, new);
    };
    let mut updates: Vec<AccessUpdate> = Vec::new();
    let mut previous_id = None;
    for (id, next) in &new.peers {
        let adjacent = previous_id;
        previous_id = Some(*id);
        let previous = &old.peers[id];
        if previous.inbound == next.inbound && previous.outbound == next.outbound {
            continue;
        }
        let inbound = (previous.inbound != next.inbound).then(|| next.inbound.clone());
        let outbound = (previous.outbound != next.outbound).then(|| next.outbound.clone());
        if let Some(last) = updates.last_mut()
            && Some(last.last) == adjacent
            && last.inbound == inbound
            && last.outbound == outbound
        {
            last.last = *id;
        } else {
            updates.push(AccessUpdate {
                first: *id,
                last: *id,
                inbound,
                outbound,
            });
        }
    }
    let mut parts = configuration::chunks(Some(new), new)?;
    let part = &mut parts[0];
    part.from_version = Some(old.version);
    part.access_updates = updates;
    // Negotiation changes representation, never the established body budget.
    // Fragmented edits or large port unions use the original staging encoder.
    if serde_json::to_vec(part)
        .map_err(|_| "Mesh encoding failed.")?
        .len()
        > infraternal_plugin_api::MAX_ACTION_BYTES - 64
    {
        return configuration::chunks(Some(old), new);
    }
    Ok(parts)
}

/// Replace rules only for exact, existing, ordered disjoint inclusive ranges.
/// # Errors
/// Refuses missing endpoints and reversed or overlapping ranges.
#[cfg(feature = "agent")]
pub fn apply(config: &mut Config, updates: &[AccessUpdate]) -> std::io::Result<()> {
    let mut previous = None;
    for update in updates {
        if update.first > update.last
            || previous.is_some_and(|last: NodeId| last >= update.first)
            || !config.peers.contains_key(&update.first)
            || !config.peers.contains_key(&update.last)
        {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        previous = Some(update.last);
    }
    // Validate the entire body first. Refusal cannot leave partly replaced rules.
    for update in updates {
        for (_, peer) in config.peers.range_mut(update.first..=update.last) {
            if let Some(inbound) = &update.inbound {
                peer.inbound = inbound.clone();
            }
            if let Some(outbound) = &update.outbound {
                peer.outbound = outbound.clone();
            }
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "agent"))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::dataplane::DefaultPolicy;
    use crate::policy::{
        coordinator::Coordinator,
        model::{MeshSettings, Node, PublicKey},
        rules::TrafficPolicy,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn config() -> Config {
        let member = |id| Node {
            id: NodeId(id),
            public_key: PublicKey([u8::try_from(id).unwrap(); 32]),
            host: format!("host-{id}"),
            tags: BTreeSet::new(),
        };
        let mut coordinator = Coordinator::new(MeshSettings::new([1; 5]), &[], member(1)).unwrap();
        for id in 2..=5 {
            coordinator.join(member(id)).unwrap();
        }
        configuration::compile(
            &coordinator,
            NodeId(2),
            DefaultPolicy::Allow,
            &BTreeMap::new(),
        )
        .unwrap()
    }

    #[test]
    fn compact_rules_reconstruct_the_exact_config_and_preserve_server_access() {
        let old = config();
        let mut next = old.clone();
        next.version += 1;
        next.default_policy = DefaultPolicy::Deny;
        for (id, peer) in &mut next.peers {
            peer.inbound = TrafficPolicy::None;
            if *id != NodeId(1) {
                peer.outbound = TrafficPolicy::None;
            }
        }
        let parts = chunks(Some(&old), &next).unwrap();
        assert_eq!(parts.len(), 1);
        assert!(parts[0].upserted.is_empty());
        let mut reconstructed = old;
        apply(&mut reconstructed, &parts[0].access_updates).unwrap();
        reconstructed.version = next.version;
        reconstructed.default_policy = next.default_policy;
        assert_eq!(reconstructed, next);
    }

    #[test]
    fn identity_changes_and_snapshots_keep_the_original_encoding() {
        let old = config();
        let mut next = old.clone();
        next.version += 1;
        next.peers.get_mut(&NodeId(3)).unwrap().peer.endpoint =
            Some("192.0.2.3:40000".parse().unwrap());
        assert!(
            chunks(Some(&old), &next)
                .unwrap()
                .iter()
                .all(|part| part.access_updates.is_empty())
        );
        assert!(
            chunks(None, &next)
                .unwrap()
                .iter()
                .all(|part| part.access_updates.is_empty())
        );
    }

    #[test]
    fn grouping_never_crosses_an_unchanged_protected_peer() {
        let old = config();
        let mut next = old.clone();
        next.version += 1;
        for id in [NodeId(3), NodeId(5)] {
            next.peers.get_mut(&id).unwrap().inbound = TrafficPolicy::None;
        }
        let parts = chunks(Some(&old), &next).unwrap();
        assert_eq!(parts[0].access_updates.len(), 2);
        let mut reconstructed = old;
        apply(&mut reconstructed, &parts[0].access_updates).unwrap();
        assert_eq!(reconstructed.peers, next.peers);
    }

    #[test]
    fn malformed_ranges_refuse_before_any_rule_changes() {
        let original = config();
        let update = |first, last| AccessUpdate {
            first: NodeId(first),
            last: NodeId(last),
            inbound: Some(TrafficPolicy::None),
            outbound: Some(TrafficPolicy::None),
        };
        for updates in [
            vec![update(3, 5), update(4, 5)],
            vec![update(5, 3)],
            vec![update(3, u64::MAX)],
            vec![update(0, u64::MAX)],
            vec![update(0, 3)],
        ] {
            let mut candidate = original.clone();
            assert_eq!(
                apply(&mut candidate, &updates).unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
            assert_eq!(candidate, original);
        }
        let mut gap = original.clone();
        gap.peers.remove(&NodeId(4));
        let before = gap.clone();
        apply(&mut gap, &[update(3, 5)]).unwrap();
        assert_eq!(gap.peers.len(), before.peers.len());
        assert_eq!(gap.peers[&NodeId(1)], before.peers[&NodeId(1)]);
        assert_eq!(gap.peers[&NodeId(3)].inbound, TrafficPolicy::None);
    }
}
