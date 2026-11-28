//! Applies negotiated access updates to a node snapshot.

use crate::{
    dataplane::{AccessUpdate, Config},
    policy::model::NodeId,
};

/// Replace rules only for exact, existing, ordered disjoint inclusive ranges.
/// # Errors
/// Refuses missing endpoints and reversed or overlapping ranges.
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
