//! Stage and validate incoming snapshots before they reach the live device.

use crate::dataplane::Config;
use std::io;

/// An incomplete configuration assembled from contiguous updates.
pub struct Pending {
    server: Option<crate::policy::model::NodeId>,
    next: u32,
    version: u64,
    from_version: Option<u64>,
    default_policy: crate::dataplane::DefaultPolicy,
    config: Config,
}

#[cfg(target_vendor = "apple")]
impl Pending {
    /// Whether this full snapshot can accept a continuation for the incoming authority.
    pub(super) fn continues_authority(&self, epoch: Option<&str>) -> bool {
        self.from_version.is_none() && self.config.authority_epoch.as_deref() == epoch
    }
}

/// Stage a contiguous Mac snapshot, allowing a changed authority only in a fresh full snapshot.
/// A lower same-authority revision needs the persisted replacement transaction.
/// # Errors
/// Refuses incomplete, stale, unbound, or inconsistent chunks.
pub fn stage_chunk(
    pending: &mut Option<Pending>,
    current: Option<&Config>,
    identity: &crate::dataplane::Identity,
    allow_lower_revision_replacement: bool,
    chunk: crate::dataplane::Chunk,
) -> io::Result<Option<Config>> {
    if chunk
        .authority_epoch
        .as_deref()
        .is_some_and(|epoch| !crate::dataplane::valid_authority_epoch(epoch))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if !chunk.access_updates.is_empty()
        && (chunk.from_version.is_none()
            || chunk.index != 0
            || !chunk.last
            || !chunk.upserted.is_empty()
            || !chunk.merged.is_empty()
            || !chunk.removed.is_empty()
            || current.is_none_or(|old| old.server != chunk.server))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if chunk
        .local_key
        .is_some_and(|key| key != identity.public_key)
        || current.is_some_and(|old| {
            old.node != chunk.node
                && (chunk.local_key.is_none()
                    || chunk.from_version.is_some()
                    || old.authority_epoch == chunk.authority_epoch && chunk.version <= old.version)
        })
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if chunk.index == 0 {
        let current_version = current.map(|config| config.version);
        if !allow_lower_revision_replacement
            && current.is_some_and(|old| {
                chunk.from_version.is_none()
                    && old.authority_epoch == chunk.authority_epoch
                    && chunk.version < old.version
            })
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if chunk.from_version.is_some() && chunk.from_version != current_version
            || current_version
                .is_some_and(|version| chunk.from_version.is_some() && chunk.version <= version)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let config = if chunk.from_version.is_some() {
            current.cloned().ok_or(io::ErrorKind::InvalidData)?
        } else {
            Config {
                authority_epoch: chunk.authority_epoch.clone(),
                rotation_operation: chunk.rotation_operation.clone(),
                local_key: chunk.local_key,
                server: chunk.server,
                node: chunk.node,
                #[cfg(feature = "mesh-dns")]
                name: chunk.name.clone(),
                #[cfg(feature = "mesh-dns")]
                dns_suffix: chunk.dns_suffix.clone(),
                version: chunk.version,
                addresses: chunk.addresses,
                default_policy: chunk.default_policy,
                exposure: chunk.exposure.clone(),
                peers: std::collections::BTreeMap::new(),
                #[cfg(feature = "mesh-dns")]
                peer_names: std::collections::BTreeMap::new(),
            }
        };
        let mut config = config;
        config
            .rotation_operation
            .clone_from(&chunk.rotation_operation);
        #[cfg(feature = "mesh-dns")]
        let config = {
            let mut config = config;
            config.name.clone_from(&chunk.name);
            config.dns_suffix.clone_from(&chunk.dns_suffix);
            config
        };
        *pending = Some(Pending {
            server: chunk.server,
            next: 0,
            version: chunk.version,
            from_version: chunk.from_version,
            default_policy: chunk.default_policy,
            config,
        });
    }
    let staged = pending.as_mut().ok_or(io::ErrorKind::InvalidData)?;
    #[cfg(feature = "mesh-dns")]
    let names_changed = staged.config.name != chunk.name;
    #[cfg(feature = "mesh-dns")]
    let dns_suffix_changed = staged.config.dns_suffix != chunk.dns_suffix;
    #[cfg(not(feature = "mesh-dns"))]
    let names_changed = false;
    #[cfg(not(feature = "mesh-dns"))]
    let dns_suffix_changed = false;
    if staged.server != chunk.server
        || staged.config.authority_epoch != chunk.authority_epoch
        || staged.config.rotation_operation != chunk.rotation_operation
        || staged.next != chunk.index
        || staged.config.local_key != chunk.local_key
        || staged.config.node != chunk.node
        || names_changed
        || dns_suffix_changed
        || staged.config.addresses != chunk.addresses
        || staged.version != chunk.version
        || staged.from_version != chunk.from_version
        || staged.default_policy != chunk.default_policy
        // As on Linux (#281): a delta cannot change the exposure identity.
        || staged.config.exposure != chunk.exposure
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    staged.next = staged
        .next
        .checked_add(1)
        .ok_or(io::ErrorKind::InvalidData)?;
    staged.config.version = chunk.version;
    staged.config.default_policy = chunk.default_policy;
    staged.config.server = chunk.server;
    crate::access_updates::apply(&mut staged.config, &chunk.access_updates)?;
    for node in chunk.removed {
        staged.config.peers.remove(&node);
        #[cfg(feature = "mesh-dns")]
        staged.config.peer_names.remove(&node);
    }
    staged.config.peers.extend(chunk.upserted);
    for (node, partial) in chunk.merged {
        let peer = staged
            .config
            .peers
            .get_mut(&node)
            .ok_or(io::ErrorKind::InvalidData)?;
        if !partial.continues(peer) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        peer.inbound.union(&partial.inbound);
        peer.outbound.union(&partial.outbound);
    }
    #[cfg(feature = "mesh-dns")]
    {
        for node in chunk.removed_peer_names {
            if !staged.config.peers.contains_key(&node)
                || staged.config.peer_names.remove(&node).is_none()
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        for (node, name) in chunk.peer_names {
            if !staged.config.peers.contains_key(&node)
                || name.is_empty()
                || name.len() > 63
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || name.starts_with('-')
                || name.ends_with('-')
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            staged.config.peer_names.insert(node, name);
        }
    }
    if chunk.last {
        Ok(Some(
            pending.take().ok_or(io::ErrorKind::InvalidData)?.config,
        ))
    } else {
        Ok(None)
    }
}

/// Check whether an incoming chunk carries a different authenticated server process epoch.
#[must_use]
pub fn needs_authority_reset(current: Option<&Config>, chunk: &crate::dataplane::Chunk) -> bool {
    current.is_some_and(|old| old.authority_epoch != chunk.authority_epoch)
}
