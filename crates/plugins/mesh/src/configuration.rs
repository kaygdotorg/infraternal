//! Compiles coordinator identity, directional Access grants and discovered endpoints into node configurations [164–166,216].
use crate::{
    dataplane::{Config, DefaultPolicy, ExposureIdentity, Peer, PeerPolicy},
    policy::{
        coordinator::Coordinator,
        model::{MeshError, NodeId},
        rules::TrafficPolicy,
    },
};
use std::{collections::BTreeMap, net::SocketAddr};

/// Compile one node's Access view into the same directional peer policy `WireGuard` installs.
///
/// The server runtime supplies the public-host-derived default suffix. The persisted mesh suffix
/// is used when explicitly selected; legacy non-`internal` values remain overrides. The ordinary
/// mesh snapshot always carries this value for proxy naming; resolver fields stay feature-gated.
/// # Errors
/// Returns unknown membership or invalid persisted address allocation.
pub fn compile_with_dns_suffix(
    coordinator: &Coordinator,
    node: NodeId,
    default: DefaultPolicy,
    endpoints: &BTreeMap<NodeId, SocketAddr>,
    default_dns_suffix: &str,
) -> Result<Config, MeshError> {
    compile_inner(coordinator, node, default, endpoints, default_dns_suffix)
}

/// Compile one node at a time: open defaults need n(n−1) peer entries deployment-wide,
/// avoiding an additional deployment-wide matrix inside this compiler.
/// # Errors
/// Returns unknown membership or invalid persisted address allocation.
pub fn compile(
    coordinator: &Coordinator,
    node: NodeId,
    default: DefaultPolicy,
    endpoints: &BTreeMap<NodeId, SocketAddr>,
) -> Result<Config, MeshError> {
    compile_inner(coordinator, node, default, endpoints, "internal")
}

fn compile_inner(
    coordinator: &Coordinator,
    node: NodeId,
    default: DefaultPolicy,
    endpoints: &BTreeMap<NodeId, SocketAddr>,
    default_dns_suffix: &str,
) -> Result<Config, MeshError> {
    let checkpoint = coordinator.checkpoint();
    let local = checkpoint
        .allocation
        .get(node)
        .ok_or(MeshError::UnknownNode)?;
    let view = coordinator.view(node).ok_or(MeshError::UnknownNode)?;
    #[cfg(feature = "mesh-dns-spike")]
    let name = checkpoint
        .members
        .iter()
        .find(|member| member.node.id == node)
        .map(|member| member.node.host.clone());
    #[cfg(feature = "mesh-dns-spike")]
    let dns_suffix = selected_dns_suffix(
        &checkpoint.settings.dns_suffix,
        checkpoint.settings.dns_suffix_is_explicit,
        default_dns_suffix,
    );
    #[cfg(feature = "mesh-dns-spike")]
    let exposure_dns_suffix = dns_suffix.clone();
    #[cfg(not(feature = "mesh-dns-spike"))]
    let exposure_dns_suffix = default_dns_suffix.to_owned();
    let fallback = if default == DefaultPolicy::Allow {
        TrafficPolicy::All
    } else {
        TrafficPolicy::None
    };
    let mut peers = BTreeMap::new();
    #[cfg(feature = "mesh-dns-spike")]
    let mut peer_names = BTreeMap::new();
    let machine_name = checkpoint
        .members
        .iter()
        .find(|member| member.node.id == node)
        .map(|member| member.node.host.clone())
        .ok_or(MeshError::UnknownNode)?;
    for member in &checkpoint.members {
        let other = member.node.id;
        if other == node {
            continue;
        }
        let granted = view.peers.get(&other);
        let outbound = if other == checkpoint.server {
            TrafficPolicy::All
        } else {
            granted
                .filter(|peer| peer.outbound != TrafficPolicy::None)
                .map_or_else(|| fallback.clone(), |peer| peer.outbound.clone())
        };
        let policy_inbound = granted
            .filter(|peer| peer.inbound != TrafficPolicy::None)
            .map_or_else(|| fallback.clone(), |peer| peer.inbound.clone());
        // The server's node admits every member for the control plane (D215);
        // what Access really grants toward it still travels for mesh SSH (#221).
        let (inbound, access_ssh) = if node == checkpoint.server {
            let ssh = crate::policy::rules::Port {
                protocol: crate::policy::rules::Protocol::Tcp,
                number: 22,
            };
            (TrafficPolicy::All, Some(policy_inbound.allows(ssh)))
        } else {
            (policy_inbound, None)
        };
        #[cfg(feature = "mesh-dns-spike")]
        if outbound != TrafficPolicy::None {
            // The same directional policy installed for this receiver decides whether it learns a name.
            peer_names.insert(other, member.node.host.clone());
        }
        // Retain keys even for denied pairs: a rule change needs only policy, not a fresh tunnel setup.
        peers.insert(
            other,
            PeerPolicy {
                peer: Peer {
                    key: member.keys.current,
                    addresses: checkpoint
                        .allocation
                        .get(other)
                        .ok_or(MeshError::InvalidAllocation)?,
                    endpoint: endpoints.get(&other).copied(),
                },
                inbound,
                outbound,
                access_ssh,
            },
        );
    }
    Ok(Config {
        local_key: checkpoint
            .members
            .iter()
            .find(|member| member.node.id == node)
            .map(|member| member.keys.current),
        server: Some(checkpoint.server),
        node,
        #[cfg(feature = "mesh-dns-spike")]
        name,
        #[cfg(feature = "mesh-dns-spike")]
        dns_suffix,
        version: checkpoint.generation,
        addresses: local,
        default_policy: default,
        exposure: Some(ExposureIdentity {
            machine_name,
            dns_suffix: exposure_dns_suffix,
        }),
        peers,
        #[cfg(feature = "mesh-dns-spike")]
        peer_names,
    })
}

#[cfg(any(feature = "mesh-dns-spike", test))]
fn selected_dns_suffix(
    configured_suffix: &str,
    explicit: bool,
    default_dns_suffix: &str,
) -> String {
    if explicit || configured_suffix != crate::dataplane::DEFAULT_DNS_SUFFIX {
        configured_suffix.to_owned()
    } else {
        default_dns_suffix.to_owned()
    }
}

/// Derive the default mesh zone from the server's configured public origin.
///
/// IP origins and localhost do not provide a public DNS suffix, so those retain `.internal`.
/// This function is deliberately total: malformed or non-public origins fall back to `.internal`.
#[cfg(feature = "server")]
pub(crate) fn default_dns_suffix_from_origin(public_origin: &str) -> String {
    let suffix = url::Url::parse(public_origin)
        .ok()
        .and_then(|origin| match origin.host()? {
            url::Host::Domain(domain) => Some(domain.trim_end_matches('.').to_ascii_lowercase()),
            url::Host::Ipv4(_) | url::Host::Ipv6(_) => None,
        })
        .filter(|host| host != "localhost" && !host.ends_with(".localhost"))
        .filter(|host| crate::policy::model::validate_dns(host, false).is_ok());
    suffix.unwrap_or_else(|| "internal".to_owned())
}
/// List directed pairs that lose ANY new-connection reach. Port narrowing counts as a loss.
/// # Errors
/// Returns a configuration error before proposing a switch.
pub fn preview(
    coordinator: &Coordinator,
    before: DefaultPolicy,
    after: DefaultPolicy,
) -> Result<Vec<(NodeId, NodeId)>, MeshError> {
    let mut losses = Vec::new();
    for node in coordinator.views().keys() {
        let old = compile(coordinator, *node, before, &BTreeMap::new())?;
        let new = compile(coordinator, *node, after, &BTreeMap::new())?;
        for (other, peer) in old.peers {
            if let Some(next) = new.peers.get(&other) {
                let reach_lost = match (&peer.outbound, &next.outbound) {
                    (TrafficPolicy::All, TrafficPolicy::None | TrafficPolicy::Ports(_))
                    | (TrafficPolicy::Ports(_), TrafficPolicy::None) => true,
                    (TrafficPolicy::Ports(old), TrafficPolicy::Ports(new)) => !old.is_subset(new),

                    _ => false,
                };
                if reach_lost {
                    losses.push((*node, other));
                }
            }
        }
    }
    Ok(losses)
}
/// Chunk a snapshot or minimal delta to the authenticated action body bound.
/// Large port unions continue across chunks; a byte bound never caps Access grants [214].
/// # Errors
/// Refuses incompatible node/address transitions or encoding/counter exhaustion.
pub fn chunks(
    old: Option<&Config>,
    new: &Config,
) -> Result<Vec<crate::dataplane::Chunk>, &'static str> {
    #[cfg(feature = "cutoff-measure")]
    let _encode = crate::cutoff_measure::Stage::new(new.node, new.version, "encode_chunks");
    if old.is_some_and(|old| old.node != new.node || old.addresses != new.addresses) {
        return Err("Mesh address transition needs overlap.");
    }
    let mut builder = Chunks {
        part: crate::dataplane::Chunk {
            access_updates: Vec::new(),
            local_key: new.local_key,
            server: new.server,
            node: new.node,
            #[cfg(feature = "mesh-dns-spike")]
            name: new.name.clone(),
            #[cfg(feature = "mesh-dns-spike")]
            dns_suffix: new.dns_suffix.clone(),
            from_version: old.map(|old| old.version),
            version: new.version,
            index: 0,
            last: false,
            addresses: new.addresses,
            default_policy: new.default_policy,
            exposure: new.exposure.clone(),
            upserted: BTreeMap::new(),
            merged: BTreeMap::new(),
            removed: Vec::new(),
            #[cfg(feature = "mesh-dns-spike")]
            peer_names: BTreeMap::new(),
            #[cfg(feature = "mesh-dns-spike")]
            removed_peer_names: Vec::new(),
        },
        output: Vec::new(),
    };
    for (node, peer) in &new.peers {
        if old.and_then(|old| old.peers.get(node)) != Some(peer) {
            builder.peer(*node, peer)?;
        }
    }
    #[cfg(feature = "mesh-dns-spike")]
    for (node, name) in &new.peer_names {
        if old.and_then(|old| old.peer_names.get(node)) != Some(name) {
            builder.peer_name(*node, name)?;
        }
    }
    #[cfg(feature = "mesh-dns-spike")]
    for node in old
        .into_iter()
        .flat_map(|old| old.peer_names.keys())
        .filter(|node| new.peers.contains_key(node) && !new.peer_names.contains_key(node))
    {
        builder.remove_peer_name(*node)?;
    }
    for node in old
        .into_iter()
        .flat_map(|old| old.peers.keys())
        .filter(|node| !new.peers.contains_key(node))
    {
        let previous = builder.part.clone();
        builder.part.removed.push(*node);
        if !builder.fits()? {
            builder.flush(previous)?;
            builder.part.removed.push(*node);
        }
    }
    builder.part.last = true;
    builder.output.push(builder.part);
    Ok(builder.output)
}
struct Chunks {
    part: crate::dataplane::Chunk,
    output: Vec<crate::dataplane::Chunk>,
}
impl Chunks {
    fn fits(&self) -> Result<bool, &'static str> {
        Ok(serde_json::to_vec(&self.part)
            .map_err(|_| "Mesh encoding failed.")?
            .len()
            <= infraternal_plugin_api::MAX_ACTION_BYTES - 64)
    }
    fn flush(&mut self, previous: crate::dataplane::Chunk) -> Result<(), &'static str> {
        self.part.index = self
            .part
            .index
            .checked_add(1)
            .ok_or("Mesh chunk counter exhausted.")?;
        self.part.upserted.clear();
        self.part.merged.clear();
        self.part.removed.clear();
        #[cfg(feature = "mesh-dns-spike")]
        self.part.peer_names.clear();
        #[cfg(feature = "mesh-dns-spike")]
        self.part.removed_peer_names.clear();
        self.output.push(previous);
        Ok(())
    }
    fn peer(&mut self, node: NodeId, peer: &PeerPolicy) -> Result<(), &'static str> {
        let previous = self.part.clone();
        self.part.upserted.insert(node, peer.clone());
        if self.fits()? {
            return Ok(());
        }
        self.part = previous;
        if !self.part.upserted.is_empty()
            || !self.part.merged.is_empty()
            || !self.part.removed.is_empty()
        {
            self.flush(self.part.clone())?;
        }
        self.part.upserted.insert(node, peer.clone());
        if self.fits()? {
            return Ok(());
        }
        // First publish identity and non-port policies into staging, then union
        // port-only continuations. Installed state changes only on the last chunk.
        let mut base = peer.clone();
        if matches!(base.inbound, TrafficPolicy::Ports(_)) {
            base.inbound = TrafficPolicy::None;
        }
        if matches!(base.outbound, TrafficPolicy::Ports(_)) {
            base.outbound = TrafficPolicy::None;
        }
        self.part.upserted.insert(node, base);
        if !self.fits()? {
            return Err("Mesh identity exceeds frame resource bound.");
        }
        for (inbound, policy) in [(true, &peer.inbound), (false, &peer.outbound)] {
            if let TrafficPolicy::Ports(ports) = policy {
                for port in ports {
                    self.port(node, peer, inbound, *port)?;
                }
            }
        }
        Ok(())
    }
    #[cfg(feature = "mesh-dns-spike")]
    fn peer_name(&mut self, node: NodeId, name: &str) -> Result<(), &'static str> {
        let previous = self.part.clone();
        self.part.peer_names.insert(node, name.to_owned());
        if self.fits()? {
            return Ok(());
        }
        self.part = previous;
        if !self.part.upserted.is_empty()
            || !self.part.merged.is_empty()
            || !self.part.removed.is_empty()
            || !self.part.peer_names.is_empty()
            || !self.part.removed_peer_names.is_empty()
        {
            self.flush(self.part.clone())?;
        }
        self.part.peer_names.insert(node, name.to_owned());
        if self.fits()? {
            return Ok(());
        }
        Err("Mesh name exceeds frame resource bound.")
    }
    #[cfg(feature = "mesh-dns-spike")]
    fn remove_peer_name(&mut self, node: NodeId) -> Result<(), &'static str> {
        let previous = self.part.clone();
        self.part.removed_peer_names.push(node);
        if self.fits()? {
            return Ok(());
        }
        self.part = previous;
        if !self.part.upserted.is_empty()
            || !self.part.merged.is_empty()
            || !self.part.removed.is_empty()
            || !self.part.peer_names.is_empty()
            || !self.part.removed_peer_names.is_empty()
        {
            self.flush(self.part.clone())?;
        }
        self.part.removed_peer_names.push(node);
        if self.fits()? {
            return Ok(());
        }
        Err("Mesh name removal exceeds frame resource bound.")
    }
    fn port(
        &mut self,
        node: NodeId,
        peer: &PeerPolicy,
        inbound: bool,
        port: crate::policy::rules::Port,
    ) -> Result<(), &'static str> {
        let previous = self.part.clone();
        self.insert_port(node, peer, inbound, port);
        if !self.fits()? {
            self.flush(previous)?;
            self.insert_port(node, peer, inbound, port);
        }
        Ok(())
    }
    fn insert_port(
        &mut self,
        node: NodeId,
        peer: &PeerPolicy,
        inbound: bool,
        port: crate::policy::rules::Port,
    ) {
        let partial = self.part.merged.entry(node).or_insert_with(|| PeerPolicy {
            peer: peer.peer.clone(),
            inbound: TrafficPolicy::None,
            outbound: TrafficPolicy::None,
            // Port continuations only union ports; the base part carries it.
            access_ssh: None,
        });
        let policy = if inbound {
            &mut partial.inbound
        } else {
            &mut partial.outbound
        };
        policy.union(&TrafficPolicy::Ports(std::collections::BTreeSet::from([
            port,
        ])));
    }
}

#[cfg(test)]
mod tests {
    use super::selected_dns_suffix;

    #[test]
    fn server_dns_suffix_is_default_and_explicit_or_legacy_choices_win() {
        assert_eq!(
            selected_dns_suffix("internal", false, "example.org"),
            "example.org"
        );
        assert_eq!(
            selected_dns_suffix("custom.example", false, "example.org"),
            "custom.example"
        );
        assert_eq!(
            selected_dns_suffix("internal", true, "example.org"),
            "internal"
        );
    }
}
