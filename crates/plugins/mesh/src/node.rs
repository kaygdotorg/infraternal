//! Owns the root-only Mesh node, staged public configuration and synchronous kernel lifecycle [163,166,198].
use crate::{
    dataplane::Config,
    firewall::Firewall,
    wireguard::{Client, Device, Key},
};
use std::{collections::BTreeMap, io};

pub use crate::dataplane::Chunk;
struct Pending {
    server: Option<crate::policy::model::NodeId>,
    next: u32,
    version: u64,
    from_version: Option<u64>,
    default_policy: crate::dataplane::DefaultPolicy,
    config: Config,
}
pub use crate::dataplane::Identity;

/// The component has no polling loop. Its idle netlink socket closes on explicit down.
pub struct Node {
    identity: Option<Identity>,
    enabled: bool,
    store: Option<crate::node_state::Store>,
    config: Option<Config>,
    pending: Option<Pending>,
    firewall: Firewall,
    owned: bool,
    client: Option<Client>,
}
impl Default for Node {
    fn default() -> Self {
        Self {
            identity: None,
            enabled: true,
            store: None,
            config: None,
            pending: None,
            firewall: Firewall::default(),
            owned: false,
            client: None,
        }
    }
}
impl Node {
    /// Use an explicitly selected supported packet-filter frontend in an isolated namespace.
    #[must_use]
    pub fn with_firewall(firewall: Firewall) -> Self {
        Self {
            firewall,
            ..Self::default()
        }
    }

    /// Restore public intent and adopt only an interface marked as this component's own.
    /// # Errors
    /// Refuses unsafe state, unrelated interface ownership or failed policy recovery.
    pub fn restore(path: &std::path::Path) -> io::Result<Self> {
        let (store, state) = crate::node_state::Store::open(path)?;
        let mut node = Self {
            enabled: state.enabled,
            store: Some(store),
            firewall: state
                .backend
                .map_or_else(Firewall::default, Firewall::for_backend),
            ..Self::default()
        };
        node.firewall.adopt()?;
        if Device::owned()? {
            node.owned = true;
            let identity = Device::identity();
            // A process can stop after marking the interface but before setting
            // its key. With no saved configuration there are no retained mesh
            // sessions to preserve; remove that incomplete owned startup only.
            let incomplete = state.config.is_none()
                && (identity
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::InvalidData)
                    || identity
                        .as_ref()
                        .is_ok_and(|(key, port)| key.0 == [0; 32] || *port == 0));
            if incomplete {
                Device::delete()?;
                node.owned = false;
                node.firewall.remove()?;
                return Ok(node);
            }
            let (public_key, mut port) = identity?;
            if public_key.0 == [0; 32] || port == 0 {
                return Err(io::ErrorKind::NotConnected.into());
            }
            // A retained interface from an older daemon may have selected the
            // reserved port. Rebind its socket while preserving its private key.
            if port == 51820 {
                port = Device::allocate_port()?;
            }
            node.identity = Some(Identity { public_key, port });
            node.client = Some(Client::new()?);
            if !node.enabled {
                node.down()?;
            } else if let Some(config) = state.config {
                node.apply(config)?;
            }
        }
        if !node.owned && !node.enabled {
            node.firewall.remove()?;
        }
        Ok(node)
    }
    /// Read the retained component intent, including an explicitly stopped node.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    /// Report an owned kernel identity; policy may still be awaiting the server.
    #[must_use]
    pub fn active(&self) -> bool {
        self.identity.is_some()
    }
    /// Disabled intent is not Off until retained kernel/socket ownership is gone.
    #[must_use]
    pub fn stopping(&self) -> bool {
        !self.enabled && (self.owned || self.client.is_some() || self.identity.is_some())
    }
    /// Start only an enabled node; a coordinator reconnect cannot override local down.
    /// # Errors
    /// Reports the same privilege, persistence and kernel failures as explicit up.
    pub fn ensure(&mut self) -> io::Result<Option<Identity>> {
        if self.enabled {
            self.up().map(Some)
        } else {
            Ok(None)
        }
    }
    fn save(&self, config: Option<&Config>, enabled: bool) -> io::Result<()> {
        if let Some(store) = &self.store {
            store.save(&crate::node_state::State {
                enabled,
                config: config.cloned(),
                backend: self.firewall.backend(),
            })?;
        }
        Ok(())
    }
    /// Generate the key on the node and configure its owned kernel interface once.
    /// # Errors
    /// Refuses missing privilege or any kernel error; never returns private material.
    pub fn up(&mut self) -> io::Result<Identity> {
        // A failed down may have published disabled intent while retaining only
        // part of the old kernel state. Finish cleanup before returning/recreating identity.
        if !self.enabled {
            self.down()?;
        }
        if let Some(identity) = &self.identity {
            return Ok(identity.clone());
        }
        self.firewall.adopt()?;
        let (key, public_key) = Key::generate()?;
        Device::create()?;
        self.owned = true;
        let port = 0;
        if let Err(error) = Device::configure(&key, port) {
            let _ = self.down();
            return Err(error);
        }
        let prepared = (|| {
            let (device_key, port) = Device::identity()?;
            if device_key != public_key || port == 0 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let client = Client::new()?;
            self.save(None, true)?;
            Ok((Identity { public_key, port }, client))
        })();
        match prepared {
            Ok((identity, client)) => {
                self.enabled = true;
                self.client = Some(client);
                self.identity = Some(identity.clone());
                Ok(identity)
            }
            Err(error) => {
                Device::delete()?;
                self.owned = false;
                Err(error)
            }
        }
    }
    /// Remove all owned kernel work before reporting off. A failed cleanup remains visible.
    /// # Errors
    /// Reports failed kernel cleanup rather than claiming the component is disabled.
    pub fn down(&mut self) -> io::Result<()> {
        self.save(None, false)?;
        self.enabled = false;
        if self.owned {
            // Confirmed absence is idempotent; a foreign replacement or a
            // privilege error must never be treated as successful deletion.
            if Device::owned()? {
                Device::delete()?;
            }
            self.owned = false;
        }
        self.firewall.remove()?;
        self.firewall = Firewall::default();
        self.client = None;
        self.identity = None;
        self.config = None;
        self.pending = None;
        Ok(())
    }
    /// Read the retained applied configuration, never partial incoming chunks.
    #[must_use]
    pub fn config(&self) -> Option<&Config> {
        self.config.as_ref()
    }
    /// Stage a contiguous snapshot or delta. Apply only the final complete version.
    /// # Errors
    /// Refuses stale/out-of-order/wrong-node chunks before changing installed state.
    pub fn chunk(&mut self, chunk: Chunk) -> io::Result<bool> {
        let result = self.stage(chunk);
        if result.is_err() {
            self.pending = None;
        }
        result
    }
    fn stage(&mut self, chunk: Chunk) -> io::Result<bool> {
        if self.identity.is_none() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        if chunk.index == 0 {
            let current = self.config.as_ref().map(|config| config.version);
            if chunk.from_version.is_some() && chunk.from_version != current
                || current.is_some_and(|v| {
                    chunk.version < v || chunk.from_version.is_some() && chunk.version == v
                })
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let config = if chunk.from_version.is_some() {
                self.config.clone().ok_or(io::ErrorKind::InvalidData)?
            } else {
                Config {
                    server: chunk.server,
                    node: chunk.node,
                    version: chunk.version,
                    addresses: chunk.addresses,
                    default_policy: chunk.default_policy,
                    peers: BTreeMap::new(),
                }
            };
            self.pending = Some(Pending {
                server: chunk.server,
                next: 0,
                version: chunk.version,
                from_version: chunk.from_version,
                default_policy: chunk.default_policy,
                config,
            });
        }
        let pending = self.pending.as_mut().ok_or(io::ErrorKind::InvalidData)?;
        if pending.server != chunk.server
            || pending.next != chunk.index
            || pending.config.node != chunk.node
            || pending.config.addresses != chunk.addresses
            || pending.version != chunk.version
            || pending.from_version != chunk.from_version
            || pending.default_policy != chunk.default_policy
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        pending.next = pending
            .next
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        pending.config.version = chunk.version;
        pending.config.default_policy = chunk.default_policy;
        pending.config.server = chunk.server;
        for node in chunk.removed {
            pending.config.peers.remove(&node);
        }
        pending.config.peers.extend(chunk.upserted);
        for (id, partial) in chunk.merged {
            let peer = pending
                .config
                .peers
                .get_mut(&id)
                .ok_or(io::ErrorKind::InvalidData)?;
            if peer.peer != partial.peer {
                return Err(io::ErrorKind::InvalidData.into());
            }
            for policy in [&partial.inbound, &partial.outbound] {
                if matches!(policy, crate::policy::rules::TrafficPolicy::All) {
                    return Err(io::ErrorKind::InvalidData.into());
                }
            }
            peer.inbound.union(&partial.inbound);
            peer.outbound.union(&partial.outbound);
        }
        if !chunk.last {
            return Ok(false);
        }
        let config = self
            .pending
            .take()
            .ok_or(io::ErrorKind::InvalidData)?
            .config;
        if self.config.as_ref() == Some(&config) {
            return Ok(true);
        }
        self.apply(config)?;
        Ok(true)
    }
    // Keep the apply/fence/rollback transaction and its failure ordering visible together.
    #[allow(clippy::too_many_lines)]
    fn apply(&mut self, config: Config) -> io::Result<()> {
        if self
            .config
            .as_ref()
            .is_some_and(|old| old.addresses != config.addresses)
        {
            // Address transitions require the later overlap barrier, never remove live addresses here [199].
            return Err(io::ErrorKind::Unsupported.into());
        }
        let mut keys = std::collections::BTreeSet::new();
        let mut addresses = std::collections::BTreeSet::new();
        let mut ipv6 = std::collections::BTreeSet::new();
        for (node, peer) in &config.peers {
            if *node == config.node
                || !keys.insert(peer.peer.key)
                || !addresses.insert(peer.peer.addresses.ipv4)
                || !ipv6.insert(peer.peer.addresses.ipv6)
                || peer.peer.addresses.ipv4 == config.addresses.ipv4
                || peer.peer.addresses.ipv6 == config.addresses.ipv6
                || self
                    .identity
                    .as_ref()
                    .is_some_and(|identity| identity.public_key == peer.peer.key)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        if let Some(old) = &self.config {
            let endpoints_only = old.peers.len() == config.peers.len()
                && old.default_policy == config.default_policy
                && config.peers.iter().all(|(id, peer)| {
                    old.peers.get(id).is_some_and(|old| {
                        old.inbound == peer.inbound
                            && old.outbound == peer.outbound
                            && old.peer.key == peer.peer.key
                            && old.peer.addresses == peer.peer.addresses
                    })
                });
            if endpoints_only {
                for (id, peer) in &config.peers {
                    if old.peers[id].peer.endpoint != peer.peer.endpoint {
                        if let Some(endpoint) = peer.peer.endpoint {
                            self.client
                                .as_mut()
                                .ok_or(io::ErrorKind::NotConnected)?
                                .endpoint(peer.peer.key, endpoint)?;
                        } else {
                            return Err(io::ErrorKind::Unsupported.into());
                        }
                    }
                }
                self.save(Some(&config), true)?;
                self.config = Some(config);
                return Ok(());
            }
        }
        let proposed: Vec<_> = std::iter::once(config.addresses)
            .chain(config.peers.values().map(|peer| peer.peer.addresses))
            .collect();
        Device::check_routes(&proposed)?;
        let old_peers = self.config.as_ref().map(|old| &old.peers);
        let changed: Vec<_> = config
            .peers
            .iter()
            .filter(|(node, peer)| {
                old_peers
                    .and_then(|old| old.get(node))
                    .is_none_or(|old| old.peer != peer.peer)
            })
            .map(|(_, peer)| peer.peer.clone())
            .collect();
        let retired: Vec<_> = old_peers
            .into_iter()
            .flat_map(|peers| peers.iter())
            .filter(|(node, peer)| {
                config
                    .peers
                    .get(node)
                    .is_none_or(|new| new.peer.key != peer.peer.key)
            })
            .map(|(_, peer)| peer.peer.clone())
            .collect();
        // Kernel state can be newer than the saved public snapshot after a crash.
        // Retire orphan keys as well as keys removed from the retained configuration.
        let desired: std::collections::BTreeSet<_> =
            config.peers.values().map(|peer| peer.peer.key).collect();
        let retired_keys: Vec<_> = Device::counters()?
            .keys()
            .filter(|key| !desired.contains(key))
            .copied()
            .collect();
        // Fence all NEW traffic while multi-datagram kernel state changes. Established
        // sessions keep flowing. A failed apply restores the old view before removing the fence.
        let mut fence = config.clone();
        for peer in fence.peers.values_mut() {
            peer.inbound = crate::policy::rules::TrafficPolicy::None;
            peer.outbound = crate::policy::rules::TrafficPolicy::None;
        }
        self.firewall.apply(&fence)?;
        let result = (|| {
            if self.config.is_none() {
                Device::addresses(config.addresses)?;
            }
            self.client
                .as_mut()
                .ok_or(io::ErrorKind::NotConnected)?
                .peers(&changed, &retired_keys)?;
            Device::routes(&changed, false)?;
            Device::routes(
                &retired
                    .iter()
                    .filter(|old| {
                        !config
                            .peers
                            .values()
                            .any(|new| new.peer.addresses == old.addresses)
                    })
                    .cloned()
                    .collect::<Vec<_>>(),
                true,
            )?;
            self.firewall.apply(&config)?;
            self.save(Some(&config), true)
        })();
        if let Err(error) = result {
            // Saving can fail after the permissive policy transaction. Reinstall
            // the fence before rollback so any later error still denies NEW traffic.
            self.firewall.apply(&fence)?;
            if let Some(old) = &self.config {
                let restore: Vec<_> = old.peers.values().map(|peer| peer.peer.clone()).collect();
                // If rollback itself fails the restrictive fence remains. Never report an applied version.
                self.client
                    .as_mut()
                    .ok_or(io::ErrorKind::NotConnected)?
                    .peers(
                        &restore,
                        &changed
                            .iter()
                            .filter(|peer| !old.peers.values().any(|old| old.peer.key == peer.key))
                            .map(|peer| peer.key)
                            .collect::<Vec<_>>(),
                    )?;
                Device::routes(&restore, false)?;
                let retained: std::collections::BTreeSet<_> = restore
                    .iter()
                    .map(|peer| (peer.addresses.ipv4, peer.addresses.ipv6))
                    .collect();
                Device::routes(
                    &changed
                        .iter()
                        .filter(|peer| {
                            !retained.contains(&(peer.addresses.ipv4, peer.addresses.ipv6))
                        })
                        .cloned()
                        .collect::<Vec<_>>(),
                    true,
                )?;
                self.firewall.apply(old)?;
            } else {
                self.client
                    .as_mut()
                    .ok_or(io::ErrorKind::NotConnected)?
                    .peers(
                        &[],
                        &changed.iter().map(|peer| peer.key).collect::<Vec<_>>(),
                    )?;
                Device::routes(&changed, true)?;
            }
            return Err(error);
        }
        self.config = Some(config);
        Ok(())
    }
}
// No Drop cleanup: kernel state and established flows survive control process loss [166].

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    #[test]
    fn server_identity_cannot_change_inside_a_staged_snapshot() {
        use crate::policy::model::{Addresses, NodeId, PublicKey};
        let mut node = Node {
            identity: Some(Identity {
                public_key: PublicKey([1; 32]),
                port: 44000,
            }),
            ..Node::default()
        };
        let config = Config {
            server: Some(NodeId(1)),
            node: NodeId(2),
            version: 1,
            addresses: Addresses {
                ipv4: "10.254.0.2".parse().expect("IPv4"),
                ipv6: "fd01::2".parse().expect("IPv6"),
            },
            default_policy: crate::dataplane::DefaultPolicy::default(),
            peers: BTreeMap::new(),
        };
        let mut chunk = crate::configuration::chunks(None, &config)
            .expect("snapshot")
            .remove(0);
        chunk.last = false;
        assert!(!node.chunk(chunk.clone()).expect("staged header"));
        chunk.index = 1;
        chunk.server = Some(NodeId(3));
        assert!(node.chunk(chunk).is_err());
        assert!(node.config().is_none());
    }

    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn explicit_up_recovers_disabled_intent_before_reusing_identity() {
        let mut node = Node::default();
        node.up().expect("start");
        // Down publishes disabled intent before kernel cleanup. Model an
        // interrupted cleanup at that exact boundary with a still-live identity.
        node.enabled = false;
        node.up().expect("explicit restart");
        assert!(node.enabled());
        assert!(Device::owned().expect("owned interface"));
        node.down().expect("cleanup");
    }
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn externally_removed_interface_does_not_block_down() {
        let mut node = Node::default();
        node.up().expect("start");
        Device::delete().expect("external removal");
        node.down().expect("already absent owned interface");
        assert!(!node.active());
        assert!(!node.enabled());
    }
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN; use release for timing."]
    fn chunked_snapshot_is_atomic_and_applies_1000_kernel_peers() {
        use crate::{
            dataplane::{DefaultPolicy, Peer, PeerPolicy},
            policy::{
                model::{Addresses, NodeId},
                rules::TrafficPolicy,
            },
        };
        let mut node = Node::default();
        node.up().expect("start");
        let addresses = |id: u32| Addresses {
            ipv4: std::net::Ipv4Addr::from(0x0afe_0000 + id),
            ipv6: std::net::Ipv6Addr::from((0xfd01_u128 << 112) + u128::from(id)),
        };
        let config = Config {
            server: None,
            node: NodeId(1),
            version: 1,
            addresses: addresses(1),
            default_policy: DefaultPolicy::Allow,
            peers: (2..=1001)
                .map(|id| {
                    let (_, key) = Key::generate().expect("public peer fixture");
                    (
                        NodeId(u64::from(id)),
                        PeerPolicy {
                            peer: Peer {
                                key,
                                addresses: addresses(id),
                                endpoint: Some("192.0.2.1:44000".parse().expect("public endpoint")),
                            },
                            inbound: TrafficPolicy::All,
                            outbound: TrafficPolicy::All,
                        },
                    )
                })
                .collect(),
        };
        let chunks = crate::configuration::chunks(None, &config).expect("bounded chunks");
        let count = chunks.len();
        assert!(count > 1);
        // An interrupted or out-of-order snapshot cannot mutate the live view.
        node.chunk(chunks[0].clone()).expect("first staged");
        assert!(node.chunk(chunks[count - 1].clone()).is_err());
        assert!(node.config().is_none());
        assert_eq!(Device::counters().expect("empty kernel").len(), 0);
        let started = std::time::Instant::now();
        for chunk in chunks {
            let last = chunk.last;
            assert_eq!(node.chunk(chunk).expect("stage/apply"), last);
            if !last {
                assert!(node.config().is_none());
            }
        }
        let initial = started.elapsed().as_micros();
        assert_eq!(Device::counters().expect("kernel peers").len(), 1000);
        let mut next = config.clone();
        next.version += 1;
        next.peers
            .get_mut(&NodeId(500))
            .expect("member")
            .peer
            .endpoint = Some("192.0.2.2:44000".parse().expect("public endpoint"));
        let delta = crate::configuration::chunks(Some(&config), &next).expect("delta");
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].upserted.len(), 1);
        let started = std::time::Instant::now();
        node.chunk(delta[0].clone()).expect("endpoint delta");
        println!(
            "METRIC mesh_node machine=infraternal-dev peers=1000 chunks={count} apply_us={initial} single_endpoint_us={} load={}",
            started.elapsed().as_micros(),
            std::fs::read_to_string("/proc/loadavg")
                .expect("load")
                .trim()
        );
        assert_eq!(node.config().expect("applied").version, 2);
        node.down().expect("off");
        assert!(!Device::owned().expect("absent owned interface"));
    }
}
