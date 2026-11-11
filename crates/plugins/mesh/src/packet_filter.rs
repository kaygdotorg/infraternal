//! Checks every packet at the GotaTun TUN boundary against one complete mesh policy snapshot [D164,D384].

use crate::{
    dataplane::{Config, PeerPolicy},
    policy::{
        model::NodeId,
        rules::{Port, Protocol, TrafficPolicy},
    },
};
use infraternal_mesh::proxy_ports::MeshProxyIngress;
use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

/// A packet's position relative to this host and its mesh peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Direction {
    /// A host packet that is about to enter `GotaTun` and be sent to a peer.
    HostToMesh,
    /// An authenticated peer packet that is about to enter the host stack.
    MeshToHost,
}

/// Expire idle TCP state so a stale reverse tuple cannot keep a removed grant alive.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Expire idle UDP state while allowing short request/response exchanges.
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Bound the work a peer can make the filter retain for non-TCP and non-UDP flows.
const OTHER_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Bound each peer's conntrack memory and avoid allocations as packets arrive.
const FLOWS_PER_PEER: usize = 128;
/// `FLOWS_PER_PEER` represented without narrowing a packet hash on 32-bit hosts.
const FLOWS_PER_PEER_HASH: u64 = 128;
/// IP protocol number for TCP packets.
const TCP: u8 = 6;
/// IP protocol number for UDP packets.
const UDP: u8 = 17;
/// IP protocol number for IPv4 ICMP packets.
const ICMP: u8 = 1;
/// IP protocol number for IPv6 ICMP packets.
const ICMPV6: u8 = 58;
/// TCP flag bit that starts a connection.
const TCP_SYN: u8 = 0x02;
/// TCP flag bit that closes one side of a connection.
const TCP_FIN: u8 = 0x01;
/// TCP flag bit that resets a connection.
const TCP_RST: u8 = 0x04;
/// TCP flag bit that makes a packet ineligible to start a connection.
const TCP_ACK: u8 = 0x10;

/// Publishes new policy snapshots atomically and checks packets without allocating on the data path.
pub(crate) struct PacketFilter {
    policy: RwLock<CompiledPolicy>,
}

/// One fully compiled snapshot that can be published after its related routes and peers succeed.
pub(crate) struct PreparedPolicy(CompiledPolicy);

impl PacketFilter {
    /// Build an empty, deny-by-default filter for a node that has not received its first snapshot.
    ///
    /// Peer tables are allocated with each compiled policy. They are never grown while packets
    /// are being checked, which keeps the packet path allocation-free and independently bounded.
    pub(crate) fn empty() -> Self {
        Self::with_policy(CompiledPolicy::empty())
    }

    /// Compile one complete coordinator snapshot and proxy listener view.
    ///
    /// # Errors
    /// Refuses duplicate peer addresses or a policy snapshot that cannot be indexed in memory.
    pub(crate) fn new(config: &Config, proxy_ingress: MeshProxyIngress) -> io::Result<Self> {
        Ok(Self::with_policy(CompiledPolicy::compile(
            config,
            proxy_ingress,
        )?))
    }

    /// Attach one compiled snapshot before the filter reaches packet workers.
    fn with_policy(policy: CompiledPolicy) -> Self {
        Self {
            policy: RwLock::new(policy),
        }
    }

    /// Compile a policy before changing routes or device peers, so publication cannot fail later.
    ///
    /// # Errors
    /// Refuses duplicate peer addresses or a policy snapshot that cannot be indexed in memory.
    pub(crate) fn prepare_policy(
        config: &Config,
        proxy_ingress: MeshProxyIngress,
    ) -> io::Result<PreparedPolicy> {
        Ok(PreparedPolicy(CompiledPolicy::compile(
            config,
            proxy_ingress,
        )?))
    }

    /// Publish a prepared snapshot and retire tuples the replacement no longer permits.
    pub(crate) fn publish_policy(&self, policy: PreparedPolicy) {
        let mut current = self
            .policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut next = policy.0;
        next.reuse_flow_tables(&current);
        // Packet checks take the policy read lock before a peer-table lock, so the write lock
        // holds every packet on one side of publication while revoked tuples are retired.
        for peer in &next.peers {
            let mut flows = peer
                .flows
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for slot in &mut flows.slots {
                if matches!(*slot, FlowSlot::Occupied(entry) if !next.allows_flow(entry)) {
                    *slot = FlowSlot::Removed;
                }
            }
        }
        *current = next;
    }

    /// Check one packet and apply an in-process mesh SSH port translation when needed.
    ///
    /// The source and destination must match this node's exact address and one known peer address.
    /// TCP flows start only on SYN; UDP and other protocols start only when their grant is `All`.
    /// Every later packet is admitted only while the grant that opened its flow remains present.
    pub(crate) fn check(&self, packet: &mut [u8], direction: Direction) -> bool {
        self.check_at(packet, direction, Instant::now())
    }

    /// Test seam for deterministic flow-expiry checks.
    fn check_at(&self, packet: &mut [u8], direction: Direction, now: Instant) -> bool {
        let Some(parsed) = parse_packet(packet) else {
            return false;
        };
        let policy = self
            .policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let Some(peer_address) = policy.peer_for_packet(parsed.key, direction) else {
            return false;
        };
        let Some(peer_index) = policy.peer_addresses.get(&peer_address).copied() else {
            return false;
        };
        let peer = &policy.peers[peer_index];
        let peer_id = peer.node;
        if let Some(related) = parsed.related {
            return Self::allow_related(related, peer_address, peer_id, &peer.flows, &policy, now);
        }

        let mut lookup_key = parsed.key;
        let mut ssh_reply_candidate = false;
        if direction == Direction::HostToMesh
            && parsed.key.protocol == TCP
            && parsed.key.source_port >= 960
            && parsed.key.source_port <= 1022
            && infraternal_mesh::mesh_ssh::listener_port(parsed.key.source)
                == Some(parsed.key.source_port)
        {
            lookup_key.source_port = 22;
            ssh_reply_candidate = true;
        }

        let slot_start = flow_start(lookup_key);
        let mut shard = peer
            .flows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((index, same_direction)) = shard.find(lookup_key, slot_start) {
            let entry = match shard.slots[index] {
                FlowSlot::Occupied(entry) => entry,
                FlowSlot::Empty | FlowSlot::Removed => return false,
            };
            let expired = now.saturating_duration_since(entry.last_seen) > entry.idle_timeout();
            if expired || !policy.allows_flow(entry) {
                shard.remove(index);
                // An expired tuple is treated as new. TCP continuations still cannot initiate it.
                if expired {
                    return Self::start_flow(
                        packet,
                        parsed,
                        direction,
                        peer_address,
                        peer_id,
                        peer_index,
                        &policy,
                        &mut shard,
                        now,
                    );
                }
                return false;
            }
            if ssh_reply_candidate && entry.ssh_redirect_port != Some(parsed.key.source_port) {
                return false;
            }
            let mut refreshed = entry;
            refreshed.last_seen = now;
            shard.slots[index] = FlowSlot::Occupied(refreshed);
            if let Some(port) = entry.ssh_redirect_port {
                let rewrite = if same_direction { port } else { 22 };
                let rewrite_offset = if same_direction {
                    parsed.transport_offset + 2
                } else {
                    parsed.transport_offset
                };
                if rewrite_offset + 2 > parsed.packet_end {
                    return false;
                }
                write_u16(packet, rewrite_offset, rewrite);
                recompute_transport_checksum(packet, &parsed);
            }
            return true;
        }

        if ssh_reply_candidate {
            return false;
        }
        Self::start_flow(
            packet,
            parsed,
            direction,
            peer_address,
            peer_id,
            peer_index,
            &policy,
            &mut shard,
            now,
        )
    }

    /// Admit and record a new tuple after its current grant and TCP initiation flags pass.
    fn start_flow(
        packet: &mut [u8],
        parsed: ParsedPacket,
        direction: Direction,
        peer_address: IpAddr,
        peer_id: NodeId,
        peer_index: usize,
        policy: &CompiledPolicy,
        shard: &mut FlowShard,
        now: Instant,
    ) -> bool {
        if parsed.key.protocol == TCP
            && !parsed.tcp_flags.is_some_and(|flags| {
                flags & TCP_SYN != 0 && flags & (TCP_ACK | TCP_FIN | TCP_RST) == 0
            })
        {
            return false;
        }
        let peer = &policy.peers[peer_index];
        let Some(grant) = policy.new_grant(peer, parsed.key, direction) else {
            return false;
        };
        let entry = FlowEntry {
            key: parsed.key,
            peer_address,
            peer_id,
            initiated: direction,
            grant,
            last_seen: now,
            ssh_redirect_port: grant.ssh_redirect_port,
        };
        let slot_start = flow_start(entry.key);
        if !shard.insert(entry, slot_start) {
            shard.reclaim_expired(now);
            if !shard.insert(entry, slot_start) {
                return false;
            }
        }
        if let Some(port) = entry.ssh_redirect_port {
            write_u16(packet, parsed.transport_offset + 2, port);
            recompute_transport_checksum(packet, &parsed);
        }
        true
    }

    /// Admit only an ICMP error that quotes a still-authorized flow to this exact peer.
    fn allow_related(
        key: FlowKey,
        peer_address: IpAddr,
        peer_id: NodeId,
        flow_table: &Mutex<FlowShard>,
        policy: &CompiledPolicy,
        now: Instant,
    ) -> bool {
        let slot_start = flow_start(key);
        let mut shard = flow_table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((index, _)) = shard.find(key, slot_start) else {
            return false;
        };
        let FlowSlot::Occupied(mut entry) = shard.slots[index] else {
            return false;
        };
        if entry.peer_address != peer_address
            || entry.peer_id != peer_id
            || now.saturating_duration_since(entry.last_seen) > entry.idle_timeout()
            || !policy.allows_flow(entry)
        {
            shard.remove(index);
            return false;
        }
        entry.last_seen = now;
        shard.slots[index] = FlowSlot::Occupied(entry);
        true
    }
}

/// The address and grant indexes that make up one atomically published policy snapshot.
#[derive(Clone)]
struct CompiledPolicy {
    local4: Ipv4Addr,
    local6: Ipv6Addr,
    node: crate::policy::model::NodeId,
    server: Option<crate::policy::model::NodeId>,
    peer_addresses: HashMap<IpAddr, usize>,
    peers: Vec<PeerAccess>,
    proxy_ingress: MeshProxyIngress,
}

impl CompiledPolicy {
    /// Build the empty snapshot used before this node receives coordinator policy.
    fn empty() -> Self {
        Self {
            local4: Ipv4Addr::UNSPECIFIED,
            local6: Ipv6Addr::UNSPECIFIED,
            node: crate::policy::model::NodeId(0),
            server: None,
            peer_addresses: HashMap::new(),
            peers: Vec::new(),
            proxy_ingress: MeshProxyIngress::default(),
        }
    }

    /// Build direct address indexes from one complete coordinator and proxy snapshot.
    fn compile(config: &Config, proxy_ingress: MeshProxyIngress) -> io::Result<Self> {
        let mut peer_addresses = HashMap::new();
        peer_addresses
            .try_reserve(config.peers.len().saturating_mul(2))
            .map_err(|_| io::Error::other("mesh peer address index could not be allocated"))?;
        let mut peers = Vec::new();
        peers
            .try_reserve(config.peers.len())
            .map_err(|_| io::Error::other("mesh peer policy index could not be allocated"))?;
        for (node, policy) in &config.peers {
            let index = peers.len();
            peers.push(PeerAccess::from_policy(*node, policy)?);
            for address in [
                IpAddr::V4(policy.peer.addresses.ipv4),
                IpAddr::V6(policy.peer.addresses.ipv6),
            ] {
                if address == IpAddr::V4(config.addresses.ipv4)
                    || address == IpAddr::V6(config.addresses.ipv6)
                    || peer_addresses.insert(address, index).is_some()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "mesh packet policy contains duplicate local or peer addresses",
                    ));
                }
            }
        }
        Ok(Self {
            local4: config.addresses.ipv4,
            local6: config.addresses.ipv6,
            node: config.node,
            server: config.server,
            peer_addresses,
            peers,
            proxy_ingress,
        })
    }

    /// Reuse each surviving peer's fixed conntrack table across an atomic policy replacement.
    fn reuse_flow_tables(&mut self, previous: &Self) {
        let mut old_index = 0;
        for peer in &mut self.peers {
            while old_index < previous.peers.len() && previous.peers[old_index].node < peer.node {
                old_index += 1;
            }
            if let Some(old) = previous
                .peers
                .get(old_index)
                .filter(|old| old.node == peer.node)
            {
                peer.flows = Arc::clone(&old.flows);
            }
        }
    }

    /// Return the peer address only when this packet uses the configured local address at this edge.
    fn peer_for_packet(&self, key: FlowKey, direction: Direction) -> Option<IpAddr> {
        let local_source = match key.source {
            IpAddr::V4(address) => address == self.local4,
            IpAddr::V6(address) => address == self.local6,
        };
        let local_destination = match key.destination {
            IpAddr::V4(address) => address == self.local4,
            IpAddr::V6(address) => address == self.local6,
        };
        match direction {
            Direction::HostToMesh if local_source => Some(key.destination),
            Direction::MeshToHost if local_destination => Some(key.source),
            _ => None,
        }
    }

    /// Resolve the current directional grant for a new flow, including proxy and SSH exceptions.
    fn new_grant(&self, peer: &PeerAccess, key: FlowKey, direction: Direction) -> Option<Grant> {
        let access = match direction {
            Direction::HostToMesh => &peer.outbound,
            Direction::MeshToHost => &peer.inbound,
        };
        // The listener's private port is only a destination after the authorized TCP/22 packet
        // has passed this filter. A direct packet to that port must not inherit an `All` grant.
        if direction == Direction::MeshToHost
            && key.protocol == TCP
            && key.destination_port != 22
            && infraternal_mesh::mesh_ssh::listener_port(key.destination)
                == Some(key.destination_port)
        {
            return None;
        }
        let transport = transport_protocol(key.protocol);
        let destination_port = (transport.is_some()).then_some(key.destination_port);

        if direction == Direction::MeshToHost && key.protocol == TCP && key.destination_port == 22 {
            if !self.admits_ssh(peer) {
                return None;
            }
            let listener_port = infraternal_mesh::mesh_ssh::listener_port(key.destination)?;
            let ssh_redirect_port = (listener_port != 22).then_some(listener_port);
            return Some(Grant {
                protocol: Some(Protocol::Tcp),
                port: Some(22),
                ssh: true,
                proxy: None,
                ssh_redirect_port,
            });
        }

        if direction == Direction::MeshToHost
            && key.protocol == TCP
            && let Some(backend_port) = self.proxy_backend_port(key.destination_port, access)
        {
            let listener_port = key.destination_port;
            return Some(Grant {
                protocol: Some(Protocol::Tcp),
                port: Some(backend_port),
                ssh: false,
                proxy: Some(ProxyGrant {
                    listener_port,
                    backend_port,
                }),
                ssh_redirect_port: None,
            });
        }

        if let (Some(protocol), Some(port)) = (transport, destination_port) {
            return access
                .allows(Port {
                    protocol,
                    number: port,
                })
                .then_some(Grant {
                    protocol: Some(protocol),
                    port: Some(port),
                    ssh: false,
                    proxy: None,
                    ssh_redirect_port: None,
                });
        }

        matches!(access, TrafficPolicy::All).then_some(Grant {
            protocol: None,
            port: None,
            ssh: false,
            proxy: None,
            ssh_redirect_port: None,
        })
    }

    /// Check a tracked flow against today's grant so a policy update closes revoked connections.
    fn allows_flow(&self, entry: FlowEntry) -> bool {
        let Some(index) = self.peer_addresses.get(&entry.peer_address).copied() else {
            return false;
        };
        let peer = &self.peers[index];
        if peer.node != entry.peer_id {
            return false;
        }
        if entry.grant.ssh {
            let expected_listener = entry.ssh_redirect_port.unwrap_or(22);
            return self.admits_ssh(peer)
                && infraternal_mesh::mesh_ssh::listener_port(entry.key.destination)
                    == Some(expected_listener);
        }
        if let Some(proxy) = entry.grant.proxy {
            let listener_matches = matches!(
                proxy.listener_port,
                port if self.proxy_ingress.listener_pair.is_some_and(|pair| pair.http == port || pair.https == port)
            );
            if !listener_matches
                || !self
                    .proxy_ingress
                    .backend_ports
                    .contains(&proxy.backend_port)
            {
                return false;
            }
        }
        let access = match entry.initiated {
            Direction::HostToMesh => &peer.outbound,
            Direction::MeshToHost => &peer.inbound,
        };
        match (entry.grant.protocol, entry.grant.port) {
            (Some(protocol), Some(number)) => access.allows(Port { protocol, number }),
            _ => matches!(access, TrafficPolicy::All),
        }
    }

    /// Apply the separate TCP/22 authority used on the server's own mesh node.
    fn admits_ssh(&self, peer: &PeerAccess) -> bool {
        match (peer.access_ssh, self.server) {
            (Some(admitted), _) => admitted,
            (None, Some(server)) if server != self.node => peer.inbound.allows(Port {
                protocol: Protocol::Tcp,
                number: 22,
            }),
            (None, _) => false,
        }
    }

    /// Find a published backend port that the peer may reach through the selected proxy listener.
    fn proxy_backend_port(&self, listener_port: u16, access: &TrafficPolicy) -> Option<u16> {
        let pair = self.proxy_ingress.listener_pair?;
        if listener_port != pair.http && listener_port != pair.https {
            return None;
        }
        self.proxy_ingress
            .backend_ports
            .iter()
            .copied()
            .find(|port| {
                access.allows(Port {
                    protocol: Protocol::Tcp,
                    number: *port,
                })
            })
    }
}

/// The directional grants copied from one peer's coordinator policy.
#[derive(Clone)]
struct PeerAccess {
    node: NodeId,
    inbound: TrafficPolicy,
    outbound: TrafficPolicy,
    access_ssh: Option<bool>,
    /// Each peer owns a separate fixed table so shard collisions cannot share its quota.
    flows: Arc<Mutex<FlowShard>>,
}

impl PeerAccess {
    /// Copy access data and allocate this peer's fixed conntrack table, not peer keys or endpoints.
    fn from_policy(node: NodeId, policy: &PeerPolicy) -> io::Result<Self> {
        Ok(Self {
            node,
            inbound: policy.inbound.clone(),
            outbound: policy.outbound.clone(),
            access_ssh: policy.access_ssh,
            flows: Arc::new(Mutex::new(FlowShard::new()?)),
        })
    }
}

/// The precise permission that admitted a flow and must remain true for its replies.
#[derive(Clone, Copy)]
struct Grant {
    protocol: Option<Protocol>,
    port: Option<u16>,
    ssh: bool,
    proxy: Option<ProxyGrant>,
    ssh_redirect_port: Option<u16>,
}

/// The proxy listener and backend port that admitted one reverse-proxy flow.
#[derive(Clone, Copy)]
struct ProxyGrant {
    listener_port: u16,
    backend_port: u16,
}

/// One bounded conntrack entry, stored under the tuple that initiated it.
#[derive(Clone, Copy)]
struct FlowEntry {
    key: FlowKey,
    peer_address: IpAddr,
    peer_id: NodeId,
    initiated: Direction,
    grant: Grant,
    last_seen: Instant,
    ssh_redirect_port: Option<u16>,
}

impl FlowEntry {
    /// Select the idle expiry that matches this flow's transport protocol.
    fn idle_timeout(self) -> Duration {
        match self.key.protocol {
            TCP => TCP_IDLE_TIMEOUT,
            UDP => UDP_IDLE_TIMEOUT,
            _ => OTHER_IDLE_TIMEOUT,
        }
    }

    /// Report whether an entry has exceeded its protocol-specific idle lifetime.
    fn expired(self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_seen) > self.idle_timeout()
    }
}

/// The fixed-size tuple used by the conntrack table and indexed in both directions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct FlowKey {
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    protocol: u8,
}

impl FlowKey {
    /// Reverse endpoint and port order for stateful reply lookups.
    fn reverse(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
            source_port: self.destination_port,
            destination_port: self.source_port,
            protocol: self.protocol,
        }
    }

    /// Choose one direction-independent tuple so both packet directions share one shard.
    fn canonical(self) -> Self {
        self.min(self.reverse())
    }
}

/// One open-addressing slot; removed entries remain tombstones until a later insert reuses them.
#[derive(Clone, Copy)]
enum FlowSlot {
    /// No entry has occupied this slot in the current probe chain.
    Empty,
    /// An entry was removed, so later keys in the probe chain must still be checked.
    Removed,
    /// A tracked tuple and the state needed to recheck its grant.
    Occupied(FlowEntry),
}

/// One fixed-size open-addressed conntrack shard protected independently from other flows.
struct FlowShard {
    slots: Vec<FlowSlot>,
}

impl FlowShard {
    /// Allocate this peer's complete slot array before packet workers start.
    fn new() -> io::Result<Self> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(FLOWS_PER_PEER)
            .map_err(|_| io::Error::other("mesh conntrack slots could not be allocated"))?;
        slots.resize(FLOWS_PER_PEER, FlowSlot::Empty);
        Ok(Self { slots })
    }

    /// Find either orientation of one flow and report whether the stored direction matched.
    fn find(&self, key: FlowKey, start: usize) -> Option<(usize, bool)> {
        for offset in 0..self.slots.len() {
            let index = (start + offset) % self.slots.len();
            match self.slots[index] {
                FlowSlot::Empty => return None,
                FlowSlot::Occupied(entry) if entry.key == key => return Some((index, true)),
                FlowSlot::Occupied(entry) if entry.key == key.reverse() => {
                    return Some((index, false));
                }
                FlowSlot::Removed | FlowSlot::Occupied(_) => {}
            }
        }
        None
    }

    /// Insert a flow without growing the slot array or allocating on the packet path.
    fn insert(&mut self, entry: FlowEntry, start: usize) -> bool {
        let mut removed = None;
        for offset in 0..self.slots.len() {
            let index = (start + offset) % self.slots.len();
            match self.slots[index] {
                FlowSlot::Empty => {
                    self.slots[removed.unwrap_or(index)] = FlowSlot::Occupied(entry);
                    return true;
                }
                FlowSlot::Removed => {
                    removed.get_or_insert(index);
                }
                FlowSlot::Occupied(existing)
                    if existing.key == entry.key || existing.key == entry.key.reverse() =>
                {
                    self.slots[index] = FlowSlot::Occupied(entry);
                    return true;
                }
                FlowSlot::Occupied(_) => {}
            }
        }
        if let Some(index) = removed {
            self.slots[index] = FlowSlot::Occupied(entry);
            true
        } else {
            false
        }
    }

    /// Turn one expired or revoked entry into a tombstone without breaking later probes.
    fn remove(&mut self, index: usize) {
        self.slots[index] = FlowSlot::Removed;
    }

    /// Reclaim idle entries only when a full shard refuses a new flow.
    fn reclaim_expired(&mut self, now: Instant) {
        for slot in &mut self.slots {
            if matches!(*slot, FlowSlot::Occupied(entry) if entry.expired(now)) {
                *slot = FlowSlot::Removed;
            }
        }
    }
}

/// Index a tuple inside its peer's fixed-size table in either packet direction.
fn flow_start(key: FlowKey) -> usize {
    let mut tuple_hasher = DefaultHasher::new();
    key.canonical().hash(&mut tuple_hasher);
    let tuple_hash = tuple_hasher.finish();
    usize::try_from(tuple_hash % FLOWS_PER_PEER_HASH).unwrap_or_default()
}

/// Parsed packet fields used for policy, conntrack and checksum-safe SSH translation.
#[derive(Clone, Copy)]
struct ParsedPacket {
    key: FlowKey,
    tcp_flags: Option<u8>,
    transport_offset: usize,
    packet_end: usize,
    related: Option<FlowKey>,
    version: u8,
}

/// Parse an IPv4 or IPv6 packet without copying its bytes or accepting fragments.
fn parse_packet(packet: &[u8]) -> Option<ParsedPacket> {
    let version = packet.first()? >> 4;
    let (source, destination, protocol, offset, packet_end) = match version {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let total_len = usize::from(read_u16(packet, 2)?);
            let fragment = read_u16(packet, 6)?;
            if header_len < 20
                || header_len > packet.len()
                || total_len < header_len
                || total_len > packet.len()
                || fragment & 0x3fff != 0
            {
                return None;
            }
            let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            (
                IpAddr::V4(source),
                IpAddr::V4(destination),
                packet[9],
                header_len,
                total_len,
            )
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let payload_len = usize::from(read_u16(packet, 4)?);
            let end = 40_usize.checked_add(payload_len)?;
            if end > packet.len() {
                return None;
            }
            let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
            let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
            let mut protocol = packet[6];
            let mut offset = 40;
            let mut headers = 0;
            while matches!(protocol, 0 | 43 | 44 | 51 | 60 | 135 | 139 | 140) {
                headers += 1;
                if headers > 8 || offset + 2 > end {
                    return None;
                }
                let next = packet[offset];
                let ext_len = match protocol {
                    44 => return None,
                    51 => (usize::from(packet[offset + 1]) + 2).checked_mul(4)?,
                    _ => (usize::from(packet[offset + 1]) + 1).checked_mul(8)?,
                };
                if ext_len < 8 || offset + ext_len > end {
                    return None;
                }
                protocol = next;
                offset += ext_len;
            }
            (
                IpAddr::V6(source),
                IpAddr::V6(destination),
                protocol,
                offset,
                end,
            )
        }
        _ => return None,
    };

    let (source_port, destination_port, tcp_flags, related) = match protocol {
        TCP => {
            if offset + 20 > packet_end {
                return None;
            }
            let header_len = usize::from(packet[offset + 12] >> 4) * 4;
            if header_len < 20 || offset + header_len > packet_end {
                return None;
            }
            (
                read_u16(packet, offset)?,
                read_u16(packet, offset + 2)?,
                Some(packet[offset + 13]),
                None,
            )
        }
        UDP => {
            if offset + 8 > packet_end {
                return None;
            }
            let udp_len = usize::from(read_u16(packet, offset + 4)?);
            if udp_len < 8 || offset + udp_len > packet_end {
                return None;
            }
            (
                read_u16(packet, offset)?,
                read_u16(packet, offset + 2)?,
                None,
                None,
            )
        }
        ICMP | ICMPV6 => {
            if offset + 4 > packet_end {
                return None;
            }
            let kind = packet[offset];
            let code = packet[offset + 1];
            if (protocol == ICMP && matches!(kind, 3 | 4 | 5 | 11 | 12))
                || (protocol == ICMPV6 && kind < 128)
            {
                let related = parse_quoted_flow(packet, offset + 8, packet_end)?;
                (0, 0, None, Some(related))
            } else if (protocol == ICMP && kind == 8 && code == 0)
                || (protocol == ICMPV6 && kind == 128 && code == 0)
            {
                if offset + 8 > packet_end {
                    return None;
                }
                (read_u16(packet, offset + 4)?, 0, None, None)
            } else if (protocol == ICMP && kind == 0 && code == 0)
                || (protocol == ICMPV6 && kind == 129 && code == 0)
            {
                if offset + 8 > packet_end {
                    return None;
                }
                (0, read_u16(packet, offset + 4)?, None, None)
            } else {
                (0, 0, None, None)
            }
        }
        _ => (0, 0, None, None),
    };

    Some(ParsedPacket {
        key: FlowKey {
            source,
            destination,
            source_port,
            destination_port,
            protocol,
        },
        tcp_flags,
        transport_offset: offset,
        packet_end,
        related,
        version,
    })
}

/// Read a quoted first packet tuple from an ICMP error for conntrack-related admission.
fn parse_quoted_flow(packet: &[u8], offset: usize, outer_end: usize) -> Option<FlowKey> {
    if offset + 20 > outer_end {
        return None;
    }
    let version = packet[offset] >> 4;
    let (source, destination, protocol, transport) = match version {
        4 => {
            let header_len = usize::from(packet[offset] & 0x0f) * 4;
            if header_len < 20 || offset + header_len + 4 > outer_end {
                return None;
            }
            let fragment = read_u16(packet, offset + 6)?;
            if fragment & 0x1fff != 0 {
                return None;
            }
            (
                IpAddr::V4(Ipv4Addr::new(
                    packet[offset + 12],
                    packet[offset + 13],
                    packet[offset + 14],
                    packet[offset + 15],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    packet[offset + 16],
                    packet[offset + 17],
                    packet[offset + 18],
                    packet[offset + 19],
                )),
                packet[offset + 9],
                offset + header_len,
            )
        }
        6 => {
            if offset + 44 > outer_end {
                return None;
            }
            let source =
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[offset + 8..offset + 24]).ok()?);
            let destination =
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[offset + 24..offset + 40]).ok()?);
            let mut protocol = packet[offset + 6];
            let mut transport = offset + 40;
            let mut headers = 0;
            while matches!(protocol, 0 | 43 | 44 | 51 | 60 | 135 | 139 | 140) {
                headers += 1;
                if headers > 8 || transport + 2 > outer_end || protocol == 44 {
                    return None;
                }
                let next = packet[transport];
                let ext_len = if protocol == 51 {
                    (usize::from(packet[transport + 1]) + 2) * 4
                } else {
                    (usize::from(packet[transport + 1]) + 1) * 8
                };
                if transport + ext_len + 4 > outer_end {
                    return None;
                }
                transport += ext_len;
                protocol = next;
            }
            (
                IpAddr::V6(source),
                IpAddr::V6(destination),
                protocol,
                transport,
            )
        }
        _ => return None,
    };
    if protocol != TCP && protocol != UDP {
        return None;
    }
    Some(FlowKey {
        source,
        destination,
        source_port: read_u16(packet, transport)?,
        destination_port: read_u16(packet, transport + 2)?,
        protocol,
    })
}

/// Translate an IP protocol number into the only port-bearing grant protocols.
fn transport_protocol(protocol: u8) -> Option<Protocol> {
    match protocol {
        TCP => Some(Protocol::Tcp),
        UDP => Some(Protocol::Udp),
        _ => None,
    }
}

/// Read one network-order 16-bit field after checking that both bytes exist.
fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *packet.get(offset)?,
        *packet.get(offset + 1)?,
    ]))
}

/// Write one network-order 16-bit field into a packet region already validated by the parser.
fn write_u16(packet: &mut [u8], offset: usize, value: u16) {
    packet[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

/// Recompute TCP's pseudo-header checksum after rewriting a mesh SSH port.
fn recompute_transport_checksum(packet: &mut [u8], parsed: &ParsedPacket) {
    if parsed.key.protocol != TCP || parsed.transport_offset + 18 > parsed.packet_end {
        return;
    }
    let checksum_offset = parsed.transport_offset + 16;
    packet[checksum_offset..checksum_offset + 2].fill(0);
    let transport_len = parsed.packet_end - parsed.transport_offset;
    let mut sum = 0_u32;
    if parsed.version == 4 {
        add_checksum_bytes(&mut sum, &packet[12..20]);
        sum += u32::from(TCP);
        sum += u32::try_from(transport_len).unwrap_or(u32::MAX);
    } else {
        add_checksum_bytes(&mut sum, &packet[8..40]);
        let transport_len = u32::try_from(transport_len).unwrap_or(u32::MAX);
        sum += transport_len >> 16;
        sum += transport_len & 0xffff;
        sum += u32::from(TCP);
    }
    add_checksum_bytes(
        &mut sum,
        &packet[parsed.transport_offset..parsed.packet_end],
    );
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    write_u16(
        packet,
        checksum_offset,
        !u16::try_from(sum).unwrap_or_default(),
    );
}

/// Add network-order 16-bit words to a folded one's-complement checksum accumulator.
fn add_checksum_bytes(sum: &mut u32, bytes: &[u8]) {
    for pair in bytes.chunks(2) {
        *sum += u32::from(u16::from_be_bytes([
            pair[0],
            pair.get(1).copied().unwrap_or(0),
        ]));
    }
}

#[cfg(test)]
/// Exercises D164 policy shapes and tuple behavior using real packet bytes.
mod tests {
    #![allow(clippy::expect_used)]

    use super::{Direction, PacketFilter};
    use crate::{
        dataplane::{Config, DefaultPolicy, Peer, PeerPolicy},
        policy::{
            model::{Addresses, NodeId, PublicKey},
            rules::{Port, Protocol, TrafficPolicy},
        },
    };
    use infraternal_mesh::{
        mesh_ssh,
        proxy_ports::{ListenerPortPair, MeshProxyIngress},
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        hash::{DefaultHasher, Hash, Hasher},
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::{Duration, Instant},
    };

    /// Local IPv4 mesh address used by the rule contract fixtures.
    const LOCAL4: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 1);
    /// Peer IPv4 mesh address used by the rule contract fixtures.
    const PEER4: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 2);
    /// Second known peer used to prove one source cannot consume another's flow budget.
    const OTHER_PEER4: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 3);
    /// Unknown IPv4 source used to prove spoofed packets are refused.
    const UNKNOWN4: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 99);
    /// Local IPv6 mesh address used by the rule contract fixtures.
    const LOCAL6: Ipv6Addr = Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 1);
    /// Peer IPv6 mesh address used by the rule contract fixtures.
    const PEER6: Ipv6Addr = Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 2);
    /// TCP SYN flag used to start a test flow.
    const SYN: u8 = 0x02;
    /// TCP SYN plus ACK flags used for a test reply.
    const SYN_ACK: u8 = 0x12;
    /// TCP ACK flag used to prove midstream packets cannot start a flow.
    const ACK: u8 = 0x10;

    /// Build one local mesh and one peer with the supplied directional access rules.
    fn config(inbound: TrafficPolicy, outbound: TrafficPolicy) -> Config {
        Config {
            local_key: None,
            server: None,
            authority_epoch: None,
            node: NodeId(1),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            version: 1,
            addresses: Addresses {
                ipv4: LOCAL4,
                ipv6: LOCAL6,
            },
            default_policy: DefaultPolicy::Deny,
            exposure: None,
            peers: BTreeMap::from([(
                NodeId(2),
                PeerPolicy {
                    peer: Peer {
                        key: PublicKey([2; 32]),
                        previous_key: None,
                        previous_active: false,
                        addresses: Addresses {
                            ipv4: PEER4,
                            ipv6: PEER6,
                        },
                        endpoint: None,
                    },
                    inbound,
                    outbound,
                    access_ssh: None,
                },
            )]),
            #[cfg(feature = "mesh-dns")]
            peer_names: BTreeMap::new(),
        }
    }

    /// Build a one-port grant for one transport protocol.
    fn grant(protocol: Protocol, number: u16) -> TrafficPolicy {
        TrafficPolicy::Ports(BTreeSet::from([Port { protocol, number }]))
    }

    /// Find peer ids that collided in the old shared-shard layout, so the test keeps covering that regression.
    fn legacy_shard(peer: NodeId) -> usize {
        let mut hasher = DefaultHasher::new();
        peer.0.hash(&mut hasher);
        usize::try_from(hasher.finish() & 63).expect("legacy shard index")
    }

    /// Build a minimal IPv4 TCP packet with a valid TCP checksum.
    fn tcp4(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let mut packet = vec![0; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        let checksum = tcp_checksum4(&packet);
        packet[36..38].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    /// Build a minimal IPv6 TCP packet with a valid TCP checksum.
    fn tcp6(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let mut packet = vec![0; 60];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&20_u16.to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[52] = 0x50;
        packet[53] = flags;
        let checksum = tcp_checksum6(&packet);
        packet[56..58].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    /// Build a minimal IPv4 UDP packet.
    fn udp4(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
        packet
    }

    /// Calculate the checksum of an IPv4 TCP packet, including its pseudo-header.
    fn tcp_checksum4(packet: &[u8]) -> u16 {
        let mut pseudo = [0_u8; 12];
        pseudo[..4].copy_from_slice(&packet[12..16]);
        pseudo[4..8].copy_from_slice(&packet[16..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&20_u16.to_be_bytes());
        checksum(&[&pseudo, &packet[20..]])
    }

    /// Calculate the checksum of an IPv6 TCP packet, including its pseudo-header.
    fn tcp_checksum6(packet: &[u8]) -> u16 {
        let mut pseudo = [0_u8; 40];
        pseudo[..32].copy_from_slice(&packet[8..40]);
        pseudo[32..36].copy_from_slice(&20_u32.to_be_bytes());
        pseudo[39] = 6;
        checksum(&[&pseudo, &packet[40..]])
    }

    /// Calculate the Internet checksum over several adjacent slices.
    fn checksum(parts: &[&[u8]]) -> u16 {
        let mut sum = 0_u32;
        for part in parts {
            for pair in part.chunks(2) {
                sum += u32::from(u16::from_be_bytes([
                    pair[0],
                    pair.get(1).copied().unwrap_or(0),
                ]));
            }
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !u16::try_from(sum).expect("folded checksum fits")
    }

    /// A packet policy change applies to the next packet and cannot keep a revoked flow open.
    #[test]
    fn none_denies_new_flows_in_both_directions() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, TrafficPolicy::None),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut outgoing = tcp4(LOCAL4, PEER4, 40000, 443, SYN);
        let mut incoming = tcp4(PEER4, LOCAL4, 40001, 443, SYN);
        assert!(!filter.check_at(&mut outgoing, Direction::HostToMesh, now));
        assert!(!filter.check_at(&mut incoming, Direction::MeshToHost, now));
    }

    /// An all-ports grant admits new TCP SYN and UDP flows, but never a midstream TCP packet.
    #[test]
    fn all_grants_allow_new_tcp_and_udp_but_not_midstream_tcp() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::All, TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut syn = tcp4(LOCAL4, PEER4, 40000, 443, SYN);
        let mut udp = udp4(LOCAL4, PEER4, 40001, 53);
        let mut ack = tcp4(LOCAL4, PEER4, 40002, 443, ACK);
        assert!(filter.check_at(&mut syn, Direction::HostToMesh, now));
        assert!(filter.check_at(&mut udp, Direction::HostToMesh, now));
        assert!(!filter.check_at(&mut ack, Direction::HostToMesh, now));
    }

    /// A busy peer reaches its per-caller flow bound without exhausting another peer's budget.
    #[test]
    fn flow_state_is_bounded_per_peer() {
        const PER_PEER_LIMIT: usize = 128;
        let mut policy = config(TrafficPolicy::All, TrafficPolicy::All);
        policy.peers.insert(
            NodeId(3),
            PeerPolicy {
                peer: Peer {
                    key: PublicKey([3; 32]),
                    previous_key: None,
                    previous_active: false,
                    addresses: Addresses {
                        ipv4: OTHER_PEER4,
                        ipv6: "fd01::3".parse().expect("other IPv6 peer"),
                    },
                    endpoint: None,
                },
                inbound: TrafficPolicy::All,
                outbound: TrafficPolicy::All,
                access_ssh: None,
            },
        );
        let filter = PacketFilter::new(&policy, MeshProxyIngress::default())
            .expect("compile two-peer policy");
        let now = Instant::now();
        for index in 0..PER_PEER_LIMIT {
            let mut packet = tcp4(
                LOCAL4,
                PEER4,
                20_000 + u16::try_from(index).expect("flow index"),
                443,
                SYN,
            );
            assert!(
                filter.check_at(&mut packet, Direction::HostToMesh, now),
                "peer flow {index}"
            );
        }
        let mut over_limit = tcp4(
            LOCAL4,
            PEER4,
            20_000 + u16::try_from(PER_PEER_LIMIT).expect("limit"),
            443,
            SYN,
        );
        assert!(!filter.check_at(&mut over_limit, Direction::HostToMesh, now));

        let mut other_peer = tcp4(LOCAL4, OTHER_PEER4, 40_000, 443, SYN);
        assert!(filter.check_at(&mut other_peer, Direction::HostToMesh, now));
    }

    /// Four peers filling a former shared shard cannot consume a fifth peer's independent quota.
    #[test]
    fn colliding_peers_keep_independent_flow_quotas() {
        const PER_PEER_LIMIT: usize = 128;
        let target_shard = legacy_shard(NodeId(2));
        let colliders: Vec<_> = (3_u64..=100_000)
            .filter(|id| legacy_shard(NodeId(*id)) == target_shard)
            .take(4)
            .map(NodeId)
            .collect();
        assert_eq!(colliders.len(), 4);

        let mut policy = config(TrafficPolicy::All, TrafficPolicy::All);
        let mut addresses = vec![(NodeId(2), PEER4)];
        for (index, node) in colliders.iter().enumerate() {
            let last = u8::try_from(index + 20).expect("fixture address");
            let address = Ipv4Addr::new(10, 254, 0, last);
            policy.peers.insert(
                *node,
                PeerPolicy {
                    peer: Peer {
                        key: PublicKey([last; 32]),
                        previous_key: None,
                        previous_active: false,
                        addresses: Addresses {
                            ipv4: address,
                            ipv6: Ipv6Addr::from(0xfd01_u128 << 112 | u128::from(last)),
                        },
                        endpoint: None,
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                    access_ssh: None,
                },
            );
            addresses.push((*node, address));
        }
        let filter = PacketFilter::new(&policy, MeshProxyIngress::default())
            .expect("compile colliding peer policies");
        let now = Instant::now();
        for (node, address) in addresses.iter().take(4) {
            for index in 0..PER_PEER_LIMIT {
                let mut packet = tcp4(
                    LOCAL4,
                    *address,
                    20_000 + u16::try_from(index).expect("flow index"),
                    443,
                    SYN,
                );
                assert!(
                    filter.check_at(&mut packet, Direction::HostToMesh, now),
                    "peer {} flow {index}",
                    node.0
                );
            }
        }

        let (fifth, address) = addresses.last().expect("fifth peer");
        let mut packet = tcp4(LOCAL4, *address, 50_000, 443, SYN);
        assert!(
            filter.check_at(&mut packet, Direction::HostToMesh, now),
            "peer {} must retain its own quota after older shard occupants fill theirs",
            fifth.0
        );
    }

    /// One peer cannot double its conntrack allowance by alternating IPv4 and IPv6.
    #[test]
    fn flow_state_limit_is_shared_across_address_families() {
        const PER_PEER_LIMIT: usize = 128;
        let filter = PacketFilter::new(
            &config(TrafficPolicy::All, TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        for index in 0..PER_PEER_LIMIT {
            let mut packet = tcp4(
                LOCAL4,
                PEER4,
                20_000 + u16::try_from(index).expect("flow index"),
                443,
                SYN,
            );
            assert!(filter.check_at(&mut packet, Direction::HostToMesh, now));
        }
        let mut ipv6 = tcp6(LOCAL6, PEER6, 40_000, 443, SYN);
        assert!(
            !filter.check_at(&mut ipv6, Direction::HostToMesh, now),
            "IPv4 and IPv6 addresses for one peer share the same flow quota"
        );
    }

    /// A policy replacement immediately releases tuple quota for flows it revokes.
    #[test]
    fn policy_replacement_reclaims_revoked_flow_quota() {
        const PER_PEER_LIMIT: usize = 128;
        let mut policy = config(TrafficPolicy::All, TrafficPolicy::All);
        let filter = PacketFilter::new(&policy, MeshProxyIngress::default())
            .expect("compile initial policy");
        let now = Instant::now();
        for index in 0..PER_PEER_LIMIT {
            let mut packet = tcp4(
                LOCAL4,
                PEER4,
                20_000 + u16::try_from(index).expect("flow index"),
                443,
                SYN,
            );
            assert!(filter.check_at(&mut packet, Direction::HostToMesh, now));
        }

        policy.peers.get_mut(&NodeId(2)).expect("peer").outbound = TrafficPolicy::None;
        filter.publish_policy(
            PacketFilter::prepare_policy(&policy, MeshProxyIngress::default())
                .expect("prepare revocation"),
        );
        policy.peers.get_mut(&NodeId(2)).expect("peer").outbound = grant(Protocol::Tcp, 8443);
        filter.publish_policy(
            PacketFilter::prepare_policy(&policy, MeshProxyIngress::default())
                .expect("prepare replacement grant"),
        );

        let mut replacement = tcp4(LOCAL4, PEER4, 40_000, 8443, SYN);
        assert!(filter.check_at(
            &mut replacement,
            Direction::HostToMesh,
            now + Duration::from_secs(1)
        ));
    }

    /// A port grant matches both the protocol and destination port, not just the number.
    #[test]
    fn port_grants_are_narrowed_by_transport_and_port() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut https = tcp4(LOCAL4, PEER4, 40000, 443, SYN);
        let mut ssh = tcp4(LOCAL4, PEER4, 40001, 22, SYN);
        let mut udp = udp4(LOCAL4, PEER4, 40002, 443);
        assert!(filter.check_at(&mut https, Direction::HostToMesh, now));
        assert!(!filter.check_at(&mut ssh, Direction::HostToMesh, now));
        assert!(!filter.check_at(&mut udp, Direction::HostToMesh, now));
    }

    /// Inbound and outbound grants remain separate, while a permitted flow keeps its reply.
    #[test]
    fn inbound_and_outbound_grants_are_directional_and_stateful() {
        let filter = PacketFilter::new(
            &config(grant(Protocol::Tcp, 443), TrafficPolicy::None),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut request = tcp4(PEER4, LOCAL4, 40000, 443, SYN);
        let mut response = tcp4(LOCAL4, PEER4, 443, 40000, SYN_ACK);
        let mut continuation = tcp4(PEER4, LOCAL4, 40000, 443, ACK);
        let mut unrelated = tcp4(LOCAL4, PEER4, 40001, 443, SYN);
        assert!(filter.check_at(&mut request, Direction::MeshToHost, now));
        assert!(filter.check_at(&mut response, Direction::HostToMesh, now));
        assert!(filter.check_at(&mut continuation, Direction::MeshToHost, now));
        assert!(!filter.check_at(&mut unrelated, Direction::HostToMesh, now));
    }

    /// A TCP flow starts only with SYN set and ACK, FIN and RST clear.
    #[test]
    fn tcp_initiation_requires_syn_without_ack() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        for flags in [ACK, SYN_ACK, 0x01, 0x04] {
            let mut packet = tcp4(LOCAL4, PEER4, 40000, 443, flags);
            assert!(
                !filter.check_at(&mut packet, Direction::HostToMesh, now),
                "flags {flags:#04x}"
            );
        }
    }

    /// Host-origin packets use only the local addresses, and tunnel packets use known peer sources.
    #[test]
    fn spoofed_mesh_addresses_are_rejected_at_both_tun_edges() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::All, TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut spoofed_local = tcp4(UNKNOWN4, PEER4, 40000, 443, SYN);
        let mut unknown_peer = tcp4(UNKNOWN4, LOCAL4, 40001, 443, SYN);
        assert!(!filter.check_at(&mut spoofed_local, Direction::HostToMesh, now));
        assert!(!filter.check_at(&mut unknown_peer, Direction::MeshToHost, now));
    }

    /// Expired state cannot admit a reply whose reverse-direction grant is absent.
    #[test]
    fn expired_flows_stop_admitting_replies() {
        let filter = PacketFilter::new(
            &config(grant(Protocol::Tcp, 443), TrafficPolicy::None),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let started = Instant::now();
        let mut request = tcp4(PEER4, LOCAL4, 40000, 443, SYN);
        let mut reply = tcp4(LOCAL4, PEER4, 443, 40000, SYN_ACK);
        assert!(filter.check_at(&mut request, Direction::MeshToHost, started));
        assert!(!filter.check_at(
            &mut reply,
            Direction::HostToMesh,
            started + super::TCP_IDLE_TIMEOUT + Duration::from_secs(1)
        ));
    }

    /// Updating one complete snapshot preserves still-allowed flows and closes revoked ones.
    #[test]
    fn policy_updates_apply_to_existing_flows() {
        let mut initial = config(grant(Protocol::Tcp, 443), TrafficPolicy::None);
        let filter = PacketFilter::new(&initial, MeshProxyIngress::default())
            .expect("compile initial policy");
        let now = Instant::now();
        let mut request = tcp4(PEER4, LOCAL4, 40000, 443, SYN);
        let mut reply = tcp4(LOCAL4, PEER4, 443, 40000, SYN_ACK);
        assert!(filter.check_at(&mut request, Direction::MeshToHost, now));
        filter.publish_policy(
            PacketFilter::prepare_policy(&initial, MeshProxyIngress::default())
                .expect("prepare same policy"),
        );
        assert!(filter.check_at(
            &mut reply,
            Direction::HostToMesh,
            now + Duration::from_secs(1)
        ));
        initial.peers.get_mut(&NodeId(2)).expect("peer").inbound = TrafficPolicy::None;
        filter.publish_policy(
            PacketFilter::prepare_policy(&initial, MeshProxyIngress::default())
                .expect("prepare revocation"),
        );
        let mut revoked = tcp4(PEER4, LOCAL4, 40000, 443, ACK);
        assert!(!filter.check_at(
            &mut revoked,
            Direction::MeshToHost,
            now + Duration::from_secs(2)
        ));
    }

    /// Reassigning one peer address cannot transfer its already-open flow to another mesh node.
    #[test]
    fn a_reassigned_peer_address_does_not_inherit_existing_flow_state() {
        let mut initial = config(grant(Protocol::Tcp, 443), TrafficPolicy::None);
        let filter = PacketFilter::new(&initial, MeshProxyIngress::default())
            .expect("compile initial policy");
        let now = Instant::now();
        let mut request = tcp4(PEER4, LOCAL4, 40000, 443, SYN);
        assert!(filter.check_at(&mut request, Direction::MeshToHost, now));

        let previous_shard = legacy_shard(NodeId(2));
        let replacement = (3_u64..=100_000)
            .map(NodeId)
            .find(|node| legacy_shard(*node) == previous_shard)
            .expect("another peer id shares this shard");
        let mut reassigned = initial.peers.remove(&NodeId(2)).expect("old peer");
        reassigned.peer.key = PublicKey([3; 32]);
        initial.peers.insert(replacement, reassigned);
        filter.publish_policy(
            PacketFilter::prepare_policy(&initial, MeshProxyIngress::default())
                .expect("prepare address reassignment"),
        );

        let mut continuation = tcp4(PEER4, LOCAL4, 40000, 443, ACK);
        assert!(!filter.check_at(
            &mut continuation,
            Direction::MeshToHost,
            now + Duration::from_secs(1)
        ));
    }

    /// IPv6 packets use the same directional and port-narrowing rules as IPv4.
    #[test]
    fn ipv6_uses_directional_port_policy() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let mut allowed = tcp6(LOCAL6, PEER6, 40000, 443, SYN);
        let mut denied = tcp6(LOCAL6, PEER6, 40001, 22, SYN);
        let now = Instant::now();
        assert!(filter.check_at(&mut allowed, Direction::HostToMesh, now));
        assert!(!filter.check_at(&mut denied, Direction::HostToMesh, now));
    }

    /// Mesh SSH checks the original TCP/22 grant before translation and restores replies to port 22.
    #[test]
    fn ssh_redirect_translates_requests_and_replies_inside_the_filter() {
        let mut policy = config(TrafficPolicy::All, TrafficPolicy::None);
        policy.server = Some(NodeId(3));
        let filter =
            PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile policy");
        mesh_ssh::publish_listener(IpAddr::V4(LOCAL4), 1001).expect("publish private listener");
        let now = Instant::now();
        let mut request = tcp4(PEER4, LOCAL4, 40000, 22, SYN);
        assert!(filter.check_at(&mut request, Direction::MeshToHost, now));
        assert_eq!(u16::from_be_bytes([request[22], request[23]]), 1001);
        assert_eq!(tcp_checksum4(&request), 0);
        let mut reply = tcp4(LOCAL4, PEER4, 1001, 40000, SYN_ACK);
        assert!(filter.check_at(
            &mut reply,
            Direction::HostToMesh,
            now + Duration::from_secs(1)
        ));
        assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 22);
        assert_eq!(tcp_checksum4(&reply), 0);
        mesh_ssh::clear_listener(IpAddr::V4(LOCAL4), 1001);
    }

    /// A grant for all ports cannot reach the SSH listener's private redirect port directly.
    #[test]
    fn ssh_private_redirect_port_is_not_a_grantable_mesh_port() {
        let local = Ipv4Addr::new(10, 254, 99, 5);
        let peer = Ipv4Addr::new(10, 254, 99, 6);
        let address = IpAddr::V4(local);
        mesh_ssh::clear_listener(address, 1005);
        mesh_ssh::publish_listener(address, 1005).expect("publish private listener");
        let mut policy = config(TrafficPolicy::All, TrafficPolicy::All);
        policy.addresses.ipv4 = local;
        policy
            .peers
            .get_mut(&NodeId(2))
            .expect("fixture peer")
            .peer
            .addresses
            .ipv4 = peer;
        let filter =
            PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile policy");
        let mut direct = tcp4(peer, local, 40_005, 1005, SYN);

        assert!(!filter.check_at(&mut direct, Direction::MeshToHost, Instant::now()));
        mesh_ssh::clear_listener(address, 1005);
    }

    /// An IPv6 peer with an `All` grant cannot use the SSH redirect port as an independent port.
    #[test]
    fn ipv6_ssh_private_redirect_port_is_not_a_grantable_mesh_port() {
        let local: Ipv6Addr = "fd01::5".parse().expect("local IPv6 address");
        let peer: Ipv6Addr = "fd01::6".parse().expect("peer IPv6 address");
        let address = IpAddr::V6(local);
        mesh_ssh::clear_listener(address, 1006);
        mesh_ssh::publish_listener(address, 1006).expect("publish private listener");
        let mut policy = config(TrafficPolicy::All, TrafficPolicy::All);
        policy.addresses.ipv6 = local;
        policy
            .peers
            .get_mut(&NodeId(2))
            .expect("fixture peer")
            .peer
            .addresses
            .ipv6 = peer;
        let filter =
            PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile policy");
        let mut direct = tcp6(peer, local, 40_006, 1006, SYN);

        assert!(!filter.check_at(&mut direct, Direction::MeshToHost, Instant::now()));
        mesh_ssh::clear_listener(address, 1006);
    }

    /// A TCP/22 grant cannot fall through to the host SSH daemon without a mesh listener.
    #[test]
    fn ssh_access_is_refused_without_a_published_local_listener() {
        let local = Ipv4Addr::new(10, 254, 99, 1);
        let peer = Ipv4Addr::new(10, 254, 99, 2);
        let address = IpAddr::V4(local);
        mesh_ssh::clear_listener(address, 1001);
        let mut policy = config(TrafficPolicy::All, TrafficPolicy::None);
        policy.server = Some(NodeId(3));
        policy.addresses.ipv4 = local;
        policy
            .peers
            .get_mut(&NodeId(2))
            .expect("fixture peer")
            .peer
            .addresses
            .ipv4 = peer;
        let filter =
            PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile policy");
        let mut request = tcp4(peer, local, 40_000, 22, SYN);

        assert!(!filter.check_at(&mut request, Direction::MeshToHost, Instant::now()));
    }

    /// Closing a mesh SSH listener retires its existing TCP/22 flow immediately.
    #[test]
    fn stopping_ssh_listener_revokes_open_filter_flows() {
        let local = Ipv4Addr::new(10, 254, 99, 3);
        let peer = Ipv4Addr::new(10, 254, 99, 4);
        let address = IpAddr::V4(local);
        mesh_ssh::clear_listener(address, 1003);
        mesh_ssh::publish_listener(address, 1003).expect("publish private listener");
        let mut policy = config(TrafficPolicy::All, TrafficPolicy::None);
        policy.server = Some(NodeId(3));
        policy.addresses.ipv4 = local;
        policy
            .peers
            .get_mut(&NodeId(2))
            .expect("fixture peer")
            .peer
            .addresses
            .ipv4 = peer;
        let filter =
            PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile policy");
        let now = Instant::now();
        let mut request = tcp4(peer, local, 40_000, 22, SYN);
        assert!(filter.check_at(&mut request, Direction::MeshToHost, now));
        mesh_ssh::clear_listener(address, 1003);
        let mut continuation = tcp4(peer, local, 40_000, 22, ACK);

        assert!(!filter.check_at(
            &mut continuation,
            Direction::MeshToHost,
            now + Duration::from_secs(1)
        ));
    }

    /// The selected proxy pair is admitted only to peers with an inbound backend-port grant.
    #[test]
    fn proxy_listener_exception_uses_the_peer_backend_grant() {
        let ingress = MeshProxyIngress {
            listener_pair: Some(ListenerPortPair {
                http: 10080,
                https: 10443,
            }),
            backend_ports: BTreeSet::from([8080]),
            ..MeshProxyIngress::default()
        };
        let filter = PacketFilter::new(
            &config(grant(Protocol::Tcp, 8080), TrafficPolicy::None),
            ingress,
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut proxy = tcp4(PEER4, LOCAL4, 40000, 10080, SYN);
        let mut unselected = tcp4(PEER4, LOCAL4, 40001, 10081, SYN);
        assert!(filter.check_at(&mut proxy, Direction::MeshToHost, now));
        assert!(!filter.check_at(&mut unselected, Direction::MeshToHost, now));
    }

    /// Malformed and fragmented headers fail closed because their initiating tuple is ambiguous.
    #[test]
    fn malformed_and_fragmented_packets_are_rejected() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::All, TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut malformed = vec![0; 8];
        let mut fragmented = tcp4(LOCAL4, PEER4, 40000, 443, SYN);
        fragmented[6] = 0x20;
        assert!(!filter.check_at(&mut malformed, Direction::HostToMesh, now));
        assert!(!filter.check_at(&mut fragmented, Direction::HostToMesh, now));
    }

    /// The parsed test addresses are ordinary values, not packet-path allocations.
    #[test]
    fn test_addresses_match_the_configured_families() {
        assert_eq!(
            IpAddr::V4(LOCAL4),
            "10.254.0.1".parse::<IpAddr>().expect("IPv4")
        );
        assert_eq!(
            IpAddr::V6(PEER6),
            "fd01::2".parse::<IpAddr>().expect("IPv6")
        );
    }
}
