//! Checks every packet at the GotaTun TUN boundary against one complete mesh policy snapshot [D164,D384].
//!
//! # State and memory (J675, J721, #265)
//!
//! A peer gets a fixed flow table only when its first flow is admitted (J721, #265). The table
//! is never grown while packets are checked:
//! - **Flows:** 256 per direction ([`FLOWS_PER_DIRECTION`]), 512 slots of 104 bytes. When a
//!   direction is full, a new flow first reclaims expired and revoked entries. Then it evicts
//!   that direction's least recently seen flow that is not an established TCP connection. Only
//!   when every flow left is established does it evict one, the oldest that has been silent
//!   for at least [`TCP_ESTABLISHED_EVICTABLE_IDLE`]. A live connection is never evicted.
//! - **Timeouts** follow Linux conntrack's defaults: established TCP 5 days, opening 60 s,
//!   closing 120 s, closed 10 s; UDP 30 s unreplied and 120 s replied; other protocols 60 s.
//! - **Revocation:** every packet of a tracked flow is checked against the grants published
//!   now. A revoked grant therefore ends its flows the moment the new policy is published,
//!   whatever their timeout. The sweep after a publish frees their slots.
//! - **Memory:** about 0.1 KB per configured peer, plus about 68 KB for each peer that has
//!   flows. Its 64 fragment slots are allocated separately, the first time the peer fragments.
//!   The table must fit the 72 KiB budget ([`PER_PEER_MEMORY_BUDGET`], checked at build time).
//!   At D393's design scale of 1,000 peers with 10 of them active, the filter adds under
//!   1 MiB. Compiling a policy allocates no tables, so publishing never doubles memory.
//! - **Publishing** a policy swaps one pointer under the write lock, the only lock every packet
//!   waits behind, so it costs the same at 4,096 peers as at 4. The flow tables live outside the
//!   policy, in [`PacketFilter::tables`], and survive the swap unchanged.

use crate::{
    dataplane::{Config, PeerPolicy},
    policy::{
        model::NodeId,
        rules::{Port, Protocol, TrafficPolicy},
    },
};
use infraternal_mesh::proxy_ports::MeshProxyIngress;
use std::{
    collections::{BTreeMap, HashMap, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::{Duration, Instant},
};

/// Host settings the filter relies on instead of parsing the packet itself, with the value each
/// must have (J592 P3-11, #265).
///
/// The filter judges the source, destination, protocol and ports of the packet as it arrives.
/// Linux can act on parts of a packet the filter does not judge, and these settings turn that
/// off:
/// - `net.ipv4.conf.all.accept_source_route = 0`: an IPv4 packet carrying a loose or strict
///   source-route option (LSRR/SSRR) is dropped rather than routed on to the next hop it names.
/// - `net.ipv6.conf.all.accept_source_route <= 0`: an IPv6 routing header with segments left is
///   not followed (0 still accepts the type 2 header that Mobile IPv6 uses; -1 refuses all).
///
/// Both are the kernel defaults on a host that does not forward. Known gaps that no setting
/// closes, documented here rather than hidden: under an `All` grant a peer can reach the
/// kernel's default IPIP, GRE and SIT tunnel devices (it is trusted for every protocol anyway);
/// ICMP errors about a mesh SSH flow redirected to its private port are not translated back, so
/// path-MTU discovery on that flow relies on the peer's MSS; and a later fragment that arrives
/// before its first fragment is dropped, so the sender retransmits.
#[cfg(any(test, target_os = "linux"))]
pub(crate) const REQUIRED_SYSCTLS: [(&str, i64); 2] = [
    ("net/ipv4/conf/all/accept_source_route", 0),
    ("net/ipv6/conf/all/accept_source_route", 0),
];

/// The required settings this host does not meet, as `name = value (want <= limit)` lines.
///
/// `read` returns a setting's current text, or `None` when it cannot be read (a missing IPv6
/// stack, a sandbox); unreadable settings are not reported. Values above the limit are reported.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn sysctl_gaps(read: impl Fn(&str) -> Option<String>) -> Vec<String> {
    REQUIRED_SYSCTLS
        .iter()
        .filter_map(|(name, limit)| {
            let value = read(name)?.trim().parse::<i64>().ok()?;
            (value > *limit)
                .then(|| format!("{} = {value} (want <= {limit})", name.replace('/', ".")))
        })
        .collect()
}

/// Read [`REQUIRED_SYSCTLS`] from `/proc/sys` and log a warning for each setting that would
/// let the kernel act on a part of a packet the filter does not judge.
///
/// Called once when the `GotaTun` engine starts. It warns rather than refuses: the settings are
/// host-wide, owned by the host's own configuration, and the defaults are already correct.
#[cfg(target_os = "linux")]
pub(crate) fn warn_about_sysctl_gaps() {
    for gap in sysctl_gaps(|name| std::fs::read_to_string(format!("/proc/sys/{name}")).ok()) {
        tracing::warn!(setting = %gap, "mesh packet filter relies on a host setting that is not at its required value");
    }
}

/// A packet's position relative to this host and its mesh peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Direction {
    /// A host packet that is about to enter `GotaTun` and be sent to a peer.
    HostToMesh,
    /// An authenticated peer packet that is about to enter the host stack.
    MeshToHost,
}

// Idle timeouts per flow state (J672 P1, #265). They follow the Linux conntrack defaults the
// `GotaTun` path relied on before D384 (`tcp_timeouts[]` in
// `net/netfilter/nf_conntrack_proto_tcp.c` and `nf_conntrack_proto_udp.c`), so a connection that
// lived under the kernel firewall lives the same way under this filter. A long timeout cannot
// keep a revoked grant alive: [`PacketFilter::publish_policy`] retires every flow the new
// snapshot no longer permits, whatever its age. Table pressure is handled by
// [`FlowShard::evict_idle`], which evicts an established connection only after an hour of
// silence, and only from a full direction.

/// Keep an established TCP connection through long idle periods: 5 days, conntrack's
/// `ESTABLISHED` timeout. An idle SSH session, a database pool or a keep-alive HTTP connection
/// with no keep-alive traffic must still carry its next packet hours later.
const TCP_ESTABLISHED_TIMEOUT: Duration = Duration::from_hours(120);
/// How long an established TCP connection must be silent before a full direction may evict it
/// to admit a new flow: 1 hour (J721, #265).
///
/// Why: when a peer loses power or leaves the network, its connections end without a FIN or
/// RST the filter could see. Under the 5-day timeout alone, a peer that went silent holding a
/// full quota of connections could open no new connection from its side for 5 days (J718 P2).
/// An hour is longer than any keep-alive a live connection sends (Linux TCP sends its first
/// keepalive after 2 h only when enabled; SSH and databases that want a long-idle connection
/// to survive set keep-alives in minutes). It is used only under quota pressure, so an idle
/// connection survives for the full 5 days unless its peer pair is actually full. Rejected:
/// going back to short timeouts, which cut long-idle connections that have room (J672 P1).
const TCP_ESTABLISHED_EVICTABLE_IDLE: Duration = Duration::from_hours(1);
/// Expire a TCP flow whose three-way handshake has not finished: its SYN is unanswered, or its
/// SYN-ACK has not been acknowledged yet (half-open). Conntrack's `SYN_RECV` timeout, 60 s. (Its
/// `SYN_SENT` is 120 s; a SYN retransmitted after this expiry simply opens the flow again.)
const TCP_OPENING_TIMEOUT: Duration = Duration::from_secs(60);
/// Expire a half-closed TCP flow (FIN seen in one direction) that has gone quiet: conntrack's
/// `FIN_WAIT` and `TIME_WAIT` timeout, 120 s.
const TCP_CLOSING_TIMEOUT: Duration = Duration::from_secs(120);
/// Keep a closed TCP flow (FIN both ways, or RST) just long enough for the last ACK and any
/// retransmitted FIN, then free its slot: conntrack's `CLOSE` timeout, 10 s.
const TCP_CLOSED_TIMEOUT: Duration = Duration::from_secs(10);
/// Keep a UDP flow that has seen a reply for 120 s of silence: conntrack's
/// `nf_conntrack_udp_timeout_stream` in current kernels (older kernels used 180 s). Long enough
/// for request/response protocols with slow keep-alives.
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Expire a UDP flow that never saw a reply sooner: conntrack's `nf_conntrack_udp_timeout`, 30 s.
const UDP_UNREPLIED_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound the work a peer can make the filter retain for non-TCP and non-UDP flows.
const OTHER_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// The most flows one peer pair may track in each direction: opened by this host towards the
/// peer, and opened by the peer towards this host.
///
/// 256 (J675, #265; was 128): an established connection is never evicted and now lives for
/// days, so the quota is what a busy process on the peer must exhaust before other users of
/// that peer are refused new connections from the same side. 256 per side doubles that
/// headroom at no memory cost; see [`PER_PEER_MEMORY_BUDGET`].
///
/// Each direction has its own quota, so connections opened from one side can never use up the
/// other side's slots: a process on the peer that holds 256 connections to this host does not
/// stop this host connecting to the peer, nor the owner's mesh SSH arriving from elsewhere on
/// the mesh (J617 P2, #265). When a direction's quota is full, a new flow in that direction
/// first reclaims expired entries and then evicts that direction's least recently seen flow
/// that is not an established TCP connection, or else its oldest established connection silent
/// for [`TCP_ESTABLISHED_EVICTABLE_IDLE`] (see [`FlowShard::evict_idle`]), so closed
/// connections, finished UDP exchanges and connections whose peer vanished never cut a peer off
/// for long (J592 P1-3, J718 P2).
const FLOWS_PER_DIRECTION: usize = 256;
/// Slots in each peer's fixed table: room for both directions' full quotas at once, so a
/// direction under its quota always finds a free slot.
const FLOW_SLOTS_PER_PEER: usize = 2 * FLOWS_PER_DIRECTION;
/// `FLOW_SLOTS_PER_PEER` represented without narrowing a packet hash on 32-bit hosts. A test
/// checks that the two agree.
const FLOW_SLOTS_PER_PEER_HASH: u64 = 512;
/// The memory budget for the fixed filter tables of one peer that has flows: 72 KiB.
///
/// Why this number: it is the footprint already reviewed and measured for D394 (J618: 68,144
/// bytes per peer) with a little room, so raising the flow quota does not grow the filter.
/// Measured at J675 (`flow_table_memory_per_peer_times_one_thousand_peers` prints it): a flow
/// slot is 104 bytes, so the 512 flow slots take 53,248 bytes; the 64 fragment associations
/// with their 32-range coverage records take about 15 KiB. Since J721 only peers with flows
/// pay it. An idle peer costs its [`PeerAccess`] entry and, once it has sent a packet, a
/// [`PeerFlows`] cell of about 100 bytes (`idle_peers_allocate_no_flow_tables` measures RSS).
const PER_PEER_MEMORY_BUDGET: usize = 72 * 1024;
// The build fails when the fixed tables outgrow the budget, so a change to an entry's layout or
// a table size cannot grow per-peer memory unnoticed.
const _: () = assert!(
    std::mem::size_of::<FlowSlot>() * FLOW_SLOTS_PER_PEER
        + (std::mem::size_of::<FragmentSlot>() + std::mem::size_of::<FragmentCoverage>())
            * FRAGMENTS_PER_PEER
        + std::mem::size_of::<PeerFlows>()
        + std::mem::size_of::<PeerAccess>()
        <= PER_PEER_MEMORY_BUDGET
);
/// Expire a fragment association before the IP reassembly window can become stale.
const FRAGMENT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound the number of fragmented datagrams each peer can have in flight.
const FRAGMENTS_PER_PEER: usize = 64;
/// `FRAGMENTS_PER_PEER` represented without narrowing a packet hash on 32-bit hosts.
const FRAGMENTS_PER_PEER_HASH: u64 = 64;
/// Bound the number of disjoint fragment ranges tracked for one datagram without allocating.
///
/// 32 gaps is far more than real reordering produces: a 64 KiB datagram in 1,280-byte
/// fragments has 52 fragments, and in-order arrival keeps a single range. A datagram that needs
/// more is still delivered; its association just stays until [`FRAGMENT_IDLE_TIMEOUT`] instead
/// of retiring when complete. Each range is 4 bytes, so 32 instead of 128 saves 24 KiB per
/// peer and pays for the doubled flow quota (J675, see [`PER_PEER_MEMORY_BUDGET`]).
const FRAGMENT_RANGES_PER_DATAGRAM: usize = 32;
/// IP protocol number for TCP packets.
const TCP: u8 = 6;
/// Length of a TCP header without options, the least every judged TCP packet must carry.
const TCP_MIN_HEADER: usize = 20;
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

/// Publishes new policy snapshots atomically and checks packets against the current one.
///
/// Lock order, always taken in this order and never the reverse: `writer`, then `policy`, then
/// `tables`, then one peer's [`PeerFlows::table`]. A packet takes the `policy` read lock, then
/// `tables` only when it binds a peer's cell (see [`Self::flows_for`]), then the peer's table.
/// The post-publish sweep takes `tables` and only `try_lock`s peer tables, so a packet never
/// waits for it.
pub(crate) struct PacketFilter {
    /// The published snapshot. A publish replaces the pointer and nothing else, so the write
    /// lock that every packet waits behind lasts the same at any peer count (J721, #265).
    policy: RwLock<Arc<CompiledPolicy>>,
    /// Each peer's flow cell, keyed by node, outside any one policy snapshot so that flows
    /// survive a publish without being copied. A peer gets an entry on its first packet. The
    /// sweep after each publish drops the entries of peers the new policy no longer has.
    tables: Mutex<BTreeMap<NodeId, Arc<PeerFlows>>>,
    /// Serialises publish, withdraw and their sweep, so a sweep never judges flows against a
    /// snapshot that a concurrent publish has already replaced.
    writer: Mutex<()>,
}

/// One fully compiled snapshot that can be published after its related routes and peers succeed.
pub(crate) struct PreparedPolicy(CompiledPolicy);

impl PreparedPolicy {
    /// Leave these peers out of the snapshot before it is published, so their addresses admit
    /// nothing; see [`PacketFilter::withdraw_peers`]. Publishing the result also retires their
    /// open flows, because [`CompiledPolicy::allows_flow`] resolves a flow's peer by address.
    #[must_use]
    pub(crate) fn without_peers(mut self, withdrawn: &std::collections::BTreeSet<NodeId>) -> Self {
        self.0.withdraw(withdrawn);
        self
    }
}

impl PacketFilter {
    /// Build an empty, deny-by-default filter for a node that has not received its first snapshot.
    ///
    /// A peer's flow table is allocated once, when its first flow is admitted, and is never
    /// grown while packets are checked. If it cannot be allocated, that packet is dropped.
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
            policy: RwLock::new(Arc::new(policy)),
            tables: Mutex::new(BTreeMap::new()),
            writer: Mutex::new(()),
        }
    }

    /// Compile a policy before changing routes or device peers, so publication cannot fail later.
    ///
    /// It copies only the grants and the address index. No flow tables are allocated here:
    /// each peer's existing table stays in [`Self::tables`] and is found again on its next
    /// packet after the publish.
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

    /// A prepared deny-all snapshot, published when a failed transaction cannot rebuild the
    /// previous one, so the packet path fails closed.
    pub(crate) fn deny_all_policy() -> PreparedPolicy {
        PreparedPolicy(CompiledPolicy::empty())
    }

    /// Stop admitting packets from these peers' addresses at once, before the engine's peer set
    /// changes.
    ///
    /// The filter knows a peer only by its source address. When a snapshot gives a removed
    /// peer's address to another node, or moves a peer to a new address, the engine starts
    /// delivering the new owner's packets as soon as its peers are applied; until the new policy
    /// is published, those packets would otherwise use the old owner's grants and open flows
    /// (J592 P2-5, #265). Withdrawing only removes index entries. Their flows stop matching
    /// too, because [`CompiledPolicy::allows_flow`] resolves the flow's peer by address.
    ///
    /// The snapshot is edited in place under the write lock. Packets borrow it through the
    /// read lock without holding a second reference, so the edit allocates nothing. Only a
    /// sweep running at that moment holds one, and `writer` rules that out.
    pub(crate) fn withdraw_peers(&self, withdrawn: &std::collections::BTreeSet<NodeId>) {
        if withdrawn.is_empty() {
            return;
        }
        let _writer = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut current = self
            .policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::make_mut(&mut current).withdraw(withdrawn);
    }

    /// Publish a prepared snapshot. From that moment no packet rides a flow the replacement
    /// no longer permits.
    ///
    /// Under the write lock this only swaps the snapshot pointer, so a publish holds packets
    /// for the same short time at 4,096 peers as at 4 (J721, #265; J718 measured 7.3 ms while
    /// every peer's table was copied and scanned under the lock). Revocation needs no scan
    /// under the lock either: every packet of a tracked flow is checked with
    /// [`CompiledPolicy::allows_flow`] against the snapshot it reads, so a revoked flow admits
    /// nothing after the swap. The sweep that follows frees revoked and expired slots outside
    /// the lock. It visits only peers that have a table. The old snapshot is dropped after the
    /// lock is released.
    pub(crate) fn publish_policy(&self, policy: PreparedPolicy) {
        let _writer = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next = Arc::new(policy.0);
        let previous = {
            let mut current = self
                .policy
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::replace(&mut *current, Arc::clone(&next))
        };
        drop(previous);
        self.sweep(&next, Instant::now());
    }

    /// Free the slots of flows `policy` no longer permits or that have expired, free tables
    /// left empty, and forget peers `policy` no longer has.
    ///
    /// Runs after a publish and outside every packet lock. It walks only the peers that have a
    /// flow cell, not every configured peer. A table that a packet is using right now is
    /// skipped rather than waited for. It is cleaned the next time its direction fills up
    /// (see [`FlowShard::reclaim`]), and its revoked flows admit nothing in the meantime.
    fn sweep(&self, policy: &CompiledPolicy, now: Instant) {
        let mut tables = self
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tables.retain(|node, cell| {
            if policy.peer_by_node(*node).is_none() {
                return false;
            }
            let mut table = match cell.table.try_lock() {
                Ok(table) => table,
                Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => return true,
            };
            if let Some(shard) = table.as_mut() {
                shard.reclaim(now, policy);
                shard.remove_orphaned_fragments();
                if shard.is_empty() {
                    *table = None;
                }
            }
            true
        });
    }

    /// The flow cell of `peer`, binding the snapshot's peer entry to it on the peer's first
    /// packet after a publish.
    ///
    /// The bound pointer is read without a lock on every later packet. Binding takes the
    /// `tables` lock once per peer per publish. A new cell is about 100 bytes; the 68 KB table
    /// inside it is allocated, fallibly, only when a flow is admitted (see
    /// [`Self::start_flow`]).
    fn flows_for<'policy>(&self, peer: &'policy PeerAccess) -> &'policy PeerFlows {
        if let Some(cell) = peer.flows.get() {
            return cell;
        }
        let cell = {
            let mut tables = self
                .tables
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(tables.entry(peer.node).or_default())
        };
        peer.flows.get_or_init(|| cell)
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
        // Checked before the peer's flow cell is looked up: a stateless message never touches
        // flow state, so it must not create a cell either.
        if parsed.icmp == IcmpKind::Stateless {
            return Self::allow_stateless(parsed, direction, peer, &policy);
        }
        let flows = self.flows_for(peer);
        if let Some(fragment) = parsed.fragment.filter(|fragment| !fragment.first) {
            return Self::allow_fragment(
                fragment,
                parsed.packet_end,
                direction,
                peer_address,
                peer_id,
                flows,
                &policy,
                now,
            );
        }
        if let Some(related) = parsed.related {
            return Self::allow_related(
                related,
                parsed,
                direction,
                peer_address,
                peer_id,
                flows,
                &policy,
                now,
            );
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
        let mut table = flows
            .table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(shard) = table.as_mut()
            && let Some((index, same_direction)) = shard.find(lookup_key, slot_start)
        {
            let entry = match shard.slots[index] {
                FlowSlot::Occupied(entry) => entry,
                FlowSlot::Empty | FlowSlot::Removed => return false,
            };
            // An echo flow carries only echoes the way it was opened and their replies back.
            // The tuple alone cannot tell them apart: a request and a reply with identifier 0
            // share one key (J672 P3, #265). Any other ICMP message is judged on its own.
            if matches!(parsed.icmp, IcmpKind::EchoRequest | IcmpKind::EchoReply)
                && (parsed.icmp == entry.opened_by()) != same_direction
            {
                return Self::allow_stateless(parsed, direction, peer, &policy);
            }
            let expired = now.saturating_duration_since(entry.last_seen) > entry.idle_timeout();
            // A bare SYN never rides existing state. Against the opening direction it would let
            // a peer open a connection to this host through this host's own outbound tuple,
            // with no inbound grant; kernel conntrack treats it as new as well (J592 P2, D164).
            // On a closed connection it starts a new one, which needs a fresh grant check.
            let bare_syn = parsed.key.protocol == TCP
                && parsed
                    .tcp_flags
                    .is_some_and(|flags| flags & (TCP_SYN | TCP_ACK) == TCP_SYN);
            if bare_syn && !expired && !same_direction && !entry.closed() {
                return false;
            }
            let reopened = bare_syn && entry.closed();
            if expired || reopened || !policy.allows_flow(entry) {
                shard.remove(index);
                // An expired or closed tuple is treated as new. TCP continuations still cannot
                // initiate it, and a reverse SYN needs a grant in its own direction.
                if expired || reopened {
                    return Self::start_flow(
                        packet,
                        parsed,
                        direction,
                        peer_address,
                        peer_id,
                        peer_index,
                        &policy,
                        &mut table,
                        now,
                    );
                }
                return false;
            }
            if ssh_reply_candidate && entry.ssh_redirect_port != Some(parsed.key.source_port) {
                return false;
            }
            let rewrite = entry.ssh_redirect_port.map(|port| {
                let offset = if same_direction {
                    parsed.transport_offset + 2
                } else {
                    parsed.transport_offset
                };
                (offset, if same_direction { port } else { 22 })
            });
            if rewrite.is_some() && !can_rewrite_ssh_packet(&parsed) {
                return false;
            }
            if let Some((offset, port)) = rewrite {
                rewrite_ssh_port(packet, &parsed, offset, port);
            }
            if !Self::remember_first_fragment(shard, parsed, direction, entry.key, now) {
                return false;
            }
            let mut refreshed = entry;
            refreshed.last_seen = now;
            refreshed.observe(same_direction, parsed.tcp_flags);
            shard.slots[index] = FlowSlot::Occupied(refreshed);
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
            &mut table,
            now,
        )
    }

    /// Remember a fragmented first packet only after its ordinary grant check passes.
    fn remember_first_fragment(
        shard: &mut FlowShard,
        parsed: ParsedPacket,
        direction: Direction,
        flow: FlowKey,
        now: Instant,
    ) -> bool {
        let Some(fragment) = parsed
            .fragment
            .filter(|fragment| fragment.first && fragment.more)
        else {
            return true;
        };
        let Some(first_range) = FragmentRange::from_fragment(fragment, parsed.packet_end) else {
            return false;
        };
        let Some(judged_end) = parsed
            .header_end
            .checked_sub(fragment.data_offset)
            .and_then(|end| u16::try_from(end).ok())
        else {
            return false;
        };
        shard.insert_fragment(
            FragmentEntry {
                key: fragment.key,
                flow,
                direction,
                last_seen: now,
                judged_end,
            },
            fragment_start(fragment.key, direction),
            now,
            first_range,
        )
    }

    /// Admit a later fragment only while its first fragment's authorized flow remains live.
    fn allow_fragment(
        fragment_packet: PacketFragment,
        packet_end: usize,
        direction: Direction,
        peer_address: IpAddr,
        peer_id: NodeId,
        flows: &PeerFlows,
        policy: &CompiledPolicy,
        now: Instant,
    ) -> bool {
        let mut table = flows
            .table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(shard) = table.as_mut() else {
            return false;
        };
        let Some(fragment_index) = shard.find_fragment(
            fragment_packet.key,
            direction,
            fragment_start(fragment_packet.key, direction),
        ) else {
            return false;
        };
        let FragmentSlot::Occupied(mut fragment) = shard.fragment_slot(fragment_index) else {
            return false;
        };
        if fragment.expired(now) {
            shard.remove_fragment(fragment_index);
            return false;
        }
        if fragment_packet.offset_bytes < usize::from(fragment.judged_end) {
            return false;
        }
        let Some((flow_index, _)) = shard.find(fragment.flow, flow_start(fragment.flow)) else {
            shard.remove_fragment(fragment_index);
            return false;
        };
        let FlowSlot::Occupied(mut flow) = shard.slots[flow_index] else {
            shard.remove_fragment(fragment_index);
            return false;
        };
        if flow.peer_address != peer_address
            || flow.peer_id != peer_id
            || flow.expired(now)
            || !policy.allows_flow(flow)
        {
            shard.remove(flow_index);
            shard.remove_fragment(fragment_index);
            return false;
        }
        flow.last_seen = now;
        fragment.last_seen = now;
        shard.slots[flow_index] = FlowSlot::Occupied(flow);
        let Some(fragments) = shard.fragments.as_mut() else {
            return false;
        };
        let completed = fragments.coverage[fragment_index].observe(fragment_packet, packet_end);
        if completed {
            fragments.remove(fragment_index);
        } else {
            fragments.slots[fragment_index] = FragmentSlot::Occupied(fragment);
        }
        true
    }

    /// Admit and record a new tuple after its current grant and TCP initiation flags pass.
    ///
    /// `table` is the peer's flow table, still unallocated if the peer has never had a flow.
    /// It is allocated here, after the grant check passes, so a packet that is refused never
    /// costs memory. If the allocation fails, the packet is refused: fail closed.
    fn start_flow(
        packet: &mut [u8],
        parsed: ParsedPacket,
        direction: Direction,
        peer_address: IpAddr,
        peer_id: NodeId,
        peer_index: usize,
        policy: &CompiledPolicy,
        table: &mut Option<FlowShard>,
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
        if grant.ssh_redirect_port.is_some() && !can_rewrite_ssh_packet(&parsed) {
            return false;
        }
        let shard = match table {
            Some(shard) => shard,
            None => match FlowShard::new() {
                Ok(shard) => table.insert(shard),
                Err(_) => return false,
            },
        };
        let entry = FlowEntry {
            key: parsed.key,
            peer_address,
            peer_id,
            initiated: direction,
            grant,
            last_seen: now,
            ssh_redirect_port: grant.ssh_redirect_port,
            state: if parsed.icmp == IcmpKind::EchoReply {
                FlowState::OPENED_BY_ECHO_REPLY
            } else {
                0
            },
        };
        let slot_start = flow_start(entry.key);
        if !shard.insert(entry, slot_start) {
            shard.reclaim(now, policy);
            let inserted = shard.insert(entry, slot_start)
                || (shard.evict_idle(direction, now) && shard.insert(entry, slot_start));
            if !inserted {
                return false;
            }
        }
        if let Some(port) = entry.ssh_redirect_port {
            rewrite_ssh_port(packet, &parsed, parsed.transport_offset + 2, port);
        }
        if !Self::remember_first_fragment(shard, parsed, direction, entry.key, now) {
            // A dropped first fragment must not leave a reverse tuple that admits its reply.
            if let Some((index, _)) = shard.find(entry.key, slot_start)
                && matches!(shard.slots[index], FlowSlot::Occupied(current) if current.key == entry.key)
            {
                shard.remove(index);
            }
            return false;
        }
        true
    }

    /// Judge one ICMP message that keeps no flow state against the grant alone.
    ///
    /// Used for ICMP that is neither an echo nor an error (timestamps, router messages and the
    /// like) and for an echo whose role does not fit the flow its tuple names. Such a message
    /// passes only when its direction's grant is `All`, the same rule that admits a new
    /// non-TCP, non-UDP flow, and it never creates or refreshes state, so it can neither ride
    /// nor open an echo flow (J672 P3, #265). A fragmented one is refused: no later fragment
    /// could follow it without state, and real ICMP of this kind is never that large.
    fn allow_stateless(
        parsed: ParsedPacket,
        direction: Direction,
        peer: &PeerAccess,
        policy: &CompiledPolicy,
    ) -> bool {
        parsed.fragment.is_none() && policy.new_grant(peer, parsed.key, direction).is_some()
    }

    /// Admit only an ICMP error that quotes a still-authorized flow to this exact peer.
    fn allow_related(
        key: FlowKey,
        parsed: ParsedPacket,
        direction: Direction,
        peer_address: IpAddr,
        peer_id: NodeId,
        flows: &PeerFlows,
        policy: &CompiledPolicy,
        now: Instant,
    ) -> bool {
        let slot_start = flow_start(key);
        let mut table = flows
            .table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(shard) = table.as_mut() else {
            return false;
        };
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
        if !Self::remember_first_fragment(shard, parsed, direction, entry.key, now) {
            return false;
        }
        entry.last_seen = now;
        shard.slots[index] = FlowSlot::Occupied(entry);
        true
    }

    /// Test seam: how many peers hold an allocated flow table right now.
    #[cfg(test)]
    fn allocated_tables(&self) -> usize {
        self.tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|cell| {
                cell.table
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .is_some()
            })
            .count()
    }

    /// Test seam: run `inspect` on one peer's flow table, `None` while it is unallocated.
    #[cfg(test)]
    fn with_table<R>(&self, node: NodeId, inspect: impl FnOnce(Option<&FlowShard>) -> R) -> R {
        let cell = self
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&node)
            .cloned();
        match cell {
            Some(cell) => inspect(
                cell.table
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_ref(),
            ),
            None => inspect(None),
        }
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
            peers.push(PeerAccess::from_policy(*node, policy));
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

    /// Drop these peers' addresses from the index, so packets from or to them match no peer.
    /// Only removes entries, so it never allocates and cannot fail.
    fn withdraw(&mut self, withdrawn: &std::collections::BTreeSet<NodeId>) {
        if withdrawn.is_empty() {
            return;
        }
        let Self {
            peer_addresses,
            peers,
            ..
        } = self;
        peer_addresses.retain(|_, index| !withdrawn.contains(&peers[*index].node));
    }

    /// Find a peer by node id. `peers` is built from the config's `BTreeMap`, so it is sorted
    /// by node and a binary search finds the entry.
    fn peer_by_node(&self, node: NodeId) -> Option<&PeerAccess> {
        self.peers
            .binary_search_by(|peer| peer.node.cmp(&node))
            .ok()
            .map(|index| &self.peers[index])
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
    /// This snapshot's pointer to the peer's flow cell in [`PacketFilter::tables`]. It starts
    /// unset and is set on the peer's first packet after the snapshot is published (see
    /// [`PacketFilter::flows_for`]), so compiling a snapshot allocates nothing per peer. Each
    /// peer has its own cell, so peers whose tuples hash alike never share a quota.
    flows: OnceLock<Arc<PeerFlows>>,
}

impl PeerAccess {
    /// Copy access data only: no peer keys or endpoints, and no flow table.
    fn from_policy(node: NodeId, policy: &PeerPolicy) -> Self {
        Self {
            node,
            inbound: policy.inbound.clone(),
            outbound: policy.outbound.clone(),
            access_ssh: policy.access_ssh,
            flows: OnceLock::new(),
        }
    }
}

/// One peer's flow state, kept across policy publishes.
///
/// The table stays `None` until the peer's first flow is admitted, and returns to `None` when
/// the sweep after a publish finds it empty. An idle peer therefore costs this cell (about
/// 100 bytes), not the 68 KB table (J721, #265).
#[derive(Default)]
struct PeerFlows {
    table: Mutex<Option<FlowShard>>,
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
    /// What the flow has seen so far, as [`FlowState`] bits.
    state: u8,
}

/// Bits of [`FlowEntry::state`]. A packet can only add bits; a flow is never reopened in place.
struct FlowState;

impl FlowState {
    /// A packet travelled against the initiating direction (a reply).
    const REPLIED: u8 = 1;
    /// The initiator sent FIN.
    const FIN_ORIGINAL: u8 = 2;
    /// The responder sent FIN.
    const FIN_REPLY: u8 = 4;
    /// Either side sent RST.
    const RESET: u8 = 8;
    /// The initiator acknowledged the reply, so the TCP three-way handshake is complete. Until
    /// then a connection is half-open: it keeps the short opening timeout and a full table may
    /// evict it (J617 P3, #265).
    const HANDSHAKE_DONE: u8 = 16;
    /// An ICMP echo reply opened this flow (only an `All` grant allows that), so the replies
    /// that may travel back are echo requests. Unset on every other flow, including echo flows
    /// opened by a request.
    const OPENED_BY_ECHO_REPLY: u8 = 32;
}

impl FlowEntry {
    /// Select the idle expiry that matches this flow's transport protocol and lifecycle.
    fn idle_timeout(self) -> Duration {
        match self.key.protocol {
            TCP if self.closed() => TCP_CLOSED_TIMEOUT,
            TCP if self.state & (FlowState::FIN_ORIGINAL | FlowState::FIN_REPLY) != 0 => {
                TCP_CLOSING_TIMEOUT
            }
            TCP if self.state & FlowState::HANDSHAKE_DONE == 0 => TCP_OPENING_TIMEOUT,
            TCP => TCP_ESTABLISHED_TIMEOUT,
            UDP if self.state & FlowState::REPLIED == 0 => UDP_UNREPLIED_TIMEOUT,
            UDP => UDP_IDLE_TIMEOUT,
            _ => OTHER_IDLE_TIMEOUT,
        }
    }

    /// The echo role of the packet that opened this ICMP echo flow. Only meaningful for echo
    /// flows; see [`FlowState::OPENED_BY_ECHO_REPLY`].
    fn opened_by(self) -> IcmpKind {
        if self.state & FlowState::OPENED_BY_ECHO_REPLY == 0 {
            IcmpKind::EchoRequest
        } else {
            IcmpKind::EchoReply
        }
    }

    /// Whether this TCP connection is over: reset, or FIN seen in both directions.
    fn closed(self) -> bool {
        self.state & FlowState::RESET != 0
            || self.state & (FlowState::FIN_ORIGINAL | FlowState::FIN_REPLY)
                == FlowState::FIN_ORIGINAL | FlowState::FIN_REPLY
    }

    /// Whether this is a live TCP connection that a full table must never evict: its three-way
    /// handshake finished, and it is neither reset nor closing. A half-open connection (SYN
    /// answered, final ACK missing) is not established.
    fn established(self) -> bool {
        self.key.protocol == TCP
            && self.state & FlowState::HANDSHAKE_DONE != 0
            && self.state & (FlowState::FIN_ORIGINAL | FlowState::FIN_REPLY | FlowState::RESET) == 0
    }

    /// Record what one admitted packet says about the flow. `same_direction` is true when the
    /// packet travels the way the flow was opened.
    fn observe(&mut self, same_direction: bool, tcp_flags: Option<u8>) {
        if self.key.protocol == TCP {
            let flags = tcp_flags.unwrap_or(0);
            // The initiator's ACK after the reply completes the handshake. A SYN or RST from
            // the initiator does not, and neither does anything before the reply.
            if same_direction
                && self.state & FlowState::REPLIED != 0
                && flags & (TCP_ACK | TCP_SYN | TCP_RST) == TCP_ACK
            {
                self.state |= FlowState::HANDSHAKE_DONE;
            }
            if flags & TCP_RST != 0 {
                self.state |= FlowState::RESET;
            }
            if flags & TCP_FIN != 0 {
                self.state |= if same_direction {
                    FlowState::FIN_ORIGINAL
                } else {
                    FlowState::FIN_REPLY
                };
            }
        }
        if !same_direction {
            self.state |= FlowState::REPLIED;
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

/// One key that identifies all IP fragments belonging to one datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FragmentKey {
    version: u8,
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    identification: u32,
}

/// One fragment association that inherits authority from its admitted first packet.
#[derive(Clone, Copy)]
struct FragmentEntry {
    key: FragmentKey,
    flow: FlowKey,
    direction: Direction,
    last_seen: Instant,
    /// How far into the fragmentable part the first fragment's judged headers reach: every
    /// IPv6 extension header after the Fragment header, plus the transport header. A later
    /// fragment that starts before this offset overlaps bytes the filter already judged (the
    /// TCP flags, the ports) and is refused (RFC 1858, RFC 5722; J718 P3, #265). Linux and XNU
    /// discard such overlaps on their own; this keeps the filter from relying on that.
    judged_end: u16,
}

/// One half-open byte range covered by fragments of the same datagram.
#[derive(Clone, Copy)]
struct FragmentRange {
    start: u16,
    end: u16,
}

impl FragmentRange {
    /// Build a checked range from one packet's fragment offset and payload length.
    fn from_fragment(fragment: PacketFragment, packet_end: usize) -> Option<Self> {
        let payload_len = packet_end.checked_sub(fragment.data_offset)?;
        let end = fragment.offset_bytes.checked_add(payload_len)?;
        Some(Self {
            start: u16::try_from(fragment.offset_bytes).ok()?,
            end: u16::try_from(end).ok()?,
        })
    }
}

/// Fixed, sorted coverage intervals used to retire a datagram after all its bytes arrive.
///
/// Each peer has a bounded table of these values, so packet checks never allocate. A full range
/// set remains live until timeout rather than claiming that a partially tracked datagram finished.
#[derive(Clone, Copy)]
struct FragmentCoverage {
    ranges: [FragmentRange; FRAGMENT_RANGES_PER_DATAGRAM],
    range_count: u8,
    final_end: Option<u16>,
    overflowed: bool,
}

impl FragmentCoverage {
    /// One empty coverage record, the fill value of a newly allocated [`FragmentTable`].
    fn empty() -> Self {
        Self {
            ranges: [FragmentRange { start: 0, end: 0 }; FRAGMENT_RANGES_PER_DATAGRAM],
            range_count: 0,
            final_end: None,
            overflowed: false,
        }
    }

    /// Start a fresh association with the already-authorized first fragment's byte range.
    fn reset(&mut self, first_range: FragmentRange) {
        self.range_count = 0;
        self.final_end = None;
        self.overflowed = false;
        self.insert_range(first_range);
    }

    /// Record one later fragment and report whether it completed the datagram.
    fn observe(&mut self, fragment: PacketFragment, packet_end: usize) -> bool {
        if self.overflowed {
            return false;
        }
        let Some(range) = FragmentRange::from_fragment(fragment, packet_end) else {
            self.overflowed = true;
            return false;
        };
        let range_count = usize::from(self.range_count);
        if fragment.more {
            if self
                .final_end
                .is_some_and(|final_end| range.end >= final_end)
            {
                self.overflowed = true;
                return false;
            }
        } else {
            if self
                .final_end
                .is_some_and(|final_end| final_end != range.end)
                || self.ranges[..range_count]
                    .iter()
                    .any(|previous| previous.end > range.end)
            {
                self.overflowed = true;
                return false;
            }
            self.final_end = Some(range.end);
        }
        self.insert_range(range);
        !self.overflowed
            && self.final_end.is_some_and(|final_end| {
                self.range_count > 0 && self.ranges[0].start == 0 && self.ranges[0].end == final_end
            })
    }

    /// Merge one range into sorted, non-touching coverage intervals without growing storage.
    fn insert_range(&mut self, mut incoming: FragmentRange) {
        let range_count = usize::from(self.range_count);
        let mut start = 0;
        while start < range_count && self.ranges[start].end < incoming.start {
            start += 1;
        }
        let mut end = start;
        while end < range_count && self.ranges[end].start <= incoming.end {
            incoming.start = incoming.start.min(self.ranges[end].start);
            incoming.end = incoming.end.max(self.ranges[end].end);
            end += 1;
        }

        if end == start {
            if range_count == FRAGMENT_RANGES_PER_DATAGRAM {
                self.overflowed = true;
                return;
            }
            if start < range_count {
                self.ranges.copy_within(start..range_count, start + 1);
            }
            self.ranges[start] = incoming;
            self.range_count += 1;
            return;
        }

        self.ranges[start] = incoming;
        if end < range_count {
            self.ranges.copy_within(end..range_count, start + 1);
        }
        self.range_count -= u8::try_from(end - start - 1).unwrap_or_default();
    }
}

impl FragmentEntry {
    /// Report whether this datagram association has exceeded its bounded reassembly window.
    fn expired(self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_seen) > FRAGMENT_IDLE_TIMEOUT
    }
}

/// One fragment slot; tombstones preserve open-addressing probe chains after expiry or revocation.
#[derive(Clone, Copy)]
enum FragmentSlot {
    /// No fragment association has occupied this slot in the current probe chain.
    Empty,
    /// An association was removed, so later keys in the probe chain must still be checked.
    Removed,
    /// A bounded fragment-to-flow association.
    Occupied(FragmentEntry),
}

/// One peer's fixed-size conntrack table, guarded separately from every other peer's.
///
/// Invariant: `initiated[d]` is the number of occupied slots whose flow was opened in direction
/// `d` (see [`direction_slot`]), and never exceeds [`FLOWS_PER_DIRECTION`]. Every change to
/// `slots` that adds, removes or replaces an entry goes through [`FlowShard::insert`],
/// [`FlowShard::remove`] or [`FlowShard::evict_idle`], which keep the counts in step; refreshing
/// an entry in place keeps its direction and so needs no update.
struct FlowShard {
    slots: Vec<FlowSlot>,
    initiated: [usize; 2],
    /// The fragment associations, allocated the first time this peer fragments a datagram:
    /// most peers never do.
    fragments: Option<FragmentTable>,
}

/// One peer's fixed fragment associations and the byte coverage of each, index for index.
struct FragmentTable {
    slots: Vec<FragmentSlot>,
    coverage: Vec<FragmentCoverage>,
}

impl FragmentTable {
    /// Allocate the complete fragment arrays once, failing instead of aborting when memory is
    /// short.
    fn new() -> io::Result<Self> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(FRAGMENTS_PER_PEER)
            .map_err(|_| io::Error::other("mesh fragment slots could not be allocated"))?;
        slots.resize(FRAGMENTS_PER_PEER, FragmentSlot::Empty);
        let mut coverage = Vec::new();
        coverage
            .try_reserve_exact(FRAGMENTS_PER_PEER)
            .map_err(|_| io::Error::other("mesh fragment coverage slots could not be allocated"))?;
        coverage.resize(FRAGMENTS_PER_PEER, FragmentCoverage::empty());
        Ok(Self { slots, coverage })
    }

    /// Remove one association without breaking later entries in its probe chain.
    fn remove(&mut self, index: usize) {
        self.slots[index] = FragmentSlot::Removed;
    }

    /// Whether no association is open, so the table can be freed.
    fn is_empty(&self) -> bool {
        !self
            .slots
            .iter()
            .any(|slot| matches!(slot, FragmentSlot::Occupied(_)))
    }
}

/// The index of a direction's flow count in [`FlowShard::initiated`].
fn direction_slot(direction: Direction) -> usize {
    match direction {
        Direction::HostToMesh => 0,
        Direction::MeshToHost => 1,
    }
}

impl FlowShard {
    /// Allocate this peer's complete flow slot array, once, when its first flow is admitted.
    ///
    /// # Errors
    /// Fails, rather than aborting the process, when the memory is not available. The caller
    /// then refuses the packet.
    fn new() -> io::Result<Self> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(FLOW_SLOTS_PER_PEER)
            .map_err(|_| io::Error::other("mesh conntrack slots could not be allocated"))?;
        slots.resize(FLOW_SLOTS_PER_PEER, FlowSlot::Empty);
        Ok(Self {
            slots,
            initiated: [0; 2],
            fragments: None,
        })
    }

    /// Whether the table tracks no flow and no fragment, so the sweep can free it.
    fn is_empty(&self) -> bool {
        self.initiated == [0; 2] && self.fragments.as_ref().is_none_or(FragmentTable::is_empty)
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
    ///
    /// Refuses (returns false) when the flow's direction already holds [`FLOWS_PER_DIRECTION`]
    /// flows, whatever the other direction holds.
    fn insert(&mut self, entry: FlowEntry, start: usize) -> bool {
        let direction = direction_slot(entry.initiated);
        let full = self.initiated[direction] >= FLOWS_PER_DIRECTION;
        let mut removed = None;
        for offset in 0..self.slots.len() {
            let index = (start + offset) % self.slots.len();
            match self.slots[index] {
                FlowSlot::Empty => {
                    if full {
                        return false;
                    }
                    self.slots[removed.unwrap_or(index)] = FlowSlot::Occupied(entry);
                    self.initiated[direction] += 1;
                    return true;
                }
                FlowSlot::Removed => {
                    removed.get_or_insert(index);
                }
                FlowSlot::Occupied(existing)
                    if existing.key == entry.key || existing.key == entry.key.reverse() =>
                {
                    let previous = direction_slot(existing.initiated);
                    if previous != direction && full {
                        return false;
                    }
                    self.initiated[previous] -= 1;
                    self.slots[index] = FlowSlot::Occupied(entry);
                    self.initiated[direction] += 1;
                    return true;
                }
                FlowSlot::Occupied(_) => {}
            }
        }
        match removed {
            Some(index) if !full => {
                self.slots[index] = FlowSlot::Occupied(entry);
                self.initiated[direction] += 1;
                true
            }
            Some(_) | None => false,
        }
    }

    /// Turn one expired or revoked entry into a tombstone without breaking later probes.
    ///
    /// When the next slot is empty, no probe chain passes through this one, so this tombstone
    /// and the run of tombstones before it become empty again. Without that, a table that has
    /// seen churn has no empty slot left and every miss probes all slots.
    fn remove(&mut self, index: usize) {
        let len = self.slots.len();
        if let FlowSlot::Occupied(entry) = self.slots[index] {
            self.initiated[direction_slot(entry.initiated)] -= 1;
        }
        self.slots[index] = FlowSlot::Removed;
        if !matches!(self.slots[(index + 1) % len], FlowSlot::Empty) {
            return;
        }
        let mut current = index;
        for _ in 0..len {
            if !matches!(self.slots[current], FlowSlot::Removed) {
                break;
            }
            self.slots[current] = FlowSlot::Empty;
            current = (current + len - 1) % len;
        }
    }

    /// Free one slot of `direction` when its full quota refuses a new flow: its least recently
    /// seen flow that is not an established TCP connection, or else its least recently seen
    /// established connection that has been silent for [`TCP_ESTABLISHED_EVICTABLE_IDLE`].
    ///
    /// Closed and half-closed connections, unanswered SYNs, half-open connections (SYN-ACK
    /// without the final ACK) and UDP or ICMP exchanges always go first; recency protects
    /// active ones. Only flows opened in the same direction are candidates, so one side's new
    /// flows never evict the other side's: the peer's held inbound connections cannot lock this
    /// host out (J617 P2, #265). A live established connection is never evicted. One silent
    /// for an hour is evicted only when nothing else is left. Its peer most likely vanished
    /// without a FIN or RST, and keeping it would refuse that side's new connections for the
    /// 5-day timeout (J718 P2). Returns whether a slot was freed. The scan is O(slots) and runs
    /// only when the quota is full.
    fn evict_idle(&mut self, direction: Direction, now: Instant) -> bool {
        // Ranked by (established, last seen): every unestablished flow sorts before every
        // established one, and the oldest of each kind first.
        let victim = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| match slot {
                FlowSlot::Occupied(entry) if entry.initiated == direction => {
                    let established = entry.established();
                    (!established
                        || now.saturating_duration_since(entry.last_seen)
                            >= TCP_ESTABLISHED_EVICTABLE_IDLE)
                        .then_some((established, entry.last_seen, index))
                }
                FlowSlot::Empty | FlowSlot::Removed | FlowSlot::Occupied(_) => None,
            })
            .min();
        let Some((_, _, index)) = victim else {
            return false;
        };
        self.remove(index);
        true
    }

    /// The fragment slot at `index`, or an empty one while the fragment table is unallocated.
    fn fragment_slot(&self, index: usize) -> FragmentSlot {
        self.fragments
            .as_ref()
            .map_or(FragmentSlot::Empty, |fragments| fragments.slots[index])
    }

    /// Find one fragment association by its complete IP identity and packet direction.
    fn find_fragment(&self, key: FragmentKey, direction: Direction, start: usize) -> Option<usize> {
        let fragments = &self.fragments.as_ref()?.slots;
        for offset in 0..fragments.len() {
            let index = (start + offset) % fragments.len();
            match fragments[index] {
                FragmentSlot::Empty => return None,
                FragmentSlot::Occupied(entry)
                    if entry.key == key && entry.direction == direction =>
                {
                    return Some(index);
                }
                FragmentSlot::Removed | FragmentSlot::Occupied(_) => {}
            }
        }
        None
    }

    /// Insert a first-fragment association without growing the table or replacing an active ID.
    ///
    /// Allocates the fragment table on this peer's first fragmented datagram. If that
    /// allocation fails, the association is refused, and so is its first fragment.
    fn insert_fragment(
        &mut self,
        entry: FragmentEntry,
        start: usize,
        now: Instant,
        first_range: FragmentRange,
    ) -> bool {
        let fragments = match &mut self.fragments {
            Some(fragments) => fragments,
            None => match FragmentTable::new() {
                Ok(fragments) => self.fragments.insert(fragments),
                Err(_) => return false,
            },
        };
        let mut removed = None;
        for offset in 0..fragments.slots.len() {
            let index = (start + offset) % fragments.slots.len();
            match fragments.slots[index] {
                FragmentSlot::Empty => {
                    let index = removed.unwrap_or(index);
                    fragments.slots[index] = FragmentSlot::Occupied(entry);
                    fragments.coverage[index].reset(first_range);
                    return true;
                }
                FragmentSlot::Removed => {
                    removed.get_or_insert(index);
                }
                FragmentSlot::Occupied(existing)
                    if existing.key == entry.key && existing.direction == entry.direction =>
                {
                    if !existing.expired(now) && existing.flow != entry.flow {
                        return false;
                    }
                    fragments.slots[index] = FragmentSlot::Occupied(entry);
                    fragments.coverage[index].reset(first_range);
                    return true;
                }
                FragmentSlot::Occupied(existing) if existing.expired(now) => {
                    fragments.slots[index] = FragmentSlot::Removed;
                    removed.get_or_insert(index);
                }
                FragmentSlot::Occupied(_) => {}
            }
        }
        if let Some(index) = removed {
            fragments.slots[index] = FragmentSlot::Occupied(entry);
            fragments.coverage[index].reset(first_range);
            true
        } else {
            false
        }
    }

    /// Remove one association without breaking later entries in its probe chain.
    fn remove_fragment(&mut self, index: usize) {
        if let Some(fragments) = &mut self.fragments {
            fragments.remove(index);
        }
    }

    /// Retire associations whose conntrack entry was removed or replaced, and free the
    /// fragment table once none is left.
    fn remove_orphaned_fragments(&mut self) {
        let Some(fragments) = &self.fragments else {
            return;
        };
        for index in 0..fragments.slots.len() {
            let FragmentSlot::Occupied(entry) = self.fragment_slot(index) else {
                continue;
            };
            if self.find(entry.flow, flow_start(entry.flow)).is_none() {
                self.remove_fragment(index);
            }
        }
        if self.fragments.as_ref().is_some_and(FragmentTable::is_empty) {
            self.fragments = None;
        }
    }

    /// Free the slots of flows that have expired or that `policy` no longer permits, and of
    /// expired fragment associations.
    ///
    /// Called when a full direction refuses a new flow, and by the sweep after each publish. A
    /// revoked flow admits nothing even before this runs, because every packet re-checks
    /// [`CompiledPolicy::allows_flow`]; this only gives its slot back to the quota.
    fn reclaim(&mut self, now: Instant, policy: &CompiledPolicy) {
        for index in 0..self.slots.len() {
            if matches!(self.slots[index], FlowSlot::Occupied(entry) if entry.expired(now) || !policy.allows_flow(entry))
            {
                self.remove(index);
            }
        }
        if let Some(fragments) = &mut self.fragments {
            for slot in &mut fragments.slots {
                if matches!(*slot, FragmentSlot::Occupied(entry) if entry.expired(now)) {
                    *slot = FragmentSlot::Removed;
                }
            }
        }
    }
}

/// Index a tuple inside its peer's fixed-size table in either packet direction.
fn flow_start(key: FlowKey) -> usize {
    let mut tuple_hasher = DefaultHasher::new();
    key.canonical().hash(&mut tuple_hasher);
    let tuple_hash = tuple_hasher.finish();
    usize::try_from(tuple_hash % FLOW_SLOTS_PER_PEER_HASH).unwrap_or_default()
}

/// Index one fragment identity inside its peer's fixed-size table.
fn fragment_start(key: FragmentKey, direction: Direction) -> usize {
    let mut tuple_hasher = DefaultHasher::new();
    key.hash(&mut tuple_hasher);
    direction.hash(&mut tuple_hasher);
    usize::try_from(tuple_hasher.finish() % FRAGMENTS_PER_PEER_HASH).unwrap_or_default()
}

/// Parsed packet fields used for policy, conntrack and checksum-safe SSH translation.
#[derive(Clone, Copy)]
struct ParsedPacket {
    key: FlowKey,
    tcp_flags: Option<u8>,
    transport_offset: usize,
    /// Packet index just past the last header byte the filter judged: the whole TCP header,
    /// the UDP header, the ICMP header, or an ICMP error's quoted ports. A later fragment that
    /// starts before it would rewrite judged bytes (see [`FragmentEntry::judged_end`]).
    header_end: usize,
    packet_end: usize,
    related: Option<FlowKey>,
    version: u8,
    fragment: Option<PacketFragment>,
    icmp: IcmpKind,
}

/// What an ICMP or `ICMPv6` message means for flow state (J672 P3, #265).
#[derive(Clone, Copy, PartialEq, Eq)]
enum IcmpKind {
    /// Not ICMP, or an ICMP error, which follows its quoted flow as related traffic.
    NotIcmp,
    /// An echo request (IPv4 type 8, IPv6 type 128), keyed by its identifier as source port.
    EchoRequest,
    /// An echo reply (IPv4 type 0, IPv6 type 129), keyed by its identifier as destination port.
    EchoReply,
    /// Any other ICMP message: judged alone, see [`PacketFilter::allow_stateless`].
    Stateless,
}

/// One validated first or later fragment with its address-and-ID association key.
#[derive(Clone, Copy)]
struct PacketFragment {
    key: FragmentKey,
    first: bool,
    more: bool,
    /// Offset of this fragment's payload in the original datagram.
    offset_bytes: usize,
    /// Packet index where this fragment's payload starts.
    data_offset: usize,
}

/// Parse an IPv4 or IPv6 packet without copying bytes and retain valid fragment identity.
fn parse_packet(packet: &[u8]) -> Option<ParsedPacket> {
    let version = packet.first()? >> 4;
    let (source, destination, protocol, offset, packet_end, fragment) = match version {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            let total_len = usize::from(read_u16(packet, 2)?);
            let fragment_field = read_u16(packet, 6)?;
            let fragment_offset = fragment_field & 0x1fff;
            let more_fragments = fragment_field & 0x2000 != 0;
            let fragmented = fragment_offset != 0 || more_fragments;
            if header_len < 20
                || header_len > packet.len()
                || total_len < header_len
                || total_len > packet.len()
                || fragment_field & 0x8000 != 0
                || (fragment_field & 0x4000 != 0 && fragmented)
            {
                return None;
            }
            let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let source = IpAddr::V4(source);
            let destination = IpAddr::V4(destination);
            let payload_len = total_len - header_len;
            let fragment = if fragmented {
                let offset_bytes = usize::from(fragment_offset) * 8;
                if payload_len == 0
                    || (more_fragments && payload_len % 8 != 0)
                    || offset_bytes + payload_len > usize::from(u16::MAX)
                {
                    return None;
                }
                Some(PacketFragment {
                    key: FragmentKey {
                        version: 4,
                        source,
                        destination,
                        protocol: packet[9],
                        identification: u32::from(read_u16(packet, 4)?),
                    },
                    first: fragment_offset == 0,
                    more: more_fragments,
                    offset_bytes,
                    data_offset: header_len,
                })
            } else {
                None
            };
            (
                source,
                destination,
                packet[9],
                header_len,
                total_len,
                fragment,
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
            let source = IpAddr::V6(source);
            let destination = IpAddr::V6(destination);
            let mut protocol = packet[6];
            let mut offset = 40;
            let mut headers = 0;
            let mut fragment = None;
            // Only the headers Linux itself skips before the upper-layer protocol: hop-by-hop
            // (0), routing (43), fragment (44), authentication (51) and destination options
            // (60). Mobility (135), HIP (139) and Shim6 (140) are delivered to sockets as
            // protocols of their own, so the filter must judge them as such (J592 P3, #265).
            while matches!(protocol, 0 | 43 | 44 | 51 | 60) {
                if protocol == 44 {
                    headers += 1;
                    if headers > 8 || fragment.is_some() || offset + 8 > end {
                        return None;
                    }
                    let next = packet[offset];
                    let offset_and_flags = read_u16(packet, offset + 2)?;
                    let fragment_offset = offset_and_flags >> 3;
                    let more_fragments = offset_and_flags & 1 != 0;
                    let payload_len = end - (offset + 8);
                    let offset_bytes = usize::from(fragment_offset) * 8;
                    if packet[offset + 1] != 0
                        || offset_and_flags & 0x0006 != 0
                        || payload_len == 0
                        || (more_fragments && payload_len % 8 != 0)
                        || offset_bytes + payload_len > usize::from(u16::MAX)
                    {
                        return None;
                    }
                    fragment = Some(PacketFragment {
                        key: FragmentKey {
                            version: 6,
                            source,
                            destination,
                            protocol: next,
                            identification: u32::from_be_bytes(
                                packet[offset + 4..offset + 8].try_into().ok()?,
                            ),
                        },
                        first: fragment_offset == 0,
                        more: more_fragments,
                        offset_bytes,
                        data_offset: offset + 8,
                    });
                    protocol = next;
                    offset += 8;
                    if fragment_offset != 0 {
                        break;
                    }
                    continue;
                }
                headers += 1;
                if headers > 8 || offset + 2 > end {
                    return None;
                }
                let next = packet[offset];
                let ext_len = match protocol {
                    51 => (usize::from(packet[offset + 1]) + 2).checked_mul(4)?,
                    _ => (usize::from(packet[offset + 1]) + 1).checked_mul(8)?,
                };
                if ext_len < 8 || offset + ext_len > end {
                    return None;
                }
                protocol = next;
                offset += ext_len;
            }
            (source, destination, protocol, offset, end, fragment)
        }
        _ => return None,
    };

    if let Some(fragment) = fragment.filter(|fragment| !fragment.first) {
        // A later TCP fragment that starts inside the minimum TCP header could rewrite the
        // first fragment's flags after the filter judged them (RFC 1858's overlapping-fragment
        // attack). Every first fragment carries the whole header (see below), so a real later
        // fragment never starts this early (J672 P2, #265). This cheap check needs no state.
        // It sees only fragments whose next header is TCP. The complete guard, which also
        // covers IPv6 extension headers before TCP and every judged header, is
        // `FragmentEntry::judged_end` in `allow_fragment`.
        if protocol == TCP && fragment.offset_bytes < TCP_MIN_HEADER {
            return None;
        }
        return Some(ParsedPacket {
            key: FlowKey {
                source,
                destination,
                source_port: 0,
                destination_port: 0,
                protocol,
            },
            tcp_flags: None,
            transport_offset: offset,
            header_end: offset,
            packet_end,
            related: None,
            version,
            fragment: Some(fragment),
            icmp: IcmpKind::NotIcmp,
        });
    }

    let (source_port, destination_port, tcp_flags, related, icmp, header_end) = match protocol {
        TCP => {
            // Every TCP packet the filter judges carries its whole TCP header, options
            // included, a first fragment too. A first fragment cut short of the flags would
            // hide a SYN in a later fragment, where the filter never looks, and let it ride
            // existing state (J672 P2, #265; RFC 1858 for IPv4, RFC 7112 for IPv6). Real
            // senders never split the TCP header: it is at most 60 bytes and every link MTU
            // is far larger.
            if offset + TCP_MIN_HEADER > packet_end {
                return None;
            }
            let header_len = usize::from(packet[offset + 12] >> 4) * 4;
            if header_len < TCP_MIN_HEADER || offset + header_len > packet_end {
                return None;
            }
            (
                read_u16(packet, offset)?,
                read_u16(packet, offset + 2)?,
                Some(packet[offset + 13]),
                None,
                IcmpKind::NotIcmp,
                offset + header_len,
            )
        }
        UDP => {
            if offset + 8 > packet_end {
                return None;
            }
            let udp_len = usize::from(read_u16(packet, offset + 4)?);
            let first_fragment = fragment.is_some_and(|fragment| fragment.first && fragment.more);
            if udp_len < 8 || (!first_fragment && offset + udp_len > packet_end) {
                return None;
            }
            (
                read_u16(packet, offset)?,
                read_u16(packet, offset + 2)?,
                None,
                None,
                IcmpKind::NotIcmp,
                offset + 8,
            )
        }
        ICMP | ICMPV6 => {
            if offset + 4 > packet_end {
                return None;
            }
            let kind = packet[offset];
            let code = packet[offset + 1];
            // Only real errors follow a flow as related traffic: destination unreachable, time
            // exceeded and parameter problem (v4 3/11/12; v6 1-4, packet too big included).
            // Redirects, source quench and unassigned v6 types are ordinary ICMP that needs an
            // `All` grant (J592 P3, #265).
            if (protocol == ICMP && matches!(kind, 3 | 11 | 12))
                || (protocol == ICMPV6 && matches!(kind, 1..=4))
            {
                let (related, quoted_end) = parse_quoted_flow(packet, offset + 8, packet_end)?;
                (0, 0, None, Some(related), IcmpKind::NotIcmp, quoted_end)
            } else if (protocol == ICMP && kind == 8 && code == 0)
                || (protocol == ICMPV6 && kind == 128 && code == 0)
            {
                if offset + 8 > packet_end {
                    return None;
                }
                (
                    read_u16(packet, offset + 4)?,
                    0,
                    None,
                    None,
                    IcmpKind::EchoRequest,
                    offset + 8,
                )
            } else if (protocol == ICMP && kind == 0 && code == 0)
                || (protocol == ICMPV6 && kind == 129 && code == 0)
            {
                if offset + 8 > packet_end {
                    return None;
                }
                (
                    0,
                    read_u16(packet, offset + 4)?,
                    None,
                    None,
                    IcmpKind::EchoReply,
                    offset + 8,
                )
            } else {
                (0, 0, None, None, IcmpKind::Stateless, offset + 4)
            }
        }
        _ => (0, 0, None, None, IcmpKind::NotIcmp, offset),
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
        header_end,
        packet_end,
        related,
        version,
        fragment,
        icmp,
    })
}

/// Read a quoted first packet tuple from an ICMP error for conntrack-related admission.
///
/// Also returns the packet index just past the quoted ports, the last byte this judgement
/// read.
fn parse_quoted_flow(packet: &[u8], offset: usize, outer_end: usize) -> Option<(FlowKey, usize)> {
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
            // Only the headers Linux itself skips before the upper-layer protocol: hop-by-hop
            // (0), routing (43), fragment (44), authentication (51) and destination options
            // (60). Mobility (135), HIP (139) and Shim6 (140) are delivered to sockets as
            // protocols of their own, so the filter must judge them as such (J592 P3, #265).
            while matches!(protocol, 0 | 43 | 44 | 51 | 60) {
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
    Some((
        FlowKey {
            source,
            destination,
            source_port: read_u16(packet, transport)?,
            destination_port: read_u16(packet, transport + 2)?,
            protocol,
        },
        transport + 4,
    ))
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

/// Check that a mesh SSH rewrite can update the TCP checksum in this packet.
fn can_rewrite_ssh_packet(parsed: &ParsedPacket) -> bool {
    parsed.key.protocol == TCP
        && parsed
            .transport_offset
            .checked_add(4)
            .is_some_and(|end| end <= parsed.packet_end)
}

/// Rewrite one mesh SSH port and keep the TCP checksum valid.
///
/// Callers first check [`can_rewrite_ssh_packet`]. A whole packet gets its checksum
/// recomputed. A first fragment has only part of the segment, so its checksum field (always
/// present: the parser refuses TCP first fragments without the whole header) is adjusted for the
/// one changed word instead; summing only the first fragment would break the reassembled
/// segment.
fn rewrite_ssh_port(packet: &mut [u8], parsed: &ParsedPacket, offset: usize, port: u16) {
    let previous = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    write_u16(packet, offset, port);
    if parsed
        .fragment
        .is_some_and(|fragment| fragment.first && fragment.more)
    {
        let checksum_offset = parsed.transport_offset + 16;
        let checksum = u16::from_be_bytes([packet[checksum_offset], packet[checksum_offset + 1]]);
        write_u16(
            packet,
            checksum_offset,
            adjust_checksum_for_word(checksum, previous, port),
        );
    } else {
        recompute_transport_checksum(packet, parsed);
    }
}

/// Adjust a checksum after replacing one 16-bit network-order word.
fn adjust_checksum_for_word(checksum: u16, previous: u16, replacement: u16) -> u16 {
    let mut sum = u32::from(!checksum) + u32::from(!previous) + u32::from(replacement);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or_default()
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

    use super::{
        Direction, FLOW_SLOTS_PER_PEER, FLOW_SLOTS_PER_PEER_HASH, FLOWS_PER_DIRECTION,
        FRAGMENT_IDLE_TIMEOUT, FRAGMENTS_PER_PEER, FlowSlot, FragmentCoverage, FragmentSlot,
        PER_PEER_MEMORY_BUDGET, PacketFilter, PeerAccess, PeerFlows, TCP_CLOSED_TIMEOUT,
        TCP_ESTABLISHED_EVICTABLE_IDLE, TCP_ESTABLISHED_TIMEOUT, UDP, UDP_IDLE_TIMEOUT,
    };
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

    /// Build an IPv4 UDP datagram long enough to split into two valid IP fragments.
    fn udp4_payload(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut packet = udp4(source, destination, source_port, destination_port);
        packet.extend_from_slice(&[0xa5; 16]);
        let total_len = u16::try_from(packet.len()).expect("test packet fits IPv4 length");
        packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        packet[24..26].copy_from_slice(&24_u16.to_be_bytes());
        packet
    }

    /// Copy one portion of an IPv4 datagram into a valid fragment for filter tests.
    fn ipv4_fragment(
        packet: &[u8],
        identification: u16,
        offset_bytes: usize,
        payload_bytes: usize,
        more_fragments: bool,
    ) -> Vec<u8> {
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        let payload_start = header_len + offset_bytes;
        let payload_end = payload_start + payload_bytes;
        let mut fragment = Vec::with_capacity(header_len + payload_bytes);
        fragment.extend_from_slice(&packet[..header_len]);
        fragment.extend_from_slice(&packet[payload_start..payload_end]);
        let total_len = u16::try_from(fragment.len()).expect("test fragment fits IPv4 length");
        fragment[2..4].copy_from_slice(&total_len.to_be_bytes());
        fragment[4..6].copy_from_slice(&identification.to_be_bytes());
        let offset = u16::try_from(offset_bytes / 8).expect("test offset fits IPv4 field");
        let flags = offset | if more_fragments { 0x2000 } else { 0 };
        fragment[6..8].copy_from_slice(&flags.to_be_bytes());
        fragment
    }

    /// Build an IPv6 UDP datagram long enough to split into two valid fragments.
    fn udp6_payload(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0; 64];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&24_u16.to_be_bytes());
        packet[6] = UDP;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[44..46].copy_from_slice(&24_u16.to_be_bytes());
        packet
    }

    /// Copy one portion of an IPv6 datagram into a valid Fragment-header packet.
    fn ipv6_fragment(
        packet: &[u8],
        identification: u32,
        offset_bytes: usize,
        payload_bytes: usize,
        more_fragments: bool,
    ) -> Vec<u8> {
        let payload_len = u16::try_from(8 + payload_bytes).expect("test fragment payload fits");
        let mut fragment = vec![0; 48 + payload_bytes];
        fragment[..40].copy_from_slice(&packet[..40]);
        fragment[4..6].copy_from_slice(&payload_len.to_be_bytes());
        fragment[6] = 44;
        fragment[40] = packet[6];
        let offset = u16::try_from(offset_bytes / 8).expect("test offset fits IPv6 field");
        let more = u16::from(more_fragments);
        let offset_and_flags = (offset << 3) | more;
        fragment[42..44].copy_from_slice(&offset_and_flags.to_be_bytes());
        fragment[44..48].copy_from_slice(&identification.to_be_bytes());
        let payload_start = 40 + offset_bytes;
        let payload_end = payload_start + payload_bytes;
        fragment[48..].copy_from_slice(&packet[payload_start..payload_end]);
        fragment
    }

    /// Calculate the checksum of an IPv4 TCP packet, including its pseudo-header.
    fn tcp_checksum4(packet: &[u8]) -> u16 {
        let mut pseudo = [0_u8; 12];
        pseudo[..4].copy_from_slice(&packet[12..16]);
        pseudo[4..8].copy_from_slice(&packet[16..20]);
        pseudo[9] = 6;
        let transport_len = u16::try_from(packet.len() - 20).expect("test TCP segment fits");
        pseudo[10..12].copy_from_slice(&transport_len.to_be_bytes());
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
        const PER_PEER_LIMIT: usize = FLOWS_PER_DIRECTION;
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
            assert!(
                establish4(
                    &filter,
                    PEER4,
                    20_000 + u16::try_from(index).expect("flow index"),
                    now
                ),
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
        const PER_PEER_LIMIT: usize = FLOWS_PER_DIRECTION;
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
                assert!(
                    establish4(
                        &filter,
                        *address,
                        20_000 + u16::try_from(index).expect("flow index"),
                        now
                    ),
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
        const PER_PEER_LIMIT: usize = FLOWS_PER_DIRECTION;
        let filter = PacketFilter::new(
            &config(TrafficPolicy::All, TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        for index in 0..PER_PEER_LIMIT {
            assert!(establish4(
                &filter,
                PEER4,
                20_000 + u16::try_from(index).expect("flow index"),
                now
            ));
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
        const PER_PEER_LIMIT: usize = FLOWS_PER_DIRECTION;
        let mut policy = config(TrafficPolicy::All, TrafficPolicy::All);
        let filter = PacketFilter::new(&policy, MeshProxyIngress::default())
            .expect("compile initial policy");
        let now = Instant::now();
        for index in 0..PER_PEER_LIMIT {
            assert!(establish4(
                &filter,
                PEER4,
                20_000 + u16::try_from(index).expect("flow index"),
                now
            ));
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
            started + super::TCP_OPENING_TIMEOUT + Duration::from_secs(1)
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

    /// A fragmented mesh SSH redirect adjusts the TCP checksum for the reassembled segment.
    #[test]
    fn ssh_redirect_translates_fragmented_tcp_with_a_valid_checksum() {
        let local = Ipv4Addr::new(10, 254, 99, 20);
        let peer = Ipv4Addr::new(10, 254, 99, 21);
        let address = IpAddr::V4(local);
        mesh_ssh::clear_listener(address, 1007);
        mesh_ssh::publish_listener(address, 1007).expect("publish private listener");
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
        let mut datagram = tcp4(peer, local, 40_000, 22, SYN);
        datagram.extend_from_slice(&[0xa5; 16]);
        let total_len = u16::try_from(datagram.len()).expect("test TCP packet fits IPv4 length");
        datagram[2..4].copy_from_slice(&total_len.to_be_bytes());
        datagram[36..38].fill(0);
        let checksum = tcp_checksum4(&datagram);
        datagram[36..38].copy_from_slice(&checksum.to_be_bytes());
        let mut first = ipv4_fragment(&datagram, 0x123b, 0, 24, true);
        let mut later = ipv4_fragment(&datagram, 0x123b, 24, 12, false);

        assert!(filter.check_at(&mut first, Direction::MeshToHost, Instant::now()));
        assert_eq!(u16::from_be_bytes([first[22], first[23]]), 1007);
        assert!(filter.check_at(
            &mut later,
            Direction::MeshToHost,
            Instant::now() + Duration::from_secs(1)
        ));

        let mut reassembled = vec![0; datagram.len()];
        reassembled[..20].copy_from_slice(&first[..20]);
        reassembled[2..4].copy_from_slice(&total_len.to_be_bytes());
        reassembled[6..8].fill(0);
        reassembled[20..44].copy_from_slice(&first[20..44]);
        reassembled[44..].copy_from_slice(&later[20..]);
        assert_eq!(tcp_checksum4(&reassembled), 0);
        mesh_ssh::clear_listener(address, 1007);
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

    /// A narrow UDP grant admits later IPv4 fragments only after its first fragment passes.
    #[test]
    fn ipv4_fragments_follow_only_an_admitted_first_fragment() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Udp, 53)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let datagram = udp4_payload(LOCAL4, PEER4, 40_000, 53);
        let mut later = ipv4_fragment(&datagram, 0x1234, 16, 8, false);
        let mut first = ipv4_fragment(&datagram, 0x1234, 0, 16, true);

        assert!(!filter.check_at(&mut later, Direction::HostToMesh, now));
        assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
        assert!(filter.check_at(
            &mut later,
            Direction::HostToMesh,
            now + Duration::from_secs(1)
        ));

        let denied = udp4_payload(LOCAL4, PEER4, 40_001, 5353);
        let mut denied_first = ipv4_fragment(&denied, 0x1235, 0, 16, true);
        let mut denied_later = ipv4_fragment(&denied, 0x1235, 16, 8, false);
        assert!(!filter.check_at(&mut denied_first, Direction::HostToMesh, now));
        assert!(!filter.check_at(&mut denied_later, Direction::HostToMesh, now));
    }

    /// Completed fragmented datagrams release slots while an out-of-order tail still passes.
    #[test]
    fn completed_ipv4_datagrams_release_fragment_slots() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::All, TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();

        for index in 0..=FRAGMENTS_PER_PEER {
            let number = u16::try_from(index).expect("fragment test index fits");
            let source_port = 40_000 + number;
            let datagram = udp4_payload(LOCAL4, PEER4, source_port, 53);
            let mut first = ipv4_fragment(&datagram, 0x4000 + number, 0, 8, true);
            let mut last = ipv4_fragment(&datagram, 0x4000 + number, 16, 8, false);
            let mut middle = ipv4_fragment(&datagram, 0x4000 + number, 8, 8, true);

            assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
            assert!(filter.check_at(&mut last, Direction::HostToMesh, now));
            assert!(filter.check_at(&mut middle, Direction::HostToMesh, now));
        }
    }

    /// Completed IPv6 datagrams release slots while an out-of-order tail still passes.
    #[test]
    fn completed_ipv6_datagrams_release_fragment_slots() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::All, TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();

        for index in 0..=FRAGMENTS_PER_PEER {
            let number = u32::try_from(index).expect("fragment test index fits");
            let source_port = 40_000 + u16::try_from(number).expect("port index fits");
            let datagram = udp6_payload(LOCAL6, PEER6, source_port, 53);
            let mut first = ipv6_fragment(&datagram, 0x4000 + number, 0, 8, true);
            let mut last = ipv6_fragment(&datagram, 0x4000 + number, 16, 8, false);
            let mut middle = ipv6_fragment(&datagram, 0x4000 + number, 8, 8, true);

            assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
            assert!(filter.check_at(&mut last, Direction::HostToMesh, now));
            assert!(filter.check_at(&mut middle, Direction::HostToMesh, now));
        }
    }

    /// A TCP first fragment must carry the whole TCP header. One cut after its ports hides the
    /// flags in a later fragment the filter never parses, so it is refused, and its later
    /// fragment finds no association to follow (J672 P2, #265). This also covers a mesh SSH
    /// redirect, whose checksum then always sits in the first fragment.
    #[test]
    fn a_tcp_first_fragment_without_the_whole_header_is_refused() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let datagram = tcp4(LOCAL4, PEER4, 40_000, 443, SYN);
        let mut first = ipv4_fragment(&datagram, 0x1239, 0, 16, true);
        let mut later = ipv4_fragment(&datagram, 0x1239, 16, 4, false);

        assert!(!filter.check_at(&mut first, Direction::HostToMesh, now));
        assert!(!filter.check_at(
            &mut later,
            Direction::HostToMesh,
            now + Duration::from_secs(1)
        ));
    }

    /// A full fragment table refuses a new datagram without leaving a conntrack flow behind.
    #[test]
    fn fragment_capacity_refusal_does_not_open_a_flow() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Udp, 53)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        for index in 0..FRAGMENTS_PER_PEER {
            let source_port = 40_000 + u16::try_from(index).expect("port index fits");
            let datagram = udp4_payload(LOCAL4, PEER4, source_port, 53);
            let mut first = ipv4_fragment(
                &datagram,
                0x2000 + u16::try_from(index).expect("fragment id fits"),
                0,
                16,
                true,
            );
            assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
        }

        let refused_port = 40_000 + u16::try_from(FRAGMENTS_PER_PEER).expect("port index fits");
        let refused = udp4_payload(LOCAL4, PEER4, refused_port, 53);
        let mut refused_first = ipv4_fragment(&refused, 0x3000, 0, 16, true);
        assert!(!filter.check_at(&mut refused_first, Direction::HostToMesh, now));

        let mut unsolicited_reply = udp4(PEER4, LOCAL4, 53, refused_port);
        assert!(!filter.check_at(
            &mut unsolicited_reply,
            Direction::MeshToHost,
            now + Duration::from_secs(1)
        ));
    }

    /// A narrow UDP grant admits later IPv6 fragments only after its first fragment passes.
    #[test]
    fn ipv6_fragments_follow_only_an_admitted_first_fragment() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Udp, 53)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let datagram = udp6_payload(LOCAL6, PEER6, 40_000, 53);
        let mut later = ipv6_fragment(&datagram, 0x1234_5678, 16, 8, false);
        let mut first = ipv6_fragment(&datagram, 0x1234_5678, 0, 16, true);

        assert!(!filter.check_at(&mut later, Direction::HostToMesh, now));
        assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
        assert!(filter.check_at(
            &mut later,
            Direction::HostToMesh,
            now + Duration::from_secs(1)
        ));
    }

    /// Fragment state expires with the flow and cannot survive a policy that revokes its grant.
    #[test]
    fn fragment_state_expires_and_policy_publication_revokes_it() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Udp, 53)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let datagram = udp4_payload(LOCAL4, PEER4, 40_000, 53);
        let mut first = ipv4_fragment(&datagram, 0x1236, 0, 16, true);
        let mut later = ipv4_fragment(&datagram, 0x1236, 16, 8, false);
        assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
        assert!(!filter.check_at(
            &mut later,
            Direction::HostToMesh,
            now + FRAGMENT_IDLE_TIMEOUT + Duration::from_secs(1)
        ));

        let fresh = udp4_payload(LOCAL4, PEER4, 40_001, 53);
        let mut fresh_first = ipv4_fragment(&fresh, 0x1237, 0, 16, true);
        let mut fresh_later = ipv4_fragment(&fresh, 0x1237, 16, 8, false);
        let refreshed = now + UDP_IDLE_TIMEOUT + Duration::from_secs(2);
        assert!(filter.check_at(&mut fresh_first, Direction::HostToMesh, refreshed));
        let revoked = PacketFilter::prepare_policy(
            &config(TrafficPolicy::None, TrafficPolicy::None),
            MeshProxyIngress::default(),
        )
        .expect("prepare revoked policy");
        filter.publish_policy(revoked);
        assert!(!filter.check_at(
            &mut fresh_later,
            Direction::HostToMesh,
            refreshed + Duration::from_secs(1)
        ));
    }

    /// A fragmented ICMP error inherits access only from its quoted, still-authorized flow.
    #[test]
    fn fragmented_icmp_errors_follow_the_quoted_flow() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Udp, 53)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut request = udp4(LOCAL4, PEER4, 40_000, 53);
        assert!(filter.check_at(&mut request, Direction::HostToMesh, now));

        let mut error = vec![0; 64];
        error[0] = 0x45;
        error[2..4].copy_from_slice(&64_u16.to_be_bytes());
        error[8] = 64;
        error[9] = 1;
        error[12..16].copy_from_slice(&PEER4.octets());
        error[16..20].copy_from_slice(&LOCAL4.octets());
        error[20] = 3;
        error[21] = 3;
        error[28..56].copy_from_slice(&request);
        let mut first = ipv4_fragment(&error, 0x123a, 0, 40, true);
        let mut later = ipv4_fragment(&error, 0x123a, 40, 4, false);

        assert!(filter.check_at(&mut first, Direction::MeshToHost, now));
        assert!(filter.check_at(
            &mut later,
            Direction::MeshToHost,
            now + Duration::from_secs(1)
        ));
    }

    /// A fragment from an unconfigured source cannot reuse another peer's admitted fragment ID.
    #[test]
    fn fragment_state_is_scoped_to_the_configured_peer_address() {
        let filter = PacketFilter::new(
            &config(grant(Protocol::Udp, 53), TrafficPolicy::None),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let datagram = udp4_payload(PEER4, LOCAL4, 40_000, 53);
        let mut first = ipv4_fragment(&datagram, 0x1238, 0, 16, true);
        assert!(filter.check_at(&mut first, Direction::MeshToHost, now));

        let spoofed = udp4_payload(OTHER_PEER4, LOCAL4, 40_000, 53);
        let mut spoofed_later = ipv4_fragment(&spoofed, 0x1238, 16, 8, false);
        assert!(!filter.check_at(
            &mut spoofed_later,
            Direction::MeshToHost,
            now + Duration::from_secs(1)
        ));
    }

    /// Malformed packets and non-final fragments with invalid lengths fail closed.
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

    /// TCP FIN plus ACK, used to close a test connection.
    const FIN_ACK: u8 = 0x11;
    /// J592 review (P1, availability, D384, #265): closing a connection never ends its flow
    /// entry. FIN and RST are only inspected when a flow starts, so a closed TCP flow keeps one
    /// of the peer's 128 slots for the full 300 s idle timeout, and a full table drops every new
    /// flow. A peer granted TCP/443 that opens and cleanly closes 129 short connections within
    /// a few seconds (a browser, a health check, a backup job) is cut off for minutes. Kernel
    /// conntrack, which the full policy used, ends closed flows and holds far more.
    #[test]
    fn review_j592_closed_tcp_connections_do_not_exhaust_the_peer_flow_table() {
        let filter = PacketFilter::new(
            &config(grant(Protocol::Tcp, 443), TrafficPolicy::None),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let start = Instant::now();
        for index in 0..200_u16 {
            // One complete connection every 20 ms: 200 connections in 4 s.
            let now = start + Duration::from_millis(u64::from(index) * 20);
            let port = 40_000 + index;
            let steps = [
                (tcp4(PEER4, LOCAL4, port, 443, SYN), Direction::MeshToHost),
                (
                    tcp4(LOCAL4, PEER4, 443, port, SYN_ACK),
                    Direction::HostToMesh,
                ),
                (tcp4(PEER4, LOCAL4, port, 443, ACK), Direction::MeshToHost),
                (
                    tcp4(PEER4, LOCAL4, port, 443, FIN_ACK),
                    Direction::MeshToHost,
                ),
                (
                    tcp4(LOCAL4, PEER4, 443, port, FIN_ACK),
                    Direction::HostToMesh,
                ),
                (tcp4(PEER4, LOCAL4, port, 443, ACK), Direction::MeshToHost),
            ];
            for (step, (mut packet, direction)) in steps.into_iter().enumerate() {
                assert!(
                    filter.check_at(&mut packet, direction, now),
                    "connection {index} (step {step}) was dropped: closed connections still \
                     hold the peer's flow slots"
                );
            }
        }
    }

    /// J592 review (P1, availability, D384, #265): UDP has no close, so each request from a new
    /// source port holds a slot for 60 s. 128 slots per peer allow about two new UDP flows per
    /// second: a peer resolving names through the mesh DNS service at four queries a second is
    /// cut off after about 32 s, and the kernel conntrack it replaced did not do that.
    #[test]
    fn review_j592_a_peer_can_send_four_dns_queries_a_second_for_a_minute() {
        let filter = PacketFilter::new(
            &config(grant(Protocol::Udp, 53), TrafficPolicy::None),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let start = Instant::now();
        let mut dropped = Vec::new();
        for index in 0..240_u16 {
            let now = start + Duration::from_millis(u64::from(index) * 250);
            let port = 30_000 + index;
            let mut query = udp4(PEER4, LOCAL4, port, 53);
            let mut answer = udp4(LOCAL4, PEER4, 53, port);
            if !filter.check_at(&mut query, Direction::MeshToHost, now)
                || !filter.check_at(&mut answer, Direction::HostToMesh, now)
            {
                dropped.push(index);
            }
        }
        assert!(
            dropped.is_empty(),
            "{} of 240 queries dropped, the first at query {:?}",
            dropped.len(),
            dropped.first()
        );
    }

    /// TCP RST, used to abort a test connection.
    const RST: u8 = 0x04;

    /// J592 review (P2, security, D384 vs D164, #265): the established path never looks at TCP
    /// flags and matches a tuple in either direction. After this host's outbound connection
    /// from port 40000 to the peer's 443 is reset, the peer can still send a SYN from 443 to
    /// 40000 and it is admitted as "established", although the peer has no inbound grant and
    /// kernel conntrack would treat that SYN as a new, refused connection. By refreshing the
    /// tuple every 299 s the peer keeps that door open indefinitely.
    #[test]
    fn review_j592_a_reset_outbound_flow_cannot_be_reopened_by_the_peer() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut open = tcp4(LOCAL4, PEER4, 40_000, 443, SYN);
        assert!(filter.check_at(&mut open, Direction::HostToMesh, now));
        let mut accept = tcp4(PEER4, LOCAL4, 443, 40_000, SYN_ACK);
        assert!(filter.check_at(&mut accept, Direction::MeshToHost, now));
        let mut reset = tcp4(LOCAL4, PEER4, 40_000, 443, RST);
        assert!(filter.check_at(&mut reset, Direction::HostToMesh, now));

        let mut reverse_syn = tcp4(PEER4, LOCAL4, 443, 40_000, SYN);
        assert!(
            !filter.check_at(
                &mut reverse_syn,
                Direction::MeshToHost,
                now + Duration::from_secs(299)
            ),
            "a peer with no inbound grant opened a connection to this host's port 40000"
        );
    }

    /// J592 review (P3, security, D384, #265): IPv6 next-header values 135, 139 and 140 are
    /// parsed as extension headers, but Linux delivers them as upper-layer protocols (raw
    /// sockets, MIP6). A peer granted only TCP/443 wraps a TCP/443 segment behind next header
    /// 139: the filter checks TCP/443 while the kernel hands protocol 139 to whatever listens
    /// for it. The filter and the kernel must agree on the protocol; protocols outside a
    /// port grant need an `All` grant.
    #[test]
    fn review_j592_ipv6_upper_layer_protocols_are_not_skipped_as_extension_headers() {
        let filter = PacketFilter::new(
            &config(grant(Protocol::Tcp, 443), TrafficPolicy::None),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        // An 8-byte header claiming next header TCP, then the unchanged TCP segment.
        let wrap = |next_header: u8, source_port: u16| {
            let plain = tcp6(PEER6, LOCAL6, source_port, 443, SYN);
            let mut wrapped = plain[..40].to_vec();
            wrapped.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
            wrapped.extend_from_slice(&plain[40..]);
            wrapped[6] = next_header;
            wrapped[4..6].copy_from_slice(&28_u16.to_be_bytes());
            wrapped
        };
        // Control: a real Destination Options header (60) in front of TCP/443 is admitted, so
        // the refusal below is about the protocol number, not the packet shape.
        let mut options = wrap(60, 40_001);
        assert!(filter.check_at(&mut options, Direction::MeshToHost, Instant::now()));
        let mut wrapped = wrap(139, 40_000);
        assert!(
            !filter.check_at(&mut wrapped, Direction::MeshToHost, Instant::now()),
            "a TCP/443 grant admitted an IPv6 packet whose upper-layer protocol is 139"
        );
    }

    /// J592 review (P3, D384, #265): only ICMP errors may follow a flow as related traffic.
    /// `ICMPv4` redirects (type 5) and source quench (4), and `ICMPv6` types 0 and 5-127 (not
    /// errors), are admitted today whenever they quote a live flow.
    #[test]
    fn review_j592_only_real_icmp_errors_are_related_to_a_flow() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Udp, 53)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut request = udp4(LOCAL4, PEER4, 40_000, 53);
        assert!(filter.check_at(&mut request, Direction::HostToMesh, now));
        for (kind, code) in [(5_u8, 1_u8), (4, 0)] {
            let mut message = vec![0; 56];
            message[0] = 0x45;
            message[2..4].copy_from_slice(&56_u16.to_be_bytes());
            message[8] = 64;
            message[9] = 1;
            message[12..16].copy_from_slice(&PEER4.octets());
            message[16..20].copy_from_slice(&LOCAL4.octets());
            message[20] = kind;
            message[21] = code;
            message[28..56].copy_from_slice(&request);
            assert!(
                !filter.check_at(&mut message, Direction::MeshToHost, now),
                "ICMP type {kind} code {code} was admitted as related to the flow"
            );
        }
    }

    /// Open an established outbound TCP connection from `port` to `peer`:443 with the whole
    /// three-way handshake (SYN out, SYN-ACK back, ACK out); true when all three packets pass.
    ///
    /// Stopping at the SYN-ACK would leave a half-open connection, which the filter rightly
    /// treats as still opening (J617 P3, #265).
    fn establish4(filter: &PacketFilter, peer: Ipv4Addr, port: u16, now: Instant) -> bool {
        let mut syn = tcp4(LOCAL4, peer, port, 443, SYN);
        let mut syn_ack = tcp4(peer, LOCAL4, 443, port, SYN_ACK);
        let mut ack = tcp4(LOCAL4, peer, port, 443, ACK);
        filter.check_at(&mut syn, Direction::HostToMesh, now)
            && filter.check_at(&mut syn_ack, Direction::MeshToHost, now)
            && filter.check_at(&mut ack, Direction::HostToMesh, now)
    }

    /// A full table evicts the least recently seen flow that is not an established connection:
    /// here the oldest unanswered SYN goes, the next oldest stays, and established connections
    /// are never evicted (J592 P1-3, #265).
    #[test]
    fn a_full_table_evicts_the_oldest_unestablished_flow_and_never_an_established_one() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let start = Instant::now();
        let half =
            u16::try_from(FLOWS_PER_DIRECTION / 2).expect("half the quota fits a port count");
        for index in 0..half {
            assert!(establish4(&filter, PEER4, 10_000 + index, start));
        }
        for index in 0..half {
            let mut syn = tcp4(LOCAL4, PEER4, 20_000 + index, 443, SYN);
            let at = start + Duration::from_millis(u64::from(index) + 1);
            assert!(filter.check_at(&mut syn, Direction::HostToMesh, at));
        }
        let later = start + Duration::from_secs(1);
        let mut extra = tcp4(LOCAL4, PEER4, 30_000, 443, SYN);
        assert!(
            filter.check_at(&mut extra, Direction::HostToMesh, later),
            "a full table must make room by evicting an unanswered SYN"
        );
        let mut evicted = tcp4(PEER4, LOCAL4, 443, 20_000, SYN_ACK);
        assert!(
            !filter.check_at(&mut evicted, Direction::MeshToHost, later),
            "the oldest unanswered SYN was the one evicted"
        );
        let mut kept = tcp4(PEER4, LOCAL4, 443, 20_001, SYN_ACK);
        assert!(filter.check_at(&mut kept, Direction::MeshToHost, later));
        for index in 0..half {
            let mut data = tcp4(PEER4, LOCAL4, 443, 10_000 + index, ACK);
            assert!(
                filter.check_at(&mut data, Direction::MeshToHost, later),
                "established connection {index} was evicted"
            );
        }
    }

    /// A closed connection lingers only for its last ACK: after `TCP_CLOSED_TIMEOUT` its tuple
    /// is gone, and a half-closed one still carries data the other way.
    #[test]
    fn closed_tcp_flows_expire_quickly_and_half_closed_ones_keep_flowing() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        assert!(establish4(&filter, PEER4, 40_000, now));
        let mut fin = tcp4(LOCAL4, PEER4, 40_000, 443, FIN_ACK);
        assert!(filter.check_at(&mut fin, Direction::HostToMesh, now));
        let half_closed = now + TCP_CLOSED_TIMEOUT + Duration::from_secs(1);
        let mut data = tcp4(PEER4, LOCAL4, 443, 40_000, ACK);
        assert!(
            filter.check_at(&mut data, Direction::MeshToHost, half_closed),
            "a half-closed connection still carries the other direction's data"
        );
        let mut fin_back = tcp4(PEER4, LOCAL4, 443, 40_000, FIN_ACK);
        assert!(filter.check_at(&mut fin_back, Direction::MeshToHost, half_closed));
        let mut last_ack = tcp4(LOCAL4, PEER4, 40_000, 443, ACK);
        assert!(filter.check_at(&mut last_ack, Direction::HostToMesh, half_closed));
        let mut late = tcp4(PEER4, LOCAL4, 443, 40_000, ACK);
        assert!(
            !filter.check_at(
                &mut late,
                Direction::MeshToHost,
                half_closed + TCP_CLOSED_TIMEOUT + Duration::from_secs(1)
            ),
            "a closed connection's tuple outlived its close timeout"
        );
    }

    /// A SYN in the opening direction on a closed tuple starts a new connection, checked
    /// against the current grant; on a live connection a reverse SYN is refused.
    #[test]
    fn a_syn_reopens_a_closed_tuple_only_through_a_fresh_grant_check() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        assert!(establish4(&filter, PEER4, 40_000, now));
        let mut reverse = tcp4(PEER4, LOCAL4, 443, 40_000, SYN);
        assert!(
            !filter.check_at(&mut reverse, Direction::MeshToHost, now),
            "a reverse SYN rode a live outbound connection"
        );
        let mut data = tcp4(PEER4, LOCAL4, 443, 40_000, ACK);
        assert!(
            filter.check_at(&mut data, Direction::MeshToHost, now),
            "a refused reverse SYN must not tear down the live connection"
        );
        let mut reset = tcp4(PEER4, LOCAL4, 443, 40_000, RST);
        assert!(filter.check_at(&mut reset, Direction::MeshToHost, now));
        let mut again = tcp4(LOCAL4, PEER4, 40_000, 443, SYN);
        assert!(
            filter.check_at(&mut again, Direction::HostToMesh, now),
            "this host may reopen its own granted tuple after a reset"
        );
        let mut accept = tcp4(PEER4, LOCAL4, 443, 40_000, SYN_ACK);
        assert!(filter.check_at(&mut accept, Direction::MeshToHost, now));
    }

    /// Removing flows turns their slots back into empty ones once no probe chain needs them,
    /// so a table that has seen churn still ends a miss at the first empty slot.
    #[test]
    fn revoked_flows_leave_empty_slots_not_tombstones() {
        let mut policy = config(TrafficPolicy::None, TrafficPolicy::All);
        let filter =
            PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile policy");
        let now = Instant::now();
        for index in 0..100_u16 {
            assert!(establish4(&filter, PEER4, 20_000 + index, now));
        }
        policy.peers.get_mut(&NodeId(2)).expect("peer").outbound = TrafficPolicy::None;
        filter.publish_policy(
            PacketFilter::prepare_policy(&policy, MeshProxyIngress::default())
                .expect("prepare revocation"),
        );
        assert!(
            filter.with_table(NodeId(2), |table| table.is_none_or(|shard| shard
                .slots
                .iter()
                .all(|slot| matches!(slot, FlowSlot::Empty)))),
            "every slot of a fully revoked table is empty again"
        );
        assert_eq!(
            filter.allocated_tables(),
            0,
            "the sweep after the publish frees a table left empty"
        );
    }

    /// Memory of one active peer's fixed conntrack and fragment tables, times D393's 1,000-peer
    /// design scale and 4,096-peer test scale, the worst case where every peer has flows
    /// (PROCESS §1: memory per unit times the expected count). Printed for the issue; the
    /// bound keeps a later change from growing it unnoticed. Idle peers allocate none; see
    /// `idle_peers_add_under_five_mib_of_rss`.
    #[test]
    fn flow_table_memory_per_peer_times_one_thousand_peers() {
        let per_peer = std::mem::size_of::<FlowSlot>() * FLOW_SLOTS_PER_PEER
            + (std::mem::size_of::<FragmentSlot>() + std::mem::size_of::<FragmentCoverage>())
                * FRAGMENTS_PER_PEER
            + std::mem::size_of::<PeerFlows>()
            + std::mem::size_of::<PeerAccess>();
        println!(
            "FLOW_TABLE_MEMORY flow_slot={} flow_slots={} per_direction={} fragment_slot={} \
             coverage={} fragments={} per_peer={per_peer} x1000={} x4096={}",
            std::mem::size_of::<FlowSlot>(),
            FLOW_SLOTS_PER_PEER,
            FLOWS_PER_DIRECTION,
            std::mem::size_of::<FragmentSlot>(),
            std::mem::size_of::<FragmentCoverage>(),
            FRAGMENTS_PER_PEER,
            per_peer * 1000,
            per_peer * 4096
        );
        assert_eq!(
            usize::try_from(FLOW_SLOTS_PER_PEER_HASH).ok(),
            Some(FLOW_SLOTS_PER_PEER)
        );
        assert!(
            per_peer <= PER_PEER_MEMORY_BUDGET,
            "{per_peer} bytes per peer exceeds the {PER_PEER_MEMORY_BUDGET}-byte budget"
        );
    }

    /// Each direction has its own quota: this host holding a full quota of established
    /// outbound connections still admits the peer's new inbound connection, and a full
    /// direction makes room by evicting its own oldest unestablished flow, never one the other
    /// side opened (J617 P2, #265).
    #[test]
    fn each_direction_keeps_its_own_quota_and_evicts_only_its_own_flows() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::All, TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let start = Instant::now();
        let mut inbound_syn = tcp4(PEER4, LOCAL4, 30_000, 443, SYN);
        assert!(filter.check_at(&mut inbound_syn, Direction::MeshToHost, start));
        let quota = u16::try_from(FLOWS_PER_DIRECTION).expect("quota fits a port count");
        for index in 0..quota {
            let mut syn = tcp4(LOCAL4, PEER4, 20_000 + index, 443, SYN);
            let at = start + Duration::from_millis(u64::from(index) + 1);
            assert!(filter.check_at(&mut syn, Direction::HostToMesh, at));
        }
        let later = start + Duration::from_secs(1);
        let mut extra = tcp4(LOCAL4, PEER4, 21_000, 443, SYN);
        assert!(
            filter.check_at(&mut extra, Direction::HostToMesh, later),
            "a full outbound quota makes room among its own flows"
        );
        let mut evicted = tcp4(PEER4, LOCAL4, 443, 20_000, SYN_ACK);
        assert!(
            !filter.check_at(&mut evicted, Direction::MeshToHost, later),
            "the oldest outbound SYN is the one evicted"
        );
        let mut accept = tcp4(LOCAL4, PEER4, 443, 30_000, SYN_ACK);
        assert!(
            filter.check_at(&mut accept, Direction::HostToMesh, later),
            "the older inbound SYN belongs to the other quota and must survive"
        );

        let held = PacketFilter::new(
            &config(grant(Protocol::Tcp, 8443), TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        for index in 0..quota {
            assert!(establish4(&held, PEER4, 20_000 + index, start));
        }
        let mut inbound = tcp4(PEER4, LOCAL4, 40_000, 8443, SYN);
        assert!(
            held.check_at(&mut inbound, Direction::MeshToHost, later),
            "this host's {quota} held outbound connections locked the peer out of its inbound grant"
        );
    }

    /// Withdrawn peers lose their address at once: the old owner's open flows and grants stop
    /// matching before the engine hands the address to a new node, and the new owner starts
    /// with only its own grants when the next policy is published (J592 P2-5).
    #[test]
    fn a_withdrawn_peer_address_admits_nothing_until_its_new_owner_is_published() {
        let old = config(TrafficPolicy::All, TrafficPolicy::All);
        let filter = PacketFilter::new(&old, MeshProxyIngress::default()).expect("compile policy");
        let now = Instant::now();
        assert!(establish4(&filter, PEER4, 40_000, now));

        filter.withdraw_peers(&BTreeSet::from([NodeId(2)]));
        let mut data = tcp4(PEER4, LOCAL4, 443, 40_000, ACK);
        assert!(!filter.check_at(&mut data, Direction::MeshToHost, now));
        let mut syn = tcp4(PEER4, LOCAL4, 40_001, 22, SYN);
        assert!(!filter.check_at(&mut syn, Direction::MeshToHost, now));

        let mut moved = config(TrafficPolicy::None, TrafficPolicy::None);
        let owner = moved.peers.remove(&NodeId(2)).expect("peer");
        moved.peers.insert(NodeId(9), owner);
        filter.publish_policy(
            PacketFilter::prepare_policy(&moved, MeshProxyIngress::default())
                .expect("prepare moved address"),
        );
        let mut data = tcp4(PEER4, LOCAL4, 443, 40_000, ACK);
        assert!(
            !filter.check_at(&mut data, Direction::MeshToHost, now),
            "the new owner inherited the old owner's flow"
        );
    }

    /// Only readable settings above their limit are reported, with the dotted name.
    #[test]
    fn sysctl_gaps_report_only_values_above_their_limit() {
        let gaps = super::sysctl_gaps(|name| match name {
            "net/ipv4/conf/all/accept_source_route" => Some("1\n".to_owned()),
            _ => None,
        });
        assert_eq!(
            gaps,
            ["net.ipv4.conf.all.accept_source_route = 1 (want <= 0)"]
        );
        assert_eq!(
            super::sysctl_gaps(|name| Some(
                if name.contains("ipv6") { "-1" } else { "0" }.to_owned()
            )),
            Vec::<String>::new()
        );
    }

    /// J617 review (P2, #265, D384): one peer's held inbound connections must not stop this
    /// host from opening its own connections to that peer.
    ///
    /// The 128 slots are shared by both directions and established connections are never
    /// evicted. Any process on the peer, an unprivileged account or an ordinary connection pool
    /// included, that holds 128 connections to a granted port therefore refuses every new
    /// connection in both directions for as long as it holds them: this host can no longer
    /// reach the peer, and nobody else on the peer can reach this host (mesh SSH included). The
    /// kernel conntrack this replaces had no per-peer cap. The fix commit's doc says such a peer
    /// "can only stop itself"; this test shows the host is stopped too.
    #[test]
    fn review_j617_a_peers_inbound_connections_cannot_lock_this_host_out_of_it() {
        let filter = PacketFilter::new(
            &config(grant(Protocol::Tcp, 443), TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let held = u16::try_from(FLOWS_PER_DIRECTION).expect("cap fits a port count");
        for index in 0..held {
            let port = 40_000 + index;
            let mut syn = tcp4(PEER4, LOCAL4, port, 443, SYN);
            let mut syn_ack = tcp4(LOCAL4, PEER4, 443, port, SYN_ACK);
            let mut ack = tcp4(PEER4, LOCAL4, port, 443, ACK);
            assert!(filter.check_at(&mut syn, Direction::MeshToHost, now));
            assert!(filter.check_at(&mut syn_ack, Direction::HostToMesh, now));
            assert!(filter.check_at(&mut ack, Direction::MeshToHost, now));
        }
        let mut outbound = tcp4(LOCAL4, PEER4, 50_000, 22, SYN);
        assert!(
            filter.check_at(
                &mut outbound,
                Direction::HostToMesh,
                now + Duration::from_secs(1)
            ),
            "the peer's {held} inbound connections locked this host out of its own outbound grant"
        );
    }

    /// J617 review (P3, #265, D384): an answered SYN that never gets its final ACK is a
    /// half-open connection, not an established one.
    ///
    /// `observe` marks a flow replied on the SYN-ACK, so `established()` is true before the
    /// handshake completes: a half-open connection keeps the 300 s established timeout and can
    /// never be evicted. Kernel conntrack keeps it in `SYN_RECV` (60 s) and may drop it under
    /// pressure. Here 127 complete connections plus one half-open fill the table; a new SYN
    /// must evict the half-open one.
    #[test]
    fn review_j617_a_half_open_connection_is_not_established() {
        let filter = PacketFilter::new(
            &config(grant(Protocol::Tcp, 443), TrafficPolicy::None),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let complete = u16::try_from(FLOWS_PER_DIRECTION - 1).expect("cap fits a port count");
        for index in 0..complete {
            let port = 40_000 + index;
            let mut syn = tcp4(PEER4, LOCAL4, port, 443, SYN);
            let mut syn_ack = tcp4(LOCAL4, PEER4, 443, port, SYN_ACK);
            let mut ack = tcp4(PEER4, LOCAL4, port, 443, ACK);
            assert!(filter.check_at(&mut syn, Direction::MeshToHost, now));
            assert!(filter.check_at(&mut syn_ack, Direction::HostToMesh, now));
            assert!(filter.check_at(&mut ack, Direction::MeshToHost, now));
        }
        let mut half_syn = tcp4(PEER4, LOCAL4, 45_000, 443, SYN);
        let mut half_syn_ack = tcp4(LOCAL4, PEER4, 443, 45_000, SYN_ACK);
        assert!(filter.check_at(&mut half_syn, Direction::MeshToHost, now));
        assert!(filter.check_at(&mut half_syn_ack, Direction::HostToMesh, now));
        let mut fresh = tcp4(PEER4, LOCAL4, 46_000, 443, SYN);
        assert!(
            filter.check_at(
                &mut fresh,
                Direction::MeshToHost,
                now + Duration::from_secs(1)
            ),
            "a half-open connection (SYN, SYN-ACK, no ACK) was treated as established and never evicted"
        );
    }

    /// J672 P1 (#265): an established connection that stays quiet for six minutes still
    /// carries its next packet in both directions. Kernel conntrack, which the `GotaTun` path
    /// used before D384, keeps an established TCP entry for 5 days.
    #[test]
    fn an_idle_established_connection_survives_six_quiet_minutes() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        assert!(establish4(&filter, PEER4, 40_000, now));
        let later = now + Duration::from_secs(360);
        let mut data = tcp4(LOCAL4, PEER4, 40_000, 443, ACK);
        assert!(
            filter.check_at(&mut data, Direction::HostToMesh, later),
            "an established connection idle for 6 minutes was cut: its next ACK was dropped"
        );
        let mut answer = tcp4(PEER4, LOCAL4, 443, 40_000, ACK);
        assert!(filter.check_at(&mut answer, Direction::MeshToHost, later));
    }

    /// An established connection still ends at conntrack's 5-day limit: after it, a
    /// continuation cannot reopen the tuple.
    #[test]
    fn an_established_connection_expires_after_five_idle_days() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        assert!(establish4(&filter, PEER4, 40_000, now));
        let just_before = now + TCP_ESTABLISHED_TIMEOUT;
        let mut data = tcp4(LOCAL4, PEER4, 40_000, 443, ACK);
        assert!(filter.check_at(&mut data, Direction::HostToMesh, just_before));
        let past = just_before + TCP_ESTABLISHED_TIMEOUT + Duration::from_secs(1);
        let mut stale = tcp4(LOCAL4, PEER4, 40_000, 443, ACK);
        assert!(!filter.check_at(&mut stale, Direction::HostToMesh, past));
    }

    /// J672 P2 (#265): a peer with no inbound grant cannot get a reverse SYN to this host's
    /// port by splitting it after the ports, so the first fragment carries no TCP flags and the
    /// SYN bit arrives in a later fragment. Here on a reset tuple (J592's case).
    #[test]
    fn a_tiny_first_fragment_cannot_hide_a_reverse_syn() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut open = tcp4(LOCAL4, PEER4, 40_000, 443, SYN);
        assert!(filter.check_at(&mut open, Direction::HostToMesh, now));
        let mut accept = tcp4(PEER4, LOCAL4, 443, 40_000, SYN_ACK);
        assert!(filter.check_at(&mut accept, Direction::MeshToHost, now));
        let mut reset = tcp4(LOCAL4, PEER4, 40_000, 443, RST);
        assert!(filter.check_at(&mut reset, Direction::HostToMesh, now));
        let later = now + Duration::from_secs(1);
        let whole = tcp4(PEER4, LOCAL4, 443, 40_000, SYN);
        let mut first = ipv4_fragment(&whole, 7, 0, 8, true);
        let mut second = ipv4_fragment(&whole, 7, 8, 12, false);
        let first_ok = filter.check_at(&mut first, Direction::MeshToHost, later);
        let second_ok = filter.check_at(&mut second, Direction::MeshToHost, later);
        assert!(
            !first_ok && !second_ok,
            "a reverse SYN split after its ports reached port 40000 with no inbound grant \
             (first fragment {first_ok}, second {second_ok})"
        );
    }

    /// J672 P2 (#265): the same split on a live established tuple, where the whole reverse
    /// SYN is refused by the bare-SYN rule, is refused too; and the same for IPv6.
    #[test]
    fn a_tiny_first_fragment_cannot_hide_a_reverse_syn_on_a_live_tuple() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        assert!(establish4(&filter, PEER4, 40_000, now));
        let whole = tcp4(PEER4, LOCAL4, 443, 40_000, SYN);
        let mut control = whole.clone();
        assert!(!filter.check_at(&mut control, Direction::MeshToHost, now));
        let mut first = ipv4_fragment(&whole, 9, 0, 8, true);
        let mut second = ipv4_fragment(&whole, 9, 8, 12, false);
        assert!(!filter.check_at(&mut first, Direction::MeshToHost, now));
        assert!(!filter.check_at(&mut second, Direction::MeshToHost, now));

        let mut open6 = tcp6(LOCAL6, PEER6, 40_000, 443, SYN);
        let mut accept6 = tcp6(PEER6, LOCAL6, 443, 40_000, SYN_ACK);
        let mut ack6 = tcp6(LOCAL6, PEER6, 40_000, 443, ACK);
        assert!(filter.check_at(&mut open6, Direction::HostToMesh, now));
        assert!(filter.check_at(&mut accept6, Direction::MeshToHost, now));
        assert!(filter.check_at(&mut ack6, Direction::HostToMesh, now));
        let whole6 = tcp6(PEER6, LOCAL6, 443, 40_000, SYN);
        let mut first6 = ipv6_fragment(&whole6, 11, 0, 8, true);
        let mut second6 = ipv6_fragment(&whole6, 11, 8, 12, false);
        assert!(!filter.check_at(&mut first6, Direction::MeshToHost, now));
        assert!(!filter.check_at(&mut second6, Direction::MeshToHost, now));
    }

    /// RFC 1858: a later TCP fragment that starts inside the minimum TCP header could
    /// overwrite the flags the filter judged in the first fragment, so it is refused even
    /// when its first fragment was admitted.
    #[test]
    fn a_later_tcp_fragment_cannot_overlap_the_tcp_header() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut datagram = tcp4(LOCAL4, PEER4, 40_000, 443, SYN);
        datagram.extend_from_slice(&[0; 16]);
        let total_len = u16::try_from(datagram.len()).expect("test TCP packet fits IPv4 length");
        datagram[2..4].copy_from_slice(&total_len.to_be_bytes());
        let mut first = ipv4_fragment(&datagram, 13, 0, 24, true);
        let mut overlap = ipv4_fragment(&datagram, 13, 8, 8, true);
        let mut rest = ipv4_fragment(&datagram, 13, 24, 12, false);
        assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
        assert!(!filter.check_at(&mut overlap, Direction::HostToMesh, now));
        assert!(filter.check_at(&mut rest, Direction::HostToMesh, now));
    }

    /// Build an `ICMPv4` message of `kind` (code 0) with identifier `identifier`.
    fn icmp4(source: Ipv4Addr, destination: Ipv4Addr, kind: u8, identifier: u16) -> Vec<u8> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20] = kind;
        packet[24..26].copy_from_slice(&identifier.to_be_bytes());
        packet
    }

    /// J672 P3 (#265): an outbound ping with identifier 0 lets back only its echo reply, not
    /// the peer's other ICMP types (here a timestamp request) and not the peer's own echo
    /// request, which shares the reply's tuple.
    #[test]
    fn an_outbound_ping_admits_only_its_echo_reply() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut ping = icmp4(LOCAL4, PEER4, 8, 0);
        assert!(filter.check_at(&mut ping, Direction::HostToMesh, now));
        let mut timestamp = icmp4(PEER4, LOCAL4, 13, 0);
        assert!(
            !filter.check_at(&mut timestamp, Direction::MeshToHost, now),
            "the peer's ICMP timestamp request rode this host's echo flow"
        );
        let mut request = icmp4(PEER4, LOCAL4, 8, 0);
        assert!(
            !filter.check_at(&mut request, Direction::MeshToHost, now),
            "the peer's echo request rode this host's echo flow"
        );
        let mut reply = icmp4(PEER4, LOCAL4, 0, 0);
        assert!(filter.check_at(&mut reply, Direction::MeshToHost, now));
        let mut other_id = icmp4(PEER4, LOCAL4, 0, 7);
        assert!(!filter.check_at(&mut other_id, Direction::MeshToHost, now));
    }

    /// ICMP that is neither an echo nor an error passes only under an `All` grant in its own
    /// direction and leaves no state behind for the other direction.
    #[test]
    fn other_icmp_is_judged_alone_and_leaves_no_state() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut outbound = icmp4(LOCAL4, PEER4, 13, 0);
        assert!(filter.check_at(&mut outbound, Direction::HostToMesh, now));
        let mut back = icmp4(PEER4, LOCAL4, 14, 0);
        assert!(!filter.check_at(&mut back, Direction::MeshToHost, now));
        assert!(
            filter.with_table(NodeId(2), |table| table.is_none_or(|shard| shard
                .slots
                .iter()
                .all(|slot| !matches!(slot, FlowSlot::Occupied(_))))),
            "a stateless ICMP message created a flow"
        );
    }

    /// J672 owner question (a), green: a peer holding a full direction of established inbound
    /// connections does not stop this host opening its own full quota of outbound ones.
    #[test]
    fn held_inbound_quota_does_not_block_outbound() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::All, TrafficPolicy::All),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let quota = u16::try_from(FLOWS_PER_DIRECTION).expect("quota fits a port count");
        for port in 0..quota {
            let mut syn = tcp4(PEER4, LOCAL4, 20_000 + port, 22_000, SYN);
            let mut syn_ack = tcp4(LOCAL4, PEER4, 22_000, 20_000 + port, SYN_ACK);
            let mut ack = tcp4(PEER4, LOCAL4, 20_000 + port, 22_000, ACK);
            assert!(filter.check_at(&mut syn, Direction::MeshToHost, now));
            assert!(filter.check_at(&mut syn_ack, Direction::HostToMesh, now));
            assert!(filter.check_at(&mut ack, Direction::MeshToHost, now));
        }
        let mut extra = tcp4(PEER4, LOCAL4, 30_000, 22_000, SYN);
        assert!(!filter.check_at(&mut extra, Direction::MeshToHost, now));
        for port in 0..quota {
            assert!(establish4(&filter, PEER4, 40_000 + port, now));
        }
    }

    /// The IPv4 mesh address of synthetic peer `n` (2 ≤ n < 65,536), for scale tests.
    fn scale_peer4(n: u32) -> Ipv4Addr {
        let [_, _, high, low] = n.to_be_bytes();
        Ipv4Addr::new(10, 254, high, low)
    }

    /// One local node with `peers` synthetic peers, every one with `All` grants both ways,
    /// shaped like D393's design and test scales (J718's fixture, #265).
    fn scale_config(peers: u32) -> Config {
        let mut config = config(TrafficPolicy::All, TrafficPolicy::All);
        let template = config.peers.remove(&NodeId(2)).expect("template peer");
        for n in 2..peers + 2 {
            let mut peer = template.clone();
            let [_, _, high, low] = n.to_be_bytes();
            peer.peer.addresses = Addresses {
                ipv4: scale_peer4(n),
                ipv6: Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 1, u16::from_be_bytes([high, low])),
            };
            config.peers.insert(NodeId(u64::from(n)), peer);
        }
        config
    }

    /// Only peers with flows get a flow table (J721, #265): compiling, preparing and
    /// publishing a 1,000-peer policy allocates none, and the 10 peers that open flows get one
    /// each. Their flows survive the publish without being copied.
    #[test]
    fn idle_peers_allocate_no_flow_tables() {
        let config = scale_config(1000);
        let filter = PacketFilter::new(&config, MeshProxyIngress::default()).expect("compile");
        assert_eq!(
            filter.allocated_tables(),
            0,
            "compiling allocated flow tables"
        );
        let now = Instant::now();
        for n in 2..12 {
            for port in 0..8 {
                assert!(establish4(&filter, scale_peer4(n), 40_000 + port, now));
            }
        }
        assert_eq!(filter.allocated_tables(), 10);
        let prepared =
            PacketFilter::prepare_policy(&config, MeshProxyIngress::default()).expect("prepare");
        assert_eq!(
            filter.allocated_tables(),
            10,
            "preparing allocated flow tables"
        );
        filter.publish_policy(prepared);
        assert_eq!(
            filter.allocated_tables(),
            10,
            "publishing allocated or lost tables"
        );
        for n in 2..12 {
            let mut reply = tcp4(scale_peer4(n), LOCAL4, 443, 40_000, ACK);
            assert!(
                filter.check_at(&mut reply, Direction::MeshToHost, now),
                "peer {n}'s connection did not survive the publish"
            );
        }
    }

    /// A publish never waits for a peer's flow table (J721, #265): with the tables of every
    /// active peer held by a packet worker, it still completes and the new grants apply at
    /// once. The lock every packet waits behind is held only to swap a pointer. Before J721 a
    /// publish locked and scanned every peer's table under that lock (J718: 7.3 ms at 4,096
    /// peers). This checks the structure, not wall-clock time: PROCESS keeps timing in the
    /// bench harness.
    #[test]
    fn publish_never_waits_for_a_peer_table() {
        let mut config = scale_config(64);
        let filter = std::sync::Arc::new(
            PacketFilter::new(&config, MeshProxyIngress::default()).expect("compile"),
        );
        let now = Instant::now();
        for n in 2..6 {
            assert!(establish4(&filter, scale_peer4(n), 40_000, now));
        }
        let cells: Vec<_> = filter
            .tables
            .lock()
            .expect("tables")
            .values()
            .cloned()
            .collect();
        assert_eq!(cells.len(), 4);
        let guards: Vec<_> = cells
            .iter()
            .map(|cell| cell.table.lock().expect("table"))
            .collect();
        config.peers.get_mut(&NodeId(2)).expect("peer").outbound = TrafficPolicy::None;
        let prepared =
            PacketFilter::prepare_policy(&config, MeshProxyIngress::default()).expect("prepare");
        let (done, publish_finished) = std::sync::mpsc::channel();
        let publisher = std::sync::Arc::clone(&filter);
        let thread = std::thread::spawn(move || {
            publisher.publish_policy(prepared);
            done.send(()).expect("report publish");
        });
        let finished = publish_finished.recv_timeout(Duration::from_secs(30));
        drop(guards);
        thread.join().expect("publisher thread");
        assert!(
            finished.is_ok(),
            "publish waited for a peer table held by a packet worker"
        );
        // The sweep skipped the held tables, so the revoked flow's entry is still there, yet
        // its next packet is refused.
        let mut revoked = tcp4(LOCAL4, scale_peer4(2), 40_000, 443, ACK);
        assert!(!filter.check_at(&mut revoked, Direction::HostToMesh, now));
        let mut kept = tcp4(LOCAL4, scale_peer4(3), 40_000, 443, ACK);
        assert!(filter.check_at(&mut kept, Direction::HostToMesh, now));
    }

    /// Revocation ends flows at publish even when the sweep could not visit the peer's table
    /// (J721, #265): no revoked flow admits another packet, and their slots go back to the
    /// quota the moment the full direction needs them.
    #[test]
    fn revoked_flows_skipped_by_the_sweep_free_their_quota_on_demand() {
        let mut policy = config(TrafficPolicy::All, TrafficPolicy::All);
        let filter = PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile");
        let now = Instant::now();
        let quota = u16::try_from(FLOWS_PER_DIRECTION).expect("quota");
        for port in 0..quota {
            assert!(establish4(&filter, PEER4, 20_000 + port, now));
        }
        policy.peers.get_mut(&NodeId(2)).expect("peer").outbound = grant(Protocol::Tcp, 8443);
        let prepared =
            PacketFilter::prepare_policy(&policy, MeshProxyIngress::default()).expect("prepare");
        let cell = filter
            .tables
            .lock()
            .expect("tables")
            .get(&NodeId(2))
            .cloned()
            .expect("peer cell");
        {
            // Hold the table as a packet worker would, so the sweep skips it.
            let _busy = cell.table.lock().expect("table");
            filter.publish_policy(prepared);
        }
        assert_eq!(
            filter.with_table(NodeId(2), |table| table.map(|shard| shard.initiated)),
            Some([usize::from(quota), 0]),
            "the sweep waited for a busy table"
        );
        let mut replacement = tcp4(LOCAL4, PEER4, 40_000, 8443, SYN);
        assert!(filter.check_at(&mut replacement, Direction::HostToMesh, now));
        assert_eq!(
            filter.with_table(NodeId(2), |table| table.map(|shard| shard.initiated)),
            Some([1, 0]),
            "the full direction did not reclaim its revoked flows"
        );
        for port in [0, quota / 2, quota - 1] {
            let mut stale = tcp4(LOCAL4, PEER4, 20_000 + port, 443, ACK);
            assert!(!filter.check_at(&mut stale, Direction::HostToMesh, now));
        }
    }

    /// Set in the child process that [`idle_peers_add_under_five_mib_of_rss`] starts, so the
    /// measurement runs alone and other tests' allocations do not blur it.
    #[cfg(target_os = "linux")]
    const RSS_CHILD_ENV: &str = "INFRATERNAL_PACKET_FILTER_RSS_CHILD";

    /// Read one `/proc/self/status` field, in KiB.
    #[cfg(target_os = "linux")]
    fn status_kib(field: &str) -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .expect("status")
            .lines()
            .find(|line| line.starts_with(field))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
            .expect("status field")
    }

    /// Build a filter for `peers` peers, open 8 connections on each of 10 of them, then
    /// prepare and publish the same policy 21 times, the way config applies do. Print the RSS
    /// added since before the filter existed, the peak (`VmHWM`, reset first) and the median and
    /// worst publish time. The config is built before the baseline, so only the filter is
    /// counted.
    #[cfg(target_os = "linux")]
    fn measure_filter_rss(peers: u32) -> (u64, u64) {
        let config = scale_config(peers);
        // "5" resets VmHWM to the current RSS, so the peak below is this run's own.
        std::fs::write("/proc/self/clear_refs", "5").expect("reset peak RSS");
        let baseline = status_kib("VmRSS:");
        let filter = PacketFilter::new(&config, MeshProxyIngress::default()).expect("compile");
        let now = Instant::now();
        for n in 2..12 {
            for port in 0..8 {
                assert!(establish4(&filter, scale_peer4(n), 40_000 + port, now));
            }
        }
        // 21 prepare + publish rounds: the first is the memory figure, all give the timing.
        let mut publish_us = Vec::new();
        for _ in 0..21 {
            let prepared = PacketFilter::prepare_policy(&config, MeshProxyIngress::default())
                .expect("prepare");
            let started = Instant::now();
            filter.publish_policy(prepared);
            publish_us.push(started.elapsed().as_micros());
        }
        let rss = status_kib("VmRSS:").saturating_sub(baseline);
        let peak = status_kib("VmHWM:").saturating_sub(baseline);
        publish_us.sort_unstable();
        println!(
            "FILTER_RSS peers={peers} active=10x8 rss_added_kib={rss} peak_added_kib={peak} \
             publish_us_median={} publish_us_max={} tables={}",
            publish_us[publish_us.len() / 2],
            publish_us[publish_us.len() - 1],
            filter.allocated_tables()
        );
        drop(filter);
        (rss, peak)
    }

    /// RSS regression guard (J721, #265; J718 measured +66.2 MiB and a 137.5 MiB peak): at
    /// D393's 1,000 peers with 10 active, the filter adds under 5 MiB, and a prepare plus
    /// publish raises the peak by under 5 MiB too, so memory never doubles. It re-runs itself
    /// in a child process, so the numbers are this filter's alone; it also prints the 4,096-peer
    /// figures and the publish time for the issue.
    #[cfg(target_os = "linux")]
    #[test]
    fn idle_peers_add_under_five_mib_of_rss() {
        const LIMIT_KIB: u64 = 5 * 1024;
        if std::env::var_os(RSS_CHILD_ENV).is_some() {
            let (rss, peak) = measure_filter_rss(1000);
            assert!(
                rss < LIMIT_KIB,
                "1,000 peers with 10 active added {rss} KiB of RSS"
            );
            assert!(
                peak < LIMIT_KIB,
                "a publish at 1,000 peers peaked {peak} KiB above baseline"
            );
            measure_filter_rss(4096);
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "packet_filter::tests::idle_peers_add_under_five_mib_of_rss",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(RSS_CHILD_ENV, "1")
            .output()
            .expect("run the measurement child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().filter(|line| line.contains("FILTER_RSS")) {
            println!("{line}");
        }
        assert!(
            output.status.success() && stdout.contains("FILTER_RSS peers=4096"),
            "the RSS measurement failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Connections that ended where the filter could not see it (the peer lost power, or its
    /// host timed out without a RST on the wire) do not lock the peer out for the 5-day
    /// established timeout (J718 P2, #265; J718's red test). With a full inbound quota of such
    /// connections, a new one is still refused for the first hour of silence, because they may
    /// be live and idle. After that, it evicts the oldest silent connection, and only that one.
    #[test]
    fn silent_established_connections_give_way_after_an_hour_only_when_full() {
        let filter = PacketFilter::new(
            &config(grant(Protocol::Tcp, 443), TrafficPolicy::None),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let start = Instant::now();
        let quota = u16::try_from(FLOWS_PER_DIRECTION).expect("quota");
        for index in 0..quota {
            let port = 20_000 + index;
            // Port 20,000 is the oldest; later ones were seen a millisecond apart.
            let at = start + Duration::from_millis(u64::from(index));
            let mut syn = tcp4(PEER4, LOCAL4, port, 443, SYN);
            let mut syn_ack = tcp4(LOCAL4, PEER4, 443, port, SYN_ACK);
            let mut ack = tcp4(PEER4, LOCAL4, port, 443, ACK);
            assert!(filter.check_at(&mut syn, Direction::MeshToHost, at));
            assert!(filter.check_at(&mut syn_ack, Direction::HostToMesh, at));
            assert!(filter.check_at(&mut ack, Direction::MeshToHost, at));
        }
        // One connection stays live: it carries a packet just before the hour is up.
        let live_at = start + TCP_ESTABLISHED_EVICTABLE_IDLE - Duration::from_secs(1);
        let mut live = tcp4(PEER4, LOCAL4, 20_001, 443, ACK);
        assert!(filter.check_at(&mut live, Direction::MeshToHost, live_at));

        let mut too_soon = tcp4(PEER4, LOCAL4, 50_000, 443, SYN);
        assert!(
            !filter.check_at(&mut too_soon, Direction::MeshToHost, live_at),
            "a connection silent for under an hour was evicted"
        );
        let day = start + Duration::from_secs(86_400);
        let mut fresh = tcp4(PEER4, LOCAL4, 50_001, 443, SYN);
        assert!(
            filter.check_at(&mut fresh, Direction::MeshToHost, day),
            "a day after {quota} connections went silent, the peer still cannot open a new one"
        );
        // Only the oldest silent connection (20,000) made room. The one that carried a packet
        // later (20,001) and every younger one are still admitted.
        let mut evicted = tcp4(PEER4, LOCAL4, 20_000, 443, ACK);
        assert!(!filter.check_at(&mut evicted, Direction::MeshToHost, day));
        for port in [20_001, 20_002, 20_000 + quota - 1] {
            let mut kept = tcp4(PEER4, LOCAL4, port, 443, ACK);
            assert!(
                filter.check_at(&mut kept, Direction::MeshToHost, day),
                "connection {port} was evicted too"
            );
        }
        let mut later = tcp4(PEER4, LOCAL4, 50_004, 443, SYN);
        assert!(
            filter.check_at(
                &mut later,
                Direction::MeshToHost,
                start + Duration::from_secs(4 * 86_400)
            ),
            "4 days after the connections went silent, the peer still cannot open a new one"
        );
    }

    /// A full direction still evicts an unestablished flow before any established
    /// connection, however long that connection has been silent (J721, #265).
    #[test]
    fn unestablished_flows_go_before_silent_established_ones() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::All, TrafficPolicy::None),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let start = Instant::now();
        let quota = u16::try_from(FLOWS_PER_DIRECTION).expect("quota");
        for index in 0..quota - 1 {
            let port = 20_000 + index;
            let mut syn = tcp4(PEER4, LOCAL4, port, 443, SYN);
            let mut syn_ack = tcp4(LOCAL4, PEER4, 443, port, SYN_ACK);
            let mut ack = tcp4(PEER4, LOCAL4, port, 443, ACK);
            assert!(filter.check_at(&mut syn, Direction::MeshToHost, start));
            assert!(filter.check_at(&mut syn_ack, Direction::HostToMesh, start));
            assert!(filter.check_at(&mut ack, Direction::MeshToHost, start));
        }
        // A UDP flow opened last, and seen more recently than every connection.
        let udp_at = start + Duration::from_hours(2);
        let mut udp = udp4(PEER4, LOCAL4, 5_353, 5_353);
        assert!(filter.check_at(&mut udp, Direction::MeshToHost, udp_at));
        let mut fresh = tcp4(PEER4, LOCAL4, 50_000, 443, SYN);
        assert!(filter.check_at(&mut fresh, Direction::MeshToHost, udp_at));
        let mut udp_again = udp4(LOCAL4, PEER4, 5_353, 5_353);
        assert!(
            !filter.check_at(&mut udp_again, Direction::HostToMesh, udp_at),
            "the unestablished UDP flow should have been evicted first"
        );
        let mut oldest = tcp4(PEER4, LOCAL4, 20_000, 443, ACK);
        assert!(filter.check_at(&mut oldest, Direction::MeshToHost, udp_at));
    }

    /// An IPv6 first fragment of a reply on an established outbound connection, whose
    /// fragmentable part starts with an 8-byte destination-options header: IPv6 | Fragment
    /// (next 60, offset 0, more) | Destination options (next TCP) | TCP ACK (20 bytes) | 4
    /// bytes of data. The judged headers end 28 bytes into the fragmentable part.
    fn ipv6_first_fragment_behind_destination_options(identification: u32) -> Vec<u8> {
        let mut first = vec![0_u8; 40 + 8 + 32];
        first[0] = 0x60;
        first[4..6].copy_from_slice(&40_u16.to_be_bytes());
        first[6] = 44;
        first[7] = 64;
        first[8..24].copy_from_slice(&PEER6.octets());
        first[24..40].copy_from_slice(&LOCAL6.octets());
        first[40] = 60;
        first[42..44].copy_from_slice(&1_u16.to_be_bytes());
        first[44..48].copy_from_slice(&identification.to_be_bytes());
        first[48] = 6;
        first[50] = 1; // PadN, filling the header's 6 option bytes.
        first[51] = 4;
        first[56..58].copy_from_slice(&443_u16.to_be_bytes());
        first[58..60].copy_from_slice(&40_000_u16.to_be_bytes());
        first[68] = 0x50;
        first[69] = ACK;
        first
    }

    /// A later IPv6 fragment of `first` at `offset` bytes into the fragmentable part, with 16
    /// bytes of payload whose byte 5 is a SYN flag (where TCP's flags sit if it starts at 16).
    fn ipv6_later_fragment(first: &[u8], offset: u16) -> Vec<u8> {
        let mut later = vec![0_u8; 40 + 8 + 16];
        later[..40].copy_from_slice(&first[..40]);
        later[4..6].copy_from_slice(&24_u16.to_be_bytes());
        later[40] = 60;
        later[42..44].copy_from_slice(&((offset / 8) << 3).to_be_bytes());
        later[44..48].copy_from_slice(&first[44..48]);
        later[48 + 5] = SYN;
        later
    }

    /// The overlap guard covers every header the filter judged, IPv6 extension headers
    /// included (J718 P3, #265; J718's red test). When a destination-options header comes
    /// before TCP, a later fragment's next header is 60, not TCP, so the parser's stateless
    /// TCP check never runs. A later fragment at offset 16 would overwrite the TCP flags, at
    /// byte 21, after they were judged. It is refused. One that starts past the headers, at
    /// offset 32, still passes.
    #[test]
    fn ipv6_later_fragments_cannot_overlap_headers_behind_destination_options() {
        let filter = PacketFilter::new(
            &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
            MeshProxyIngress::default(),
        )
        .expect("compile policy");
        let now = Instant::now();
        let mut open6 = tcp6(LOCAL6, PEER6, 40_000, 443, SYN);
        let mut accept6 = tcp6(PEER6, LOCAL6, 443, 40_000, SYN_ACK);
        let mut ack6 = tcp6(LOCAL6, PEER6, 40_000, 443, ACK);
        assert!(filter.check_at(&mut open6, Direction::HostToMesh, now));
        assert!(filter.check_at(&mut accept6, Direction::MeshToHost, now));
        assert!(filter.check_at(&mut ack6, Direction::HostToMesh, now));

        let mut first = ipv6_first_fragment_behind_destination_options(21);
        let mut overlapping = ipv6_later_fragment(&first, 16);
        let mut following = ipv6_later_fragment(&first, 32);
        assert!(filter.check_at(&mut first, Direction::MeshToHost, now));
        assert!(
            !filter.check_at(&mut overlapping, Direction::MeshToHost, now),
            "a later fragment overlapping the TCP flags behind destination options was admitted"
        );
        assert!(
            filter.check_at(&mut following, Direction::MeshToHost, now),
            "a later fragment past the judged headers was refused"
        );
    }
}
