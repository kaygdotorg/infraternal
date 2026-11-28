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
//! - **Memory:** about 0.1 KB per configured peer, plus the peer's fixed tables once it has
//!   flows. The flow table is 512 slots of 104 bytes: 53,248 bytes, 52 KiB. The fragment table
//!   (64 slots of 104 bytes and 64 coverage records of 134 bytes: 15,232 bytes, about 15 KiB)
//!   is allocated separately, the first time the peer fragments. All of a peer's state is
//!   68,672 bytes (67 KiB, or 68.7 kB in decimal units): both tables plus 192 bytes of cell and
//!   policy entry, as `flow_table_memory_per_peer_times_one_thousand_peers` prints. It must
//!   fit the 72 KiB budget ([`PER_PEER_MEMORY_BUDGET`], checked at build time). At D393's design scale of
//!   1,000 peers with 10 of them active, the filter adds under 1 MiB.
//!   - **Measured (J750, #265):** all 4,096 of D393's tested peers active with one flow each
//!     added 214,396 KiB, 209 MiB (about 52 KiB per peer: the first flow writes the whole flow
//!     table, and no fragment table exists yet).
//!   - **Bound:** at most 288 MiB, the 72 KiB budget times 4,096 peers, with every peer's flow
//!     table and fragment table in use (68,672 bytes each, 268 MiB, for the current sizes). No
//!     path can exceed it: each authenticated peer in the policy gets at most one flow table
//!     and one fragment table, and only after a grant check passes.
//!
//!   Compiling a policy allocates no tables, so publishing never doubles memory.
//! - **Freeing:** a table is freed only by the sweep after a publish, when it is empty or its
//!   peer has left the policy. A peer that was busy once keeps its table, expired entries and
//!   all, until the next publish finds it empty.
//! - **Publishing** a policy swaps one pointer under the write lock, the only lock every packet
//!   waits behind, so that lock is held for the same short time at 4,096 peers as at 4. The flow
//!   tables live outside the policy, in [`PacketFilter::tables`], and survive the swap
//!   unchanged. The sweep that follows scans every active peer's table, so its own cost grows
//!   with the number of active peers, but it holds the `tables` lock only while it copies the
//!   list of cells. A packet that binds its peer's cell after the publish waits at most for that
//!   copy, never for the scan (J753, #265).

use crate::{
    dataplane::{Config, PeerPolicy},
    policy::{
        model::NodeId,
        rules::{Port, Protocol, TrafficPolicy},
    },
};
use infraternal_mesh::{networks::Network, proxy_ports::MeshProxyIngress};
use std::{
    collections::{BTreeMap, HashMap},
    hash::BuildHasher,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex, OnceLock, RwLock,
        atomic::{AtomicBool, Ordering},
    },
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
pub const REQUIRED_SYSCTLS: [(&str, i64); 2] = [
    ("net/ipv4/conf/all/accept_source_route", 0),
    ("net/ipv6/conf/all/accept_source_route", 0),
];

/// The required settings this host does not meet, as `name = value (want <= limit)` lines.
///
/// `read` returns a setting's current text, or `None` when it cannot be read (a missing IPv6
/// stack, a sandbox); unreadable settings are not reported. Values above the limit are reported.
#[cfg(any(test, target_os = "linux"))]
pub fn sysctl_gaps(read: impl Fn(&str) -> Option<String>) -> Vec<String> {
    REQUIRED_SYSCTLS
        .iter()
        .filter_map(|(name, limit)| {
            let value = read(name)?.trim().parse::<i64>().ok()?;
            (value > *limit)
                .then(|| format!("{} = {value} (want <= {limit})", name.replace('/', ".")))
        })
        .collect()
}

/// A packet's position relative to this host and its mesh peers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
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
/// bytes per peer, 66.5 KiB) with a little room, so raising the flow quota does not grow the
/// filter.
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
/// The post-publish sweep holds `tables` only to copy the list of cells, then releases it and
/// only `try_lock`s peer tables, so a packet never waits for the scan (J753, #265).
pub struct PacketFilter {
    /// The published snapshot. A publish replaces the pointer and nothing else under the write
    /// lock, so that lock, which every packet waits behind, is held for the same short time at
    /// any peer count (J721, #265).
    policy: RwLock<Arc<CompiledPolicy>>,
    /// Each peer's flow cell, keyed by node, outside any one policy snapshot so that flows
    /// survive a publish without being copied. A peer gets an entry on its first packet. The
    /// sweep after each publish drops the entries of peers the new policy no longer has.
    tables: Mutex<BTreeMap<NodeId, Arc<PeerFlows>>>,
    /// Serialises publish, withdraw and their sweep, so a sweep never judges flows against a
    /// snapshot that a concurrent publish has already replaced.
    writer: Mutex<()>,
    /// Whether this node forwards for the networks it serves (D197 M3): set by the node only while
    /// the kernel table that forwards and masquerades them is in place. Shared with every published
    /// snapshot, so turning it off refuses forwarded packets at once, open flows included.
    forwarding: Arc<AtomicBool>,
    /// Test seam: called by the sweep just before it visits each peer's cell, so a test can
    /// pause the sweep part-way through and check what a packet can do meanwhile.
    #[cfg(test)]
    sweep_probe: Mutex<Option<Box<dyn Fn() + Send>>>,
}

/// One fully compiled snapshot that can be published after its related routes and peers succeed.
pub struct PreparedPolicy(CompiledPolicy);

impl PreparedPolicy {
    /// Leave these peers out of the snapshot before it is published, so their addresses admit
    /// nothing; see [`PacketFilter::withdraw_peers`]. Publishing the result also retires their
    /// open flows, because [`CompiledPolicy::allows_flow`] resolves a flow's peer by address.
    #[must_use]
    /// Drop these peers' addresses from this prepared snapshot before publishing it.
    ///
    /// Used when an earlier transaction fails mid-apply so the filter stops admitting removed or
    /// moved peers' packets while the previous snapshot is restored.
    #[cfg(target_os = "linux")]
    pub fn without_peers(mut self, withdrawn: &std::collections::BTreeSet<NodeId>) -> Self {
        self.0.withdraw(withdrawn);
        self
    }
}

impl PacketFilter {
    /// Build an empty, deny-by-default filter for a node that has not received its first snapshot.
    ///
    /// A peer's flow table is allocated once, when its first flow is admitted, and is never
    /// grown while packets are checked. If it cannot be allocated, that packet is dropped.
    #[must_use]
    pub fn empty() -> Self {
        Self::with_policy(CompiledPolicy::empty())
    }

    /// Compile one complete coordinator snapshot and proxy listener view.
    ///
    /// # Errors
    /// Refuses duplicate peer addresses or a policy snapshot that cannot be indexed in memory.
    pub fn new(config: &Config, proxy_ingress: MeshProxyIngress) -> io::Result<Self> {
        Ok(Self::with_policy(CompiledPolicy::compile(
            config,
            proxy_ingress,
        )?))
    }

    /// Attach one compiled snapshot before the filter reaches packet workers.
    fn with_policy(mut policy: CompiledPolicy) -> Self {
        let forwarding = Arc::new(AtomicBool::new(false));
        policy.forwarding = Arc::clone(&forwarding);
        Self {
            policy: RwLock::new(Arc::new(policy)),
            tables: Mutex::new(BTreeMap::new()),
            writer: Mutex::new(()),
            forwarding,
            #[cfg(test)]
            sweep_probe: Mutex::new(None),
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
    pub fn prepare_policy(
        config: &Config,
        proxy_ingress: MeshProxyIngress,
    ) -> io::Result<PreparedPolicy> {
        Ok(PreparedPolicy(CompiledPolicy::compile(
            config,
            proxy_ingress,
        )?))
    }

    /// Turn forwarding for this node's served networks on or off (D197 M3). The node turns it on
    /// only after the kernel table that forwards and masquerades them is installed, and off before
    /// that table goes; until then a packet for a served network is refused like any packet that
    /// is not for this node.
    #[cfg(any(target_os = "linux", test))]
    pub fn set_forwarding(&self, on: bool) {
        self.forwarding.store(on, Ordering::Release);
    }

    /// A prepared deny-all snapshot, published when a failed transaction cannot rebuild the
    /// previous one, so the packet path fails closed.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn deny_all_policy() -> PreparedPolicy {
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
    #[cfg(any(target_os = "linux", test))]
    pub fn withdraw_peers(&self, withdrawn: &std::collections::BTreeSet<NodeId>) {
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
    /// Under the write lock this only swaps the snapshot pointer, so the write lock holds
    /// packets for the same short time at 4,096 peers as at 4 (J721, #265; J718 measured
    /// 7.3 ms while every peer's table was copied and scanned under the lock). Revocation
    /// needs no scan under the lock either: every packet of a tracked flow is checked with
    /// [`CompiledPolicy::allows_flow`] against the snapshot it reads, so a revoked flow admits
    /// nothing after the swap. The sweep that follows frees revoked and expired slots outside
    /// the lock. It visits only peers that have a cell, and its time grows with them; packets
    /// do not wait for it (see [`Self::sweep`]). The old snapshot is dropped after the lock is
    /// released.
    pub fn publish_policy(&self, policy: PreparedPolicy) {
        let _writer = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut next = policy.0;
        next.forwarding = Arc::clone(&self.forwarding);
        let next = Arc::new(next);
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
    ///
    /// The `tables` lock is held only to drop removed peers and copy the remaining cell
    /// pointers into a list (J753, #265). The tables themselves are scanned from that list
    /// with the lock released. Every active peer's first packet after a publish takes
    /// `tables` to bind its cell (see [`Self::flows_for`]), so holding it through the scan
    /// made each of those packets wait for the whole sweep: J750 measured 3.6-13 ms (median)
    /// at 4,096 active peers. With the lock released, a packet waits at most for the copy, or
    /// for its own table while the sweep cleans that one table. Removed peers' cells are
    /// freed after the lock is released too. A cell created for a new peer after the copy is
    /// cleaned by the next sweep. Rejected: binding the new snapshot's cells before the swap,
    /// which adds O(peers) work to every publish for nothing the copy does not already give.
    fn sweep(&self, policy: &CompiledPolicy, now: Instant) {
        let (removed, cells) = {
            let mut tables = self
                .tables
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let removed: Vec<Arc<PeerFlows>> = tables
                .extract_if(.., |node, _| policy.peer_by_node(*node).is_none())
                .map(|(_, cell)| cell)
                .collect();
            let cells: Vec<Arc<PeerFlows>> = tables.values().cloned().collect();
            (removed, cells)
        };
        drop(removed);
        for cell in cells {
            #[cfg(test)]
            self.run_sweep_probe();
            let mut table = match cell.table.try_lock() {
                Ok(table) => table,
                Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => continue,
            };
            if let Some(shard) = table.as_mut() {
                shard.reclaim(now, policy);
                shard.remove_orphaned_fragments();
                if shard.is_empty() {
                    *table = None;
                }
            }
        }
    }

    /// The flow cell of `peer`, binding the snapshot's peer entry to it on the peer's first
    /// packet after a publish.
    ///
    /// The bound pointer is read without a lock on every later packet. Binding takes the
    /// `tables` lock once per peer per publish. A new cell is about 100 bytes; the 52 KiB flow
    /// table inside it is allocated, fallibly, only when a flow is admitted (see
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
    pub fn check(&self, packet: &mut [u8], direction: Direction) -> bool {
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

        let Some((peer_address, peer_index)) = policy.resolve(parsed.key, direction) else {
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

    /// Test seam: run the probe a test installed in [`Self::sweep_probe`], if any.
    #[cfg(test)]
    fn run_sweep_probe(&self) {
        if let Some(probe) = self
            .sweep_probe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            probe();
        }
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
    peer_addresses: HashMap<IpAddr, usize, FlowHashState>,
    peers: Vec<PeerAccess>,
    proxy_ingress: MeshProxyIngress,
    /// Every network behind a router peer that this node may reach (D197 M3), with that peer's
    /// index. The coordinator never approves overlapping networks, so an address matches one
    /// entry at most; a handful of entries are scanned, no prefix tree is needed.
    through: Vec<(Network, usize)>,
    /// The filter's forwarding switch ([`PacketFilter::set_forwarding`]), shared by every
    /// snapshot it publishes. A snapshot not yet published holds its own, which is off.
    forwarding: Arc<AtomicBool>,
}

/// Which grant governs a packet: an ordinary node-to-node packet, or one that crosses a router.
enum RouteAccess<'policy> {
    /// One end is this node and the other the peer's own mesh address: the peer's node grants,
    /// with the mesh SSH and proxy rules, decide.
    Host,
    /// A subnet route (D197 M3) grants this new flow: into a network behind the peer, or into a
    /// network this node serves for the peer. Only plain port grants apply.
    Routed(&'policy TrafficPolicy),
    /// A packet that crosses a router but may not start a flow: a reply that only tracked state
    /// admits, or traffic from a routed network, whose hosts are never mesh initiators.
    Denied,
}

impl CompiledPolicy {
    /// Build the empty snapshot used before this node receives coordinator policy.
    fn empty() -> Self {
        Self {
            local4: Ipv4Addr::UNSPECIFIED,
            local6: Ipv6Addr::UNSPECIFIED,
            node: crate::policy::model::NodeId(0),
            server: None,
            peer_addresses: HashMap::default(),
            peers: Vec::new(),
            proxy_ingress: MeshProxyIngress::default(),
            through: Vec::new(),
            forwarding: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Build direct address indexes from one complete coordinator and proxy snapshot.
    fn compile(config: &Config, proxy_ingress: MeshProxyIngress) -> io::Result<Self> {
        let mut peer_addresses = HashMap::default();
        peer_addresses
            .try_reserve(config.peers.len().saturating_mul(2))
            .map_err(|_| io::Error::other("mesh peer address index could not be allocated"))?;
        let mut peers = Vec::new();
        peers
            .try_reserve(config.peers.len())
            .map_err(|_| io::Error::other("mesh peer policy index could not be allocated"))?;
        let mut through = Vec::new();
        for (node, policy) in &config.peers {
            let index = peers.len();
            peers.push(PeerAccess::from_policy(*node, policy));
            for network in &policy.networks.through {
                if network.network.is_ipv4() && network.outbound != TrafficPolicy::None {
                    through.push((network.network, index));
                }
            }
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
            through,
            forwarding: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Drop these peers' addresses from the index, so packets from or to them match no peer.
    /// Only removes entries, so it never allocates and cannot fail.
    #[cfg(any(target_os = "linux", test))]
    fn withdraw(&mut self, withdrawn: &std::collections::BTreeSet<NodeId>) {
        if withdrawn.is_empty() {
            return;
        }
        let Self {
            peer_addresses,
            peers,
            through,
            ..
        } = self;
        peer_addresses.retain(|_, index| !withdrawn.contains(&peers[*index].node));
        through.retain(|(_, index)| !withdrawn.contains(&peers[*index].node));
    }

    /// Whether `address` is one of this node's own mesh addresses.
    fn is_local(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => address == self.local4,
            IpAddr::V6(address) => address == self.local6,
        }
    }

    /// Whether forwarding for served networks is on right now.
    fn forwarding(&self) -> bool {
        self.forwarding.load(Ordering::Acquire)
    }

    /// The peer a packet belongs to, and the address its flows are filed under.
    ///
    /// The address is always one of the peer's own mesh addresses, so tracked flows, fragments
    /// and related ICMP find the peer again through [`Self::peer_addresses`] and a withdrawn peer
    /// loses them all at once:
    /// - this node ↔ a peer's mesh address: that address, as before subnet routes;
    /// - this node ↔ a host in a network behind a router peer: the router's IPv4 mesh address
    ///   (routed networks are IPv4; the `WireGuard` allowed IPs prove the router sent the reply);
    /// - a peer ↔ a host in a network this node serves (forwarded): the peer's mesh address, and
    ///   only while forwarding is on and the peer may reach that network.
    ///
    /// Anything else (a packet between two foreign addresses, or from a network nobody routes)
    /// belongs to no peer and is refused.
    fn resolve(&self, key: FlowKey, direction: Direction) -> Option<(IpAddr, usize)> {
        if let Some(address) = self.peer_for_packet(key, direction) {
            if let Some(index) = self.peer_addresses.get(&address) {
                return Some((address, *index));
            }
            let index = self.router_for(address)?;
            return Some((IpAddr::V4(self.peers[index].ipv4), index));
        }
        if !self.forwarding() {
            return None;
        }
        let (peer_end, network_end) = match direction {
            Direction::MeshToHost => (key.source, key.destination),
            Direction::HostToMesh => (key.destination, key.source),
        };
        let index = *self.peer_addresses.get(&peer_end)?;
        self.peers[index]
            .served
            .iter()
            .any(|(network, _)| network.contains(network_end))
            .then_some((peer_end, index))
    }

    /// The router peer for an address inside one of the networks this node may reach.
    fn router_for(&self, address: IpAddr) -> Option<usize> {
        self.through
            .iter()
            .find(|(network, _)| network.contains(address))
            .map(|(_, index)| *index)
    }

    /// Which grant governs a flow with tuple `key` started in `direction` with `peer`.
    ///
    /// A routed packet never falls back to node grants: a host on a served network must not
    /// inherit what this node may start toward its peers, and a peer's grant to this node is
    /// not a grant to the networks behind it.
    fn route_access<'policy>(
        &'policy self,
        peer: &'policy PeerAccess,
        key: FlowKey,
        direction: Direction,
    ) -> RouteAccess<'policy> {
        match direction {
            Direction::MeshToHost if self.is_local(key.destination) => {
                if peer.owns(key.source) {
                    RouteAccess::Host
                } else {
                    // A reply from a network behind the peer: tracked state only.
                    RouteAccess::Denied
                }
            }
            Direction::MeshToHost => {
                if !self.forwarding() || !peer.owns(key.source) {
                    return RouteAccess::Denied;
                }
                peer.served
                    .iter()
                    .find(|(network, _)| network.contains(key.destination))
                    .map_or(RouteAccess::Denied, |(_, access)| {
                        RouteAccess::Routed(access)
                    })
            }
            Direction::HostToMesh if self.is_local(key.source) => {
                if peer.owns(key.destination) {
                    return RouteAccess::Host;
                }
                peer.through
                    .iter()
                    .find(|(network, _)| network.contains(key.destination))
                    .map_or(RouteAccess::Denied, |(_, access)| {
                        RouteAccess::Routed(access)
                    })
            }
            // From a served network toward a peer: replies only.
            Direction::HostToMesh => RouteAccess::Denied,
        }
    }

    /// A plain port grant for a routed flow, the same rule node flows follow without the mesh
    /// SSH and proxy exceptions: a TCP or UDP port must be granted, anything else needs `All`.
    fn routed_grant(access: &TrafficPolicy, key: FlowKey) -> Option<Grant> {
        let transport = transport_protocol(key.protocol);
        if let Some(protocol) = transport {
            return access
                .allows(Port {
                    protocol,
                    number: key.destination_port,
                })
                .then_some(Grant {
                    protocol: Some(protocol),
                    port: Some(key.destination_port),
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
        match self.route_access(peer, key, direction) {
            RouteAccess::Host => {}
            RouteAccess::Routed(access) => return Self::routed_grant(access, key),
            RouteAccess::Denied => return None,
        }
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
        // A routed flow is judged by the route grant that admitted it, against today's
        // networks: a revoked network or a withdrawn route ends it at once.
        match self.route_access(peer, entry.key, entry.initiated) {
            RouteAccess::Host => {}
            RouteAccess::Routed(access) => {
                return match (entry.grant.protocol, entry.grant.port) {
                    (Some(protocol), Some(number)) => access.allows(Port { protocol, number }),
                    _ => matches!(access, TrafficPolicy::All),
                };
            }
            RouteAccess::Denied => return false,
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
    /// The peer's own mesh addresses, to tell its packets from those of a network behind it.
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
    inbound: TrafficPolicy,
    outbound: TrafficPolicy,
    access_ssh: Option<bool>,
    /// Networks behind this peer that this node may start into, with the grant (D197 M3).
    through: Vec<(Network, TrafficPolicy)>,
    /// This node's networks that the peer may start into, with the grant (D197 M3).
    served: Vec<(Network, TrafficPolicy)>,
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
            ipv4: policy.peer.addresses.ipv4,
            ipv6: policy.peer.addresses.ipv6,
            inbound: policy.inbound.clone(),
            outbound: policy.outbound.clone(),
            access_ssh: policy.access_ssh,
            through: policy
                .networks
                .through
                .iter()
                .filter(|network| network.network.is_ipv4())
                .map(|network| (network.network, network.outbound.clone()))
                .collect(),
            served: policy
                .networks
                .served
                .iter()
                .filter(|network| network.network.is_ipv4())
                .map(|network| (network.network, network.inbound.clone()))
                .collect(),
            flows: OnceLock::new(),
        }
    }

    /// Whether `address` is one of the peer's own mesh addresses.
    fn owns(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => address == self.ipv4,
            IpAddr::V6(address) => address == self.ipv6,
        }
    }
}

/// One peer's flow state, kept across policy publishes.
///
/// The table stays `None` until the peer's first flow is admitted, and returns to `None` when
/// the sweep after a publish finds it empty. An idle peer therefore costs this cell (about
/// 100 bytes), not the 52 KiB flow table (J721, #265).
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Hash, PartialOrd, Ord))]
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

/// Hasher state for every per-packet table in this module (#260, J1226).
///
/// `foldhash::fast::RandomState` is seeded randomly per process. The slot of a tuple therefore
/// cannot be precomputed by a peer, which the previous `DefaultHasher::new()` (`SipHash` with fixed
/// zero keys) allowed: crafted tuples piled 256 flows onto one slot (mean probe 127.5 of 512,
/// against below 0.6 seeded; `flow_slot_collisions_stay_spread_under_a_crafted_search`). Never
/// swap in an unkeyed hasher here: the tuples are chosen by the peer.
type FlowHashState = foldhash::fast::RandomState;

/// The one process-wide seeded state shared by the flow and fragment slot functions.
fn flow_hash_state() -> &'static FlowHashState {
    static STATE: std::sync::OnceLock<FlowHashState> = std::sync::OnceLock::new();
    STATE.get_or_init(FlowHashState::default)
}

/// Index a tuple in either direction by summing the seeded endpoint hashes and protocol.
fn flow_start(key: FlowKey) -> usize {
    let state = flow_hash_state();
    let source = state.hash_one((key.source, key.source_port));
    let destination = state.hash_one((key.destination, key.destination_port));
    let sum = source
        .wrapping_add(destination)
        .wrapping_add(u64::from(key.protocol));
    // The commutative sum keeps replies in the same slot. Mix again so related endpoint
    // pairs do not keep the sum's additive structure in the slot index.
    usize::try_from(state.hash_one(sum) % FLOW_SLOTS_PER_PEER_HASH).unwrap_or_default()
}

/// Index one fragment identity inside its peer's fixed-size table.
fn fragment_start(key: FragmentKey, direction: Direction) -> usize {
    let tuple_hash = flow_hash_state().hash_one((key, direction));
    usize::try_from(tuple_hash % FRAGMENTS_PER_PEER_HASH).unwrap_or_default()
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
#[path = "packet_filter_tests.rs"]
/// The filter's unit tests, kept in `packet_filter_tests.rs` to stay under the per-file size
/// limit.
mod tests;

#[cfg(test)]
#[path = "packet_filter_hash_tests.rs"]
/// Regression test for the seeded flow-slot hash (#260, J1226).
mod hash_tests;
