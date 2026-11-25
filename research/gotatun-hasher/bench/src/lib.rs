//! Key shapes and table variants for the per-packet bookkeeping bench (#260, J1204).
//!
//! The shapes below are copies of what GotaTun's data path really hashes (see
//! `research/gotatun-hasher/README.md` for the call sites). They are copied, not imported, so the
//! bench builds without the product workspace. Each `*_start` / table type is one candidate;
//! the criterion bench in `benches/hot_paths.rs` times them all on the same key streams.

use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The conntrack tuple of the mesh packet filter (`FlowKey` in `packet_filter.rs`): the derived
/// `Hash` writes an enum discriminant, a length prefix and the octets for each address, which is
/// what makes SipHash expensive here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    /// Source address of the packet.
    pub source: IpAddr,
    /// Destination address of the packet.
    pub destination: IpAddr,
    /// Source port (or ICMP identifier).
    pub source_port: u16,
    /// Destination port.
    pub destination_port: u16,
    /// IP protocol number.
    pub protocol: u8,
}

impl FlowKey {
    /// The same tuple seen from the other end.
    pub fn reverse(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
            source_port: self.destination_port,
            destination_port: self.source_port,
            protocol: self.protocol,
        }
    }

    /// One direction-independent form, as the product does before hashing (derived `Ord`).
    pub fn canonical(self) -> Self {
        self.min(self.reverse())
    }
}

/// Slots in one peer's flow table (`FLOW_SLOTS_PER_PEER_HASH`), a power of two.
pub const FLOW_SLOTS: u64 = 512;

/// A small deterministic generator (xorshift64*), so every run sees the same key streams.
pub struct Rng(pub u64);

impl Rng {
    /// The next 64 random bits.
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// A mesh address as the coordinator hands them out: `10.254.0.0/16`, in order from `.1`.
pub fn mesh_v4(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(0x0AFE_0000 + 1 + n)
}

/// The IPv6 mesh address of peer `n` (unique-local prefix, host part counting up).
pub fn mesh_v6(n: u32) -> Ipv6Addr {
    Ipv6Addr::from(0xfd7a_115c_a1e0_0000_0000_0000_0000_0000u128 + 1 + u128::from(n))
}

/// `count` TCP flows towards one peer: this host (`.0`) to `peer`, sequential-ish ephemeral
/// source ports as a busy client produces them, and a handful of well-known server ports.
pub fn tcp_flows(count: usize, v6: bool, seed: u64) -> Vec<FlowKey> {
    let mut rng = Rng(seed | 1);
    let server_ports = [22u16, 80, 443, 5432, 8080, 9100];
    (0..count)
        .map(|i| {
            let (source, destination) = if v6 {
                (IpAddr::V6(mesh_v6(0)), IpAddr::V6(mesh_v6(1)))
            } else {
                (IpAddr::V4(mesh_v4(0)), IpAddr::V4(mesh_v4(1)))
            };
            FlowKey {
                source,
                destination,
                source_port: 32768 + (i as u16).wrapping_mul(2) + (rng.next() % 2) as u16,
                destination_port: server_ports[(rng.next() % server_ports.len() as u64) as usize],
                protocol: 6,
            }
        })
        .collect()
}

/// The current product function: `DefaultHasher::new()` (SipHash-1-3 with fixed zero keys) over
/// the canonical tuple, reduced modulo the slot count.
pub fn start_sip13_fixed(key: FlowKey) -> usize {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    key.canonical().hash(&mut h);
    (h.finish() % FLOW_SLOTS) as usize
}

/// Drop-in: the same canonical tuple and derived `Hash`, hashed by any `BuildHasher`.
pub fn start_with<S: BuildHasher>(state: &S, key: FlowKey) -> usize {
    (state.hash_one(key.canonical()) % FLOW_SLOTS) as usize
}

/// Drop-in without `canonical()`: hash each direction-ordered endpoint on its own and add the two
/// results, which is commutative, so both packet directions give the same slot with no `min`.
pub fn start_symmetric<S: BuildHasher>(state: &S, key: FlowKey) -> usize {
    let a = state.hash_one((key.source, key.source_port));
    let b = state.hash_one((key.destination, key.destination_port));
    let h = a.wrapping_add(b).wrapping_add(u64::from(key.protocol));
    ((h ^ (h >> 32)) % FLOW_SLOTS) as usize
}

/// No hasher at all: fold the tuple's raw words into 64 bits with two multiplies and a secret
/// (per-process random) multiplier. Symmetric in the two endpoints. IPv4 fast path, IPv6 folds
/// the 128-bit address halves.
pub fn start_manual(secret: u64, key: FlowKey) -> usize {
    #[inline(always)]
    fn fold(secret: u64, addr: IpAddr, port: u16) -> u64 {
        let (hi, lo) = match addr {
            IpAddr::V4(a) => (0u64, u64::from(u32::from(a))),
            IpAddr::V6(a) => {
                let v = u128::from(a);
                ((v >> 64) as u64, v as u64)
            }
        };
        let x = (hi ^ secret).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ lo ^ (u64::from(port) << 48);
        let p = u128::from(x) * u128::from(secret | 1);
        (p as u64) ^ ((p >> 64) as u64)
    }
    let h = fold(secret, key.source, key.source_port)
        .wrapping_add(fold(secret, key.destination, key.destination_port))
        .wrapping_add(u64::from(key.protocol));
    let p = u128::from(h) * u128::from(secret | 1);
    (((p as u64) ^ ((p >> 64) as u64)) % FLOW_SLOTS) as usize
}

/// A dense direct index for mesh IPv4 addresses: the coordinator hands addresses out in order
/// from the first host of one `/16`, so `address - base` indexes a flat array (no hashing, no
/// HashDoS: the index is bounded and nothing an attacker sends is ever inserted).
pub struct DirectV4 {
    /// Address of slot 0.
    base: u32,
    /// `u32::MAX` means "no peer".
    slots: Vec<u32>,
}

impl DirectV4 {
    /// Build from the peers' addresses and their peer index.
    pub fn new(peers: &[(Ipv4Addr, u32)]) -> Self {
        let base = peers.iter().map(|p| u32::from(p.0)).min().unwrap_or(0);
        let max = peers.iter().map(|p| u32::from(p.0)).max().unwrap_or(0);
        let mut slots = vec![u32::MAX; (max - base) as usize + 1];
        for (a, i) in peers {
            slots[(u32::from(*a) - base) as usize] = *i;
        }
        Self { base, slots }
    }

    /// The peer index for `address`, if any.
    #[inline]
    pub fn get(&self, address: Ipv4Addr) -> Option<u32> {
        let off = u32::from(address).wrapping_sub(self.base) as usize;
        match self.slots.get(off) {
            Some(&v) if v != u32::MAX => Some(v),
            _ => None,
        }
    }
}

/// Build a std `HashMap` with any `BuildHasher` holding `n` mesh peers by IPv4 address.
pub fn peer_map<S: BuildHasher + Default>(n: u32) -> std::collections::HashMap<IpAddr, usize, S> {
    (0..n).map(|i| (IpAddr::V4(mesh_v4(i + 1)), i as usize)).collect()
}

/// An identity hasher that returns the `u32`/`usize` it was given: the "no hash" ceiling for keys
/// that are already random. Only safe when an attacker cannot choose the keys that are stored.
#[derive(Default, Clone, Copy)]
pub struct IdentityHasher(u64);

impl Hasher for IdentityHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = (self.0 << 8) | u64::from(*b);
        }
    }
    fn write_u32(&mut self, v: u32) {
        self.0 = u64::from(v);
    }
    fn write_usize(&mut self, v: usize) {
        self.0 = v as u64;
    }
}

/// `BuildHasher` for [`IdentityHasher`].
#[derive(Default, Clone, Copy)]
pub struct IdentityState;

impl BuildHasher for IdentityState {
    type Hasher = IdentityHasher;
    fn build_hasher(&self) -> IdentityHasher {
        IdentityHasher(0)
    }
}

/// Probe-length statistics for a flow-table hash: fill `flows` into a 512-slot open-addressing
/// table the way `FlowShard::insert` does and report (mean, max) probe distance.
pub fn probe_stats(flows: &[FlowKey], start: impl Fn(FlowKey) -> usize) -> (f64, usize) {
    let mut taken = vec![false; FLOW_SLOTS as usize];
    let (mut sum, mut max) = (0usize, 0usize);
    for f in flows {
        let s = start(*f);
        let mut d = 0;
        while taken[(s + d) % FLOW_SLOTS as usize] {
            d += 1;
        }
        taken[(s + d) % FLOW_SLOTS as usize] = true;
        sum += d;
        max = max.max(d);
    }
    (sum as f64 / flows.len() as f64, max)
}
