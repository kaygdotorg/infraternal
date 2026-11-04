//! Address allocation for the mesh (D165): every node gets one IPv4 and one
//! IPv6 address that stay the same for as long as the node is a member.
//!
//! IPv4 addresses come from the deployment's configured range (by default
//! `10.254.0.0/16`) and are handed out in order, starting at the first host
//! address. IPv6 addresses live in a unique-local `/48` built from the
//! deployment's random 40-bit global ID; the last 64 bits of a node's IPv6
//! address are its IPv4 offset, so the two addresses always pair up.
//!
//! This module also checks the deployment ranges against the routes the host
//! already has ([`conflicts`]). It only reports overlaps. Choosing a different
//! range is the caller's decision.
use crate::model::{Addresses, MeshError, MeshSettings, NodeId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// A route that already exists on the host, handed to this crate by the caller.
///
/// The crate never reads or changes the host's routing table itself. Pass the
/// routes you found to [`conflicts`] or [`AddressAllocator::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// First address of the route. It must be canonical: no bits set below
    /// the prefix.
    pub network: IpAddr,
    /// Prefix length in bits: 0 to 32 for IPv4, 0 to 128 for IPv6. A prefix
    /// of 0 is a default route.
    pub prefix: u8,
}
impl Route {
    /// First and last address of the route, as integers, both inclusive.
    ///
    /// # Errors
    /// Returns `InvalidRoute` if the prefix is longer than the address
    /// family allows or if `network` has bits set below the prefix.
    fn bounds(self) -> Result<(u128, u128), MeshError> {
        let (number, width) = match self.network {
            IpAddr::V4(ip) => (u128::from(u32::from(ip)), 32),
            IpAddr::V6(ip) => (u128::from(ip), 128),
        };
        if u32::from(self.prefix) > width {
            return Err(MeshError::InvalidRoute);
        }
        let host_mask = u128::MAX
            .checked_shr(128 - (width - u32::from(self.prefix)))
            .unwrap_or(0);
        if number & host_mask != 0 {
            return Err(MeshError::InvalidRoute);
        }
        Ok((number, number | host_mask))
    }
}

/// Returns the routes that overlap the deployment's address ranges.
///
/// IPv4 routes are compared with the configured IPv4 range, IPv6 routes with
/// the deployment's unique-local `/48`. Any overlap counts, so a default route
/// (`0.0.0.0/0` or `::/0`) always conflicts. The input order is kept. An empty
/// result means the ranges are free to use. Nothing is changed.
///
/// # Errors
/// Rejects invalid deployment settings and noncanonical input routes.
pub fn conflicts(settings: &MeshSettings, routes: &[Route]) -> Result<Vec<Route>, MeshError> {
    settings.validate()?;
    let v4 = Route {
        network: settings.ipv4.network.into(),
        prefix: settings.ipv4.prefix,
    }
    .bounds()?;
    let v6 = Route {
        network: ula(settings.ula_global_id, 0).into(),
        prefix: 48,
    }
    .bounds()?;
    let mut result = Vec::new();
    for route in routes {
        let bounds = route.bounds()?;
        let deployment = if route.network.is_ipv4() { v4 } else { v6 };
        if bounds.0 <= deployment.1 && deployment.0 <= bounds.1 {
            result.push(*route);
        }
    }
    Ok(result)
}

/// Builds the IPv6 address `fd<global id>:0:0:0:<offset>`: the unique-local
/// `/48` of the deployment with the node's offset in the last 64 bits.
fn ula(global: [u8; 5], offset: u64) -> Ipv6Addr {
    let mut bytes = [0; 16];
    bytes[0] = 0xfd;
    bytes[1..6].copy_from_slice(&global);
    bytes[8..].copy_from_slice(&offset.to_be_bytes());
    Ipv6Addr::from(bytes)
}

/// Hands out one IPv4/IPv6 address pair per node, in increasing order.
///
/// An address is never given out twice, even after the node that held it was
/// removed, so a stale peer entry can never point at a different machine.
/// Because of that, the allocator's counter must be saved together with the
/// membership (it serializes as [`AllocationState`]). Rebuilding it by walking
/// the current nodes would forget removed addresses and hand them out again.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "AllocationState")]
pub struct AddressAllocator {
    settings: MeshSettings,
    next: u64,
    assigned: BTreeMap<NodeId, Addresses>,
}
impl AddressAllocator {
    /// Creates an empty allocator for `settings`.
    ///
    /// `routes` are the host's existing routes (see [`conflicts`]).
    ///
    /// # Errors
    /// Rejects invalid settings or routes, and returns `RouteOverlap` if any
    /// route overlaps the deployment ranges.
    pub fn new(settings: MeshSettings, routes: &[Route]) -> Result<Self, MeshError> {
        if !conflicts(&settings, routes)?.is_empty() {
            return Err(MeshError::RouteOverlap);
        }
        Ok(Self {
            settings,
            next: 1,
            assigned: BTreeMap::new(),
        })
    }
    /// Returns the addresses of `node`, assigning the next free pair if it has
    /// none yet. Calling it again for the same node returns the same pair.
    ///
    /// # Errors
    /// Returns `AddressExhausted` when the IPv4 range is full. Nothing is
    /// changed in that case.
    pub fn allocate(&mut self, node: NodeId) -> Result<Addresses, MeshError> {
        if let Some(addresses) = self.assigned.get(&node) {
            return Ok(*addresses);
        }
        if self.next > self.settings.ipv4.capacity() {
            return Err(MeshError::AddressExhausted);
        }
        let offset = u32::try_from(self.next).map_err(|_| MeshError::AddressExhausted)?;
        let addresses = Addresses {
            ipv4: Ipv4Addr::from(u32::from(self.settings.ipv4.network) + offset),
            ipv6: ula(self.settings.ula_global_id, self.next),
        };
        self.next += 1;
        self.assigned.insert(node, addresses);
        Ok(addresses)
    }
    /// Forgets which addresses `node` held. Unknown nodes are ignored.
    ///
    /// The addresses are not reused: the counter only ever moves forward.
    pub fn remove(&mut self, node: NodeId) {
        self.assigned.remove(&node);
    }
    /// The addresses currently assigned to `node`, if any.
    #[must_use]
    pub fn get(&self, node: NodeId) -> Option<Addresses> {
        self.assigned.get(&node).copied()
    }
}

/// The saved form of an [`AddressAllocator`].
///
/// Converting it back into an allocator (`try_from`) re-checks everything, so
/// a damaged or hand-edited checkpoint is rejected instead of trusted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AllocationState {
    /// The deployment settings the addresses were allocated under.
    pub settings: MeshSettings,
    /// The offset the next new node will receive. It is one past the highest
    /// offset ever handed out and only grows.
    pub next: u64,
    /// The addresses of the nodes that are currently members.
    pub assigned: BTreeMap<NodeId, Addresses>,
}
impl TryFrom<AllocationState> for AddressAllocator {
    type Error = MeshError;
    /// Restores an allocator from a checkpoint.
    ///
    /// # Errors
    /// Returns `InvalidAllocation` unless the counter is within the range and
    /// every assigned pair is inside the IPv4 range, below the counter, unique,
    /// and matches the IPv6 address derived from the same offset. Invalid
    /// settings are rejected with their own error.
    fn try_from(state: AllocationState) -> Result<Self, Self::Error> {
        state.settings.validate()?;
        if state.next == 0 || state.next > state.settings.ipv4.capacity() + 1 {
            return Err(MeshError::InvalidAllocation);
        }
        let mut offsets = BTreeSet::new();
        for addresses in state.assigned.values() {
            let offset = u32::from(addresses.ipv4)
                .checked_sub(u32::from(state.settings.ipv4.network))
                .ok_or(MeshError::InvalidAllocation)?;
            if offset == 0
                || u64::from(offset) >= state.next
                || !offsets.insert(offset)
                || addresses.ipv6 != ula(state.settings.ula_global_id, u64::from(offset))
            {
                return Err(MeshError::InvalidAllocation);
            }
        }
        Ok(Self {
            settings: state.settings,
            next: state.next,
            assigned: state.assigned,
        })
    }
}
impl AddressAllocator {
    /// The deployment settings this allocator was created with.
    #[must_use]
    pub fn settings(&self) -> &MeshSettings {
        &self.settings
    }
    /// How many nodes currently hold an address pair.
    #[must_use]
    pub fn assigned_count(&self) -> usize {
        self.assigned.len()
    }
}
