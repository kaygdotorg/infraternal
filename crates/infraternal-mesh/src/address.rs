//! Stable dual-stack allocation and explicit route-conflict reporting (D165).
use crate::model::{Addresses, MeshError, MeshSettings, NodeId};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// A discovered route supplied by the host; the coordinator never probes or modifies host routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub network: IpAddr,
    pub prefix: u8,
}
impl Route {
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

/// Returns every conflicting input route, including default routes, without changing settings.
/// # Errors
/// Rejects invalid deployment settings or noncanonical input routes.
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

fn ula(global: [u8; 5], offset: u64) -> Ipv6Addr {
    let mut bytes = [0; 16];
    bytes[0] = 0xfd;
    bytes[1..6].copy_from_slice(&global);
    bytes[8..].copy_from_slice(&offset.to_be_bytes());
    Ipv6Addr::from(bytes)
}

/// Monotonic allocation never recycles an address, even after removal, within this coordinator.
/// Slice 2 must persist this state with membership; reconstructing from sorted nodes is not stable.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "AllocationState")]
pub struct AddressAllocator {
    settings: MeshSettings,
    next: u64,
    assigned: BTreeMap<NodeId, Addresses>,
}
impl AddressAllocator {
    /// # Errors
    /// Rejects invalid settings/routes and reports overlapping deployment ranges.
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
    /// # Errors
    /// Returns `AddressExhausted` without mutation when the range is full.
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
    pub fn remove(&mut self, node: NodeId) {
        self.assigned.remove(&node);
    }
    #[must_use]
    pub fn get(&self, node: NodeId) -> Option<Addresses> {
        self.assigned.get(&node).copied()
    }
}

/// Serialized allocation checkpoint; restore validates addresses and the monotonic high-water mark.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AllocationState {
    pub settings: MeshSettings,
    pub next: u64,
    pub assigned: BTreeMap<NodeId, Addresses>,
}
impl TryFrom<AllocationState> for AddressAllocator {
    type Error = MeshError;
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
    #[must_use]
    pub fn settings(&self) -> &MeshSettings {
        &self.settings
    }
    #[must_use]
    pub fn assigned_count(&self) -> usize {
        self.assigned.len()
    }
}
