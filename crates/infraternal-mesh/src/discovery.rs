//! Bounds peer-socket address observations by network generation and lifetime [196,228].
//!
//! Observations come from authenticated observers of the actual peer-traffic
//! socket. They are candidates, never proof of reachability. This module owns
//! no socket, timer or path selector; the runtime supplies monotonic time.

use crate::model::NodeId;
use std::{net::SocketAddr, time::Duration};

/// Per node, including both address families. Replacement never evicts a live observer.
pub const MAX_OBSERVATIONS: usize = 16;

/// Mapping evidence does not establish the NAT's inbound filtering behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingEvidence {
    Unknown,
    /// Distinct observer destinations saw the same mapping in this generation.
    Stable,
    /// Distinct observer destinations saw different mappings in this generation.
    DestinationDependent,
}

/// Public coordinates seen by one authenticated discovery destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub observer: NodeId,
    /// The actual destination of the probe, including its UDP port.
    pub destination: SocketAddr,
    /// The source address and port observed on that destination's socket.
    pub reflexive: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryError {
    StaleGeneration,
    ClockReversed,
    InvalidAddress,
    Full,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    observation: Observation,
    expires: Duration,
}

/// One peer-traffic socket's observations; a different socket needs its own book.
#[derive(Debug)]
pub struct Discovery {
    generation: u64,
    last_time: Duration,
    entries: Vec<Entry>,
}

impl Discovery {
    #[must_use]
    pub fn new(generation: u64) -> Self {
        Self {
            generation,
            last_time: Duration::ZERO,
            entries: Vec::new(),
        }
    }

    /// Retire all coordinates after rebinding or a network/socket change.
    /// # Errors
    /// Refuses a reused generation or a backwards monotonic clock.
    pub fn restart(&mut self, generation: u64, now: Duration) -> Result<(), DiscoveryError> {
        if generation <= self.generation {
            return Err(DiscoveryError::StaleGeneration);
        }
        self.advance(now)?;
        self.generation = generation;
        self.entries.clear();
        Ok(())
    }

    /// Record an authenticated response to a probe in the current generation.
    /// The caller correlates the response with its outstanding probe and socket.
    /// # Errors
    /// Refuses stale generations, unusable addresses, reversed time, zero or
    /// overflowing lifetimes, and growth beyond the per-socket observation bound.
    pub fn observe(
        &mut self,
        generation: u64,
        mut observation: Observation,
        now: Duration,
        lifetime: Duration,
    ) -> Result<(), DiscoveryError> {
        if generation != self.generation {
            return Err(DiscoveryError::StaleGeneration);
        }
        observation.destination = usable_address(observation.destination)?;
        observation.reflexive = usable_address(observation.reflexive)?;
        if observation.destination.is_ipv4() != observation.reflexive.is_ipv4()
            || lifetime.is_zero()
        {
            return Err(DiscoveryError::InvalidAddress);
        }
        let expires = now
            .checked_add(lifetime)
            .ok_or(DiscoveryError::InvalidAddress)?;
        self.advance(now)?;
        // Multiple destinations on one observer are useful: destination port
        // dependence must not be mistaken for an endpoint-independent mapping.
        let previous = self.entries.iter_mut().find(|entry| {
            entry.observation.observer == observation.observer
                && entry.observation.destination == observation.destination
        });
        if let Some(previous) = previous {
            *previous = Entry {
                observation,
                expires,
            };
        } else {
            if self.entries.len() == MAX_OBSERVATIONS {
                return Err(DiscoveryError::Full);
            }
            self.entries.push(Entry {
                observation,
                expires,
            });
        }
        Ok(())
    }

    /// Read live candidates only; IPv4 and IPv6 evidence are independent.
    /// # Errors
    /// Refuses a backwards clock rather than making expired observations live again.
    pub fn observations(&mut self, now: Duration) -> Result<Vec<Observation>, DiscoveryError> {
        self.advance(now)?;
        Ok(self.entries.iter().map(|entry| entry.observation).collect())
    }

    /// Infer only what distinct destinations observed in the requested family.
    /// Equal mappings are evidence, not proof of full-cone or filtering behaviour.
    /// # Errors
    /// Refuses a backwards monotonic clock.
    pub fn evidence(
        &mut self,
        ipv6: bool,
        now: Duration,
    ) -> Result<MappingEvidence, DiscoveryError> {
        self.advance(now)?;
        let mut stable = false;
        for (index, first) in self.entries.iter().enumerate() {
            if first.observation.reflexive.is_ipv6() != ipv6 {
                continue;
            }
            for second in &self.entries[index + 1..] {
                if second.observation.reflexive.is_ipv6() != ipv6
                    || first.observation.destination == second.observation.destination
                {
                    continue;
                }
                if first.observation.reflexive != second.observation.reflexive {
                    return Ok(MappingEvidence::DestinationDependent);
                }
                stable = true;
            }
        }
        Ok(if stable {
            MappingEvidence::Stable
        } else {
            MappingEvidence::Unknown
        })
    }

    fn advance(&mut self, now: Duration) -> Result<(), DiscoveryError> {
        if now < self.last_time {
            return Err(DiscoveryError::ClockReversed);
        }
        self.last_time = now;
        self.entries.retain(|entry| entry.expires > now);
        Ok(())
    }
}

/// Canonical transferable address; local interface scopes cannot cross nodes.
/// Private unicast addresses remain candidates for peers on the same network.
/// # Errors
/// Refuses zero ports, unspecified, loopback, multicast, broadcast and scoped addresses.
pub fn usable_address(address: SocketAddr) -> Result<SocketAddr, DiscoveryError> {
    if address.port() == 0 {
        return Err(DiscoveryError::InvalidAddress);
    }
    let address = match address {
        SocketAddr::V6(address) => {
            if address.scope_id() != 0 || address.ip().is_unicast_link_local() {
                return Err(DiscoveryError::InvalidAddress);
            }
            address.ip().to_ipv4_mapped().map_or_else(
                || SocketAddr::new((*address.ip()).into(), address.port()),
                |ip| SocketAddr::new(ip.into(), address.port()),
            )
        }
        address @ SocketAddr::V4(_) => address,
    };
    let ip = address.ip();
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || matches!(ip, std::net::IpAddr::V4(ip) if ip.is_broadcast() || ip.is_link_local() || ip.octets()[0] == 0)
    {
        return Err(DiscoveryError::InvalidAddress);
    }
    Ok(address)
}
