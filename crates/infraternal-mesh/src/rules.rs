//! Arrow grants and stateful initiation filters; transport routing alone never grants access.
use crate::model::{MeshError, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuleId(pub u64);

/// User endpoints are represented for API compatibility, but rejected in stage 1 (D164).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Endpoint {
    Node(NodeId),
    Tag(String),
    User(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Port {
    pub protocol: Protocol,
    pub number: u16,
}

/// Union of grants. None denies new connections; established replies are a separate backend invariant.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficPolicy {
    #[default]
    None,
    All,
    Ports(BTreeSet<Port>),
}
impl TrafficPolicy {
    /// # Errors
    /// Rejects empty policies, empty port lists, and port zero.
    pub fn validate_grant(&self) -> Result<(), MeshError> {
        match self {
            Self::All => Ok(()),
            Self::Ports(ports) if !ports.is_empty() && ports.iter().all(|p| p.number > 0) => Ok(()),
            _ => Err(MeshError::InvalidPorts),
        }
    }
    /// Merge another policy as a grant union; an empty policy adds no permission.
    pub fn union(&mut self, other: &Self) {
        match (&mut *self, other) {
            (_, Self::None) | (Self::All, _) => {}
            (target, Self::All) => *target = Self::All,
            (Self::Ports(target), Self::Ports(ports)) => target.extend(ports),
            (target @ Self::None, Self::Ports(ports)) => *target = Self::Ports(ports.clone()),
        }
    }
    #[must_use]
    pub fn allows(&self, port: Port) -> bool {
        match self {
            Self::None => false,
            Self::All => true,
            Self::Ports(ports) => ports.contains(&port),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arrow {
    pub id: RuleId,
    pub from: Endpoint,
    pub to: Endpoint,
    pub both_ways: bool,
    #[serde(default = "all_ports")]
    pub ports: TrafficPolicy,
}
impl Arrow {
    /// # Errors
    /// Rejects user endpoints in stage 1 and invalid port grants.
    pub fn validate(&self) -> Result<(), MeshError> {
        if matches!(self.from, Endpoint::User(_)) || matches!(self.to, Endpoint::User(_)) {
            return Err(MeshError::UserEndpoint);
        }
        self.ports.validate_grant()
    }
}

// Arrow creation grants all services by default; compiled filters still default to None.
const fn all_ports() -> TrafficPolicy {
    TrafficPolicy::All
}
