//! Policy rules: who may start connections to whom, and on which ports.
//!
//! A rule is an [`Arrow`] between two endpoints. Being routable is never
//! enough to talk to a peer; only an arrow grants access, and it grants the
//! right to *start* connections. Replies on established connections are always
//! allowed.
use crate::model::{MeshError, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The identity of one [`Arrow`]. It must be unique among rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuleId(pub u64);

/// One side of an [`Arrow`].
///
/// `User` exists so the API shape is stable, but it is rejected in stage 1
/// (D164).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Endpoint {
    /// A single node.
    Node(NodeId),
    /// Every node that carries this tag.
    Tag(String),
    /// A person, by user id. Not accepted yet.
    User(u64),
}

/// The transport protocol of a port grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// A single service: a protocol and a port number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
// Port objects cross the action boundary directly; silently dropping a field
// would make the validated policy differ from the caller's request [40].
#[serde(deny_unknown_fields)]
pub struct Port {
    /// TCP or UDP.
    pub protocol: Protocol,
    /// The port number. Zero is not valid in a grant.
    pub number: u16,
}

/// Which new connections are allowed in one direction between two nodes. It
/// is the union of all grants that apply.
///
/// `None` denies new connections. Replies on established connections are a
/// separate guarantee that backends provide.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrafficPolicy {
    /// Nothing is allowed. This is the default.
    #[default]
    None,
    /// Every protocol and port is allowed.
    All,
    /// Only these ports are allowed.
    Ports(BTreeSet<Port>),
}
impl TrafficPolicy {
    /// Checks that this policy can be used as the ports of a new rule.
    ///
    /// # Errors
    /// Returns `InvalidPorts` for `None`, for an empty port list and for any
    /// port number of zero.
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
    /// Whether a new connection to `port` is allowed.
    #[must_use]
    pub fn allows(&self, port: Port) -> bool {
        match self {
            Self::None => false,
            Self::All => true,
            Self::Ports(ports) => ports.contains(&port),
        }
    }
}

/// A policy rule: `from` may start connections to `to`, on `ports`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Arrow {
    /// The identity of the rule.
    pub id: RuleId,
    /// The side that may start connections.
    pub from: Endpoint,
    /// The side that receives them.
    pub to: Endpoint,
    /// If `true`, `to` may also start connections to `from`, on the same ports.
    pub both_ways: bool,
    /// The services granted. When omitted in serialized input, all ports are
    /// granted.
    #[serde(default = "all_ports")]
    pub ports: TrafficPolicy,
}
impl Arrow {
    /// Checks that the rule can be accepted.
    ///
    /// # Errors
    /// Returns `UserEndpoint` if either side is a user (not supported in
    /// stage 1) and `InvalidPorts` if the port grant is invalid (see
    /// [`TrafficPolicy::validate_grant`]).
    pub fn validate(&self) -> Result<(), MeshError> {
        if matches!(self.from, Endpoint::User(_)) || matches!(self.to, Endpoint::User(_)) {
            return Err(MeshError::UserEndpoint);
        }
        self.ports.validate_grant()
    }
}

/// Default for [`Arrow::ports`] when a rule does not say: all services. This
/// is only the default for new rules; a node pair without any rule still gets
/// [`TrafficPolicy::None`].
const fn all_ports() -> TrafficPolicy {
    TrafficPolicy::All
}
