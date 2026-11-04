//! The plain data types the mesh is built from: node identities, public keys,
//! deployment settings, host addresses and the error type.
//!
//! Everything here can be serialized except [`LocalPrivateKey`], which stays on
//! the node that owns it. Private key material has no path into coordination
//! messages or checkpoints.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};
use thiserror::Error;

/// A node's identity inside the mesh. It stays the same across key rotations
/// and host renames. Only the trusted server inventory hands these out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeId(pub u64);

/// The 32-byte public `WireGuard` key of a node. This crate only stores and
/// compares keys; it does no cryptography.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

/// Node-side key only: deliberately neither serializable nor cloneable.
///
/// ```compile_fail
/// use infraternal_mesh::model::LocalPrivateKey;
/// let local = LocalPrivateKey::new([0; 32]);
/// serde_json::to_string(&local); // No serialization implementation exists.
/// ```
/// Backend implementations borrow its bytes only at the local device boundary.
/// Its `Debug` output is redacted, so logging it is safe.
pub struct LocalPrivateKey([u8; 32]);
impl LocalPrivateKey {
    /// Wraps the 32 private key bytes of this node.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Lends the key bytes to `local_device` for the duration of the call and
    /// returns whatever it returns. Use it only where the key goes into the
    /// local device configuration; do not copy the bytes elsewhere.
    pub fn expose<T>(&self, local_device: impl FnOnce(&[u8; 32]) -> T) -> T {
        local_device(&self.0)
    }
}
impl fmt::Debug for LocalPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalPrivateKey([REDACTED])")
    }
}

/// What the coordinator knows about one node: who it is and how to reach and
/// address it. Only public keys cross this boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// The node's stable identity.
    pub id: NodeId,
    /// The node's current public key.
    pub public_key: PublicKey,
    /// The host name, used as the first label of the node's DNS name. Must be
    /// a single valid DNS label (see [`validate_dns`]) and unique in the mesh.
    pub host: String,
    /// Labels that policy rules can target. Set by the trusted inventory, never
    /// by the node itself.
    pub tags: BTreeSet<String>,
}

/// The IPv4 network the mesh hands addresses out of, such as `10.254.0.0/16`.
/// It is checked at the coordinator boundary, including when deserialized.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4Range {
    /// First address of the range. Must be canonical: no bits set below the
    /// prefix.
    pub network: Ipv4Addr,
    /// Prefix length in bits, at most 30 so the range has two or more usable
    /// hosts.
    pub prefix: u8,
}
impl Ipv4Range {
    /// Checks the range is usable.
    ///
    /// # Errors
    /// Returns `InvalidRange` if the prefix is longer than 30 or if `network`
    /// has bits set below the prefix.
    pub fn validate(self) -> Result<(), MeshError> {
        if self.prefix > 30 {
            return Err(MeshError::InvalidRange);
        }
        let mask = u32::MAX
            .checked_shl(u32::from(32 - self.prefix))
            .unwrap_or(0);
        if u32::from(self.network) & !mask != 0 {
            return Err(MeshError::InvalidRange);
        }
        Ok(())
    }
    /// How many node addresses fit: all addresses in the range except the
    /// network and broadcast addresses.
    #[must_use]
    pub fn capacity(self) -> u64 {
        1_u64
            .checked_shl(u32::from(32_u8.saturating_sub(self.prefix)))
            .unwrap_or(0)
            .saturating_sub(2)
    }
}

/// Deployment-wide mesh settings.
///
/// Create them once per deployment and save them. The caller supplies a randomly
/// generated 40-bit unique-local IPv6 global ID; generating a new one later
/// changes every node's IPv6 address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshSettings {
    /// The IPv4 range node addresses come from.
    pub ipv4: Ipv4Range,
    /// The random 40-bit global ID of the deployment's unique-local IPv6 `/48`.
    pub ula_global_id: [u8; 5],
    /// The DNS suffix of mesh names: a node `web` is reachable as
    /// `web.<dns_suffix>`.
    pub dns_suffix: String,
    /// Distinguishes a user-selected suffix from the legacy `internal` default.
    #[serde(default)]
    pub dns_suffix_is_explicit: bool,
    /// How often node keys rotate, in seconds. Must be above zero.
    pub rotation_period_secs: u64,
}
impl MeshSettings {
    /// Default settings for a new deployment: range `10.254.0.0/16`, DNS suffix
    /// `internal` (not explicit), and a rotation period of seven days.
    #[must_use]
    pub fn new(ula_global_id: [u8; 5]) -> Self {
        Self {
            ipv4: Ipv4Range {
                network: Ipv4Addr::new(10, 254, 0, 0),
                prefix: 16,
            },
            ula_global_id,
            dns_suffix: "internal".into(),
            dns_suffix_is_explicit: false,
            rotation_period_secs: 7 * 24 * 3600,
        }
    }
    /// Checks every setting.
    ///
    /// # Errors
    /// Rejects a bad IPv4 range, a DNS suffix that is not valid, and a rotation
    /// period of zero.
    pub fn validate(&self) -> Result<(), MeshError> {
        self.ipv4.validate()?;
        validate_dns(&self.dns_suffix, false)?;
        if self.rotation_period_secs == 0 {
            return Err(MeshError::InvalidRotationPeriod);
        }
        Ok(())
    }
}

/// The address pair of one node. These become host routes (`/32` and `/128`)
/// on its peers. Subnet routes and exit nodes are outside stage 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Addresses {
    /// The node's IPv4 address inside the deployment range.
    pub ipv4: Ipv4Addr,
    /// The node's IPv6 address inside the deployment's unique-local `/48`.
    pub ipv6: Ipv6Addr,
}

/// Everything that can go wrong in mesh coordination. Messages are safe to
/// log: no error includes key material.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum MeshError {
    /// The IPv4 range is not canonical or is too small.
    #[error("invalid or noncanonical IPv4 range (need at least two usable hosts)")]
    InvalidRange,
    /// A host route has an impossible prefix or has host bits set.
    #[error("invalid route prefix or noncanonical network")]
    InvalidRoute,
    /// The deployment range overlaps a route the host already uses.
    #[error("deployment range overlaps routes in use")]
    RouteOverlap,
    /// A saved address allocation failed its consistency checks.
    #[error("invalid allocation checkpoint")]
    InvalidAllocation,
    /// The policy version counter reached its maximum.
    #[error("rule version counter exhausted")]
    VersionExhausted,
    /// A key rotation overlap would end past the largest representable time.
    #[error("rotation overlap deadline exceeds the deployment clock")]
    ClockExhausted,
    /// A saved coordinator state failed its consistency checks.
    #[error("invalid coordinator checkpoint")]
    InvalidCheckpoint,
    /// Every address in the IPv4 range has been handed out.
    #[error("address range exhausted")]
    AddressExhausted,
    /// No node with that identity is a member.
    #[error("unknown node")]
    UnknownNode,
    /// A node with that identity is already a member.
    #[error("node identity already exists")]
    DuplicateNode,
    /// The public key is already used by a node or by a rotation in progress.
    #[error("public key already belongs to a node or an overlapping rotation")]
    DuplicateKey,
    /// A host name or DNS suffix breaks the naming rules (see [`validate_dns`]).
    #[error("invalid DNS name or suffix")]
    InvalidName,
    /// Another node already uses that host name.
    #[error("host name already exists")]
    DuplicateName,
    /// A rule names a user, which is not supported before stage 2.
    #[error("user endpoints arrive with devices in stage 2")]
    UserEndpoint,
    /// A rule with that identity already exists.
    #[error("rule identity already exists")]
    DuplicateRule,
    /// No rule with that identity exists.
    #[error("unknown rule")]
    UnknownRule,
    /// A port grant is empty or contains port zero.
    #[error("port grants must be nonempty and use nonzero ports")]
    InvalidPorts,
    /// The key rotation period is zero.
    #[error("rotation period must be positive")]
    InvalidRotationPeriod,
    /// The node is already rotating its key.
    #[error("key rotation already in progress")]
    RotationInProgress,
    /// The server node is part of every mesh and cannot be removed.
    #[error("the server cannot be removed")]
    RemoveServer,
    /// A peer update does not continue the receiver's version. The receiver
    /// should ask for a fresh snapshot.
    #[error("diff version does not match the local view; request a snapshot")]
    StaleDiff,
}

/// Checks a mesh host name (`host` is `true`) or DNS suffix (`host` is `false`).
///
/// A value is made of labels separated by dots. Each label is 1 to 63
/// characters of lowercase ASCII letters, digits and hyphens, and neither
/// starts nor ends with a hyphen. The whole value is at most 253 bytes. A host
/// name is a single label, so it may not contain a dot. A suffix may have
/// several labels, such as `mesh.example`.
///
/// # Errors
/// Returns `InvalidName` for anything that breaks these rules, including
/// uppercase letters and non-ASCII characters.
pub fn validate_dns(value: &str, host: bool) -> Result<(), MeshError> {
    if value.is_empty() || value.len() > 253 || (host && value.contains('.')) {
        return Err(MeshError::InvalidName);
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(MeshError::InvalidName);
        }
    }
    Ok(())
}
