//! Public coordination types. Private key material has no coordination or serialization path.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};
use thiserror::Error;

/// Stable inventory identity, independent of key rotations and host names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeId(pub u64);

/// Public `WireGuard` key supplied by a node; this crate does not implement cryptography.
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
pub struct LocalPrivateKey([u8; 32]);
impl LocalPrivateKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn expose<T>(&self, local_device: impl FnOnce(&[u8; 32]) -> T) -> T {
        local_device(&self.0)
    }
}
impl fmt::Debug for LocalPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalPrivateKey([REDACTED])")
    }
}

/// Inventory facts needed by the coordinator. Only public keys cross this boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub public_key: PublicKey,
    pub host: String,
    pub tags: BTreeSet<String>,
}

/// Canonical IPv4 deployment range. Checked at the coordinator boundary, including deserialized input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4Range {
    pub network: Ipv4Addr,
    pub prefix: u8,
}
impl Ipv4Range {
    /// # Errors
    /// Rejects noncanonical ranges, invalid DNS labels, and zero rotation periods.
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
    #[must_use]
    pub fn capacity(self) -> u64 {
        1_u64
            .checked_shl(u32::from(32_u8.saturating_sub(self.prefix)))
            .unwrap_or(0)
            .saturating_sub(2)
    }
}

/// Persist this once per deployment. The caller supplies a randomly generated 40-bit ULA global ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshSettings {
    pub ipv4: Ipv4Range,
    pub ula_global_id: [u8; 5],
    pub dns_suffix: String,
    pub rotation_period_secs: u64,
}
impl MeshSettings {
    #[must_use]
    pub fn new(ula_global_id: [u8; 5]) -> Self {
        Self {
            ipv4: Ipv4Range {
                network: Ipv4Addr::new(10, 254, 0, 0),
                prefix: 16,
            },
            ula_global_id,
            dns_suffix: "internal".into(),
            rotation_period_secs: 7 * 24 * 3600,
        }
    }
    /// # Errors
    /// Rejects noncanonical ranges, invalid DNS labels, and zero rotation periods.
    pub fn validate(&self) -> Result<(), MeshError> {
        self.ipv4.validate()?;
        validate_dns(&self.dns_suffix, false)?;
        if self.rotation_period_secs == 0 {
            return Err(MeshError::InvalidRotationPeriod);
        }
        Ok(())
    }
}

/// Host routes only: subnet routes and exit nodes are outside stage 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Addresses {
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
}

/// Validation errors are safe to log: no error includes key material.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum MeshError {
    #[error("invalid or noncanonical IPv4 range (need at least two usable hosts)")]
    InvalidRange,
    #[error("invalid route prefix or noncanonical network")]
    InvalidRoute,
    #[error("deployment range overlaps routes in use")]
    RouteOverlap,
    #[error("invalid allocation checkpoint")]
    InvalidAllocation,
    #[error("rule version counter exhausted")]
    VersionExhausted,
    #[error("rotation overlap deadline exceeds the deployment clock")]
    ClockExhausted,
    #[error("invalid coordinator checkpoint")]
    InvalidCheckpoint,
    #[error("address range exhausted")]
    AddressExhausted,
    #[error("unknown node")]
    UnknownNode,
    #[error("node identity already exists")]
    DuplicateNode,
    #[error("public key already belongs to a node or an overlapping rotation")]
    DuplicateKey,
    #[error("invalid DNS name or suffix")]
    InvalidName,
    #[error("host name already exists")]
    DuplicateName,
    #[error("user endpoints arrive with devices in stage 2")]
    UserEndpoint,
    #[error("rule identity already exists")]
    DuplicateRule,
    #[error("unknown rule")]
    UnknownRule,
    #[error("port grants must be nonempty and use nonzero ports")]
    InvalidPorts,
    #[error("rotation period must be positive")]
    InvalidRotationPeriod,
    #[error("key rotation already in progress")]
    RotationInProgress,
    #[error("the server cannot be removed")]
    RemoveServer,
    #[error("diff version does not match the local view; request a snapshot")]
    StaleDiff,
}

/// Validate a mesh DNS host label or suffix using the coordinator's canonical rules.
/// # Errors
/// Rejects empty, oversized, non-ASCII, or noncanonical labels.
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
