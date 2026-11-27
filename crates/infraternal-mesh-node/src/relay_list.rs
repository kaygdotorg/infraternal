//! Relay lists and role requests received over the authenticated coordinator link.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// The coordinator-to-node action that carries a [`RelayList`].
pub const ACTION: &str = "mesh.relays";
/// Most relays one list names. D402 Q9 keeps a node on at most four relays at once.
pub const MAX_RELAYS: usize = 8;
/// Most addresses one relay lists.
pub const MAX_ADDRESSES: usize = 4;
/// Most recent revoked hosts considered for a relay list. A revoked host past this many still
/// reaches nobody, because its peers dropped its mesh key (D166); older entries also age out
/// after the seven-day leaf lifetime. The encoder trims the oldest entries again when the
/// certificates make the action exceed its frame budget.
pub const MAX_REVOKED: usize = 128;
/// Largest relay leaf (certificate and key PEM) or CA root PEM accepted.
pub const MAX_PEM: usize = 3 * 1024;
/// Most CA roots a relay role accepts host leaves from.
pub const MAX_ROOTS: usize = 2;

/// What `mesh.relays` carries to one node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayList {
    /// The relays this node may use, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<RelayEntry>,
    /// Run the relay role (only in the server node's list in slice 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve: Option<ServeRelay>,
}

/// One relay a node may connect to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayEntry {
    /// The DNS name in the relay's leaf. The node verifies it and binds pair tokens to it.
    pub name: String,
    /// The relay's UDP port.
    pub port: u16,
    /// Addresses to dial, in order. Empty means: resolve `name`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<IpAddr>,
}

/// The relay role a node runs (D402 Q3, Q4). It holds the relay leaf's private key, so it is
/// never written to disk by the node and its `Debug` output hides the key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServeRelay {
    /// The DNS name the leaf certifies; relay clients verify it.
    pub name: String,
    /// The UDP port to bind; when it is taken (or not allowed), the role binds another and
    /// reports it.
    pub port: u16,
    /// The relay leaf certificate PEM followed by its PKCS#8 key PEM.
    pub leaf: String,
    /// The deployment CA roots host leaves must chain to, as PEM.
    pub roots: Vec<String>,
    /// Hosts whose leaves the relay refuses although they still verify (revoked or removed
    /// before their 7-day leaf expired), as canonical UUID text.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked: Vec<String>,
}

impl std::fmt::Debug for ServeRelay {
    /// Report the relay metadata while redacting its private key.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServeRelay")
            .field("name", &self.name)
            .field("port", &self.port)
            .field("leaf", &"[REDACTED]")
            .field("roots", &self.roots.len())
            .field("revoked", &self.revoked.len())
            .finish()
    }
}

/// A node's answer to `mesh.relays`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaysReply {
    /// The node took the list.
    pub accepted: bool,
    /// The UDP port its relay role listens on, while it serves one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serving: Option<u16>,
}

/// Whether `name` is a plain DNS host name: 1–253 bytes of lowercase letters, digits, dots
/// and hyphens, no empty label. Relay names end up in certificates and log lines.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

impl RelayList {
    /// Check every bound and name. A node refuses a list that fails, and keeps its old one.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.relays.len() <= MAX_RELAYS
            && self.relays.iter().all(|relay| {
                valid_name(&relay.name) && relay.port != 0 && relay.addresses.len() <= MAX_ADDRESSES
            })
            && self.serve.as_ref().is_none_or(|serve| {
                valid_name(&serve.name)
                    && serve.leaf.len() <= MAX_PEM
                    && !serve.roots.is_empty()
                    && serve.roots.len() <= MAX_ROOTS
                    && serve.roots.iter().all(|root| root.len() <= MAX_PEM)
                    && serve.revoked.len() <= MAX_REVOKED
                    && serve.revoked.iter().all(|host| valid_host(host))
            })
            && serde_json::to_vec(self)
                .is_ok_and(|bytes| bytes.len() <= infraternal_plugin_api::MAX_ACTION_BYTES)
    }

    /// The same list without the relay role, which is what a node saves and shows.
    #[must_use]
    pub fn public(&self) -> Self {
        Self {
            relays: self.relays.clone(),
            serve: None,
        }
    }
}

/// Whether `host` is a canonical lowercase hyphenated UUID.
fn valid_host(host: &str) -> bool {
    host.len() == 36
        && host.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}
