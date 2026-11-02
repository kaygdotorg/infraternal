//! Shares unchanged enrollment wire models between server and node builds; no storage or signing is pulled into nodes [133][198], #190.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A host's immutable execution mode, bound into its invitation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Runs as the enrolled non-root user.
    Rootless,
    /// Runs as uid zero after explicit owner consent.
    Rootful,
}

impl Mode {
    /// Canonical stored and serialized execution mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rootless => "rootless",
            Self::Rootful => "rootful",
        }
    }
}

/// Public transport coordinates are selected by the server, never by a joining host.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinInvitation {
    /// Bound host authority.
    pub host_id: Uuid,
    /// Immutable privilege mode.
    pub mode: Mode,
    /// Bound execution uid from the trusted bootstrap probe.
    pub execution_uid: u32,
    /// Public HTTPS origin used by both enrollment and the agent's WebSocket link.
    #[serde(default)]
    pub public_origin: String,
    /// One-time capability: pass privately through stdin, never print or log it.
    pub token: String,
    /// Base64url DER public CA pin for authenticated enrollment and leg B.
    pub ca_der: String,
    /// Optional independently pinned enrollment HTTPS certificate; legacy uses `ca_der`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_der: Option<String>,
    /// Reverse-proxy HTTPS uses ordinary verified system roots instead of the internal CA.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub https_system_roots: bool,
    /// Legacy direct transport address. New invitations omit it.
    #[serde(default, skip_serializing)]
    pub endpoint: Option<std::net::SocketAddr>,
    /// D168 identity authority name retained when the transport moves to a public HTTPS origin.
    #[serde(default)]
    pub server_name: String,
}

/// Canonical bounded enrollment body; adapter never forwards requested identity extensions.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    /// Host bound by the invitation.
    pub host_id: Uuid,
    /// Mode bound by the invitation.
    pub mode: Mode,
    /// Canonical 256-bit capability, not a URL parameter.
    pub token: String,
    /// Canonical base64url PKCS10 DER, at most 4096 decoded bytes.
    pub csr_der: String,
}

/// Committed public identity; the private host key never leaves its process.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinResponse {
    /// Base64url DER seven-day client certificate.
    pub certificate_der: String,
    /// Host's trusted enrolled uid.
    pub execution_uid: u32,
}
