//! Proof that a Linux or macOS installation asked its server to retire it.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Public HTTPS endpoint used by the uninstall command.
pub const PATH: &str = "/remote/local-retirement";

/// A short-lived statement signed by the installation's current host key.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// The exact enrollment being retired.
    pub host_id: Uuid,
    /// SHA-256 of the server-issued, active certificate's DER bytes.
    pub fingerprint: [u8; 32],
    /// UTC seconds when the installation approved removal.
    pub signed_at: i64,
    /// Ed25519 signature of [`transcript`].
    pub signature: Vec<u8>,
}

/// Bind the host, certificate and time to this action alone using fixed-width fields.
#[must_use]
pub fn transcript(request: &Request) -> Vec<u8> {
    let mut bytes = b"infraternal local uninstall v1\0".to_vec();
    bytes.extend_from_slice(request.host_id.as_bytes());
    bytes.extend_from_slice(&request.fingerprint);
    bytes.extend_from_slice(&request.signed_at.to_be_bytes());
    bytes
}
