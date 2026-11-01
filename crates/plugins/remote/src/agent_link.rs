//! Defines the bounded app-level challenge used to admit D168 identities over the public WebSocket listener [168], #291.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Server challenge sent after the WebSocket upgrade, before any agent protocol frame.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLinkChallenge {
    /// Fixed message discriminator.
    #[serde(rename = "type")]
    pub message_type: String,
    /// Canonical base64url 256-bit nonce.
    pub nonce: String,
}

/// Proof carries the exact enrolled certificate and a fresh signature from its private key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLinkProof {
    /// Fixed message discriminator.
    #[serde(rename = "type")]
    pub message_type: String,
    /// The identity whose key signs the challenge.
    pub host_id: Uuid,
    /// Canonical base64url leaf certificate DER.
    pub certificate_der: String,
    /// Canonical base64url signature of [`proof_bytes`].
    pub signature: String,
}

/// Sent only after the app listener admits the certificate and signature.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLinkReady {
    /// Fixed message discriminator.
    #[serde(rename = "type")]
    pub message_type: String,
}

/// Domain separates and host-binds one connection's key-possession proof.
#[must_use]
pub fn proof_bytes(host_id: Uuid, nonce: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(35 + nonce.len());
    bytes.extend_from_slice(b"infraternal-agent-link-v1\0");
    bytes.extend_from_slice(host_id.as_bytes());
    bytes.extend_from_slice(nonce);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_message_is_domain_separated_and_bound_to_host_and_nonce() {
        let host = Uuid::from_u128(1);
        let other_host = Uuid::from_u128(2);
        let first = proof_bytes(host, &[7; 32]);
        assert_ne!(first, proof_bytes(other_host, &[7; 32]));
        assert_ne!(first, proof_bytes(host, &[8; 32]));
        assert!(first.starts_with(b"infraternal-agent-link-v1\0"));
    }
}
