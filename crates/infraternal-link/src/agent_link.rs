//! The wire models and signed transcripts of the handshake that admits D168
//! identities over the public WebSocket listener [168], #291, and makes the
//! server prove its current leg-B leaf on that path (#559).
//!
//! # The two versions
//!
//! After the WebSocket upgrade the server always sends an
//! [`AgentLinkChallenge`] (a 32-byte nonce). Then:
//!
//! - **v1** (infraternal agents built before #559): the agent answers an
//!   [`AgentLinkProof`] signed over [`proof_bytes`], and the server answers
//!   [`AgentLinkReady`]. The server proves nothing beyond the outer HTTPS
//!   certificate. The server still accepts v1 so agents that have not updated
//!   yet keep their link (and can receive the update).
//! - **v2**: the agent answers an [`AgentLinkProofV2`]. It adds a fresh agent
//!   nonce and the agent's view of the TLS session (RFC 9266 `tls-exporter`,
//!   exported under [`CHANNEL_BINDING_LABEL`]), signed over
//!   [`agent_proof_bytes_v2`]. The server answers [`AgentLinkReadyV2`]: its
//!   current leg-B leaf and a signature by that leaf's key over
//!   [`server_proof_bytes_v2`].
//!
//! This module holds only the messages and the exact bytes each side signs,
//! so every client can build and parse them (#580). Signing, verifying, the
//! TLS exporter and the leaf check stay with the TLS stack that runs the
//! link (OpenSSL in `infraternal-plugin-remote`'s `agent_link`, which
//! re-exports everything here under its old path).
//!
//! # Invariants
//!
//! - Every signed message starts with its own domain string, so neither
//!   side's signature is valid as the other's, as a v1 proof, or as a TLS
//!   handshake signature.
//! - Transcript fields are fixed-length, except the binding, which is
//!   preceded by a presence byte. No two different inputs produce the same
//!   bytes.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The `type` of an [`AgentLinkProofV2`].
pub const PROOF_V2: &str = "proof-v2";
/// The `type` of an [`AgentLinkReadyV2`].
pub const READY_V2: &str = "ready-v2";
/// Length of both nonces in bytes.
pub const NONCE_LEN: usize = 32;
/// Length of a TLS channel binding in bytes (RFC 9266 uses 32).
pub const BINDING_LEN: usize = 32;
/// RFC 9266's exporter label for the `tls-exporter` channel binding.
pub const CHANNEL_BINDING_LABEL: &str = "EXPORTER-Channel-Binding";
/// Domain of the agent's v2 signature.
const AGENT_DOMAIN_V2: &[u8] = b"infraternal-agent-link-v2\0agent\0";
/// Domain of the server's v2 signature.
const SERVER_DOMAIN_V2: &[u8] = b"infraternal-agent-link-v2\0server\0";

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

/// The v2 answer to an [`AgentLinkChallenge`]: the enrolled certificate, a
/// fresh agent nonce, the agent's TLS channel binding, and a signature over
/// [`agent_proof_bytes_v2`]. Byte fields are canonical base64url.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLinkProofV2 {
    /// Always [`PROOF_V2`].
    #[serde(rename = "type")]
    pub message_type: String,
    /// The identity whose key signs the proof.
    pub host_id: Uuid,
    /// The enrolled leaf certificate, DER.
    pub certificate_der: String,
    /// 32 fresh random bytes the server's signature must cover.
    pub client_nonce: String,
    /// The agent's TLS channel binding (RFC 9266 `tls-exporter`), absent when its TLS session has
    /// none (a reverse proxy that speaks only TLS 1.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_binding: Option<String>,
    /// Signature by the enrolled key over [`agent_proof_bytes_v2`].
    pub signature: String,
}

/// The server's v2 answer to an accepted [`AgentLinkProofV2`]: its current
/// leg-B leaf and a signature by that leaf's key over
/// [`server_proof_bytes_v2`]. Byte fields are canonical base64url.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLinkReadyV2 {
    /// Always [`READY_V2`].
    #[serde(rename = "type")]
    pub message_type: String,
    /// The leaf the server's QUIC and TCP/TLS listeners serve right now, DER.
    pub server_certificate_der: String,
    /// Whether the server checked the agent's channel binding against the TLS
    /// session it terminated itself (`false` behind a reverse proxy).
    pub channel_bound: bool,
    /// Signature by the leaf's key over [`server_proof_bytes_v2`].
    pub signature: String,
}

/// Reads only the `type` of a handshake message, so the receiver can pick
/// the strict struct to parse it into.
#[derive(Deserialize)]
struct MessageType {
    /// The message discriminator.
    #[serde(rename = "type")]
    message_type: String,
}

/// The `type` field of a JSON handshake message, or `None` if it has none.
/// Parse the message again into its strict struct after this.
#[must_use]
pub fn message_type(text: &str) -> Option<String> {
    serde_json::from_str::<MessageType>(text)
        .ok()
        .map(|message| message.message_type)
}

/// Appends a binding as a presence byte and, when present, its 32 bytes.
fn push_binding(bytes: &mut Vec<u8>, binding: Option<&[u8; BINDING_LEN]>) {
    match binding {
        Some(binding) => {
            bytes.push(1);
            bytes.extend_from_slice(binding);
        }
        None => bytes.push(0),
    }
}

/// What the infraternal agent signs in an [`AgentLinkProofV2`].
///
/// Covers the host id, the server's challenge nonce, the agent's own nonce
/// and the binding of the TLS session the agent sees.
#[must_use]
pub fn agent_proof_bytes_v2(
    host_id: Uuid,
    server_nonce: &[u8; NONCE_LEN],
    client_nonce: &[u8; NONCE_LEN],
    binding: Option<&[u8; BINDING_LEN]>,
) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(AGENT_DOMAIN_V2.len() + 16 + 2 * NONCE_LEN + 1 + BINDING_LEN);
    bytes.extend_from_slice(AGENT_DOMAIN_V2);
    bytes.extend_from_slice(host_id.as_bytes());
    bytes.extend_from_slice(server_nonce);
    bytes.extend_from_slice(client_nonce);
    push_binding(&mut bytes, binding);
    bytes
}

/// What the server signs with its leg-B leaf key in an [`AgentLinkReadyV2`].
///
/// Covers everything the agent's proof covered, plus the SHA-256 of the
/// agent's certificate and of the server leaf itself. `binding` is the value
/// the server checked against its own TLS session, or `None` when it did not
/// terminate the session (then `channel_bound` is `false`).
#[must_use]
pub fn server_proof_bytes_v2(
    host_id: Uuid,
    server_nonce: &[u8; NONCE_LEN],
    client_nonce: &[u8; NONCE_LEN],
    agent_certificate_sha256: &[u8; 32],
    server_leaf_sha256: &[u8; 32],
    binding: Option<&[u8; BINDING_LEN]>,
) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(SERVER_DOMAIN_V2.len() + 16 + 2 * NONCE_LEN + 64 + 1 + BINDING_LEN);
    bytes.extend_from_slice(SERVER_DOMAIN_V2);
    bytes.extend_from_slice(host_id.as_bytes());
    bytes.extend_from_slice(server_nonce);
    bytes.extend_from_slice(client_nonce);
    bytes.extend_from_slice(agent_certificate_sha256);
    bytes.extend_from_slice(server_leaf_sha256);
    push_binding(&mut bytes, binding);
    bytes
}

/// Tests for the proof message layout.
#[cfg(test)]
mod tests {
    use super::*;

    /// The proof bytes change with the host and the nonce, and start with the fixed domain label.
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
