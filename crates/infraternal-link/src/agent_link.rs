//! The wire models and signed transcripts of the handshake that admits D168
//! identities over the public WebSocket listener [168], #291, and makes the
//! server prove its current leg-B leaf on that path (#559).
//!
//! # The handshake
//!
//! After the WebSocket upgrade the server always sends an
//! [`AgentLinkChallenge`] (a 32-byte nonce). Then:
//!
//! - the agent answers an [`AgentLinkProofV2`]. It adds a fresh agent
//!   nonce and the agent's view of the TLS session (RFC 9266 `tls-exporter`,
//!   exported under [`CHANNEL_BINDING_LABEL`]), signed over
//!   [`agent_proof_bytes_v2`]. The server answers [`AgentLinkReadyV2`]: its
//!   current leg-B leaf and a signature by that leaf's key over
//!   [`server_proof_bytes_v2`].
//!
//! There is no older handshake: the first design (#291) had the agent sign
//! only the challenge, and it was removed (#559, J1198). Anything but a
//! `proof-v2` is refused like any malformed message.
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
//!   side's signature is valid as the other's or as a TLS handshake signature.
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
