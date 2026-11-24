//! The client side of leg B: how an infraternal client dials the server,
//! keeps that link up and moves frames over it (docs/design/client-core-split.md §2, #580).
//!
//! The infraternal agent on Linux and macOS uses this crate today; the iPhone's
//! packet tunnel extension will use it too. That is why nothing here touches
//! OpenSSL, file paths, uids or child processes: hosts pass those things in.
//! The older crates (`infraternal-agent`, `infraternal-plugin-remote`)
//! re-export what moved here under its old paths.
//!
//! - [`supervisor`]: the reconnect loop, its backoff and offline watchdog.
//! - `dial_runtime` (feature `quic`): the QUIC runtime of one dial attempt.
//! - [`transport`]: the bounded frame reader and writer over a channel.
//! - [`enrollment`], [`agent_link`]: the join and WebSocket-proof wire models.
//! - `identity`, `quic` (feature `quic`): the client identity as a signer
//!   (Ed25519 PKCS#8 on hosts, the Secure Enclave later) and the QUIC config.
//! - [`server_leaf_floor`]: the server-leaf age floor, read from DER.
//! - `wire_datagrams` (features `quic` and `native-streams`): QUIC datagram lanes for plugins.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

/// The WebSocket listener's key-possession proof: challenge, proof and ready messages.
pub mod agent_link;
/// The QUIC runtime of one dial attempt, which cancels its drivers when dropped.
#[cfg(feature = "quic")]
pub mod dial_runtime;
/// The join's wire models: invitation, request and response.
pub mod enrollment;
/// The node's identity for TLS: certificate chain plus a signer for its key.
#[cfg(feature = "quic")]
pub mod identity;
/// The client's QUIC TLS config and the transport settings both ends share.
#[cfg(feature = "quic")]
pub mod quic;
/// Refuses a server leaf older than the newest one already accepted (#559).
pub mod server_leaf_floor;
/// The reconnect loop with backoff and the offline watchdog.
pub mod supervisor;
/// The bounded frame reader and writer over a leg-B channel.
pub mod transport;
/// QUIC datagram lanes shared by plugin media streams.
#[cfg(all(feature = "quic", feature = "native-streams"))]
pub mod wire_datagrams;
