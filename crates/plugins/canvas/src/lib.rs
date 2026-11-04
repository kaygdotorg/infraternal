//! Owns the account canvas reference document and server-ordered intents [178,180,183,248].
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// The v1 JSON canvas document, its size limits and validation helpers.
pub mod model;

/// Applies one stable-ID intent to a document; refused intents leave it unchanged.
pub mod reducer;

/// Persistence behind a host-supplied per-account layout source.
pub mod store;

/// Layout subscriptions and intent handling on the authorized control stream.
pub mod socket;

/// Splitting of columns and row bands, used by the reducer; internal to this crate.
mod tiling;
