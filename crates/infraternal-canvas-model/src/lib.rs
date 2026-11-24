//! The account canvas layout tree: the v1 document, its intent reducer and the tiling rules [178,180,183,248].
//!
//! This crate holds only pure data code (serde, serde_json, uuid) so that the server plugin, the
//! fuzz targets and later the client core can share one reducer. `infraternal-plugin-canvas`
//! re-exports these modules under their old paths.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// The v1 JSON canvas document, its size limits and validation helpers.
pub mod model;

/// Applies one stable-ID intent to a document; refused intents leave it unchanged.
pub mod reducer;

/// Splitting of columns and row bands, used by the reducer; internal to this crate.
mod tiling;
