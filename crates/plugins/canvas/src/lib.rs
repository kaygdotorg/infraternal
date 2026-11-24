//! Owns the account canvas reference document and server-ordered intents [178,180,183,248].
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// The v1 JSON canvas document, re-exported from `infraternal-canvas-model` so old paths keep working.
pub use infraternal_canvas_model::model;

/// The intent reducer, re-exported from `infraternal-canvas-model` so old paths keep working.
pub use infraternal_canvas_model::reducer;

/// Persistence behind a host-supplied per-account layout source.
pub mod store;

/// Layout subscriptions and intent handling on the authorized control stream.
pub mod socket;
