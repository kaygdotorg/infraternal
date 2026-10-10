//! Houses the Mesh coordinator server feature and future node component under one plugin id [198,201].

#[cfg(feature = "server")]
pub mod api;
/// Reuse the public policy types without coupling Rust adapters to a second dependency.
pub use infraternal_mesh as policy;

#[cfg(feature = "server")]
pub mod descriptor;

#[cfg(feature = "server")]
mod socket;
#[cfg(feature = "server")]
pub use socket::{MeshPlugin, parse_subscription};

/// Public-only configuration shared by the coordinator and node component.
pub mod dataplane;
