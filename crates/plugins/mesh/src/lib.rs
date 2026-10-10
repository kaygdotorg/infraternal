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

pub mod configuration;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod netlink;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod wireguard;

#[cfg(feature = "server")]
pub mod store;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod iptables;
