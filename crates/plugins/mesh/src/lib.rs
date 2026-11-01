//! Houses the Mesh coordinator and Linux node component behind removable plugin features [198,201].

#[cfg(feature = "server")]
mod diagnostics;

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

pub mod access_updates;

#[cfg(feature = "cutoff-measure")]
mod cutoff_measure;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod netlink;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod wireguard;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod connection_state;

#[cfg(feature = "server")]
pub mod store;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod iptables;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod firewall;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod node_state;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod node;

#[cfg(all(feature = "mesh-dns-spike", target_os = "linux"))]
pub mod dns;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod node_actions;
#[cfg(all(feature = "agent", target_os = "linux"))]
mod node_presentation;

#[cfg(feature = "server")]
pub mod settings;

#[cfg(feature = "server")]
pub mod node_coordination;

#[cfg(feature = "server")]
pub mod presence;
