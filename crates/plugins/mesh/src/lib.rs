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

#[cfg(all(feature = "relay", target_os = "linux"))]
pub mod seam;

#[cfg(all(feature = "relay", target_os = "linux"))]
pub mod relay_path;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod connection_state;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod proxy_access;

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

#[cfg(all(feature = "agent", target_os = "macos"))]
pub use macos_node as node;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod gotatun_node;

#[cfg(all(feature = "agent", target_os = "linux"))]
mod gotatun_tun;

#[cfg(all(
    feature = "agent",
    feature = "mesh-dns",
    any(target_os = "linux", target_os = "macos")
))]
pub mod dns;

#[cfg(all(
    feature = "agent",
    feature = "mesh-dns",
    any(target_os = "linux", target_os = "macos")
))]
/// Routes mesh DNS suffixes through the host's per-link resolver configuration.
mod dns_integration;

#[cfg(all(feature = "agent", any(target_os = "linux", target_os = "macos")))]
pub mod node_actions;
#[cfg(all(feature = "agent", any(target_os = "linux", target_os = "macos")))]
mod node_presentation;

#[cfg(all(feature = "agent", target_os = "macos"))]
pub mod macos_service;

#[cfg(all(feature = "agent", target_os = "macos"))]
pub mod macos_key;

#[cfg(all(feature = "agent", target_os = "macos"))]
pub mod macos_node;

// Pure byte parsing, so its tests also run in the Linux gate.
#[cfg(any(all(feature = "agent", target_os = "macos"), test))]
pub mod macos_image;

#[cfg(feature = "server")]
pub mod settings;

#[cfg(feature = "server")]
pub mod node_coordination;

/// The coordinator's durable `WireGuard` key rotation driver (D166, #285).
#[cfg(feature = "server")]
mod rotation;

#[cfg(feature = "server")]
pub mod presence;
