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
pub use infraternal_mesh_node::dataplane;

/// Owns the host input policy shared by the server and mesh node [D386].
#[cfg(any(feature = "server", feature = "agent"))]
pub mod host_firewall;

/// Chooses the stable mesh UDP listener and its configured fallback behavior.
#[cfg(all(feature = "agent", any(target_os = "linux", target_os = "macos")))]
mod listen_port;

/// Direct-path candidates and the order nodes try them in (#515, D391).
pub use infraternal_mesh_node::candidates;

/// The per-peer candidate walks both `GotaTun` engines drive, Linux and macOS alike (#515).
#[cfg(all(feature = "agent", any(target_os = "linux", target_os = "macos")))]
use infraternal_mesh_node::candidate_walks;

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

/// Finds nft and the iptables-nft frontends at fixed, root-owned paths, Nix ones included [D384].
#[cfg(all(feature = "agent", target_os = "linux"))]
pub(crate) mod firewall_tools;

#[cfg(all(feature = "agent", any(target_os = "linux", target_os = "macos")))]
pub mod node_state;

/// The public enrollment identity recorded beside saved node state.
#[cfg(all(feature = "agent", any(target_os = "linux", target_os = "macos")))]
mod enrolment;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod node;

/// Subnet routes on a node: routes to networks behind routers, and (Linux) forwarding (D197 M3).
#[cfg(all(feature = "agent", any(target_os = "linux", target_os = "macos")))]
mod subnet_routes;

/// The Mac machine binding; also built for Linux unit tests, whose pure logic needs no Mac.
#[cfg(any(
    all(feature = "agent", target_os = "macos"),
    all(test, feature = "agent", target_os = "linux")
))]
mod macos_machine;

#[cfg(all(feature = "agent", target_os = "macos"))]
pub use macos_node as node;

/// The device-level switch for `GotaTun`'s second UDP socket (#260, J1211).
#[cfg(all(feature = "agent", any(target_os = "linux", target_os = "macos")))]
mod side_socket;

#[cfg(all(feature = "agent", target_os = "linux"))]
pub mod gotatun_node;

#[cfg(all(feature = "agent", target_os = "linux"))]
mod gotatun_tun;

/// Coalesces endpoint announcements from the Linux and Mac route listeners (#483).
#[cfg(all(feature = "agent", any(target_os = "linux", target_os = "macos")))]
use infraternal_mesh_node::underlay_announce;

#[cfg(all(feature = "agent", any(target_os = "linux", target_os = "macos")))]
/// Round-trip probes on the direct path, sent from the `WireGuard` port.
pub use infraternal_mesh_node::direct_probe;

#[cfg(all(feature = "agent", any(target_os = "linux", target_os = "macos")))]
/// Drops handshake initiations from ungranted keys before the userspace engine sees them.
use infraternal_mesh_node::handshake_admission;

#[cfg(all(feature = "agent", any(target_os = "linux", target_os = "macos")))]
/// Enforces per-peer grants at both GotaTun TUN boundaries on Linux and macOS.
mod packet_filter;

#[cfg(all(feature = "agent", any(target_os = "linux", target_os = "macos")))]
/// Derives per-peer mesh route MTUs and a shared IPv6-safe interface MTU.
mod mesh_mtu;

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

/// Answers queries to the mesh resolver address from the tunnel's read path (#146, J1027 F2).
/// Pure packet work, so its tests also run in the Linux gate.
#[cfg(all(
    feature = "mesh-dns",
    any(
        all(feature = "agent", target_os = "macos"),
        all(test, feature = "agent")
    )
))]
mod tunnel_dns;

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

/// Pure rules for macOS user mode: the helper's wire format, request checks, routing-table
/// reading and launchd property lists (#146). Free of side effects, so its tests also run in
/// the Linux gate.
#[cfg(any(all(feature = "agent", target_os = "macos"), test))]
pub mod macos_user_mode;

/// Raises and watches macOS Local Network access for the user-mode infraternal agent (#576).
/// Interface selection is pure code, so its tests also run in the Linux gate.
#[cfg(all(feature = "agent", any(target_os = "macos", test)))]
pub mod macos_local_network;

/// Which subnet routes a Mac client puts on its mesh utun, and why it leaves one out (D197 M3,
/// #580). Pure rules shared by root and user mode, so its tests also run in the Linux gate.
#[cfg(any(all(feature = "agent", target_os = "macos"), test))]
pub mod macos_subnet_routes;

/// The on-demand root helper for macOS user mode and the agent's client for it (#146).
#[cfg(all(feature = "agent", target_os = "macos"))]
pub mod macos_helper;

// Pure byte parsing, so its tests also run in the Linux gate.
#[cfg(any(all(feature = "agent", target_os = "macos"), test))]
pub mod macos_image;

/// The two utun ioctls (`SIOCSIFMTU`, `IFF_UP`) behind one of the crate's two scoped
/// `allow(unsafe_code)` modules (#221). Request building is safe code, so its tests also run in
/// the Linux gate.
#[cfg(any(all(feature = "agent", target_os = "macos"), test))]
mod macos_utun_ioctl;

/// Which utuns one person's infraternal agent holds, read by the root helper through `libproc`
/// (#146, J1027 F1); the crate's other scoped `allow(unsafe_code)`. The reply parser is safe
/// code, so its tests also run in the Linux gate.
#[cfg(any(all(feature = "agent", target_os = "macos"), test))]
mod macos_utun_holder;

#[cfg(feature = "server")]
pub mod settings;

/// Administrator actions for subnet routes: list, approve, revoke (D197 M3).
#[cfg(feature = "server")]
pub mod route_api;

#[cfg(feature = "server")]
pub mod node_coordination;

/// The coordinator's durable `WireGuard` key rotation driver (D166, #285).
#[cfg(feature = "server")]
mod rotation;

#[cfg(feature = "server")]
pub mod presence;
