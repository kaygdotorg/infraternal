//! Portable policy, packet handling and presentation for an infraternal mesh node.

/// Shared mesh policy and address types used by the node.
pub use infraternal_mesh as policy;

/// Apply compact access changes to an accepted node snapshot.
pub mod access_updates;
/// Choose and order direct-path endpoints.
pub mod candidates;
/// Public node configuration, the policy revision and its chunked updates.
pub mod dataplane;
/// Build name records and answer DNS requests.
#[cfg(feature = "mesh-dns")]
pub mod dns;
/// Describe the resolver state a host reports.
pub mod dns_state;
/// Bind saved mesh state to a coordinator and an enrolled public identity.
pub mod enrolment;
/// Resolve a preferred listener port and whether fallback is allowed.
pub mod listen_port;
/// Derive interface MTUs and per-peer packet budgets from underlay MTUs.
pub mod mesh_mtu;
/// Describe, parse and page the mesh node actions shared by each host.
pub mod node_actions;
/// Render public mesh status, peers and routes.
pub mod node_presentation;
/// Persistable mesh state and rotation metadata.
pub mod node_state;
/// Public peer counters and conversion from device statistics.
pub mod peer_stats;

/// Drive per-peer retries from engine observations.
#[cfg(feature = "engine")]
pub mod candidate_walks;
/// Send and receive direct-path probes on the mesh UDP socket.
#[cfg(all(unix, feature = "engine"))]
pub mod direct_probe;
/// Limit handshake work and admit installed identities.
#[cfg(all(unix, feature = "engine"))]
pub mod handshake_admission;
/// Enforce grants at a node’s packet boundaries.
#[cfg(feature = "engine")]
pub mod packet_filter;
/// Recognize and answer resolver packets inside the tunnel.
#[cfg(feature = "mesh-dns")]
pub mod tunnel_dns;
/// Coalesce underlay events for the node worker.
#[cfg(feature = "engine")]
pub mod underlay_announce;
