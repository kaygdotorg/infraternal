//! Portable policy, packet handling and presentation for an infraternal mesh node.

/// Shared mesh policy and address types used by the node.
pub use infraternal_mesh as policy;

/// Apply compact access changes to an accepted node snapshot.
pub mod access_updates;
/// Choose and order direct-path endpoints.
pub mod candidates;
/// Public node configuration, the policy revision and its chunked updates.
pub mod dataplane;
/// Describe the resolver state a host reports.
pub mod dns_state;
/// Resolve a preferred listener port and whether fallback is allowed.
pub mod listen_port;
/// Render public mesh status, peers and routes.
pub mod node_presentation;

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
/// Convert device statistics to public node counters.
#[cfg(all(unix, feature = "engine"))]
pub mod peer_stats;
/// Recognize and answer resolver packets inside the tunnel.
#[cfg(feature = "mesh-dns")]
pub mod tunnel_dns;
/// Coalesce underlay events for the node worker.
#[cfg(feature = "engine")]
pub mod underlay_announce;
