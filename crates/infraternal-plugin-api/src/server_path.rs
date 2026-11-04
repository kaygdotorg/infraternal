//! Public transport capabilities shared by node plugins and their host; credentials never cross this boundary [198,215].
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// How a host currently reaches its server. A component may propose a server destination only
/// after applying its network configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerLinkKind {
    /// Not connected.
    #[default]
    Disconnected,
    /// This machine is the server.
    Local,
    /// Over the enrolled port (the ordinary, non-mesh connection).
    Fallback,
    /// Over the mesh.
    Mesh,
}

/// Observed host transport, rather than a claim inferred from network configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerLink {
    /// How the server is reached.
    pub kind: ServerLinkKind,
    /// Server address in use, when connected.
    pub endpoint: Option<SocketAddr>,
    /// Local UDP source port, reported over the authenticated control channel.
    /// A peer behind NAT may have a different enrolled source port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    /// Why the link is in this state.
    pub reason: ServerLinkReason,
}

/// Why a host's server link is in its current state. The reasons are fixed codes, so they never
/// reflect authentication diagnostics or credentials.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerLinkReason {
    /// Connecting to the enrolled server.
    #[default]
    Connecting,
    /// The server runs on this machine.
    Local,
    /// The mesh path is not available.
    MeshUnavailable,
    /// The mesh path is proven to work.
    MeshProven,
    /// The mesh path was refused; the host retries.
    MeshRefused,
    /// The mesh path was interrupted.
    MeshInterrupted,
    /// The mesh path was withdrawn (mesh turned off).
    MeshDisabled,
}

/// Owns a listener's lifecycle: hold the value for as long as the listener should run.
/// Dropping the lease cancels its sockets and workers. Any thread-safe value can serve as one.
pub trait ListenerLease: Send + Sync {}
impl<T: Send + Sync> ListenerLease for T {}

#[cfg(test)]
mod tests {
    //! Legacy control replies remain valid when local UDP coordinates are absent.
    use super::*;
    #[test]
    fn legacy_link_omits_the_optional_source_port() {
        let link: ServerLink = serde_json::from_str(
            r#"{"kind":"Fallback","endpoint":"127.0.0.1:7443","reason":"Connecting"}"#,
        )
        .unwrap();
        assert_eq!(link.source_port, None);
        assert!(
            !serde_json::to_string(&link)
                .unwrap()
                .contains("source_port")
        );
    }
}
