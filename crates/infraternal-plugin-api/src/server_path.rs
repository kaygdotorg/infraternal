//! Public transport capabilities shared by node plugins and their host; credentials never cross this boundary [198,215].
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// A component may propose a server destination only after applying its network configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerLinkKind {
    #[default]
    Disconnected,
    Local,
    Fallback,
    Mesh,
}

/// Observed host transport, rather than a claim inferred from network configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerLink {
    pub kind: ServerLinkKind,
    pub endpoint: Option<SocketAddr>,
    /// Local UDP source port, reported over the authenticated control channel.
    /// A peer behind NAT may have a different enrolled source port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    pub reason: ServerLinkReason,
}

/// Fixed public reasons avoid reflecting authentication diagnostics or credentials.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerLinkReason {
    #[default]
    Connecting,
    Local,
    MeshUnavailable,
    MeshProven,
    MeshRefused,
    MeshInterrupted,
    MeshDisabled,
}

/// Owns a listener's lifecycle. Dropping the lease cancels its sockets and workers.
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
