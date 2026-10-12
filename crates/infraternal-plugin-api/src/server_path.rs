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
