//! Supplies plugins an already-authenticated node channel; it carries no TLS keys or transport selection [9,198,215].
use crate::PluginOperation;
use std::net::IpAddr;
/// The error a [`NodeChannel::call`] returns when the node itself answered with a refusal: the request reached
/// it, and its plugin rejected it. Timeouts, a lost channel and an ended authority return other errors, so a
/// caller can tell "the node does not accept this request" from "the request did not get an answer" (#285).
pub const CALL_REFUSED: &str = "Node action refused.";
/// The host binds identity and observed underlay address after authentication.
/// Plugins can exchange bounded public actions without knowing TCP or QUIC.
pub trait NodeChannel: Send + Sync {
    fn id(&self) -> &str;
    fn observed_ip(&self) -> IpAddr;
    fn is_server(&self) -> bool;
    /// Whether this peer accepts additive applied server-path metadata.
    /// Legacy peers keep the original configuration contract.
    fn supports_server_paths(&self) -> bool {
        false
    }
    // Notifications exist only with the optional socket host runtime.
    #[cfg(feature = "socket-host")]
    fn changes(&self) -> tokio::sync::watch::Receiver<()>;
    fn call(&self, action: &str, input: Vec<u8>) -> PluginOperation<'_, Vec<u8>>;
    /// Lease an alternative source address for this admitted peer. The host
    /// supplies its existing logical tuple and identity; plugins supply routing only.
    /// Dropping the lease removes the alternative without ending the session.
    fn route_peer(
        &self,
        _address: std::net::SocketAddr,
    ) -> PluginOperation<'_, Option<Box<dyn crate::server_path::ListenerLease>>> {
        Box::pin(async { Ok(None) })
    }
    /// Lease an additional authenticated listener on an explicitly created server.
    /// Dropping the lease stops admission; ordinary nodes cannot create listeners.
    fn listen_server(
        &self,
        _address: IpAddr,
    ) -> PluginOperation<'_, Option<Box<dyn crate::server_path::ListenerLease>>> {
        Box::pin(async { Ok(None) })
    }
}
