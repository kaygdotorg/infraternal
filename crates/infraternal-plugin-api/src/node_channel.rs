//! Supplies plugins an already-authenticated node channel; it carries no TLS keys or transport selection [9,198,215].
use crate::PluginOperation;
use std::net::IpAddr;
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
    /// Lease an additional authenticated listener on an explicitly created server.
    /// Dropping the lease stops admission; ordinary nodes cannot create listeners.
    fn listen_server(
        &self,
        _address: IpAddr,
    ) -> PluginOperation<'_, Option<Box<dyn crate::server_path::ListenerLease>>> {
        Box::pin(async { Ok(None) })
    }
}
