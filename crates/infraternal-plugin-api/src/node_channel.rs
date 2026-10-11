//! Supplies plugins an already-authenticated node channel; it carries no TLS keys or transport selection [9,198,215].
use crate::PluginOperation;
use std::net::IpAddr;
/// The host binds identity and observed underlay address after authentication.
/// Plugins can exchange bounded public actions without knowing TCP or QUIC.
pub trait NodeChannel: Send + Sync {
    fn id(&self) -> &str;
    fn observed_ip(&self) -> IpAddr;
    fn is_server(&self) -> bool;
    // Notifications exist only with the optional socket host runtime.
    #[cfg(feature = "socket-host")]
    fn changes(&self) -> tokio::sync::watch::Receiver<()>;
    fn call(&self, action: &str, input: Vec<u8>) -> PluginOperation<'_, Vec<u8>>;
}
