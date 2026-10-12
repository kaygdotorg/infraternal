//! Gives compiled plugins an admitted node capability over the existing actor, independent of TCP/QUIC [9,198,215].
use crate::embedded::EmbeddedAgent;
use infraternal_plugin_api::{PluginOperation, node_channel::NodeChannel};
use std::{net::IpAddr, time::Duration};
/// No credentials are exposed. Remote authority is checked at every plugin call.
pub(crate) struct NodeBridge {
    pub id: String,
    pub ip: IpAddr,
    pub server: bool,
    pub server_paths: bool,
    pub actor: EmbeddedAgent,
    #[cfg(feature = "remote")]
    pub authority: Option<crate::remote_guard::AuthorityGuard>,
    #[cfg(feature = "remote")]
    pub listeners: Option<crate::remote_runtime::RemoteHosts>,
}
impl NodeChannel for NodeBridge {
    fn id(&self) -> &str {
        &self.id
    }
    fn observed_ip(&self) -> IpAddr {
        self.ip
    }
    fn is_server(&self) -> bool {
        self.server
    }
    fn supports_server_paths(&self) -> bool {
        self.server_paths
    }
    fn changes(&self) -> tokio::sync::watch::Receiver<()> {
        self.actor.changes()
    }
    fn listen_server(
        &self,
        address: IpAddr,
    ) -> PluginOperation<'_, Option<Box<dyn infraternal_plugin_api::server_path::ListenerLease>>>
    {
        Box::pin(async move {
            #[cfg(feature = "remote")]
            if self.server
                && let Some(listeners) = &self.listeners
            {
                return listeners
                    .listen(address)
                    .await
                    .map(|lease| {
                        lease.map(|lease| {
                            Box::new(lease)
                                as Box<dyn infraternal_plugin_api::server_path::ListenerLease>
                        })
                    })
                    .map_err(|_| "Server listener refused.");
            }
            #[cfg(not(feature = "remote"))]
            let _ = address;
            Ok(None)
        })
    }
    fn call(&self, action: &str, input: Vec<u8>) -> PluginOperation<'_, Vec<u8>> {
        let action = action.to_owned();
        Box::pin(async move {
            #[cfg(feature = "remote")]
            if let Some(authority) = &self.authority {
                authority
                    .admit_operation()
                    .await
                    .map_err(|_| "Node authority ended.")?;
            }
            tokio::time::timeout(Duration::from_secs(5), self.actor.call(action, input))
                .await
                .map_err(|_| "Node control timed out.")?
                .map_err(|_| "Node action refused.")
        })
    }
}
