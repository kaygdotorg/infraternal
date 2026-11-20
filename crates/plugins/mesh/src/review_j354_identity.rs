//! Reviews capability negotiation against a strict pre-DNS infraternal agent (#266).
#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;

/// Emulates the previous shipping identity action: rotation and compact access, without DNS.
struct OldNode;
impl NodeChannel for OldNode {
    /// Identifies only this synthetic channel.
    fn id(&self) -> &'static str {
        "j354-old-node"
    }
    /// Uses a documentation-only underlay address without opening a socket.
    fn observed_ip(&self) -> std::net::IpAddr {
        "192.0.2.1".parse().unwrap()
    }
    /// Models a remote infraternal agent rather than the embedded server node.
    fn is_server(&self) -> bool {
        false
    }
    /// Supplies the required unused lifecycle notification channel.
    fn changes(&self) -> tokio::sync::watch::Receiver<()> {
        tokio::sync::watch::channel(()).1
    }
    /// Rejects unknown request fields and advertises only explicitly requested capabilities.
    fn call(
        &self,
        action: &str,
        input: Vec<u8>,
    ) -> infraternal_plugin_api::PluginOperation<'_, Vec<u8>> {
        assert_eq!(action, "mesh.identity");
        Box::pin(async move {
            let query: serde_json::Value = serde_json::from_slice(&input).unwrap();
            eprintln!("J354 old-node request: {query}");
            if query
                .as_object()
                .unwrap()
                .keys()
                .any(|key| key != "compact_access" && key != "key_rotation")
            {
                return Err(infraternal_plugin_api::node_channel::CALL_REFUSED);
            }
            let key = vec![2u8; 32];
            let mut reply = serde_json::json!({"public_key": key, "port": 44000});
            if query["compact_access"] == true {
                reply["compact_access"] = true.into();
            }
            if query["key_rotation"] == true {
                reply["key_rotation"] = true.into();
            }
            Ok(serde_json::to_vec(&reply).unwrap())
        })
    }
}

/// Enabling DNS must retain independently supported capabilities on existing nodes.
#[tokio::test]
async fn review_j354_dns_upgrade_keeps_old_nodes_rotation_capability() {
    let probe = read_identity(&OldNode).await.expect("old node identity");
    let identity = probe.identity;
    let rotation = probe.key_rotation_supported;
    eprintln!(
        "J354 classified rotation={rotation:?}, compact={}",
        identity.compact_access
    );
    assert_eq!(
        rotation,
        Some(true),
        "a DNS-less node still supports key rotation"
    );
    assert!(identity.compact_access);
    assert!(
        !identity.dns_names,
        "an old node does not advertise DNS names"
    );
}
