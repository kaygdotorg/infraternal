//! Checks committed host revocation wakes the actual Mesh coordinator without another edit [134,166,198], #173.
#![allow(clippy::unwrap_used)]
use crate::{enrollment::EnrollmentStore, plugins::PluginRuntime};
use infraternal_plugin_api::{PluginOperation, node_channel::NodeChannel};
use infraternal_plugin_mesh::{
    MeshPlugin,
    dataplane::{Chunk, Identity},
    policy::model::PublicKey,
};
use std::sync::Arc;

struct PeerChannel {
    changes: tokio::sync::watch::Sender<()>,
    applied: tokio::sync::mpsc::UnboundedSender<Chunk>,
}
impl NodeChannel for PeerChannel {
    fn id(&self) -> &'static str {
        "target"
    }
    fn observed_ip(&self) -> std::net::IpAddr {
        std::net::Ipv4Addr::UNSPECIFIED.into()
    }
    fn is_server(&self) -> bool {
        false
    }
    fn changes(&self) -> tokio::sync::watch::Receiver<()> {
        self.changes.subscribe()
    }
    fn call(&self, action: &str, input: Vec<u8>) -> PluginOperation<'_, Vec<u8>> {
        let action = action.to_owned();
        Box::pin(async move {
            if action == "mesh.identity" {
                return Ok(serde_json::to_vec(&Some(Identity {
                    compact_access: false,
                    // This fixture leaves resolver support unnegotiated because it tests revocation.
                    dns_names: false,
                    public_key: PublicKey([2; 32]),
                    port: 51820,
                    key_rotation: false,
                }))
                .unwrap());
            }
            if action == "host.facts.read" {
                // A node without host facts: the coordinator keeps its stored name (#236).
                return Err("host facts disabled");
            }
            assert_eq!(action, "mesh.configure");
            let chunk: Chunk = serde_json::from_slice(&input).unwrap();
            let reply = serde_json::to_vec(
                &serde_json::json!({"applied":chunk.last,"version":chunk.version}),
            )
            .unwrap();
            self.applied.send(chunk).unwrap();
            Ok(reply)
        })
    }
}

#[tokio::test]
async fn committed_host_revocation_pushes_peer_withdrawal_without_polling() {
    let (authority, pool, host) = crate::enrollment::authority::tests::enrolled().await;
    let service = infraternal_plugin_mesh::api::MeshService::new(pool.clone());
    let mesh = service.dataplane();
    mesh.attach("server", PublicKey([1; 32]), None, true)
        .await
        .unwrap();
    let (removed, _) = mesh
        .attach(&host.to_string(), PublicKey([3; 32]), None, false)
        .await
        .unwrap();
    let runtime = PluginRuntime::new(vec![Arc::new(MeshPlugin::new(pool.clone()))], "server")
        .with_store(pool.clone())
        .await
        .unwrap();
    authority.bind_plugins(&runtime);
    let (sender, mut deliveries) = tokio::sync::mpsc::unbounded_channel();
    runtime
        .attach_node(Arc::new(PeerChannel {
            changes: tokio::sync::watch::channel(()).0,
            applied: sender,
        }))
        .await
        .unwrap();
    let initial = tokio::time::timeout(std::time::Duration::from_secs(5), deliveries.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(initial.last && initial.upserted.contains_key(&removed));
    let started = std::time::Instant::now();
    authority.revoke("owner", host, 200).await.unwrap();
    let withdrawal = tokio::time::timeout(std::time::Duration::from_secs(5), deliveries.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(withdrawal.last && withdrawal.removed.contains(&removed));
    assert!(withdrawal.version > initial.version);
    assert!(
        mesh.attach(&host.to_string(), PublicKey([3; 32]), None, false)
            .await
            .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM mesh_nodes WHERE id=?")
            .bind(i64::try_from(removed.0).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    // A reconstructed authority writer needs only the durable tombstone; no live
    // transport registration or remembered coordinator snapshot can restore it.
    assert!(
        EnrollmentStore::new(pool)
            .admit(&[1; 32], 201)
            .await
            .is_err()
    );
    println!(
        "METRIC mesh_revocation_publication peers=1 elapsed_us={}",
        started.elapsed().as_micros()
    );
}
