//! Checks committed host revocation and pending person removal wake the actual Mesh coordinator without another edit [134,166,198], #173, #515.
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
                    authority_epoch: false,
                    rotation_continuity: false,
                }))
                .unwrap());
            }
            if action == "host.facts.read" {
                // A node without host facts: the coordinator keeps its stored name (#236).
                return Err("host facts disabled");
            }
            if action == "mesh.relays" {
                // A node that predates relay lists (D401) refuses them.
                return Err(infraternal_plugin_api::node_channel::CALL_REFUSED);
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

/// A server and the host-to-remove as mesh nodes, with one connected peer
/// recording every `mesh.configure` chunk it is sent.
struct Watched {
    /// The host's mesh node, which removal must withdraw.
    removed: infraternal_plugin_mesh::policy::model::NodeId,
    /// Keeps the coordinator that pushes chunks to the peer alive.
    _runtime: PluginRuntime,
    /// Chunks the peer was sent, in order, after the initial snapshot.
    deliveries: tokio::sync::mpsc::UnboundedReceiver<Chunk>,
    /// The peer's initial snapshot, which still lists the host's node.
    initial: Chunk,
}

/// Enroll `host` as a mesh node, bind the real mesh coordinator to
/// `authority`, and attach a peer that already holds the host's key.
async fn watched_by_peer(
    authority: &EnrollmentStore,
    pool: &sqlx::SqlitePool,
    host: uuid::Uuid,
) -> Watched {
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
    Watched {
        removed,
        _runtime: runtime,
        deliveries,
        initial,
    }
}

/// How many mesh node rows have this id (0 once retired).
async fn node_rows(
    pool: &sqlx::SqlitePool,
    node: infraternal_plugin_mesh::policy::model::NodeId,
) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM mesh_nodes WHERE id=?")
        .bind(i64::try_from(node.0).unwrap())
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The coordinator's current mesh revision.
async fn mesh_revision(pool: &sqlx::SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// A legacy-owner host retires at once on revocation: the peer gets the
/// `removed` chunk without polling, and the tombstone refuses re-attachment
/// and admission even for a freshly built authority writer (#173).
#[tokio::test]
async fn committed_host_revocation_pushes_peer_withdrawal_without_polling() {
    let (authority, pool, host) = crate::enrollment::authority::tests::enrolled().await;
    let Watched {
        removed,
        _runtime,
        mut deliveries,
        initial,
    } = watched_by_peer(&authority, &pool, host).await;
    let mesh = infraternal_plugin_mesh::api::MeshService::new(pool.clone()).dataplane();
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
    assert_eq!(node_rows(&pool, removed).await, 0);
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

/// A person's host (UUID owner) is cut off when its removal commits, before
/// and without its cleanup receipt, so an offline host loses every peer at
/// once (D166, #515). Its cleanup-only reconnect is still admitted and its
/// receipt still completes the removal, without a second mesh revision.
#[tokio::test]
async fn pending_person_removal_pushes_peer_withdrawal_before_the_receipt() {
    let (authority, pool, host) = crate::enrollment::authority::tests::enrolled().await;
    let person = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,name,username,owner,recovery_hash) VALUES (?,'person','person',0,'test')")
        .bind(person.to_string())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE remote_hosts SET owner_id=? WHERE id=?")
        .bind(person.to_string())
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let Watched {
        removed,
        _runtime,
        mut deliveries,
        initial,
    } = watched_by_peer(&authority, &pool, host).await;
    let mesh = infraternal_plugin_mesh::api::MeshService::new(pool.clone()).dataplane();
    let started = std::time::Instant::now();
    // The Remove-host path: commit the intent and return, as for an offline host.
    let transaction = pool.begin().await.unwrap();
    let pending = authority
        .commit_revocation_intent(transaction, host, 200)
        .await
        .unwrap();
    assert!(
        pending,
        "a UUID owner's removal waits for the host's receipt"
    );
    let withdrawal = tokio::time::timeout(std::time::Duration::from_secs(5), deliveries.recv())
        .await
        .expect("peers must be told to drop the key before the host confirms")
        .unwrap();
    let elapsed = started.elapsed();
    assert!(withdrawal.last && withdrawal.removed.contains(&removed));
    assert!(withdrawal.version > initial.version);
    assert_eq!(node_rows(&pool, removed).await, 0);
    // The receipt has not arrived: the host is not revoked yet, only retired from the mesh.
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!revoked);
    // The tombstone refuses re-attachment, and ordinary admission stays refused.
    assert!(
        mesh.attach(&host.to_string(), PublicKey([3; 32]), None, false)
            .await
            .is_err()
    );
    assert!(authority.admit(&[1; 32], 201).await.is_err());
    // The cleanup-only reconnect does not depend on mesh membership.
    let (_, cleanup_person) = authority.admit_cleanup(&[1; 32], 201).await.unwrap();
    assert_eq!(cleanup_person, person);
    let revision = mesh_revision(&pool).await;
    authority
        .confirm_removal_cleanup(host, person, None, None)
        .await
        .unwrap();
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(revoked, "the receipt still completes the removal");
    assert_eq!(
        mesh_revision(&pool).await,
        revision,
        "retirement bumps once"
    );
    println!(
        "METRIC mesh_pending_removal_publication peers=1 elapsed_us={}",
        elapsed.as_micros()
    );
}
