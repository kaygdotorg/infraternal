//! Verifies host revocation withdraws public Mesh reach from the production coordinator [134,166], #173.
#![cfg(all(feature = "remote", feature = "mesh"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    api::MeshService,
    policy::{
        model::PublicKey,
        rules::{Port, Protocol},
    },
};
use infraternal_server::enrollment::EnrollmentStore;
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;

#[tokio::test]
async fn revoked_remote_host_is_withdrawn_from_mesh_peer_policy() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner')")
        .execute(&pool).await.unwrap();
    let host = uuid::Uuid::from_u128(42);
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)")
        .bind(host.as_bytes().as_slice()).execute(&pool).await.unwrap();
    let service = MeshService::new(pool.clone());
    let mesh = service.dataplane();
    mesh.attach("server", PublicKey([1; 32]), None, true)
        .await
        .unwrap();
    let (target, _) = mesh
        .attach("target", PublicKey([2; 32]), None, false)
        .await
        .unwrap();
    let (removed, _) = mesh
        .attach(&host.to_string(), PublicKey([3; 32]), None, false)
        .await
        .unwrap();
    service
        .execute(
            "owner",
            "mesh.grant.create",
            &serde_json::to_vec(&json!({
                "name":"service-access", "from":{"Node":removed.0}, "to":{"Node":target.0},
                "both_ways":false, "ports":{"Ports":[{"protocol":"Udp","number":5540}]}
            }))
            .unwrap(),
            1_800_000_000,
        )
        .await
        .unwrap();
    let port = Port {
        protocol: Protocol::Udp,
        number: 5540,
    };
    assert!(
        mesh.config(target).await.unwrap().peers[&removed]
            .inbound
            .allows(port)
    );
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
        .fetch_one(&pool)
        .await
        .unwrap();
    // This is the public production authority transaction. The fresh host
    // removal ceremony delegates to its same commit_revocation finalizer.
    // A refused uninstall cannot be trusted to erase the removed node's key.
    EnrollmentStore::new(pool.clone())
        .revoke("owner", host, 1_800_000_001)
        .await
        .unwrap();
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(revoked);
    let after = mesh.config(target).await.unwrap();
    let still_permitted = after
        .peers
        .get(&removed)
        .is_some_and(|peer| peer.inbound.allows(port));
    assert!(
        !after.peers.contains_key(&removed),
        "revoked host remains in distributed Mesh policy: node={} key_retained={} service_permitted={still_permitted} revision_before={revision} revision_after={}",
        removed.0,
        after.peers.contains_key(&removed),
        after.version
    );
}
