//! An authenticated host cannot inherit another enrollment's Access grants by quoting a public key [164,166,235], #173.
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{api::MeshService, policy::model::PublicKey, store::Store};
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;

#[tokio::test]
async fn unbound_enrollment_public_key_is_not_host_authority() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("../../infraternal-server/migrations")
        .run(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner')")
        .execute(&pool).await.unwrap();
    let store = Store::new(pool.clone());
    store
        .attach("server", PublicKey([1; 32]), None, true)
        .await
        .unwrap();
    let (target, _) = store
        .attach("target", PublicKey([2; 32]), None, false)
        .await
        .unwrap();
    let service = MeshService::new(pool.clone());
    let victim = service
        .execute(
            "owner",
            "mesh.node.enroll",
            &serde_json::to_vec(&json!({
                "name": "intended-host", "public_key": PublicKey([3; 32])
            }))
            .unwrap(),
            1_800_000_000,
        )
        .await
        .unwrap()["node_id"]
        .as_u64()
        .unwrap();
    service
        .execute(
            "owner",
            "mesh.grant.create",
            &serde_json::to_vec(&json!({
                "name":"restricted-service", "from":{"Node":victim}, "to":{"Node":target.0},
                "both_ways":false, "ports":{"Ports":[{"protocol":"Udp", "number":5540}]}
            }))
            .unwrap(),
            1_800_000_000,
        )
        .await
        .unwrap();
    sqlx::query("UPDATE mesh_dataplane SET default_policy='deny'")
        .execute(&pool)
        .await
        .unwrap();
    // This key is public inventory, not a proof that the authenticated host owns it.
    let claim = store
        .attach(
            "different-authenticated-host",
            PublicKey([3; 32]),
            None,
            false,
        )
        .await;
    if let Ok((claimed, _)) = claim {
        // A subsequent ordinary key replacement makes the inherited grant usable
        // with the claimant's own private key, without editing the Access table.
        let (rotated, _) = store
            .attach(
                "different-authenticated-host",
                PublicKey([4; 32]),
                None,
                false,
            )
            .await
            .unwrap();
        let policy = store.config(rotated).await.unwrap();
        println!(
            "claimed_node={} intended_node={victim} rotated_node={} outbound_policy={:?}",
            claimed.0, rotated.0, policy.peers[&target].outbound
        );
        panic!("public enrollment key conferred another node's Access identity");
    }
    let bound: Option<String> =
        sqlx::query_scalar("SELECT dataplane_host FROM mesh_nodes WHERE id=?")
            .bind(i64::try_from(victim).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(bound.is_none());
}
