//! Checks authorized re-enrollment against the migrated coordinator and a live kernel node [164,166], #173.
#![cfg(all(feature = "agent", feature = "server", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    api::MeshService, configuration, firewall::Firewall, node::Node, policy::model::PublicKey,
};
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;

const HOST: &str = "00000000-0000-4000-8000-000000000001";

async fn reenroll(fallback: bool) {
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
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)")
        .bind(uuid::Uuid::parse_str(HOST).unwrap().as_bytes().as_slice())
        .execute(&pool).await.unwrap();
    let service = MeshService::new(pool);
    let store = service.dataplane();
    store
        .attach("server", PublicKey([1; 32]), None, true)
        .await
        .unwrap();
    let mut node = Node::with_firewall(if fallback {
        Firewall::nf_tables()
    } else {
        Firewall::default()
    });
    let identity = node.up().unwrap();
    let (old_id, _) = store
        .attach(HOST, identity.public_key, None, false)
        .await
        .unwrap();
    let old = store.config(old_id).await.unwrap();
    for chunk in configuration::chunks(None, &old).unwrap() {
        node.chunk(chunk).unwrap();
    }
    service
        .execute(
            "owner",
            "mesh.node.delete",
            &serde_json::to_vec(&json!({"node_id":old_id.0})).unwrap(),
            1_800_000_000,
        )
        .await
        .unwrap();
    assert!(
        store
            .attach(HOST, identity.public_key, None, false)
            .await
            .is_err()
    );
    let enrolled = service
        .execute(
            "owner",
            "mesh.node.enroll",
            &serde_json::to_vec(
                &json!({"name":"reenrolled","public_key":identity.public_key,"host_id":HOST}),
            )
            .unwrap(),
            1_800_000_000,
        )
        .await
        .unwrap();
    let (new_id, _) = store
        .attach(HOST, identity.public_key, None, false)
        .await
        .unwrap();
    assert_eq!(enrolled["node_id"], new_id.0);
    assert_ne!(new_id, old_id);
    let new = store.config(new_id).await.unwrap();
    // The coordinator discards its acknowledged source when the old binding
    // disappears and sends this full snapshot. Its unit fixture accepts every
    // snapshot; this fixture uses the same Node::chunk as the shipping plugin.
    let result = configuration::chunks(None, &new)
        .unwrap()
        .into_iter()
        .try_for_each(|chunk| node.chunk(chunk).map(|_| ()));
    let retained = node.config().unwrap().node;
    node.down().unwrap();
    assert!(
        result.is_ok(),
        "authorized re-enrollment refused: old={} new={} retained={} result={result:?}",
        old_id.0,
        new_id.0,
        retained.0
    );
}

#[tokio::test]
#[ignore = "Run in a disposable user/network namespace, #173."]
async fn nft_authorized_reenrollment_reaches_the_live_node() {
    reenroll(false).await;
}

#[tokio::test]
#[ignore = "Run in a disposable user/network namespace, #173."]
async fn nf_tables_authorized_reenrollment_reaches_the_live_node() {
    reenroll(true).await;
}
