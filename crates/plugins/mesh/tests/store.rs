//! Public allocation, restart and removed-host regressions against the production SQLite schema [165,166,216].
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used)]
use infraternal_plugin_mesh::{
    api::{MeshApiError, MeshCursor, MeshService},
    dataplane::DefaultPolicy,
    policy::model::PublicKey,
    store::Store,
};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
async fn pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("../../infraternal-server/migrations")
        .run(&pool)
        .await
        .unwrap();
    pool
}
fn key(id: u64) -> PublicKey {
    let mut key = [1; 32];
    key[..8].copy_from_slice(&id.to_le_bytes());
    PublicKey(key)
}
#[tokio::test]
async fn key_replacement_preserves_identity_and_addresses_after_restart() {
    let pool = pool().await;
    let store = Store::new(pool.clone());
    store.attach("server", key(1), None, true).await.unwrap();
    let (node, changed) = store
        .attach(
            "host",
            key(2),
            Some("192.0.2.1:44000".parse().unwrap()),
            false,
        )
        .await
        .unwrap();
    assert!(changed);
    let before = store.config(node).await.unwrap();
    let default: String = sqlx::query_scalar("SELECT default_policy FROM mesh_dataplane")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        default,
        if cfg!(feature = "ee") {
            "deny"
        } else {
            "allow"
        }
    );
    let (same, changed) = store
        .attach(
            "host",
            key(2),
            Some("192.0.2.1:44000".parse().unwrap()),
            false,
        )
        .await
        .unwrap();
    assert_eq!(same, node);
    assert!(!changed);
    let (same, changed) = store
        .attach(
            "host",
            key(3),
            Some("192.0.2.2:51821".parse().unwrap()),
            false,
        )
        .await
        .unwrap();
    assert_eq!(same, node);
    assert!(changed);
    let after = Store::new(pool.clone()).config(node).await.unwrap();
    assert_eq!(before.addresses, after.addresses);
    assert!(after.version > before.version);
}
#[tokio::test]
async fn removed_host_cannot_restore_membership_without_authorized_enrollment() {
    let pool = pool().await;
    let store = Store::new(pool.clone());
    store.attach("server", key(1), None, true).await.unwrap();
    let (node, _) = store.attach("host", key(2), None, false).await.unwrap();
    let old = store.config(node).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner')").execute(&pool).await.unwrap();
    let service = MeshService::new(pool.clone());
    let input = serde_json::to_vec(&serde_json::json!({"node_id":node.0})).unwrap();
    service
        .execute("owner", "mesh.node.delete", &input, 1_800_000_000)
        .await
        .unwrap();
    assert!(store.attach("host", key(2), None, false).await.is_err());
    assert!(store.attach("host", key(3), None, false).await.is_err());
    sqlx::query("UPDATE mesh_state SET node_id_high_water=node_id_high_water+1,revision=revision+1 WHERE singleton=1").execute(&pool).await.unwrap();
    let next: i64 = sqlx::query_scalar("SELECT node_id_high_water FROM mesh_state")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mesh_nodes(id,name,public_key) VALUES(?,'reenrolled',?)")
        .bind(next)
        .bind(key(3).0.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let (new, _) = store.attach("host", key(3), None, false).await.unwrap();
    assert_ne!(new, node);
    let config = store.config(new).await.unwrap();
    assert_ne!(config.addresses, old.addresses);
}
#[tokio::test]
async fn scale_preview_pages_do_not_allocate_the_pair_matrix() {
    let pool = pool().await;
    let store = Store::new(pool.clone());
    store.attach("server", key(1), None, true).await.unwrap();
    // Bulk fixture enrollment is public and uses the same durable high-water sequence.
    let mut tx = pool.begin().await.unwrap();
    for id in 2i64..=1000 {
        sqlx::query("INSERT INTO mesh_nodes(id,name,public_key,dataplane_host) VALUES(?,?,?,?)")
            .bind(id)
            .bind(format!("node-{id}"))
            .bind(key(u64::try_from(id).unwrap()).0.as_slice())
            .bind(format!("host-{id}"))
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE mesh_state SET node_id_high_water=1000,revision=1000")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    sqlx::query("UPDATE mesh_dataplane SET default_policy='allow' WHERE singleton=1")
        .execute(&pool)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let page = store.preview_page(DefaultPolicy::Deny, None).await.unwrap();
    assert_eq!(page["total_pairs"], 998_001);
    assert!(serde_json::to_vec(&page).unwrap().len() <= 64 * 1024);
    assert_ne!(page["loses_reach"].as_array().unwrap().len(), 0);
    let cursor: MeshCursor = serde_json::from_value(page["next_cursor"].clone()).unwrap();
    let next = store
        .preview_page(DefaultPolicy::Deny, Some(cursor))
        .await
        .unwrap();
    assert_ne!(page["loses_reach"][0], next["loses_reach"][0]);
    sqlx::query("UPDATE mesh_state SET revision=revision+1")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        store.preview_page(DefaultPolicy::Deny, Some(cursor)).await,
        Err(MeshApiError::Conflict)
    ));
    println!(
        "METRIC mesh_preview nodes=1000 pairs=998001 first_two_pages_us={} bytes={} load={}",
        started.elapsed().as_micros(),
        serde_json::to_vec(&page).unwrap().len(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}

#[tokio::test]
async fn required_server_membership_cannot_be_deleted() {
    let pool = pool().await;
    let store = Store::new(pool.clone());
    let (server, _) = store.attach("server", key(1), None, true).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner')").execute(&pool).await.unwrap();
    let input = serde_json::to_vec(&serde_json::json!({"node_id":server.0})).unwrap();
    let service = MeshService::new(pool.clone());
    assert!(matches!(
        service
            .execute("owner", "mesh.node.delete", &input, 1_800_000_000)
            .await,
        Err(MeshApiError::Denied)
    ));
    assert!(store.config(server).await.is_ok());
}

#[tokio::test]
async fn absent_discovery_preserves_the_last_known_endpoint() {
    let pool = pool().await;
    let store = Store::new(pool);
    let (server, _) = store.attach("server", key(1), None, true).await.unwrap();
    let address = "192.0.2.1:44000".parse().unwrap();
    let (node, _) = store
        .attach("host", key(2), Some(address), false)
        .await
        .unwrap();
    let before = store.config(server).await.unwrap();
    let (_, changed) = store.attach("host", key(2), None, false).await.unwrap();
    assert!(
        !changed,
        "unavailable discovery must not erase the endpoint or publish a removal"
    );
    let after = store.config(server).await.unwrap();
    assert_eq!(after.version, before.version);
    assert_eq!(after.peers[&node].peer.endpoint, Some(address));
    let replacement = "192.0.2.2:51821".parse().unwrap();
    assert!(
        store
            .attach("host", key(2), Some(replacement), false)
            .await
            .unwrap()
            .1
    );
    assert_eq!(
        store.config(server).await.unwrap().peers[&node]
            .peer
            .endpoint,
        Some(replacement)
    );
}
