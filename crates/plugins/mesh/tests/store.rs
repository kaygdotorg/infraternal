//! Public allocation, restart and removed-host regressions against the production SQLite schema [165,166,216].
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
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
#[cfg(feature = "mesh-dns-spike")]
async fn public_origin_sets_the_default_suffix_and_origin_changes_advance_the_snapshot() {
    let pool = pool().await;
    let first = Store::with_public_origin(pool.clone(), "https://ssh.kayg.org");
    first.attach("server", key(1), None, true).await.unwrap();
    let (node, _) = first.attach("host", key(2), None, false).await.unwrap();
    let before = first.config(node).await.unwrap();
    assert_eq!(before.dns_suffix, "ssh.kayg.org");

    let restarted = Store::with_public_origin(pool, "https://mesh.kayg.org");
    let after = restarted.config(node).await.unwrap();

    assert_eq!(after.dns_suffix, "mesh.kayg.org");
    assert!(after.version > before.version);
}

#[tokio::test]
async fn publication_identity_tracks_server_public_host_across_restart() {
    let pool = pool().await;
    let first = Store::with_public_origin(pool.clone(), "https://ssh.example.test");
    first.attach("server", key(1), None, true).await.unwrap();
    let (node, _) = first.attach("host", key(2), None, false).await.unwrap();
    let before = first.config(node).await.unwrap();

    #[cfg(not(feature = "mesh-dns-spike"))]
    assert!(
        serde_json::to_value(&before)
            .unwrap()
            .get("dns_suffix")
            .is_none(),
        "public proxy naming must not enable the default-off Mesh DNS resolver"
    );
    assert_eq!(
        before.exposure.as_ref().unwrap().dns_suffix,
        "ssh.example.test"
    );

    let restarted = Store::with_public_origin(pool, "https://mesh.example.test");
    let after = restarted.config(node).await.unwrap();

    assert_eq!(
        after.exposure.as_ref().unwrap().dns_suffix,
        "mesh.example.test"
    );
    assert!(after.version > before.version);
}

#[tokio::test]
#[cfg(feature = "mesh-dns-spike")]
async fn a_fallback_named_node_is_not_published_in_mesh_dns_until_it_has_a_real_name() {
    let pool = pool().await;
    let store = Store::new(pool.clone());
    let (server, _) = store.attach("server", key(1), None, true).await.unwrap();
    let (unnamed, _) = store
        .attach("00000000-0000-4000-8000-0000000000aa", key(2), None, false)
        .await
        .unwrap();
    let (name, source): (String, String) =
        sqlx::query_as("SELECT name,name_source FROM mesh_nodes WHERE id=?")
            .bind(i64::try_from(unnamed.0).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(name, "host-000000");
    assert_eq!(source, "placeholder");

    let config = store.config(server).await.unwrap();
    assert_eq!(
        config.peers[&unnamed].outbound,
        infraternal_plugin_mesh::policy::rules::TrafficPolicy::All
    );
    assert!(!config.peer_names.contains_key(&unnamed));

    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.push(11);
    query.extend_from_slice(b"host-000000");
    query.push(8);
    query.extend_from_slice(b"internal");
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    let response = infraternal_plugin_mesh::dns::response(&query, &config)
        .unwrap()
        .unwrap();
    assert_eq!(
        hickory_proto::op::Message::from_vec(&response)
            .unwrap()
            .metadata
            .response_code,
        hickory_proto::op::ResponseCode::NXDomain
    );

    // D339: the DNS name comes as soon as the machine reports a real one.
    store
        .attach_named(
            "00000000-0000-4000-8000-0000000000aa",
            key(2),
            None,
            false,
            Some("minipc01"),
        )
        .await
        .unwrap();
    let config = store.config(server).await.unwrap();
    assert_eq!(
        config.peer_names.get(&unnamed).map(String::as_str),
        Some("minipc01")
    );
}

#[tokio::test]
async fn removed_host_cannot_restore_membership_without_authorized_enrollment() {
    let pool = pool().await;
    let store = Store::new(pool.clone());
    store.attach("server", key(1), None, true).await.unwrap();
    let (node, _) = store
        .attach("00000000-0000-4000-8000-000000000001", key(2), None, false)
        .await
        .unwrap();
    let old = store.config(node).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner')").execute(&pool).await.unwrap();
    let service = MeshService::new(pool.clone());
    let input = serde_json::to_vec(&serde_json::json!({"node_id":node.0})).unwrap();
    service
        .execute("owner", "mesh.node.delete", &input, 1_800_000_000)
        .await
        .unwrap();
    assert!(
        store
            .attach("00000000-0000-4000-8000-000000000001", key(2), None, false)
            .await
            .is_err()
    );
    assert!(
        store
            .attach("00000000-0000-4000-8000-000000000001", key(3), None, false)
            .await
            .is_err()
    );
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)")
        .bind(uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap().as_bytes().as_slice())
        .execute(&pool).await.unwrap();
    service.execute("owner", "mesh.node.enroll", &serde_json::to_vec(&serde_json::json!({"name":"reenrolled","public_key":key(3),"host_id":"00000000-0000-4000-8000-000000000001"})).unwrap(), 1_800_000_000).await.unwrap();
    let (new, _) = store
        .attach("00000000-0000-4000-8000-000000000001", key(3), None, false)
        .await
        .unwrap();
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

/// #201: a mesh disable aborts coordination workers at any await. An attach
/// dropped after its writer BEGIN was acknowledged must not leave the pooled
/// connection inside that transaction (the next writer then failed `Storage`).
#[tokio::test]
async fn attach_cancelled_at_any_await_leaves_the_store_writable() {
    use std::{future::Future, task::Poll};
    for polls in 1..=6 {
        let pool = pool().await;
        let store = Store::new(pool.clone());
        store.attach("server", key(1), None, true).await.unwrap();
        let mut attach = Box::pin(store.attach(
            "host",
            key(2),
            Some("192.0.2.1:44000".parse().unwrap()),
            false,
        ));
        for _ in 0..polls {
            if std::future::poll_fn(|cx| Poll::Ready(attach.as_mut().poll(cx).is_ready())).await {
                break;
            }
            // Let the connection worker execute and acknowledge each command.
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        drop(attach);
        let retried = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            store.attach(
                "host",
                key(2),
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
            ),
        )
        .await
        .expect("pooled connection never returned");
        assert!(
            retried.is_ok(),
            "attach after cancellation at poll {polls}: {retried:?}"
        );
    }
}
