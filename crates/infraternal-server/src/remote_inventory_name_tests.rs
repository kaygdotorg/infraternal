//! Regressions for inventory hostnames, IP-added hosts, and live Mesh renames.
use super::*;

#[cfg(feature = "mesh")]
async fn add_host(pool: &SqlitePool, id: Uuid, address: &str) {
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)")
        .bind(id.as_bytes().as_slice())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,?)")
        .bind(id.as_bytes().as_slice())
        .bind(address)
        .execute(pool)
        .await
        .unwrap();
}

#[cfg(feature = "mesh")]
async fn mesh_name(pool: &SqlitePool, host: &str) -> String {
    sqlx::query_scalar("SELECT name FROM mesh_nodes WHERE dataplane_host=?")
        .bind(host)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[cfg(feature = "mesh")]
async fn mesh_names_fixture() -> (
    SqlitePool,
    Uuid,
    Uuid,
    Uuid,
    Uuid,
    infraternal_plugin_mesh::api::MeshService,
) {
    use infraternal_plugin_mesh::policy::model::PublicKey;

    let (_, pool, host) = crate::enrollment::authority::tests::enrolled().await;
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,'root@10.69.69.217')")
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let record_host = Uuid::from_u128(2);
    let duplicate_a = Uuid::from_u128(3);
    let duplicate_b = Uuid::from_u128(4);
    add_host(&pool, record_host, "root@claimed01").await;
    add_host(&pool, duplicate_a, "root@10.69.69.218").await;
    add_host(&pool, duplicate_b, "root@10.69.69.219").await;

    let mesh = infraternal_plugin_mesh::api::MeshService::new(pool.clone());
    let store = mesh.dataplane();
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("serverbox"))
        .await
        .unwrap();
    store
        .attach_named(
            &host.to_string(),
            PublicKey([2; 32]),
            None,
            false,
            Some("claimed01"),
        )
        .await
        .unwrap();
    store
        .attach_named(
            &record_host.to_string(),
            PublicKey([3; 32]),
            None,
            false,
            Some("ignored01"),
        )
        .await
        .unwrap();
    store
        .attach_named(
            &duplicate_a.to_string(),
            PublicKey([4; 32]),
            None,
            false,
            Some("duplicate01"),
        )
        .await
        .unwrap();
    store
        .attach_named(
            &duplicate_b.to_string(),
            PublicKey([5; 32]),
            None,
            false,
            Some("duplicate01"),
        )
        .await
        .unwrap();
    (pool, host, record_host, duplicate_a, duplicate_b, mesh)
}

#[tokio::test]
async fn an_ip_added_host_uses_its_cached_hostname_and_old_facts_do_not_clear_it() {
    let (_, pool, host) = crate::enrollment::authority::tests::enrolled().await;
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,'root@10.69.69.217')")
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let source = Source {
        pool,
        hosts: RemoteHosts::default(),
        #[cfg(feature = "mesh")]
        mesh: None,
    };

    // D339: no usable name yet, so `<os>-<first 6 characters of the id>`; no OS reported yet gives `host`.
    let fallback = format!("host-{}", &host.simple().to_string()[..6]);
    assert_eq!(
        source.list("owner", None).await.unwrap()["hosts"][0]["name"],
        fallback.as_str()
    );
    let changes = source
        .save_facts(host, &json!({"hostname":"MiniPC01.lan", "os":"Linux"}))
        .await;
    assert!(changes.hostname && changes.any);
    let saved = source.list("owner", None).await.unwrap();
    assert_eq!(saved["hosts"][0]["name"], "minipc01");
    assert_eq!(saved["hosts"][0]["address"], "root@10.69.69.217");

    let old_agent = source.save_facts(host, &json!({"os":"Linux"})).await;
    assert!(!old_agent.hostname);
    assert_eq!(
        source.list("owner", None).await.unwrap()["hosts"][0]["name"],
        "minipc01"
    );
}

#[cfg(feature = "mesh")]
#[tokio::test]
async fn late_hostname_inventory_renames_the_attached_mesh_node_and_notifies_viewers() {
    let (_, pool, host) = crate::enrollment::authority::tests::enrolled().await;
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,'root@10.69.69.217')")
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let mesh = infraternal_plugin_mesh::api::MeshService::new(pool.clone());
    mesh.dataplane()
        .attach(
            "server",
            infraternal_plugin_mesh::policy::model::PublicKey([1; 32]),
            None,
            true,
        )
        .await
        .unwrap();
    mesh.dataplane()
        .attach(
            &host.to_string(),
            infraternal_plugin_mesh::policy::model::PublicKey([2; 32]),
            None,
            false,
        )
        .await
        .unwrap();
    sqlx::query("UPDATE mesh_nodes SET name=?,name_source='placeholder',name_claim=NULL WHERE dataplane_host=?")
        .bind(format!("mesh-{host}"))
        .bind(host.to_string())
        .execute(&pool)
        .await
        .unwrap();
    let source = Source {
        pool: pool.clone(),
        hosts: RemoteHosts::default(),
        mesh: Some(mesh.clone()),
    };
    let mut updates = mesh.subscribe();

    let changes = source
        .apply_facts(host, &json!({"hostname":"MiniPC01.lan"}))
        .await;

    assert!(changes);
    let update = tokio::time::timeout(std::time::Duration::from_secs(1), updates.recv())
        .await
        .unwrap()
        .unwrap();
    let mesh_name: String =
        sqlx::query_scalar("SELECT name FROM mesh_nodes WHERE dataplane_host=?")
            .bind(host.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
    let inventory_name = source.list("owner", None).await.unwrap()["hosts"][0]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(mesh_name, "minipc01");
    assert_eq!(inventory_name, mesh_name);
    assert!(update.revision > 0);
}

#[cfg(feature = "mesh")]
#[tokio::test]
async fn reported_names_yield_to_records_and_collision_suffixes_and_server_identity_hold() {
    let (pool, host, record_host, duplicate_a, duplicate_b, _) = mesh_names_fixture().await;
    assert_eq!(mesh_name(&pool, &host.to_string()).await, "claimed01-2");
    assert_eq!(
        mesh_name(&pool, &record_host.to_string()).await,
        "claimed01"
    );
    assert_eq!(
        mesh_name(&pool, &duplicate_a.to_string()).await,
        "duplicate01"
    );
    assert_eq!(
        mesh_name(&pool, &duplicate_b.to_string()).await,
        "duplicate01-2"
    );
    assert_eq!(mesh_name(&pool, "server").await, "serverbox");
}

#[cfg(feature = "mesh")]
#[tokio::test]
async fn inventory_hostname_changes_publish_once_and_preserve_hand_names() {
    let (pool, host, record_host, _, _, mesh) = mesh_names_fixture().await;
    let store = mesh.dataplane();
    let record_node = store.node_for_host(&record_host.to_string()).await.unwrap();
    mesh.execute(
        "owner",
        "mesh.node.rename",
        &serde_json::to_vec(&json!({"node_id":record_node.0,"name":"hand-picked"})).unwrap(),
        1_800_000_000,
    )
    .await
    .unwrap();

    let source = Source {
        pool: pool.clone(),
        hosts: RemoteHosts::default(),
        mesh: Some(mesh.clone()),
    };
    let mut updates = mesh.subscribe();
    let before_revision: i64 =
        sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
            .fetch_one(&pool)
            .await
            .unwrap();
    let changed = source
        .apply_facts(host, &json!({"hostname":"Monitor01.lan"}))
        .await;
    assert!(changed);
    let update = tokio::time::timeout(std::time::Duration::from_secs(1), updates.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mesh_name(&pool, &host.to_string()).await, "monitor01");
    assert_eq!(update.revision, before_revision + 1);

    let unchanged = source
        .apply_facts(host, &json!({"hostname":"monitor01.other"}))
        .await;
    assert!(!unchanged);
    let after_revision: i64 =
        sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(after_revision, before_revision + 1);
    assert!(matches!(
        updates.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    let changed_hand_facts = source
        .apply_facts(record_host, &json!({"hostname":"newrecordname"}))
        .await;
    assert!(changed_hand_facts);
    assert_eq!(
        mesh_name(&pool, &record_host.to_string()).await,
        "hand-picked"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT revision FROM mesh_state WHERE singleton=1")
            .fetch_one(&pool)
            .await
            .unwrap(),
        after_revision
    );
}
