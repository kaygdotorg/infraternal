//! Regressions for inventory hostnames, IP-added hosts, and live Mesh renames.
use super::*;

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

    assert_eq!(
        source.list("owner", None).await.unwrap()["hosts"][0]["name"],
        "unnamed"
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
