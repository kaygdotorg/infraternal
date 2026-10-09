//! Reproduce reuse of deleted stable node identities by delayed commands [D180].
use super::*;

#[tokio::test]

async fn review_deleted_node_identity_is_not_reused() {
    let fixture = Fixture::new().await;
    let service = &fixture.service;
    let removed = enroll(service, "old-host", 1).await;
    call(
        service,
        OWNER,
        "mesh.node.delete",
        json!({"node_id":removed}),
        NOW,
    )
    .await
    .unwrap();
    let replacement = enroll(service, "new-host", 2).await;
    let delayed = call(
        service,
        OWNER,
        "mesh.node.rename",
        json!({"node_id":removed,"name":"stale-edit"}),
        NOW,
    )
    .await;
    let snapshot = service
        .list(OWNER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    println!(
        "removed={removed}; replacement={replacement}; delayed={delayed:?}; current_host={}",
        snapshot.nodes[0].node.host
    );
    assert_eq!(delayed, Err(MeshApiError::NotFound));
    assert_eq!(snapshot.nodes[0].node.host, "new-host");
    fixture.cleanup().await;
    assert_ne!(
        removed, replacement,
        "A stable node reference must not become a different host after deletion"
    );
}

#[tokio::test]
async fn retired_identity_survives_database_reopen_and_exhaustion_is_atomic() {
    let fixture = Fixture::new().await;
    let removed = enroll(&fixture.service, "retired-host", 4).await;
    call(
        &fixture.service,
        OWNER,
        "mesh.node.delete",
        json!({"node_id":removed}),
        NOW,
    )
    .await
    .unwrap();
    fixture.pool.close().await;
    let options = SqliteConnectOptions::new()
        .filename(&fixture.path)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let service = MeshService::new(pool.clone());
    let replacement = enroll(&service, "replacement-host", 5).await;
    assert!(replacement > removed);
    assert_eq!(
        call(
            &service,
            OWNER,
            "mesh.node.observe",
            json!({"node_id":removed}),
            NOW
        )
        .await,
        Err(MeshApiError::NotFound)
    );
    sqlx::query("UPDATE mesh_state SET node_id_high_water=?")
        .bind(i64::MAX)
        .execute(&pool)
        .await
        .unwrap();
    let before = service
        .list(OWNER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    let key = [6_u8; 32];
    assert_eq!(
        call(
            &service,
            OWNER,
            "mesh.node.enroll",
            json!({"name":"overflow-host","public_key":key}),
            NOW
        )
        .await,
        Err(MeshApiError::Conflict)
    );
    assert_eq!(
        service
            .list(OWNER, MeshFilter::default(), NOW)
            .await
            .unwrap(),
        before
    );
    pool.close().await;
    fixture.cleanup().await;
}

#[tokio::test]
async fn identity_migration_preserves_inventory_and_retired_audit_ids() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut old = sqlx::migrate!("./migrations");
    old.migrations
        .to_mut()
        .retain(|migration| migration.version <= 12);
    old.run(&pool).await.unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,?,1,'fixture',?,'Legacy')").bind(OWNER).bind(OWNER).bind(OWNER).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO mesh_nodes(id,name,public_key) VALUES (7,'existing-host',?)")
        .bind([7_u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mesh_tags(name,created_at) VALUES ('prod',?)")
        .bind(NOW)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mesh_tag_members(tag_name,node_id) VALUES ('prod',7)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mesh_audit(user_id,action,resource,revision,occurred_at,detail_json) VALUES (?,'mesh.node.enroll','retired-host',1,?,?)").bind(OWNER).bind(NOW).bind(json!({"node_id":71,"name":"retired-host"}).to_string()).execute(&pool).await.unwrap();
    sqlx::query("UPDATE mesh_state SET revision=1")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let service = MeshService::new(pool.clone());
    let next = enroll(&service, "new-host", 8).await;
    assert_eq!(next, 72);
    let snapshot = service
        .list(OWNER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    assert_eq!(snapshot.nodes[0].node.id.0, 7);
    assert_eq!(snapshot.tags[0].members[0].0, 7);
    pool.close().await;
}
