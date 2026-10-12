//! Refuses alternate UUID spellings before they can create multiple host authority bindings [166,235], #173.
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used)]
use infraternal_plugin_mesh::{
    api::{MeshApiError, MeshService},
    policy::model::PublicKey,
};
#[tokio::test]
async fn enrollment_requires_canonical_host_uuid_spelling() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("../../infraternal-server/migrations")
        .run(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner')").execute(&pool).await.unwrap();
    let host = uuid::Uuid::from_u128(42);
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)").bind(host.as_bytes().as_slice()).execute(&pool).await.unwrap();
    let service = MeshService::new(pool.clone());
    let canonical = host.to_string();
    for alternate in [
        canonical.to_uppercase(),
        canonical.replace('-', ""),
        format!("{{{canonical}}}"),
        format!("urn:uuid:{canonical}"),
    ] {
        let result=service.execute("owner","mesh.node.enroll",&serde_json::to_vec(&serde_json::json!({"name":"invalid-binding","public_key":PublicKey([3;32]),"host_id":alternate})).unwrap(),1_800_000_000).await;
        assert_eq!(
            result,
            Err(MeshApiError::InvalidInput),
            "alternate host binding was not refused"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM mesh_nodes")
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
    }
    assert!(service.execute("owner","mesh.node.enroll",&serde_json::to_vec(&serde_json::json!({"name":"canonical-binding","public_key":PublicKey([3;32]),"host_id":canonical})).unwrap(),1_800_000_000).await.is_ok());
}
