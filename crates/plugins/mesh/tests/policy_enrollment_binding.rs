//! Explicit authenticated-host enrollment and removal fences use the production schema [164,166,235], #173.
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    api::{MeshApiError, MeshService},
    policy::model::PublicKey,
    store::Store,
};
use serde_json::{Value, json};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

const HOST: &str = "00000000-0000-4000-8000-000000000001";

async fn fixture() -> (SqlitePool, MeshService) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("../../infraternal-server/migrations")
        .run(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner'),('viewer','viewer',0,'fixture','viewer','Viewer')").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)").bind(uuid::Uuid::parse_str(HOST).unwrap().as_bytes().as_slice()).execute(&pool).await.unwrap();
    let service = MeshService::new(pool.clone());
    (pool, service)
}
async fn enroll(
    service: &MeshService,
    actor: &str,
    host: &str,
    key: u8,
) -> Result<Value, MeshApiError> {
    service
        .execute(
            actor,
            "mesh.node.enroll",
            &serde_json::to_vec(
                &json!({"name":"bound-host","public_key":PublicKey([key;32]),"host_id":host}),
            )
            .unwrap(),
            1_800_000_000,
        )
        .await
}

#[tokio::test]
async fn explicit_binding_preserves_identity_and_clears_removal_only_on_enrollment() {
    let (pool, service) = fixture().await;
    let store = Store::new(pool.clone());
    store
        .attach("server", PublicKey([1; 32]), None, true)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mesh_dataplane_removed(host) VALUES(?)")
        .bind(HOST)
        .execute(&pool)
        .await
        .unwrap();
    let node = enroll(&service, "owner", HOST, 2).await.unwrap()["node_id"]
        .as_u64()
        .unwrap();
    let bound: String = sqlx::query_scalar("SELECT dataplane_host FROM mesh_nodes WHERE id=?")
        .bind(i64::try_from(node).unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(bound, HOST);
    let tombstones: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mesh_dataplane_removed")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(tombstones, 0);
    let (attached, _) = store
        .attach(HOST, PublicKey([3; 32]), None, false)
        .await
        .unwrap();
    assert_eq!(attached.0, node);
    assert_eq!(
        enroll(&service, "owner", HOST, 4).await.unwrap_err(),
        MeshApiError::Conflict
    );
}

#[tokio::test]
async fn host_binding_requires_global_authority_and_existing_unrevoked_host() {
    let (pool, service) = fixture().await;
    assert_eq!(
        enroll(&service, "viewer", HOST, 2).await.unwrap_err(),
        MeshApiError::Denied
    );
    assert_eq!(
        enroll(&service, "owner", "00000000-0000-4000-8000-000000000002", 2)
            .await
            .unwrap_err(),
        MeshApiError::NotFound
    );
    sqlx::query("UPDATE remote_hosts SET revoked_at=2")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        enroll(&service, "owner", HOST, 2).await.unwrap_err(),
        MeshApiError::NotFound
    );
    let nodes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mesh_nodes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(nodes, 0);
}

#[tokio::test]
async fn noncanonical_host_binding_is_refused() {
    let (_, service) = fixture().await;
    for host in ["server", "host", "00000000000040008000000000000001"] {
        assert_eq!(
            enroll(&service, "owner", host, 2).await.unwrap_err(),
            MeshApiError::InvalidInput
        );
    }
}
