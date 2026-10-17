//! Automatic Mesh node names are audited and yield to the owner's names (#236, break-it review findings 1 and 4).
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_mesh::{
    api::{MeshFilter, MeshService},
    policy::model::PublicKey,
};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

const A: &str = "00000000-0000-4000-8000-00000000000a";
const B: &str = "00000000-0000-4000-8000-00000000000b";
const NOW: i64 = 1_800_000_000;

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
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner')").execute(&pool).await.unwrap();
    pool
}

async fn add_host(pool: &SqlitePool, host: &str, address: &str) {
    let id = uuid::Uuid::parse_str(host).unwrap();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)").bind(id.as_bytes().as_slice()).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,?)")
        .bind(id.as_bytes().as_slice())
        .bind(address)
        .execute(pool)
        .await
        .unwrap();
}

async fn names(service: &MeshService, actor: &str) -> Vec<String> {
    service
        .list(actor, MeshFilter::default(), NOW)
        .await
        .unwrap()
        .nodes
        .into_iter()
        .map(|node| node.node.host)
        .collect()
}

async fn audits(pool: &SqlitePool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT user_id,detail_json FROM mesh_audit WHERE action='mesh.node.name' ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// A machine that squats a name before the owner adds the host of that name yields when that host attaches, and
/// both automatic renames are audited.
#[tokio::test]
async fn a_squatter_yields_to_a_host_added_later_and_the_renames_are_audited() {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    store
        .attach_named(A, PublicKey([10; 32]), None, false, Some("minipc01"))
        .await
        .unwrap();
    assert_eq!(names(&service, "owner").await, ["monitor01", "minipc01"]);
    // The owner adds the real minipc01 afterwards.
    add_host(&pool, B, "root@minipc01").await;
    store
        .attach_named(B, PublicKey([11; 32]), None, false, None)
        .await
        .unwrap();
    assert_eq!(
        names(&service, "owner").await,
        ["monitor01", "minipc01-2", "minipc01"]
    );
    let audits = audits(&pool).await;
    let details: Vec<serde_json::Value> = audits
        .iter()
        .map(|(_, detail)| serde_json::from_str(detail).unwrap())
        .collect();
    assert!(audits.iter().all(|(actor, _)| actor == "owner"));
    assert_eq!(
        details
            .iter()
            .map(|detail| (
                detail["previous"].as_str().unwrap(),
                detail["name"].as_str().unwrap()
            ))
            .collect::<Vec<_>>(),
        [("minipc01", "minipc01-2")]
    );
    assert!(details.iter().all(|detail| detail["automatic"] == true));
    // Reattaching changes nothing and writes nothing.
    store
        .attach_named(A, PublicKey([10; 32]), None, false, Some("minipc01"))
        .await
        .unwrap();
    assert_eq!(audits_len(&pool).await, 1);
}

async fn audits_len(pool: &SqlitePool) -> usize {
    audits(pool).await.len()
}
