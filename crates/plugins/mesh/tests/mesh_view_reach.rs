//! What a person's Mesh view contains (D327, D329, #331): a machine the viewer may reach appears under its real
//! name, the one DNS answers to; a machine the viewer may not reach is absent from every part of the view. There
//! is no placeholder name for a machine that exists but may not be named.
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_mesh::{
    api::{MeshFilter, MeshService},
    policy::model::{NodeId, PublicKey},
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

/// A non-owner person holding `mesh.manage_nodes`, limited to `scope` (`None`: every node).
async fn add_manager(pool: &SqlitePool, user: &str, scope: Option<&str>) {
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES(?,?,0,'fixture',?,?)")
        .bind(user).bind(user).bind(user).bind(user)
        .execute(pool).await.unwrap();
    let role = format!("{user}-nodes");
    sqlx::query("INSERT INTO mesh_roles(name,created_at) VALUES(?,1)")
        .bind(&role)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO mesh_role_actions(role_name,action,scope_tag) VALUES(?,'mesh.manage_nodes',?)",
    )
    .bind(&role)
    .bind(scope)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO mesh_user_roles(user_id,role_name) VALUES(?,?)")
        .bind(user)
        .bind(&role)
        .execute(pool)
        .await
        .unwrap();
}

async fn tag(pool: &SqlitePool, tag: &str, node: NodeId) {
    sqlx::query("INSERT INTO mesh_tags(name,created_at) VALUES(?,1) ON CONFLICT DO NOTHING")
        .bind(tag)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mesh_tag_members(tag_name,node_id) VALUES(?,?)")
        .bind(tag)
        .bind(i64::try_from(node.0).unwrap())
        .execute(pool)
        .await
        .unwrap();
}

/// Two machines that report their own hostnames, `lab07` in tag `dev` and `lab08` in tag `prod`, plus the server.
async fn fixture() -> (MeshService, NodeId, NodeId) {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    add_host(&pool, B, "root@10.69.69.6").await;
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    let (dev, _) = store
        .attach_named(A, PublicKey([10; 32]), None, false, Some("lab07"))
        .await
        .unwrap();
    let (prod, _) = store
        .attach_named(B, PublicKey([11; 32]), None, false, Some("lab08"))
        .await
        .unwrap();
    tag(&pool, "dev", dev).await;
    tag(&pool, "prod", prod).await;
    add_manager(&pool, "dev-admin", Some("dev")).await;
    add_manager(&pool, "guest", None).await;
    (service, dev, prod)
}

async fn view(service: &MeshService, actor: &str) -> String {
    let snapshot = service
        .list(actor, MeshFilter::default(), NOW)
        .await
        .unwrap();
    serde_json::to_string(&snapshot).unwrap()
}

/// A reported hostname is the machine's name for every viewer who may see the machine: the same string DNS
/// answers to, never a label built from the node id.
#[tokio::test]
async fn a_viewer_who_may_see_a_machine_reads_its_real_name() {
    let (service, _, _) = fixture().await;
    let guest = view(&service, "guest").await;
    for name in ["monitor01", "lab07", "lab08"] {
        assert!(guest.contains(&format!("\"host\":\"{name}\"")), "{guest}");
    }
    let scoped = view(&service, "dev-admin").await;
    assert!(scoped.contains("\"host\":\"lab07\""), "{scoped}");
}

/// A machine outside the viewer's scope is not in the view at all: no node, no name, no tag, no placeholder.
#[tokio::test]
async fn a_machine_the_viewer_may_not_reach_is_absent_from_their_view() {
    let (service, dev, prod) = fixture().await;
    let snapshot = service
        .list("dev-admin", MeshFilter::default(), NOW)
        .await
        .unwrap();
    let ids: Vec<NodeId> = snapshot.nodes.iter().map(|node| node.node.id).collect();
    assert_eq!(ids, [dev], "the scoped view lists other machines: {ids:?}");
    assert!(snapshot.tags.iter().all(|tag| tag.name == "dev"));
    let text = serde_json::to_string(&snapshot).unwrap();
    for hidden in ["lab08", "monitor01", "prod"] {
        assert!(!text.contains(hidden), "{hidden} leaked into {text}");
    }
    assert!(!text.contains(&format!("\"id\":{}", prod.0)), "{text}");
}

/// No view invents a name for a machine it may not name.
#[tokio::test]
async fn no_view_contains_an_unnamed_projection() {
    let (service, _, _) = fixture().await;
    for actor in ["owner", "guest", "dev-admin"] {
        let text = view(&service, actor).await;
        assert!(!text.contains("unnamed-"), "{actor}: {text}");
    }
}
