//! Round-4 regression proofs for Mesh name privacy, refusal atomicity and keepalive inference (#236).
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_mesh::{
    api::{MeshApiError, MeshFilter, MeshService},
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
    if let Some(scope) = scope {
        sqlx::query("INSERT INTO mesh_tags(name,created_at) VALUES(?,1) ON CONFLICT DO NOTHING")
            .bind(scope)
            .execute(pool)
            .await
            .unwrap();
    }
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

async fn rename(
    service: &MeshService,
    actor: &str,
    node: NodeId,
    name: &str,
) -> Result<(), MeshApiError> {
    service
        .execute(
            actor,
            "mesh.node.rename",
            &serde_json::to_vec(&serde_json::json!({"node_id":node.0,"name":name})).unwrap(),
            NOW,
        )
        .await
        .map(drop)
}

async fn name_of(pool: &SqlitePool, node: NodeId) -> String {
    sqlx::query_scalar("SELECT name FROM mesh_nodes WHERE id=?")
        .bind(i64::try_from(node.0).unwrap())
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The global-manager proof from round 3 does not cover a manager who can name their own nodes but cannot
/// rename the hidden holder. A browser user need not be a Mesh member and cannot use its private DNS.
#[tokio::test]
async fn a_scoped_manager_cannot_confirm_a_hidden_reported_hostname() {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    add_host(&pool, B, "root@10.69.69.6").await;
    add_manager(&pool, "dev-admin", Some("dev")).await;
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    let (hidden, _) = store
        .attach_named(A, PublicKey([10; 32]), None, false, Some("private-machine"))
        .await
        .unwrap();
    let (own, _) = store
        .attach_named(B, PublicKey([11; 32]), None, false, None)
        .await
        .unwrap();
    tag(&pool, "prod", hidden).await;
    tag(&pool, "dev", own).await;
    let visible = service
        .list("dev-admin", MeshFilter::default(), NOW)
        .await
        .unwrap();
    assert!(visible.nodes.iter().all(|node| node.node.id != hidden));
    let unused = rename(&service, "dev-admin", own, "private-machinf").await;
    let correct = rename(&service, "dev-admin", own, "private-machine").await;
    assert_eq!(
        correct, unused,
        "a correct hidden-hostname guess and an unused name differ"
    );
}

/// A refused move must leave inventory, audit and revision intact, including the automatic rename performed
/// before authorization. The next query reacquires the sole connection, so it observes the queued rollback.
#[tokio::test]
async fn evidence_a_refused_move_rolls_back_inventory_audit_and_revision() {
    let pool = pool().await;
    add_host(&pool, A, "root@minipc01").await;
    add_host(&pool, B, "root@10.69.69.6").await;
    add_manager(&pool, "dev-admin", Some("dev")).await;
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    let (hidden, _) = store
        .attach_named(A, PublicKey([10; 32]), None, false, None)
        .await
        .unwrap();
    let (own, _) = store
        .attach_named(B, PublicKey([11; 32]), None, false, None)
        .await
        .unwrap();
    tag(&pool, "prod", hidden).await;
    tag(&pool, "dev", own).await;
    let before = name_of(&pool, own).await;
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state")
        .fetch_one(&pool)
        .await
        .unwrap();
    let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM mesh_audit")
        .fetch_one(&pool)
        .await
        .unwrap();
    let mut changes = service.subscribe();
    assert_eq!(
        rename(&service, "dev-admin", own, "minipc01").await,
        Err(MeshApiError::Conflict)
    );
    assert_eq!(name_of(&pool, hidden).await, "minipc01");
    assert_eq!(name_of(&pool, own).await, before);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT revision FROM mesh_state")
            .fetch_one(&pool)
            .await
            .unwrap(),
        revision
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM mesh_audit")
            .fetch_one(&pool)
            .await
            .unwrap(),
        audit
    );
    assert!(matches!(
        changes.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

/// The server hostname yields only to someone already allowed to rename that server node directly. Global
/// node management supplies that authority; an ordinary member or a manager of a different tag does not.
#[tokio::test]
async fn evidence_server_hostname_moves_only_with_server_rename_authority() {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    add_manager(&pool, "dev-admin", Some("dev")).await;
    add_manager(&pool, "global-admin", None).await;
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    let (server, _) = store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    let (own, _) = store
        .attach_named(A, PublicKey([10; 32]), None, false, None)
        .await
        .unwrap();
    tag(&pool, "dev", own).await;
    assert_eq!(
        rename(&service, "dev-admin", own, "monitor01").await,
        Err(MeshApiError::Conflict)
    );
    assert_eq!(name_of(&pool, server).await, "monitor01");
    assert_eq!(
        rename(&service, "global-admin", own, "monitor01").await,
        Ok(())
    );
    assert_eq!(name_of(&pool, server).await, "monitor01-2");
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    assert_eq!(name_of(&pool, server).await, "monitor01-2");
    // The same manager could rename the server directly, so this did not add authority.
    assert_eq!(
        rename(&service, "global-admin", server, "control-host").await,
        Ok(())
    );
}

/// Execute the documented SQL against `SQLx`'s actual schema, with both migrators, rather than checking only
/// SQLite syntax. The version-25 rename updates only `name` (api.rs at 895bcdd23:983), so its choice must
/// survive rolling forward even though it cannot maintain the newer `name_source` and `name_claim` columns.
#[tokio::test]
async fn a_name_chosen_while_rewound_survives_rolling_forward_and_reattaching() {
    let pool = pool().await;
    add_host(&pool, A, "root@minipc01").await;
    let service = MeshService::new(pool.clone());
    let (node, _) = service
        .dataplane()
        .attach_named(A, PublicKey([10; 32]), None, false, None)
        .await
        .unwrap();
    let original: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version,checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    let runbook = include_str!("../../../../docs/operations/deploy.md");
    let steps: Vec<&str> = runbook
        .split("```sql\n")
        .skip(1)
        .map(|part| part.split("```").next().unwrap())
        .collect();
    assert_eq!(steps.len(), 2);
    sqlx::raw_sql(steps[0]).execute(&pool).await.unwrap();
    let mut old = sqlx::migrate!("../../infraternal-server/migrations");
    old.migrations
        .to_mut()
        .retain(|migration| migration.version <= 25);
    old.run(&pool).await.unwrap();
    sqlx::query("UPDATE mesh_nodes SET name='during-rewind' WHERE id=?")
        .bind(i64::try_from(node.0).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(steps[1]).execute(&pool).await.unwrap();
    sqlx::migrate!("../../infraternal-server/migrations")
        .run(&pool)
        .await
        .unwrap();
    assert_eq!(name_of(&pool, node).await, "during-rewind");
    let restored: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version,checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(restored, original);
    service
        .dataplane()
        .attach_named(A, PublicKey([10; 32]), None, false, None)
        .await
        .unwrap();
    assert_eq!(
        name_of(&pool, node).await,
        "during-rewind",
        "rolling forward and reconnecting erased the name chosen on the previous release"
    );
}
