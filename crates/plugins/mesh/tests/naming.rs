//! Automatic Mesh node names are audited, yield to the owner's names, and hide hostnames from viewers without
//! host facts (#236, break-it review findings 1, 4 and 9).
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_mesh::{
    api::{MeshApiError, MeshFilter, MeshService},
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

/// A Mesh viewer who is not the owner and may see every machine reads the same names as the owner, reported
/// hostnames included: the name is the one DNS answers to, and there is no projected label (D327, D329, #331).
#[tokio::test]
async fn a_manager_who_may_see_a_machine_reads_its_real_name() {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    add_host(&pool, B, "root@minipc01").await;
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('guest','guest',0,'fixture','guest','Guest')").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO mesh_roles(name,created_at) VALUES('nodes',1)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mesh_role_actions(role_name,action,scope_tag) VALUES('nodes','mesh.manage_nodes',NULL)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mesh_user_roles(user_id,role_name) VALUES('guest','nodes')")
        .execute(&pool)
        .await
        .unwrap();
    let service = MeshService::new(pool);
    let store = service.dataplane();
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    store
        .attach_named(A, PublicKey([10; 32]), None, false, Some("lab07"))
        .await
        .unwrap();
    store
        .attach_named(B, PublicKey([11; 32]), None, false, Some("ignored"))
        .await
        .unwrap();
    assert_eq!(
        names(&service, "owner").await,
        ["monitor01", "lab07", "minipc01"]
    );
    assert_eq!(
        names(&service, "guest").await,
        ["monitor01", "lab07", "minipc01"]
    );
}

async fn rename(service: &MeshService, node: u64, name: &str) -> Result<(), MeshApiError> {
    let input = serde_json::json!({"node_id":node,"name":name});
    service
        .execute(
            "owner",
            "mesh.node.rename",
            &serde_json::to_vec(&input).unwrap(),
            NOW,
        )
        .await
        .map(drop)
}

/// `server` belongs to the server's node: a person cannot give it to a remote machine (the refusal says so
/// plainly), and the server's node itself may still be called `server`. The server's hostname is an automatic
/// name and yields to a person like any other (round-3 review: a refusal would confirm the hidden hostname to
/// viewers who see the server only as `server`).
#[tokio::test]
async fn the_servers_names_are_kept_for_the_server() {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    let service = MeshService::new(pool);
    let store = service.dataplane();
    let (server, _) = store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    let (a, _) = store
        .attach_named(A, PublicKey([10; 32]), None, false, None)
        .await
        .unwrap();
    assert_eq!(
        rename(&service, a.0, "server").await,
        Err(MeshApiError::Reserved)
    );
    assert_eq!(rename(&service, a.0, "monitor01").await, Ok(()));
    assert_eq!(names(&service, "owner").await, ["monitor01-2", "monitor01"]);
    // The server keeps its suffix across a restart; a person's name is never taken back.
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    assert_eq!(names(&service, "owner").await, ["monitor01-2", "monitor01"]);
    assert_eq!(rename(&service, server.0, "server").await, Ok(()));
    assert_eq!(names(&service, "owner").await, ["server", "monitor01"]);
}

/// A person outranks every automatic name: renaming a node to a name another host's record gave it moves that
/// node aside (audited as automatic), and only another person's name refuses.
#[tokio::test]
async fn a_person_takes_an_automatic_name_and_the_machine_moves_aside() {
    let pool = pool().await;
    add_host(&pool, A, "root@minipc01").await;
    add_host(&pool, B, "root@10.69.69.6").await;
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    store
        .attach_named(A, PublicKey([10; 32]), None, false, None)
        .await
        .unwrap();
    let (b, _) = store
        .attach_named(B, PublicKey([11; 32]), None, false, None)
        .await
        .unwrap();
    let before = audits_len(&pool).await;
    assert_eq!(rename(&service, b.0, "minipc01").await, Ok(()));
    assert_eq!(
        names(&service, "owner").await,
        ["monitor01", "minipc01-2", "minipc01"]
    );
    assert_eq!(audits_len(&pool).await, before + 1);
    // The record's machine restarts: it keeps its suffix, and the person's name stays.
    store
        .attach_named(A, PublicKey([10; 32]), None, false, None)
        .await
        .unwrap();
    assert_eq!(
        names(&service, "owner").await,
        ["monitor01", "minipc01-2", "minipc01"]
    );
    // A name a person chose is final: another person cannot take it.
    let a = store.node_for_host(A).await.unwrap();
    assert_eq!(
        rename(&service, a.0, "minipc01").await,
        Err(MeshApiError::Conflict)
    );
}

async fn node_names(pool: &SqlitePool) -> Vec<(String, String)> {
    sqlx::query_as("SELECT name,name_source FROM mesh_nodes ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap()
}

/// D339: the reported hostname is the name; two machines with the same hostname get a short suffix, and each keeps
/// its own across restarts whatever order they reconnect in.
#[tokio::test]
async fn the_reported_hostname_is_the_name_and_a_collision_suffix_is_stable() {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    add_host(&pool, B, "root@10.69.69.6").await;
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    for (host, key) in [(A, 10), (B, 11)] {
        store
            .attach_named(host, PublicKey([key; 32]), None, false, Some("RaspberryPi"))
            .await
            .unwrap();
    }
    assert_eq!(
        names(&service, "owner").await,
        ["raspberrypi", "raspberrypi-2"]
    );
    let audited = audits_len(&pool).await;
    // Restarts in the opposite order rename nothing.
    for (host, key) in [(B, 11), (A, 10), (B, 11), (A, 10)] {
        store
            .attach_named(host, PublicKey([key; 32]), None, false, Some("raspberrypi"))
            .await
            .unwrap();
    }
    assert_eq!(
        names(&service, "owner").await,
        ["raspberrypi", "raspberrypi-2"]
    );
    assert_eq!(audits_len(&pool).await, audited);
}

/// D339: an empty name or `localhost` falls back to `<os>-<first 6 characters of the id>`; the OS word is the
/// machine's reported OS; a second machine with the same six characters takes `-2`, and keeps it.
#[tokio::test]
async fn an_empty_or_localhost_name_falls_back_to_os_and_id() {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    add_host(&pool, B, "root@10.69.69.6").await;
    sqlx::query("UPDATE remote_host_bootstrap SET os='macOS 26.5' WHERE host_id=?")
        .bind(uuid::Uuid::parse_str(A).unwrap().as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    store
        .attach_named(A, PublicKey([10; 32]), None, false, Some("localhost"))
        .await
        .unwrap();
    store
        .attach_named(B, PublicKey([11; 32]), None, false, Some(""))
        .await
        .unwrap();
    assert_eq!(
        names(&service, "owner").await,
        ["macos-000000", "host-000000"]
    );
    // Two unknown-OS machines whose ids share the first six characters.
    let c = "00000000-0000-4000-8000-00000000000c";
    add_host(&pool, c, "root@10.69.69.7").await;
    store
        .attach_named(c, PublicKey([12; 32]), None, false, Some("localhost"))
        .await
        .unwrap();
    assert_eq!(
        names(&service, "owner").await,
        ["macos-000000", "host-000000", "host-000000-2"]
    );
    for (host, key) in [(c, 12), (B, 11), (c, 12)] {
        store
            .attach_named(host, PublicKey([key; 32]), None, false, None)
            .await
            .unwrap();
    }
    assert_eq!(
        names(&service, "owner").await,
        ["macos-000000", "host-000000", "host-000000-2"]
    );
    assert!(
        node_names(&pool)
            .await
            .iter()
            .all(|(_, source)| source == "placeholder")
    );
}

/// D339: a machine gets its real name (and with it its DNS name, which only `reported`/`record` names have) as
/// soon as it reports one, and a later empty report never takes it back to the fallback.
#[tokio::test]
async fn a_machine_leaves_its_fallback_as_soon_as_it_has_a_real_name() {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    store
        .attach_named(A, PublicKey([10; 32]), None, false, None)
        .await
        .unwrap();
    assert_eq!(
        node_names(&pool).await,
        [("host-000000".to_owned(), "placeholder".to_owned())]
    );
    store
        .attach_named(A, PublicKey([10; 32]), None, false, Some("minipc01"))
        .await
        .unwrap();
    assert_eq!(
        node_names(&pool).await,
        [("minipc01".to_owned(), "reported".to_owned())]
    );
    store
        .attach_named(A, PublicKey([10; 32]), None, false, Some("localhost"))
        .await
        .unwrap();
    assert_eq!(
        node_names(&pool).await,
        [("minipc01".to_owned(), "reported".to_owned())]
    );
}

/// D339: a name a person picked always wins, including one that looks like the old placeholder, and a machine's
/// report never replaces it.
#[tokio::test]
async fn a_hand_picked_name_always_wins() {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    let (a, _) = store
        .attach_named(A, PublicKey([10; 32]), None, false, None)
        .await
        .unwrap();
    assert_eq!(rename(&service, a.0, "unnamed-3").await, Ok(()));
    for reported in [Some("minipc01"), Some("localhost"), None] {
        store
            .attach_named(A, PublicKey([10; 32]), None, false, reported)
            .await
            .unwrap();
    }
    assert_eq!(
        node_names(&pool).await,
        [("unnamed-3".to_owned(), "hand".to_owned())]
    );
}

/// D339: a stored `unnamed` / `unnamed-<n>` label that a database still carries is replaced at the machine's next
/// attach, and a hostname that really is `unnamed` is kept like any other.
#[tokio::test]
async fn legacy_unnamed_labels_are_replaced_and_a_real_unnamed_hostname_is_kept() {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    add_host(&pool, B, "root@10.69.69.6").await;
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    for (host, key) in [(A, 10), (B, 11)] {
        store
            .attach_named(host, PublicKey([key; 32]), None, false, None)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE mesh_nodes SET name='unnamed-7' WHERE dataplane_host=?")
        .bind(A)
        .execute(&pool)
        .await
        .unwrap();
    store
        .attach_named(A, PublicKey([10; 32]), None, false, None)
        .await
        .unwrap();
    store
        .attach_named(B, PublicKey([11; 32]), None, false, Some("unnamed"))
        .await
        .unwrap();
    assert_eq!(
        node_names(&pool).await,
        [
            ("host-000000".to_owned(), "placeholder".to_owned()),
            ("unnamed".to_owned(), "reported".to_owned())
        ]
    );
}
