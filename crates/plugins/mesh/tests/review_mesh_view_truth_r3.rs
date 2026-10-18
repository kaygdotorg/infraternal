//! Break-it delta review, round 3, of the honest Mesh view (#236) at ea6ed45e3: a person's name moving automatic
//! holders aside (`make_room`), the server's reserved names, and presence read from the handshake age.
//!
//! Every test here states a claim or an invariant of the branch and FAILS on ea6ed45e3.
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_mesh::{
    api::{MeshApiError, MeshFilter, MeshService},
    policy::model::{NodeId, PublicKey},
    presence::{PeerRow, Tracker},
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

/// A manager limited to the `dev` tag may rename only `dev` nodes (`rename_node` authorizes against the target's
/// tags). Since b101071e1 the same rename also renames the node that held the name, here a `prod` node the owner
/// added as `minipc01`: the authorization covers the target only, and the moved node's tags are added afterwards,
/// for the change notice alone. The scoped manager thus changes a node outside their scope and takes its name,
/// the name the rest of the mesh (and every node's config, `Store::config`) knows that machine by.
#[tokio::test]
async fn a_scoped_manager_cannot_rename_a_node_outside_their_scope_by_taking_its_name() {
    let pool = pool().await;
    add_host(&pool, A, "root@minipc01").await;
    add_host(&pool, B, "root@10.69.69.6").await;
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    let (prod, _) = store
        .attach_named(A, PublicKey([10; 32]), None, false, None)
        .await
        .unwrap();
    let (dev, _) = store
        .attach_named(B, PublicKey([11; 32]), None, false, None)
        .await
        .unwrap();
    tag(&pool, "prod", prod).await;
    tag(&pool, "dev", dev).await;
    add_manager(&pool, "dev-admin", Some("dev")).await;
    // Sanity: the scoped manager cannot rename the prod node directly.
    assert_eq!(
        rename(&service, "dev-admin", prod, "elsewhere").await,
        Err(MeshApiError::Denied)
    );
    let outcome = rename(&service, "dev-admin", dev, "minipc01").await;
    assert_eq!(
        name_of(&pool, prod).await,
        "minipc01",
        "a dev-scoped manager renamed the prod node (their own rename returned {outcome:?})"
    );
}

/// `make_room`'s own rule: "a name a machine reported (a host fact, hidden from viewers who are not the owner)
/// never refuses anything", so a refusal is no oracle. The server's hostname is such a host fact: a non-owner sees
/// the server's node only as `server` (`decode_host`). Yet renaming a node to the server's hostname answers
/// "reserved for the server", while an unused name succeeds, so any non-owner manager can confirm a guess of the
/// server's hidden hostname with one call (and undo the rename with another).
#[tokio::test]
async fn a_non_owner_cannot_confirm_the_servers_hidden_hostname() {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    add_manager(&pool, "guest", None).await;
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    let (a, _) = store
        .attach_named(A, PublicKey([10; 32]), None, false, None)
        .await
        .unwrap();
    let seen: Vec<String> = service
        .list("guest", MeshFilter::default(), NOW)
        .await
        .unwrap()
        .nodes
        .into_iter()
        .map(|node| node.node.host)
        .collect();
    assert!(
        !seen.iter().any(|name| name == "monitor01"),
        "precondition: {seen:?}"
    );
    let wrong_guess = rename(&service, "guest", a, "monitor02").await;
    let right_guess = rename(&service, "guest", a, "monitor01").await;
    assert_eq!(
        right_guess.is_ok(),
        wrong_guess.is_ok(),
        "the server's hidden hostname answers {right_guess:?}, a wrong guess {wrong_guess:?}"
    );
}

/// The automatic rename a person's rename causes is written with the owner's user id (`audit_renames` picks the
/// first owner), so the audit log says the owner moved the node when a different person did. The change's own
/// `mesh.node.rename` row names the real actor; the move should too.
#[tokio::test]
async fn a_node_moved_aside_by_a_person_is_audited_under_that_person() {
    let pool = pool().await;
    add_host(&pool, A, "root@minipc01").await;
    add_host(&pool, B, "root@10.69.69.6").await;
    add_manager(&pool, "guest", None).await;
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
    assert_eq!(rename(&service, "guest", b, "minipc01").await, Ok(()));
    let actors: Vec<String> =
        sqlx::query_scalar("SELECT user_id FROM mesh_audit WHERE action='mesh.node.name'")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(actors, ["guest"]);
}

fn row(handshake: u64, received: u64) -> PeerRow {
    PeerRow {
        node: NodeId(3),
        handshake,
        received,
        keepalive: 25,
    }
}

/// The case round 2 recorded as the owner's question: a host with keepalives on both ends that dies with a fresh
/// handshake. Round 2 read it offline 55–60 s after its last byte; 615ec1deb made received bytes a reason for
/// online only, so it now stays online until the handshake leaves the 155 s rekey window: here 145 s after it
/// died. The peer's own sending habit is observable (its bytes moved every keepalive until it died), so the quiet
/// rule can still apply to peers that showed a keepalive of their own without flashing quiet peers offline.
#[test]
fn a_dead_peer_that_sent_its_own_keepalives_is_offline_within_a_minute() {
    let start = 1_800_000_000;
    let mut tracker = Tracker::default();
    // Rekey at 0, a keepalive every 25 s through 100; then the host dies.
    let mut received = 0;
    for at in (0..=100).step_by(5) {
        if at % 25 == 0 {
            received += 32;
        }
        tracker.record(Some((true, vec![row(start, received)])), start + at);
        assert!(tracker.live(None, start + at).contains_key(&NodeId(3)));
    }
    let mut gone = None;
    for at in (105..=180).step_by(5) {
        tracker.record(Some((true, vec![row(start, received)])), start + at);
        if gone.is_none() && !tracker.live(None, start + at).contains_key(&NodeId(3)) {
            gone = Some(at - 100);
        }
    }
    // Dies at 10 s into a fresh session instead: the handshake window keeps it online for ~145 s.
    let mut tracker = Tracker::default();
    tracker.record(Some((true, vec![row(start, 32)])), start);
    tracker.record(Some((true, vec![row(start, 64)])), start + 5);
    let mut fresh_gone = None;
    for at in (10..=180).step_by(5) {
        tracker.record(Some((true, vec![row(start, 64)])), start + at);
        if fresh_gone.is_none() && !tracker.live(None, start + at).contains_key(&NodeId(3)) {
            fresh_gone = Some(at - 5);
        }
    }
    let fresh_gone = fresh_gone.expect("never went offline");
    assert!(
        fresh_gone <= 60,
        "offline {fresh_gone} s after its last byte (late in the session: {gone:?} s)"
    );
}

/// The gap the module docs accept: an idle peer without its own keepalive that started the session. As responder
/// the server does not rekey at 120 s; the peer rekeys when a server keepalive reaches it after 165 s (`WireGuard`'s
/// receive-side rule for an initiator). Here that is at 170 s. The session is live throughout, yet the node reads
/// offline from 160 s, and every viewer gets two resyncs for it. 155 s is not the bound for this direction.
#[test]
fn an_idle_peer_that_started_its_session_stays_online_until_it_rekeys() {
    let start = 1_800_000_000;
    let mut tracker = Tracker::default();
    let mut offline = Vec::new();
    for at in (0..=340).step_by(5) {
        let last_rekey = if at >= 170 { start + 170 } else { start };
        let received = if at >= 170 { 148 + 148 } else { 148 };
        tracker.record(Some((true, vec![row(last_rekey, received)])), start + at);
        if !tracker.live(None, start + at).contains_key(&NodeId(3)) {
            offline.push(at);
        }
    }
    assert!(
        offline.is_empty(),
        "a live session read offline at seconds {offline:?}"
    );
}
