//! Break-it delta review, round 2, of the honest Mesh view (#236) at 6df86d28c: name provenance (migration 0026),
//! collision suffixes across restarts, who may hold the server's label, and the 55 s / 15 s presence timing.
//!
//! Tests whose name starts with `evidence_` record behaviour the review checked and found sound; they pass. Every
//! other test states a claim of the branch and FAILS on 6df86d28c.
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_mesh::{
    api::{MeshFilter, MeshService},
    policy::model::{NodeId, PublicKey},
    presence::{PeerRow, Tracker},
    store::machine_name,
};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

const A: &str = "00000000-0000-4000-8000-00000000000a";
const B: &str = "00000000-0000-4000-8000-00000000000b";
const C: &str = "00000000-0000-4000-8000-00000000000c";
const NOW: i64 = 1_800_000_000;

async fn memory() -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

async fn pool() -> SqlitePool {
    let pool = memory().await;
    sqlx::migrate!("../../infraternal-server/migrations")
        .run(&pool)
        .await
        .unwrap();
    seed_owner(&pool).await;
    pool
}

async fn seed_owner(pool: &SqlitePool) {
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner')").execute(pool).await.unwrap();
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

/// A non-owner Mesh manager (unscoped `mesh.manage_nodes`), the role a household member or a co-admin gets.
async fn add_guest_manager(pool: &SqlitePool) {
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('guest','guest',0,'fixture','guest','Guest')").execute(pool).await.unwrap();
    sqlx::query("INSERT INTO mesh_roles(name,created_at) VALUES('nodes',1)")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mesh_role_actions(role_name,action,scope_tag) VALUES('nodes','mesh.manage_nodes',NULL)")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mesh_user_roles(user_id,role_name) VALUES('guest','nodes')")
        .execute(pool)
        .await
        .unwrap();
}

async fn names(service: &MeshService, actor: &str) -> Vec<(u64, String)> {
    service
        .list(actor, MeshFilter::default(), NOW)
        .await
        .unwrap()
        .nodes
        .into_iter()
        .map(|node| (node.node.id.0, node.node.host))
        .collect()
}

async fn name_rows(pool: &SqlitePool) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as("SELECT name,name_source,dataplane_host FROM mesh_nodes ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn automatic_renames(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM mesh_audit WHERE action='mesh.node.name'")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn rename(
    service: &MeshService,
    actor: &str,
    node: u64,
    name: &str,
) -> Result<serde_json::Value, String> {
    service
        .execute(
            actor,
            "mesh.node.rename",
            &serde_json::to_vec(&serde_json::json!({"node_id":node,"name":name})).unwrap(),
            NOW,
        )
        .await
        .map_err(|error| format!("{error:?}"))
}

/// A production-shaped database at version 25 (before name provenance), as dev's attach left it: the server node
/// still `server`, two remote nodes under `mesh-<host id>`, and one node the owner renamed by hand. The owner's
/// hand-set name is the name another host's record claims, so the upgrade must suffix the record, not the person.
async fn version_25_database() -> SqlitePool {
    let pool = memory().await;
    let mut old = sqlx::migrate!("../../infraternal-server/migrations");
    old.migrations
        .to_mut()
        .retain(|migration| migration.version <= 25);
    old.run(&pool).await.unwrap();
    seed_owner(&pool).await;
    add_host(&pool, A, "root@minipc01").await;
    add_host(&pool, B, "root@10.69.69.5").await;
    add_host(&pool, C, "kayg@lab07.lan:2222").await;
    for (id, name, key, host) in [
        (1_i64, "server".to_owned(), 1_u8, "server"),
        (2, format!("mesh-{A}"), 10, A),
        (3, "minipc01".to_owned(), 11, B),
        (4, format!("mesh-{C}"), 12, C),
    ] {
        sqlx::query("INSERT INTO mesh_nodes(id,name,public_key,dataplane_host) VALUES(?,?,?,?)")
            .bind(id)
            .bind(name)
            .bind([key; 32].as_slice())
            .bind(host)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE mesh_state SET node_id_high_water=4,revision=7")
        .execute(&pool)
        .await
        .unwrap();
    pool
}

/// Upgrade of a realistic database (placeholders end as D339 fallbacks, the shared id prefix suffixed): placeholders are marked as such, the owner's hand-set name survives, the
/// first round of attaches (in an unlucky order: the host whose record collides first, the server last) names
/// every machine, and a second round in the opposite order renames nothing and audits nothing.
#[tokio::test]
async fn evidence_migrations_0026_and_0029_upgrade_a_realistic_database_without_churn() {
    let pool = version_25_database().await;
    sqlx::migrate!("../../infraternal-server/migrations")
        .run(&pool)
        .await
        .unwrap();
    assert_eq!(
        name_rows(&pool).await,
        [
            ("server".into(), "placeholder".into(), Some("server".into())),
            ("host-000000".into(), "placeholder".into(), Some(A.into())),
            ("minipc01".into(), "hand".into(), Some(B.into())),
            ("host-000000-2".into(), "placeholder".into(), Some(C.into())),
        ]
    );
    let migration_revision: i64 =
        sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
            .fetch_one(&pool)
            .await
            .unwrap();
    let migration_audits = automatic_renames(&pool).await;
    sqlx::migrate!("../../infraternal-server/migrations")
        .run(&pool)
        .await
        .unwrap();
    assert_eq!(
        name_rows(&pool).await,
        [
            ("server".into(), "placeholder".into(), Some("server".into())),
            ("host-000000".into(), "placeholder".into(), Some(A.into())),
            ("minipc01".into(), "hand".into(), Some(B.into())),
            ("host-000000-2".into(), "placeholder".into(), Some(C.into())),
        ]
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT revision FROM mesh_state WHERE singleton=1")
            .fetch_one(&pool)
            .await
            .unwrap(),
        migration_revision
    );
    assert_eq!(automatic_renames(&pool).await, migration_audits);
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    let round = |order: [(&'static str, u8, Option<&'static str>); 4]| {
        let store = store.clone();
        async move {
            for (host, key, reported) in order {
                store
                    .attach_named(host, PublicKey([key; 32]), None, host == "server", reported)
                    .await
                    .unwrap();
            }
        }
    };
    round([
        (A, 10, Some("minipc01")),
        (C, 12, Some("lab07")),
        (B, 11, Some("raspberrypi")),
        ("server", 1, Some("monitor01")),
    ])
    .await;
    let named: Vec<String> = name_rows(&pool)
        .await
        .into_iter()
        .map(|row| row.0)
        .collect();
    assert_eq!(named, ["monitor01", "minipc01-2", "minipc01", "lab07"]);
    let audited = automatic_renames(&pool).await;
    // Two from migration 0029, two from 0049, three from the first round of attaches.
    assert_eq!(audited, 7);
    round([
        ("server", 1, Some("monitor01")),
        (B, 11, Some("raspberrypi")),
        (C, 12, Some("lab07")),
        (A, 10, Some("minipc01")),
    ])
    .await;
    let again: Vec<String> = name_rows(&pool)
        .await
        .into_iter()
        .map(|row| row.0)
        .collect();
    assert_eq!(again, named);
    assert_eq!(automatic_renames(&pool).await, audited);
}

/// Rollback without the database copy. D295 promises that a failed update brings back the previous binary *and*
/// the copy of the database taken before the switch. The deploy path on this base (`scripts/release/deploy_remote.py`,
/// identical to dev) restarts the previous binary on the live database instead ("Never overwrite a running SQLite
/// database ... automatic rollback keeps its data"); the copy-restoring implementation is #211 and is not in dev.
/// The previous release's migrator refuses a database that carries 0026 (`VersionMissing(26)`), so a health
/// failure after 0026 ran leaves no server running. Not a defect of this branch's code: a deploy gate.
///
/// Resolution (#236): production deploys run through the owner's deploy script, which copies the whole
/// `/var/lib/infraternal` before the switch and restores that copy on a failed health check, so the previous binary
/// starts on its own database. Migration 0029 rewrites old UUID-shaped placeholder labels; rollback restores the
/// pre-switch database copy. The test stays as a record of the rule and runs with `--ignored`.
#[tokio::test]
#[ignore = "deploy gate, not code: production rollback restores the database copy (#236)"]
async fn the_previous_release_starts_on_a_database_this_release_migrated() {
    let pool = version_25_database().await;
    sqlx::migrate!("../../infraternal-server/migrations")
        .run(&pool)
        .await
        .unwrap();
    let mut previous = sqlx::migrate!("../../infraternal-server/migrations");
    previous
        .migrations
        .to_mut()
        .retain(|migration| migration.version <= 25);
    let started = previous.run(&pool).await;
    assert!(
        started.is_ok(),
        "the previous release refuses the migrated database: {started:?}"
    );
}

/// A node moved aside takes a suffix of the *claimant's* name, not of its own claim, so it renames again on its
/// own next attach (a restart): one more DNS change and audit row for nothing. Fleets with numbered names make
/// this ordinary: two by-IP machines report `web`, and the owner adds the real `web-2` by name.
#[tokio::test]
async fn a_node_moved_aside_keeps_its_name_on_its_next_attach() {
    let pool = pool().await;
    add_host(&pool, B, "root@10.0.0.11").await;
    add_host(&pool, C, "root@10.0.0.12").await;
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    store
        .attach_named(B, PublicKey([11; 32]), None, false, Some("web"))
        .await
        .unwrap();
    let (c, _) = store
        .attach_named(C, PublicKey([12; 32]), None, false, Some("web"))
        .await
        .unwrap();
    add_host(&pool, A, "root@web-2").await;
    store
        .attach_named(A, PublicKey([10; 32]), None, false, None)
        .await
        .unwrap();
    let moved = names(&service, "owner")
        .await
        .into_iter()
        .find(|(id, _)| *id == c.0)
        .unwrap()
        .1;
    let audited = automatic_renames(&pool).await;
    // C restarts and reports the same hostname as before.
    store
        .attach_named(C, PublicKey([12; 32]), None, false, Some("web"))
        .await
        .unwrap();
    let after = names(&service, "owner")
        .await
        .into_iter()
        .find(|(id, _)| *id == c.0)
        .unwrap()
        .1;
    assert_eq!(
        (after.as_str(), automatic_renames(&pool).await),
        (moved.as_str(), audited),
        "the node moved aside to {moved} renamed itself again on its next attach"
    );
}

/// "A person's name is final" and hand outranks every automatic claim, but a person cannot take a name a machine
/// gave itself: the rename is refused as a conflict, and the automatic holder is not moved aside. The refusal is
/// also an oracle: a manager learns that some node, possibly outside their scope, reported that hostname.
#[tokio::test]
async fn a_person_can_take_a_name_a_machine_reported() {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    add_host(&pool, B, "root@10.69.69.6").await;
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
    let (b, _) = store
        .attach_named(B, PublicKey([11; 32]), None, false, None)
        .await
        .unwrap();
    let renamed = rename(&service, "owner", b.0, "minipc01").await;
    assert!(
        renamed.is_ok(),
        "the owner's rename lost to a reported hostname: {renamed:?}"
    );
}

/// Before this branch the server node held `server`, so nobody could take it. Once the server is named after its
/// hostname, `server` is free: a Mesh manager could hand-name a remote machine `server`, and a viewer reads the
/// label `server` as the server itself. No viewer may see a machine other than the server's node called `server`.
/// `a_remote_machine_cannot_be_called_server` covers only the automatic path.
#[tokio::test]
async fn no_viewer_sees_a_remote_machine_called_server() {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    add_guest_manager(&pool).await;
    let service = MeshService::new(pool);
    let store = service.dataplane();
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    let (a, _) = store
        .attach_named(A, PublicKey([10; 32]), None, false, None)
        .await
        .unwrap();
    let _ = rename(&service, "guest", a.0, "server").await;
    let called_server: Vec<u64> = names(&service, "guest")
        .await
        .into_iter()
        .filter(|(id, name)| name == "server" && *id != 1)
        .map(|(id, _)| id)
        .collect();
    assert!(
        called_server.is_empty(),
        "a non-owner sees remote nodes {called_server:?} called server"
    );
}

/// Names are unique everywhere (unique index, DNS), and the Mesh view keys rows and pills by name for people, so
/// no viewer may read two nodes under one name.
#[tokio::test]
async fn a_viewer_without_host_facts_still_sees_distinct_names() {
    let pool = pool().await;
    add_host(&pool, A, "root@10.69.69.5").await;
    add_host(&pool, B, "root@10.69.69.6").await;
    add_guest_manager(&pool).await;
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
        .attach_named(B, PublicKey([11; 32]), None, false, Some("lab08"))
        .await
        .unwrap();
    let mut seen: Vec<String> = names(&service, "guest")
        .await
        .into_iter()
        .map(|(_, name)| name)
        .collect();
    let all = seen.len();
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), all, "duplicate names for a non-owner: {seen:?}");
}

/// Hex and single-number IPv4 spellings are addresses to `inet_aton` (and so to ssh and most resolvers), but pass
/// the "never an address" filter because their first label is not all digits.
#[test]
fn a_hex_ipv4_spelling_never_becomes_a_name() {
    for address in ["root@0x0a.0x45.0x45.0x05", "root@0x0a454505", "root@0x7f.1"] {
        assert_eq!(machine_name(address), None, "{address}");
    }
}

fn row(handshake: u64, received: u64) -> PeerRow {
    PeerRow {
        node: NodeId(3),
        handshake,
        received,
        keepalive: 25,
    }
}

/// The quiet rule reads `persistent_keepalive_secs` from the *server's* peer entry and assumes the remote sends at
/// that rate too. A remote whose own entry has no keepalive (an infraternal agent from before 849c6c50e / #129,
/// 2026-10-11, or any peer configured without one) on an idle link sends only handshake responses: the server's
/// keepalives make it rekey every 120 s, and the remote answers that handshake and nothing else. The session is
/// live the whole time (handshake at most 120 s old), yet the node reads offline for ~65 s of every 2 minutes and
/// every viewer of it gets two resyncs per cycle.
#[test]
fn an_idle_healthy_peer_without_its_own_keepalive_stays_online() {
    let start = 1_800_000_000;
    let mut tracker = Tracker::default();
    let mut offline = Vec::new();
    for at in (0..=360).step_by(5) {
        let now = start + at;
        let last_rekey = start + at / 120 * 120;
        // Each rekey adds one 92-byte handshake response to the server's received bytes.
        let received = 148 + 92 * (at / 120);
        tracker.record(Some((true, vec![row(last_rekey, received)])), now);
        if !tracker.live(None, now).contains_key(&NodeId(3)) {
            offline.push(at);
        }
    }
    assert!(
        offline.is_empty(),
        "a live session read offline at seconds {offline:?}"
    );
}

/// Keep the lost-keepalive no-flapping control. A received packet refreshes relay activity for the full session
/// window, even when the direct handshake is older.
#[test]
fn evidence_a_silent_peer_expires_with_its_session_without_flapping() {
    let start = 1_800_000_000;
    let mut tracker = Tracker::default();
    // Healthy: a keepalive every 25 s, one of them lost (no movement from 25 to 75).
    let mut received = 0;
    for at in (0..=100).step_by(5) {
        if at % 25 == 0 && at != 50 {
            received += 32;
        }
        tracker.record(Some((true, vec![row(start, received)])), start + at);
        assert!(
            tracker.live(None, start + at).contains_key(&NodeId(3)),
            "healthy at {at}"
        );
    }
    // Dead from 100 on: that final receive refreshes the session even though the handshake is already 100 s old.
    let mut gone = None;
    for at in (105..=285).step_by(5) {
        tracker.record(Some((true, vec![row(start, received)])), start + at);
        if gone.is_none() && !tracker.live(None, start + at).contains_key(&NodeId(3)) {
            gone = Some(at - 100);
        }
    }
    let gone = gone.expect("never went offline");
    assert_eq!(gone, 185, "expiry after the last received byte");
}
