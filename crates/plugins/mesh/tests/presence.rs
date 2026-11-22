//! The Mesh list tells the server's live presence: online nodes and their path, transitions announced (#236).
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_mesh::{
    api::{MeshFilter, MeshService},
    policy::model::{NodeId, PublicKey},
    presence::{Live, NodePath},
};
use sqlx::sqlite::SqlitePoolOptions;

const NOW: i64 = 1_800_000_000;
const HOST: &str = "00000000-0000-4000-8000-000000000003";

async fn service() -> (MeshService, NodeId, NodeId) {
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
    let host = uuid::Uuid::parse_str(HOST).unwrap();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)").bind(host.as_bytes().as_slice()).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,'root@minipc01')")
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let service = MeshService::new(pool);
    let store = service.dataplane();
    let (server, _) = store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    let (peer, _) = store
        .attach(HOST, PublicKey([2; 32]), None, false)
        .await
        .unwrap();
    (service, server, peer)
}

fn json_nodes(snapshot: &infraternal_plugin_mesh::api::MeshSnapshot) -> Vec<serde_json::Value> {
    serde_json::to_value(snapshot).unwrap()["nodes"]
        .as_array()
        .unwrap()
        .clone()
}

/// Owner report 2026-10-17: "server" and the new host showed "offline" while traffic flowed directly.
#[tokio::test]
async fn nodes_the_server_sees_are_online_with_their_path_and_named_by_machine() {
    let (service, server, peer) = service().await;
    let before = service
        .list("owner", MeshFilter::default(), NOW)
        .await
        .unwrap();
    assert!(before.nodes.iter().all(|node| !node.live));
    let announced = service.subscribe_presence();
    service.set_presence(Live::from([(server, None), (peer, Some(NodePath::Direct))]));
    assert!(
        announced.has_changed().unwrap(),
        "a transition is announced"
    );
    let after = service
        .list("owner", MeshFilter::default(), NOW)
        .await
        .unwrap();
    let nodes = json_nodes(&after);
    assert_eq!(nodes[0]["node"]["host"], "monitor01");
    assert_eq!(nodes[0]["live"], true);
    assert_eq!(nodes[0]["key_rotation_supported"], false);
    assert_eq!(nodes[0]["restore_safe"], false);
    assert!(
        nodes[0].get("path").is_none(),
        "the server has no path to itself"
    );
    assert_eq!(nodes[1]["node"]["host"], "minipc01");
    assert_eq!(nodes[1]["live"], true);
    assert_eq!(nodes[1]["key_rotation_supported"], false);
    assert_eq!(nodes[1]["restore_safe"], false);
    assert_eq!(nodes[1]["path"], "direct");
    // Presence moves no stored revision: viewers are told by the transition, not a revision.
    assert_eq!(after.revision, before.revision);
}

/// A proved authority-epoch capability makes the API report a peer as restore-safe.
#[tokio::test]
async fn a_node_with_proved_authority_epoch_support_is_restore_safe() {
    let (service, _, _) = service().await;
    service
        .dataplane()
        .attach_named_with_probed_capabilities(
            HOST,
            PublicKey([2; 32]),
            None,
            false,
            None,
            Some(false),
            Some(true),
        )
        .await
        .unwrap();

    let nodes = json_nodes(
        &service
            .list("owner", MeshFilter::default(), NOW)
            .await
            .unwrap(),
    );
    assert_eq!(nodes[1]["restore_safe"], true);
}

#[tokio::test]
async fn an_unchanged_reading_is_not_announced_and_a_lost_session_goes_offline() {
    let (service, server, peer) = service().await;
    let live = Live::from([(server, None), (peer, Some(NodePath::Direct))]);
    service.set_presence(live.clone());
    let announced = service.subscribe_presence();
    service.set_presence(live);
    assert!(
        !announced.has_changed().unwrap(),
        "nothing changed, nothing sent"
    );
    service.set_presence(Live::from([(server, None)]));
    assert!(
        announced.has_changed().unwrap(),
        "the peer going offline is announced"
    );
    let nodes = json_nodes(
        &service
            .list("owner", MeshFilter::default(), NOW)
            .await
            .unwrap(),
    );
    assert_eq!(nodes[1]["live"], false);
    assert!(nodes[1].get("path").is_none());
}

/// A server node channel that only counts the calls presence makes on it (#562).
struct CountingChannel {
    calls: std::sync::atomic::AtomicUsize,
    notices: tokio::sync::watch::Sender<()>,
}

impl infraternal_plugin_api::node_channel::NodeChannel for CountingChannel {
    fn id(&self) -> &'static str {
        "server"
    }
    fn observed_ip(&self) -> std::net::IpAddr {
        std::net::Ipv4Addr::LOCALHOST.into()
    }
    fn is_server(&self) -> bool {
        true
    }
    fn changes(&self) -> tokio::sync::watch::Receiver<()> {
        self.notices.subscribe()
    }
    fn call(
        &self,
        action: &str,
        _input: Vec<u8>,
    ) -> infraternal_plugin_api::PluginOperation<'_, Vec<u8>> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let reply = if action == "mesh.status" {
            br#"{"state":"On"}"#.to_vec()
        } else {
            br#"{"peers":[],"next_cursor":null}"#.to_vec()
        };
        Box::pin(async move { Ok(reply) })
    }
}

/// D81, #562: a server whose node has no mesh configuration makes no presence call at all; polling starts when a
/// configuration is delivered and stops, with every node reading offline, when it goes away.
#[tokio::test]
async fn presence_polls_only_while_the_servers_node_has_a_mesh_configuration() {
    use std::sync::atomic::Ordering::Relaxed;
    use std::time::Duration;
    let (service, server, _peer) = service().await;
    let channel = std::sync::Arc::new(CountingChannel {
        calls: std::sync::atomic::AtomicUsize::new(0),
        notices: tokio::sync::watch::channel(()).0,
    });
    let period = Duration::from_millis(40);
    let worker = tokio::spawn(infraternal_plugin_mesh::presence::run_every(
        service.clone(),
        channel.clone(),
        period,
    ));
    // No configuration: the first poll used to run at once, then every period.
    // sleep: waiting out absent polls; "nothing happens" has no event to wait for.
    tokio::time::sleep(period * 10).await;
    assert_eq!(
        channel.calls.load(Relaxed),
        0,
        "an idle server polls nothing"
    );

    service.set_server_configured(true);
    // sleep: waiting out absent polls; "nothing happens" has no event to wait for.
    tokio::time::sleep(period * 10).await;
    let polling = channel.calls.load(Relaxed);
    assert!(
        polling >= 4,
        "polling starts at once and repeats: {polling}"
    );
    assert!(service.subscribe_presence().borrow().contains_key(&server));

    service.set_server_configured(false);
    // A poll in flight may finish; none starts after the signal.
    // sleep: waiting out absent polls; "nothing happens" has no event to wait for.
    tokio::time::sleep(period * 3).await;
    let stopped = channel.calls.load(Relaxed);
    // sleep: waiting out absent polls; "nothing happens" has no event to wait for.
    tokio::time::sleep(period * 10).await;
    assert_eq!(channel.calls.load(Relaxed), stopped, "polling stopped");
    assert!(
        service.subscribe_presence().borrow().is_empty(),
        "nodes read offline once the mesh is off"
    );

    // Turned on again later, it resumes.
    service.set_server_configured(true);
    // sleep: waiting out absent polls; "nothing happens" has no event to wait for.
    tokio::time::sleep(period * 5).await;
    assert!(channel.calls.load(Relaxed) > stopped);
    worker.abort();
}
