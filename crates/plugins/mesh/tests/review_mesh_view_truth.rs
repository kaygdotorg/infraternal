//! Break-it review of the honest Mesh view (#236): naming authority and presence staleness.
//!
//! Each test states a claim of the branch and is expected to FAIL on 2b527330f:
//! - the host record's name (what the owner typed) loses to another machine's self-reported hostname when that
//!   machine attaches first, and a remote machine can take the server's names;
//! - a name a person chose that equals a placeholder (`server`) is overwritten on the next attach;
//! - an IPv6 address with a zone becomes a node name;
//! - presence keeps a peer online forever when the server's node stops answering.
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_api::node_channel::NodeChannel;
use infraternal_plugin_mesh::{
    api::{MeshFilter, MeshService},
    policy::model::PublicKey,
    store::machine_name,
};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

const A: &str = "00000000-0000-4000-8000-00000000000a";
const B: &str = "00000000-0000-4000-8000-00000000000b";

async fn service(hosts: &[(&str, &str)]) -> MeshService {
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
    for (host, address) in hosts {
        let id = uuid::Uuid::parse_str(host).unwrap();
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)").bind(id.as_bytes().as_slice()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,?)")
            .bind(id.as_bytes().as_slice())
            .bind(*address)
            .execute(&pool)
            .await
            .unwrap();
    }
    MeshService::new(pool)
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

async fn name_of(service: &MeshService, id: u64) -> String {
    let list = service
        .list("owner", MeshFilter::default(), now())
        .await
        .unwrap();
    list.nodes
        .into_iter()
        .find(|node| node.node.id.0 == id)
        .unwrap()
        .node
        .host
}

/// The owner added B as `root@minipc01`. A, added by IP, reports the hostname `minipc01` and happened to attach
/// first. The doc says the host record wins over what a machine reports; attach order must not decide.
#[tokio::test]
async fn a_host_record_name_beats_another_machines_reported_hostname() {
    let service = service(&[(A, "root@10.69.69.5"), (B, "root@minipc01")]).await;
    let store = service.dataplane();
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    let (a, _) = store
        .attach_named(A, PublicKey([10; 32]), None, false, Some("minipc01"))
        .await
        .unwrap();
    let (b, _) = store
        .attach_named(B, PublicKey([11; 32]), None, false, None)
        .await
        .unwrap();
    assert_eq!(
        name_of(&service, b.0).await,
        "minipc01",
        "the machine the owner named minipc01 is shown as something else; A is {:?}",
        name_of(&service, a.0).await
    );
}

/// After the upgrade every node is still a placeholder. A remote machine whose hostname is the server's hostname
/// attaches before the server's own channel; the server must still be called by its own name.
#[tokio::test]
async fn a_remote_machine_cannot_take_the_servers_hostname() {
    let service = service(&[(A, "root@10.69.69.5")]).await;
    let store = service.dataplane();
    let (server, _) = store
        .attach("server", PublicKey([1; 32]), None, true)
        .await
        .unwrap();
    store
        .attach_named(A, PublicKey([10; 32]), None, false, Some("monitor01"))
        .await
        .unwrap();
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    assert_eq!(name_of(&service, server.0).await, "monitor01");
}

/// Once the server took its hostname, `server` is free and a remote machine reporting `server` is shown as the
/// server. A remote node must never be called `server`.
#[tokio::test]
async fn a_remote_machine_cannot_be_called_server() {
    let service = service(&[(A, "root@10.69.69.5")]).await;
    let store = service.dataplane();
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    let (a, _) = store
        .attach_named(A, PublicKey([10; 32]), None, false, Some("server"))
        .await
        .unwrap();
    assert_ne!(name_of(&service, a.0).await, "server");
}

/// The owner renamed the server node back to `server` by hand. The next attach (any restart) must keep it.
#[tokio::test]
async fn a_hand_set_name_equal_to_the_placeholder_is_kept() {
    let service = service(&[]).await;
    let store = service.dataplane();
    let (server, _) = store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    assert_eq!(name_of(&service, server.0).await, "monitor01");
    service
        .execute(
            "owner",
            "mesh.node.rename",
            &serde_json::to_vec(&serde_json::json!({"node_id":server.0,"name":"server"})).unwrap(),
            now(),
        )
        .await
        .unwrap();
    store
        .attach_named("server", PublicKey([1; 32]), None, true, Some("monitor01"))
        .await
        .unwrap();
    assert_eq!(
        name_of(&service, server.0).await,
        "server",
        "the name a person chose was replaced"
    );
}

/// "Never an IP": an IPv6 link-local address with a zone does not parse as `IpAddr`, so it is cut at the first
/// colon and becomes the node name `fe80`. A shorthand IPv4 (`10.69.69`) becomes `10`.
#[test]
fn an_address_that_is_an_ip_never_becomes_a_name() {
    for source in ["root@fe80::1%eth0", "fe80::1%25eth0", "root@10.69.69"] {
        assert_eq!(machine_name(source), None, "{source}");
    }
}

/// The server's own node: answers once with a peer whose handshake is nearly 180 s old, then stops answering
/// (calls fail) while the channel stays attached.
struct FailingAfterOnce {
    peer: u64,
    handshake: u64,
    broken: AtomicBool,
    notices: tokio::sync::watch::Sender<()>,
}
impl NodeChannel for FailingAfterOnce {
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
        if self.broken.load(Ordering::SeqCst) {
            return Box::pin(async { Err("node unavailable") });
        }
        let reply = match action {
            "mesh.status" => serde_json::json!({"state":"On"}),
            "mesh.peers" => {
                self.broken.store(true, Ordering::SeqCst);
                serde_json::json!({"peers":[{"node":self.peer,"counters":{"handshake_secs":self.handshake}}],"next_cursor":null})
            }
            _ => return Box::pin(async { Err("unknown action") }),
        };
        Box::pin(async move { Ok(serde_json::to_vec(&reply).unwrap()) })
    }
}

/// Claim: a peer is online while its last handshake is at most 180 s old. A reading taken when the handshake was
/// 175 s old must not keep the peer online once that handshake is older than 180 s, whatever the node answers.
#[tokio::test]
async fn a_peer_does_not_stay_online_past_its_session_when_the_server_node_stops_answering() {
    let service = service(&[(A, "root@minipc01")]).await;
    let store = service.dataplane();
    store
        .attach("server", PublicKey([1; 32]), None, true)
        .await
        .unwrap();
    let (peer, _) = store
        .attach(A, PublicKey([10; 32]), None, false)
        .await
        .unwrap();
    let handshake = u64::try_from(now()).unwrap() - 175;
    let channel = Arc::new(FailingAfterOnce {
        peer: peer.0,
        handshake,
        broken: AtomicBool::new(false),
        notices: tokio::sync::watch::channel(()).0,
    });
    let worker = tokio::spawn(infraternal_plugin_mesh::presence::run(
        service.clone(),
        channel,
    ));
    // Two failed polls later the handshake is more than 180 s old.
    tokio::time::sleep(std::time::Duration::from_secs(11)).await;
    assert!(u64::try_from(now()).unwrap() - handshake > 180);
    let live = service
        .list("owner", MeshFilter::default(), now())
        .await
        .unwrap()
        .nodes
        .into_iter()
        .find(|node| node.node.id == peer)
        .unwrap()
        .live;
    worker.abort();
    assert!(
        !live,
        "the peer is still shown online with a handshake older than the session window"
    );
}

/// Poll cost at scale, userspace only: the server node's `mesh.peers` paging as node_actions.rs builds it
/// (re-encode the page after every row, 8 KiB pages, skip rows up to the cursor) and the server's `read_peers`
/// over every page. The real poll adds one kernel peer dump per page. Run with
/// `cargo test -p infraternal-plugin-mesh --release --test review_mesh_view_truth -- --ignored --nocapture poll_cost`.
#[test]
#[ignore = "measurement"]
fn poll_cost() {
    use infraternal_plugin_mesh::{dataplane::Peer, policy::model::Addresses};
    for peers in [50_u64, 500, 1000] {
        let config: std::collections::BTreeMap<u64, Peer> = (1..=peers)
            .map(|id| {
                let ip = u32::try_from(id).unwrap();
                (
                    id,
                    Peer {
                        key: PublicKey([u8::try_from(id % 251).unwrap(); 32]),
                        addresses: Addresses {
                            ipv4: std::net::Ipv4Addr::from(0x0afe_0000 + ip),
                            ipv6: std::net::Ipv6Addr::from(0xfd01_u128 << 112 | u128::from(ip)),
                        },
                        endpoint: Some(std::net::SocketAddr::from(([203, 0, 113, 7], 40_000))),
                    },
                )
            })
            .collect();
        let limit = infraternal_plugin_api::MAX_ACTION_BYTES - 128;
        let rounds = 20;
        let started = std::time::Instant::now();
        let mut pages = 0;
        for _ in 0..rounds {
            let mut cursor: Option<u64> = None;
            let mut live = std::collections::BTreeMap::new();
            pages = 0;
            loop {
                pages += 1;
                let mut rows = Vec::new();
                let (mut last, mut more) = (None, false);
                for (id, peer) in &config {
                    if cursor.is_some_and(|c| *id <= c) {
                        continue;
                    }
                    rows.push(serde_json::json!({"node":id,"peer":peer,"inbound":{"state":"All"},"outbound":{"state":"All"},"counters":{"persistent_keepalive_secs":25,"handshake_secs":1_800_000_000_u64,"received_bytes":925_000,"sent_bytes":925_000},"path":"Direct"}));
                    if serde_json::to_vec(&rows).unwrap().len() > limit {
                        rows.pop();
                        more = true;
                        break;
                    }
                    last = Some(*id);
                }
                let page = serde_json::json!({"peers":rows,"version":4,"next_cursor":if more {last.map(|node| serde_json::json!({"version":4,"node":node}))} else {None}});
                let wire = serde_json::to_vec(&page).unwrap();
                let page: serde_json::Value = serde_json::from_slice(&wire).unwrap();
                match infraternal_plugin_mesh::presence::read_peers(&page, 1_800_000_000, &mut live)
                {
                    Some(next) => cursor = next["node"].as_u64(),
                    None => break,
                }
            }
            assert_eq!(live.len(), usize::try_from(peers).unwrap());
        }
        let per_poll = started.elapsed() / rounds;
        println!(
            "peers={peers} pages={pages} per_poll={per_poll:?} cpu_share_at_5s={:.3}%",
            per_poll.as_secs_f64() / 5.0 * 100.0
        );
    }
}
