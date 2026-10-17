//! Live Mesh presence: which nodes pass traffic right now, read from the server's own `WireGuard` device [201], #236.
//!
//! The Mesh view, the pill dot and `infraternal mesh peers` must tell the same truth (docs/design/TASTE.md, "Status
//! tells the truth everywhere"). The only first-hand record of whether a peer passes traffic is the kernel's
//! handshake time and byte counters for that peer, which the server's node component already reports through
//! `mesh.peers`. This module reads them on the server and keeps the answer in memory:
//!
//! - **The server node is online while its own Mesh component is On.** It is the machine answering the request.
//! - **A peer is online, on a direct path, while its last handshake is recent.** `WireGuard` discards a session
//!   [`SESSION_SECS`] after its handshake and renews it every two minutes while traffic flows, so a handshake
//!   younger than that window means packets can pass now; an older one (or none) means they cannot.
//!
//! Choices, and the alternatives rejected:
//! - In memory, not in `mesh_nodes.last_seen`: writing an observation per peer per poll would cost an fsync, an audit
//!   row and a revision per node every few seconds, and every viewer would relist for nothing. Presence is runtime
//!   state; it starts empty after a restart and is rebuilt within one poll.
//! - Pushed only on a transition: a change sends every Mesh viewer one authoritative resync snapshot, the same frame
//!   the liveness-expiry path already uses, so an unchanged mesh costs viewers nothing.
//! - A poll, not an event: the kernel has no handshake notification. One netlink dump on the server every
//!   [`POLL`] is microseconds; it never runs on remote nodes and never touches the terminal path.
use crate::api::MeshService;
use infraternal_mesh::model::NodeId;
use infraternal_plugin_api::node_channel::NodeChannel;
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// `WireGuard`'s reject-after time: a session this old carries no packets.
pub const SESSION_SECS: u64 = 180;
/// How often the server reads its own peer table.
pub const POLL: Duration = Duration::from_secs(5);
/// The most `mesh.peers` pages one poll follows; a page is up to one action frame of peers.
const MAX_PAGES: usize = 1024;

/// How packets reach a node from the server, when it is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NodePath {
    /// A `WireGuard` session straight between the server and the node.
    Direct,
}

/// Nodes that are online now, each with its path when one is known. Absent means offline.
pub type Live = BTreeMap<NodeId, Option<NodePath>>;

/// The server's view of who is online, shared by every Mesh list.
#[derive(Default)]
pub struct Presence {
    live: std::sync::Mutex<Live>,
}

impl Presence {
    /// Replace the whole view. Returns whether anything a viewer can see changed.
    pub fn replace(&self, next: Live) -> bool {
        let Ok(mut live) = self.live.lock() else {
            return false;
        };
        if *live == next {
            return false;
        }
        *live = next;
        true
    }
    /// The node's presence: `None` offline, `Some(path)` online.
    #[must_use]
    pub fn get(&self, node: NodeId) -> Option<Option<NodePath>> {
        self.live.lock().ok()?.get(&node).copied()
    }
}

/// Reads one `mesh.peers` page into `live`. Returns the next page's cursor, if the node said there is one.
///
/// A row counts only when its handshake is no older than [`SESSION_SECS`] and not from the future by more than the
/// same margin (a wrong clock must not keep a node online forever).
pub fn read_peers(page: &Value, now: u64, live: &mut Live) -> Option<Value> {
    for row in page["peers"].as_array().into_iter().flatten() {
        let (Some(node), Some(handshake)) = (
            row["node"].as_u64().filter(|id| *id > 0),
            row["counters"]["handshake_secs"].as_u64(),
        ) else {
            continue;
        };
        if handshake > 0 && now.abs_diff(handshake) <= SESSION_SECS {
            live.insert(NodeId(node), Some(NodePath::Direct));
        }
    }
    page.get("next_cursor")
        .filter(|cursor| !cursor.is_null())
        .cloned()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// One reading of the server's own node: the server while its Mesh is On, and every peer with a live session.
/// `None` when the node could not be read; the caller keeps the last reading rather than flash nodes offline for
/// one failed local call (the worker's end clears it, see [`Clear`]).
pub async fn observe(channel: &dyn NodeChannel, server: Option<NodeId>, now: u64) -> Option<Live> {
    let mut live = Live::new();
    let status = channel.call("mesh.status", b"{}".to_vec()).await.ok()?;
    let status: Value = serde_json::from_slice(&status).ok()?;
    if status["state"] != "On" {
        return Some(live);
    }
    if let Some(server) = server {
        live.insert(server, None);
    }
    let mut cursor = Value::Null;
    for _ in 0..MAX_PAGES {
        let input = serde_json::json!({ "cursor": cursor });
        let Ok(input) = serde_json::to_vec(&input) else {
            break;
        };
        let reply = channel.call("mesh.peers", input).await.ok()?;
        let page: Value = serde_json::from_slice(&reply).ok()?;
        match read_peers(&page, now, &mut live) {
            Some(next) => cursor = next,
            None => break,
        }
    }
    Some(live)
}

/// Clears presence when the server's worker ends, so a stopped worker never leaves nodes shown online.
struct Clear(MeshService);
impl Drop for Clear {
    fn drop(&mut self) {
        self.0.set_presence(Live::new());
    }
}

/// Keeps presence current for as long as the server's own node channel is attached. The caller runs it only for
/// the server's channel (socket.rs), so a remote host's worker never polls.
pub async fn run(service: MeshService, channel: Arc<dyn NodeChannel>) {
    let _clear = Clear(service.clone());
    let mut revisions = service.subscribe();
    let mut server = None;
    loop {
        if server.is_none() {
            server = service.dataplane().node_for_host("server").await;
        }
        if let Some(live) = observe(channel.as_ref(), server, unix_now()).await {
            service.set_presence(live);
        }
        // A new or changed peer is read at once; otherwise the next poll.
        tokio::select! {
            () = tokio::time::sleep(POLL) => {}
            result = revisions.recv() => {
                if matches!(result, Err(tokio::sync::broadcast::error::RecvError::Closed)) {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use serde_json::json;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn a_recent_handshake_is_online_on_a_direct_path() {
        let mut live = Live::new();
        let page = json!({"peers":[{"node":3,"path":"Direct","counters":{"handshake_secs":NOW - 20,"received_bytes":925_000,"sent_bytes":925_000}}],"next_cursor":null});
        assert_eq!(read_peers(&page, NOW, &mut live), None);
        assert_eq!(live.get(&NodeId(3)), Some(&Some(NodePath::Direct)));
    }

    #[test]
    fn no_handshake_a_stale_one_or_a_future_one_is_offline() {
        let mut live = Live::new();
        let page = json!({"peers":[
            {"node":4,"counters":{"handshake_secs":0,"received_bytes":0,"sent_bytes":0}},
            {"node":5,"counters":{"handshake_secs":NOW - SESSION_SECS - 1,"received_bytes":9,"sent_bytes":9}},
            {"node":6,"counters":{"handshake_secs":NOW + SESSION_SECS + 1,"received_bytes":9,"sent_bytes":9}},
            {"node":0,"counters":{"handshake_secs":NOW}},
            {"counters":{"handshake_secs":NOW}}
        ]});
        assert_eq!(read_peers(&page, NOW, &mut live), None);
        assert!(live.is_empty(), "{live:?}");
    }

    #[test]
    fn the_edge_of_the_session_window_is_still_online() {
        let mut live = Live::new();
        let page = json!({"peers":[{"node":7,"counters":{"handshake_secs":NOW - SESSION_SECS}}]});
        read_peers(&page, NOW, &mut live);
        assert!(live.contains_key(&NodeId(7)));
    }

    #[test]
    fn a_page_cursor_is_followed() {
        let mut live = Live::new();
        let cursor = json!({"version":4,"node":3});
        let page = json!({"peers":[],"next_cursor":cursor});
        assert_eq!(read_peers(&page, NOW, &mut live), Some(cursor));
    }

    #[test]
    fn replace_reports_only_visible_changes() {
        let presence = Presence::default();
        assert!(!presence.replace(Live::new()));
        let next = Live::from([(NodeId(1), None), (NodeId(3), Some(NodePath::Direct))]);
        assert!(presence.replace(next.clone()));
        assert!(!presence.replace(next));
        assert_eq!(presence.get(NodeId(3)), Some(Some(NodePath::Direct)));
        assert_eq!(presence.get(NodeId(1)), Some(None));
        assert_eq!(presence.get(NodeId(2)), None);
    }

    /// The server's node as `mesh.status` and `mesh.peers` answer on production (#236).
    struct ServerNode {
        state: &'static str,
        handshake: u64,
    }
    impl NodeChannel for ServerNode {
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
            tokio::sync::watch::channel(()).1
        }
        fn call(
            &self,
            action: &str,
            _input: Vec<u8>,
        ) -> infraternal_plugin_api::PluginOperation<'_, Vec<u8>> {
            let reply = match action {
                "mesh.status" => json!({"state":self.state,"peer_count":1}),
                "mesh.peers" => {
                    json!({"peers":[{"node":3,"path":"Direct","counters":{"handshake_secs":self.handshake,"received_bytes":925_000,"sent_bytes":925_000}}],"next_cursor":null})
                }
                _ => return Box::pin(async { Err("unknown action") }),
            };
            Box::pin(async move { Ok(serde_json::to_vec(&reply).unwrap()) })
        }
    }

    #[tokio::test]
    async fn the_server_and_a_peer_passing_traffic_are_online() {
        let node = ServerNode {
            state: "On",
            handshake: NOW - 30,
        };
        let live = observe(&node, Some(NodeId(1)), NOW).await;
        assert_eq!(
            live,
            Some(Live::from([
                (NodeId(1), None),
                (NodeId(3), Some(NodePath::Direct))
            ]))
        );
    }

    #[tokio::test]
    async fn a_mesh_that_is_off_shows_nobody_online() {
        let node = ServerNode {
            state: "Off",
            handshake: NOW - 30,
        };
        assert_eq!(
            observe(&node, Some(NodeId(1)), NOW).await,
            Some(Live::new())
        );
    }

    #[tokio::test]
    async fn an_unreadable_node_keeps_the_last_reading() {
        let node = ServerNode {
            state: "On",
            handshake: NOW - 30,
        };
        let unreadable = ServerNode {
            state: "unreadable",
            handshake: 0,
        };
        assert!(observe(&node, None, NOW).await.is_some());
        assert_eq!(observe(&Broken(unreadable), None, NOW).await, None);
    }

    /// A node whose local calls fail.
    struct Broken(ServerNode);
    impl NodeChannel for Broken {
        fn id(&self) -> &'static str {
            "server"
        }
        fn observed_ip(&self) -> std::net::IpAddr {
            self.0.observed_ip()
        }
        fn is_server(&self) -> bool {
            true
        }
        fn changes(&self) -> tokio::sync::watch::Receiver<()> {
            self.0.changes()
        }
        fn call(
            &self,
            _action: &str,
            _input: Vec<u8>,
        ) -> infraternal_plugin_api::PluginOperation<'_, Vec<u8>> {
            Box::pin(async { Err("node unavailable") })
        }
    }
}
