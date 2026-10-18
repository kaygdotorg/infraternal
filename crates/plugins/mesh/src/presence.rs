//! Mesh presence from current sessions on the server's own `WireGuard` device [201], #236.
//!
//! The Mesh view, the pill dot and `infraternal mesh peers` must tell the same truth (docs/design/TASTE.md, "Status
//! tells the truth everywhere"). The only first-hand record of whether a peer passes traffic is the kernel's
//! handshake time and byte counters for that peer, which the server's node component already reports through
//! `mesh.peers`. This module reads them on the server and keeps the answer in memory:
//!
//! - **The server node is online while its own Mesh component is On.** It is the machine answering the request.
//! - **A peer is online, on a direct path, for the full session window after its last handshake.**
//!   `WireGuard` rejects a session after [`SESSION_SECS`], so an older handshake (or none) is offline.
//!   Silence before that cannot prove death. Even a peer configured to send keepalives every 25 seconds may
//!   stop sending them when incoming server keepalives keep rearming its timer. A passive empty reply also
//!   has the same size as a persistent keepalive. No received-byte pattern promises future sends (#236 R4).
//!   Inferring that promise caused healthy peers to flash offline, including current infraternal agents.
//!   A dead peer therefore stays online until its session expires: up to 180 seconds plus one poll. The
//!   earlier 55–60 second target is incompatible with avoiding false offline from these observations alone.
//!   Both rekey directions get the full window, including a peer-initiated session that rekeys after 165 seconds.
//!   Each poll replaces all peer state; a reset counter or recreated peer inherits no sending classification.
//! - **Every reading has an age limit.** When the server's own node stops answering, the last reading counts for
//!   at most [`STALE`] and is then dropped: nodes read offline, never frozen online. Presence is only re-evaluated
//!   when a poll ends, so nodes go offline at the first poll that ends after that: **20 s** after the last good
//!   reading, whether the node's calls fail at once (polls at +5, +10, +15, +20 s) or each runs into the node
//!   channel's 5 s call timeout (polls ending at +10 and +20 s). Within that limit the session and handshake rules
//!   above still apply to the age of the data at every poll.
//!
//! Choices, and the alternatives rejected:
//! - In memory, not in `mesh_nodes.last_seen`: writing an observation per peer per poll would cost an fsync, an audit
//!   row and a revision per node every few seconds, and every viewer would relist for nothing. Presence is runtime
//!   state; it starts empty after a restart and is rebuilt within one poll.
//! - Pushed only on a transition: a change notifies each Mesh viewer, who is sent a resync only when a node it can
//!   see changed (socket.rs), so an unchanged mesh costs viewers nothing and a hidden node leaves no trace.
//! - A poll every [`POLL`], not an event, and not on every Mesh revision: the kernel has no handshake
//!   notification, and a revision does not change who passes traffic. A poll is one `mesh.status` call and one
//!   `mesh.peers` listing in its compact presence form, which reads the kernel once however many pages it has
//!   (`node_actions.rs`). Measured on the perf VM (#236): 0.3 ms of userspace work at 500 peers (2 pages) and
//!   0.6 ms at 1000 (4 pages), plus one kernel peer dump of a few milliseconds; the full listing it replaced
//!   was 27 dumps and 15 ms at 500 peers. It never runs on remote nodes and never touches the terminal path.
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
/// How long a reading counts once the server's node stops answering. Offline follows at the first poll that ends
/// after it, 20 s after the last good reading (module docs).
pub const STALE: Duration = Duration::from_secs(15);
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

/// The server's view of who is online, shared by every Mesh list; socket workers watch it for transitions.
pub struct Presence {
    live: tokio::sync::watch::Sender<Arc<Live>>,
}

impl Default for Presence {
    fn default() -> Self {
        Self {
            live: tokio::sync::watch::Sender::new(Arc::default()),
        }
    }
}

impl Presence {
    /// Replace the whole view. Returns whether anything changed; watchers are woken only then.
    // Watchers are already woken on a change; callers may ignore whether there was one.
    #[allow(clippy::must_use_candidate)]
    pub fn replace(&self, next: Live) -> bool {
        self.live.send_if_modified(|live| {
            if **live == next {
                return false;
            }
            *live = Arc::new(next);
            true
        })
    }
    /// The node's presence: `None` offline, `Some(path)` online.
    #[must_use]
    pub fn get(&self, node: NodeId) -> Option<Option<NodePath>> {
        self.live.borrow().get(&node).copied()
    }
    /// Watch the view: each transition carries the whole new view.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<Arc<Live>> {
        self.live.subscribe()
    }
}

/// One peer row of a `mesh.peers` page, as far as presence needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerRow {
    pub node: NodeId,
    pub handshake: u64,
    pub received: u64,
    pub keepalive: u64,
}

/// Reads one `mesh.peers` page in its presence form (`node_actions.rs` `Page::presence`, rows of
/// `[node, handshake_secs, received_bytes, persistent_keepalive_secs]`) into `rows`. `None` when the reply is not
/// such a page, else the next page's cursor, if any.
#[must_use]
pub fn read_peers(reply: &[u8], rows: &mut Vec<PeerRow>) -> Option<Option<Value>> {
    let mut page: Value = serde_json::from_slice(reply).ok()?;
    for row in page["peers"].as_array()? {
        let field = |index: usize| row.get(index).and_then(Value::as_u64);
        let (node, handshake) = (field(0)?, field(1)?);
        if node > 0 {
            rows.push(PeerRow {
                node: NodeId(node),
                handshake,
                received: field(2)?,
                keepalive: field(3)?,
            });
        }
    }
    Some(Some(page["next_cursor"].take()).filter(|cursor| !cursor.is_null()))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// One reading of the server's own node: whether its Mesh is On, and its peers' counters. `None` when the node
/// could not be read.
pub async fn observe(channel: &dyn NodeChannel) -> Option<(bool, Vec<PeerRow>)> {
    let status = channel.call("mesh.status", b"{}".to_vec()).await.ok()?;
    let status: Value = serde_json::from_slice(&status).ok()?;
    let mut rows = Vec::new();
    if status["state"] != "On" {
        return Some((false, rows));
    }
    let mut cursor = Value::Null;
    for _ in 0..MAX_PAGES {
        let input =
            serde_json::to_vec(&serde_json::json!({ "cursor": cursor, "presence": true })).ok()?;
        let reply = channel.call("mesh.peers", input).await.ok()?;
        match read_peers(&reply, &mut rows)? {
            Some(next) => cursor = next,
            None => break,
        }
    }
    Some((true, rows))
}

/// Presence from the last good reading and its time. No inferred sending habits survive between polls.
#[derive(Default)]
pub struct Tracker {
    read_at: Option<u64>,
    server_on: bool,
    /// Last handshake per peer; byte counters and keepalive settings do not establish a sending promise.
    peers: BTreeMap<NodeId, u64>,
}

impl Tracker {
    /// Takes a reading made at `now`, or notes that the node did not answer (`None`).
    pub fn record(&mut self, reading: Option<(bool, Vec<PeerRow>)>, now: u64) {
        let Some((on, rows)) = reading else {
            return;
        };
        self.read_at = Some(now);
        self.server_on = on;
        self.peers.clear();
        for row in rows {
            self.peers.insert(row.node, row.handshake);
        }
    }
    /// Who is online at `now`. Nothing once the last good reading is older than [`STALE`].
    #[must_use]
    pub fn live(&self, server: Option<NodeId>, now: u64) -> Live {
        let mut live = Live::new();
        if self
            .read_at
            .is_none_or(|at| now.saturating_sub(at) > STALE.as_secs())
            || !self.server_on
        {
            return live;
        }
        if let Some(server) = server {
            live.insert(server, None);
        }
        for (&node, &handshake) in &self.peers {
            // A clock far in the future must not keep a node online forever either.
            let age = now.abs_diff(handshake);
            let in_session = handshake > 0 && age <= SESSION_SECS;
            if in_session {
                live.insert(node, Some(NodePath::Direct));
            }
        }
        live
    }
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
    let mut tracker = Tracker::default();
    let mut server = None;
    loop {
        if server.is_none() {
            server = service.dataplane().node_for_host("server").await;
        }
        tracker.record(observe(channel.as_ref()).await, unix_now());
        service.set_presence(tracker.live(server, unix_now()));
        // The first poll runs at once, so presence is rebuilt within one poll of a restart.
        tokio::time::sleep(POLL).await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use serde_json::json;

    const NOW: u64 = 1_800_000_000;

    fn wire(page: &Value) -> Vec<u8> {
        serde_json::to_vec(page).unwrap()
    }

    fn row(node: u64, handshake: u64, received: u64, keepalive: u64) -> PeerRow {
        PeerRow {
            node: NodeId(node),
            handshake,
            received,
            keepalive,
        }
    }

    fn tracked(rows: Vec<PeerRow>) -> Tracker {
        let mut tracker = Tracker::default();
        tracker.record(Some((true, rows)), NOW);
        tracker
    }

    #[test]
    fn a_recent_handshake_is_online_on_a_direct_path() {
        let mut rows = Vec::new();
        let page = json!({"peers":[[3, NOW - 20, 925_000, 25]],"version":4,"next_cursor":null});
        assert_eq!(read_peers(&wire(&page), &mut rows), Some(None));
        assert_eq!(rows, [row(3, NOW - 20, 925_000, 25)]);
        let live = tracked(rows).live(None, NOW);
        assert_eq!(live.get(&NodeId(3)), Some(&Some(NodePath::Direct)));
    }

    #[test]
    fn no_handshake_a_stale_one_or_a_future_one_is_offline() {
        let tracker = tracked(vec![
            row(4, 0, 0, 0),
            row(5, NOW - SESSION_SECS - 1, 9, 0),
            row(6, NOW + SESSION_SECS + 1, 9, 0),
        ]);
        assert!(tracker.live(None, NOW).is_empty());
        let mut rows = Vec::new();
        let page = json!({"peers":[[0, NOW, 1, 25]],"next_cursor":null});
        assert_eq!(read_peers(&wire(&page), &mut rows), Some(None));
        assert!(rows.is_empty(), "{rows:?}");
        let page = json!({"peers":[{"node":3}],"next_cursor":null});
        assert_eq!(
            read_peers(&wire(&page), &mut rows),
            None,
            "not a presence page"
        );
    }

    #[test]
    fn the_edge_of_the_session_window_is_still_online() {
        let live = tracked(vec![row(7, NOW - SESSION_SECS, 0, 0)]).live(None, NOW);
        assert!(live.contains_key(&NodeId(7)));
    }

    #[test]
    fn a_page_cursor_is_followed() {
        let cursor = json!({"version":4,"node":3});
        let page = json!({"peers":[],"next_cursor":cursor});
        assert_eq!(
            read_peers(&wire(&page), &mut Vec::new()),
            Some(Some(cursor))
        );
    }

    /// A keepalive-sized receive is no promise of future sends. Quiet peers keep the same full session
    /// window regardless of their earlier counters; these deterministic ages exercise the expiry boundary.
    #[test]
    fn receiving_a_keepalive_does_not_shorten_the_session_window() {
        let mut tracker = tracked(vec![row(3, NOW, 100, 25), row(4, NOW, 100, 25)]);
        for at in (5..=SESSION_SECS + 5).step_by(5) {
            tracker.record(
                Some((true, vec![row(3, NOW, 132, 25), row(4, NOW, 180, 25)])),
                NOW + at,
            );
            assert_eq!(
                tracker.live(None, NOW + at).len(),
                if at <= SESSION_SECS { 2 } else { 0 },
                "{at}"
            );
        }
    }

    /// Bytes still arriving never keep a peer online past its session window.
    #[test]
    fn traffic_proves_a_session_until_it_ends() {
        let mut tracker = tracked(vec![row(3, NOW, 0, 25)]);
        for at in (5..=SESSION_SECS).step_by(5) {
            tracker.record(Some((true, vec![row(3, NOW, at, 25)])), NOW + at);
            assert!(
                tracker.live(None, NOW + at).contains_key(&NodeId(3)),
                "{at}"
            );
        }
        let at = NOW + SESSION_SECS + 5;
        tracker.record(Some((true, vec![row(3, NOW, at, 25)])), at);
        assert!(tracker.live(None, at).is_empty());
    }

    #[test]
    fn a_reading_expires_when_the_node_stops_answering() {
        let mut tracker = tracked(vec![row(3, NOW - 10, 100, 0)]);
        tracker.record(None, NOW + 5);
        assert_eq!(tracker.live(Some(NodeId(1)), NOW + 5).len(), 2);
        tracker.record(None, NOW + STALE.as_secs() + 1);
        assert!(
            tracker
                .live(Some(NodeId(1)), NOW + STALE.as_secs() + 1)
                .is_empty()
        );
    }

    /// The documented bound: polls that fail at once leave nodes online through +15 s and offline at +20 s.
    #[test]
    fn nodes_go_offline_twenty_seconds_after_the_last_good_reading() {
        let mut tracker = tracked(vec![row(3, NOW - 10, 100, 25)]);
        for at in [5, 10, 15] {
            tracker.record(None, NOW + at);
            assert!(!tracker.live(None, NOW + at).is_empty(), "{at}");
        }
        tracker.record(None, NOW + 20);
        assert!(tracker.live(None, NOW + 20).is_empty());
    }

    #[test]
    fn replace_reports_only_visible_changes() {
        let presence = Presence::default();
        let mut watch = presence.subscribe();
        assert!(!presence.replace(Live::new()));
        assert!(!watch.has_changed().unwrap());
        let next = Live::from([(NodeId(1), None), (NodeId(3), Some(NodePath::Direct))]);
        assert!(presence.replace(next.clone()));
        assert_eq!(**watch.borrow_and_update(), next);
        assert!(!presence.replace(next));
        assert!(!watch.has_changed().unwrap());
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
            if self.state == "unreadable" {
                return Box::pin(async { Err("node unavailable") });
            }
            let reply = match action {
                "mesh.status" => json!({"state":self.state,"peer_count":1}),
                "mesh.peers" => {
                    json!({"peers":[[3, self.handshake, 925_000, 0]],"next_cursor":null})
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
        let mut tracker = Tracker::default();
        tracker.record(observe(&node).await, NOW);
        assert_eq!(
            tracker.live(Some(NodeId(1)), NOW),
            Live::from([(NodeId(1), None), (NodeId(3), Some(NodePath::Direct))])
        );
    }

    #[tokio::test]
    async fn a_mesh_that_is_off_shows_nobody_online() {
        let node = ServerNode {
            state: "Off",
            handshake: NOW - 30,
        };
        let mut tracker = Tracker::default();
        tracker.record(observe(&node).await, NOW);
        assert!(tracker.live(Some(NodeId(1)), NOW).is_empty());
    }

    #[tokio::test]
    async fn an_unreadable_node_is_no_reading() {
        let node = ServerNode {
            state: "unreadable",
            handshake: 0,
        };
        assert_eq!(observe(&node).await, None);
    }
}
