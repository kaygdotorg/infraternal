//! Live Mesh presence: which nodes pass traffic right now, read from the server's own `WireGuard` device [201], #236.
//!
//! The Mesh view, the pill dot and `infraternal mesh peers` must tell the same truth (docs/design/TASTE.md, "Status
//! tells the truth everywhere"). The only first-hand record of whether a peer passes traffic is the kernel's
//! handshake time and byte counters for that peer, which the server's node component already reports through
//! `mesh.peers`. This module reads them on the server and keeps the answer in memory:
//!
//! - **The server node is online while its own Mesh component is On.** It is the machine answering the request.
//! - **A peer is online, on a direct path, while its session is live and it is still sending.** `WireGuard` discards
//!   a session [`SESSION_SECS`] after its handshake, so an older handshake (or none) is offline. Within the
//!   session, a peer with a persistent keepalive sends at least once per keepalive interval; when its received
//!   bytes stop moving for [`quiet_secs`] (two intervals plus one poll), it is gone. With 25 s keepalives a dead
//!   peer reads offline after at most ~55–60 s instead of up to 180 s. Two intervals, not one: a single lost
//!   keepalive datagram must not flash a healthy node offline.
//! - **Every reading has an age limit.** When the server's own node stops answering, the last reading counts for
//!   at most [`STALE`] and is then dropped: nodes read offline, never frozen online. Within that limit the session
//!   and quiet rules above still apply to the age of the data at every poll.
//!
//! Choices, and the alternatives rejected:
//! - In memory, not in `mesh_nodes.last_seen`: writing an observation per peer per poll would cost an fsync, an audit
//!   row and a revision per node every few seconds, and every viewer would relist for nothing. Presence is runtime
//!   state; it starts empty after a restart and is rebuilt within one poll.
//! - Pushed only on a transition: a change sends every Mesh viewer one authoritative resync snapshot, the same frame
//!   the liveness-expiry path already uses, so an unchanged mesh costs viewers nothing.
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
/// How long a reading counts once the server's node stops answering: two missed polls, then offline.
pub const STALE: Duration = Duration::from_secs(15);
/// The most `mesh.peers` pages one poll follows; a page is up to one action frame of peers.
const MAX_PAGES: usize = 1024;

/// How long a peer with `keepalive` may send nothing before it reads offline: two keepalive intervals and one poll.
/// `None` without a keepalive, when silence is normal and only the session window applies.
#[must_use]
pub fn quiet_secs(keepalive: u64) -> Option<u64> {
    (keepalive > 0).then(|| 2 * keepalive + POLL.as_secs())
}

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

/// What one peer last showed, carried between polls so silence can be timed.
#[derive(Clone, Copy)]
struct Seen {
    row: PeerRow,
    /// When its received bytes last moved (or when it was first seen).
    moved_at: u64,
}

/// Presence derived from the polls so far: the last good reading, its time, and each peer's last movement.
#[derive(Default)]
pub struct Tracker {
    read_at: Option<u64>,
    server_on: bool,
    peers: BTreeMap<NodeId, Seen>,
}

impl Tracker {
    /// Takes a reading made at `now`, or notes that the node did not answer (`None`).
    pub fn record(&mut self, reading: Option<(bool, Vec<PeerRow>)>, now: u64) {
        let Some((on, rows)) = reading else {
            return;
        };
        self.read_at = Some(now);
        self.server_on = on;
        let mut peers = BTreeMap::new();
        for row in rows {
            let moved_at = match self.peers.get(&row.node) {
                Some(seen) if seen.row.received == row.received => seen.moved_at,
                _ => now,
            };
            peers.insert(row.node, Seen { row, moved_at });
        }
        self.peers = peers;
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
        for (node, seen) in &self.peers {
            let handshake = seen.row.handshake;
            // A clock far in the future must not keep a node online forever either.
            let in_session = handshake > 0 && now.abs_diff(handshake) <= SESSION_SECS;
            let sending = quiet_secs(seen.row.keepalive)
                .is_none_or(|quiet| now.saturating_sub(seen.moved_at) <= quiet);
            if in_session && sending {
                live.insert(*node, Some(NodePath::Direct));
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

    /// A peer that stops sending reads offline two keepalives and one poll later, not when its session ends.
    #[test]
    fn a_peer_that_stops_sending_is_offline_before_its_session_ends() {
        let mut tracker = tracked(vec![row(3, NOW - 10, 100, 25)]);
        let quiet = quiet_secs(25).unwrap();
        assert_eq!(quiet, 55);
        // Still sending: online.
        tracker.record(Some((true, vec![row(3, NOW - 10, 200, 25)])), NOW + 30);
        assert!(tracker.live(None, NOW + 30).contains_key(&NodeId(3)));
        // Silent from NOW + 30 on: online through the quiet window, offline after it.
        for at in (35..=30 + quiet).step_by(5) {
            tracker.record(Some((true, vec![row(3, NOW - 10, 200, 25)])), NOW + at);
            assert!(
                tracker.live(None, NOW + at).contains_key(&NodeId(3)),
                "{at}"
            );
        }
        let at = NOW + 30 + quiet + 5;
        tracker.record(Some((true, vec![row(3, NOW - 10, 200, 25)])), at);
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
