//! Mesh presence from current sessions on the server's own `WireGuard` device [201], #236.
//!
//! The Mesh view, the pill dot and `infraternal mesh peers` must tell the same truth (docs/design/TASTE.md, "Status
//! tells the truth everywhere"). The only first-hand record of whether a peer passes traffic is the kernel's
//! handshake time and byte counters for that peer, which the server's node component already reports through
//! `mesh.peers`. This module reads them on the server and keeps the answer in memory:
//!
//! - **The server node is online while its own Mesh component is On.** It is the machine answering the request.
//! - **A recent direct handshake or newly received packet proves current activity.** `WireGuard` rejects a
//!   session after [`SESSION_SECS`], so a direct handshake or last observed packet older than that is offline.
//!   A receive-counter increase proves a packet arrived on some path, including a relay path that has no
//!   server-device handshake. An unchanged cumulative counter does not keep a peer live, and a reset counter
//!   or recreated peer inherits no activity timestamp. A live peer therefore stays online for at most 180
//!   seconds after its last direct handshake or newly received packet, plus one poll. This is a bound on
//!   observed activity, not a promise that the peer will send again.
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
//! - **Only while the server's node has a mesh configuration (#562).** With the mesh off, nothing runs: no timer
//!   and no call, which D81 asks of an idle server. The node worker tells [`run`] when a configuration is
//!   delivered and when it goes away.
//! - A poll every [`POLL`], not an event, and not on every Mesh revision: the kernel has no handshake
//!   notification, and a revision does not change who passes traffic. A poll is one `mesh.status` call and one
//!   `mesh.peers` listing in its compact presence form, which reads the kernel once however many pages it has
//!   (`node_actions.rs`). Measured on the perf VM (#236): 0.3 ms of userspace work at 500 peers (2 pages) and
//!   0.6 ms at 1000 (4 pages), plus one kernel peer dump of a few milliseconds; the full listing it replaced
//!   was 27 dumps and 15 ms at 500 peers. It never runs on remote nodes and never touches the terminal path.
//!
//! **Server-reflexive addresses ride on the same reading (#515, D391).** Each row also carries the address the
//! server's device currently sends that peer's packets to. `GotaTun` and kernel `WireGuard` move it to the source
//! of every authenticated packet, so it is where the node's mesh socket was last seen from: its server-reflexive
//! address, port included, unless the device set it itself from the coordinator's own list. [`Reflexive`] says
//! which: new data or a newer handshake proves the address; otherwise only an address the coordinator never
//! published for that node counts (contracts/mesh-discovery.md). [`run`] hands each observation to the store, which
//! writes and republishes only a changed address, so a quiet mesh costs no write and a NAT rebind reaches the node's
//! peers one poll after its next packet, keepalives included, to the server.
use crate::api::MeshService;
use infraternal_mesh::model::NodeId;
use infraternal_plugin_api::node_channel::NodeChannel;
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
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
    /// Recent peer traffic arrived without a recent direct server-device handshake.
    Relay,
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
    /// Where the server's device sends this peer's packets now; absent from older rows.
    pub endpoint: Option<SocketAddr>,
}

/// Reads one `mesh.peers` page in its presence form (`node_actions.rs` `Page::presence`, rows of
/// `[node, handshake_secs, received_bytes, persistent_keepalive_secs, endpoint]`, the last optional) into `rows`. `None` when the reply is not
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
                endpoint: row
                    .get(4)
                    .and_then(Value::as_str)
                    .and_then(|text| text.parse().ok()),
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
    /// Last direct handshake and newly received packet per peer.
    peers: BTreeMap<NodeId, PeerObservation>,
}

/// What the last reading showed for one peer: the newest direct handshake, the received byte counter, and when that
/// counter last grew (relayed packets count, so a relay-only peer stays live).
#[derive(Clone, Copy, Debug, Default)]
struct PeerObservation {
    handshake: u64,
    received: u64,
    last_received_at: Option<u64>,
    /// The device's address for the peer in this reading.
    endpoint: Option<SocketAddr>,
    /// What this reading says about the peer's server-reflexive address, if anything.
    reflexive: Option<Reflexive>,
}

/// One server-reflexive observation (#515): the address the server's device holds for a node, and how strong the
/// evidence is that the node's packets come from there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reflexive {
    /// The node seen.
    pub node: NodeId,
    /// Where the server's device sends that node's packets now.
    pub address: SocketAddr,
    /// New received data or a newer handshake arrived since the previous reading. Both engines move the address to
    /// the source of every authenticated packet, so it is where those packets came from.
    ///
    /// When false, the address is merely new to this tracker (a first reading, or it moved since the previous one).
    /// The device sets an address only from the coordinator's own list, from a walk through that list, or from an
    /// authenticated packet, so the store accepts such an address only when the coordinator never published it for
    /// that node. `GotaTun` counts no bytes for a keepalive, so this is how an idle node's NAT rebind is seen.
    pub proven: bool,
}

impl Tracker {
    /// Takes a reading made at `now`, or notes that the node did not answer (`None`).
    pub fn record(&mut self, reading: Option<(bool, Vec<PeerRow>)>, now: u64) {
        let Some((on, rows)) = reading else {
            return;
        };
        let previous_reading_within_session = self
            .read_at
            .is_some_and(|at| now.abs_diff(at) <= SESSION_SECS);
        self.read_at = Some(now);
        self.server_on = on;
        let mut peers = BTreeMap::new();
        for row in rows {
            let previous = previous_reading_within_session
                .then(|| self.peers.get(&row.node).copied())
                .flatten();
            // A receive delta across a gap no longer than one WireGuard session
            // proves a packet arrived since the last reading. Stamp it now:
            // being late to observe an active relay path must not exempt its
            // peer from the ack barrier.
            let grew = previous.is_some_and(|previous| row.received > previous.received);
            let last_received_at = match previous {
                Some(_) if grew => Some(now),
                Some(previous) if row.received == previous.received => previous.last_received_at,
                Some(_) | None => None,
            };
            // The same handshake can read one second later (J602 F4); that is not news.
            let proven = grew
                || previous.is_some_and(|previous| {
                    crate::candidates::newer_handshake(row.handshake, previous.handshake)
                });
            let moved = previous.is_none_or(|previous| previous.endpoint != row.endpoint);
            let reflexive = row
                .endpoint
                .filter(|_| proven || moved)
                .and_then(|endpoint| crate::policy::discovery::usable_address(endpoint).ok())
                .map(|address| Reflexive {
                    node: row.node,
                    address,
                    proven,
                });
            peers.insert(
                row.node,
                PeerObservation {
                    handshake: row.handshake,
                    received: row.received,
                    last_received_at,
                    endpoint: row.endpoint,
                    reflexive,
                },
            );
        }
        self.peers = peers;
    }
    /// The last reading's server-reflexive observations (#515), see [`Reflexive`].
    #[must_use]
    pub fn reflexive(&self) -> Vec<Reflexive> {
        self.peers
            .values()
            .filter_map(|peer| peer.reflexive)
            .collect()
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
        for (&node, peer) in &self.peers {
            // A clock far in the future must not keep a node online forever either.
            let direct = peer.handshake > 0 && now.abs_diff(peer.handshake) <= SESSION_SECS;
            if direct {
                live.insert(node, Some(NodePath::Direct));
            } else if peer
                .last_received_at
                .is_some_and(|at| now.abs_diff(at) <= SESSION_SECS)
            {
                live.insert(node, Some(NodePath::Relay));
            }
        }
        live
    }
}

/// Clears presence when the server's worker ends, so a stopped worker never leaves nodes shown online. It also
/// forgets that the server's node was configured: the next channel starts from "nothing delivered yet" (#562).
struct Clear(MeshService);
impl Drop for Clear {
    fn drop(&mut self) {
        self.0.set_presence(Live::new());
        self.0.set_server_configured(false);
    }
}

/// Stores the last reading's server-reflexive observations and republishes the mesh when one changed (#515).
///
/// The store compares each address with what it holds and writes only a change, so this costs one in-memory
/// comparison per observed peer per poll. Returns whether anything was republished.
pub async fn publish_reflexive(service: &MeshService, tracker: &Tracker) -> bool {
    let observed = tracker.reflexive();
    if observed.is_empty() {
        return false;
    }
    match service.dataplane().record_reflexive(&observed).await {
        Ok(true) => {
            service.invalidate_dataplane().await;
            true
        }
        // A storage failure keeps the last published addresses; the next poll observes again.
        Ok(false) | Err(_) => false,
    }
}

/// Keeps presence current for as long as the server's own node channel is attached **and** its node holds a mesh
/// configuration. The caller runs it only for the server's channel (socket.rs), so a remote host's worker never polls.
///
/// While the mesh is off, nothing is polled: the task sleeps on the "configured" signal the node worker publishes
/// (`node_coordination.rs`), so an idle server wakes no thread for it (D81, #562). When the signal drops (the mesh
/// is turned off or the membership removed) polling stops and every node reads offline at once.
pub async fn run(service: MeshService, channel: Arc<dyn NodeChannel>) {
    run_every(service, channel, POLL).await;
}

/// [`run`] with the time between polls given, so a test need not wait [`POLL`].
#[doc(hidden)]
pub async fn run_every(service: MeshService, channel: Arc<dyn NodeChannel>, period: Duration) {
    let _clear = Clear(service.clone());
    let mut configured = service.subscribe_server_configured();
    loop {
        if configured.wait_for(|on| *on).await.is_err() {
            return;
        }
        poll_while_configured(&service, channel.as_ref(), &mut configured, period).await;
        service.set_presence(Live::new());
    }
}

/// One stretch of polling: from a configuration being delivered until it goes away. Returns early, with no
/// further poll, as soon as the "configured" signal drops or its sender is gone.
async fn poll_while_configured(
    service: &MeshService,
    channel: &dyn NodeChannel,
    configured: &mut tokio::sync::watch::Receiver<bool>,
    period: Duration,
) {
    let mut tracker = Tracker::default();
    let mut server = None;
    loop {
        if server.is_none() {
            server = service.dataplane().node_for_host("server").await;
        }
        tracker.record(observe(channel).await, unix_now());
        service.set_presence(tracker.live(server, unix_now()));
        publish_reflexive(service, &tracker).await;
        // The first poll runs at once, so presence is rebuilt within one poll of a restart.
        tokio::select! {
            () = tokio::time::sleep(period) => {}
            gone = configured.wait_for(|on| !*on) => {
                let _ = gone;
                return;
            }
        }
    }
}

/// Presence tracking checks.
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use serde_json::json;

    const NOW: u64 = 1_800_000_000;

    fn wire(page: &Value) -> Vec<u8> {
        serde_json::to_vec(page).unwrap()
    }

    /// One presence row without an engine address.
    fn row(node: u64, handshake: u64, received: u64, keepalive: u64) -> PeerRow {
        PeerRow {
            node: NodeId(node),
            handshake,
            received,
            keepalive,
            endpoint: None,
        }
    }

    fn tracked(rows: Vec<PeerRow>) -> Tracker {
        let mut tracker = Tracker::default();
        tracker.record(Some((true, rows)), NOW);
        tracker
    }

    /// A recent handshake on a direct path counts as online.
    #[test]
    fn a_recent_handshake_is_online_on_a_direct_path() {
        let mut rows = Vec::new();
        let page = json!({"peers":[[3, NOW - 20, 925_000, 25]],"version":4,"next_cursor":null});
        assert_eq!(read_peers(&wire(&page), &mut rows), Some(None));
        assert_eq!(rows, [row(3, NOW - 20, 925_000, 25)]);
        let live = tracked(rows).live(None, NOW);
        assert_eq!(live.get(&NodeId(3)), Some(&Some(NodePath::Direct)));
    }

    /// A peer that is reachable only through the relay stays live while its received counter grows.
    #[test]
    fn a_relay_only_peer_stays_live_while_packets_arrive_without_a_direct_handshake() {
        let mut tracker = Tracker::default();
        tracker.record(Some((true, vec![row(3, 0, 100, 0)])), NOW);
        assert!(!tracker.live(None, NOW).contains_key(&NodeId(3)));

        tracker.record(Some((true, vec![row(3, 0, 101, 0)])), NOW + 5);
        assert_eq!(
            tracker.live(None, NOW + 5).get(&NodeId(3)),
            Some(&Some(NodePath::Relay)),
            "new received data proves an active path even without a server handshake"
        );

        let at_expiry = NOW + 5 + SESSION_SECS;
        tracker.record(Some((true, vec![row(3, 0, 101, 0)])), at_expiry);
        assert!(tracker.live(None, at_expiry).contains_key(&NodeId(3)));
        let after_expiry = at_expiry + 1;
        tracker.record(Some((true, vec![row(3, 0, 101, 0)])), after_expiry);
        assert!(!tracker.live(None, after_expiry).contains_key(&NodeId(3)));
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

    /// An unchanged cumulative receive counter is not fresh activity; handshake age still expires normally.
    #[test]
    fn an_unchanged_receive_counter_does_not_extend_a_direct_session() {
        let mut tracker = tracked(vec![row(3, NOW, 100, 25), row(4, NOW, 100, 25)]);
        for at in (5..=SESSION_SECS + 5).step_by(5) {
            tracker.record(
                Some((true, vec![row(3, NOW, 100, 25), row(4, NOW, 100, 25)])),
                NOW + at,
            );
            assert_eq!(
                tracker.live(None, NOW + at).len(),
                if at <= SESSION_SECS { 2 } else { 0 },
                "{at}"
            );
        }
    }

    /// Received packets refresh the activity window even when the direct handshake timestamp is absent.
    #[test]
    fn traffic_proves_a_relay_path_until_the_activity_window_ends() {
        let mut tracker = tracked(vec![row(3, 0, 0, 25)]);
        for at in (5..=SESSION_SECS).step_by(5) {
            tracker.record(Some((true, vec![row(3, 0, at, 25)])), NOW + at);
            assert!(
                tracker
                    .live(None, NOW + at)
                    .get(&NodeId(3))
                    .is_some_and(|path| *path == Some(NodePath::Relay)),
                "{at}"
            );
        }
        let at_expiry = NOW + SESSION_SECS * 2;
        tracker.record(Some((true, vec![row(3, 0, SESSION_SECS, 25)])), at_expiry);
        assert!(tracker.live(None, at_expiry).contains_key(&NodeId(3)));
        let after_expiry = at_expiry + 1;
        tracker.record(
            Some((true, vec![row(3, 0, SESSION_SECS, 25)])),
            after_expiry,
        );
        assert!(tracker.live(None, after_expiry).is_empty());
    }

    /// A reading expires once the node stops answering.
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

    /// A counter that grew across a gap between readings still counts as recent traffic.
    #[test]
    fn a_counter_delta_after_a_stale_poll_gap_keeps_a_recent_relay_peer_live() {
        let mut tracker = tracked(vec![row(3, 0, 100, 0)]);
        tracker.record(None, NOW + STALE.as_secs() + 1);
        let activity_at = NOW + STALE.as_secs() + 5;
        tracker.record(Some((true, vec![row(3, 0, 200, 0)])), activity_at);
        assert_eq!(
            tracker.live(None, activity_at).get(&NodeId(3)),
            Some(&Some(NodePath::Relay)),
            "a counter increase since the last reading proves activity within this recent gap"
        );

        let at_expiry = activity_at + SESSION_SECS;
        tracker.record(Some((true, vec![row(3, 0, 200, 0)])), at_expiry);
        assert!(tracker.live(None, at_expiry).contains_key(&NodeId(3)));
        let after_expiry = at_expiry + 1;
        tracker.record(Some((true, vec![row(3, 0, 200, 0)])), after_expiry);
        assert!(!tracker.live(None, after_expiry).contains_key(&NodeId(3)));
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
        received: u64,
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
                    json!({"peers":[[3, self.handshake, self.received, 0]],"next_cursor":null})
                }
                _ => return Box::pin(async { Err("unknown action") }),
            };
            Box::pin(async move { Ok(serde_json::to_vec(&reply).unwrap()) })
        }
    }

    /// The server and a peer passing traffic count as online.
    #[tokio::test]
    async fn the_server_and_a_peer_passing_traffic_are_online() {
        let node = ServerNode {
            state: "On",
            handshake: NOW - 30,
            received: 925_000,
        };
        let mut tracker = Tracker::default();
        tracker.record(observe(&node).await, NOW);
        assert_eq!(
            tracker.live(Some(NodeId(1)), NOW),
            Live::from([(NodeId(1), None), (NodeId(3), Some(NodePath::Direct))])
        );
    }

    /// A mesh that is off shows nobody online.
    #[tokio::test]
    async fn a_mesh_that_is_off_shows_nobody_online() {
        let node = ServerNode {
            state: "Off",
            handshake: NOW - 30,
            received: 925_000,
        };
        let mut tracker = Tracker::default();
        tracker.record(observe(&node).await, NOW);
        assert!(tracker.live(Some(NodeId(1)), NOW).is_empty());
    }

    /// An unreadable node counts as no reading.
    #[tokio::test]
    async fn an_unreadable_node_is_no_reading() {
        let node = ServerNode {
            state: "unreadable",
            handshake: 0,
            received: 0,
        };
        assert_eq!(observe(&node).await, None);
    }

    /// The server's own observation tracks relayed packets without a direct handshake.
    #[tokio::test]
    async fn a_server_observation_tracks_a_relay_packet_without_a_direct_handshake() {
        let mut tracker = Tracker::default();
        let before = ServerNode {
            state: "On",
            handshake: 0,
            received: 100,
        };
        tracker.record(observe(&before).await, NOW);
        let after = ServerNode {
            state: "On",
            handshake: 0,
            received: 101,
        };
        tracker.record(observe(&after).await, NOW + 5);
        assert_eq!(
            tracker.live(None, NOW + 5).get(&NodeId(3)),
            Some(&Some(NodePath::Relay))
        );
    }

    /// What each reading says about a node's server-reflexive address (#515): a new address is reported unproven,
    /// an address new packets or a newer handshake came from is proven, an unchanged quiet address is nothing, and an
    /// address that cannot be sent to is never reported.
    #[test]
    fn readings_report_new_and_proven_reflexive_addresses() {
        let first: SocketAddr = "198.51.100.21:30254".parse().unwrap();
        let rebound: SocketAddr = "198.51.100.21:30999".parse().unwrap();
        let mut rows = Vec::new();
        let page = json!({"peers":[[3, NOW - 20, 1000, 25, "198.51.100.21:30254"], [4, NOW - 20, 500, 25]],
            "version":4,"next_cursor":null});
        assert_eq!(read_peers(&wire(&page), &mut rows), Some(None));
        assert_eq!(rows[0].endpoint, Some(first));
        assert_eq!(rows[1].endpoint, None, "older rows have no address");
        let seen = |address, proven| Reflexive {
            node: NodeId(3),
            address,
            proven,
        };

        let mut tracker = Tracker::default();
        tracker.record(Some((true, rows.clone())), NOW);
        assert_eq!(
            tracker.reflexive(),
            [seen(first, false)],
            "a first reading reports the address, unproven"
        );

        // Quiet and unchanged: nothing new.
        tracker.record(Some((true, rows.clone())), NOW + 5);
        assert_eq!(tracker.reflexive(), Vec::<Reflexive>::new());

        // An idle node's NAT rebinds: its keepalive moves the address but adds no bytes.
        let mut moved = rows.clone();
        moved[0].endpoint = Some(rebound);
        tracker.record(Some((true, moved.clone())), NOW + 10);
        assert_eq!(tracker.reflexive(), [seen(rebound, false)]);

        // New data proves the address it came from.
        moved[0].received = 1100;
        moved[1].received = 600;
        tracker.record(Some((true, moved.clone())), NOW + 15);
        assert_eq!(tracker.reflexive(), [seen(rebound, true)]);

        // So does a newer handshake.
        moved[0].handshake = NOW + 18;
        tracker.record(Some((true, moved.clone())), NOW + 20);
        assert_eq!(tracker.reflexive(), [seen(rebound, true)]);

        // A loopback address (a relay shim) is never reported.
        moved[0].received = 1200;
        moved[0].endpoint = Some("127.0.0.1:4000".parse().unwrap());
        tracker.record(Some((true, moved)), NOW + 25);
        assert_eq!(tracker.reflexive(), Vec::<Reflexive>::new());
    }

    /// J602 F4 (#515): a handshake time that only moved by one second is the same handshake, so
    /// it proves nothing about the address the device holds.
    ///
    /// The engine reports a handshake as "wall clock minus its age", truncated to seconds, so the
    /// same handshake can read one second later (J587 deduplicates this in the walk, `tick`). Here
    /// it counts as a newer handshake, and the reading becomes *proven*. A proven reading
    /// bypasses the reflexive history (J585 F3), so if a snapshot compiled earlier has just put an
    /// old, dead address back on the server's device, that address is stored and republished.
    #[test]
    fn a_handshake_one_second_later_is_not_proof() {
        let current: SocketAddr = "198.51.100.21:30999".parse().unwrap();
        let stale: SocketAddr = "198.51.100.21:30254".parse().unwrap();
        let row = |handshake, endpoint| PeerRow {
            node: NodeId(3),
            handshake,
            received: 1_000,
            keepalive: 25,
            endpoint: Some(endpoint),
        };
        let mut tracker = Tracker::default();
        tracker.record(Some((true, vec![row(NOW - 20, current)])), NOW);
        // A delayed snapshot sets the old address; the same handshake reads one second later.
        tracker.record(Some((true, vec![row(NOW - 19, stale)])), NOW + 5);
        assert_eq!(
            tracker.reflexive(),
            [Reflexive {
                node: NodeId(3),
                address: stale,
                proven: false,
            }],
            "one second of reporting jitter proved the address a stale snapshot installed"
        );
    }
}
