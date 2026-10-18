//! Round-4 presence regressions: an observed empty transport message is not a permanent sending promise (#236).
#![cfg(feature = "server")]
use infraternal_plugin_mesh::{
    policy::model::NodeId,
    presence::{PeerRow, Tracker},
};

const START: u64 = 1_800_000_000;

fn record(tracker: &mut Tracker, at: u64, handshake: u64, received: u64) -> bool {
    tracker.record(
        Some((
            true,
            vec![PeerRow {
                node: NodeId(3),
                handshake,
                received,
                keepalive: 25,
            }],
        )),
        START + at,
    );
    tracker.live(None, START + at).contains_key(&NodeId(3))
}

/// Receiving an authenticated empty message rearms the peer's persistent timer too. Once the server's own
/// timer wins, its empty messages can suppress the remote's sends for the rest of the session even with both
/// ends configured at 25 seconds. The remote's next handshake still completes normally.
#[test]
fn a_peer_with_25_second_keepalives_stays_online_when_server_keepalives_suppress_its_sends() {
    let mut tracker = Tracker::default();
    assert!(record(&mut tracker, 0, START, 180));
    assert!(record(&mut tracker, 30, START, 212));
    let mut offline = Vec::new();
    for at in (35..=105).step_by(5) {
        // Kernel fixture: server RX remains 212 while the client's RX grows from 92 to 188. Both peer
        // entries are configured at 25 seconds. Decreasing underlay delay lets server messages reach the
        // client before its timer fires. Receipt and bounded reproduction source are attached to #236.
        if !record(&mut tracker, at, START, 212) {
            offline.push(at);
        }
    }
    assert!(
        offline.is_empty(),
        "a healthy configured peer reads offline at logical seconds {offline:?}"
    );
}

/// A legacy peer may send one passive empty response ten seconds after receiving server data. That message
/// has the same length as a persistent keepalive, but commits it to no further idle sends.
#[test]
fn a_passive_keepalive_does_not_turn_later_silence_into_a_false_offline() {
    let mut tracker = Tracker::default();
    assert!(record(&mut tracker, 0, START, 180));
    assert!(record(&mut tracker, 10, START, 212));
    let mut offline = Vec::new();
    for at in (15..=160).step_by(5) {
        let (handshake, received) = if at < 130 {
            (START, 212)
        } else {
            (START + 130, 392)
        };
        if !record(&mut tracker, at, handshake, received) {
            offline.push(at);
        }
    }
    assert!(
        offline.is_empty(),
        "one passive reply poisoned later sessions: {offline:?}"
    );
}

/// Recreating a kernel peer resets its counters and handshake while keeping the inventory node ID. A
/// sending habit from the removed peer must not survive into the fresh peer's quiet live session.
#[test]
fn a_counter_reset_discards_the_previous_peers_keepalive_classification() {
    let mut tracker = Tracker::default();
    assert!(record(&mut tracker, 0, START, 1_000));
    assert!(record(&mut tracker, 25, START, 1_032));
    assert!(!record(&mut tracker, 30, 0, 0));
    assert!(record(&mut tracker, 35, START + 35, 180));
    let mut offline = Vec::new();
    for at in (40..=155).step_by(5) {
        if !record(&mut tracker, at, START + 35, 180) {
            offline.push(at);
        }
    }
    assert!(
        offline.is_empty(),
        "a recreated peer inherited the removed peer's habit: {offline:?}"
    );
}
