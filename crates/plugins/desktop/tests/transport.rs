//! Session ownership, decoder dependency and bounded datagram regressions [D104,D208,D232].
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_desktop::{
    datagram::{FRAGMENT_BYTES, Reassembler, fragments},
    session::{AccessRules, Error, HostCommand, Session, Video},
};
use infraternal_protocol::desktop::{Input, Message};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
struct Access(AtomicBool);
impl AccessRules for Access {
    fn may_view(&self, user: &str, _host: &str, owner: &str) -> bool {
        self.0.load(Ordering::Acquire) && (user == owner || user == "watcher")
    }
    fn may_control(&self, user: &str, _host: &str, owner: &str) -> bool {
        self.0.load(Ordering::Acquire) && user == owner
    }
}
fn video(sequence: u64, keyframe: bool, size: usize) -> Video {
    Video {
        sequence,
        capture_ns: 42,
        keyframe,
        bytes: vec![7; size].into(),
    }
}
fn session() -> (
    Arc<Session>,
    tokio::sync::mpsc::Receiver<HostCommand>,
    Arc<Access>,
) {
    let access = Arc::new(Access(AtomicBool::new(true)));
    let (session, commands) = Session::new([1; 16], "mac".into(), "owner".into(), access.clone());
    (session, commands, access)
}
#[tokio::test]
async fn cached_idr_is_immediate_but_current_deltas_wait_for_fresh_idr() {
    let (session, mut commands, _) = session();
    session.publish(video(1, true, 100)).unwrap();
    session.publish(video(9, false, 100)).unwrap();
    let mut viewer = session.attach("owner".into()).unwrap();
    assert_eq!(commands.recv().await, Some(HostCommand::Keyframe));
    assert_eq!(viewer.next().await.unwrap().sequence, 1);
    session.publish(video(10, false, 100)).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), viewer.next())
            .await
            .is_err()
    );
    session.publish(video(11, true, 100)).unwrap();
    assert_eq!(viewer.next().await.unwrap().sequence, 11);
    session.publish(video(12, false, 100)).unwrap();
    assert_eq!(viewer.next().await.unwrap().sequence, 12);
}
#[tokio::test]
async fn stalled_viewer_repairs_without_stalling_sibling_and_session_survives_detach() {
    let (session, mut commands, _) = session();
    let mut fast = session.attach("owner".into()).unwrap();
    let mut slow = session.attach("watcher".into()).unwrap();
    assert_eq!(commands.recv().await, Some(HostCommand::Keyframe));
    session.publish(video(1, true, 100)).unwrap();
    assert_eq!(fast.next().await.unwrap().sequence, 1);
    assert_eq!(slow.next().await.unwrap().sequence, 1);
    for sequence in 2..=10 {
        session.publish(video(sequence, false, 100)).unwrap();
        assert_eq!(fast.next().await.unwrap().sequence, sequence);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(10), slow.next())
            .await
            .is_err()
    );
    assert_eq!(commands.recv().await, Some(HostCommand::Keyframe));
    assert_eq!(session.retained_bytes(), 200);
    session.publish(video(11, true, 100)).unwrap();
    assert_eq!(slow.next().await.unwrap().sequence, 11);
    drop(fast);
    drop(slow);
    let mut reconnect = session.attach("owner".into()).unwrap();
    assert_eq!(reconnect.next().await.unwrap().sequence, 11);
}
#[tokio::test]
async fn viewer_cap_live_access_rules_handover_and_disable_are_enforced() {
    let (session, mut commands, access) = session();
    let viewers: Vec<_> = (0..5)
        .map(|_| session.attach("owner".into()).unwrap())
        .collect();
    assert!(matches!(session.attach("owner".into()), Err(Error::Limit)));
    assert!(matches!(
        session.attach("stranger".into()),
        Err(Error::Forbidden)
    ));
    commands.recv().await.unwrap();
    viewers[0].take_control().unwrap();
    assert!(matches!(
        commands.recv().await,
        Some(HostCommand::Control { .. })
    ));
    let key = Input::Key {
        keycode: 0,
        down: true,
        modifiers: 0,
    };
    viewers[0].input(key).unwrap();
    assert_eq!(
        commands.recv().await,
        Some(HostCommand::Input {
            viewer: 1,
            lease: 1,
            input: key
        })
    );
    viewers[1].take_control().unwrap();
    assert!(matches!(
        commands.recv().await,
        Some(HostCommand::Control { .. })
    ));
    assert_eq!(viewers[0].input(key), Err(Error::Forbidden));
    viewers[1].resize(960, 600, 2000).unwrap();
    assert_eq!(
        commands.recv().await,
        Some(HostCommand::Size {
            viewer: 2,
            lease: 2,
            width: 960,
            height: 600,
            density_milli: 2000
        })
    );
    access.0.store(false, Ordering::Release);
    assert_eq!(viewers[1].input(key), Err(Error::Forbidden));
    assert_eq!(viewers[1].resize(960, 600, 2000), Err(Error::Forbidden));
    session.close();
    assert_eq!(session.retained_bytes(), 0);
    assert_eq!(session.publish(video(1, true, 10)), Err(Error::Unavailable));
}
#[test]
fn reversed_fragments_duplicates_conflicts_foreign_sessions_and_shapes() {
    let id = [1; 16];
    let frame = video(1, true, 3 * FRAGMENT_BYTES + 17);
    let mut packets = Vec::new();
    fragments(&id, &frame, |message| {
        packets.push(message);
        Ok(())
    })
    .unwrap();
    let mut receiver = Reassembler::new(id);
    let now = Instant::now();
    assert!(receiver.push(packets[3], now).unwrap().is_none());
    assert!(receiver.push(packets[3], now).unwrap().is_none());
    let mut foreign = packets[0];
    if let Message::Fragment { session_id, .. } = &mut foreign {
        *session_id = &[2; 16];
    }
    assert!(matches!(receiver.push(foreign, now), Err(Error::Forbidden)));
    for packet in packets[..2].iter().rev() {
        assert!(receiver.push(*packet, now).unwrap().is_none());
    }
    let decoded = receiver.push(packets[2], now).unwrap().unwrap();
    assert_eq!(decoded.bytes, frame.bytes);
    assert_eq!(receiver.retained_bytes(), 0);
    let mut receiver = Reassembler::new(id);
    receiver.push(packets[0], now).unwrap();
    let corrupted = [8; FRAGMENT_BYTES];
    let mut conflict = packets[0];
    if let Message::Fragment { bytes, .. } = &mut conflict {
        *bytes = &corrupted;
    }
    assert!(matches!(receiver.push(conflict, now), Err(Error::Invalid)));
    let mut malformed = packets[0];
    if let Message::Fragment { offset, .. } = &mut malformed {
        *offset = 1;
    }
    assert!(matches!(receiver.push(malformed, now), Err(Error::Invalid)));
}
#[test]
fn missing_frame_expires_once_and_deltas_wait_for_idr() {
    let id = [1; 16];
    let now = Instant::now();
    let first = video(1, true, 2048);
    let mut receiver = Reassembler::new(id);
    let mut packets = Vec::new();
    fragments(&id, &first, |message| {
        packets.push(message);
        Ok(())
    })
    .unwrap();
    receiver.push(packets[0], now).unwrap();
    assert!(receiver.deadline().is_some());
    receiver.expire(now + Duration::from_millis(251));
    assert_eq!(receiver.retained_bytes(), 0);
    assert!(receiver.take_repair());
    assert!(!receiver.take_repair());
    assert!(receiver.deadline().is_none());
    let delta = video(2, false, 100);
    fragments(&id, &delta, |message| {
        assert!(receiver.push(message, now).unwrap().is_none());
        Ok(())
    })
    .unwrap();
    assert!(receiver.take_repair());
    let key = video(3, true, 100);
    fragments(&id, &key, |message| {
        assert!(receiver.push(message, now).unwrap().is_some());
        Ok(())
    })
    .unwrap();
    assert!(!receiver.take_repair());
    let delta = video(4, false, 100);
    fragments(&id, &delta, |message| {
        assert!(receiver.push(message, now).unwrap().is_some());
        Ok(())
    })
    .unwrap();
}

#[tokio::test]
async fn queued_commands_cannot_inherit_a_replacement_controller_or_revoked_access_rule() {
    let (session, mut commands, access) = session();
    let first = session.attach("owner".into()).unwrap();
    commands.recv().await.unwrap();
    first.take_control().unwrap();
    commands.recv().await.unwrap();
    first
        .input(Input::Key {
            keycode: 1,
            down: true,
            modifiers: 0,
        })
        .unwrap();
    let queued = commands.recv().await.unwrap();
    assert!(session.command_allowed(queued).unwrap());
    let second = session.attach("owner".into()).unwrap();
    second.take_control().unwrap();
    assert!(!session.command_allowed(queued).unwrap());
    commands.recv().await.unwrap();
    second
        .input(Input::Key {
            keycode: 2,
            down: true,
            modifiers: 0,
        })
        .unwrap();
    let queued = commands.recv().await.unwrap();
    assert!(session.command_allowed(queued).unwrap());
    access.0.store(false, Ordering::SeqCst);
    assert!(!session.command_allowed(queued).unwrap());
    access.0.store(true, Ordering::SeqCst);
    drop(second);
    assert!(!session.command_allowed(queued).unwrap());
    session.close();
    assert!(session.command_allowed(HostCommand::ReleaseInput).unwrap());
}

#[test]
fn registry_disable_clears_retention_and_ends_existing_viewers() {
    use infraternal_plugin_desktop::registry::Registry;
    let registry = Registry::new(1);
    let (session, _commands, _access_rules) = session();
    assert_eq!(registry.insert(session.clone()), Err(Error::Unavailable));
    registry.set_enabled(true).unwrap();
    registry.insert(session.clone()).unwrap();
    assert_eq!(registry.insert(session.clone()), Err(Error::Invalid));
    session.publish(video(1, true, 4097)).unwrap();
    let _viewer = registry.attach(&session.id(), "owner".into()).unwrap();
    assert_eq!(registry.retained_bytes(), 4097);
    registry.set_enabled(false).unwrap();
    assert!(registry.is_empty());
    assert_eq!(registry.retained_bytes(), 0);
    assert_eq!(session.retained_bytes(), 0);
    assert_eq!(session.publish(video(2, true, 10)), Err(Error::Unavailable));
    registry.set_enabled(true).unwrap();
    assert!(matches!(
        registry.attach(&session.id(), "owner".into()),
        Err(Error::Unavailable)
    ));
}

#[test]
fn lost_delta_fragments_coalesce_repair_and_retry_on_new_sequence() {
    let id = [1; 16];
    let now = Instant::now();
    let mut receiver = Reassembler::new(id);
    let delta = video(2, false, 2048);
    let mut packets = Vec::new();
    fragments(&id, &delta, |message| {
        packets.push(message);
        Ok(())
    })
    .unwrap();
    receiver.push(packets[0], now).unwrap();
    assert!(receiver.take_repair());
    receiver.push(packets[1], now).unwrap();
    assert!(
        !receiver.take_repair(),
        "one lost frame must not repair once per fragment"
    );
    receiver
        .push(
            packets[0],
            now + infraternal_plugin_desktop::session::ASSEMBLY_TIMEOUT,
        )
        .unwrap();
    assert!(
        !receiver.take_repair(),
        "a duplicate missing frame cannot repeat control work"
    );
    let retry = video(3, false, 1);
    fragments(&id, &retry, |message| {
        receiver.push(message, now).unwrap();
        Ok(())
    })
    .unwrap();
    assert!(
        receiver.take_repair(),
        "a lost replacement IDR must permit immediate retry on a new sequence"
    );
    receiver.push(packets[0], now).unwrap();
    assert!(
        !receiver.take_repair(),
        "late older fragments cannot alternate repair sequences"
    );
    let idr = video(4, true, 1);
    fragments(&id, &idr, |message| {
        assert!(
            receiver
                .push(message, now + Duration::from_millis(251))
                .unwrap()
                .is_some()
        );
        Ok(())
    })
    .unwrap();
    let gap = video(6, false, 1);
    fragments(&id, &gap, |message| {
        receiver
            .push(message, now + Duration::from_millis(252))
            .unwrap();
        Ok(())
    })
    .unwrap();
    assert!(
        receiver.take_repair(),
        "a recovered dependency resets repair coalescing"
    );
}

#[test]
fn a_new_missing_frame_can_repair_before_the_prior_assembly_timeout() {
    let id = [1; 16];
    let now = Instant::now();
    let mut receiver = Reassembler::new(id);
    for sequence in [2, 3] {
        let frame = video(sequence, false, 1);
        fragments(&id, &frame, |message| {
            receiver.push(message, now).unwrap();
            Ok(())
        })
        .unwrap();
        assert!(
            receiver.take_repair(),
            "new dependency loss cannot wait on an unrelated earlier frame"
        );
    }
}
