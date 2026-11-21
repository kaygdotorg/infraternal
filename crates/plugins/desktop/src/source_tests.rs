//! Controls cleanup scheduling to prove a retired source generation cannot remove a freshly prepared UUID [D198,D232], #146.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::protocol::{Size, Target};
use std::{future::Future, task::Poll};

/// A valid window capture request for tests that exercise bridge lifecycle.
fn start() -> Start {
    Start {
        passive_geometry: false,
        target: Target::Screen { display_id: 1 },
        size: Size {
            width: 960,
            height: 600,
            canvas_width: 960.0,
            canvas_height: 600.0,
            backing_scale: 1.0,
        },
    }
}

#[tokio::test]
async fn duplicate_stop_cannot_remove_a_new_uuid_generation() {
    let bridge = SourceBridge::new("missing-runtime".into(), "missing-helper".into(), 2);
    bridge.set_enabled(true).await.unwrap();
    let id = Uuid::from_u128(1);
    bridge.prepare(id, start()).unwrap();
    let (released, cleanup) = oneshot::channel();
    let worker = Worker::new(
        watch::channel(false).0,
        None,
        None,
        tokio::spawn(async move {
            cleanup.await.unwrap();
            Outcome {
                output: Ok(Value::Null),
                cleanup: Ok(()),
            }
        }),
    );
    bridge
        .0
        .state
        .lock()
        .unwrap()
        .prepared
        .get_mut(&id)
        .unwrap()
        .worker = Some(worker);
    let mut first = Box::pin(bridge.stop(id));
    let mut duplicate = Box::pin(bridge.stop(id));
    // Poll both callers into the same cleanup before completing it. Keeping the
    // duplicate unpolled after the first completes makes UUID reuse deterministic.
    std::future::poll_fn(|context| {
        assert!(first.as_mut().poll(context).is_pending());
        assert!(duplicate.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    released.send(()).unwrap();
    first.await.unwrap();
    let mut replacement = start();
    replacement.target = Target::Screen { display_id: 2 };
    bridge.prepare(id, replacement.clone()).unwrap();
    duplicate.await.unwrap();
    assert!(bridge.status_value(Some(id)).is_ok());
    assert!(bridge.prepare(id, replacement).is_ok());
    assert_eq!(bridge.status_value(None).unwrap()["prepared_count"], 1);
}

#[tokio::test]
async fn replacement_leg_requires_successful_joined_previous_cleanup() {
    let bridge = SourceBridge::new("missing-runtime".into(), "missing-helper".into(), 2);
    bridge.set_enabled(true).await.unwrap();
    let id = Uuid::from_u128(1);
    bridge.prepare(id, start()).unwrap();
    let worker = Worker::new(
        watch::channel(false).0,
        None,
        None,
        tokio::spawn(async {
            Outcome {
                output: Err(PluginError::Rejected),
                cleanup: Err(PluginError::Rejected),
            }
        }),
    );
    assert!(worker.retire().await.is_err());
    assert!(worker.finished());
    bridge
        .0
        .state
        .lock()
        .unwrap()
        .prepared
        .get_mut(&id)
        .unwrap()
        .worker = Some(worker);
    assert!(bridge.retire_previous(id).await.is_err());
}

/// A link that offers desktop lanes switches the source on by itself; one that
/// does not (an HTTPS link, or a server without app windows) leaves it off, and
/// a dropped link never switches it off again (#146, D349).
#[tokio::test]
async fn desktop_lanes_on_the_link_switch_the_source_on() {
    let mut bridge = SourceBridge::new("missing-runtime".into(), "missing-helper".into(), 2);
    let id = Uuid::from_u128(7);
    AgentPlugin::transport_capabilities(&mut bridge, 0);
    assert!(bridge.prepare(id, start()).is_err(), "no lanes: still off");
    AgentPlugin::transport_capabilities(&mut bridge, WIRE.capability);
    assert!(bridge.prepare(id, start()).is_ok(), "lanes offered: on");
    AgentPlugin::transport_capabilities(&mut bridge, 0);
    assert!(bridge.0.state.lock().unwrap().enabled, "a drop keeps it on");
}

/// An explicit `desktop.down` in progress wins over a link coming up: the
/// switch is skipped while the lifecycle lock is held.
#[tokio::test]
async fn a_held_lifecycle_lock_blocks_the_automatic_switch() {
    let mut bridge = SourceBridge::new("missing-runtime".into(), "missing-helper".into(), 2);
    // A clone shares the same state, as the explicit switch's caller would.
    let explicit = bridge.clone();
    let held = explicit.0.lifecycle.try_lock().unwrap();
    AgentPlugin::transport_capabilities(&mut bridge, WIRE.capability);
    assert!(!bridge.0.state.lock().unwrap().enabled);
    drop(held);
}

/// A whole-screen session first shown for one console user is never shown
/// for another: a leg for someone else ends it for good, and the server's
/// next prepare reads `gone` (owner decision 2026-11-20, #146, D203 C2).
#[tokio::test]
async fn a_whole_screen_session_ends_when_the_person_at_the_screen_changes() {
    let bridge = SourceBridge::new("missing-runtime".into(), "missing-helper".into(), 2);
    bridge.set_enabled(true).await.unwrap();
    let id = Uuid::from_u128(7);
    bridge.prepare(id, start()).unwrap();
    let metadata = bridge.0.state.lock().unwrap().prepared[&id]
        .metadata
        .clone();
    assert!(
        metadata.bind_console(None),
        "a same-user helper never changes person"
    );
    assert!(
        metadata.bind_console(Some(501)),
        "the first person binds the session"
    );
    assert!(
        metadata.bind_console(Some(501)),
        "the same person may reattach"
    );
    assert_eq!(bridge.prepare(id, start()).unwrap()["state"], Value::Null);
    assert!(
        !metadata.bind_console(Some(502)),
        "another person must not see it"
    );
    assert_eq!(bridge.prepare(id, start()).unwrap()["state"], "gone");
}

/// A running leg that sees the console change ends its session the same way.
#[test]
fn a_console_change_during_a_leg_latches_gone() {
    let metadata = Metadata::new(start(), 0);
    assert!(metadata.bind_console(Some(501)));
    metadata.console_changed();
    assert!(metadata.gone.load(Ordering::Acquire));
    assert_eq!(metadata.gone_reason(), EndReason::ConsoleUserChanged);
}

/// A console change tells the server why through the `gone` reply, so the viewer
/// hears "the person changed" (Close 4411), while a closed window keeps its
/// default reason, and the first reason a session latched stays (#146).
#[tokio::test]
async fn the_gone_reply_names_a_console_change_and_the_first_reason_stays() {
    let bridge = SourceBridge::new("missing-runtime".into(), "missing-helper".into(), 2);
    bridge.set_enabled(true).await.unwrap();
    let (changed, closed) = (Uuid::from_u128(8), Uuid::from_u128(9));
    for id in [changed, closed] {
        bridge.prepare(id, start()).unwrap();
    }
    let metadata = |id| {
        bridge.0.state.lock().unwrap().prepared[&id]
            .metadata
            .clone()
    };
    metadata(changed).console_changed();
    metadata(closed).latch_gone(EndReason::WindowClosed);
    metadata(closed).console_changed();
    assert_eq!(
        bridge.prepare(changed, start()).unwrap()["reason"],
        "console_user_changed"
    );
    assert_eq!(
        bridge.prepare(closed, start()).unwrap()["reason"],
        "window_closed"
    );
}

/// Every window list after the first carries the icons the agent holds, and
/// `Helper::send` refuses a body the validator refuses, which left the picker
/// unanswered until the agent restarted (J992, #146). This drives the real
/// path: icons absorbed from a helper's inventory, then the next List body,
/// then the validator. It covers the full key count and the longest bundle
/// identifier the store keeps, so the store and the validator cannot drift.
#[test]
fn every_later_window_list_passes_the_helpers_validator() {
    use base64::Engine;
    let png =
        base64::engine::general_purpose::STANDARD.encode(crate::app_icons::tests::png(64, 64, 0));
    let mut icons = crate::app_icons::IconStore::default();
    let first = list_request(&icons).unwrap();
    crate::protocol::validate_command(Kind::List, &first).unwrap();
    let longest = "a".repeat(256);
    let mut entries: Vec<Value> = (0..crate::protocol::MAX_KNOWN_ICONS + 4)
        .map(|n| json!({"bundle_id": format!("org.example.app{n}"), "app_version": "1.0+1", "png_64": png}))
        .collect();
    entries.push(json!({"bundle_id": longest, "app_version": "v".repeat(128), "png_64": png}));
    let mut inventory = json!({"windows": [], "app_icons": entries});
    icons.absorb(&mut inventory);
    let later = list_request(&icons).unwrap();
    let request: Value = serde_json::from_slice(&later).unwrap();
    assert_eq!(
        request["known_icons"].as_array().map(Vec::len),
        Some(crate::protocol::MAX_KNOWN_ICONS)
    );
    crate::protocol::validate_command(Kind::List, &later).unwrap();
}
