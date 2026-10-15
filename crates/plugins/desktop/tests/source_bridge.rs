//! Proves disabled source admission and retained preparation without starting a helper [D198,D232], #146.
#![cfg(feature = "source")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_api::{AgentPlugin, ComponentPlugin, PluginState};
use infraternal_plugin_desktop::{
    protocol::{Size, Start, Target},
    source::SourceBridge,
};
use std::path::PathBuf;
use uuid::Uuid;

#[test]
fn replay_repairs_coalesce_at_the_source_interval() {
    let scratch =
        PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap()).join("desktop-replay-tests");
    let status = std::process::Command::new("python3")
        .arg("tests/fixtures/replay-pacing.py")
        .arg(scratch)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "replay repair fixture violated source pacing"
    );
}

fn start() -> Start {
    Start {
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
async fn preparation_requires_enable_and_idempotent_prepare_preserves_metadata() {
    let bridge = SourceBridge::new(
        PathBuf::from("missing-runtime"),
        PathBuf::from("missing-helper"),
        2,
    );
    assert_eq!(bridge.status().state, PluginState::Off);
    assert!(bridge.prepare(Uuid::from_u128(1), start()).is_err());
    bridge.set_enabled(true).await.unwrap();
    let ack = bridge.prepare(Uuid::from_u128(1), start()).unwrap();
    assert_eq!(ack["session_id"], Uuid::from_u128(1).to_string());
    assert_eq!(
        bridge.prepare(Uuid::from_u128(1), start()).unwrap()["sequence"],
        0
    );
    let mut different = start();
    different.target = Target::Screen { display_id: 2 };
    assert!(bridge.prepare(Uuid::from_u128(1), different).is_err());
    bridge.prepare(Uuid::from_u128(2), start()).unwrap();
    assert!(bridge.prepare(Uuid::from_u128(3), start()).is_err());
    bridge.set_enabled(false).await.unwrap();
    assert_eq!(bridge.status().state, PluginState::Off);
    assert_eq!(bridge.status().active_work, 0);
}

#[tokio::test]
async fn unsupported_transport_refuses_new_preparation_but_keeps_known_metadata() {
    let mut bridge = SourceBridge::new(
        PathBuf::from("missing-runtime"),
        PathBuf::from("missing-helper"),
        2,
    );
    bridge.set_enabled(true).await.unwrap();
    bridge.transport_capabilities(0);
    assert!(bridge.prepare(Uuid::from_u128(1), start()).is_err());
    bridge.transport_capabilities(infraternal_plugin_desktop::wire::WIRE.capability);
    bridge.prepare(Uuid::from_u128(1), start()).unwrap();
    bridge.transport_capabilities(0);
    assert!(bridge.prepare(Uuid::from_u128(2), start()).is_err());
    assert_eq!(
        bridge.prepare(Uuid::from_u128(1), start()).unwrap()["sequence"],
        0
    );
    bridge.set_enabled(false).await.unwrap();
}

#[tokio::test]
async fn lifecycle_json_obeys_the_frozen_action_bound_before_enabling() {
    let mut bridge = SourceBridge::new("missing-runtime".into(), "missing-helper".into(), 2);
    let mut input = b"{}".to_vec();
    input.resize(infraternal_plugin_api::MAX_ACTION_BYTES + 1, b' ');
    assert!(
        bridge
            .call_async("desktop.up", &input)
            .unwrap()
            .await
            .is_err()
    );
    assert_eq!(bridge.status().state, PluginState::Off);
}

#[cfg(target_os = "linux")]
#[path = "source/native.rs"]
mod native;
