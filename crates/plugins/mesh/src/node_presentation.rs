//! Adds Linux `GotaTun` health to the shared mesh status presentation.

#[cfg(target_os = "linux")]
use infraternal_mesh_node::node_presentation::plural;
use infraternal_mesh_node::node_presentation::present_with;
use infraternal_plugin_api::{
    PluginError,
    present::{Presented, Tone},
};
use serde_json::Value;

/// Present the mesh node action with health from the host engine.
pub(crate) fn present(action: &str, output: &[u8], width: usize) -> Result<Presented, PluginError> {
    present_with(action, output, width, engine_health)
}

/// The Mac node reports no engine health yet, so its status has no health rows.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
fn engine_health(
    _value: &Value,
    _rows: &mut Vec<(&str, String)>,
) -> Result<Option<(Tone, String)>, PluginError> {
    Ok(None)
}

/// The `GotaTun` engine's health rows, and a replacement headline while it is stopped. Absent
/// for kernel `WireGuard`, and quiet while the engine has nothing to report.
#[cfg(target_os = "linux")]
fn engine_health(
    value: &Value,
    rows: &mut Vec<(&str, String)>,
) -> Result<Option<(Tone, String)>, PluginError> {
    let Some(engine) = value.get("engine").filter(|engine| !engine.is_null()) else {
        return Ok(None);
    };
    let health: crate::gotatun_node::EngineHealth =
        serde_json::from_value(engine.clone()).map_err(|_| PluginError::Rejected)?;
    if health.restarts > 0 {
        rows.push((
            "Engine",
            format!(
                "restarted {} after an error",
                plural(health.restarts, "time", "times")
            ),
        ));
    }
    if health.refused_frames > 0 {
        rows.push((
            "Dropped",
            format!(
                "{} this machine sent that the mesh could not read",
                plural(health.refused_frames, "packet", "packets")
            ),
        ));
    }
    let short_queue = health
        .tx_queue_len
        .filter(|&len| len < crate::gotatun_node::TUN_TX_QUEUE_LEN);
    if let Some(len) = short_queue {
        rows.push((
            "Queue",
            if len == 0 {
                "the TUN transmit queue could not be read; the engine needs 1024 packets".to_owned()
            } else {
                format!(
                    "the TUN transmit queue holds {len} packets, below the 1024 the engine needs; raising it needs network-admin rights"
                )
            },
        ));
    }
    Ok(if health.stopped {
        Some((
            Tone::Attention,
            "Mesh engine stopped on an error and restarts in a moment.".to_owned(),
        ))
    } else {
        short_queue.map(|_| {
            (
                Tone::Attention,
                "Mesh is on, but its TUN transmit queue is short and can drop packets under load."
                    .to_owned(),
            )
        })
    })
}

/// Linux-specific presentation checks use the real engine health schema.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;

    use infraternal_mesh_node::node_presentation::status_with;

    /// Run one status fixture through the shared presenter with Linux engine health.
    fn status(value: Value, width: usize) -> Result<Presented, PluginError> {
        status_with(value, width, engine_health)
    }

    /// Render engine restarts and queue warnings without adding rows for a healthy engine.
    #[test]
    #[cfg(target_os = "linux")]
    fn status_shows_a_stopped_or_restarted_engine_and_stays_quiet_when_healthy() {
        let healthy = serde_json::json!({"state":"On","peer_count":1,
            "engine":{"stopped":false,"restarts":0,"refused_frames":0}});
        let shown = status(healthy, 100).expect("healthy");
        assert_eq!(shown.message, "Mesh is on. 1 peer.");
        assert!(!shown.body.contains("Engine"), "{}", shown.body);
        let stopped = serde_json::json!({"state":"On","peer_count":1,
            "engine":{"stopped":true,"restarts":2,"refused_frames":1}});
        let shown = status(stopped, 100).expect("stopped");
        assert!(matches!(shown.tone, Tone::Attention));
        assert_eq!(
            shown.message,
            "Mesh engine stopped on an error and restarts in a moment."
        );
        assert!(
            shown.body.contains("restarted 2 times after an error"),
            "{}",
            shown.body
        );
        assert!(
            shown.body.contains("1 packet this machine sent"),
            "{}",
            shown.body
        );
        let short = serde_json::json!({"state":"On","peer_count":1,
            "engine":{"stopped":false,"restarts":0,"refused_frames":0,"tx_queue_len":500}});
        let shown = status(short, 120).expect("short queue");
        assert!(matches!(shown.tone, Tone::Attention));
        assert!(
            shown.message.contains("transmit queue is short"),
            "{}",
            shown.message
        );
        assert!(shown.body.contains("holds 500 packets"), "{}", shown.body);
        let raised = serde_json::json!({"state":"On","peer_count":1,
            "engine":{"stopped":false,"restarts":0,"refused_frames":0,"tx_queue_len":1024}});
        assert_eq!(
            status(raised, 100).expect("raised").message,
            "Mesh is on. 1 peer."
        );
        let kernel = serde_json::json!({"state":"On","peer_count":1,"engine":null});
        assert_eq!(
            status(kernel, 100).expect("kernel").message,
            "Mesh is on. 1 peer."
        );
    }
}
