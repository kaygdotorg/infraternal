//! Fuzz the exact bounded public and coordinator-only node action parser without entering kernel work [12,169].
#![no_main]
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
use infraternal_plugin_api::AgentPlugin;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    #[cfg(target_os = "linux")]
    if let Some((&selector, input)) = data.split_first() {
        let plugin = infraternal_plugin_mesh::node_actions::MeshNodePlugin::default();
        let actions = infraternal_plugin_mesh::node_actions::ACTIONS;
        let controls = plugin.control_actions();
        let index = usize::from(selector) % (actions.len() + controls.len());
        let action = if index < actions.len() {
            &actions[index]
        } else {
            &controls[index - actions.len()]
        };
        let _ = infraternal_plugin_mesh::node_actions::parse_action(action.id, input);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = data;
});
