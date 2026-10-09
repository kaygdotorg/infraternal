//! Fuzz production action, strict view and bounded topic parsers through their plugin declarations [12,164,187,198].
#![no_main]
#![forbid(unsafe_code)]

use infraternal_plugin_api::routing::subscription_topic;
use infraternal_plugin_mesh::{
    api::{MAX_MESH_FRAME_LEN, parse_action},
    descriptor::ACTIONS,
    parse_subscription,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };
    let action = ACTIONS[usize::from(selector) % ACTIONS.len()].id;
    let _ = parse_action(action, input);
    let _ = parse_subscription(input);
    let _ = subscription_topic(input, MAX_MESH_FRAME_LEN);
});
