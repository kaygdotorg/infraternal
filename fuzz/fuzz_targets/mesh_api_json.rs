//! Fuzzes the production Mesh JSON action parser at the authenticated API boundary [164,187].
#![no_main]
#![forbid(unsafe_code)]

use infraternal_plugin_mesh::api::parse_action;
use libfuzzer_sys::fuzz_target;

const ACTIONS: [&str; 16] = [
    "mesh.list",
    "mesh.node.enroll",
    "mesh.node.observe",
    "mesh.node.rename",
    "mesh.node.delete",
    "mesh.tag.create",
    "mesh.tag.rename",
    "mesh.tag.delete",
    "mesh.tag.member.add",
    "mesh.tag.member.remove",
    "mesh.grant.create",
    "mesh.grant.move",
    "mesh.grant.delete",
    "mesh.grant.rename",
    "mesh.role.define",
    "mesh.role.assign",
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };
    let action = ACTIONS[usize::from(selector) % ACTIONS.len()];
    let _ = parse_action(action, input);
});
