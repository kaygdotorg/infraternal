//! Pins unpublish idempotence to the public node action contract [#281, D303].

use super::agent::ProxyAgentPlugin;
use infraternal_plugin_api::AgentPlugin;

fn missing_reply(target: &str) -> serde_json::Value {
    let mut plugin = ProxyAgentPlugin::default();
    let result = plugin.call(
        "proxy.unpublish",
        &serde_json::to_vec(&serde_json::json!({ "target": target }))
            .expect("encode unpublish request"),
    );
    assert!(
        result.is_ok(),
        "a missing target is a D303 result, not an unknown action: {result:?}"
    );
    serde_json::from_slice(&result.expect("unpublish result")).expect("unpublish result is JSON")
}

#[test]
fn unpublishing_a_missing_port_returns_d303_missing_idempotently() {
    let reply = missing_reply("3000");

    assert_eq!(reply["error"]["code"], "missing");
    assert_eq!(reply["message"], "No publication matches port 3000.");
}

#[test]
fn unpublishing_a_missing_name_returns_d303_missing_idempotently() {
    let reply = missing_reply("port-3000.host-2.ssh.kayg.org");

    assert_eq!(reply["error"]["code"], "missing");
    assert_eq!(
        reply["message"],
        "No publication matches port-3000.host-2.ssh.kayg.org."
    );
}

#[test]
fn publishing_without_an_accepted_mesh_context_returns_a_typed_unreachable_result() {
    let mut plugin = ProxyAgentPlugin::default();
    let result = plugin.call("proxy.publish", br#"{"port":3000}"#);

    assert!(
        result.is_ok(),
        "missing accepted Mesh context should use the shared error envelope: {result:?}"
    );
    let reply: serde_json::Value = serde_json::from_slice(&result.expect("typed publish result"))
        .expect("publish result is JSON");
    assert_eq!(reply["error"]["code"], "unreachable");
    assert_eq!(
        reply["message"],
        "Mesh identity is unavailable; turn Mesh on before publishing."
    );
}
