//! Background counts come only from trusted host context, never a facts request [D178], #151.
use super::*;
use infraternal_plugin_api::{AgentPlugin, admission::NodeContext};

#[test]
fn host_owned_session_counts_are_additive_and_refresh_on_request() {
    let mut plugin = HostFactsPlugin::new(AgentMode::Embedded);
    let initial: serde_json::Value =
        serde_json::from_slice(&plugin.call("host.facts.read", b"{}").unwrap()).unwrap();
    assert!(initial.get("sessionCount").is_none());
    for context in [
        NodeContext {
            session_count: 200,
            background_session_count: 180,
        },
        NodeContext::default(),
    ] {
        plugin.update_context(context);
        let facts: serde_json::Value =
            serde_json::from_slice(&plugin.call("host.facts.read", b"{}").unwrap()).unwrap();
        assert_eq!(facts["sessionCount"], context.session_count);
        assert_eq!(
            facts["backgroundSessionCount"],
            context.background_session_count
        );
    }
    assert!(
        plugin
            .call("host.facts.read", br#"{"sessionCount":999}"#)
            .is_err()
    );
}
