//! Tests for generic plugin metadata validation and bounded action dispatch.
use crate::{
    API_VERSION, ActionDef, AgentPlugin, Effect, PluginDescriptor, PluginError, PluginRegistry,
};

const ACTIONS: &[ActionDef] = &[ActionDef {
    target: crate::Target::Node,
    dry_run: crate::DryRun::Unsupported,
    opens: None,
    id: "example.read",
    summary: "Read example state",
    input: crate::SchemaRef("{}"),
    output: crate::SchemaRef("{}"),
    instructions: &["Read example state."],
    effect: Effect::Read,
    permission: crate::Permission::One("example.read"),
}];
const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    defaults: &[],
    dependencies: &[],
    can_enable_components: &[],
    events: &[],
    streams: &[],
    id: "example",
    api: API_VERSION,
    actions: ACTIONS,
    settings: Some(crate::SchemaRef("{}")),
    topics: &[],
    roles: &[crate::RoleDef {
        id: "node",
        requires: &[],
        default_enabled: true,
    }],
    max_frame_len: crate::MAX_ACTION_BYTES,
    unavailable: br#"{"error":"action unavailable"}"#,
    unavailable_event: br#"{"type":"error","error":"action unavailable"}"#,
};

struct EchoPlugin;

impl AgentPlugin for EchoPlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }

    fn call(&mut self, _: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        Ok(input.to_vec())
    }
}

#[test]
fn registry_routes_only_declared_actions() {
    let mut registry = PluginRegistry::default();
    registry
        .register(Box::new(EchoPlugin))
        .expect("valid descriptor");
    assert_eq!(registry.call("example.read", b"{}"), Ok(b"{}".to_vec()));
    assert_eq!(
        registry.call("other.read", b"{}"),
        Err(PluginError::UnknownAction)
    );
}

#[test]
fn registry_rejects_oversized_json_before_plugin_dispatch() {
    let mut registry = PluginRegistry::default();
    registry
        .register(Box::new(EchoPlugin))
        .expect("valid descriptor");
    let oversized = vec![b' '; crate::MAX_ACTION_BYTES + 1];
    assert_eq!(
        registry.call("example.read", &oversized),
        Err(PluginError::MessageTooLarge)
    );
}
