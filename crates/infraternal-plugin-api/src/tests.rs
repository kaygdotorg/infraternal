//! Tests for generic plugin metadata validation and bounded action dispatch.
use crate::{
    API_VERSION, ActionDef, AgentPlugin, Effect, PluginDescriptor, PluginError, PluginRegistry,
    SettingsDef, Target,
};

const ACTIONS: &[ActionDef] = &[ActionDef {
    id: "example.read",
    summary: "Read example state",
    input_schema: "{}",
    output_schema: "{}",
    target: Target::Host,
    effect: Effect::Read,
    permission: "example.read",
}];
const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "example",
    api: API_VERSION,
    actions: ACTIONS,
    settings: SettingsDef {
        schema: "{}",
        defaults: "{}",
        configure_action: "example.read",
    },
    role_dependencies: &[],
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
