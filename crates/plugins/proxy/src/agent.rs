//! Declares the node-side publication action and refuses until trusted mesh DNS and grants are present [#266, #281].

use crate::cli::PUBLISH_ACTION;
use infraternal_plugin_api::{
    AgentPlugin, Dependency, PluginDescriptor, PluginError, RoleDef, SchemaRef, SettingDefault,
};
use serde::Deserialize;

/// Node action exposed through the compiled infraternal agent registry.
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "proxy",
    api: infraternal_plugin_api::API_VERSION,
    actions: &[PUBLISH_ACTION],
    topics: &[],
    settings: Some(SchemaRef(
        r#"{"type":"object","properties":{"enabled":{"type":"boolean","default":true}},"additionalProperties":false}"#,
    )),
    defaults: &[SettingDefault {
        id: "enabled",
        value: infraternal_plugin_api::DefaultValue::Bool(true),
    }],
    dependencies: &[Dependency::ExistingServer],
    can_enable_components: &[],
    events: &[],
    streams: &[],
    roles: &[RoleDef {
        id: "node",
        requires: &[],
        default_enabled: true,
    }],
    max_frame_len: infraternal_plugin_api::MAX_ACTION_BYTES,
    unavailable: br#"{"error":"Proxy publication is unavailable."}"#,
    unavailable_event: br#"{"type":"error","error":"Proxy publication is unavailable."}"#,
};

/// Implements listing while refusing publication without trusted mesh DNS and service grants.
#[derive(Default)]
pub struct ProxyAgentPlugin;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishRequest {
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    public: bool,
    #[serde(default)]
    confirm_public: bool,
    #[serde(default)]
    flat_name: bool,
}

impl AgentPlugin for ProxyAgentPlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }

    fn call(&mut self, action_id: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        if action_id != "proxy.publish" {
            return Err(PluginError::UnknownAction);
        }
        let request: PublishRequest =
            serde_json::from_slice(input).map_err(|_| PluginError::Rejected)?;
        match request.port {
            None if !request.public && !request.confirm_public && !request.flat_name => {
                serde_json::to_vec(&serde_json::json!({"services": []}))
                    .map_err(|_| PluginError::Rejected)
            }
            Some(port) if port > 0 => {
                // #266's trusted suffix and grant revision are not present in this base.
                // Fail closed until an accepted context can authorize a concrete route.
                Err(PluginError::Rejected)
            }
            _ => Err(PluginError::Rejected),
        }
    }
}
