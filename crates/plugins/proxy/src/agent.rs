//! Exposes `publish` and `unpublish` while accepting Mesh identity only from applied snapshots [#266, #281].

use crate::{
    cli::{PUBLISH_ACTION, UNPUBLISH_ACTION},
    controller::ProxyController,
    supervisor::ProxyLog,
};
use infraternal_plugin_api::{
    AgentPlugin, ComponentPlugin, Dependency, PluginDescriptor, PluginError, PluginState,
    PluginStatus, RoleDef, SchemaRef, SettingDefault,
    present::{Presented, Tone},
};
use serde_json::{Value, json};
use std::{io, path::Path, sync::Arc};

/// Node actions exposed by the compiled infraternal agent registry.
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "proxy",
    api: infraternal_plugin_api::API_VERSION,
    actions: &[PUBLISH_ACTION, UNPUBLISH_ACTION],
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

/// Calls the node-local publication book and its lazy Traefik supervisor.
#[derive(Clone, Default)]
pub struct ProxyAgentPlugin {
    controller: ProxyController,
}

impl ProxyAgentPlugin {
    /// Bind the proxy to the agent state directory and its sanitized log pipeline.
    ///
    /// # Errors
    /// Returns an error when the configured mirror or public DNS profile is malformed.
    pub fn for_agent(state_dir: &Path, log: Arc<ProxyLog>) -> io::Result<Self> {
        Ok(Self {
            controller: ProxyController::for_agent(state_dir, log)?,
        })
    }

    /// Share the controller with the Mesh accepted-configuration observer.
    #[must_use]
    pub fn controller(&self) -> ProxyController {
        self.controller.clone()
    }
}

impl AgentPlugin for ProxyAgentPlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }

    fn has_cli(&self) -> bool {
        true
    }

    fn present(
        &self,
        action_id: &str,
        output: &[u8],
        _width: usize,
    ) -> Result<Presented, PluginError> {
        let value: Value = serde_json::from_slice(output).map_err(|_| PluginError::Rejected)?;
        match action_id {
            "proxy.publish" => present_publications(value),
            "proxy.unpublish" => present_unpublish(&value),
            _ => Err(PluginError::UnknownAction),
        }
    }

    fn call(&mut self, action_id: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        self.controller.call(action_id, input)
    }
}

impl ComponentPlugin for ProxyAgentPlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }

    fn status(&self) -> PluginStatus {
        PluginStatus {
            state: if self.controller.is_enabled() {
                PluginState::On
            } else {
                PluginState::Off
            },
            active_work: 0,
        }
    }

    fn set_enabled(&self, enabled: bool) -> infraternal_plugin_api::PluginOperation<'_, ()> {
        Box::pin(async move {
            self.controller
                .set_enabled(enabled)
                .map_err(|_| "Proxy publication routes could not be updated.")
        })
    }
}

fn present_publications(value: Value) -> Result<Presented, PluginError> {
    let services = value
        .get("services")
        .and_then(Value::as_array)
        .ok_or(PluginError::Rejected)?;
    let message = if services.is_empty() {
        "No services are published.".to_owned()
    } else {
        format!("{} published service(s).", services.len())
    };
    let body = services
        .iter()
        .map(|service| {
            let url = service
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or("Unknown address");
            let access = service
                .get("access")
                .and_then(Value::as_str)
                .unwrap_or("Mesh access unavailable");
            format!("{url} · {access}")
        })
        .chain(
            value["containment"]["detail"]
                .as_str()
                .map(|detail| format!("Containment: {detail}")),
        )
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Presented {
        tone: if services
            .iter()
            .any(|service| service.get("reachable").and_then(Value::as_bool) == Some(false))
        {
            Tone::Attention
        } else {
            Tone::Good
        },
        message,
        body: if body.is_empty() {
            String::new()
        } else {
            format!("{body}\n")
        },
        next: Vec::new(),
        data: value,
    })
}

fn present_unpublish(value: &Value) -> Result<Presented, PluginError> {
    let message = value
        .get("message")
        .and_then(Value::as_str)
        .filter(|message| !message.trim().is_empty())
        .ok_or(PluginError::Rejected)?
        .to_owned();
    let data = value.get("data").cloned().unwrap_or_else(|| json!({}));
    Ok(Presented {
        tone: Tone::Good,
        message,
        body: String::new(),
        next: Vec::new(),
        data,
    })
}
