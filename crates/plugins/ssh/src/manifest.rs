//! Declares SSH host provisioning actions and node defaults for all adapters [16][198][201][202].

use infraternal_plugin_api::{
    API_VERSION, ActionDef, DefaultValue, Dependency, DryRun, Effect, EventDef, Permission,
    PluginDescriptor, SchemaRef, SettingDefault, StreamDef, Target,
};

pub(crate) const CONCURRENT_HOSTS: usize = 8;
pub(crate) const CONCURRENT_BATCHES: usize = 16;

const fn action(
    id: &'static str,
    summary: &'static str,
    instructions: &'static [&'static str],
    input: &'static str,
    output: &'static str,
    effect: Effect,
) -> ActionDef {
    ActionDef {
        id,
        summary,
        instructions,
        input: SchemaRef(input),
        output: SchemaRef(output),
        target: Target::Node,
        effect,
        permission: Permission::One("ssh.manage"),
        dry_run: DryRun::Unsupported,
        opens: None,
        api_scope: None,
        fresh_passkey: false,
    }
}

/// Add-host: the one key-callable SSH action. Every adapter (browser socket, API-key
/// stream, CLI) names it directly rather than by its position in the descriptor.
pub const START: ActionDef = action(
    "ssh.start",
    "Set up selected hosts.",
    &[
        "Select the hosts and their setup mode.",
        "Confirm the setup steps, then follow each host's progress.",
    ],
    "ssh.start",
    "ssh.batch",
    Effect::Write,
)
.with_api_access(Some("hosts:write"), false);

/// Provisioning joins nodes to an existing server; component admission never initializes one.
pub static DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    topics: &[],
    roles: &[infraternal_plugin_api::RoleDef {
        id: "server",
        requires: &["server"],
        default_enabled: true,
    }],
    max_frame_len: 64 * 1024,
    unavailable: br#"{"error":"SSH host provisioning is off"}"#,
    unavailable_event: br#"{"error":"SSH host provisioning is off"}"#,
    id: "ssh",
    api: API_VERSION,
    // Provisioning streams use the component adapter's bounded event protocol.
    actions: &[
        START,
        action(
            "ssh.start-fresh",
            "Start fresh",
            &[
                "Select the host with leftovers from an earlier setup.",
                "Start fresh to remove its proven leftovers and continue the setup steps.",
            ],
            "ssh.start-fresh",
            "ssh.batch",
            Effect::Write,
        ),
        action(
            "ssh.retry",
            "Retry a host",
            &[
                "Select a failed host.",
                "Confirm its setup steps and retry with current login material.",
            ],
            "ssh.retry",
            "ssh.batch",
            Effect::Write,
        ),
        action(
            "ssh.confirm-host-key",
            "Confirm an SSH host",
            &[
                "Verify the displayed fingerprint through a trusted source.",
                "Confirm the current observation and retry the host check.",
            ],
            "ssh.confirm-host-key",
            "ssh.confirmed",
            Effect::Write,
        ),
        action(
            "ssh.replay",
            "Read host setup progress",
            &[
                "Provide the last observed sequence.",
                "Read retained events or refresh the current batch.",
            ],
            "ssh.replay",
            "ssh.events",
            Effect::Read,
        ),
        action(
            "ssh.setup-watch",
            "Read a host's remaining setup steps",
            &[
                "Select the host and its existing terminal window.",
                "Read retained setup stages, then follow live updates.",
            ],
            "ssh.setup-watch",
            "ssh.setup-event",
            Effect::Read,
        ),
        action(
            "ssh.setup-retry",
            "Retry remaining setup steps",
            &[
                "Select a host with failed setup steps.",
                "Retry with current owner access; keep its existing terminal session.",
            ],
            "ssh.setup-retry",
            "ssh.setup-event",
            Effect::Write,
        ),
        action(
            "ssh.up",
            "Turn on SSH host provisioning",
            &["Choose an existing node.", "Turn on its SSH component."],
            "ssh.empty",
            "ssh.status",
            Effect::Write,
        ),
        action(
            "ssh.down",
            "Turn off SSH host provisioning",
            &[
                "Choose the node's SSH component.",
                "Wait for its host work and cleanup to finish.",
            ],
            "ssh.empty",
            "ssh.status",
            Effect::Write,
        ),
        action(
            "ssh.status",
            "Read SSH component status",
            &[
                "Choose a node.",
                "Read its component state and active work count.",
            ],
            "ssh.empty",
            "ssh.status",
            Effect::Read,
        ),
    ],
    events: &[
        EventDef {
            id: "ssh.progress",
            schema: SchemaRef("ssh.event"),
        },
        EventDef {
            id: "ssh.setup",
            schema: SchemaRef("ssh.setup-event"),
        },
    ],
    streams: &[StreamDef::json(
        "ssh.progress",
        SchemaRef("ssh.event"),
        true,
    )],
    settings: Some(SchemaRef("ssh.settings")),
    defaults: &[
        SettingDefault {
            id: "enabled",
            value: DefaultValue::Bool(true),
        },
        SettingDefault {
            id: "concurrent-hosts",
            value: DefaultValue::Unsigned(CONCURRENT_HOSTS as u64),
        },
        SettingDefault {
            id: "concurrent-batches",
            value: DefaultValue::Unsigned(CONCURRENT_BATCHES as u64),
        },
        SettingDefault {
            id: "setup-mode",
            value: DefaultValue::Text("rootless"),
        },
    ],
    dependencies: &[Dependency::ExistingServer],
    can_enable_components: &["agent"],
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn node_provisioning_declares_an_existing_server_and_only_node_components() {
        assert!(DESCRIPTOR.validate().is_ok());
        assert_eq!(DESCRIPTOR.dependencies, &[Dependency::ExistingServer]);
        assert_eq!(DESCRIPTOR.can_enable_components, &["agent"]);
        assert!(
            DESCRIPTOR
                .actions
                .iter()
                .all(|action| !action.id.contains("server"))
        );
    }
}
