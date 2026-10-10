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

const EVENTS: &[crate::EventDef] = &[crate::EventDef {
    id: "example.changed",
    schema: crate::SchemaRef("Empty"),
}];
const EVENT_DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    events: EVENTS,
    ..DESCRIPTOR
};
const CONTROL_ACTIONS: &[ActionDef] = &[ActionDef {
    id: "example.configure",
    ..ACTIONS[0]
}];
struct EventPlugin {
    event: Option<(&'static str, Vec<u8>)>,
}
impl AgentPlugin for EventPlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &EVENT_DESCRIPTOR
    }
    fn control_actions(&self) -> &'static [ActionDef] {
        CONTROL_ACTIONS
    }
    fn take_events(&mut self) -> Vec<(&'static str, Vec<u8>)> {
        self.event.take().into_iter().collect()
    }
    fn call(&mut self, _: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        Ok(input.to_vec())
    }
}
#[test]
fn machine_actions_are_declared_without_entering_human_discovery() {
    let mut registry = PluginRegistry::default();
    registry
        .register(Box::new(EventPlugin { event: None }))
        .unwrap();
    assert_eq!(
        registry.call("example.configure", b"{}"),
        Ok(b"{}".to_vec())
    );
    let metadata = serde_json::to_string(&EVENT_DESCRIPTOR).unwrap();
    assert!(metadata.contains("example.read"));
    assert!(!metadata.contains("example.configure"));
}
#[test]
fn notifications_are_declared_json_bounded_and_drained_once() {
    for (id, body, expected) in [
        ("example.changed", b"{}".to_vec(), None),
        ("other.changed", b"{}".to_vec(), Some(PluginError::Rejected)),
        (
            "example.changed",
            b"not json".to_vec(),
            Some(PluginError::Rejected),
        ),
        (
            "example.changed",
            vec![b' '; 1025],
            Some(PluginError::Rejected),
        ),
        (
            "example.changed",
            serde_json::to_vec(&"x".repeat(1000)).unwrap(),
            Some(PluginError::MessageTooLarge),
        ),
    ] {
        let mut registry = PluginRegistry::default();
        registry
            .register(Box::new(EventPlugin {
                event: Some((id, body)),
            }))
            .unwrap();
        let result = registry.events();
        if let Some(error) = expected {
            assert_eq!(result, Err(error));
        } else {
            let events = result.unwrap();
            assert_eq!(events.len(), 1);
            let event: serde_json::Value = serde_json::from_slice(&events[0]).unwrap();
            assert_eq!(event["type"], "plugin.event");
            assert_eq!(event["id"], "example.changed");
        }
        assert_eq!(registry.events().unwrap(), Vec::<Vec<u8>>::new());
    }
}

#[test]
fn public_dispatch_cannot_call_a_machine_control_action() {
    struct Controlled;
    const CONTROL: &[ActionDef] = &[ActionDef {
        id: "example.control",
        ..ACTIONS[0]
    }];
    impl AgentPlugin for Controlled {
        fn descriptor(&self) -> &'static PluginDescriptor {
            &DESCRIPTOR
        }
        fn control_actions(&self) -> &'static [ActionDef] {
            CONTROL
        }
        fn call(&mut self, _: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
            Ok(input.to_vec())
        }
    }
    let mut registry = PluginRegistry::default();
    registry
        .register(Box::new(Controlled))
        .expect("valid declarations");
    assert_eq!(
        registry.call_public("example.read", b"{}"),
        Ok(b"{}".to_vec())
    );
    assert_eq!(
        registry.call_public("example.control", b"{}"),
        Err(PluginError::UnknownAction)
    );
    assert_eq!(registry.call("example.control", b"{}"), Ok(b"{}".to_vec()));
}

#[test]
fn operator_presentation_cannot_follow_a_private_control_action() {
    struct Presented(Option<&'static str>);
    impl AgentPlugin for Presented {
        fn descriptor(&self) -> &'static PluginDescriptor {
            &DESCRIPTOR
        }
        fn control_actions(&self) -> &'static [ActionDef] {
            CONTROL_ACTIONS
        }
        fn has_cli(&self) -> bool {
            true
        }
        fn human_status_action(&self, _: &str) -> Option<&'static str> {
            self.0
        }
        fn call(&mut self, _: &str, _: &[u8]) -> Result<Vec<u8>, PluginError> {
            panic!("presentation must never execute actions")
        }
    }
    for (followup, expected) in [
        (None, Ok(None)),
        (Some("example.read"), Ok(Some("example.read"))),
        (Some("example.configure"), Err(PluginError::Rejected)),
    ] {
        let mut registry = PluginRegistry::default();
        registry.register(Box::new(Presented(followup))).unwrap();
        assert_eq!(registry.cli_descriptors().len(), 1);
        assert_eq!(registry.human_status_action("example.read"), expected);
        assert_eq!(
            registry.human_status_action("example.configure"),
            Err(PluginError::UnknownAction)
        );
        assert_eq!(
            registry.format_human("example.read", b"{}"),
            Ok("{}".to_owned())
        );
        assert_eq!(
            registry.format_human("example.configure", b"{}"),
            Err(PluginError::UnknownAction)
        );
        assert_eq!(
            registry.format_human("example.read", &vec![b' '; crate::MAX_ACTION_BYTES + 1]),
            Err(PluginError::MessageTooLarge)
        );
    }
}
