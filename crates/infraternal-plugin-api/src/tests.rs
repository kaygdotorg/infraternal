//! Tests for generic plugin metadata validation and bounded action dispatch.
use crate::{
    API_VERSION, ActionDef, AgentPlugin, Effect, PluginDescriptor, PluginError, PluginRegistry,
};

const ACTIONS: &[ActionDef] = &[ActionDef {
    target: crate::Target::Node,
    dry_run: crate::DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
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

struct DeferredPlugin(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl AgentPlugin for DeferredPlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    fn call(&mut self, _: &str, _: &[u8]) -> Result<Vec<u8>, PluginError> {
        Err(PluginError::Rejected)
    }
    fn call_with_reply(&mut self, _: &str, _: &[u8]) -> Result<crate::ActionReply, PluginError> {
        let counter = self.0.clone();
        Ok(crate::ActionReply {
            json: b"{}".to_vec(),
            after_write: Some(Box::new(move || {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })),
        })
    }
}
#[test]
fn deferred_plugin_effect_waits_for_successful_reply_and_drops_on_cancellation() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let counter = Arc::new(AtomicUsize::new(0));
    let mut registry = PluginRegistry::default();
    registry
        .register(Box::new(DeferredPlugin(counter.clone())))
        .unwrap();
    drop(registry.call_with_reply("example.read", b"{}").unwrap());
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    assert_eq!(
        registry.call("example.read", b"{}"),
        Err(PluginError::Rejected)
    );
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    let mut reply = registry.call_with_reply("example.read", b"{}").unwrap();
    assert_eq!(counter.load(Ordering::SeqCst), 0);
    reply.after_write.take().unwrap()();
    assert_eq!(counter.load(Ordering::SeqCst), 1);
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
            registry.present("example.read", b"{}", 80).map(|p| p.data),
            Ok(serde_json::json!({}))
        );
        assert_eq!(
            registry.present("example.configure", b"{}", 80),
            Err(PluginError::UnknownAction)
        );
        assert_eq!(
            registry.present("example.read", &vec![b' '; crate::MAX_ACTION_BYTES + 1], 80),
            Err(PluginError::MessageTooLarge)
        );
    }
}

struct AsyncPlugin(std::sync::Arc<tokio::sync::Notify>);
impl AgentPlugin for AsyncPlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    fn call(&mut self, _: &str, _: &[u8]) -> Result<Vec<u8>, PluginError> {
        Err(PluginError::Rejected)
    }
    fn call_async(
        &mut self,
        _: &str,
        input: &[u8],
    ) -> Option<crate::Operation<'static, Result<crate::ActionReply, PluginError>>> {
        let input = input.to_vec();
        let ready = self.0.clone();
        Some(Box::pin(async move {
            ready.notified().await;
            Ok(crate::ActionReply {
                json: input,
                after_write: None,
            })
        }))
    }
}

#[tokio::test]
async fn asynchronous_control_owns_its_work_without_holding_the_registry() {
    let ready = std::sync::Arc::new(tokio::sync::Notify::new());
    let mut registry = PluginRegistry::default();
    registry
        .register(Box::new(AsyncPlugin(ready.clone())))
        .unwrap();
    let operation = registry.begin_call("example.read", b"{}").unwrap();
    assert!(registry.begin_call("unknown.read", b"{}").is_err());
    assert!(
        registry
            .begin_call("example.read", &vec![0; crate::MAX_ACTION_BYTES + 1])
            .is_err()
    );
    drop(registry);
    ready.notify_one();
    assert_eq!(operation.await.unwrap().json, b"{}");
}

#[tokio::test]
async fn asynchronous_control_preserves_synchronous_deferred_effects() {
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut registry = PluginRegistry::default();
    registry
        .register(Box::new(DeferredPlugin(counter.clone())))
        .unwrap();
    drop(registry.begin_call("example.read", b"{}").unwrap());
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 0);
    let mut reply = registry
        .begin_call("example.read", b"{}")
        .unwrap()
        .await
        .unwrap();
    reply.after_write.take().unwrap()();
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
}

struct DeniedProvider;
impl crate::streams::WireProvider for DeniedProvider {
    fn serve(
        &self,
        _: &'static crate::streams::WireStreamDef,
        _: bytes::Bytes,
        _: std::sync::Arc<dyn crate::streams::WireLane>,
    ) -> crate::Operation<'static, Result<(), ()>> {
        Box::pin(async { Err(()) })
    }
}
struct NativePlugin(&'static PluginDescriptor);
impl AgentPlugin for NativePlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        self.0
    }
    fn call(&mut self, _: &str, _: &[u8]) -> Result<Vec<u8>, PluginError> {
        Ok(b"{}".to_vec())
    }
    fn wire_provider(&self) -> Option<std::sync::Arc<dyn crate::streams::WireProvider>> {
        Some(std::sync::Arc::new(DeniedProvider))
    }
}
const NATIVE: crate::streams::WireStreamDef = crate::streams::WireStreamDef {
    browser_capability: None,
    capability: 256,
    opening_tag: 0x40,
    opening_identity: None,
    requests: &[0x40],
    replies: &[0x41],
    max_streams: 128,
    datagram_tag: None,
    datagram_identity: None,
};
static NATIVE_DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    streams: &[crate::StreamDef {
        id: "example.native",
        schema: crate::SchemaRef("example.wire"),
        resumable: false,
        wire: Some(NATIVE),
    }],
    ..DESCRIPTOR
};
static CONFLICTING_DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "other",
    actions: &[ActionDef {
        id: "other.read",
        ..ACTIONS[0]
    }],
    streams: &[crate::StreamDef {
        id: "other.native",
        schema: crate::SchemaRef("other.wire"),
        resumable: false,
        wire: Some(NATIVE),
    }],
    ..DESCRIPTOR
};

#[test]
fn native_discovery_refuses_undeclared_and_ambiguous_providers() {
    let mut registry = PluginRegistry::default();
    registry.register(Box::new(EchoPlugin)).unwrap();
    assert!(registry.wire_providers().unwrap().is_empty());
    let mut registry = PluginRegistry::default();
    registry
        .register(Box::new(NativePlugin(&DESCRIPTOR)))
        .unwrap();
    assert!(matches!(
        registry.wire_providers(),
        Err(PluginError::InvalidDescriptor)
    ));
    let mut registry = PluginRegistry::default();
    registry
        .register(Box::new(NativePlugin(&NATIVE_DESCRIPTOR)))
        .unwrap();
    assert_eq!(
        registry.wire_providers().unwrap()[0].definition.capability,
        256
    );
    registry
        .register(Box::new(NativePlugin(&CONFLICTING_DESCRIPTOR)))
        .unwrap();
    assert!(matches!(
        registry.wire_providers(),
        Err(PluginError::InvalidDescriptor)
    ));
}

struct TransportProbe(std::sync::Arc<std::sync::atomic::AtomicU64>);
impl AgentPlugin for TransportProbe {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    fn call(&mut self, _: &str, _: &[u8]) -> Result<Vec<u8>, PluginError> {
        Ok(b"{}".to_vec())
    }
    fn transport_capabilities(&mut self, capabilities: u64) {
        self.0
            .store(capabilities, std::sync::atomic::Ordering::SeqCst);
    }
}
#[test]
fn transport_capability_withdrawal_reaches_compiled_node_providers() {
    let caps = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
    let mut registry = PluginRegistry::default();
    registry
        .register(Box::new(TransportProbe(caps.clone())))
        .unwrap();
    for negotiated in [8, 0, 16, 0] {
        registry.transport_capabilities(negotiated);
        assert_eq!(caps.load(std::sync::atomic::Ordering::SeqCst), negotiated);
    }
}

#[cfg(feature = "socket-host")]
#[tokio::test]
async fn bulk_reply_completion_waits_for_the_last_transport_packet_reference() {
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let sender = crate::ReplySender::new(tx, "desktop", 7);
    let mut send = tokio::spawn(async move {
        sender
            .send_and_wait(bytes::Bytes::from_static(b"packet"))
            .await
    });
    let packet = rx.recv().await.unwrap();
    let retained = packet.wire.clone();
    drop(packet);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), &mut send)
            .await
            .is_err()
    );
    assert_eq!(retained.as_ref(), b"packet");
    drop(retained);
    assert_eq!(send.await.unwrap(), Ok(()));
}

#[test]
fn native_providers_cannot_alias_distinct_lanes_to_one_browser_capability() {
    const FIRST: crate::StreamDef = crate::StreamDef {
        wire: Some(crate::streams::WireStreamDef {
            browser_capability: Some(8),
            ..NATIVE
        }),
        ..NATIVE_DESCRIPTOR.streams[0]
    };
    const SECOND: crate::StreamDef = crate::StreamDef {
        wire: Some(crate::streams::WireStreamDef {
            capability: 512,
            browser_capability: Some(8),
            opening_tag: 0x50,
            requests: &[0x50],
            replies: &[0x51],
            ..NATIVE
        }),
        ..CONFLICTING_DESCRIPTOR.streams[0]
    };
    static FIRST_DESCRIPTOR: PluginDescriptor = PluginDescriptor {
        streams: &[FIRST],
        ..NATIVE_DESCRIPTOR
    };
    static SECOND_DESCRIPTOR: PluginDescriptor = PluginDescriptor {
        streams: &[SECOND],
        ..CONFLICTING_DESCRIPTOR
    };
    let combined = PluginDescriptor {
        streams: &[FIRST, SECOND],
        ..DESCRIPTOR
    };
    assert!(combined.validate().is_err());
    let mut registry = PluginRegistry::default();
    registry
        .register(Box::new(NativePlugin(&FIRST_DESCRIPTOR)))
        .unwrap();
    registry
        .register(Box::new(NativePlugin(&SECOND_DESCRIPTOR)))
        .unwrap();
    assert!(matches!(
        registry.wire_providers(),
        Err(PluginError::InvalidDescriptor)
    ));
}

#[test]
fn native_only_providers_do_not_collide_on_absent_browser_projection() {
    static SECOND_DESCRIPTOR: PluginDescriptor = PluginDescriptor {
        streams: &[crate::StreamDef {
            wire: Some(crate::streams::WireStreamDef {
                capability: 512,
                opening_tag: 0x50,
                requests: &[0x50],
                replies: &[0x51],
                ..NATIVE
            }),
            ..CONFLICTING_DESCRIPTOR.streams[0]
        }],
        ..CONFLICTING_DESCRIPTOR
    };
    let mut registry = PluginRegistry::default();
    registry
        .register(Box::new(NativePlugin(&NATIVE_DESCRIPTOR)))
        .unwrap();
    registry
        .register(Box::new(NativePlugin(&SECOND_DESCRIPTOR)))
        .unwrap();
    assert_eq!(registry.wire_providers().unwrap().len(), 2);
}

#[test]
fn native_lanes_start_above_every_core_leg_b_bit() {
    use crate::channel::{
        LIVE_RENEWAL, MIN_NATIVE_STREAM_CAPABILITY, REMOTE_PATH_BACKUP, REMOTE_PATH_PROOF,
        REMOTE_PRIMED_WRITERS, REMOTE_STANDBY, REMOTE_WRITER_BINDING, SERVER_PATH_PROPOSALS,
    };
    // Bit 0 is the resume bit. A plugin lane that shares any of these bits
    // would be negotiated by a peer that only meant the core transport feature.
    let core = 1
        | REMOTE_WRITER_BINDING
        | LIVE_RENEWAL
        | SERVER_PATH_PROPOSALS
        | REMOTE_STANDBY
        | REMOTE_PRIMED_WRITERS
        | REMOTE_PATH_BACKUP
        | REMOTE_PATH_PROOF;
    assert_eq!(MIN_NATIVE_STREAM_CAPABILITY.count_ones(), 1);
    assert!(MIN_NATIVE_STREAM_CAPABILITY > core);
}

/// J137 P2-2, D319: a destructive action is key-callable only behind its own fresh passkey.
#[test]
fn destructive_actions_need_a_fresh_passkey_to_be_key_callable() {
    let base = ACTIONS[0];
    let read = base.with_api_access(Some("hosts:read"), false);
    assert!(read.key_callable());
    assert!(!base.key_callable(), "no scope, no key");
    let destructive = ActionDef {
        effect: Effect::Destructive,
        ..base
    };
    assert!(
        !destructive
            .with_api_access(Some("hosts:write"), false)
            .key_callable(),
        "a destructive action without a fresh passkey is never key-callable"
    );
    assert!(
        destructive
            .with_api_access(Some("hosts:write"), true)
            .key_callable()
    );
}
