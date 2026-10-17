//! Rejects ambiguous native ownership while preserving legacy descriptor JSON.
use super::*;
static VALID: WireStreamDef = WireStreamDef {
    browser_capability: None,
    capability: 256,
    opening_tag: 0x40,
    opening_identity: None,
    requests: &[0x40, 0x42, 0x43, 0x44],
    replies: &[0x41],
    max_streams: 50,
    datagram_tag: None,
    datagram_identity: None,
};
fn identity(_: &[u8]) -> Option<[u8; 16]> {
    None
}
#[test]
fn native_declarations_refuse_core_tags_ambiguous_capabilities_and_unbounded_admission() {
    assert!(VALID.validate().is_ok());
    for invalid in [
        WireStreamDef {
            browser_capability: None,
            capability: 0,
            ..VALID
        },
        WireStreamDef {
            browser_capability: None,
            capability: 1,
            ..VALID
        },
        WireStreamDef {
            browser_capability: None,
            capability: 3,
            ..VALID
        },
        WireStreamDef {
            max_streams: 0,
            ..VALID
        },
        WireStreamDef {
            max_streams: 129,
            ..VALID
        },
        WireStreamDef {
            opening_tag: 0x10,
            requests: &[0x10],
            ..VALID
        },
        WireStreamDef {
            opening_tag: 0x42,
            requests: &[0x40],
            ..VALID
        },
        WireStreamDef {
            requests: &[0x40, 0x40],
            ..VALID
        },
        WireStreamDef {
            replies: &[0x41, 0x41],
            ..VALID
        },
        WireStreamDef {
            replies: &[0x10],
            ..VALID
        },
        WireStreamDef {
            datagram_tag: Some(0x45),
            ..VALID
        },
        WireStreamDef {
            datagram_identity: Some(identity),
            ..VALID
        },
        WireStreamDef {
            datagram_tag: Some(0x41),
            datagram_identity: Some(identity),
            ..VALID
        },
    ] {
        assert!(invalid.validate().is_err());
    }
    assert!(
        WireStreamDef {
            datagram_tag: Some(0x45),
            datagram_identity: Some(identity),
            ..VALID
        }
        .validate()
        .is_ok()
    );
}
#[test]
fn absent_wire_metadata_preserves_legacy_json_and_denied_authority_is_never_live() {
    let stream = crate::StreamDef {
        id: "fixture.stream",
        schema: crate::SchemaRef("fixture.value"),
        resumable: true,
        wire: None,
    };
    assert_eq!(
        serde_json::to_value(stream).unwrap(),
        serde_json::json!({"id":"fixture.stream","schema":"fixture.value","resumable":true})
    );
    assert!(!Denied.permits());
}

#[test]
fn compiled_opening_decoder_does_not_change_descriptor_json() {
    let legacy = serde_json::to_value(VALID).unwrap();
    let compiled = serde_json::to_value(WireStreamDef {
        opening_identity: Some(identity),
        ..VALID
    })
    .unwrap();
    assert_eq!(legacy, compiled);
    assert!(compiled.get("opening_identity").is_none());
}

#[tokio::test]
async fn denied_authority_never_polls_a_forwarding_operation() {
    let polled = std::sync::atomic::AtomicBool::new(false);
    let result = Denied
        .authorized(Box::pin(async {
            polled.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }))
        .await;
    assert_eq!(result, Err(()));
    assert!(!polled.load(std::sync::atomic::Ordering::Relaxed));
}

#[test]
fn native_declarations_never_alias_core_leg_b_capabilities() {
    for capability in [
        1,
        crate::channel::REMOTE_WRITER_BINDING,
        crate::channel::LIVE_RENEWAL,
        crate::channel::SERVER_PATH_PROPOSALS,
        crate::channel::REMOTE_STANDBY,
        crate::channel::REMOTE_PRIMED_WRITERS,
    ] {
        assert!(
            WireStreamDef {
                capability,
                ..VALID
            }
            .validate()
            .is_err(),
            "native capability aliases reserved core bit {capability}"
        );
    }
}

#[test]
fn browser_projection_is_optional_validated_and_independent_of_native_bits() {
    assert_eq!(VALID.browser_capability(), 0);
    assert!(
        serde_json::to_value(VALID)
            .unwrap()
            .get("browser_capability")
            .is_none()
    );
    let split = WireStreamDef {
        browser_capability: Some(8),
        ..VALID
    };
    assert_eq!(split.capability, 256);
    assert_eq!(split.browser_capability(), 8);
    assert!(split.validate().is_ok());
    for bit in [0, 1, 2, 4, 7, 9] {
        assert!(
            WireStreamDef {
                browser_capability: Some(bit),
                ..VALID
            }
            .validate()
            .is_err()
        );
    }
}
