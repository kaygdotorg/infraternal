//! Verifies the production source JSON boundary without authority, runtime or helper side effects [D40,D203,D232].
#![cfg(feature = "source")]
#![allow(clippy::unwrap_used)]
use infraternal_plugin_api::MAX_ACTION_BYTES;
use infraternal_plugin_desktop::source_request::{SourceRequest, decode};

const ID: &str = "00000000-0000-0000-0000-000000000001";
const START: &str = r#"{"session_id":"00000000-0000-0000-0000-000000000001","start":{"target":{"type":"screen","display_id":1},"size":{"width":960,"height":600,"canvas_width":960.0,"canvas_height":600.0,"backing_scale":1.0}}}"#;

#[test]
fn declared_actions_decode_their_existing_typed_shapes() {
    assert!(matches!(
        decode("desktop.up", b"{}"),
        Ok(SourceRequest::Enabled(true))
    ));
    assert!(matches!(
        decode("desktop.down", b"{}"),
        Ok(SourceRequest::Enabled(false))
    ));
    for action in ["desktop.status", "desktop.source.status"] {
        assert!(matches!(
            decode(action, b"{}"),
            Ok(SourceRequest::Status(None))
        ));
        let input = format!(r#"{{"session_id":"{ID}"}}"#);
        assert!(matches!(
            decode(action, input.as_bytes()),
            Ok(SourceRequest::Status(Some(_)))
        ));
    }
    assert!(
        matches!(decode("desktop.source.start", START.as_bytes()), Ok(SourceRequest::Start { session_id, start, sequence_floor: 0 }) if !session_id.is_nil() && start.size.width == 960)
    );
    let stop = format!(r#"{{"session_id":"{ID}"}}"#);
    assert!(matches!(
        decode("desktop.source.stop", stop.as_bytes()),
        Ok(SourceRequest::Stop(_))
    ));
    assert!(matches!(
        decode("desktop.source.clock", b"{}"),
        Ok(SourceRequest::Clock(None))
    ));
    assert!(
        matches!(decode("desktop.source.windows", br#"{"cursor":"snapshot:17"}"#), Ok(SourceRequest::Windows(Some(cursor))) if cursor == "snapshot:17")
    );
}

#[test]
fn source_decoder_rejects_duplicate_unknown_and_non_object_fields() {
    for action in [
        "desktop.up",
        "desktop.source.status",
        "desktop.source.stop",
        "desktop.source.windows",
        "desktop.source.clock",
        "desktop.source.start",
    ] {
        for input in [
            b"[]".as_slice(),
            b"null",
            br#"{"runtime":"foreign"}"#,
            b"{} {}",
            &[0xff],
        ] {
            assert!(
                decode(action, input).is_err(),
                "{action} accepted {input:?}"
            );
        }
    }
    for (action, input) in [
        (
            "desktop.source.status",
            r#"{"session_id":null,"session_id":null}"#.to_owned(),
        ),
        (
            "desktop.source.clock",
            format!(r#"{{"session_id":"{ID}","session_id":"{ID}"}}"#),
        ),
        (
            "desktop.source.windows",
            r#"{"cursor":null,"cursor":null}"#.to_owned(),
        ),
        (
            "desktop.source.stop",
            format!(r#"{{"session_id":"{ID}","session_id":"{ID}"}}"#),
        ),
        (
            "desktop.source.start",
            START.replace("\"width\":960", "\"width\":960,\"width\":960"),
        ),
        (
            "desktop.source.start",
            START.replace("\"display_id\":1", "\"display_id\":0"),
        ),
        (
            "desktop.source.start",
            START.replace("\"height\":600", "\"height\":601"),
        ),
        (
            "desktop.source.start",
            START.replace(ID, "00000000-0000-0000-0000-000000000000"),
        ),
        (
            "desktop.source.start",
            START.replacen('{', "{\"sequence_floor\":18446744073709551615,", 1),
        ),
        (
            "desktop.source.start",
            START.replacen('{', "{\"sequence_floor\":18446744073709551616,", 1),
        ),
        (
            "desktop.source.start",
            START.replacen('{', "{\"sequence_floor\":1,\"sequence_floor\":1,", 1),
        ),
    ] {
        assert!(
            decode(action, input.as_bytes()).is_err(),
            "{action} accepted {input}"
        );
    }
}

#[test]
fn exact_action_bound_is_accepted_and_extra_byte_is_rejected() {
    let mut input = b"{}".to_vec();
    input.resize(MAX_ACTION_BYTES, b' ');
    assert!(decode("desktop.up", &input).is_ok());
    input.push(b' ');
    assert!(decode("desktop.up", &input).is_err());
}
