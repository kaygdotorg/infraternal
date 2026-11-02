//! Exercises the exact pure source action decoder used before admission/helper work, including bounded strict fields and canonical request round trips [D40,D203,D232].
#![no_main]
use infraternal_plugin_api::MAX_ACTION_BYTES;
use infraternal_plugin_desktop::{
    source_manifest::DESCRIPTOR,
    source_request::{SourceRequest, decode},
};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };
    let action = DESCRIPTOR.actions[usize::from(selector) % DESCRIPTOR.actions.len()].id;
    let decoded = decode(action, input);
    if input.len() > MAX_ACTION_BYTES {
        assert!(decoded.is_err());
    }
    if let Ok(request) = decoded {
        assert!(serde_json::from_slice::<Value>(input).unwrap().is_object());
        let mut canonical = match request {
            SourceRequest::Enabled(_) => json!({}),
            SourceRequest::Status(id) | SourceRequest::Clock(id) => json!({"session_id":id}),
            SourceRequest::Start {
                session_id,
                start,
                sequence_floor,
            } => {
                assert!(!session_id.is_nil());
                assert!(sequence_floor < u64::MAX);
                start.validate().unwrap();
                json!({"session_id":session_id,"start":start,"sequence_floor":sequence_floor})
            }
            SourceRequest::Stop(id) => json!({"session_id":id}),
            SourceRequest::Windows(cursor) => json!({"cursor":cursor}),
        };
        let normalized = serde_json::to_vec(&canonical).unwrap();
        assert!(decode(action, &normalized).is_ok());
        // Accepted shapes cannot become executable/runtime configuration by
        // adding a foreign field, even when the rest of the request is valid.
        canonical["foreign_runtime"] = json!("untrusted");
        assert!(decode(action, &serde_json::to_vec(&canonical).unwrap()).is_err());
    }
});
