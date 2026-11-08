//! Fuzzes strict canvas and account-look validation, plus reference round trips through the existing JSON engine [12,40,180].
#![no_main]
use infraternal_plugin_canvas::{model::Document, reducer::valid_intent};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|input: &[u8]| {
    if input.len() > 49 * 1024 {
        return;
    }
    if let Ok(document) = serde_json::from_slice::<Document>(input) {
        if document.valid() {
            let encoded = serde_json::to_vec(&document).unwrap();
            let decoded: Document = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(document, decoded);
            assert!(decoded.valid());
        }
        let _ = valid_intent(&document.0);
    }
    if let Ok(look) = serde_json::from_slice::<serde_json::Value>(input) {
        // Wrap one arbitrary JSON value in a valid canvas envelope so mutations can reach look validation without first
        // inventing a valid layout and window tree.
        let mut canvas = Document::default().0;
        canvas.as_object_mut().unwrap().insert("look".to_owned(), look);
        let document = Document(canvas);
        if document.valid() {
            let encoded = serde_json::to_vec(&document).unwrap();
            let decoded: Document = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(document, decoded);
            assert!(decoded.valid());
        }
    }
});
