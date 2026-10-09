//! Fuzzes the native facts empty-object boundary without scanning or launching a host process.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let accepted = infraternal_agent::facts::accepts_request(bytes);
    if accepted {
        assert!(bytes.len() <= 256);
        let value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert!(value.as_object().is_some_and(serde_json::Map::is_empty));
    }
});
