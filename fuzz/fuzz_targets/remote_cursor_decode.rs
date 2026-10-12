//! Fuzzes the bounded native standby cursor shape and verifies exact round trips [215], #129.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let decoded = infraternal_agent::remote_cursor::decode(input);
    if input.len() > infraternal_agent::remote_cursor::MAX_CURSOR_JSON {
        assert!(decoded.is_err());
    }
    if let Ok(out_seq) = decoded {
        assert_eq!(input.trim_ascii_start().first(), Some(&b'{'));
        let encoded = serde_json::to_vec(&serde_json::json!({ "out_seq": out_seq })).unwrap();
        assert!(encoded.len() <= infraternal_agent::remote_cursor::MAX_CURSOR_JSON);
        assert_eq!(
            infraternal_agent::remote_cursor::decode(&encoded).unwrap(),
            out_seq
        );
    }
});
