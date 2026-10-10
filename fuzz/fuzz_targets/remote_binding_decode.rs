//! Fuzzes bounded native-stream binding without granting any host/session authority [40][64], #78.
#![no_main]

use infraternal_agent::remote_quic::binding_writer;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(writer) = binding_writer(bytes) {
        assert_ne!(writer, 0);
        assert_eq!(writer & 1, 0);
        assert!(bytes.len() <= 128);
        let mut suffix = bytes.to_vec();
        suffix.push(0);
        assert!(binding_writer(&suffix).is_err());
    }
});
