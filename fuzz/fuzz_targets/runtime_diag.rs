//! Checks kernel socket-diagnostic dump datagrams against unexpected input (#230).
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Some(owners) = infraternal_plugin_remote::runtime_lock::check_diagnostic_datagram(data) {
        // Accepted records are 20, 48 or 60 bytes, so a datagram holds at most len/20.
        assert!(owners.len() <= data.len() / 20);
        assert_eq!(data.is_empty(), owners.is_empty());
    }
});
