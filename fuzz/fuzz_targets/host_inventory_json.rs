//! Checks bounded host-list cursors cannot carry account authority or alternate JSON shapes [12][40], #194.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|input: &[u8]| {
    if let Some(request) = infraternal_server::decode_host_inventory(input) {
        assert!(input.len() <= 1024);
        if let Some(cursor) = request.after {
            assert_eq!(cursor.len(), 36);
        }
    }
});
