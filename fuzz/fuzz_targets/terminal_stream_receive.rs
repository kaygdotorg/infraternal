//! Fuzzes how the server reassembles browser terminal stream frames from WebSocket messages (leg A) [D63], #561.
#![no_main]
#![forbid(unsafe_code)]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 262_144 {
        infraternal_server::verify_receive_wire_sample(data);
    }
});
