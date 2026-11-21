//! Fuzzes PTY output into the shim's VT state: chunking independence, bounded snapshots and snapshot continuation [D13, D94], #561.
#![no_main]
#![forbid(unsafe_code)]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 65_536 {
        infraternal_shim::vt_checks::verify_vt_stream_sample(data);
    }
});
