//! Isolated harness entry point for mesh input and lifecycle fuzzing.
#![no_main]
#![forbid(unsafe_code)]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|_data: &[u8]| {});
