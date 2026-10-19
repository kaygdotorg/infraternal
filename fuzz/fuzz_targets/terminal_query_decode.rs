//! Checks bounded terminal-query state and identical identities across all output chunking [40][307].
#![no_main]
#![forbid(unsafe_code)]
use libfuzzer_sys::fuzz_target as check_sample;
check_sample!(|data: &[u8]| infraternal_server::verify_terminal_query_sample(data));
