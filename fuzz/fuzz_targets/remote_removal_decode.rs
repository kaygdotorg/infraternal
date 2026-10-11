//! Exercises the production bounded removal and private uninstall request decoders (#87).
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    let _ = infraternal_server::remote_http::decode_removal_start(bytes);
    let _ = infraternal_server::remote_http::decode_removal_finish(bytes);
    let _ = infraternal_agent::plugins::decode_uninstall_request(bytes);
});
