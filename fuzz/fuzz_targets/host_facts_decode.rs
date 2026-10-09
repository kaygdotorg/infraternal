//! Fuzzes bounded host-facts JSON request decoding and the OS release parser.
#![no_main]
#![forbid(unsafe_code)]

use infraternal_plugin_host_facts::{
    decode_configure_request, decode_read_request, parse_load_average_text,
    parse_macos_load_average, parse_os_release,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let _ = decode_read_request(input);
    let _ = decode_configure_request(input);
    let _ = parse_macos_load_average(input);
    if let Ok(text) = std::str::from_utf8(input) {
        let _ = parse_load_average_text(text);
        let _ = parse_os_release(text);
    }
});
