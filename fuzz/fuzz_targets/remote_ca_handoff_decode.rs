//! Exercises the bounded inherited CA handoff parser with arbitrary bytes [217], #154.

#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    let _ = infraternal_server::ca_handoff::parse(input);
    let _ = infraternal_server::ca_handoff_binary::has_note(input);
});
