//! Fuzzes the infraternal agent's local control socket, saved session names, CLI replies and Hello OS token [D288, D339], #561.
#![no_main]
#![forbid(unsafe_code)]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 262_144 {
        infraternal_agent::control_checks::verify_control_message_sample(data);
    }
});
