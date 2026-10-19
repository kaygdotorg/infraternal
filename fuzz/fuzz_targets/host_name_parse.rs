//! Checks host-name parser output invariants for arbitrary byte input.
#![no_main]
#![forbid(unsafe_code)]

use infraternal_plugin_api::host_name::machine_name;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if input.len() > 4096 {
        return;
    }
    let Ok(source) = std::str::from_utf8(input) else {
        return;
    };
    let Some(name) = machine_name(source) else {
        return;
    };
    assert!(!name.is_empty() && name.len() <= 63);
    assert!(!name.starts_with('-') && !name.ends_with('-'));
    assert!(
        name.bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    );
    assert_eq!(machine_name(&name).as_deref(), Some(name.as_str()));
});
