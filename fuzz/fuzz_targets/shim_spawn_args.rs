//! Fuzz the fixed private shim invocation without executing a shell or touching state (#189).
#![no_main]

// Import the real CLI module so the harness cannot drift into a second decoder.
// Its runtime adapters and feature selection are outside this parser-only target.
#[allow(dead_code)]
#[path = "../../crates/infraternal/src/output.rs"]
mod output;
#[allow(dead_code, unexpected_cfgs)]
#[path = "../../crates/infraternal/src/shim_cli.rs"]
mod shim_cli;

use libfuzzer_sys::fuzz_target;
use std::{ffi::OsString, os::unix::ffi::OsStringExt};

fuzz_target!(|data: &[u8]| {
    if data.len() > 16_384 {
        return;
    }
    let arguments: Vec<_> = data
        .split(|byte| *byte == 0)
        .take(16)
        .map(|part| OsString::from_vec(part.to_vec()))
        .collect();
    if let Some(options) = shim_cli::Options::spawned(&arguments) {
        assert_eq!(options.session.len(), 32);
        assert!(options.session.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(
            options.state.as_ref().map(|state| state.as_os_str()),
            arguments.get(9).map(OsString::as_os_str)
        );
        assert_eq!(options.ring_capacity, 8 * 1024 * 1024);
        assert_eq!(options.exit_retention_ms, 600_000);
        assert!(arguments.len() <= 12);
    }
});
