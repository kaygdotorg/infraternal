//! Fuzzes the bounded manifest and SSHSIG parsers through the public opened-descriptor hook [224].
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::{fs::File, sync::OnceLock};
fuzz_target!(|input: &[u8]| {
    static EMPTY: OnceLock<File> = OnceLock::new();
    let file = EMPTY.get_or_init(|| File::open("/dev/null").unwrap());
    let Some(prefix) = input.get(..2) else {
        return;
    };
    let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    let Some(sums) = input.get(2..2 + length) else {
        return;
    };
    let signature = &input[2 + length..];
    let _ =
        infraternal_server::release_verify::verify_release_file(file, "payload", sums, signature);
});
