//! Fuzzes the buffered SSH packet reader and its 256-byte read-ahead across key changes and hostile bytes (#538, D289).
#![no_main]
#![forbid(unsafe_code)]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A packet body is capped at about 256 KiB; inputs past 64 KiB only slow
    // the run without reaching new reader states.
    if data.len() <= 65_536 {
        russh::cipher::fuzz_hook::check_packet_reads(data);
    }
});
