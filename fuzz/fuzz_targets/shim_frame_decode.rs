//! Fuzz complete payloads and fragmented/coalesced stream framing [12][40].
#![no_main]
#![forbid(unsafe_code)]
use infraternal_shim::frame::{Decoder, Frame};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if let Ok(frame) = Frame::decode(bytes)
        && let Ok(wire) = frame.encode()
    {
        assert_eq!(Frame::decode(&wire[4..]).ok(), Some(frame));
    }
    for chunk in [1, 3, 17, 16384] {
        let mut decoder = Decoder::default();
        for part in bytes.chunks(chunk) {
            if decoder.feed(part).is_err() {
                break;
            }
        }
    }
});
