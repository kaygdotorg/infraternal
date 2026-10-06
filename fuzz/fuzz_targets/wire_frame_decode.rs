//! Checks direct raw/mux decoding and successful borrowed-frame round trips.
#![no_main]
#![forbid(unsafe_code)]
use infraternal_protocol::{
    decode_frame, decode_muxed_frame, encode_frame_into, encode_muxed_frame_into,
};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(decoded) = decode_frame(data) {
        let mut encoded = Vec::new();
        encode_frame_into(&decoded.frame, &mut encoded).unwrap();
        assert_eq!(encoded, data[..decoded.wire_len]);
    }
    if let Ok(decoded) = decode_muxed_frame(data) {
        let mut encoded = Vec::new();
        encode_muxed_frame_into(decoded.stream_id, &decoded.frame, &mut encoded).unwrap();
        assert_eq!(encoded, data[..decoded.wire_len]);
    }
});
