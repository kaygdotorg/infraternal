//! Desktop wire decoder roundtrip and incremental envelope boundaries [D12,D40,D232].
#![no_main]
#![forbid(unsafe_code)]
use infraternal_protocol::{
    Frame, MuxStreamDecoder, decode_frame, encode_frame_into, encode_muxed_frame_into,
};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if let Ok(decoded) = decode_frame(bytes)
        && let Frame::Desktop(message) = decoded.frame
    {
        message.validate().unwrap();
        let mut encoded = Vec::new();
        encode_frame_into(&decoded.frame, &mut encoded).unwrap();
        assert_eq!(encoded, &bytes[..decoded.wire_len]);
        for split in [0, encoded.len() / 2, encoded.len().saturating_sub(1)] {
            assert!(matches!(
                decode_frame(&encoded[..split]),
                Err(infraternal_protocol::DecodeError::Incomplete)
            ));
        }
        encode_muxed_frame_into(146, &decoded.frame, &mut encoded).unwrap();
        let split = usize::from(bytes.first().copied().unwrap_or(0)) % encoded.len();
        let mut decoder = MuxStreamDecoder::new();
        let mut seen = 0;
        for part in [&encoded[..split], &encoded[split..]] {
            decoder
                .feed(part, |stream, frame| {
                    assert_eq!(stream, 146);
                    assert_eq!(frame, decoded.frame);
                    seen += 1;
                })
                .unwrap();
        }
        assert_eq!(seen, 1);
        assert_eq!(decoder.buffered_len(), 0);
    }
});
