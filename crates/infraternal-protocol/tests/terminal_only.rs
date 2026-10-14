//! Proves a terminal-only protocol image omits desktop tags while retaining unchanged terminal framing [D198,D232], #146.
#![cfg(not(feature = "desktop"))]
use infraternal_protocol::{DecodeError, Frame, decode_frame, encode_frame_into};
#[test]
fn unavailable_extension_is_refused_and_terminal_bytes_round_trip() {
    let size = [7, 0x42, 0xc0, 3, 0x58, 2, 0xe8, 3];
    assert!(matches!(
        decode_frame(&size),
        Err(DecodeError::UnknownType(0x42))
    ));
    let frame = Frame::Output {
        out_seq: 7,
        bytes: b"unchanged terminal bytes",
    };
    let mut bytes = Vec::new();
    assert!(encode_frame_into(&frame, &mut bytes).is_ok());
    assert!(matches!(decode_frame(&bytes),Ok(decoded) if decoded.frame==frame));
}
