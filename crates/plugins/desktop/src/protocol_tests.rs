//! Parser properties and rejected control inputs for the local desktop trust boundary.
use super::protocol::*;
use std::io;

#[test]
fn split_at_every_byte_and_coalesced_messages_are_lossless() {
    let mut encoded = Vec::new();
    write(&mut encoded, Kind::List, b"{}").unwrap();
    for split in 0..encoded.len() {
        assert!(decode(&encoded[..split]).unwrap().is_none());
    }
    let (frame, used) = decode(&encoded).unwrap().unwrap();
    assert_eq!(
        frame,
        Frame {
            kind: Kind::List,
            payload: b"{}"
        }
    );
    assert_eq!(used, encoded.len());
    let mut twice = encoded.clone();
    twice.extend_from_slice(&encoded);
    assert_eq!(decode(&twice).unwrap().unwrap().1, encoded.len());
    assert_eq!(
        read(&mut encoded.as_slice()).unwrap(),
        (Kind::List, b"{}".to_vec())
    );
}
#[test]
fn bad_headers_are_rejected_without_payload_allocation() {
    for length in [0, 1, u32::try_from(MAX_FRAME).unwrap() + 1, u32::MAX] {
        assert!(decode(&length.to_be_bytes()).is_err());
    }
    for header in [
        [0, 0, 0, 2, 2, 1],
        [0, 0, 0, 2, 1, 0],
        [0, 1, 0, 1, 1, 1],
        [0, 0, 0, 3, 1, 70],
    ] {
        assert!(decode(&header).is_err());
    }
    let mut video = vec![0; 10];
    video[8] = 2;
    assert!(write(&mut Vec::new(), Kind::Video, &video).is_err());
    assert_eq!(
        read(&mut [0, 0, 0, 3, 1, 1].as_slice()).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
}
#[test]
fn controls_validate_identity_dimensions_and_nonfinite_coordinates() {
    let start = br#"{"target":{"type":"window","window_id":1,"owner_pid":3},"size":{"width":960,"height":600,"canvas_width":480,"canvas_height":300,"backing_scale":2}}"#;
    validate_command(Kind::Start, start).unwrap();
    validate_command(Kind::List, b"{}").unwrap();
    for body in [
        b"[]".as_slice(),
        br#"{"unexpected":true}"#,
        b"null",
        b"{",
        br#"{"width":0}"#,
    ] {
        assert!(validate_command(Kind::List, body).is_err());
    }
    assert!(validate_command(Kind::Video, b"{}").is_err());
    let mut size = Size {
        width: 960,
        height: 600,
        canvas_width: 480.0,
        canvas_height: 300.0,
        backing_scale: 2.0,
    };
    size.validate().unwrap();
    size.canvas_width = f64::NAN;
    assert!(size.validate().is_err());
    size.canvas_width = 480.0;
    size.width = 4096;
    size.height = 4096;
    assert!(size.validate().is_err());
    assert!(
        Input::Mouse {
            x: f64::INFINITY,
            y: 0.0,
            button: 0,
            state: 0,
            modifiers: 0
        }
        .validate()
        .is_err()
    );
    assert!(
        Input::Key {
            keycode: 128,
            down: true,
            modifiers: 0
        }
        .validate()
        .is_err()
    );
    assert!(
        Input::Key {
            keycode: 42,
            down: true,
            modifiers: 16
        }
        .validate()
        .is_err()
    );
}

#[test]
fn additive_repair_and_release_commands_are_strict_empty_objects() {
    for kind in [Kind::Keyframe, Kind::ReleaseInput] {
        validate_command(kind, b"{}").unwrap();
        let mut wire = Vec::new();
        write(&mut wire, kind, b"{}").unwrap();
        assert_eq!(decode(&wire).unwrap().unwrap().0.kind, kind);
        for body in [b"[]".as_slice(), b"null", b"{\"extra\":true}"] {
            assert!(validate_command(kind, body).is_err());
        }
    }
}
