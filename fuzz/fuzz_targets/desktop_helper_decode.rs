//! Desktop framing and JSON-control trust-boundary fuzz properties [D40,D203].
#![no_main]
use infraternal_plugin_desktop::protocol::{self, Kind};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if let Ok(Some((frame, used))) = protocol::decode(bytes) {
        assert!(used <= bytes.len());
        let mut encoded = Vec::new();
        protocol::write(&mut encoded, frame.kind, frame.payload).unwrap();
        assert_eq!(encoded, bytes[..used]);
        assert_eq!(
            protocol::read(&mut encoded.as_slice()).unwrap(),
            (frame.kind, frame.payload.to_vec())
        );
        let _ = protocol::validate_command(frame.kind, frame.payload);
        let split = usize::from(bytes.first().copied().unwrap_or(0)) % used;
        assert!(protocol::decode(&bytes[..split]).unwrap().is_none());
    }
    for kind in [
        Kind::List,
        Kind::Start,
        Kind::Resize,
        Kind::Input,
        Kind::Stop,
        Kind::Status,
        Kind::Keyframe,
        Kind::ReleaseInput,
        Kind::Control,
        Kind::Congested,
    ] {
        let _ = protocol::validate_command(kind, bytes);
    }
});
