//! Fuzz the exact relay control and DATAGRAM frame decoder source [313], #220.
#![no_main]
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../crates/plugins/relay/src/wire.rs"]
mod wire;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }

    if let Some((id, payload)) = wire::split(data) {
        let mut encoded = id.0.to_be_bytes().to_vec();
        encoded.extend_from_slice(payload);
        assert_eq!(wire::split(&encoded), Some((id, payload)));
    }

    if let Some((&kind, body)) = data.split_first() {
        let _ = wire::request_len(kind);
        let _ = wire::notice_len(kind);

        if let Some(request) = wire::Request::decode(kind, body) {
            let encoded = request.encode();
            assert_eq!(wire::request_len(encoded[0]), Some(encoded.len() - 1));
            assert_eq!(
                wire::Request::decode(encoded[0], &encoded[1..]),
                Some(request)
            );
        }

        if let Some(notice) = wire::Notice::decode(kind, body) {
            let (encoded, len) = notice.encode();
            assert_eq!(wire::notice_len(encoded[0]), Some(len - 1));
            assert_eq!(wire::Notice::decode(encoded[0], &encoded[1..len]), Some(notice));
        }
    }

    if let Ok(text) = std::str::from_utf8(data) {
        let _ = wire::HostId::from_uri(text);
        if let Some(host) = wire::HostId::parse(text) {
            assert_eq!(wire::HostId::parse(&host.to_string()), Some(host));
        }
    }
});
