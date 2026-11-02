//! Fuzz the fixed host-login request envelope and descriptor-count boundary [D240,D247].
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if let Ok(suffix) = std::str::from_utf8(data) {
        let local = format!("/proc/self/fd/{suffix}");
        for path in [suffix, &local] {
            if let Ok(Some(descriptor)) =
                infraternal_shim::login_ready::inherited_pin_descriptor(std::path::Path::new(path))
            {
                assert!(descriptor >= 5);
                let canonical = format!("/proc/self/fd/{descriptor}");
                assert_eq!(
                    infraternal_shim::login_ready::inherited_pin_descriptor(std::path::Path::new(
                        &canonical
                    ))
                    .unwrap(),
                    Some(descriptor)
                );
            }
        }
    }
    if let Ok(ready) = infraternal_shim::login_ready::decode(data) {
        assert_eq!(
            infraternal_shim::login_ready::encode(ready.pid, ready.uid).unwrap(),
            data
        );
        assert!(ready.pid > 0);
    }
    if let Ok(code) = infraternal_shim::login::decode_status(data) {
        assert_eq!(data.len(), 4);
        assert_eq!(code.to_le_bytes(), data);
        assert!((0..=255).contains(&code) || (-64..=-1).contains(&code));
    }
    if let Some((&count, bytes)) = data.split_first() {
        let result = infraternal_shim::login::decode_header(bytes, usize::from(count));
        if let Ok(request) = result {
            match request {
                infraternal_shim::login::RequestHeader::Ready => {
                    assert_eq!(bytes, b"?");
                    assert_eq!(count, 0);
                }
                infraternal_shim::login::RequestHeader::Stop => {
                    assert_eq!(bytes, b"!");
                    assert_eq!(count, 0);
                }
                infraternal_shim::login::RequestHeader::Terminal(id) => {
                    assert_eq!(bytes, id);
                    assert_eq!(count, 1);
                }
            }
        }
    }
});
