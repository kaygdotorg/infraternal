//! Checks the fixed public path-proof envelope; successful parsing never grants authentication [40,215], #201.
#![no_main]
use infraternal_agent::remote_quic::path_probe_header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Some((response, sequence)) = path_probe_header(bytes) {
        assert_eq!(bytes.len(), 45);
        assert_eq!(&bytes[..4], b"\x80ip1");
        assert_eq!(bytes[4], u8::from(response));
        assert_eq!(&bytes[5..13], &sequence.to_be_bytes());
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(path_probe_header(&extended).is_none());
        for length in 0..bytes.len() {
            assert!(path_probe_header(&bytes[..length]).is_none());
        }
    }
});
