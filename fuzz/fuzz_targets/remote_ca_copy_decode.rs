//! Fuzz bounded encrypted administrator-copy JSON shape; parsing grants no role or signing authority [168], #78.
#![no_main]
use infraternal_server::ca::wrapping::WrappedCa;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(copy) = WrappedCa::decode(data) {
        assert!(data.len() <= 8192);
        assert!(copy.salt().is_ok());
        let mut suffix = data.to_vec();
        suffix.push(b'x');
        assert!(WrappedCa::decode(&suffix).is_err());
    }
});
