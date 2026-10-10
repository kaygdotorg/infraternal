//! Fuzz the production bounded CA-unlock JSON decoder; accepted syntax grants no administrator or signing authority [168], #78.
#![no_main]
use infraternal_server::ca_http::{decode_membership_finish, decode_role_change, decode_unlock};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if decode_role_change(data).is_ok() || decode_membership_finish(data).is_ok() {
        assert!(data.len() <= 32768);
        let mut suffix = data.to_vec();
        suffix.push(b'x');
        assert!(decode_role_change(&suffix).is_err());
        assert!(decode_membership_finish(&suffix).is_err());
    }
    if decode_unlock(data).is_ok() {
        assert!(data.len() <= 32768);
        let mut suffix = data.to_vec();
        suffix.push(b'x');
        assert!(decode_unlock(&suffix).is_err());
    }
});
