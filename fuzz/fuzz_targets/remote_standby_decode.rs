//! Fuzzes exact bounded standby/activation objects and canonical round trips [215], #129.
#![no_main]
use infraternal_server::remote_standby_request::{activation, wants_prime};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let prime = wants_prime(input);
    let activate = activation(input);
    if input.len() > 64 {
        assert!(prime.is_err());
        assert!(activate.is_err());
    }
    if let Ok(prime) = prime {
        assert_eq!(input.trim_ascii_start().first(), Some(&b'{'));
        let canonical = serde_json::to_vec(&serde_json::json!({ "prime": prime })).unwrap();
        assert_eq!(wants_prime(&canonical).unwrap(), prime);
    }
    if activate.is_ok() {
        assert_eq!(input.trim_ascii_start().first(), Some(&b'{'));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(input).unwrap(),
            serde_json::json!({})
        );
        assert!(activation(b"{}").is_ok());
    }
});
