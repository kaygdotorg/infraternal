//! Fuzz bounded memory settings and additive public refusal JSON without losing numeric invariants [D214], #151.
#![no_main]
#![forbid(unsafe_code)]
use infraternal_plugin_api::{admission::OpenRefusal, channel::MAX_CONTROL_JSON};
use infraternal_plugin_host_facts::MemoryPolicy;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Ok(policy) = MemoryPolicy::decode(input) {
        let json = serde_json::to_vec(&policy).unwrap();
        assert_eq!(MemoryPolicy::decode(&json).unwrap(), policy);
        let _ = policy.floor_bytes(u64::MAX);
    }
    if input.len() <= MAX_CONTROL_JSON
        && let Ok(reason) = serde_json::from_slice::<OpenRefusal>(input)
    {
        assert_eq!(
            serde_json::from_slice::<OpenRefusal>(&reason.json().unwrap()).unwrap(),
            reason
        );
    }
});
