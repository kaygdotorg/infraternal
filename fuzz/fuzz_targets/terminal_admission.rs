//! Fuzz bounded terminal policy, public refusals and kernel process identity records [D214], #151.
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
    if let Some(birth) = infraternal_agent::sessions::process_birth_ticks(input) {
        let record = format!("17 (fuzz) S {}{birth}\n", "0 ".repeat(18));
        assert_eq!(
            infraternal_agent::sessions::process_birth_ticks(record.as_bytes()),
            Some(birth)
        );
    }
});
