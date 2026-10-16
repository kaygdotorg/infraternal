//! Checks fixed kernel ownership records against unexpected input (#230).
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let inode = data
        .get(20..24)
        .and_then(|value| value.try_into().ok())
        .map_or(0, u32::from_ne_bytes);
    if let Some(uid) = infraternal_plugin_remote::runtime_lock::check_diagnostic_record(data, inode)
    {
        assert_eq!(data.len(), 60);
        assert_eq!(uid, u32::from_ne_bytes(data[56..60].try_into().unwrap()));
    }
});
