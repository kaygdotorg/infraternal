//! Fuzzes version and strict channel-pointer grammars before signed VERSION authentication [226].
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|input: &[u8]| {
    if let Ok(version) = std::str::from_utf8(input)
        && let Some(channel) = infraternal_plugin_api::release_version::channel(version)
    {
        assert!(version.len() <= 127);
        assert_eq!(channel == "edge", version.starts_with("edge-"));
    }
    for channel in ["stable", "edge"] {
        if let Ok(version) = infraternal_plugin_release::pointer::parse(input, channel) {
            assert_eq!(
                infraternal_plugin_api::release_version::channel(&version),
                Some(channel)
            );
        }
    }
});
