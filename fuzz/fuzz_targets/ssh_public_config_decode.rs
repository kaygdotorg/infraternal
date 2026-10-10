//! Fuzzes public SSH policy reconstruction without accessing filesystem paths or credential material.
#![no_main]

use infraternal_plugin_ssh::{config::PublicSshConfiguration, model::Destination};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let original = Destination::parse("fixture@original.invalid").unwrap();
    if let Some(configuration) = PublicSshConfiguration::parse(&original, bytes) {
        assert_ne!(configuration.destination.host(), "");
        assert_eq!(configuration.destination.user(), original.user());
        assert!(configuration.destination.port().is_some());
        assert!(bytes.len() <= 65536);
        // Only pure parsing is exercised. Public-path metadata validation belongs
        // to the integration tests; fuzzer input must never select file accesses.
    }
});
