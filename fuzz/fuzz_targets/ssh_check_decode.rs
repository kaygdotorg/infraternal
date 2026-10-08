//! Exercises bounded production SSH check, config, destination, policy and diagnostic decoders [40][156], #87.
#![no_main]

use infraternal_plugin_ssh::{
    install::parse_linger,
    model::{Destination, FailureKind, MeshEvidence},
    openssh::{classify, scan_destination},
    probe::Check,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    for ssh_failure in [false, true] {
        for is_peer in [false, true] {
            for reachable_otherwise in [false, true] {
                let failure = classify(
                    bytes,
                    ssh_failure,
                    MeshEvidence {
                        is_peer,
                        reachable_otherwise,
                    },
                );
                assert!(failure.message.len() <= 160);
                assert_eq!(failure.fingerprints, Vec::<String>::new());
                if !ssh_failure {
                    assert_eq!(failure.kind, FailureKind::Install);
                }
            }
        }
    }
    if let Ok(enabled) = parse_linger(bytes) {
        assert_eq!(bytes, if enabled { &b"yes\n"[..] } else { &b"no\n"[..] });
    }
    let original = Destination::parse("user@fixture").unwrap();
    if let Some(endpoint) = scan_destination(&original, bytes) {
        assert!(bytes.len() <= 65536);
        assert_eq!(endpoint.user(), "user");
        assert!(endpoint.port().is_some_and(|port| port != 0));
        assert!(endpoint.host().len() <= 253);
    }
    if let Ok(text) = std::str::from_utf8(bytes)
        && let Ok(endpoint) = Destination::parse(text)
    {
        assert!(text.len() <= 320);
        assert!(!endpoint.host().starts_with('-'));
    }
    if let Ok(check) = Check::parse(bytes) {
        assert!(bytes.len() <= 256);
        assert!(bytes.ends_with(b"\n"));
        let mut suffix = bytes.to_vec();
        suffix.push(b'!');
        assert!(Check::parse(&suffix).is_err());
        if check.uid == 0 {
            assert!(
                check
                    .authorize_mode(infraternal_plugin_ssh::model::InstallMode::Rootless)
                    .is_err()
            );
        }
    }
});
