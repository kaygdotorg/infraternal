//! Fuzzes production keyscan syntax independently of the selected engine's cryptographic validation.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    if let Some(record) = infraternal_plugin_ssh::trust::public_record(data, "fixture") {
        let fields: Vec<_> = record.split_whitespace().collect();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0], "fixture");
        assert!(matches!(
            fields[1],
            "ssh-ed25519"
                | "ssh-rsa"
                | "ecdsa-sha2-nistp256"
                | "ecdsa-sha2-nistp384"
                | "ecdsa-sha2-nistp521"
        ));
        assert!(!fields[2].is_empty() && fields[2].len() <= 4096);
        assert!(
            fields[2]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        );
        assert!(record.ends_with('\n'));
    }
});
