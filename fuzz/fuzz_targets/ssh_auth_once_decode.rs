//! Fuzzes bounded input-only SSH credential decoding and batch bindings; no real credential corpus is used [40][183].
#![no_main]
use infraternal_plugin_ssh::auth_once::{OneUseAuth, TargetAuth};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    // Match the bootstrap frame bound before creating zeroizing private owners.
    if bytes.len() > 32 * 1024 {
        return;
    }
    if let Ok(material) = serde_json::from_slice::<OneUseAuth>(bytes) {
        let result = material.validate();
        assert!(material.remaining() <= std::time::Duration::from_secs(60));
        if result.is_ok() {
            assert!(material.key.is_some() || material.password.is_some());
            assert!(material.passphrase.is_none() || material.key.is_some());
            if let Some(key) = &material.key {
                assert!(!key.expose().is_empty() && key.expose().len() <= 24576);
                assert!(!key.expose().contains(&0));
            }
            for prompt in [&material.passphrase, &material.password]
                .into_iter()
                .flatten()
            {
                assert!(!prompt.expose().is_empty() && prompt.expose().len() <= 16384);
                assert!(
                    !prompt
                        .expose()
                        .iter()
                        .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
                );
            }
        }
    }
    if let Ok(binding) = serde_json::from_slice::<TargetAuth>(bytes) {
        let _ = binding.auth.validate();
    }
});
