//! Exercises bounded host CSR parsing and proof-of-possession without issuing authority [40][133], #78.
//!
//! Every input goes through both admitted shapes: the Ed25519 host shape and
//! the P-256 device shape (#580). Seeds for both live in
//! `fuzz/corpus/remote_csr_decode`.
#![no_main]

use infraternal_server::{csr::ValidatedCsr, identity_key::KeyAlgorithm};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let ed25519 = ValidatedCsr::parse(bytes);
    let p256 = ValidatedCsr::parse_as(bytes, KeyAlgorithm::P256);
    // One request names one key algorithm, so no bytes pass as both.
    assert!(ed25519.is_err() || p256.is_err());
    if let Ok(csr) = ed25519 {
        // Every admitted request carries exactly the host key algorithm promised
        // by bootstrap, irrespective of attacker-selected names or extensions.
        assert_eq!(csr.algorithm(), KeyAlgorithm::Ed25519);
        assert_eq!(csr.key().raw_public_key().unwrap().len(), 32);
        assert!(bytes.len() <= 4096);
    }
    if let Ok(csr) = p256 {
        // A device key is a P-256 point, never another curve or algorithm.
        assert_eq!(csr.algorithm(), KeyAlgorithm::P256);
        assert!(csr.key().ec_key().is_ok());
        assert_eq!(csr.key().bits(), 256);
        assert!(bytes.len() <= 4096);
    }
});
