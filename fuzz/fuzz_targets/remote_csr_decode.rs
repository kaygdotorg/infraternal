//! Exercises bounded host CSR parsing and proof-of-possession without issuing authority [40][133], #78.
#![no_main]

use infraternal_server::csr::ValidatedCsr;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(csr) = ValidatedCsr::parse(bytes) {
        // Every admitted request carries exactly the host key algorithm promised
        // by bootstrap, irrespective of attacker-selected names or extensions.
        assert_eq!(csr.key().raw_public_key().unwrap().len(), 32);
        assert!(bytes.len() <= 4096);
    }
});
