//! Fuzz bounded renewal proof/certificate JSON; decoded fields grant no authority [12][133], #78.
#![no_main]
use infraternal_agent::remote_renewal::{MAX_RENEWAL_JSON, decode_certificate, decode_proof};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Ok(proof) = decode_proof(input) {
        assert!(input.len() <= MAX_RENEWAL_JSON);
        assert!(proof.csr_der.len() <= 4096);
        let mut suffix = input.to_vec();
        suffix.push(b'x');
        assert!(decode_proof(&suffix).is_err());
    }
    if let Ok(update) = decode_certificate(input) {
        assert!(input.len() <= MAX_RENEWAL_JSON);
        assert!(update.certificate_der.len() <= 8192);
        let mut suffix = input.to_vec();
        suffix.push(b'x');
        assert!(decode_certificate(&suffix).is_err());
    }
});
