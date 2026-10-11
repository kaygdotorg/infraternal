//! Verifies that encrypted CA copies bind the issuer and administrator membership without printing secret material [168], #78.
use super::*;

#[test]
fn wrapped_seed_roundtrip_validates_the_same_issuer_key() {
    let material = crate::ca::tests::test_material();
    let envelope = WrappedCa::seal(&material, "administrator", 1, &[3; 32], &[5; 32]).unwrap();
    let restored = envelope
        .open(material.issuer(), "administrator", 1, &[5; 32])
        .unwrap();
    assert!(restored.key.public_eq(&material.key));
    assert!(crate::ca::CertificateAuthority::from_material(restored).is_ok());
    let encoded = serde_json::to_vec(&envelope).unwrap();
    let decoded: WrappedCa = serde_json::from_slice(&encoded).unwrap();
    assert!(
        decoded
            .open(material.issuer(), "administrator", 1, &[5; 32])
            .is_ok()
    );
}

#[test]
fn wrong_key_member_epoch_or_issuer_cannot_unwrap_a_copy() {
    let material = crate::ca::tests::test_material();
    let envelope = WrappedCa::seal(&material, "administrator", 1, &[3; 32], &[5; 32]).unwrap();
    assert!(
        envelope
            .open(material.issuer(), "administrator", 1, &[6; 32])
            .is_err()
    );
    assert!(
        envelope
            .open(material.issuer(), "other", 1, &[5; 32])
            .is_err()
    );
    assert!(
        envelope
            .open(material.issuer(), "administrator", 2, &[5; 32])
            .is_err()
    );
    let other = crate::ca::tests::test_material();
    assert!(
        envelope
            .open(other.issuer(), "administrator", 1, &[5; 32])
            .is_err()
    );
}

#[test]
fn ciphertext_nonce_salt_and_issuer_tampering_fail_authenticated_decryption() {
    let material = crate::ca::tests::test_material();
    for field in 0..4 {
        let mut envelope =
            WrappedCa::seal(&material, "administrator", 1, &[3; 32], &[5; 32]).unwrap();
        match field {
            0 => envelope.ciphertext[0] ^= 1,
            1 => envelope.nonce[0] ^= 1,
            2 => envelope.salt[0] ^= 1,
            3 => envelope.issuer_fingerprint[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(
            envelope
                .open(material.issuer(), "administrator", 1, &[5; 32])
                .is_err()
        );
    }
}

#[test]
fn creation_rejects_unbound_membership_and_malformed_copies_cannot_open() {
    let material = crate::ca::tests::test_material();
    assert!(WrappedCa::seal(&material, "", 1, &[3; 32], &[5; 32]).is_err());
    assert!(WrappedCa::seal(&material, "administrator", 0, &[3; 32], &[5; 32]).is_err());
    assert!(WrappedCa::seal(&material, &"x".repeat(257), 1, &[3; 32], &[5; 32]).is_err());
    let mut envelope = WrappedCa::seal(&material, "administrator", 1, &[3; 32], &[5; 32]).unwrap();
    envelope.ciphertext.pop();
    assert!(
        envelope
            .open(material.issuer(), "administrator", 1, &[5; 32])
            .is_err()
    );
    envelope.ciphertext.clear();
    assert!(
        envelope
            .open(material.issuer(), "administrator", 1, &[5; 32])
            .is_err()
    );
}

/// Measures actual existing-provider encrypt/authenticate operations with 1,000
/// retained envelopes; excludes HTTP, database, passkey and initial credential setup.
#[test]
#[ignore = "optimized CA copy diagnostic; no own builds/browser overlap"]
fn encrypted_copy_cost_at_1000_administrators() {
    use std::time::Instant;
    fn rss() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    }
    let material = crate::ca::tests::test_material();
    let before = rss();
    let mut encrypted = Vec::with_capacity(1000);
    let mut seal_times = Vec::with_capacity(1000);
    let mut open_times = Vec::with_capacity(1000);
    let mut bytes = 0;
    for index in 0..1000 {
        let member = format!("administrator-diagnostic-{index}");
        let start = Instant::now();
        let copy = WrappedCa::seal(&material, &member, 1, &[3; 32], &[7; 32]).unwrap();
        seal_times.push(start.elapsed().as_nanos());
        bytes += serde_json::to_vec(&copy).unwrap().len();
        let start = Instant::now();
        assert!(copy.open(material.issuer(), &member, 1, &[7; 32]).is_ok());
        open_times.push(start.elapsed().as_nanos());
        encrypted.push(copy);
    }
    seal_times.sort_unstable();
    open_times.sort_unstable();
    println!(
        "encrypted_ca_copies n=1000 seal_p50_ns={} seal_p99_ns={} open_validate_p50_ns={} open_validate_p99_ns={} baseline_rss_kib={before} retained_rss_kib={} serialized_encrypted_bytes={bytes} excludes_http_database_passkey_and_initial_credentials=true cores={} machine={} load={}",
        seal_times[499],
        seal_times[989],
        open_times[499],
        open_times[989],
        rss(),
        std::thread::available_parallelism().unwrap(),
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    assert_eq!(encrypted.len(), 1000);
}

#[test]
fn invalid_issuer_key_binding_is_refused_before_a_copy_is_persisted() {
    let material = crate::ca::tests::test_material();
    let foreign = crate::ca::tests::test_material();
    let mismatched = CaMaterial::new(material.key.clone(), foreign.issuer().clone());
    assert!(WrappedCa::seal(&mismatched, "administrator", 1, &[3; 32], &[5; 32]).is_err());
}

#[test]
fn bounded_decoder_rejects_duplicate_unknown_fields_and_exact_oversize() {
    let material = crate::ca::tests::test_material();
    let copy = WrappedCa::seal(&material, "administrator", 1, &[3; 32], &[5; 32]).unwrap();
    let bytes = serde_json::to_vec(&copy).unwrap();
    assert!(WrappedCa::decode(&bytes).is_ok());
    let mut boundary = bytes.clone();
    boundary.resize(8192, b' ');
    assert!(WrappedCa::decode(&boundary).is_ok());
    boundary.push(b' ');
    assert!(WrappedCa::decode(&boundary).is_err());
    let mut fields: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    fields["extra"] = serde_json::json!(1);
    assert!(WrappedCa::decode(&serde_json::to_vec(&fields).unwrap()).is_err());
    let mut duplicate = bytes[..bytes.len() - 1].to_vec();
    duplicate.extend_from_slice(b",\"epoch\":1}");
    assert!(WrappedCa::decode(&duplicate).is_err());
    let mut malformed = serde_json::to_value(&copy).unwrap();
    for field in ["salt", "nonce", "ciphertext", "issuer_fingerprint"] {
        let old = malformed[field].take();
        malformed[field] = serde_json::json!([]);
        assert!(WrappedCa::decode(&serde_json::to_vec(&malformed).unwrap()).is_err());
        malformed[field] = old;
    }
}
