//! Exercises the real socketpair, OpenSSL validation and a deterministic malformed-frame property corpus [168][217], #154.

use super::*;
use crate::ca_memory::AdministratorCaUnlock;

struct Unlocked(CaMaterial);
impl AdministratorCaUnlock for Unlocked {
    fn unlock(&self) -> Result<CaMaterial, CaError> {
        Ok(self.0.clone())
    }
}
fn source() -> MemoryCaSource {
    let material = crate::ca::tests::test_material();
    let source = MemoryCaSource::cold_start(material.issuer().clone());
    source.unlock_from(&Unlocked(material)).unwrap();
    source
}

#[test]
fn socketpair_preserves_unlock_and_cold_start_still_locks() {
    let source = source();
    let socket = prepare(&source).unwrap();
    let material = receive(&socket).unwrap();
    let successor = MemoryCaSource::cold_start(source.issuer().unwrap());
    successor.install(material).unwrap();
    assert!(crate::ca::CertificateAuthority::from_source(&successor).is_ok());
    assert!(!*successor.subscribe_locked().borrow());
    assert!(
        MemoryCaSource::cold_start(source.issuer().unwrap())
            .load()
            .is_err()
    );
}

#[test]
fn truncated_wrong_generation_and_wrong_version_leave_successor_locked() {
    let source = source();
    let frame = encode(&source.load().unwrap()).unwrap();
    let cold = MemoryCaSource::cold_start(source.issuer().unwrap());
    for end in 0..frame.len() {
        assert!(parse(&frame[..end]).is_err());
    }
    let mut wrong = Zeroizing::new(frame.to_vec());
    wrong[4] = 2;
    assert!(parse(&wrong).is_err());
    let different = crate::ca::tests::test_material();
    assert!(cold.install(different).is_err());
    assert!(cold.load().is_err());
    let (writer, reader) = UnixStream::pair().unwrap();
    drop(writer);
    assert!(receive(&reader).is_err());
}

#[test]
fn parser_property_corpus_is_bounded_and_never_accepts_trailing_bytes() {
    let source = source();
    let frame = encode(&source.load().unwrap()).unwrap();
    for length in 0..=4096 {
        let mut data = Zeroizing::new(vec![0; length]);
        for (offset, byte) in data.iter_mut().enumerate() {
            *byte = u8::try_from((offset * 31 + length * 17) % 256).unwrap();
        }
        assert!(parse(&data).is_err());
    }
    for offset in 0..frame.len() {
        let mut data = Zeroizing::new(frame.to_vec());
        data[offset] ^= 0xff;
        if let Ok(material) = parse(&data) {
            // Some certificate fields may vary while retaining a valid signature;
            // the install boundary must still require exact retained trust.
            assert!(
                MemoryCaSource::cold_start(source.issuer().unwrap())
                    .install(material)
                    .is_err()
            );
        }
    }
    let mut trailing = Zeroizing::new(frame.to_vec());
    trailing.push(0);
    assert!(parse(&trailing).is_err());
}
