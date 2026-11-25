//! The server-leaf floor's ordering and persistence tests, with real
//! certificates built by OpenSSL. The floor itself lives in
//! `infraternal-link` (#580, L2); these tests stay here, next to the OpenSSL
//! fixtures, and also check its DER reader against OpenSSL.
use crate::server_leaf_floor::{ServerLeafFloor, ServerLeafStore, not_before_seconds};
use openssl::{asn1::Asn1Time, hash::MessageDigest, pkey::PKey, x509::X509, x509::X509NameBuilder};
use std::{
    io,
    sync::{Arc, Mutex},
};

/// A self-signed certificate whose only meaningful field is `notBefore`.
fn certificate(not_before: i64) -> X509 {
    let key = PKey::generate_ed25519().unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "leaf").unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix(not_before).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix(not_before + 86_400).unwrap())
        .unwrap();
    builder.sign(&key, MessageDigest::null()).unwrap();
    builder.build()
}

/// The same certificate as DER, the form the floor reads.
fn leaf(not_before: i64) -> Vec<u8> {
    certificate(not_before).to_der().unwrap()
}

/// Records every persisted value, and can be told to fail.
#[derive(Default)]
struct Recorder {
    values: Mutex<Vec<i64>>,
    fail: bool,
}
impl ServerLeafStore for Recorder {
    fn remember(&self, not_before: i64) -> io::Result<()> {
        self.values.lock().unwrap().push(not_before);
        if self.fail {
            Err(io::Error::other("storage unavailable"))
        } else {
            Ok(())
        }
    }
}

/// Newer and equal leaves pass; an older one is refused once a newer one was seen.
#[test]
fn older_leaf_is_refused_after_a_newer_one() {
    let floor = ServerLeafFloor::default();
    assert_eq!(floor.newest(), None);
    floor.admit(&leaf(1_800_000_000)).unwrap();
    floor.admit(&leaf(1_800_000_000)).unwrap();
    floor.admit(&leaf(1_800_086_400)).unwrap();
    assert_eq!(floor.newest(), Some(1_800_086_400));
    let error = floor.admit(&leaf(1_800_000_000)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(floor.newest(), Some(1_800_086_400));
}

/// Only a rise is persisted, and the durable start value is honoured.
#[test]
fn durable_floor_starts_from_storage_and_records_only_rises() {
    let store = Arc::new(Recorder::default());
    let floor = ServerLeafFloor::new(Some(1_800_000_000), store.clone());
    assert!(floor.admit(&leaf(1_799_999_999)).is_err());
    floor.admit(&leaf(1_800_000_000)).unwrap();
    floor.admit(&leaf(1_800_000_100)).unwrap();
    floor.admit(&leaf(1_800_000_100)).unwrap();
    assert_eq!(*store.values.lock().unwrap(), vec![1_800_000_100]);
}

/// A failed write keeps the raised floor in memory and still accepts the newer leaf.
#[test]
fn storage_failure_keeps_the_raised_floor_in_memory() {
    let store = Arc::new(Recorder {
        fail: true,
        ..Recorder::default()
    });
    let floor = ServerLeafFloor::new(None, store);
    floor.admit(&leaf(1_800_000_100)).unwrap();
    assert!(floor.admit(&leaf(1_800_000_000)).is_err());
}

/// The floor's DER reader agrees with OpenSSL's own `notBefore` arithmetic,
/// across both time encodings (OpenSSL writes `UTCTime` up to 2049 and
/// `GeneralizedTime` from 2050) and leap days.
#[test]
fn der_reader_matches_openssl_for_real_certificates() {
    let epoch = Asn1Time::from_unix(0).unwrap();
    for not_before in [
        0,
        1,
        951_782_400,
        1_709_208_000,
        1_800_001_800,
        2_524_607_999,
        2_524_608_000,
        4_107_542_400,
    ] {
        let issued = certificate(not_before);
        let difference = epoch.diff(issued.not_before()).unwrap();
        let openssl = i64::from(difference.days) * 86_400 + i64::from(difference.secs);
        assert_eq!(openssl, not_before);
        assert_eq!(
            not_before_seconds(&issued.to_der().unwrap()).unwrap(),
            not_before
        );
    }
}
