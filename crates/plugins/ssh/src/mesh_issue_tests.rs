//! Issues with a real in-memory key and checks the exact shape the target verifier accepts.
use super::*;
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use std::cell::Cell;

const NOW: u64 = 1_800_000_000;

fn key() -> PrivateKey {
    PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap()
}

fn ca_public(ca: &PrivateKey) -> [u8; 32] {
    ca.public_key().key_data().ed25519().unwrap().0
}

fn sign_with(ca: &PrivateKey) -> impl Fn(&[u8]) -> Option<[u8; 64]> + '_ {
    |body: &[u8]| {
        let signature: russh::keys::ssh_key::Signature = ca.try_sign(body).ok()?;
        signature.as_bytes().try_into().ok()
    }
}

fn person_request<'a>(subject: &'a PublicKey, lifetime: u64) -> PersonRequest<'a> {
    PersonRequest {
        subject,
        person: "0b5c8a64-7d1f-4c43-9d0e-0c6a8a5b7f10",
        source_address: "10.254.0.7".parse().unwrap(),
        now: NOW,
        lifetime,
    }
}

#[test]
fn person_certificate_has_exactly_the_verified_shape() {
    let ca = key();
    let subject = key().public_key().clone();
    let certificate = person_certificate(
        ca_public(&ca),
        &sign_with(&ca),
        &person_request(&subject, MAX_LIFETIME),
    )
    .unwrap();
    let fingerprint = ca.public_key().fingerprint(HashAlg::Sha256);
    certificate.validate_at(NOW, [&fingerprint]).unwrap();
    assert_eq!(certificate.cert_type(), CertType::User);
    assert_eq!(
        certificate.valid_principals(),
        ["0b5c8a64-7d1f-4c43-9d0e-0c6a8a5b7f10"]
    );
    assert_eq!(certificate.critical_options().len(), 1);
    assert_eq!(
        certificate
            .critical_options()
            .get("source-address")
            .unwrap(),
        "10.254.0.7/32"
    );
    assert!(
        certificate
            .extensions()
            .get("permit-pty")
            .unwrap()
            .is_empty()
    );
    assert_eq!(certificate.extensions().len(), 1);
    assert_eq!(certificate.public_key(), subject.key_data());
    // Back-dated for clock skew, but never longer than the admission bound.
    assert!(certificate.valid_after() <= NOW - CLOCK_SKEW);
    assert_eq!(
        certificate.valid_before() - certificate.valid_after(),
        MAX_LIFETIME
    );
    assert!(certificate.valid_before() - certificate.valid_after() <= 24 * 60 * 60);
}

#[test]
fn ipv6_source_is_bound_to_one_address() {
    let ca = key();
    let subject = key().public_key().clone();
    let mut request = person_request(&subject, 3600);
    request.source_address = "fd00:1::7".parse().unwrap();
    let certificate = person_certificate(ca_public(&ca), &sign_with(&ca), &request).unwrap();
    assert_eq!(
        certificate
            .critical_options()
            .get("source-address")
            .unwrap(),
        "fd00:1::7/128"
    );
}

#[test]
fn lifetime_is_between_one_hour_and_one_day() {
    let ca = key();
    let subject = key().public_key().clone();
    for lifetime in [0, 59 * 60, MAX_LIFETIME + 1, u64::MAX] {
        assert!(
            person_certificate(
                ca_public(&ca),
                &sign_with(&ca),
                &person_request(&subject, lifetime)
            )
            .is_err(),
            "{lifetime}"
        );
    }
}

#[test]
fn empty_person_or_a_locked_signer_refuses() {
    let ca = key();
    let subject = key().public_key().clone();
    let mut request = person_request(&subject, 3600);
    request.person = "";
    assert!(person_certificate(ca_public(&ca), &sign_with(&ca), &request).is_err());
    let locked = |_: &[u8]| None;
    assert!(person_certificate(ca_public(&ca), &locked, &person_request(&subject, 3600)).is_err());
}

#[test]
fn a_signer_that_is_not_the_named_ca_is_caught() {
    let ca = key();
    let other = key();
    let subject = key().public_key().clone();
    assert!(
        person_certificate(
            ca_public(&ca),
            &sign_with(&other),
            &person_request(&subject, 3600)
        )
        .is_err()
    );
}

#[test]
fn the_signer_only_sees_an_ssh_certificate_body() {
    let ca = key();
    let subject = key().public_key().clone();
    let seen = Cell::new(false);
    let inner = sign_with(&ca);
    let checking = |body: &[u8]| {
        seen.set(body.starts_with(CERTIFICATE_BODY_PREFIX));
        inner(body)
    };
    person_certificate(ca_public(&ca), &checking, &person_request(&subject, 3600)).unwrap();
    assert!(seen.get());
}

#[test]
fn host_certificate_names_the_host_and_carries_no_options() {
    let ca = key();
    let host = key().public_key().clone();
    let principals = [
        "db-01".to_owned(),
        "db-01.internal".into(),
        "10.254.0.9".into(),
    ];
    let certificate = host_certificate(
        ca_public(&ca),
        &sign_with(&ca),
        &HostRequest {
            subject: &host,
            principals: &principals,
            now: NOW,
            lifetime: MAX_LIFETIME,
        },
    )
    .unwrap();
    let fingerprint = ca.public_key().fingerprint(HashAlg::Sha256);
    certificate.validate_at(NOW, [&fingerprint]).unwrap();
    assert_eq!(certificate.cert_type(), CertType::Host);
    assert_eq!(certificate.valid_principals(), principals);
    assert!(certificate.critical_options().is_empty());
    assert!(certificate.extensions().is_empty());
}

#[test]
fn host_certificate_needs_a_name() {
    let ca = key();
    let host = key().public_key().clone();
    let request = HostRequest {
        subject: &host,
        principals: &[],
        now: NOW,
        lifetime: 3600,
    };
    // An empty list would make the certificate valid for every host name.
    assert!(host_certificate(ca_public(&ca), &sign_with(&ca), &request).is_err());
}
