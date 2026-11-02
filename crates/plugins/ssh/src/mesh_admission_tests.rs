//! Exercises claim time/source boundaries and independent current access checks, not SSH cryptography.
use super::*;
use std::cell::Cell;

struct Access {
    certificate: CertificateClaims<'static>,
    node: Option<u64>,
    current: bool,
    network: bool,
    login: bool,
    network_checks: Cell<usize>,
    login_checks: Cell<usize>,
}

impl CurrentAccess for Access {
    fn source_node(&self, _: IpAddr) -> Option<u64> {
        self.node
    }

    fn certificate_current(&self, cert: &CertificateClaims<'_>) -> bool {
        self.current
            && cert.fingerprint == self.certificate.fingerprint
            && cert.person == self.certificate.person
            && cert.source_node == self.certificate.source_node
            && cert.source_address == self.certificate.source_address
    }

    fn network_access(&self, source: u64, target: u64, port: u16) -> bool {
        self.network_checks.set(self.network_checks.get() + 1);
        self.network && (source, target, port) == (7, 9, 22)
    }

    fn login_access(&self, person: &str, target: u64, account: &str) -> bool {
        self.login_checks.set(self.login_checks.get() + 1);
        self.login && (person, target, account) == ("person-1", 9, "operator")
    }
}

fn fixture(address: &str) -> (Access, LoginRequest<'static>) {
    let source_address = address.parse().unwrap();
    let certificate = CertificateClaims {
        fingerprint: [3; 32],
        person: "person-1",
        source_node: 7,
        source_address,
        valid_after: 100,
        valid_before: 100 + MAX_CERTIFICATE_SECONDS,
    };
    (
        Access {
            certificate,
            node: Some(7),
            current: true,
            network: true,
            login: true,
            network_checks: Cell::new(0),
            login_checks: Cell::new(0),
        },
        LoginRequest {
            source_address,
            target_node: 9,
            target_account: "operator",
        },
    )
}

#[test]
fn valid_claims_need_both_access_checks_in_both_address_families() {
    for address in ["10.254.0.7", "fd00::7"] {
        let (mut access, request) = fixture(address);
        assert_eq!(
            admit_certificate_claims(&access, &access.certificate, request, 100),
            Ok(())
        );
        assert_eq!(
            (access.network_checks.get(), access.login_checks.get()),
            (1, 1)
        );
        access.network = false;
        assert_eq!(
            admit_certificate_claims(&access, &access.certificate, request, 100),
            Err(Refusal::NetworkAccess)
        );
        access.network = true;
        access.login = false;
        assert_eq!(
            admit_certificate_claims(&access, &access.certificate, request, 100),
            Err(Refusal::LoginAccess)
        );
    }
}

#[test]
fn every_admission_rechecks_revocation_and_login_access() {
    let (mut access, request) = fixture("10.254.0.7");
    assert!(admit_certificate_claims(&access, &access.certificate, request, 100).is_ok());
    access.current = false;
    assert_eq!(
        admit_certificate_claims(&access, &access.certificate, request, 100),
        Err(Refusal::Revoked)
    );
    access.current = true;
    access.login = false;
    assert_eq!(
        admit_certificate_claims(&access, &access.certificate, request, 100),
        Err(Refusal::LoginAccess)
    );
    access.login = true;
    access.network = false;
    assert_eq!(
        admit_certificate_claims(&access, &access.certificate, request, 100),
        Err(Refusal::NetworkAccess)
    );
    access.network = true;
    assert_eq!(
        admit_certificate_claims(
            &access,
            &access.certificate,
            request,
            access.certificate.valid_before
        ),
        Err(Refusal::CertificateTime)
    );
}

#[test]
fn time_interval_is_bounded_and_end_exclusive() {
    let (access, request) = fixture("10.254.0.7");
    for (start, end, now, accepted) in [
        (100, 200, 99, false),
        (100, 200, 100, true),
        (100, 200, 199, true),
        (100, 200, 200, false),
        (100, 100, 100, false),
        (200, 100, 150, false),
        (0, MAX_CERTIFICATE_SECONDS, 1, true),
        (0, MAX_CERTIFICATE_SECONDS + 1, 1, false),
        (0, u64::MAX, 1, false),
        (u64::MAX - 1, u64::MAX, u64::MAX - 1, true),
        (u64::MAX - 1, u64::MAX, u64::MAX, false),
    ] {
        let cert = CertificateClaims {
            valid_after: start,
            valid_before: end,
            ..access.certificate
        };
        assert_eq!(
            admit_certificate_claims(&access, &cert, request, now).is_ok(),
            accepted,
            "{start}..{end} at {now}"
        );
    }
}

#[test]
fn claims_cannot_substitute_another_person_or_certificate() {
    let (access, request) = fixture("10.254.0.7");
    for cert in [
        CertificateClaims {
            person: "person-2",
            ..access.certificate
        },
        CertificateClaims {
            fingerprint: [4; 32],
            ..access.certificate
        },
    ] {
        assert_eq!(
            admit_certificate_claims(&access, &cert, request, 100),
            Err(Refusal::Revoked)
        );
    }
    let cert = CertificateClaims {
        person: "",
        ..access.certificate
    };
    assert_eq!(
        admit_certificate_claims(&access, &cert, request, 100),
        Err(Refusal::InvalidClaims)
    );
    let request = LoginRequest {
        target_account: "",
        ..request
    };
    assert_eq!(
        admit_certificate_claims(&access, &access.certificate, request, 100),
        Err(Refusal::InvalidClaims)
    );
}

#[test]
fn exact_source_and_current_membership_are_required() {
    for (address, wrong) in [("10.254.0.7", "10.254.0.8"), ("fd00::7", "fd00::8")] {
        let (mut access, request) = fixture(address);
        let other_source = LoginRequest {
            source_address: wrong.parse().unwrap(),
            ..request
        };
        assert_eq!(
            admit_certificate_claims(&access, &access.certificate, other_source, 100),
            Err(Refusal::Source)
        );
        let cert = CertificateClaims {
            source_node: 8,
            ..access.certificate
        };
        assert_eq!(
            admit_certificate_claims(&access, &cert, request, 100),
            Err(Refusal::Source)
        );
        for node in [None, Some(8)] {
            access.node = node;
            assert_eq!(
                admit_certificate_claims(&access, &access.certificate, request, 100),
                Err(Refusal::Source)
            );
        }
    }
}

#[test]
fn admission_does_not_extend_to_another_host_or_target_account() {
    let (access, request) = fixture("10.254.0.7");
    assert_eq!(
        admit_certificate_claims(
            &access,
            &access.certificate,
            LoginRequest {
                target_node: 10,
                ..request
            },
            100,
        ),
        Err(Refusal::NetworkAccess)
    );
    assert_eq!(
        admit_certificate_claims(
            &access,
            &access.certificate,
            LoginRequest {
                target_account: "root",
                ..request
            },
            100,
        ),
        Err(Refusal::LoginAccess)
    );
}
