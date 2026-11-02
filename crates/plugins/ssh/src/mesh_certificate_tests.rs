//! Uses real in-memory signatures to audit the protocol-to-authority boundary.
use super::*;
use russh::keys::{Algorithm, HashAlg, PrivateKey, ssh_key::certificate::Builder};

pub(super) struct Access {
    pub ca: Fingerprint,
    pub registered: [u8; 32],
    pub person: String,
    pub source: IpAddr,
    pub current: bool,
    pub network: bool,
    pub login: bool,
}

impl CurrentAccess for Access {
    fn source_node(&self, source: IpAddr) -> Option<u64> {
        (source == self.source && self.current).then_some(7)
    }
    fn certificate_current(&self, certificate: &CertificateClaims<'_>) -> bool {
        self.current
            && certificate.fingerprint == self.registered
            && certificate.person == self.person
            && certificate.source_node == 7
            && certificate.source_address == self.source
    }
    fn network_access(&self, source: u64, target: u64, port: u16) -> bool {
        self.network && (source, target, port) == (7, 9, 22)
    }
    fn login_access(&self, person: &str, target: u64, account: &str) -> bool {
        self.login && (person, target, account) == (self.person.as_str(), 9, "operator")
    }
}
impl CertificateAccess for Access {
    fn trusted_ca(&self) -> &Fingerprint {
        &self.ca
    }
    fn identity(&self, digest: &[u8; 32]) -> Option<Identity> {
        (*digest == self.registered).then(|| Identity {
            person: self.person.clone(),
            source_node: 7,
            source_address: self.source,
        })
    }
}

fn key() -> PrivateKey {
    PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap()
}

fn certificate(
    ca: &PrivateKey,
    source: &str,
    principal: &str,
    start: u64,
    end: u64,
    option: Option<&str>,
    host: bool,
) -> Certificate {
    let user = key();
    let mut builder = Builder::new(vec![1; 32], user.public_key(), start, end).unwrap();
    builder
        .cert_type(if host { CertType::Host } else { CertType::User })
        .unwrap();
    builder.valid_principal(principal).unwrap();
    builder.critical_option("source-address", source).unwrap();
    if let Some(option) = option {
        builder.critical_option(option, "").unwrap();
    }
    builder.sign(ca).unwrap()
}

fn fixture(ca: &PrivateKey, certificate: &Certificate, source: &str) -> Access {
    Access {
        ca: ca.public_key().fingerprint(HashAlg::Sha256),
        registered: digest(certificate).unwrap(),
        person: "person-1".into(),
        source: source.parse().unwrap(),
        current: true,
        network: true,
        login: true,
    }
}
fn request(source: IpAddr) -> LoginRequest<'static> {
    LoginRequest {
        source_address: source,
        target_node: 9,
        target_account: "operator",
    }
}

#[test]
fn signed_person_is_distinct_from_the_requested_os_account() {
    let ca = key();
    for source in ["10.254.0.7", "fd00::7"] {
        let cert = certificate(&ca, source, "person-1", 100, 200, None, false);
        let mut access = fixture(&ca, &cert, source);
        let req = request(access.source);
        assert_eq!(verify(&access, &cert, req, 100).unwrap().person, "person-1");
        access.login = false;
        assert_eq!(verify(&access, &cert, req, 100), Err(Refusal::LoginAccess));
        access.login = true;
        access.network = false;
        assert_eq!(
            verify(&access, &cert, req, 100),
            Err(Refusal::NetworkAccess)
        );
        access.network = true;
        access.current = false;
        assert_eq!(verify(&access, &cert, req, 100), Err(Refusal::Source));
    }
}

#[test]
fn issuer_principal_type_source_and_critical_options_are_all_required() {
    let ca = key();
    let wrong_ca = key();
    for (issuer, source, principal, option, host) in [
        (&wrong_ca, "10.254.0.7", "person-1", None, false),
        (&ca, "10.254.0.7", "operator", None, false),
        (&ca, "10.254.0.7", "person-1", None, true),
        (&ca, "10.254.0.8/32", "person-1", None, false),
        (&ca, "10.254.0.0/24", "person-1", None, false),
        (&ca, "10.254.0.7/32,10.254.0.8/32", "person-1", None, false),
        (&ca, "10.254.0.7", "person-1", Some("force-command"), false),
    ] {
        let cert = certificate(issuer, source, principal, 100, 200, option, host);
        let access = fixture(&ca, &cert, "10.254.0.7");
        assert_eq!(
            verify(&access, &cert, request(access.source), 100),
            Err(Refusal::InvalidClaims)
        );
    }
}

#[test]
fn expiry_lifetime_and_complete_certificate_registration_cannot_be_borrowed() {
    let ca = key();
    let cert = certificate(&ca, "10.254.0.7/32", "person-1", 100, 200, None, false);
    let mut access = fixture(&ca, &cert, "10.254.0.7");
    let req = request(access.source);
    assert!(verify(&access, &cert, req, 199).is_ok());
    assert!(verify(&access, &cert, req, 200).is_err());
    assert!(verify(&access, &cert, req, 99).is_err());
    // A renewal can keep the same user key: identity must be bound to the
    // complete signed certificate, not only that key's fingerprint.
    let mut renewal = Builder::new(vec![1; 32], cert.public_key().clone(), 100, 300).unwrap();
    renewal.valid_principal("person-1").unwrap();
    renewal
        .critical_option("source-address", "10.254.0.7/32")
        .unwrap();
    let renewed = renewal.sign(&ca).unwrap();
    assert_eq!(cert.public_key(), renewed.public_key());
    assert_ne!(digest(&cert), digest(&renewed));
    assert_eq!(verify(&access, &renewed, req, 100), Err(Refusal::Revoked));
    let too_long = certificate(&ca, "10.254.0.7", "person-1", 100, 100 + 86401, None, false);
    access.registered = digest(&too_long).unwrap();
    assert_eq!(
        verify(&access, &too_long, req, 100),
        Err(Refusal::CertificateTime)
    );
    access.person = "person-2".into();
    assert_eq!(
        verify(&access, &too_long, req, 100),
        Err(Refusal::InvalidClaims)
    );
}

#[test]
fn registered_bytes_with_an_invalid_signature_are_refused() {
    let ca = key();
    let cert = certificate(&ca, "10.254.0.7", "person-1", 100, 200, None, false);
    let mut bytes = cert.to_bytes().unwrap();
    // Corrupt signature bytes while retaining an otherwise decodable certificate.
    *bytes.last_mut().unwrap() ^= 1;
    let changed = Certificate::from_bytes(&bytes).unwrap();
    let access = fixture(&ca, &changed, "10.254.0.7");
    assert_eq!(
        verify(&access, &changed, request(access.source), 100),
        Err(Refusal::InvalidClaims)
    );
}
