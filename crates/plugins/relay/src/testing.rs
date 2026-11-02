//! Disposable deployment CA and leaves for relay tests and namespace fixtures; never in a shipped build.
//!
//! The leaves mirror what enrollment issues: a host leaf is client-purpose with
//! one `urn:infraternal:host:<uuid>` URI, a relay leaf is server-purpose with a
//! DNS name. Keys live only in memory.
#![allow(clippy::missing_panics_doc, clippy::unwrap_used)]

use crate::{tls::Credentials, wire::HostId};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A disposable deployment CA.
pub struct Authority {
    certificate: X509,
    key: PKey<Private>,
    serial: u32,
}

/// What a leaf may be used for.
#[derive(Clone, Copy)]
pub enum Purpose<'a> {
    /// An enrolled host: client purpose, one host URI.
    Host(HostId),
    /// A relay: server purpose, this DNS name.
    Relay(&'a str),
}

impl Authority {
    #[must_use]
    pub fn new() -> Self {
        let key = PKey::generate_ed25519().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "relay test CA").unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(2).unwrap())
            .unwrap();
        cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        cert.append_extension(KeyUsage::new().critical().key_cert_sign().build().unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::null()).unwrap();
        Self {
            certificate: cert.build(),
            key,
            serial: 1,
        }
    }

    /// The CA certificate, PEM encoded, for handing to another process.
    #[must_use]
    pub fn pem(&self) -> String {
        String::from_utf8(self.certificate.to_pem().unwrap()).unwrap()
    }

    /// Issue a leaf and return it with the CA as the only root.
    #[must_use]
    pub fn issue(&mut self, purpose: Purpose<'_>) -> Credentials {
        let (certificate, key) = self.leaf(purpose);
        Credentials {
            chain: vec![CertificateDer::from(certificate.to_der().unwrap())],
            key: PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
                key.private_key_to_pkcs8().unwrap(),
            )),
            roots: vec![CertificateDer::from(self.certificate.to_der().unwrap())],
        }
    }

    /// Issue a leaf as PEM certificate and PKCS#8 PEM key.
    #[must_use]
    pub fn issue_pem(&mut self, purpose: Purpose<'_>) -> (String, String) {
        let (certificate, key) = self.leaf(purpose);
        (
            String::from_utf8(certificate.to_pem().unwrap()).unwrap(),
            String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap(),
        )
    }

    fn leaf(&mut self, purpose: Purpose<'_>) -> (X509, PKey<Private>) {
        self.serial += 1;
        let key = PKey::generate_ed25519().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "relay test leaf").unwrap();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(
            &BigNum::from_u32(self.serial)
                .unwrap()
                .to_asn1_integer()
                .unwrap(),
        )
        .unwrap();
        cert.set_subject_name(&name.build()).unwrap();
        cert.set_issuer_name(self.certificate.subject_name())
            .unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        cert.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
        let context = cert.x509v3_context(Some(&self.certificate), None);
        let (usage, san) = match purpose {
            Purpose::Host(host) => (
                ExtendedKeyUsage::new().client_auth().build().unwrap(),
                SubjectAlternativeName::new()
                    .uri(&format!("urn:infraternal:host:{host}"))
                    .build(&context)
                    .unwrap(),
            ),
            Purpose::Relay(dns) => (
                ExtendedKeyUsage::new().server_auth().build().unwrap(),
                SubjectAlternativeName::new()
                    .dns(dns)
                    .build(&context)
                    .unwrap(),
            ),
        };
        cert.append_extension(usage).unwrap();
        cert.append_extension(san).unwrap();
        cert.sign(&self.key, MessageDigest::null()).unwrap();
        (cert.build(), key)
    }
}

impl Default for Authority {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse PEM credentials handed over by a test driver.
#[must_use]
pub fn credentials_from_pem(certificate: &str, key: &str, root: &str) -> Credentials {
    let der =
        |pem: &str| CertificateDer::from(X509::from_pem(pem.as_bytes()).unwrap().to_der().unwrap());
    Credentials {
        chain: vec![der(certificate)],
        key: PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
            PKey::private_key_from_pem(key.as_bytes())
                .unwrap()
                .private_key_to_pkcs8()
                .unwrap(),
        )),
        roots: vec![der(root)],
    }
}
