//! Signs host identities from independently validated keys, with CA unlock policy supplied by the owner [133], #78.

pub mod wrapping;

use crate::{csr::ValidatedCsr, enrollment::CertificateRecord};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{Id, PKey, Private},
    stack::Stack,
    x509::{
        X509, X509NameBuilder, X509StoreContext,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        store::X509StoreBuilder,
        verify::X509VerifyParam,
    },
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Issuer primitive selected by the owner in D168.
pub const CA_KEY_ALGORITHM: CaAlgorithm = CaAlgorithm::Ed25519;

/// The two issuer candidates proposed on #78; host keys stay Ed25519 in either case.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CaAlgorithm {
    /// Consistent with the existing host-key contract.
    Ed25519,
    /// The measured alternative, restricted to the P-256 curve.
    P256,
}
impl CaAlgorithm {
    fn accepts(self, key: &PKey<Private>) -> bool {
        match self {
            Self::Ed25519 => key.id() == Id::ED25519,
            Self::P256 => {
                key.id() == Id::EC
                    && key.ec_key().is_ok_and(|key| {
                        key.group().curve_name() == Some(openssl::nid::Nid::X9_62_PRIME256V1)
                    })
            }
        }
    }
}

/// Content-free failures; keys and OpenSSL diagnostics never enter logs.
#[derive(Debug, thiserror::Error)]
#[error("internal CA unavailable")]
pub struct CaError;

/// Unlocked material supplied in memory; no Debug/serialization or implicit key generation.
#[derive(Clone)]
pub struct CaMaterial {
    key: PKey<Private>,
    issuer: X509,
}
impl CaMaterial {
    /// Carry already unlocked material across the policy boundary.
    #[must_use]
    pub fn new(key: PKey<Private>, issuer: X509) -> Self {
        Self { key, issuer }
    }

    /// Import through the existing decoder, which allocates the Ed25519 seed
    /// with `OPENSSL_secure_zalloc`. The pinned raw-key fromdata import instead
    /// uses ordinary malloc even after secure-heap initialization (#154).
    /// This fixed 48-byte PKCS#8 exists only in locked, dump-excluded pages;
    /// it changes neither encrypted persistence nor the raw handoff format.
    pub(crate) fn key_from_seed(seed: &[u8]) -> Result<PKey<Private>, CaError> {
        if seed.len() != 32 {
            return Err(CaError);
        }
        let mut encoded =
            infraternal_shim::locked_bytes::LockedBytes::new(48).map_err(|_| CaError)?;
        encoded[..16].copy_from_slice(&[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ]);
        encoded[16..].copy_from_slice(seed);
        PKey::private_key_from_der(&encoded).map_err(|_| CaError)
    }

    /// Borrow the signer only for the private exec channel; never serialize to storage.
    pub(crate) fn handoff_key(&self) -> &PKey<Private> {
        &self.key
    }

    /// Public trust remains usable while the signing source is locked [168].
    pub(crate) fn issuer(&self) -> &X509 {
        &self.issuer
    }
}

/// The owner-selected restart/unlock adapter supplies private material, never SQLite.
pub trait CaKeySource: Send + Sync {
    /// Monotonic public issuer epoch bound into host identity transitions.
    /// The current single-root deployment begins at generation one.
    fn issuer_generation(&self) -> u64 {
        1
    }
    /// Configured reverse proxy enrollment verifies against system HTTPS roots.
    fn uses_system_https(&self) -> bool {
        false
    }
    /// Retained public trust is readable even while signing is cold-locked.
    fn public_issuer(&self) -> Option<X509> {
        None
    }
    /// Ordered public roots that clients may trust during an overlap.
    ///
    /// Existing sources expose one root through `public_issuer`. A rollover
    /// source can override this with the current and next generations while
    /// keeping the signing key locked.
    fn public_roots(&self) -> Vec<(u64, X509)> {
        self.public_issuer()
            .map(|issuer| vec![(1, issuer)])
            .unwrap_or_default()
    }
    /// Optional enrollment HTTPS pin when its trust differs from machine trust.
    fn https_certificate(&self) -> Option<X509> {
        None
    }
    /// Load an unlocked key and corresponding public issuer generation.
    /// # Errors
    /// Missing/wrong unlock credentials fail closed without regeneration.
    fn load(&self) -> Result<CaMaterial, CaError>;
    /// Optional lock events wake deferred renewal immediately after an administrator unlock.
    /// Sources without events retain bounded retry deadlines.
    fn subscribe_locked(&self) -> Option<tokio::sync::watch::Receiver<bool>> {
        None
    }
}

/// One immutable unlocked issuer generation; rotation retains previous public issuers.
pub struct CertificateAuthority(CaMaterial);

/// Signed public host identity and trusted ledger metadata; contains no private key.
pub struct SignedCertificate {
    /// Exact DER sent to the host and fingerprinted in the ledger.
    pub der: Vec<u8>,
    /// Authority fields constructed only by this signer.
    pub record: CertificateRecord,
}

impl CertificateAuthority {
    /// Validate material obtained from the configured key source.
    /// # Errors
    /// Refuses unavailable or inconsistent CA material.
    pub fn from_source(source: &(impl CaKeySource + ?Sized)) -> Result<Self, CaError> {
        Self::from_material(source.load()?)
    }

    pub(crate) fn from_material(material: CaMaterial) -> Result<Self, CaError> {
        let public = material.issuer.public_key().map_err(|_| CaError)?;
        if !CA_KEY_ALGORITHM.accepts(&material.key)
            || !material.key.public_eq(&public)
            || material
                .issuer
                .subject_name()
                .to_der()
                .map_err(|_| CaError)?
                != material
                    .issuer
                    .issuer_name()
                    .to_der()
                    .map_err(|_| CaError)?
            || !material.issuer.verify(&public).map_err(|_| CaError)?
        {
            return Err(CaError);
        }
        Ok(Self(material))
    }

    /// Issue a seven-day client-only identity, ignoring all requested extensions and names.
    /// # Errors
    /// Refuses invalid time or a generation that cannot cover the leaf's lifetime.
    pub fn sign_host(
        &self,
        host: Uuid,
        csr: &ValidatedCsr,
        now: i64,
    ) -> Result<SignedCertificate, CaError> {
        let end = now
            .checked_add(604_800)
            .filter(|_| now >= 0)
            .ok_or(CaError)?;
        let start_time = Asn1Time::from_unix(now).map_err(|_| CaError)?;
        let end_time = Asn1Time::from_unix(end).map_err(|_| CaError)?;
        if self.0.issuer.not_before() > start_time || self.0.issuer.not_after() < end_time {
            return Err(CaError);
        }
        let leaf = self
            .build_host(host, csr, &start_time, &end_time)
            .map_err(|_| CaError)?;
        // Checking the newly built chain also enforces CA BasicConstraints and
        // signing usages on the supplied issuer. A key match alone is insufficient.
        let mut trust = X509StoreBuilder::new().map_err(|_| CaError)?;
        trust.add_cert(self.0.issuer.clone()).map_err(|_| CaError)?;
        let mut parameters = X509VerifyParam::new().map_err(|_| CaError)?;
        parameters.set_time(now);
        trust.set_param(&parameters).map_err(|_| CaError)?;
        let chain = Stack::new().map_err(|_| CaError)?;
        let mut context = X509StoreContext::new().map_err(|_| CaError)?;
        if !context
            .init(&trust.build(), &leaf, &chain, |context| {
                context.verify_cert()
            })
            .map_err(|_| CaError)?
        {
            return Err(CaError);
        }
        let der = leaf.to_der().map_err(|_| CaError)?;
        let issuer_der = self.0.issuer.to_der().map_err(|_| CaError)?;
        let public_key = csr
            .key()
            .raw_public_key()
            .map_err(|_| CaError)?
            .try_into()
            .map_err(|_| CaError)?;
        let record = CertificateRecord {
            fingerprint: Sha256::digest(&der).into(),
            issuer_fingerprint: Sha256::digest(&issuer_der).into(),
            public_key,
            not_before: now,
            not_after: end,
        };
        Ok(SignedCertificate { der, record })
    }

    /// The issuer's raw Ed25519 public key, which mesh SSH trusts as its CA
    /// (owner question Q1 on #221: reuse the D168 key).
    /// # Errors
    /// Refuses a key that is not Ed25519.
    #[cfg(feature = "ssh")]
    pub fn ssh_public_key(&self) -> Result<[u8; 32], CaError> {
        if self.0.key.id() != Id::ED25519 {
            return Err(CaError);
        }
        self.0
            .key
            .raw_public_key()
            .map_err(|_| CaError)?
            .try_into()
            .map_err(|_| CaError)
    }

    /// Issue a mesh SSH person certificate [D235], #221: one principal, exactly
    /// one `source-address` for one mesh address, `permit-pty` only, 1–24 h.
    /// # Errors
    /// Refuses any other shape, a non-Ed25519 key and signing failures.
    #[cfg(feature = "ssh")]
    pub fn issue_ssh_person(
        &self,
        request: &infraternal_plugin_ssh::mesh_issue::PersonRequest<'_>,
    ) -> Result<infraternal_plugin_ssh::mesh_issue::Certificate, CaError> {
        use infraternal_plugin_ssh::mesh_issue;
        let sign = |body: &[u8]| self.sign_ssh(body).ok();
        let certificate = mesh_issue::person_certificate(self.ssh_public_key()?, &sign, request)
            .map_err(|_| CaError)?;
        mesh_issue::check_person(&certificate).map_err(|_| CaError)?;
        Ok(certificate)
    }

    /// Issue a mesh SSH host certificate [D235], #221: host type, at least one
    /// principal (the server derives them from the node record), no options,
    /// 1–24 h.
    /// # Errors
    /// Refuses any other shape, a non-Ed25519 key and signing failures.
    #[cfg(feature = "ssh")]
    pub fn issue_ssh_host(
        &self,
        request: &infraternal_plugin_ssh::mesh_issue::HostRequest<'_>,
    ) -> Result<infraternal_plugin_ssh::mesh_issue::Certificate, CaError> {
        use infraternal_plugin_ssh::mesh_issue;
        let sign = |body: &[u8]| self.sign_ssh(body).ok();
        let certificate = mesh_issue::host_certificate(self.ssh_public_key()?, &sign, request)
            .map_err(|_| CaError)?;
        mesh_issue::check_host(&certificate).map_err(|_| CaError)?;
        Ok(certificate)
    }

    #[cfg(feature = "ssh")]
    /// Sign one SSH certificate body. Private: only the typed issuers above
    /// reach it (J181 M6), so no caller can mint another certificate shape.
    ///
    /// Invariant: the D168 key signs X.509 bodies (DER, starting `0x30`) and
    /// these SSH certificate bodies (starting with the Ed25519 certificate
    /// type string). Any future use of this key needs its own fixed prefix
    /// that cannot overlap either.
    /// # Errors
    /// Refuses any other body and signing failures.
    fn sign_ssh(&self, body: &[u8]) -> Result<[u8; 64], CaError> {
        const BODY_PREFIX: &[u8] = b"\0\0\0\x20ssh-ed25519-cert-v01@openssh.com";
        if !body.starts_with(BODY_PREFIX) || self.0.key.id() != Id::ED25519 {
            return Err(CaError);
        }
        let mut signer =
            openssl::sign::Signer::new_without_digest(&self.0.key).map_err(|_| CaError)?;
        signer
            .sign_oneshot_to_vec(body)
            .map_err(|_| CaError)?
            .try_into()
            .map_err(|_| CaError)
    }

    fn build_host(
        &self,
        host: Uuid,
        csr: &ValidatedCsr,
        start: &Asn1Time,
        end: &Asn1Time,
    ) -> Result<X509, openssl::error::ErrorStack> {
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", &host.to_string())?;
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        // Positive, unpredictable serials fit RFC5280's twenty-octet ceiling.
        let mut serial = rand::random::<[u8; 20]>();
        serial[0] = (serial[0] & 0x7f) | 1;
        let serial = BigNum::from_slice(&serial)?.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;
        builder.set_subject_name(&name.build())?;
        builder.set_issuer_name(self.0.issuer.subject_name())?;
        builder.set_pubkey(csr.key())?;
        builder.set_not_before(start)?;
        builder.set_not_after(end)?;
        builder.append_extension(BasicConstraints::new().critical().build()?)?;
        builder.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
        builder.append_extension(ExtendedKeyUsage::new().client_auth().build()?)?;
        let san = SubjectAlternativeName::new()
            .uri(&format!("urn:infraternal:host:{host}"))
            .build(&builder.x509v3_context(Some(&self.0.issuer), None))?;
        builder.append_extension(san)?;
        builder.sign(
            &self.0.key,
            if CA_KEY_ALGORITHM == CaAlgorithm::Ed25519 {
                MessageDigest::null()
            } else {
                MessageDigest::sha256()
            },
        )?;
        Ok(builder.build())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        stack::Stack,
        x509::{
            X509NameBuilder, X509Req, X509StoreContext,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
            store::X509StoreBuilder,
            verify::X509VerifyFlags,
        },
    };

    pub(crate) struct MemorySource {
        key: PKey<Private>,
        issuer: X509,
    }
    impl CaKeySource for MemorySource {
        fn load(&self) -> Result<CaMaterial, CaError> {
            Ok(CaMaterial::new(self.key.clone(), self.issuer.clone()))
        }
    }
    /// Test-only leaf construction isolates renewal constraints against the same issuer and retained host key.
    pub(crate) fn altered_renewal_leaf(
        material: &CaMaterial,
        key: &PKey<Private>,
        host: Uuid,
        epoch: i64,
        lifetime: i64,
        client_auth: bool,
    ) -> X509 {
        let mut subject = X509NameBuilder::new().unwrap();
        subject
            .append_entry_by_text("CN", &host.to_string())
            .unwrap();
        let mut leaf = X509::builder().unwrap();
        leaf.set_version(2).unwrap();
        leaf.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        leaf.set_subject_name(&subject.build()).unwrap();
        leaf.set_issuer_name(material.issuer.subject_name())
            .unwrap();
        leaf.set_pubkey(key).unwrap();
        leaf.set_not_before(&Asn1Time::from_unix(epoch).unwrap())
            .unwrap();
        leaf.set_not_after(&Asn1Time::from_unix(epoch + lifetime).unwrap())
            .unwrap();
        leaf.append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        leaf.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
        let mut purpose = ExtendedKeyUsage::new();
        if client_auth {
            purpose.client_auth();
        } else {
            purpose.server_auth();
        }
        leaf.append_extension(purpose.build().unwrap()).unwrap();
        leaf.append_extension(
            SubjectAlternativeName::new()
                .uri(&format!("urn:infraternal:host:{host}"))
                .build(&leaf.x509v3_context(Some(&material.issuer), None))
                .unwrap(),
        )
        .unwrap();
        leaf.sign(&material.key, MessageDigest::null()).unwrap();
        leaf.build()
    }

    struct Locked;
    impl CaKeySource for Locked {
        fn load(&self) -> Result<CaMaterial, CaError> {
            Err(CaError)
        }
    }

    pub(crate) fn source(is_ca: bool) -> MemorySource {
        let key = PKey::generate_ed25519().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "infraternal test CA")
            .unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::from_unix(1_700_000_000).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::from_unix(2_000_000_000).unwrap())
            .unwrap();
        if is_ca {
            cert.append_extension(
                BasicConstraints::new()
                    .critical()
                    .ca()
                    .pathlen(0)
                    .build()
                    .unwrap(),
            )
            .unwrap();
            cert.append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        }
        cert.sign(&key, MessageDigest::null()).unwrap();
        MemorySource {
            key,
            issuer: cert.build(),
        }
    }

    fn malicious_csr() -> ValidatedCsr {
        let key = PKey::generate_ed25519().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "attacker").unwrap();
        let mut req = X509Req::builder().unwrap();
        req.set_pubkey(&key).unwrap();
        req.set_subject_name(&name.build()).unwrap();
        let mut ext = Stack::new().unwrap();
        ext.push(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        ext.push(ExtendedKeyUsage::new().server_auth().build().unwrap())
            .unwrap();
        ext.push(
            SubjectAlternativeName::new()
                .dns("attacker.example")
                .build(&req.x509v3_context(None))
                .unwrap(),
        )
        .unwrap();
        req.add_extensions(&ext).unwrap();
        req.sign(&key, MessageDigest::null()).unwrap();
        ValidatedCsr::parse(&req.build().to_der().unwrap()).unwrap()
    }

    pub(crate) fn test_authority() -> CertificateAuthority {
        CertificateAuthority::from_source(&source(true)).unwrap()
    }

    pub(crate) fn test_material() -> CaMaterial {
        source(true).load().unwrap()
    }

    #[cfg(feature = "ssh")]
    #[test]
    fn ssh_signing_is_limited_to_ssh_certificate_bodies() {
        let source = source(true);
        let ca = CertificateAuthority::from_source(&source).unwrap();
        let public = ca.ssh_public_key().unwrap();
        assert_eq!(public.as_slice(), source.key.raw_public_key().unwrap());
        let body = b"\0\0\0\x20ssh-ed25519-cert-v01@openssh.com\0\0\0\x20nonce";
        let signature = ca.sign_ssh(body).unwrap();
        let mut verifier = openssl::sign::Verifier::new_without_digest(&source.key).unwrap();
        assert!(verifier.verify_oneshot(&signature, body).unwrap());
        // An X.509 body, a bare message or a different SSH key type is refused.
        for refused in [
            &b"\x30\x82\x01\x00"[..],
            b"",
            b"\0\0\0\x20ssh-ed25519-cert-v01@openssh.co",
            b"\0\0\0\x1cecdsa-sha2-nistp256-cert-v01",
        ] {
            assert!(ca.sign_ssh(refused).is_err());
        }
    }

    #[cfg(feature = "ssh")]
    #[test]
    fn the_ca_issues_only_the_two_mesh_certificate_shapes() {
        use infraternal_plugin_ssh::mesh_issue::{HostRequest, PersonRequest, PublicKey};
        // J181 M6: callers get typed issuance, never a raw signature.
        let ca = CertificateAuthority::from_source(&source(true)).unwrap();
        let subject = PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGXPXKkPzpN6tM1N1a8nGiE0pBsTzZAOZn3ZK7mFx0z0",
        )
        .unwrap();
        let now = 1_800_000_000;
        let person = ca
            .issue_ssh_person(&PersonRequest {
                subject: &subject,
                person: "kayg-id",
                source_address: "10.254.0.7".parse().unwrap(),
                now,
                lifetime: 24 * 3600,
            })
            .unwrap();
        assert_eq!(person.valid_principals(), ["kayg-id"]);
        let principals = ["db-01".to_owned()];
        let host = ca
            .issue_ssh_host(&HostRequest {
                subject: &subject,
                principals: &principals,
                now,
                lifetime: 3600,
            })
            .unwrap();
        assert_eq!(host.valid_principals(), principals);
        // A shape the mesh never needs is refused by the CA itself.
        assert!(
            ca.issue_ssh_host(&HostRequest {
                subject: &subject,
                principals: &[],
                now,
                lifetime: 3600,
            })
            .is_err()
        );
        assert!(
            ca.issue_ssh_person(&PersonRequest {
                subject: &subject,
                person: "kayg-id",
                source_address: "10.254.0.7".parse().unwrap(),
                now,
                lifetime: 48 * 3600,
            })
            .is_err()
        );
    }

    #[test]
    fn signed_identity_has_only_server_constructed_host_authority_and_seven_days() {
        let source = source(true);
        let ca = CertificateAuthority::from_source(&source).unwrap();
        let host = Uuid::from_u128(42);
        let csr = malicious_csr();
        let signed = ca.sign_host(host, &csr, 1_800_000_000).unwrap();
        let leaf = X509::from_der(&signed.der).unwrap();
        assert!(leaf.verify(&source.key).unwrap());
        assert_eq!(signed.record.not_before, 1_800_000_000);
        assert_eq!(signed.record.not_after, 1_800_604_800);
        assert_eq!(
            signed.record.public_key.as_slice(),
            csr.key().raw_public_key().unwrap()
        );
        let sans = leaf.subject_alt_names().unwrap();
        assert_eq!(sans.len(), 1);
        assert_eq!(
            sans[0].uri(),
            Some("urn:infraternal:host:00000000-0000-0000-0000-00000000002a")
        );
        let text = String::from_utf8(leaf.to_text().unwrap()).unwrap();
        assert!(!text.contains("attacker"));
        assert!(text.contains("CA:FALSE"));
        assert!(text.contains("TLS Web Client Authentication"));
        assert!(!text.contains("TLS Web Server Authentication"));
        let mut trust = X509StoreBuilder::new().unwrap();
        trust.add_cert(source.issuer).unwrap();
        trust.set_flags(X509VerifyFlags::NO_CHECK_TIME).unwrap();
        let mut ctx = X509StoreContext::new().unwrap();
        assert!(
            ctx.init(
                &trust.build(),
                &leaf,
                &Stack::new().unwrap(),
                openssl::x509::X509StoreContextRef::verify_cert
            )
            .unwrap()
        );
    }

    #[test]
    fn source_mismatch_locked_and_uncovered_validity_fail_closed() {
        assert!(CertificateAuthority::from_source(&Locked).is_err());
        let mut mismatch = source(true);
        mismatch.key = PKey::generate_ed25519().unwrap();
        assert!(CertificateAuthority::from_source(&mismatch).is_err());
        let ca = test_authority();
        let csr = malicious_csr();
        let non_ca = CertificateAuthority::from_source(&source(false)).unwrap();
        assert!(
            non_ca
                .sign_host(Uuid::from_u128(42), &csr, 1_800_000_000)
                .is_err()
        );
        for now in [-1, 1_699_999_999, 1_999_900_000, i64::MAX] {
            assert!(ca.sign_host(Uuid::from_u128(42), &csr, now).is_err());
        }
    }
    #[test]
    #[ignore = "explicit signing-boundary diagnostic; not live renewal or connected-agent RSS"]
    fn signing_boundary_at_1000_public_identities() {
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
        fn ticks() -> u64 {
            let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
            let tail: Vec<_> = stat
                .rsplit_once(')')
                .unwrap()
                .1
                .split_whitespace()
                .collect();
            tail[11].parse::<u64>().unwrap() + tail[12].parse::<u64>().unwrap()
        }
        let ca = test_authority();
        let csr = malicious_csr();
        let before = rss();
        let cpu = ticks();
        let mut retained = Vec::with_capacity(1000);
        let mut timings = Vec::with_capacity(1000);
        let mut bytes = 0;
        for host in 1..=1000 {
            let start = Instant::now();
            let certificate = ca
                .sign_host(Uuid::from_u128(host), &csr, 1_800_000_000)
                .unwrap();
            timings.push(start.elapsed().as_micros());
            bytes += certificate.der.len();
            retained.push(certificate);
        }
        timings.sort_unstable();
        println!(
            "signing_boundary n=1000 p50_us={} p99_us={} cpu_ticks={} retained_der_bytes={bytes} baseline_rss_kib={before} retained_rss_kib={} rss_delta_per_identity_kib={} scale=1000 load={}",
            timings[500],
            timings[990],
            ticks() - cpu,
            rss(),
            f64::from(u32::try_from(rss().saturating_sub(before)).unwrap()) / 1000.0,
            std::fs::read_to_string("/proc/loadavg").unwrap().trim()
        );
    }
}
