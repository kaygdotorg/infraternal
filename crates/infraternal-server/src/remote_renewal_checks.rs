//! Defensive renewal publication regressions using signed host leaves and the real CA, #78.
//!
//! Successful leaves start one second before the fixture clock: these cases
//! exercise key, purpose, lifetime and publication rather than the boundary
//! between independent wall-clock reads. The explicit future `notBefore` case
//! still starts almost a minute in the future.
use super::*;
use infraternal_agent::remote_renewal::{
    CertificatePublisher, CertificateUpdate, CsrProof, RenewalIdentity,
};
use infraternal_plugin_remote::identity_rotation::{
    Challenge, CompletedRotation, Proof, RotationPublisher, RotationStorage,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Published(AtomicUsize, bool);
impl CertificatePublisher for Published {
    fn publish(&self, _: &X509) -> std::io::Result<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        if self.1 {
            Ok(())
        } else {
            Err(std::io::ErrorKind::PermissionDenied.into())
        }
    }
}

/// Records the challenge and proof the test agent produced, so the test can check them.
#[derive(Default)]
struct RotationFixture(std::sync::Mutex<Option<(Challenge, Vec<u8>)>>);

impl RotationPublisher for RotationFixture {
    fn load(&self) -> std::io::Result<RotationStorage> {
        Ok(RotationStorage {
            pending: None,
            completed: None,
        })
    }

    fn store_candidate(&self, challenge: &Challenge, key_pkcs8: &[u8]) -> std::io::Result<()> {
        *self
            .0
            .lock()
            .map_err(|_| std::io::Error::other("fixture lock poisoned"))? =
            Some((challenge.clone(), key_pkcs8.to_vec()));
        Ok(())
    }

    fn store_certificate(&self, _: Uuid, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    fn promote(&self, _: &CompletedRotation) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn renewal_validates_host_dates_json_and_durable_publication_before_ack() {
    let (_, host, root, material) = identities();
    let signer = crate::ca::CertificateAuthority::from_material(material).unwrap();
    let publisher = Arc::new(Published(AtomicUsize::new(0), true));
    let current = RenewalIdentity::new(&host, std::slice::from_ref(&root), publisher.clone());
    let json = current.action("transport.csr", b"{}").unwrap();
    let proof: CsrProof = serde_json::from_slice(&json).unwrap();
    let request = crate::csr::ValidatedCsr::parse(&proof.csr_der).unwrap();
    let epoch = now().unwrap() - 1;
    let renewed = signer
        .sign_host(Uuid::from_u128(42), &request, epoch + 60)
        .unwrap();
    let payload = serde_json::to_vec(&CertificateUpdate {
        certificate_der: renewed.der.clone(),
    })
    .unwrap();
    // Future notBefore is intentionally refused until it is current; reconstruct
    // the older retained leaf so the new leaf can be validated against real time.
    let earlier = signer
        .sign_host(Uuid::from_u128(42), &request, epoch - 1)
        .unwrap();
    let host = Identity {
        key: host.key,
        certificate: X509::from_der(&earlier.der).unwrap(),
    };
    let current = RenewalIdentity::new(&host, std::slice::from_ref(&root), publisher.clone());
    assert!(current.action("transport.certificate", &payload).is_err());
    let renewed = signer
        .sign_host(Uuid::from_u128(42), &request, epoch)
        .unwrap();
    let payload = serde_json::to_vec(&CertificateUpdate {
        certificate_der: renewed.der.clone(),
    })
    .unwrap();
    let other = signer
        .sign_host(Uuid::from_u128(43), &request, epoch)
        .unwrap();
    let foreign = serde_json::to_vec(&CertificateUpdate {
        certificate_der: other.der,
    })
    .unwrap();
    assert!(current.action("transport.certificate", &foreign).is_err());
    assert!(
        current
            .action(
                "transport.certificate",
                b"{\"certificate_der\":[],\"other\":true}"
            )
            .is_err()
    );
    assert!(
        current
            .action("transport.csr", b"{\"other\":true}")
            .is_err()
    );
    assert!(
        current
            .action("transport.csr", &vec![b' '; 32_769])
            .is_err()
    );
    assert_eq!(publisher.0.load(Ordering::Relaxed), 0);
    assert_eq!(
        current.action("transport.certificate", &payload).unwrap(),
        b"{}"
    );
    assert_eq!(
        current.current().unwrap().certificate.to_der().unwrap(),
        renewed.der
    );
    assert!(
        current.action("transport.certificate", &payload).is_err(),
        "duplicate publication cannot extend authority"
    );
    let failed = Arc::new(Published(AtomicUsize::new(0), false));
    let current = RenewalIdentity::new(&host, &[root], failed.clone());
    assert!(current.action("transport.certificate", &payload).is_err());
    assert_eq!(
        current.current().unwrap().certificate.to_der().unwrap(),
        earlier.der
    );
    assert_eq!(failed.0.load(Ordering::Relaxed), 1);
}

#[test]
fn renewal_refuses_same_issuer_wrong_key_purpose_or_lifetime_before_publication() {
    let (_, retained, root, material) = identities();
    let signer = crate::ca::CertificateAuthority::from_material(material.clone()).unwrap();
    let proof = RenewalIdentity::new(
        &retained,
        std::slice::from_ref(&root),
        Arc::new(Published(AtomicUsize::new(0), true)),
    )
    .action("transport.csr", b"{}")
    .unwrap();
    let proof: CsrProof = serde_json::from_slice(&proof).unwrap();
    let csr = crate::csr::ValidatedCsr::parse(&proof.csr_der).unwrap();
    let epoch = now().unwrap() - 1;
    let previous = signer
        .sign_host(Uuid::from_u128(42), &csr, epoch - 60)
        .unwrap();
    let identity = Identity {
        key: retained.key,
        certificate: X509::from_der(&previous.der).unwrap(),
    };
    let publisher = Arc::new(Published(AtomicUsize::new(0), true));
    let renewal = RenewalIdentity::new(&identity, &[root], publisher.clone());
    let other_key = openssl::pkey::PKey::generate_ed25519().unwrap();
    for (key, lifetime, client_auth) in [
        (&other_key, 604_800, true),
        (&identity.key, 604_800, false),
        (&identity.key, 604_799, true),
        (&identity.key, 604_801, true),
    ] {
        let leaf = crate::ca::tests::altered_renewal_leaf(
            &material,
            key,
            Uuid::from_u128(42),
            epoch,
            lifetime,
            client_auth,
        );
        let payload = serde_json::to_vec(&CertificateUpdate {
            certificate_der: leaf.to_der().unwrap(),
        })
        .unwrap();
        assert!(renewal.action("transport.certificate", &payload).is_err());
        assert_eq!(publisher.0.load(Ordering::Relaxed), 0);
        assert_eq!(
            renewal.current().unwrap().certificate.to_der().unwrap(),
            previous.der
        );
    }
    let matching = crate::ca::tests::altered_renewal_leaf(
        &material,
        &identity.key,
        Uuid::from_u128(42),
        epoch,
        604_800,
        true,
    );
    let payload = serde_json::to_vec(&CertificateUpdate {
        certificate_der: matching.to_der().unwrap(),
    })
    .unwrap();
    assert_eq!(
        renewal.action("transport.certificate", &payload).unwrap(),
        b"{}"
    );
    assert_eq!(publisher.0.load(Ordering::Relaxed), 1);
}

/// A replacement CSR carries a new Ed25519 key and is signed by the old identity.
#[test]
fn replacement_csr_is_bound_to_the_old_identity_and_a_new_ed25519_key() {
    let (_, retained, root, _) = identities();
    let publisher = Arc::new(RotationFixture::default());
    let mut rotation = RenewalIdentity::new(
        &retained,
        std::slice::from_ref(&root),
        Arc::new(Published(AtomicUsize::new(0), true)),
    );
    rotation
        .enable_identity_rotation(publisher.clone())
        .unwrap();
    let fingerprint = |certificate: &X509| {
        <[u8; 32]>::try_from(
            certificate
                .digest(openssl::hash::MessageDigest::sha256())
                .unwrap()
                .as_ref(),
        )
        .unwrap()
    };
    let challenge = Challenge {
        host_id: Uuid::from_u128(42),
        operation_id: Uuid::from_u128(285),
        sequence: 1,
        challenge: [0x5a; 32],
        predecessor_fingerprint: fingerprint(&retained.certificate),
        issuer_fingerprint: fingerprint(&root),
        issuer_generation: 1,
    };
    let input = serde_json::to_vec(&challenge).unwrap();
    let proof: Proof =
        serde_json::from_slice(&rotation.action("transport.csr.rotate", &input).unwrap()).unwrap();
    assert_eq!(proof.operation_id, challenge.operation_id);
    assert_eq!(proof.sequence, challenge.sequence);
    let request = openssl::x509::X509Req::from_der(&proof.csr_der).unwrap();
    let replacement = request.public_key().unwrap();

    assert_eq!(replacement.id(), openssl::pkey::Id::ED25519);
    assert!(!replacement.public_eq(&retained.key));
    let stored_key = {
        let stored = publisher.0.lock().unwrap();
        let (_, key_pkcs8) = stored
            .as_ref()
            .expect("candidate key is stored before its CSR is returned");
        PKey::private_key_from_pkcs8(key_pkcs8).unwrap()
    };
    assert!(stored_key.public_eq(&replacement));
    let message =
        infraternal_plugin_remote::identity_rotation::transcript(&challenge, &proof.csr_der)
            .unwrap();
    let mut verifier = openssl::sign::Verifier::new_without_digest(&retained.key).unwrap();
    assert!(
        verifier
            .verify_oneshot(&proof.old_signature, &message)
            .unwrap()
    );
}
