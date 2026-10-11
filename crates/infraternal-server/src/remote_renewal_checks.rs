//! Defensive renewal publication regressions using signed host leaves and the real CA, #78.
use super::*;
use infraternal_agent::remote_renewal::{
    CertificatePublisher, CertificateUpdate, CsrProof, RenewalIdentity,
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

#[test]
fn renewal_validates_host_dates_json_and_durable_publication_before_ack() {
    let (_, host, root, material) = identities();
    let signer = crate::ca::CertificateAuthority::from_material(material).unwrap();
    let publisher = Arc::new(Published(AtomicUsize::new(0), true));
    let current = RenewalIdentity::new(&host, std::slice::from_ref(&root), publisher.clone());
    let json = current.action("transport.csr", b"{}").unwrap();
    let proof: CsrProof = serde_json::from_slice(&json).unwrap();
    let request = crate::csr::ValidatedCsr::parse(&proof.csr_der).unwrap();
    let epoch = now().unwrap();
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
    let epoch = now().unwrap();
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
