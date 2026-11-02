//! Live half-life scheduler regression with real TLS, the production router and a memory-only signer, #78.
use super::*;

pub(super) async fn enrolled_at_half_life(
    fixture: &Fixture,
) -> (uuid::Uuid, infraternal_agent::remote_tls::Identity) {
    use crate::ca::CertificateAuthority;
    use openssl::{
        hash::MessageDigest,
        pkey::PKey,
        x509::{X509NameBuilder, X509Req},
    };
    let host = uuid::Uuid::new_v4();
    let uid = nix::unistd::Uid::effective().as_raw();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES (?,'owner','rootless',?,?)")
        .bind(host.as_bytes().as_slice()).bind(uid).bind(unix_seconds().unwrap()).execute(&fixture.pool).await.unwrap();
    let key = PKey::generate_ed25519().unwrap();
    let mut request = X509Req::builder().unwrap();
    request
        .set_subject_name(&X509NameBuilder::new().unwrap().build())
        .unwrap();
    request.set_pubkey(&key).unwrap();
    request.sign(&key, MessageDigest::null()).unwrap();
    let csr = crate::csr::ValidatedCsr::parse(&request.build().to_der().unwrap()).unwrap();
    let now = unix_seconds().unwrap();
    let signed = CertificateAuthority::from_material(fixture.material.clone())
        .unwrap()
        .sign_host(host, &csr, now - 302_401)
        .unwrap();
    let store = crate::enrollment::EnrollmentStore::new(fixture.pool.clone());
    let key_digest = openssl::sha::sha256(&key.raw_public_key().unwrap());
    let token = store
        .issue("owner", host, crate::enrollment::Mode::Rootless, now, &key_digest)
        .await
        .unwrap();
    store
        .redeem(
            token.secret(),
            host,
            crate::enrollment::Mode::Rootless,
            now,
            &signed.record,
        )
        .await
        .unwrap();
    (
        host,
        infraternal_agent::remote_tls::Identity {
            certificate: X509::from_der(&signed.der).unwrap(),
            key,
        },
    )
}

#[tokio::test]
async fn half_life_requests_proof_on_live_authenticated_control() {
    use infraternal_agent::{
        remote_tls,
        transport::{Receive, Transmit},
    };
    let directory = Directory::new();
    let fixture = fixture_at(
        &directory,
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;
    let (_host, identity) = enrolled_at_half_life(&fixture).await;
    let config = remote_tls::client_config(&identity, std::slice::from_ref(&fixture.root)).unwrap();
    let connection = remote_tls::dial(
        fixture.listeners.as_ref().unwrap().local_addr().unwrap(),
        "localhost",
        &config,
    )
    .await
    .unwrap();
    Transmit::default()
        .send(
            &connection.channel,
            0,
            &Frame::Hello {
                version: 1,
                caps: 1 << 2,
                client_info: "renewal regression",
            },
        )
        .await
        .unwrap();
    let mut receive = Receive::default();
    assert!(matches!(
        receive.next(&connection.channel).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    let requested =
        tokio::time::timeout(Duration::from_secs(2), receive.next(&connection.channel)).await;
    assert!(
        matches!(requested, Ok(Ok(frame)) if matches!(frame.frame, Frame::Call { action_id:"transport.csr", .. })),
        "half-life did not request CSR over the live control stream"
    );
}
