//! Checks the key socket's message handling, its refusals and a stock OpenSSH client against it.
use super::*;
use crate::mesh_issue::{self, PersonRequest};
use russh::keys::{Algorithm, HashAlg, PublicKey};
use std::sync::Arc;

fn identity() -> PersonKey {
    let ca = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
    let key = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
    let sign = |body: &[u8]| {
        let signature: Signature = ca.try_sign(body).ok()?;
        signature.as_bytes().try_into().ok()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let certificate = mesh_issue::person_certificate(
        ca.public_key().key_data().ed25519().unwrap().0,
        &sign,
        &PersonRequest {
            subject: key.public_key(),
            person: "0b5c8a64-7d1f-4c43-9d0e-0c6a8a5b7f10",
            source_address: "10.254.0.7".parse().unwrap(),
            now,
            lifetime: mesh_issue::MAX_LIFETIME,
        },
    )
    .unwrap();
    PersonKey { certificate, key }
}

fn string(bytes: &[u8]) -> Vec<u8> {
    let mut out = (u32::try_from(bytes.len()).unwrap()).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn sign_request(blob: &[u8], data: &[u8]) -> Vec<u8> {
    let mut body = vec![SIGN_REQUEST];
    body.extend(string(blob));
    body.extend(string(data));
    body.extend(0_u32.to_be_bytes());
    body
}

fn session_bind(forwarding: u8) -> Vec<u8> {
    let mut body = vec![EXTENSION];
    body.extend(string(b"session-bind@openssh.com"));
    body.extend(string(b"host key"));
    body.extend(string(b"session id"));
    body.extend(string(b"signature"));
    body.push(forwarding);
    body
}

#[test]
fn lists_nothing_without_an_identity() {
    let reply = Session::default()
        .answer(&[REQUEST_IDENTITIES], None)
        .unwrap();
    assert_eq!(reply, [IDENTITIES_ANSWER, 0, 0, 0, 0]);
}

#[test]
fn lists_the_certificate_and_signs_with_its_key() {
    let identity = identity();
    let mut session = Session::default();
    let listed = session
        .answer(&[REQUEST_IDENTITIES], Some(&identity))
        .unwrap();
    let blob = identity.certificate.to_bytes().unwrap();
    let mut expected = vec![IDENTITIES_ANSWER, 0, 0, 0, 1];
    expected.extend(string(&blob));
    expected.extend(string(b"infraternal mesh"));
    assert_eq!(listed, expected);

    let reply = session
        .answer(&sign_request(&blob, b"challenge"), Some(&identity))
        .unwrap();
    assert_eq!(reply[0], SIGN_RESPONSE);
    let mut fields = Fields(&reply[1..]);
    let encoded = fields.string().unwrap();
    assert!(fields.done());
    let mut encoded = Fields(encoded);
    assert_eq!(encoded.string().unwrap(), b"ssh-ed25519");
    let bytes = encoded.string().unwrap();
    let signature = Signature::new(Algorithm::Ed25519, bytes.to_vec()).unwrap();
    let public: &PublicKey = identity.key.public_key();
    // The inherent `PublicKey::verify` is SSHSIG; this is the raw signature check.
    <PublicKey as russh::keys::signature::Verifier<Signature>>::verify(
        public,
        b"challenge",
        &signature,
    )
    .unwrap();
}

#[test]
fn refuses_to_sign_for_any_other_key() {
    let identity = identity();
    let other = identity_blob_of_plain_key(&identity);
    let reply = Session::default()
        .answer(&sign_request(&other, b"challenge"), Some(&identity))
        .unwrap();
    assert_eq!(reply, [FAILURE]);
    let reply = Session::default()
        .answer(&sign_request(b"", b"challenge"), Some(&identity))
        .unwrap();
    assert_eq!(reply, [FAILURE]);
}

fn identity_blob_of_plain_key(identity: &PersonKey) -> Vec<u8> {
    // The bare public key of the same pair is not the listed identity.
    identity.key.public_key().to_bytes().unwrap()
}

#[test]
fn a_forwarded_connection_never_signs() {
    let identity = identity();
    let blob = identity.certificate.to_bytes().unwrap();
    let mut session = Session::default();
    assert_eq!(
        session.answer(&session_bind(1), Some(&identity)).unwrap(),
        [SUCCESS]
    );
    assert_eq!(
        session
            .answer(&sign_request(&blob, b"challenge"), Some(&identity))
            .unwrap(),
        [FAILURE]
    );
    assert_eq!(
        session
            .answer(&[REQUEST_IDENTITIES], Some(&identity))
            .unwrap(),
        [IDENTITIES_ANSWER, 0, 0, 0, 0]
    );
    // Any nonzero flag is forwarding.
    let mut odd = Session::default();
    odd.answer(&session_bind(7), Some(&identity)).unwrap();
    assert_eq!(
        odd.answer(&sign_request(&blob, b"x"), Some(&identity))
            .unwrap(),
        [FAILURE]
    );
}

#[test]
fn a_direct_binding_still_signs() {
    let identity = identity();
    let blob = identity.certificate.to_bytes().unwrap();
    let mut session = Session::default();
    session.answer(&session_bind(0), Some(&identity)).unwrap();
    assert_eq!(
        session
            .answer(&sign_request(&blob, b"challenge"), Some(&identity))
            .unwrap()[0],
        SIGN_RESPONSE
    );
}

#[test]
fn key_management_requests_fail() {
    let identity = identity();
    // Add identity, remove identity, remove all, lock, unlock, add smartcard.
    for kind in [17_u8, 18, 19, 22, 23, 20, 25, 0, 255] {
        assert_eq!(
            Session::default()
                .answer(&[kind, 0, 0, 0, 0], Some(&identity))
                .unwrap(),
            [FAILURE],
            "{kind}"
        );
    }
    let mut unknown = vec![EXTENSION];
    unknown.extend(string(b"query"));
    assert_eq!(
        Session::default()
            .answer(&unknown, Some(&identity))
            .unwrap(),
        [FAILURE]
    );
}

#[test]
fn malformed_messages_end_the_connection() {
    let identity = identity();
    let blob = identity.certificate.to_bytes().unwrap();
    let mut truncated = sign_request(&blob, b"challenge");
    truncated.pop();
    let mut trailing = sign_request(&blob, b"challenge");
    trailing.push(0);
    let mut lying = vec![SIGN_REQUEST];
    lying.extend(u32::MAX.to_be_bytes());
    let mut bind_trailing = session_bind(0);
    bind_trailing.push(1);
    for body in [
        Vec::new(),
        vec![REQUEST_IDENTITIES, 0],
        truncated,
        trailing,
        lying,
        bind_trailing,
        session_bind(1)[..10].to_vec(),
    ] {
        assert!(Session::default().answer(&body, Some(&identity)).is_none());
    }
}

#[test]
fn only_ordinary_accounts_may_ask() {
    let linux = OrdinaryUids::LINUX;
    assert!(!may_ask(0, linux));
    assert!(!may_ask(999, linux));
    assert!(may_ask(1000, linux));
    assert!(!may_ask(65_534, linux));
    assert!(may_ask(501, OrdinaryUids::MACOS));
}

#[tokio::test]
async fn oversized_and_empty_lengths_are_refused() {
    for length in [0_u32, u32::try_from(MAX_MESSAGE + 1).unwrap(), u32::MAX] {
        let (mut client, server) = tokio::io::duplex(64);
        let task = tokio::spawn(serve(server, || None));
        client.write_all(&length.to_be_bytes()).await.unwrap();
        let result = task.await.unwrap();
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::InvalidData,
            "{length}"
        );
    }
}

#[tokio::test]
async fn stock_ssh_add_lists_the_certificate() {
    if std::process::Command::new("ssh-add")
        .arg("-h")
        .output()
        .is_err()
    {
        eprintln!("SKIP: ssh-add is not installed");
        return;
    }
    let identity = Arc::new(identity());
    let directory = std::env::temp_dir().join(format!("j175-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("agent.sock");
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let shared = Arc::clone(&identity);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve(stream, move || Some(Arc::clone(&shared))).await
    });
    let output = tokio::task::spawn_blocking({
        let path = path.clone();
        move || {
            std::process::Command::new("ssh-add")
                .arg("-L")
                .env("SSH_AUTH_SOCK", path)
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();
    server.await.unwrap().unwrap();
    let listed = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "{listed}");
    assert!(
        listed.starts_with("ssh-ed25519-cert-v01@openssh.com "),
        "{listed}"
    );
    // The listed key is this certificate, not some other key in the line.
    let listed_key = russh::keys::Certificate::from_openssh(listed.trim()).unwrap();
    assert_eq!(
        listed_key.public_key().fingerprint(HashAlg::Sha256),
        identity
            .certificate
            .public_key()
            .fingerprint(HashAlg::Sha256)
    );
    std::fs::remove_dir_all(&directory).unwrap();
}
