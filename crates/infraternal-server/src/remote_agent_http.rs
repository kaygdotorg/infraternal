//! Admits D168 host links over an app-listener WebSocket proof [168,196], #291.

use crate::{
    enrollment::EnrollmentStore, remote_guard::AuthorityGuard, remote_runtime::RemoteHosts,
};
use axum::{
    Router,
    extract::{
        ConnectInfo, Request, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use infraternal_plugin_remote::agent_link::{
    AgentLinkChallenge, AgentLinkProof, AgentLinkReady, proof_bytes,
};
use openssl::{hash::MessageDigest, pkey::Id, rand::rand_bytes, sign::Verifier, x509::X509};
use std::{io, net::IpAddr, sync::Arc, time::Duration};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

const MAX_PROOF_MESSAGE: usize = 8192;
const MAX_MESSAGE: usize = infraternal_protocol::MAX_FRAME_LEN + 64;
const HANDSHAKE: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct Api {
    hosts: RemoteHosts,
    store: EnrollmentStore,
    admission: Arc<Semaphore>,
    sources: Arc<crate::remote_admission::SourceSlots>,
}

fn trace_test_phase<T>(phase: &'static str, result: io::Result<T>) -> io::Result<T> {
    #[cfg(test)]
    match &result {
        Ok(_) => eprintln!("remote agent HTTPS phase={phase} complete"),
        Err(error) => eprintln!("remote agent HTTPS phase={phase} error={error:?}"),
    }
    let _ = phase;
    result
}

/// Add the agent path only when D168 enrollment is configured for this runtime.
/// Admission limits cover unauthenticated handshake work; enrolled links use `RemoteHosts`.
pub(crate) fn router(hosts: RemoteHosts, store: EnrollmentStore) -> Router {
    Router::new()
        .route("/remote/agent", get(upgrade))
        .with_state(Api {
            hosts,
            store,
            admission: Arc::new(Semaphore::new(64)),
            sources: Arc::new(crate::remote_admission::SourceSlots::new(4)),
        })
}

async fn upgrade(State(api): State<Api>, ws: WebSocketUpgrade, request: Request) -> Response {
    let address = request
        .extensions()
        .get::<crate::runtime::ClientAddress>()
        .map(|address| address.0)
        .or_else(|| {
            request
                .extensions()
                .get::<ConnectInfo<std::net::SocketAddr>>()
                .map(|address| address.0.ip())
        })
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    let Some(source) = api.sources.reserve(address) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let Ok(permit) = api.admission.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    ws.max_message_size(MAX_MESSAGE)
        .max_frame_size(MAX_MESSAGE)
        .on_upgrade(move |socket| async move {
            if let Err(error) = admit(socket, api, address, source, permit).await {
                eprintln!("Infraternal agent HTTPS link ended ({:?})", error.kind());
            }
        })
}

async fn admit(
    mut socket: WebSocket,
    api: Api,
    address: IpAddr,
    source: OwnedSemaphorePermit,
    permit: OwnedSemaphorePermit,
) -> io::Result<()> {
    let mut nonce = [0; 32];
    rand_bytes(&mut nonce).map_err(io::Error::other)?;
    let challenge = AgentLinkChallenge {
        message_type: "challenge".to_owned(),
        nonce: B64.encode(nonce),
    };
    trace_test_phase("challenge-send", send_text(&mut socket, &challenge).await)?;
    let proof = trace_test_phase(
        "proof-receive",
        tokio::time::timeout(HANDSHAKE, socket.recv())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?
            .map_err(io::Error::other),
    )?;
    let Message::Text(proof) = proof else {
        return Err(io::ErrorKind::PermissionDenied.into());
    };
    if proof.len() > MAX_PROOF_MESSAGE {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let proof: AgentLinkProof = serde_json::from_str(proof.as_str())
        .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
    let authority = trace_test_phase(
        "proof-authenticate",
        authenticate(api.store.clone(), &proof, &nonce).await,
    )?;
    trace_test_phase(
        "ready-send",
        send_text(
            &mut socket,
            &AgentLinkReady {
                message_type: "ready".to_owned(),
            },
        )
        .await,
    )?;
    let link = trace_test_phase(
        "protocol-greeting",
        crate::remote_link::RemoteLink::websocket(socket).await,
    )?;
    drop(source);
    drop(permit);
    trace_test_phase(
        "host-admission",
        api.hosts
            .admit_observed(authority, link, Some(address))
            .await,
    )
}

async fn send_text<T: serde::Serialize>(socket: &mut WebSocket, message: &T) -> io::Result<()> {
    let text = serde_json::to_string(message).map_err(io::Error::other)?;
    tokio::time::timeout(HANDSHAKE, socket.send(Message::Text(text.into())))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(io::Error::other)
}

fn canonical_base64(value: &str) -> io::Result<Vec<u8>> {
    let decoded = B64
        .decode(value)
        .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
    if B64.encode(&decoded) != value {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(decoded)
}

fn verify_signature(certificate: &X509, host_id: Uuid, nonce: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = certificate.public_key() else {
        return false;
    };
    let verifier = match key.id() {
        Id::ED25519 => Verifier::new_without_digest(&key),
        Id::EC
            if key.ec_key().is_ok_and(|key| {
                key.group().curve_name() == Some(openssl::nid::Nid::X9_62_PRIME256V1)
            }) =>
        {
            Verifier::new(MessageDigest::sha256(), &key)
        }
        _ => return false,
    };
    verifier.is_ok_and(|mut verifier| {
        verifier
            .verify_oneshot(signature, &proof_bytes(host_id, nonce))
            .unwrap_or(false)
    })
}

async fn authenticate(
    store: EnrollmentStore,
    proof: &AgentLinkProof,
    nonce: &[u8],
) -> io::Result<AuthorityGuard> {
    if proof.message_type != "proof" || nonce.len() != 32 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let der = canonical_base64(&proof.certificate_der)?;
    if der.len() > 4096 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let certificate = X509::from_der(&der).map_err(|_| io::ErrorKind::PermissionDenied)?;
    if certificate.to_der().map_err(io::Error::other)? != der {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let signature = canonical_base64(&proof.signature)?;
    if signature.len() > 512 || !verify_signature(&certificate, proof.host_id, nonce, &signature) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let digest = certificate
        .digest(MessageDigest::sha256())
        .map_err(io::Error::other)?;
    let fingerprint: [u8; 32] = digest
        .as_ref()
        .try_into()
        .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
    let authority = tokio::time::timeout(HANDSHAKE, AuthorityGuard::admit(store, fingerprint))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    if authority.identity.host != proof.host_id {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkey::{PKey, Private},
        sign::Signer,
        x509::{X509Builder, X509NameBuilder},
    };

    fn signing_certificate() -> (X509, PKey<Private>) {
        let key = PKey::generate_ed25519().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "fixture").unwrap();
        let name = name.build();
        let mut certificate = X509Builder::new().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        certificate.sign(&key, MessageDigest::null()).unwrap();
        (certificate.build(), key)
    }

    #[test]
    fn challenge_signature_requires_the_d168_key_host_and_nonce() {
        let (certificate, key) = signing_certificate();
        let host_id = Uuid::from_u128(1);
        let nonce = [9; 32];
        let mut signer = Signer::new_without_digest(&key).unwrap();
        let signature = signer
            .sign_oneshot_to_vec(&proof_bytes(host_id, &nonce))
            .unwrap();
        assert!(verify_signature(&certificate, host_id, &nonce, &signature));
        assert!(!verify_signature(
            &certificate,
            Uuid::from_u128(2),
            &nonce,
            &signature
        ));
        assert!(!verify_signature(
            &certificate,
            host_id,
            &[8; 32],
            &signature
        ));
    }
}
