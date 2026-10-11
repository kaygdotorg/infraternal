//! Schedules half-life renewal over the authenticated actor's control stream without replacing terminal streams [133][168], #78.

use crate::{
    ca::CaKeySource,
    embedded::{AgentError, EmbeddedAgent},
    remote_enrollment::RemoteEnrollment,
    remote_guard::AuthorityGuard,
};
use infraternal_agent::remote_renewal::{CertificateUpdate, decode_proof};
use std::{
    io,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {}

/// Only one exchange per admitted host; global admission bounds concurrent signer work.
static SIGNING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

pub(crate) async fn run(
    authority: &AuthorityGuard,
    actor: &EmbeddedAgent,
    source: Arc<dyn CaKeySource>,
) {
    let mut deadline = authority.renewal_deadline();
    let mut locked = source.subscribe_locked();
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => {},
            changed = async { match &mut locked {
                Some(receiver) => receiver.changed().await,
                None => std::future::pending().await,
            }} => {
                if changed.is_err() { locked = None; }
                else if locked.as_mut().is_some_and(|receiver| !*receiver.borrow_and_update()) {
                    deadline = authority.renewal_deadline().max(tokio::time::Instant::now());
                }
                continue;
            },
        }
        if !authority.permits() {
            return;
        }
        if source.load().is_err() {
            deadline = tokio::time::Instant::now() + Duration::from_secs(3600);
            continue;
        }
        match exchange(authority, actor, source.clone()).await {
            Ok(()) => {
                deadline = authority.renewal_deadline();
            }
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                // A legacy peer remains subject to its admitted expiry. Reconnecting
                // with a capability replaces this waiter; there is no retry timer.
                authority.cancelled().await;
                return;
            }
            Err(_) => {
                // Failed/busy exchanges spread retries, so synchronized half-lives
                // across 1,000 hosts cannot strand all but eight for an hour.
                let jitter = u64::from(uuid::Uuid::new_v4().as_bytes()[0]) % 60;
                deadline = tokio::time::Instant::now() + Duration::from_secs(5 + jitter);
            }
        }
    }
}

pub(crate) async fn exchange(
    authority: &AuthorityGuard,
    actor: &EmbeddedAgent,
    source: Arc<dyn CaKeySource>,
) -> io::Result<()> {
    let _permit = SIGNING.try_acquire().map_err(|_| denied())?;
    authority.admit_operation().await?;
    // Avoid asking hosts for proof while the CA is locked. Signing still repeats
    // this source check after the proof; role/unlock changes never bypass policy.
    source.load().map_err(|_| denied())?;
    let proof = actor
        .control_call("transport.csr", b"{}".to_vec())
        .await
        .map_err(control_error)?;
    let proof = decode_proof(&proof)?;
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| denied())?
            .as_secs(),
    )
    .map_err(|_| denied())?;
    let predecessor = authority.predecessor();
    let signed = RemoteEnrollment::new(source, authority.store())
        .renew(&predecessor, &proof.csr_der, now)
        .await
        .map_err(|_| denied())?;
    let update = serde_json::to_vec(&CertificateUpdate {
        certificate_der: signed.der,
    })
    .map_err(|_| denied())?;
    let ack = actor
        .control_call("transport.certificate", update)
        .await
        .map_err(|_| denied())?;
    serde_json::from_slice::<Ack>(&ack).map_err(|_| denied())?;
    // Commit precedes delivery, host fsync precedes Ack, Ack precedes authority
    // extension. A dropped connection keeps the predecessor's original cap.
    authority.acknowledge(signed.record.fingerprint).await
}
fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}

fn control_error(error: AgentError) -> io::Error {
    if error == AgentError::Unsupported {
        io::ErrorKind::Unsupported.into()
    } else {
        denied()
    }
}
