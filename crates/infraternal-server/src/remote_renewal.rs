//! Schedules half-life renewal over the authenticated actor's control stream without replacing terminal streams [133][168], #78.

use crate::{
    ca::CaKeySource,
    embedded::{AgentError, EmbeddedAgent},
    remote_enrollment::RemoteEnrollment,
    remote_guard::AuthorityGuard,
};
use infraternal_agent::remote_renewal::{CertificateUpdate, decode_proof};
use infraternal_plugin_remote::identity_rotation::{CandidateCertificate, Proof};
use std::{
    io,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {}

/// The agent's empty reply to a rotation acknowledgment.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationAck {}

/// What happens to the connection after a rotation step: done, or reconnect so the next step uses the new state.
enum RotationResult {
    Complete,
    Reconnect,
}

/// Only one exchange per admitted host; global admission bounds concurrent signer work.
static SIGNING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

pub(crate) async fn run(
    authority: &AuthorityGuard,
    actor: &EmbeddedAgent,
    source: Arc<dyn CaKeySource>,
    identity_rotation: bool,
) {
    let mut deadline = authority.renewal_deadline();
    let mut locked = source.subscribe_locked();
    let host = authority.host_id();
    let rotation = identity_rotation
        .then(|| crate::identity_rotation::Service::new(authority.store(), source.clone()));
    let mut rotation_retry = tokio::time::Instant::now();
    loop {
        if !authority.permits() {
            return;
        }
        if let Some(rotation) = &rotation
            && rotation_retry <= tokio::time::Instant::now()
        {
            match rotation.next_action(host, authority.predecessor()).await {
                Ok(Some(action)) => {
                    match exchange_rotation(authority, actor, rotation, action).await {
                        Ok(RotationResult::Complete) => {
                            rotation_retry = tokio::time::Instant::now();
                        }
                        Ok(RotationResult::Reconnect) => {
                            let _ = actor.retire_connection().await;
                            return;
                        }
                        Err(_) => rotation_retry = retry_deadline(),
                    }
                }
                Ok(None) => {
                    rotation_retry = tokio::time::Instant::now() + Duration::from_secs(3600);
                }
                Err(_) => rotation_retry = retry_deadline(),
            }
        }
        tokio::select! {
            biased;
            () = authority.cancelled() => return,
            () = async {
                if let Some(rotation) = &rotation {
                    let delay = rotation
                        .next_delay(host)
                        .await
                        .unwrap_or(Duration::from_secs(3600))
                        .min(Duration::from_hours(8_760));
                    let due = tokio::time::Instant::now() + delay;
                    tokio::time::sleep_until(due.max(rotation_retry)).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {},
            () = tokio::time::sleep_until(deadline) => {},
            changed = async { match &mut locked {
                Some(receiver) => receiver.changed().await,
                None => std::future::pending().await,
            }} => {
                if changed.is_err() { locked = None; }
                else if locked.as_mut().is_some_and(|receiver| !*receiver.borrow_and_update()) {
                    deadline = authority.renewal_deadline().max(tokio::time::Instant::now());
                    rotation_retry = tokio::time::Instant::now();
                }
                continue;
            },
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

/// When to try a failed exchange again: 5 s plus up to a minute of jitter, so hosts do not retry together.
fn retry_deadline() -> tokio::time::Instant {
    let jitter = u64::from(Uuid::new_v4().as_bytes()[0]) % 60;
    tokio::time::Instant::now() + Duration::from_secs(5 + jitter)
}

/// Run one rotation step with the agent: send the challenge or the candidate certificate (then reconnect), or the
/// acknowledgment (then done).
async fn exchange_rotation(
    authority: &AuthorityGuard,
    actor: &EmbeddedAgent,
    service: &crate::identity_rotation::Service,
    action: crate::identity_rotation::Action,
) -> io::Result<RotationResult> {
    match action {
        crate::identity_rotation::Action::Challenge(challenge) => {
            let request = serde_json::to_vec(&challenge).map_err(|_| denied())?;
            let proof = actor
                .control_call("transport.csr.rotate", request)
                .await
                .map_err(control_error)?;
            if proof.len() > infraternal_plugin_api::channel::MAX_CONTROL_JSON {
                return Err(denied());
            }
            let proof: Proof = serde_json::from_slice(&proof).map_err(|_| denied())?;
            let der = service
                .accept_proof(authority.host_id(), authority.predecessor(), proof)
                .await?;
            let update = serde_json::to_vec(&CandidateCertificate {
                operation_id: challenge.operation_id,
                sequence: challenge.sequence,
                certificate_der: der,
            })
            .map_err(|_| denied())?;
            let acknowledgment = actor
                .control_call("transport.identity.rotate.certificate", update)
                .await
                .map_err(control_error)?;
            serde_json::from_slice::<RotationAck>(&acknowledgment).map_err(|_| denied())?;
            Ok(RotationResult::Reconnect)
        }
        crate::identity_rotation::Action::Certificate(update) => {
            let request = serde_json::to_vec(&update).map_err(|_| denied())?;
            let acknowledgment = actor
                .control_call("transport.identity.rotate.certificate", request)
                .await
                .map_err(control_error)?;
            serde_json::from_slice::<RotationAck>(&acknowledgment).map_err(|_| denied())?;
            Ok(RotationResult::Reconnect)
        }
        crate::identity_rotation::Action::Acknowledgment(acknowledgment) => {
            let request = serde_json::to_vec(&acknowledgment).map_err(|_| denied())?;
            let response = actor
                .control_call("transport.identity.rotate.ack", request)
                .await
                .map_err(control_error)?;
            serde_json::from_slice::<RotationAck>(&response).map_err(|_| denied())?;
            service
                .acknowledge(authority.host_id(), authority.predecessor(), acknowledgment)
                .await?;
            Ok(RotationResult::Complete)
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
