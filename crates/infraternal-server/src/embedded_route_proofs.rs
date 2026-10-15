//! Batches host and shim-fenced proofs on the existing tick without waking payload consumers [81,265], #199.

use super::{
    AgentConnection, AsyncWriteExt, AttachmentState, Command, Duration, Frame, HashMap, Liveness,
    Peer, PendingCall, TerminalOutput, encode_muxed_frame_into, process_command, write_frame,
};

pub(super) async fn tick(
    connection: &mut AgentConnection,
    attachments: &mut HashMap<u64, AttachmentState>,
    routes: &mut HashMap<u32, u64>,
    pending: &mut HashMap<u32, PendingCall>,
    available: bool,
    remote_probes: &mut std::collections::VecDeque<u64>,
    mut control: Option<&mut Liveness>,
) -> bool {
    let local = matches!(connection.peer, Peer::Local { .. });
    // Remote peers retain their owned control writer and queue admission.
    if !local && let Some(control) = control.as_deref_mut() {
        let (nonce, sent_us) = control.ping();
        if !write_frame(connection, 0, &Frame::Ping { nonce, sent_us }).await {
            return false;
        }
    }
    let expired: Vec<u64> = attachments
        .iter()
        .filter_map(|(&id, a)| {
            (!a.awaiting_ack
                && !a.proof_rebind_pending
                && a.route.as_ref().is_some_and(Liveness::expired))
            .then_some(id)
        })
        .collect();
    for id in expired {
        let Some(attachment) = attachments.get_mut(&id) else {
            continue;
        };
        // Stop probing while the authenticated consumer owns the transition.
        // A full queue retires this attachment instead of losing readiness ordering.
        attachment.proof_rebind_pending = true;
        let notice = if available {
            TerminalOutput::RouteExpired
        } else {
            TerminalOutput::Reconnecting
        };
        if attachment.output.try_send(notice).is_err()
            && !process_command(
                Command::Detach { attachment_id: id },
                connection,
                attachments,
                routes,
                pending,
            )
            .await
        {
            return false;
        }
    }

    // Reuse the connection's buffer between ticks. The batch contains only
    // bounded proof headers, never terminal payloads or buffered user input.
    let mut batch = std::mem::take(&mut connection.encode);
    batch.clear();
    let mut encoded = Vec::with_capacity(24);
    // Local peers have no owned control writer. Stamp their host proof after
    // expiry work, then send it first in the same write as the ready routes.
    let mut valid =
        !local || control.is_none_or(|lease| append_probe(&mut batch, &mut encoded, 0, lease));
    remote_probes.retain(|id| {
        attachments
            .get(id)
            .is_some_and(|a| !a.awaiting_ack && !a.proof_rebind_pending && a.route.is_some())
    });
    let fill_remote_queue = remote_probes.is_empty();
    for (&id, attachment) in attachments.iter_mut() {
        if !valid {
            break;
        }
        if attachment.awaiting_ack || attachment.proof_rebind_pending {
            continue;
        }
        let Some(route) = &mut attachment.route else {
            continue;
        };
        if !local {
            if fill_remote_queue {
                remote_probes.push_back(id);
            }
            continue;
        }
        valid = append_probe(&mut batch, &mut encoded, attachment.stream_id, route);
    }
    if valid && !batch.is_empty() {
        valid = match &mut connection.peer {
            Peer::Local { writer, .. } => matches!(
                tokio::time::timeout(Duration::from_secs(1), writer.write_all(&batch)).await,
                Ok(Ok(()))
            ),
            #[cfg(feature = "remote")]
            Peer::Remote(_) => true,
        };
    }
    // Failed writes also restore the reusable buffer for ordinary teardown.
    batch.clear();
    connection.encode = batch;
    valid
}

/// Only header bytes enter this batch; no await separates issuance and encoding.
fn append_probe(
    batch: &mut Vec<u8>,
    encoded: &mut Vec<u8>,
    stream: u32,
    lease: &mut Liveness,
) -> bool {
    let (nonce, sent_us) = lease.ping();
    if encode_muxed_frame_into(stream, &Frame::Ping { nonce, sent_us }, encoded).is_err() {
        return false;
    }
    batch.extend_from_slice(encoded);
    true
}

/// A queued remote proof owns at most one write before the actor polls replies again.
pub(super) async fn probe(
    connection: &mut AgentConnection,
    attachments: &mut HashMap<u64, AttachmentState>,
    id: u64,
) -> bool {
    let Some(attachment) = attachments.get_mut(&id) else {
        return true;
    };
    if attachment.awaiting_ack || attachment.proof_rebind_pending {
        return true;
    }
    let Some(route) = &mut attachment.route else {
        return true;
    };
    let (nonce, sent_us) = route.ping();
    write_frame(
        connection,
        attachment.stream_id,
        &Frame::Ping { nonce, sent_us },
    )
    .await
}
