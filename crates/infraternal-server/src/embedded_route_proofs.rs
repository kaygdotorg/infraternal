//! Batches shim-fenced browser proofs on the existing host tick without waking payload consumers [81,265], #199.

use super::{
    AgentConnection, AsyncWriteExt, AttachmentState, Command, Duration, Frame, HashMap, Liveness,
    Peer, PendingCall, TerminalOutput, encode_muxed_frame_into, process_command, write_frame,
};

/// One host tick of route-liveness proofs. First, attachments whose route proof expired are told so (`RouteExpired` when a route is available, otherwise `Reconnecting`); if their output queue is full they are detached instead. Then, for a local peer, one Ping per eligible attachment is written in a single batch; for a remote peer, eligible attachments are only queued for [`probe`], one write each. Attachments waiting for an acknowledgement or a rebind are skipped. Returns `false` if the connection can no longer be used (a detach failed, a frame could not be encoded, or the batch write failed or took over a second).
pub(super) async fn tick(
    connection: &mut AgentConnection,
    attachments: &mut HashMap<u64, AttachmentState>,
    routes: &mut HashMap<u32, u64>,
    pending: &mut HashMap<u32, PendingCall>,
    available: bool,
    remote_probes: &mut std::collections::VecDeque<u64>,
) -> bool {
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
    let local = matches!(connection.peer, Peer::Local { .. });
    let mut valid = true;
    remote_probes.retain(|id| {
        attachments
            .get(id)
            .is_some_and(|a| !a.awaiting_ack && !a.proof_rebind_pending && a.route.is_some())
    });
    let fill_remote_queue = remote_probes.is_empty();
    for (&id, attachment) in attachments.iter_mut() {
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
        let (nonce, sent_us) = route.ping();
        let frame = Frame::Ping { nonce, sent_us };
        if local {
            if encode_muxed_frame_into(attachment.stream_id, &frame, &mut encoded).is_err() {
                valid = false;
                break;
            }
            batch.extend_from_slice(&encoded);
        }
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
