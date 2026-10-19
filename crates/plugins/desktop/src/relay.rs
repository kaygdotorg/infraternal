//! Owns one admitted capture lane while the server-held session outlives its viewers [D104,D208,D232].
use crate::{
    datagram::Reassembler,
    delivery::receive_datagram,
    session::{ASSEMBLY_TIMEOUT, HostCommand, Session},
};
use infraternal_plugin_api::streams::{NodeHost, WireLane};
use infraternal_protocol::{
    Frame, decode_frame,
    desktop::{Delivery, Input, Message},
    encode_frame_into,
};
use std::{sync::Arc, time::Instant};
use tokio::sync::mpsc;

// Retiring this lease on cancellation seals partial reliable writes and withdraws
// its datagram queue. It never closes the authenticated connection or session.
struct Lease(Arc<dyn WireLane>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.retire();
    }
}

/// Run only after existing host admission and capture action have succeeded.
/// Returns on peer loss; the registry retains the session for a replacement lane.
/// Input is never replayed: commands queued for this lease are consumed or discarded.
/// # Errors
/// Reports malformed capture, ended authority or unavailable transport without payloads.
pub async fn run(
    session: Arc<Session>,
    host: Arc<dyn NodeHost>,
    lane: Arc<dyn WireLane>,
    mode: Delivery,
    commands: &mut mpsc::Receiver<HostCommand>,
) -> Result<(), crate::session::Error> {
    run_inner(session, host, lane, mode, commands)
        .await
        .map_err(|()| crate::session::Error::Unavailable)
}

async fn run_inner(
    session: Arc<Session>,
    host: Arc<dyn NodeHost>,
    lane: Arc<dyn WireLane>,
    mode: Delivery,
    commands: &mut mpsc::Receiver<HostCommand>,
) -> Result<(), ()> {
    let lease = Lease(lane);
    let mut stopped = session.stopped();
    let mut assembly = Reassembler::new(session.id());
    let datagrams = match mode {
        Delivery::Reliable => None,
        Delivery::Datagram => Some(lease.0.datagrams().ok_or(())?),
    };
    let mut wire = Vec::new();
    while commands.try_recv().is_ok() {}
    // Clear native held keys before accepting any current controller's input.
    // A reconnect cannot inherit the old connection's partially delivered input.
    send(
        &session,
        host.as_ref(),
        lease.0.as_ref(),
        HostCommand::ReleaseInput,
        &mut wire,
    )
    .await?;
    send(
        &session,
        host.as_ref(),
        lease.0.as_ref(),
        HostCommand::Keyframe,
        &mut wire,
    )
    .await?;
    if let Some(control) = session.control_command().map_err(|_| ())? {
        send(
            &session,
            host.as_ref(),
            lease.0.as_ref(),
            control,
            &mut wire,
        )
        .await?;
    }
    loop {
        if *stopped.borrow() || !host.permits() {
            return Err(());
        }
        tokio::select! {
            biased;
            _ = stopped.changed() => {
                let _ = send(&session, host.as_ref(), lease.0.as_ref(), HostCommand::ReleaseInput, &mut wire).await;
                return Ok(());
            },
            command = commands.recv() => {
                let Some(command) = command else { return Ok(()); };
                send(&session, host.as_ref(), lease.0.as_ref(), command, &mut wire).await?;
            },
            packet = async {
                match &datagrams { Some(lane) => lane.receive().await, None => lease.0.receive().await }
            } => {
                let packet = packet?;
                let frame = match mode {
                    Delivery::Datagram => receive_datagram(&mut assembly, &packet, Instant::now()).map_err(|_| ())?,
                    Delivery::Reliable => {
                        let decoded = decode_frame(&packet).map_err(|_| ())?;
                        if decoded.wire_len != packet.len() { return Err(()); }
                        let Frame::Desktop(Message::Video { sequence, capture_ns, keyframe, bytes }) = decoded.frame else { return Err(()); };
                        let offset = packet.len() - bytes.len();
                        Some(crate::session::Video { sequence, capture_ns, keyframe, bytes: packet.slice(offset..) })
                    },
                };
                if let Some(frame) = frame {
                    crate::measurement::frame("relay_receive", &frame);
                    session.publish(frame).map_err(|_| ())?;
                }
                if assembly.take_repair() {
                    send(&session, host.as_ref(), lease.0.as_ref(), HostCommand::Keyframe, &mut wire).await?;
                }
            },
            // Only incomplete assembly owns a timer. Idle sessions do no timer work.
            () = async {
                match assembly.deadline() {
                    Some(deadline) => tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await,
                    None => std::future::pending().await,
                }
            } => {
                assembly.expire(Instant::now());
                if assembly.take_repair() {
                    send(&session, host.as_ref(), lease.0.as_ref(), HostCommand::Keyframe, &mut wire).await?;
                }
            },
        }
    }
}

async fn send(
    session: &Session,
    host: &dyn NodeHost,
    lane: &dyn WireLane,
    command: HostCommand,
    wire: &mut Vec<u8>,
) -> Result<(), ()> {
    if !session.command_allowed(command).map_err(|_| ())? {
        return Ok(());
    }
    let message = match command {
        HostCommand::Keyframe => Message::Repair { last_sequence: 0 },
        HostCommand::ReleaseInput => Message::Input(Input::Control { active: false }),
        HostCommand::Control { .. } => Message::Input(Input::Control { active: true }),
        HostCommand::Input { input, .. } => Message::Input(input),
        HostCommand::Size {
            width,
            height,
            density_milli,
            ..
        } => Message::Size {
            width,
            height,
            density_milli,
        },
    };
    encode_frame_into(&Frame::Desktop(message), wire).map_err(|_| ())?;
    // Admission checks and its cancellation signal guard the actual write, not
    // just queue insertion. The bounded deadline also prevents stale control.
    let mut forwarded = false;
    session
        .command_authorized(
            command,
            Box::pin(host.authorized(Box::pin(async {
                if !session.command_allowed(command).map_err(|_| ())? {
                    return Ok(());
                }
                if matches!(command, HostCommand::Input { .. }) {
                    crate::measurement::control(
                        "server_input_write_begin",
                        crate::protocol::Kind::Input,
                    );
                }
                tokio::time::timeout(ASSEMBLY_TIMEOUT, lane.send(wire))
                    .await
                    .map_err(|_| ())??;
                if matches!(command, HostCommand::Input { .. }) {
                    crate::measurement::control(
                        "server_input_write_end",
                        crate::protocol::Kind::Input,
                    );
                }
                forwarded = true;
                Ok(())
            }))),
        )
        .await
        .map_err(|_| ())?;
    if forwarded {
        session.checkpoint_size(command).map_err(|_| ())?;
    }
    Ok(())
}
