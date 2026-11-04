//! Runs a mesh SSH shell in the person's real login and bridges it to the SSH channel [D235, D240], #221.
//!
//! The shell is opened by `infraternal_agent::daemon::open_mesh_ssh_shell`,
//! the same ordered path a browser terminal takes (real login, login access
//! check, fencing), so SSH never starts a second kind of shell. One task per
//! channel then moves bytes between the shim's framed socket and the SSH
//! attachment.
//!
//! Invariants:
//! - Output is written one frame at a time and the shim is not read while a
//!   write is pending, so a slow SSH client backpressures the PTY instead of
//!   growing a queue. Input and control (resize, signals) keep flowing while
//!   output is blocked, as `contracts/mesh-ssh.md` requires.
//! - Dropping the attachment ends this task and closes the shim link; the
//!   shim session itself keeps its normal lifetime.
//! - Slice 1 opens shells only. Commands (`ssh host cmd`) are refused until
//!   the runtime can run one inside the same real login.

use crate::{
    mesh_admission::Refusal,
    mesh_authority::SessionRuntime,
    mesh_flow::PACKET_BYTES,
    mesh_login::{Attachment, Control, Exit, SessionKind, Terminal, TerminalSize},
};
use infraternal_agent::sessions::{self, Reader, Session};
use infraternal_shim::frame::Frame;
use std::path::PathBuf;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::{mpsc, oneshot},
};

/// The production runtime: shells in the infraternal agent's session state.
pub struct ShimRuntime {
    state: PathBuf,
}

impl ShimRuntime {
    #[must_use]
    pub fn new(state: PathBuf) -> Self {
        Self { state }
    }
}

impl SessionRuntime for ShimRuntime {
    async fn open(
        &self,
        person: &str,
        account: &str,
        kind: SessionKind,
        terminal: Option<Terminal>,
    ) -> Result<Attachment, Refusal> {
        if !matches!(kind, SessionKind::Shell) {
            return Err(Refusal::LoginAccess);
        }
        let person = uuid::Uuid::parse_str(person).map_err(|_| Refusal::InvalidClaims)?;
        let size = terminal.map_or_else(TerminalSize::default, |terminal| terminal.size);
        // Every runtime failure reads as a refusal to the SSH peer; the
        // adapter never tells an unauthenticated peer why.
        let session = infraternal_agent::daemon::open_mesh_ssh_shell(
            &self.state,
            person,
            account,
            size.columns,
            size.rows,
        )
        .await
        .map_err(|_| Refusal::LoginAccess)?;
        Ok(bridge(session, size))
    }
}

fn bridge(session: Session, size: TerminalSize) -> Attachment {
    let (input, from_client) = tokio::io::duplex(PACKET_BYTES);
    let (to_client, output) = tokio::io::duplex(PACKET_BYTES);
    let (control, controls) = mpsc::channel(8);
    let (exit, exited) = oneshot::channel();
    tokio::spawn(async move {
        let status = pump(session, size, from_client, to_client, controls).await;
        let _ = exit.send(Exit::Status(status.unwrap_or(255)));
    });
    Attachment {
        input: Box::pin(input),
        output: Box::pin(output),
        errors: None,
        control,
        exit: exited,
    }
}

/// Move bytes until the shell exits or either side goes away. Returns the
/// shell's exit status when the shim reported one.
async fn pump(
    session: Session,
    size: TerminalSize,
    mut from_client: DuplexStream,
    mut to_client: DuplexStream,
    mut controls: mpsc::Receiver<Control>,
) -> Option<u32> {
    let mut peer = session.peer;
    let start = [
        Frame::Attach(0),
        resize(size),
        // From the start of this new session: the first prompt included.
        Frame::ReadFrom(0),
    ];
    for frame in &start {
        sessions::send(&mut peer, frame).await.ok()?;
    }
    let mut reader = Reader::default();
    let mut input = vec![0; PACKET_BYTES];
    let mut pending: Option<(Vec<u8>, usize)> = None;
    let mut input_open = true;
    loop {
        tokio::select! {
            // Reading a frame is cancellation safe (`Reader` keeps partial
            // frames), so losing a race to input or control loses no bytes.
            frame = reader.read(&mut peer), if pending.is_none() => match frame.ok()? {
                Frame::Output(_, bytes)
                | Frame::Snapshot(_, bytes)
                | Frame::SnapshotWithFlags(_, _, bytes) => {
                    if !bytes.is_empty() {
                        pending = Some((bytes, 0));
                    }
                }
                Frame::Exited(status, _) => {
                    let _ = sessions::send(&mut peer, &Frame::ExitAck).await;
                    // The shim reports a wait status; SSH carries 0-255.
                    return Some(u32::from(u8::try_from(status & 0xff).unwrap_or(255)));
                }
                Frame::Error(..) => return None,
                _ => {}
            },
            written = async {
                let (bytes, offset) = pending.as_ref().map_or((&[][..], 0), |(b, o)| (b.as_slice(), *o));
                to_client.write(&bytes[offset..]).await
            }, if pending.is_some() => {
                let written = written.ok()?;
                if written == 0 {
                    return None;
                }
                if let Some((bytes, offset)) = pending.as_mut() {
                    *offset += written;
                    if *offset >= bytes.len() {
                        pending = None;
                    }
                }
            }
            read = from_client.read(&mut input), if input_open => match read.ok()? {
                // EOF from the client: keep showing output until the shell exits.
                0 => input_open = false,
                count => sessions::send(&mut peer, &Frame::Input(input[..count].to_vec())).await.ok()?,
            },
            control = controls.recv() => {
                let frame = match control? {
                    Control::Resize(size) => resize(size),
                    Control::Signal(signal) => match signal_number(&signal) {
                        Some(number) => Frame::Signal(number),
                        None => continue,
                    },
                };
                sessions::send(&mut peer, &frame).await.ok()?;
            }
        }
    }
}

fn resize(size: TerminalSize) -> Frame {
    Frame::Resize {
        cols: size.columns,
        rows: size.rows,
        px_w: size.width_pixels,
        px_h: size.height_pixels,
    }
}

/// Linux signal numbers for the names SSH carries (RFC 4254 section 6.10).
fn signal_number(signal: &russh::Sig) -> Option<u8> {
    Some(match signal {
        russh::Sig::HUP => 1,
        russh::Sig::INT => 2,
        russh::Sig::QUIT => 3,
        russh::Sig::ILL => 4,
        russh::Sig::ABRT => 6,
        russh::Sig::FPE => 8,
        russh::Sig::KILL => 9,
        russh::Sig::USR1 => 10,
        russh::Sig::SEGV => 11,
        russh::Sig::PIPE => 13,
        russh::Sig::ALRM => 14,
        russh::Sig::TERM => 15,
        russh::Sig::Custom(_) => return None,
    })
}

#[cfg(test)]
#[path = "mesh_runtime_tests.rs"]
mod tests;
