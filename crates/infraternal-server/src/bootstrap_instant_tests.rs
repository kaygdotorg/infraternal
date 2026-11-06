//! Exercises a real interactive early shell through the original terminal actor before/after admitted handover (D255).

use super::*;
use crate::embedded::AttachmentHandle;
use infraternal_protocol::{Frame, encode_muxed_frame_into};

pub(super) struct EarlyTerminal {
    handle: AttachmentHandle,
    output: tokio::sync::mpsc::Receiver<TerminalOutput>,
    input: u64,
    confirmed: u64,
    received: Vec<u8>,
}
impl EarlyTerminal {
    /// Attach the early session and prove input works before handover.
    pub(super) async fn attach(actor: &EmbeddedAgent, session: Uuid, started: Instant) -> Self {
        let (handle, output) = actor
            .attach(*session.as_bytes(), 0, 0, 2)
            .await
            .unwrap()
            .split();
        let mut terminal = Self {
            handle,
            output,
            input: 0,
            confirmed: 0,
            received: Vec::new(),
        };
        terminal.send(&Frame::Credit { bytes: 65536 }).await;
        tokio::time::timeout(Duration::from_secs(30), async {
            while !terminal
                .received
                .windows(2)
                .any(|bytes| matches!(bytes, b"$ " | b"# "))
            {
                terminal.receive().await;
            }
        })
        .await
        .unwrap();
        println!(
            "METRIC addhost_instant time_to_prompt_ms={:.3}",
            started.elapsed().as_secs_f64() * 1000.0
        );
        terminal
            .command(b"printf 'BEFORE_%s\\n' HANDOVER\n", b"BEFORE_HANDOVER\r\n")
            .await;
        println!(
            "PROOF early_prompt=interactive input_before=confirmed session={session} writer={}",
            terminal.handle.stream_id()
        );
        terminal
    }
    /// A new terminal on an existing host answers input, then exits (#189).
    pub(super) async fn open_on_named_host(actor: &EmbeddedAgent, session: Uuid) {
        // Terminal streams are even; 2 belongs to the early session above.
        let (handle, output) = actor
            .attach(*session.as_bytes(), 0, 0, 4)
            .await
            .unwrap()
            .split();
        let mut terminal = Self {
            handle,
            output,
            input: 0,
            confirmed: 0,
            received: Vec::new(),
        };
        terminal.send(&Frame::Credit { bytes: 65536 }).await;
        terminal
            .command(b"printf 'OPENED_%s\\n' TERMINAL\n", b"OPENED_TERMINAL\r\n")
            .await;
        terminal
            .send(&Frame::Input {
                in_seq: terminal.input,
                bytes: b"exit\n",
            })
            .await;
        println!(
            "PROOF open_terminal=interactive session={session} input_acked_bytes={}",
            terminal.confirmed
        );
    }
    /// Send one framed terminal message on the original attachment.
    async fn send(&self, frame: &Frame<'_>) {
        let mut wire = Vec::new();
        encode_muxed_frame_into(1, frame, &mut wire).unwrap();
        self.handle
            .send_frame(bytes::Bytes::from(wire))
            .await
            .unwrap();
    }
    /// Record bounded output and input acknowledgements from that attachment.
    async fn receive(&mut self) {
        match self.output.recv().await.unwrap() {
            TerminalOutput::Output { bytes, .. } | TerminalOutput::Snapshot { bytes, .. } => {
                assert!(self.received.len() + bytes.len() <= 256 * 1024);
                self.received.extend_from_slice(&bytes);
            }
            TerminalOutput::Ack { in_seq_acked } => {
                self.confirmed = self.confirmed.max(in_seq_acked);
            }
            TerminalOutput::Event { .. }
            | TerminalOutput::Reconnecting
            | TerminalOutput::LinkDoubt
            | TerminalOutput::Recovered => {}
            TerminalOutput::Closed { .. } | TerminalOutput::RouteExpired => {
                panic!("the original early session closed or expired during handover")
            }
        }
    }
    /// Wait for both command acknowledgement and its output marker.
    async fn command(&mut self, command: &[u8], marker: &[u8]) {
        self.received.clear();
        self.send(&Frame::Input {
            in_seq: self.input,
            bytes: command,
        })
        .await;
        self.input += command.len() as u64;
        tokio::time::timeout(Duration::from_secs(30), async {
            while self.confirmed < self.input
                || !self
                    .received
                    .windows(marker.len())
                    .any(|bytes| bytes == marker)
            {
                self.receive().await;
            }
        })
        .await
        .unwrap();
    }
    /// Prove the same attachment accepts input after handover.
    pub(super) async fn after_handover(mut self) {
        self.command(b"printf 'AFTER_%s\\n' HANDOVER\n", b"AFTER_HANDOVER\r\n")
            .await;
        assert_eq!(self.handle.stream_id(), 2);
        self.send(&Frame::Input {
            in_seq: self.input,
            bytes: b"exit\n",
        })
        .await;
        println!(
            "PROOF same_session=true same_writer=true input_after=confirmed output_before_after=present input_acked_bytes={}",
            self.confirmed
        );
    }
}
