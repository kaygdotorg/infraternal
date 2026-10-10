//! Checks durable host Ack authority and unchanged terminal routing over real admitted TLS connections, #78.
use super::*;
use crate::{
    embedded::{AttachmentHandle, TerminalOutput},
    remote_guard::AuthorityGuard,
};
use infraternal_agent::{
    remote_renewal::{CertificatePublisher, RenewalIdentity, decode_certificate},
    remote_tls,
    remote_tls::{Connection, Identity},
    transport::{Receive, Transmit},
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc;

struct Publication(AtomicUsize, bool);
impl CertificatePublisher for Publication {
    fn publish(&self, _: &X509) -> std::io::Result<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        if self.1 {
            Ok(())
        } else {
            Err(std::io::ErrorKind::PermissionDenied.into())
        }
    }
}
struct Peer {
    connection: Connection,
    transmit: Transmit,
    receive: Receive,
}
impl Peer {
    async fn connect(fixture: &Fixture, identity: &Identity) -> Self {
        let config =
            remote_tls::client_config(identity, std::slice::from_ref(&fixture.root)).unwrap();
        let connection = remote_tls::dial(
            fixture.listeners.as_ref().unwrap().local_addr().unwrap(),
            "localhost",
            &config,
        )
        .await
        .unwrap();
        let mut peer = Self {
            connection,
            transmit: Transmit::default(),
            receive: Receive::default(),
        };
        peer.transmit
            .send(
                &peer.connection.channel,
                0,
                &Frame::Hello {
                    version: 1,
                    caps: 1 << 2,
                    client_info: "renewal Ack regression",
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            peer.receive
                .next(&peer.connection.channel)
                .await
                .unwrap()
                .frame,
            Frame::Hello { .. }
        ));
        peer
    }
    async fn terminal(
        &mut self,
        fixture: &Fixture,
        host: uuid::Uuid,
    ) -> (
        AttachmentHandle,
        mpsc::Receiver<TerminalOutput>,
        AuthorityGuard,
    ) {
        let hosts = &fixture.listeners.as_ref().unwrap().diagnostic_hosts;
        let actor = hosts.actor(host).await.unwrap();
        let guard = hosts.admission_for_test(host).await.unwrap();
        let session = uuid::Uuid::new_v4();
        let terminal = actor.attach(*session.as_bytes(), 0, 0, 2).await.unwrap();
        let attached = self.receive.next(&self.connection.channel).await.unwrap();
        assert!(
            matches!(attached.frame, Frame::AttachTerm { session_id, .. } if session_id == session.as_bytes())
        );
        assert_eq!(attached.stream_id, 2);
        self.transmit
            .send(&self.connection.channel, 2, &Frame::Ack { in_seq_acked: 0 })
            .await
            .unwrap();
        let (input, mut output) = terminal.split();
        assert!(matches!(
            output.recv().await.unwrap(),
            TerminalOutput::Ack { in_seq_acked: 0 }
        ));
        let mut credit = Vec::new();
        encode_muxed_frame_into(1, &Frame::Credit { bytes: 1024 }, &mut credit).unwrap();
        input.send_frame(credit.into()).await.unwrap();
        assert!(matches!(
            self.receive
                .next(&self.connection.channel)
                .await
                .unwrap()
                .frame,
            Frame::Credit { bytes: 1024 }
        ));
        self.transmit
            .send(
                &self.connection.channel,
                2,
                &Frame::Output {
                    out_seq: 0,
                    bytes: b"before",
                },
            )
            .await
            .unwrap();
        assert!(
            matches!(output.recv().await.unwrap(), TerminalOutput::Output { out_seq:0, bytes } if bytes.as_ref()==b"before")
        );
        (input, output, guard)
    }
    async fn control_result(&mut self, call_id: u32, ok: bool, json: &[u8]) -> usize {
        let frame = Frame::Result { call_id, ok, json };
        let bytes = control_bytes(&frame);
        self.transmit
            .send(&self.connection.channel, 0, &frame)
            .await
            .unwrap();
        bytes
    }
    async fn exchange(
        &mut self,
        fixture: &Fixture,
        identity: &Identity,
        guard: &AuthorityGuard,
        durable: bool,
    ) {
        let predecessor = guard.predecessor();
        let deadline = guard.renewal_deadline();
        let sink = Arc::new(Publication(AtomicUsize::new(0), durable));
        let renewal =
            RenewalIdentity::new(identity, std::slice::from_ref(&fixture.root), sink.clone());
        let requested = tokio::time::timeout(
            Duration::from_secs(2),
            self.receive.next(&self.connection.channel),
        )
        .await
        .unwrap()
        .unwrap();
        let mut wire_bytes = control_bytes(&requested.frame);
        let Frame::Call {
            call_id,
            action_id: "transport.csr",
            input_json,
        } = requested.frame
        else {
            panic!("expected bounded CSR request")
        };
        let proof = renewal.action("transport.csr", input_json).unwrap();
        wire_bytes += self.control_result(call_id, true, &proof).await;
        let delivered = tokio::time::timeout(
            Duration::from_secs(2),
            self.receive.next(&self.connection.channel),
        )
        .await
        .unwrap()
        .unwrap();
        wire_bytes += control_bytes(&delivered.frame);
        let Frame::Call {
            call_id,
            action_id: "transport.certificate",
            input_json,
        } = delivered.frame
        else {
            panic!("expected replacement certificate")
        };
        let update = decode_certificate(input_json).unwrap();
        let fingerprint: [u8; 32] = X509::from_der(&update.certificate_der)
            .unwrap()
            .digest(openssl::hash::MessageDigest::sha256())
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        assert_ne!(fingerprint, predecessor);
        assert_eq!(guard.predecessor(), predecessor);
        let publication = renewal.action("transport.certificate", input_json);
        assert_eq!(sink.0.load(Ordering::Relaxed), 1);
        assert_eq!(
            guard.predecessor(),
            predecessor,
            "publication alone extended server authority"
        );
        assert_eq!(publication.is_ok(), durable);
        let ack = publication.unwrap_or_else(|_| b"{}".to_vec());
        wire_bytes += self.control_result(call_id, durable, &ack).await;
        println!(
            "renewal_control requests=2 results=2 durable={durable} tcp_mux_application_bytes={wire_bytes} raw_quic_frame_bytes={} excludes_encryption_and_packet_headers=true",
            wire_bytes - 4
        );
        if !durable {
            assert_eq!(
                renewal.current().unwrap().certificate.to_der().unwrap(),
                identity.certificate.to_der().unwrap()
            );
        }
        Self::check_ack(guard, predecessor, deadline, fingerprint, durable).await;
    }
    async fn check_ack(
        guard: &AuthorityGuard,
        predecessor: [u8; 32],
        deadline: tokio::time::Instant,
        fingerprint: [u8; 32],
        durable: bool,
    ) {
        if durable {
            tokio::time::timeout(Duration::from_secs(2), async {
                while guard.predecessor() != fingerprint {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(guard.renewal_deadline() > deadline);
        } else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(guard.predecessor(), predecessor);
            assert_eq!(guard.renewal_deadline(), deadline);
        }
    }
    async fn continued_terminal(
        &mut self,
        input: AttachmentHandle,
        mut output: mpsc::Receiver<TerminalOutput>,
    ) {
        self.transmit
            .send(
                &self.connection.channel,
                2,
                &Frame::Output {
                    out_seq: 6,
                    bytes: b"after",
                },
            )
            .await
            .unwrap();
        assert!(
            matches!(output.recv().await.unwrap(), TerminalOutput::Output { out_seq:6, bytes } if bytes.as_ref()==b"after")
        );
        let mut bytes = Vec::new();
        encode_muxed_frame_into(
            1,
            &Frame::Input {
                in_seq: 0,
                bytes: b"same writer",
            },
            &mut bytes,
        )
        .unwrap();
        input.send_frame(bytes.into()).await.unwrap();
        let forwarded = self.receive.next(&self.connection.channel).await.unwrap();
        assert_eq!(forwarded.stream_id, 2);
        assert!(matches!(
            forwarded.frame,
            Frame::Input {
                in_seq: 0,
                bytes: b"same writer"
            }
        ));
        assert_eq!(input.stream_id(), 2);
    }
}

#[tokio::test]
async fn unlock_renews_live_identity_only_after_publication_ack_with_terminal_intact() {
    let directory = Directory::new();
    let fixture = fixture_at_with_lock(
        &directory,
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        true,
    )
    .await;
    let (host, identity) = super::renewal::enrolled_at_half_life(&fixture).await;
    let mut peer = Peer::connect(&fixture, &identity).await;
    let (input, output, guard) = peer.terminal(&fixture, host).await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            peer.receive.next(&peer.connection.channel)
        )
        .await
        .is_err(),
        "cold-locked signer issued renewal call"
    );
    fixture
        .signer
        .unlock_from(&Administrator(fixture.material.clone()))
        .unwrap();
    peer.exchange(&fixture, &identity, &guard, true).await;
    peer.continued_terminal(input, output).await;
    assert!(guard.permits());
}

#[tokio::test]
async fn failed_publication_retains_original_admission_without_interrupting_terminal() {
    let directory = Directory::new();
    let fixture = fixture_at_with_lock(
        &directory,
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        true,
    )
    .await;
    let (host, identity) = super::renewal::enrolled_at_half_life(&fixture).await;
    let mut peer = Peer::connect(&fixture, &identity).await;
    let (input, output, guard) = peer.terminal(&fixture, host).await;
    fixture
        .signer
        .unlock_from(&Administrator(fixture.material.clone()))
        .unwrap();
    peer.exchange(&fixture, &identity, &guard, false).await;
    peer.continued_terminal(input, output).await;
    assert!(guard.permits());
}

/// Count actual canonical control frames; stream-zero mux adds exactly one byte.
/// This is application framing, excluding TLS records and QUIC/IP headers.
fn control_bytes(frame: &Frame<'_>) -> usize {
    let mut wire = Vec::new();
    encode_muxed_frame_into(0, frame, &mut wire).unwrap();
    wire.len()
}
