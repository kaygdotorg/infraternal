//! Proves actor native admission and raw delivery over real in-memory mTLS QUIC, without terminal queues [D198,D232], #146.
use super::*;
use crate::{embedded::EmbeddedAgent, remote_guard::AuthorityGuard};
use infraternal_plugin_api::streams::{WireLane, WireStreamDef};
use infraternal_protocol::{
    desktop::{Delivery, Message},
    encode_frame_into,
};
use uuid::Uuid;

struct Pair {
    _server: quinn::Endpoint,
    _host: quinn::Endpoint,
    connection: quinn::Connection,
    control: NativeChannel,
    actor: EmbeddedAgent,
    store: crate::enrollment::EnrollmentStore,
    host_id: Uuid,
    accepts: mpsc::Sender<RemoteLink>,
}
impl Pair {
    async fn new(caps: u64) -> Self {
        Self::with_credit(caps, None).await
    }
    async fn with_credit(caps: u64, credit: Option<u32>) -> Self {
        let (server, host, root, _) = crate::remote_runtime::tests::identities();
        let fingerprint = openssl::sha::sha256(&host.certificate.to_der().unwrap());
        let (store, _pool, id) = crate::enrollment::authority::tests::enrolled().await;
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let key_digest = openssl::sha::sha256(&host.key.raw_public_key().unwrap());
        let token = store
            .issue(
                "owner",
                id,
                crate::enrollment::Mode::Rootless,
                now,
                &key_digest,
            )
            .await
            .unwrap();
        store
            .redeem(
                token.secret(),
                id,
                crate::enrollment::Mode::Rootless,
                now,
                &crate::enrollment::CertificateRecord {
                    fingerprint,
                    issuer_fingerprint: openssl::sha::sha256(&root.to_der().unwrap()),
                    public_key: host.key.raw_public_key().unwrap().try_into().unwrap(),
                    not_before: now,
                    not_after: now + 604_800,
                },
            )
            .await
            .unwrap();
        let authority = AuthorityGuard::admit(store.clone(), fingerprint)
            .await
            .unwrap();
        let server = quinn::Endpoint::server(
            remote_quic::server_config(&server, std::slice::from_ref(&root)).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut config = remote_quic::client_config(&host, &[root]).unwrap();
        if let Some(credit) = credit {
            let mut transport = quinn::TransportConfig::default();
            transport.max_concurrent_bidi_streams(credit.into());
            config.transport_config(Arc::new(transport));
        }
        endpoint.set_default_client_config(config);
        let (host, server_connection) = tokio::join!(
            endpoint
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap(),
            async { server.accept().await.unwrap().await }
        );
        let host = host.unwrap();
        let (send, receive) = host.open_bi().await.unwrap();
        let control = NativeChannel::control(send, receive).unwrap();
        Transmit::default()
            .send(
                &control,
                0,
                &Frame::Hello {
                    version: 1,
                    caps,
                    client_info: "test",
                },
            )
            .await
            .unwrap();
        let link = RemoteLink::quic(server_connection.unwrap())
            .await
            .unwrap()
            .authorize(authority);
        let (actor, accepts) = EmbeddedAgent::remote(1002);
        accepts.send(link).await.unwrap();
        let mut receive = Receive::default();
        let hello = receive.next(&control).await.unwrap();
        assert!(
            matches!(hello.frame, Frame::Hello { caps, .. } if caps & infraternal_protocol::desktop::NATIVE_CAPABILITY != 0)
        );
        Self {
            _server: server,
            _host: endpoint,
            connection: host,
            control,
            actor,
            store,
            host_id: id,
            accepts,
        }
    }
    fn binding(&self) -> BindingConnection {
        remote_quic::negotiate_binding(
            &self.connection,
            &Frame::Hello {
                version: 1,
                caps: remote_quic::REMOTE_WRITER_BINDING,
                client_info: "test",
            },
        )
        .unwrap()
    }
    async fn control_live(&self) {
        self.control_live_with_receive(&mut Receive::default())
            .await;
    }
    async fn control_live_with_receive(&self, receive: &mut Receive) {
        let call = self.actor.call("terminal.list".into(), b"{}".to_vec());
        let peer = async {
            let call_id = loop {
                let decoded = receive.next(&self.control).await.unwrap();
                match decoded.frame {
                    Frame::Ping { nonce, sent_us } => {
                        // A live actor may probe while a native fixture is sending bulk data.
                        Transmit::default()
                            .send(&self.control, 0, &Frame::Pong { nonce, sent_us })
                            .await
                            .unwrap();
                    }
                    Frame::Call {
                        call_id,
                        action_id: "terminal.list",
                        ..
                    } => break call_id,
                    _ => panic!("expected control call or liveness probe"),
                }
            };
            Transmit::default()
                .send(
                    &self.control,
                    0,
                    &Frame::Result {
                        call_id,
                        ok: true,
                        json: b"[]",
                    },
                )
                .await
                .unwrap();
        };
        let (reply, ()) = tokio::join!(call, peer);
        assert_eq!(reply.unwrap(), b"[]");
        assert!(self.connection.close_reason().is_none());
    }
    async fn terminal_live(
        &self,
        writer: u32,
    ) -> (crate::embedded::TerminalAttachment, NativeChannel) {
        let attach = self
            .actor
            .attach(*Uuid::from_u128(7).as_bytes(), 123, 456, writer);
        let peer = async {
            let bound = remote_quic::accept_bound(&self.binding()).await.unwrap();
            assert_eq!(bound.writer_id, writer);
            let terminal = NativeChannel::terminal(bound).unwrap();
            let mut receive = Receive::default();
            assert!(matches!(
                receive.next(&terminal).await.unwrap().frame,
                Frame::AttachTerm {
                    last_out_seq: 123,
                    last_in_seq: 456,
                    ..
                }
            ));
            Transmit::default()
                .send(&terminal, writer, &Frame::Ack { in_seq_acked: 456 })
                .await
                .unwrap();
            terminal
        };
        let (attachment, terminal) = tokio::join!(attach, peer);
        (attachment.unwrap(), terminal)
    }
}
fn definition() -> &'static WireStreamDef {
    crate::compiled_plugins()
        .iter()
        .flat_map(|descriptor| descriptor.streams)
        .find_map(|stream| stream.wire.as_ref())
        .unwrap()
}
fn opening() -> Bytes {
    opening_for(1)
}
fn opening_for(id: u128) -> Bytes {
    let mut bytes = Vec::new();
    encode_frame_into(
        &Frame::Desktop(Message::Attach {
            session_id: Uuid::from_u128(id).as_bytes(),
            delivery: Delivery::Reliable,
        }),
        &mut bytes,
    )
    .unwrap();
    Bytes::from(bytes)
}

static UNCOMPILED: WireStreamDef = WireStreamDef {
    browser_capability: None,
    capability: 512,
    opening_tag: 0x40,
    opening_identity: None,
    requests: &[0x40],
    replies: &[0x41],
    max_streams: 1,
    datagram_tag: None,
    datagram_identity: None,
};

#[tokio::test]
async fn unsupported_or_invalid_opening_never_creates_native_stream() {
    let pair = Pair::new(remote_quic::REMOTE_WRITER_BINDING).await;
    assert!(matches!(
        pair.actor.open_wire(definition(), 42, opening()).await,
        Err(crate::embedded::AgentError::Unsupported)
    ));
    pair.control_live().await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            remote_quic::accept_bound(&pair.binding())
        )
        .await
        .is_err()
    );
    let pair = Pair::new(
        remote_quic::REMOTE_WRITER_BINDING | infraternal_protocol::desktop::NATIVE_CAPABILITY | 512,
    )
    .await;
    assert!(matches!(
        pair.actor.open_wire(&UNCOMPILED, 42, opening()).await,
        Err(crate::embedded::AgentError::Unsupported)
    ));
    for writer in [0, 43] {
        assert!(
            pair.actor
                .open_wire(definition(), writer, opening())
                .await
                .is_err()
        );
    }
    let mut trailing = opening().to_vec();
    trailing.push(0);
    for packet in [Bytes::from(trailing), Bytes::from_static(&[1, 0x40])] {
        assert!(
            pair.actor
                .open_wire(definition(), 42, packet)
                .await
                .is_err()
        );
    }
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            remote_quic::accept_bound(&pair.binding())
        )
        .await
        .is_err()
    );
    pair.control_live().await;
}

#[tokio::test]
async fn actor_delivers_mebibyte_raw_native_packets_and_retirement_keeps_control_live() {
    let pair = Pair::new(
        remote_quic::REMOTE_WRITER_BINDING | infraternal_protocol::desktop::NATIVE_CAPABILITY,
    )
    .await;
    let lane = pair
        .actor
        .open_wire(definition(), 42, opening())
        .await
        .unwrap();
    let bound = remote_quic::accept_bound(&pair.binding()).await.unwrap();
    assert_eq!(bound.writer_id, 42);
    let provider = infraternal_agent::wire::Lane::new(
        NativeChannel::terminal(bound).unwrap(),
        definition(),
        infraternal_agent::wire::Side::Provider,
        None,
    )
    .unwrap();
    assert_eq!(provider.receive().await.unwrap(), opening());
    let bytes = vec![7; 1024 * 1024];
    let mut video = Vec::new();
    encode_frame_into(
        &Frame::Desktop(Message::Video {
            sequence: 1,
            capture_ns: 2,
            keyframe: true,
            bytes: &bytes,
        }),
        &mut video,
    )
    .unwrap();
    assert!(lane.send(&video).await.is_err());
    let (sent, received) = tokio::join!(provider.send(&video), lane.receive());
    sent.unwrap();
    assert_eq!(received.unwrap().as_ref(), video);
    let retained = lane.datagrams();
    lane.retire();
    assert!(lane.receive().await.is_err());
    if let Some(retained) = retained {
        assert!(retained.max_payload().is_none());
    }
    let (attachment, _terminal) = pair.terminal_live(44).await;
    let (_handle, mut output) = attachment.split();
    assert!(matches!(
        output.recv().await,
        Some(crate::embedded::TerminalOutput::Ack { in_seq_acked: 456 })
    ));
    pair.control_live().await;
}

#[tokio::test]
async fn cancelling_opener_waiting_for_native_credit_leaves_control_available() {
    let pair = Pair::with_credit(
        remote_quic::REMOTE_WRITER_BINDING | infraternal_protocol::desktop::NATIVE_CAPABILITY,
        Some(0),
    )
    .await;
    // No native stream credit exists. Cancelling the real actor request must
    // interrupt open_bound rather than monopolize the actor's control turn.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            pair.actor.open_wire(definition(), 42, opening())
        )
        .await
        .is_err()
    );
    tokio::time::timeout(Duration::from_secs(2), pair.control_live())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            remote_quic::accept_bound(&pair.binding())
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn pending_native_opener_does_not_block_actor_control_calls() {
    let pair = Pair::with_credit(
        remote_quic::REMOTE_WRITER_BINDING | infraternal_protocol::desktop::NATIVE_CAPABILITY,
        Some(0),
    )
    .await;
    let opener = pair.actor.open_wire(definition(), 42, opening());
    tokio::pin!(opener);
    // Polling queues Wire before the control Call, then waits on its reply.
    // Zero transport credit guarantees that native opening remains pending.
    std::future::poll_fn(|cx| {
        assert!(opener.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    tokio::time::timeout(Duration::from_secs(2), pair.control_live())
        .await
        .expect("pending native opening blocked control");
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut opener)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn actor_drop_aborts_pending_native_open_and_closes_retained_transport() {
    let pair = Pair::with_credit(
        remote_quic::REMOTE_WRITER_BINDING | infraternal_protocol::desktop::NATIVE_CAPABILITY,
        Some(0),
    )
    .await;
    let opener = pair.actor.open_wire(definition(), 42, opening());
    tokio::pin!(opener);
    std::future::poll_fn(|cx| {
        assert!(opener.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    tokio::time::timeout(Duration::from_secs(2), pair.control_live())
        .await
        .unwrap();
    // The opening task holds the current RemoteLink Arc. Actor exit must fence
    // it explicitly, rather than waiting for that task to release its clone.
    drop(pair.accepts);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), opener)
            .await
            .unwrap()
            .is_err()
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), pair.connection.closed())
            .await
            .unwrap(),
        quinn::ConnectionError::ApplicationClosed(_)
    ));
}

#[tokio::test]
async fn retired_datagram_clone_releases_uuid_and_cannot_withdraw_replacement_route() {
    let pair = Pair::new(
        remote_quic::REMOTE_WRITER_BINDING | infraternal_protocol::desktop::NATIVE_CAPABILITY,
    )
    .await;
    let old = pair
        .actor
        .open_wire(definition(), 42, opening())
        .await
        .unwrap();
    let _old_provider = remote_quic::accept_bound(&pair.binding()).await.unwrap();
    let inert = old.datagrams().unwrap();
    old.retire();
    assert!(inert.max_payload().is_none());
    let fresh = pair
        .actor
        .open_wire(definition(), 44, opening())
        .await
        .expect("retired datagram registration retained UUID");
    let _fresh_provider = remote_quic::accept_bound(&pair.binding()).await.unwrap();
    let receive = fresh.datagrams().unwrap();
    // Dropping a predecessor after re-admission must remove only its ticket.
    drop(inert);
    drop(old);
    let mut packet = Vec::new();
    encode_frame_into(
        &Frame::Desktop(Message::Fragment {
            session_id: Uuid::from_u128(1).as_bytes(),
            sequence: 1,
            capture_ns: 2,
            keyframe: true,
            total: 5,
            offset: 0,
            bytes: b"fresh",
        }),
        &mut packet,
    )
    .unwrap();
    pair.connection
        .send_datagram(Bytes::copy_from_slice(&packet))
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), receive.receive())
            .await
            .unwrap()
            .unwrap()
            .as_ref(),
        packet
    );
    pair.control_live().await;
}

#[tokio::test]
async fn revoked_host_withdraws_pending_native_reads_and_retained_datagrams() {
    let pair = Pair::new(
        remote_quic::REMOTE_WRITER_BINDING | infraternal_protocol::desktop::NATIVE_CAPABILITY,
    )
    .await;
    let lane = pair
        .actor
        .open_wire(definition(), 42, opening())
        .await
        .unwrap();
    let _provider = remote_quic::accept_bound(&pair.binding()).await.unwrap();
    let retained = lane.datagrams().unwrap();
    let receive = lane.receive();
    tokio::pin!(receive);
    std::future::poll_fn(|cx| {
        assert!(receive.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    pair.store.revoke("owner", pair.host_id, now).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), receive)
            .await
            .unwrap()
            .is_err()
    );
    assert!(lane.send(&opening()).await.is_err());
    assert!(retained.max_payload().is_none());
    assert!(retained.receive().await.is_err());
    assert!(retained.send(b"invalid").await.is_err());
}

#[tokio::test]
async fn dropping_actor_connection_retires_returned_native_lease_and_datagram_clones() {
    let pair = Pair::new(
        remote_quic::REMOTE_WRITER_BINDING | infraternal_protocol::desktop::NATIVE_CAPABILITY,
    )
    .await;
    let lane = pair
        .actor
        .open_wire(definition(), 42, opening())
        .await
        .unwrap();
    let _provider = remote_quic::accept_bound(&pair.binding()).await.unwrap();
    let retained = lane.datagrams().unwrap();
    // The host's admission receiver closes while callers still own the lane.
    // The weak registry must retire those caller leases when the actor exits.
    drop(pair.accepts);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), lane.receive())
            .await
            .unwrap()
            .is_err()
    );
    assert!(lane.send(&opening()).await.is_err());
    assert!(retained.max_payload().is_none());
    assert!(retained.receive().await.is_err());
}

#[tokio::test]
async fn wrong_incoming_native_direction_retires_only_its_lane() {
    let pair = Pair::new(
        remote_quic::REMOTE_WRITER_BINDING | infraternal_protocol::desktop::NATIVE_CAPABILITY,
    )
    .await;
    let lane = pair
        .actor
        .open_wire(definition(), 42, opening())
        .await
        .unwrap();
    let bound = remote_quic::accept_bound(&pair.binding()).await.unwrap();
    let provider = NativeChannel::terminal(bound).unwrap();
    assert_eq!(
        Receive::default().next_wire(&provider).await.unwrap(),
        opening()
    );
    // A peer cannot send a requester-only opening back as a reply.
    provider.write(&opening()).await.unwrap();
    assert!(lane.receive().await.is_err());
    assert!(lane.send(&opening()).await.is_err());
    let (_attachment, _terminal) = pair.terminal_live(44).await;
    pair.control_live().await;
}

#[tokio::test]
async fn terminal_and_native_lanes_share_one_connection_reserve() {
    let pair = Pair::new(
        remote_quic::REMOTE_WRITER_BINDING | infraternal_protocol::desktop::NATIVE_CAPABILITY,
    )
    .await;
    let (_attachment, _terminal) = pair.terminal_live(2).await;
    let mut lanes = Vec::new();
    let mut providers = Vec::new();
    let mut control = Receive::default();
    let fill_reserve = async {
        for index in 1..128 {
            let writer = 2 * (index + 1);
            let lane = pair
                .actor
                .open_wire(definition(), writer, opening_for(u128::from(index)))
                .await
                .unwrap();
            let bound = remote_quic::accept_bound(&pair.binding()).await.unwrap();
            let provider = infraternal_agent::wire::Lane::new(
                NativeChannel::terminal(bound).unwrap(),
                definition(),
                infraternal_agent::wire::Side::Provider,
                None,
            )
            .unwrap();
            assert_eq!(
                provider.receive().await.unwrap(),
                opening_for(u128::from(index))
            );
            lanes.push(lane);
            providers.push(provider);
        }
        assert!(matches!(
            pair.actor
                .open_wire(definition(), 258, opening_for(128))
                .await,
            Err(crate::embedded::AgentError::Rejected)
        ));
        assert!(matches!(
            pair.actor
                .attach(*Uuid::from_u128(7).as_bytes(), 0, 0, 260)
                .await,
            Err(crate::embedded::AgentError::Rejected)
        ));
    };
    tokio::pin!(fill_reserve);
    loop {
        tokio::select! {
            () = &mut fill_reserve => break,
            probe = control.next(&pair.control) => {
                // Filling the complete reserve still represents a live peer.
                // Retain this decoder through cancellations and the final Call.
                let Frame::Ping { nonce, sent_us } = probe.unwrap().frame else {
                    panic!("expected ordinary control liveness during native admission");
                };
                Transmit::default().send(&pair.control, 0, &Frame::Pong { nonce, sent_us }).await.unwrap();
            }
        }
    }
    pair.control_live_with_receive(&mut control).await;
}
