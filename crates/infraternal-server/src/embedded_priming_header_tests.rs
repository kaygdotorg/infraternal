//! Exercises promotion through ledger-admitted real QUIC when a parked writer cannot accept headers [128,215], #129.
use super::super::{BytesMut, process_priming};
use super::*;
use infraternal_agent::{
    remote_native::NativeChannel,
    transport::{Receive, Transmit},
};
use infraternal_plugin_remote::remote_quic;
use std::sync::Arc;

struct OwnedFlight(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for OwnedFlight {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct PrimedPair {
    link: Arc<RemoteLink>,
    control: NativeChannel,
    peer: quinn::Connection,
    _listener: quinn::Endpoint,
    _endpoint: quinn::Endpoint,
    _pool: sqlx::SqlitePool,
    _activation: oneshot::Receiver<()>,
}
fn greeting() -> Frame<'static> {
    Frame::Hello {
        version: 1,
        caps: remote_quic::REMOTE_WRITER_BINDING
            | infraternal_plugin_api::channel::REMOTE_PRIMED_WRITERS,
        client_info: "promotion fixture",
    }
}

async fn primed_pair() -> PrimedPair {
    let (server, node, ca, _) = crate::remote_runtime::tests::identities();
    let (store, pool, _host, fingerprint) =
        crate::remote_runtime::tests::revocation::admitted_store(&node, &ca).await;
    let authority = crate::remote_guard::AuthorityGuard::admit(store, fingerprint)
        .await
        .unwrap();
    let first = Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .unwrap();
    let second = Arc::new(tokio::sync::Semaphore::new(1))
        .acquire_owned()
        .await
        .unwrap();
    let mut admission =
        crate::remote_standby::Admission::new(authority, (first, second), Arc::default());
    let listener = quinn::Endpoint::server(
        remote_quic::server_config(&server, std::slice::from_ref(&ca)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut config = remote_quic::client_config(&node, std::slice::from_ref(&ca)).unwrap();
    let mut transport = quinn::TransportConfig::default();
    transport
        .stream_receive_window(4096u32.into())
        .receive_window(8192u32.into());
    config.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(config);
    let (peer, admitted) = tokio::join!(
        endpoint
            .connect(listener.local_addr().unwrap(), "localhost")
            .unwrap(),
        async { listener.accept().await.unwrap().await.unwrap() }
    );
    let peer = peer.unwrap();
    let hello = greeting();
    let joining = async {
        let (send, receive) = peer.open_bi().await.unwrap();
        let control = NativeChannel::control(send, receive).unwrap();
        let mut tx = Transmit::default();
        let mut rx = Receive::default();
        tx.send(
            &control,
            0,
            &Frame::Ping {
                nonce: 94,
                sent_us: 0,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            rx.next(&control).await.unwrap().frame,
            Frame::Pong { nonce: 94, .. }
        ));
        tx.send(
            &control,
            0,
            &Frame::Call {
                call_id: 0,
                action_id: "transport.standby",
                input_json: b"{\"prime\":true}",
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            rx.next(&control).await.unwrap().frame,
            Frame::Result { ok: true, .. }
        ));
        assert!(matches!(
            rx.next(&control).await.unwrap().frame,
            Frame::Hello { .. }
        ));
        tx.send(&control, 0, &hello).await.unwrap();
        control
    };
    let (control, link) = tokio::join!(
        joining,
        crate::remote_link::RemoteLink::quic_admitted(admitted, Some(&mut admission))
    );
    let link = Arc::new(link.unwrap());
    link.hello(&hello).unwrap();
    let mut greeting = BytesMut::new();
    link.read(&mut greeting, &mut [0; 4096]).await.unwrap();
    let (activation, activated) = oneshot::channel();
    link.activation(activation).unwrap();
    PrimedPair {
        link,
        control,
        peer,
        _listener: listener,
        _endpoint: endpoint,
        _pool: pool,
        _activation: activated,
    }
}

async fn attach_writer(fixture: &PrimedPair) -> NativeChannel {
    let hello = greeting();
    let binding = remote_quic::negotiate_binding(&fixture.peer, &hello).unwrap();
    let attach = Frame::AttachTerm {
        session_id: &[7; 16],
        last_out_seq: 10,
        last_in_seq: 0,
    };
    let mut encoded = Vec::new();
    encode_muxed_frame_into(42, &attach, &mut encoded).unwrap();
    fixture.link.write(42, &attach, &encoded).await.unwrap();
    let parked =
        NativeChannel::terminal(remote_quic::accept_bound(&binding).await.unwrap()).unwrap();
    let mut rx = Receive::default();
    assert!(matches!(
        rx.next(&parked).await.unwrap().frame,
        Frame::Call {
            action_id: "transport.prime",
            ..
        }
    ));
    assert!(matches!(
        rx.next(&parked).await.unwrap().frame,
        Frame::AttachTerm { .. }
    ));
    parked
}

async fn block_writer(fixture: &PrimedPair) -> (NativeChannel, OwnedFlight) {
    let parked = attach_writer(fixture).await;
    fixture.link.limit_send_window(256);
    let mut encoded = Vec::new();
    infraternal_protocol::encode_frame_into(
        &Frame::Input {
            in_seq: 0,
            bytes: &[b'x'; 16384],
        },
        &mut encoded,
    )
    .unwrap();
    let sender = fixture.link.clone();
    let mut flight = OwnedFlight(tokio::spawn(async move {
        sender.write_encoded_terminal(42, &encoded).await
    }));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut flight.0)
            .await
            .is_err(),
        "fixture writer must be flow-control blocked"
    );
    (parked, flight)
}

#[tokio::test]
async fn blocked_promotion_header_does_not_stop_actor_control_progress() {
    let fixture = primed_pair().await;
    let (_parked, mut flight) = block_writer(&fixture).await;
    let (socket, _unused) = tokio::net::UnixStream::pair().unwrap();
    let mut shadow = tests::shadow(socket);
    shadow.connection.peer = Peer::Remote(fixture.link.clone());
    let slot = shadow.slots.remove(&1).unwrap();
    shadow.slots.insert(42, slot);
    let mut hot = State::default();
    hot.shadow = Some(shadow);
    let (mut attachment, _output) = tests::attachment();
    attachment.stream_id = 42;
    let mut attachments = HashMap::from([(1, attachment)]);
    let mut connection = None;
    let (changes, _changed) = tokio::sync::watch::channel(());
    let mut writes = super::super::writes::State::default();
    let returned = tokio::time::timeout(
        Duration::from_millis(100),
        process_priming(
            Event::Incoming(Some(Incoming::Activate)),
            &mut hot,
            &mut connection,
            &mut attachments,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &changes,
            &mut writes,
        ),
    )
    .await
    .is_ok();
    Transmit::default()
        .send(
            &fixture.control,
            0,
            &Frame::Result {
                call_id: 93,
                ok: true,
                json: b"{}",
            },
        )
        .await
        .unwrap();
    let mut received = BytesMut::new();
    let progress = tokio::time::timeout(
        Duration::from_millis(100),
        fixture.link.read(&mut received, &mut [0; 4096]),
    )
    .await;
    writes.stop().await;
    flight.0.abort();
    let _ = (&mut flight.0).await;
    fixture.link.retire_writer(42).await;
    assert!(
        progress.is_ok_and(|result| result.is_ok()),
        "sibling control must progress with blocked promotion headers"
    );
    assert!(
        returned,
        "promotion headers must be owned, not awaited by the actor"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn promotion_never_publishes_an_unstarted_shadow_flight_as_credited() {
    let fixture = primed_pair().await;
    let _parked = attach_writer(&fixture).await;
    let (socket, _unused) = tokio::net::UnixStream::pair().unwrap();
    let mut shadow = tests::shadow(socket);
    shadow.connection.peer = Peer::Remote(fixture.link.clone());
    let slot = shadow.slots.remove(&1).unwrap();
    shadow.slots.insert(42, slot);
    let mut hot = State::default();
    hot.shadow = Some(shadow);
    hot.waiting.insert(
        1,
        Waiting {
            ack: 0,
            since: Instant::now() - HEDGE_AFTER,
        },
    );
    let (mut attachment, _output) = tests::attachment();
    attachment.stream_id = 42;
    let attachments = HashMap::from([(1, attachment)]);
    assert!(hot.hedge(&attachments).await);
    // spawn never polls inline and this ready await cannot yield. Promotion
    // must join the dormant task without treating its grants as delivered.
    let (_promoted, slots) = hot.promote().await.unwrap();
    let valid = slots
        .get(&42)
        .is_none_or(|(_, credit, hedged)| *credit == 0 && !*hedged);
    fixture.link.retire_writer(42).await;
    assert!(
        valid,
        "unstarted Cursor/Credit cannot be published as a hedged, credited writer"
    );
}

#[tokio::test]
async fn promoted_owned_attach_opens_a_missing_native_writer_binding() {
    let fixture = primed_pair().await;
    fixture.link.promote().await.unwrap();
    let binding = remote_quic::negotiate_binding(&fixture.peer, &greeting()).unwrap();
    let attach = Frame::AttachTerm {
        session_id: &[7; 16],
        last_out_seq: 10,
        last_in_seq: 0,
    };
    let mut encoded = Vec::new();
    infraternal_protocol::encode_frame_into(&attach, &mut encoded).unwrap();
    let mut input = Vec::new();
    infraternal_protocol::encode_frame_into(
        &Frame::Input {
            in_seq: 0,
            bytes: b"x",
        },
        &mut input,
    )
    .unwrap();
    assert!(
        fixture
            .link
            .write_encoded_terminal(43, &input)
            .await
            .is_err()
    );
    let mut coalesced = encoded.clone();
    coalesced.extend_from_slice(&input);
    assert!(
        fixture
            .link
            .write_encoded_terminal(44, &coalesced)
            .await
            .is_err()
    );
    let opened = fixture.link.write_encoded_terminal(42, &encoded).await;
    assert!(
        opened.is_ok(),
        "owned promotion Attach must bind an absent writer: {opened:?}"
    );
    let bound = tokio::time::timeout(Duration::from_secs(2), remote_quic::accept_bound(&binding))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bound.writer_id, 42);
    let channel = NativeChannel::terminal(bound).unwrap();
    // The promoted path is ordinary: its first frame is Attach, never prime.
    assert!(matches!(
        Receive::default().next(&channel).await.unwrap().frame,
        Frame::AttachTerm {
            session_id,
            last_out_seq: 10,
            last_in_seq: 0
        } if session_id == &[7; 16]
    ));
    fixture.link.retire_writer(42).await;
}
