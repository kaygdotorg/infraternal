//! Verifies parked fallback authority and activation on real mTLS QUIC without replacing the live host actor [64,128,215], #129.
use super::*;
use bytes::Bytes;
use infraternal_agent::remote_native::NativeChannel;

pub(super) async fn connect_control(
    address: SocketAddr,
    identity: &Identity,
    root: &X509,
) -> (quinn::Endpoint, quinn::Connection, NativeChannel) {
    connect_control_with_window(address, identity, root, false).await
}
async fn connect_control_with_window(
    address: SocketAddr,
    identity: &Identity,
    root: &X509,
    limited: bool,
) -> (quinn::Endpoint, quinn::Connection, NativeChannel) {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let mut config = remote_quic::client_config(identity, std::slice::from_ref(root)).unwrap();
    if limited {
        let mut transport = quinn::TransportConfig::default();
        transport
            .stream_receive_window(4096u32.into())
            .receive_window(8192u32.into());
        config.transport_config(Arc::new(transport));
    }
    endpoint.set_default_client_config(config);
    let connection = endpoint
        .connect(address, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (send, receive) = connection.open_bi().await.unwrap();
    let channel = NativeChannel::control(send, receive).unwrap();
    (endpoint, connection, channel)
}

fn hello() -> Frame<'static> {
    Frame::Hello {
        version: 1,
        caps: remote_quic::REMOTE_WRITER_BINDING,
        client_info: "fixture",
    }
}

async fn park(channel: &impl Channel, rx: &mut Receive) {
    let mut tx = Transmit::default();
    tx.send(
        channel,
        0,
        &Frame::Ping {
            nonce: 41,
            sent_us: 0,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        rx.next(channel).await.unwrap().frame,
        Frame::Pong {
            nonce: 41,
            sent_us: 0
        }
    );
    tx.send(
        channel,
        0,
        &Frame::Call {
            call_id: 0,
            action_id: "transport.standby",
            input_json: b"{}",
        },
    )
    .await
    .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(2), rx.next(channel))
        .await
        .unwrap()
        .expect("enrolled fallback must park");
    assert!(matches!(
        reply.frame,
        Frame::Result {
            call_id: 0,
            ok: true,
            ..
        }
    ));
    assert!(matches!(
        rx.next(channel).await.unwrap().frame,
        Frame::Hello { version: 1, .. }
    ));
}

#[tokio::test]
async fn parked_fallback_survives_greeting_deadline_and_activates_without_another_hello() {
    let (server, node, root, _) = identities();
    let (store, _pool, host_id, _) = super::revocation::admitted_store(&node, &root).await;
    let hosts = RemoteHosts::default();
    let listener = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store,
        hosts.clone(),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let (_live_endpoint, _live_connection, live) = connect_control(address, &node, &root).await;
    Transmit::default().send(&live, 0, &hello()).await.unwrap();
    assert!(matches!(
        Receive::default().next(&live).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    let generation = hosts.0.lock().await[&host_id].generation;
    let (_warm_endpoint, connection, warm) = connect_control(address, &node, &root).await;
    let mut rx = Receive::default();
    park(&warm, &mut rx).await;
    assert_eq!(
        hosts.0.lock().await[&host_id].generation,
        generation,
        "parking must not replace the actor"
    );
    tokio::time::sleep(Duration::from_millis(5200)).await;
    assert!(
        connection.close_reason().is_none(),
        "standby must outlive the ordinary greeting cap"
    );
    Transmit::default().send(&warm, 0, &hello()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while hosts.0.lock().await[&host_id].generation == generation {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // The cached server Hello lets activation and terminal replay share a flight.
    assert!(
        tokio::time::timeout(Duration::from_millis(25), rx.next(&warm))
            .await
            .is_err(),
        "activation must not send a second server Hello"
    );
    assert!(connection.close_reason().is_none());
}

#[tokio::test]
async fn parked_fallback_is_cancelled_by_ledger_revocation() {
    let (server, node, root, _) = identities();
    let (store, _pool, host_id, _) = super::revocation::admitted_store(&node, &root).await;
    let listener = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store.clone(),
        RemoteHosts::default(),
    )
    .await
    .unwrap();
    let (_endpoint, connection, channel) =
        connect_control(listener.local_addr().unwrap(), &node, &root).await;
    park(&channel, &mut Receive::default()).await;
    store
        .revoke("owner", host_id, now().unwrap())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), connection.closed())
        .await
        .expect("revocation must close the parked fallback");
}

#[tokio::test]
async fn a_second_parked_fallback_cannot_replace_the_first() {
    let (server, node, root, _) = identities();
    let (store, _pool, _host_id, _) = super::revocation::admitted_store(&node, &root).await;
    let listener = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store,
        RemoteHosts::default(),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let (_first_endpoint, first, channel) = connect_control(address, &node, &root).await;
    park(&channel, &mut Receive::default()).await;
    let (_second_endpoint, second, channel) = connect_control(address, &node, &root).await;
    let mut tx = Transmit::default();
    let mut rx = Receive::default();
    tx.send(
        &channel,
        0,
        &Frame::Ping {
            nonce: 17,
            sent_us: 0,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        rx.next(&channel).await.unwrap().frame,
        Frame::Pong { nonce: 17, .. }
    ));
    tx.send(
        &channel,
        0,
        &Frame::Call {
            call_id: 0,
            action_id: "transport.standby",
            input_json: b"{}",
        },
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), second.closed())
        .await
        .unwrap();
    assert!(
        first.close_reason().is_none(),
        "a duplicate must not retire the admitted standby"
    );
}

#[tokio::test]
async fn tcp_fallback_parks_without_a_host_actor_and_activates_on_the_existing_tls_channel() {
    let (server, node, root, _) = identities();
    let (store, _pool, host_id, _) = super::revocation::admitted_store(&node, &root).await;
    let hosts = RemoteHosts::default();
    let listener = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store,
        hosts.clone(),
    )
    .await
    .unwrap();
    let config = remote_tls::client_config(&node, std::slice::from_ref(&root)).unwrap();
    let connection = remote_tls::dial(listener.local_addr().unwrap(), "localhost", &config)
        .await
        .unwrap();
    let mut receive = Receive::default();
    park(&connection.channel, &mut receive).await;
    assert!(hosts.actor(host_id).await.is_none());
    Transmit::default()
        .send(&connection.channel, 0, &hello())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while hosts.actor(host_id).await.is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(25), receive.next(&connection.channel))
            .await
            .is_err(),
        "activation must reuse the cached greeting on TCP too"
    );
}

/// An opt-in native standby proves and greets its node without superseding the
/// active host; only an authenticated activation changes actor generation.
#[tokio::test]
async fn primed_standby_greets_without_replacing_the_live_actor_before_activation() {
    primed_fixture(false, false, false, false, false).await;
}
#[tokio::test]
async fn primed_fallback_activates_after_the_primary_closes() {
    primed_fixture(true, false, false, false, false).await;
}

#[tokio::test]
async fn primed_fallback_hedges_while_primary_native_send_buffer_is_full() {
    primed_fixture(false, true, false, false, false).await;
}

#[tokio::test]
async fn primed_fallback_hedges_when_credit_arrives_behind_a_blocked_primary_write() {
    primed_fixture(false, true, true, false, false).await;
}

// One fixture owns both transports and retained browser attachment through promotion.
#[tokio::test]
async fn primed_hedge_survives_blocked_control_call() {
    primed_fixture(false, true, false, true, false).await;
}

#[tokio::test]
async fn detached_primed_writers_release_native_binding_budget() {
    primed_fixture(false, false, false, false, true).await;
}

async fn bounded_retired_native_counts(endpoint: &quinn::Endpoint) {
    let peer = endpoint.local_addr().unwrap();
    let mut latest = None;
    let bounded = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            latest = crate::remote_link::RemoteLink::native_counts_for_peer(peer);
            // One control binding remains. Its reader and briefly joining
            // terminal pumps may overlap, but cannot accumulate across churn.
            if matches!(latest, Some([Some(0..=1), Some(0..=4), _, _, _])) {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        bounded.is_ok(),
        "retired native ownership is unbounded: {latest:?}"
    );
}

#[allow(clippy::too_many_lines, clippy::fn_params_excessive_bools)] // Independent fixture fault switches, not production policy.
async fn primed_fixture(
    close_primary: bool,
    blocked_primary: bool,
    late_credit: bool,
    late_control: bool,
    churn: bool,
) {
    let (server, node, root, _) = identities();
    let (store, _pool, host_id, _) = super::revocation::admitted_store(&node, &root).await;
    let hosts = RemoteHosts::default();
    let listener = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&root),
        store,
        hosts.clone(),
    )
    .await
    .unwrap();
    let address = listener.local_addr().unwrap();
    let (live_endpoint, live_connection, live) =
        connect_control_with_window(address, &node, &root, blocked_primary).await;
    Transmit::default().send(&live, 0, &hello()).await.unwrap();
    assert!(matches!(
        Receive::default().next(&live).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    let live_binding = remote_quic::negotiate_binding(&live_connection, &hello()).unwrap();
    let (prior_authority, retained_admission) = {
        let admitted = hosts.0.lock().await;
        let host = &admitted[&host_id];
        (host.authority.clone(), host.admission.clone())
    };
    let generation = hosts.0.lock().await[&host_id].generation;
    let (warm_endpoint, connection, warm) = connect_control(address, &node, &root).await;
    let mut receive = Receive::default();
    let mut transmit = Transmit::default();
    transmit
        .send(
            &warm,
            0,
            &Frame::Ping {
                nonce: 91,
                sent_us: 0,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        receive.next(&warm).await.unwrap().frame,
        Frame::Pong { nonce: 91, .. }
    ));
    transmit
        .send(
            &warm,
            0,
            &Frame::Call {
                call_id: 0,
                action_id: "transport.standby",
                input_json: b"{\"prime\":true}",
            },
        )
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(2), receive.next(&warm))
        .await
        .unwrap()
        .expect("native priming must be admitted");
    assert!(matches!(
        reply.frame,
        Frame::Result {
            call_id: 0,
            ok: true,
            ..
        }
    ));
    assert!(
        matches!(receive.next(&warm).await.unwrap().frame, Frame::Hello { caps, .. } if caps & infraternal_plugin_api::channel::REMOTE_PRIMED_WRITERS != 0)
    );
    transmit
        .send(
            &warm,
            0,
            &Frame::Hello {
                version: 1,
                caps: remote_quic::REMOTE_WRITER_BINDING
                    | infraternal_plugin_api::channel::REMOTE_PRIMED_WRITERS,
                client_info: "fixture",
            },
        )
        .await
        .unwrap();
    // Open the PTY after parking: the warm connection must incrementally
    // attach this writer without replacing its working ordinary peer.
    let warm_binding = remote_quic::negotiate_binding(&connection, &hello()).unwrap();
    let actor = hosts.0.lock().await[&host_id].actor.clone();
    let attachment = actor.attach([9; 16], 0, 0, 42).await.unwrap();
    let live_bound = tokio::time::timeout(
        Duration::from_secs(2),
        remote_quic::accept_bound(&live_binding),
    )
    .await
    .unwrap()
    .unwrap();
    let live_terminal = NativeChannel::terminal(live_bound).unwrap();
    assert!(matches!(
        Receive::default().next(&live_terminal).await.unwrap().frame,
        Frame::AttachTerm { .. }
    ));
    Transmit::default()
        .send(&live_terminal, 42, &Frame::Ack { in_seq_acked: 0 })
        .await
        .unwrap();
    let warm_bound = tokio::time::timeout(
        Duration::from_secs(2),
        remote_quic::accept_bound(&warm_binding),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(warm_bound.writer_id, 42);
    let warm_terminal = NativeChannel::terminal(warm_bound).unwrap();
    let mut terminal_receive = Receive::default();
    assert!(matches!(
        terminal_receive.next(&warm_terminal).await.unwrap().frame,
        Frame::Call {
            call_id: 0,
            action_id: "transport.prime",
            input_json: b"{}"
        }
    ));
    assert!(matches!(
        terminal_receive.next(&warm_terminal).await.unwrap().frame,
        Frame::AttachTerm { .. }
    ));
    Transmit::default()
        .send(&warm_terminal, 42, &Frame::Ack { in_seq_acked: 0 })
        .await
        .unwrap();
    tokio::task::yield_now().await;
    assert_eq!(hosts.0.lock().await[&host_id].generation, generation);
    assert!(connection.close_reason().is_none());
    if churn {
        // Await the initial setup/Ack transition before the deliberately pending
        // writer churn; this wait is fixture synchronization, not a latency result.
        tokio::time::sleep(Duration::from_millis(20)).await;
        // EOF verifies server retirement, but both peer halves must then drop
        // to return QUIC's bidirectional stream quota. Keep the connections
        // alive while repeatedly retiring only their writer channels.
        drop(attachment);
        assert!(matches!(
            Receive::default().next(&live_terminal).await.unwrap().frame,
            Frame::Close { .. }
        ));
        assert!(
            tokio::time::timeout(
                Duration::from_secs(2),
                Receive::default().next(&live_terminal)
            )
            .await
            .unwrap()
            .is_err()
        );
        assert!(
            tokio::time::timeout(
                Duration::from_secs(2),
                Receive::default().next(&warm_terminal)
            )
            .await
            .unwrap()
            .is_err()
        );
        drop(live_terminal);
        drop(warm_terminal);
        let mut active_retirements = 1;
        let mut warm_retirements = 1;
        for index in 0..129u32 {
            let writer = 44 + 2 * index;
            bounded_retired_native_counts(&live_endpoint).await;
            bounded_retired_native_counts(&warm_endpoint).await;
            let handle = actor
                .attach([u8::try_from(index).unwrap(); 16], 0, 0, writer)
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "primary attach {index}: {error:?}, live={:?}, warm={:?}, live_counts={:?}, warm_counts={:?}",
                        live_connection.close_reason(),
                        connection.close_reason(),
                        crate::remote_link::RemoteLink::native_counts_for_peer(live_endpoint.local_addr().unwrap()),
                        crate::remote_link::RemoteLink::native_counts_for_peer(warm_endpoint.local_addr().unwrap())
                    )
                });
            let active = NativeChannel::terminal(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    remote_quic::accept_bound(&live_binding),
                )
                .await
                .unwrap()
                .unwrap(),
            )
            .unwrap();
            assert!(matches!(
                Receive::default().next(&active).await.unwrap().frame,
                Frame::AttachTerm { .. }
            ));
            Transmit::default()
                .send(&active, writer, &Frame::Ack { in_seq_acked: 0 })
                .await
                .unwrap();
            let parked = NativeChannel::terminal(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    remote_quic::accept_bound(&warm_binding),
                )
                .await
                .expect("detached shadow must release its native binding budget")
                .unwrap_or_else(|error| {
                    panic!(
                        "warm admission {index}: {error:?}, close={:?}",
                        connection.close_reason()
                    )
                }),
            )
            .unwrap();
            let mut receive = Receive::default();
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(2), receive.next(&parked))
                    .await
                    .expect("fresh shadow binding must carry priming and attach frames")
                    .unwrap()
                    .frame,
                Frame::Call {
                    action_id: "transport.prime",
                    ..
                }
            ));
            assert!(matches!(
                tokio::time::timeout(Duration::from_secs(2), receive.next(&parked))
                    .await
                    .expect("fresh shadow binding must carry priming and attach frames")
                    .unwrap()
                    .frame,
                Frame::AttachTerm { .. }
            ));
            // Detach before the first shadow Ack: no late inbound frame may
            // accidentally retire the leaked channel and hide the budget leak.
            drop(handle);
            assert!(matches!(
                Receive::default().next(&active).await.unwrap().frame,
                Frame::Close { .. }
            ));
            assert!(
                tokio::time::timeout(Duration::from_secs(2), Receive::default().next(&active))
                    .await
                    .unwrap()
                    .is_err()
            );
            drop(active);
            active_retirements += 1;
            assert!(
                tokio::time::timeout(Duration::from_secs(2), Receive::default().next(&parked))
                    .await
                    .expect("detach must close the native shadow binding before the next admission")
                    .is_err()
            );
            drop(parked);
            warm_retirements += 1;
        }
        assert_eq!(active_retirements, 130);
        assert_eq!(warm_retirements, 130);
        bounded_retired_native_counts(&live_endpoint).await;
        bounded_retired_native_counts(&warm_endpoint).await;
        assert!(live_connection.close_reason().is_none());
        assert!(connection.close_reason().is_none());
        return;
    }
    if blocked_primary {
        // The primary advertises a4KiB receive window and stops reading. This
        // bounded2MiB input exceeds the server's1MiB QUIC send buffer.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (input, mut output) = attachment.split();
        let mut wire = Vec::new();
        infraternal_protocol::encode_muxed_frame_into(
            41,
            &Frame::Credit { bytes: 65536 },
            &mut wire,
        )
        .unwrap();
        input.send_frame(Bytes::from(wire)).await.unwrap();
        let payload = vec![b'x'; 2 * 1024 * 1024];
        let mut wire = Vec::new();
        infraternal_protocol::encode_muxed_frame_into(
            41,
            &Frame::Input {
                in_seq: 0,
                bytes: &payload,
            },
            &mut wire,
        )
        .unwrap();
        input.send_frame(Bytes::from(wire)).await.unwrap();
        if late_credit {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut wire = Vec::new();
            infraternal_protocol::encode_muxed_frame_into(
                41,
                &Frame::Credit { bytes: 16 },
                &mut wire,
            )
            .unwrap();
            input.send_frame(Bytes::from(wire)).await.unwrap();
        }
        let control_task = if late_control {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Some(tokio::spawn(async move {
                actor.call("fixture.blocked".into(), vec![b' '; 8192]).await
            }))
        } else {
            None
        };
        let cursor = tokio::time::timeout(
            Duration::from_millis(700),
            terminal_receive.next(&warm_terminal),
        )
        .await
        .expect("secondary must run while the primary write is backpressured")
        .unwrap();
        assert!(matches!(
            cursor.frame,
            Frame::Call {
                action_id: "transport.cursor",
                ..
            }
        ));
        assert!(matches!(
            terminal_receive.next(&warm_terminal).await.unwrap().frame,
            Frame::Credit { .. }
        ));
        let incoming = terminal_receive.next(&warm_terminal).await.unwrap();
        let Frame::Input { in_seq: 0, bytes } = incoming.frame else {
            panic!("retained input on warm writer");
        };
        assert!(bytes.len() <= 16384);
        let acknowledged = bytes.len() as u64;
        Transmit::default()
            .send(
                &warm_terminal,
                42,
                &Frame::Ack {
                    in_seq_acked: acknowledged,
                },
            )
            .await
            .unwrap();
        Transmit::default()
            .send(
                &warm_terminal,
                42,
                &Frame::Output {
                    out_seq: 0,
                    bytes: b"proof",
                },
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop { if matches!(output.recv().await.unwrap(), crate::embedded::TerminalOutput::Output { bytes, .. } if bytes.as_ref() == b"proof") { break; } }
        }).await.unwrap();
        if let Some(task) = control_task {
            task.abort();
            let _ = task.await;
        }
        return;
    }
    if close_primary {
        live_connection.close(0u32.into(), b"fixture primary closed");
        // Let the actor enter its no-primary reconnect wait before activating
        // the connection it already owns; this is no performance assertion.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    transmit
        .send(
            &warm,
            0,
            &Frame::Call {
                call_id: 0,
                action_id: "transport.activate",
                input_json: b"{}",
            },
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while hosts.0.lock().await[&host_id].generation == generation {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(25), async {
            loop {
                // Promotion still sends no greeting. The active route now has
                // ordinary liveness probes, which the fixture must answer.
                let frame = receive.next(&warm).await.unwrap();
                let Frame::Ping { nonce, sent_us } = frame.frame else {
                    break;
                };
                transmit
                    .send(&warm, 0, &Frame::Pong { nonce, sent_us })
                    .await
                    .unwrap();
            }
        })
        .await
        .is_err(),
        "promotion must not send a second greeting"
    );
    assert!(connection.close_reason().is_none());
    // Existing NodeHost handles share this admission slot. Expiring the old
    // certificate must not revoke operations on the newly promoted transport.
    prior_authority.expire_for_test();
    assert!(hosts.0.lock().await[&host_id].authority.permits());
    assert!(
        retained_admission.read().unwrap().permits(),
        "promotion left retained NodeHost handles on the prior certificate"
    );
}

#[path = "remote_control_queue_tests.rs"]
mod control_queue;

#[path = "remote_control_pause_tests.rs"]
mod control_pause;

#[path = "remote_liveness_doubt_tests.rs"]
mod liveness_doubt;
