//! Verifies parked fallback authority and activation on real mTLS QUIC without replacing the live host actor [64,128,215], #129.
use super::*;
use infraternal_agent::remote_native::NativeChannel;

async fn connect_control(
    address: SocketAddr,
    identity: &Identity,
    root: &X509,
) -> (quinn::Endpoint, quinn::Connection, NativeChannel) {
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(
        remote_quic::client_config(identity, std::slice::from_ref(root)).unwrap(),
    );
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
