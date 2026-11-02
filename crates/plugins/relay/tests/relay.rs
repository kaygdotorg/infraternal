//! Real quinn relay on loopback: mutual links, unchanged forwarding, refusals, replacement and probes [313].
#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use bytes::{BufMut, Bytes, BytesMut};
use infraternal_plugin_relay::{
    client::{Client, Notices},
    probe,
    relay::{Admission, Limits, Relay},
    testing::{Authority, Purpose},
    tls,
    wire::{HostId, LinkId, Notice},
};
use std::{net::SocketAddr, sync::Arc, time::Duration};

const NAME: &str = "relay-1.mesh.test";
const WAIT: Duration = Duration::from_secs(5);

fn host(byte: u8) -> HostId {
    HostId([byte; 16])
}

fn everyone() -> Admission {
    Arc::new(|_| true)
}

fn relay(ca: &mut Authority, admission: Admission) -> Relay {
    Relay::start(
        "127.0.0.1:0".parse().unwrap(),
        ca.issue(Purpose::Relay(NAME)),
        Limits::default(),
        admission,
    )
    .unwrap()
}

async fn client(ca: &mut Authority, relay: SocketAddr, id: HostId) -> (Client, Notices) {
    let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let config = tls::client_config(ca.issue(Purpose::Host(id))).unwrap();
    Client::connect(&endpoint, config, relay, NAME, WAIT)
        .await
        .unwrap()
}

async fn stalled_client(
    ca: &mut Authority,
    relay: SocketAddr,
    id: HostId,
) -> Option<(quinn::Endpoint, quinn::Connection)> {
    let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let config = tls::client_config(ca.issue(Purpose::Host(id))).unwrap();
    let connection = endpoint
        .connect_with(config, relay, NAME)
        .ok()?
        .await
        .ok()?;
    Some((endpoint, connection))
}

async fn notice(notices: &mut Notices) -> Notice {
    tokio::time::timeout(WAIT, notices.next())
        .await
        .expect("notice in time")
        .expect("relay still connected")
}

fn frame(id: LinkId, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(4 + payload.len());
    out.put_u32(id.0);
    out.put_slice(payload);
    out.freeze()
}

async fn linked(
    a: &Client,
    an: &mut Notices,
    b: &Client,
    bn: &mut Notices,
    ids: (HostId, HostId),
) -> LinkId {
    a.link(ids.1).await.unwrap();
    b.link(ids.0).await.unwrap();
    let Notice::Linked { peer, id } = notice(an).await else {
        panic!("a not linked");
    };
    assert_eq!(peer, ids.1);
    assert_eq!(notice(bn).await, Notice::Linked { peer: ids.0, id });
    id
}

#[tokio::test]
async fn linked_hosts_exchange_unchanged_datagrams_and_others_cannot_inject() {
    let mut ca = Authority::new();
    let relay = relay(&mut ca, everyone());
    let address = relay.local_addr().unwrap();
    let (a, mut an) = client(&mut ca, address, host(1)).await;
    let (b, mut bn) = client(&mut ca, address, host(2)).await;
    let (c, mut cn) = client(&mut ca, address, host(3)).await;
    let id = linked(&a, &mut an, &b, &mut bn, (host(1), host(2))).await;

    a.connection().send_datagram(frame(id, &[])).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), b.connection().read_datagram())
            .await
            .is_err(),
        "header-only datagram was relayed"
    );

    for size in [1, 92, 148, 1000] {
        let payload: Vec<u8> = (0..size).map(|i| u8::try_from(i % 251).unwrap()).collect();
        a.connection().send_datagram(frame(id, &payload)).unwrap();
        let got = tokio::time::timeout(WAIT, b.connection().read_datagram())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, frame(id, &payload), "a to b, {size} bytes");
        b.connection().send_datagram(frame(id, &payload)).unwrap();
        let got = tokio::time::timeout(WAIT, a.connection().read_datagram())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, frame(id, &payload), "b to a, {size} bytes");
    }

    // C asks for A, but A never asked for C: no link, and C's guess of the
    // A-B id is dropped rather than delivered to either end.
    c.link(host(1)).await.unwrap();
    c.connection()
        .send_datagram(frame(id, b"injected"))
        .unwrap();
    c.connection()
        .send_datagram(frame(LinkId(id.0 + 1), b"injected"))
        .unwrap();
    a.connection().send_datagram(frame(id, b"after")).unwrap();
    let got = tokio::time::timeout(WAIT, b.connection().read_datagram())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, frame(id, b"after"));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), cn.next())
            .await
            .is_err()
    );
    let stats = relay.stats();
    assert_eq!((stats.hosts, stats.links), (3, 1));
    assert_eq!(stats.forwarded, 9);
    assert!(stats.dropped >= 3, "{stats:?}");
    relay.close().await;
}

#[tokio::test]
async fn relay_bounds_stalled_handshakes_from_one_source_ip() {
    let mut ca = Authority::new();
    let relay = relay(&mut ca, everyone());
    let address = relay.local_addr().unwrap();
    let mut stalled = Vec::new();

    for index in 1..=9 {
        match stalled_client(&mut ca, address, host(index)).await {
            Some(connection) => stalled.push(connection),
            None => break,
        }
    }

    assert_eq!(
        stalled.len(),
        8,
        "the ninth pre-hello handshake was admitted"
    );
    assert_eq!(relay.stats().hosts, 0, "stalled clients were registered");
    for (_, connection) in stalled {
        connection.close(quinn::VarInt::from_u32(0), b"test finished");
    }
    relay.close().await;
}

#[tokio::test]
async fn stalled_control_hello_times_out_and_releases_its_permit() {
    let mut ca = Authority::new();
    let handshake = Duration::from_millis(500);
    let limits = Limits {
        handshakes: 1,
        handshakes_per_ip: 1,
        handshake,
        ..Limits::default()
    };
    let relay = Relay::start(
        "127.0.0.1:0".parse().unwrap(),
        ca.issue(Purpose::Relay(NAME)),
        limits,
        everyone(),
    )
    .unwrap();
    let address = relay.local_addr().unwrap();
    let (_first_endpoint, first) = stalled_client(&mut ca, address, host(1))
        .await
        .expect("first stalled client completed its QUIC handshake");

    let started = tokio::time::Instant::now();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), first.closed())
            .await
            .is_ok(),
        "relay kept a pre-auth control hello open past its deadline"
    );
    assert!(
        started.elapsed() >= handshake,
        "relay closed a stalled hello before its configured deadline"
    );

    let Some((second_endpoint, second)) = stalled_client(&mut ca, address, host(2)).await else {
        panic!("timed-out control hello did not release its pre-auth permit");
    };
    second.close(quinn::VarInt::from_u32(0), b"test finished");
    drop(second_endpoint);
    relay.close().await;
}

#[tokio::test]
async fn unlink_and_disconnect_end_the_link_for_the_other_end() {
    let mut ca = Authority::new();
    let relay = relay(&mut ca, everyone());
    let address = relay.local_addr().unwrap();
    let (a, mut an) = client(&mut ca, address, host(1)).await;
    let (b, mut bn) = client(&mut ca, address, host(2)).await;
    let id = linked(&a, &mut an, &b, &mut bn, (host(1), host(2))).await;
    a.unlink(host(2)).await.unwrap();
    assert_eq!(notice(&mut bn).await, Notice::Unlinked { peer: host(1) });
    assert_eq!(notice(&mut an).await, Notice::Unlinked { peer: host(2) });
    b.connection().send_datagram(frame(id, b"late")).unwrap();

    // B's request is still pending: A asking again links with a fresh id.
    a.link(host(2)).await.unwrap();
    let Notice::Linked { id: second, .. } = notice(&mut an).await else {
        panic!("not relinked");
    };
    assert_ne!(second, id);
    assert_eq!(
        notice(&mut bn).await,
        Notice::Linked {
            peer: host(1),
            id: second
        }
    );

    // A replacement connection for B ends the old link; B's new request relinks.
    let (b2, mut b2n) = client(&mut ca, address, host(2)).await;
    assert_eq!(notice(&mut an).await, Notice::Unlinked { peer: host(2) });
    assert!(
        tokio::time::timeout(WAIT, bn.next())
            .await
            .unwrap()
            .is_none(),
        "old B closed"
    );
    b2.link(host(1)).await.unwrap();
    let Notice::Linked { id: third, .. } = notice(&mut b2n).await else {
        panic!("replacement not linked");
    };
    assert_eq!(
        notice(&mut an).await,
        Notice::Linked {
            peer: host(2),
            id: third
        }
    );

    b2.close();
    assert_eq!(notice(&mut an).await, Notice::Unlinked { peer: host(2) });
    relay.close().await;
    assert!(
        tokio::time::timeout(WAIT, an.next())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn probes_from_an_enrolled_connection_learn_their_source() {
    let mut ca = Authority::new();
    let relay = relay(&mut ca, everyone());
    let address = relay.local_addr().unwrap();
    let (a, _an) = client(&mut ca, address, host(1)).await;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transaction = probe::transaction().unwrap();
    socket
        .send_to(&a.probe_key().request(transaction), address)
        .await
        .unwrap();
    let mut buf = [0; 256];
    let (len, from) = tokio::time::timeout(WAIT, socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, address);
    assert_eq!(
        a.probe_key().reply(&buf[..len]),
        Some((transaction, socket.local_addr().unwrap()))
    );
    // A forged probe gets nothing; the relay connection is unaffected.
    let mut forged = a.probe_key().request(transaction);
    forged[20] ^= 1;
    socket.send_to(&forged, address).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), socket.recv_from(&mut buf))
            .await
            .is_err()
    );
    let stats = relay.stats();
    assert_eq!((stats.probes_answered, stats.probes_refused), (1, 1));
    assert_eq!(stats.hosts, 1);
    relay.close().await;
}

#[tokio::test]
async fn identities_without_admission_host_or_purpose_are_refused() {
    let mut ca = Authority::new();
    let relay = relay(&mut ca, Arc::new(|host| host != HostId([9; 16])));
    let address = relay.local_addr().unwrap();
    let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let refused = |credentials| {
        let config = tls::client_config(credentials).unwrap();
        let endpoint = endpoint.clone();
        async move {
            match Client::connect(&endpoint, config, address, NAME, WAIT).await {
                Err(_) => true,
                // The relay closes after the handshake: the notices end at once.
                Ok((_, mut notices)) => tokio::time::timeout(WAIT, notices.next())
                    .await
                    .unwrap()
                    .is_none(),
            }
        }
    };
    assert!(
        refused(ca.issue(Purpose::Host(host(9)))).await,
        "not admitted"
    );
    // A relay leaf as a client has no host URI and the wrong purpose.
    assert!(
        refused(ca.issue(Purpose::Relay("other.mesh.test"))).await,
        "no host"
    );
    // Another deployment's host leaf does not chain to this CA.
    let mut other = Authority::new();
    let mut foreign = other.issue(Purpose::Host(host(1)));
    foreign.roots = ca.issue(Purpose::Host(host(1))).roots;
    assert!(refused(foreign).await, "foreign CA");
    // A relay presenting a host (client-purpose) leaf is refused by the node.
    let impostor = Relay::start(
        "127.0.0.1:0".parse().unwrap(),
        ca.issue(Purpose::Host(host(5))),
        Limits::default(),
        everyone(),
    )
    .unwrap();
    let config = tls::client_config(ca.issue(Purpose::Host(host(1)))).unwrap();
    assert!(
        Client::connect(
            &endpoint,
            config,
            impostor.local_addr().unwrap(),
            NAME,
            WAIT
        )
        .await
        .is_err()
    );
    assert_eq!(relay.stats().hosts, 0);
    relay.close().await;
    impostor.close().await;
}
