//! Real quinn relay on loopback: token links, unchanged forwarding, refusals, replacement and probes [313, D402].
#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use bytes::{BufMut, Bytes, BytesMut};
use infraternal_plugin_relay::{
    client::{Client, Notices},
    probe,
    relay::{Admission, Limits, Relay},
    testing::{Authority, Purpose},
    tls,
    wire::{HostId, LinkId, Notice, Token},
};
use std::{net::SocketAddr, sync::Arc, time::Duration};

const NAME: &str = "relay-1.mesh.test";
const WAIT: Duration = Duration::from_secs(5);

/// A host id made of one repeated byte.
fn host(byte: u8) -> HostId {
    HostId([byte; 16])
}

/// The token the pair of hosts `a` and `b` would derive; any value both ends share works.
fn token(a: u8, b: u8) -> Token {
    Token([a.min(b) << 4 | a.max(b); 16])
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

/// Both clients ask for `pair`; returns the link id after both got the same `Linked` notice.
async fn linked(a: &Client, an: &mut Notices, b: &Client, bn: &mut Notices, pair: Token) -> LinkId {
    a.link(pair).await.unwrap();
    b.link(pair).await.unwrap();
    let Notice::Linked { token, id } = notice(an).await else {
        panic!("a not linked");
    };
    assert_eq!(token, pair);
    assert_eq!(notice(bn).await, Notice::Linked { token: pair, id });
    id
}

/// Two hosts with one token exchange datagrams unchanged; a third host cannot join or inject.
#[tokio::test]
async fn linked_hosts_exchange_unchanged_datagrams_and_others_cannot_inject() {
    let mut ca = Authority::new();
    let relay = relay(&mut ca, everyone());
    let address = relay.local_addr().unwrap();
    let (a, mut an) = client(&mut ca, address, host(1)).await;
    let (b, mut bn) = client(&mut ca, address, host(2)).await;
    let (c, mut cn) = client(&mut ca, address, host(3)).await;
    let id = linked(&a, &mut an, &b, &mut bn, token(1, 2)).await;

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

    // C asks for a token A never asked for, and for the A-B token itself
    // (which two hosts already hold): no link either way, and C's guess of the
    // A-B id is dropped rather than delivered to either end.
    c.link(token(1, 3)).await.unwrap();
    c.link(token(1, 2)).await.unwrap();
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

/// Unlink, a replacing connection and a disconnect each end the link for the other end.
#[tokio::test]
async fn unlink_and_disconnect_end_the_link_for_the_other_end() {
    let mut ca = Authority::new();
    let relay = relay(&mut ca, everyone());
    let address = relay.local_addr().unwrap();
    let (a, mut an) = client(&mut ca, address, host(1)).await;
    let (b, mut bn) = client(&mut ca, address, host(2)).await;
    let pair = token(1, 2);
    let id = linked(&a, &mut an, &b, &mut bn, pair).await;
    a.unlink(pair).await.unwrap();
    assert_eq!(notice(&mut bn).await, Notice::Unlinked { token: pair });
    assert_eq!(notice(&mut an).await, Notice::Unlinked { token: pair });
    b.connection().send_datagram(frame(id, b"late")).unwrap();

    // B's request is still pending: A asking again links with a fresh id.
    a.link(pair).await.unwrap();
    let Notice::Linked { id: second, .. } = notice(&mut an).await else {
        panic!("not relinked");
    };
    assert_ne!(second, id);
    assert_eq!(
        notice(&mut bn).await,
        Notice::Linked {
            token: pair,
            id: second
        }
    );

    // A replacement connection for B ends the old link; B's new request relinks.
    let (b2, mut b2n) = client(&mut ca, address, host(2)).await;
    assert_eq!(notice(&mut an).await, Notice::Unlinked { token: pair });
    assert!(
        tokio::time::timeout(WAIT, bn.next())
            .await
            .unwrap()
            .is_none(),
        "old B closed"
    );
    b2.link(pair).await.unwrap();
    let Notice::Linked { id: third, .. } = notice(&mut b2n).await else {
        panic!("replacement not linked");
    };
    assert_eq!(
        notice(&mut an).await,
        Notice::Linked {
            token: pair,
            id: third
        }
    );

    b2.close();
    assert_eq!(notice(&mut an).await, Notice::Unlinked { token: pair });
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

/// Hosts without admission or a host URI, foreign CAs and relays without a relay leaf are refused.
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
    // A server-purpose leaf with the right name but no relay URI (the server's leg-B kind)
    // is refused too: only a relay leaf may serve relay connections (D402 Q3).
    let server_leaf = Relay::start(
        "127.0.0.1:0".parse().unwrap(),
        ca.issue(Purpose::Server(NAME)),
        Limits::default(),
        everyone(),
    )
    .unwrap();
    let config = tls::client_config(ca.issue(Purpose::Host(host(1)))).unwrap();
    assert!(
        Client::connect(
            &endpoint,
            config,
            server_leaf.local_addr().unwrap(),
            NAME,
            WAIT
        )
        .await
        .is_err(),
        "a leaf without the relay URI served a relay connection"
    );
    assert_eq!(relay.stats().hosts, 0);
    relay.close().await;
    impostor.close().await;
    server_leaf.close().await;
}

/// A host revoked after its handshake is closed by `recheck`, and its link ends for the
/// other end too; a host still admitted keeps its connection (D402 Q3).
#[tokio::test]
async fn recheck_closes_a_host_revoked_after_its_handshake() {
    let mut ca = Authority::new();
    let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let admission: Admission = {
        let revoked = revoked.clone();
        Arc::new(move |candidate| {
            candidate != host(2) || !revoked.load(std::sync::atomic::Ordering::SeqCst)
        })
    };
    let relay = relay(&mut ca, admission);
    let address = relay.local_addr().unwrap();
    let (a, mut an) = client(&mut ca, address, host(1)).await;
    let (b, mut bn) = client(&mut ca, address, host(2)).await;
    let pair = token(1, 2);
    linked(&a, &mut an, &b, &mut bn, pair).await;
    relay.recheck();
    assert_eq!(relay.stats().hosts, 2, "nothing changed, nobody is closed");
    revoked.store(true, std::sync::atomic::Ordering::SeqCst);
    relay.recheck();
    assert_eq!(notice(&mut an).await, Notice::Unlinked { token: pair });
    assert!(
        tokio::time::timeout(WAIT, bn.next())
            .await
            .unwrap()
            .is_none(),
        "the revoked host's connection is closed"
    );
    assert_eq!(relay.stats().hosts, 1);
    relay.close().await;
}

/// A host revoked while the control hello is pending must not register afterward (D402 Q3).
#[tokio::test]
async fn revocation_during_control_hello_must_refuse_host() {
    let mut ca = Authority::new();
    let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let admission: Admission = {
        let revoked = revoked.clone();
        Arc::new(move |candidate| {
            candidate != host(2) || !revoked.load(std::sync::atomic::Ordering::SeqCst)
        })
    };
    let relay = relay(&mut ca, admission);
    let address = relay.local_addr().unwrap();
    let (_endpoint, connection) = stalled_client(&mut ca, address, host(2))
        .await
        .expect("the host completes TLS before revocation");
    let (mut hello, _notices) = connection.open_bi().await.unwrap();
    // sleep: let serve accept the stream and wait for its IFR2 bytes.
    tokio::time::sleep(Duration::from_millis(100)).await;

    revoked.store(true, std::sync::atomic::Ordering::SeqCst);
    relay.recheck();
    hello.write_all(b"IFR2").await.unwrap();

    tokio::time::timeout(WAIT, connection.closed())
        .await
        .expect("the newly revoked host is closed");
    assert_eq!(relay.stats().hosts, 0, "revoked host was registered");
    relay.close().await;
}

/// Credentials parsed from the PEM layout the server's leaf files use serve relay
/// connections; a key that does not match the leaf is refused.
#[tokio::test]
async fn credentials_from_pem_serve_and_a_mismatched_key_is_refused() {
    let mut ca = Authority::new();
    let (certificate, key) = ca.issue_pem(Purpose::Relay(NAME));
    let root = ca.pem();
    let credentials =
        tls::Credentials::from_pem(&format!("{certificate}{key}"), &[root.clone()]).unwrap();
    let relay = Relay::start(
        "127.0.0.1:0".parse().unwrap(),
        credentials,
        Limits::default(),
        everyone(),
    )
    .unwrap();
    let (_client, _notices) = client(&mut ca, relay.local_addr().unwrap(), host(1)).await;
    let (_, other_key) = ca.issue_pem(Purpose::Relay(NAME));
    assert!(tls::Credentials::from_pem(&format!("{certificate}{other_key}"), &[root]).is_err());
    assert!(tls::Credentials::from_pem(&format!("{certificate}{key}"), &[]).is_err());
    relay.close().await;
}
