//! Proves the Mac UDP listener keeps its prebound socket, drops ungranted handshakes and passes
//! installed ones.

use super::super::{
    BoundUdpFactory, PeerAdmission, RwLock, StaticSecret, UdpSocketFactory,
    UdpTransportFactoryParams,
};
use gotatun::udp::UdpTransportFactory;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

/// A reconfigured device reuses the prebound socket, so the advertised port never changes.
#[tokio::test]
async fn prebound_wireguard_socket_keeps_the_advertised_port_on_reconfiguration() {
    let mut factory = UdpSocketFactory::default();
    let params = UdpTransportFactoryParams {
        addr: None,
        port: 0,
    };
    let (send, receive) = factory.bind(&params).await.expect("prebind UDP");
    let port = send.local_addr().expect("UDP address").port();
    let mut bound = BoundUdpFactory {
        send,
        receive,
        port,
        admission: Arc::new(RwLock::new(PeerAdmission::new(StaticSecret::from([7; 32])))),
    };
    let (reused_send, reused_receive) = bound
        .bind(&UdpTransportFactoryParams { addr: None, port })
        .await
        .expect("reuse the prebound UDP socket");
    assert_eq!(reused_send.local_addr().expect("send address").port(), port);
    assert_eq!(
        reused_receive.local_addr().expect("receive address").port(),
        port
    );
}

/// J555 F2 (#483): ungranted keys get no reply on the Mac either.
///
/// J510c answers J534 on Linux with a receive guard that drops MAC1-valid initiations from
/// keys outside the accepted snapshot, so `GotaTun`'s limiter never sends them a cookie. The
/// Mac listener built here hands every datagram straight to `GotaTun`, whose limiter answers
/// the 101st initiation per second from any MAC1-valid sender with a cookie before it looks
/// up the peer. This sends one initiation from a key no snapshot ever named and requires the
/// Mac receive path to drop it, as Linux does.
#[tokio::test]
async fn j555_mac_listener_drops_initiations_from_unknown_keys() {
    use gotatun::{
        noise::{Tunn, index_table::IndexTable, rate_limiter::RateLimiter},
        packet::PacketBufPool,
        udp::UdpRecv as _,
        x25519::{PublicKey as X25519PublicKey, StaticSecret},
    };
    let (mut factory, port) = super::super::bind_udp(
        crate::listen_port::Request {
            port: 0,
            allow_fallback: true,
        },
        StaticSecret::from([0x31; 32]),
    )
    .await
    .expect("listener");
    let (_send, mut receive) = factory
        .bind(&UdpTransportFactoryParams { addr: None, port })
        .await
        .expect("bound listener");
    let node_public = X25519PublicKey::from(&StaticSecret::from([0x31; 32]));
    let stranger = StaticSecret::from([0x55; 32]);
    let stranger_public = X25519PublicKey::from(&stranger);
    let mut initiator = Tunn::new(
        stranger,
        node_public,
        None,
        None,
        IndexTable::from_os_rng(),
        Arc::new(RateLimiter::new(&stranger_public, 100)),
    );
    let initiation = initiator
        .format_handshake_initiation(false)
        .expect("a MAC1-valid initiation from an unknown key")
        .into_bytes()
        .as_ref()
        .to_vec();
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
    sender
        .send_to(&initiation, SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .expect("send initiation");
    let mut pool = PacketBufPool::new(4);
    // sleep: a dropped datagram has no event to wait for; 500 ms on loopback is ample.
    let received = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        receive.recv_from(&mut pool),
    )
    .await;
    assert!(
        received.is_err(),
        "the Mac listener passed an unknown key's initiation to GotaTun's cookie path"
    );
}

/// J648 (#483): the Mac guard admits an installed key, so J555's drop test above cannot pass by
/// dropping everything.
///
/// The worker installs its peers into the listener's guard (`set_peers`) before the device
/// starts and after every accepted apply. This installs one key the same way and requires its
/// MAC1-valid initiation to reach the receive half that `GotaTun` reads.
#[tokio::test]
async fn mac_listener_passes_initiations_from_installed_keys() {
    use gotatun::{
        noise::{Tunn, index_table::IndexTable, rate_limiter::RateLimiter},
        packet::PacketBufPool,
        udp::UdpRecv as _,
        x25519::PublicKey as X25519PublicKey,
    };
    let (mut factory, port) = super::super::bind_udp(
        crate::listen_port::Request {
            port: 0,
            allow_fallback: true,
        },
        StaticSecret::from([0x31; 32]),
    )
    .await
    .expect("listener");
    let peer = StaticSecret::from([0x66; 32]);
    let peer_public = X25519PublicKey::from(&peer);
    factory
        .admission
        .write()
        .await
        .set_peers([crate::policy::model::PublicKey(*peer_public.as_bytes())]);
    let (_send, mut receive) = factory
        .bind(&UdpTransportFactoryParams { addr: None, port })
        .await
        .expect("bound listener");
    let node_public = X25519PublicKey::from(&StaticSecret::from([0x31; 32]));
    let mut initiator = Tunn::new(
        peer,
        node_public,
        None,
        None,
        IndexTable::from_os_rng(),
        Arc::new(RateLimiter::new(&peer_public, 100)),
    );
    let initiation = initiator
        .format_handshake_initiation(false)
        .expect("a MAC1-valid initiation from an installed key")
        .into_bytes()
        .as_ref()
        .to_vec();
    let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("sender");
    sender
        .send_to(&initiation, SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .expect("send initiation");
    let mut pool = PacketBufPool::new(4);
    let (packet, from) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        receive.recv_from(&mut pool),
    )
    .await
    .expect("the Mac listener dropped an installed key's initiation")
    .expect("receive");
    assert_eq!(packet.as_ref(), initiation.as_slice());
    // A dual-stack listener reports an IPv4 sender as IPv4-mapped IPv6.
    assert_eq!(from.ip().to_canonical(), Ipv4Addr::LOCALHOST);
    assert_eq!(
        from.port(),
        sender.local_addr().expect("sender address").port()
    );
}
