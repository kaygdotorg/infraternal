//! The Mac node's use of `GotaTun`'s second ("side") UDP socket (#260, J1211, J1256): which
//! peers are opted in, and what the product's socket factory binds on macOS.
//!
//! The Linux node has the same two rules and its own tests. They are repeated here because the
//! Mac node builds its peers and sockets with its own code: the factory adds the handshake
//! admission guard and the connected-send choice, and macOS binds each port as an IPv4 and an
//! IPv6 socket. None of these tests needs root or a utun.

use super::config;
use crate::{
    dataplane::PeerPolicy,
    handshake_admission::PeerAdmissionUdpReceiver,
    listen_port::Request,
    policy::model::{NodeId, PublicKey},
};
use gotatun::{
    packet::{Packet, PacketBufPool},
    udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
    x25519::StaticSecret,
};
use std::{net::SocketAddr, time::Duration};

/// A peer is opted in to the second socket only when its node advertised the capability and this
/// node's own switch is on; every other peer, including both rotation identities of one, gets an
/// explicit "no", so the engine never marks a datagram to a peer that did not say it takes them
/// (kernel `WireGuard` and plain `GotaTun` drop marked packets).
#[test]
fn only_advertising_peers_are_opted_in_while_the_switch_is_on() {
    let mut config = config();
    let policy = config.peers.get_mut(&NodeId(4)).expect("the peer");
    let opted = |policy: &PeerPolicy, on: bool| -> Vec<Option<bool>> {
        super::super::peer_for_policy_with(policy, on)
            .expect("peer")
            .iter()
            .map(|peer| peer.side_port)
            .collect()
    };
    assert_eq!(
        opted(policy, true),
        [Some(false)],
        "no advertisement, no mark"
    );
    assert_eq!(opted(policy, false), [Some(false)]);
    policy.peer.side_port = true;
    assert_eq!(opted(policy, true), [Some(true)], "advertised and on");
    assert_eq!(
        opted(policy, false),
        [Some(false)],
        "this node's switch off beats the advertisement"
    );
    // Both identities of a peer mid-rotation follow the same rule.
    policy.peer.previous_key = Some(PublicKey([9; 32]));
    assert_eq!(opted(policy, true), [Some(true), Some(true)]);
    policy.peer.side_port = false;
    assert_eq!(opted(policy, true), [Some(false), Some(false)]);
}

/// A `WireGuard` data datagram of `len` bytes: the message type and zeroes.
fn data(len: usize) -> Packet {
    let mut bytes = vec![0_u8; len];
    bytes[0] = 4;
    Packet::from_bytes(bytes.as_slice().into())
}

/// The next datagram a device receive half hands on, with its source.
async fn receive(receiver: &mut PeerAdmissionUdpReceiver) -> (usize, SocketAddr) {
    let mut pool = PacketBufPool::new(4);
    let (packet, source) =
        tokio::time::timeout(Duration::from_secs(5), receiver.recv_from(&mut pool))
            .await
            .expect("a datagram arrives")
            .expect("receive");
    (packet.len(), source)
}

/// The product's factory (connected sends as shipped) binds a second socket on its own port; on
/// both address families a datagram sent from it leaves that port, so the sending Mac's queue
/// sees it as a flow of its own, and a datagram that reaches that port comes through its receive
/// half. A request for any other mesh port is refused.
#[tokio::test]
async fn the_factory_binds_a_second_socket_with_its_own_flow() {
    let (mut factory, port) = super::super::bind_udp(
        Request {
            port: 0,
            allow_fallback: true,
        },
        StaticSecret::from([4; 32]),
    )
    .await
    .expect("bound engine socket");
    let params = UdpTransportFactoryParams { addr: None, port };
    let (main, _main_receiver) = factory.bind(&params).await.expect("main sockets");
    let (side, mut side_receiver) = factory
        .bind_side(&main, &params)
        .await
        .expect("side socket binds")
        .expect("the engine factory has a second socket");
    let side_port = side.local_addr().expect("side address").port();
    assert_ne!(side_port, 0);
    assert_ne!(side_port, port, "its own port");

    for loopback in ["127.0.0.1:0", "[::1]:0"] {
        let far = tokio::net::UdpSocket::bind(loopback)
            .await
            .expect("far end");
        let far_address = far.local_addr().expect("far address");
        side.send_to(data(96), far_address)
            .await
            .expect("send from the side socket");
        let mut buffer = [0_u8; 256];
        let (length, from) =
            tokio::time::timeout(Duration::from_secs(5), far.recv_from(&mut buffer))
                .await
                .expect("the datagram arrives")
                .expect("receive");
        assert_eq!((length, from.port()), (96, side_port), "{loopback}");

        let side_address = SocketAddr::new(far_address.ip(), side_port);
        far.send_to(&buffer[..length], side_address)
            .await
            .expect("send to the side port");
        assert_eq!(
            receive(&mut side_receiver).await,
            (96, far_address),
            "{loopback}"
        );
    }

    let wrong = UdpTransportFactoryParams {
        addr: None,
        port: port.wrapping_add(1),
    };
    assert!(factory.bind_side(&main, &wrong).await.is_err());
}
