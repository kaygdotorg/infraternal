//! Proves that real Mac MTU-only authority refreshes preserve encrypted sessions.

use super::{
    AUTHORITY_EPOCH_A, AUTHORITY_EPOCH_B, Arc, BTreeMap, Command, Duration, Ipv4Addr, Node, NodeId,
    PublicKey, SocketAddr, chunks_with_epoch, config, test_directory, thread, write_key,
};

/// Start a real encrypted loopback peer whose decrypted UDP endpoint echoes each datagram.
/// Only the node has a utun: the remote endpoint uses bounded packet channels so no second
/// host address can accidentally deliver traffic outside the encrypted tunnel.
fn mtu_echo_peer(
    local_key: PublicKey,
    local_address: Ipv4Addr,
    peer_address: Ipv4Addr,
) -> (
    PublicKey,
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    thread::JoinHandle<()>,
) {
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let join = thread::spawn(move || {
        use gotatun::{
            device::{DeviceBuilder, Peer},
            packet::PacketBufPool,
            tun::{MtuWatcher, channel::new_udp_tun_channel},
            udp::{
                UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams,
                socket::UdpSocketFactory,
            },
            x25519::{PublicKey as XKey, StaticSecret},
        };
        super::super::RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let secret = StaticSecret::from([47_u8; 32]);
                let key = PublicKey(*XKey::from(&secret).as_bytes());
                let (tx, rx, mut app) = new_udp_tun_channel(
                    64,
                    peer_address,
                    "fd47::4".parse().unwrap(),
                    MtuWatcher::new(1280),
                );
                let (send, mut recv) = app
                    .bind(&UdpTransportFactoryParams {
                        addr: None,
                        port: 4287,
                    })
                    .await
                    .unwrap();
                let device = DeviceBuilder::new()
                    .with_udp(UdpSocketFactory::default())
                    .with_private_key(secret)
                    .with_listen_port(0)
                    .with_ip_pair(tx, rx)
                    .with_peers(vec![Peer::new(XKey::from(local_key.0)).with_allowed_ips(
                        vec![ipnetwork::IpNetwork::new(local_address.into(), 32).unwrap()],
                    )])
                    .build()
                    .await
                    .unwrap();
                let port = device.read(async |read| read.listen_port()).await;
                ready_tx
                    .send((key, SocketAddr::from(([127, 0, 0, 1], port))))
                    .unwrap();
                let mut pool = PacketBufPool::new(0);
                tokio::pin!(stop_rx);
                loop {
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        packet = recv.recv_from(&mut pool) => {
                            let (packet, source) = packet.unwrap();
                            send.send_to(packet, source).await.unwrap();
                        }
                    }
                }
                device.stop().await;
            });
    });
    let (key, endpoint) = ready_rx.recv().unwrap();
    (key, endpoint, stop_tx, join)
}

/// An MTU-only authority refresh must preserve established peers and encrypted traffic.
#[test]
#[ignore = "Run on the macOS VM with system service privileges under the mesh lock."]
fn mtu_only_authority_refresh_keeps_peer_sessions() {
    use std::sync::atomic::Ordering;
    let directory = test_directory();
    write_key(&directory);
    let mut node = Node::restore(&directory.0, None).expect("restore isolated node");
    let identity = node.up().expect("start isolated node");
    let mut current = config();
    current.local_key = Some(identity.public_key);
    current.addresses.ipv4 = "10.253.47.1".parse().unwrap();
    current.addresses.ipv6 = "fd47::1".parse().unwrap();
    current
        .peers
        .get_mut(&NodeId(4))
        .unwrap()
        .peer
        .addresses
        .ipv4 = "10.253.47.4".parse().unwrap();
    current
        .peers
        .get_mut(&NodeId(4))
        .unwrap()
        .peer
        .addresses
        .ipv6 = "fd47::4".parse().unwrap();
    #[cfg(feature = "mesh-dns")]
    {
        current.dns_suffix = "j472.invalid".to_owned();
    }
    let (key, endpoint, stop, remote) = mtu_echo_peer(
        identity.public_key,
        current.addresses.ipv4,
        current.peers[&NodeId(4)].peer.addresses.ipv4,
    );
    let peer = &mut current.peers.get_mut(&NodeId(4)).unwrap().peer;
    peer.key = key;
    peer.endpoint = Some(endpoint);
    for chunk in chunks_with_epoch(None, &current, AUTHORITY_EPOCH_A) {
        node.chunk(chunk).expect("install original snapshot");
    }
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let finished = done.clone();
    let (running_tx, running_rx) = std::sync::mpsc::sync_channel(1);
    let local = current.addresses.ipv4;
    let peer = current.peers[&NodeId(4)].peer.addresses.ipv4;
    let traffic = thread::spawn(move || {
        let socket = std::net::UdpSocket::bind((local, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket.connect((peer, 4287)).unwrap();
        let mut count = 0_u64;
        while count < 200 || !finished.load(Ordering::SeqCst) {
            let payload = count.to_be_bytes();
            socket.send(&payload).unwrap();
            let mut reply = [0_u8; 8];
            assert_eq!(socket.recv(&mut reply).unwrap(), payload.len());
            assert_eq!(reply, payload);
            count += 1;
            if count == 20 {
                running_tx.send(()).unwrap();
            }
        }
        count
    });
    running_rx.recv().unwrap();
    let before = super::super::J472_REBUILDS.load(Ordering::SeqCst);
    let mut replacement = current.clone();
    replacement.authority_epoch = Some(AUTHORITY_EPOCH_B.to_owned());
    let mut budgets = super::super::PathBudgets::probe(Some(&replacement));
    // Simulate the caller's successful re-probe after its underlay path budget changed.
    for mtu in budgets.route_mtus.values_mut() {
        *mtu -= 16;
    }
    budgets.interface_mtu = if budgets.interface_mtu > 1280 {
        budgets.interface_mtu - 16
    } else {
        budgets.interface_mtu + 16
    };
    let expected_budgets = budgets.clone();
    let (reply, result) = std::sync::mpsc::sync_channel(1);
    node.worker
        .as_ref()
        .unwrap()
        .commands
        .send(super::super::WorkerCommand::ReplaceAuthority {
            config: Box::new(replacement),
            budgets,
            reply,
        })
        .expect("send MTU-only replacement");
    let applied = result.recv().expect("receive apply result");
    let after = super::super::J472_REBUILDS.load(Ordering::SeqCst);
    let peers = node.counters().expect("installed peers").len();
    let metrics = applied.as_ref().ok().map(|info| {
        let output = Command::new("/sbin/ifconfig")
            .arg(&info.interface)
            .output()
            .unwrap();
        let interface_mtu =
            crate::mesh_mtu::parse_macos_interface_mtu(&String::from_utf8_lossy(&output.stdout))
                .unwrap();
        let route_mtus: BTreeMap<_, _> = expected_budgets
            .route_mtus
            .keys()
            .map(|address| {
                let output = Command::new("/sbin/route")
                    .args([
                        "-n",
                        "get",
                        if address.is_ipv4() { "-inet" } else { "-inet6" },
                        &address.to_string(),
                    ])
                    .output()
                    .unwrap();
                let (mtu, interface) =
                    crate::mesh_mtu::parse_macos_route(&String::from_utf8_lossy(&output.stdout))
                        .unwrap();
                assert_eq!(interface, info.interface);
                (*address, u16::try_from(mtu).unwrap())
            })
            .collect();
        (interface_mtu, route_mtus)
    });
    done.store(true, Ordering::SeqCst);
    let packets = traffic.join();
    let _ = stop.send(());
    remote.join().unwrap();
    node.down()
        .expect("remove isolated routes, resolver and utun");
    let packets = packets.expect("encrypted echo traffic survives refresh");
    eprintln!("MTU_TRAFFIC_SENT={packets} RECEIVED={packets} LOST=0");
    eprintln!(
        "J472_MTU_APPLY_OK={} PEERS={peers} PEER_REBUILDS={}",
        applied.is_ok(),
        after - before
    );
    assert!(applied.is_ok());
    let (interface_mtu, route_mtus) = metrics.unwrap();
    assert_eq!(interface_mtu, u32::from(expected_budgets.interface_mtu));
    assert_eq!(route_mtus, expected_budgets.route_mtus);
    eprintln!("MTU_INTERFACE={interface_mtu} ROUTE_MTUS={route_mtus:?}");
    assert_eq!(
        after, before,
        "MTU-only authority refresh cleared and recreated peers"
    );
}
