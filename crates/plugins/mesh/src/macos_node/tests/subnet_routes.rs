//! Real-Mac proof of the subnet-route client (D197 M3, #580), run as root on the Mac VM under
//! its lock.
//!
//! The Mac runs its real node: a kernel utun, the `GotaTun` device, the shared packet filter and
//! the route plan. The router is a second, in-process `GotaTun` device on loopback whose far side
//! plays the router's LAN: it answers ICMP echo for any address in [`LAN`], from that address, the
//! way a host behind a real router would after forwarding. A Linux router node reachable from the
//! Mac VM over the mesh is not available here (see #580, J1169); the Linux router's own half
//! (forwarding, masquerade) is proven by `tests/subnet_routes.rs` in a namespace.
//!
//! Nothing is ever sent before `route get` proves the destination goes into our utun, so no
//! probe can leave the Mac through its default route.
use super::{
    AUTHORITY_EPOCH_A, Arc, Command, Ipv4Addr, Node, NodeId, PublicKey, SocketAddr,
    chunks_with_epoch, config, test_directory, thread, write_key,
};
use crate::dataplane::{PeerNetworks, ReachableNetwork};
use crate::policy::{networks::Network, rules::TrafficPolicy};
use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
};
use std::{io, sync::Mutex};
use tokio::sync::mpsc;

/// The router's LAN: private space, so the same network is valid for the user-mode helper.
const LAN: &str = "10.77.0.0/24";
/// A host on that LAN.
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 5);

/// The router device's side of its LAN: decrypted packets from the Mac go to the LAN host task.
struct LanTx(mpsc::Sender<Vec<u8>>);

impl IpSend for LanTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let bytes = packet.into_bytes();
        self.0
            .send(bytes.as_ref().to_vec())
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}

/// The LAN host's replies, read by the router device and encrypted back to the Mac.
struct LanRx {
    replies: mpsc::Receiver<Vec<u8>>,
    mtu: MtuWatcher,
}

impl IpRecv for LanRx {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let bytes = self.replies.recv().await.ok_or(io::ErrorKind::BrokenPipe)?;
        let mut packet = pool.get();
        packet[..bytes.len()].copy_from_slice(&bytes);
        packet.truncate(bytes.len());
        let packet = packet
            .try_into_ip()
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok(std::iter::once(packet))
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}

/// Turn an IPv4 ICMP echo request to a LAN address into its reply, as that host would send it.
/// Swapping the addresses keeps the IPv4 header checksum; the ICMP checksum is recomputed.
fn echo_reply(request: &[u8], lan: Network) -> Option<Vec<u8>> {
    let header = usize::from(request.first()? & 0x0f) * 4;
    if request.first()? >> 4 != 4 || request.get(9) != Some(&1) || request.len() < header + 8 {
        return None;
    }
    let destination = Ipv4Addr::new(request[16], request[17], request[18], request[19]);
    if request[header] != 8 || !lan.contains(destination.into()) {
        return None;
    }
    let mut reply = request.to_vec();
    reply[12..16].copy_from_slice(&request[16..20]);
    reply[16..20].copy_from_slice(&request[12..16]);
    reply[header] = 0;
    reply[header + 2..header + 4].copy_from_slice(&[0, 0]);
    let mut sum = 0_u32;
    for pair in reply[header..].chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !u16::try_from(sum).unwrap_or(0);
    reply[header + 2..header + 4].copy_from_slice(&checksum.to_be_bytes());
    Some(reply)
}

/// Start the in-process router: a `GotaTun` device on loopback that accepts the Mac's mesh
/// address, and a LAN host that answers echo requests. Returns its key, its endpoint, the
/// sources of the requests it saw, a stop switch and the thread.
#[allow(clippy::type_complexity)]
fn lan_router(
    mac_key: PublicKey,
    mac_address: Ipv4Addr,
) -> (
    PublicKey,
    SocketAddr,
    Arc<Mutex<Vec<Ipv4Addr>>>,
    tokio::sync::oneshot::Sender<()>,
    thread::JoinHandle<()>,
) {
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sources = Arc::clone(&seen);
    let join = thread::spawn(move || {
        use gotatun::{
            device::{DeviceBuilder, Peer},
            udp::socket::UdpSocketFactory,
            x25519::{PublicKey as XKey, StaticSecret},
        };
        super::super::RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let secret = StaticSecret::from([77_u8; 32]);
                let key = PublicKey(*XKey::from(&secret).as_bytes());
                let (to_lan, mut from_mac) = mpsc::channel::<Vec<u8>>(64);
                let (to_device, replies) = mpsc::channel::<Vec<u8>>(64);
                let device = DeviceBuilder::new()
                    .with_udp(UdpSocketFactory::default())
                    .with_private_key(secret)
                    .with_listen_port(0)
                    .with_ip_pair(
                        LanTx(to_lan),
                        LanRx {
                            replies,
                            mtu: MtuWatcher::new(1280),
                        },
                    )
                    .with_peers(vec![Peer::new(XKey::from(mac_key.0)).with_allowed_ips(
                        vec![ipnetwork::IpNetwork::new(mac_address.into(), 32).unwrap()],
                    )])
                    .build()
                    .await
                    .unwrap();
                let port = device.read(async |read| read.listen_port()).await;
                ready_tx
                    .send((key, SocketAddr::from(([127, 0, 0, 1], port))))
                    .unwrap();
                let lan: Network = LAN.parse().unwrap();
                tokio::pin!(stop_rx);
                loop {
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        packet = from_mac.recv() => {
                            let Some(packet) = packet else { break };
                            if packet.len() >= 20 {
                                sources.lock().unwrap().push(Ipv4Addr::new(
                                    packet[12], packet[13], packet[14], packet[15],
                                ));
                            }
                            if let Some(reply) = echo_reply(&packet, lan) {
                                let _ = to_device.send(reply).await;
                            }
                        }
                    }
                }
                device.stop().await;
            });
    });
    let (key, endpoint) = ready_rx.recv().unwrap();
    (key, endpoint, seen, stop_tx, join)
}

/// The interface the Mac's routing table picks for `address` (`route -n get`), if any.
fn route_interface(address: Ipv4Addr) -> Option<String> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", "-inet", &address.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("interface:")
                .map(|name| name.trim().to_owned())
        })
}

/// The Mac's first LAN network (an IPv4 interface network on a non-tunnel interface).
fn mac_lan() -> Option<Network> {
    crate::macos_helper::local_networks(true)
        .ok()?
        .into_iter()
        .filter(|row| row.interface.starts_with("en") && row.network.prefix < 32)
        .find_map(|row| Network::new(row.network.address, row.network.prefix).ok())
}

/// A Mac client routes an approved network behind a router peer into its utun, reaches a host
/// there through the tunnel with only the network grant, leaves out a network its own LAN
/// already covers (and says why), and takes the route away again when the grant is revoked.
#[test]
#[ignore = "Run on the macOS VM with system service privileges under the Mac lock: it routes 10.77.0.0/24 into a utun."]
fn a_mac_reaches_a_network_behind_a_router_peer_only_while_approved() {
    let directory = test_directory();
    write_key(&directory);
    let mut node = Node::restore(&directory.0, None).expect("restore isolated node");
    let identity = node.up().expect("start isolated node");
    let mut current = config();
    current.local_key = Some(identity.public_key);
    current.addresses.ipv4 = "10.253.77.1".parse().unwrap();
    current.addresses.ipv6 = "fd77::1".parse().unwrap();
    let (router_key, endpoint, seen, stop, router) =
        lan_router(identity.public_key, current.addresses.ipv4);
    let lan: Network = LAN.parse().unwrap();
    let own_lan = mac_lan();
    {
        let policy = current.peers.get_mut(&NodeId(4)).unwrap();
        policy.peer.key = router_key;
        policy.peer.endpoint = Some(endpoint);
        policy.peer.addresses.ipv4 = "10.253.77.4".parse().unwrap();
        policy.peer.addresses.ipv6 = "fd77::4".parse().unwrap();
        // No node-to-node access: only the network grant lets the Mac start anything.
        policy.inbound = TrafficPolicy::None;
        policy.outbound = TrafficPolicy::None;
        let mut through = vec![ReachableNetwork {
            network: lan,
            outbound: TrafficPolicy::All,
        }];
        if let Some(own_lan) = own_lan {
            through.push(ReachableNetwork {
                network: own_lan,
                outbound: TrafficPolicy::All,
            });
        }
        policy.networks = PeerNetworks {
            through,
            served: Vec::new(),
        };
    }
    #[cfg(feature = "mesh-dns")]
    {
        current.dns_suffix = "j1169.invalid".to_owned();
    }
    let applying = std::time::Instant::now();
    for chunk in chunks_with_epoch(None, &current, AUTHORITY_EPOCH_A) {
        node.chunk(chunk)
            .expect("install the snapshot with a routed network");
    }
    eprintln!(
        "J1169 first snapshot with two networks applied in {} us",
        applying.elapsed().as_micros()
    );
    let interface = node
        .test_state()
        .interface
        .clone()
        .expect("the node has a utun");
    let state = node.network_route_state(lan);
    eprintln!("J1169 {LAN} on {interface}: {state}");
    assert_eq!(state["state"], "installed", "{state}");
    assert_eq!(
        route_interface(LAN_HOST).as_deref(),
        Some(interface.as_str()),
        "the LAN host must route into our utun before anything is sent"
    );
    let netstat = Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .unwrap();
    let table = String::from_utf8_lossy(&netstat.stdout).into_owned();
    let row = table
        .lines()
        .find(|line| line.starts_with("10.77/24") || line.starts_with("10.77.0/24"))
        .unwrap_or("(none)");
    eprintln!("J1169 netstat row: {row}");
    assert!(row.contains(&interface), "{row}");
    if let Some(own_lan) = own_lan {
        let skipped = node.network_route_state(own_lan);
        eprintln!("J1169 own LAN {own_lan}: {skipped}");
        assert_eq!(skipped["state"], "not installed", "{skipped}");
        assert!(
            skipped["reason"].as_str().unwrap().contains("through en"),
            "{skipped}"
        );
    }
    let started = std::time::Instant::now();
    let ping = Command::new("/sbin/ping")
        .args(["-c", "3", "-i", "0.2", "-t", "10", &LAN_HOST.to_string()])
        .output()
        .unwrap();
    let ping_text = String::from_utf8_lossy(&ping.stdout).into_owned();
    eprintln!(
        "J1169 ping through the tunnel ({} ms):\n{ping_text}",
        started.elapsed().as_millis()
    );
    assert!(ping.status.success(), "{ping_text}");
    let sources = seen.lock().unwrap().clone();
    eprintln!("J1169 sources the LAN host saw: {sources:?}");
    assert!(
        sources
            .iter()
            .all(|source| *source == current.addresses.ipv4)
    );
    assert_ne!(sources, [] as [std::net::Ipv4Addr; 0]);

    // Revoke: the next snapshot carries no networks; the route leaves the utun.
    let mut revoked = current.clone();
    revoked.version += 1;
    revoked.peers.get_mut(&NodeId(4)).unwrap().networks = PeerNetworks::default();
    revoked.peers.get_mut(&NodeId(4)).unwrap().outbound = TrafficPolicy::All;
    let revoking = std::time::Instant::now();
    for chunk in chunks_with_epoch(Some(&current), &revoked, AUTHORITY_EPOCH_A) {
        node.chunk(chunk).expect("install the revoking snapshot");
    }
    eprintln!(
        "J1169 revoking snapshot applied in {} us",
        revoking.elapsed().as_micros()
    );
    // A snapshot with no networks before or after does no route work at all.
    let mut quiet = revoked.clone();
    quiet.version += 1;
    let idle = std::time::Instant::now();
    for chunk in chunks_with_epoch(Some(&revoked), &quiet, AUTHORITY_EPOCH_A) {
        node.chunk(chunk)
            .expect("install a snapshot without networks");
    }
    eprintln!(
        "J1169 snapshot without networks applied in {} us",
        idle.elapsed().as_micros()
    );
    let after = route_interface(LAN_HOST);
    eprintln!(
        "J1169 after revoke: {LAN} -> {after:?}, state {}",
        node.network_route_state(lan)
    );
    assert_ne!(after.as_deref(), Some(interface.as_str()));
    assert_eq!(node.network_route_state(lan)["state"], "pending");
    node.down().expect("stop the node");
    let _ = stop.send(());
    router.join().unwrap();
}
