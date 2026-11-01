//! Checks authenticated ingress after a host destination-NAT rule translates an underlay packet [163,216], #129.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy},
    firewall::Firewall,
    node::Node,
    policy::model::{Addresses, NodeId},
};
use std::{collections::BTreeMap, process::Command};

// Both ends of this veth are disposable namespace fixtures. AF_PACKET avoids
// the local route shortcut and injects exactly one packet on the receiving end.
const PACKET: &str = r"
import json, socket, struct, subprocess
def run(*args):
 return subprocess.run(args, check=True, capture_output=True, text=True).stdout
run('ip','link','add','underlay0','type','veth','peer','name','underlay1')
for interface in ['underlay0','underlay1']:
 run('ip','link','set',interface,'up')
run('ip','addr','add','10.220.0.2/24','dev','underlay1')
run('/usr/sbin/sysctl','-qw','net.ipv4.conf.all.rp_filter=0')
run('/usr/sbin/sysctl','-qw','net.ipv4.conf.underlay1.rp_filter=0')
run('/usr/sbin/nft', 'add table ip review_nat; add chain ip review_nat pre { type nat hook prerouting priority -100; policy accept; }; add rule ip review_nat pre ip daddr 10.220.0.2 udp dport 5222 dnat to 10.254.0.1')
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('10.254.0.1',5222));s.settimeout(1)
mac=lambda interface: bytes.fromhex(json.loads(run('ip','-j','link','show',interface))[0]['address'].replace(':',''))
payload=b'public fixture'
udp=struct.pack('!HHHH',5221,5222,8+len(payload),0)+payload
header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),1,0,64,17,0,socket.inet_aton('10.220.0.99'),socket.inet_aton('10.220.0.2'))
checksum=sum(struct.unpack('!10H',header))
while checksum>>16: checksum=(checksum&65535)+(checksum>>16)
header=header[:10]+struct.pack('!H',(~checksum)&65535)+header[12:]
raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);raw.bind(('underlay0',0))
raw.send(mac('underlay1')+mac('underlay0')+b'\x08\x00'+header+udp);raw.close()
try:
 data=s.recv(1024)
 print('RECEIVED' if data==payload else 'UNEXPECTED')
except TimeoutError:
 print('BLOCKED')
finally:
 s.close()
 run('/usr/sbin/nft','delete','table','ip','review_nat')
 run('ip','link','delete','underlay0')
";

fn check(firewall: Firewall) {
    assert!(
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success()
    );
    let mut node = Node::with_firewall(firewall);
    node.up().unwrap();
    node.chunk(Chunk {
        access_updates: Vec::new(),
        local_key: None,
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns-spike")]
        name: None,
        #[cfg(feature = "mesh-dns-spike")]
        dns_suffix: "internal".to_owned(),
        from_version: None,
        version: 1,
        index: 0,
        last: true,
        addresses: Addresses {
            ipv4: "10.254.0.1".parse().unwrap(),
            ipv6: "fd01::1".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        upserted: BTreeMap::new(),
        merged: BTreeMap::new(),
        removed: Vec::new(),
        #[cfg(feature = "mesh-dns-spike")]
        peer_names: std::collections::BTreeMap::new(),
        #[cfg(feature = "mesh-dns-spike")]
        removed_peer_names: Vec::new(),
    })
    .unwrap();
    let packet = Command::new("python3")
        .args(["-c", PACKET])
        .output()
        .unwrap();
    node.down().unwrap();
    assert!(
        packet.status.success(),
        "packet fixture failed: {}",
        String::from_utf8_lossy(&packet.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&packet.stdout).trim(),
        "BLOCKED",
        "translated underlay ingress reached a Mesh-bound service"
    );
}

#[test]
#[ignore = "Run inside a dedicated user/network namespace with CAP_NET_ADMIN."]
fn nft_translated_underlay_ingress_is_refused() {
    check(Firewall::default());
}

#[test]
#[ignore = "Run inside a dedicated user/network namespace with CAP_NET_ADMIN."]
fn nf_tables_translated_underlay_ingress_is_refused() {
    check(Firewall::nf_tables());
}
