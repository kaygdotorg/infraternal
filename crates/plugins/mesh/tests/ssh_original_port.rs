//! Audits original-service admission after mesh SSH destination-port translation [D235], #221.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    dataplane::{Config, DefaultPolicy, Peer, PeerPolicy},
    firewall::Firewall,
    policy::{
        model::{Addresses, NodeId, PublicKey},
        rules::{Port, Protocol, TrafficPolicy},
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    process::{Command, Stdio},
};

fn command(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn nft(script: &str) {
    let mut child = Command::new("/usr/sbin/nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
}

// Emit one TCP SYN at Ethernet ingress. No socket/handshake can silently take
// the node-local route; a later input hook counts only accepted service packets.
const SYN: &str = r"
import json, socket, struct, subprocess, sys
ipv6, sport = int(sys.argv[1]), int(sys.argv[2])
def mac(interface):
 link=json.loads(subprocess.check_output(['ip','-j','link','show',interface]))[0]
 return bytes.fromhex(link['address'].replace(':',''))
def checksum(data):
 if len(data)%2: data+=b'\0'
 value=sum(struct.unpack('!%dH'%(len(data)//2),data))
 while value>>16: value=(value&65535)+(value>>16)
 return (~value)&65535
if ipv6:
 src=socket.inet_pton(socket.AF_INET6,'fd00:3::3');dst=socket.inet_pton(socket.AF_INET6,'fd00:3::2')
 pseudo=src+dst+struct.pack('!I3xB',20,6)
 header=struct.pack('!IHBB',6<<28,20,6,64)+src+dst
 ether=b'\x86\xdd'
else:
 src=socket.inet_aton('10.254.3.3');dst=socket.inet_aton('10.254.3.2')
 pseudo=src+dst+struct.pack('!BBH',0,6,20)
 header=struct.pack('!BBHHHBBH',0x45,0,40,sport,0,64,6,0)+src+dst
 header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
 ether=b'\x08\x00'
tcp=struct.pack('!HHIIBBHHH',sport,22,1,0,5<<4,2,65535,0,0)
tcp=tcp[:16]+struct.pack('!H',checksum(pseudo+tcp))+tcp[18:]
with socket.socket(socket.AF_PACKET,socket.SOCK_RAW) as raw:
 raw.bind(('sshpeer',0));raw.send(mac('infraternal0')+mac('sshpeer')+ether+header+tcp)
";

/// A configuration for the SSH original-port tests.
fn configuration() -> Config {
    Config {
        local_key: None,
        server: None,
        node: NodeId(2),
        version: 1,
        addresses: Addresses {
            ipv4: "10.254.3.2".parse().unwrap(),
            ipv6: "fd00:3::2".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: BTreeMap::from([(
            NodeId(3),
            PeerPolicy {
                peer: Peer {
                    key: PublicKey([3; 32]),
                    previous_key: None,
                    previous_active: false,
                    addresses: Addresses {
                        ipv4: "10.254.3.3".parse().unwrap(),
                        ipv6: "fd00:3::3".parse().unwrap(),
                    },
                    endpoint: None,
                },
                inbound: TrafficPolicy::None,
                outbound: TrafficPolicy::None,
            },
        )]),
    }
}

fn check(mut firewall: Firewall) {
    command("ip", &["link", "set", "lo", "up"]);
    command(
        "ip",
        &[
            "link",
            "add",
            "infraternal0",
            "type",
            "veth",
            "peer",
            "name",
            "sshpeer",
        ],
    );
    for interface in ["infraternal0", "sshpeer"] {
        command("ip", &["link", "set", interface, "up"]);
    }
    command(
        "ip",
        &["addr", "add", "10.254.3.2/24", "dev", "infraternal0"],
    );
    command(
        "ip",
        &[
            "addr",
            "add",
            "fd00:3::2/64",
            "dev",
            "infraternal0",
            "nodad",
        ],
    );
    nft(
        "create table inet ssh_port_test { chain nat { type nat hook prerouting priority dstnat; policy accept; ip daddr 10.254.3.2 tcp dport 22 dnat ip to 10.254.3.2:22022; ip6 daddr fd00:3::2 tcp dport 22 dnat ip6 to [fd00:3::2]:22022; }\n counter delivered {}\n chain observe { type filter hook input priority 0; policy accept; tcp dport 22022 tcp flags & syn == syn counter name delivered; }\n}\n",
    );
    let mut config = configuration();
    let mut observations = Vec::new();
    for (index, allowed) in [22, 22022].into_iter().enumerate() {
        config.peers.get_mut(&NodeId(3)).unwrap().inbound =
            TrafficPolicy::Ports(BTreeSet::from([Port {
                protocol: Protocol::Tcp,
                number: allowed,
            }]));
        firewall.apply(&config).unwrap();
        for ipv6 in [0, 1] {
            command(
                "python3",
                &[
                    "-c",
                    SYN,
                    &ipv6.to_string(),
                    &(30000 + index * 2 + ipv6).to_string(),
                ],
            );
        }
        // Packet injection completes synchronously. nft's counter read follows
        // those netlink/socket calls and observes both address-family paths.
        let counters: serde_json::Value = serde_json::from_str(&command(
            "/usr/sbin/nft",
            &[
                "-j",
                "list",
                "counter",
                "inet",
                "ssh_port_test",
                "delivered",
            ],
        ))
        .unwrap();
        observations.push(
            counters["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .find_map(|entry| entry["counter"]["packets"].as_u64())
                .unwrap(),
        );
    }
    firewall.remove().unwrap();
    nft("delete table inet ssh_port_test\n");
    command("ip", &["link", "delete", "infraternal0"]);
    assert_eq!(
        observations,
        [2, 2],
        "TCP/22 must be admitted by its original port; permitting only the internal port must refuse it"
    );
}

#[test]
#[ignore = "Run alone inside unshare -Urn with a disposable network namespace."]
fn nft_ssh_checks_the_original_service_after_translation() {
    check(Firewall::default());
}
#[test]
#[ignore = "Run alone inside unshare -Urn with a disposable network namespace."]
fn nf_tables_ssh_checks_the_original_service_after_translation() {
    check(Firewall::nf_tables());
}
