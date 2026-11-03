//! Proves proxied Mesh flows from a port-granted peer pass the real packet filter end to end [#281].
//!
//! A veth pair named like the Mesh interface stands in for the tunnel; the peer
//! end lives in a second network namespace and owns two peer addresses. An echo
//! listener on the selected HTTPS listener port stands in for Traefik: the
//! packet filter only sees TCP, so several round trips over one connection
//! prove that packets after the SYN, in both directions, are admitted. The
//! route behaviour of Traefik itself is covered by the Pebble integration.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use infraternal_mesh::proxy_ports::{MIXED_LISTENER_PAIRS, MeshProxyIngress};
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
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    thread,
    time::Duration,
};

// Connect from one bound peer address, then echo each stdin line over the same flow.
const CLIENT: &str = r"
import socket, sys
source, destination, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.socket(); s.bind((source, 0)); s.settimeout(1.5)
try:
    s.connect((destination, port)); print('connected', flush=True)
except OSError:
    print('BLOCKED', flush=True); sys.exit(0)
for line in sys.stdin:
    try:
        s.sendall(line.encode()); data = s.recv(64)
        print('echo' if data == line.encode() else 'mismatch', flush=True)
    except OSError:
        print('lost', flush=True)
";

fn command(program: &str, args: &[&str]) {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn tcp(numbers: &[u16]) -> TrafficPolicy {
    TrafficPolicy::Ports(
        numbers
            .iter()
            .map(|number| Port {
                protocol: Protocol::Tcp,
                number: *number,
            })
            .collect(),
    )
}

fn peer(id: u8, inbound: TrafficPolicy) -> (NodeId, PeerPolicy) {
    (
        NodeId(u64::from(id)),
        PeerPolicy {
            peer: Peer {
                key: PublicKey([id; 32]),
                addresses: Addresses {
                    ipv4: format!("10.254.0.{id}").parse().unwrap(),
                    ipv6: format!("fd01::{id}").parse().unwrap(),
                },
                endpoint: None,
            },
            inbound,
            outbound: TrafficPolicy::None,
        },
    )
}

fn configuration(granted_ports: &[u16]) -> Config {
    Config {
        local_key: None,
        server: None,
        node: NodeId(1),
        version: 1,
        addresses: Addresses {
            ipv4: "10.254.0.1".parse().unwrap(),
            ipv6: "fd01::1".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        // Peer .2 is granted only an unpublished port; peer .3 holds the published backend grant.
        peers: BTreeMap::from([peer(2, tcp(&[3000])), peer(3, tcp(granted_ports))]),
    }
}

struct Client {
    process: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Client {
    fn connect(namespace: u32, source: &str, port: u16) -> Self {
        let mut process = Command::new("nsenter")
            .args(["-t", &namespace.to_string(), "-n", "python3", "-c", CLIENT])
            .args([source, "10.254.0.1", &port.to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = process.stdin.take().unwrap();
        let output = BufReader::new(process.stdout.take().unwrap());
        Self {
            process,
            input,
            output,
        }
    }
    // A client that was refused has exited; report that instead of failing on its pipes.
    fn line(&mut self) -> String {
        let mut line = String::new();
        match self.output.read_line(&mut line) {
            Ok(1..) => line.trim().to_owned(),
            _ => "exited".to_owned(),
        }
    }
    fn echo(&mut self) -> String {
        if writeln!(self.input, "ping").is_err() {
            return "exited".to_owned();
        }
        self.line()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn check(mut firewall: Firewall) {
    let mut namespace = Command::new("unshare")
        .args(["-n", "sleep", "120"])
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(100));
    let pid = namespace.id().to_string();
    let inside = |args: &[&str]| {
        let mut full = vec!["-t", pid.as_str(), "-n"];
        full.extend_from_slice(args);
        command("nsenter", &full);
    };
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
            "proxypeer",
        ],
    );
    command("ip", &["link", "set", "proxypeer", "netns", &pid]);
    command(
        "ip",
        &["addr", "add", "10.254.0.1/24", "dev", "infraternal0"],
    );
    command("ip", &["link", "set", "infraternal0", "up"]);
    inside(&["ip", "link", "set", "lo", "up"]);
    for address in ["10.254.0.2/24", "10.254.0.3/24"] {
        inside(&["ip", "addr", "add", address, "dev", "proxypeer"]);
    }
    inside(&["ip", "link", "set", "proxypeer", "up"]);

    let pair = MIXED_LISTENER_PAIRS[1];
    let listener = TcpListener::bind(("10.254.0.1", pair.https)).unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                let mut buffer = [0; 64];
                while let Ok(read @ 1..) = stream.read(&mut buffer) {
                    if stream.write_all(&buffer[..read]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    let ingress = MeshProxyIngress {
        listener_pair: Some(pair),
        backend_ports: BTreeSet::from([8080]),
        ..MeshProxyIngress::default()
    };
    let config = configuration(&[8080, 22]);
    firewall.apply(&config).unwrap();
    firewall.apply_proxy_ingress(&config, &ingress).unwrap();

    let mut granted = Client::connect(namespace.id(), "10.254.0.3", pair.https);
    let connected = granted.line();
    let before = [granted.echo(), granted.echo(), granted.echo()];
    let mut ungranted = Client::connect(namespace.id(), "10.254.0.2", pair.https);
    let refused = ungranted.line();
    // Narrow a grant that has nothing to do with the route. Conntrack retirement must
    // keep the proxied flow, because its source still holds the published backend grant.
    firewall.apply(&configuration(&[8080])).unwrap();
    let after = granted.echo();

    drop(granted);
    drop(ungranted);
    firewall.remove().unwrap();
    command("ip", &["link", "delete", "infraternal0"]);
    let _ = namespace.kill();
    let _ = namespace.wait();
    assert_eq!(
        connected, "connected",
        "a port-granted peer reaches the pair"
    );
    assert_eq!(
        before,
        ["echo", "echo", "echo"],
        "packets after the SYN must pass in both directions"
    );
    assert_eq!(
        refused, "BLOCKED",
        "a peer without a route grant is refused"
    );
    assert_eq!(
        after, "echo",
        "an unrelated narrowing must not retire a proxied flow"
    );
}

#[test]
#[ignore = "Run alone inside unshare -Urn with a disposable network namespace."]
fn nft_admits_a_port_granted_peer_to_the_proxy_listener_for_the_whole_flow() {
    check(Firewall::default());
}

#[test]
#[ignore = "Run alone inside unshare -Urn with a disposable network namespace."]
fn nf_tables_admits_a_port_granted_peer_to_the_proxy_listener_for_the_whole_flow() {
    check(Firewall::nf_tables());
}
