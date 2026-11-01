//! Checks redirect scope/ownership and real listener cleanup in disposable network namespaces.
use super::*;
use std::{net::TcpStream, time::Duration};

#[test]
fn coordinates_cannot_become_nft_syntax_or_wildcard_listeners() {
    let address = "10.254.0.2".parse().unwrap();
    for interface in [
        "",
        "infraternal0;",
        "lo\n",
        "x\"",
        "$(id)",
        "abcdefghijklmnop",
    ] {
        assert!(validate(address, interface).is_err());
    }
    for address in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "::", "::1", "ff02::1"] {
        assert!(validate(address.parse().unwrap(), "infraternal0").is_err());
    }
    assert!(validate(address, "infraternal0").is_ok());
}

#[test]
fn both_families_preserve_the_destination_and_guard_the_internal_port() {
    for (address, family, destination) in [
        ("10.254.0.2", "ip", "10.254.0.2:22022"),
        ("fd00::2", "ip6", "[fd00::2]:22022"),
    ] {
        let rules = render(address.parse().unwrap(), "infraternal0", 22022);
        assert!(rules.contains("create table inet infraternal_ssh"));
        assert!(rules.contains("comment \"infraternal.ssh.v1\""));
        assert!(rules.contains(&format!("iifname \"infraternal0\" {family} daddr {address} tcp dport 22 dnat {family} to {destination}")));
        assert!(rules.contains(&format!(
            "ct original {family} daddr {address} ct original proto-dst 22 return"
        )));
        assert!(rules.contains(&format!("{family} daddr {address} tcp dport 22022 drop")));
        assert!(!rules.contains("flush ruleset"));
        assert!(!rules.contains("accept; }"));
    }
}

fn ip(args: &[&str]) {
    assert!(
        Command::new("/usr/bin/ip")
            .args(args)
            .status()
            .unwrap()
            .success()
    );
}

fn assert_delivery(binding: &MeshPort, address: SocketAddr) {
    let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
    let (mut server, _) = binding.listener().unwrap().accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client.write_all(b"mesh").unwrap();
    let mut bytes = [0; 4];
    std::io::Read::read_exact(&mut server, &mut bytes).unwrap();
    assert_eq!(&bytes, b"mesh");
}

#[test]
#[ignore = "Run alone inside unshare -Urn with a disposable network namespace."]
fn namespace_direct_redirect_guard_and_cleanup() {
    ip(&["link", "set", "lo", "up"]);
    for (address, prefix, wildcard) in [
        ("10.254.0.2", "10.254.0.2/32", "0.0.0.0:22"),
        ("fd00::2", "fd00::2/128", "[::]:22"),
    ] {
        if address.contains(':') {
            ip(&["address", "add", prefix, "dev", "lo", "nodad"]);
        } else {
            ip(&["address", "add", prefix, "dev", "lo"]);
        }
        let address: IpAddr = address.parse().unwrap();
        let public = SocketAddr::new(address, 22);
        let mut direct = MeshPort::bind(address, "infraternal0").unwrap();
        assert_eq!(direct.mode(), PortMode::Direct);
        assert!(!presence(address).unwrap());
        assert_delivery(&direct, public);
        direct.stop().unwrap();
        direct.stop().unwrap();
        assert!(direct.listener().is_none());
        assert_eq!(direct.mode(), PortMode::Stopped);

        // A wildcard TCP listener models the kernel bind conflict. This is not
        // a substitute for the separately required real host SSH server test.
        let host = TcpListener::bind(wildcard).unwrap();
        let mut redirected = MeshPort::bind(address, "infraternal0").unwrap();
        assert_eq!(redirected.mode(), PortMode::Redirect);
        assert!(presence(address).unwrap());
        let internal = redirected.listener().unwrap().local_addr().unwrap();
        assert_ne!(internal.port(), 22);
        assert_delivery(&redirected, public);
        assert!(TcpStream::connect_timeout(&internal, Duration::from_millis(100)).is_err());
        // A second lifecycle cannot overwrite a live instance's owned rules.
        assert!(MeshPort::bind(address, "infraternal0").is_err());
        redirected.stop().unwrap();
        redirected.stop().unwrap();
        assert_eq!(redirected.mode(), PortMode::Stopped);
        assert!(!presence(address).unwrap());
        let dropped = MeshPort::bind(address, "infraternal0").unwrap();
        assert!(presence(address).unwrap());
        drop(dropped);
        assert!(!presence(address).unwrap());
        let client = TcpStream::connect_timeout(&public, Duration::from_secs(1)).unwrap();
        let (_, peer) = host.accept().unwrap();
        assert_eq!(peer, client.local_addr().unwrap());
        drop(client);
        drop(host);

        // Recovery/uninstall is idempotent and leaves unrelated tables intact.
        let name = table(address);
        for fixture in [
            format!("add table inet {name}\n"),
            format!("create table inet {name} {{ comment \"{MARKER}.foreign\"; }}\n"),
        ] {
            transaction(&fixture).unwrap();
            assert_eq!(
                MeshPort::recover(address).unwrap_err().kind(),
                io::ErrorKind::AlreadyExists
            );
            transaction(&format!("delete table inet {name}\n")).unwrap();
        }
        transaction(&render(address, "infraternal0", 22022)).unwrap();
        assert!(transaction(&format!("delete table inet {name}\ninvalid command\n")).is_err());
        assert!(presence(address).unwrap());
        MeshPort::recover(address).unwrap();
        MeshPort::recover(address).unwrap();
        assert!(!presence(address).unwrap());
    }
}

const PEER: &str = r#"
"""Connect from an isolated peer namespace and check the internal port is closed."""
import socket, subprocess, sys
print('ready', flush=True)
address, port = sys.stdin.readline().split()
for args in [
    ['link', 'set', 'lo', 'up'],
    ['link', 'set', 'sshpeer', 'up'],
    ['address', 'add', '10.254.3.3/24', 'dev', 'sshpeer'],
    ['address', 'add', 'fd00:3::3/64', 'dev', 'sshpeer', 'nodad'],
]:
    subprocess.run(['/usr/bin/ip', *args], check=True)
with socket.create_connection((address, 22), timeout=2) as stream:
    stream.sendall(b'mesh')
    assert stream.recv(4) == b'pass'
try:
    stream = socket.create_connection((address, int(port)), timeout=0.2)
except OSError:
    print('internal refused', flush=True)
else:
    stream.close()
    raise AssertionError('internal port reachable')
sys.stdin.readline()
"#;

struct PeerProcess(std::process::Child);
impl Drop for PeerProcess {
    fn drop(&mut self) {
        // Only this test's subprocess is stopped, including on assertion failure.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "Run alone inside unshare -Urn with a disposable network namespace."]
fn namespace_incoming_redirect_and_internal_port_refusal() {
    use std::io::{BufRead as _, BufReader};

    ip(&["link", "set", "lo", "up"]);
    for (address, wildcard) in [("10.254.3.2", "0.0.0.0:22"), ("fd00:3::2", "[::]:22")] {
        let address: IpAddr = address.parse().unwrap();
        let mut peer = PeerProcess(
            Command::new("/usr/bin/unshare")
                .args(["-n", "python3", "-c", PEER])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut output = BufReader::new(peer.0.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "ready\n");
        ip(&[
            "link",
            "add",
            "infraternal0",
            "type",
            "veth",
            "peer",
            "name",
            "sshpeer",
        ]);
        ip(&["link", "set", "sshpeer", "netns", &peer.0.id().to_string()]);
        ip(&["link", "set", "infraternal0", "up"]);
        ip(&["address", "add", "10.254.3.2/24", "dev", "infraternal0"]);
        ip(&[
            "address",
            "add",
            "fd00:3::2/64",
            "dev",
            "infraternal0",
            "nodad",
        ]);
        let host = TcpListener::bind(wildcard).unwrap();
        let mut binding = MeshPort::bind(address, "infraternal0").unwrap();
        assert_eq!(binding.mode(), PortMode::Redirect);
        let listener = binding.listener().unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut control = peer.0.stdin.take().unwrap();
        writeln!(
            control,
            "{address} {}",
            listener.local_addr().unwrap().port()
        )
        .unwrap();
        // A failed peer must not leave the parent blocked in accept indefinitely.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline, "peer did not connect");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = [0; 4];
        std::io::Read::read_exact(&mut stream, &mut bytes).unwrap();
        assert_eq!(&bytes, b"mesh");
        stream.write_all(b"pass").unwrap();
        line.clear();
        output.read_line(&mut line).unwrap();
        assert_eq!(line, "internal refused\n");
        binding.stop().unwrap();
        assert!(!presence(address).unwrap());
        drop(host);
        // Remove the pair while its peer namespace is still alive.
        ip(&["link", "delete", "infraternal0"]);
        drop(control);
        assert!(peer.0.wait().unwrap().success());
    }
}
