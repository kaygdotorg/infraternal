//! Exercises the real restart ingress fence before retained replacement aliases are reconciled [166,199], #173.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::{
    dataplane::DefaultPolicy,
    firewall::Backend,
    policy::model::{Addresses, NodeId},
};
use std::{
    net::UdpSocket,
    process::{Command, Stdio},
    time::Duration,
};
fn command(program: &str, args: &[&str]) {
    assert!(
        Command::new(program)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
}
// Keep the retained address, recovery fence and packet observation in one scenario.
#[allow(clippy::too_many_lines)]
fn check(backend: Backend) {
    let mut node = Node::with_firewall(Firewall::for_backend(backend));
    node.up().unwrap();
    let proposed = Addresses {
        ipv4: "10.254.0.3".parse().unwrap(),
        ipv6: "fd01::3".parse().unwrap(),
    };
    Device::addresses(proposed).unwrap();
    let accepted = Config {
        local_key: None,
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns-spike")]
        name: None,
        #[cfg(feature = "mesh-dns-spike")]
        dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
        version: 1,
        addresses: Addresses {
            ipv4: "10.254.0.1".parse().unwrap(),
            ipv6: "fd01::1".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: BTreeMap::new(),
        #[cfg(feature = "mesh-dns-spike")]
        peer_names: std::collections::BTreeMap::new(),
    };
    // Restore invokes this same boundary with no in-memory accepted config.
    // The kernel can still carry a proposed address from an interrupted apply.
    assert!(node.config.is_none());
    node.apply_fence(&accepted, &accepted).unwrap();
    let mut child = Command::new("unshare")
        .args(["-n", "sleep", "30"])
        .spawn()
        .unwrap();
    let pid = child.id().to_string();
    for _ in 0..100 {
        if std::fs::read_link(format!("/proc/{pid}/ns/net")).unwrap()
            != std::fs::read_link("/proc/self/ns/net").unwrap()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    command(
        "ip",
        &[
            "link",
            "add",
            "underlay0",
            "type",
            "veth",
            "peer",
            "name",
            "underlay1",
        ],
    );
    command("ip", &["link", "set", "underlay1", "netns", &pid]);
    command("ip", &["addr", "add", "10.220.0.1/24", "dev", "underlay0"]);
    command("ip", &["link", "set", "underlay0", "up"]);
    command(
        "nsenter",
        &[
            "-t",
            &pid,
            "-n",
            "ip",
            "addr",
            "add",
            "10.220.0.2/24",
            "dev",
            "underlay1",
        ],
    );
    command(
        "nsenter",
        &["-t", &pid, "-n", "ip", "link", "set", "underlay1", "up"],
    );
    command(
        "nsenter",
        &[
            "-t",
            &pid,
            "-n",
            "ip",
            "route",
            "add",
            "10.254.0.3/32",
            "via",
            "10.220.0.1",
        ],
    );
    let receiver = UdpSocket::bind((proposed.ipv4, 5540)).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    command(
        "nsenter",
        &[
            "-t",
            &pid,
            "-n",
            "python3",
            "-c",
            "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'public-fixture',('10.254.0.3',5540))",
        ],
    );
    let result = receiver.recv_from(&mut [0; 64]);
    child.kill().unwrap();
    child.wait().unwrap();
    node.down().unwrap();
    assert!(
        result.is_err(),
        "retained replacement address accepted underlay traffic during restart fence"
    );
}

/// After a rotation, a restarted node still adopts its interface as its own.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn rotated_interface_remains_owned_after_process_restart() {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    struct StateDirectory(PathBuf);
    impl Drop for StateDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "infraternal-mesh-rotation-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let _cleanup = StateDirectory(path.clone());

    let operation = "00000000-0000-4000-8000-000000000002";
    let mut node = Node::restore(&path).unwrap();
    let previous = node.up().unwrap();
    let candidate = node.prepare_rotation(operation, 1).unwrap();
    assert_ne!(previous.public_key, candidate);
    assert!(
        Node::plan_retirement(&path).unwrap().interface,
        "the previous key remains owned before local activation"
    );

    // Recreate the crash boundary after the durable commit intent and kernel
    // key update, but before the ownership marker can be replaced.
    let (store, _) = crate::node_state::Store::open(&path).unwrap();
    let mut rotation = store.rotation_secret().unwrap().unwrap();
    rotation.commit_requested = true;
    store.save_rotation_secret(&rotation).unwrap();
    let (candidate_key, candidate_public) = Key::from_private(&rotation.candidate).unwrap();
    assert_eq!(candidate_public, candidate);
    Device::configure(&candidate_key, previous.port).unwrap();
    assert!(
        Node::plan_retirement(&path).unwrap().interface,
        "the candidate key is owned after kernel acceptance even before the marker update"
    );
    drop(rotation);
    drop(store);
    drop(node);

    let started = Instant::now();
    let mut restored = Node::restore(&path).unwrap();
    let identity = restored.up().unwrap();
    let recovery_us = started.elapsed().as_micros();
    assert_eq!(identity.public_key, candidate);
    assert!(
        Node::plan_retirement(&path).unwrap().interface,
        "the rotated kernel interface must remain provably owned after restart"
    );
    println!("METRIC mesh_rotation_restart_recovery_us={recovery_us}");
    restored.down().unwrap();
}

#[test]
#[ignore = "Run in a disposable user/network namespace, #173."]
fn nft_restart_fences_retained_replacement_address() {
    check(Backend::Nft);
}
#[test]
#[ignore = "Run in a disposable user/network namespace, #173."]
fn nf_tables_restart_fences_retained_replacement_address() {
    check(Backend::NfTables);
}
