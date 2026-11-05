//! Abrupt-stop proofs for disabled intent, bulk teardown and durable route retirement at 1,000 peers [166,170,198], #129.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]
// These proofs read kernel WireGuard state directly, so every node here selects the kernel engine
// explicitly; GotaTun is the default (D346).

use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy, Peer, PeerPolicy},
    firewall::{Backend, Firewall},
    node::{EngineKind, Node},
    node_state::{State, Store},
    policy::{
        model::{Addresses, NodeId},
        rules::TrafficPolicy,
    },
    wireguard::{Client, Device, Key},
};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

// Even a failed assertion must reap the parked child and remove its public fixture files.
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn addresses(id: u32) -> Addresses {
    Addresses {
        ipv4: (0x0afe_0000 + id).into(),
        ipv6: ((0xfd01_u128 << 112) + u128::from(id)).into(),
    }
}

/// Configure `node` with 1000 peers.
fn configure(node: &mut Node) {
    let peers: Vec<_> = (2..=1001)
        .map(|id| {
            (
                NodeId(u64::from(id)),
                PeerPolicy {
                    peer: Peer {
                        key: Key::generate().unwrap().1,
                        previous_key: None,
                        previous_active: false,
                        addresses: addresses(id),
                        endpoint: None,
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                },
            )
        })
        .collect();
    let chunk_count = peers.len().div_ceil(16);
    for (index, peers) in peers.chunks(16).enumerate() {
        let chunk = Chunk {
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
            index: u32::try_from(index).unwrap(),
            last: index + 1 == chunk_count,
            addresses: addresses(1),
            default_policy: DefaultPolicy::Deny,
            exposure: None,
            upserted: peers.iter().cloned().collect::<BTreeMap<_, _>>(),
            merged: BTreeMap::new(),
            removed: Vec::new(),
            #[cfg(feature = "mesh-dns-spike")]
            peer_names: std::collections::BTreeMap::new(),
            #[cfg(feature = "mesh-dns-spike")]
            removed_peer_names: Vec::new(),
        };
        assert!(serde_json::to_vec(&chunk).unwrap().len() <= 8192);
        node.chunk(chunk).unwrap();
    }
    assert_eq!(Device::counters().unwrap().len(), 1000);
}

#[test]
#[ignore = "Child-only fixture for the weighted user/network namespace restart proof."]
fn crash_child() {
    let Ok(boundary) = std::env::var("INFRATERNAL_MESH_DOWN_TEST_BOUNDARY") else {
        return;
    };
    let directory = PathBuf::from(std::env::var_os("INFRATERNAL_MESH_DOWN_TEST_STATE").unwrap());
    let backend = match std::env::var("INFRATERNAL_MESH_DOWN_TEST_BACKEND")
        .unwrap()
        .as_str()
    {
        "nft" => Backend::Nft,
        "nf_tables" => Backend::NfTables,
        _ => panic!("unknown fixture backend"),
    };
    let (store, _) = Store::open(&directory).unwrap();
    store
        .save(&State {
            enabled: true,
            config: None,
            backend: Some(backend),
        })
        .unwrap();
    let mut node = Node::restore_with_engine(&directory, EngineKind::Kernel).unwrap();
    node.up().unwrap();
    configure(&mut node);
    // Use the real persistence and kernel operations at the production down
    // boundaries. No test hook, Drop cleanup or private material is persisted.
    let (store, _) = Store::open(&directory).unwrap();
    store
        .save(&State {
            enabled: false,
            config: None,
            backend: Some(backend),
        })
        .unwrap();
    if boundary != "intent" {
        Client::new().unwrap().clear_peers().unwrap();
    }
    if matches!(boundary.as_str(), "link" | "policy") {
        Device::delete().unwrap();
    }
    if boundary == "policy" {
        let mut firewall = Firewall::for_backend(backend);
        firewall.adopt().unwrap();
        firewall.remove().unwrap();
    }
    println!("BOUNDARY_READY");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}

fn assert_clean_policy(backend: &str) {
    if backend == "nft" {
        let output = Command::new("/usr/sbin/nft")
            .args(["-j", "list", "tables"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let tables: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            tables["nftables"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["table"]["name"] != "infraternal_mesh")
        );
    } else {
        assert!(
            infraternal_plugin_mesh::iptables::presence()
                .unwrap()
                .iter()
                .all(|owner| !owner.any())
        );
    }
}

fn assert_foreign_routes() {
    for args in [
        vec!["-j", "route", "show", "10.253.0.1/32"],
        vec!["-j", "-6", "route", "show", "fd03::1/128"],
    ] {
        let output = Command::new("ip").args(args).output().unwrap();
        assert!(output.status.success());
        let routes: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(routes.as_array().unwrap().len(), 1);
        assert_eq!(routes[0]["dev"], "lo");
    }
}

fn restart_at(directory: &Path, boundary: &str, backend: &str) {
    let mut child = Process(
        Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "crash_child", "--nocapture"])
            .env("INFRATERNAL_MESH_DOWN_TEST_BOUNDARY", boundary)
            .env("INFRATERNAL_MESH_DOWN_TEST_STATE", directory)
            .env("INFRATERNAL_MESH_DOWN_TEST_BACKEND", backend)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let ready = BufReader::new(child.0.stdout.take().unwrap())
        .lines()
        .any(|line| line.unwrap().contains("BOUNDARY_READY"));
    assert!(ready, "child did not reach {backend}/{boundary}");
    child.0.kill().unwrap();
    assert_eq!(child.0.wait().unwrap().signal(), Some(9));
    let (store, intent) = Store::open(directory).unwrap();
    assert!(!intent.enabled);
    assert!(intent.config.is_none());
    assert_eq!(store.route_inventory().unwrap().len(), 2000);
    let node = Node::restore_with_engine(directory, EngineKind::Kernel).unwrap();
    assert!(!node.enabled());
    assert!(!node.active());
    assert!(!node.stopping());
    assert!(!Device::owned().unwrap());
    assert_clean_policy(backend);
    assert_foreign_routes();
    let (store, _) = Store::open(directory).unwrap();
    assert!(
        store.route_inventory().unwrap().is_empty(),
        "replay must durably retire the route journal at {backend}/{boundary}"
    );
    let journal = directory.join("mesh-routes.json");
    let metadata = fs::metadata(&journal).unwrap();
    drop(node);
    let node = Node::restore_with_engine(directory, EngineKind::Kernel).unwrap();
    assert!(!node.enabled());
    assert!(!node.active());
    // An already completed replay does not rewrite the empty inventory.
    assert_eq!(fs::metadata(journal).unwrap().ino(), metadata.ino());
    println!(
        "RECOVERY_PASS backend={backend} boundary={boundary} peers=1000 routes=2000 abrupt_stop=SIGKILL journal_replay=idempotent"
    );
}

#[test]
#[ignore = "Run inside a dedicated user/network namespace under CPUWeight=10000."]
fn restart_finishes_interrupted_down_at_1000_peers() {
    for args in [
        vec!["link", "set", "lo", "up"],
        vec!["route", "add", "10.253.0.1/32", "dev", "lo"],
        vec!["-6", "route", "add", "fd03::1/128", "dev", "lo"],
    ] {
        assert!(Command::new("ip").args(args).status().unwrap().success());
    }
    let target = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    for backend in ["nft", "nf_tables"] {
        for boundary in ["intent", "peers", "link", "policy"] {
            let directory = Directory(target.join(format!(
                "shutdown-restart-{}-{backend}-{boundary}",
                std::process::id()
            )));
            fs::create_dir(&directory.0).unwrap();
            fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
            restart_at(&directory.0, boundary, backend);
        }
    }
}

#[test]
#[ignore = "Run inside a dedicated user/network namespace under CPUWeight=10000."]
fn refused_journal_retirement_keeps_stopping_until_explicit_retry() {
    let target = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    let directory = Directory(target.join(format!("shutdown-retry-{}", std::process::id())));
    fs::create_dir(&directory.0).unwrap();
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
    let mut node = Node::restore_with_engine(&directory.0, EngineKind::Kernel).unwrap();
    node.up().unwrap();
    configure(&mut node);
    let journal = directory.0.join("mesh-routes.json");
    let saved = directory.0.join("mesh-routes.saved");
    fs::rename(&journal, &saved).unwrap();
    fs::create_dir(&journal).unwrap();
    // Disable intent can be published, but the final inventory rename cannot
    // replace this directory. Kernel cleanup must not falsely report Off.
    assert!(node.down().is_err());
    assert!(!node.enabled());
    assert!(node.stopping());
    assert!(!Device::owned().unwrap());
    assert_clean_policy("nft");
    fs::remove_dir(&journal).unwrap();
    fs::rename(saved, journal).unwrap();
    node.down().unwrap();
    assert!(!node.stopping());
    assert!(!node.active());
    let (store, intent) = Store::open(&directory.0).unwrap();
    assert!(!intent.enabled);
    assert!(store.route_inventory().unwrap().is_empty());
}
