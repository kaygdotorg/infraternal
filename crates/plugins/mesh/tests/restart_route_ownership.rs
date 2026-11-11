//! Checks that route retirement removes orphan routes in both families while preserving routes outside mesh ownership [206,228], #129.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]
#![expect(
    clippy::expect_used,
    reason = "isolated route fixtures report setup failures at the exact step that failed"
)]

use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy, Peer},
    node::{EngineKind, Node},
    policy::model::{Addresses, NodeId},
    wireguard::{Device, Key},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader},
    net::IpAddr,
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// Retiring orphan routes on restart leaves routes this node does not own.
#[test]
#[ignore = "Run inside a dedicated user/network namespace with CAP_NET_ADMIN."]
/// Marks mesh routes separately and retires orphan routes without removing foreign host routes.
fn orphan_route_retirement_preserves_foreign_routes() {
    let target = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    let directory = target.join(format!("review-routes-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let mut node = Node::restore_with_engine(&directory, EngineKind::Kernel).unwrap();
    node.up().unwrap();
    node.chunk(Chunk {
        access_updates: Vec::new(),
        local_key: None,
        authority_epoch: None,
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
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
        #[cfg(feature = "mesh-dns")]
        peer_names: std::collections::BTreeMap::new(),
        #[cfg(feature = "mesh-dns")]
        removed_peer_names: Vec::new(),
    })
    .unwrap();
    let (_, key) = Key::generate().unwrap();
    let orphan = Peer {
        key,
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().unwrap(),
            ipv6: "fd01::2".parse().unwrap(),
        },
        endpoint: None,
    };
    // Model a stop after peers/routes reached the kernel, before public-state
    // fsync. Node deliberately has no Drop cleanup so existing sessions survive.
    Device::peers(std::slice::from_ref(&orphan), &[]).unwrap();
    // A normal upgrade may find routes left by the prior generic-static encoding.
    for arguments in [
        vec![
            "route",
            "replace",
            "10.254.0.2/32",
            "dev",
            "infraternal0",
            "proto",
            "static",
            "scope",
            "link",
        ],
        vec![
            "-6",
            "route",
            "replace",
            "fd01::2/128",
            "dev",
            "infraternal0",
            "proto",
            "static",
            "scope",
            "link",
        ],
    ] {
        assert!(
            Command::new("ip")
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }
    Device::routes(std::slice::from_ref(&orphan), false).unwrap();
    for (arguments, family) in [
        (vec!["-j", "route", "show", "10.254.0.2/32"], "IPv4"),
        (vec!["-j", "-6", "route", "show", "fd01::2/128"], "IPv6"),
    ] {
        let output = Command::new("ip").args(arguments).output().unwrap();
        assert!(output.status.success());
        let routes: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let route = routes.as_array().unwrap().first().unwrap();
        assert!(
            route.get("protocol") == Some(&serde_json::Value::from("250"))
                || route.get("protocol") == Some(&serde_json::Value::from(250)),
            "{family} mesh peer routes need protocol 250 so NetworkManager can preserve them during reapply; got {:?}",
            route.get("protocol")
        );
    }
    assert!(Device::counters().unwrap().contains_key(&key));
    install_foreign_routes();
    Device::retain_routes(&[]).unwrap();
    drop(node);
    let mut restored = Node::restore_with_engine(&directory, EngineKind::Kernel).unwrap();
    assert!(restored.config().unwrap().peers.is_empty());
    assert!(!Device::counters().unwrap().contains_key(&key));
    let mut counts = Vec::new();
    for arguments in [
        vec!["-j", "route", "show", "10.254.0.2/32"],
        vec!["-j", "-6", "route", "show", "fd01::2/128"],
        vec!["-j", "route", "show", "10.253.0.1/32"],
        vec!["-j", "route", "show", "table", "100", "10.252.0.1/32"],
        vec!["-j", "route", "show", "10.251.0.0/24"],
        vec!["-j", "route", "show", "10.250.0.1/32"],
        vec!["-j", "route", "show", "table", "local", "10.254.0.1/32"],
    ] {
        let output = Command::new("ip").args(arguments).output().unwrap();
        assert!(output.status.success());
        let routes: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        counts.push(routes.as_array().unwrap().len());
    }
    restored.down().unwrap();
    fs::remove_dir_all(directory).unwrap();
    assert_eq!(counts, [0, 0, 1, 1, 1, 1, 1]);
}

// Each route falls outside one ownership boundary; none may be retired.
fn install_foreign_routes() {
    assert!(
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success()
    );
    for arguments in [
        vec![
            "route",
            "add",
            "10.253.0.1/32",
            "dev",
            "lo",
            "proto",
            "static",
        ],
        vec![
            "route",
            "add",
            "10.252.0.1/32",
            "dev",
            "infraternal0",
            "table",
            "100",
            "proto",
            "static",
        ],
        vec![
            "route",
            "add",
            "10.251.0.0/24",
            "dev",
            "infraternal0",
            "proto",
            "static",
        ],
        vec![
            "route",
            "add",
            "10.250.0.1/32",
            "dev",
            "infraternal0",
            "proto",
            "boot",
        ],
    ] {
        assert!(
            Command::new("ip")
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }
}

/// Restart repairs routes lost by the old DNS reapply, tags both families, and preserves foreign routes.
#[test]
#[ignore = "Run inside a dedicated user/network namespace with CAP_NET_ADMIN."]
fn review_j519_restart_repairs_missing_routes() {
    let target = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    let directory = target.join(format!("j519-survival-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let mut node = Node::restore_with_engine(&directory, EngineKind::Kernel).unwrap();
    node.up().unwrap();
    let (_, key) = Key::generate().unwrap();
    let peer = Peer {
        key,
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().unwrap(),
            ipv6: "fd01::2".parse().unwrap(),
        },
        endpoint: None,
    };
    node.chunk(Chunk {
        access_updates: Vec::new(),
        local_key: None,
        authority_epoch: None,
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
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
        upserted: BTreeMap::from([(
            NodeId(2),
            infraternal_plugin_mesh::dataplane::PeerPolicy {
                peer,
                inbound: infraternal_plugin_mesh::policy::rules::TrafficPolicy::All,
                outbound: infraternal_plugin_mesh::policy::rules::TrafficPolicy::All,
                access_ssh: None,
            },
        )]),
        merged: BTreeMap::new(),
        removed: Vec::new(),
        #[cfg(feature = "mesh-dns")]
        peer_names: std::collections::BTreeMap::new(),
        #[cfg(feature = "mesh-dns")]
        removed_peer_names: Vec::new(),
    })
    .unwrap();
    // Model an upgrade after the old resolver reapply removed both peer routes.
    for arguments in [
        vec!["route", "del", "10.254.0.2/32", "dev", "infraternal0"],
        vec!["-6", "route", "del", "fd01::2/128", "dev", "infraternal0"],
    ] {
        assert!(
            Command::new("ip")
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }
    drop(node);
    let mut restored = Node::restore_with_engine(&directory, EngineKind::Kernel).unwrap();
    for arguments in [
        vec!["-j", "route", "show", "10.254.0.2/32"],
        vec!["-j", "-6", "route", "show", "fd01::2/128"],
    ] {
        let output = Command::new("ip").args(arguments).output().unwrap();
        assert!(output.status.success());
        let routes: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let routes = routes.as_array().unwrap();
        assert_eq!(routes.len(), 1, "restart must repair a lost peer route");
        assert!(routes[0]["protocol"] == "250" || routes[0]["protocol"] == 250);
    }
    install_foreign_routes();
    drop(restored);
    restored = Node::restore_with_engine(&directory, EngineKind::Kernel).unwrap();
    for arguments in [
        vec!["-j", "route", "show", "10.254.0.2/32"],
        vec!["-j", "-6", "route", "show", "fd01::2/128"],
        vec!["-j", "route", "show", "10.250.0.1/32"],
    ] {
        let output = Command::new("ip").args(arguments).output().unwrap();
        let routes: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            routes.as_array().unwrap().len(),
            1,
            "restart must preserve peer and foreign routes"
        );
    }
    restored.down().unwrap();
    fs::remove_dir_all(directory).unwrap();
}

/// A changed networkd configuration loses protocol-250 peer routes, which the live node must restore.
#[test]
#[ignore = "MESH_REVIEW_PROBE: run with scripts/review-j519-networkd-route-repair in a private networkd namespace."]
fn review_j519_networkd_reload_repairs_peer_routes() {
    let target = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    let directory = target.join(format!("j519-networkd-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let mut node = Node::restore_with_engine(&directory, EngineKind::Kernel).unwrap();
    node.up().unwrap();
    seed_udev_link_data("infraternal0");
    let networkd = NetworkdFixture::start();
    assert!(
        wait_for_networkd_configuration(),
        "networkd must configure the mesh link before its peer routes are installed"
    );
    let (_, key) = Key::generate().unwrap();
    let peer = Peer {
        key,
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().unwrap(),
            ipv6: "fd01::2".parse().unwrap(),
        },
        endpoint: None,
    };
    node.chunk(Chunk {
        access_updates: Vec::new(),
        local_key: None,
        authority_epoch: None,
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
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
        upserted: BTreeMap::from([(
            NodeId(2),
            infraternal_plugin_mesh::dataplane::PeerPolicy {
                peer,
                inbound: infraternal_plugin_mesh::policy::rules::TrafficPolicy::All,
                outbound: infraternal_plugin_mesh::policy::rules::TrafficPolicy::All,
                access_ssh: None,
            },
        )]),
        merged: BTreeMap::new(),
        removed: Vec::new(),
        #[cfg(feature = "mesh-dns")]
        peer_names: std::collections::BTreeMap::new(),
        #[cfg(feature = "mesh-dns")]
        removed_peer_names: Vec::new(),
    })
    .unwrap();

    let ipv4: IpAddr = "10.254.0.2".parse().unwrap();
    let ipv6: IpAddr = "fd01::2".parse().unwrap();
    let foreign: IpAddr = "10.250.0.1".parse().unwrap();
    let observed = BTreeSet::from([ipv4, ipv6, foreign]);
    let events = RouteEventMonitor::start(&observed);
    let config_path = "/etc/systemd/network/10-j519.network";
    let mut configuration = fs::read_to_string(config_path).expect("matching networkd file");
    configuration.push_str("\n[Link]\nMTUBytes=1400\n");
    fs::write(config_path, configuration).expect("change the matching networkd file");
    assert!(
        Command::new("networkctl")
            .args(["reload"])
            .status()
            .unwrap()
            .success(),
        "networkd reload must be accepted"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut deleted = BTreeMap::new();
    let mut added = BTreeMap::new();
    let mut networkd_reconfigured = false;
    while Instant::now() < deadline {
        let status = Command::new("networkctl")
            .args(["status", "infraternal0", "--no-pager"])
            .output()
            .unwrap();
        let status = String::from_utf8_lossy(&status.stdout);
        networkd_reconfigured = status.contains("(configured)") && status.contains("MTU: 1400");
        if networkd_reconfigured
            && [ipv4, ipv6]
                .iter()
                .all(|address| deleted.contains_key(address) && added.contains_key(address))
        {
            break;
        }
        // The event wait bounds a failing regression; its duration is not a route-speed limit.
        if let Ok(event) = events.next(Duration::from_millis(100)) {
            if event.deleted {
                deleted.insert(event.address, event.at);
                added.remove(&event.address);
            } else if deleted.contains_key(&event.address) {
                added.insert(event.address, event.at);
            }
        }
    }

    let gap_ipv4 = added
        .get(&ipv4)
        .zip(deleted.get(&ipv4))
        .map(|(added, deleted)| added.duration_since(*deleted));
    let gap_ipv6 = added
        .get(&ipv6)
        .zip(deleted.get(&ipv6))
        .map(|(added, deleted)| added.duration_since(*deleted));
    assert!(
        networkd_reconfigured,
        "networkd did not apply the changed MTU"
    );
    let Some(gap_ipv4) = gap_ipv4 else {
        panic!("networkd deleted the IPv4 peer route without a repair event");
    };
    let Some(gap_ipv6) = gap_ipv6 else {
        panic!("networkd deleted the IPv6 peer route without a repair event");
    };
    println!("NETWORKD_DELETE_TO_REPAIR_IPV4_US={}", gap_ipv4.as_micros());
    println!("NETWORKD_DELETE_TO_REPAIR_IPV6_US={}", gap_ipv6.as_micros());
    println!(
        "NETWORKD_DELETE_TO_REPAIR_MAX_US={}",
        gap_ipv4.max(gap_ipv6).as_micros()
    );
    assert!(
        owned_route_present(ipv4),
        "IPv4 peer route must be restored"
    );
    assert!(
        owned_route_present(ipv6),
        "IPv6 peer route must be restored"
    );

    assert!(
        Command::new("ip")
            .args([
                "route",
                "add",
                "10.250.0.1/32",
                "dev",
                "lo",
                "proto",
                "boot"
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("ip")
            .args([
                "route",
                "del",
                "10.250.0.1/32",
                "dev",
                "lo",
                "proto",
                "boot"
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("ip")
            .args([
                "route",
                "del",
                "10.254.0.2/32",
                "dev",
                "infraternal0",
                "proto",
                "250"
            ])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut foreign_deleted = false;
    let mut peer_deleted_after_foreign = false;
    let mut peer_repaired_after_foreign = false;
    while Instant::now() < deadline && !peer_repaired_after_foreign {
        if let Ok(event) = events.next(Duration::from_millis(100)) {
            if event.address == foreign && event.deleted {
                foreign_deleted = true;
            } else if event.address == ipv4 && event.deleted && foreign_deleted {
                peer_deleted_after_foreign = true;
            } else if event.address == ipv4 && !event.deleted && peer_deleted_after_foreign {
                peer_repaired_after_foreign = true;
            }
        }
    }
    assert!(
        foreign_deleted,
        "the monitor must observe the foreign route deletion"
    );
    assert!(
        peer_repaired_after_foreign,
        "the peer route repair must act as an event-order barrier"
    );
    assert!(
        !owned_route_present(foreign),
        "the route worker must not recreate a foreign route"
    );
    drop(events);
    node.down().unwrap();
    drop(networkd);
    fs::remove_dir_all(&directory).unwrap();
}

/// One IPv4 or IPv6 route notification read from `ip monitor route`.
struct RouteEvent {
    /// The host prefix named by the kernel event.
    address: IpAddr,
    /// Whether the kernel removed this route.
    deleted: bool,
    /// When this test process read the notification, used to measure recovery gap.
    at: Instant,
}

/// Owns the test's route monitor child and the channel carrying peer route events.
struct RouteEventMonitor {
    /// The exact `ip monitor` process started for this regression.
    child: Child,
    /// Events for the peer routes this test is following.
    events: Receiver<RouteEvent>,
    /// Reader thread stopped after the child is killed and its output closes.
    reader: Option<JoinHandle<()>>,
}

/// Owns the exact networkd process used by the J519 route-loss reproduction.
struct NetworkdFixture {
    /// The private daemon that receives configuration reload requests.
    process: Child,
}

impl NetworkdFixture {
    /// Start networkd after the test has created the real mesh interface and its udev record.
    fn start() -> Self {
        let log = fs::File::create("/run/networkd.log").expect("private networkd log");
        let process = Command::new("/lib/systemd/systemd-networkd")
            .stdout(Stdio::from(log.try_clone().expect("clone networkd log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("start private systemd-networkd");
        let version = Command::new("networkctl")
            .args(["--version"])
            .output()
            .expect("read private networkd version");
        assert!(
            version.status.success(),
            "networkctl must report its version"
        );
        eprintln!("{}", String::from_utf8_lossy(&version.stdout).trim());
        Self { process }
    }
}

impl Drop for NetworkdFixture {
    /// Stop and reap only the networkd process this fixture started.
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl RouteEventMonitor {
    /// Start a private `ip monitor route` reader for the selected peer addresses.
    fn start(addresses: &BTreeSet<IpAddr>) -> Self {
        let mut child = Command::new("ip")
            .args(["monitor", "route"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start ip route event reader");
        let stdout = child.stdout.take().expect("route event stdout");
        let addresses = addresses.clone();
        let (sender, events) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let deleted = line.starts_with("Deleted ");
                let address = line
                    .split_whitespace()
                    .find_map(|word| word.split('/').next()?.parse::<IpAddr>().ok());
                if let Some(address) = address.filter(|address| addresses.contains(address)) {
                    let _ = sender.send(RouteEvent {
                        address,
                        deleted,
                        at: Instant::now(),
                    });
                }
            }
        });
        Self {
            child,
            events,
            reader: Some(reader),
        }
    }

    /// Wait for one route notification, using a timeout only as a test hang bound.
    fn next(&self, timeout: Duration) -> Result<RouteEvent, mpsc::RecvTimeoutError> {
        self.events.recv_timeout(timeout)
    }
}

impl Drop for RouteEventMonitor {
    /// Stop this test's exact `ip monitor` process and reap its output reader.
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// Reports whether one route is the single protocol-250 mesh route for its host prefix.
fn owned_route_present(address: IpAddr) -> bool {
    let prefix = match address {
        IpAddr::V4(address) => format!("{address}/32"),
        IpAddr::V6(address) => format!("{address}/128"),
    };
    let arguments = match address {
        IpAddr::V4(_) => vec!["-j", "route", "show", prefix.as_str()],
        IpAddr::V6(_) => vec!["-j", "-6", "route", "show", prefix.as_str()],
    };
    let Ok(output) = Command::new("ip").args(arguments).output() else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .ok()
        .and_then(|routes| routes.as_array().cloned())
        .is_some_and(|routes| {
            routes.len() == 1
                && (routes[0]["protocol"] == "250" || routes[0]["protocol"] == 250)
                && routes[0]["dev"] == "infraternal0"
        })
}

/// Read the network manager's current link state when its private control bus is available.
fn networkd_status(interface: &str) -> Option<String> {
    let output = Command::new("networkctl")
        .args(["status", interface, "--no-pager"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Write the link's udev record so networkd can identify the newly created `WireGuard` interface.
fn seed_udev_link_data(interface: &str) {
    let output = Command::new("ip")
        .args(["-o", "link", "show", "dev", interface])
        .output()
        .expect("read mesh interface index");
    assert!(output.status.success(), "mesh interface must exist");
    let index = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .expect("mesh interface index")
        .trim_end_matches(':')
        .parse::<u32>()
        .expect("numeric mesh interface index");
    let directory = std::path::Path::new("/run/udev/data");
    fs::create_dir_all(directory).expect("private udev data directory");
    fs::write(
        directory.join(format!("n{index}")),
        "I:1\nE:ID_NET_DRIVER=wireguard\n",
    )
    .expect("private WireGuard udev record");
}

/// Wait until networkd has applied the fixture's first matching file to the live mesh link.
fn wait_for_networkd_configuration() -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if networkd_status("infraternal0").is_some_and(|status| {
            status.contains("(configured)") && status.contains("10-j519.network")
        }) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        // sleep: poll the networkd configuration state until it changes or the fixture times out.
        thread::sleep(Duration::from_millis(25));
    }
}
