//! Exercises missed-notification reconciliation and measures idle repair in a private network namespace.

#![expect(
    clippy::expect_used,
    reason = "namespace fixtures identify setup failures precisely"
)]

use super::*;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    time::{Duration, Instant},
};

/// Shared independent kernel-route observer for unit and integration namespace proofs.
#[path = "../tests/support/route_inventory.rs"]
mod route_inventory;

/// Build an owned link and accepted inventory without starting a resolver or host service.
fn fixture(peers: u32) -> (Node, std::path::PathBuf) {
    let directory = std::env::temp_dir().join(format!("mesh-recheck-{}", std::process::id()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .expect("private fixture directory");
    let mut node = Node::restore_with_engine(&directory, EngineKind::Kernel).expect("node");
    node.up().expect("owned link");
    node.route_repair.take();
    let inventory = (2..peers + 2)
        .map(|id| crate::dataplane::Peer {
            key: Key::generate().expect("peer identity").1,
            previous_key: None,
            previous_active: false,
            addresses: crate::policy::model::Addresses {
                ipv4: std::net::Ipv4Addr::from(0x0afe_0000 + id),
                ipv6: std::net::Ipv6Addr::from((0xfd01_u128 << 112) + u128::from(id)),
            },
            endpoint: None,
        })
        .collect::<Vec<_>>();
    Device::routes(&inventory, false).expect("accepted routes");
    lock_route_state(&node.peer_route_state).set_peers(&inventory);
    (node, directory)
}

/// Missing notifications cannot prevent a periodic pass from restoring all accepted routes.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn fallback_after_unobserved_deletion_repairs_inventory() {
    let (mut node, directory) = fixture(256);
    let expected = route_inventory::installed_routes();
    assert_eq!(
        expected.len(),
        512,
        "the fixture must install both routes per peer"
    );
    let peers = lock_route_state(&node.peer_route_state)
        .peers
        .values()
        .cloned()
        .collect::<Vec<_>>();
    // Delete before subscribing: no listener can receive the lost events retroactively.
    Device::routes(&peers, true).expect("remove routes");
    assert!(route_inventory::installed_routes().is_empty());
    node.ensure_route_repair()
        .expect("fresh listener after deletion");
    let started = Instant::now();
    let deadline = started + Duration::from_secs(90);
    loop {
        if route_inventory::installed_routes() == expected {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fallback must eventually restore the inventory"
        );
        // sleep: allow the real 30-second fallback deadline to expire; 90 seconds is a hang guard.
        thread::sleep(Duration::from_millis(100));
    }
    println!(
        "FALLBACK_RECOVERED_ROUTES={} OBSERVED_ELAPSED_MS={}",
        expected.len(),
        started.elapsed().as_millis()
    );
    node.down().expect("owned cleanup");
    fs::remove_dir_all(directory).expect("fixture cleanup");
}

/// Measure the worker's idle CPU ticks, context switches, and RSS on the pinned performance VM.
#[test]
#[ignore = "Measurement only: execute on the perf VM through perf-run in a disposable network namespace."]
fn periodic_recheck_idle_measurement() {
    let peers = std::env::var("MESH_BENCH_PEERS")
        .unwrap_or_else(|_| "256".to_owned())
        .parse()
        .expect("peer count");
    let (mut node, directory) = fixture(peers);
    node.ensure_route_repair().expect("worker");
    let readiness_deadline = Instant::now() + Duration::from_secs(10);
    let task = loop {
        let task = fs::read_dir("/proc/self/task")
            .expect("task list")
            .map(|entry| entry.expect("task entry").path())
            .find(|path| {
                fs::read_to_string(path.join("comm"))
                    .is_ok_and(|name| name.trim() == "mesh-route-repa")
            });
        if let Some(task) = task {
            break task;
        }
        assert!(
            Instant::now() < readiness_deadline,
            "repair thread startup hang"
        );
        // sleep: wait for the spawned worker to publish its thread name before sampling it.
        thread::sleep(Duration::from_millis(1));
    };
    println!("IDLE_PEERS={peers} SAMPLE_SECONDS=65");
    println!(
        "IDLE_BEFORE_SCHEDSTAT={}",
        fs::read_to_string(task.join("schedstat")).expect("thread runtime")
    );
    println!(
        "IDLE_BEFORE_STAT={}",
        fs::read_to_string(task.join("stat")).expect("thread stat")
    );
    println!(
        "IDLE_BEFORE_STATUS=\n{}",
        fs::read_to_string(task.join("status")).expect("thread status")
    );
    // sleep: the perf-only sample covers two real fallback passes without a functional speed assertion.
    thread::sleep(Duration::from_secs(65));
    println!(
        "IDLE_AFTER_SCHEDSTAT={}",
        fs::read_to_string(task.join("schedstat")).expect("thread runtime")
    );
    println!(
        "IDLE_AFTER_STAT={}",
        fs::read_to_string(task.join("stat")).expect("thread stat")
    );
    println!(
        "IDLE_AFTER_STATUS=\n{}",
        fs::read_to_string(task.join("status")).expect("thread status")
    );
    assert_eq!(
        route_inventory::installed_routes().len(),
        usize::try_from(peers * 2).expect("route count")
    );
    node.down().expect("owned cleanup");
    fs::remove_dir_all(directory).expect("fixture cleanup");
}
