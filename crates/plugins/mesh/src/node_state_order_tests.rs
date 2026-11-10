//! Checks durable revision ordering across independent worker lifetimes [166,198,235], #225.
#![allow(clippy::expect_used)]
use super::{State, Store, tests::Directory};
use crate::{
    dataplane::{Config, DefaultPolicy},
    policy::model::{Addresses, NodeId},
};

/// Builds a stored node state at the supplied revision for ordering regressions.
fn revision(version: u64) -> State {
    State {
        enabled: true,
        config: Some(Config {
            authority_epoch: None,
            local_key: None,
            server: None,
            node: NodeId(1),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            version,
            addresses: Addresses {
                ipv4: "10.254.0.1".parse().expect("IPv4"),
                ipv6: "fd01::1".parse().expect("IPv6"),
            },
            default_policy: if version == 1 {
                DefaultPolicy::Allow
            } else {
                DefaultPolicy::Deny
            },
            exposure: None,
            peers: std::collections::BTreeMap::new(),
            #[cfg(feature = "mesh-dns")]
            peer_names: std::collections::BTreeMap::new(),
        }),
        authority_reset_pending: false,
        backend: None,
    }
}

#[test]
fn stale_and_conflicting_snapshots_cannot_replace_acknowledged_intent() {
    let directory = Directory::new();
    let (old, _) = Store::open(&directory.0).expect("old worker");
    old.save(&revision(1)).expect("initial intent");
    let (new, _) = Store::open(&directory.0).expect("new worker");
    new.save(&revision(2)).expect("acknowledged intent");
    assert!(old.save(&revision(1)).is_err());
    let mut conflict = revision(2);
    conflict.config.as_mut().expect("config").default_policy = DefaultPolicy::Allow;
    assert!(old.save(&conflict).is_err());
    new.save(&revision(2)).expect("identical replay");
    let (_, state) = Store::open(&directory.0).expect("persisted state");
    assert_eq!(state.config, revision(2).config);
}

#[test]
fn worker_start_stop_apply_interleavings_never_decrease_acknowledged_revision() {
    // Exhaust six-operation schedules over two alternating worker slots. Start
    // binds a candidate revision, stop drops that owner, and apply may arrive
    // after a newer durable acknowledgement. Track only accepted writes.
    for mut schedule in 0_u32..729 {
        let directory = Directory::new();
        let mut workers = [None, None];
        let mut acknowledged = 0;
        for step in 0..6 {
            let operation = schedule % 3;
            schedule /= 3;
            let slot = step % 2;
            match operation {
                0 => {
                    let (store, _) = Store::open(&directory.0).expect("start");
                    workers[slot] = Some((store, revision((step / 2 + 1) as u64)));
                }
                1 => workers[slot] = None,
                _ => {
                    if let Some((store, state)) = &workers[slot] {
                        let version = state.config.as_ref().expect("revision").version;
                        let applied = store.save(state).is_ok();
                        assert_eq!(applied, version >= acknowledged);
                        if applied {
                            acknowledged = version;
                        }
                    }
                }
            }
            let (_, persisted) = Store::open(&directory.0).expect("inspect");
            assert_eq!(
                persisted.config.map_or(0, |config| config.version),
                acknowledged
            );
        }
    }
}

#[test]
fn concurrent_workers_serialize_revision_check_and_publication() {
    for _ in 0..32 {
        let directory = Directory::new();
        let (first, _) = Store::open(&directory.0).expect("first worker");
        let (second, _) = Store::open(&directory.0).expect("second worker");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let started = barrier.clone();
        let old = std::thread::spawn(move || {
            started.wait();
            first.save(&revision(1))
        });
        let new = std::thread::spawn(move || {
            barrier.wait();
            second.save(&revision(2))
        });
        let _ = old.join().expect("old worker exit");
        new.join().expect("new worker exit").expect("new revision");
        let (_, persisted) = Store::open(&directory.0).expect("persisted intent");
        assert_eq!(persisted.config, revision(2).config);
    }
}

/// Persisting an accepted snapshot with 1000 peers stays within budget.
#[test]
#[ignore = "Run release on the locked performance VM; public-state persistence at 1000 peers."]
fn accepted_snapshot_persistence_at_1000_peers() {
    use crate::{
        dataplane::{Peer, PeerPolicy},
        policy::{model::PublicKey, rules::TrafficPolicy},
    };
    let directory = Directory::new();
    let (store, _) = Store::open(&directory.0).expect("store");
    let mut state = revision(1);
    let config = state.config.as_mut().expect("config");
    config.peers = (2_u32..1002)
        .map(|id| {
            let mut key = [0; 32];
            key[..4].copy_from_slice(&id.to_le_bytes());
            (
                NodeId(u64::from(id)),
                PeerPolicy {
                    peer: Peer {
                        key: PublicKey(key),
                        previous_key: None,
                        previous_active: false,
                        addresses: Addresses {
                            ipv4: std::net::Ipv4Addr::from(0x0afe_0000 + id),
                            ipv6: std::net::Ipv6Addr::from((0xfd01_u128 << 112) + u128::from(id)),
                        },
                        endpoint: Some("192.0.2.1:44000".parse().expect("endpoint")),
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                    access_ssh: None,
                },
            )
        })
        .collect();
    store.save(&state).expect("initial snapshot");
    let mut samples = Vec::new();
    for version in 2..=102 {
        state.config.as_mut().expect("config").version = version;
        let started = std::time::Instant::now();
        store.save(&state).expect("accepted newer snapshot");
        samples.push(started.elapsed().as_micros());
    }
    samples.sort_unstable();
    println!(
        "METRIC accepted_snapshot peers=1000 samples={} p50_us={} p99_us={} bytes={} machine={} load={}",
        samples.len(),
        samples[50],
        samples[99],
        std::fs::metadata(directory.0.join("mesh-public.json"))
            .expect("snapshot")
            .len(),
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .expect("machine")
            .trim(),
        std::fs::read_to_string("/proc/loadavg")
            .expect("load")
            .trim(),
    );
}

#[test]
fn exact_legacy_binding_upgrade_preserves_the_revision_fence() {
    let directory = Directory::new();
    let (store, _) = Store::open(&directory.0).expect("store");
    let mut state = revision(2);
    store.save(&state).expect("legacy snapshot");
    state.config.as_mut().expect("config").local_key =
        Some(crate::policy::model::PublicKey([1; 32]));
    store.save(&state).expect("key-only metadata upgrade");
    assert!(
        store.save(&revision(2)).is_err(),
        "binding cannot be erased"
    );
    state.config.as_mut().expect("config").default_policy = DefaultPolicy::Allow;
    assert!(
        store.save(&state).is_err(),
        "binding cannot hide an access change"
    );
}

/// Explicit off can replace corrupt saved intent without reviving its mesh peers.
#[test]
fn explicit_off_can_replace_a_corrupt_public_snapshot() {
    let directory = Directory::new();
    let (store, _) = Store::open(&directory.0).expect("running component");
    store.save(&revision(2)).expect("accepted intent");
    std::fs::write(directory.0.join("mesh-public.json"), b"unexpected input")
        .expect("interrupted public snapshot fixture");
    store
        .save(&State {
            enabled: false,
            config: None,
            authority_reset_pending: false,
            backend: None,
        })
        .expect("explicit off must replace invalid retained data");
    let (_, persisted) = Store::open(&directory.0).expect("disabled snapshot");
    assert!(!persisted.enabled);
    assert!(persisted.config.is_none());
}
