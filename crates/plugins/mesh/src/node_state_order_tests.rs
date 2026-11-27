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
            rotation_operation: None,
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
                        candidates: Vec::new(),
                        ipv4_only: false,
                        side_port: false,
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                    access_ssh: None,
                    networks: crate::dataplane::PeerNetworks::default(),
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

/// A peer with deterministic addresses, identity and grant content for journal tests.
fn journal_peer(id: u8, word: u64) -> crate::dataplane::PeerPolicy {
    use crate::{
        dataplane::{Peer, PeerPolicy},
        policy::{
            model::PublicKey,
            rules::{Port, Protocol, TrafficPolicy},
        },
    };
    PeerPolicy {
        peer: Peer {
            key: PublicKey([id; 32]),
            previous_key: None,
            previous_active: false,
            addresses: Addresses {
                ipv4: std::net::Ipv4Addr::new(10, 0, 0, id),
                ipv6: std::net::Ipv6Addr::from((0xfd01_u128 << 112) + u128::from(id)),
            },
            endpoint: word
                .is_multiple_of(3)
                .then(|| std::net::SocketAddr::from(([127, 0, 0, 1], 30_000 + u16::from(id)))),
            candidates: Vec::new(),
            ipv4_only: false,
            side_port: false,
        },
        inbound: TrafficPolicy::Ports(
            (0..40)
                .map(|port| Port {
                    protocol: Protocol::Tcp,
                    number: u16::try_from(word % 60_000).expect("bounded port") + port + 1,
                })
                .collect(),
        ),
        outbound: TrafficPolicy::None,
        access_ssh: None,
        networks: crate::dataplane::PeerNetworks::default(),
    }
}

/// An enrolled baseline with a stable authority and no retained rotation.
fn journal_base() -> State {
    let mut state = revision(2);
    let config = state.config.as_mut().expect("baseline");
    config.local_key = Some(crate::policy::model::PublicKey([42; 32]));
    config.authority_epoch = Some("00000000-0000-4000-8000-000000000042".to_owned());
    state
}

/// Replayed adds, replacements, removals and names equal full snapshots even across compaction
/// and every byte boundary of one interrupted append per seed.
#[test]
fn journal_matches_full_snapshots_through_compaction_and_torn_records() {
    use infraternal_mesh::public_journal;
    use std::{fs, os::unix::fs::MetadataExt};

    for mut random in [13_u64, 47, 193] {
        let directory = Directory::new();
        let reference = Directory::new();
        let (store, _) = Store::open(&directory.0).expect("delta writer");
        let (full, _) = Store::open(&reference.0).expect("full writer");
        let mut state = journal_base();
        store.save(&state).expect("baseline");
        full.save(&state).expect("reference baseline");
        let path = directory.0.join(public_journal::JOURNAL_FILE);
        let mut previous_size = 0;
        let mut compacted = false;
        for version in 3..=240 {
            let old = state.config.clone().expect("old state");
            let next = state.config.as_mut().expect("state");
            next.version = version;
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let id = u8::try_from(random % 23 + 2).expect("bounded peer");
            let node = NodeId(u64::from(id));
            if random.is_multiple_of(5) {
                next.peers.remove(&node);
                #[cfg(feature = "mesh-dns")]
                next.peer_names.remove(&node);
            } else {
                next.peers.insert(node, journal_peer(id, random));
                #[cfg(feature = "mesh-dns")]
                next.peer_names
                    .insert(node, format!("name-{}", random % 13));
            }

            store
                .save_peer_revision(&old, next, state.backend)
                .expect("journal save");
            full.save(&state).expect("full save");
            let meta = fs::metadata(&path).expect("journal metadata");
            assert_eq!(meta.mode() & 0o777, 0o600);
            compacted |= meta.len() < previous_size;
            previous_size = meta.len();
            let (_, restored) = Store::open(&directory.0).expect("journal restore");
            let (_, fresh) = Store::open(&reference.0).expect("full restore");
            assert_eq!(restored.config, fresh.config, "revision {version}");
            let anchor = fs::read(directory.0.join("mesh-public.json")).expect("legacy anchor");
            let token = public_journal::read_token(&anchor).expect("journal selector");
            let body = fs::read(&path).expect("journal");
            assert_eq!(
                public_journal::peer_count(&body, token),
                restored.config.as_ref().map(|config| config.peers.len()),
            );

            if version == 4 {
                let start = body[..body.len() - 1]
                    .iter()
                    .rposition(|&byte| byte == b'\n')
                    .expect("checkpoint frame")
                    + 1;
                for cut in start..body.len() {
                    fs::write(&path, &body[..cut]).expect("model a torn append");
                    let (_, recovered) = Store::open(&directory.0).expect("old prefix");
                    assert_eq!(recovered.config.as_ref(), Some(&old), "cut {cut}");
                }
                // The next writer must remove the partial bytes before retrying the same record.
                store
                    .save_peer_revision(&old, state.config.as_ref().expect("retry"), state.backend)
                    .expect("retry after torn append");
            }
        }
        assert!(
            compacted,
            "the byte limit must trigger checkpoint compaction"
        );
    }
}

/// The downgrade reader sees a deny-only snapshot. A later full write supersedes the journal
/// even when an independent Store still has a cached cursor.
#[test]
fn journal_is_fenced_by_legacy_and_independent_full_writes() {
    let directory = Directory::new();
    let (writer, _) = Store::open(&directory.0).expect("journal writer");
    let (other, _) = Store::open(&directory.0).expect("other writer");
    let mut state = journal_base();
    let previous = state.config.clone().expect("baseline");
    writer.save(&state).expect("baseline");
    let next = state.config.as_mut().expect("next");
    next.version += 1;
    next.peers.insert(NodeId(2), journal_peer(2, 123));
    writer
        .save_peer_revision(&previous, next, state.backend)
        .expect("begin journal");
    let legacy: State = super::read_public(&directory.0.join("mesh-public.json"))
        .expect("legacy JSON")
        .expect("legacy snapshot");
    let legacy = legacy.config.expect("legacy config");
    assert!(legacy.peers.is_empty());
    assert_eq!(legacy.default_policy, DefaultPolicy::Deny);
    assert_eq!(legacy.local_key, next.local_key);

    let old = next.clone();
    next.version += 2;
    next.peers.clear();
    other.save(&state).expect("authoritative full write");
    let mut stale = old.clone();
    stale.version += 1;
    assert!(
        writer
            .save_peer_revision(&old, &stale, state.backend)
            .is_err()
    );
    let (_, restored) = Store::open(&directory.0).expect("restore the full write");
    assert_eq!(restored.config, state.config);
}
