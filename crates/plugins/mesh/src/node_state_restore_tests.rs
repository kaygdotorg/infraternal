//! Compares public snapshot restore semantics and opt-in file-parser costs; no kernel nodes or private key material are created [166,243], #201.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::{
    dataplane::{DefaultPolicy, Peer, PeerPolicy},
    policy::{
        model::{Addresses, NodeId, PublicKey},
        rules::TrafficPolicy,
    },
};
use std::{collections::BTreeMap, io::Read, os::unix::fs::PermissionsExt};

/// Frozen reader baseline includes the same descriptor validation as production.
fn prior_reader<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => {
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.uid() != nix::unistd::Uid::effective().as_raw()
                || meta.mode() & 0o777 != 0o600
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            serde_json::from_reader(file)
                .map(Some)
                .map_err(io::Error::other)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// A public state with `peers` peers, for restore measurements.
fn public_state(peers: u16) -> State {
    let mut config = Config {
        authority_epoch: None,
        rotation_operation: None,
        local_key: Some(PublicKey([1; 32])),
        server: Some(NodeId(1)),
        node: NodeId(2),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
        dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
        version: 7,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().unwrap(),
            ipv6: "fd01::2".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: BTreeMap::new(),
        #[cfg(feature = "mesh-dns")]
        peer_names: std::collections::BTreeMap::new(),
    };
    for index in 1..=peers {
        let [a, b] = index.to_be_bytes();
        let mut key = [0; 32];
        key[..2].copy_from_slice(&index.to_be_bytes());
        config.peers.insert(
            NodeId(u64::from(index) + 2),
            PeerPolicy {
                peer: Peer {
                    key: PublicKey(key),
                    previous_key: None,
                    previous_active: false,
                    addresses: Addresses {
                        ipv4: [10, 254, a, b].into(),
                        ipv6: std::net::Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, index),
                    },
                    endpoint: Some(([10, 220, a, b], 7443).into()),
                    candidates: Vec::new(),
                    ipv4_only: false,
                    side_port: false,
                },
                inbound: TrafficPolicy::All,
                outbound: TrafficPolicy::None,
                access_ssh: None,
                networks: crate::dataplane::PeerNetworks::default(),
            },
        );
    }
    State {
        enabled: false,
        config: Some(config),
        authority_reset_pending: false,
        backend: Some(crate::firewall::Backend::Nft),
    }
}

#[test]
fn public_restore_retains_large_intent_and_matches_reader() {
    let directory = super::tests::Directory::new();
    let (store, _) = Store::open(&directory.0).unwrap();
    let expected = public_state(1000);
    store.save(&expected).unwrap();
    let prior: State = prior_reader(&store.path).unwrap().unwrap();
    let (_, restored) = Store::open(&directory.0).unwrap();
    assert_eq!(restored.config, expected.config);
    assert_eq!(restored.config, prior.config);
    assert!(!restored.enabled && !prior.enabled);
    assert!(matches!(
        restored.backend,
        Some(crate::firewall::Backend::Nft)
    ));
    assert_eq!(fs::metadata(&store.path).unwrap().mode() & 0o777, 0o600);
}

#[test]
fn restore_rejects_invalid_schema_trailing_data_and_unsafe_descriptors() {
    let directory = super::tests::Directory::new();
    let path = directory.0.join("mesh-public.json");
    assert!(read_public::<State>(&path).unwrap().is_none());
    for body in [
        br#"{"enabled":false,"config":null,"unknown":1}"#.as_slice(),
        br#"{"enabled":false,"config":null} true"#,
        br#"{"enabled":false,"config":{"node":1}}"#,
        b"",
        b"{",
    ] {
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let prior = prior_reader::<State>(&path).err().unwrap();
        let current = read_public::<State>(&path).err().unwrap();
        assert_eq!(current.kind(), prior.kind());
        assert_eq!(current.kind(), io::ErrorKind::Other);
    }
    fs::write(&path, br#"{"enabled":false,"config":null}"#).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(
        read_public::<State>(&path).err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        read_public::<State>(&path).err().unwrap().kind(),
        io::ErrorKind::PermissionDenied
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
}

/// Run reader and slice in separate invocations, selecting the public env mode.
/// RSS includes fixture setup and allocator retention; it is not attributed
/// solely to parsing. The capacity bound applies only to this fixed fixture's
/// encoded buffer, excluding the decoded tree; production has no file-size cap.
#[test]
#[ignore = "Run only on the perf VM under its lock; INFRATERNAL_STATE_RESTORE_MODE=reader|slice, separate processes."]
fn public_state_restore_at_1000_peers() {
    use std::{hint::black_box, time::Instant};
    let mode = std::env::var("INFRATERNAL_STATE_RESTORE_MODE").unwrap();
    assert!(mode == "reader" || mode == "slice");
    let directory = super::tests::Directory::new();
    let (store, _) = Store::open(&directory.0).unwrap();
    store.save(&public_state(1000)).unwrap();
    let encoded_bytes = usize::try_from(fs::metadata(&store.path).unwrap().len()).unwrap();
    // Observe the actual growable-buffer capacity separately from timed work.
    // Capacity grows monotonically; old plus replacement capacity during growth
    // is at most twice the final capacity. Allocator metadata/RSS are separate.
    let input_capacity = if mode == "slice" {
        let mut buffer = Vec::new();
        fs::File::open(&store.path)
            .unwrap()
            .read_to_end(&mut buffer)
            .unwrap();
        assert_eq!(buffer.len(), encoded_bytes);
        buffer.capacity()
    } else {
        0
    };
    let mut samples = Vec::with_capacity(31);
    for _ in 0..31 {
        let start = Instant::now();
        let restored: State = if mode == "reader" {
            prior_reader(&store.path).unwrap().unwrap()
        } else {
            read_public(&store.path).unwrap().unwrap()
        };
        samples.push(start.elapsed().as_nanos());
        assert_eq!(
            black_box(restored.config.as_ref().unwrap().peers.len()),
            1000
        );
        assert!(!restored.enabled);
        black_box(restored);
    }
    samples.sort_unstable();
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let memory = status
        .lines()
        .filter(|line| line.starts_with("VmRSS:") || line.starts_with("VmHWM:"))
        .collect::<Vec<_>>()
        .join(" ");
    println!(
        "public_state_restore mode={mode} samples=31 public_config_peers=1000 daemons=0 restore_concurrency=1 input_size_limit=none encoded_bytes={encoded_bytes} whole_input_capacity_bytes={input_capacity} fixture_input_growth_live_capacity_bound_bytes={} p50_ns={} p99_ns={} scope=validated_descriptor_read_and_parse_page_cache_warm_rss_includes_fixture_setup_capacity_excludes_decoded_tree_and_allocator_metadata machine={} load={} memory={memory}",
        input_capacity * 2,
        samples[15],
        samples[30],
        fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        fs::read_to_string("/proc/loadavg").unwrap().trim(),
    );
}

/// A symlink to a runtime ID must be refused even though the link lives on disk.
#[test]
fn runtime_machine_id_symlink_is_not_persistent() {
    let directory = super::tests::Directory::new();
    let runtime = super::tests::Directory::new_in(Path::new("/dev/shm"));
    let primary = directory.0.join("machine-id");
    let fallback = directory.0.join("dbus-machine-id");
    let id = "0123456789abcdef0123456789abcdef";
    fs::write(&fallback, id).unwrap();
    let persistent = machine_fingerprint_at(&primary, &fallback).unwrap();
    std::os::unix::fs::symlink(&fallback, &primary).unwrap();
    assert_eq!(
        machine_fingerprint_at(&primary, &fallback),
        Some(persistent)
    );

    let transient = runtime.0.join("machine-id");
    fs::write(&transient, id).unwrap();
    fs::remove_file(&primary).unwrap();
    std::os::unix::fs::symlink(&transient, &primary).unwrap();
    assert_eq!(machine_fingerprint_at(&primary, &fallback), None);
    assert_eq!(machine_fingerprint_at(&transient, &fallback), None);
}

/// Missing machine identity leaves a fresh enrollment directory without a binding record.
#[test]
fn missing_machine_id_refuses_enrollment_without_writing_state() {
    let directory = super::tests::Directory::new();
    let enrolment = crate::enrolment::Enrolment::new(b"coordinator", "host", b"agent key");
    let missing = machine_fingerprint_at(&directory.0.join("etc"), &directory.0.join("dbus"));
    let result =
        crate::node::Node::prepare_enrolled_restore_with_machine(&directory.0, enrolment, missing);
    let error = result.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("/etc/machine-id"));
    assert!(!directory.0.join(ENROLMENT_FILE).exists());
}

/// A fresh OS installation must leave the original record intact and explain how to re-enroll.
#[test]
fn fresh_os_machine_id_requires_add_host() {
    let directory = super::tests::Directory::new();
    let enrolment = crate::enrolment::Enrolment::new(b"coordinator", "host", b"agent key");
    let primary = directory.0.join("machine-id");
    let fallback = directory.0.join("dbus-machine-id");
    fs::write(&primary, "0123456789abcdef0123456789abcdef").unwrap();
    let original = machine_fingerprint_at(&primary, &fallback);
    assert!(original.is_some());
    crate::node::Node::prepare_enrolled_restore_with_machine(
        &directory.0,
        enrolment.clone(),
        original,
    )
    .unwrap();
    let record = fs::read(directory.0.join(ENROLMENT_FILE)).unwrap();
    fs::write(&primary, "fedcba9876543210fedcba9876543210").unwrap();
    let replacement = machine_fingerprint_at(&primary, &fallback);
    assert!(replacement.is_some());
    assert_ne!(replacement, original);
    let error = crate::node::Node::prepare_enrolled_restore_with_machine(
        &directory.0,
        enrolment,
        replacement,
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("Add host"));
    assert_eq!(fs::read(directory.0.join(ENROLMENT_FILE)).unwrap(), record);
}

/// A pre-fix record without a fingerprint cannot establish this installation as its owner.
#[test]
fn unbound_enrolment_record_requires_add_host() {
    let directory = super::tests::Directory::new();
    let binding = directory.0.join(ENROLMENT_FILE);
    let original =
        br#"{"machine":null,"enrolment":{"coordinator":"ca","host":"host","agent_key":"key"}}"#;
    fs::write(&binding, original).unwrap();
    fs::set_permissions(&binding, fs::Permissions::from_mode(0o600)).unwrap();
    let Err(error) = read_enrolment_with(&directory.0, || Some([1; 32])) else {
        panic!("a record without a binding must be refused");
    };
    assert!(error.to_string().contains("Add host"));
    assert_eq!(fs::read(binding).unwrap(), original);
}

/// A restored remote Mesh directory cannot start on a machine with a different ID.
#[test]
fn foreign_machine_mesh_restore_is_refused_before_network_setup() {
    let directory = super::tests::Directory::new();
    let binding = directory.0.join("mesh-enrolment.json");
    fs::write(
        &binding,
        br#"{"machine":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"enrolment":{"coordinator":"ca","host":"host","agent_key":"key"}}"#,
    )
    .unwrap();
    fs::set_permissions(&binding, fs::Permissions::from_mode(0o600)).unwrap();
    let Err(error) = Store::open(&directory.0) else {
        panic!("a copied Mesh directory must be refused");
    };
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("different machine"));
}

/// Restart reuses a matching enrollment, while re-enrollment retires the prior key and routes.
#[test]
fn enrollment_restore_preserves_matching_state_and_retires_a_changed_key() {
    use crate::node::{Enrolment, Node};

    let directory = super::tests::Directory::new();
    let enrolled = || Enrolment::new(b"coordinator", "host", b"original agent key");
    Node::prepare_enrolled_restore(&directory.0, enrolled()).unwrap();
    let (store, _) = Store::open(&directory.0).unwrap();
    let mut state = public_state(1);
    // No kernel objects are needed to test the retained intent and private key.
    state.config.as_mut().unwrap().local_key = None;
    state.backend = None;
    store.save(&state).unwrap();
    store
        .record_routes(&["10.254.0.3".parse().unwrap()].into_iter().collect())
        .unwrap();
    store.write_private_key(&[17; 32]).unwrap();
    store
        .record_engine(crate::node::EngineKind::GotaTun)
        .unwrap();
    store
        .save_rotation_secret(&RotationSecret {
            operation_id: "00000000-0000-4000-8000-000000000221".into(),
            sequence: 1,
            previous: [17; 32],
            candidate: [19; 32],
            commit_requested: false,
            completed: false,
        })
        .unwrap();
    let rotation_path = directory.0.join("mesh-key-rotation.bin");
    let key_path = directory.0.join("mesh-private-key");
    for path in [&rotation_path, &key_path] {
        assert_eq!(fs::symlink_metadata(path).unwrap().mode() & 0o777, 0o600);
    }
    drop(store);

    Node::prepare_enrolled_restore(&directory.0, enrolled()).unwrap();
    let (store, same) = Store::open(&directory.0).unwrap();
    assert_eq!(same.config, state.config);
    assert!(store.read_private_key().unwrap().is_some());
    assert!(store.rotation_secret().unwrap().is_some());
    assert_eq!(
        store.recorded_engine().unwrap(),
        Some(crate::node::EngineKind::GotaTun)
    );
    assert_eq!(store.route_inventory().unwrap().len(), 1);
    drop(store);

    let replacement = Enrolment::new(b"coordinator", "host", b"replacement agent key");
    Node::prepare_enrolled_restore(&directory.0, replacement).unwrap();
    let (store, fresh) = Store::open(&directory.0).unwrap();
    assert!(!fresh.enabled);
    assert!(fresh.config.is_none());
    assert!(store.read_private_key().unwrap().is_none());
    assert!(store.rotation_secret().unwrap().is_none());
    assert!(store.recorded_engine().unwrap().is_none());
    assert!(store.route_inventory().unwrap().is_empty());
    for path in [&rotation_path, &key_path] {
        assert_eq!(
            fs::symlink_metadata(path).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }
}

/// An unbound directory with a key alone must retire it before claiming the enrollment.
#[test]
fn enrollment_restore_retires_a_legacy_key_without_a_snapshot() {
    let directory = super::tests::Directory::new();
    let (store, _) = Store::open(&directory.0).unwrap();
    store.write_private_key(&[23; 32]).unwrap();
    drop(store);

    let enrolment = crate::node::Enrolment::new(b"coordinator", "host", b"agent key");
    crate::node::Node::prepare_enrolled_restore(&directory.0, enrolment).unwrap();
    let (restored, _) = Store::open(&directory.0).unwrap();
    assert!(restored.read_private_key().unwrap().is_none());
}
