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

fn public_state(peers: u16) -> State {
    let mut config = Config {
        local_key: Some(PublicKey([1; 32])),
        server: Some(NodeId(1)),
        node: NodeId(2),
        #[cfg(feature = "mesh-dns-spike")]
        name: None,
        #[cfg(feature = "mesh-dns-spike")]
        dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
        version: 7,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().unwrap(),
            ipv6: "fd01::2".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: BTreeMap::new(),
        #[cfg(feature = "mesh-dns-spike")]
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
                    addresses: Addresses {
                        ipv4: [10, 254, a, b].into(),
                        ipv6: std::net::Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, index),
                    },
                    endpoint: Some(([10, 220, a, b], 7443).into()),
                },
                inbound: TrafficPolicy::All,
                outbound: TrafficPolicy::None,
                access_ssh: None,
            },
        );
    }
    State {
        enabled: false,
        config: Some(config),
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
