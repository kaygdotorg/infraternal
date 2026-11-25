//! A failed retirement save on the Mac never leaves the old, peer-carrying snapshot enabled for
//! the next start (J330), and the deny state reaches disk before the worker is fenced.
//!
//! The first two tests make the state directory read-only, so the atomic rename fails and the
//! node falls back to its in-place write: once with no Store, and once with the node's Store open,
//! as a running Mac node keeps it (J778).

use super::{
    AUTHORITY_EPOCH_B, Arc, DefaultPolicy, Identity, Mutex, Node, PUBLIC_STATE, SavedState,
    chunks_with_epoch, config, fs, mac_private_public, read_public_state, recording_worker,
    recording_worker_with_replace_hook, route_addresses, write_public_state,
};
use std::os::unix::fs::PermissionsExt;

/// A failed retirement save must not leave the old snapshot enabled for restart.
#[test]
fn failed_retirement_does_not_preserve_a_persisted_peer_rollback() {
    failed_retirement_case(false);
}

/// The same failed retirement save with the node's own Store open, as on a running Mac node.
///
/// The Store holds a shared lease on the state directory for its whole life, so an in-place
/// fallback that locks that directory exclusively waits on its own process forever (J778, after
/// 26bc92ba5). The case runs on its own thread so a deadlock fails the test instead of hanging
/// the suite.
#[test]
fn failed_retirement_with_an_open_store_does_not_deadlock() {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        failed_retirement_case(true);
        let _ = done.send(());
    });
    match finished.recv_timeout(std::time::Duration::from_secs(30)) {
        Ok(()) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("the in-place fallback deadlocked on the node's own store lease")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("the failed retirement case panicked; see its message above")
        }
    }
}

/// Make the state directory read-only under a node holding a peer-carrying snapshot, apply a
/// peer-free authority replacement, and check that the node stops with a peer-free deny
/// snapshot on disk. With `open_store`, the node holds its Store (and so its directory lease)
/// throughout, as `Node::restore` leaves a running Mac node.
fn failed_retirement_case(open_store: bool) {
    let mut current = config();
    current.version = 11;
    let mut restored = current.clone();
    restored.version = 2;
    restored.peers.clear();
    let directory = std::env::temp_dir().join(format!(
        "infraternal-j330-mac-{}-{open_store}",
        std::process::id()
    ));
    fs::create_dir(&directory).expect("state directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("private state directory");
    let state_path = directory.join(PUBLIC_STATE);
    write_public_state(
        &state_path,
        &SavedState {
            enabled: true,
            config: Some(current.clone()),
            routes: route_addresses(&current),
            interface: Some("utun-test".to_owned()),
            port: 51820,
            ..SavedState::default()
        },
    )
    .expect("accepted snapshot");
    // Opened while the directory is still private and writable, as at node start.
    let store = open_store.then(|| {
        crate::node_state::Store::open_for_macos(&directory).expect("open the node's store")
    });
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500))
        .expect("make state directory unwritable");
    let identity = Identity {
        public_key: current.local_key.expect("bound key"),
        port: 51820,
        compact_access: true,
        #[cfg(feature = "mesh-dns")]
        dns_names: false,
        key_rotation: false,
        authority_epoch: true,
        rotation_continuity: false,
    };
    let applied_configs = Arc::new(Mutex::new(Vec::new()));
    let mut node = Node {
        enabled: true,
        worker: Some(recording_worker(Arc::clone(&applied_configs))),
        store,
        identity: Some(identity),
        config: Some(current.clone()),
        authority_reset_pending: false,
        pending: None,
        routes: route_addresses(&current),
        interface: Some("utun-test".to_owned()),
        port: 51820,
        path: Some(state_path.clone()),
        binding: None,
        network_status: crate::macos_node::subnet::NetworkStatus::default(),
    };
    let result = chunks_with_epoch(None, &restored, AUTHORITY_EPOCH_B)
        .into_iter()
        .try_for_each(|chunk| node.chunk(chunk).map(|_| ()));
    let saved = read_public_state(&state_path)
        .expect("read saved state")
        .expect("saved state exists");
    let runtime_configs = applied_configs.lock().expect("recorded configs").clone();
    let stopped_after_failure = !node.enabled && node.worker.is_none();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("restore state directory permissions");
    node.down().expect("stop test worker");
    fs::remove_dir_all(&directory).expect("remove state directory");

    assert!(
        result.is_err(),
        "the injected persistence failure was ignored"
    );
    assert_eq!(
        runtime_configs.len(),
        0,
        "a failed durable checkpoint must not apply a partial replacement"
    );
    assert!(
        stopped_after_failure,
        "a failed durable checkpoint must stop the runtime"
    );
    // The unwritable directory also blocks the authority record, so the epoch may still read
    // as the old one. That is safe: the saved snapshot is peer-free, and the next server
    // snapshot counts as an authority change (#382 P2).
    assert!(
        saved.config.as_ref().is_some_and(
            |config| config.peers.is_empty() && config.default_policy == DefaultPolicy::Deny
        ),
        "a failed replacement must leave a peer-free deny snapshot: {saved:?}"
    );
    assert!(
        !saved.enabled
            || saved
                .config
                .as_ref()
                .is_none_or(|config| config.peers.is_empty()),
        "a restart could restore the retired peer: {saved:?}"
    );
}

/// The peer-free authority state is durable before the worker hears about the new authority.
#[test]
fn mac_retirement_persists_deny_state_before_worker_fence() {
    let current = config();
    let directory = std::env::temp_dir().join(format!(
        "infraternal-j363-mac-retirement-order-{}",
        std::process::id()
    ));
    fs::create_dir(&directory).expect("state directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("private state directory");
    let state_path = directory.join(PUBLIC_STATE);
    write_public_state(
        &state_path,
        &SavedState {
            enabled: true,
            config: Some(current.clone()),
            routes: route_addresses(&current),
            interface: Some("utun-test".to_owned()),
            port: 51820,
            ..SavedState::default()
        },
    )
    .expect("persist original peer-bearing snapshot");
    let identity = Identity {
        public_key: current.local_key.expect("bound key"),
        port: 51820,
        compact_access: true,
        #[cfg(feature = "mesh-dns")]
        dns_names: false,
        key_rotation: false,
        authority_epoch: true,
        rotation_continuity: false,
    };
    let at_fence = Arc::new(Mutex::new(None));
    let observed = Arc::clone(&at_fence);
    let hook_path = state_path.clone();
    let mut node = Node {
        enabled: true,
        worker: Some(recording_worker_with_replace_hook(
            Arc::new(Mutex::new(Vec::new())),
            move |_| {
                let saved = read_public_state(&hook_path)
                    .expect("read state when worker retirement begins")
                    .expect("state exists when worker retirement begins");
                *observed.lock().expect("retirement state lock") = Some(saved);
            },
        )),
        identity: Some(identity),
        store: None,
        config: Some(current.clone()),
        authority_reset_pending: false,
        pending: None,
        routes: route_addresses(&current),
        interface: Some("utun-test".to_owned()),
        port: 51820,
        path: Some(state_path),
        binding: None,
        network_status: crate::macos_node::subnet::NetworkStatus::default(),
    };

    // The production replacement path: persist the reset, then hand the worker the
    // complete new snapshot. Read the disk between the two steps.
    let mut replacement = current.clone();
    replacement.authority_epoch = Some(AUTHORITY_EPOCH_B.to_owned());
    node.prepare_authority_replacement(&replacement)
        .expect("persist the new authority's reset");
    let saved_before_worker = read_public_state(&directory.join(PUBLIC_STATE))
        .expect("read state before the worker is told")
        .expect("state exists before the worker is told");
    let worker_touched_peers = at_fence.lock().expect("replacement state lock").is_some();
    node.down().expect("stop test worker");
    fs::remove_dir_all(directory).expect("remove state directory");

    assert!(
        !worker_touched_peers,
        "the worker was told before the reset was durable"
    );
    let denied = saved_before_worker
        .config
        .expect("retained denied snapshot");
    assert_eq!(denied.authority_epoch.as_deref(), Some(AUTHORITY_EPOCH_B));
    assert!(denied.peers.is_empty(), "retired peers were persisted");
    assert_eq!(denied.default_policy, DefaultPolicy::Deny);
    assert!(saved_before_worker.authority_reset_pending);
}

/// A changed authority retires its old rotation journal but keeps the active interface marker.
#[test]
fn authority_change_discards_old_rotation_journal() {
    authority_rotation_receipt_case(false, false, false);
}

/// A new coordinator process keeps the completed receipt for the same database operation.
#[test]
fn authority_change_keeps_the_matching_rotation_receipt() {
    authority_rotation_receipt_case(true, false, false);
}

/// An interrupted reset cannot retire a matching receipt from an unfinished snapshot header.
#[test]
fn j862_incomplete_reset_snapshot_retains_the_mac_rotation_receipt() {
    authority_rotation_receipt_case(true, true, false);
}

/// A rejected new authority stops old peers without deleting their pending completion receipt.
#[test]
fn rejected_new_authority_fences_peers_and_retains_the_mac_receipt() {
    authority_rotation_receipt_case(true, false, true);
}

/// Compare valid replacement, interrupted reset and rejected content against one active Mac key.
fn authority_rotation_receipt_case(continues: bool, incomplete: bool, rejected: bool) {
    let private_key = [9; 32];
    let active_key = mac_private_public(&private_key);
    let mut current = config();
    current.local_key = Some(active_key);
    let directory = std::env::temp_dir().join(format!(
        "infraternal-j363-mac-rotation-retirement-{}-{continues}-{incomplete}-{rejected}",
        std::process::id()
    ));
    fs::create_dir(&directory).expect("state directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("private state directory");
    let state_path = directory.join(PUBLIC_STATE);
    let store = crate::node_state::Store::open_for_macos(&directory).expect("open node store");
    store
        .record_interface(&active_key)
        .expect("record active key");
    store
        .replace_private_key(&private_key)
        .expect("save active key");
    store
        .save_rotation_secret(&crate::node_state::RotationSecret {
            operation_id: "00000000-0000-4000-8000-000000000367".to_owned(),
            sequence: 11,
            previous: [3; 32],
            candidate: private_key,
            commit_requested: true,
            completed: true,
        })
        .expect("save old authority journal");
    let identity = Identity {
        public_key: active_key,
        port: 51820,
        compact_access: true,
        #[cfg(feature = "mesh-dns")]
        dns_names: false,
        key_rotation: true,
        authority_epoch: true,
        rotation_continuity: true,
    };
    let store = Some(store);
    let applied = Arc::new(Mutex::new(Vec::new()));
    let mut node = Node {
        enabled: true,
        worker: Some(recording_worker(Arc::clone(&applied))),
        identity: Some(identity),
        store,
        config: Some(current.clone()),
        authority_reset_pending: false,
        pending: None,
        routes: route_addresses(&current),
        interface: Some("utun-test".to_owned()),
        port: 51820,
        path: Some(state_path),
        binding: None,
        network_status: crate::macos_node::subnet::NetworkStatus::default(),
    };

    let mut replacement = current.clone();
    replacement.authority_epoch = Some(AUTHORITY_EPOCH_B.to_owned());
    replacement.rotation_operation = continues.then(|| crate::dataplane::RotationContinuation {
        operation_id: "00000000-0000-4000-8000-000000000367".into(),
        sequence: 11,
    });
    if rejected {
        let mut chunk = crate::configuration::chunks(None, &replacement)
            .unwrap()
            .remove(0);
        chunk.rotation_operation = None;
        chunk.upserted.values_mut().next().unwrap().peer.key = active_key;
        assert_eq!(
            node.chunk(chunk).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(
            node.config
                .as_ref()
                .is_some_and(
                    |config| config.authority_epoch.as_deref() == Some(AUTHORITY_EPOCH_B)
                        && config.peers.is_empty()
                        && config.default_policy == DefaultPolicy::Deny
                )
        );
        assert!(node.worker.is_none());
        assert!(
            node.store
                .as_ref()
                .unwrap()
                .rotation_secret()
                .unwrap()
                .is_some()
        );
        let saved = read_public_state(node.path.as_ref().unwrap())
            .unwrap()
            .unwrap();
        assert!(saved.authority_reset_pending && !saved.enabled);
        assert!(saved.config.unwrap().peers.is_empty());
        drop(node);
        fs::remove_dir_all(directory).unwrap();
        return;
    }
    node.prepare_authority_replacement(&replacement)
        .expect("persist the new authority's reset");
    if incomplete {
        let mut chunk = crate::configuration::chunks(None, &replacement)
            .unwrap()
            .remove(0);
        chunk.rotation_operation = None;
        chunk.last = false;
        assert!(!node.chunk(chunk).expect("stage the first chunk only"));
        assert!(
            node.store
                .as_ref()
                .unwrap()
                .rotation_secret()
                .unwrap()
                .is_some()
        );
        let mut inconsistent = crate::configuration::chunks(None, &replacement)
            .unwrap()
            .remove(0);
        inconsistent.index = 1;
        assert_eq!(
            node.chunk(inconsistent).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(
            node.store
                .as_ref()
                .unwrap()
                .rotation_secret()
                .unwrap()
                .is_some()
        );
        let mut rejected = crate::configuration::chunks(None, &replacement)
            .unwrap()
            .remove(0);
        rejected.rotation_operation = None;
        rejected.upserted.values_mut().next().unwrap().peer.key = active_key;
        assert_eq!(
            node.chunk(rejected).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }
    #[cfg(feature = "mesh-dns")]
    if incomplete {
        // DNS is validated on the assembled config, not by an unfinished chunk header.
        let mut invalid_dns = replacement.clone();
        invalid_dns.rotation_operation = None;
        invalid_dns.dns_suffix = "bad..suffix".into();
        let chunk = crate::configuration::chunks(None, &invalid_dns)
            .unwrap()
            .remove(0);
        assert_eq!(
            node.chunk(chunk).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(
            node.store
                .as_ref()
                .unwrap()
                .rotation_secret()
                .unwrap()
                .is_some()
        );
    }
    let journal = node
        .store
        .as_ref()
        .expect("node store")
        .rotation_secret()
        .expect("read journal");
    let retained_key = node
        .store
        .as_ref()
        .expect("node store")
        .recorded_interface()
        .expect("read interface marker");
    let retained_private_key = node
        .store
        .as_ref()
        .expect("node store")
        .read_private_key()
        .expect("read active key");
    if continues && !incomplete {
        for chunk in crate::configuration::chunks(None, &replacement).expect("continuing snapshot")
        {
            node.chunk(chunk)
                .expect("complete interrupted authority adoption");
        }
        replacement.rotation_operation = None;
        for chunk in crate::configuration::chunks(None, &replacement).expect("completed snapshot") {
            node.chunk(chunk)
                .expect("clear operation metadata at the same policy revision");
        }
    }
    if incomplete {
        // Cached operation metadata must not substitute for the complete incoming proof.
        replacement.rotation_operation = None;
        for chunk in crate::configuration::chunks(None, &replacement).unwrap() {
            node.chunk(chunk).expect("accept a validated replacement");
        }
        assert!(
            node.store
                .as_ref()
                .unwrap()
                .rotation_secret()
                .unwrap()
                .is_none()
        );
    }
    node.down().expect("stop test worker");
    fs::remove_dir_all(directory).expect("remove state directory");

    println!(
        "J862_MAC_RESET incomplete={incomplete} retained_receipt={}",
        journal.is_some()
    );
    assert_eq!(
        journal.is_some(),
        continues,
        "only the matching receipt may remain"
    );
    assert_eq!(retained_key, Some(active_key));
    assert!(
        retained_private_key
            .as_ref()
            .is_some_and(|key| key.as_slice() == private_key)
    );
}
