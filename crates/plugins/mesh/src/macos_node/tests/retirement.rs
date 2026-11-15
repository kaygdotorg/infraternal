//! A failed retirement save on the Mac never leaves the old, peer-carrying snapshot enabled for
//! the next start (J330), and the deny state reaches disk before the worker is fenced.
//!
//! The first test makes the state directory read-only, so the atomic rename fails and the node
//! falls back to its in-place write.

use super::{
    AUTHORITY_EPOCH_B, Arc, DefaultPolicy, Identity, Mutex, Node, PUBLIC_STATE, SavedState,
    chunks_with_epoch, config, fs, read_public_state, recording_worker,
    recording_worker_with_replace_hook, route_addresses, write_public_state,
};
use std::os::unix::fs::PermissionsExt;

/// A failed retirement save must not leave the old snapshot enabled for restart.
#[test]
fn failed_retirement_does_not_preserve_a_persisted_peer_rollback() {
    let mut current = config();
    current.version = 11;
    let mut restored = current.clone();
    restored.version = 2;
    restored.peers.clear();
    let directory =
        std::env::temp_dir().join(format!("infraternal-j330-mac-{}", std::process::id()));
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
    };
    let applied_configs = Arc::new(Mutex::new(Vec::new()));
    let mut node = Node {
        enabled: true,
        worker: Some(recording_worker(Arc::clone(&applied_configs))),
        store: None,
        identity: Some(identity),
        config: Some(current.clone()),
        authority_reset_pending: false,
        pending: None,
        routes: route_addresses(&current),
        interface: Some("utun-test".to_owned()),
        port: 51820,
        path: Some(state_path.clone()),
        binding: None,
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
