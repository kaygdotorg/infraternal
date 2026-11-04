//! Checks the client-side file and socket safety rules and the session brake.
use super::*;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

fn directory(mode: u32) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "j175-node-{}-{mode:o}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[test]
fn only_directories_owned_by_root_and_closed_to_others_are_trusted() {
    // J181 M4: a writable known-hosts directory would let any local user add
    // their own CA for mesh names. Tests stand in their own uid for root.
    let me = nix::unistd::Uid::effective().as_raw();
    let closed = directory(0o755);
    assert!(trusted_directory(&closed, me));
    assert!(!trusted_directory(&closed, me.wrapping_add(1)));
    for open in [0o775, 0o777, 0o757] {
        let open = directory(open);
        assert!(!trusted_directory(&open, me), "{open:?}");
        std::fs::remove_dir_all(open).unwrap();
    }
    assert!(!trusted_directory(Path::new("/nonexistent/j175"), me));
    std::fs::remove_dir_all(closed).unwrap();
}

#[test]
fn turning_off_or_leaving_the_mesh_ends_sessions_but_renewal_does_not() {
    // J181 M7: off is the emergency brake for open connections.
    let key = |node, certificate: &[u8]| {
        Some(ListenerKey {
            node,
            addresses: vec!["10.254.0.9".parse().unwrap()],
            interface: "infraternal0".into(),
            certificate: certificate.to_vec(),
        })
    };
    assert!(ends_sessions(key(9, b"a").as_ref(), None));
    assert!(ends_sessions(key(9, b"a").as_ref(), key(10, b"a").as_ref()));
    assert!(!ends_sessions(key(9, b"a").as_ref(), key(9, b"b").as_ref()));
    assert!(!ends_sessions(None, key(9, b"a").as_ref()));
}

#[tokio::test]
async fn a_brake_ends_a_running_connection() {
    let (brake, watched) = watch::channel(0_u64);
    let running = tokio::spawn(until_braked(std::future::pending::<()>(), watched));
    brake.send_replace(1);
    tokio::time::timeout(std::time::Duration::from_secs(5), running)
        .await
        .expect("connection ended")
        .unwrap();
}

#[test]
fn a_stale_snapshot_is_reported_not_accepted() {
    // J181 M1: the server must learn that a push was refused.
    let node = MeshSshNode::new(std::env::temp_dir(), |_| None).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut node = node;
        let snapshot = |sequence| {
            json!({
                "enabled": false,
                "snapshot": {"sequence": sequence, "node": 9, "ca": vec![7_u8; 32], "certificates": [], "grants": {}},
            })
        };
        let first = node.call("mesh.ssh.configure", &serde_json::to_vec(&snapshot(5)).unwrap());
        assert!(first.is_ok());
        let stale = node.call("mesh.ssh.configure", &serde_json::to_vec(&snapshot(5)).unwrap());
        assert!(stale.is_err());
        let newer = node.call("mesh.ssh.configure", &serde_json::to_vec(&snapshot(6)).unwrap());
        assert!(newer.is_ok());
    });
}

#[test]
fn unauthenticated_connections_are_bounded_per_source_and_in_total() {
    // J181 M2: a peer with no key cannot exhaust the agent's descriptors.
    let pending = Pending::default();
    let a: IpAddr = "10.254.0.7".parse().unwrap();
    let b: IpAddr = "10.254.0.8".parse().unwrap();
    let held: Vec<_> = (0..PENDING_PER_SOURCE)
        .map(|_| pending.admit(a).expect("within the source bound"))
        .collect();
    assert!(pending.admit(a).is_none());
    assert!(pending.admit(b).is_some());
    drop(held);
    assert!(pending.admit(a).is_some());
    let mut many = Vec::new();
    for index in 0..PENDING_TOTAL {
        let source = IpAddr::from([10, 254, 1, u8::try_from(index % 250).unwrap()]);
        if let Some(slot) = pending.admit(source) {
            many.push(slot);
        }
    }
    assert!(pending.admit("10.254.2.1".parse().unwrap()).is_none());
}
