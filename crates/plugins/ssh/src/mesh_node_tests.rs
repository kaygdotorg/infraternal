//! Checks the client-side file and socket safety rules and the session brake.
use super::*;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

/// Directory.
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

/// Only directories owned by root and closed to others are trusted.
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

/// Turning off or leaving the mesh ends sessions but renewal does not.
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

/// A brake ends a running connection.
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

/// A stale snapshot is reported not accepted.
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
        let first = node.call("mesh-ssh-node.configure", &serde_json::to_vec(&snapshot(5)).unwrap());
        assert!(first.is_ok());
        let stale = node.call("mesh-ssh-node.configure", &serde_json::to_vec(&snapshot(5)).unwrap());
        assert!(stale.is_err());
        let newer = node.call("mesh-ssh-node.configure", &serde_json::to_vec(&snapshot(6)).unwrap());
        assert!(newer.is_ok());
    });
}

/// Unauthenticated connections are bounded per source and in total.
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

/// The component registers in a real infraternal agent registry: every
/// action carries the plugin's ID as its prefix.
#[test]
fn the_component_registers_in_an_agent_registry() {
    let node = MeshSshNode::new(std::env::temp_dir(), |_| None).unwrap();
    let mut registry = infraternal_plugin_api::PluginRegistry::default();
    assert!(registry.register(Box::new(node)).is_ok());
}

/// The infraternal agent calls node plugins on its own OS thread with no
/// Tokio runtime; configuring the component there must not panic.
#[test]
fn configure_works_from_a_thread_without_a_runtime() {
    let configured = std::thread::spawn(|| {
        let mut node = MeshSshNode::new(std::env::temp_dir(), |_| None).unwrap();
        let input = json!({
            "enabled": false,
            "snapshot": {"sequence": 1, "node": 9, "ca": vec![7_u8; 32], "certificates": [], "grants": {}},
        });
        node.call(
            "mesh-ssh-node.configure",
            &serde_json::to_vec(&input).unwrap(),
        )
        .is_ok()
    })
    .join();
    assert!(matches!(configured, Ok(true)), "{configured:?}");
}

/// The key socket's directory must let every account reach the socket (the
/// peer-credential check decides who may ask), and stay closed to writes:
/// measured on compute01, where the agent's own `/run/infraternal` is 0700.
#[test]
fn the_socket_directory_is_traversable_and_closed() {
    let me = nix::unistd::Uid::effective().as_raw();
    let fresh = std::env::temp_dir().join(format!("j175-sock-{}", uuid::Uuid::new_v4().simple()));
    prepare_socket_directory(&fresh, me).unwrap();
    let existing = directory(0o700);
    prepare_socket_directory(&existing, me).unwrap();
    for path in [&fresh, &existing] {
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "{path:?}");
        assert!(trusted_directory(path, me));
    }
    // A directory someone else can write to is refused, never repaired.
    let open = directory(0o777);
    assert!(prepare_socket_directory(&open, me).is_err());
    for path in [fresh, existing, open] {
        std::fs::remove_dir_all(path).unwrap();
    }
}

/// Wait up to five seconds for `condition`.
fn eventually(condition: impl Fn() -> bool) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if condition() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    condition()
}

/// Stopping the infraternal agent removes the owned redirect before the
/// listener goes, so mesh :22 reaches the host's sshd again (contract
/// "Stop removes owned rules before releasing the listener"). Measured on
/// dev-02 (#221): before the stop hook, `systemctl stop` left both tables
/// and mesh :22 led to a closed port. A stopped component never binds again.
#[test]
#[ignore = "Run alone inside unshare -Urn with a disposable network namespace."]
fn stopping_the_agent_removes_the_redirect_and_mesh_22_reaches_sshd() {
    use std::net::{SocketAddr, TcpListener, TcpStream};
    for args in [
        ["link", "set", "lo", "up"].as_slice(),
        ["address", "add", "10.254.0.4/32", "dev", "lo"].as_slice(),
    ] {
        assert!(
            std::process::Command::new("/usr/bin/ip")
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    let address: IpAddr = "10.254.0.4".parse().unwrap();
    // The host's sshd holds the wildcard, so the component must redirect.
    let sshd = TcpListener::bind("0.0.0.0:22").unwrap();
    let ca = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
    let ca_public = ca.public_key().key_data().ed25519().unwrap().0;
    let sign = |body: &[u8]| {
        use russh::keys::signature::Signer as _;
        let signature: russh::keys::ssh_key::Signature = ca.try_sign(body).ok()?;
        signature.as_bytes().try_into().ok()
    };
    let mut node = MeshSshNode::new(std::env::temp_dir(), |_| None).unwrap();
    let host_key = node.shared.host_key.public_key().clone();
    let principals = ["db-04".to_owned()];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let certificate = crate::mesh_issue::host_certificate(
        ca_public,
        &sign,
        &crate::mesh_issue::HostRequest {
            subject: &host_key,
            principals: &principals,
            now,
            lifetime: 3600,
        },
    )
    .unwrap();
    let view = MeshView {
        node: 9,
        addresses: vec![address],
        interface: "infraternal0".into(),
        peers: std::collections::BTreeMap::new(),
    };
    let observe = node.mesh_observer();
    observe(Some(view.clone()));
    let configure = |node: &mut MeshSshNode, sequence: u64| {
        let input = json!({
            "enabled": true,
            "snapshot": {"sequence": sequence, "node": 9, "ca": ca_public.to_vec(), "certificates": [], "grants": {}},
            "host_certificate": certificate.to_openssh().unwrap(),
        });
        node.call(
            "mesh-ssh-node.configure",
            &serde_json::to_vec(&input).unwrap(),
        )
    };
    configure(&mut node, 1).unwrap();
    assert!(
        eventually(|| crate::mesh_port::presence(address).unwrap_or(false)),
        "the redirect was never installed"
    );

    let hook = node.stop_hook().upgrade().expect("a live component's hook");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(3), hook.stop()).await })
        .expect("the stop hook finished within its bound");
    // Rules are gone by the time the hook returns, not eventually.
    assert!(!crate::mesh_port::presence(address).unwrap());
    let client = TcpStream::connect_timeout(&SocketAddr::new(address, 22), Duration::from_secs(1))
        .expect("mesh :22 reaches the host's sshd");
    let (_, peer) = sshd.accept().unwrap();
    assert_eq!(peer, client.local_addr().unwrap());

    // Later configuration (a push racing the shutdown) never binds again.
    let _ = configure(&mut node, 2);
    observe(Some(view));
    std::thread::sleep(Duration::from_millis(500));
    assert!(!crate::mesh_port::presence(address).unwrap());
    // The hook never keeps a finished component alive.
    let weak = node.stop_hook();
    drop(hook);
    drop(node);
    assert!(eventually(|| weak.upgrade().is_none()));
}

/// J236 P1-1 (#221 comment 79805): while logins keep overlapping, a
/// revoking push must still land, and a login that starts after it must see
/// it. Before the fix every push came back busy (J236: 0 of 30), so a person
/// who still had access could hold off their own revocation.
#[test]
fn a_revoking_push_lands_while_logins_keep_overlapping() {
    use crate::mesh_admission::CurrentAccess as _;
    const PERSON: &str = "0b5c8a64-7d1f-4c43-9d0e-0c6a8a5b7f10";
    let mut node = MeshSshNode::new(std::env::temp_dir(), |_| None).unwrap();
    let push = |node: &mut MeshSshNode, sequence: u64, grants: serde_json::Value| {
        let input = json!({
            "enabled": false,
            "snapshot": {"sequence": sequence, "node": 9, "ca": vec![7_u8; 32], "certificates": [], "grants": grants},
        });
        node.call(
            "mesh-ssh-node.configure",
            &serde_json::to_vec(&input).unwrap(),
        )
        .is_ok()
    };
    assert!(push(&mut node, 1, json!({ PERSON: {"any_account": true} })));
    node.mesh_observer()(Some(MeshView {
        node: 9,
        addresses: vec!["10.254.0.9".parse().unwrap()],
        interface: "infraternal0".into(),
        peers: std::collections::BTreeMap::new(),
    }));
    let runtime = node.handle().unwrap();
    let shared = Arc::clone(&node.shared);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while runtime.block_on(shared.authority.current()).is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "the mesh view never applied"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // Two staggered logins, each holding the guard 300 ms, as a channel open
    // does across the shim login.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let logins: Vec<_> = [0_u64, 150]
        .into_iter()
        .map(|offset| {
            let shared = Arc::clone(&shared);
            let stop = Arc::clone(&stop);
            runtime.spawn(async move {
                tokio::time::sleep(Duration::from_millis(offset)).await;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let guard = shared.authority.current().await;
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    drop(guard);
                }
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(200));
    let mut accepted = None;
    for attempt in 0..30_u64 {
        if push(&mut node, 10 + attempt, json!({})) {
            accepted = Some(attempt);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let still_allowed = runtime.block_on(async {
        shared
            .authority
            .current()
            .await
            .is_ok_and(|guard| guard.login_access(PERSON, 9, "kayg"))
    });
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for login in logins {
        runtime.block_on(login).unwrap();
    }
    assert!(accepted.is_some(), "a revoking push never installed");
    assert!(!still_allowed, "a login after the revocation still passed");
}

/// J236 P3-2 (#221): turning a person off (`{"person":null}`, pushed to every
/// node with mesh SSH off) removes only client files infraternal wrote, the
/// same content check uninstall makes; a same-named file it did not write
/// stays.
#[test]
fn turning_the_client_off_removes_only_files_infraternal_wrote() {
    use infraternal_plugin_api::mesh_ssh_files::{CONFIG_PATH, HEADER, KNOWN_HOSTS_PATH};
    let root = directory(0o755);
    let at = |path: &str| root.join(path.trim_start_matches('/'));
    std::fs::create_dir_all(at(CONFIG_PATH).parent().unwrap()).unwrap();
    let mut node = MeshSshNode::new(std::env::temp_dir(), |_| None)
        .unwrap()
        .with_files_root(root.clone());
    let off = serde_json::to_vec(&json!({"person": null})).unwrap();
    // Not ours: a person's own files of the same names stay.
    std::fs::write(at(CONFIG_PATH), "Host *\n    User someone\n").unwrap();
    std::fs::write(at(KNOWN_HOSTS_PATH), "db-01 ssh-ed25519 AAAA\n").unwrap();
    node.call("mesh-ssh-node.client", &off).unwrap();
    assert!(at(CONFIG_PATH).exists());
    assert!(at(KNOWN_HOSTS_PATH).exists());
    // Ours: removed.
    std::fs::write(at(CONFIG_PATH), format!("{HEADER} for mesh names only.\n")).unwrap();
    std::fs::write(
        at(KNOWN_HOSTS_PATH),
        "@cert-authority *.mesh ssh-ed25519 AAAA\n",
    )
    .unwrap();
    node.call("mesh-ssh-node.client", &off).unwrap();
    assert!(!at(CONFIG_PATH).exists());
    assert!(!at(KNOWN_HOSTS_PATH).exists());
    std::fs::remove_dir_all(root).unwrap();
}

/// J236 P3-3 (#221): the key socket decides per message, not only when a
/// connection is accepted. A connection from the allowed account keeps no
/// signing power once that account is no longer allowed, even if a new
/// identity arrives later.
#[test]
fn a_key_socket_connection_loses_the_identity_when_its_account_is_no_longer_allowed() {
    use russh::keys::signature::Signer as _;
    let node = MeshSshNode::new(std::env::temp_dir(), |_| None).unwrap();
    let ca = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
    let key = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let certificate = crate::mesh_issue::person_certificate(
        ca.public_key().key_data().ed25519().unwrap().0,
        &|body: &[u8]| {
            let signature: russh::keys::ssh_key::Signature = ca.try_sign(body).ok()?;
            signature.as_bytes().try_into().ok()
        },
        &crate::mesh_issue::PersonRequest {
            subject: key.public_key(),
            person: "0b5c8a64-7d1f-4c43-9d0e-0c6a8a5b7f10",
            source_address: "10.254.0.7".parse().unwrap(),
            now,
            lifetime: 3600,
        },
    )
    .unwrap();
    *node.shared.identity.write().unwrap() = Some(Arc::new(PersonKey { certificate, key }));
    *node.shared.allowed.write().unwrap() = Some(1500);
    let ordinary = infraternal_plugin_api::login_access::OrdinaryUids::LINUX;
    let identity = socket_identity(Arc::clone(&node.shared), 1500, ordinary);
    assert!(
        identity().is_some(),
        "the allowed account gets the identity"
    );
    // Another account is allowed now (the machine's added-with changed).
    *node.shared.allowed.write().unwrap() = Some(1600);
    assert!(
        identity().is_none(),
        "the earlier connection kept the identity"
    );
    // Turned off, then on again for this account: it may ask again.
    *node.shared.allowed.write().unwrap() = Some(1500);
    assert!(identity().is_some());
}
