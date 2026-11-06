//! Exercises the real restart ingress fence before retained replacement aliases are reconciled [166,199], #173.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::{
    dataplane::DefaultPolicy,
    firewall::Backend,
    policy::model::{Addresses, NodeId},
};
use std::{
    net::UdpSocket,
    process::{Command, Stdio},
    time::Duration,
};
fn command(program: &str, args: &[&str]) {
    assert!(
        Command::new(program)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
}

/// Stop a child test at one rotation durability boundary so its parent can send SIGKILL.
pub(super) fn crash_checkpoint(name: &str) {
    if std::env::var("INFRATERNAL_ROTATION_CRASH_POINT").as_deref() != Ok(name) {
        return;
    }
    let ready = std::env::var_os("INFRATERNAL_ROTATION_CRASH_READY")
        .expect("the crash proof supplies a readiness path");
    std::fs::write(ready, name).expect("publish the reached crash boundary");
    loop {
        std::thread::park();
    }
}

/// Exercise the child side of [`gotatun_rotation_recovers_after_sigkill_at_every_durable_step`].
#[test]
#[ignore = "launched by the GotaTun SIGKILL recovery proof"]
fn gotatun_rotation_crash_child() {
    let state = std::env::var_os("INFRATERNAL_ROTATION_STATE")
        .expect("the parent supplies the isolated state directory");
    let state = std::path::PathBuf::from(state);
    let mut node = Node::restore_with_engine(&state, EngineKind::GotaTun).unwrap();
    let previous = node.up().unwrap();
    assert!(previous.key_rotation, "GotaTun offers durable rotation");
    std::fs::write(
        state.join("rotation-crash-previous-public"),
        previous.public_key.0,
    )
    .expect("save the public predecessor for the parent proof");
    let operation = "00000000-0000-4000-8000-000000000367";
    node.prepare_rotation(operation, 1).unwrap();
    node.commit_rotation(operation, 1).unwrap();
    node.finish_rotation(operation, 1).unwrap();
    crash_checkpoint("rotation_finished");
    panic!("the requested crash boundary was never reached");
}

/// SIGKILL after each durable GotaTun transition leaves enough journal evidence to restart safely.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn gotatun_rotation_recovers_after_sigkill_at_every_durable_step() {
    use std::{
        os::unix::process::ExitStatusExt,
        process::Stdio,
        time::{Duration, Instant},
    };

    let stages = [
        "rotation_prepared",
        "rotation_commit_requested",
        "rotation_device_key_changed",
        "rotation_owner_marker_changed",
        "rotation_private_key_saved",
        "rotation_finished",
    ];
    for stage in stages {
        let state = RotationState::new();
        let ready = state.0.join("rotation-crash-ready");
        let mut child = Command::new(std::env::current_exe().expect("test binary"))
            .args(["--ignored", "gotatun_rotation_crash_child", "--nocapture"])
            .env("INFRATERNAL_ROTATION_STATE", &state.0)
            .env("INFRATERNAL_ROTATION_CRASH_POINT", stage)
            .env("INFRATERNAL_ROTATION_CRASH_READY", &ready)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the rotation child");
        let deadline = Instant::now() + Duration::from_secs(20);
        while !ready.exists() {
            if let Some(status) = child.try_wait().expect("check the child") {
                let output = child.wait_with_output().expect("collect the child's failure");
                panic!(
                    "child exited before {stage}: {status}\n{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            assert!(Instant::now() < deadline, "child did not reach {stage}");
            // sleep: allow the child to finish the next durability boundary without busy polling.
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().expect("send SIGKILL at the reached boundary");
        let status = child.wait().expect("reap the killed child");
        assert_eq!(status.signal(), Some(nix::libc::SIGKILL), "stage {stage}");

        let previous: [u8; 32] = std::fs::read(state.0.join("rotation-crash-previous-public"))
            .expect("child recorded the predecessor")
            .try_into()
            .expect("public key length");
        let (store, _) = crate::node_state::Store::open(&state.0).expect("open the journal");
        let journal = store
            .rotation_secret()
            .expect("read the journal")
            .expect("prepared rotation survives SIGKILL");
        let previous_public = if journal.completed {
            assert!(journal.previous == [0; 32], "finish erases the predecessor");
            crate::policy::model::PublicKey(previous)
        } else {
            Key::from_private(&journal.previous).unwrap().1
        };
        let candidate_public = Key::from_private(&journal.candidate).unwrap().1;
        assert_eq!(previous_public.0, previous, "stage {stage}");
        assert_eq!(journal.completed, stage == "rotation_finished", "stage {stage}");
        drop(journal);
        drop(store);

        let expects_candidate = stage != "rotation_prepared";
        let expected = if expects_candidate {
            candidate_public
        } else {
            previous_public
        };
        let mut restored = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
        let identity = restored.up().unwrap();
        assert!(identity.key_rotation, "GotaTun retains rotation support");
        assert_eq!(identity.public_key, expected, "recovered key at {stage}");
        let link = Device::active_link().unwrap().unwrap();
        assert_eq!(link.owner, Some(expected), "recovered owner marker at {stage}");
        let (store, _) = crate::node_state::Store::open(&state.0).unwrap();
        let bytes = store.read_private_key().unwrap().unwrap();
        assert_eq!(
            crate::gotatun_node::secret_from_bytes(&bytes).unwrap().1,
            expected,
            "recovered private-key file at {stage}"
        );
        restored.commit_rotation("00000000-0000-4000-8000-000000000367", 1)
            .unwrap();
        restored.finish_rotation("00000000-0000-4000-8000-000000000367", 1)
            .unwrap();
        assert!(store.rotation_secret().unwrap().unwrap().completed);
        drop(store);
        restored.down().unwrap();
    }
}
// Keep the retained address, recovery fence and packet observation in one scenario.
fn check(backend: Backend) {
    let mut node = Node::with_firewall(Firewall::for_backend(backend));
    node.up().unwrap();
    let proposed = Addresses {
        ipv4: "10.254.0.3".parse().unwrap(),
        ipv6: "fd01::3".parse().unwrap(),
    };
    Device::addresses(proposed).unwrap();
    let accepted = Config {
        local_key: None,
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns-spike")]
        name: None,
        #[cfg(feature = "mesh-dns-spike")]
        dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
        version: 1,
        addresses: Addresses {
            ipv4: "10.254.0.1".parse().unwrap(),
            ipv6: "fd01::1".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: BTreeMap::new(),
        #[cfg(feature = "mesh-dns-spike")]
        peer_names: std::collections::BTreeMap::new(),
    };
    // Restore invokes this same boundary with no in-memory accepted config.
    // The kernel can still carry a proposed address from an interrupted apply.
    assert!(node.config.is_none());
    node.apply_fence(&accepted, &accepted).unwrap();
    let mut child = Command::new("unshare")
        .args(["-n", "sleep", "30"])
        .spawn()
        .unwrap();
    let pid = child.id().to_string();
    for _ in 0..100 {
        if std::fs::read_link(format!("/proc/{pid}/ns/net")).unwrap()
            != std::fs::read_link("/proc/self/ns/net").unwrap()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    command(
        "ip",
        &[
            "link",
            "add",
            "underlay0",
            "type",
            "veth",
            "peer",
            "name",
            "underlay1",
        ],
    );
    command("ip", &["link", "set", "underlay1", "netns", &pid]);
    command("ip", &["addr", "add", "10.220.0.1/24", "dev", "underlay0"]);
    command("ip", &["link", "set", "underlay0", "up"]);
    command(
        "nsenter",
        &[
            "-t",
            &pid,
            "-n",
            "ip",
            "addr",
            "add",
            "10.220.0.2/24",
            "dev",
            "underlay1",
        ],
    );
    command(
        "nsenter",
        &["-t", &pid, "-n", "ip", "link", "set", "underlay1", "up"],
    );
    command(
        "nsenter",
        &[
            "-t",
            &pid,
            "-n",
            "ip",
            "route",
            "add",
            "10.254.0.3/32",
            "via",
            "10.220.0.1",
        ],
    );
    let receiver = UdpSocket::bind((proposed.ipv4, 5540)).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    command(
        "nsenter",
        &[
            "-t",
            &pid,
            "-n",
            "python3",
            "-c",
            "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'public-fixture',('10.254.0.3',5540))",
        ],
    );
    let result = receiver.recv_from(&mut [0; 64]);
    child.kill().unwrap();
    child.wait().unwrap();
    node.down().unwrap();
    assert!(
        result.is_err(),
        "retained replacement address accepted underlay traffic during restart fence"
    );
}

/// A private, mode-0700 state directory removed when the test ends.
struct RotationState(std::path::PathBuf);
impl RotationState {
    /// Create a fresh directory named for this process and the current time.
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "infraternal-mesh-rotation-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for RotationState {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The live link's index and owner marker, and the public key its private key derives.
fn kernel_link_identity() -> (
    u32,
    Option<crate::policy::model::PublicKey>,
    crate::policy::model::PublicKey,
) {
    let link = Device::active_link().unwrap().unwrap();
    assert_eq!(link.engine, EngineKind::Kernel);
    let private = Device::private_key_at(link.ifindex).unwrap();
    let (_, public) = Key::from_private(&private[..]).unwrap();
    (link.ifindex, link.owner, public)
}

/// A kernel rotation sends the candidate to our own link by its index, moves the owner marker
/// with it and records it; the link keeps its index throughout (#285).
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn kernel_rotation_sends_the_candidate_to_our_index_and_moves_the_marker() {
    let state = RotationState::new();
    let operation = "00000000-0000-4000-8000-000000000003";
    let mut node = Node::restore_with_engine(&state.0, EngineKind::Kernel).unwrap();
    let previous = node.up().unwrap();
    assert!(previous.key_rotation, "kernel WireGuard offers rotation");
    let (index, owner, key) = kernel_link_identity();
    assert_eq!(
        (owner, key),
        (Some(previous.public_key), previous.public_key)
    );

    let candidate = node.prepare_rotation(operation, 1).unwrap();
    assert_ne!(candidate, previous.public_key);
    assert_eq!(
        kernel_link_identity(),
        (index, Some(previous.public_key), previous.public_key),
        "preparing changes nothing on the link"
    );

    let committed = node.commit_rotation(operation, 1).unwrap();
    assert_eq!(committed.public_key, candidate);
    assert_eq!(
        kernel_link_identity(),
        (index, Some(candidate), candidate),
        "the candidate key and marker are on our link, at the same index"
    );
    let (store, _) = crate::node_state::Store::open(&state.0).unwrap();
    assert_eq!(store.recorded_interface().unwrap(), Some(candidate));
    assert_eq!(
        node.commit_rotation(operation, 1).unwrap().public_key,
        candidate,
        "a repeated commit changes nothing"
    );
    node.finish_rotation(operation, 1).unwrap();
    assert!(Node::plan_retirement(&state.0).unwrap().interface);
    node.down().unwrap();
}

/// The `GotaTun` node reports rotation support and changes its key, marker and private key file together.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn gotatun_rotation_changes_the_live_identity_and_marker() {
    let state = RotationState::new();
    let operation = "00000000-0000-4000-8000-000000000041";
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    let previous = node.up().unwrap();
    assert!(previous.key_rotation, "GotaTun offers durable rotation");
    let link = Device::active_link().unwrap().unwrap();
    assert_eq!(link.engine, EngineKind::GotaTun);
    assert_eq!(link.owner, Some(previous.public_key));

    let candidate = node.prepare_rotation(operation, 1).unwrap();
    assert_ne!(candidate, previous.public_key);
    assert_eq!(
        Device::active_link().unwrap().unwrap().owner,
        Some(previous.public_key),
        "prepare leaves the live TUN identity unchanged"
    );

    let committed = node.commit_rotation(operation, 1).unwrap();
    assert_eq!(committed.public_key, candidate);
    assert_eq!(
        Device::active_link().unwrap().unwrap().owner,
        Some(candidate),
        "the TUN marker follows the active device key"
    );
    let (store, _) = crate::node_state::Store::open(&state.0).unwrap();
    assert_eq!(store.recorded_interface().unwrap(), Some(candidate));
    let bytes = store.read_private_key().unwrap().unwrap();
    assert_eq!(
        crate::gotatun_node::secret_from_bytes(&bytes).unwrap().1,
        candidate
    );
    node.finish_rotation(operation, 1).unwrap();
    assert!(store.rotation_secret().unwrap().unwrap().completed);
    drop(store);
    node.down().unwrap();
}

/// After a rotation, a restarted node still adopts its interface as its own.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn rotated_interface_remains_owned_after_process_restart() {
    use std::time::Instant;

    let state = RotationState::new();
    let path = state.0.clone();
    let operation = "00000000-0000-4000-8000-000000000002";
    let mut node = Node::restore_with_engine(&path, EngineKind::Kernel).unwrap();
    let previous = node.up().unwrap();
    let (index, _, _) = kernel_link_identity();
    let candidate = node.prepare_rotation(operation, 1).unwrap();
    assert_ne!(previous.public_key, candidate);
    assert!(
        Node::plan_retirement(&path).unwrap().interface,
        "the previous key remains owned before local activation"
    );

    // Recreate the crash boundary after the durable commit intent and kernel
    // key update, but before the ownership marker can be replaced.
    let (store, _) = crate::node_state::Store::open(&path).unwrap();
    let mut rotation = store.rotation_secret().unwrap().unwrap();
    rotation.commit_requested = true;
    store.save_rotation_secret(&rotation).unwrap();
    let (candidate_key, candidate_public) = Key::from_private(&rotation.candidate).unwrap();
    assert_eq!(candidate_public, candidate);
    Device::configure(index, previous.public_key, &candidate_key, previous.port).unwrap();
    assert_eq!(
        kernel_link_identity(),
        (index, Some(previous.public_key), candidate),
        "the crash left the candidate key under the predecessor's marker"
    );
    assert!(
        Node::plan_retirement(&path).unwrap().interface,
        "the candidate key is owned after kernel acceptance even before the marker update"
    );
    drop(rotation);
    drop(store);
    drop(node);

    let started = Instant::now();
    let mut restored = Node::restore_with_engine(&path, EngineKind::Kernel).unwrap();
    let identity = restored.up().unwrap();
    let recovery_us = started.elapsed().as_micros();
    assert_eq!(identity.public_key, candidate);
    assert!(
        Node::plan_retirement(&path).unwrap().interface,
        "the rotated kernel interface must remain provably owned after restart"
    );
    // The retried commit finishes what the crash interrupted: the marker, then the record.
    restored.commit_rotation(operation, 1).unwrap();
    assert_eq!(kernel_link_identity(), (index, Some(candidate), candidate));
    println!("METRIC mesh_rotation_restart_recovery_us={recovery_us}");
    restored.down().unwrap();
}

/// J262: after the coordinator abandons an operation this node only prepared (a probe that could not show
/// support), a strictly higher sequence settles the open journal on the live key and prepares the new operation,
/// on the live node and after a restart. A lower or equal sequence is still refused.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn a_higher_sequence_settles_a_prepared_journal_the_coordinator_abandoned() {
    let state = RotationState::new();
    let first = "00000000-0000-4000-8000-000000000011";
    let second = "00000000-0000-4000-8000-000000000012";
    let mut node = Node::restore_with_engine(&state.0, EngineKind::Kernel).unwrap();
    let live = node.up().unwrap().public_key;
    let abandoned = node.prepare_rotation(first, 1).unwrap();
    let (index, _, _) = kernel_link_identity();
    assert_eq!(
        node.prepare_rotation(second, 1)
            .map(|_| ())
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock,
        "a sequence that does not move past the open operation proves nothing"
    );

    // The coordinator abandoned `first` (sequence + 1) and began `second` (sequence + 1 again).
    let fresh = node.prepare_rotation(second, 3).unwrap();
    assert_ne!(fresh, abandoned);
    assert_ne!(fresh, live);
    assert_eq!(
        kernel_link_identity(),
        (index, Some(live), live),
        "settling the abandoned candidate changes nothing on the link"
    );
    let (store, _) = crate::node_state::Store::open(&state.0).unwrap();
    let journal = store.rotation_secret().unwrap().unwrap();
    assert_eq!(
        (journal.operation_id.as_str(), journal.sequence),
        (second, 3)
    );
    assert_eq!(Key::from_private(&journal.previous).unwrap().1, live);
    drop(journal);
    drop(store);
    drop(node);

    let mut restored = Node::restore_with_engine(&state.0, EngineKind::Kernel).unwrap();
    assert_eq!(restored.up().unwrap().public_key, live);
    assert_eq!(
        restored.prepare_rotation(second, 3).unwrap(),
        fresh,
        "a retried prepare after a restart returns the same candidate"
    );
    let committed = restored.commit_rotation(second, 3).unwrap();
    assert_eq!(committed.public_key, fresh);
    assert_eq!(kernel_link_identity(), (index, Some(fresh), fresh));
    restored.down().unwrap();
}

/// J262, downgrade and upgrade back: the node committed its candidate, then ran a binary without rotation
/// support, so the coordinator abandoned the operation while the journal stayed open. On the upgraded binary a
/// higher sequence completes the old journal on the candidate the link holds and rotates from it.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn a_committed_journal_left_open_by_a_downgrade_is_completed_by_a_higher_sequence() {
    let state = RotationState::new();
    let first = "00000000-0000-4000-8000-000000000021";
    let second = "00000000-0000-4000-8000-000000000022";
    let mut node = Node::restore_with_engine(&state.0, EngineKind::Kernel).unwrap();
    let original = node.up().unwrap().public_key;
    let committed = node.prepare_rotation(first, 1).unwrap();
    node.commit_rotation(first, 1).unwrap();
    let (index, _, _) = kernel_link_identity();
    // The older binary never finishes the operation; the upgraded one restarts on the open journal.
    drop(node);

    let mut upgraded = Node::restore_with_engine(&state.0, EngineKind::Kernel).unwrap();
    assert_eq!(upgraded.up().unwrap().public_key, committed);
    let next = upgraded.prepare_rotation(second, 3).unwrap();
    assert!(next != committed && next != original);
    let (store, _) = crate::node_state::Store::open(&state.0).unwrap();
    let journal = store.rotation_secret().unwrap().unwrap();
    assert_eq!(
        Key::from_private(&journal.previous).unwrap().1,
        committed,
        "the new operation rotates from the key the link holds"
    );
    assert_eq!(store.recorded_interface().unwrap(), Some(committed));
    drop(journal);
    drop(store);
    upgraded.commit_rotation(second, 3).unwrap();
    assert_eq!(kernel_link_identity(), (index, Some(next), next));
    upgraded.down().unwrap();
}

/// J262 with a stop inside the abandoned commit: the candidate key reached the link but the marker still names
/// the predecessor. Settling finishes the marker on our index before the new operation starts.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn settling_an_abandoned_commit_moves_the_marker_the_stop_left_behind() {
    let state = RotationState::new();
    let first = "00000000-0000-4000-8000-000000000031";
    let second = "00000000-0000-4000-8000-000000000032";
    let mut node = Node::restore_with_engine(&state.0, EngineKind::Kernel).unwrap();
    let previous = node.up().unwrap();
    let candidate = node.prepare_rotation(first, 1).unwrap();
    let (index, _, _) = kernel_link_identity();
    let (store, _) = crate::node_state::Store::open(&state.0).unwrap();
    let mut rotation = store.rotation_secret().unwrap().unwrap();
    rotation.commit_requested = true;
    store.save_rotation_secret(&rotation).unwrap();
    let (candidate_key, _) = Key::from_private(&rotation.candidate).unwrap();
    Device::configure(index, previous.public_key, &candidate_key, previous.port).unwrap();
    drop(rotation);
    drop(store);
    drop(node);
    assert_eq!(
        kernel_link_identity(),
        (index, Some(previous.public_key), candidate)
    );

    let mut restored = Node::restore_with_engine(&state.0, EngineKind::Kernel).unwrap();
    assert_eq!(restored.up().unwrap().public_key, candidate);
    let next = restored.prepare_rotation(second, 3).unwrap();
    assert_ne!(next, candidate);
    assert_eq!(
        kernel_link_identity(),
        (index, Some(candidate), candidate),
        "the marker follows the key the link holds"
    );
    restored.commit_rotation(second, 3).unwrap();
    assert_eq!(kernel_link_identity(), (index, Some(next), next));
    restored.down().unwrap();
}

/// J273 P3-3: a settle that moves this node's key to the candidate the link already holds (a commit that stopped
/// between sending the key and moving the marker, then an abandoned operation) changes the identity the
/// coordinator knows, so the prepare that settles it raises the change notice.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn a_settle_that_changes_the_key_raises_the_change_notice() {
    use infraternal_plugin_api::AgentPlugin;
    let state = RotationState::new();
    let first = "00000000-0000-4000-8000-000000000041";
    let second = "00000000-0000-4000-8000-000000000042";
    let mut node = Node::restore_with_engine(&state.0, EngineKind::Kernel).unwrap();
    let previous = node.up().unwrap();
    let candidate = node.prepare_rotation(first, 1).unwrap();
    let (index, _, _) = kernel_link_identity();
    let (store, _) = crate::node_state::Store::open(&state.0).unwrap();
    let mut rotation = store.rotation_secret().unwrap().unwrap();
    rotation.commit_requested = true;
    store.save_rotation_secret(&rotation).unwrap();
    let (candidate_key, _) = Key::from_private(&rotation.candidate).unwrap();
    Device::configure(index, previous.public_key, &candidate_key, previous.port).unwrap();
    drop(rotation);
    drop(store);

    let mut plugin = crate::node_actions::MeshNodePlugin::from_node(node);
    let _ = plugin.take_events();
    let input = format!(r#"{{"operation_id":"{second}","sequence":3}}"#);
    plugin
        .call("mesh.rotation.prepare", input.as_bytes())
        .unwrap();
    assert_eq!(kernel_link_identity(), (index, Some(candidate), candidate));
    assert_eq!(
        plugin.take_events(),
        vec![("mesh.changed", b"{}".to_vec())],
        "the coordinator learns the key moved"
    );
    // A prepare that changes no key raises nothing.
    plugin
        .call("mesh.rotation.prepare", input.as_bytes())
        .unwrap();
    assert_eq!(
        plugin.take_events(),
        Vec::<(&str, Vec<u8>)>::new(),
        "a prepare that changes no key raises nothing"
    );
    plugin.call("mesh.down", b"{}").unwrap();
}

/// `GotaTun` cannot rotate yet: it says so, and every rotation step refuses without touching the
/// device or the state (D166, D352; #285).
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn gotatun_reports_no_rotation_support_and_refuses_every_step() {
    let state = RotationState::new();
    let operation = "00000000-0000-4000-8000-000000000004";
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    let identity = node.up().unwrap();
    assert!(
        !identity.key_rotation,
        "GotaTun must not offer key rotation"
    );
    for result in [
        node.prepare_rotation(operation, 1).map(|_| ()),
        node.commit_rotation(operation, 1).map(|_| ()),
        node.finish_rotation(operation, 1),
    ] {
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Unsupported);
    }
    let (store, _) = crate::node_state::Store::open(&state.0).unwrap();
    assert!(
        store.rotation_secret().unwrap().is_none(),
        "no rotation journal is written"
    );
    assert_eq!(
        store.recorded_interface().unwrap(),
        Some(identity.public_key)
    );
    node.down().unwrap();
}

#[test]
#[ignore = "Run in a disposable user/network namespace, #173."]
fn nft_restart_fences_retained_replacement_address() {
    check(Backend::Nft);
}
#[test]
#[ignore = "Run in a disposable user/network namespace, #173."]
fn nf_tables_restart_fences_retained_replacement_address() {
    check(Backend::NfTables);
}
