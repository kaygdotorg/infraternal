//! Proves Linux node recovery across ingress fences and journaled key-rotation stops [166,199], #173, #367.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
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
    panic!("the requested crash boundary was never reached");
}

/// SIGKILL after each durable `GotaTun` transition leaves enough journal evidence to restart safely.
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
        "rotation_interface_recorded",
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
                let output = child
                    .wait_with_output()
                    .expect("collect the child's failure");
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
            assert_eq!(
                journal.previous, previous,
                "finish retains only its public predecessor"
            );
            crate::policy::model::PublicKey(journal.previous)
        } else {
            Key::from_private(&journal.previous).unwrap().1
        };
        let candidate_public = Key::from_private(&journal.candidate).unwrap().1;
        assert_eq!(previous_public.0, previous, "stage {stage}");
        assert_eq!(
            journal.completed,
            stage == "rotation_finished",
            "stage {stage}"
        );
        let bytes = store
            .read_private_key()
            .expect("read the key left by the child")
            .expect("the GotaTun key file survives the crash");
        let file_key_at_crash =
            if matches!(stage, "rotation_private_key_saved" | "rotation_finished") {
                candidate_public
            } else {
                previous_public
            };
        assert_eq!(
            crate::gotatun_node::secret_from_bytes(&bytes).unwrap().1,
            file_key_at_crash,
            "private-key file at the crash boundary {stage}"
        );
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
        let marker = if expects_candidate {
            candidate_public
        } else {
            previous_public
        };
        assert_eq!(link.owner, Some(marker), "owner marker at {stage}");
        assert!(
            Node::plan_retirement(&state.0).unwrap().interface,
            "the journal proves the link is still ours at {stage}"
        );
        let (store, _) = crate::node_state::Store::open(&state.0).unwrap();
        let bytes = store.read_private_key().unwrap().unwrap();
        assert_eq!(
            crate::gotatun_node::secret_from_bytes(&bytes).unwrap().1,
            expected,
            "journal recovery selects the live identity at {stage}"
        );
        restored
            .commit_rotation("00000000-0000-4000-8000-000000000367", 1)
            .unwrap();
        restored
            .finish_rotation("00000000-0000-4000-8000-000000000367", 1)
            .unwrap();
        assert!(store.rotation_secret().unwrap().unwrap().completed);
        assert_eq!(
            Device::active_link().unwrap().unwrap().owner,
            Some(candidate_public),
            "the retry completes the marker transition at {stage}"
        );
        let bytes = store.read_private_key().unwrap().unwrap();
        assert_eq!(
            crate::gotatun_node::secret_from_bytes(&bytes).unwrap().1,
            candidate_public,
            "the retry completes the private-key transition at {stage}"
        );
        drop(store);
        restored.down().unwrap();
    }
}

/// A restart during commit accepts the old saved binding only when the open journal proves both keys.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn gotatun_restart_recovers_commit_intent_with_a_predecessor_snapshot_binding() {
    let state = RotationState::new();
    let operation = "00000000-0000-4000-8000-000000000042";
    let node_id = NodeId(1);
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    let previous = node.up().unwrap().public_key;
    let snapshot = crate::dataplane::Config {
        authority_epoch: None,
        local_key: Some(previous),
        server: None,
        node: node_id,
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
        dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
        version: 1,
        addresses: Addresses {
            ipv4: "10.254.0.1".parse().unwrap(),
            ipv6: "fd01::1".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: BTreeMap::new(),
        #[cfg(feature = "mesh-dns")]
        peer_names: BTreeMap::new(),
    };
    let (store, mut saved) = crate::node_state::Store::open(&state.0).unwrap();
    saved.config = Some(snapshot);
    store.save(&saved).unwrap();
    let previous_private = store.read_private_key().unwrap().unwrap();
    let (candidate_key, candidate_public) = Key::generate().unwrap();
    store
        .save_rotation_secret(&crate::node_state::RotationSecret {
            operation_id: operation.to_owned(),
            sequence: 1,
            previous: previous_private.as_slice().try_into().unwrap(),
            candidate: candidate_key.private_bytes().try_into().unwrap(),
            commit_requested: true,
            completed: false,
        })
        .unwrap();
    store
        .replace_private_key(candidate_key.private_bytes())
        .unwrap();
    drop(store);
    drop(node);

    let mut restored = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    assert_eq!(restored.up().unwrap().public_key, candidate_public);
    restored.commit_rotation(operation, 1).unwrap();
    restored.finish_rotation(operation, 1).unwrap();
    assert_eq!(
        Device::active_link().unwrap().unwrap().owner,
        Some(candidate_public)
    );
    restored.down().unwrap();
}

/// A finished rotation leaves no identity behind when `down` retires this node (#367).
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn gotatun_rotation_down_retires_identity_and_uses_a_fresh_key() {
    let state = RotationState::new();
    let first = "00000000-0000-4000-8000-000000000047";
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    node.up().unwrap();
    let candidate = node.prepare_rotation(first, 1).unwrap();
    node.commit_rotation(first, 1).unwrap();
    node.finish_rotation(first, 1).unwrap();
    node.down().unwrap();
    drop(node);

    let (store, _) = crate::node_state::Store::open(&state.0).unwrap();
    assert!(store.rotation_secret().unwrap().is_none());
    assert!(store.recorded_interface().unwrap().is_none());
    assert!(store.read_private_key().unwrap().is_none());
    drop(store);

    let mut restored = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    assert_ne!(restored.up().unwrap().public_key, candidate);
    restored.down().unwrap();
}

/// A `GotaTun` candidate is not an ownership proof until its durable commit intent exists.
#[test]
fn gotatun_owner_proof_rejects_a_candidate_before_commit_intent() {
    let state = RotationState::new();
    let operation = "00000000-0000-4000-8000-000000000046";
    let (previous_key, previous) = Key::generate().unwrap();
    let (candidate_key, candidate) = Key::generate().unwrap();
    let (store, _) = crate::node_state::Store::open(&state.0).unwrap();
    store.record_engine(EngineKind::GotaTun).unwrap();
    store.record_interface(&previous).unwrap();
    store
        .write_private_key(previous_key.private_bytes())
        .unwrap();
    store
        .save_rotation_secret(&crate::node_state::RotationSecret {
            operation_id: operation.to_owned(),
            sequence: 1,
            previous: previous_key.private_bytes().try_into().unwrap(),
            candidate: candidate_key.private_bytes().try_into().unwrap(),
            commit_requested: false,
            completed: false,
        })
        .unwrap();
    let proof = gotatun_owner_proof(&store, Some(previous)).unwrap();
    assert!(proof.accepts(previous));
    assert!(!proof.accepts(candidate));

    store
        .replace_private_key(candidate_key.private_bytes())
        .unwrap();
    let inconsistent = gotatun_owner_proof(&store, Some(previous)).unwrap();
    assert!(
        inconsistent.is_empty(),
        "a candidate file without durable commit intent cannot prove either owner"
    );
}

/// Checks address replacement, recovery fencing, and packet delivery in one backend scenario.
fn check(backend: Backend) {
    let mut node = Node::with_firewall(Firewall::for_backend(backend));
    node.up().unwrap();
    let proposed = Addresses {
        ipv4: "10.254.0.3".parse().unwrap(),
        ipv6: "fd01::3".parse().unwrap(),
    };
    Device::addresses(proposed).unwrap();
    let accepted = Config {
        authority_epoch: None,
        local_key: None,
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
        dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
        version: 1,
        addresses: Addresses {
            ipv4: "10.254.0.1".parse().unwrap(),
            ipv6: "fd01::1".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: BTreeMap::new(),
        #[cfg(feature = "mesh-dns")]
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

/// A higher coordinator sequence settles both prepared and committed `GotaTun` journals on the held key.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn gotatun_higher_sequence_settles_abandoned_rotations_on_the_held_key() {
    let state = RotationState::new();
    let first = "00000000-0000-4000-8000-000000000043";
    let second = "00000000-0000-4000-8000-000000000044";
    let third = "00000000-0000-4000-8000-000000000045";
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    let original = node.up().unwrap().public_key;
    let abandoned = node.prepare_rotation(first, 1).unwrap();
    assert_eq!(
        node.prepare_rotation(second, 1).unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "an equal sequence does not prove the server abandoned the first operation"
    );

    let committed = node.prepare_rotation(second, 3).unwrap();
    assert_ne!(committed, abandoned);
    assert_eq!(node.interface_key(), Some(original));
    node.commit_rotation(second, 3).unwrap();
    drop(node);

    let mut restored = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    assert_eq!(restored.up().unwrap().public_key, committed);
    let next = restored.prepare_rotation(third, 5).unwrap();
    assert_ne!(next, committed);
    let (store, _) = crate::node_state::Store::open(&state.0).unwrap();
    let journal = store.rotation_secret().unwrap().unwrap();
    assert_eq!(
        (journal.operation_id.as_str(), journal.sequence),
        (third, 5)
    );
    assert_eq!(Key::from_private(&journal.previous).unwrap().1, committed);
    assert_eq!(store.recorded_interface().unwrap(), Some(committed));
    let bytes = store.read_private_key().unwrap().unwrap();
    assert_eq!(
        crate::gotatun_node::secret_from_bytes(&bytes).unwrap().1,
        committed
    );
    assert_eq!(
        Device::active_link().unwrap().unwrap().owner,
        Some(committed)
    );
    drop(journal);
    drop(store);
    restored.commit_rotation(third, 5).unwrap();
    restored.finish_rotation(third, 5).unwrap();
    restored.down().unwrap();
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

/// J284 P3-b: when the settle's journal save fails after the marker moved, the node keeps presenting the
/// predecessor (the journal still says the operation is open) while its proof accepts both of its keys, so a
/// retry proves its own link and completes the settle.
#[cfg(feature = "test-support")]
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn a_failed_settle_save_leaves_the_presented_key_unchanged_and_is_retryable() {
    use std::os::unix::fs::PermissionsExt;
    let state = RotationState::new();
    let first = "00000000-0000-4000-8000-000000000051";
    let second = "00000000-0000-4000-8000-000000000052";
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

    // An unsafe journal mode makes the save refuse, as any durable-write failure would.
    let journal = state.0.join("mesh-key-rotation.bin");
    let unsafe_journal = journal.clone();
    *BEFORE_SETTLE_SAVE.lock().unwrap() = Some(Box::new(move || {
        std::fs::set_permissions(&unsafe_journal, std::fs::Permissions::from_mode(0o644)).unwrap();
    }));
    assert!(node.prepare_rotation(second, 3).is_err(), "the save fails");
    assert_eq!(
        node.interface_key(),
        Some(previous.public_key),
        "the presented key changes only after the journal records it"
    );
    assert_eq!(kernel_link_identity(), (index, Some(candidate), candidate));

    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
    let next = node.prepare_rotation(second, 3).unwrap();
    assert_ne!(next, candidate);
    assert_eq!(node.interface_key(), Some(candidate));
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

/// The original authority used by the independent SIGKILL retirement reproducer.
const J363_EPOCH_A: &str = "00000000-0000-4000-8000-000000000001";
/// The replacement authority used by the independent SIGKILL retirement reproducer.
const J363_EPOCH_B: &str = "00000000-0000-4000-8000-000000000002";

/// Pause a test child after durable retirement intent and before the runtime fence.
pub(super) fn j363_retirement_crash_checkpoint() {
    if let Some(ready) = std::env::var_os("J363_RETIREMENT_READY") {
        std::fs::write(ready, b"retirement persisted; runtime fence not entered").unwrap();
        loop {
            std::thread::park();
        }
    }
}

/// Construct an authenticated peer-bearing snapshot for the J363 authority transition tests.
fn j363_config(key: crate::policy::model::PublicKey) -> Config {
    Config {
        authority_epoch: Some(J363_EPOCH_A.to_owned()),
        local_key: Some(key),
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
        dns_suffix: "internal".to_owned(),
        version: 10,
        addresses: Addresses {
            ipv4: "10.254.0.1".parse().unwrap(),
            ipv6: "fd01::1".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: BTreeMap::from([(
            NodeId(2),
            crate::dataplane::PeerPolicy {
                peer: crate::dataplane::Peer {
                    key: Key::generate().unwrap().1,
                    previous_key: None,
                    previous_active: false,
                    addresses: Addresses {
                        ipv4: "10.254.0.2".parse().unwrap(),
                        ipv6: "fd01::2".parse().unwrap(),
                    },
                    endpoint: None,
                },
                inbound: crate::policy::rules::TrafficPolicy::All,
                outbound: crate::policy::rules::TrafficPolicy::All,
                access_ssh: None,
            },
        )]),
        #[cfg(feature = "mesh-dns")]
        peer_names: BTreeMap::new(),
    }
}

/// A child installs authority A, then blocks after persisting B's deny state while applying B.
#[test]
#[ignore = "child process of the independent retirement crash proof"]
fn j363_retirement_crash_child() {
    let path = std::path::PathBuf::from(std::env::var_os("J363_STATE").unwrap());
    let mut node = Node::restore_with_engine(&path, EngineKind::Kernel).unwrap();
    let identity = node.up().unwrap();
    let old = j363_config(identity.public_key);
    for chunk in crate::configuration::chunks(None, &old).unwrap() {
        node.chunk(chunk).unwrap();
    }
    assert_eq!(Device::counters().unwrap().len(), 1);
    let mut replacement = old.clone();
    replacement.authority_epoch = Some(J363_EPOCH_B.to_owned());
    replacement.peers.clear();
    for chunk in crate::configuration::chunks(None, &replacement).unwrap() {
        node.chunk(chunk).unwrap();
    }
    panic!("retirement checkpoint was not reached");
}

/// SIGKILL between durable retirement and the runtime fence must not restore retired peers.
#[test]
#[ignore = "Run as root inside a dedicated network namespace"]
fn j363_kill_between_persist_and_fence() {
    use std::time::Instant;

    command("ip", &["link", "set", "lo", "up"]);
    let state = RotationState::new();
    let ready = state.0.join("j363-ready");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "j363_retirement_crash_child", "--nocapture"])
        .env("J363_STATE", &state.0)
        .env("J363_RETIREMENT_READY", &ready)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ready.exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("child exited before retirement checkpoint: {status}");
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("retirement checkpoint timed out");
        }
        // sleep: wait for the child to publish the exact retirement boundary.
        std::thread::sleep(Duration::from_millis(10));
    }
    let runtime_peers_before_fence = Device::counters().unwrap().len();
    let durable: serde_json::Value =
        serde_json::from_slice(&std::fs::read(state.0.join("mesh-public.json")).unwrap()).unwrap();
    println!(
        "J363_RUNTIME_PEERS_BEFORE_FENCE={runtime_peers_before_fence} DURABLE_EPOCH={} DURABLE_PEERS={}",
        durable["config"]["authority_epoch"],
        durable["config"]["peers"].as_object().unwrap().len()
    );
    child.kill().unwrap();
    child.wait().unwrap();
    let mut restored = Node::restore_with_engine(&state.0, EngineKind::Kernel).unwrap();
    let peers = Device::counters().unwrap().len();
    println!(
        "J363_RESTORED_PEERS={peers} RESTORED_EPOCH={:?}",
        restored
            .config()
            .and_then(|config| config.authority_epoch.as_deref())
    );
    restored.down().unwrap();
    assert_eq!(
        runtime_peers_before_fence, 1,
        "the checkpoint precedes the runtime fence"
    );
    assert_eq!(durable["config"]["authority_epoch"], J363_EPOCH_B);
    assert_eq!(durable["config"]["peers"].as_object().unwrap().len(), 0);
    assert_eq!(
        peers, 0,
        "retired authority peers resurrected after SIGKILL"
    );
}

/// An authority change removes its abandoned rotation journal before the new server rotates again.
#[test]
#[ignore = "Run as root inside a dedicated network namespace"]
fn j363_epoch_change_retires_old_rotation_journal() {
    command("ip", &["link", "set", "lo", "up"]);
    let mut failures = Vec::new();
    for engine in [EngineKind::Kernel, EngineKind::GotaTun] {
        let state = RotationState::new();
        let mut node = Node::restore_with_engine(&state.0, engine).unwrap();
        let identity = node.up().unwrap();
        let old = j363_config(identity.public_key);
        for chunk in crate::configuration::chunks(None, &old).unwrap() {
            node.chunk(chunk).unwrap();
        }
        node.prepare_rotation("00000000-0000-4000-8000-000000000011", 11)
            .unwrap();

        let mut replacement = old.clone();
        replacement.authority_epoch = Some(J363_EPOCH_B.to_owned());
        replacement.peers.clear();
        for chunk in crate::configuration::chunks(None, &replacement).unwrap() {
            node.chunk(chunk).unwrap();
        }

        let journal = node.store.as_ref().unwrap().rotation_secret().unwrap();
        println!(
            "J363_ENGINE={engine:?} RETAINED_OLD_JOURNAL={}",
            journal.is_some()
        );
        drop(journal);
        let result = node.prepare_rotation("00000000-0000-4000-8000-000000000001", 1);
        println!("J363_ENGINE={engine:?} NEW_AUTHORITY_PREPARE={result:?}");
        if result.is_err() {
            failures.push(engine);
        }
        node.down().unwrap();
    }
    assert!(
        failures.is_empty(),
        "retired authority journal blocks its replacement: {failures:?}"
    );
}

/// A new authority must stage the complete replacement before it changes live kernel peers.
#[test]
#[ignore = "Run as root inside a dedicated network namespace"]
fn j363b_authority_replacement_keeps_identical_peers_live_until_complete() {
    command("ip", &["link", "set", "lo", "up"]);
    let state = RotationState::new();
    let mut node = Node::restore_with_engine(&state.0, EngineKind::Kernel).unwrap();
    let identity = node.up().unwrap();
    let current = j363_config(identity.public_key);
    for chunk in crate::configuration::chunks(None, &current).unwrap() {
        node.chunk(chunk).unwrap();
    }
    let mut replacement = current.clone();
    replacement.authority_epoch = Some(J363_EPOCH_B.to_owned());
    let mut complete = crate::configuration::chunks(None, &replacement)
        .unwrap()
        .pop()
        .unwrap();
    complete.authority_epoch = Some(J363_EPOCH_B.to_owned());
    let mut first = complete.clone();
    first.last = false;
    complete.index = 1;
    complete.last = true;
    complete.upserted.clear();
    complete.merged.clear();
    complete.removed.clear();
    #[cfg(feature = "mesh-dns")]
    {
        complete.peer_names.clear();
        complete.removed_peer_names.clear();
    }

    let staged = node.chunk(first);
    let config_while_staged = node.config().cloned();
    let peers_while_staged = Device::counters().unwrap().len();
    let applied = node.chunk(complete);
    let accepted = node.config().cloned();
    let peers_after_replacement = Device::counters().unwrap().len();
    node.down().unwrap();

    assert!(
        matches!(staged, Ok(false)),
        "the first part should remain staged: {staged:?}"
    );
    assert_eq!(config_while_staged, Some(current.clone()));
    assert_eq!(
        peers_while_staged, 1,
        "the old runtime was cut before staging ended"
    );
    assert!(
        matches!(applied, Ok(true)),
        "the full replacement should be applied: {applied:?}"
    );
    assert_eq!(accepted, Some(replacement));
    assert_eq!(
        peers_after_replacement, 1,
        "the replacement peer disappeared"
    );
}
