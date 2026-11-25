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
        // The same database survives a cold coordinator restart even if this node stopped
        // between the live key switch and the final durable key write.
        let mut before_restart = j363_config(expected);
        before_restart.rotation_operation = Some(crate::dataplane::RotationContinuation {
            operation_id: "00000000-0000-4000-8000-000000000367".into(),
            sequence: 1,
        });
        for chunk in crate::configuration::chunks(None, &before_restart).unwrap() {
            restored.chunk(chunk).unwrap();
        }
        let mut after_restart = before_restart.clone();
        after_restart.authority_epoch = Some(J363_EPOCH_B.into());
        for chunk in crate::configuration::chunks(None, &after_restart).unwrap() {
            restored.chunk(chunk).unwrap();
        }
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
        rotation_operation: None,
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

/// A committed local key must survive the coordinator's complete same-authority config apply.
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn gotatun_rotation_applies_the_complete_key_binding_delta() {
    let state = RotationState::new();
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun)
        .expect("restore an isolated GotaTun node");
    let result = (|| {
        let identity = node.up().map_err(|error| error.to_string())?;
        let previous = crate::dataplane::Config {
            authority_epoch: None,
            rotation_operation: None,
            local_key: Some(identity.public_key),
            server: Some(NodeId(1)),
            node: NodeId(2),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            version: 4,
            addresses: Addresses {
                ipv4: "10.254.0.2".parse().expect("local IPv4"),
                ipv6: "fd01::2".parse().expect("local IPv6"),
            },
            default_policy: DefaultPolicy::Allow,
            exposure: None,
            peers: std::collections::BTreeMap::new(),
            #[cfg(feature = "mesh-dns")]
            peer_names: std::collections::BTreeMap::new(),
        };
        for chunk in crate::configuration::chunks(None, &previous).map_err(str::to_owned)? {
            node.chunk(chunk)
                .map_err(|error| format!("initial config: {error:?}"))?;
        }

        let operation = "00000000-0000-4000-8000-000000000526";
        let candidate = node
            .prepare_rotation(operation, 1)
            .map_err(|error| error.to_string())?;
        node.commit_rotation(operation, 1)
            .map_err(|error| error.to_string())?;
        if node.interface_key() != Some(candidate) {
            return Err("committed engine identity did not advance to the candidate".to_owned());
        }

        let mut next = previous.clone();
        next.local_key = Some(candidate);
        next.version = 5;
        for chunk in crate::configuration::chunks(Some(&previous), &next).map_err(str::to_owned)? {
            node.validate_binding(&chunk)
                .map_err(|error| format!("committed key binding validation: {error:?}"))?;
            node.chunk(chunk)
                .map_err(|error| format!("committed key binding delta: {error:?}"))?;
        }
        if node.config().map(|config| config.version) != Some(5) {
            return Err(format!(
                "node kept config version {:?}",
                node.config().map(|config| config.version)
            ));
        }
        Ok::<_, String>(())
    })();
    let shutdown = if node.active() { node.down() } else { Ok(()) };
    assert!(result.is_ok(), "complete rotation apply failed: {result:?}");
    shutdown.expect("stop the test node after the assertion data is captured");
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
    let _nft_override = crate::host_firewall::NftTestPathOverride::with_fixed_nft_fixture();
    let mut node = Node::with_firewall(Firewall::for_backend(backend));
    node.up().unwrap();
    let proposed = Addresses {
        ipv4: "10.254.0.3".parse().unwrap(),
        ipv6: "fd01::3".parse().unwrap(),
    };
    Device::addresses(proposed).unwrap();
    let accepted = Config {
        authority_epoch: None,
        rotation_operation: None,
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
        rotation_operation: None,
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
                    candidates: Vec::new(),
                    ipv4_only: false,
                    side_port: false,
                },
                inbound: crate::policy::rules::TrafficPolicy::All,
                outbound: crate::policy::rules::TrafficPolicy::All,
                access_ssh: None,
                networks: crate::dataplane::PeerNetworks::default(),
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
    // The epoch lives in its own record beside the snapshot (D295, #382 P2).
    let durable_authority: serde_json::Value = serde_json::from_slice(
        &std::fs::read(state.0.join(crate::node_state::AUTHORITY_FILE)).unwrap(),
    )
    .unwrap();
    println!(
        "J363_RUNTIME_PEERS_BEFORE_FENCE={runtime_peers_before_fence} DURABLE_EPOCH={} DURABLE_RESET={} DURABLE_PEERS={}",
        durable_authority["epoch"],
        durable_authority["reset_pending"],
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
    assert_eq!(durable_authority["epoch"], J363_EPOCH_B);
    assert_eq!(durable_authority["reset_pending"], true);
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
    for (engine, committed, replacement_operation) in [
        (EngineKind::Kernel, false, None),
        (EngineKind::GotaTun, false, None),
        (EngineKind::GotaTun, true, None),
        (
            EngineKind::GotaTun,
            true,
            Some(("00000000-0000-4000-8000-000000000012", 11)),
        ),
        (
            EngineKind::GotaTun,
            true,
            Some(("00000000-0000-4000-8000-000000000011", 12)),
        ),
    ] {
        let state = RotationState::new();
        let mut node = Node::restore_with_engine(&state.0, engine).unwrap();
        let identity = node.up().unwrap();
        let old = j363_config(identity.public_key);
        for chunk in crate::configuration::chunks(None, &old).unwrap() {
            node.chunk(chunk).unwrap();
        }
        let abandoned_candidate = node
            .prepare_rotation("00000000-0000-4000-8000-000000000011", 11)
            .unwrap();

        if committed {
            node.commit_rotation("00000000-0000-4000-8000-000000000011", 11)
                .unwrap();
        }
        let mut replacement = node.config().unwrap().clone();
        replacement.local_key = node.interface_key();
        replacement.rotation_operation = replacement_operation.map(|(operation_id, sequence)| {
            crate::dataplane::RotationContinuation {
                operation_id: operation_id.into(),
                sequence,
            }
        });
        replacement.authority_epoch = Some(J363_EPOCH_B.to_owned());
        replacement.peers.clear();
        if committed {
            let mut interrupted = replacement.clone();
            interrupted.rotation_operation = Some(crate::dataplane::RotationContinuation {
                operation_id: "00000000-0000-4000-8000-000000000011".into(),
                sequence: 11,
            });
            node.prepare_authority_replacement(&interrupted).unwrap();
            drop(node);
            node = Node::restore_with_engine(&state.0, engine).unwrap();
            node.ensure().unwrap();
        }
        for chunk in crate::configuration::chunks(None, &replacement).unwrap() {
            node.chunk(chunk).unwrap();
        }

        let journal = node.store.as_ref().unwrap().rotation_secret().unwrap();
        println!(
            "J363_ENGINE={engine:?} RETAINED_OLD_JOURNAL={}",
            journal.is_some()
        );
        assert!(
            journal.is_none(),
            "a foreign operation retained the old journal"
        );
        drop(journal);
        let result = node.prepare_rotation("00000000-0000-4000-8000-000000000001", 1);
        println!("J363_ENGINE={engine:?} NEW_AUTHORITY_PREPARE={result:?}");
        match result {
            Ok(candidate) => {
                assert_ne!(
                    candidate, abandoned_candidate,
                    "a new authority reused an abandoned candidate"
                );
                assert_ne!(
                    Some(candidate),
                    node.interface_key(),
                    "a new operation reused the active key"
                );
            }
            Err(_) => failures.push(engine),
        }
        node.down().unwrap();
    }
    assert!(
        failures.is_empty(),
        "retired authority journal blocks its replacement: {failures:?}"
    );
}

/// A same-database coordinator restart must be able to finish the candidate it committed before its epoch changed.
#[test]
#[ignore = "Run as root inside a dedicated network namespace"]
fn a_cold_coordinator_restart_can_finish_its_committed_rotation() {
    use std::os::unix::fs::PermissionsExt;
    command("ip", &["link", "set", "lo", "up"]);
    let state = RotationState::new();
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    let identity = node.up().unwrap();
    let old = j363_config(identity.public_key);
    for chunk in crate::configuration::chunks(None, &old).unwrap() {
        node.chunk(chunk).unwrap();
    }
    let operation = "00000000-0000-4000-8000-000000000534";
    let candidate = node.prepare_rotation(operation, 1).unwrap();
    node.commit_rotation(operation, 1).unwrap();
    drop(node);

    let mut restored = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    assert_eq!(restored.ensure().unwrap().unwrap().public_key, candidate);
    let mut replacement = restored.config().unwrap().clone();
    replacement.authority_epoch = Some(J363_EPOCH_B.to_owned());
    replacement.version += 1;
    replacement.rotation_operation = Some(crate::dataplane::RotationContinuation {
        operation_id: operation.into(),
        sequence: 1,
    });
    // Knowledge of the public operation cannot replace the authenticated local-key binding.
    let mut forged = replacement.clone();
    forged.local_key = Some(Key::generate().unwrap().1);
    for chunk in crate::configuration::chunks(None, &forged).unwrap() {
        assert!(restored.chunk(chunk).is_err());
    }
    assert_eq!(restored.interface_key(), Some(candidate));
    assert!(
        restored
            .store
            .as_ref()
            .unwrap()
            .rotation_secret()
            .unwrap()
            .is_some()
    );
    // Stop after the durable deny checkpoint, before applying the replacement runtime.
    // Recovery must prove continuity from the incoming snapshot again.
    restored
        .prepare_authority_replacement(&replacement)
        .unwrap();
    drop(restored);
    let mut restored = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    assert_eq!(restored.ensure().unwrap().unwrap().public_key, candidate);
    for chunk in crate::configuration::chunks(None, &replacement).unwrap() {
        restored.chunk(chunk).unwrap();
    }
    // The coordinator kept its SQLite rotation row across restart and still names this operation.
    assert_eq!(
        std::fs::metadata(state.0.join("mesh-key-rotation.bin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let finished = restored.finish_rotation(operation, 1);
    // Completion clears the coordinator's operation without advancing policy revision.
    // A reconnect with that metadata-only full view must still be accepted.
    replacement.rotation_operation = None;
    for chunk in crate::configuration::chunks(None, &replacement).unwrap() {
        restored.chunk(chunk).unwrap();
    }
    restored.down().unwrap();
    assert!(
        finished.is_ok(),
        "a cold coordinator restart stranded its persisted rotation finish: {finished:?}"
    );
}

/// An interrupted authority reset must retain its journal until a complete replacement is validated.
#[test]
#[ignore = "Run as root inside a dedicated network namespace"]
fn j862_incomplete_reset_snapshot_must_not_discard_the_rotation_receipt() {
    rejected_reset_receipt_case(false);
}

/// A rejected new authority fences stale peers while preserving its receipt through restart.
#[test]
#[ignore = "Run as root inside a dedicated network namespace"]
fn j863_rejected_new_authority_retains_receipt_and_fences_peers() {
    rejected_reset_receipt_case(true);
}

/// Exercise receipt preservation either during an interrupted reset or its first rejected replacement.
fn rejected_reset_receipt_case(reject_new_authority: bool) {
    command("ip", &["link", "set", "lo", "up"]);
    let state = RotationState::new();
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    let identity = node.up().unwrap();
    for chunk in crate::configuration::chunks(None, &j363_config(identity.public_key)).unwrap() {
        node.chunk(chunk).unwrap();
    }
    let operation = "00000000-0000-4000-8000-000000000862";
    node.prepare_rotation(operation, 1).unwrap();
    node.commit_rotation(operation, 1).unwrap();
    let mut replacement = node.config().unwrap().clone();
    replacement.local_key = node.interface_key();
    replacement.authority_epoch = Some(J363_EPOCH_B.into());
    replacement.rotation_operation = Some(crate::dataplane::RotationContinuation {
        operation_id: operation.into(),
        sequence: 1,
    });
    if reject_new_authority {
        let mut rejected = crate::configuration::chunks(None, &replacement)
            .unwrap()
            .remove(0);
        rejected.rotation_operation = None;
        rejected.upserted.values_mut().next().unwrap().peer.key = node.interface_key().unwrap();
        let refusal = node.chunk(rejected);
        println!("J863_REJECTED_AUTHORITY refusal={refusal:?}");
        assert!(refusal.is_err());
        assert!(
            node.config()
                .is_some_and(
                    |config| config.authority_epoch.as_deref() == Some(J363_EPOCH_B)
                        && config.peers.is_empty()
                        && config.default_policy == DefaultPolicy::Deny
                )
        );
        assert!(
            node.store
                .as_ref()
                .unwrap()
                .rotation_secret()
                .unwrap()
                .is_some()
        );
        drop(node);
        let restored = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
        // A rejected authority is explicitly disabled; restore must retain its receipt.
        assert!(!restored.enabled());
        assert!(
            restored
                .store
                .as_ref()
                .unwrap()
                .rotation_secret()
                .unwrap()
                .is_some()
        );
        return;
    }
    node.prepare_authority_replacement(&replacement).unwrap();
    drop(node);
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    node.ensure().unwrap();
    let mut incomplete = crate::configuration::chunks(None, &replacement)
        .unwrap()
        .remove(0);
    incomplete.rotation_operation = None;
    incomplete.last = false;
    assert!(!node.chunk(incomplete).unwrap());
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
    // A complete header still cannot authorize receipt loss when its content is invalid.
    let mut rejected = crate::configuration::chunks(None, &replacement)
        .unwrap()
        .remove(0);
    rejected.rotation_operation = None;
    rejected.upserted.values_mut().next().unwrap().peer.key = node.interface_key().unwrap();
    assert_eq!(
        node.chunk(rejected).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    #[cfg(feature = "mesh-dns")]
    {
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
    let retained = node
        .store
        .as_ref()
        .unwrap()
        .rotation_secret()
        .unwrap()
        .is_some();
    println!("J862_INCOMPLETE_RESET retained_receipt={retained} complete_snapshot=false");
    // The cached deny checkpoint still names the operation. Only the newly validated
    // snapshot may prove continuity, so a valid full view without it must now retire.
    replacement.rotation_operation = None;
    for chunk in crate::configuration::chunks(None, &replacement).unwrap() {
        node.chunk(chunk).unwrap();
    }
    assert!(
        node.store
            .as_ref()
            .unwrap()
            .rotation_secret()
            .unwrap()
            .is_none()
    );
    node.down().unwrap();
    assert!(
        retained,
        "an incomplete snapshot discarded the receipt before full-snapshot validation"
    );
}

/// Rehearse an atomic receipt restore while the real coordinator's cleanup retry waits five seconds.
#[cfg(feature = "server")]
#[tokio::test]
#[ignore = "Run as root inside a dedicated network namespace"]
async fn atomic_journal_recovery_completes_the_pending_cleanup_retry() {
    use infraternal_plugin_api::{PluginOperation, node_channel::NodeChannel};
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };

    /// Give the production rotation driver the real node's finish action only.
    struct FinishChannel {
        /// The restored userspace node whose journal was retired by the new epoch.
        node: std::sync::Mutex<Node>,
        /// Count the refusal before recovery and the successful retry afterwards.
        attempts: std::sync::atomic::AtomicUsize,
        /// Retain the ordinary channel watch for the authenticated-channel contract.
        changes: tokio::sync::watch::Sender<()>,
    }
    impl NodeChannel for FinishChannel {
        /// Bind this isolated embedded node to the server inventory entry.
        fn id(&self) -> &'static str {
            "server"
        }
        /// Keep fixture observations inside its private network namespace.
        fn observed_ip(&self) -> std::net::IpAddr {
            std::net::Ipv4Addr::LOCALHOST.into()
        }
        /// This fixture models the server's own embedded node.
        fn is_server(&self) -> bool {
            true
        }
        /// Offer the same watch contract without injecting a source event.
        fn changes(&self) -> tokio::sync::watch::Receiver<()> {
            self.changes.subscribe()
        }
        /// Dispatch finish to the real node, returning the protocol's ordinary refusal on missing receipt.
        fn call(&self, action: &str, input: Vec<u8>) -> PluginOperation<'_, Vec<u8>> {
            let action = action.to_owned();
            Box::pin(async move {
                assert_eq!(action, "mesh.rotation.finish");
                self.attempts
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let input: serde_json::Value = serde_json::from_slice(&input).unwrap();
                self.node
                    .lock()
                    .unwrap()
                    .finish_rotation(
                        input["operation_id"].as_str().unwrap(),
                        input["sequence"].as_u64().unwrap(),
                    )
                    .map_err(|_| infraternal_plugin_api::node_channel::CALL_REFUSED)?;
                Ok(b"{}".to_vec())
            })
        }
    }

    command("ip", &["link", "set", "lo", "up"]);
    let state = RotationState::new();
    let backup = RotationState::new();
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(2)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("../../infraternal-server/migrations")
        .run(&pool)
        .await
        .unwrap();
    let service =
        crate::api::MeshService::with_authority_epoch_for_test(pool.clone(), J363_EPOCH_A.into());
    let store = service.dataplane();
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    let identity = node.up().unwrap();
    let (id, _) = store
        .attach("server", identity.public_key, None, true)
        .await
        .unwrap();
    let old = store.config(id).await.unwrap();
    for chunk in crate::configuration::chunks(None, &old).unwrap() {
        node.chunk(chunk).unwrap();
    }
    sqlx::query("UPDATE mesh_nodes SET key_rotation_supported=1")
        .execute(&pool)
        .await
        .unwrap();
    let operation = "00000000-0000-4000-8000-000000000535";
    sqlx::query("UPDATE mesh_node_key_rotation SET last_rotation=100,rotation_phase='preparing',operation_id=?,sequence=1 WHERE node_id=?")
        .bind(operation).bind(i64::try_from(id.0).unwrap()).execute(&pool).await.unwrap();
    let candidate = node.prepare_rotation(operation, 1).unwrap();
    store
        .start_rotation_overlap(id, operation, candidate, 100, "test-boot", 1_000)
        .await
        .unwrap();
    node.commit_rotation(operation, 1).unwrap();
    store.commit_rotation(id, operation).await.unwrap();
    let receipt = backup.0.join("mesh-key-rotation.bin");
    std::fs::copy(state.0.join("mesh-key-rotation.bin"), &receipt).unwrap();
    drop(node);

    let restarted =
        crate::api::MeshService::with_authority_epoch_for_test(pool.clone(), J363_EPOCH_B.into());
    let store = restarted.dataplane();
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    let identity = node.ensure().unwrap().unwrap();
    assert_eq!(identity.public_key, candidate);
    let replacement = store.config(id).await.unwrap();
    for chunk in crate::configuration::chunks(None, &replacement).unwrap() {
        node.chunk(chunk).unwrap();
    }
    let revision = store.begin_rotation_cleanup(id, operation).await.unwrap();
    let cleanup = store.config(id).await.unwrap();
    for chunk in crate::configuration::chunks(None, &cleanup).unwrap() {
        node.chunk(chunk).unwrap();
    }
    store.acknowledge_applied(id, revision).await.unwrap();
    assert!(state.0.join("mesh-key-rotation.bin").exists());
    // Simulate the old release's receipt loss so the atomic repair still exercises a real retry.
    std::fs::remove_file(state.0.join("mesh-key-rotation.bin")).unwrap();
    drop(node);
    // Deploying the fix cannot reconstruct the receipt lost by an older release.
    // Reattach the committed candidate and replay the exact open operation after restart.
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    assert_eq!(node.ensure().unwrap().unwrap().public_key, candidate);
    let mut deployed = cleanup.clone();
    deployed.authority_epoch = Some("00000000-0000-4000-8000-000000000862".into());
    for chunk in crate::configuration::chunks(None, &deployed).unwrap() {
        node.chunk(chunk).unwrap();
    }
    assert!(!state.0.join("mesh-key-rotation.bin").exists());
    assert_eq!(
        node.finish_rotation(operation, 1).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    println!(
        "J862_NO_RECOVERY restarted=true exact_operation=true receipt_absent=true finish=NotFound"
    );
    let channel = FinishChannel {
        node: std::sync::Mutex::new(node),
        attempts: std::sync::atomic::AtomicUsize::new(0),
        changes: tokio::sync::watch::channel(()).0,
    };
    let retry = crate::rotation::drive(
        &store,
        &restarted,
        &channel,
        id,
        &identity,
        &BTreeSet::new(),
    )
    .await;
    assert_eq!(retry, Some(Duration::from_secs(5)));
    let phase: Option<String> =
        sqlx::query_scalar("SELECT rotation_phase FROM mesh_node_key_rotation WHERE node_id=?")
            .bind(i64::try_from(id.0).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(phase.as_deref(), Some("cleanup"));

    // Rehearse the production writer: a new 0600 file in the same directory, fsync, rename, then directory fsync.
    let temporary = state.0.join(".j858-recovery-new");
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .unwrap();
    let mut input = std::fs::File::open(&receipt).unwrap();
    std::io::copy(&mut input, &mut output).unwrap();
    output.flush().unwrap();
    output.sync_all().unwrap();
    drop(output);
    let destination = state.0.join("mesh-key-rotation.bin");
    std::fs::rename(&temporary, &destination).unwrap();
    std::fs::File::open(&state.0).unwrap().sync_all().unwrap();
    assert_eq!(
        std::fs::metadata(&destination)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    // sleep: exercise the production five-second retry deadline returned after the missing finish receipt.
    tokio::time::sleep(retry.unwrap()).await;
    assert_eq!(
        crate::rotation::drive(
            &store,
            &restarted,
            &channel,
            id,
            &identity,
            &BTreeSet::new()
        )
        .await,
        Some(Duration::ZERO)
    );
    let row: (Option<String>, i64) = sqlx::query_as(
        "SELECT rotation_phase,last_rotation FROM mesh_node_key_rotation WHERE node_id=?",
    )
    .bind(i64::try_from(id.0).unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, None);
    assert!(
        row.1 > 100,
        "successful completion advances the weekly schedule"
    );
    assert_eq!(
        channel.attempts.load(std::sync::atomic::Ordering::Relaxed),
        2
    );
    assert_eq!(
        channel.node.lock().unwrap().interface_key(),
        Some(candidate)
    );
    channel.node.lock().unwrap().down().unwrap();
    println!(
        "J858_RECOVERY atomic_mode=0600 finish_attempts=2 retry_secs=5 phase=none last_rotation_advanced=true identity_preserved=true"
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

/// #382 P2 (J418): a server rolled back to a release without epochs (D295) sends epoch-less
/// snapshots. A node that saw an epoch adopts the full one as a new authority, keeps the
/// unchanged peer installed, and records no epoch, instead of dropping its mesh for good.
#[test]
#[ignore = "Run as root inside a dedicated network namespace"]
fn j418_epochless_rollback_snapshot_is_adopted() {
    command("ip", &["link", "set", "lo", "up"]);
    let state = RotationState::new();
    let mut node = Node::restore_with_engine(&state.0, EngineKind::Kernel).unwrap();
    let identity = node.up().unwrap();
    let current = j363_config(identity.public_key);
    for chunk in crate::configuration::chunks(None, &current).unwrap() {
        node.chunk(chunk).unwrap();
    }
    let mut rolled_back = current.clone();
    rolled_back.authority_epoch = None;
    rolled_back.version = 3;
    let mut applied = Ok(false);
    for mut chunk in crate::configuration::chunks(None, &rolled_back).unwrap() {
        chunk.authority_epoch = None;
        applied = node.chunk(chunk);
    }
    let accepted = node.config().cloned();
    let installed = Device::counters().unwrap().len();
    let (_, restored) = crate::node_state::Store::open(&state.0).unwrap();
    node.down().unwrap();

    assert!(
        matches!(applied, Ok(true)),
        "the epoch-less full snapshot must be adopted: {applied:?}"
    );
    assert_eq!(accepted, Some(rolled_back));
    assert_eq!(installed, 1, "the unchanged peer must stay installed");
    assert_eq!(
        restored.config.map(|config| config.authority_epoch),
        Some(None),
        "the durable state must no longer claim the old epoch"
    );
}

/// A minimal IPv4 TCP SYN from `source` to `destination`:443, enough for the mesh filter to
/// judge it (the filter does not check the TCP checksum).
#[cfg(feature = "test-support")]
fn j618_syn(source: std::net::Ipv4Addr, destination: std::net::Ipv4Addr) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = 0x02;
    packet
}

/// #265 J617 P2 (J618): when a full transaction fails after the engine took the new peer set,
/// the old grants must not come back for an address the engine now gives to another node.
///
/// Node 2 holds 10.254.0.2 with an `All` inbound grant; the new snapshot removes it and gives
/// that address to node 3 with no grants. The save fails, so the transaction rolls back.
/// - When the rollback completes, the engine has node 2 back and so does the filter.
/// - When the rollback stops before the engine gets its old peers back, node 3 holds the
///   address in the engine, so the filter must not admit node 2's grants for it. Restoring the
///   old policy first (J593) admitted node 3's packets under node 2's `All` grant.
#[cfg(feature = "test-support")]
#[test]
#[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
fn j618_failed_rollback_keeps_a_reused_address_off_its_old_owners_grants() {
    command("ip", &["link", "set", "lo", "up"]);
    let state = RotationState::new();
    let mut node = Node::restore_with_engine(&state.0, EngineKind::GotaTun).unwrap();
    let identity = node.up().unwrap();
    let old = j363_config(identity.public_key);
    node.apply(old.clone()).unwrap();
    let local: std::net::Ipv4Addr = "10.254.0.1".parse().unwrap();
    let reused: std::net::Ipv4Addr = "10.254.0.2".parse().unwrap();
    let admitted = |node: &Node| {
        node.gotatun.as_ref().unwrap().check_packet(
            &mut j618_syn(reused, local),
            crate::packet_filter::Direction::MeshToHost,
        )
    };
    assert!(admitted(&node), "node 2's grant admits its own address");

    let mut moved = old.clone();
    moved.version += 1;
    let mut owner = moved.peers.remove(&NodeId(2)).unwrap();
    owner.peer.key = Key::generate().unwrap().1;
    owner.inbound = crate::policy::rules::TrafficPolicy::None;
    owner.outbound = crate::policy::rules::TrafficPolicy::None;
    moved.peers.insert(NodeId(3), owner);

    let fail = |seam: &TransactionSeam| {
        *seam.lock().unwrap() = Some(Box::new(|| Err(io::Error::other("J618 injected failure"))));
    };
    fail(&BEFORE_TRANSACTION_SAVE);
    assert!(node.apply(moved.clone()).is_err(), "the save fails");
    assert_eq!(node.config(), Some(&old));
    let restored = admitted(&node);

    fail(&BEFORE_TRANSACTION_SAVE);
    fail(&BEFORE_ROLLBACK_ENGINE_APPLY);
    assert!(node.apply(moved).is_err(), "the save and the rollback fail");
    let while_engine_holds_new_owner = admitted(&node);
    node.down().unwrap();

    assert!(
        restored,
        "a completed rollback gives node 2 its address and grants back"
    );
    assert!(
        !while_engine_holds_new_owner,
        "node 3 holds 10.254.0.2 in the engine, but the filter admitted it under node 2's grants"
    );
}

/// A finished `GotaTun` marker authorizes only its predecessor or candidate snapshot key.
#[test]
fn j356_completed_snapshot_binding_rejects_an_unrelated_key() {
    let directory = crate::node_state::tests::Directory::new();
    let (store, _) = crate::node_state::Store::open(&directory.0).expect("store");
    let previous = [0x11; 32];
    let candidate = [0x22; 32];
    let unrelated = [0x33; 32];
    let previous_public = Key::from_private(&previous).expect("previous key").1;
    let candidate_public = Key::from_private(&candidate).expect("candidate key").1;
    let unrelated_public = Key::from_private(&unrelated).expect("unrelated key").1;
    store.record_engine(EngineKind::GotaTun).expect("engine");
    store
        .record_interface(&candidate_public)
        .expect("candidate interface record");
    store
        .write_private_key(&candidate)
        .expect("candidate key file");
    store
        .save_rotation_secret(&crate::node_state::RotationSecret {
            operation_id: "00000000-0000-4000-8000-000000000367".to_owned(),
            sequence: 1,
            previous,
            candidate,
            commit_requested: true,
            completed: false,
        })
        .expect("commit intent");
    store
        .complete_rotation_secret("00000000-0000-4000-8000-000000000367", 1)
        .expect("finish rotation");

    assert!(gotatun_snapshot_binding_is_authorized(&store, previous_public).expect("old"));
    assert!(gotatun_snapshot_binding_is_authorized(&store, candidate_public).expect("new"));
    assert!(
        !gotatun_snapshot_binding_is_authorized(&store, unrelated_public).expect("unrelated"),
        "a completed marker does not authorize an unrelated saved binding"
    );
}
