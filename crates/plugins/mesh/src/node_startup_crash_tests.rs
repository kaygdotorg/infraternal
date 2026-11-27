//! Stop or fail a real Linux `GotaTun` start after each of its steps and check that the next
//! start works (D332, #580).
//!
//! A start can end early in two ways: its process goes away (a crash, a kill, a reboot), or one
//! step returns an error. The production code marks each step with a [`checkpoint`] call. A test
//! picks one step and either kills a child process there or makes the step fail. Every test
//! refuses to run unless its network namespace holds nothing but loopback.

#![expect(
    clippy::unwrap_used,
    reason = "fixture setup and restart must succeed at each checkpoint"
)]

use super::{Device, EngineKind, Node};
use std::{
    io,
    os::unix::{fs::DirBuilderExt as _, net::UnixDatagram, process::ExitStatusExt as _},
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    time::Duration,
};

/// Every checkpoint of a `GotaTun` start, in the order the start reaches them.
const STEPS: [&str; 10] = [
    "recorded",
    "created",
    "marked",
    "activated",
    "bound",
    "port-recorded",
    "route-listening",
    "saved",
    "persisted",
    "listening",
];

/// How many of [`STEPS`] come before the TUN is made persistent.
const BEFORE_COMMIT: usize = 8;

/// Names the step at which a child process stops and waits to be killed.
const CRASH_AT: &str = "INFRATERNAL_TEST_TUN_CRASH_AT";
/// Names the socket on which that child says it has arrived.
const CRASH_SOCKET: &str = "INFRATERNAL_TEST_TUN_CRASH_SOCKET";
/// Names the child's state directory; without it the child runs a node that saves nothing.
const CRASH_STATE: &str = "INFRATERNAL_TEST_TUN_CRASH_STATE";

/// The step that returns an error in this process, while a test has set one.
static FAIL_AT: Mutex<Option<&str>> = Mutex::new(None);

/// Mark one step of a start. It does nothing unless a test chose this step: then it returns an
/// error, or, in a child process, reports its arrival and waits to be killed.
pub(crate) fn checkpoint(step: &str) -> io::Result<()> {
    if *FAIL_AT.lock().unwrap() == Some(step) {
        return Err(io::Error::other("injected start failure"));
    }
    if std::env::var(CRASH_AT).as_deref() == Ok(step) {
        let socket = std::env::var_os(CRASH_SOCKET).unwrap();
        UnixDatagram::unbound()
            .unwrap()
            .send_to(step.as_bytes(), socket)
            .unwrap();
        loop {
            std::thread::park();
        }
    }
    Ok(())
}

/// Child half of the kill tests: start a node as the infraternal agent does. An enabled node,
/// which includes a new state directory, starts inside its restore; a node that saves nothing
/// starts on the explicit `up`.
#[test]
#[ignore = "Child-only fixture: the startup tests spawn it and kill it at a checkpoint."]
fn startup_child() {
    if std::env::var_os(CRASH_SOCKET).is_none() {
        return;
    }
    let mut node = match std::env::var_os(CRASH_STATE) {
        Some(path) => Node::restore_with_engine(Path::new(&path), EngineKind::GotaTun).unwrap(),
        None => Node::default().with_engine(EngineKind::GotaTun),
    };
    node.up().unwrap();
    panic!("the start did not reach its checkpoint");
}

/// One test's private scratch directory, removed when the test ends, even on a failed assertion.
struct Fixture(PathBuf);

impl Fixture {
    /// Check that the namespace is disposable, then create the scratch directory.
    fn new(name: &str) -> Self {
        let links = Command::new("ip")
            .args(["-o", "link", "show", "up"])
            .output()
            .unwrap();
        assert!(links.status.success());
        let links = String::from_utf8(links.stdout).unwrap();
        assert!(
            links.lines().all(|line| line.starts_with("1: lo:")),
            "run only in a fresh network namespace where nothing but loopback is up"
        );
        assert!(
            Device::active_link().unwrap().is_none(),
            "run only in a namespace without a mesh interface"
        );
        let fixture =
            Self(std::env::temp_dir().join(format!("j1287-{name}-{}", std::process::id())));
        private_directory(&fixture.0);
        fixture
    }

    /// A new, empty state directory: what a new installation starts from.
    fn state(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        private_directory(&path);
        path
    }

    /// Run a child start until it reaches `step`, kill it there with `SIGKILL`, and wait for the
    /// kernel to close its descriptors.
    fn kill_at(&self, step: &str, state: Option<&Path>) {
        let socket = self.0.join("checkpoint");
        let receiver = UnixDatagram::bind(&socket).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "node::startup_crash_tests::startup_child",
                "--nocapture",
            ])
            .env(CRASH_AT, step)
            .env(CRASH_SOCKET, &socket)
            .env_remove(CRASH_STATE);
        if let Some(path) = state {
            command.env(CRASH_STATE, path);
        }
        let mut child = command.spawn().unwrap();
        let mut message = [0; 32];
        let arrived = receiver.recv(&mut message);
        let killed = child.kill();
        let status = child.wait().unwrap();
        std::fs::remove_file(&socket).unwrap();
        let length = arrived.unwrap_or_else(|error| panic!("{step}: {error} ({status})"));
        assert_eq!(&message[..length], step.as_bytes());
        killed.unwrap();
        assert_eq!(status.signal(), Some(nix::libc::SIGKILL));
    }
}

impl Drop for Fixture {
    /// Delete only the directory this fixture created.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Create a directory only this user can read, as the node's state store requires.
fn private_directory(path: &Path) {
    std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

/// Restore the installation saved in `state` and bring it up, as a restarted agent does.
fn start(state: &Path) -> io::Result<(Node, super::Identity)> {
    let mut node = Node::restore_with_engine(state, EngineKind::GotaTun)?;
    let identity = node.up()?;
    Ok((node, identity))
}

/// The live mesh link as the facts that must survive a reattach: its index and its owner key.
fn live_link() -> Option<(u32, Option<crate::policy::model::PublicKey>)> {
    Device::active_link()
        .unwrap()
        .map(|link| (link.ifindex, link.owner))
}

/// Kill a first start after each step. Before the commit point nothing stays, so the next start
/// works even from new records. After it, the same records take the link back, and new records,
/// which cannot prove they made it, leave it alone.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn a_kill_during_a_first_start_leaves_the_next_start_working() {
    let fixture = Fixture::new("first");
    for (index, step) in STEPS.iter().enumerate() {
        let state = fixture.state(step);
        fixture.kill_at(step, Some(&state));
        let left = live_link();
        assert_eq!(left.is_some(), index >= BEFORE_COMMIT, "{step}: link left");
        let other = fixture.state(&format!("{step}-other"));
        if left.is_some() {
            let refusal = start(&other).map(|_| ()).unwrap_err();
            assert_eq!(refusal.kind(), io::ErrorKind::AlreadyExists, "{step}");
            assert_eq!(
                live_link(),
                left,
                "{step}: another installation's link changed"
            );
        } else {
            let (mut node, _) = start(&other).unwrap();
            node.down().unwrap();
        }
        let (mut node, identity) = start(&state).unwrap();
        if let Some((_, owner)) = left {
            assert_eq!(Some(identity.public_key), owner, "{step}");
            assert_eq!(
                live_link(),
                left,
                "{step}: the owner must reattach its link"
            );
        }
        node.down().unwrap();
        assert_eq!(live_link(), None, "{step}");
        eprintln!("first start, killed after {step}: next start works");
    }
}

/// Kill the restart of an installed node after each step. Its persistent link stays through
/// every kill, and the following start reattaches that same link.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn a_kill_during_a_restart_keeps_the_link_for_the_next_start() {
    let fixture = Fixture::new("restart");
    let state = fixture.state("installed");
    fixture.kill_at("listening", Some(&state));
    let installed = live_link();
    assert!(installed.is_some());
    for step in STEPS {
        fixture.kill_at(step, Some(&state));
        assert_eq!(live_link(), installed, "{step}: link after the kill");
        let (node, _) = start(&state).unwrap();
        assert_eq!(live_link(), installed, "{step}: link after the next start");
        drop(node);
        eprintln!("restart, killed after {step}: next start reattaches");
    }
    let (mut node, _) = start(&state).unwrap();
    node.down().unwrap();
    assert_eq!(live_link(), None);
}

/// Make each step before the commit point return an error, first in the start that a restore
/// runs and then in an explicit `up` after `down`. A failed start leaves no interface, and the
/// retry works.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn a_failed_start_leaves_no_interface_and_the_retry_works() {
    let fixture = Fixture::new("failed");
    for step in &STEPS[..BEFORE_COMMIT] {
        let state = fixture.state(step);
        *FAIL_AT.lock().unwrap() = Some(step);
        let failed_restore = Node::restore_with_engine(&state, EngineKind::GotaTun).map(|_| ());
        *FAIL_AT.lock().unwrap() = None;
        assert!(
            failed_restore.is_err(),
            "{step}: the restore's failure was lost"
        );
        assert_eq!(
            live_link(),
            None,
            "{step}: a failed restore left its interface"
        );

        let (mut node, _) = start(&state).unwrap();
        node.down().unwrap();
        *FAIL_AT.lock().unwrap() = Some(step);
        let failed_up = node.up();
        *FAIL_AT.lock().unwrap() = None;
        assert!(failed_up.is_err(), "{step}: the failure of `up` was lost");
        assert_eq!(
            live_link(),
            None,
            "{step}: a failed `up` left its interface"
        );

        node.up().unwrap();
        node.down().unwrap();
        assert_eq!(live_link(), None, "{step}");
        eprintln!("start failed after {step}: no interface left, retry works");
    }
}

/// A reboot drops the kernel link and keeps the saved records. The next start makes a new link
/// with the same identity. A node that saves nothing never keeps a link at all.
#[test]
#[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
fn a_start_after_a_reboot_or_without_saved_records_makes_a_new_link() {
    let fixture = Fixture::new("reboot");
    let state = fixture.state("installed");
    fixture.kill_at("listening", Some(&state));
    let (before, owner) = live_link().unwrap();
    // Deleting the link is all a reboot does to the kernel side of an installation.
    Device::delete_ifindex(before).unwrap();
    let (mut node, identity) = start(&state).unwrap();
    assert_eq!(Some(identity.public_key), owner);
    let (after, after_owner) = live_link().unwrap();
    assert_eq!(after_owner, owner);
    assert_ne!(after, before);
    node.down().unwrap();

    fixture.kill_at("listening", None);
    assert_eq!(live_link(), None, "a node without a store kept its link");
    let mut node = Node::default().with_engine(EngineKind::GotaTun);
    node.up().unwrap();
    node.down().unwrap();
    assert_eq!(live_link(), None);
}
