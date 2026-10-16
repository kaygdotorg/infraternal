//! Verify retained setup recovery on a minimal host without an extra interpreter.
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};

const HOST: &str = "11111111111111111111111111111111";
const TRANSACTION: &str = "22222222222222222222222222222222";

struct MinimalHost {
    root: PathBuf,
}

impl MinimalHost {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let scratch = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map_or_else(
            || PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cache/codex-scratch/ar3"),
            PathBuf::from,
        );
        fs::create_dir_all(&scratch).unwrap();
        let root = scratch.join(format!(
            "r{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let fixture = Self { root };
        let base = fixture.base();
        fs::create_dir_all(base.join("sessions")).unwrap();
        for directory in [
            &fixture.root,
            &fixture.root.join(".local"),
            &fixture.root.join(".local/share"),
            &base,
            &base.join("sessions"),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let owner = base.join(".bootstrap-owner");
        fs::write(&owner, format!("{HOST}\n")).unwrap();
        fs::set_permissions(owner, fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = fs::metadata(&base).unwrap();
        fs::write(
            fixture.receipt(),
            format!(
                "{HOST} {TRANSACTION} fresh {}:{}\n",
                metadata.dev(),
                metadata.ino()
            ),
        )
        .unwrap();
        fs::set_permissions(fixture.receipt(), fs::Permissions::from_mode(0o600)).unwrap();
        drop(UnixListener::bind(base.join("sessions/plugins.sock")).unwrap());
        fixture
    }

    fn base(&self) -> PathBuf {
        self.root.join(".local/share/infraternal")
    }
    fn receipt(&self) -> PathBuf {
        self.base()
            .with_file_name(format!("infraternal.bootstrap-rollback-{TRANSACTION}"))
    }

    fn run(&self, body: &str) -> Output {
        let metadata = fs::metadata(&self.root).unwrap();
        let mut child = Command::new("sudo")
            .args(["-n", "docker", "run", "--rm", "--network", "none", "--user"])
            .arg(format!("{}:{}", metadata.uid(), metadata.gid()))
            .arg("--mount")
            .arg(format!(
                "type=bind,src={},dst=/fixture",
                self.root.display()
            ))
            .args([
                "--env",
                "HOME=/fixture",
                "-i",
                "debian:trixie-slim",
                "/bin/sh",
                "-c",
                "if command -v python3 >/dev/null 2>&1; then exit 99; fi; exec /bin/sh",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
}

impl Drop for MinimalHost {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

// Read the same embedded programs as the installer, without maintaining a copy
// of their ownership checks or bringing a service manager into this final receipt case.
fn installer_constant(name: &str) -> &str {
    let source = include_str!("../src/install.rs");
    let marker = format!("const {name}: &str = r#\"");
    source
        .split_once(&marker)
        .unwrap()
        .1
        .split_once("\"#;")
        .unwrap()
        .0
}

fn recovery_scripts() -> (String, String) {
    let preamble = format!(
        "set -euC\numask 077\nbase=\"$HOME/.local/share/infraternal\"\nhost={HOST}\ntransaction={TRANSACTION}\n"
    );
    let programs = format!(
        "{preamble}{}\n{}\n",
        include_str!("../src/setup_lock.sh"),
        include_str!("../src/runtime_cleanup.sh")
    );
    let inspect = format!(
        "{programs}{}\ninspect_previous\n",
        include_str!("../src/previous_attempt.sh")
    );
    let rollback = format!(
        "{programs}{}\n{}\n",
        installer_constant("FRESH_CLEANUP"),
        installer_constant("ROLLBACK_TRANSACTION")
    );
    (inspect, rollback)
}

#[test]
#[ignore = "requires sudo -n Docker and the local debian:trixie-slim image"]
fn review_stale_receipt_recovers_without_host_python() {
    let host = MinimalHost::new();
    let (inspect, rollback) = recovery_scripts();
    let mut inspection = Vec::new();
    let mut cleanup = Vec::new();
    // Retry must progress with the same exact receipt, rather than requiring
    // an administrator to install software or manually remove owned state.
    for _ in 0..2 {
        inspection.push(host.run(&inspect).status.code());
        cleanup.push(host.run(&rollback).status.code());
    }
    let receipt_retained = host.receipt().exists();
    let socket_retained = host.base().join("sessions/plugins.sock").exists();
    // The same host and receipt succeed when no control socket needs probing.
    // This separates interpreter dependence from missing base shell utilities.
    if socket_retained {
        fs::remove_file(host.base().join("sessions/plugins.sock")).unwrap();
    }
    let without_socket = host.run(&rollback);
    assert!(
        without_socket.status.success(),
        "fixture without socket refused: {:?}",
        without_socket.status.code()
    );
    assert!(
        inspection.iter().all(|status| *status == Some(0))
            && cleanup.iter().all(|status| *status == Some(0))
            && !receipt_retained,
        "minimal host retry stops: inspection={inspection:?}, cleanup={cleanup:?}, receipt_retained={receipt_retained}, socket_retained={socket_retained}, without_socket={:?}",
        without_socket.status.code()
    );
}

/// A process still owns its bound control socket during the bind-to-listen gap.
#[test]
fn review_bound_control_socket_before_listen_preserves_receipt() {
    let host = MinimalHost::new();
    let control = host.base().join("sessions/plugins.sock");
    fs::remove_file(&control).unwrap();
    // Relative bind plus chdir keeps cwd/descriptor paths from supplying an
    // unrelated liveness signal. EOF proves the same holder can still listen.
    let mut holder = Command::new("python3")
        .args(["-u", "-c", "import os,socket,sys; s=socket.socket(socket.AF_UNIX); s.bind('sessions/plugins.sock'); os.chdir('/'); print('ready',flush=True); sys.stdin.read(); s.listen(); print('listening',flush=True)"])
        .current_dir(host.base())
        .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut ready = [0; 6];
    holder
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .unwrap();
    assert_eq!(&ready, b"ready\n");
    let (inspect, rollback) = recovery_scripts();
    let run = |script: &str| {
        Command::new("/bin/sh")
            .args(["-c", &script.replace("$HOME", host.root.to_str().unwrap())])
            .output()
            .unwrap()
    };
    let inspection = run(&inspect);
    let cleanup = run(&rollback);
    let socket_preserved = control.exists();
    let receipt_retained = host.receipt().exists();
    drop(holder.stdin.take());
    let mut listening = [0; 10];
    holder
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut listening)
        .unwrap();
    assert_eq!(&listening, b"listening\n");
    assert!(holder.wait().unwrap().success());
    assert!(
        !inspection.status.success()
            && !cleanup.status.success()
            && socket_preserved
            && receipt_retained,
        "bound control endpoint removed: inspection={:?}, cleanup={:?}, socket_preserved={socket_preserved}, receipt_retained={receipt_retained}",
        inspection.status.code(),
        cleanup.status.code()
    );
}
