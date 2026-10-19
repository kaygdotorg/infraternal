//! Verify retained setup recovery on a minimal host without an extra interpreter. The private
//! SSH root can be shorter than the workspace scratch root so socket fixture names fit `sun_path`.
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    io::{Read, Write},
    os::fd::AsRawFd,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};

#[allow(dead_code)]
mod common;

const HOST: &str = "11111111111111111111111111111111";
const TRANSACTION: &str = "22222222222222222222222222222222";

struct MinimalHost {
    root: PathBuf,
}

impl MinimalHost {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        // Only these ownership fixtures need the short alias: the rest of the
        // workspace keeps the canonical cache root for rename and execution tests.
        let scratch = std::env::var_os("INFRATERNAL_SSH_TEST_STATE_ROOT")
            .or_else(|| std::env::var_os("INFRATERNAL_TEST_STATE_ROOT"))
            .map_or_else(
                || {
                    // Absolute kernel socket names must fit sun_path, including
                    // the newline-home case. Use the private runtime directory
                    // for these short-lived fixtures; build artifacts stay cached.
                    std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
                        || {
                            PathBuf::from(std::env::var_os("HOME").unwrap())
                                .join(".cache/codex-scratch/ar3")
                        },
                        PathBuf::from,
                    )
                },
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
        fs::create_dir_all(base.parent().unwrap()).unwrap();
        let cache = base.with_file_name("infraternal.bootstrap-cache");
        fs::create_dir(&cache).unwrap();
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
        fs::copy(common::runtime_helper(), cache.join("payload")).unwrap();
        fs::set_permissions(cache.join("payload"), fs::Permissions::from_mode(0o700)).unwrap();
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
                "if command -v python3 >/dev/null 2>&1; then exit 99; fi; [ \"$(id -u)\" != 0 ] || exit 98; exec /bin/sh",
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
        "{preamble}{}{}\n{}\n",
        include_str!("../src/setup_guard.sh"),
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
    // The VM runner is root; only this bind-mounted fixture becomes a rootless
    // uid in the image. The build-host runner already uses its ordinary uid.
    if fs::metadata(&host.root).unwrap().uid() == 0 {
        assert!(
            Command::new("chown")
                .args(["-R", "65534:65534"])
                .arg(&host.root)
                .status()
                .unwrap()
                .success()
        );
    }
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
    // Continue through fresh staging in the same minimal image. The verified
    // executable cache survives rollback; no additional host tool is installed.
    let fresh = format!(
        "set -euC\numask 077\nbase=\"$HOME/.local/share/infraternal\"\nhost={HOST}\ntransaction={TRANSACTION}\n{}{}\n{}\n{}\nln \"$cache/payload\" \"$stage/payload\"\nhandoff_setup_lease \"$stage/payload\" yes\n{}\n{}\n{}\n",
        include_str!("../src/setup_guard.sh"),
        include_str!("../src/setup_lock.sh"),
        installer_constant("PAYLOAD_CACHE"),
        installer_constant("STAGE_TRANSACTION"),
        include_str!("../src/runtime_cleanup.sh"),
        installer_constant("FRESH_CLEANUP"),
        installer_constant("ROLLBACK_TRANSACTION"),
    );
    let retried = host.run(&fresh);
    assert!(
        retried.status.success(),
        "minimal image fresh retry status={:?}",
        retried.status.code()
    );
    assert!(!host.base().exists());
    assert!(!host.receipt().exists());
}

/// A process still owns its bound control socket during the bind-to-listen gap.
#[test]
fn review_bound_control_socket_before_listen_preserves_receipt() {
    bound_legacy_control_socket_retains_receipt(false, None, false, false);
}

/// Restricted descriptor inspection cannot prove a bound legacy endpoint stale.
#[test]
fn private_legacy_control_socket_preserves_receipt() {
    bound_legacy_control_socket_retains_receipt(true, None, false, false);
}

/// The kernel's socket name includes the full home path, including spaces.
#[test]
fn legacy_control_socket_in_spaced_home_preserves_receipt() {
    bound_legacy_control_socket_retains_receipt(false, Some(" space"), false, false);
}

/// Another directory's same-user endpoint is not runtime ownership of this file.
#[test]
fn unrelated_same_user_relative_socket_does_not_block_cleanup() {
    bound_legacy_control_socket_retains_receipt(false, None, true, false);
}

/// A kernel socket name can contain a newline without ending runtime ownership.
#[test]
fn legacy_control_socket_in_newline_home_preserves_receipt() {
    bound_legacy_control_socket_retains_receipt(false, Some("\nname"), false, false);
}

/// An absolute alias still names the same owned control endpoint.
#[test]
fn legacy_control_socket_through_absolute_alias_preserves_receipt() {
    bound_legacy_control_socket_retains_receipt(false, None, false, true);
}

fn bound_legacy_control_socket_retains_receipt(
    private: bool,
    home_suffix: Option<&str>,
    unrelated: bool,
    aliased: bool,
) {
    let mut host = MinimalHost::new();
    if let Some(suffix) = home_suffix {
        let name = host.root.file_name().unwrap().to_str().unwrap();
        let root = host.root.with_file_name(format!("{name}{suffix}"));
        fs::rename(&host.root, &root).unwrap();
        host.root = root;
    }
    let control = host.base().join("sessions/plugins.sock");
    let bind_directory = if unrelated {
        let directory = host.root.join("unrelated");
        fs::create_dir(&directory).unwrap();
        directory
    } else {
        fs::remove_file(&control).unwrap();
        host.base()
    };
    let endpoint = if aliased {
        let alias = host.root.join("alias");
        std::os::unix::fs::symlink(host.base(), &alias).unwrap();
        alias.join("sessions/plugins.sock")
    } else if unrelated {
        bind_directory.join("plugins.sock")
    } else {
        control.clone()
    };
    // Relative bind plus chdir keeps cwd/descriptor paths from supplying an
    // unrelated liveness signal. EOF proves the same holder can still listen.
    let privacy = if private {
        "import ctypes; assert ctypes.CDLL(None).prctl(4,0,0,0,0)==0; "
    } else {
        ""
    };
    let address = if home_suffix.is_some() || aliased {
        "sys.argv[1]"
    } else if unrelated {
        "'plugins.sock'"
    } else {
        "'sessions/plugins.sock'"
    };
    let program = format!(
        "import os,socket,sys; s=socket.socket(socket.AF_UNIX); s.bind({address}); os.chdir('/'); {privacy}print('ready',flush=True); sys.stdin.read(); s.listen(); print('listening',flush=True)"
    );
    let mut holder = Command::new("python3")
        .args(["-u", "-c", &program])
        .arg(&endpoint)
        .current_dir(&bind_directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
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
    let endpoint_retained = endpoint.exists();
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
    if unrelated {
        assert!(
            inspection.status.success()
                && cleanup.status.success()
                && !socket_preserved
                && !receipt_retained
                && endpoint_retained,
            "unrelated endpoint retained cleanup: inspection={:?}, cleanup={:?}, socket_preserved={socket_preserved}, receipt_retained={receipt_retained}",
            inspection.status.code(),
            cleanup.status.code()
        );
        return;
    }
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

/// A helper's lock survives its exit because the installer owns the same description.
#[test]
fn cleanup_holds_runtime_lock_until_all_receipts_retire() {
    let host = MinimalHost::new();
    let stage = host.base().join(".bootstrap-lock");
    fs::create_dir(&stage).unwrap();
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(stage.join("kind"), b"fresh\n").unwrap();
    fs::set_permissions(stage.join("kind"), fs::Permissions::from_mode(0o600)).unwrap();
    let lock_path = host.base().join("sessions/.lifetime-lock");
    fs::write(&lock_path, b"").unwrap();
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
    let metadata = fs::metadata(host.base()).unwrap();
    let mut holder = Command::new("/bin/sh")
        .args(["-c", "exec 6< \"$1\"; \"$2\" --bootstrap-runtime \"$3\" \"$4\" inspect <&6 || exit $?; echo ready; read answer", "sh"])
        .arg(&lock_path).arg(common::runtime_helper()).arg(host.base())
        .arg(format!("{}:{}", metadata.dev(), metadata.ino()))
        .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut ready = [0; 6];
    holder
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .unwrap();
    assert_eq!(&ready, b"ready\n");
    let independent = fs::File::open(&lock_path).unwrap();
    assert!(independent.try_lock().is_err());
    let (inspect, rollback) = recovery_scripts();
    for program in [&inspect, &rollback] {
        let observed = Command::new("/bin/sh")
            .args(["-c", &program.replace("$HOME", host.root.to_str().unwrap())])
            .output()
            .unwrap();
        assert_eq!(observed.status.code(), Some(73));
        assert!(
            stage.join("kind").exists(),
            "live runtime lost its partial staging receipt"
        );
        assert!(host.receipt().exists());
        assert!(host.base().join("sessions/plugins.sock").exists());
    }
    holder.stdin.take().unwrap().write_all(b"done\n").unwrap();
    assert!(holder.wait().unwrap().success());
    let cleaned = Command::new("/bin/sh")
        .args([
            "-c",
            &rollback.replace("$HOME", host.root.to_str().unwrap()),
        ])
        .output()
        .unwrap();
    assert!(
        cleaned.status.success(),
        "cleanup status={:?}",
        cleaned.status.code()
    );
    assert!(!host.receipt().exists());
}

/// Review R10 (#230): a surviving non-dumpable session holder is visible only
/// through the kernel socket table, because `/proc/<pid>` of a non-dumpable
/// process is not owned by the user. Its listening session endpoint must keep
/// cleanup away in every home spelling.
#[test]
fn review_live_session_socket_in_plain_home_blocks_cleanup() {
    live_session_socket_blocks_cleanup(None);
}

/// Review R10 (#230): a newline in the home path splits the session endpoint's
/// kernel table row; the live endpoint must still block cleanup. The runtime
/// fixture root keeps the absolute name within `sun_path`.
#[test]
fn review_live_session_socket_in_newline_home_blocks_cleanup() {
    live_session_socket_blocks_cleanup(Some("\nn"));
}

fn live_session_socket_blocks_cleanup(home_suffix: Option<&str>) {
    let mut host = MinimalHost::new();
    if let Some(suffix) = home_suffix {
        let name = host.root.file_name().unwrap().to_str().unwrap();
        let root = host.root.with_file_name(format!("{name}{suffix}"));
        fs::rename(&host.root, &root).unwrap();
        host.root = root;
    }
    // Distinct per variant: the table check also matches any same-named
    // endpoint, so parallel variants must not observe each other's holder.
    let session = host.base().join(if home_suffix.is_some() {
        "sessions/44444444444444444444444444444444.sock"
    } else {
        "sessions/33333333333333333333333333333333.sock"
    });
    let program = "import ctypes,os,socket,sys; os.umask(0o177); s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(); os.chdir('/'); assert ctypes.CDLL(None).prctl(4,0,0,0,0)==0; print('ready',flush=True); sys.stdin.read()";
    // Keep the unusual home name in the kernel's diagnostic path, but omit
    // the long HOME-cache prefix from sockaddr_un. Changing only the child's
    // working directory is safe while sibling fixtures run concurrently.
    let parent = host.root.parent().unwrap();
    let mut holder = Command::new("python3")
        .args(["-u", "-c", program])
        .arg(session.strip_prefix(parent).unwrap())
        .current_dir(parent)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = [0; 6];
    holder
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .unwrap();
    assert_eq!(&ready, b"ready\n");
    let (inspect, _) = recovery_scripts();
    // The stale-attempt retirement body: revalidate liveness, then remove
    // session endpoints before the rollback (same order as the installer).
    let programs = inspect.trim_end().trim_end_matches("inspect_previous");
    let fresh = format!(
        "{programs}\nsetup_guard\nobserved=$(inspect_previous)\nidentity=${{observed% *}}\nidentity=${{identity##* }}\nnot_live\nretire_control_socket\nfor entry in \"$base/sessions\"/*.sock \"$base/sessions/sessions\"/*.sock; do\n [ \"$entry\" != \"$base/sessions/plugins.sock\" ] || continue\n [ ! -S \"$entry\" ] || rm -- \"$entry\"\ndone\n{}\n{}",
        installer_constant("FRESH_CLEANUP"),
        installer_constant("ROLLBACK_TRANSACTION")
    );
    let run = |script: &str| {
        Command::new("/bin/sh")
            .args(["-c", &script.replace("$HOME", host.root.to_str().unwrap())])
            .output()
            .unwrap()
    };
    let inspection = run(&inspect);
    let cleanup = run(&fresh);
    let session_preserved = session.exists();
    let receipt_retained = host.receipt().exists();
    eprintln!(
        "inspection={:?} cleanup={:?} session_preserved={session_preserved} receipt_retained={receipt_retained} stderr={}",
        inspection.status.code(),
        cleanup.status.code(),
        String::from_utf8_lossy(&cleanup.stderr)
    );
    drop(holder.stdin.take());
    assert!(holder.wait().unwrap().success());
    assert!(
        inspection.status.code() == Some(73)
            && !cleanup.status.success()
            && session_preserved
            && receipt_retained,
        "live session endpoint removed: inspection={:?}, cleanup={:?}, session_preserved={session_preserved}, receipt_retained={receipt_retained}",
        inspection.status.code(),
        cleanup.status.code()
    );
}

/// Review R11 (#230): a cached helper from before the `sessions` mode passes
/// the version probe (`--bootstrap-runtime-version` exits 0), then refuses the
/// unknown mode with 71. Only 76 makes the server refresh the cached helper, so
/// 71 is shown as "ownership is not proven" on every Retry and the cache, the
/// real cause, is never replaced. A helper that cannot run the session check
/// must be reported as unavailable (76).
#[test]
fn review_cached_helper_without_session_mode_asks_for_a_refresh() {
    let host = MinimalHost::new();
    let payload = host
        .base()
        .with_file_name("infraternal.bootstrap-cache/payload");
    // Same answers as the previous helper: the version probe succeeds, and the
    // unknown mode is refused by the mode check with 71.
    fs::write(
        &payload,
        "#!/bin/sh\n[ \"$1\" = --bootstrap-runtime-version ] && exit 0\ncase \"$4\" in inspect|retire) exit 0;; esac\nexit 71\n",
    )
    .unwrap();
    fs::set_permissions(&payload, fs::Permissions::from_mode(0o700)).unwrap();
    // A shim that died and left its endpoint behind.
    // A directory descriptor keeps the bind name short without changing the
    // process-wide working directory or shortening the canonical session ID.
    let directory = fs::File::open(host.base()).unwrap();
    drop(
        UnixListener::bind(
            PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
                .join("sessions/55555555555555555555555555555555.sock"),
        )
        .unwrap(),
    );
    let (inspect, _) = recovery_scripts();
    let output = Command::new("/bin/sh")
        .args(["-c", &inspect.replace("$HOME", host.root.to_str().unwrap())])
        .output()
        .unwrap();
    eprintln!(
        "inspection={:?} stdout={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        output.status.code(),
        Some(76),
        "an outdated cached helper is reported as an ownership failure and never refreshed"
    );
}

/// R11 (#230): the cleanup script compares the helper's capability level with
/// the one it was written for; both sides must name the same level.
#[test]
fn cleanup_script_requires_the_shipped_helper_level() {
    let level = std::str::from_utf8(infraternal_plugin_remote::runtime_lock::LEVEL)
        .unwrap()
        .trim();
    assert!(
        include_str!("../src/runtime_cleanup.sh").contains(&format!("[ \"$level\" = {level} ]")),
        "runtime_cleanup.sh and runtime_lock::LEVEL disagree"
    );
}
