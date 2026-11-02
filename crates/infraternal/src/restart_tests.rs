//! Tests private control endpoints and replacement-path trust before any key is exported [217], #154.

#[cfg(target_os = "linux")]
#[path = "restart_deleted_path_review_tests.rs"]
mod deleted_path_review;

use super::*;
use crate::restart_binary::fixture::{RESTART_TEST_HANG_BOUND as HANG_BOUND, Signed};
use std::os::{fd::AsRawFd, unix::process::CommandExt};

struct Directory(PathBuf, Option<PathBuf>);
impl Directory {
    fn new() -> Self {
        const MAX_UNIX_SOCKET_PATH_BYTES: usize = 107;
        let socket_directory = format!("c{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let default_root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/infraternal");
        let root = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT")
            .map_or_else(|| default_root.clone(), PathBuf::from);
        let path = root.join("restart-tests").join(&socket_directory);
        let needs_short_root = path
            .join("restart/control.sock")
            .as_os_str()
            .as_encoded_bytes()
            .len()
            > MAX_UNIX_SOCKET_PATH_BYTES;
        // Executable fixtures must retain trusted HOME ancestry and share the
        // running image's filesystem for hard-link checks. Only sockets use /tmp.
        let directory = if needs_short_root {
            Self(
                default_root.join("restart-tests").join(socket_directory),
                Some(nix::unistd::mkdtemp("/tmp/ir-XXXXXX").unwrap()),
            )
        } else {
            Self(path, None)
        };
        let socket = directory.state().join("restart/control.sock");
        assert!(
            socket.as_os_str().as_encoded_bytes().len() <= MAX_UNIX_SOCKET_PATH_BYTES,
            "restart fixture socket path exceeds Linux sun_path: {} bytes",
            socket.as_os_str().as_encoded_bytes().len()
        );

        // The running unit-test image is also used as a replacement fixture.
        // A shared build umask can make it group-writable, which the production
        // validator correctly refuses; keep this private test image executable.
        std::fs::set_permissions(
            std::env::current_exe().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory.0)
            .unwrap();
        directory
    }

    fn state(&self) -> &Path {
        self.1.as_deref().unwrap_or(&self.0)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        if let Some(root) = &self.1 {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

fn copy_private_image(source: &Path, target: &Path) {
    std::fs::copy(source, target).unwrap();
    std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn strip_image(image: &Path) {
    let child = std::process::Command::new("strip")
        .arg("--strip-all")
        .arg(image)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let output = bounded_output(child, HANG_BOUND, "strip test image");
    assert!(
        output.status.success(),
        "strip test image failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Cache one stripped source image; each test still signs a separate private copy.
fn stripped_test_image(source: &Path) -> PathBuf {
    if source
        .file_name()
        .is_some_and(|name| name.to_string_lossy().ends_with(".all-stripped"))
    {
        return source.to_owned();
    }
    let target_root = crate::restart_binary::fixture::scratch_root();
    let cache = target_root.join("restart-test-images");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Include source identity so a rebuilt test executable cannot reuse stale fixture bytes.
    let source_metadata = std::fs::metadata(source).unwrap();
    let modified = source_metadata
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut image_name = source
        .file_name()
        .expect("test image has a name")
        .to_os_string();
    image_name.push(format!(
        ".{}-{modified}.all-stripped",
        source_metadata.len()
    ));
    let image = cache.join(&image_name);
    if !image.exists() {
        let mut staging_name = image_name;
        staging_name.push(format!(".{}", uuid::Uuid::new_v4().simple()));
        let staging = cache.join(staging_name);
        copy_private_image(source, &staging);
        strip_image(&staging);
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();
        match std::fs::hard_link(&staging, &image) {
            Ok(()) => std::fs::remove_file(&staging).unwrap(),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                std::fs::remove_file(&staging).unwrap();
            }
            Err(error) => panic!("could not retain the stripped test image: {error}"),
        }
    }
    let metadata = std::fs::symlink_metadata(&image).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.mode() & 0o777, 0o700);
    image
}

/// Sign a stripped byte copy at an owner-only path so admission exercises release verification.
fn copy_signed_private_image(source: &Path, target: &Path) -> Signed {
    let source = stripped_test_image(source);
    let bytes = std::fs::read(source).unwrap();
    Signed::new(target.to_owned(), &bytes)
}

fn bounded_output(
    mut child: std::process::Child,
    deadline: Duration,
    description: &str,
) -> std::process::Output {
    let until = std::time::Instant::now() + deadline;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if std::time::Instant::now() >= until {
            let process_group = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
            let _ = nix::sys::signal::killpg(process_group, nix::sys::signal::Signal::SIGKILL);
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "{description} exceeded {deadline:?}; status={}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[tokio::test]
async fn private_control_endpoint_cannot_be_stolen_or_created_by_a_client() {
    let directory = Directory::new();
    assert!(request(directory.state(), None).await.is_err());
    assert!(!directory.state().join("restart").exists());
    let control = Control::start(directory.state()).unwrap();
    assert_eq!(
        std::fs::metadata(directory.state().join("restart"))
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&control.path).unwrap().mode() & 0o777,
        0o600
    );
    assert!(Control::start(directory.state()).is_err());
    assert!(control.path.exists());
    drop(control);
    assert!(!directory.state().join("restart/control.sock").exists());
}

#[tokio::test]
async fn restart_requests_use_the_servers_binary_and_reject_untrusted_paths() {
    let directory = Directory::new();
    let mut control = Control::start(directory.state()).unwrap();
    let (received, requested) = tokio::time::timeout(HANG_BOUND, async {
        tokio::join!(control.requested(None), request(directory.state(), None))
    })
    .await
    .expect("owner restart request deadline");
    assert!(requested.is_ok());
    assert_eq!(
        received.unwrap().binary.path,
        std::env::current_exe().unwrap()
    );
    let alias = directory.0.join("alias");
    std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &alias).unwrap();
    assert!(executable(&alias).is_err());
    let binary = directory.0.join("binary");
    std::fs::write(&binary, b"fixture").unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(executable(&binary).is_err());
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(executable(&binary).is_err());
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(executable(&binary).is_err());
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(executable(&binary).is_err());
}

#[tokio::test]
async fn runtime_directory_symlinks_and_public_permissions_are_refused() {
    let directory = Directory::new();
    let external = Directory::new();
    std::os::unix::fs::symlink(&external.0, directory.state().join("restart")).unwrap();
    assert!(Control::start(directory.state()).is_err());
    std::fs::remove_file(directory.state().join("restart")).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(directory.state().join("restart"))
        .unwrap();
    assert!(Control::start(directory.state()).is_err());
}

#[test]
fn private_path_prefix_cannot_authorize_a_parent_directory_escape() {
    let directory = Directory::new();
    let depth = directory
        .0
        .components()
        .filter(|part| matches!(part, std::path::Component::Normal(_)))
        .count();
    let escaped = directory
        .0
        .join(format!("{}usr/bin/true", "../".repeat(depth)));
    assert!(escaped.exists());
    assert!(executable(&escaped).is_err());
}

#[test]
fn replacement_never_exports_to_a_general_purpose_binary() {
    struct Probe(std::sync::atomic::AtomicUsize);
    impl infraternal_server::ca::CaKeySource for Probe {
        fn load(
            &self,
        ) -> Result<infraternal_server::ca::CaMaterial, infraternal_server::ca::CaError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err(infraternal_server::ca::CaError)
        }
    }
    let source = Probe(std::sync::atomic::AtomicUsize::new(0));
    assert!(crate::restart_binary::Opened::open(PathBuf::from("/usr/bin/bash")).is_err());
    assert_eq!(
        source.0.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "an unmarked executable must never receive signing material, even as root"
    );
}

#[test]
fn rootless_even_marked_replacement_is_cold_and_open_fd_pins_the_inode() {
    if nix::unistd::Uid::effective().is_root() {
        return;
    }
    let directory = Directory::new();
    let binary = directory.0.join("infraternal");
    let signed = copy_signed_private_image(&std::env::current_exe().unwrap(), &binary);
    let opened = signed.open().unwrap();
    assert!(infraternal_server::ca_handoff_binary::capable(&opened.file).unwrap());
    assert!(!opened.warm);
    let original = std::fs::metadata(&binary).unwrap().ino();
    let sealed = opened.file.metadata().unwrap().ino();
    assert_ne!(original, sealed);
    std::fs::rename(&binary, directory.0.join("retained")).unwrap();
    std::fs::copy("/usr/bin/bash", &binary).unwrap();
    assert_eq!(opened.file.metadata().unwrap().ino(), sealed);
    assert_eq!(
        std::fs::metadata(directory.0.join("retained"))
            .unwrap()
            .ino(),
        original
    );
    assert_ne!(std::fs::metadata(&binary).unwrap().ino(), original);
    assert!(Replacement::new(opened, None).unwrap().input.is_none());
}

#[test]
fn root_owned_marked_target_requires_protected_root_parents() {
    if !nix::unistd::Uid::effective().is_root() {
        return; // Explicitly run this test again in the root fixture scope.
    }
    let directory = Directory::new();
    let binary = directory.0.join("infraternal");
    let signed = copy_signed_private_image(&std::env::current_exe().unwrap(), &binary);
    let opened = signed.open().unwrap();
    assert!(opened.warm);
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(!Signed::existing(binary.clone()).open().unwrap().warm);
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::copy("/usr/bin/bash", &binary).unwrap();
    assert!(Signed::existing(binary).open().is_err());
}

#[test]
fn real_fd_exec_pins_replacement_and_cold_rollback_uses_null_stdin() {
    const NAME: &str =
        "restart::tests::real_fd_exec_pins_replacement_and_cold_rollback_uses_null_stdin";
    if std::env::var_os("INFRATERNAL_RESTART_FD_TEST").is_some() {
        let directory = PathBuf::from(std::env::var_os("INFRATERNAL_RESTART_FD_TEST").unwrap());
        let retained = directory.join("retained");
        if retained.exists() {
            // Execution uses a sealed memfd snapshot, while the renamed source
            // inode remains intact beside the overwritten install pathname.
            let expected_source_inode: u64 =
                std::fs::read_to_string(directory.join("source-inode"))
                    .unwrap()
                    .parse()
                    .unwrap();
            let expected_image_inode: u64 = std::fs::read_to_string(directory.join("image-inode"))
                .unwrap()
                .parse()
                .unwrap();
            assert!(
                std::env::current_exe()
                    .unwrap()
                    .as_os_str()
                    .as_bytes()
                    .starts_with(b"/memfd:"),
                "replacement must execute the sealed image descriptor"
            );
            assert_eq!(
                std::fs::metadata("/proc/self/exe").unwrap().ino(),
                expected_image_inode
            );
            assert_eq!(
                std::fs::metadata(&retained).unwrap().ino(),
                expected_source_inode
            );
            assert_ne!(
                std::fs::metadata(directory.join("candidate"))
                    .unwrap()
                    .ino(),
                expected_source_inode
            );
            assert_eq!(
                std::fs::read_link("/proc/self/fd/0").unwrap(),
                Path::new("/dev/null")
            );
            return;
        }
        let binary = directory.join("candidate");
        let signed = copy_signed_private_image(&std::env::current_exe().unwrap(), &binary);
        let source_inode = std::fs::metadata(&binary).unwrap().ino();
        let opened = signed.open().unwrap();
        std::fs::write(directory.join("source-inode"), source_inode.to_string()).unwrap();
        std::fs::write(
            directory.join("image-inode"),
            opened.file.metadata().unwrap().ino().to_string(),
        )
        .unwrap();
        std::fs::rename(&binary, directory.join("retained")).unwrap();
        assert_eq!(
            std::fs::metadata(directory.join("retained")).unwrap().ino(),
            source_inode
        );
        std::fs::copy("/usr/bin/bash", &binary).unwrap();
        assert_ne!(std::fs::metadata(&binary).unwrap().ino(), source_inode);
        // Keep cleanup with the outer process: successful exec replaces Rust destructors.
        let error = Replacement::new(opened, None).unwrap().exec();
        panic!("fd replacement failed: {}", error.kind());
    }
    let directory = Directory::new();
    let source = stripped_test_image(&std::env::current_exe().unwrap());
    let child = std::process::Command::new(source)
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_RESTART_FD_TEST", &directory.0)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let output = bounded_output(child, HANG_BOUND, NAME);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn closed_reply_and_missing_reload_target_do_not_end_restart_control() {
    let directory = Directory::new();
    let mut control = Control::start(directory.state()).unwrap();
    let path = control.path.clone();
    let receive = async {
        let result =
            tokio::time::timeout(Duration::from_millis(200), control.requested(None)).await;
        assert!(
            result.is_err(),
            "EPIPE must be handled in the request loop, without ending serve"
        );
    };
    // Own the path independently of the mutable control borrow.
    let broken = async {
        let mut socket = UnixStream::connect(path).await.unwrap();
        nix::sys::socket::shutdown(socket.as_raw_fd(), nix::sys::socket::Shutdown::Read).unwrap();
        socket.write_u16(1).await.unwrap();
        socket.write_all(b".").await.unwrap();
        socket.shutdown().await.unwrap();
        drop(socket);
    };
    tokio::time::timeout(HANG_BOUND, async { tokio::join!(receive, broken) })
        .await
        .expect("closed reply fixture must finish");
    let (received, requested) = tokio::time::timeout(HANG_BOUND, async {
        tokio::join!(control.requested(None), request(directory.state(), None))
    })
    .await
    .expect("valid request after a closed reply must finish");
    assert!(received.is_ok());
    assert!(!requested.unwrap());
}

#[test]
fn reload_reopens_install_path_when_the_running_inode_was_replaced() {
    const NAME: &str =
        "restart::tests::reload_reopens_install_path_when_the_running_inode_was_replaced";
    if std::env::var_os("INFRATERNAL_DELETED_BINARY_TEST").is_some() {
        let installed = std::env::current_exe().unwrap();
        // Linux rejects rename-overwrite while the destination is executing.
        // Unlink this name first, then write a new inode while /proc/self/exe
        // continues to pin the running image.
        std::fs::remove_file(&installed).unwrap();
        copy_private_image(Path::new("/proc/self/exe"), &installed);
        assert!(
            std::env::current_exe()
                .unwrap()
                .as_os_str()
                .as_bytes()
                .ends_with(b" (deleted)")
        );
        assert_eq!(current_binary().unwrap(), installed);
        return;
    }
    let directory = Directory::new();
    let installed = directory.0.join("installed");
    // A hard link is an executable fixture without a write window after copy.
    // The child unlinks only this name, leaving the cargo test image intact.
    std::fs::hard_link(std::env::current_exe().unwrap(), &installed).unwrap();
    let child = std::process::Command::new(&installed)
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_DELETED_BINARY_TEST", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let output = bounded_output(child, HANG_BOUND, NAME);
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn default_restart_opens_the_receiver_target_exactly_once() {
    const NAME: &str = "restart::tests::default_restart_opens_the_receiver_target_exactly_once";
    if std::env::var_os("INFRATERNAL_DEFAULT_RESTART_TEST").is_none() {
        // Admission retains both target and recovery images. Debug information
        // makes those snapshots hundreds of MiB each without testing another
        // invariant; use the same stripped executable as the other exec tests.
        let source = stripped_test_image(&std::env::current_exe().unwrap());
        let child = std::process::Command::new(source)
            .args(["--exact", NAME, "--nocapture"])
            .env("INFRATERNAL_DEFAULT_RESTART_TEST", "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let output = bounded_output(child, HANG_BOUND, NAME);
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let directory = Directory::new();
    let mut control = Control::start(directory.state()).unwrap();
    crate::restart_binary::reset_test_opens();
    let (received, sent) = tokio::time::timeout(HANG_BOUND, async {
        tokio::join!(control.requested(None), request(directory.state(), None))
    })
    .await
    .expect("default restart request must finish");
    assert!(received.is_ok());
    assert!(sent.is_ok());
    assert_eq!(
        crate::restart_binary::test_opens(),
        1,
        "receiver must pin one opened fd, including default-path restart"
    );
}

#[test]
fn runtime_shutdown_never_waits_forever_on_a_blocking_waiter() {
    const NAME: &str = "restart::tests::runtime_shutdown_never_waits_forever_on_a_blocking_waiter";
    if std::env::var_os("INFRATERNAL_RUNTIME_BOUND_TEST").is_some() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let entered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started = entered.clone();
        runtime.spawn_blocking(move || {
            started.store(true, std::sync::atomic::Ordering::Release);
            let _ = nix::sys::wait::waitpid(pid, None);
        });
        let startup_deadline = std::time::Instant::now() + HANG_BOUND;
        while !entered.load(std::sync::atomic::Ordering::Acquire) {
            assert!(
                std::time::Instant::now() < startup_deadline,
                "blocking waiter did not start before the hang bound"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        shutdown_runtime(runtime);
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
        let _ = child.wait();
        return;
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_RUNTIME_BOUND_TEST", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + HANG_BOUND;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            return;
        }
        if std::time::Instant::now() >= deadline {
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap()),
                nix::sys::signal::Signal::SIGKILL,
            );
            let _ = child.wait();
            panic!("runtime shutdown waited forever on a blocking waitpid");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn early_hangup_is_queued_until_control_installs_its_handler() {
    const NAME: &str = "restart::tests::early_hangup_is_queued_until_control_installs_its_handler";
    if let Some(state) = std::env::var_os("INFRATERNAL_EARLY_HUP_TEST") {
        queue_reload().unwrap();
        // Direct the signal to this thread: the real image does this before
        // creating any runtime threads, which then inherit the blocked mask.
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGHUP).unwrap();
        let state = PathBuf::from(state);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let mut control = Control::start(&state).unwrap();
            assert!(
                tokio::time::timeout(HANG_BOUND, control.requested(None))
                    .await
                    .unwrap()
                    .is_ok()
            );
        });
        return;
    }
    // Keep cleanup in the parent: a bounded stop cannot run child destructors.
    let directory = Directory::new();
    let child_image = stripped_test_image(&std::env::current_exe().unwrap());
    let child = std::process::Command::new(child_image)
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_EARLY_HUP_TEST", directory.state())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let output = bounded_output(child, HANG_BOUND, NAME);
    assert!(
        output.status.success(),
        "early SIGHUP ended the fresh image: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn restart_request_logs_kernel_peer_target_and_cold_outcome() {
    const NAME: &str = "restart::tests::restart_request_logs_kernel_peer_target_and_cold_outcome";
    if let Some(state) = std::env::var_os("INFRATERNAL_RESTART_LOG_TEST") {
        infraternal_server::configure_logging(false);
        let state = PathBuf::from(state);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let mut control = Control::start(&state).unwrap();
            let (received, sent) = tokio::join!(control.requested(None), request(&state, None));
            assert!(received.is_ok());
            assert!(!sent.unwrap());
        });
        return;
    }
    // Own both roots through success, child failure, and timeout unwinding.
    let directory = Directory::new();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_RESTART_LOG_TEST", directory.state())
        .env("RUST_LOG", "infraternal=info")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let pid = child.id();
    let output = bounded_output(child, HANG_BOUND, NAME);
    assert!(output.status.success());
    let logs = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        logs.contains(&format!("request_pid=Some({pid})")),
        "restart log must include authenticated peer PID: {logs}"
    );
    assert!(logs.contains(&format!(
        "request_uid=Some({})",
        nix::unistd::Uid::effective().as_raw()
    )));
    assert!(logs.contains("server_restart_request"));
    assert!(logs.contains("cold"));
    assert!(!logs.contains("seed") && !logs.contains("key_bytes") && !logs.contains("key_length"));
}

#[test]
fn cold_exec_with_closed_stdin_keeps_the_image_pinned_and_maps_null() {
    const NAME: &str =
        "restart::tests::cold_exec_with_closed_stdin_keeps_the_image_pinned_and_maps_null";
    if let Ok(stage) = std::env::var("INFRATERNAL_CLOSED_STDIN_TEST") {
        let path = PathBuf::from(std::env::var_os("INFRATERNAL_CLOSED_STDIN_BINARY").unwrap());
        let mut opened = if stage == "before" {
            Some(Signed::existing(path.clone()).open().unwrap())
        } else {
            None
        };
        nix::unistd::close(0).unwrap();
        let opened = opened
            .take()
            .unwrap_or_else(|| Signed::existing(path).open().unwrap());
        let error = Replacement::new(opened, None).unwrap().exec();
        panic!(
            "closed stdin must not overwrite the checked executable fd: {}",
            error.kind()
        );
    }
    let mut failures = Vec::new();
    let deadline = std::time::Instant::now() + HANG_BOUND;
    for stage in ["before", "after"] {
        let directory = Directory::new();
        let target = directory.0.join("cold-exec-successor");
        // A native probe observes inherited descriptors before the Rust runtime
        // can repair closed standard input and mask the exec boundary failure.
        let source = directory.0.join("stdin-probe.c");
        std::fs::write(&source, r#"/* Tests null stdin at the actual exec boundary, before runtime repair [217], #154. */
#include <sys/stat.h>
#include <unistd.h>
int main(void) {
    struct stat input, expected;
    return fstat(STDIN_FILENO, &input) != 0 || stat("/dev/null", &expected) != 0
        || input.st_dev != expected.st_dev || input.st_ino != expected.st_ino;
}
"#).unwrap();
        let compiled = std::process::Command::new("cc")
            .arg(&source)
            .arg("-o")
            .arg(&target)
            .env("TMPDIR", &directory.0)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let compiled = bounded_output(
            compiled,
            deadline.saturating_duration_since(std::time::Instant::now()),
            "native stdin probe compiler",
        );
        assert!(
            compiled.status.success(),
            "native stdin probe compile failed: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        strip_image(&target);
        // The inherited shared umask may make compiler output group-writable.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _signed = Signed::new(target.clone(), &std::fs::read(&target).unwrap());
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env("INFRATERNAL_CLOSED_STDIN_TEST", stage)
            .env("INFRATERNAL_CLOSED_STDIN_BINARY", &target)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap();
        let output = bounded_output(
            child,
            deadline.saturating_duration_since(std::time::Instant::now()),
            NAME,
        );
        if !output.status.success() {
            failures.push(format!(
                "stage={stage}\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn reviewer_fifo_replacement_is_refused_without_waiting_for_a_writer() {
    const NAME: &str =
        "restart::tests::reviewer_fifo_replacement_is_refused_without_waiting_for_a_writer";
    if let Some(path) = std::env::var_os("INFRATERNAL_REVIEW_FIFO") {
        let result = crate::restart_binary::Opened::open(PathBuf::from(path));
        assert!(result.is_err(), "a FIFO is not a replacement executable");
        return;
    }
    let directory = Directory::new();
    let fifo = directory.0.join("candidate");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME])
        .env("INFRATERNAL_REVIEW_FIFO", &fifo)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    // A separate process bounds a synchronous open; an async timeout on the
    // same runtime thread cannot fire while that thread waits inside open(2).
    let deadline = std::time::Instant::now() + HANG_BOUND;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "invalid replacement must be refused");
            return;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("FIFO validation waited for a writer beyond the hang bound");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "linux")]
#[path = "restart_path_review_tests.rs"]
mod path_review;
