//! Tests private control endpoints and replacement-path trust before any key is exported [217], #154.

use super::*;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/ca-handoff")
            .join(format!(
                "c{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            ));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn private_control_endpoint_cannot_be_stolen_or_created_by_a_client() {
    let directory = Directory::new();
    assert!(request(&directory.0, None).await.is_err());
    assert!(!directory.0.join("restart").exists());
    let control = Control::start(&directory.0).unwrap();
    assert_eq!(
        std::fs::metadata(directory.0.join("restart"))
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&control.path).unwrap().mode() & 0o777,
        0o600
    );
    assert!(Control::start(&directory.0).is_err());
    assert!(control.path.exists());
    drop(control);
    assert!(!directory.0.join("restart/control.sock").exists());
}

#[tokio::test]
async fn restart_requests_use_the_servers_binary_and_reject_untrusted_paths() {
    let directory = Directory::new();
    let mut control = Control::start(&directory.0).unwrap();
    let (received, requested) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(control.requested(None), request(&directory.0, None))
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
    assert!(executable(&binary).is_ok());
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(executable(&binary).is_ok());
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(executable(&binary).is_err());
}

#[tokio::test]
async fn runtime_directory_symlinks_and_public_permissions_are_refused() {
    let directory = Directory::new();
    let external = Directory::new();
    std::os::unix::fs::symlink(&external.0, directory.0.join("restart")).unwrap();
    assert!(Control::start(&directory.0).is_err());
    std::fs::remove_file(directory.0.join("restart")).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(directory.0.join("restart"))
        .unwrap();
    assert!(Control::start(&directory.0).is_err());
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
    let _replacement = Replacement::new(
        crate::restart_binary::Opened::open(PathBuf::from("/usr/bin/bash")).unwrap(),
        Some(&source),
    );
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
    std::fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
    let opened = crate::restart_binary::Opened::open(binary.clone()).unwrap();
    assert!(infraternal_server::ca_handoff_binary::capable(&opened.file).unwrap());
    assert!(!opened.warm);
    let original = opened.file.metadata().unwrap().ino();
    std::fs::rename(&binary, directory.0.join("retained")).unwrap();
    std::fs::copy("/usr/bin/bash", &binary).unwrap();
    assert_eq!(opened.file.metadata().unwrap().ino(), original);
    assert_ne!(std::fs::metadata(&binary).unwrap().ino(), original);
    assert!(Replacement::new(opened, None).input.is_none());
}

#[test]
fn root_owned_marked_target_requires_protected_root_parents() {
    if !nix::unistd::Uid::effective().is_root() {
        return; // Explicitly run this test again in the root fixture scope.
    }
    let directory = Directory::new();
    let binary = directory.0.join("infraternal");
    std::fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
    let opened = crate::restart_binary::Opened::open(binary.clone()).unwrap();
    assert!(opened.warm);
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(
        !crate::restart_binary::Opened::open(binary.clone())
            .unwrap()
            .warm
    );
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::copy("/usr/bin/bash", &binary).unwrap();
    assert!(!crate::restart_binary::Opened::open(binary).unwrap().warm);
}

#[test]
fn real_fd_exec_pins_replacement_and_cold_rollback_uses_null_stdin() {
    const NAME: &str =
        "restart::tests::real_fd_exec_pins_replacement_and_cold_rollback_uses_null_stdin";
    if std::env::var_os("INFRATERNAL_RESTART_FD_TEST").is_some() {
        if std::env::current_exe().unwrap().file_name().unwrap() == "retained" {
            assert_eq!(
                std::fs::read_link("/proc/self/fd/0").unwrap(),
                Path::new("/dev/null")
            );
            return;
        }
        let directory = PathBuf::from(std::env::var_os("INFRATERNAL_RESTART_FD_TEST").unwrap());
        let binary = directory.join("candidate");
        std::fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
        let opened = crate::restart_binary::Opened::open(binary.clone()).unwrap();
        std::fs::rename(&binary, directory.join("retained")).unwrap();
        std::fs::copy("/usr/bin/bash", &binary).unwrap();
        // Keep cleanup with the outer process: successful exec replaces Rust destructors.
        let error = Replacement::new(opened, None).exec();
        panic!("fd replacement failed: {}", error.kind());
    }
    let directory = Directory::new();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_RESTART_FD_TEST", &directory.0)
        .stdin(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[tokio::test]
async fn closed_reply_and_missing_reload_target_do_not_end_restart_control() {
    let directory = Directory::new();
    let mut control = Control::start(&directory.0).unwrap();
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
        socket.write_u16(1).await.unwrap();
        socket.write_all(b".").await.unwrap();
        socket.shutdown().await.unwrap();
        drop(socket);
    };
    tokio::join!(receive, broken);
    let (received, requested) = tokio::join!(control.requested(None), request(&directory.0, None));
    assert!(received.is_ok());
    assert!(!requested.unwrap());
}

#[test]
fn reload_reopens_install_path_when_the_running_inode_was_replaced() {
    const NAME: &str =
        "restart::tests::reload_reopens_install_path_when_the_running_inode_was_replaced";
    if std::env::var_os("INFRATERNAL_DELETED_BINARY_TEST").is_some() {
        let installed = std::env::current_exe().unwrap();
        let staged = installed.with_extension("next");
        std::fs::copy(&installed, &staged).unwrap();
        std::fs::rename(&staged, &installed).unwrap();
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
    std::fs::copy(std::env::current_exe().unwrap(), &installed).unwrap();
    let output = std::process::Command::new(&installed)
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_DELETED_BINARY_TEST", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn default_restart_opens_the_receiver_target_exactly_once() {
    let directory = Directory::new();
    let mut control = Control::start(&directory.0).unwrap();
    crate::restart_binary::reset_test_opens();
    let (received, sent) = tokio::join!(control.requested(None), request(&directory.0, None));
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
    use std::os::unix::process::CommandExt;
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
        while !entered.load(std::sync::atomic::Ordering::Acquire) {
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
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
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
    if std::env::var_os("INFRATERNAL_EARLY_HUP_TEST").is_some() {
        queue_reload().unwrap();
        // Direct the signal to this thread: the real image does this before
        // creating any runtime threads, which then inherit the blocked mask.
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGHUP).unwrap();
        let directory = Directory::new();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let mut control = Control::start(&directory.0).unwrap();
            assert!(
                tokio::time::timeout(Duration::from_secs(2), control.requested(None))
                    .await
                    .unwrap()
                    .is_ok()
            );
        });
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_EARLY_HUP_TEST", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "early SIGHUP ended the fresh image: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
