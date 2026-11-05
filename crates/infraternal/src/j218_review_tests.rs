//! Independent host installation refusal and rollback regressions (#338, J218).
use super::*;
use std::io::BufRead;

/// Remove only this probe's private filesystem tree, including on an assertion failure.
struct Fixture(
    /// The private namespace root owned exclusively by this probe.
    PathBuf,
);
impl Fixture {
    /// Build a private namespace root whose owner matches the invoking test account.
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("j218-{}", uuid::Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    /// Keep failed review probes from leaving installation fixture state behind.
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// D349 makes the short invocation a supported spelling of the running server.
#[test]
fn j218_running_server_alias_is_detected() {
    assert_eq!(
        inspect::command(b"/usr/local/bin/infra\0server\0--data\0/srv/custom\0"),
        Some(b"server".as_slice())
    );
}

/// A custom service invoking the supported alias must refuse before creating host state.
#[test]
fn j218_installed_server_alias_is_detected() {
    let fixture = Fixture::new();
    let units = fixture.0.join("etc/systemd/system");
    fs::create_dir_all(&units).unwrap();
    fs::write(
        units.join("control.service"),
        b"[Service]\nExecStart=/opt/infra server --data /srv/custom\n",
    )
    .unwrap();
    assert!(
        preflight(&fixture.0, nix::unistd::geteuid().as_raw()).is_err(),
        "server alias passed read-only preflight"
    );
}

/// Process arguments retain boundaries; unresolved units need a whole CLI name or path component.
#[test]
fn j218_alias_commands_respect_word_boundaries() {
    assert_eq!(
        inspect::command(b"/opt/custom path/infra\0--json\0server\0--data=/srv/private\0"),
        Some(b"server".as_slice())
    );
    for (command, server) in [
        (
            "\"/opt/custom path/infra\" --json server --data /srv/private",
            true,
        ),
        ("/opt/infra ssh host server", true),
        ("/opt/unrelated server --data /srv/private", false),
        ("/opt/infra-other server", false),
    ] {
        let fixture = Fixture::new();
        let units = fixture.0.join("etc/systemd/system");
        fs::create_dir_all(&units).unwrap();
        fs::write(
            units.join("control.service"),
            format!("[Service]\n  ExecStart={command}\n"),
        )
        .unwrap();
        assert_eq!(
            preflight(&fixture.0, nix::unistd::geteuid().as_raw()).is_err(),
            server
        );
        assert!(!fixture.0.join("var").exists());
        assert!(!fixture.0.join("usr").exists());
    }
}

/// Child helper holds the actual transaction after enrollment files have been written.
#[test]
#[ignore = "run only by the interruption probe"]
fn j218_hold_enrollment_transaction() {
    let root = PathBuf::from(std::env::var_os("J218_ROOT").unwrap());
    let result = super::super::termination::run(|interrupted| async move {
        let _transaction = Install::begin(
            &root,
            nix::unistd::geteuid().as_raw(),
            Path::new("/bin/false"),
        )
        .unwrap()
        .interrupt_on(interrupted);
        fs::write(
            root.join("var/lib/infraternal/agent/identity.json"),
            b"fixture enrollment",
        )
        .unwrap();
        println!("\nJ218_TRANSACTION_READY");
        std::io::stdout().flush().unwrap();
        std::future::pending::<()>().await;
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    std::process::exit(1);
}

/// A normal termination signal must not strand enrollment state that blocks every retry.
#[test]
fn j218_sigterm_rolls_back_enrollment() {
    if isolated_enrollment_proof("j218_sigterm_rolls_back_enrollment") {
        return;
    }
    for signal in [
        nix::sys::signal::Signal::SIGTERM,
        nix::sys::signal::Signal::SIGINT,
        nix::sys::signal::Signal::SIGHUP,
    ] {
        enrollment_interruption(signal);
    }
}

/// Run the complete lock-sensitive proof outside the multithreaded suite's concurrent forks.
/// Until exec, unrelated forked children can inherit this test's flock descriptors.
fn isolated_enrollment_proof(test: &str) -> bool {
    if std::env::var_os("J198_ISOLATED_ENROLLMENT").is_some() {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("up::install::j218_review::{test}"),
            "--nocapture",
        ])
        .env("J198_ISOLATED_ENROLLMENT", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated enrollment proof failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
    true
}

/// Deliver one signal to a child in the production cancellation scope, then prove retry succeeds.
fn enrollment_interruption(signal: nix::sys::signal::Signal) {
    use std::os::unix::process::CommandExt as _;
    let fixture = Fixture::new();
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "up::install::j218_review::j218_hold_enrollment_transaction",
                "--ignored",
                "--nocapture",
            ])
            .env("J218_ROOT", &fixture.0)
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let ready = std::io::BufReader::new(child.0.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok)
        .any(|line| line == "J218_TRANSACTION_READY");
    assert!(ready);
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(child.0.id()).unwrap()),
        signal,
    )
    .unwrap();
    let status = child.0.wait().unwrap();
    assert!(!status.success());
    let identity = fixture.0.join("var/lib/infraternal/agent/identity.json");
    println!(
        "{signal:?}: enrollment_survived={} retry_preflight_refused={}",
        identity.exists(),
        preflight(&fixture.0, nix::unistd::geteuid().as_raw()).is_err()
    );
    if signal == nix::sys::signal::Signal::SIGKILL {
        assert!(identity.exists(), "abrupt stop unexpectedly ran Drop");
        let journal = fixture.0.join(".infraternal-up.journal");
        let before = fs::read(&journal).unwrap();
        preflight(&fixture.0, nix::unistd::geteuid().as_raw()).unwrap();
        assert!(identity.exists(), "read-only preflight performed recovery");
        assert_eq!(fs::read(&journal).unwrap(), before);
        let retry = Install::begin(
            &fixture.0,
            nix::unistd::geteuid().as_raw(),
            Path::new("/bin/false"),
        )
        .unwrap();
        assert!(
            !identity.exists(),
            "next privileged run did not recover enrollment"
        );
        drop(retry);
    }
    assert!(
        !identity.exists(),
        "interrupted enrollment was not recovered"
    );
    preflight(&fixture.0, nix::unistd::geteuid().as_raw()).unwrap();
    assert!(!fixture.0.join("var").exists());
}

/// Writable and symlinked install ancestors must be refused without creating host state.
#[test]
fn j218_untrusted_install_ancestry_is_read_only() {
    for symlink in [false, true] {
        let fixture = Fixture::new();
        if symlink {
            fs::create_dir(fixture.0.join("foreign")).unwrap();
            std::os::unix::fs::symlink("foreign", fixture.0.join("var")).unwrap();
        } else {
            fs::create_dir(fixture.0.join("var")).unwrap();
            fs::set_permissions(fixture.0.join("var"), fs::Permissions::from_mode(0o777)).unwrap();
        }
        assert!(
            Install::begin(
                &fixture.0,
                nix::unistd::geteuid().as_raw(),
                Path::new("/bin/false")
            )
            .is_err()
        );
        assert!(!fixture.0.join("etc").exists());
        assert!(!fixture.0.join("var/lib").exists());
    }
}

/// Disabling a failed installation must preserve an earlier unit alias owned by its administrator.
#[test]
fn j218_rollback_preserves_preexisting_unit_alias() {
    let fixture = Fixture::new();
    let units = fixture.0.join("etc/systemd/system");
    fs::create_dir_all(&units).unwrap();
    let alias = units.join("control.service");
    std::os::unix::fs::symlink("infraternal-agent.service", &alias).unwrap();
    let before = fs::symlink_metadata(&alias).unwrap();
    let source = fixture.0.join("source");
    fs::write(&source, b"fixture executable").unwrap();
    let systemctl = fixture.0.join("systemctl");
    let log = fixture.0.join("offline-disable.log");
    fs::write(&log, b"").unwrap();
    // Offline disable exercises real unit-file removal without touching the host manager.
    crate::test_executable::write(
        &systemctl,
        format!(
            "#!/bin/sh\nif [ \"$1\" = show ]; then printf 'LoadState=loaded\\nExecStart={{ path=/usr/bin/true ; argv[]=true ; }}\\n'; exit 0; fi\nif [ \"$1\" = disable ]; then\n  /usr/bin/systemctl --root='{}' disable infraternal-agent.service > '{}' 2>&1\n  exit $?\nfi\n[ \"$1\" != is-active ]\n",
            fixture.0.display(),
            log.display()
        ),
        0o755,
    );
    assert!(
        Install::begin(&fixture.0, nix::unistd::geteuid().as_raw(), &systemctl)
            .unwrap()
            .activate(&source)
            .is_err()
    );
    println!(
        "offline unit-file disable: {}",
        fs::read_to_string(log).unwrap()
    );
    let after = fs::symlink_metadata(&alias).expect("rollback removed a pre-existing unit alias");
    assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
}

/// Hold activation after every public install path exists, without contacting the host manager.
#[test]
#[ignore = "run only by the installed-state interruption probe"]
fn j218_hold_activation_transaction() {
    let root = PathBuf::from(std::env::var_os("J218_ROOT").unwrap());
    let result = super::super::termination::run(|interrupted| async move {
        let install = Install::begin(
            &root,
            nix::unistd::geteuid().as_raw(),
            &root.join("systemctl"),
        )
        .unwrap()
        .interrupt_on(interrupted);
        install.activate(&root.join("source"))
    });
    assert!(!matches!(result, Ok(Ok(()))));
    std::process::exit(1);
}

/// Reap this probe's process group even when an assertion unwinds the parent test.
struct Child(
    /// The process-group leader; every fixture subprocess remains in its group.
    std::process::Child,
);

impl Drop for Child {
    /// A dedicated process group contains only this child and its fake service manager.
    fn drop(&mut self) {
        if self.0.try_wait().is_ok_and(|status| status.is_none()) {
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(i32::try_from(self.0.id()).unwrap()),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = self.0.wait();
    }
}

/// Termination after publication must undo the unit, binary and both command links.
#[test]
fn j218_sigterm_rolls_back_published_install() {
    use std::os::unix::process::CommandExt as _;
    let fixture = Fixture::new();
    let ready = fixture.0.join("ready");
    let hold = fixture.0.join("hold");
    for path in [&ready, &hold] {
        nix::unistd::mkfifo(
            path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
    }
    fs::write(fixture.0.join("source"), b"fixture executable").unwrap();
    let systemctl = fixture.0.join("systemctl");
    crate::test_executable::write(
        &systemctl,
        format!(
            "#!/bin/sh\nif [ \"$1\" = is-active ]; then\n  printf 'ready\\n' > '{}'\n  read -r hold < '{}'\n  printf 'active\\n'\nfi\n",
            ready.display(),
            hold.display()
        ),
        0o755,
    );
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "up::install::j218_review::j218_hold_activation_transaction",
                "--ignored",
                "--nocapture",
            ])
            .env("J218_ROOT", &fixture.0)
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    assert_eq!(fs::read_to_string(&ready).unwrap(), "ready\n");
    for relative in [
        "var/lib/infraternal/bin/infraternal",
        "usr/local/bin/infraternal",
        "usr/local/bin/infra",
        "etc/systemd/system/infraternal-agent.service",
        "etc/systemd/system/multi-user.target.wants/infraternal-agent.service",
    ] {
        assert!(fs::symlink_metadata(fixture.0.join(relative)).is_ok());
    }
    // Terminal termination reaches both our helper and its currently executing manager.
    nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(i32::try_from(child.0.id()).unwrap()),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    assert!(!child.0.wait().unwrap().success());
    assert!(
        !fixture.0.join("var").exists(),
        "SIGTERM stranded the installed binary"
    );
    assert!(
        !fixture.0.join("usr").exists(),
        "SIGTERM stranded command links"
    );
    assert!(
        !fixture.0.join("etc").exists(),
        "SIGTERM stranded the installed unit"
    );
    preflight(&fixture.0, nix::unistd::geteuid().as_raw()).unwrap();
}

/// Valid manager syntax must not hide an installed server with custom storage.
#[test]
fn j226_systemd_command_forms_refuse_server() {
    for command in [
        r"@/opt/infraternal harmless server --data /srv/private",
        r"/opt/infra \x73erver --data /srv/private",
        r"/opt/infra ${MODE} --data /srv/private",
        "infra server --data /srv/private",
        "-infra server --data /srv/private",
        "/opt/infra \\\n server --data /srv/private",
    ] {
        let fixture = Fixture::new();
        let units = fixture.0.join("etc/systemd/system");
        fs::create_dir_all(&units).unwrap();
        fs::write(
            units.join("control.service"),
            format!("[Service]\nEnvironment=MODE=server\nExecStart={command}\n"),
        )
        .unwrap();
        let refused = preflight(&fixture.0, nix::unistd::geteuid().as_raw()).is_err();
        println!("J226 command={command:?} refused={refused}");
        assert!(refused, "systemd command form bypassed read-only refusal");
    }
    // The kernel establishes executable identity before arguments are interpreted.
    assert_eq!(
        inspect::command(b"harmless\0server\0--data\0/srv/private\0"),
        Some(b"server".as_slice())
    );
    let fixture = Fixture::new();
    fs::create_dir_all(fixture.0.join("etc/systemd/system")).unwrap();
    fs::write(
        fixture.0.join("etc/systemd/system/control.service"),
        "[Service]\nExecStart=@/opt/infraternal harmless server --data /srv/private\n",
    )
    .unwrap();
    assert!(
        preflight(&fixture.0, nix::unistd::geteuid().as_raw()).is_err(),
        "valid @ unit bypassed preflight"
    );
}

/// The actual offline enable operation must preserve our tracked link, which rollback removes.
#[test]
fn j226_offline_enable_leaves_no_owned_link() {
    let fixture = Fixture::new();
    let units = fixture.0.join("etc/systemd/system");
    fs::create_dir_all(&units).unwrap();
    let alias = units.join("control.service");
    std::os::unix::fs::symlink("infraternal-agent.service", &alias).unwrap();
    let before = fs::symlink_metadata(&alias).unwrap();
    fs::write(fixture.0.join("source"), b"fixture executable").unwrap();
    let systemctl = fixture.0.join("systemctl");
    let log = fixture.0.join("enable.log");
    crate::test_executable::write(
        &systemctl,
        format!(
            "#!/bin/sh\nif [ \"$1\" = show ]; then printf 'LoadState=loaded\\nExecStart={{ path=/usr/bin/true ; argv[]=true ; }}\\n'; exit 0; fi\nif [ \"$1\" = enable ]; then\n stat -c '%d:%i' '{0}/etc/systemd/system/multi-user.target.wants/infraternal-agent.service' >> '{1}'\n /usr/bin/systemctl --root='{0}' enable infraternal-agent.service >> '{1}' 2>&1 || exit $?\n stat -c '%d:%i' '{0}/etc/systemd/system/multi-user.target.wants/infraternal-agent.service' >> '{1}'\nfi\n[ \"$1\" != is-active ]\n",
            fixture.0.display(),
            log.display()
        ),
        0o755,
    );
    assert!(
        Install::begin(&fixture.0, nix::unistd::geteuid().as_raw(), &systemctl)
            .unwrap()
            .activate(&fixture.0.join("source"))
            .is_err()
    );
    println!("J226 offline enable: {}", fs::read_to_string(log).unwrap());
    assert!(
        fs::symlink_metadata(units.join("multi-user.target.wants/infraternal-agent.service"))
            .is_err()
    );
    let after = fs::symlink_metadata(alias).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
}

/// A concurrent replacement is outside rollback ownership, even at the enablement pathname.
#[test]
fn j226_replaced_enablement_inode_survives() {
    let fixture = Fixture::new();
    let enabled = fixture
        .0
        .join("etc/systemd/system/multi-user.target.wants/infraternal-agent.service");
    let replacement = fixture.0.join("replacement");
    std::os::unix::fs::symlink("administrator.service", &replacement).unwrap();
    let before = fs::symlink_metadata(&replacement).unwrap();
    fs::write(fixture.0.join("source"), b"fixture executable").unwrap();
    let systemctl = fixture.0.join("systemctl");
    crate::test_executable::write(
        &systemctl,
        format!(
            "#!/bin/sh\nif [ \"$1\" = is-active ]; then\n mv '{}' '{}'\n exit 1\nfi\n",
            replacement.display(),
            enabled.display()
        ),
        0o755,
    );
    assert!(
        Install::begin(&fixture.0, nix::unistd::geteuid().as_raw(), &systemctl)
            .unwrap()
            .activate(&fixture.0.join("source"))
            .is_err()
    );
    let after = fs::symlink_metadata(&enabled).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
}
/// An abrupt helper stop must leave a recoverable installation on its next attempt.
#[test]
fn j226_sigkill_retry_recovers_enrollment() {
    if isolated_enrollment_proof("j226_sigkill_retry_recovers_enrollment") {
        return;
    }
    enrollment_interruption(nix::sys::signal::Signal::SIGKILL);
}

/// Malformed or publicly writable recovery records must never authorize installation writes.
#[test]
fn j226_untrusted_recovery_record_is_read_only() {
    for (mode, bytes) in [
        (0o600, b"not a journal\n".as_slice()),
        (0o600, b"{\"Begin\":{\"version\":2}}\n".as_slice()),
        (0o666, b"".as_slice()),
    ] {
        let fixture = Fixture::new();
        let journal = fixture.0.join(".infraternal-up.journal");
        fs::write(&journal, bytes).unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(mode)).unwrap();
        let before = fs::symlink_metadata(&journal).unwrap();
        assert!(
            Install::begin(
                &fixture.0,
                nix::unistd::geteuid().as_raw(),
                Path::new("/bin/false")
            )
            .is_err()
        );
        let after = fs::symlink_metadata(&journal).unwrap();
        assert_eq!(
            (after.dev(), after.ino(), after.mode()),
            (before.dev(), before.ino(), before.mode())
        );
        assert_eq!(fs::read(&journal).unwrap(), bytes);
        assert!(!fixture.0.join("var").exists());
    }
}

/// A second installer cannot recover or remove the live installer's enrollment directory.
#[test]
fn j226_live_transaction_cannot_be_recovered() {
    let fixture = Fixture::new();
    let first = Install::begin(
        &fixture.0,
        nix::unistd::geteuid().as_raw(),
        Path::new("/bin/false"),
    )
    .unwrap();
    let path = fixture.0.join("var/lib/infraternal/agent");
    let before = fs::symlink_metadata(&path).unwrap();
    assert!(
        Install::begin(
            &fixture.0,
            nix::unistd::geteuid().as_raw(),
            Path::new("/bin/false")
        )
        .is_err()
    );
    let after = fs::symlink_metadata(&path).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    drop(first);
    assert!(!fixture.0.join("var").exists());
    assert_eq!(
        fs::read(fixture.0.join(".infraternal-up.journal")).unwrap(),
        Vec::<u8>::new()
    );
}

/// Retry recovers a published but uncommitted installation while preserving a foreign short name.
#[test]
fn j226_sigkill_retry_recovers_published_install() {
    use std::os::unix::process::CommandExt as _;
    let fixture = Fixture::new();
    let ready = fixture.0.join("ready");
    let foreign = fixture.0.join("usr/local/bin/infra");
    fs::create_dir_all(foreign.parent().unwrap()).unwrap();
    fs::write(&foreign, b"earlier command").unwrap();
    let foreign_before = fs::symlink_metadata(&foreign).unwrap();
    fs::write(fixture.0.join("source"), b"fixture executable").unwrap();
    crate::test_executable::write(
        &fixture.0.join("systemctl"),
        format!(
            "#!/bin/sh\nif [ \"$1\" = is-active ]; then\n touch '{}'\n while :; do sleep 1; done\nfi\nexit 0\n",
            ready.display()
        ),
        0o755,
    );
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "up::install::j218_review::j218_hold_activation_transaction",
                "--ignored",
                "--nocapture",
            ])
            .env("J218_ROOT", &fixture.0)
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    while !ready.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "activation helper exited before readiness"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "activation fixture did not become ready"
        );
        // sleep: wait for the activation helper to publish readiness, with an independent hang bound.
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let identity = fixture.0.join("var/lib/infraternal/agent/identity.json");
    fs::write(&identity, b"fixture enrollment").unwrap();
    nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(i32::try_from(child.0.id()).unwrap()),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    assert!(!child.0.wait().unwrap().success());
    let journal = fixture.0.join(".infraternal-up.journal");
    let before = fs::read(&journal).unwrap();
    assert_eq!(fs::metadata(&journal).unwrap().mode() & 0o777, 0o600);
    preflight(&fixture.0, nix::unistd::geteuid().as_raw()).unwrap();
    assert_eq!(
        fs::read(&journal).unwrap(),
        before,
        "preflight wrote the journal"
    );
    assert!(identity.exists(), "read-only preflight performed recovery");
    let retry = Install::begin(
        &fixture.0,
        nix::unistd::geteuid().as_raw(),
        &fixture.0.join("systemctl"),
    )
    .unwrap();
    assert!(
        !identity.exists(),
        "next privileged attempt did not recover enrollment"
    );
    drop(retry);
    let foreign_after = fs::symlink_metadata(&foreign).unwrap();
    assert_eq!(
        (foreign_before.dev(), foreign_before.ino()),
        (foreign_after.dev(), foreign_after.ino())
    );
    assert_eq!(fs::read(&foreign).unwrap(), b"earlier command");
    assert!(!fixture.0.join("var").exists());
    assert!(!fixture.0.join("etc").exists());
}

/// A durable commit transfers the installation to the service, so retry never removes it.
#[test]
fn j226_committed_install_is_not_recovered() {
    let fixture = Fixture::new();
    let manager = fixture.0.join("systemctl");
    crate::test_executable::write(
        &manager,
        b"#!/bin/sh\nif [ \"$1\" = is-active ]; then printf 'active\\n'; fi\n",
        0o755,
    );
    let source = fixture.0.join("source");
    fs::write(&source, b"fixture executable").unwrap();
    Install::begin(&fixture.0, nix::unistd::geteuid().as_raw(), &manager)
        .unwrap()
        .activate(&source)
        .unwrap();
    let binary = fixture.0.join(SERVICE_BINARY.trim_start_matches('/'));
    let before = fs::symlink_metadata(&binary).unwrap();
    assert!(fixture.0.join(".infraternal-up.journal").exists());
    assert!(Install::begin(&fixture.0, nix::unistd::geteuid().as_raw(), &manager).is_err());
    let after = fs::symlink_metadata(&binary).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(fs::read(binary).unwrap(), b"fixture executable");
}

/// A replacement enrollment directory has no durable ownership and must refuse before recovery.
#[test]
fn j226_recovery_preserves_replaced_enrollment_inode() {
    use std::os::unix::process::CommandExt as _;
    let fixture = Fixture::new();
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "up::install::j218_review::j218_hold_enrollment_transaction",
                "--ignored",
                "--nocapture",
            ])
            .env("J218_ROOT", &fixture.0)
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    assert!(
        std::io::BufReader::new(child.0.stdout.take().unwrap())
            .lines()
            .map_while(Result::ok)
            .any(|line| line == "J218_TRANSACTION_READY")
    );
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(child.0.id()).unwrap()),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    assert!(!child.0.wait().unwrap().success());
    let agent = fixture.0.join("var/lib/infraternal/agent");
    let original = fixture.0.join("earlier-enrollment");
    fs::rename(&agent, &original).unwrap();
    fs::create_dir(&agent).unwrap();
    fs::write(agent.join("keep"), b"administrator replacement").unwrap();
    let before = fs::symlink_metadata(&agent).unwrap();
    let journal = fixture.0.join(".infraternal-up.journal");
    let recorded = fs::read(&journal).unwrap();
    assert!(
        Install::begin(
            &fixture.0,
            nix::unistd::geteuid().as_raw(),
            Path::new("/bin/false")
        )
        .is_err()
    );
    let after = fs::symlink_metadata(&agent).unwrap();
    assert_eq!(
        (before.dev(), before.ino(), before.mode()),
        (after.dev(), after.ino(), after.mode())
    );
    assert_eq!(
        fs::read(agent.join("keep")).unwrap(),
        b"administrator replacement"
    );
    assert_eq!(
        fs::read(original.join("identity.json")).unwrap(),
        b"fixture enrollment"
    );
    assert_eq!(
        fs::read(journal).unwrap(),
        recorded,
        "refusal modified the durable journal"
    );
}

/// A failed stop retains durable ownership, and a later healthy manager can recover it.
#[test]
fn j226_failed_stop_keeps_recovery_authority() {
    let fixture = Fixture::new();
    let manager = fixture.0.join("systemctl");
    crate::test_executable::write(
        &manager,
        "#!/bin/sh\ncase \"$1\" in is-active|stop) exit 1;; esac\n",
        0o755,
    );
    let source = fixture.0.join("source");
    fs::write(&source, b"fixture executable").unwrap();
    let install = Install::begin(&fixture.0, nix::unistd::geteuid().as_raw(), &manager).unwrap();
    let identity = fixture.0.join("var/lib/infraternal/agent/identity.json");
    fs::write(&identity, b"fixture enrollment").unwrap();
    assert!(install.activate(&source).is_err());
    assert!(
        identity.exists(),
        "failed stop discarded enrollment before the service stopped"
    );
    assert!(
        fixture
            .0
            .join(SERVICE_BINARY.trim_start_matches('/'))
            .exists()
    );
    assert_ne!(
        fs::read(fixture.0.join(".infraternal-up.journal")).unwrap(),
        Vec::<u8>::new()
    );
    crate::test_executable::write(&manager, "#!/bin/sh\nexit 0\n", 0o755);
    let retry = Install::begin(&fixture.0, nix::unistd::geteuid().as_raw(), &manager).unwrap();
    assert!(!identity.exists());
    drop(retry);
    assert!(!fixture.0.join("var").exists());
    assert!(!fixture.0.join("etc").exists());
    assert_eq!(
        fs::read(fixture.0.join(".infraternal-up.journal")).unwrap(),
        Vec::<u8>::new()
    );
}

/// J245: the privileged repeat of preflight runs against the real host's manager.
/// A host with no infraternal service must not be refused because of stock units
/// (templates, masked or not-found entries, bare command names).
#[test]
#[ignore = "needs a real host service manager; invoke explicitly on compute01"]
fn j245_real_host_manager_accepts_stock_units() {
    let result = inspect::installed_services(
        Path::new("/"),
        Path::new("/usr/bin/systemctl"),
        &journal::Snapshot::default(),
    );
    println!("J245 real-host installed_services: {result:?}");
    assert!(
        result.is_ok(),
        "stock units refused a fresh host: {result:?}"
    );
}

/// J245: the documented `infraternal up` runs its first preflight unprivileged.
/// A retained root-owned 0600 journal from an earlier attempt must not refuse it.
#[test]
#[ignore = "needs J245_ROOT prepared by root with a retained journal; run as an ordinary user"]
fn j245_unprivileged_preflight_reads_retained_journal() {
    let root = PathBuf::from(std::env::var_os("J245_ROOT").unwrap());
    let result = journal::inspect(&root, 0).map(|_| ());
    println!(
        "J245 euid={} journal inspect: {result:?}",
        nix::unistd::geteuid()
    );
    assert!(
        result.is_ok(),
        "retained journal refused the unprivileged preflight: {result:?}"
    );
}

/// Retry the public read-only stage with the same ordinary-user privileges as the CLI.
#[test]
#[ignore = "child of the privileged abrupt-stop retry probe"]
fn j245_retry_as_normal_user() {
    assert!(!nix::unistd::geteuid().is_root());
    let root = PathBuf::from(std::env::var_os("J218_ROOT").unwrap());
    preflight(&root, 0).expect("ordinary-user preflight must hand private recovery to root");
    println!("J245_USER_RETRY_ACCEPTED");
}

/// A root transaction interrupted during enrollment must remain retryable through the normal user stage.
#[test]
#[ignore = "requires root and J198_UNPRIVILEGED_IMAGE accessible to uid 1500"]
fn j245_sigkill_then_normal_user_retry_recovers() {
    use std::os::unix::process::CommandExt as _;
    assert!(nix::unistd::geteuid().is_root());
    let fixture = Fixture(PathBuf::from(format!(
        "/tmp/j198-retry-{}",
        uuid::Uuid::new_v4()
    )));
    fs::DirBuilder::new()
        .mode(0o755)
        .create(&fixture.0)
        .unwrap();
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o755)).unwrap();
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "up::install::j218_review::j218_hold_enrollment_transaction",
                "--ignored",
                "--nocapture",
            ])
            .env("J218_ROOT", &fixture.0)
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    assert!(
        std::io::BufReader::new(child.0.stdout.take().unwrap())
            .lines()
            .map_while(Result::ok)
            .any(|line| line == "J218_TRANSACTION_READY")
    );
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(child.0.id()).unwrap()),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    assert!(!child.0.wait().unwrap().success());
    let journal = fixture.0.join(".infraternal-up.journal");
    let bytes = fs::read(&journal).unwrap();
    let identity = fixture.0.join("var/lib/infraternal/agent/identity.json");
    assert!(identity.exists());
    let retry = std::process::Command::new(std::env::var_os("J198_UNPRIVILEGED_IMAGE").unwrap())
        .args([
            "--exact",
            "up::install::j218_review::j245_retry_as_normal_user",
            "--ignored",
            "--nocapture",
        ])
        .env("J218_ROOT", &fixture.0)
        .uid(1500)
        .gid(1500)
        .output()
        .unwrap();
    println!("{}", String::from_utf8_lossy(&retry.stdout));
    assert!(
        retry.status.success(),
        "normal-user retry failed: {}",
        String::from_utf8_lossy(&retry.stderr)
    );
    assert_eq!(
        fs::read(&journal).unwrap(),
        bytes,
        "normal-user preflight changed private recovery"
    );
    assert!(
        identity.exists(),
        "normal-user preflight performed recovery"
    );
    let transaction = Install::begin(&fixture.0, 0, Path::new("/bin/false")).unwrap();
    assert!(
        !identity.exists(),
        "privileged handoff did not recover enrollment"
    );
    drop(transaction);
    assert!(!fixture.0.join("var").exists());
}

/// Hold a forced fallback publication with its durable journal ready for abrupt termination.
#[test]
#[ignore = "child helper for the abrupt fallback-publication recovery proof"]
fn j245_hold_fallback_transaction() {
    let root = PathBuf::from(std::env::var_os("J218_ROOT").unwrap());
    let mut transaction = Install::begin(
        &root,
        nix::unistd::geteuid().as_raw(),
        Path::new("/bin/false"),
    )
    .unwrap();
    let destination = root.join("usr");
    let staging = transaction.temporary(&destination).unwrap();
    fs::DirBuilder::new().mode(0o711).create(&staging).unwrap();
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o711)).unwrap();
    let metadata = fs::symlink_metadata(&staging).unwrap();
    transaction
        .record(staging.clone(), &metadata, false)
        .unwrap();
    transaction
        .record(destination.clone(), &metadata, false)
        .unwrap();
    transaction
        .publish_directory(
            &staging,
            &destination,
            Err(io::Error::from_raw_os_error(nix::libc::ENOSYS)),
        )
        .unwrap();
    fs::write(
        root.join("var/lib/infraternal/agent/identity.json"),
        b"fallback enrollment",
    )
    .unwrap();
    println!("\nJ245_FALLBACK_READY");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}

/// The next run must replay the fallback's new inode ownership after SIGKILL, not its revoked claim.
#[test]
fn j245_sigkill_recovers_fallback_publication() {
    use std::os::unix::process::CommandExt as _;
    if isolated_enrollment_proof("j245_sigkill_recovers_fallback_publication") {
        return;
    }
    let fixture = Fixture::new();
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "up::install::j218_review::j245_hold_fallback_transaction",
                "--ignored",
                "--nocapture",
            ])
            .env("J218_ROOT", &fixture.0)
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    assert!(
        std::io::BufReader::new(child.0.stdout.take().unwrap())
            .lines()
            .map_while(Result::ok)
            .any(|line| line == "J245_FALLBACK_READY")
    );
    nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(i32::try_from(child.0.id()).unwrap()),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    assert!(!child.0.wait().unwrap().success());
    let published = fixture.0.join("usr");
    assert_eq!(fs::metadata(&published).unwrap().mode() & 0o777, 0o711);
    let snapshot = journal::inspect(&fixture.0, nix::unistd::geteuid().as_raw()).unwrap();
    assert_eq!(
        snapshot
            .created
            .iter()
            .filter(|entry| entry.path == published)
            .count(),
        1,
        "revoked staging inode retained destination authority"
    );
    assert!(
        snapshot.owns(&published),
        "fallback publication lost durable ownership"
    );
    let retry = Install::begin(
        &fixture.0,
        nix::unistd::geteuid().as_raw(),
        Path::new("/bin/false"),
    )
    .unwrap();
    assert!(
        !published.exists(),
        "next-run rollback left fallback publication"
    );
    assert!(
        !fixture
            .0
            .join("var/lib/infraternal/agent/identity.json")
            .exists()
    );
    println!("fallback mode=0711; SIGKILL retry removed published inode and enrollment");
    drop(retry);
}
