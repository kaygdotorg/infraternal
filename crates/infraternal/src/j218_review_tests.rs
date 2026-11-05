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
        process_command(b"/usr/local/bin/infra\0server\0--data\0/srv/custom\0"),
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

/// Quoted custom paths and JSON output still identify the host command, never SSH arguments.
#[test]
fn j218_alias_commands_respect_word_boundaries() {
    assert_eq!(
        process_command(b"/opt/custom path/infra\0--json\0server\0--data=/srv/private\0"),
        Some(b"server".as_slice())
    );
    for (command, server) in [
        (
            "\"/opt/custom path/infra\" --json server --data /srv/private",
            true,
        ),
        ("/opt/infra ssh host server", false),
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
    for signal in [
        nix::sys::signal::Signal::SIGTERM,
        nix::sys::signal::Signal::SIGINT,
        nix::sys::signal::Signal::SIGHUP,
    ] {
        enrollment_interruption(signal);
    }
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
    assert!(
        !identity.exists(),
        "SIGTERM stranded enrollment; retry is refused"
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
    fs::write(&systemctl, format!("#!/bin/sh\nif [ \"$1\" = disable ]; then\n  /usr/bin/systemctl --root='{}' disable infraternal-agent.service > '{}' 2>&1\n  exit $?\nfi\n[ \"$1\" != is-active ]\n", fixture.0.display(), log.display())).unwrap();
    fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
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
    fs::write(&systemctl, format!("#!/bin/sh\nif [ \"$1\" = is-active ]; then\n  printf 'ready\\n' > '{}'\n  read -r hold < '{}'\n  printf 'active\\n'\nfi\n", ready.display(), hold.display())).unwrap();
    fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
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
