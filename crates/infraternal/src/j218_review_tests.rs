//! Independent host installation refusal and rollback regressions (#338, J218).
use super::*;

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
