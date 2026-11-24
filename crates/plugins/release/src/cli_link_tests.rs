//! Unit tests for the world-executable CLI image and `/usr/local/bin/infraternal` link (#211).
#![expect(
    clippy::unwrap_used,
    reason = "unit tests unwrap fixture setup and assertions"
)]
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Isolated temporary root for one CLI-link test, removed on drop.
struct Fixture {
    /// Root folder under `TMPDIR`.
    root: PathBuf,
    /// Configured `lib_dir` and `path_link` inside `root`.
    paths: CliPaths,
}

impl Fixture {
    /// Create a fresh temporary root with a `sources/` folder for fake release images.
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("cli-link-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o755)
            .recursive(true)
            .create(root.join("sources"))
            .unwrap();
        let paths = CliPaths {
            lib_dir: root.join("usr/local/lib/infraternal"),
            path_link: root.join("usr/local/bin/infraternal"),
        };
        Self { root, paths }
    }

    /// Write a private (`0700`) release image named `name` with `bytes`, like `<data>/updates/releases/`.
    fn image(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join("sources").join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// No-op `SELinux` labeler for tests that focus on file and symlink behavior.
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the publish/restore label callback signature"
)]
fn noop_label(_file: &File) -> io::Result<()> {
    Ok(())
}

/// Fresh publish creates `lib_dir` (0755), installs a world-executable copy (0755), and links `path_link`.
#[test]
fn publish_fresh_creates_world_executable_copy_and_link() {
    let f = Fixture::new();
    let img_a = f.image("v1", b"release-v1-binary");

    let outcome = publish(&img_a, &f.paths, noop_label).unwrap();
    assert_eq!(
        outcome,
        PublishOutcome::Updated {
            previous_saved: false
        }
    );
    assert_eq!(
        std::fs::symlink_metadata(&f.paths.lib_dir).unwrap().mode() & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::symlink_metadata(f.paths.active()).unwrap().mode() & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::read(f.paths.active()).unwrap(),
        b"release-v1-binary"
    );
    assert!(!f.paths.previous().exists());
    assert_eq!(
        std::fs::read_link(&f.paths.path_link).unwrap(),
        f.paths.active()
    );
    assert_eq!(check_link(&f.paths).unwrap(), LinkStatus::Current);
}

/// Upgrading replaces the active copy atomically, preserves the previous copy, and idempotent
/// re-publishing does not clobber the preserved previous copy.
#[test]
fn publish_upgrade_keeps_previous_and_idempotent_republish_preserves_it() {
    let f = Fixture::new();
    let img_a = f.image("v1", b"release-v1-binary");
    let img_b = f.image("v2", b"release-v2-binary");

    publish(&img_a, &f.paths, noop_label).unwrap();
    let inode_a = std::fs::symlink_metadata(f.paths.active()).unwrap().ino();

    let outcome = publish(&img_b, &f.paths, noop_label).unwrap();
    assert_eq!(
        outcome,
        PublishOutcome::Updated {
            previous_saved: true
        }
    );
    assert_eq!(
        std::fs::read(f.paths.active()).unwrap(),
        b"release-v2-binary"
    );
    assert_eq!(
        std::fs::read(f.paths.previous()).unwrap(),
        b"release-v1-binary"
    );
    assert_eq!(
        std::fs::symlink_metadata(f.paths.previous()).unwrap().ino(),
        inode_a,
        "previous copy preserves the original active inode"
    );

    // Re-publishing the same bytes must not overwrite `previous` with v2.
    let repeat = publish(&img_b, &f.paths, noop_label).unwrap();
    assert_eq!(repeat, PublishOutcome::Unchanged);
    assert_eq!(
        std::fs::read(f.paths.previous()).unwrap(),
        b"release-v1-binary"
    );
}

/// Existing symlinks to earlier infraternal releases (such as `/opt/infraternal/.../infraternal`)
/// are recognized as ours and atomically re-pointed.
#[test]
fn publish_repoints_older_infraternal_symlink() {
    let f = Fixture::new();
    let img_b = f.image("v2", b"release-v2-binary");
    std::fs::create_dir_all(f.paths.path_link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(
        "/opt/infraternal/edge-20261122T202819Z/infraternal",
        &f.paths.path_link,
    )
    .unwrap();

    assert!(matches!(check_link(&f.paths).unwrap(), LinkStatus::Ours(_)));
    publish(&img_b, &f.paths, noop_label).unwrap();
    assert_eq!(
        std::fs::read_link(&f.paths.path_link).unwrap(),
        f.paths.active()
    );
    assert_eq!(
        std::fs::read(&f.paths.path_link).unwrap(),
        b"release-v2-binary"
    );
}

/// A foreign regular file at `/usr/local/bin/infraternal` is refused loudly and never overwritten,
/// and `lib_dir` is not created.
#[test]
fn publish_refuses_foreign_regular_file_without_touching_anything() {
    let f = Fixture::new();
    let img_a = f.image("v1", b"release-v1-binary");
    std::fs::create_dir_all(f.paths.path_link.parent().unwrap()).unwrap();
    std::fs::write(&f.paths.path_link, b"custom-user-script").unwrap();

    let err = publish(&img_a, &f.paths, noop_label).unwrap_err();
    assert!(matches!(err, CliLinkError::Foreign { .. }), "{err}");
    assert_eq!(
        std::fs::read(&f.paths.path_link).unwrap(),
        b"custom-user-script"
    );
    assert!(!f.paths.lib_dir.exists());
}

/// A symlink to a non-infraternal binary is refused loudly and left untouched.
#[test]
fn publish_refuses_foreign_symlink_without_touching_anything() {
    let f = Fixture::new();
    let img_a = f.image("v1", b"release-v1-binary");
    std::fs::create_dir_all(f.paths.path_link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink("/usr/bin/some-other-tool", &f.paths.path_link).unwrap();

    let err = publish(&img_a, &f.paths, noop_label).unwrap_err();
    assert!(matches!(err, CliLinkError::Foreign { .. }), "{err}");
    assert_eq!(
        std::fs::read_link(&f.paths.path_link).unwrap(),
        Path::new("/usr/bin/some-other-tool")
    );
    assert!(!f.paths.lib_dir.exists());
}

/// A directory at `/usr/local/bin/infraternal` is refused loudly and left untouched.
#[test]
fn publish_refuses_foreign_directory() {
    let f = Fixture::new();
    let img_a = f.image("v1", b"release-v1-binary");
    std::fs::create_dir_all(&f.paths.path_link).unwrap();

    let err = publish(&img_a, &f.paths, noop_label).unwrap_err();
    assert!(matches!(err, CliLinkError::Foreign { .. }), "{err}");
    assert!(f.paths.path_link.is_dir());
}

/// Rollback restores `infraternal.previous` over the active CLI copy while keeping `0755` and the symlink.
#[test]
fn restore_puts_previous_cli_back_on_rollback() {
    let f = Fixture::new();
    let img_a = f.image("v1", b"release-v1-binary");
    let img_b = f.image("v2", b"release-v2-binary");

    publish(&img_a, &f.paths, noop_label).unwrap();
    publish(&img_b, &f.paths, noop_label).unwrap();
    assert_eq!(
        std::fs::read(&f.paths.path_link).unwrap(),
        b"release-v2-binary"
    );

    let outcome = restore(&f.paths, None, noop_label).unwrap();
    assert_eq!(outcome, RestoreOutcome::RestoredPrevious);
    assert_eq!(
        std::fs::read(f.paths.active()).unwrap(),
        b"release-v1-binary"
    );
    assert_eq!(
        std::fs::read(&f.paths.path_link).unwrap(),
        b"release-v1-binary"
    );
    assert_eq!(
        std::fs::symlink_metadata(f.paths.active()).unwrap().mode() & 0o777,
        0o755
    );
}

/// When `infraternal.previous` does not exist yet (first rollback after upgrading from a pre-J1147
/// server), `restore` copies the fallback image into place.
#[test]
fn restore_uses_fallback_when_previous_copy_is_absent() {
    let f = Fixture::new();
    let img_a = f.image("v1", b"release-v1-binary");
    let img_b = f.image("v2", b"release-v2-binary");

    // Simulate a server that upgraded to v2 without a prior `/usr/local/lib/infraternal` copy.
    publish(&img_b, &f.paths, noop_label).unwrap();
    assert!(!f.paths.previous().exists());

    let outcome = restore(&f.paths, Some(&img_a), noop_label).unwrap();
    assert_eq!(outcome, RestoreOutcome::RestoredFromFallback);
    assert_eq!(
        std::fs::read(f.paths.active()).unwrap(),
        b"release-v1-binary"
    );
    assert_eq!(
        std::fs::symlink_metadata(f.paths.active()).unwrap().mode() & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::read_link(&f.paths.path_link).unwrap(),
        f.paths.active()
    );
}

/// Rollback also refuses a foreign `/usr/local/bin/infraternal` loudly without modifying anything.
#[test]
fn restore_refuses_foreign_link() {
    let f = Fixture::new();
    let img_a = f.image("v1", b"release-v1-binary");
    let img_b = f.image("v2", b"release-v2-binary");
    publish(&img_a, &f.paths, noop_label).unwrap();
    publish(&img_b, &f.paths, noop_label).unwrap();

    // Replace the symlink with a foreign file.
    std::fs::remove_file(&f.paths.path_link).unwrap();
    std::fs::write(&f.paths.path_link, b"foreign").unwrap();

    let err = restore(&f.paths, None, noop_label).unwrap_err();
    assert!(matches!(err, CliLinkError::Foreign { .. }), "{err}");
    assert_eq!(std::fs::read(&f.paths.path_link).unwrap(), b"foreign");
    assert_eq!(
        std::fs::read(f.paths.active()).unwrap(),
        b"release-v2-binary"
    );
}

/// The `SELinux` label callback runs on the staged file before rename; if labeling fails, the
/// active copy is unchanged and the staged temporary file is removed.
#[test]
fn publish_labels_before_rename_and_cleans_up_on_label_failure() {
    let f = Fixture::new();
    let img_a = f.image("v1", b"release-v1-binary");
    let img_b = f.image("v2", b"release-v2-binary");

    let calls = AtomicUsize::new(0);
    publish(&img_a, &f.paths, |_| {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let err = publish(&img_b, &f.paths, |_| {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "simulated SELinux refusal",
        ))
    })
    .unwrap_err();
    assert!(matches!(err, CliLinkError::Label(_)), "{err}");
    assert_eq!(
        std::fs::read(f.paths.active()).unwrap(),
        b"release-v1-binary"
    );
    let leftovers: Vec<_> = std::fs::read_dir(&f.paths.lib_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(leftovers, [std::ffi::OsStr::new(ACTIVE_NAME)]);
}

/// A group- or world-writable `lib_dir`, or a symlinked `lib_dir`, is refused as unsafe.
#[test]
fn publish_refuses_unsafe_lib_dir() {
    let f = Fixture::new();
    let img_a = f.image("v1", b"release-v1-binary");
    std::fs::create_dir_all(&f.paths.lib_dir).unwrap();
    std::fs::set_permissions(&f.paths.lib_dir, std::fs::Permissions::from_mode(0o775)).unwrap();

    let err = publish(&img_a, &f.paths, noop_label).unwrap_err();
    assert!(matches!(err, CliLinkError::UnsafeDir { .. }), "{err}");

    // Symlinked `lib_dir` is also refused.
    std::fs::remove_dir(&f.paths.lib_dir).unwrap();
    let other = f.root.join("other");
    std::fs::create_dir_all(&other).unwrap();
    std::os::unix::fs::symlink(&other, &f.paths.lib_dir).unwrap();
    let err = publish(&img_a, &f.paths, noop_label).unwrap_err();
    assert!(matches!(err, CliLinkError::UnsafeDir { .. }), "{err}");
}
