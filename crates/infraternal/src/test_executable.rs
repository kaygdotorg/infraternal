//! Publishes the executables that tests are about to run, so that running them
//! can never fail with "Text file busy" (`ETXTBSY`).
//!
//! # Why tests need this
//!
//! Linux refuses to exec a file while any process holds it open for writing.
//! A test that writes a script or binary with `std::fs::write` or
//! `std::fs::copy` closes its descriptor before it runs the file, so on its
//! own it is fine. But the test harness runs many tests on threads of one
//! process, and other tests spawn children all the time. A child forked while
//! our write descriptor is open gets a copy of it, and keeps that copy until
//! the child itself calls exec (close-on-exec only acts at that point). If we
//! exec our file inside that window, the kernel still counts a writer and
//! refuses. Under load the window is wide enough to break gates (#355).
//!
//! # What the helpers do
//!
//! The test process never opens the final file for writing. [`copy`] runs the
//! standard `install` tool, which creates the final file in a short-lived,
//! single-threaded child process. That child forks nothing, and by the time
//! `install` has exited, no process anywhere holds a writer on the file.
//! [`write`] first puts the bytes into a separate staging file that is never
//! executed, then publishes it with [`copy`].
//!
//! Use these for any file a test (or the product code under test) will exec by
//! its path. Files that are only read, or that are executed through a sealed
//! in-memory snapshot, do not need them.
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Creates a new executable file at `path` holding `bytes`, with permission
/// bits `mode` (for example `0o700`). An existing file at `path` is replaced.
pub(crate) fn write(path: &Path, bytes: impl AsRef<[u8]>, mode: u32) {
    let staging = staging_path(path);
    std::fs::write(&staging, bytes).unwrap();
    copy(&staging, path, mode);
    std::fs::remove_file(&staging).unwrap();
}

/// Creates a new executable file at `path` with the contents of `source` and
/// permission bits `mode`. `source` may be the running test executable.
pub(crate) fn copy(source: &Path, path: &Path, mode: u32) {
    let output = Command::new("install")
        .arg("-m")
        .arg(format!("{mode:o}"))
        .arg("--")
        .arg(source)
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "install {} -> {} failed: {}",
        source.display(),
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Links an executable into a private fixture, or copies it with its permission
/// bits when the target directory and passwd home are on different filesystems.
/// Other link errors still fail the test. The copy uses [`copy`] so concurrent
/// test children cannot inherit a writable executable descriptor (#506).
pub(crate) fn link_or_copy(source: &Path, path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::hard_link(source, path) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(nix::libc::EXDEV) => {
            let mode = std::fs::metadata(source).unwrap().permissions().mode() & 0o7777;
            copy(source, path, mode);
        }
        Err(error) => panic!("could not link test executable: {error}"),
    }
}

/// A unique sibling of `path` for staged bytes, so concurrent tests never share one.
fn staging_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .expect("executable path has a file name")
        .to_os_string();
    name.push(format!(".staging-{}", uuid::Uuid::new_v4().simple()));
    path.with_file_name(name)
}

/// A published script runs with the requested mode, can be replaced with new
/// contents and mode, and leaves no staging file behind.
#[test]
fn published_executables_run_and_can_be_replaced() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let directory = std::env::temp_dir().join(format!("test-exec-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let script = directory.join("tool");
    write(&script, "#!/bin/sh\nexit 3\n", 0o700);
    let first = std::fs::metadata(&script).unwrap();
    assert_eq!(first.mode() & 0o777, 0o700);
    assert_eq!(Command::new(&script).status().unwrap().code(), Some(3));
    write(&script, "#!/bin/sh\nexit 4\n", 0o755);
    let second = std::fs::metadata(&script).unwrap();
    assert_eq!(second.permissions().mode() & 0o777, 0o755);
    assert_eq!(Command::new(&script).status().unwrap().code(), Some(4));
    assert_eq!(
        std::fs::read_dir(&directory).unwrap().count(),
        1,
        "staging file left behind"
    );
    std::fs::remove_dir_all(directory).unwrap();
}

/// Build-target executables retain their bytes and mode in temporary fixtures,
/// whether those directories share a filesystem or require the EXDEV fallback.
#[test]
fn fixture_executables_retain_contents_and_mode() {
    use std::os::unix::fs::PermissionsExt;
    let name = format!("test-exec-{}", uuid::Uuid::new_v4());
    let build_directory = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join(&name);
    let fixture_directory = std::env::temp_dir().join(&name);
    std::fs::create_dir(&build_directory).unwrap();
    std::fs::create_dir(&fixture_directory).unwrap();
    let source = build_directory.join("source");
    let installed = fixture_directory.join("installed");
    let script = b"#!/bin/sh\nexit 7\n";
    write(&source, script, 0o751);
    link_or_copy(&source, &installed);
    assert_eq!(std::fs::read(&installed).unwrap(), script);
    assert_eq!(
        std::fs::metadata(&installed).unwrap().permissions().mode() & 0o7777,
        0o751
    );
    assert_eq!(Command::new(&installed).status().unwrap().code(), Some(7));
    std::fs::remove_dir_all(build_directory).unwrap();
    std::fs::remove_dir_all(fixture_directory).unwrap();
}
